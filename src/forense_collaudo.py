#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - collaudo con immagini di riferimento (By silvexe).

Prepara un caso per ogni immagine della cartella di collaudo e confronta i risultati con i valori
attesi scritti in `atteso.json`, ricavati con strumenti indipendenti (hash dei file originali messi
nelle immagini, ewfinfo, icat di Sleuth Kit per APFS). Scrive `collaudo_<data>.md` con l'esito di
ogni controllo e l'ambiente (versione, impronta del programma e versioni degli strumenti): è la
documentazione da allegare per dimostrare che RepertIA, su quel computer, dà i risultati attesi.

Uso:  python3 forense_collaudo.py <cartella di collaudo> [cartella dei risultati] [--lingua it|en]
Con --lingua i casi di prova si preparano in quella lingua (predefinita: quella delle impostazioni).
"""
import bz2
import datetime as dt
import glob
import gzip
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import struct
import sys
import tempfile
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import forense_agent as fa  # noqa: E402
import forense_lingua as lg  # noqa: E402
from forense_lingua import tr, N_  # noqa: E402


def atteso_tradotto(testo):
    """Il testo atteso (in italiano in atteso.json) nella lingua dei casi di prova: se coincide con un modello del
    dizionario («Rete Wi-Fi: {ssid}» → «Rete Wi-Fi: CasaRossi») si traduce il modello e si rimettono i valori."""
    if lg.lingua() == lg.PREDEFINITA:
        return testo
    d = lg.dizionario(lg.lingua())
    if testo in d:
        return d[testo]
    migliore = None             # il modello più specifico: quello con più testo fisso
    for k, v in d.items():
        parti = re.split(r"\{(\w+)\}", k)
        if len(parti) < 3 or re.search(r"\{[^}]*[:!][^}]*\}", k):
            continue
        rx = "".join(re.escape(x) if i % 2 == 0 else f"(?P<{x}>.+?)" for i, x in enumerate(parti))
        try:
            m = re.fullmatch(rx, testo)
            fisso = sum(len(x) for x in parti[::2])
            if m and (migliore is None or fisso > migliore[0]):
                migliore = (fisso, v.format(**m.groupdict()))
        except (re.error, KeyError, IndexError, ValueError):
            continue
    return migliore[1] if migliore else testo


def sha_of(case, part, inode):
    h = hashlib.sha256()
    for chunk in fa.icat_stream(case, part, inode):
        h.update(chunk)
    return h.hexdigest()


def md5_of(case, part, inode):
    h = hashlib.md5()
    for chunk in fa.icat_stream(case, part, inode):
        h.update(chunk)
    return h.hexdigest()


def norm(p):
    return p.replace("\\", "/").strip("/").lower()


SKIP_EXT = (".json", ".md", ".txt", ".zip", ".bz2", ".gz", ".log", ".pdf", ".html", ".csv")


def prepare_public(base):
    """Estrae gli zip/bz2/gz scaricati (nella cartella di collaudo o in pubbliche/) in _estratte/."""
    out = base / "_estratte"
    for arc in sorted(set(base.glob("*.zip")) | set(base.glob("pubbliche/*")) | set(base.glob("*.bz2")) | set(base.glob("*.gz"))
                      | set(base.glob("nist/*.bz2"))):       # (3.0.2) immagini NIST CFTT DFR (.dd.bz2)
        if not arc.is_file():
            continue
        dest = out / arc.name
        if dest.exists():
            continue
        try:
            if zipfile.is_zipfile(arc):
                with zipfile.ZipFile(arc) as z:
                    for m in z.infolist():
                        if m.is_dir() or ".." in m.filename:
                            continue
                        tgt = dest / Path(m.filename).name
                        tgt.parent.mkdir(parents=True, exist_ok=True)
                        with z.open(m) as src, open(tgt, "wb") as dst:
                            shutil.copyfileobj(src, dst, 8 << 20)
            elif arc.suffix in (".bz2", ".gz"):
                dest.mkdir(parents=True, exist_ok=True)
                op = bz2.open if arc.suffix == ".bz2" else gzip.open
                with op(arc, "rb") as src, open(dest / arc.stem, "wb") as dst:
                    shutil.copyfileobj(src, dst, 8 << 20)
        except Exception as e:
            print(tr("  non riesco a estrarre {name}: {e}").format(name=arc.name, e=e), flush=True)
    # (3.0.2) immagini NIST CFReDS così come pubblicate (7z): estratte con il 7-Zip del programma
    for arc in sorted(base.glob("nist/*.7z")):
        dest = out / arc.name
        if dest.exists():
            continue
        import forense_estesa as fx
        exe = fx.seven_zip()
        if not exe:
            print(tr("  non riesco a estrarre {name}: {e}").format(name=arc.name, e=tr("7-Zip non trovato")), flush=True)
            continue
        tmp = out / (arc.name + ".parziale")
        shutil.rmtree(tmp, ignore_errors=True)
        cp = subprocess.run([exe, "x", "-y", f"-o{tmp}", "-bso0", "-bsp0", str(arc)], capture_output=True,
                            stdin=subprocess.DEVNULL, timeout=3600)
        if cp.returncode == 0:
            tmp.rename(dest)
        else:
            print(tr("  non riesco a estrarre {name}: {e}").format(name=arc.name, e=fa.dec(cp.stderr)[-300:]), flush=True)


class Finder:
    """Trova un'immagine per nome o per MD5 pubblicato (così non conta come si chiama il file scaricato)."""
    def __init__(self, base):
        self.base = base
        self.cache_f = base / "_estratte" / "_md5.json"
        try:
            self.cache = json.loads(self.cache_f.read_text())
        except (OSError, ValueError):
            self.cache = {}

    def files(self):
        for p in sorted(self.base.rglob("*")):
            if p.is_file() and not p.name.startswith(("_", ".")) and p.suffix.lower() not in SKIP_EXT \
                    and p.stat().st_size <= (4 << 30):
                yield p

    def md5(self, p):
        st = p.stat()
        k = f"{p}|{st.st_size}|{int(st.st_mtime)}"
        if k not in self.cache:
            h = hashlib.md5()
            with open(p, "rb") as f:
                while c := f.read(8 << 20):
                    h.update(c)
            self.cache[k] = h.hexdigest()
            try:
                self.cache_f.parent.mkdir(exist_ok=True)
                self.cache_f.write_text(json.dumps(self.cache))
            except OSError:
                pass
        return self.cache[k]

    def find(self, t):
        if t.get("immagine"):
            p = self.base / t["immagine"]
            if p.exists():
                return p
        want = (t.get("md5_immagine") or "").lower()
        if want:
            for p in self.files():
                if self.md5(p) == want:
                    return p
        return None


def find(con, path):
    return con.execute("SELECT part, inode, deleted FROM files WHERE lower(path)=? ORDER BY deleted LIMIT 1",
                       (path.lower(),)).fetchone()


def run_test(t, img, out):
    case_dir = out / t["nome"]
    if case_dir.exists():
        fa.rmtree_force(case_dir)          # copie derivate in sola lettura: su Windows rmtree non le toglie
    env = dict(os.environ, **{k: str(v) for k, v in (t.get("ambiente") or {}).items()})
    env.pop("FORENSE_DA_GUI", None)
    mob = t.get("tipo") in ("smartphone", "logica")
    prog = ["forense_mobile.py", "prepara"] if mob else ["forense_agent.py", "prepara"]
    cmd = [sys.executable, str(HERE / prog[0]), prog[1], "--image", str(img), "--case", str(case_dir),
           "--lingua", lg.lingua(), *(["--logica"] if t.get("tipo") == "logica" else []), *t.get("opzioni", [])]
    if t.get("portachiavi"):            # (2.20) portachiavi finto accanto all'estrazione di prova
        cmd += ["--keychain", str(Path(str(img)[:-len(t["immagine"])]) / t["portachiavi"])]
    for sd in t.get("sysdiagnose") or []:   # (2.20) sysdiagnose di prova accanto all'estrazione
        cmd += ["--sysdiagnose", str(Path(str(img)[:-len(t["immagine"])]) / sd)]
    t0 = dt.datetime.now()
    cp = subprocess.run(cmd, capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)
    res = []

    def check(nome, ok, dettaglio="", misura=False, interno=False):
        # interno: controllo del programma (es. pulsanti dell'interfaccia), non un valore pubblicato da terzi
        res.append({"controllo": nome, "ok": bool(ok), "dettaglio": dettaglio, "misura": bool(misura), "interno": bool(interno)})

    if cp.returncode != 0 and not t.get("puo_fallire"):
        check(tr("preparazione del caso"), False, (cp.stdout + cp.stderr)[-1500:])
        return res, cp
    check(tr("preparazione del caso"), True, f"{(dt.datetime.now() - t0).total_seconds():.0f} s")
    if t.get("ambiente", {}).get("REPERTIA_APFS_SECRETS"):
        os.environ["REPERTIA_APFS_SECRETS"] = t["ambiente"]["REPERTIA_APFS_SECRETS"]
    case = fa.load_case(case_dir)
    m = case.meta
    con = fa.sqlite3.connect(case.db_path)
    a = t.get("atteso", {})
    hd = m.get("hash_dati") or {}
    if "hash_esito" in a:
        check(tr("hash dei dati: esito"), hd.get("esito") == a["hash_esito"],
              tr("atteso {hash_esito}, ottenuto {v1} ({v2})").format(hash_esito=a['hash_esito'], v1=hd.get('esito'), v2=fa.hash_dati_testo(hd)))
    for alg in ("md5", "sha1", "sha256"):
        if f"hash_{alg}" in a:
            got = (hd.get("calcolati") or {}).get(alg)
            check(tr("hash dei dati: {v1}").format(v1=alg.upper()), got == a[f"hash_{alg}"], tr("atteso {v1}, ottenuto {got}").format(v1=a[f'hash_{alg}'], got=got))
    parts = [p for p in m.get("partitions", []) if p.get("readable")]
    if "partizioni_leggibili" in a:
        check(tr("partizioni leggibili"), len(parts) == a["partizioni_leggibili"],
              tr("attese {partizioni_leggibili}, trovate {v1} ({v2})").format(partizioni_leggibili=a['partizioni_leggibili'], v1=len(parts), v2=', '.join(str(p.get('fs')) for p in parts)))
    if "file_system" in a:
        fs = sorted({str(p.get("fs")) for p in parts})
        check(tr("tipo di file system"), a["file_system"] in " ".join(fs), tr("atteso {file_system}, trovato {fs}").format(file_system=a['file_system'], fs=fs))
    for path, want in (a.get("file_sha256") or {}).items():
        r = find(con, path)
        if not r:
            check(f"file {path}", False, tr("non trovato nell'elenco dei file"))
            continue
        got = sha_of(case, r[0], r[1])
        check(tr("SHA-256 di {path}").format(path=path), got == want, tr("atteso {want}, letto {got}").format(want=want, got=got))
    for path in a.get("file_cancellati", []):
        r = find(con, path)
        # (3.0.2) 2 = cancellato con l'inode riassegnato a un altro file (es. ext4 di prova: f1.jpg, inode ora della cartella etc)
        check(tr("{path} riconosciuto come cancellato").format(path=path), bool(r) and r[2] in (1, 2, 3),
              (tr("presente e segnato cancellato, inode riassegnato a un altro file") if r[2] == 2 else
               tr("presente e segnato cancellato")) if r and r[2]
              else (tr("presente ma non segnato cancellato") if r else tr("non trovato")))
    if "fuso" in a:
        fz = (m.get("fuso_dispositivo") or {})
        check(tr("fuso del dispositivo rilevato"), fz.get("tz") == a["fuso"] and fz.get("stato") in ("rilevato", "confermato"),
              tr("atteso {fuso}, ottenuto {v1} ({v2})").format(fuso=a['fuso'], v1=fz.get('tz'), v2=fz.get('stato')))
    if a.get("artefatti_titoli") or a.get("artefatti_min"):
        try:
            rows = con.execute("SELECT cat, title, detail FROM artifacts").fetchall()
        except fa.sqlite3.Error:
            rows = []
        for sub in a.get("artefatti_titoli", []):
            alt = {sub.lower(), atteso_tradotto(sub).lower()}
            hit = [r for r in rows if any(x in (r[1] + " " + r[2]).lower() for x in alt)]
            check(tr("artefatto «{sub}»").format(sub=sub), bool(hit), tr("trovato in {v1}").format(v1=hit[0][0]) if hit else tr("non trovato"))
        for cat, n in (a.get("artefatti_min") or {}).items():
            got = sum(1 for r in rows if r[0] == cat)
            check(tr("artefatti «{cat}» almeno {n}").format(cat=cat, n=n), got >= n, f"trovati {got}")
    if "volumi_cifrati_min" in a:
        v = m.get("volumi_cifrati") or []
        check(tr("volumi cifrati segnalati (almeno {volumi_cifrati_min})").format(volumi_cifrati_min=a['volumi_cifrati_min']), len(v) >= a["volumi_cifrati_min"],
              ", ".join(str(x.get("tipo") or x.get("kind") or x) for x in v)[:300] or "nessuno")
    # ---- controlli sulle immagini pubbliche (valori pubblicati da terzi)
    files = None

    def all_files():
        nonlocal files
        if files is None:
            files = con.execute("SELECT part, inode, deleted, type, path FROM files").fetchall()
        return files
    md5c = {}

    def md5f(part, inode):
        k = (part, str(inode))
        if k not in md5c:
            try:
                md5c[k] = md5_of(case, part, inode)
            except Exception:
                md5c[k] = None
        return md5c[k]
    for path, want in (a.get("file_md5") or {}).items():
        it = want if isinstance(want, dict) else {"md5": want}
        r = con.execute("SELECT part, inode, deleted FROM files WHERE lower(path)=? ORDER BY deleted LIMIT 1",
                        (norm(path),)).fetchone()
        got = md5f(r[0], r[1]) if r else None
        check(tr("MD5 di {path}").format(path=path), got == it["md5"], (tr("atteso {md5}, letto {got}").format(md5=it['md5'], got=got) if r else tr("non trovato nell'elenco dei file"))
              + (f" — {it['nota']}" if it.get("nota") else ""), it.get("misura"))
    for it in a.get("cancellati_md5", []):
        cands = [f for f in all_files() if f[2] == 1 and (str(f[3]).startswith("r") or str(f[3]).endswith("r"))]
        name = norm(it["nome"]).rsplit("/", 1)[-1]
        cands.sort(key=lambda f: (f[4].lower().rsplit("/", 1)[-1][1:] != name[1:], f[4]))
        hit = next((f for f in cands if md5f(f[0], f[1]) == it["md5"]), None)
        if hit:
            det = tr("recuperato come «{v1}» (inode {v2}), MD5 uguale").format(v1=hit[4], v2=hit[1])
        else:
            same = [f for f in cands if f[4].lower().rsplit("/", 1)[-1][1:] == name[1:]]
            det = (tr("trovato come cancellato ma con contenuto diverso: ") + ", ".join(
                f"«{f[4]}» MD5 {md5f(f[0], f[1])}" for f in same[:3])) if same else tr("non trovato tra i file cancellati")
        check(tr("file cancellato {nome} recuperato integro").format(nome=it['nome']), hit is not None,
              det + (f" — {it['nota']}" if it.get("nota") else ""), it.get("misura"))
    if a.get("estratti_md5"):
        try:
            xs = con.execute("SELECT path, md5 FROM xitems").fetchall()
        except fa.sqlite3.Error:
            xs = []
        for it in a["estratti_md5"]:
            hit = next((x for x in xs if (x[1] or "").lower() == it["md5"]), None)
            check(tr("{nome} estratto dall'archivio").format(nome=it['nome']), hit is not None,
                  (tr("estratto come «{v1}»").format(v1=hit[0]) if hit else tr("non estratto")) + (f" — {it['nota']}" if it.get("nota") else ""),
                  it.get("misura"))
    for it in a.get("ora_dispositivo", []):
        zone = (m.get("fuso_dispositivo") or {}).get("tz") or "Europe/Rome"
        r = con.execute("SELECT ts FROM events WHERE origin='tsk' AND kind=? AND lower(path) LIKE ? ORDER BY ts LIMIT 1",
                        (it.get("evento", "B"), "%" + norm(it["path"]))).fetchone()
        got = None
        if r:
            from zoneinfo import ZoneInfo
            got = dt.datetime.fromisoformat(r[0][:19]).replace(tzinfo=dt.timezone.utc).astimezone(ZoneInfo(zone)) \
                .strftime("%Y-%m-%d %H:%M")
        check(tr("ora di {path} ({v1}) nel fuso del dispositivo").format(path=it['path'], v1=it.get('evento', 'B')), got == it["atteso"],
              tr("attesa {atteso}, mostrata {got} ({zone}; in UTC {v1})").format(atteso=it['atteso'], got=got, zone=zone, v1=r[0] if r else '-'), it.get("misura"))
    if a.get("carving_md5"):
        cv = []
        try:
            for name, relpath, off in con.execute("SELECT name, relpath, img_offset FROM carved"):
                f = case.root / relpath if relpath else None
                if f and f.exists():
                    cv.append((name, hashlib.md5(f.read_bytes()).hexdigest(), off))
        except fa.sqlite3.Error:
            pass
        on_disk = [f for f in (case.root / "carving").glob("photorec_p*/recup.*/*") if f.name != "report.xml"]
        check(tr("carving: tutti i file trovati da PhotoRec sono nel caso"), len(cv) == len(on_disk) and len(cv) > 0,
              tr("{v1} nel caso, {v2} nelle cartelle di PhotoRec").format(v1=len(cv), v2=len(on_disk)))
        for it in a["carving_md5"]:
            hit = next((c for c in cv if c[1] == it["md5"]), None)
            off_ok = hit is not None and ("settore" not in it or hit[2] == it["settore"] * 512)
            check(tr("carving: {nome} recuperato identico").format(nome=it['nome']) + (tr(" all'offset pubblicato") if "settore" in it else ""), off_ok,
                  (tr("come {v1}, offset {v2}").format(v1=hit[0], v2=hit[2]) + (tr(" (pubblicato: settore {settore} = {v1})").format(settore=it['settore'], v1=it['settore'] * 512)
                                                         if "settore" in it else "") if hit else
                   tr("non recuperato identico ({v1} file recuperati in tutto)").format(v1=len(cv)))
                  + (f" — {it['nota']}" if it.get("nota") else ""), it.get("misura", True))
    if t.get("tipo") == "smartphone":
        controlli_smartphone(t, img, case, con, a, check)
    elif t.get("tipo") == "logica":
        controlli_logica_nist(t, img, case, con, a, check)
    elif t.get("tipo") == "dfr":
        controlli_dfr(t, img, case, con, a, check)
    elif fa.table_exists(con, "meta"):         # (3.0.1) memorie di massa: foto, video e audio riconosciuti dal contenuto
        controlli_media(case, con, check)
        controlli_media_dftt8(t, con, check)
    if t.get("tipo") == "smartphone" or (fa.table_exists(con, "artifacts") and
                                         con.execute("SELECT 1 FROM artifacts WHERE src_path IS NOT NULL AND inode IS NOT NULL LIMIT 1").fetchone()):
        controlli_pulsanti(case, con, check)
    try:
        controlli_relazione(case, con, check)
    except Exception as e:
        check(tr("report illustrato"), False, f"{type(e).__name__}: {e}", interno=True)
    if a.get("manomissione_registro"):          # (2.20.1, AI Act) su un caso dei dischi, prima del controllo del registro
        controlli_reperti_ia(case, check)
    av = fa.audit_verifica(case)
    check(tr("registro: catena integra"), av.get("ok") is True, fa.audit_testo(av))
    controlli_verifica_registro(case, check, bool(a.get("manomissione_registro")))
    if a.get("manomissione_registro"):
        tmp = Path(tempfile.mkdtemp()) / "audit_log.jsonl"
        lines = case.log_path.read_bytes().splitlines(keepends=True)
        if len(lines) >= 3:
            lines[1] = lines[1].replace(b'"ts": "', b'"ts": "X', 1)
            tmp.write_bytes(b"".join(lines))
            bad = fa.audit_verifica(tmp)
            check(tr("registro: una riga modificata viene scoperta"), bad.get("ok") is False, fa.audit_testo(bad))
        shutil.rmtree(tmp.parent, ignore_errors=True)
    try:
        av0 = fa.audit_verifica(case)
        rp = fa.write_report(case)
        txt = rp.read_text(encoding="utf-8")
        mob = fa.is_mobile(case)
        need = [tr("## Hash confrontato con quello dell'acquisizione") if mob else tr("## Hash dei dati acquisiti"),
                tr("## Registro delle operazioni"), tr("## Ambiente di analisi")]
        check(tr("report con le sezioni di integrità"), all(n in txt for n in need), "")
        # (2.20) numero di voci e hash finale del registro nel report = quelli del registro prima della riga «report»
        ok = (tr("- Voci nel registro al momento del report: {v1}").format(v1=av0.get("righe")) in txt
              and (av0.get("ultimo_hash") or "-") in txt)
        check(tr("report: numero di voci e hash finale del registro"), ok,
              tr("{n} voci, {h}").format(n=av0.get("righe"), h=(av0.get("ultimo_hash") or "")[:16]), interno=True)
        controlli_report_strumenti(case, txt, check)
    except Exception as e:
        check("report", False, f"{type(e).__name__}: {e}")
    con.close()
    return res, cp


def controlli_relazione(case, con, check):
    """(3.0.1) Report illustrato, su una copia temporanea del caso: HTML, PDF e Word creati; una chat dei Preferiti con tutti
    i suoi messaggi in fumetti e gli allegati (foto visibili, originali copiati identici); un elemento tolto non compare;
    «tutte le foto» mostra ogni foto riconosciuta dal contenuto; impronte.csv giusto per ogni file; nessuno script nelle
    pagine; evento nel registro."""
    import forense_gui as G
    import forense_relazione as frl
    import xml.dom.minidom as _md
    mob = fa.is_mobile(case)
    chat = None
    if fa.table_exists(con, "chat_threads") and fa.table_exists(con, "artifacts"):   # sorgente logica: niente artefatti
        chat = con.execute("SELECT a.id, t.id, (SELECT COUNT(*) FROM chat_messages m WHERE m.thread = t.id) FROM artifacts a JOIN chat_threads t "
                           "ON t.id = json_extract(a.data, '$.chat_thread') WHERE a.cat='messaggi' AND json_valid(a.data) AND EXISTS "
                           "(SELECT 1 FROM chat_attachments x JOIN chat_messages m ON m.id = x.msg WHERE m.thread = t.id AND x.inode IS NOT NULL "
                           "AND x.inode != 'None' AND lower(x.name) GLOB '*.[jJ][pP]*[gG]') ORDER BY t.n_msg DESC LIMIT 1").fetchone()
    foto = con.execute("SELECT part, inode, path FROM media_file WHERE tipo='foto' ORDER BY path LIMIT 1").fetchone() \
        if fa.table_exists(con, "media_file") else None
    n_foto = con.execute("SELECT COUNT(*) FROM media_file WHERE tipo='foto'").fetchone()[0] if foto else 0
    if not chat and not foto:
        return
    with tempfile.TemporaryDirectory() as d:
        copia = Path(d) / case.root.name
        shutil.copytree(case.root, copia, ignore=shutil.ignore_patterns("cache", "export"))
        c = fa.Case(copia)
        G.search_db(c).close()
        if chat:
            G.bm_add(c, {"cat": "Collaudo report", "item": {"source": "art", "id": chat[0]}})
        if foto:
            G.bm_add(c, {"cat": "Collaudo report", "item": {"source": "fs", "part": foto[0], "inode": foto[1], "path": foto[2], "name": Path(foto[2]).name}})
        altro = con.execute("SELECT id FROM artifacts WHERE cat != 'messaggi' ORDER BY id LIMIT 1").fetchone() \
            if fa.table_exists(con, "artifacts") else None
        if altro:
            G.bm_add(c, {"cat": "Collaudo report", "item": {"source": "art", "id": altro[0]}})
        cat = next(x for x in G.bm_categories(c) if x["name"] == "Collaudo report")
        els = frl.elementi_categoria(c, cat["cid"])
        tolto = None
        if altro:
            cx = G.search_db(c)
            try:
                r0 = cx.execute("SELECT id FROM bm WHERE cid=? AND source='art' AND inode=?", (cat["cid"], str(altro[0]))).fetchone()
            finally:
                cx.close()
            tolto = next((x for x in els if r0 and x["id"] == r0[0]), None)
        o = {"formati": ["html", "pdf", "docx"], "sezioni": ["caso", "reperti"], "tz": "utc",
             "preferiti": {str(cat["cid"]): {"on": 1, "esclusi": [tolto["id"]] if tolto else []}},
             "tutto": (["foto"] if foto and n_foto <= 400 else [])
             + [f"art:{x[0]}" for x in (con.execute("SELECT cat FROM artifacts WHERE cat NOT IN ('messaggi', 'leapp') GROUP BY cat "
                                                    "HAVING COUNT(*) <= 2000 ORDER BY COUNT(*) LIMIT 1")
                                        if fa.table_exists(con, "artifacts") else [])]}       # sorgente logica: niente artefatti
        r = frl.crea(c, o, lambda *_: None)
        out = Path(r["path"])
        pagine = [out / "report.html"] + sorted((out / "pagine").glob("*.html"))
        tutto_html = "\n".join(p.read_text(encoding="utf-8") for p in pagine)
        check(tr("report illustrato: HTML, PDF e Word creati nella cartella del report"),
              all((out / n).exists() for n in ("report.html", "report.pdf", "report.docx")) and (out / "report.pdf").read_bytes()[:5] == b"%PDF-",
              r["rel"], interno=True)
        imp = {}
        for riga in (out / "impronte.csv").read_text(encoding="utf-8").splitlines()[1:]:
            f, _b, h = riga.rsplit(";", 2)
            imp[f] = h
        tutti = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file() and p.name != "impronte.csv")
        sbagliati = [f for f in tutti if imp.get(f) != fa.sha256_file(out / f)]
        check(tr("report illustrato: impronte.csv con lo SHA-256 giusto di ogni file del report"), not sbagliati and set(imp) == set(tutti),
              tr("{n} file, diversi o mancanti: {d}").format(n=len(tutti), d=", ".join(sbagliati[:3]) or "0"), interno=True)
        check(tr("report illustrato: nessuno script nelle pagine (il contenuto delle prove è solo testo e immagini)"),
              "<script" not in tutto_html.lower() and 'http-equiv="Content-Security-Policy"' in tutto_html, "", interno=True)
        if chat:
            n_bolle = len(re.findall(r'<div class="b (?:in|out|sys)', tutto_html))
            cx = fa.db_ro(c)
            try:
                att = cx.execute("SELECT x.name, x.part, x.inode FROM chat_attachments x JOIN chat_messages m ON m.id = x.msg WHERE m.thread=? "
                                 "AND x.inode IS NOT NULL AND x.inode != 'None' AND lower(x.name) GLOB '*.[jJ][pP]*[gG]' LIMIT 1", (chat[1],)).fetchone()
            finally:
                cx.close()
            copiato = next((f for f in (out / "file").iterdir() if f.name.endswith("_" + re.sub(r"[^\w.\-]+", "_", att[0]))), None) if att else None
            if mob:
                import forense_mobile as fm
                h = hashlib.sha256()
                for b in fm.stream(c, int(att[1]), str(att[2])):
                    h.update(b)
                atteso = h.hexdigest()
            else:
                atteso = None
            check(tr("report illustrato: la chat dei Preferiti ha tutti i suoi messaggi in fumetti"), n_bolle >= chat[2],
                  tr("{a} fumetti, {b} messaggi nella chat").format(a=n_bolle, b=chat[2]), interno=True)
            check(tr("report illustrato: la foto allegata alla chat si vede (anteprima) e l'originale copiato è identico"),
                  copiato is not None and (atteso is None or fa.sha256_file(copiato) == atteso)
                  and re.search(r'<div class="a"><a href="\.\./[^"]+" target="_blank"><img src="\.\./anteprime/', tutto_html) is not None,
                  copiato.name if copiato else tr("non copiato"), interno=True)
        if tolto:
            titolo_t = G.art_campi(c, {"id": altro[0]})[0]
            pag = "\n".join(p.read_text(encoding="utf-8") for p in (out / "pagine").glob(f"*_bm{cat['cid']}*.html"))
            check(tr("report illustrato: un elemento tolto dalla categoria non compare"),
                  bool(pag) and not re.search(r"<h3>\d+ \S+ \d+ – " + re.escape(html.escape(str(titolo_t))) + "</h3>", pag), str(titolo_t)[:60], interno=True)
        sezioni_ok, n_tot = True, 0
        for stem in sorted({re.sub(r"_\d+$", "", p.stem) for p in (out / "pagine").glob("*.html")}):
            testo = "\n".join(p.read_text(encoding="utf-8") for p in sorted((out / "pagine").glob(stem + "*.html"),
                                                                            key=lambda x: int(re.search(r"_(\d+)$", x.stem).group(1)) if re.search(r"_(\d+)$", x.stem) else 1)
                              if re.sub(r"_\d+$", "", p.stem) == stem)
            coppie = [(int(x), int(y)) for t in re.findall(r'<div class="num">(\d+)<small>\S+ (\d+)</small>|<h3>(?:💬 |✉️ )?(\d+) \S+ (\d+) – |<tr><td>(\d+) \S+ (\d+)</td>', testo)
                      for x, y in [tuple(v for v in t if v)]]
            n_tot += len(coppie)
            sezioni_ok = sezioni_ok and [x for x, _ in coppie] == list(range(1, len(coppie) + 1)) and all(y == len(coppie) for _, y in coppie)
        check(tr("report illustrato: in ogni sezione le evidenze sono numerate «1 di N», «2 di N»… con N il totale della sezione"),
              n_tot > 0 and sezioni_ok, tr("{n} evidenze numerate").format(n=n_tot), interno=True)
        if foto and "foto" in o["tutto"]:
            pf = "\n".join(p.read_text(encoding="utf-8") for p in (out / "pagine").glob("*_foto*.html"))
            n_el, n_altro = pf.count('<div class="el'), pf.count('<div class="th">📦')
            n_altro += 0 if f"<b>🖼 {html.escape(Path(foto[2]).name)}</b>" in pf else 1
            check(tr("report illustrato: «tutte le foto» mostra ogni foto riconosciuta dal contenuto, anche senza estensione"),
                  n_el >= n_foto and not n_altro, tr("{a} schede, {b} foto nel caso, {c} non mostrate come foto").format(a=n_el, b=n_foto, c=n_altro),
                  interno=True)
        with zipfile.ZipFile(out / "report.docx") as dx:      # chiuso subito: su Windows un file aperto non si cancella
            _md.parseString(dx.read("word/document.xml"))
            media = any(n.startswith("word/media/") for n in dx.namelist())
        pdf = (out / "report.pdf").read_bytes()
        check(tr("report illustrato: il Word è valido e il PDF contiene le immagini"),
              media and pdf.count(b"/Subtype /Image") >= 1, "", interno=True)
        reg = [json.loads(x) for x in (c.root / "audit_log.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
        ev = [x for x in reg if x.get("event") == "report_illustrato"]
        check(tr("report illustrato: registrato nel registro del caso con l'impronta di impronte.csv"),
              bool(ev) and ev[-1]["data"].get("impronte_sha256") == fa.sha256_file(out / "impronte.csv"), "", interno=True)


def controlli_preferiti_chat(case, con, check):
    """(2.21) Scheda di una chat nei Preferiti: l'anteprima porta alla conversazione, la cronologia è in ordine di data, il report
    e l'esportazione contengono la chat, il periodo limita i messaggi. Su una copia temporanea: il caso del collaudo non cambia."""
    import forense_gui as G
    if not fa.table_exists(con, "chat_threads"):
        return
    r = con.execute("SELECT a.id, json_extract(a.data, '$.chat_thread') FROM artifacts a JOIN chat_threads t ON t.id = json_extract(a.data, '$.chat_thread') "
                    "WHERE a.cat='messaggi' AND json_valid(a.data) ORDER BY t.n_msg DESC LIMIT 1").fetchone()
    if not r:
        return
    aid, tid = r
    with tempfile.TemporaryDirectory() as d:
        copia = Path(d) / case.root.name
        shutil.copytree(case.root, copia, ignore=shutil.ignore_patterns("cache", "export", "leapp"))
        c = fa.Case(copia)
        G.search_db(c).close()
        G.bm_add(c, {"cat": "Collaudo", "item": {"source": "art", "id": aid}})
        v = G.art_view(c, {"id": aid})
        check(tr("Preferiti: la scheda di una chat porta alla conversazione («Apri chat»)"), v.get("chat") == tid, str(v.get("chat")), interno=True)
        tl = fa.bookmarks_timeline(c)
        check(tr("Preferiti: la cronologia indica la chat con il suo periodo"), len(tl) == 1 and tl[0]["chat"] == tid and tl[0]["evento"] == tr("conversazione") and bool(tl[0]["ts"]),
              json.dumps(tl[0] if tl else None, ensure_ascii=False, default=str)[:160], interno=True)
        md = fa.write_report(c).read_text(encoding="utf-8")
        check(tr("Preferiti: il report contiene cronologia e testo della chat"), tr("### Cronologia dei preferiti") in md and tr("### Chat nei Preferiti") in md, "", interno=True)
        cx = fa.db_ro(c)
        n_tot = cx.execute("SELECT COUNT(*) FROM chat_messages WHERE thread=?", (tid,)).fetchone()[0]
        giorno = (cx.execute("SELECT MIN(ts) FROM chat_messages WHERE thread=?", (tid,)).fetchone()[0] or "")[:10]
        n_giorno = cx.execute("SELECT COUNT(*) FROM chat_messages WHERE thread=? AND substr(ts,1,10)=?", (tid, giorno)).fetchone()[0]
        cx.close()
        q = {"cid": G.bm_categories(c)[0]["cid"]}
        res = G.export_selection(c, {"kind": "hits", "all": True, "query": {"kind": "hits", **q}, "chat_da": giorno, "chat_a": giorno}, lambda *_: None)
        fh = list((Path(res["path"]) / "chat").glob("chat_*.csv"))
        righe = sum(1 for x in fh[0].read_text(encoding="utf-8-sig").splitlines() if x and not x.startswith("#")) - 1 if fh else -1
        check(tr("Preferiti: esportazione della chat limitata a un periodo, nel manifest"),
              righe >= n_giorno > 0 and (n_tot == n_giorno or n_giorno <= righe < n_tot + 200) and "[chat]" in (Path(res["path"]) / "manifest.csv").read_text(encoding="utf-8-sig"),
              f"{n_giorno}/{n_tot}", interno=True)
        p0 = c.meta.get("evidence")
        c.meta["evidence"] = c.meta["image"] = "/percorso/di/un/altro/computer/copia.dd"
        c.save()
        sb = Path(d) / "falso.dd"
        sb.write_bytes(b"non e la copia")
        c.meta["sha256"] = {"copia.dd": "0" * 64}
        c.save()
        try:
            fa.collega_copia(c, str(sb))
            rifiutata = False
        except ValueError:
            rifiutata = True
        c.meta["sha256"] = {"copia.dd": fa.sha256_file(sb)}
        c.save()
        r2 = fa.collega_copia(c, str(sb))
        reg = (c.root / "audit_log.jsonl").read_text(encoding="utf-8")
        check(tr("Collega copia forense: rifiuta uno SHA-256 diverso, accetta quello giusto, resta nel registro"),
              rifiutata and r2.get("sha256") == "uguale" and "copia_collegata" in reg and fa.load_case(c.root).meta["evidence"] == str(sb.resolve()),
              str(p0 is not None), interno=True)


def controlli_diagnostica(check):
    """(2.21) Il log diagnostico non deve contenere percorsi, nomi tra virgolette, numeri, email; resta il dato tecnico."""
    import forense_diagnostica as fd
    with tempfile.TemporaryDirectory() as d:
        vecchio = fd.FILE
        fd.FILE = Path(d) / "diagnostica.log"
        try:
            try:
                raise ValueError("File '/Users/mario.rossi/Casi/foto al mare.jpg' di +39 333 1234567 mario@esempio.it C:\\Users\\Anna\\casa mia.E01")
            except ValueError as e:
                fd.errore("POST /api/prova", e)
            fd.errore_processo("indice", 1, ["Traceback (most recent call last):", '  File "/Users/mario.rossi/x/forense_agent.py", line 12, in run',
                                             "foto al mare.jpg", "KeyError: 'segreto'"])
            t = fd.testo("collaudo")
        finally:
            fd.FILE = vecchio
    vietati = ("mario", "rossi", "foto", "mare", "333", "1234567", "Anna", "casa mia", "segreto")
    check(tr("Log diagnostici: nessun percorso, nome o numero; restano tipo di errore e riga del programma"),
          not any(x in t for x in vietati) and "ValueError" in t and "KeyError" in t and "forense_agent.py:12" in t,
          ", ".join(x for x in vietati if x in t) or tr("nessun dato sensibile"), interno=True)


def controlli_database(check):
    """(3.0) Gestore dei database: solo letture, originale intatto, query e CSV nel registro, -wal letto dalla copia."""
    import shutil as _sh
    import sqlite3 as _sq
    import forense_database as fdb

    class Caso:
        def __init__(self, r):
            self.root, self.export_dir, self.voci = Path(r), Path(r) / "export", []

        def log(self, azione, dati):
            self.voci.append((azione, dati))

    with tempfile.TemporaryDirectory() as d:
        orig = Path(d) / "orig" / "prova.db"
        orig.parent.mkdir()
        c = _sq.connect(str(orig))
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA wal_autocheckpoint=0")
        c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, testo TEXT)")
        c.execute("INSERT INTO t VALUES (1,'uno')")
        c.commit()
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        c.execute("INSERT INTO t VALUES (2,'nel wal')")
        c.commit()
        lav = Path(d) / "lav"
        lav.mkdir()
        for suf in ("", "-wal"):
            _sh.copy(str(orig) + suf, str(lav / ("prova.db" + suf)))
        c.close()
        prima = fdb._sha(orig)
        caso = Caso(d)
        (Path(d) / "export").mkdir()

        class G:
            @staticmethod
            def file_ident(_case, _b):
                return {"source": "x", "path": "/prova.db", "name": "prova.db", "part": None, "inode": None, "id": 1}

            @staticmethod
            def unique(p):
                return p

            @staticmethod
            def safe_part(s):
                return s

            @staticmethod
            def stamp_now():
                return "prova"

        orig_copia = fdb._copia_lavoro
        tmp = Path(d) / (fdb.PREFISSO + "prova")

        def copia(_g, _c, _i):
            tmp.mkdir()
            for suf in ("", "-wal"):
                _sh.copy(lav / ("prova.db" + suf), tmp / ("prova.db" + suf))
            return tmp, tmp / "prova.db"

        fdb._copia_lavoro = copia
        try:
            a = fdb.apri(G, caso, {})
        finally:
            fdb._copia_lavoro = orig_copia
        vietate = ["INSERT INTO t VALUES (3,'x')", "UPDATE t SET testo='x'", "DELETE FROM t", "DROP TABLE t",
                   "CREATE TABLE z(a)", "ATTACH '" + str(Path(d) / "z.db") + "' AS z", "VACUUM",
                   "PRAGMA journal_mode=DELETE", "PRAGMA query_only=OFF", "SELECT load_extension('x')",
                   "SELECT 1; DROP TABLE t", "PRAGMA writable_schema=ON"]
        rifiutate = 0
        passate = []
        for q in vietate:
            try:
                fdb.query(caso, {"id": a["id"], "sql": q, "scritta": True})
                passate.append(q)
            except ValueError:
                rifiutate += 1
        r = fdb.query(caso, {"id": a["id"], "sql": "SELECT id, testo FROM t ORDER BY id", "scritta": True})
        valori = [x[1][1] for x in r["righe"]]
        check(tr("Gestore database: scritture, ATTACH, estensioni e PRAGMA di modifica rifiutati; le letture funzionano"),
              rifiutate == len(vietate) and bool(r["colonne"]), f"{rifiutate}/{len(vietate)} " + "; ".join(passate), interno=True)
        check(tr("Gestore database: righe del file -wal lette dalla copia di lavoro"),
              valori == ["uno", "nel wal"] and "prova.db-wal" in a["accanto"], ", ".join(valori), interno=True)
        e = fdb.esporta_csv(G, caso, {"id": a["id"], "sql": "SELECT * FROM t"})
        azioni = [v[0] for v in caso.voci]
        testo_csv = (Path(d) / e["path"]).read_text(encoding="utf-8-sig")
        fdb.chiudi(caso, {"id": a["id"]})
        check(tr("Gestore database: l'originale non cambia, la query e il CSV sono nel registro"),
              fdb._sha(orig) == prima and "db_apri" in azioni and "db_query" in azioni and "db_csv" in azioni
              and e["righe"] == 2 and "nel wal" in testo_csv and not tmp.exists(), ", ".join(sorted(set(azioni))), interno=True)
        tn = Path(d) / "_non_sqlite"
        tn.mkdir()
        (tn / "thumbcache_idx.db").write_bytes(b"IMMM" + bytes(60))
        fdb._copia_lavoro = lambda *_: (tn, tn / "thumbcache_idx.db")
        ns = fdb.apri(G, caso, {})
        check(tr("Gestore database: un file che non è SQLite dà un avviso con il formato, senza errore né copie rimaste"),
              ns.get("non_sqlite") is True and "thumbcache" in ns["formato"] and not tn.exists(), str(ns.get("formato")), interno=True)
        import forense_lingua as lgv
        with lgv.usa("en"):
            v_en = lgv.valore("estrazione di uno smartphone iOS 15")
        with lgv.usa("it"):
            v_it = lgv.valore("extraction of a smartphone iOS 15")
        check(tr("Lingua: i testi salvati nel caso si mostrano nella lingua dell'interfaccia, i dati restano invariati"),
              v_en == "extraction of a smartphone iOS 15" and v_it == "estrazione di uno smartphone iOS 15"
              and lgv.valore("undefined") == "undefined", f"{v_en} | {v_it}", interno=True)
        fdb._copia_lavoro = copia
        try:
            t_ok = fdb.interroga(G, caso, {}, "SELECT testo FROM t")
            t_no = fdb.interroga(G, caso, {}, "DELETE FROM t")
        finally:
            fdb._copia_lavoro = orig_copia
        check(tr("Gestore database: l'agente legge in sola lettura, le sue query sono nel registro e la copia viene chiusa"),
              "nel wal" in t_ok and "SHA-256" in t_no + t_ok and "DELETE" not in t_no and not tmp.exists()
              and sum(1 for v in caso.voci if v[0] == "db_query" and v[1].get("origine") == "agente") == 2,
              t_no[:80], interno=True)


def controlli_mappa(check):
    """(3.0) Punti della mappa da una base costruita; KML separato dalle evidenze; esportazioni nel registro."""
    import sqlite3 as _sq
    import forense_mappe as fmp

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)

        class Caso:
            root, export_dir, voci = d, d / "export", []
            meta = {"tipo_caso": "smartphone"}
            db_path = d / "caso.sqlite"

            def log(self, azione, dati):
                self.voci.append((azione, dati))

        caso = Caso()
        con = _sq.connect(str(caso.db_path))
        con.execute("CREATE TABLE meta(source TEXT, part INTEGER, inode TEXT, deleted INTEGER, path TEXT, make TEXT, model TEXT, taken TEXT, lat REAL, lon REAL, author TEXT, data TEXT)")
        con.executemany("INSERT INTO meta VALUES ('fs',1,?,0,?,'','',?,?,?,'','')", [("5", "a.jpg", "2024:01:02 10:00:00", 41.9, 12.5), ("6", "b.jpg", "x", 0, 0), ("7", "c.jpg", "", 200, 12)])
        con.execute("CREATE TABLE artifacts(id INTEGER PRIMARY KEY, cat TEXT, ts TEXT, title TEXT, detail TEXT, user TEXT, src_path TEXT, part INTEGER, inode TEXT, data TEXT, grp TEXT, sub TEXT)")
        con.execute("INSERT INTO artifacts(cat,ts,data,sub) VALUES ('leapp','2024-02-03 09:00:00',?,'Viaggi')", (json.dumps({"campi": {"Origin Latitude": "45.46", "Origin Longitude": "9.19", "Destination Latitude": "40.85", "Destination Longitude": "14.27", "Note": "x"}}),))
        con.commit()
        con.close()
        vecchia = fa.db_ro
        fa.db_ro = lambda _c: _sq.connect(str(caso.db_path))
        try:
            r = fmp.punti(caso)
            nomi = {x["nome"]: x["punti"] for x in r["categorie"]}
            check(tr("Mappa: punti da metadati e artefatti, coppie di campi, punti a 0,0 esclusi"),
                  len(r["punti"]) == 3 and r["esclusi"] == {"zero": 1, "fuori_scala": 1} and nomi.get("Viaggi (Origin)") == 1
                  and nomi.get("Viaggi (Destination)") == 1 and r["punti"][0][4] == "2024-01-02 10:00:00", str(nomi)[:90], interno=True)

            class G:
                unique = staticmethod(lambda p: p)
                stamp_now = staticmethod(lambda: "prova")

            k = d / "traccia.kml"
            k.write_text('<?xml version="1.0"?><kml xmlns="http://www.opengis.net/kml/2.2"><Placemark><name>A</name><LineString><coordinates>12,41 13,42</coordinates></LineString></Placemark></kml>', encoding="utf-8")
            liv = fmp.importa_kml(caso, str(k))
            cattivo = d / "c.kml"
            cattivo.write_text('<!DOCTYPE x [<!ENTITY a "b">]><kml/>', encoding="utf-8")
            rif = False
            try:
                fmp.importa_kml(caso, str(cattivo))
            except ValueError:
                rif = True
            e1 = fmp.esporta(G, caso, {"formato": "kml", "categorie": list(nomi)})
            e2 = fmp.esporta(G, caso, {"formato": "gpx", "categorie": ["Viaggi (Origin)"], "da": "2024-02-01"})
            az = {v[0] for v in caso.voci}
            kml = (d / "export/mappa/punti_prova.kml").read_text(encoding="utf-8")
            gpx = (d / "export/mappa/punti_prova.gpx").read_text(encoding="utf-8")
            check(tr("Mappa: KML importato come livello separato, DOCTYPE rifiutato, esportazione KML e GPX nel registro"),
                  liv["kml"][0]["elementi"] == 1 and rif and {"mappa_kml", "mappa_esporta"} <= az and kml.count("<Placemark>") == 3
                  and gpx.count("<wpt ") == 1 and len(fmp.punti(caso)["punti"]) == 3, f"{e1['message'][:24]} {e2['message'][:24]}", interno=True)
            pt = fmp.punti(caso)["punti"]
            fmp.preferito(caso, {"k": fmp.chiave(pt[0]), "on": True})
            fmp.preferito(caso, {"k": fmp.chiave(pt[1]), "on": True})
            pr = fmp.preferito(caso, {"k": fmp.chiave(pt[1]), "on": False})["preferiti"]
            G.stamp_now = staticmethod(lambda: "preferiti")        # le esportazioni sono in sola lettura: un nome nuovo
            fmp.esporta(G, caso, {"formato": "kml", "categorie": list(nomi), "solo_preferiti": True})
            falso = False
            try:
                fmp.preferito(caso, {"k": "a|999|1|2|", "on": True})
            except ValueError:
                falso = True
            kml = (d / "export/mappa/punti_preferiti.kml").read_text(encoding="utf-8")
            check(tr("Mappa: punti preferiti salvati nel caso e nel registro, esportazione dei soli preferiti, punto inesistente rifiutato"),
                  pr == [fmp.chiave(pt[0])] and fmp.punti(caso)["preferiti"] == pr and kml.count("<Placemark>") == 1 and falso
                  and sum(1 for v in caso.voci if v[0] == "mappa_preferito") == 3, str(pr)[:60], interno=True)
        finally:
            fa.db_ro = vecchia


def controlli_mappa_font(check):
    """(3.0) Scritte delle mappe: font nel programma, percorso locale, nessun indirizzo esterno nello stile."""
    d = Path(__file__).resolve().parent
    n = [len(list((d / "mappa" / "fonts" / f"Noto Sans {x}").glob("*-*.pbf"))) for x in ("Regular", "Medium", "Italic")]
    h = (d / "forense_gui.html").read_text(encoding="utf-8")
    check(tr("Mappa: font delle scritte inclusi, con licenza, e letti in locale"),
          n == [256, 256, 256] and (d / "mappa" / "fonts" / "OFL.txt").is_file() and 'glyphs: "/mappa/fonts/{fontstack}/{range}.pbf"' in h, str(n), interno=True)


def controlli_mappe_rete(check):
    """(3.0) Estrazione da un archivio PMTiles costruito, servito in locale; blocco della rete con un caso aperto."""
    import gzip
    import http.server
    import struct
    import threading
    import forense_gui as G
    import forense_mappe_scarica as fms

    ids_ok = [fms.zxy_id(0, 0, 0), fms.zxy_id(1, 0, 0), fms.zxy_id(1, 0, 1), fms.zxy_id(1, 1, 1), fms.zxy_id(1, 1, 0)] == [0, 1, 2, 3, 4]
    tess = {fms.zxy_id(2, x, y): bytes([x, y]) * 50 for x in range(4) for y in range(4)}
    tess[0] = b"zero"
    corpo, voci = b"", []
    for t in sorted(tess):
        voci.append((t, 1, len(corpo), len(tess[t])))
        corpo += tess[t]
    rad = fms._dir_scrivi(voci)
    meta = gzip.compress(b"{}", mtime=0)
    fonte = (b"PMTiles\x03" + struct.pack("<QQQQQQQQQQQ", 127, len(rad), 127 + len(rad), len(meta), 0, 0, 127 + len(rad) + len(meta), len(corpo), len(voci), len(voci), len(voci))
             + bytes([1, 2, 2, 1, 0, 2]) + struct.pack("<iiii", 0, 0, 0, 0) + bytes([0]) + struct.pack("<ii", 0, 0) + rad + meta + corpo)
    guasto = [False]

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            a, b = self.headers["Range"].split("=")[1].split("-")
            a, b = int(a), min(int(b), len(fonte) - 1)
            if guasto[0] and a >= 127 + len(rad) + len(meta):
                self.send_error(500)
                return
            self.send_response(206)
            self.send_header("Content-Length", str(b - a + 1))
            self.end_headers()
            self.wfile.write(fonte[a:b + 1])

        def log_message(self, *_a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    vecchia = fms.BASE
    fms.BASE = f"http://127.0.0.1:{srv.server_port}/"
    with tempfile.TemporaryDirectory() as d:
        dest = Path(d) / "m.pmtiles"
        try:
            info = fms.scarica("Prova", [[-170, 1, -1, 80]], 2, "x", dest, lambda _p: None)     # quadrante nord-ovest
            b = dest.read_bytes()
            ro, rl = struct.unpack("<QQ", b[8:24])
            do = struct.unpack("<Q", b[56:64])[0]
            lette = {}
            for t, r, o, ln in fms._dir_leggi(gzip.decompress(b[ro:ro + rl])):
                for k in range(r):
                    lette[t + k] = b[do + o:do + o + ln]
            attese = {t: tess[t] for t in fms.tessere([[-170, 1, -1, 80]], 2) if t in tess}
            guasto[0] = True
            dest2 = Path(d) / "n.pmtiles"
            caduta = False
            attese_get = fms._get
            fms._get = lambda u, i=None, f=None, tentativi=1, esatto=True: attese_get(u, i, f, 1, esatto)
            try:
                fms.scarica("Prova", [[-170, 1, -1, 80]], 2, "x", dest2, lambda _p: None)
            except OSError:
                caduta = True
            finally:
                fms._get = attese_get
            nessuno = not dest2.exists() and not Path(str(dest2) + ".parziale").exists()
        finally:
            fms.BASE = vecchia
            srv.shutdown()
    check(tr("Mappe: estrazione uguale alla sorgente, numeri Hilbert corretti, nessun file a metà se la rete cade"),
          ids_ok and lette == attese and len(attese) >= 3 and caduta and nessuno and bool(info["sha256"]), f"{len(lette)}/{len(attese)}", interno=True)
    caso, prep = G.SES.case, G.PREP.running
    try:
        G.SES.case = object()
        a = False
        try:
            G.senza_caso()
        except ValueError:
            a = True
        G.SES.case = None
        G.senza_caso()
        passa = True
    finally:
        G.SES.case = caso
    check(tr("Rete: con un caso aperto o in preparazione mappe e modelli non si scaricano"), a and passa, f"{a} {passa}", interno=True)


def controlli_aggiornamenti(check):
    """(3.0.1) Avviso di nuove versioni con un finto GitHub locale: versione nuova (anche di sicurezza), uguale, in prova,
    bozza, risposta guasta o troppo grande, rete assente; collegamenti solo verso github.com; scelta «mai»; nessuna
    richiesta con un caso aperto. Le impostazioni vanno in un file temporaneo, mai in quelle dell'analista."""
    import http.server
    import threading
    import forense_aggiornamenti as fag
    import forense_gui as G

    risposte, richieste = {}, []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            richieste.append(self.path)
            corpo = risposte.get("corpo", b"")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(corpo)))
            self.end_headers()
            self.wfile.write(corpo)

        def log_message(self, *_a):
            pass

    def rel(tag, **x):
        return json.dumps({"tag_name": tag, "draft": False, "prerelease": False, "published_at": "2026-12-01T10:00:00Z",
                           "html_url": f"https://github.com/{fag.REPO}/releases/tag/{tag}", "body": "Novità", **x}).encode()

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url0, env0, imp0 = fag.URL, os.environ.get("REPERTIA_AGGIORNAMENTI_URL"), fa.SETTINGS_PATH
    caso, tmp = G.SES.case, Path(tempfile.mkdtemp())
    fag.URL = os.environ["REPERTIA_AGGIORNAMENTI_URL"] = f"http://127.0.0.1:{srv.server_port}/latest"
    fa.SETTINGS_PATH = tmp / "impostazioni.json"
    G.SES.case = None
    esiti = {}
    try:
        cur = fag.versione(fa.APP_VERSION)
        piu = "v%d.%d.%d" % (cur[0], cur[1], cur[2] + 1)
        prove = {"nuova": rel(piu, body="[sicurezza] corregge <script>x</script>", html_url="https://evil.example/x",
                              assets=[{"name": "SHA256SUMS.txt", "browser_download_url": "http://127.0.0.1:9/s"}]),
                 "uguale": rel("v" + fa.APP_VERSION), "vecchia": rel("v1.0.0"), "prova": rel(piu, prerelease=True),
                 "bozza": rel(piu, draft=True), "guasta": b"{non json", "tag": rel("ultima"),
                 "grande": b"{" + b" " * (fag.MAX_JSON + 10) + b"}"}
        for k, corpo in prove.items():
            risposte["corpo"] = corpo
            esiti[k] = fag.controlla(fa.APP_VERSION)
        n = esiti["nuova"]
        ok_nuova = (n["esito"] == "nuova" and n["sicurezza"] and n["url"] == fag.PAGINA and "sha256" not in n
                    and n["note"].startswith("[sicurezza]"))
        ok_altre = (esiti["uguale"]["esito"] == esiti["vecchia"]["esito"] == "aggiornato"
                    and all(esiti[k]["esito"] == "errore" for k in ("prova", "bozza", "guasta", "tag", "grande")))
        check(tr("Aggiornamenti: versione nuova riconosciuta (anche di sicurezza), uguale o vecchia no, scartate prove, bozze e "
                 "risposte guaste; collegamenti solo verso github.com"), ok_nuova and ok_altre,
              ", ".join(f"{k}={v['esito']}" for k, v in esiti.items()), interno=True)
        adesso = dt.datetime.now(dt.timezone.utc)
        ieri = (adesso - dt.timedelta(hours=25)).isoformat()
        ora = (adesso - dt.timedelta(hours=1)).isoformat()
        tempi = (not fag.da_controllare_all_avvio({"modo": "mano"}) and fag.da_controllare_all_avvio({"modo": "avvio"})
                 and fag.da_controllare_all_avvio({"modo": "avvio", "ultimo": {"controllato_il": ieri}})
                 and not fag.da_controllare_all_avvio({"modo": "avvio", "ultimo": {"controllato_il": ora}})
                 and fag.da_mostrare({"modo": "mano", "ultimo": n})
                 and not fag.da_mostrare({"modo": "mano", "ultimo": n, "saltata": n["versione"]})
                 and not fag.da_mostrare({"modo": "mai", "ultimo": n})
                 and not fag.da_mostrare({"modo": "mano", "ultimo": n, "rimanda_fino": (adesso + dt.timedelta(hours=3)).isoformat()}))
        check(tr("Aggiornamenti: controllo automatico al massimo una volta al giorno; avviso nascosto se saltato, rimandato o con «Mai»"),
              tempi, str(tempi), interno=True)
        # (dopo la 3.0.2) dopo l'aggiornamento: l'esito salvato «c'è la versione X» con X ormai installata non fa più comparire l'avviso
        vecchio = {**n, "versione": fa.APP_VERSION, "attuale": "1.0.0", "pacchetto": "x", "sha256": "0" * 64}
        dopo = fag.stato({"aggiornamenti": {"modo": "mano", "ultimo": vecchio}}, fa.APP_VERSION)
        ancora = fag.stato({"aggiornamenti": {"modo": "mano", "ultimo": n}}, fa.APP_VERSION)
        ok_dopo = (not fag.da_mostrare(dopo) and dopo["ultimo"]["esito"] == "aggiornato" and dopo["ultimo"]["attuale"] == fa.APP_VERSION
                   and "sha256" not in dopo["ultimo"] and fag.da_mostrare(ancora) and ancora["ultimo"]["esito"] == "nuova"
                   and fag.da_controllare_all_avvio({"modo": "avvio", "ultimo": {"controllato_il": ora, "attuale": "1.0.0"}},
                                                    versione_app=fa.APP_VERSION)
                   and not fag.da_controllare_all_avvio({"modo": "avvio", "ultimo": {"controllato_il": ora, "attuale": fa.APP_VERSION}},
                                                        versione_app=fa.APP_VERSION))
        check(tr("Aggiornamenti: dopo l'aggiornamento l'avviso della versione ormai installata non compare più"), ok_dopo,
              str(dopo["ultimo"].get("esito")), interno=True)
        risposte["corpo"] = prove["nuova"]
        G.aggiornamenti_post({"azione": "modo", "modo": "avvio"})
        st1 = G.aggiornamenti_post({"azione": "controlla", "auto": True})
        prima = len(richieste)
        st2 = G.aggiornamenti_post({"azione": "controlla", "auto": True})          # stesso giorno: nessuna richiesta
        G.aggiornamenti_post({"azione": "modo", "modo": "mai"})
        mai = False
        try:
            G.aggiornamenti_post({"azione": "controlla"})
        except ValueError:
            mai = True
        G.aggiornamenti_post({"azione": "modo", "modo": "mano"})
        G.SES.case = object()
        bloccato = False
        try:
            G.aggiornamenti_post({"azione": "controlla"})
        except ValueError:
            bloccato = True
        G.SES.case = None
        salvate = json.loads(fa.SETTINGS_PATH.read_text()).get("aggiornamenti", {})
        ok_srv = (st1["mostra"] and st1["ultimo"]["esito"] == "nuova" and len(richieste) == prima and st2["mostra"]
                  and mai and bloccato and len(richieste) == prima and salvate.get("modo") == "mano")
        check(tr("Aggiornamenti: scelta salvata, nessuna richiesta con «Mai» o con un caso aperto"), ok_srv,
              tr("{n} richieste, «Mai» rifiutato: {m}, caso aperto rifiutato: {c}").format(n=len(richieste), m=mai, c=bloccato), interno=True)
        srv.shutdown()
        e = fag.controlla(fa.APP_VERSION)
        check(tr("Aggiornamenti: senza rete un messaggio, nessun errore"), e["esito"] == "errore" and bool(e.get("motivo")),
              e.get("motivo", ""), interno=True)
    finally:
        fag.URL, fa.SETTINGS_PATH, G.SES.case = url0, imp0, caso
        if env0 is None:
            os.environ.pop("REPERTIA_AGGIORNAMENTI_URL", None)
        else:
            os.environ["REPERTIA_AGGIORNAMENTI_URL"] = env0
        shutil.rmtree(tmp, ignore_errors=True)


def controlli_droni(check):
    """(3.0) Lettori dei voli su testi costruiti: valori veri, file estranei ignorati, ordine incerto segnalato."""
    import forense_droni as fdr
    srt = ("1\n00:00:00,000 --> 00:00:00,033\n2024-05-01 12:00:00.100\n[latitude: 41.890210] [longitude: 12.492310] [rel_alt: 10.0 abs_alt: 60.5]\n\n"
           "2\n00:00:00,033 --> 00:00:00,066\n2024-05-01 12:00:01.100\n[latitude: 41.890310] [longitude: 12.492410] [rel_alt: 11.0 abs_alt: 61.5]\n")
    a = fdr.leggi_srt(srt)
    b = fdr.leggi_srt("1\n00:00:00,000 --> 00:00:01,000\nGPS(41.89,12.49,60)\n")
    incerto = fdr.INCERTI[0]
    c1, f1 = fdr.leggi_csv("latitude,longitude,altitude(m),datetime(utc)\n45.4642,9.19,120,2024-06-01 10:00:00\n0,0,1,x\n")
    c2, f2 = fdr.leggi_csv("datetime(utc),latitude,longitude,altitude(feet),height_above_takeoff(feet)\n2024-06-01 10:00:00,45.4,9.1,100,10\n")
    no, _f = fdr.leggi_csv("nome,citta\nanna,roma\n")
    v = fdr._volo("x", "p", "srt", "RepertIA", a)
    check(tr("Droni: SRT e CSV letti con i valori giusti, CSV estranei ignorati, DJI tramite ALEAPP se presente"),
          a == [[12.49231, 41.89021, 60.5, "2024-05-01 12:00:00"], [12.49241, 41.89031, 61.5, "2024-05-01 12:00:01"]]
          and b == [[12.49, 41.89, 60.0, ""]] and incerto and c1 == [[9.19, 45.4642, 120.0, "2024-06-01 10:00:00"]]
          and f1 == "csv" and f2 == "csv_airdata" and c2[0][2] == 30.48 and no is None and v["lunghezza_m"] == 14 and v["quota_max"] == 61.5,
          f"{a[:1]} {c1[:1]}"[:90], interno=True)
    # (3.0) registri binari costruiti secondo i formati pubblici: valori veri, tipo di record ignoto, versione ignota, file estranei
    testa = b"SN1".ljust(18, b"\0") + b"BAT".ljust(32, b"\0") + b"Roma".ljust(64, b"\0") + bytes([3]) + struct.pack("<fIfI", 1000.0, 60, 50.0, 0) + struct.pack("<Qi", 1700000000000, 60) + struct.pack("<ffHHH", 41.5, 12.5, 0, 0, 2) + b"f\0"
    rec = b"".join(bytes([0]) + struct.pack("<Ifff", 1000 * i, 41.5 + i / 1000, 12.5, 10.0).ljust(268, b"\0") for i in range(3))
    au = fdr.leggi_binario("autel_x", b"AUTEL_FR" + struct.pack("<IH", 3, len(testa)) + testa + rec)
    au_rotto = fdr.leggi_autel(b"AUTEL_FR" + struct.pack("<IH", 3, len(testa)) + testa + rec + b"\x63")
    au_ign = fdr.leggi_binario("autel_y", b"AUTEL_FR" + struct.pack("<IH", 9, 0) + bytes(200))

    def mav1(msg, pay, extra):
        c = bytes([len(pay), 0, 1, 1, msg]) + pay
        return struct.pack(">Q", 1700000000000000) + b"\xfe" + c + struct.pack("<H", fdr._x25(c, extra))
    gpi = struct.pack("<Iiiii", 0, 419000000, 125000000, 50000, 0).ljust(28, b"\0")
    tl = fdr.leggi_binario("a.tlog", mav1(33, gpi, 104) + mav1(33, gpi, 1))     # il secondo ha il CRC sbagliato
    fmt = b"\xa3\x95\x80\x80\x59FMT\0BBnNZ".ljust(25, b"\0") + b"Type,Length,Name,Format,Columns".ljust(64, b"\0")
    fg = b"\xa3\x95\x80\x82\x1aGPS\0BLLe".ljust(25, b"\0") + b"Status,Lat,Lng,Alt".ljust(64, b"\0")
    df = fdr.leggi_binario("1.BIN", fmt + fg + b"\xa3\x95\x82" + bytes([3]) + struct.pack("<iii", 419000000, 125000000, 5000) + bytes(10))
    ul = b"ULog\x01\x12\x35\x01" + bytes(8)
    def um(t, c):
        return struct.pack("<HB", len(c), ord(t)) + c
    ul += um("F", b"vehicle_gps_position:uint64_t timestamp;uint64_t time_utc_usec;int32_t lat;int32_t lon;int32_t alt;uint8_t fix_type;") + um("A", b"\0" + struct.pack("<H", 1) + b"vehicle_gps_position")
    ul += um("D", struct.pack("<HQQiiiB", 1, 1, 1700000000000000, 419000000, 125000000, 5000, 3)) + um("D", struct.pack("<HQQiiiB", 1, 2, 0, 419000000, 125000000, 5000, 0))
    ug = fdr.leggi_binario("a.ulg", ul)
    check(tr("Droni: registri Autel, ULog, tlog e DataFlash letti con i valori giusti; CRC errato, assenza di fix e versione ignota non danno punti"),
          [au["punti"][0][:3], len(au["punti"]), au["punti"][0][3], au["riepilogo"]["Location"]] == [[12.5, 41.5, 10.0], 3, "2023-11-14 22:13:20", "Roma"]
          and au_rotto[3] and len(au_rotto[0]) == 3 and au_ign["stato"] == "versione_ignota" and not au_ign["punti"]
          and tl["punti"] == [[12.5, 41.9, 50.0, "2023-11-14 22:13:20"]] and df["punti"] == [[12.5, 41.9, 50.0, ""]]
          and ug["punti"] == [[12.5, 41.9, 5.0, "2023-11-14 22:13:20"]] and fdr.leggi_binario("x.bin", b"MZ" + bytes(99)) is None,
          f"{au['punti'][:1]} {tl['punti']} {df['punti']} {ug['punti']}"[:120], interno=True)


def controlli_sorgente_logica(check):
    """(3.0.2) Sorgente logica: zip, tar.gz, 7z, RAR 4, RAR 5 e AD1 preparati come casi; contenuto, date (UTC) e loro
    fonte uguali a quelli noti; hash registrati nell'AD1 verificati; GPX come livelli della mappa; chat WhatsApp lette da
    una consegna con e senza la struttura del telefono; 7z, rar e AD1 rifiutati come estrazioni di telefoni."""
    import base64
    import contextlib
    import io
    import tarfile
    import types
    import forense_estesa as fx
    import forense_mobile as fm
    import forense_mobile_gui as fmg
    tmp = Path(tempfile.mkdtemp(prefix="collaudo_logica_"))

    def prepara(img, no_hash=True, logica=True, chat=False):
        a = types.SimpleNamespace(case=str(tmp / "casi" / img.name), image=str(img), no_hash=no_hash, no_indice=True,
                                  hash_file=False, chat=chat, leapp=False, drone=False, logica=logica,
                                  decomprimi=img.name.endswith(".tar.gz"), info=None, lingua=None, fuso="Europe/Rome",
                                  keychain=None, sysdiagnose=None, wa_backup=False, trascrizione=None)
        with contextlib.redirect_stdout(io.StringIO()):
            fm.cmd_prepara(a)
        case = fa.Case(a.case)
        m = fm.mx(case)
        rows = {r[0]: r[1:] for r in m.execute("SELECT path, id, mtime, datesrc FROM mobile_files WHERE isdir=0")}
        m.close()
        return case, rows

    def leggi(case, rows, path):
        r = rows.get(path)
        return (b"".join(fm.stream(case, fm.part_key(0), r[0])), r[1], r[2]) if r else (None, None, None)

    try:
        src = tmp / "src" / "docs"
        (src / "sotto").mkdir(parents=True)
        (src / "contratto.txt").write_bytes(b"contratto Rossi 2024\n")
        (src / "sotto" / "nota.txt").write_bytes(b"nota segreta\n")
        for p in (src / "contratto.txt", src / "sotto" / "nota.txt"):
            os.utime(p, (1704205800, 1704205800))                      # 2024-01-02 14:30:00 UTC
        arch = {}
        z = arch["zip"] = tmp / "prova.zip"
        with zipfile.ZipFile(z, "w") as zf:                             # solo data DOS: ora locale (15:30 a Roma)
            for rel in ("docs/contratto.txt", "docs/sotto/nota.txt"):
                zf.writestr(zipfile.ZipInfo(rel, (2024, 1, 2, 15, 30, 0)), (tmp / "src" / rel).read_bytes())
            zf.writestr("posizioni/giro.gpx", GPX_PROVA)
        with tarfile.open(tmp / "prova.tar.gz", "w:gz") as tf:
            tf.add(src, arcname="docs")
        arch["tar.gz"] = tmp / "prova.tar.gz"
        exe = fx.seven_zip()
        if exe:
            subprocess.run([exe, "a", "-bso0", "-bsp0", str(tmp / "prova.7z"), str(src)], capture_output=True, timeout=120,
                           stdin=subprocess.DEVNULL)
            arch["7z"] = tmp / "prova.7z"
        esiti, attesi, lv = [], [], None
        for fmt, f in arch.items():
            case, rows = prepara(f)
            if fmt == "zip":
                import forense_mappe as fmp
                lv = [(k.get("nome"), k.get("elementi"), k.get("dalla_sorgente"), k.get("percorso")) for k in fmp.livelli(case)["kml"]]
            esiti.append((fmt, leggi(case, rows, "docs/contratto.txt"), leggi(case, rows, "docs/sotto/nota.txt")[0]))
            attesi.append((fmt, (b"contratto Rossi 2024\n", "2024-01-02T14:30:00",
                                 {"zip": "dos", "tar.gz": "utc", "7z": "archivio"}[fmt]), b"nota segreta\n"))
        check(tr("Sorgente logica: zip, tar.gz e 7z con lo stesso contenuto e la stessa data UTC (zip DOS convertito col fuso)"),
              bool(exe) and esiti == attesi, str(esiti if esiti != attesi else len(esiti))[:160] if exe else tr("7-Zip non trovato"),
              interno=True)
        import forense_mappe as fmp
        import forense_mobile_chat as fmc
        g = fmp._gpx(GPX_PROVA.encode())
        try:
            fmp._gpx(b'<!DOCTYPE x [<!ENTITY a "b">]><gpx/>')
            dtd = False
        except ValueError:
            dtd = True
        geo = [(f["geometry"]["type"], f["geometry"]["coordinates"]) for f in g["features"]]
        check(tr("Sorgente logica: KML/GPX contenuti diventano livelli della mappa (punti e tracce giusti, DOCTYPE rifiutato)"),
              lv == [("giro.gpx", 2, True, "posizioni/giro.gpx")] and dtd and
              geo == [("Point", [12.4964, 41.9028]), ("LineString", [[12.49, 41.9], [12.5, 41.91], [12.51, 41.92]])],
              f"{lv} {geo}"[:160], interno=True)
        import sqlite3
        mm = sqlite3.connect(":memory:")
        fm.ensure_schema(mm)
        for i, pth in enumerate(("consegna/WhatsApp/msgstore.db", "consegna/WhatsApp/wa.db", "iphone/sms.db", "note/appunti.db"), 1):
            mm.execute(fm.INSERT_MF, (i, 7, pth, 0, 1, 0, None, None, None, None, "utc", "zip", 0, 1, 0, None))
        sì, no = fmc.trova_db(mm, 7, logica=True)[0], fmc.trova_db(mm, 7)[0]
        check(tr("Sorgente logica: database di telefoni riconosciuti dal nome anche fuori dalla struttura del telefono"),
              sorted(sì) == ["imessage", "wa_contacts_android", "whatsapp_android"] and not no, f"{sorted(sì)} {sorted(no)}",
              interno=True)
        # chat lette davvero da una consegna senza la struttura del telefono (e, a confronto, con la struttura)
        wadb = tmp / "wadb"
        wadb.mkdir()
        db = sqlite3.connect(str(wadb / "msgstore.db"))
        db.executescript("""
            CREATE TABLE jid(_id INTEGER PRIMARY KEY, user TEXT, server TEXT, raw_string TEXT);
            CREATE TABLE chat(_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT);
            CREATE TABLE message(_id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER, key_id TEXT,
                sender_jid_row_id INTEGER, status INTEGER, timestamp INTEGER, received_timestamp INTEGER,
                message_type INTEGER, text_data TEXT, starred INTEGER);
            INSERT INTO jid VALUES (1, '390000000009', 's.whatsapp.net', '390000000009@s.whatsapp.net');
            INSERT INTO chat VALUES (1, 1, NULL);
            INSERT INTO message VALUES (1, 1, 0, 'L1', NULL, 0, 1704205800000, 1704205801000, 0, 'ciao dalla consegna', 0);
            INSERT INTO message VALUES (2, 1, 1, 'L2', NULL, 13, 1704205860000, 1704205861000, 0, 'ricevuto', 0);""")
        db.commit()
        db.close()
        db = sqlite3.connect(str(wadb / "wa.db"))
        db.executescript("""CREATE TABLE wa_contacts(_id INTEGER PRIMARY KEY, jid TEXT, display_name TEXT, wa_name TEXT, number TEXT);
            INSERT INTO wa_contacts VALUES (1, '390000000009@s.whatsapp.net', 'Anna Verdi', 'Anna', '+39 000 000 0009');""")
        db.commit()
        db.close()
        chat_esiti = []
        for nome, cart in (("consegna_wa.zip", "consegna/WhatsApp_Database"),
                           ("struttura_wa.zip", "data/data/com.whatsapp/databases")):
            with zipfile.ZipFile(tmp / nome, "w") as zf:
                for f in ("msgstore.db", "wa.db"):
                    zf.write(wadb / f, f"{cart}/{f}")
            cw, _rw = prepara(tmp / nome, chat=True)
            tel = cw.meta.get("logica_telefono") or {}
            cc = sqlite3.connect(str(cw.root / "caso.sqlite"))
            try:
                thr = cc.execute("SELECT app, title, n_msg, src_path FROM chat_threads").fetchall()
                txt = [r[0] for r in cc.execute("SELECT text FROM chat_messages ORDER BY ts")]
            finally:
                cc.close()
            chat_esiti.append((tel.get("piattaforma"), sorted(tel.get("database") or {}), tel.get("struttura_telefono"),
                               thr, txt))
        att = [("android", ["wa_contacts_android", "whatsapp_android"], s,
                [("whatsapp", "Anna Verdi", 2, f"{c}/msgstore.db")], ["ciao dalla consegna", "ricevuto"])
               for s, c in ((False, "consegna/WhatsApp_Database"), (True, "data/data/com.whatsapp/databases"))]
        check(tr("Sorgente logica: chat WhatsApp e rubrica lette da una consegna anche senza la struttura del telefono "
                 "(piattaforma riconosciuta, struttura dichiarata)"), chat_esiti == att, str(chat_esiti)[:160], interno=True)
        (tmp / "r4.rar").write_bytes(base64.b64decode("".join(LOGICA_RAR4)))
        (tmp / "r5.rar").write_bytes(base64.b64decode("".join(LOGICA_RAR5)))
        c4, r4 = prepara(tmp / "r4.rar")
        c5, r5 = prepara(tmp / "r5.rar")
        a4, a5 = leggi(c4, r4, "testdir/test.txt"), leggi(c5, r5, "helloworld.txt")
        check(tr("Sorgente logica: RAR 4 (date in ora locale, convertite e dichiarate) e RAR 5 (UTC) letti con contenuto e date giusti"),
              a4 == (b"test text document\r\n", "2011-06-26T12:59:07", "locale") and
              a5 == (b"hello libarchive test suite!\n", "2018-09-26T04:43:42", "archivio"), f"{a4} {a5}"[:160], interno=True)
        (tmp / "prova.ad1").write_bytes(base64.b64decode("".join(LOGICA_AD1)))
        try:
            import dissect.evidence.ad1  # noqa: F401
            ok_ad1 = True
        except ImportError:
            ok_ad1 = False
        if ok_ad1:
            ca, ra = prepara(tmp / "prova.ad1", no_hash=False)
            v = ca.meta.get("verifica_ad1") or {}
            d1 = leggi(ca, ra, "E:/AD1_test/doc1.txt")
            got = (d1, len(ra), v.get("controllati"), v.get("uguali"), len(v.get("diversi") or []))
            check(tr("Sorgente logica: AD1 letto (contenuto e data registrata) e hash MD5/SHA-1 di FTK verificati su tutti i file"),
                  got == ((b"Inhoud document 1", "2017-03-31T18:02:49", "ad1"), 2, 2, 2, 0), str(got)[:160], interno=True)
        else:
            check(tr("Sorgente logica: AD1 letto (contenuto e data registrata) e hash MD5/SHA-1 di FTK verificati su tutti i file"),
                  False, tr("componente dissect.evidence non incluso"), interno=True)
        import lzma
        cd = []
        for nome, dati in (("cd_udf.iso", LOGICA_UDF), ("cd_iso.iso", LOGICA_ISO)):
            (tmp / nome).write_bytes(lzma.decompress(base64.b64decode("".join(dati))))
            if exe:
                cc, rc = prepara(tmp / nome)
                cd.append((fm.cd_dvd(tmp / nome), leggi(cc, rc, "prezzi.txt"), leggi(cc, rc, "cartella/nota.txt")[0]))
        check(tr("Sorgente logica: immagini di CD/DVD in UDF (non letto da Sleuth Kit) e ISO 9660 estratte con 7-Zip, "
                 "con contenuto e date UTC giusti"),
              bool(exe) and cd == [(t, (b"prezzi\n", "2024-03-15T09:30:00", "disco"), b"progetto segreto\n") for t in ("udf", "iso9660")],
              str(cd)[:160] if exe else tr("7-Zip non trovato"), interno=True)
        rif = []
        for f in [tmp / "r5.rar", tmp / "prova.ad1", tmp / "cd_udf.iso"] + ([arch["7z"]] if "7z" in arch else []):
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    fm.cmd_prepara(types.SimpleNamespace(case=str(tmp / "tel" / f.name), image=str(f), logica=False,
                                                         lingua=None))
                rif.append(False)
            except SystemExit:
                rif.append(not fmg.check(str(f))["ok"] and fmg.check(str(f), logica=True)["ok"])
        check(tr("Sorgente logica: 7z, rar, AD1 e immagini di CD/DVD rifiutati come estrazioni di telefoni, accettati come sorgente logica"),
              rif and all(rif), str(rif), interno=True)
    except Exception as e:
        check(tr("Sorgente logica: preparazione dei casi di prova"), False, f"{type(e).__name__}: {e}"[:160], interno=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def controlli_nist_lacune(check):
    """(3.0.2) Lacune emerse dal caso NIST CFReDS «Data Leakage»: eventi di Windows 4608/1100/4634/4647/20001/20003/133
    (XML sintetici passati al lettore, provider controllato, uscite di rete scartate) e Google Drive per Windows
    (sync_config.db, snapshot.db anche con un record cancellato, sync_log.log in ora locale), costruiti sul modello delle
    risposte NIST."""
    import sqlite3
    import types
    import forense_estesa as fx
    tmp = Path(tempfile.mkdtemp(prefix="collaudo_nist_"))
    salva = {k: getattr(fx, k) for k in ("hive_rows", "fetch", "evtx_records", "find_files", "fetch_sqlite")}

    class A0:
        def __init__(self):
            self.v = []

        def add(self, cat, ts, title, detail="", user="", src=None, data=None):
            self.v.append((cat, ts, title, detail, data or {}))
    try:
        sec = "Microsoft-Windows-Security-Auditing"

        def ev(eid, prov, campi, ft):
            return (eid, ft, prov, "<Event><EventData>" + "".join(
                f'<Data Name="{k}">{v}</Data>' if k else f"<Data>{v}</Data>" for k, v in campi) + "</EventData></Event>", False)
        ft0 = 130715000000000000                          # FILETIME 2015-03-23
        eventi = {"security.evtx": [ev(4608, sec, [], ft0), ev(1100, "Microsoft-Windows-Eventlog", [], ft0 + 1),
                                    ev(4634, sec, [("TargetUserName", "informant"), ("LogonType", "2"), ("TargetLogonId", "0x1")], ft0 + 2),
                                    ev(4634, sec, [("TargetUserName", "informant"), ("LogonType", "3")], ft0 + 3),
                                    ev(4647, sec, [("TargetUserName", "informant"), ("TargetLogonId", "0x1")], ft0 + 4),
                                    ev(4608, "AltroProvider", [], ft0 + 5)],
                  "system.evtx": [ev(20001, "Microsoft-Windows-UserPnp", [("DeviceInstanceID", "USBSTOR\\DISK&VEN_SANDISK"),
                                                                           ("DriverName", "disk.inf")], ft0 + 6),
                                  ev(20003, "Microsoft-Windows-UserPnp", [("DeviceInstanceID", "USBSTOR\\DISK&VEN_SANDISK"),
                                                                           ("ServiceName", "disk")], ft0 + 7),
                                  ev(133, "cdrom", [(None, "\\Device\\CdRom0")], ft0 + 8)]}
        fx.hive_rows = lambda ctx, part, like: ([(0, 1, 0, like)] if like.split("/")[-1] in eventi else [])
        fx.fetch = lambda ctx, part, inode, path, limit=0: path
        fx.evtx_records = lambda f, ids, raw=False, stats=None: [e for e in eventi.get(str(f).split("/")[-1], []) if e[0] in ids]
        A = A0()
        fx.win_eventi(A, types.SimpleNamespace(), 0)
        got = sorted((d.get("evento"), c) for c, _t, _ti, _de, d in A.v if d.get("evento"))
        uscite = [ti for c, _t, ti, _de, d in A.v if d.get("evento") in (4634, 4647)]
        check(tr("Eventi di Windows: avvio e chiusura (4608, 1100), uscite (4634 solo interattive, 4647), driver installati "
                 "(20001, 20003) e masterizzazione (133), con il provider controllato"),
              got == [(133, "dispositivi"), (1100, "eventi"), (4608, "eventi"), (4634, "eventi"), (4647, "eventi"),
                      (20001, "usb"), (20003, "usb")] and uscite == [tr("Uscita: {v1}").format(v1="informant")] * 2,
              f"{got} {uscite}"[:160], interno=True)
        for k, v in salva.items():
            setattr(fx, k, v)
        # Google Drive: file costruiti sul modello delle risposte NIST (domande 30, 31 e 49)
        gd = tmp / "Users/informant/AppData/Local/Google/Drive/user_default"
        gd.mkdir(parents=True)
        db = sqlite3.connect(str(gd / "sync_config.db"))
        db.executescript("""CREATE TABLE data(entry_key TEXT, data_key TEXT, data_value TEXT);
            INSERT INTO data VALUES ('user_email', 'value', 'iaman.informant.personal@gmail.com'),
                                    ('local_sync_root_path', 'value', '\\\\?\\C:\\Users\\informant\\Google Drive'),
                                    ('tango_storage', 'value', 'gettone-che-non-deve-entrare-nel-caso');""")
        db.commit()
        db.close()
        db = sqlite3.connect(str(gd / "snapshot.db"))
        db.executescript("""PRAGMA secure_delete = 0; PRAGMA auto_vacuum = 0;
            CREATE TABLE cloud_entry(doc_id TEXT, filename TEXT, modified INTEGER, created INTEGER, acl_role INTEGER,
                doc_type INTEGER, removed INTEGER, size INTEGER, checksum TEXT, shared INTEGER, resource_type TEXT, PRIMARY KEY (doc_id));
            INSERT INTO cloud_entry VALUES ('0Bz0ye6gXtiZaTEST0000000001', 'happy_holiday.jpg', 1422636560, 1427142765, 0, 1, 0, 440517,
                                            'aabbccddeeff00112233445566778899', 0, 'file');
            INSERT INTO cloud_entry VALUES ('0Bz0ye6gXtiZaVl8yVU5mWHlGbWc', 'do_u_wanna_build_a_snow_man.mp3', 1422636560, 1427142765, 0, 1, 0,
                                            6844294, '00112233445566778899aabbccddeeff', 0, 'file');""")
        db.commit()
        db.execute("DELETE FROM cloud_entry WHERE doc_id = '0Bz0ye6gXtiZaVl8yVU5mWHlGbWc'")
        db.commit()
        db.close()
        (gd / "sync_log.log").write_text(
            "2015-03-23 16:05:32,279 -0400 INFO pid=2576 2828:LaunchThreads common.service.user:64 Initializing User instance "
            "with new credentials. iaman.informant.personal@gmail.com\n"
            "2015-03-23 16:42:17,026 -0400 INFO pid=2576 4004:LocalWatcher common.aggregator:114 --------> Received event "
            "RawEvent(DELETE, path=u'\\\\\\\\?\\\\C:\\\\Users\\\\informant\\\\Google Drive\\\\happy_holiday.jpg', time=1427143337.0, "
            "ino=4503599627374809L, parent_ino=844424930207017L, affects_gdoc=False) None\n"
            "2015-03-23 16:42:17,026 -0400 INFO pid=2576 4004:LocalWatcher common.change_buffer:1017 Adding event to change buffer: "
            "RawEvent(DELETE, path=u'\\\\\\\\?\\\\C:\\\\Users\\\\informant\\\\Google Drive\\\\happy_holiday.jpg', time=1427143337.0, "
            "ino=4503599627374809L, parent_ino=844424930207017L, affects_gdoc=False)\n",
            encoding="utf-8")
        righe = [(0, i, 0, f"Users/informant/AppData/Local/Google/Drive/user_default/{n}")
                 for i, n in enumerate(("sync_config.db", "snapshot.db", "sync_log.log"), 1)]
        fx.find_files = lambda con, part, like, deleted_ok=False: [r for r in righe if r[3].lower().endswith(like.split("/")[-1])]
        ctx = types.SimpleNamespace(con=None, tmp=tmp / "lavoro")
        ctx.tmp.mkdir()
        fx.fetch = lambda ctx, part, inode, path, limit=0: tmp / path
        import forense_agent as fag
        lk = fag.lookup
        fag.lookup = lambda con, part, path: None
        try:
            A = A0()
            fx.win_gdrive(A, ctx, 0)
        finally:
            fag.lookup = lk
        v = {(c, t, ti) for c, t, ti, _de, _d in A.v}
        att = {("cloud", None, tr("Google Drive: account {v1}").format(v1="iaman.informant.personal@gmail.com")),
               ("cloud", "2015-03-23T20:05:32", tr("Google Drive: accesso con l'account {v1}").format(v1="iaman.informant.personal@gmail.com")),
               ("cloud", "2015-03-23T20:42:17", tr("Google Drive: {v1} {v2}").format(v1=tr("file") + " " + tr("cancellato"), v2="happy_holiday.jpg")),
               ("cloud", "2015-01-30T16:49:20", tr("Google Drive (cloud): {v1}").format(v1="happy_holiday.jpg")),
               ("cloud", "2015-01-30T16:49:20", tr("Google Drive (cloud): {v1}").format(v1="do_u_wanna_build_a_snow_man.mp3")
                + tr(" (record cancellato, da verificare)"))}
        dele = [d for _c, _t, _ti, _de, d in A.v if d.get("azione") == "DELETE"]
        segreti = [1 for _c, _t, _ti, de, d in A.v if "gettone" in de + json.dumps(d)]
        check(tr("Google Drive per Windows: account, accesso e file cancellato in UTC dal registro, file del cloud anche da un "
                 "record cancellato di snapshot.db"),
              v == att and len(dele) == 1 and not segreti and dele[0].get("percorso") == "C:\\Users\\informant\\Google Drive\\happy_holiday.jpg",
              str(sorted(v ^ att, key=str))[:160], interno=True)
    except Exception as e:
        check(tr("Lacune NIST: eventi di Windows e Google Drive"), False, f"{type(e).__name__}: {e}"[:160], interno=True)
    finally:
        for k, v in salva.items():
            setattr(fx, k, v)
        shutil.rmtree(tmp, ignore_errors=True)


# (3.0.2) StickyNotes.snt del PC del caso NIST CFReDS «Data Leakage» (opera del governo degli Stati Uniti, pubblico
# dominio; SHA-256 6ccbffc4e978aafeb950ca5d87a413f96435514ca16d6be5508ed68df071b7b2), compresso con lzma
NIST_SNT = (
    "/Td6WFoAAATm1rRGAgAhARwAAAAQz1jM4A//ArpdAGgzvhyGMHdg9KSEKkAMHHYngvKRhtyIyirh/cWK+fpgy3DJNRrUYuGP2nim9xJii5vgHY"
    "6sXFLCHrj6nhy74/ZRqLP6U2SuhQyLHchbSrIfFZacPOAkdeVQyXlanQm9a0cKIBDEyEWVso6gGS/3cBTvGAH4I10sKaZjqqpyuT5kJ96t/Qkw"
    "rOWs9utlawpzd5OGS2+LJ1RqXdyMFL8e/LpLqN5wBxF9hBvmEhFXeiriPYCjxcClatcW/JexAqHf0Yn5cAMBb6jTeLB3JqJSd4Vys/187LBQgG"
    "baO0HIqEytH4T3WyFGZRimGTX7RlYPH9NAqbqJx4VIEi4pjnzqTrjg2Z/BEFlM/BcxqfvI2+BvXkaiKHbPnqWCVsEPVRnkWxs2skO3zxL7Mdta"
    "djqRRFs58XrNrXIG/OZgI2qfVHLljC1hExCQgpV1+ad/skYcLfMns23V6WkfeaIhZVBMJMuZvkC2Zss/84hUR0T8PhyCeVwCooUfIdDWv3gwbG"
    "bEnanHhhtq44tNev6Sf9X6kVkVvr8VfF29fdSzpBu9onU68oTvgH5XWXPMBpv7CAnsaqfOPSX2DYOA/KIlHf5uJmM4K+BWyMpokb16xODbCEzL"
    "2/l5WWWTRIZLgNYwYOlNzUPiAfDnzXxa6LAM2dH/bIxYYP18KBY9gETqPVdCzR6w+QvtQ416pllPKl0M4UVf+hHi86KhBbgKZ6Xq5YdDHTDdZj"
    "6rQldacdyYxNLZjTkkJn1qv0EwxdNI5TOND0e66jFM1j3XVihIyG7edZVYX6wvS2zf38/NGhgm+UU+XBWTrXhRyCBjCPu38so4SNf+XbGUz7go"
    "2clkBwgn/MqTe750oSyTuBqM6xlWV2EA4INZ2i1Upe+fO9++c5g7g8PoVuy1WFCpKouoztmFE0QePl4DI9gjpWbh5ZSAAAAAhI/PhCo0nOEAAd"
    "YFgCAAAERUxhqxxGf7AgAAAAAEWVo=")


class _EseCol:
    def __init__(self, name, tipo):
        self.name, self.type = name, tipo


class _EseRec:
    def __init__(self, valori):
        self.v = valori

    def get_value_data(self, j):
        x = self.v[j]
        return x if isinstance(x, bytes) or x is None else str(x).encode("utf-16-le")

    def get_value_data_as_string(self, j):
        return self.v[j]

    def get_value_data_as_integer(self, j):
        return self.v[j]


class _EseTab:
    """Tabella ESE costruita per il collaudo, con la stessa interfaccia di pyesedb (colonne e record)."""
    def __init__(self, name, colonne, righe):
        self.name, self._c = name, [_EseCol(n, t) for n, t in colonne]
        self.number_of_columns, self.number_of_records = len(colonne), len(righe)
        self._r = [_EseRec([r.get(n) for n, _t in colonne]) for r in righe]

    def get_column(self, j):
        return self._c[j]

    def get_record(self, i):
        return self._r[i]


class _EseDb:
    def __init__(self, tabelle):
        self._t = tabelle
        self.number_of_tables = len(tabelle)

    def get_table(self, i):
        return self._t[i]

    def get_table_by_name(self, n):
        return next((t for t in self._t if t.name == n), None)


def controlli_nist_validazione(check):
    """(3.0.2) Difetti trovati confrontando RepertIA con le risposte NIST del caso «Data Leakage» (domande 23 e 55):
    nel journal NTFS un file rinominato più volte prendeva per tutte le rinomine il nome vecchio dell'ultima; i documenti
    rinominati .amr o .svg non erano segnalati come estensione falsa. Record USN v2 costruiti come quelli del PC NIST."""
    import sqlite3
    import types
    import forense_estesa as fx

    def rec(usn, fref, pref, reason, attr, nome, ft):
        n = nome.encode("utf-16-le")
        rl = (60 + len(n) + 7) & ~7
        b = struct.pack("<IHH", rl, 2, 0) + struct.pack("<QQQQI", fref, pref, usn, ft, reason) + \
            struct.pack("<III", 0, 0, attr) + struct.pack("<HH", len(n), 60) + n
        return b + bytes(rl - len(b))

    class A0:
        def __init__(self):
            self.v = []

        def add(self, cat, ts, title, detail="", user="", src=None, data=None):
            self.v.append((title, detail))
    ft = 130716000000000000
    cart, file_ = (1 << 48) | 100, (1 << 48) | 200          # (sequenza 1) cartella «S data» e il file
    buf = b"".join([rec(1, file_, cart, 0x1000, 0x20, "[secret_project]_detailed_design.pptx", ft),
                    rec(2, file_, cart, 0x2000, 0x20, "winter_whether_advisory.zip", ft),
                    rec(3, file_, cart, 0x80002000, 0x20, "winter_whether_advisory.zip", ft),
                    rec(4, file_, cart, 0x1000, 0x20, "winter_whether_advisory.zip", ft + 10 ** 7),
                    rec(5, file_, cart, 0x2000, 0x20, "winter_storm.amr", ft + 10 ** 7),
                    rec(6, file_, cart, 0x80002000, 0x20, "winter_storm.amr", ft + 10 ** 7)])
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE files (part, inode, deleted, type, path)")
    con.execute("INSERT INTO files VALUES (0, '100-144-1', 0, 'd/d', 'Users/informant/Desktop/S data')")
    A = A0()
    fx.usn_to_artifacts(A, types.SimpleNamespace(con=con), 0, [(0, len(buf))], len(buf), lambda p, n: buf[p:p + n])
    pr = tr(" (prima: {v1})").split("{")[0].lstrip()            # «(prima: » / «(before: »: il dettaglio è tradotto
    prima = [(t.rsplit("/", 1)[-1], d.split(pr, 1)[-1].split(")")[0].rsplit("/", 1)[-1]) for t, d in A.v
             if pr in d]
    check(tr("Journal NTFS: un file rinominato due volte ha per ogni rinomina il suo nome vecchio (difetto trovato con il "
             "caso NIST «Data Leakage», domanda 23)"),
          prima == [("winter_whether_advisory.zip", "[secret_project]_detailed_design.pptx"),
                    ("winter_storm.amr", "winter_whether_advisory.zip")], str(prima)[:160], interno=True)
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(504)
    fam = fx.detect_sig(ole)[0]
    check(tr("Estensioni false: un documento Office rinominato .amr o .svg è riconosciuto (audio AMR e SVG tra le "
             "estensioni conosciute; caso NIST «Data Leakage», domanda 55)"),
          fam == "ole" and fx.detect_sig(b"#!AMR\n" + bytes(32))[0] == "amr" and {"amr", "svg"} <= fx.KNOWN_EXT
          and "amr" not in fx.FAMILY_EXT["ole"] and "svg" not in fx.FAMILY_EXT["ole"], fam, interno=True)


def controlli_nist_ese(check):
    """(3.0.2) Indice di Ricerca di Windows (Windows.edb), cronologia di Internet Explorer 11 (WebCacheV01.dat) e Sticky
    Notes, sul modello del caso NIST «Data Leakage» (domande 13-15 e 40-46). Un database ESE non si può scrivere: si
    usano valori grezzi veri copiati dal Windows.edb NIST (7 bit, XOR, date big endian) e tabelle costruite con la stessa
    interfaccia di pyesedb, con i testi codificati come in Windows 7; StickyNotes.snt è il file NIST vero."""
    import types
    import forense_ese as fz
    import forense_estesa as fx
    tmp = Path(tempfile.mkdtemp(prefix="collaudo_ese_"))
    salva = {k: getattr(fx, k) for k in ("fw", "fetch", "find_files", "fetch_sqlite")}
    salva_z = {k: getattr(fz, k) for k in ("windows_search", "webcache")}

    class A0:
        def __init__(self):
            self.v = []

        def add(self, cat, ts, title, detail="", user="", src=None, data=None):
            self.v.append((cat, ts, title, detail, data or {}))

    def sette(s, tipo=0x13):                     # testo a 7 bit di Windows 7
        out, acc, n = bytearray([tipo]), 0, 0
        for ch in s.encode("ascii"):
            acc |= ch << n
            n += 7
            while n >= 8:
                out.append(acc & 0xFF)
                acc >>= 8
                n -= 8
        if n:
            out.append(acc & 0xFF)
        return bytes(out)

    def blocchi(s):                              # UTF-16 a blocchi: [quanti][byte alto][byte bassi…]
        out, i = bytearray([0]), 0
        while i < len(s):
            hi, j = ord(s[i]) >> 8, i
            while j < len(s) and ord(s[j]) >> 8 == hi and j - i < 255:
                j += 1
            out += bytes([j - i, hi]) + bytes(ord(c) & 0xFF for c in s[i:j])
            i = j
        return bytes(out)

    def xor(b):                                  # maschera di Windows 7 (chiave dalla lunghezza)
        m = 0x05000113 ^ len(b)
        return bytes(c ^ (((m >> (8 * (k % 4))) & 0xFF) ^ (k & 0xFF)) for k, c in enumerate(b))

    def ft(s):                                   # FILETIME da 'AAAA-MM-GGTHH:MM:SS' (UTC)
        return int((dt.datetime.fromisoformat(s) - dt.datetime(1601, 1, 1)).total_seconds()) * 10 ** 7

    try:
        # 1. valori grezzi veri del Windows.edb NIST
        vero = {"store": fz.ws_testo(b"\x14Szz\xbc\xce;\xdf\xf4\xf2\x1c"),
                "url": fz.ws_testo(b"\x12h:\x1d\xae{\xbd\xee\xf7\xbb\xab=w\xbb\xc6\xef\xf6\xeb\xf7\x1e\xa7\xc9\xbdt\x19\r\x07"),
                "data": fz.ws_data(b"\x01\xd0d\xb2.%\xf4`"),
                "nota": fz.ws_testo(b"\x14\xd4w\xfb-\x97\xbf\xef.\x97\xab\xa1h(\x8a\xf6\xb2<OG\xa7\xddg\xd0=\xcdf\x83\xc4e"
                                    b"\xd0s\xe9r\xb9\x1a\x8a\x86\x02"),
                "riassunto": fz.ws_testo(fz.smaschera(b":TmkPvtmD&$ :\x01K|NbkbG}xu\x03osrK<|\x7f;oi\x081\n+/"))}
        check(tr("Ricerca di Windows: valori veri del caso NIST decodificati (testo a 7 bit, data big endian, testo mascherato)"),
              vero["store"] == "StickyNotes" and vero["url"] == "http://www.msn.com/?ocid=iehp"
              and vero["data"] == "2015-03-22T15:09:23" and vero["nota"] == "Tomorrow...\r\n\r\nEverything will be OK..."
              and (vero["riassunto"] or "").startswith("Tomorrow...") and "Everything will be OK" in vero["riassunto"],
              str(vero)[:160], interno=True)

        # 2. indice costruito: un file del Desktop, una mail con allegato, una visita di IE (colonne con il prefisso di Windows 10)
        C = [("System_ItemPathDisplay", 12), ("4447-System_Search_Store", 12), ("System_DateCreated", 9),
             ("System_DateModified", 9), ("System_Size", 9), ("System_Subject", 12), ("System_Message_FromName", 12),
             ("System_Message_ToAddress", 12), ("System_Message_ToName", 12), ("System_Message_DateSent", 9),
             ("System_Message_DateReceived", 9), ("System_Message_AttachmentNames", 12), ("System_Search_AutoSummary", 11),
             ("System_ItemFolderPathDisplay", 12), ("Microsoft_IE_TargetUrl", 12), ("Microsoft_IE_VisitCount", 14)]
        be = lambda s: ft(s).to_bytes(8, "big")
        desk = r"C:\Users\informant\Desktop\Resignation_Letter_(Iaman_Informant).docx"
        righe = [{"System_ItemPathDisplay": sette(desk), "4447-System_Search_Store": sette("file"),
                  "System_DateCreated": be("2015-03-24T18:48:40"), "System_DateModified": be("2015-03-24T18:50:00"),
                  "System_Size": (12345).to_bytes(8, "big")},
                 {"System_ItemPathDisplay": sette("/iaman.informant@nist.gov/Sent Items/RE: Good job, buddy."),
                  "4447-System_Search_Store": sette("mapi15", 0x11), "System_Subject": blocchi("RE: Good job, buddy."),
                  "System_Message_FromName": sette("iaman"), "System_Message_ToAddress": sette("spy.conspirator@nist.gov"),
                  "System_Message_ToName": sette("spy"), "System_Message_DateSent": be("2015-03-23T19:19:22"),
                  "System_Message_DateReceived": be("2015-03-23T19:19:22"),
                  "System_Message_AttachmentNames": sette("space_and_earth.mp4"),
                  "System_Search_AutoSummary": xor(blocchi("This is a sample. I’ll be in touch.")),
                  "System_ItemFolderPathDisplay": sette("/iaman.informant@nist.gov/Sent Items")},
                 {"System_ItemPathDisplay": sette("http://www.msn.com/?ocid=iehp", 0x16), "4447-System_Search_Store": sette("iehistory", 0x16),
                  "Microsoft_IE_TargetUrl": sette("http://www.msn.com/?ocid=iehp", 0x16),
                  "System_DateModified": b"\x01\xd0d\xb2.%\xf4`", "Microsoft_IE_VisitCount": (2).to_bytes(4, "little")},
                 {"System_Size": b"*" * 8}]                         # riga senza percorso: scartata
        db_ws = _EseDb([_EseTab("MSysObjects", [("Name", 12)], []), _EseTab("SystemIndex_0A", C, righe)])
        fz.windows_search = lambda f, max_righe=0: fz.ws_righe(db_ws)
        fx.fw = lambda ctx, part, like, deleted_ok=False: ([(0, 1, 0, "ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb")]
                                                             if like.endswith("windows.edb") else [])
        fx.fetch = lambda ctx, part, inode, path, limit=0: tmp / "x"
        A = A0()
        fx.win_ricerca(A, types.SimpleNamespace(), 0, {})
        ind = {d.get("store"): (ts, ti, d) for c, ts, ti, _de, d in A.v if c == "indice"}
        rie = [d for c, _ts, _ti, _de, d in A.v if c == "sistema" and d.get("fonte") == "Windows Search"]
        f, m, ie = ind.get("file"), ind.get("mapi15"), ind.get("iehistory")
        ok = (f and f[2].get("percorso") == desk and f[2].get("creato") == "2015-03-24T18:48:40" and f[2].get("dimensione") == 12345
              and m and m[0] == "2015-03-23T19:19:22" and m[1] == "RE: Good job, buddy." and m[2].get("a") == "spy <spy.conspirator@nist.gov>"
              and m[2].get("allegati") == "space_and_earth.mp4" and m[2].get("testo") == "This is a sample. I’ll be in touch."
              and ie and ie[0] == "2015-03-22T15:09:23" and ie[2].get("url") == "http://www.msn.com/?ocid=iehp" and ie[2].get("visite") == 2
              and len(rie) == 1 and rie[0].get("elementi") == 3 and rie[0].get("contenuti") == {"file": 1, "mapi15": 1, "iehistory": 1})
        check(tr("Ricerca di Windows (Windows.edb): file del Desktop con la data di creazione, posta con destinatario, allegato e "
                 "testo, visita di Internet Explorer, riepilogo dell'indice"), bool(ok),
              str([(k, v[0], v[1]) for k, v in ind.items()] + rie)[:160], interno=True)

        # 3. WebCache costruita: contenitore History (UTC), MSHist (ModifiedTime locale da ignorare), cache dei contenuti esclusa
        cont = _EseTab("Containers", [("ContainerId", 4), ("Name", 12), ("Directory", 12)], [
            {"ContainerId": 1, "Name": "History", "Directory": r"C:\Users\informant\AppData\Local\Microsoft\Windows\History\Low\History.IE5" "\\"},
            {"ContainerId": 2, "Name": "MSHist012015032320150324", "Directory": r"C:\Users\informant\History.IE5\MSHist012015032320150324" "\\"},
            {"ContainerId": 3, "Name": "Content", "Directory": r"C:\Users\informant\Content.IE5" "\\"}])
        cc = [("Url", 12), ("AccessedTime", 15), ("ModifiedTime", 15), ("AccessCount", 4)]
        tab = [cont,
               _EseTab("Container_1", cc, [{"Url": "Visited: informant@http://go.microsoft.com/fwlink/?LinkId=69157",
                                            "AccessedTime": ft("2015-03-23T17:27:36"), "ModifiedTime": ft("2015-03-22T15:09:01"),
                                            "AccessCount": 2}]),
               _EseTab("Container_2", cc, [{"Url": ":2015032320150324: informant@http://www.bing.com/news?q=sports+news&FORM=NSBABR",
                                            "AccessedTime": ft("2015-03-23T20:55:57"), "ModifiedTime": ft("2015-03-23T16:55:57"),
                                            "AccessCount": 1},
                                           {"Url": ":2015032320150324: informant@:Host: www.bing.com",
                                            "AccessedTime": ft("2015-03-23T20:55:57"), "ModifiedTime": 0, "AccessCount": 1}]),
               _EseTab("Container_3", cc, [{"Url": "http://non.deve.comparire/immagine.jpg", "AccessedTime": ft("2015-03-23T20:00:00"),
                                            "ModifiedTime": 0, "AccessCount": 1}])]
        fz.webcache = lambda f, max_righe=0: fz.wc_visite(_EseDb(tab))
        wc = "Users/informant/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat"
        fx.find_files = lambda con, part, like, deleted_ok=False: [(0, 2, 0, wc)] if like.endswith("webcachev01.dat") else []
        A = A0()
        fx.win_webcache(A, types.SimpleNamespace(con=None), 0)
        web = sorted((ts, d.get("url"), d.get("prima"), d.get("visite")) for c, ts, _ti, _de, d in A.v if c == "web")
        att = [("2015-03-23T17:27:36", "http://go.microsoft.com/fwlink/?LinkId=69157", "2015-03-22T15:09:01", 2),
               ("2015-03-23T20:55:57", "http://www.bing.com/news?q=sports+news&FORM=NSBABR", None, 1)]
        check(tr("Internet Explorer 11 (WebCacheV01.dat): visite dei contenitori History e MSHist in UTC, prima visita, "
                 "voci «:Host:» e cache dei contenuti escluse"), web == att, str(web)[:160], interno=True)

        # 4. Sticky Notes: StickyNotes.snt vero del caso NIST
        import base64
        import lzma
        snt = tmp / "StickyNotes.snt"
        snt.write_bytes(lzma.decompress(base64.b64decode(NIST_SNT)))
        sp = "Users/informant/AppData/Roaming/Microsoft/Sticky Notes/StickyNotes.snt"
        fx.find_files = lambda con, part, like, deleted_ok=False: [(0, 3, 0, sp)] if like.endswith("stickynotes.snt") else []
        fx.fetch = lambda ctx, part, inode, path, limit=0: snt
        A = A0()
        fx.win_sticky(A, types.SimpleNamespace(con=None), 0)
        note = [(c, ts, d.get("testo")) for c, ts, _ti, _de, d in A.v]
        check(tr("Sticky Notes (StickyNotes.snt del caso NIST): testo della nota e data di modifica"),
              note == [("note", "2015-03-24T18:31:17", "Tomorrow...\r\n\r\nEverything will be OK...")], str(note)[:160], interno=True)
    except Exception as e:
        check(tr("Lacune NIST: Ricerca di Windows, Internet Explorer e Sticky Notes"), False, f"{type(e).__name__}: {e}"[:160],
              interno=True)
    finally:
        for k, v in salva.items():
            setattr(fx, k, v)
        for k, v in salva_z.items():
            setattr(fz, k, v)
        shutil.rmtree(tmp, ignore_errors=True)


# (3.0.2) dati di prova incorporati per la sorgente logica: AD1 compresso dei test di dissect.evidence (Fox-IT,
# AGPL-3.0-or-later, tests/_data/ad1/compressed.ad1); RAR 4 e RAR 5 dei test di libarchive (BSD-2-Clause,
# libarchive/test/test_read_format_rar.rar.uu e test_read_format_rar5_stored.rar.uu)
GPX_PROVA = ('<?xml version="1.0" encoding="UTF-8"?><gpx version="1.1" xmlns="http://www.topografix.com/GPX/1/1">'
             '<wpt lat="41.9028" lon="12.4964"><name>Roma</name></wpt><trk><name>giro</name><trkseg><trkpt lat="41.90" '
             'lon="12.49"/><trkpt lat="41.91" lon="12.50"/><trkpt lat="41.92" lon="12.51"/></trkseg></trk></gpx>')
LOGICA_AD1 = (
    "QURTRUdNRU5URURGSUxFAAEAAAACAAAAAQAAAAEAAAAAAMBdAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAABBRExPR0lDQUxJTUFHRQAABAAAAAEAAAAAAAEAZwAAAAAAAACGAAAAAAAAAAsAAABBRAAAXAAAAAAAAAA1BQAAAA"
    "AAAAAAAAAAAAAAcQYAAAAAAAAAAAAAAAAAAEU6XEFEMV90ZXN0AAAAAAAAAAABAAAAAgABAAsAAABFOlxBRDFfdGVzdL0CAAAAAAAAAAAAAAAA"
    "AAD3AAAAAAAAAMYAAAAAAAAAEQAAAAAAAAAAAAAACAAAAGRvYzEudHh0AAAAAAAAAAABAAAAAAAAAN4AAAAAAAAA9wAAAAAAAAB4nPPMy8gvTV"
    "FIyU8uzU3NK1EwBAA6GwY4DAEAAAAAAAACAAAAAgAAAAEAAAAxIgEAAAAAAAADAAAAAwAAAAIAAAAxN0wBAAAAAAAABQAAAAcAAAAWAAAAMjAx"
    "NzAzMzFUMTgwMjMxLjE4OTY4MnYBAAAAAAAABQAAAAgAAAAWAAAAMjAxNzAzMzFUMTgwMjMxLjE4OTY4MqABAAAAAAAABQAAAAkAAAAWAAAAMj"
    "AxNzAzMzFUMTgwMjQ5LjcyMjYxNrkBAAAAAAAABAAAAA0AAAAFAAAAZmFsc2XSAQAAAAAAAAQAAAAOAAAABQAAAGZhbHNl6gEAAAAAAAAEAAAA"
    "HgAAAAQAAAB0cnVlAwIAAAAAAAAEAAAAAhAAAAUAAABmYWxzZRwCAAAAAAAABAAAAAMQAAAFAAAAZmFsc2U1AgAAAAAAAAQAAAAEEAAABQAAAG"
    "ZhbHNlTQIAAAAAAAAEAAAABRAAAAQAAAB0cnVlgQIAAAAAAAABAAAAAVAAACAAAAA4NjNhYWI1Y2NmYzFmMGQ2MzBlZGM4MTY2N2Y5N2YxOQAA"
    "AAAAAAAAAQAAAAJQAAAoAAAANDg4MDIyOWVmZTFjYzUwYTdmNWNhNmVjMGZjODE0YTNlYjc0NzFmYQAAAAAAAAAAAAAAAAAAAABuAwAAAAAAAP"
    "0CAAAAAAAAjgAAAAAAAAAAAAAACAAAAGRvYzIudHh0AAAAAAAAAAABAAAAAAAAABUDAAAAAAAAbgMAAAAAAAB4nEVL2w2AIAz8J2EHZnALxzCe"
    "bQMKH5X9pdRomt4zt1ZpHQlt79dR77TEYKeIgUxs0KlYQawGJUMFhbLoicJGIxIm3xG/75uBMzUXw996+nVkBvQAMG8sX4MDAAAAAAAAAgAAAA"
    "IAAAABAAAAMZoDAAAAAAAAAwAAAAMAAAADAAAAMTQyxAMAAAAAAAAFAAAABwAAABYAAAAyMDE3MDMzMVQxODAyMzguOTgzNjI07gMAAAAAAAAF"
    "AAAACAAAABYAAAAyMDE3MDMzMVQxODAyMzguOTgzNjI0GAQAAAAAAAAFAAAACQAAABYAAAAyMDE3MDMzMVQxODAzMDYuOTA1MjM0MQQAAAAAAA"
    "AEAAAADQAAAAUAAABmYWxzZUoEAAAAAAAABAAAAA4AAAAFAAAAZmFsc2ViBAAAAAAAAAQAAAAeAAAABAAAAHRydWV7BAAAAAAAAAQAAAACEAAA"
    "BQAAAGZhbHNllAQAAAAAAAAEAAAAAxAAAAUAAABmYWxzZa0EAAAAAAAABAAAAAQQAAAFAAAAZmFsc2XFBAAAAAAAAAQAAAAFEAAABAAAAHRydW"
    "X5BAAAAAAAAAEAAAABUAAAIAAAAGYxN2UxZmU1NDJiOTliYWVjNDk3ZDQ3ZTg5NmRkNGNkAAAAAAAAAAABAAAAAlAAACgAAABjYWIzODU4Mjli"
    "ZGJhNDMxNjI2N2M4ZWFlMGFlZTRiZDU4ZjJiMGU3QVRUUkdVSUQAAAAADwAAAAIAAAD0c9iKsMBqR7oaNoHBgWsLAwAAAIqECDVMdiFHl5qHDh"
    "waM+AHAAAAN6bM5UMEV0++yoA25PeFdAgAAAD8DRDzNcbvQKt7LqTxHYlHCQAAAMimbK3v21dCnCetpE4P6LcNAAAAtoEyjN7DsEykU2B0tom5"
    "CQ4AAAB+Sg8GX+ukS4E/CItogdZ/HgAAAGSsZM5kOn5PhTKBKJaFWAwCEAAARVUEQp6tH0KB4/eJtUF5jgMQAAD39mqhPaoUTZYQAXPcgaQ2BB"
    "AAAF4Qy+k1YqtFqmUuKmBelbQFEAAAZXlcHQcUYkO97f4XWk1xQAFQAAAKM+Jr4hXqTbY+IZjoHqt1AlAAABj/6EAnIyRMk1jb6p+k3VwCAAEA"
    "ZZ2rXvKjoUSq3RVfVQb9FkxPQ1NHVUlEAAAAAAEAAAABAAAAPqD6omJJikSsWImDaAFvxw==")
# (3.0.2) immagini di CD/DVD costruite per il collaudo (hdiutil makehybrid su macOS, compresse con lzma): UDF e
# ISO 9660 con prezzi.txt e cartella/nota.txt (15/03/2024 09:30 UTC)
LOGICA_UDF = (
    "/Td6WFoAAATm1rRGAgAhARwAAAAQz1jM8Nf/BGZdAABv/f//o7f/Rz5IFXI5YVG4kijmo4YH+e7kHoLTL8U6PAFLsX7JiopNL6MN2X+m44wjEV"
    "PgWRjFdYrid/dF3wqDSd0lzkOkZMb7/GykU+G5zXr6KWg4QtDYrIBvgm1s5XpPPTTB4c8EnY1U6CaIAheQl/XMLk870P9oQE551pREtf6udvj/"
    "yR6g50DjpoNCiPe+vWY77dq+Z9/bXmL+mphI57ZwVA4JBD0lJGPT6trFe6/uR50d0HnRRnrPBKQMvdvhLCJBJrZYSRsKPzBUomHvv2rwNDBmTN"
    "vyQUHATmif+twESdpzsbF/viGPQyxsaZWMaJ5TNs5acyJ5ibLyj8rdt1v8f7GpHJDP/J0jdUH24XCRsIXSuXdQ2JqbDrJ7B9TccCVgqf7lVeI3"
    "16eRLZ2gVAmugnIM/8PLSI6lMLzNJnTXJlpqdQLn1pXPAc5wahxpuRAJ21zXB1EO7snNuedezYu591Q2PToY6/SolIeOuEoBWAXEkorfjCuJBv"
    "eaPUPVL7Z2ybq0HeZ/9eaasraYPAX9aYtCdvWIT4Q62ZvT2Cz9D0kGdUJVmcnbPa8FihZDJPFCoywMJVRdRJ3k9P/XDB1yKDrJmT3/QfHvKDFf"
    "CfcUZuWA6Z+mi5T3i0sOdFc/8MNRxRCSuNvNnW5LlYEm8/fijsQzqVT/7wo4HB7OHTNAaYi3BhoKhLDhhUhq+zWQ2v1aaTELslaJWd2JEHC5am"
    "u6NUMnuY7aZuFO6j2ZSRYrlflH+k7nUuKSBlYZnkSe4tLkRvTBpIa2awmYOSOrnIWIny+sF7+kByxKm94rkl2XB+d5nE0PnetjpZEITDMvWLz2"
    "UJh991zBvsKc3aGpEG+u0/fZPPvh7g+DETifHmKsM1N5TIdLNGbBP1LeGVgrS8x6KF7c2DrP88S+3xbtUrA301VrnPbmmh+fDB0o/TC54/peeZ"
    "PEDd0AcaHnLlF+sT8Hg7p08h1zpab7agLYFF/Jmd1INMr9PA4Q+cyTpLFJY2B50Sy7E9AKCPTUkVgxralnCb+UBz5mwsrRn4PdH3hdmzGpbhz+"
    "Eix8M70eS1PB2wmuNYggrK1kFz5dKVKSP5LKrXBFecfA84jTTsXsMRosHSxw6CodpUSYWKfUaUy5VQtRg0C2izM8RAjqQFtePMa7wOuG0nOY2q"
    "rzdtNNyAQFkQTcLFhgKSdTDN6euKWy/kfOnFOysR8TenGaieJGQWPIT5HeFUub+7zR0vR+BAC8s5ZIGj/PhFknaUjs+dGf8WMXxf/VOx23Moca"
    "IFHoQrdIrVZhtWFnyC5EX4ENgo5WhkXnMofxFMD1vHDmj3i/fpYWXczFuk61DtBIcljfZkPf+1TS0VvGRQp0JQt/Cs5SaA9glwqeR4F4J+gEJS"
    "LSPPqWVftNJSueW3NE6uNWjHAaO4FHZv5eLf8u65odus6xJxhcWYbpZlJYvul2rFnk5VsFCPnH2q38+1IrdM0eWyBC+d1TPfgpZAk7gMspK0Oo"
    "wAAAAABQ8ERM7d7cDQABggmAsEMAkldubrHEZ/sCAAAAAARZWg==")
LOGICA_ISO = (
    "/Td6WFoAAATm1rRGAgAhARwAAAAQz1jM7g//A05dAABv/f//o7f/Rz5IFXI5YVG4kijmo4YH+e7kHoLTL8U6PAFLsX7JiopNL6MN2X+m44wjEV"
    "PgWRjFdYrid/dE790OjkefKuUNGdrowmcelHU2dZCyW5owxKOVQ9hRXzInsxkkP5dyFYHZ/C3IKETEDzfOzic0KEYB/RKDASrld9e9zYFhiRJt"
    "pJFVMIZdc7Gyq+Jc6LMhQwkIw1AN9ecbw7e5VtoUJm8JNaU7aSyZBmR+9/UP/bxUMDjiYKmVTiCA3xU4cBeEXmRxXfynK3EQJ6KUkMYOVI1o/e"
    "GBg43stbN9k5RePqE1k7OCiLwO4GRFNWUFE9d1crFgfbamb9tl/wj1oPjze79Y1cUmzMOTz2Q+4M8pvSOE06UcEuyOYz9Bf2YAIA3XRvoz1HCk"
    "vu119Z6yB5+9GhAa8YQCPWAPRaoYWDlsWAlfgvnJbjmkR14QwoVCjugLsr/NMpO9e2IWHtcox8r1dc763gYfbE8WU/MW46hIa7oRonMAHgyg/R"
    "3tm6kRZeDCTu6pnsMYagiWaSUewi97d/KtcB2FE8HdGa3v6Gx8RFfngIVppob142meYcD9Tqe6cJj0XtvY5L/wQygLgYtl1HC+ws7iVfNdK41Y"
    "lk/TRt8j9OjrGSSZIdUmTtv4bVsoo9DIcFz46ztp+j0sUWFNWGOv74ciAj/jzgkjoG5GpEY57u+bZn77FyS7GdkMDx6fJCEdgrONS24QzMPuFS"
    "zuBB6834iimfxSaBJ7zFDxobiAo2gPQ1TbfC5wwmDxZKDOnKubW8Vt3Y6iNwZXmPlYtl4+mFE1xa/RgwGQNhNijupsJpgf4JQ4pqGDEky3cvBW"
    "9QSb5VjxEFQ/pwVqijYVL5uE76dBRk7zAob6VOF08bMYBPI8xqd0Svj4TlBhj/JiFuYme08XYaWKKNP9N/tNOb2xHUiJpHBiLrM17suUAp1UNj"
    "0YuSBJ2BqIGAEPa1ZEfskPsfGTVdBi9EnKwLoCxCImUUKY92z48h/ftTvwxL0uX6oPPktmQpATDv8Qk/hxeFn4C83/lShGD6n8fN77mjAuVsCP"
    "hfODgcBlxCVT+PWRNjEFpbDub8FwTUcM0ZERqq1gHbrOsScYXFmG6WZSWL7pdqsLkCcgAAAAAAN0tBtXNXNEAAHqBoCgOAA5TnTYscRn+wIAAA"
    "AABFla")
LOGICA_RAR4 = (
    "UmFyIRoHAM+QcwAADQAAAAAAAACEUnQgkDIAFAAAABQAAAADQqLIvrd22j4UMAgApIEAAHRlc3QudHh0gAi3dto+t3baPnRlc3QgdGV4dCBkb2"
    "N1bWVudA0KnS90IJAyAAgAAAAIAAAAA3tEybbRTNg+FDAIAP+hAAB0ZXN0bGlua8AI0UzYPlBf2j50ZXN0LnR4dM3gdCCQOgAUAAAAFAAAAANC"
    "osi+Y3faPhQwEACkgQAAdGVzdGRpclx0ZXN0LnR4dMDMY3faPmN32j50ZXN0IHRleHQgZG9jdW1lbnQNCqHIdOCQMQAAAAAAAAAAAAMAAAAAY3"
    "faPhQwBwDtQQAAdGVzdGRpcsDMY3faPmR32j7m53TgkDYAAAAAAAAAAAADAAAAAJ2r1T4UMAwA7UEAAHRlc3RlbXB0eWRpcoDMnavVPsVd2j7E"
    "PXsAQAcA")
LOGICA_RAR5 = (
    "UmFyIRoHAQAzkrXlCgEFBgAFAQGAgAA4MAZjLAIDC50ABJ0ApIMCtEOglYAAAQ5oZWxsb3dvcmxkLnR4dAoDE34Oq1tW6Q4aaGVsbG8gbGliYX"
    "JjaGl2ZSB0ZXN0IHN1aXRlIQodd1ZRAwUEAA==")

def controlli_copia_smartphone(check):
    """(3.0) Un caso smartphone collegato a una nuova posizione legge i file da lì, anche se collegato con la 2.21."""
    import forense_mobile as fm

    class Caso:
        def __init__(self, x, meta):
            self.root, self.meta = Path(x), meta

        def save(self):
            pass

        def log(self, *_a, **_k):
            pass

    with tempfile.TemporaryDirectory() as d:
        nuovo = Path(d) / "estrazione.zip"
        nuovo.write_bytes(b"PK")
        chiave = fm.part_key(0)
        parti = [{"offset": chiave, "readable": True, "mobile": {"file": "/non/esiste/estrazione.zip", "formato": "zip", "nome": "estrazione.zip"}}]
        vecchio = Caso(d, {"tipo_caso": "smartphone", "evidence": str(nuovo), "image": str(nuovo), "partitions": parti})
        letto = fm._sorgente(vecchio, chiave)["file"]
        c2 = Caso(d, {"tipo_caso": "smartphone", "evidence": "/non/esiste/estrazione.zip", "image": "/non/esiste/estrazione.zip",
                      "partitions": [dict(parti[0], mobile=dict(parti[0]["mobile"]))]})
        fa.collega_copia(c2, str(nuovo), conferma=True)
    check(tr("Collega copia forense: nei casi smartphone i file si leggono dalla nuova posizione"),
          letto == str(nuovo) and c2.meta["partitions"][0]["mobile"]["file"] == str(nuovo.resolve()), letto[-30:], interno=True)


def controlli_cache_web(check):
    """(3.0.1) Voci della Simple Cache di Chromium costruite con contenuto noto: inizio e lunghezza del contenuto, indirizzo,
    nome del file, intestazione vecchia di 20 byte, voce troncata, voce che non è una foto (pagina HTML)."""
    import hashlib
    import struct
    import zlib
    import forense_mobile_media as fmm
    ini, fin = struct.pack("<Q", 0xfcfb6d1ba7725c30), struct.pack("<Q", 0xf4fa6f45970d41d8)

    def voce(key, body, hdr=24):
        k = key.encode()
        s0 = b"HTTP/1.1 200\0content-type: image/jpeg\0\0"
        return (ini + struct.pack("<III", 5, len(k), zlib.crc32(k)) + (b"\0" * 4 if hdr == 24 else b"") + k + body + fin
                + struct.pack("<IIII", 1, zlib.crc32(body), 0, 0) + s0 + hashlib.sha256(k).digest() + fin
                + struct.pack("<IIII", 3, zlib.crc32(s0), len(s0), 0))
    jpg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + bytes(range(256)) * 4 + b"\xff\xd9"
    key = "1/0/_dk_https://a.test https://a.test https://img.a.test/foto/gatto%20nero.jpg?w=800"
    v = voce(key, jpg)
    r = fmm.voce_chromium(v)
    ok1 = r == (24 + len(key), len(jpg), "https://img.a.test/foto/gatto%20nero.jpg?w=800") and v[r[0]:r[0] + r[1]] == jpg
    r2 = fmm.voce_chromium(voce("https://b.test/a.png", jpg, hdr=20))
    r3 = fmm.voce_chromium(v[:24 + len(key) + 500])
    r4 = fmm.voce_chromium(voce("https://c.test/index.html", b"<html></html>"))
    ok2 = r2 is not None and r2[0] == 20 + len("https://b.test/a.png") and r2[1] == len(jpg)
    ok3 = r3 is not None and r3[1] == 500 and fmm.firma(v[r3[0]:r3[0] + 32]) == ("foto", "jpg")
    ok4 = r4 is not None and fmm.firma(b"<html></html>" + b"\0" * 20) is None
    nomi = (fmm.nome_da_url(r[2], "jpg"), fmm.nome_da_url("https://b.test/a.png", "jpg"), fmm.nome_da_url("https://v.test/clip", "mp4"))
    ok5 = nomi == ("gatto_nero.jpg", "a.png.jpg", "clip.mp4") and fmm.voce_chromium(jpg) is None
    check(tr("Cache dei browser (Chromium): foto riconosciuta dentro la voce, con offset, lunghezza e indirizzo giusti"), ok1,
          f"{r[:2] if r else None}", interno=True)
    check(tr("Cache dei browser: intestazione di 20 byte, voce troncata e pagina HTML (non è una foto)"), ok2 and ok3 and ok4,
          f"{r2[:2] if r2 else None} · {r3[:2] if r3 else None}", interno=True)
    check(tr("Cache dei browser: nome del file dall'indirizzo con l'estensione del formato vero"), ok5, " · ".join(nomi), interno=True)


def controlli_recupero(check):
    """(3.0) Record cancellati su database costruiti con cancellazioni note: valori veri o nessun record, mai valori inventati."""
    import shutil as _sh
    import sqlite3 as _sq
    import forense_database as fdb
    import forense_recupero as fr

    def crea(f, sec="OFF", wal=False):
        c = _sq.connect(str(f))
        c.execute(f"PRAGMA secure_delete={sec}")
        if wal:
            c.execute("PRAGMA journal_mode=WAL")
        c.execute("CREATE TABLE m(id INTEGER PRIMARY KEY, ts INTEGER, chi TEXT, testo TEXT)")
        c.executemany("INSERT INTO m VALUES (?,?,?,?)", [(i, 1700000000 + i, f"+39000{i:05d}", f"testo numero {i:06d} " + "x" * 30) for i in range(1, 301)])
        c.commit()
        return c

    def vero(r):
        v = [x[1] for x in r["valori"]]
        i = int(v[3].split()[2])
        return v[1:] == [str(1700000000 + i), f"+39000{i:05d}", f"testo numero {i:06d} " + "x" * 30], i

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        f = d / "sparsi.db"
        c = crea(f)
        tolte = list(range(10, 300, 10))
        c.executemany("DELETE FROM m WHERE id=?", [(i,) for i in tolte])
        c.commit()
        c.close()
        r = fr.recupera(str(f))
        sicuri = [x for x in r["record"] if x["livello"] != "ambiguo"]
        esiti = [vero(x) for x in sicuri]
        rid = all((x["rowid"] is None and x["valori"][0][0] == "?") or x["valori"][0][1] == str(x["rowid"]) for x in sicuri)
        check(tr("Record cancellati: righe sparse lette con i valori veri, nessuna riga viva, ROWID mai inventato"),
              len(sicuri) >= 10 and all(e[0] and e[1] in tolte for e in esiti) and rid, f"{len(sicuri)}/{len(tolte)}", interno=True)
        f = d / "wal.db"
        c = crea(f, wal=True)
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        c.execute("PRAGMA wal_autocheckpoint=0")
        c.executemany("DELETE FROM m WHERE id=?", [(i,) for i in tolte])
        c.commit()
        lav = d / "wal_lav"
        lav.mkdir()
        for suf in ("", "-wal"):
            _sh.copy(str(f) + suf, str(lav / ("wal.db" + suf)))
        c.close()
        rw = fr.recupera(str(lav / "wal.db"))
        nw = {x["rowid"] for x in rw["record"] if x["fonte"] == "cancellata_nel_wal"}
        f = d / "secure.db"
        c = crea(f, sec="ON")
        c.executemany("DELETE FROM m WHERE id=?", [(i,) for i in tolte])
        c.commit()
        c.close()
        rs = fr.recupera(str(f))
        check(tr("Record cancellati: le righe cancellate nel WAL risultano tali; con secure_delete nessun record"),
              nw == set(tolte) and not rs["record"], f"WAL {len(nw)}/{len(tolte)}, secure_delete {len(rs['record'])}", interno=True)
        f = d / "default.db"
        c = _sq.connect(str(f))
        c.execute("PRAGMA secure_delete=OFF")
        c.execute("CREATE TABLE m(id INTEGER PRIMARY KEY, chi TEXT, n INTEGER)")
        c.executemany("INSERT INTO m VALUES (?,?,?)", [(i, f"+39000{i:05d}", 200 + i) for i in range(1, 101)])
        c.commit()
        c.execute("ALTER TABLE m ADD COLUMN sub INTEGER DEFAULT -1")
        c.executemany("DELETE FROM m WHERE id=?", [(i,) for i in range(10, 100, 10)])
        c.commit()
        c.close()
        rd = fr.recupera(str(f))
        sd = [x for x in rd["record"] if x["livello"] != "ambiguo"]
        check(tr("Record cancellati: colonna aggiunta dopo la riga presa dal DEFAULT e segnata"),
              bool(sd) and all(x["valori"][3][1] == "-1" and x["dal_default"] == [3] for x in sd),
              f"{len(sd)}", interno=True)

        class Caso:
            def __init__(self, x):
                self.root, self.export_dir, self.voci = Path(x), Path(x) / "export", []

            def log(self, azione, dati):
                self.voci.append((azione, dati))

        class G:
            @staticmethod
            def file_ident(_case, _b):
                return {"source": "x", "path": "/sparsi.db", "name": "sparsi.db", "part": None, "inode": None, "id": 1}

        base = Path(d) / "caso"
        base.mkdir()
        tmp = base / (fdb.PREFISSO + "prova")

        def copia(_g, _c, _i):
            tmp.mkdir()
            _sh.copy(d / "sparsi.db", tmp / "sparsi.db")
            return tmp, tmp / "sparsi.db"

        caso, orig_copia = Caso(base), fdb._copia_lavoro
        fdb._copia_lavoro = copia
        try:
            a = fdb.apri(G, caso, {})
        finally:
            fdb._copia_lavoro = orig_copia
        rc = fdb.recuperati(caso, {"id": a["id"]})
        x0 = next(x for x in rc["record"] if x["livello"] != "ambiguo")
        fq = d / "fq.csv"
        fq.write_bytes(b"_TBLNAME;_PLL;_ROWID;_STATUS;_OFFSET;id\n" + f"m;[9|4];-1;D;{x0['offset'] + 3};testo\nspezzato\n".encode()
                       + b"m;[9|4];7; ;99999;viva\n")
        e = fdb.riscontro_csv(caso, {"id": a["id"], "path": str(fq), "strumento": "FQLite 5.0"})
        rifiuto = False
        estraneo = d / "altro.csv"
        estraneo.write_text("a;b;c\n1;2;3\n", encoding="utf-8")
        try:
            fdb.riscontro_csv(caso, {"id": a["id"], "path": str(estraneo)})
        except ValueError:
            rifiuto = True
        scelta = next(i for i in tolte if any(y["valori"][3][1].startswith(f"testo numero {i:06d}") for y in rc["record"] if y["livello"] != "ambiguo"))
        viva = fdb.cerca(caso, {"id": a["id"], "testo": "+3900000001"})
        solo = fdb.cerca(caso, {"id": a["id"], "testo": f"testo numero {scelta:06d}", "recuperati": True})
        jolly = fdb.cerca(caso, {"id": a["id"], "testo": "100%_"})
        check(tr("Gestore database: ricerca di un valore: tabelle e colonne giuste, anche nei record cancellati e con caratteri speciali"),
              [t["tabella"] for t in viva["tabelle"]] == ["m"] and viva["tabelle"][0]["colonne"][0]["colonna"] == "chi"
              and not solo["tabelle"] and solo["recuperati"] == {"m": 1} and not jolly["tabelle"]
              and bool(fdb.query(caso, {"id": a["id"], "sql": viva["tabelle"][0]["sql"]})["righe"]), f"{viva['tabelle']}"[:90], interno=True)
        hx = fdb.esadecimale(caso, {"id": a["id"], "file": "db", "offset": x0["offset"]})
        azioni = {v[0] for v in caso.voci}
        fdb.chiudi(caso, {"id": a["id"]})
        check(tr("Record cancellati: riscontro col CSV per posizione, formato estraneo rifiutato, voce nel registro"),
              e["abbinati"] == 1 and rifiuto and bool(hx["testo"]) and {"db_recupero", "db_riscontro_csv"} <= azioni,
              f"{e['abbinati']}", interno=True)


def controlli_reperti_ia(case, check):
    """(2.20.1, AI Act) Un reperto registrato dall'agente (strumento record_finding, con un modello finto) risulta
    «modello IA – da verificare» in findings.json e nel report, che non dice «ogni reperto è stato verificato»; Word e PDF
    dichiarano nei metadati il testo generato da IA; dopo «Confermo, verificato» il reperto è verificato con operatore e
    data, anche nel registro. Più la distinzione fra server LLM locali/privati ed esterni."""
    import forense_gui as G
    import tempfile as _tf

    class _Finto:
        log_path = None
        findings = staticmethod(lambda: [])
    with _tf.TemporaryDirectory() as td:
        _Finto.log_path = Path(td) / "audit_log.jsonl"
        righe = [{"ts": "t0", "event": "sessione", "data": {"model": "m-a", "url": "http://127.0.0.1:1", "backend": "b"}}]
        _Finto.log_path.write_text("\n".join(json.dumps(r) for r in righe), encoding="utf-8")
        solo_collegato = fa.modelli_report_md(_Finto)
        righe += [{"ts": "t1", "event": "user", "data": "d"}, {"ts": "t2", "event": "assistant", "data": {"tool_calls": [1]}},
                  {"ts": "t3", "event": "assistant", "data": {"tool_calls": None}}]
        _Finto.log_path.write_text("\n".join(json.dumps(r) for r in righe), encoding="utf-8")
        usato = fa.modelli_usati(_Finto)
    check(tr("report: server collegato senza domande = nessun modello; con domande = nome, domande e risposte"),
          "m-a" not in solo_collegato[0] and len(usato) == 1 and usato[0]["model"] == "m-a"
          and (usato[0]["domande"], usato[0]["risposte"], usato[0]["al"]) == (1, 1, "t3"), solo_collegato[0][:70], interno=True)
    md0 = fa.write_report(case).read_text(encoding="utf-8")
    check(tr("report: riga sul modello IA presente e note metodologiche coerenti con il registro"),
          any(l.startswith(tr("- Modello IA")) for l in md0.splitlines()) and fa.modello_metodo_md(case).strip() in md0, "", interno=True)
    m0, llm0 = fa.MODEL, case.meta.get("llm")
    fa.MODEL = "modello-collaudo"
    case.meta["llm"] = {"backend": "collaudo", "url": "http://127.0.0.1:1234", "model": fa.MODEL, "remoto": False,
                        "esterno": False}
    try:
        tools = fa.make_tools(case)
        tools["record_finding"]("Collaudo: reperto dell'agente", "Descrizione scritta dal modello finto del collaudo.",
                                "offset 0, inode 0")
        x = case.findings()[-1]
        check(tr("AI Act: reperto dell'agente in findings.json come «modello IA», con modello, server e «da verificare»"),
              x.get("origine") == fa.FINDING_IA and x.get("modello") == fa.MODEL and x.get("server") == "http://127.0.0.1:1234"
              and x.get("stato") == "da verificare", json.dumps({k: x.get(k) for k in ("origine", "modello", "server", "stato")},
                                                                ensure_ascii=False), interno=True)
        md = fa.write_report(case).read_text(encoding="utf-8")
        lbl = fa.finding_label(x)
        tutti = tr("Ogni reperto è stato verificato dall'analista sugli strumenti forensi. ").strip()
        check(tr("AI Act: nel report il reperto è «da verificare» e non c'è la frase «ogni reperto è stato verificato»"),
              f"**[{lbl}]**" in md and tutti not in md, lbl, interno=True)
        ia = fa.report_ia(case)
        dx, pdf = G.report_docx(md, "collaudo", ia), G.report_pdf(md, "collaudo", ia)
        import io as _io
        core = zipfile.ZipFile(_io.BytesIO(dx)).read("docProps/core.xml").decode("utf-8")
        check(tr("AI Act: i metadati di Word e PDF dichiarano il testo generato da IA"),
              ia and "AI-generated content" in core and b"/Keywords (AI-generated content" in pdf,
              tr("Word: cp:keywords; PDF: /Keywords"), interno=True)
        fa.confirm_finding(case, x["n"], "Operatore del collaudo")
        y = next(f for f in case.findings() if f["n"] == x["n"])
        md2 = fa.write_report(case).read_text(encoding="utf-8")
        log = [json.loads(r) for r in case.log_path.read_text(encoding="utf-8").splitlines() if r.strip()]
        conf = [r for r in log if r.get("event") == "finding_verificato" and (r.get("data") or {}).get("n") == x["n"]]
        check(tr("AI Act: dopo «Confermo, verificato» il reperto è verificato (operatore e data) nel report e nel registro"),
              y.get("stato") == "verificato" and y.get("verificato_da") == "Operatore del collaudo" and y.get("verificato_il")
              and f"**[{fa.finding_label(y)}]**" in md2 and tr("Verificato da {op} il {data}").format(
                  op="Operatore del collaudo", data=y.get("verificato_il")) in md2
              and (tutti in md2) == all(fa.finding_verificato(f) for f in case.findings())
              and bool(conf) and conf[-1]["data"].get("operatore") == "Operatore del collaudo",
              fa.finding_label(y), interno=True)
    finally:
        fa.MODEL = m0
        if llm0 is None:
            case.meta.pop("llm", None)
        else:
            case.meta["llm"] = llm0
    interni = ["http://localhost:1234", "127.0.0.1:8080", "http://10.1.2.3:11434", "172.16.0.5", "172.31.255.1:1234",
               "192.168.1.20", "http://server-ia:8080", "http://ia.local:8080", "http://[fd00::1]:8080"]
    esterni = ["http://172.32.0.1:8080", "https://8.8.8.8", "https://api.example.com/v1", "http://11.0.0.1"]
    sbagliati = [u for u in interni if fa.url_esterno(u)] + [u for u in esterni if not fa.url_esterno(u)]
    check(tr("AI Act: server LLM locali e della rete privata riconosciuti, server esterni segnalati"), not sbagliati,
          ", ".join(sbagliati) or tr("{a} locali/privati, {b} esterni").format(a=len(interni), b=len(esterni)), interno=True)


def controlli_verifica_registro(case, check, scenari):
    """(2.20) Verifica a posteriori del registro (forense_registro, la stessa di «Verifica registro» e di
    tools/verifica_registro.py). Sempre: registro del caso integro, hash finale trovato. Con `scenari`, su copie del
    registro: una riga modificata, una tolta in mezzo, righe tolte alla fine senza e con l'hash finale."""
    import forense_registro as frg
    R = frg.verifica(case.root)
    av = fa.audit_verifica(case)
    check(tr("verifica del registro: catena integra, stesso hash finale del programma"),
          R["integro"] and R["hash_finale"] == av.get("ultimo_hash") and R["voci"] == av.get("righe"),
          "; ".join(frg.testo(R)[1:3]), interno=True)
    R2 = frg.verifica(case.root, R["hash_finale"], R["voci"])
    check(tr("verifica del registro: hash finale e voci del report trovati"), (R2.get("atteso") or {}).get("esito") == "trovato",
          str((R2.get("atteso") or {}).get("esito")), interno=True)
    x = R.get("esportati") or {}
    if x.get("controllati") or (x.get("manifest") or {}).get("controllati"):
        check(tr("verifica del registro: file esportati ancora uguali"), not x["diversi"] and not x["manifest"]["diversi"],
              tr("{c} file controllati").format(c=x["controllati"] + x["manifest"]["controllati"]), interno=True)
    if not scenari:
        return
    lines = case.log_path.read_bytes().rstrip(b"\n").split(b"\n")
    if len(lines) < 8:
        check(tr("verifica del registro: scenari di manomissione"), False, tr("registro troppo corto ({n} righe)").format(n=len(lines)))
        return
    hf, nv = R["hash_finale"], R["voci"]
    tmp = Path(tempfile.mkdtemp())

    def prova(nome, righe, hash_finale=None, voci=None):
        d = tmp / nome
        d.mkdir()
        (d / "audit_log.jsonl").write_bytes(b"\n".join(righe) + b"\n")
        return frg.verifica(d, hash_finale, voci, file_esportati=False)
    try:
        k = len(lines) // 2
        mod = list(lines)
        mod[k] = mod[k].replace(b'"ts": "', b'"ts": "X', 1)
        r = prova("modificata", mod)
        pa = r.get("prima_alterata") or {}
        check(tr("verifica del registro: una riga modificata viene indicata (riga {k})").format(k=k + 1),
              frg.esito_breve(r) == "alterato" and pa.get("riga") == k + 1, tr("indicata la riga {r}").format(r=pa.get("riga")))
        r = prova("tolta_mezzo", lines[:k] + lines[k + 1:])
        mm = r.get("mancanti") or [{}]
        check(tr("verifica del registro: una riga tolta in mezzo viene indicata (voce n. {k})").format(k=k + 1),
              frg.esito_breve(r) == "mancanti" and mm[0].get("da_n") == k + 1 and mm[0].get("quante") == 1,
              tr("mancanti: {m}").format(m=mm))
        r = prova("tolte_fondo", lines[:-3])
        check(tr("verifica del registro: righe tolte alla fine, senza hash finale: non scopribili (catena integra)"),
              frg.esito_breve(r) == "integro", frg.esito_breve(r))
        r = prova("tolte_fondo_hash", lines[:-3], hf, nv)
        check(tr("verifica del registro: righe tolte alla fine scoperte con l'hash finale e le voci del report"),
              frg.esito_breve(r) == "mancanti_in_fondo" and (r.get("atteso") or {}).get("quante") == 3,
              str(r.get("atteso")))
        r = prova("aggiunte_dopo", lines + [lines[-1]], hf, nv)
        check(tr("verifica del registro: righe aggiunte dopo il report non sono una manomissione delle righe di allora"),
              (r.get("atteso") or {}).get("esito") == "trovato", str((r.get("atteso") or {}).get("esito")), interno=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def controlli_report_strumenti(case, txt, check):
    """(2.20) Report: i casi smartphone elencano solo gli strumenti usati (niente Sleuth Kit, metodo = estrazione del file
    system); i casi dei dischi restano come prima."""
    if not fa.is_mobile(case):
        check(tr("report del disco: metodo con The Sleuth Kit"), tr("L'analisi è stata condotta su copia in sola lettura con The Sleuth Kit") in txt, "")
        return
    import forense_mobile_chat as fmc
    usati = fmc.strumenti_usati(case)
    lp = case.meta.get("leapp") or {}
    ok = ("Sleuth Kit" not in txt and "sleuthkit" not in txt and "plaso" not in txt.lower().split(tr("## Artefatti con iLEAPP/ALEAPP"))[0]
          and tr("L'analisi è stata condotta sull'estrazione del file system del telefono") in txt)
    if lp.get("esito") == "ok":
        ok = ok and f"{lp.get('strumento')}: {lp.get('versione')}, " in txt and (lp.get("impronta") or "") in txt
    for v in case.meta.get("sysdiagnose") or []:
        ok = ok and v.get("sha256", "") in txt
    if case.meta.get("portachiavi"):
        ok = ok and case.meta["portachiavi"].get("sha256", "") in txt
    check(tr("report dello smartphone: solo gli strumenti usati, metodo dell'estrazione"), ok,
          ", ".join(k for k, _v in usati), interno=True)


def controlli_sysdiagnose(case, con, a, check):
    """(2.20) Sysdiagnose forniti a parte: SHA-256 nel caso e nel registro, nessuna copia nel caso, data di creazione e
    dispositivo dal nome, righe di iLEAPP nel gruppo «Sysdiagnose» marcate con il nome del file, processi di ps.txt
    contati senza iLEAPP, togli e rimetti."""
    import forense_mobile_sysdiagnose as fms
    reg = {v.get("sha256"): v for v in fms.elenco(case)}
    log = [json.loads(x) for x in case.log_path.read_text(encoding="utf-8").splitlines() if x.strip()]
    for s in a["sysdiagnose"]:
        v = reg.get(s["sha256"]) or {}
        in_log = any(x.get("event") == "sysdiagnose" and (x.get("data") or {}).get("sha256") == s["sha256"] for x in log)
        check(tr("sysdiagnose {f}: SHA-256 nel caso e nel registro a catena").format(f=s["file"][:40]), bool(v) and in_log, s["sha256"][:16])
        copie = [p for p in case.root.rglob("*") if p.is_file() and p.name == s["file"]]
        check(tr("sysdiagnose {f}: non copiato nel caso").format(f=s["file"][:40]), not copie, ", ".join(str(p) for p in copie[:3]), interno=True)
        check(tr("sysdiagnose {f}: data di creazione e dispositivo").format(f=s["file"][:40]),
              v.get("creato_utc") == s["creato_utc"] and v.get("build") == s["build"] and v.get("dispositivo") == s["dispositivo"],
              tr("{c}, {d}").format(c=v.get("creato_utc"), d=fms.descrivi_dispositivo(v)))
        il = v.get("ileapp") or {}
        if il.get("esito") != "ok":
            check(tr("sysdiagnose {f}: letto con iLEAPP").format(f=s["file"][:40]), False, str(il.get("esito") or tr("non eseguito")), misura=not il)
            continue
        rows = con.execute("SELECT grp, sub, data FROM artifacts WHERE cat='leapp' AND (CASE WHEN json_valid(data) THEN "
                           "json_extract(data, '$.sysdiagnose_sha256') END) = ?", (s["sha256"],)).fetchall()
        marc = tr("da sysdiagnose {n}").format(n=s["file"])
        ok = bool(rows) and all(r[0] == fms.GRUPPO and (json.loads(r[2]).get("campi") or {}).get(tr("Origine")) == marc for r in rows)
        check(tr("sysdiagnose {f}: righe nel gruppo «Sysdiagnose» marcate con il nome del file").format(f=s["file"][:40]), ok,
              tr("{n} righe").format(n=len(rows)))
        for art, n in (s.get("righe_min") or {}).items():
            got = sum(1 for r in rows if r[1] == art)
            check(tr("sysdiagnose: «{art}» = processi di ps.txt contati senza iLEAPP ({n})").format(art=art, n=n),
                  got == n if s.get("righe_esatte") else got >= n, tr("righe {g}").format(g=got))
    if len(reg) >= 2:                    # togli e rimetti: solo le righe di quel sysdiagnose
        s = a["sysdiagnose"][-1]
        prima = con.execute("SELECT COUNT(*) FROM artifacts WHERE cat='leapp'").fetchone()[0]
        n = fms.togli(case, con, s["sha256"])
        dopo = con.execute("SELECT COUNT(*) FROM artifacts WHERE cat='leapp'").fetchone()[0]
        altri = con.execute("SELECT COUNT(*) FROM artifacts WHERE grp=?", (fms.GRUPPO,)).fetchone()[0]
        check(tr("sysdiagnose: «Togli» toglie solo le righe di quel file"), n > 0 and prima - dopo == n and altri > 0,
              tr("tolte {n}, restano {r} righe di altri sysdiagnose").format(n=n, r=altri), interno=True)


def controlli_righe_tsv(check):
    """TSV di iLEAPP come li scrive su Windows (righe chiuse da \\r\\r\\n): nessuna riga vuota nel caso, su ogni sistema."""
    import forense_mobile_leapp as fml
    d = Path(tempfile.mkdtemp(prefix="repertia_tsv_"))
    con = fa.sqlite3.connect(":memory:")
    try:
        con.execute("CREATE TABLE artifacts(id INTEGER PRIMARY KEY, cat TEXT, ts TEXT, title TEXT, detail TEXT, user TEXT, "
                    "src_path TEXT, part INTEGER, inode TEXT, data TEXT)")
        (d / "_TSV Exports").mkdir()
        (d / "_TSV Exports" / "Prova.tsv").write_bytes("\ufeffColonna\tValore\r\r\na\t1\r\r\nb\t2\r\r\nc\t3\r\r\n".encode("utf-8"))
        res = fml.import_tsv(con, d, "iLEAPP", 0)[0]
        n = con.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
        check(tr("TSV di iLEAPP scritto su Windows: 3 righe nel file, 3 nel caso"), n == 3 and res.get("Prova") == 3,
              tr("righe {got}").format(got=n), interno=True)
    finally:
        con.close()
        shutil.rmtree(d, ignore_errors=True)


def controlli_chiamate_chat(con, check):
    """Chiamate WhatsApp nella chat (lette da call_log o CallHistory.sqlite dell'app): ognuna ha la sua riga nelle
    Chiamate (stessa tabella e riga della fonte), lo stesso orario e la stessa durata, e sta nella conversazione del
    contatto della chiamata."""
    import forense_mobile_chat as fmc
    try:
        msgs = con.execute("SELECT m.ts, m.src_table, m.src_row, m.extra, t.key FROM chat_messages m JOIN chat_threads t "
                           "ON t.id = m.thread WHERE m.kind = 'chiamata'").fetchall()
    except fa.sqlite3.Error:
        return
    if not msgs:
        return
    fonti = {}
    for (d,) in con.execute("SELECT data FROM artifacts WHERE cat='chiamate'"):
        c = json.loads(d or "{}")
        for f in c.get("fonti") or []:
            if f.get("strumento") == "RepertIA" and f.get("tabella"):
                fonti[(f["tabella"], f.get("riga"))] = c
    bad = []
    for ts, tb, row, ex, key in msgs:
        c, e = fonti.get((tb, row)), json.loads(ex or "{}")
        if not c:
            bad.append(f"{tb}#{row}: " + tr("non nelle Chiamate"))
        elif c.get("ts") != ts or c.get("durata_s") != e.get("durata_s") or fmc.norm_number(key) != fmc.norm_number(c.get("numero") or ""):
            bad.append(f"{tb}#{row}: {ts} {e.get('durata_s')} {key} ≠ {c.get('ts')} {c.get('durata_s')} {c.get('numero')}")
    check(tr("chiamate WhatsApp nella chat: {n} eventi con riga, orario, durata e contatto uguali alle Chiamate").format(n=len(msgs)),
          not bad, "; ".join(bad[:3]))


def controlli_fase4(case, con, check):
    """(2.20) Foto e video ↔ chat, Solo foto/Solo video, avvisi di WhatsApp, backup WhatsApp decifrati (con un backup
    FINTO costruito qui con una chiave inventata: i backup veri non si possono distribuire)."""
    import forense_gui as G
    import forense_mobile_gui as fmg
    if fa.table_exists(con, "meta"):
        tot = con.execute("SELECT COUNT(*) FROM meta").fetchone()[0]
        nf_ = con.execute("SELECT COUNT(*) FROM meta WHERE " + G.photo_where(), G.photo_args()).fetchone()[0]
        nv = con.execute("SELECT COUNT(*) FROM meta WHERE " + G.video_where(), G.video_args()).fetchone()[0]
        both = con.execute(f"SELECT COUNT(*) FROM meta WHERE {G.photo_where()} AND {G.video_where()}",
                           G.photo_args() + G.video_args()).fetchone()[0]
        check(tr("Foto e metadati: «Solo foto» e «Solo video» senza sovrapposizioni (foto {f}, video {v}, su {t})").format(
            f=nf_, v=nv, t=tot), both == 0 and nf_ + nv <= tot, tr("in comune {n}").format(n=both), interno=True)
        cm = fmg.meta_counts(con)
        if cm["n"]:
            w, a = [], []
            fmg.meta_filter(con, {"orig": "*"}, w, a)
            rows = con.execute("SELECT part, inode FROM meta WHERE " + " AND ".join(w), a).fetchall()
            bad = [f"{p}/{i}" for p, i in rows if not fmg.origine(case, {"part": p, "inode": i})["origine"]]
            check(tr("Foto e metadati «Dalle chat»: {n} file, ognuno con il messaggio di origine").format(n=len(rows)),
                  len(rows) == cm["n"] and not bad, "; ".join(bad[:3]), interno=True)
    st = G.requirements()["strumenti"]
    manca = [x["nome"] for x in st if not x["ok"] and not x.get("facoltativo")]
    check(tr("strumenti: elenco completo con iLEAPP e ALEAPP, stato di ciascuno; mancanti: {m}").format(m=", ".join(manca) or "-"),
          len(st) >= 25 and {"ileapp", "aleapp", "7zip", "pypff"} <= {x["id"] for x in st} and all(isinstance(x["ok"], bool) for x in st), "", interno=True)
    # (3.0) Documenti e Foto/Video/Audio: dimensione e date del file, con il filtro per dimensione e l'ordinamento
    for sez, tab in (("doc", "doc_text"), ("meta", "meta")):
        if not fa.table_exists(con, tab) or not con.execute(f"SELECT 1 FROM {tab} WHERE source IN ('fs', 'carving') LIMIT 1").fetchone():
            continue
        for _ in range(600):        # l'indice di navigazione si prepara in un thread
            if G.ensure_nav(case)["state"] != "building":
                break
            time.sleep(0.5)
        r = G.results(case, {"kind": sez}, limit=None)["rows"]
        con_dim = [x["size"] for x in r if x.get("source") in ("fs", "carving") and x.get("size") is not None]
        soglia = max(con_dim) if con_dim else 0
        filt = G.results(case, {"kind": sez, "cf": json.dumps({"size": {"min": soglia}})}, limit=None)["rows"]
        ord_ = G.results(case, {"kind": sez, "sk": "size", "sd": "desc"}, limit=None)["rows"]
        check(tr("{sez}: dimensione e date dei file, filtro per dimensione e ordinamento ({n} file con dimensione)").format(sez=sez, n=len(con_dim)),
              bool(con_dim) and (any(x.get("mtime") for x in r) or not any(x.get("source") == "fs" for x in r)) and bool(filt) and all(x["size"] >= soglia for x in filt)
              and ord_[0]["size"] == soglia, f"{len(filt)}/{len(r)}", interno=True)
    # (2.20) sottovoce «Audio» di Foto/Video/Audio: i file audio dall'elenco dei file, quelli delle chat con il messaggio
    mf = G.media_contenuto(case, con)      # (3.0.1) audio riconosciuti dal contenuto
    na = con.execute("SELECT COUNT(*) FROM files WHERE type LIKE '%/r' AND " + (mf.filtro("audio") if mf else G.audio_where())).fetchone()[0]
    if na:
        r = G.results(case, {"kind": "meta", "aud": "1"}, limit=None)
        ok_ext = all((x.get("mtipo") == "audio") if mf else Path(x["path"]).suffix.lower() in G.AUDIO_EXT for x in r["rows"])
        check(tr("Foto/Video/Audio «Audio»: {n} file audio dell'estrazione, tutti nell'elenco").format(n=na),
              r["total"] == na and ok_ext, tr("nell'elenco {n}").format(n=r["total"]), interno=True)
        ca = fmg.media_counts(con, "files", "type LIKE '%/r' AND " + mf.filtro("audio"), [],
                              "t.type LIKE '%/r' AND " + mf.filtro("audio", "t.part", "t.inode")) if mf else \
            fmg.media_counts(con, "files", "type LIKE '%/r' AND " + G.audio_where(), [])
        if ca["n"]:
            rc = G.results(case, {"kind": "meta", "aud": "1", "orig": "*"}, limit=None)
            bad = [x["path"] for x in rc["rows"] if not fmg.origine(case, {"part": x["part"], "inode": x["inode"]})["origine"]]
            check(tr("Foto/Video/Audio «Audio › Dalle chat»: {n} file, ognuno con il messaggio di origine").format(n=rc["total"]),
                  rc["total"] == ca["n"] == sum(n for _, n in ca["app"]) and not bad, "; ".join(bad[:3]), interno=True)
    try:
        r = con.execute("SELECT COUNT(*), SUM(direction='out'), (SELECT COUNT(*) FROM chat_receipts c JOIN chat_messages x ON "
                        "x.id = c.msg WHERE x.kind='sistema' AND x.app='whatsapp') FROM chat_messages WHERE app='whatsapp' "
                        "AND kind='sistema'").fetchone()
    except fa.sqlite3.Error:
        r = None
    if r and r[0]:
        check(tr("WhatsApp: {n} avvisi di sistema, nessuno «inviato» e senza ricevute").format(n=r[0]), not r[1] and not r[2],
              tr("inviati {a}, ricevute {b}").format(a=r[1], b=r[2]), interno=True)
    # (2.20) avvisi di WhatsApp iOS (ChatStorage.sqlite, tipi 6 e 10): di sistema, con valori registrati e senza ricevute
    try:
        r = con.execute("SELECT COUNT(*), SUM(direction != 'sys'), SUM(json_extract(extra, '$.avviso.db') IS NOT "
                        "'ChatStorage.sqlite'), (SELECT COUNT(*) FROM chat_receipts c JOIN chat_messages x ON x.id = c.msg "
                        "WHERE x.app='whatsapp' AND x.src_table='ZWAMESSAGE' AND json_extract(x.extra, '$.codice') IN (6, 10)) "
                        "FROM chat_messages WHERE app='whatsapp' AND src_table='ZWAMESSAGE' "
                        "AND json_extract(extra, '$.codice') IN (6, 10)").fetchone()
    except fa.sqlite3.Error:
        r = None
    if r and r[0]:
        check(tr("WhatsApp iOS: {n} avvisi di sistema (tipi 6 e 10), tutti «di sistema», con i valori registrati e senza ricevute").format(n=r[0]),
              not r[1] and not r[2] and not r[3], tr("non di sistema {a}, senza dettaglio {b}, ricevute {c}").format(a=r[1], b=r[2], c=r[3]),
              interno=True)
    # (2.20) WhatsApp iOS: «letto» (ZSENTDATE) solo sui messaggi ricevuti, con la fonte, mai prima della ricezione - 5 s
    try:
        r = con.execute("SELECT COUNT(*), SUM(direction != 'in'), SUM(json_extract(extra, '$.letto_fonte') IS NOT "
                        "'ZWAMESSAGE.ZSENTDATE'), SUM(read_ts < datetime(ts, '-5 seconds')) FROM chat_messages "
                        "WHERE app='whatsapp' AND src_table='ZWAMESSAGE' AND read_ts IS NOT NULL").fetchone()
    except fa.sqlite3.Error:
        r = None
    if r and r[0]:
        check(tr("WhatsApp iOS: {n} messaggi ricevuti con l'ora di lettura su questo telefono (ZSENTDATE), solo ricevuti e con la fonte").format(n=r[0]),
              not r[1] and not r[2] and not r[3], tr("non ricevuti {a}, senza fonte {b}, lettura prima della ricezione {c}").format(a=r[1], b=r[2], c=r[3]),
              interno=True)
    controlli_wa_backup(case, check)
    controlli_crypt15(case, check)
    controlli_media(case, con, check)


def controlli_media_dftt8(t, con, check):
    """(3.0.1) DFTT 8 (NTFS): secondo la documentazione del test, alloc/file2.dat è un JPEG con l'estensione sbagliata e
    del2/file7.hmm un JPEG cancellato con un'estensione inventata: per estensione restavano fuori da Foto."""
    if t.get("nome") != "DFTT_08_NTFS_JPEG" or not fa.table_exists(con, "media_file"):
        return
    got = {p: (tp, m) for p, tp, m in con.execute("SELECT path, tipo, metodo FROM media_file")}
    for p in ("alloc/file2.dat", "del2/file7.hmm"):
        check(tr("DFTT 8: {p} tra le foto, riconosciuto dal contenuto").format(p=p), got.get(p) == ("foto", "contenuto"),
              str(got.get(p) or tr("assente")))


def controlli_media(case, con, check):
    """(3.0.1) Foto, video e audio riconosciuti dal contenuto: la firma letta di nuovo dal file, ogni file con la sua app,
    nessun file con l'estensione di una foto o di un video lasciato fuori, elenchi e voci per app con gli stessi numeri."""
    import forense_gui as G
    import forense_mobile as fm
    import forense_mobile_media as fmm
    mf = G.media_contenuto(case, con)
    if not mf:
        if "media" in (case.meta.get("indice") or {}):      # indicizzazione della 3.0.1 (telefoni e dischi)
            check(tr("foto, video e audio riconosciuti dal contenuto (indicizzazione della 3.0.1)"), False, tr("elenco assente"), interno=True)
        return
    rows = con.execute("SELECT part, inode, path, tipo, formato, metodo, app FROM media_file ORDER BY random() LIMIT 300").fetchall()
    if not rows and not con.execute("SELECT COUNT(*) FROM meta WHERE " + G.photo_where() + " OR " + G.video_where(),
                                    G.photo_args() + G.video_args()).fetchone()[0]:
        return                  # estrazione senza foto, video né audio (es. le prove del portachiavi)
    bad = []
    leggi = fmm.lettore(case)
    for part, inode, path, tipo, fmt, metodo, app in rows:
        f = fmm.riconosci(case, part, inode, Path(path).suffix.lower(), leggi)
        # «estensione» con una firma di un altro tipo: solo un file cancellato il cui contenuto non è verificabile (dischi)
        if not app or (metodo == "contenuto" and f != (tipo, fmt)) or (metodo == "estensione" and ((f and f[0] == tipo) or fmm.EXT_TIPO.get(Path(path).suffix.lower()) != tipo)):
            bad.append(f"{path}: {tipo}/{fmt}/{metodo} ≠ {f}")
    tot = con.execute("SELECT COUNT(*), SUM(metodo='contenuto'), SUM(area='cache') FROM media_file").fetchone()
    check(tr("foto, video e audio per contenuto: {n} file ({c} dal contenuto, {k} nelle cache), firma riletta e app di {m} a caso").format(
        n=tot[0], c=tot[1], k=tot[2], m=len(rows)), bool(rows) and not bad, "; ".join(bad[:3]), interno=True)
    scambiati = [p for p, t in con.execute("SELECT path, tipo FROM media_file WHERE tipo = 'video'")
                 if fmm.EXT_TIPO.get(Path(p).suffix.lower()) == "audio"]
    check(tr("audio in contenitore MP4 (es. .m4a) riconosciuti come audio, non come video"), not scambiati, "; ".join(scambiati[:3]), interno=True)
    fuori = con.execute("SELECT COUNT(*) FROM meta WHERE source = 'fs' AND (" + G.photo_where() + " OR " + G.video_where() + ") AND (part, inode) NOT IN "
                        "(SELECT part, inode FROM media_file)", G.photo_args() + G.video_args()).fetchone()[0]
    check(tr("foto e video per estensione: tutti anche nell'elenco per contenuto"), fuori == 0, tr("fuori {n}").format(n=fuori), interno=True)
    rt = G.res_tree(case)
    pa = rt.get("mediaapp") or {}
    for k, tipo, flt in (("foto", "foto", {"foto": "1"}), ("video", "video", {"vid": "1"}), ("audio", "audio", {"aud": "1"})):
        n = rt.get(k) or 0
        somma = sum(x[2] for x in pa.get(tipo, []))
        r = G.results(case, {"kind": "meta", **flt}, limit=None)
        if not n:
            continue
        app0 = (pa.get(tipo) or [[None]])[0][0]
        ra = G.results(case, {"kind": "meta", **flt, "mapp": app0}, limit=None)
        check(tr("Foto/Video/Audio «{k}»: {n} file, elenco, somma delle voci per app e voce «{a}» uguali").format(k=k, n=n, a=fmm.etichetta(app0)),
              r["total"] == n == somma and all(x.get("mtipo") == tipo for x in r["rows"]) and ra["total"] == pa[tipo][0][2]
              and all(x.get("mapp") == app0 for x in ra["rows"]), tr("elenco {a}, somma {b}, voce {c}").format(a=r["total"], b=somma, c=ra["total"]),
              interno=True)
    senza = con.execute("SELECT part, inode, path FROM media_file WHERE tipo='foto' AND metodo='contenuto' AND formato IN ('jpg', 'png') "
                        "AND path NOT LIKE '%.jpg' AND path NOT LIKE '%.jpeg' AND path NOT LIKE '%.png' LIMIT 1").fetchone()
    if senza:
        v = G.view_info(case, {"source": "fs", "part": senza[0], "inode": senza[1]})
        check(tr("anteprima di una foto senza estensione (cache): mostrata come immagine"), v.get("type") == "image", senza[2], interno=True)


def controlli_telegram_chiamate(check):
    """(3.0.1) Chiamate di Telegram scritte come messaggi di servizio: formato di ALEAPP («[Phone call (…)]») e di iLEAPP
    («Action: <phoneCall (…)>»), con id, esito, durata e video come scritti; senza «video call» ALEAPP non dice il tipo."""
    import forense_mobile_leapp_chat as fmlc
    mp = fmlc.carica()
    sa, si = mp["chiamate"]["ALEAPP|Telegram - Messages"]["estrai"], mp["chiamate"]["iLEAPP|Telegram Messages"]["estrai"]
    a = fmlc._chiamata(sa, {"Message": "[Phone call (call id 1873875638318552256, outcome hung up, duration seconds 96)]"})
    b = fmlc._chiamata(sa, {"Message": "[Phone call (call id 6381608536058416468, outcome missed)]"})
    c = fmlc._chiamata(si, {"Action Data": "Action: <phoneCall (id=5859382380446882168, discard reason=hung up, duration (seconds)=109, video call=yes)>"})
    d = fmlc._chiamata(si, {"Action Data": "Action: <phoneCall (id=6381608536056868852, discard reason=hung up, duration (seconds)=105)>"})
    n = fmlc._chiamata(sa, {"Message": "Ti chiamo [Phone call] dopo"})
    ok = (a and a["id"] == "1873875638318552256" and a["esito"] == "hung up" and a["durata_s"] == 96 and a["video"] is None
          and b and b["esito"] == "missed" and b["durata_s"] is None and fmlc._esito_chiamata(sa, b, "in")[:2] == ("persa", False)
          and c and c["video"] is True and c["durata_s"] == 109 and d and d["video"] is False and n is None)
    check(tr("Telegram: chiamate dai messaggi di servizio di ALEAPP e iLEAPP (id, esito, durata, video), un testo qualsiasi non è una chiamata"),
          bool(ok), str([a, b, c, d, n]), interno=True)


def _crypt14_finto(db, key, iv, firma):
    """Backup crypt14 FINTO con lo stesso formato di quelli veri (intestazione protobuf, AES-GCM, zlib)."""
    import zlib
    import forense_mobile_wabackup as fmwb
    AES = fmwb._aes()

    def ld(n, b):
        return bytes([n << 3 | 2]) + _vint(len(b)) + b
    inner = ld(1, b"\x00\x01") + ld(2, b"2") + ld(3, firma) + ld(4, bytes(16)) + ld(5, iv)
    hdr = b"\x08\x00" + ld(2, inner) + ld(4, b"\x0a\x072.24.14")
    ct, tag = AES.new(key, AES.MODE_GCM, nonce=iv).encrypt_and_digest(zlib.compress(db))
    return _vint(len(hdr)) + hdr + ct + tag + bytes(16)


def _vint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def controlli_portatile_timeline(case, con, check):
    """(2.20) Report portatile: timeline in file per giorno (in parti da EV_PARTE eventi) con tutti gli eventi una volta
    sola, e la ricerca veloce nei risultati del caso nella pagina."""
    import forense_portatile as fpo
    n_db = con.execute("SELECT COUNT(*) FROM events WHERE ts > '1970' AND origin IN ('tsk','plaso')").fetchone()[0]
    if not n_db:
        return
    out = fpo.export_portable(case, {"contenuto": "scelti", "testi": False}, lambda *a, **k: None)
    root = Path(out["path"])
    info = json.loads((root / "dati" / "caso.js").read_text(encoding="ascii").split(",", 1)[1].rsplit(");", 1)[0])
    righe, troppe, giorni = 0, 0, set()
    for f in sorted((root / "dati" / "eventi").rglob("*.js")):
        d = json.loads(f.read_text(encoding="ascii").split(",", 1)[1].rsplit(");", 1)[0])
        righe += len(d["rows"])
        troppe += len(d["rows"]) > fpo.EV_PARTE
        giorni.add(d["d"])
        if any(not r[0].startswith(d["d"]) for r in d["rows"]):
            troppe += 1
    parti = info.get("ev_parts") or {}
    check(tr("report portatile: timeline in file per giorno, {n} eventi tutti presenti una volta").format(n=n_db),
          righe == n_db and not troppe and set(parti) == giorni and sum(info["months"].values()) == n_db,
          tr("nei file {a}, nel caso {b}, file non conformi {c}").format(a=righe, b=n_db, c=troppe), interno=True)
    n_lp = con.execute("SELECT COUNT(*) FROM artifacts WHERE cat='leapp'").fetchone()[0] \
        if fa.table_exists(con, "artifacts") else 0
    if n_lp:
        est = json.loads((root / "dati" / "estese.js").read_text(encoding="ascii").split(",", 1)[1].rsplit(");", 1)[0])
        nf_ = 0
        for f in (root / "dati" / "leapp").rglob("*.js"):
            d = json.loads(f.read_text(encoding="ascii").split(",", 1)[1].rsplit(");", 1)[0])
            nf_ += sum(1 for r in d["rows"] if r[0] == "leapp")
        nest = sum(1 for r in est.get("art", []) if r[0] == "leapp")
        check(tr("report portatile: righe di iLEAPP/ALEAPP in file per artefatto caricati a richiesta ({n} righe)").format(n=n_lp),
              nf_ == n_lp and nest == 0 and est.get("leapp_n") == n_lp,
              tr("nei file {a}, nel caso {b}, rimaste nel file principale {c}").format(a=nf_, b=n_lp, c=nest), interno=True)
    html = (root / "index.html").read_text(encoding="utf-8")
    fmap = root / "dati" / "mappa.js"
    if fmap.exists():
        tm = fmap.read_text(encoding="ascii")
        check(tr("report portatile: mappa inclusa con i punti del caso e lo sfondo, senza richieste esterne"),
              (root / "dati" / "sfondo_mappa.js").exists() and '"punti"' in tm and "initMappa" in html and "maplibre-gl" not in html.lower(),
              "", interno=True)
    import forense_gui as Gt
    if fa.table_exists(con, "chat_messages"):
        n_m = con.execute("SELECT COUNT(*) FROM chat_messages WHERE ts GLOB '[0-9][0-9][0-9][0-9]-*'").fetchone()[0]
        h_m = sum(b["n"] for b in Gt.tl_hist(case, {"origin": "msg:"})["bins"])
        r_m = Gt.tl_evidenze_pagina(case, {"origin": "msg:"}, None, 0, 50)["total"]
        check(tr("Timeline per evidenza: tabella e grafico contano tutti i {n} messaggi con una data").format(n=n_m), h_m == n_m == r_m, f"{h_m}/{r_m}", interno=True)
    if fa.table_exists(con, "artifacts"):       # anche sui casi disco, i cui artefatti non hanno gruppo e voce
        n_a = con.execute("SELECT COUNT(*) FROM artifacts WHERE cat <> 'messaggi' AND ts GLOB '[0-9][0-9][0-9][0-9]-*'").fetchone()[0]
        r_a = Gt.tl_evidenze_pagina(case, {"origin": "ev:[]"}, None, 0, 50)
        h_a = sum(b["n"] for b in Gt.tl_hist(case, {"origin": "ev:[]"})["bins"])
        check(tr("Timeline per evidenza: tabella e grafico contano tutti i {n} artefatti con una data").format(n=n_a), h_a == n_a == r_a["total"] and len(r_a["rows"]) == min(n_a, 50), f"{h_a}/{r_a['total']}", interno=True)
    # (3.0) filtri di colonna sulle fonti per evidenza: i valori ci sono, sommano al totale e filtrano tabella e grafico
    fonti = (["msg:"] if fa.table_exists(con, "chat_messages") else []) + (["ev:[]"] if fa.table_exists(con, "artifacts") else [])
    if [x for x in fa.bookmarks_timeline(case, False) if x["ts"]]:
        fonti.append("preferiti")
    for o in fonti:
        tot, male = Gt.results(case, {"kind": "timeline", "origin": o})["total"], []
        for col in ("kind", "source", "detail"):
            vals = Gt.results(case, {"kind": "timeline", "origin": o, "cfv": col})["values"]
            if (sum(v[1] for v in vals) != tot and col != "detail") or (tot and not vals):
                male.append(col)
            if vals:
                fq = {"kind": "timeline", "origin": o, "cf": json.dumps({col: {"sel": [vals[0][0]]}})}
                if Gt.results(case, dict(fq))["total"] != vals[0][1] or sum(b["n"] for b in Gt.tl_hist(case, dict(fq))["bins"]) != vals[0][1]:
                    male.append(col + "=" + str(vals[0][0]))
        check(tr("Timeline per evidenza: i filtri di colonna elencano i valori e filtrano tabella e grafico ({o}, {n} righe)").format(o=o, n=tot), not male, ",".join(male), interno=True)
    # (3.0) pagine dell'agente: scorrendole si vede ogni riga una volta e la fine è dichiarata
    ta = fa.make_tools(case)
    if "query_artifacts" in ta and fa.table_exists(con, "artifacts"):
        n_a, off, viste, fine = con.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0], 0, [], False
        for _ in range(2000):
            t = ta["query_artifacts"](limit=7, offset=off).split("\n")
            nota = next((x for x in t if re.match(r"\S+ \d+–\d+", x)), "")
            righe = t[t.index(nota) + 1:] if nota in t else []
            if not righe:
                break
            viste += righe
            off += len(righe)
            if "=" not in nota:
                fine = True
                break
        conti = sum(int(x.rsplit(": ", 1)[1]) for x in ta["count_artifacts"]().split("\n")[1:]) if "count_artifacts" in ta else n_a
        check(tr("Agente: le pagine di artefatti e messaggi coprono ogni riga una volta sola e i conteggi coincidono ({n} righe)").format(n=n_a),
              off == n_a and conti == n_a and (fine or not n_a), f"{off}/{conti}", interno=True)
    # (3.0.1) ogni dato del caso che si vede nell'interfaccia arriva anche all'agente: tabella con righe -> suo strumento
    copre = {"files": "find_files", "events": "query_timeline", "doc_text": "search_text", "artifacts": "query_artifacts",
             "chat_messages": "read_chat", "mail": "search_emails", "xitems": "list_extracted", "anomalies": "list_anomalies",
             "carved": "carved_files", "features": "search_traces", "hashes": "find_by_hash", "media_file": "list_media"}
    manca = [f"{tb} ({s})" for tb, s in copre.items() if s not in ta and fa.table_exists(con, tb)
             and con.execute(f"SELECT 1 FROM {tb} LIMIT 1").fetchone()]
    check(tr("Agente: ogni tipo di dato presente nel caso ha il suo strumento ({n} strumenti)").format(n=len(ta)), not manca,
          ", ".join(manca), interno=True)
    if "read_chat" in ta and fa.table_exists(con, "chat_receipts"):
        r = con.execute("SELECT c.msg FROM chat_receipts c ORDER BY c.id LIMIT 1").fetchone()
        if r:
            t = ta["read_message"](r[0])
            check(tr("Agente: le ricevute di consegna e lettura arrivano con il messaggio, con la fonte"), "    ✓ " in t, t[-120:], interno=True)
    html_p = (Path(out["path"]) / "index.html").read_text(encoding="utf-8", errors="replace")
    n_doc = con.execute("SELECT COUNT(*) FROM doc_text").fetchone()[0] if fa.table_exists(con, "doc_text") else 0
    docs_p = (Path(out["path"]) / "dati" / "documenti.js").read_text(encoding="ascii")
    check(tr("report portatile: albero delle sezioni, Documenti ({n}) ed elenco dei file inclusi con dimensione e date").format(n=n_doc),
          "function navBuild" in html_p and 'id="attList"' in html_p and "datiFile(m[1], m[2])" in html_p
          and len(json.loads(docs_p[docs_p.index(",") + 1:docs_p.rindex(")")])) == n_doc, str(n_doc), interno=True)
    check(tr("report portatile: ricerca veloce nei risultati del caso presente"),
          'value="fast"' in html and "fastSearchP" in html, "", interno=True)


def controlli_lid(check):
    """(3.0) LID di WhatsApp e numero: solo coppie scritte da WhatsApp, in conversazioni, mittenti e rubrica; ripetibile."""
    import sqlite3
    import forense_mobile_chat as fmc
    db = sqlite3.connect(":memory:")
    db.executescript("""CREATE TABLE jid(_id INTEGER PRIMARY KEY, raw_string TEXT); CREATE TABLE jid_map(lid_row_id INTEGER, jid_row_id INTEGER);
        INSERT INTO jid VALUES (1, '205690463334636@lid'), (2, '390000000001@s.whatsapp.net'), (3, '999999999999999@lid');
        INSERT INTO jid_map VALUES (1, 2);
        CREATE TABLE ZWAADDRESSBOOKCONTACT(ZFULLNAME TEXT, ZWHATSAPPID TEXT, ZPHONENUMBER TEXT, ZLID TEXT);
        INSERT INTO ZWAADDRESSBOOKCONTACT VALUES ('Anna', '390000000002@s.whatsapp.net', NULL, '111111111111111@lid'), ('Solo LID', NULL, NULL, '222222222222222@lid');""")
    coppie = fmc.lid_da_db(db)
    check(tr("LID di WhatsApp: si leggono solo le coppie registrate (jid_map, ZLID), mai dedotte"),
          {x[:2] for x in coppie} == {("205690463334636@lid", "390000000001@s.whatsapp.net"), ("111111111111111@lid", "390000000002@s.whatsapp.net")},
          str(coppie), interno=True)
    con = sqlite3.connect(":memory:")
    fmc.ensure_schema(con)
    con.executemany("INSERT INTO chat_lid VALUES (?,?,?)", [(a, b, "msgstore.db · " + c) for a, b, c in coppie])
    con.execute("INSERT INTO chat_threads(id, app, key, title, participants) VALUES (1, 'whatsapp', '205690463334636@lid', '205690463334636@lid', '[\"205690463334636@lid\"]')")
    con.execute("INSERT INTO chat_messages(thread, app, sender) VALUES (1, 'whatsapp', '205690463334636@lid')")
    con.execute("INSERT INTO chat_contacts(source, name, value, norm) VALUES ('c', 'Anna', '111111111111111@lid', '111111111111111@lid')")
    fmc.lid_applica(con)
    primo = [con.execute(q).fetchone() for q in ("SELECT title, participants FROM chat_threads", "SELECT sender, sender_name FROM chat_messages", "SELECT value, norm FROM chat_contacts WHERE name = 'Anna'", "SELECT COUNT(*) FROM chat_contacts")]
    fmc.lid_applica(con)
    secondo = [con.execute(q).fetchone() for q in ("SELECT title, participants FROM chat_threads", "SELECT sender, sender_name FROM chat_messages", "SELECT value, norm FROM chat_contacts WHERE name = 'Anna'", "SELECT COUNT(*) FROM chat_contacts")]
    check(tr("LID di WhatsApp: conversazione, mittente e rubrica mostrano LID e numero, il valore grezzo resta, si può ripetere"),
          "+390000000001" in primo[0][0] and "205690463334636@lid (+390000000001)" in primo[0][1] and primo[1] == ("205690463334636@lid", "+390000000001")
          and primo[2] == ("111111111111111@lid (+390000000002)", fmc.norm_number("390000000002")) and primo[3][0] == 2 and primo == secondo, str(primo), interno=True)


def controlli_chiamate_wa(check):
    """(3.0.1) Chiamate WhatsApp Android: esiti 2 (non risposta) e 4 (rifiutata) di call_log, contatto col LID tradotto nel
    numero registrato da WhatsApp, chiamata col LID nella chat che ha il numero, sottovoci «esito › voce/video»."""
    import sqlite3
    import forense_mobile_chat as fmc
    import forense_mobile_chiamate as fmca
    import forense_mobile_leapp_chat as fmlc

    class W0:
        db = sqlite3.connect(":memory:")

        def tables(self):
            return {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    w = W0()
    w.db.row_factory = sqlite3.Row
    w.db.executescript("""CREATE TABLE jid(_id INTEGER PRIMARY KEY, raw_string TEXT);
        INSERT INTO jid VALUES (1, '205690463334636@lid'), (2, '390000000001@s.whatsapp.net');
        CREATE TABLE call_log(_id INTEGER PRIMARY KEY, jid_row_id INTEGER, from_me INTEGER, call_id TEXT, timestamp INTEGER,
                              video_call INTEGER, duration INTEGER, call_result INTEGER);
        INSERT INTO call_log VALUES (1, 1, 0, 'a', 1717000000000, 0, 0, 2), (2, 1, 1, 'b', 1717000600000, 1, 0, 2),
                                    (3, 2, 0, 'c', 1717001200000, 1, 0, 4), (4, 1, 1, 'd', 1717001800000, 0, 65, 5);""")
    recs = fmca.wa_android(w, (0, "1", "data/data/com.whatsapp/databases/msgstore.db"))
    con = sqlite3.connect(":memory:")
    fmc.ensure_schema(con)
    con.execute("INSERT INTO chat_lid VALUES ('205690463334636@lid', '390000000001@s.whatsapp.net', 'msgstore.db · jid_map')")
    W = fmc.Writer(con, "whatsapp", 0, 1, "msgstore.db")
    W.thread("390000000001@s.whatsapp.net", "Anna", ["390000000001@s.whatsapp.net"])
    n_chat = fmca.nella_chat(W, recs, "call_log")
    n_lid = fmlc.risolvi_lid(con, recs)
    sotto = [fmlc.sotto_chiamata(r) for r in recs]
    check(tr("Chiamate WhatsApp: esiti 2 e 4 di call_log, LID tradotto nel numero registrato, chiamate col LID nella chat del numero, sottovoci per esito e voce/video"),
          [r["risposta"] for r in recs] == [False, False, False, True] and n_chat == 4 and n_lid == 3
          and {r["numero"] for r in recs} == {"390000000001@s.whatsapp.net"} and recs[0]["lid"] == "205690463334636@lid"
          and sotto == [tr("Non risposte") + " › " + tr("Voce"), tr("Non risposte") + " › " + tr("Video"),
                        tr("Rifiutate") + " › " + tr("Video"), tr("Risposte") + " › " + tr("Voce")],
          f"{n_chat} {n_lid} {sotto}", interno=True)


def controlli_solo_chiamate(check):
    """(3.0.1) Chiamate WhatsApp con un contatto senza conversazione: conversazione «solo chiamate» (origin 'chiamate')
    col nome in rubrica e il numero (anche partendo dal LID), mai per i gruppi né per i backup."""
    import sqlite3
    import forense_mobile_chat as fmc
    import forense_mobile_chiamate as fmca

    def rec(jid, ts, riga):
        return {"chat": {"jid": jid}, "ts": ts, "verso": "in", "durata_s": 0, "tipo": "voce", "esito": None,
                "risposta": None, "fonti": [{"artefatto": "msgstore.db", "riga": riga}]}
    recs = [rec("390000000001@s.whatsapp.net", "2024-06-01T10:00:00", 1), rec("205690463334636@lid", "2024-06-01T11:00:00", 2),
            rec("390000000002@s.whatsapp.net", "2024-06-01T12:00:00", 3), rec("120363000000@g.us", "2024-06-01T13:00:00", 4)]
    esiti = []
    for solo in (True, False):
        con = sqlite3.connect(":memory:")
        fmc.ensure_schema(con)
        con.execute("INSERT INTO chat_lid VALUES ('205690463334636@lid', '390000000003@s.whatsapp.net', 'msgstore.db · jid_map')")
        W = fmc.Writer(con, "whatsapp", 0, 1, "msgstore.db")
        W.thread("390000000001@s.whatsapp.net", "Anna", ["390000000001@s.whatsapp.net"])
        n = fmca.nella_chat(W, recs, "call_log", {fmc.norm_number("390000000003"): "Bruno"}, solo_chiamate=solo)
        esiti.append((n, sorted(con.execute("SELECT title, origin FROM chat_threads WHERE origin IS NOT NULL").fetchall())))
    check(tr("Chiamate WhatsApp senza conversazione: conversazione «solo chiamate» a parte (nome e numero, anche dal LID), non per gruppi e backup"),
          esiti == [(3, [("+390000000002", "chiamate"), ("Bruno +390000000003", "chiamate")]), (1, [])], str(esiti), interno=True)


def controlli_recupero_wa(check):
    """(3.0.1) Messaggi e chiamate WhatsApp cancellati: letti dai byte del database (forense_recupero), uguali agli originali,
    segnati come recuperati, mai doppioni delle righe vive."""
    import shutil
    import sqlite3
    import tempfile
    import forense_mobile_chat as fmc
    import forense_mobile_chiamate as fmca
    tmp = Path(tempfile.mkdtemp(prefix="collaudo_rec_"))
    try:
        f = tmp / "db" / "msgstore.db"
        f.parent.mkdir()
        db = sqlite3.connect(str(f))
        db.executescript("""PRAGMA secure_delete = 0; PRAGMA auto_vacuum = 0;
            CREATE TABLE jid(_id INTEGER PRIMARY KEY, raw_string TEXT); INSERT INTO jid VALUES (1, '390000000001@s.whatsapp.net');
            CREATE TABLE message(_id INTEGER PRIMARY KEY AUTOINCREMENT, chat_row_id INTEGER, from_me INTEGER, key_id TEXT NOT NULL,
                                 timestamp INTEGER, message_type INTEGER, text_data TEXT);
            CREATE TABLE call_log(_id INTEGER PRIMARY KEY AUTOINCREMENT, jid_row_id INTEGER, from_me INTEGER, call_id TEXT,
                                  timestamp INTEGER, video_call INTEGER, duration INTEGER, call_result INTEGER);""")
        for i in range(30):
            db.execute("INSERT INTO message(chat_row_id, from_me, key_id, timestamp, message_type, text_data) VALUES (1, ?, ?, ?, 0, ?)",
                       (i % 2, f"KEY{i:02d}", 1717000000000 + i * 1000, f"messaggio di prova numero {i:02d}"))
            db.execute("INSERT INTO call_log(jid_row_id, from_me, call_id, timestamp, video_call, duration, call_result) VALUES (1, ?, ?, ?, ?, ?, ?)",
                       (i % 2, f"call:{i:02d}", 1717000000000 + i * 60000, i % 3 == 0, 0 if i % 4 else 30, (2, 4, 5)[i % 3]))
        db.commit()
        db.execute("DELETE FROM message WHERE key_id IN ('KEY05', 'KEY12', 'KEY20')")
        db.execute("DELETE FROM call_log WHERE call_id IN ('call:05', 'call:12', 'call:20')")
        db.commit()
        db.close()

        class W0:
            pass
        w = W0()
        w.tmp, w.file = f.parent, f
        w.db = sqlite3.connect(str(f))
        w.db.row_factory = sqlite3.Row
        w.tables = lambda: {r[0] for r in w.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        fmc._RECUPERO.clear()
        rec = fmc.recuperati_wa(w, (0, "1", "msgstore.db"))
        msg = sorted((d["key_id"], d["text_data"], d["timestamp"]) for d, _i in rec.get("message", []))
        calls = [r for r in fmca.wa_android(w, (0, "1", "msgstore.db")) if r.get("recuperato")]
        w.db.close()
        fmc._RECUPERO.clear()
        check(tr("WhatsApp: messaggi e chiamate cancellati letti dai byte del database, uguali agli originali e segnati come recuperati"),
              {k for k, _t, _s in msg} <= {"KEY05", "KEY12", "KEY20"} and len(msg) >= 2
              and all(t == f"messaggio di prova numero {k[3:]}" and s == 1717000000000 + int(k[3:]) * 1000 for k, t, s in msg)
              and len(calls) >= 2 and all(r["esito"] == tr(fmca.WA_AND_ESITO[(2, 4, 5)[int(r["chat"]["id"][5:]) % 3]])
                                          and tr("record cancellato") in r["fonti"][0]["artefatto"] for r in calls),
              f"{msg} {[(r['chat']['id'], r['esito']) for r in calls]}", interno=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def controlli_eliminati_recenti(check):
    """(3.0.2) iMessage cancellati dall'utente ma ancora in «Eliminati di recente» (sms.db di iOS 16 e successivi): riconosciuti
    da chat_recoverable_message_join, con la conversazione e la data della cancellazione; i messaggi normali no."""
    import sqlite3
    import forense_mobile_chat as fmc
    db = sqlite3.connect(":memory:")
    db.executescript("""CREATE TABLE message(ROWID INTEGER PRIMARY KEY, text TEXT);
        CREATE TABLE chat_message_join(chat_id INTEGER, message_id INTEGER);
        CREATE TABLE chat_recoverable_message_join(chat_id INTEGER, message_id INTEGER, delete_date INTEGER, ck_sync_state INTEGER);
        INSERT INTO message VALUES (1, 'normale'), (2, 'cancellato');
        INSERT INTO chat_message_join VALUES (7, 1);
        INSERT INTO chat_recoverable_message_join VALUES (7, 2, 743872096906034048, 0);""")
    r = fmc.eliminati_recenti(db)
    vuoto = sqlite3.connect(":memory:")
    vuoto.execute("CREATE TABLE message(ROWID INTEGER PRIMARY KEY)")
    check(tr("iMessage in «Eliminati di recente»: riconosciuti con conversazione e data della cancellazione"),
          r == {2: (7, "2024-07-28T15:08:16")} and fmc.eliminati_recenti(vuoto) == {}, str(r), interno=True)


def controlli_gps_segno(check):
    """(3.0) Il segno di latitudine e longitudine viene dalla direzione: Ovest e Sud sono negativi."""
    con_c = {"GPS:GPSLatitude": 35.6, "GPS:GPSLatitudeRef": "S", "GPS:GPSLongitude": 78.8, "GPS:GPSLongitudeRef": "W",
             "Composite:GPSLatitude": -35.6, "Composite:GPSLongitude": -78.8}
    senza = {k: v for k, v in con_c.items() if not k.startswith("Composite")}
    est = {"GPS:GPSLatitude": 35.6, "GPS:GPSLatitudeRef": "N", "GPS:GPSLongitude": 14.5, "GPS:GPSLongitudeRef": "E"}
    check(tr("coordinate delle foto: Sud e Ovest negativi, Nord ed Est positivi"),
          fa.gps_da(con_c) == (-35.6, -78.8) and fa.gps_da(senza) == (-35.6, -78.8) and fa.gps_da(est) == (35.6, 14.5), interno=True)


def controlli_ricerca_veloce(case, con, check):
    """(2.20) Ricerca veloce nei risultati del caso: indice costruito, un messaggio ritrovato da una parte del testo, un
    numero della rubrica ritrovato scritto in un altro formato, nessun valore segreto del portachiavi nell'indice."""
    import forense_ricerca_veloce as rv
    rv.costruisci(case, fa.db_ro)
    st = rv.stato(case) or {}
    ok = rv.aggiornato(case, con) and not st.get("errore")
    check(tr("ricerca veloce: indice dei risultati costruito ({n} righe)").format(n=st.get("fatte", 0)), ok,
          st.get("errore") or "", interno=True)
    if not ok:
        return
    if fa.table_exists(con, "chat_messages"):
        r = con.execute("SELECT id, text FROM chat_messages WHERE length(trim(text)) >= 14 ORDER BY id LIMIT 1").fetchone()
        if r:
            q = r[1].strip()[3:13]
            ids, tot, _x = rv.cerca_id(case, q, rv.MAX_SALVA)
            check(tr("ricerca veloce: messaggio ritrovato da una parte del testo («{q}», {n} risultati)").format(q=q, n=tot),
                  ("msg", r[0]) in {(f, int(i)) for f, i, _t in ids}, interno=True)
    # (3.0) confronto, ricerche corte, limite per fonte e fonti senza indice
    check(tr("ricerca veloce: maiuscole, accenti, apostrofi e spazi non contano nel confronto"),
          rv._piega(rv._spazi("PERCHÉ  It’s\nok")) == "perche it's ok", interno=True)
    if fa.table_exists(con, "chat_messages"):
        r = con.execute("SELECT id, text FROM chat_messages WHERE length(trim(text)) >= 2 ORDER BY id LIMIT 1").fetchone()
        if r:
            q = r[1].strip()[:2]
            ids, tot, _x = rv.cerca_id(case, q, rv.MAX_SALVA)
            check(tr("ricerca veloce: messaggio ritrovato con due soli caratteri («{q}», {n} risultati)").format(q=q, n=tot),
                  ("msg", r[0]) in {(f, int(i)) for f, i, _t in ids}, interno=True)
            ids, tot, _x = rv.cerca_id(case, q, 1)
            fonti = [f for f, _i, _t in ids]
            check(tr("ricerca veloce: il limite vale per fonte, una fonte non nasconde le altre"),
                  "msg" in fonti and len(fonti) == len(set(fonti)), ", ".join(fonti), interno=True)
    import forense_gui as G0
    for _ in range(600):        # l'albero si prepara in un thread
        if G0.ensure_nav(case)["state"] != "building":
            break
        time.sleep(0.5)
    nav = G0.nav_db(case)
    try:
        r = nav.execute("SELECT name FROM nav WHERE isdir = 0 AND type NOT LIKE 'v/%' AND length(name) >= 5 ORDER BY id LIMIT 1").fetchone()
        if r:
            gr, _non = rv.altri(con, nav, r[0])
            check(tr("ricerca veloce: file ritrovato dal nome («{q}»)").format(q=r[0]),
                  any(g["chiave"] == "file" and g["n"] for g in gr), interno=True)
    finally:
        nav.close()
    if fa.table_exists(con, "chat_contacts"):
        for cid, value in con.execute("SELECT id, value FROM chat_contacts WHERE value IS NOT NULL ORDER BY id"):
            d = re.sub(r"\D", "", value.split("@")[0])
            if len(d) >= 10:
                fmt = "+" + d[:-9] + " (" + d[-9:-6] + ") " + d[-6:-3] + "-" + d[-3:]
                ids, tot, _x = rv.cerca_id(case, fmt, rv.MAX_SALVA)
                check(tr("ricerca veloce: numero della rubrica ritrovato scritto in un altro formato ({a} → {b}, {n} risultati)")
                      .format(a=value, b=fmt, n=tot), ("rub", cid) in {(f, int(i)) for f, i, _t in ids}, interno=True)
                import forense_gui as G
                import forense_mobile_gui as fmg
                v = fmg.rub_view(G, case, {"id": cid})
                src = con.execute("SELECT source FROM chat_contacts WHERE id=?", (cid,)).fetchone()[0]
                check(tr("ricerca veloce: anteprima della voce della rubrica con valore e database di origine"),
                      v.get("valore") == value and v.get("src_path") == src and (not src or v.get("inode")),
                      f"{v.get('src_path')} · inode {v.get('inode')}", interno=True)
                break
    if fa.table_exists(con, "leapp_segreti"):
        trovati = []
        for (v,) in con.execute("SELECT valore FROM leapp_segreti WHERE length(valore) >= 4 LIMIT 200"):
            if rv.cerca_id(case, v, 1)[1]:
                trovati.append(v[:3] + "…")
        check(tr("ricerca veloce: nessun valore segreto del portachiavi nell'indice"), not trovati, ", ".join(trovati),
              interno=True)


def controlli_wa_backup(case, check):
    """Backup finto del msgstore.db dell'estrazione con un messaggio in più: decifrato uguale all'originale, rifiutato con
    un'altra chiave o un byte cambiato, letto come conversazioni «backup» con quel solo messaggio «solo nel backup»."""
    import tempfile
    import forense_mobile as fm
    import forense_mobile_chat as fmc
    import forense_mobile_wabackup as fmwb
    try:
        fmwb._aes()
    except ImportError:
        check(tr("backup WhatsApp: libreria AES (pycryptodome di iLEAPP/ALEAPP)"), False, tr("non trovata"), misura=True)
        return
    for p in fm.sorgenti(case):
        part = int(p["offset"])
        m = fm.mx(case)
        try:
            r = m.execute("SELECT id, path FROM mobile_files WHERE part=? AND isdir=0 AND path LIKE '%com.whatsapp/databases/msgstore.db'",
                          (part,)).fetchone()
        finally:
            m.close()
        if not r:
            continue
        w = fmc.WorkDB(case, part, str(r[0]), r[1], None)
        tmp = Path(tempfile.mkdtemp(prefix="collaudo_bk_", dir=str(case.root)))
        try:
            tab = "message" if w.db.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='message'").fetchone()[0] and \
                w.db.execute("SELECT COUNT(*) FROM message").fetchone()[0] else "messages"
            cols = [c[1] for c in w.db.execute(f"PRAGMA table_info({tab})") if c[1] != "_id"]
            w.db.execute(f"INSERT INTO {tab}({','.join(cols)}) SELECT {','.join('? ' if c == 'key_id' else c for c in cols)} "
                         f"FROM {tab} WHERE _id=(SELECT MAX(_id) FROM {tab})", ("REPERTIA-COLLAUDO-BACKUP",))
            w.db.commit()
            w.db.execute(f"VACUUM INTO '{(tmp / 'msgstore.db').as_posix()}'")
            db = (tmp / "msgstore.db").read_bytes()
            key, iv, firma = bytes(range(1, 33)), bytes(range(40, 56)), bytes(range(100, 132))
            keyfile = bytes.fromhex("aced0005757200025b42acf317f8060854e002000078700000008300") [:27] + b"\x00\x01\x02" + firma + bytes(64) + key
            bk = _crypt14_finto(db, key, iv, firma)
            raw, (es, _m) = fmwb.decifra(bk, keyfile)
            check(tr("backup WhatsApp finto: decifrato uguale al database di partenza (tag GCM verificato)"),
                  raw == db and es == "decifrato", es, interno=True)
            _r2, (es2, _m2) = fmwb.decifra(bk, keyfile[:30] + bytes(32) + keyfile[62:])
            check(tr("backup WhatsApp finto: con un'altra chiave riconosciuto e non letto"), es2 == "altra_chiave", es2, interno=True)
            guasto = bytearray(bk)
            guasto[len(bk) // 2] ^= 1
            r3, (es3, _m3) = fmwb.decifra(bytes(guasto), keyfile)
            check(tr("backup WhatsApp finto: un byte cambiato → rifiutato (tag GCM non verificato)"), r3 is None and es3 == "errore",
                  es3, interno=True)
            (tmp / "dec.db").write_bytes(raw or b"")
            c2 = fa.sqlite3.connect(str(tmp / "prova.sqlite"))
            try:
                fmc.ensure_schema(c2)
                fmc.read_whatsapp_android(case, c2, part, str(r[0]), r[1], {})
                W = fmc.read_whatsapp_android(case, c2, part, str(r[0]), r[1], {},
                                              backup={"file": tmp / "dec.db", "nome": "msgstore.db.crypt14"})
                n = fmc.segna_backup(c2)
                k = [x[0] for x in c2.execute("SELECT json_extract(extra, '$.key_id') FROM chat_messages WHERE app='whatsapp_backup' "
                                              "AND json_extract(extra, '$.solo_nel_backup')")]
                nb = c2.execute("SELECT COUNT(*) FROM chat_messages WHERE app='whatsapp_backup'").fetchone()[0]
                nv = c2.execute("SELECT COUNT(*) FROM chat_messages WHERE app='whatsapp'").fetchone()[0]
                # (3.0.1) lo stesso database come WhatsApp Business (com.whatsapp.w4b): app a parte, backup a parte
                pb = r[1].replace("com.whatsapp/", "com.whatsapp.w4b/")
                Wb = fmc.read_whatsapp_android(case, c2, part, str(r[0]), pb, {})
                fmc.read_whatsapp_android(case, c2, part, str(r[0]), "WhatsApp Business/Databases/msgstore.db.crypt14", {},
                                          backup={"file": tmp / "dec.db", "nome": "msgstore.db.crypt14 (Business)"})
                nb2 = fmc.segna_backup(c2)
                # il database letto come Business non ha il suo -wal: i messaggi «solo nel backup» di Business si contano
                # confrontando con i messaggi Business letti, non con quelli di WhatsApp
                atteso_b = c2.execute("SELECT COUNT(*) FROM chat_messages WHERE app='whatsapp_business_backup' AND "
                                      "json_extract(extra, '$.key_id') IS NOT NULL AND json_extract(extra, '$.key_id') NOT IN "
                                      "(SELECT json_extract(extra, '$.key_id') FROM chat_messages WHERE app='whatsapp_business' "
                                      "AND json_extract(extra, '$.key_id') IS NOT NULL)").fetchone()[0]
                per = dict(c2.execute("SELECT app, COUNT(*) FROM chat_messages GROUP BY 1").fetchall())
                tb = dict(c2.execute("SELECT app, COUNT(*) FROM chat_threads GROUP BY 1").fetchall())
            finally:
                c2.close()
            check(tr("WhatsApp Business (com.whatsapp.w4b): conversazioni e backup separati da WhatsApp, messaggi solo nel backup per app"),
                  Wb is not None and Wb.app == "whatsapp_business" and per.get("whatsapp_business", 0) > 0 and per.get("whatsapp") == nv
                  and per.get("whatsapp_business_backup") == nb and tb.get("whatsapp_business", 0) > 0 and nb2 == n + atteso_b
                  and atteso_b >= n,
                  str(per), interno=True)
            check(tr("backup WhatsApp finto letto come conversazioni: {b} messaggi (attuale {v}), solo nel backup {n}").format(
                b=nb, v=nv, n=n), W is not None and nb == nv + 1 and k == ["REPERTIA-COLLAUDO-BACKUP"], ", ".join(map(str, k)),
                interno=True)
            # chiamata (tipo 90) prima degli allegati: un difetto della 2.20.2 fermava la lettura di tutto il database
            cols = [c[1] for c in w.db.execute("PRAGMA table_info(message)") if c[1] != "_id"]
            if tab == "message":
                w.db.execute("CREATE TABLE IF NOT EXISTS call_log(_id INTEGER PRIMARY KEY, video_call INTEGER, duration INTEGER, "
                             "call_result INTEGER, timestamp INTEGER, from_me INTEGER, jid_row_id INTEGER, call_id TEXT)")
                w.db.execute("CREATE TABLE IF NOT EXISTS message_call_log(message_row_id INTEGER, call_log_row_id INTEGER)")
                t0 = w.db.execute("SELECT MIN(timestamp) FROM message").fetchone()[0]
                sel = ",".join({"message_type": "90", "timestamp": "?", "key_id": "'REPERTIA-COLLAUDO-CHIAMATA'"}.get(c, c) for c in cols)
                w.db.execute(f"INSERT INTO message({','.join(cols)}) SELECT {sel} FROM message ORDER BY _id LIMIT 1", (t0 - 1000,))
                mid = w.db.execute("SELECT MAX(_id) FROM message").fetchone()[0]
                w.db.execute("INSERT INTO call_log(_id, video_call, duration, call_result, timestamp, from_me, jid_row_id, call_id) "
                             "VALUES (1, 0, 30, 5, ?, 1, 1, 'c1')", (t0 - 1000,))
                w.db.execute("INSERT INTO message_call_log VALUES (?, 1)", (mid,))
                w.db.commit()
                w.db.execute(f"VACUUM INTO '{(tmp / 'chiamata.db').as_posix()}'")
                c3 = fa.sqlite3.connect(str(tmp / "prova3.sqlite"))
                try:
                    fmc.ensure_schema(c3)
                    Wc = fmc.read_whatsapp_android(case, c3, part, str(r[0]), r[1], {},
                                                   backup={"file": tmp / "chiamata.db", "nome": "chiamata"})
                    nc = c3.execute("SELECT COUNT(*) FROM chat_messages WHERE kind='chiamata'").fetchone()[0]
                    check(tr("WhatsApp Android: una chiamata seguita da allegati non ferma la lettura del database"),
                          Wc is not None and nc == 1 and Wc.n_att > 0, tr("{n} chiamate, {a} allegati").format(n=nc, a=Wc.n_att), interno=True)
                finally:
                    c3.close()
        finally:
            w.close()
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


def controlli_crypt15(case, check):
    """Backup crypt15 VERO e la sua chiave (file di prova pubblici di wa-crypt-tools, GPL-3.0): decifrato con il tag GCM
    verificato, database SQLite integro; un'altra chiave e un byte cambiato sono rifiutati; chiave scritta a mano."""
    import forense_mobile_wabackup as fmwb
    if (case.meta.get("mobile") or {}).get("piattaforma") != "android":
        return
    d = next((Path(p).parent / "crypt15" for p in (case.meta.get("evidence"), case.meta.get("origine_decompressa"), case.meta.get("image"))
              if p and (Path(p).parent / "crypt15" / "msgstore-2.26.db.crypt15").is_file()), None)
    if d is None:
        check(tr("backup crypt15 reale: file di prova presenti"), False, tr("non trovati"), misura=True)
        return
    try:
        fmwb._aes()
    except ImportError:
        check(tr("backup WhatsApp: libreria AES (pycryptodome di iLEAPP/ALEAPP)"), False, tr("non trovata"), misura=True)
        return
    bk = (d / "msgstore-2.26.db.crypt15").read_bytes()
    k = fmwb.chiave_file15((d / "encrypted_backup.key").read_bytes())
    raw, (es, _m) = fmwb.decifra15(bk, k) if k else (None, ("errore", ""))
    integro = False
    if raw:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "x.db"
            f.write_bytes(raw)
            c = fa.sqlite3.connect(f)
            try:
                integro = c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            finally:
                c.close()
    check(tr("backup crypt15 reale (wa-crypt-tools): decifrato con encrypted_backup.key, tag GCM verificato, SQLite integro"),
          integro, es, interno=True)
    guasto = bytearray(bk)
    guasto[len(bk) // 2] ^= 1
    check(tr("backup crypt15 reale: un'altra chiave e un byte cambiato sono rifiutati"),
          fmwb.decifra15(bk, bytes(32))[0] is None and fmwb.decifra15(bytes(guasto), k)[0] is None, "", interno=True)
    check(tr("backup crypt15: la chiave di 64 cifre scritta dall'analista vale come il file"),
          bool(k) and fmwb.chiave_digitata(" ".join(k.hex()[i:i + 4] for i in range(0, 64, 4))) == k, "", interno=True)


def controlli_logica_nist(t, img, case, con, a, check):
    """(3.0.2) Sorgente logica su un'immagine pubblica NIST (CD-R RM#3 del «Data Leakage Case»): archivio uguale a quello
    pubblicato (SHA-1 NIST), file finali e file delle VAT precedenti con i nomi e gli orari delle risposte ufficiali."""
    import forense_mobile as fm
    arc = Path(img).parents[2] / "nist" / Path(img).parent.name
    for nome, sha1 in (a.get("sha1_archivio") or {}).items():
        h = hashlib.sha1()
        try:
            with open(arc.parent / nome, "rb") as f:
                while c := f.read(8 << 20):
                    h.update(c)
            got = h.hexdigest()
        except OSError:
            got = None
        check(tr("SHA-1 dell'archivio {nome} uguale a quello pubblicato da NIST").format(nome=nome), got == sha1.lower(),
              tr("atteso {want}, letto {got}").format(want=sha1.lower(), got=got))
    m = fm.mx(case)
    try:
        righe = m.execute("SELECT path, crtime FROM mobile_files WHERE isdir=0").fetchall()
    finally:
        m.close()
    if "radice" in a:
        got = sorted(p for p, _c in righe if "/" not in p)
        check(tr("file presenti alla fine sul disco: {v1}").format(v1=", ".join(a["radice"])), got == sorted(a["radice"]),
              ", ".join(got)[:300] + (f" — {a['nota_radice']}" if a.get("nota_radice") else ""))
    prec = {p.split("/", 1)[1]: c for p, c in righe if p.startswith("[") and "/" in p}
    if "vat_precedenti" in a:
        want = set(a["vat_precedenti"])
        check(tr("{n} file recuperati dalle VAT precedenti, con i nomi pubblicati").format(n=len(want)), set(prec) == want,
              (tr("differenze: {v1}").format(v1=sorted(set(prec) ^ want)) if set(prec) != want else str(len(prec)))[:300]
              + (f" — {a['nota_vat']}" if a.get("nota_vat") else ""))
    if "vat_creati_tra" in a:
        da, a_ = a["vat_creati_tra"]
        ore = sorted(c for c in prec.values() if c)
        check(tr("file delle VAT precedenti masterizzati tra {da} e {a} UTC").format(da=da, a=a_),
              len(ore) == len(prec) > 0 and ore[0] >= da and ore[-1] <= a_, f"{ore[:1]} … {ore[-1:]}"
              + (f" — {a['nota_ore']}" if a.get("nota_ore") else ""))
    if "cancellati_vat" in a:
        n = con.execute("SELECT count(*) FROM files WHERE deleted=1 AND type='r/r'").fetchone()[0]
        check(tr("file delle VAT precedenti segnati come cancellati"), n == a["cancellati_vat"],
              tr("attesi {v1}, trovati {v2}").format(v1=a["cancellati_vat"], v2=n))


DFR_TAG = re.compile(rb"\nDFR\n(?:File (?P<f1>\S+) path|Block (?P<b>\d+) Segment \d+ file (?P<f2>\S+) path)")


def controlli_dfr(t, img, case, con, a, check):
    """(3.0.2) Immagini NIST CFTT «Deleted File Recovery»: archivio uguale a quello pubblicato (SHA-256 NIST), file
    cancellati con i metadati elencati come cancellati e, per quelli non sovrascritti, contenuto letto come
    nell'interfaccia (icat_stream) uguale al file: dimensione NIST e ogni settore pieno con l'etichetta NIST del file,
    in ordine (primo settore «File <nome>», poi «Block 1, 2, …»), nessun settore di un altro file."""
    arc = Path(img).parents[2] / "nist" / Path(img).parent.name
    for nome, want in (a.get("sha256_archivio") or {}).items():
        h = hashlib.sha256()
        try:
            with open(arc.parent / nome, "rb") as f:
                while c := f.read(8 << 20):
                    h.update(c)
            got = h.hexdigest()
        except OSError:
            got = None
        check(tr("SHA-256 dell'archivio {nome} uguale a quello pubblicato da NIST").format(nome=nome), got == want.lower(),
              tr("atteso {want}, letto {got}").format(want=want.lower()[:16], got=(got or "-")[:16]))
    voci = con.execute("SELECT part, inode, type, path FROM files WHERE deleted>=1").fetchall()

    def cerca(nome):
        return [(p, i) for p, i, ty, pa in voci if (pa == nome or pa.endswith("/" + nome)) and ty.endswith("r")]
    if "cancellati_elencati" in a:
        manca = [f for f in a["cancellati_elencati"] if not cerca(f)]
        check(tr("{n} file cancellati con i metadati elencati come cancellati, con il nome intatto").format(
            n=len(a["cancellati_elencati"])), not manca,
            tr("mancano: {v1}").format(v1=", ".join(manca))[:300] if manca else ", ".join(a["cancellati_elencati"])[:300])
    for it in a.get("contenuto", []):
        data = b""
        for p, i in cerca(it["nome"]):
            data = fa.icat_read(case, p, i, it["byte"] + (1 << 20))
            if data:
                break
        st = []
        for k in range(0, len(data) // 512 * 512, 512):
            m = DFR_TAG.match(data[k:k + 512])
            st.append(None if not m else ((m.group("f1") or m.group("f2")).decode("latin-1"),
                                          0 if m.group("f1") else int(m.group("b"))))
        pieni = it["byte"] // 512
        propri = [x[1] for x in st if x and x[0] == it["etichetta"]]
        altri = sorted({x[0] for x in st if x and x[0] != it["etichetta"]})
        check(tr("{nome}: contenuto del file cancellato integro ({n} byte, settori in ordine)").format(
            nome=it["nome"], n=it["byte"]), len(data) == it["byte"] and propri == list(range(pieni)) and not altri,
            tr("{v1} byte, settori propri {v2}/{v3}").format(v1=len(data), v2=len(propri), v3=pieni)
            + (tr(", di altri file {v1}").format(v1=altri) if altri else ""))


def controlli_smartphone(t, img, case, con, a, check):
    """Controlli delle prove «smartphone» (2.20): estrazione, sistema, chat (numero, orari, testi, mittenti), allegati,
    iLEAPP/ALEAPP. Gli orari attesi sono confrontati come impronta SHA-256 dell'elenco ordinato."""
    m = case.meta
    if t.get("sha256_immagine"):
        got = (m.get("sha256") or {}).get(img.name)
        check(tr("estrazione di prova: SHA-256 uguale a quello registrato"), got == t["sha256_immagine"],
              tr("atteso {a}, calcolato {b}").format(a=t["sha256_immagine"], b=got))
    mob = m.get("mobile") or {}
    if "piattaforma" in a:
        check(tr("piattaforma del telefono"), mob.get("piattaforma") == a["piattaforma"],
              tr("attesa {a}, riconosciuta {b}").format(a=a["piattaforma"], b=mob.get("piattaforma")))
    if "sistema_versione" in a:
        v = (mob.get("sistema") or {}).get("versione")
        check(tr("versione del sistema del telefono"), v == a["sistema_versione"],
              tr("attesa {a}, letta {b}").format(a=a["sistema_versione"], b=v))
    if a.get("decompressa"):
        d = m.get("decompressa") or {}
        ok = bool(d) and d.get("sha256_origine") == (m.get("sha256") or {}).get(img.name) and Path(m["image"]).exists()
        if ok:
            h = hashlib.sha256()
            with open(m["image"], "rb") as fh:
                while b := fh.read(8 << 20):
                    h.update(b)
            ok = h.hexdigest() == d.get("sha256")
        check(tr("copia derivata decompressa: SHA-256 registrato e verificato"), ok, f"{d.get('sha256')}")
    mparts = [p for p in m.get("partitions", []) if p.get("mobile")]
    st = (mparts[0]["mobile"].get("statistiche") if mparts else None) or {}
    for k, key in (("date_utc_min", "utc"), ("date_dos_min", "dos")):
        if k in a:
            n = (st.get("date") or {}).get(key, 0)
            check(tr("voci con date {k} (almeno {n})").format(k=key.upper(), n=a[k]), n >= a[k], tr("trovate {n}").format(n=n))
    try:
        # le chiamate nella chat (genere «chiamata») non sono messaggi: i valori attesi vengono dai messaggi di iLEAPP/ALEAPP
        rows = con.execute("SELECT app, ts FROM chat_messages WHERE kind IS NOT 'chiamata'").fetchall()
    except fa.sqlite3.Error:
        rows = []
    for app, n in (a.get("chat_messaggi") or {}).items():
        got = sum(1 for r in rows if r[0] == app)
        check(tr("chat {app}: numero di messaggi").format(app=app), got == n, tr("attesi {n}, letti {got}").format(n=n, got=got))
    for app, want in (a.get("chat_orari_sha256") or {}).items():
        ts = sorted(r[1] or "" for r in rows if r[0] == app)
        got = hashlib.sha256("\n".join(ts).encode()).hexdigest()
        check(tr("chat {app}: orari (UTC) di tutti i messaggi uguali agli attesi").format(app=app), got == want,
              tr("impronta dell'elenco ordinato: attesa {a}, ottenuta {b}").format(a=want[:16], b=got[:16]))
    for app, n in (a.get("chat_conversazioni") or {}).items():
        got = con.execute("SELECT COUNT(*) FROM chat_threads WHERE app=?", (app,)).fetchone()[0]
        check(tr("chat {app}: numero di conversazioni").format(app=app), got == n, tr("attese {n}, trovate {got}").format(n=n, got=got))
    for it in a.get("chat_testi", []):
        r = con.execute("SELECT text, sender_name FROM chat_messages WHERE app=? AND ts=? AND text LIKE ?",
                        (it["app"], it["ts"], "%" + it["contiene"] + "%")).fetchone()
        ok = bool(r) and (not it.get("mittente") or it["mittente"] in (r[1] or ""))
        check(tr("chat {app}: messaggio «{c}» delle {ts}").format(app=it["app"], c=it["contiene"][:40], ts=it["ts"]) +
              (tr(" da {m}").format(m=it["mittente"]) if it.get("mittente") else ""), ok,
              tr("trovato, mittente «{s}»").format(s=r[1]) if r else tr("non trovato"))
    if "allegati_collegati_min" in a:
        n = con.execute("SELECT COUNT(*) FROM chat_attachments WHERE inode IS NOT NULL").fetchone()[0]
        check(tr("allegati collegati al file dell'estrazione (almeno {n})").format(n=a["allegati_collegati_min"]),
              n >= a["allegati_collegati_min"], tr("collegati {n}").format(n=n))
    for name, want in (a.get("allegato_sha256") or {}).items():
        r = con.execute("SELECT part, inode FROM chat_attachments WHERE name=? AND inode IS NOT NULL", (name,)).fetchone()
        got = sha_of(case, r[0], r[1]) if r else None
        check(tr("allegato {name}: contenuto letto dall'estrazione").format(name=name), got == want,
              tr("atteso {want}, letto {got}").format(want=want[:16], got=(got or "-")[:16]))
    if a.get("chat_messaggi"):
        ch = m.get("chat") or {}
        check(tr("chat: riepilogo dell'importazione salvato nel caso"), bool(ch.get("ts")), ch.get("ts") or tr("assente"))
    controlli_allegati(con, a, check)
    controlli_chiamate_chat(con, check)
    controlli_fase4(case, con, check)
    controlli_ricerca_veloce(case, con, check)
    controlli_gps_segno(check)
    controlli_lid(check)
    controlli_chiamate_wa(check)
    controlli_solo_chiamate(check)
    controlli_recupero_wa(check)
    controlli_eliminati_recenti(check)
    controlli_portatile_timeline(case, con, check)
    controlli_preferiti_chat(case, con, check)
    if a.get("posizione"):
        r = con.execute("SELECT COUNT(*) FROM chat_attachments WHERE abs(lat-?) < 1e-6 AND abs(lon-?) < 1e-6",
                        (a["posizione"]["lat"], a["posizione"]["lon"])).fetchone()[0]
        check(tr("posizione condivisa in chat"), r > 0, f"{a['posizione']}")
    if a.get("leapp_righe_min"):
        lp = m.get("leapp") or {}
        if lp.get("esito") != "ok":
            check(tr("iLEAPP/ALEAPP eseguito"), False, tr("non eseguito o non incluso: {e}").format(
                e=lp.get("esito") or tr("strumento non trovato")), misura=not lp)
        else:
            for art, n in a["leapp_righe_min"].items():
                got = (lp.get("artefatti") or {}).get(art, 0)
                check(tr("{s}: artefatto «{art}» (almeno {n} righe)").format(s=lp.get("strumento"), art=art, n=n), got >= n,
                      tr("righe {got}").format(got=got))
            controlli_leapp_chat(case, con, lp, check)
            controlli_file_citati(case, con, a, check)
    controlli_esporta_chat(case, con, check)
    if a.get("righe_citate"):
        controlli_righe_citate(case, a, check)
    if a.get("portachiavi") or a.get("segreti"):
        controlli_portachiavi(case, con, a, check)
    if a.get("sysdiagnose"):
        controlli_sysdiagnose(case, con, a, check)
        controlli_righe_tsv(check)
        controlli_diagnostica(check)
        controlli_database(check)
        controlli_recupero(check)
        controlli_copia_smartphone(check)
        controlli_cache_web(check)
        controlli_mappa(check)
        controlli_mappa_font(check)
        controlli_mappe_rete(check)
        controlli_aggiornamenti(check)
        controlli_telegram_chiamate(check)
        controlli_droni(check)
        controlli_sorgente_logica(check)
        controlli_nist_lacune(check)
        controlli_nist_ese(check)
        controlli_nist_validazione(check)
    if a.get("leapp_righe_min") or a.get("sysdiagnose"):
        import forense_mobile_leapp as fml
        n = fml.righe_vuote(con)
        check(tr("iLEAPP/ALEAPP: nessuna riga vuota tra gli artefatti"), n == 0, tr("righe {got}").format(got=n), interno=True)
    if t["nome"] == TRASCRIZIONE_PROVA:
        controlli_trascrizione(case, check)


def controlli_portachiavi(case, con, a, check):
    """(2.20) Portachiavi di iOS (finto): SHA-256 nel registro a catena, passaggio a iLEAPP con --keychain, portachiavi
    usato dichiarato nel caso; valori segreti mai in chiaro nelle tabelle del caso, nell'interfaccia, nel report portatile
    (salvo scelta esplicita) e negli strumenti dell'agente; «Mostra» registrato."""
    import forense_mobile_portachiavi as fmk
    pa = a.get("portachiavi") or {}
    m = case.meta
    lp = m.get("leapp") or {}
    pk = lp.get("portachiavi") or {}
    log = []
    try:
        log = [json.loads(x) for x in case.log_path.read_text(encoding="utf-8").splitlines() if x.strip()]
    except (OSError, ValueError):
        pass
    if pa.get("sha256"):
        got = (m.get("portachiavi") or {}).get("sha256")
        in_log = any(x.get("event") == "portachiavi" and (x.get("data") or {}).get("sha256") == pa["sha256"] for x in log)
        check(tr("portachiavi: SHA-256 registrato nel caso e nel registro a catena"), got == pa["sha256"] and in_log,
              tr("atteso {a}, registrato {b}").format(a=pa["sha256"][:16], b=(got or "-")[:16]))
        cmd = " ".join(str(x) for x in lp.get("comando") or [])
        check(tr("portachiavi: passato a iLEAPP con --keychain e letto da iLEAPP"),
              "--keychain" in cmd and pk.get("voci_lette") == pa.get("voci_lette"),
              tr("voci lette da iLEAPP: {n}").format(n=pk.get("voci_lette")))
    if pa.get("uso"):
        ok = pk.get("uso") == pa["uso"] and (not pa.get("file_finisce") or str(pk.get("file") or "").endswith(pa["file_finisce"])) \
            and (not pa.get("anche_nell_estrazione") or bool(pk.get("anche_nell_estrazione")))
        check(tr("portachiavi usato da iLEAPP dichiarato nel caso: {u}").format(u=tr(fmk.USO.get(pa["uso"], pa["uso"]))), ok,
              fmk.testo_esito(pk))
    sg = a.get("segreti") or {}
    if not sg:
        return
    segreti = sg.get("mai_in_chiaro") or []
    # tabelle del caso: i valori solo in leapp_segreti
    trovati = []
    for (tab,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name <> 'leapp_segreti'"):
        cols = [r[1] for r in con.execute(f'PRAGMA table_info("{tab}")') if (r[2] or "").upper() in ("TEXT", "")]
        for c in cols:
            for v in segreti:
                try:
                    if con.execute(f'SELECT 1 FROM "{tab}" WHERE CAST("{c}" AS TEXT) LIKE ? LIMIT 1', (f"%{v}%",)).fetchone():
                        trovati.append(f"{tab}.{c}")
                except fa.sqlite3.Error:
                    pass
    check(tr("valori segreti: mai in chiaro nelle tabelle del caso (solo in leapp_segreti)"), not trovati,
          ", ".join(sorted(set(trovati))) or tr("nessuno"))
    r = con.execute("SELECT id, data FROM artifacts WHERE cat='leapp' AND sub=?", (sg["artefatto"],)).fetchone()
    if not r:
        check(tr("valori segreti: artefatto «{a}» presente").format(a=sg["artefatto"]), False, tr("non trovato"))
        return
    import forense_gui as G
    v = G.art_view(case, {"id": r[0]})
    check(tr("valori segreti: nascosti nell'interfaccia (dettagli di «{a}»)").format(a=sg["artefatto"]),
          sg["valore"] not in json.dumps(v, ensure_ascii=False) and sg["visibile"] in v["html"] and bool(v.get("segreti")),
          tr("campi nascosti: {c}").format(c=", ".join(v.get("segreti") or [])))
    n0 = sum(1 for x in log if x.get("event") == "segreto_mostrato")
    try:
        val = fmk.segreto(case, con, r[0], (v.get("segreti") or ["-"])[0], mostra_da="collaudo")
    except ValueError as e:
        val = f"errore: {e}"
    log2 = case.log_path.read_text(encoding="utf-8").splitlines()
    n1 = sum(1 for x in log2 if '"event": "segreto_mostrato"' in x)
    check(tr("valori segreti: «Mostra» rivela il valore e lo registra nel registro (senza il valore)"),
          val == sg["valore"] and n1 == n0 + 1 and not any(sg["valore"] in x for x in log2), "")
    # report portatile: senza la scelta i valori non ci sono, con la scelta sì
    import forense_portatile as fpo

    def report_ha(opts):
        out = fpo.export_portable(case, dict(opts, contenuto="scelti"), lambda d: None)
        root = Path(out["path"])
        testo = ""
        for f in root.rglob("*"):
            if f.is_file() and f.suffix.lower() in (".js", ".html", ".txt", ".csv", ".json", ".md"):
                testo += f.read_text(encoding="utf-8", errors="replace")
        return [x for x in segreti if x in testo]
    senza = report_ha({})
    con_scelta = report_ha({"segreti": True})
    check(tr("valori segreti: assenti dal report portatile, presenti solo con la scelta esplicita"),
          not senza and sg["valore"] in con_scelta,
          tr("senza scelta: {a}; con la scelta: {b} valori").format(a=", ".join(senza) or tr("nessuno"), b=len(con_scelta)))
    # strumenti dell'agente: gli artefatti arrivano con il segnaposto
    try:
        tools = fa.make_tools(case)
    except Exception:
        tools = {}
    txt = ""
    for nome, fn in (tools.items() if isinstance(tools, dict) else []):
        if nome in ("query_artifacts",):
            try:
                txt += str(fn(category="leapp", contains="", limit=300))
            except Exception as e:
                txt += f"errore: {e}"
    # (3.0) l'agente arriva agli elementi nuovi: voli, artefatto dalla riga citata nei riferimenti, preferiti
    if tools:
        r0 = con.execute("SELECT id, title FROM artifacts ORDER BY id LIMIT 1").fetchone()
        for nome in ("flights", "location_points", "query_database", "deleted_records", "list_bookmarks", "read_artifact"):
            check(tr("agente: strumento {n} disponibile").format(n=nome), nome in tools, interno=True)
        if r0 and "read_artifact" in tools:
            check(tr("agente: artefatto letto dal numero di riga"), (r0[1] or "") in tools["read_artifact"](r0[0]), interno=True)
    check(tr("valori segreti: non dati all'agente IA (strumento degli artefatti)"),
          bool(txt) and sg["visibile"] in txt and not any(x in txt for x in segreti),
          tr("righe lette dall'agente: {n}").format(n=txt.count("\n")))


def _conteggio(c):
    return ", ".join(f"{k} {v}" for k, v in sorted(c.items())) or "-"


def controlli_allegati(con, a, check):
    """(2.20) Allegati delle chat: come è stato trovato il file (percorso, hash), quelli con la sola miniatura del
    database e quelli assenti; SHA-256 dei file uguale a quello registrato dall'app."""
    from collections import Counter
    for app, want in (a.get("allegati_esito") or {}).items():
        got = Counter()
        for inode, path, metodo, th in con.execute(
                "SELECT a.inode, a.path, a.metodo, a.thumb IS NOT NULL FROM chat_attachments a JOIN chat_messages m "
                "ON m.id = a.msg WHERE m.app=? AND a.lat IS NULL", (app,)):
            got[(metodo or "percorso") if inode not in (None, "") else "rapporto" if str(path or "").startswith("leapp:")
                else "miniatura" if th else "assente"] += 1
        check(tr("allegati {app}: trovati (per percorso, per hash), con la sola miniatura, assenti").format(app=app),
              dict(got) == want, tr("attesi {a}; ottenuti {b}").format(a=_conteggio(want), b=_conteggio(got)))
    for app, n in (a.get("allegati_hash_verificati") or {}).items():
        got = con.execute("SELECT COUNT(*) FROM chat_attachments a JOIN chat_messages m ON m.id = a.msg WHERE m.app=? AND "
                          "a.verifica='uguale'", (app,)).fetchone()[0]
        bad = con.execute("SELECT COUNT(*) FROM chat_attachments a JOIN chat_messages m ON m.id = a.msg WHERE m.app=? AND "
                          "a.verifica='diverso'", (app,)).fetchone()[0]
        check(tr("allegati {app}: SHA-256 del file uguale a quello registrato dall'app").format(app=app), got == n and not bad,
              tr("uguali {g}, diversi {b} (attesi {n} uguali)").format(g=got, b=bad, n=n))


def controlli_file_citati(case, con, a, check):
    """(2.20) File citati dagli artefatti di iLEAPP/ALEAPP (es. «File Path» di Google Photos): trovati per percorso
    (tabella dei percorsi del telefono), per nome e dimensione, assenti."""
    from collections import Counter
    import forense_percorsi as fp
    cols = ("id", "cat", "ts", "title", "detail", "user", "src_path", "part", "inode", "data")
    for sub, want in (a.get("file_citati") or {}).items():
        got = Counter()
        try:
            with fp.Indice(case) as ix:
                for row in con.execute("SELECT " + ", ".join(cols) + " FROM artifacts WHERE cat='leapp' AND sub=?", (sub,)):
                    for x in fp.file_citati(case, dict(zip(cols, row)), idx=ix)["file"]:
                        if x["ruolo"] == "file":
                            got[x["metodo"] if x["stato"] == "trovato" else x["stato"]] += 1
        except Exception as e:
            got["errore: " + f"{type(e).__name__}: {e}"] += 1
        check(tr("file citati da «{sub}»: trovati per percorso, per nome e dimensione, assenti").format(sub=sub),
              dict(got) == want, tr("attesi {a}; ottenuti {b}").format(a=_conteggio(want), b=_conteggio(got)))
    for sub, want in (a.get("file_citati_livelli") or {}).items():
        got = Counter({"certo": 0, "probabile": 0, "assente": 0, "uniti": 0})
        try:
            with fp.Indice(case) as ix:
                for row in con.execute("SELECT " + ", ".join(cols) + " FROM artifacts WHERE cat='leapp' AND sub=?", (sub,)):
                    for x in fp.file_citati(case, dict(zip(cols, row)), idx=ix)["file"]:
                        if x["ruolo"] == "file":
                            got[x["livello"]] += 1
                            got["uniti"] += len(x["campi"]) > 1
        except Exception as e:
            got["errore: " + f"{type(e).__name__}: {e}"] += 1
        check(tr("file citati da «{sub}»: un solo file per riga, campi uniti, esito certo/probabile/assente").format(sub=sub),
              dict(got) == want, tr("attesi {a}; ottenuti {b}").format(a=_conteggio(want), b=_conteggio(got)), interno=True)


def controlli_righe_citate(case, a, check):
    """(2.20) Righe costruite nello stile di iLEAPP valutate sull'estrazione finta della prova: cartella + nome = percorso
    completo, un solo file citato per file diverso, esito certo/probabile/assente, candidati, copie, collegamento
    «cartella»; stessa risposta nella tabella (miniatura una volta sola) e nel report portatile."""
    import forense_percorsi as fp
    import forense_gui as G
    import forense_portatile as P
    mobile = fa.is_mobile(case)
    for i, rg in enumerate(a.get("righe_citate") or []):
        riga = {"id": -1 - i, "cat": "leapp", "title": rg["nome"], "src_path": None, "part": None, "inode": None,
                "user": None, "data": {"leapp": "iLEAPP", "artefatto": "collaudo", "campi": rg["campi"]}}
        diff = []
        try:
            with fp.Indice(case) as ix:
                fs = [x for x in fp.file_citati(case, dict(riga), idx=ix)["file"] if x["ruolo"] == "file"]
                rapido = [x for x in fp.file_citati(case, dict(riga), veloce=True, idx=ix)["file"] if x["ruolo"] == "file"]
            if len(fs) != len(rg["atteso"]):
                diff.append(tr("{n} file citati invece di {m}").format(n=len(fs), m=len(rg["atteso"])))
            for x, w in zip(fs, rg["atteso"]):
                if x["livello"] != w["livello"]:
                    diff.append(tr("esito {g} invece di {w}").format(g=x["livello"], w=w["livello"]))
                if w.get("metodo") and x.get("metodo") != w["metodo"]:
                    diff.append(tr("metodo {g} invece di {w}").format(g=x.get("metodo"), w=w["metodo"]))
                if w.get("verifica") and x.get("verifica") != w["verifica"]:
                    diff.append(tr("verifica dell'hash {g} invece di {w}").format(g=x.get("verifica"), w=w["verifica"]))
                if w.get("campi") and x.get("campi") != w["campi"]:
                    diff.append(tr("campi {g} invece di {w}").format(g=", ".join(x.get("campi") or []), w=", ".join(w["campi"])))
                if w.get("finisce") and not str(x.get("path") or "").endswith(w["finisce"]):
                    diff.append(tr("file {g}").format(g=x.get("path")))
                if "copie" in w and (x.get("copie") or 0) != w["copie"] or w.get("copie") and len(x.get("copie_elenco") or []) != w["copie"]:
                    diff.append(tr("copie {g} invece di {w}").format(g=x.get("copie") or 0, w=w["copie"]))
                if w.get("candidati") and (x.get("n_candidati") != w["candidati"] or len(x.get("candidati") or []) != w["candidati"]):
                    diff.append(tr("candidati {g} invece di {w}").format(g=x.get("n_candidati"), w=w["candidati"]))
                if w.get("cartella_finisce") and not any(str(d.get("path") or "").endswith(w["cartella_finisce"])
                                                         for d in x.get("cartelle") or []):
                    diff.append(tr("collegamento «cartella» mancante"))
                lab = fp.etichetta_disco(x, mobile)
                if tr(fp.LIVELLI[x["livello"]]) not in lab:
                    diff.append(tr("esito non scritto nel testo: {t}").format(t=lab))
            if [x["livello"] for x in rapido] != [x["livello"] for x in fs]:
                diff.append(tr("la ricerca veloce (tabella) dà un esito diverso"))
            tab = [dict(riga, data=json.dumps(riga["data"]))]
            G.cited_rows(case, tab)
            if (tab[0].get("cited") or {}).get("n", 0) != len(rg["atteso"]):
                diff.append(tr("tabella: {n} file citati").format(n=(tab[0].get("cited") or {}).get("n", 0)))
            prow = [["leapp", None, rg["nome"], "", None, None, None, None, None, None, None, json.dumps(riga["data"])]]
            with tempfile.TemporaryDirectory() as td:
                P.art_cited(case, Path(td), prow)
            pc = [c for c in prow[0][11] or [] if c[15] == "file"]
            if [c[8] for c in pc] != [w["livello"] for w in rg["atteso"]]:
                diff.append(tr("report portatile: esiti {g}").format(g=", ".join(c[8] for c in pc)))
        except Exception as e:
            diff.append(f"{type(e).__name__}: {e}")
        check(tr("file citati: {n}").format(n=rg["nome"]), not diff,
              "; ".join(diff) if diff else ", ".join(tr(fp.LIVELLI[w["livello"]]) for w in rg["atteso"]), interno=True)


def controlli_leapp_chat(case, con, lp, check):
    """(2.20) Chat e chiamate ricavate dagli artefatti di iLEAPP/ALEAPP: nessuna riga persa né contata due volte, durate
    uguali a quelle della fonte."""
    import forense_mobile_leapp_chat as fmlc
    lc = case.meta.get("leapp_chat") or {}
    cs = case.meta.get("chiamate") or {}
    if lc.get("chat"):
        n_msg = n_alt = 0
        for (ex,) in con.execute("SELECT m.extra FROM chat_messages m JOIN chat_threads t ON t.id = m.thread WHERE t.origin='leapp'"):
            n_msg += 1
            n_alt += len((json.loads(ex or "{}")).get("altre_fonti") or [])
        want = sum(lc["chat"].values())
        check(tr("chat da {s}: ogni riga degli artefatti è in un solo messaggio").format(s=lp.get("strumento")), n_msg + n_alt == want,
              tr("righe {r}, messaggi {m} + doppioni uniti {d}").format(r=want, m=n_msg, d=n_alt))
    if cs.get("artefatti"):
        calls = [json.loads(d) for (d,) in con.execute("SELECT data FROM artifacts WHERE cat='chiamate'")]
        refs = sum(len(c.get("fonti") or []) for c in calls)
        check(tr("chiamate da {s}: ogni riga delle fonti è in una sola chiamata").format(s=lp.get("strumento")), refs == cs.get("righe"),
              tr("righe {r}, riferimenti {f}, chiamate {n}").format(r=cs.get("righe"), f=refs, n=len(calls)))
        specs = fmlc.carica().get("chiamate") or {}
        bad, tot = [], 0
        for c in calls:
            f = (c.get("fonti") or [None])[0]
            spec = next((v for k, v in specs.items() if k.split("|")[-1] == (f or {}).get("artefatto")), None)
            if not f or not spec or not spec.get("durata") or len(c["fonti"]) != 1:
                continue
            r = con.execute("SELECT data FROM artifacts WHERE id=?", (f["riga"],)).fetchone()
            want = fmlc._durata(fmlc._get(json.loads(r[0]).get("campi") or {}, spec["durata"])) if r else None
            if want is None:
                continue
            tot += 1
            if c.get("durata_s") != want:
                bad.append(f"{c.get('ts')}: {c.get('durata_s')} ≠ {want}")
        if tot:
            check(tr("chiamate: durata uguale a quella della fonte ({n} chiamate)").format(n=tot), not bad, "; ".join(bad[:3]) or "")


def controlli_pulsanti(case, con, check):
    """(2.20) Pulsanti dell'interfaccia con le stesse richieste della pagina (/api/...): Preferiti, Reperto, Fonte e
    «Mostra nel File System» su un file, un artefatto e, nei casi smartphone, un artefatto di iLEAPP/ALEAPP, una chat e una
    chiamata; apertura delle cartelle dell'albero fino al secondo livello; indice dell'albero cancellato a caso aperto."""
    import time
    import forense_gui as G
    H = G.Handler.__new__(G.Handler)
    mobile = fa.is_mobile(case)
    bad_txt = ("undefined", "None", "null", "NaN")

    def call(method, path, b):
        try:
            return (H.post(path, b) if method == "P" else H.get(path, {k: str(v) for k, v in b.items()})), None
        except Exception as e:
            return None, f"{type(e).__name__}: {e}"
    r, err = call("P", "/api/open", {"root": str(case.root), "resume": False})
    if err:
        check(tr("interfaccia: apertura del caso"), False, err, interno=True)
        return

    def tree_ready():
        for _ in range(600):
            t, e = call("G", "/api/tree", {})
            if e or (t or {}).get("state") != "building":
                return t, e
            time.sleep(0.5)
        return None, tr("albero non pronto")
    root, err = tree_ready()
    if err or (root or {}).get("state") != "ready":
        check(tr("interfaccia: albero delle cartelle"), False, err or str(root), interno=True)
        return
    # elementi da provare, come li costruisce la pagina (itemRef / extRef / locRef)
    items = []
    nav = G.nav_db(case)
    try:
        fr = nav.execute("SELECT part, inode, path FROM nav WHERE isdir=0 AND deleted=0 AND inode IS NOT NULL "
                         "ORDER BY path LIMIT 1").fetchone()
    finally:
        nav.close()
    if fr:
        items.append((tr("file"), {"source": "fs", "part": fr[0], "inode": str(fr[1]), "path": fr[2]},
                      {"part": fr[0], "inode": str(fr[1]), "path": fr[2]}, fr[2]))
    cats = ([("leapp", tr("artefatto di iLEAPP/ALEAPP")), ("messaggi", tr("chat")), ("chiamate", tr("chiamata"))] if mobile
            else [(None, tr("artefatto"))])
    for cat, nome in cats:
        res, err = call("G", "/api/results", {"kind": "art", **({"cat": cat} if cat else {})})
        rows = [x for x in (res or {}).get("rows", []) if x.get("src_path") and (mobile or x.get("inode"))]   # con un file d'origine
        if cat == "leapp":              # (2.20) righe dei sysdiagnose: la fonte è fuori dall'estrazione (messaggio chiaro)
            sdr = [x for x in rows if (x.get("data") or {}).get("sysdiagnose")]
            if sdr:
                x = sdr[0]
                _r, err = call("P", "/api/locate_file", {"part": x["part"], "inode": x["inode"] or "", "path": x["src_path"]})
                check(tr("pulsante Fonte: riga di un sysdiagnose (fuori dall'estrazione, detto chiaramente)"),
                      bool(err) and "sysdiagnose" in err and (x["data"]["sysdiagnose"] in err), err or tr("nessun errore"), interno=True)
            rows = [x for x in rows if not (x.get("data") or {}).get("sysdiagnose")]
        if not rows:
            continue
        x = rows[0]
        loc = {"part": x["part"], "inode": x["inode"] or "", "path": x["src_path"]}      # come locRef della pagina
        items.append((nome, {"source": "art", "id": x["id"], "part": x["part"], "inode": x["inode"], "path": x["title"]},
                      loc, x["src_path"]))
    for nome, it, loc, want in items:
        # ⭐ Preferiti
        r, err = call("P", "/api/bm_add", {"cat": tr("collaudo"), "note": "", "item": it})
        last = None
        with open(case.root / "audit_log.jsonl", encoding="utf-8") as fh:
            for line in fh:
                if '"preferiti"' in line:
                    last = line
        refs = (json.loads(last).get("data") or {}).get("riferimenti") if last else None
        ok = not err and (r or {}).get("total", 0) >= 1 and bool(refs) and not any(b in " ".join(refs) for b in bad_txt)
        check(tr("pulsante Preferiti: {n}").format(n=nome), ok, err or "; ".join(refs or [])[:300], interno=True)
        # 📌 Reperto: riferimento scritto dal server, registrato tra i reperti
        rf, err = call("P", "/api/item_ref", it)
        txt = (rf or {}).get("text") or ""
        if not err:
            r, err = call("P", "/api/finding", {"title": tr("collaudo: {n}").format(n=nome), "description": "", "references": txt})
        ok = not err and bool(txt) and not any(b in txt for b in bad_txt) and \
            (not mobile or (tr("percorso nell'estrazione") in txt or tr("database {db}").format(db="").strip() in txt)) and \
            any(f.get("references") == txt for f in (r or {}).get("findings", []))
        check(tr("pulsante Reperto: {n}").format(n=nome), ok, err or txt[:300], interno=True)
        # Fonte / Mostra nel File System
        r, err = call("P", "/api/locate_file", loc)
        got = (r or {}).get("select") or (r or {}).get("dir")
        check(tr("pulsante {b}: {n}").format(b=tr("Mostra nel File System") if it["source"] == "fs" else tr("Fonte"), n=nome),
              not err and got == want, err or tr("atteso {a}, aperto {b}").format(a=want, b=got), interno=True)
    # cartelle dell'albero fino al secondo livello: ogni cartella si apre e mostra quanti elementi dice il numero accanto
    n = 0
    errs = []
    for p in root.get("parts", []):
        lv1, err = call("G", "/api/tree", {"part": p["part"], "path": ""})
        if err:
            errs.append(err)
            continue
        level = [(d, 1) for d in (lv1 or {}).get("dirs", [])]
        while level:
            d, depth = level.pop(0)
            n += 1
            lst, err = call("G", "/api/results", {"kind": "explore", "part": p["part"], "dir": d["path"]})
            if err or (not d.get("virtual") and (lst or {}).get("total") != d.get("nitems")):    # $Unalloc: senza numero
                errs.append(f"{d['path']}: {err or tr('{a} elementi invece di {b}').format(a=(lst or {}).get('total'), b=d.get('nitems'))}")
            if depth < 2 and d.get("ndirs"):
                sub, err = call("G", "/api/tree", {"part": p["part"], "path": d["path"]})
                if err:
                    errs.append(f"{d['path']}: {err}")
                level += [(s, depth + 1) for s in (sub or {}).get("dirs", [])]
    check(tr("albero: cartelle aperte fino al secondo livello ({n})").format(n=n), n > 0 and not errs, "; ".join(errs[:3]), interno=True)
    # indice dell'albero cancellato a caso aperto (es. dopo il cambio del fuso): si ricostruisce, nessun errore
    try:
        G.nav_file(case).unlink()
    except OSError:
        pass
    t, err = tree_ready()
    lst, err2 = call("G", "/api/results", {"kind": "explore", "part": (root.get("parts") or [{}])[0].get("part"), "dir": ""})
    check(tr("albero: indice cancellato a caso aperto, ricostruito"), not err and not err2 and (t or {}).get("state") == "ready",
          err or err2 or "", interno=True)


TRASCRIZIONE_PROVA = "21_smartphone_android_targz"     # (2.20) caso con le registrazioni pubbliche allegate agli MMS
TRASCR_PAROLA = "PAROLA-CHIAVE-COLLAUDO-TRASCRIZIONE"


def controlli_trascrizione(case, check):
    """(2.20) Trascrizione degli audio. I modelli NON sono nei pacchetti (si scaricano con il consenso), quindi i controlli
    che contano non dipendono dal modello: elenco dei modelli, consenso obbligatorio, file non validi rifiutati e il
    percorso del testo con un motore FINTO che restituisce una frase nota (tabella, ricerca nel testo, chat, registro,
    report). Misura (non conta): trascrizione vera delle registrazioni se motore, ffmpeg e un modello sono presenti."""
    import forense_trascrizione as ftr
    import forense_gui as G
    import forense_mobile_gui as fmg
    import re as _re
    ok = len(ftr.MODELLI) == 3 and all(_re.fullmatch(r"[0-9a-f]{64}", m["sha256"]) and m["size"] > 1 << 20 for m in ftr.MODELLI) \
        and ftr.HF_URL.endswith("/" + ftr.HF_COMMIT + "/") and sum(bool(m.get("consigliato")) for m in ftr.MODELLI) == 1
    check(tr("trascrizione: elenco dei modelli con SHA-256, dimensione e indirizzo a versione fissata"), ok,
          ", ".join(f"{m['file']} {m['sha256'][:12]}…" for m in ftr.MODELLI), interno=True)
    try:
        ftr.dettatura(b"", "it")
        det_ok = False
    except ValueError:
        det_ok = True
    check(tr("Dettatura: una registrazione vuota viene rifiutata e non resta alcun file"), det_ok and not list(Path(tempfile.gettempdir()).glob("repertia_dettatura_*")), "", interno=True)
    prima = set(ftr.models_dir().iterdir())
    try:
        ftr.scarica("base", False, lambda p: None)
        rif = False
    except ValueError:
        rif = True
    check(tr("trascrizione: senza il consenso dell'analista il modello non si scarica"),
          rif and set(ftr.models_dir().iterdir()) == prima, tr("nessun file scritto") if rif else tr("download partito"), interno=True)
    tmp = Path(tempfile.mkdtemp())
    try:
        f1 = tmp / "ggml-base-q5_1.bin"
        f1.write_bytes(b"non un modello")
        f2 = tmp / "uguale_dimensione.bin"
        with open(f2, "wb") as fh:                  # stessa dimensione del modello base, contenuto diverso
            fh.truncate(ftr.BY_ID["base"]["size"])
        esiti = []
        for f in (f1, f2):
            try:
                ftr.importa(f, lambda p: None)
                esiti.append(False)
            except ValueError:
                esiti.append(True)
        check(tr("trascrizione: un file che non è un modello dell'elenco viene rifiutato (dimensione o SHA-256 diversi)"),
              all(esiti) and set(ftr.models_dir().iterdir()) == prima, str(esiti), interno=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # misura: trascrizione vera, se possibile (non tocca il caso)
    inst = ftr.installed()
    con = fa.sqlite3.connect(case.db_path)
    try:
        rows = ftr.audio_rows(con, "chat")
        mid = next((k for k in ("small", "base", "turbo") if k in inst), None)
        if ftr.exe() and ftr.ffmpeg() and mid and rows:
            import forense_estesa as fe
            ctx = fe.Ctx(case, con, N_("Trascrizione"))
            testi, t0 = [], time.time()
            try:
                for k, (part, inode, _d, path) in enumerate(rows):
                    src, wav = ctx.tmp / f"m{k}{Path(path).suffix}", ctx.tmp / f"m{k}.wav"
                    fe.copy_fs_file(case, part, inode, src)
                    dur = ftr._wav(src, wav)
                    lingua, segs = ftr._whisper(Path(inst[mid]["path"]), wav, "auto", ctx.tmp / f"m{k}", 300)
                    testi.append(f"[{lingua}] " + " ".join(x[2] for x in segs))
            finally:
                ctx.close()
            check(tr("trascrizione vera delle {n} registrazioni pubbliche (modello {m}, {s} s)").format(
                n=len(rows), m=inst[mid]["file"], s=round(time.time() - t0, 1)), all(len(x) > 8 for x in testi),
                " | ".join(testi)[:400], misura=True)
        else:
            check(tr("trascrizione vera delle registrazioni pubbliche"), False,
                  tr("non eseguita: motore, ffmpeg o modello non presenti (il modello si installa con il consenso)"), misura=True)
        # percorso del testo con un motore finto (frase nota, nessun modello)
        n_audio = len(rows)
        vecchi = (ftr.exe, ftr.ffmpeg, ftr.installed, ftr._wav, ftr._whisper, ftr.sha256)
        ftr.exe = ftr.ffmpeg = lambda: "prova"
        ftr.installed = lambda: {"small": {"path": "prova"}}
        ftr._wav = lambda src, dest, timeout=600: 3.0
        ftr._whisper = lambda model, wav, lang, out, timeout: ("it", [[0.0, 1.5, "Prima frase"], [1.5, 3.0, TRASCR_PAROLA]])
        ftr.sha256 = lambda path, progress=None: "0" * 64
        try:
            case.meta["trascrizione_opzioni"] = {"scope": "chat", "modello": "small", "lingua": "auto", "rifai": True}
            res = ftr.run(case, con)
            con.commit()
        finally:
            ftr.exe, ftr.ffmpeg, ftr.installed, ftr._wav, ftr._whisper, ftr.sha256 = vecchi
        nt = con.execute("SELECT COUNT(*) FROM trascrizioni WHERE testo LIKE ?", ("%" + TRASCR_PAROLA + "%",)).fetchone()[0]
        check(tr("trascrizione (motore finto): {n} audio delle chat trascritti e salvati con i segmenti").format(n=n_audio),
              bool(res) and n_audio > 0 and res["con_testo"] == n_audio == nt, json.dumps(res, ensure_ascii=False)[:200], interno=True)
    finally:
        con.close()
    r = G.results(case, {"kind": "doc", "q": TRASCR_PAROLA}, limit=None)
    check(tr("trascrizione: il testo si trova con la ricerca nel testo, come «Trascrizione automatica»"),
          r["total"] == n_audio and all(x.get("kind") == tr(ftr.KIND) for x in r["rows"]), tr("trovati {n}").format(n=r["total"]),
          interno=True)
    con = fa.db_ro(case)
    try:
        ids = [x[0] for x in con.execute("SELECT DISTINCT msg FROM chat_attachments a JOIN trascrizioni t ON t.part = a.part "
                                         "AND t.inode = a.inode")]
        att = fmg._attachments(con, ids)
    finally:
        con.close()
    n_att = sum(1 for v in att.values() for x in v if TRASCR_PAROLA in ((x.get("trascrizione") or {}).get("testo") or ""))
    check(tr("trascrizione: il testo compare sotto l'allegato nella vista chat"), n_att >= n_audio,
          tr("allegati con trascrizione {n}").format(n=n_att), interno=True)
    log = [json.loads(x) for x in open(case.root / "audit_log.jsonl", encoding="utf-8")]
    av = [x for x in log if x.get("event") == "trascrizione_avviata"]
    ok = bool(av) and av[-1]["data"].get("modello_sha256") == ftr.BY_ID["small"]["sha256"] and av[-1]["data"].get("ambito") == "chat"
    case.meta.setdefault("estese", {})["trascrizione"] = res      # come fa l'analisi aggiuntiva
    fa.write_report(case)
    rep = (case.root / "report.md").read_text(encoding="utf-8")
    check(tr("trascrizione: registro del caso (modello e SHA-256, motore, ambito) e sezione nel report"),
          ok and tr("## Trascrizione automatica degli audio") in rep, json.dumps(av[-1]["data"] if av else {})[:200],
          interno=True)


def controlli_esporta_chat(case, con, check):
    """(2.20) «Esporta chat»: HTML e CSV scritti, SHA-256 dei file uguale a quello registrato nel registro a catena."""
    try:
        r = con.execute("SELECT t.id FROM chat_threads t ORDER BY (SELECT COUNT(*) FROM chat_attachments a JOIN chat_messages m "
                        "ON m.id = a.msg WHERE m.thread = t.id) DESC, t.n_msg DESC LIMIT 1").fetchone()
    except fa.sqlite3.Error:
        r = None
    if not r:
        return
    import forense_gui as G
    import forense_mobile_gui as fmg
    out = fmg.export_chat(G, case, {"thread": r[0], "tz": "utc"})
    d = case.root / out["rel"]
    ok = all((d / f["file"]).is_file() and hashlib.sha256((d / f["file"]).read_bytes()).hexdigest() == f["sha256"] for f in out["files"])
    last = None
    with open(case.root / "audit_log.jsonl", encoding="utf-8") as fh:
        for line in fh:
            if '"export_chat"' in line:
                last = json.loads(line)
    logged = {f["file"]: f["sha256"] for f in ((last or {}).get("data") or {}).get("file", [])}
    ok = ok and all(logged.get(f["file"]) == f["sha256"] for f in out["files"])
    check(tr("esporta chat: HTML e CSV scritti, SHA-256 uguale a quello del registro"), ok,
          ", ".join(f"{f['file']} {f['sha256'][:12]}…" for f in out["files"]))
    # (2.20) verifica del registro: un file esportato cambiato dopo l'esportazione viene scoperto (su una copia)
    import forense_registro as frg
    tmp = Path(tempfile.mkdtemp())
    try:
        shutil.copy2(case.log_path, tmp / "audit_log.jsonl")
        dd = tmp / out["rel"]
        shutil.copytree(d, dd)
        f0 = dd / out["files"][0]["file"]
        f0.chmod(0o644)
        f0.write_bytes(f0.read_bytes() + b" ")
        R = frg.verifica(tmp)
        diff = [y["file"] for y in (R.get("esportati") or {}).get("diversi") or []]
        check(tr("verifica del registro: un file esportato modificato viene scoperto"),
              any(y.endswith(out["files"][0]["file"]) for y in diff) and R["integro"], ", ".join(diff))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    if "--lingua" in sys.argv:
        i = sys.argv.index("--lingua")
        lg.imposta(sys.argv[i + 1] if i + 1 < len(sys.argv) else None)
        del sys.argv[i:i + 2]
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    base = Path(sys.argv[1]).expanduser().resolve()
    specs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(base.glob("atteso*.json"))]
    if not specs:
        sys.exit(tr("Nessun file atteso*.json in {base}").format(base=base))
    spec = {"set": " + ".join(x.get("set", "?") for x in specs), "prove": []}
    for x in specs:
        for t in x["prove"]:
            t.setdefault("fonte", x.get("fonte"))
            t.setdefault("indipendente", x.get("indipendente", False))
            spec["prove"].append(t)
    prepare_public(base)
    finder = Finder(base)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(sys.argv[2]).expanduser().resolve() if len(sys.argv) > 2 else \
        Path(os.environ.get("FORENSE_CASI", "~/CasiForensi")).expanduser() / "_collaudo" / stamp
    out.mkdir(parents=True, exist_ok=True)
    amb = fa.ambiente()
    L = [tr("# Collaudo di {APP_NAME} {APP_VERSION}").format(APP_NAME=fa.APP_NAME, APP_VERSION=fa.APP_VERSION), "",
         tr("- Eseguito: {v1} su {v2}").format(v1=fa.now(), v2=amb['strumenti'].get('sistema')),
         tr("- Cartella di collaudo: `{base}` (set «{v1}», {v2} prove)").format(base=base, v1=spec.get('set', '?'), v2=len(spec['prove'])),
         tr("- Impronta del programma: `{impronta_programma}`").format(impronta_programma=amb['impronta_programma']),
         tr("- Lingua dei casi di prova: {v1}").format(v1=lg.LINGUE[lg.lingua()]),
         tr("- Strumenti: ") + "; ".join(f"{k}: {v}" for k, v in amb["strumenti"].items()), ""]
    tot = ok = 0
    tot_i = ok_i = 0
    saltate, misure = [], []
    for t in spec["prove"]:
        print(f"\n=== {t['nome']}: {t.get('descrizione', '')}", flush=True)
        img = finder.find(t)
        if img is None:
            print(tr("  SALTATA: immagine non presente nella cartella di collaudo") + (tr(" (scaricala da {scarica})").format(scarica=t['scarica']) if t.get("scarica") else ""), flush=True)
            saltate.append(t)
            continue
        res, cp = run_test(t, img, out)
        L += [f"## {t['nome']}", "", t.get("descrizione", ""), ""]
        if t.get("fonte"):
            L += [tr("Valori attesi: {fonte}").format(fonte=t['fonte']) + (tr(" — **pubblicati da terzi, indipendenti da RepertIA**") if t.get("indipendente") else ""), ""]
        L += [tr("Immagine: `{name}`").format(name=img.name) + (tr(" (MD5 `{md5_immagine}`, uguale a quello pubblicato)").format(md5_immagine=t['md5_immagine']) if t.get("md5_immagine") else ""), "",
              tr("| Controllo | Esito | Dettaglio |"), "|---|---|---|"]
        for r in res:
            if r["misura"]:
                misure.append((t["nome"], r))
                tag = "  MISURA " + ("✓ " if r["ok"] else "✗ ")
                L.append(f"| {r['controllo']} | {tr('misura: sì') if r['ok'] else tr('misura: no')} | "
                         f"{str(r['dettaglio']).replace('|', '/').replace(chr(10), ' ')[:400]} |")
            else:
                tot += 1
                ok += r["ok"]
                if t.get("indipendente") and not r.get("interno"):
                    tot_i += 1
                    ok_i += r["ok"]
                tag = "  OK     " if r["ok"] else "  ERRORE "
                L.append(f"| {r['controllo']} | {tr('superato') if r['ok'] else '**' + tr('NON SUPERATO') + '**'} | "
                         f"{str(r['dettaglio']).replace('|', '/').replace(chr(10), ' ')[:400]} |")
            print(tag + r["controllo"] + (f" — {r['dettaglio']}" if r["dettaglio"] else ""), flush=True)
        L.append("")
        (out / f"{t['nome']}.log").write_text(cp.stdout + "\n" + cp.stderr, encoding="utf-8")
    head = ["", tr("**Esito: {ok} controlli superati su {tot}").format(ok=ok, tot=tot) + (tr(" — TUTTI SUPERATI**") if ok == tot else
                                                              tr(" — {v1} NON SUPERATI**").format(v1=tot - ok))]
    if tot_i:
        head.append(tr("- Di cui su immagini pubbliche con valori attesi pubblicati da terzi: {ok_i} su {tot_i}").format(ok_i=ok_i, tot_i=tot_i))
    if misure:
        head.append(tr("- Misure (limiti noti, non contano nell'esito): {v1} positive su {v2}; il dettaglio è "
                       "nelle tabelle").format(v1=sum(1 for _n, r in misure if r['ok']), v2=len(misure)))
    if saltate:
        head.append(tr("- Prove saltate perché l'immagine non è nella cartella: ") + ", ".join(
            f"{t['nome']}" + (f" ({t['scarica']})" if t.get("scarica") else "") for t in saltate))
    L[1:1] = head
    rep = out / f"collaudo_{stamp}.md"
    rep.write_text("\n".join(L), encoding="utf-8")
    print(tr("\nEsito: {ok}/{tot} controlli superati").format(ok=ok, tot=tot) + (tr(" ({ok_i}/{tot_i} su immagini pubbliche)").format(ok_i=ok_i, tot_i=tot_i) if tot_i else "")
          + (tr(", {v1} prove saltate").format(v1=len(saltate)) if saltate else "") + tr(". Rapporto: {rep}").format(rep=rep))
    sys.exit(0 if ok == tot else 1)


if __name__ == "__main__":
    main()
