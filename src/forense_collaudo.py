#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
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
import json
import os
import re
import shutil
import subprocess
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
    for arc in sorted(set(base.glob("*.zip")) | set(base.glob("pubbliche/*")) | set(base.glob("*.bz2")) | set(base.glob("*.gz"))):
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
        shutil.rmtree(case_dir)
    env = dict(os.environ, **{k: str(v) for k, v in (t.get("ambiente") or {}).items()})
    env.pop("FORENSE_DA_GUI", None)
    prog = ["forense_mobile.py", "prepara"] if t.get("tipo") == "smartphone" else ["forense_agent.py", "prepara"]
    cmd = [sys.executable, str(HERE / prog[0]), prog[1], "--image", str(img), "--case", str(case_dir),
           "--lingua", lg.lingua(), *t.get("opzioni", [])]
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
        check(tr("{path} riconosciuto come cancellato").format(path=path), bool(r) and r[2] == 1, tr("presente e segnato cancellato") if r and r[2]
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
    if t.get("tipo") == "smartphone" or (fa.table_exists(con, "artifacts") and
                                         con.execute("SELECT 1 FROM artifacts WHERE src_path IS NOT NULL AND inode IS NOT NULL LIMIT 1").fetchone()):
        controlli_pulsanti(case, con, check)
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


def controlli_reperti_ia(case, check):
    """(2.20.1, AI Act) Un reperto registrato dall'agente (strumento record_finding, con un modello finto) risulta
    «modello IA – da verificare» in findings.json e nel report, che non dice «ogni reperto è stato verificato»; Word e PDF
    dichiarano nei metadati il testo generato da IA; dopo «Confermo, verificato» il reperto è verificato con operatore e
    data, anche nel registro. Più la distinzione fra server LLM locali/privati ed esterni."""
    import forense_gui as G
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
    # (2.20) sottovoce «Audio» di Foto/Video/Audio: i file audio dall'elenco dei file, quelli delle chat con il messaggio
    na = con.execute("SELECT COUNT(*) FROM files WHERE type LIKE '%/r' AND " + G.audio_where()).fetchone()[0]
    if na:
        r = G.results(case, {"kind": "meta", "aud": "1"}, limit=None)
        ok_ext = all(Path(x["path"]).suffix.lower() in G.AUDIO_EXT for x in r["rows"])
        check(tr("Foto/Video/Audio «Audio»: {n} file audio dell'estrazione, tutti nell'elenco").format(n=na),
              r["total"] == na and ok_ext, tr("nell'elenco {n}").format(n=r["total"]), interno=True)
        ca = fmg.media_counts(con, "files", "type LIKE '%/r' AND " + G.audio_where(), [])
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
    check(tr("report portatile: ricerca veloce nei risultati del caso presente"),
          'value="fast"' in html and "fastSearchP" in html, "", interno=True)


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
            finally:
                c2.close()
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
    controlli_portatile_timeline(case, con, check)
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
    «Mostra nell'albero» su un file, un artefatto e, nei casi smartphone, un artefatto di iLEAPP/ALEAPP, una chat e una
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
        # Fonte / Mostra nell'albero
        r, err = call("P", "/api/locate_file", loc)
        got = (r or {}).get("select") or (r or {}).get("dir")
        check(tr("pulsante {b}: {n}").format(b=tr("Mostra nell'albero") if it["source"] == "fs" else tr("Fonte"), n=nome),
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
