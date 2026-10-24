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
    cmd = [sys.executable, str(HERE / "forense_agent.py"), "prepara", "--image", str(img), "--case", str(case_dir),
           "--lingua", lg.lingua(), *t.get("opzioni", [])]
    t0 = dt.datetime.now()
    cp = subprocess.run(cmd, capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)
    res = []

    def check(nome, ok, dettaglio="", misura=False):
        res.append({"controllo": nome, "ok": bool(ok), "dettaglio": dettaglio, "misura": bool(misura)})

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
    av = fa.audit_verifica(case)
    check(tr("registro: catena integra"), av.get("ok") is True, fa.audit_testo(av))
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
        rp = fa.write_report(case)
        txt = rp.read_text(encoding="utf-8")
        need = [tr("## Hash dei dati acquisiti"), tr("## Registro delle operazioni"), tr("## Ambiente di analisi")]
        check(tr("report con le sezioni di integrità"), all(n in txt for n in need), "")
    except Exception as e:
        check("report", False, f"{type(e).__name__}: {e}")
    con.close()
    return res, cp


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
                L.append(f"| {r['controllo']} | {'misura: sì' if r['ok'] else 'misura: no'} | "
                         f"{str(r['dettaglio']).replace('|', '/').replace(chr(10), ' ')[:400]} |")
            else:
                tot += 1
                ok += r["ok"]
                if t.get("indipendente"):
                    tot_i += 1
                    ok_i += r["ok"]
                tag = "  OK     " if r["ok"] else "  ERRORE "
                L.append(f"| {r['controllo']} | {'superato' if r['ok'] else '**NON SUPERATO**'} | "
                         f"{str(r['dettaglio']).replace('|', '/').replace(chr(10), ' ')[:400]} |")
            print(tag + r["controllo"] + (f" — {r['dettaglio']}" if r["dettaglio"] else ""), flush=True)
        L.append("")
        (out / f"{t['nome']}.log").write_text(cp.stdout + "\n" + cp.stderr, encoding="utf-8")
    head = ["", f"**Esito: {ok} controlli superati su {tot}" + (tr(" — TUTTI SUPERATI**") if ok == tot else
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
