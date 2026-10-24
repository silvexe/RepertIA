# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - riscontro con altri strumenti forensi (By silvexe).

Confronta l'elenco dei file del caso con un elenco esportato da un altro strumento sulla STESSA copia
forense (Autopsy, FTK Imager, X-Ways, EnCase, Magnet AXIOM, Sleuth Kit `fls -m`…): file trovati da
entrambi, con hash uguale o diverso, file trovati da uno solo, stato «cancellato» discordante.
È il riscontro con un secondo strumento da citare nel verbale: lo strumento esterno legge la copia per
conto suo, quindi un hash uguale è una conferma indipendente del contenuto estratto da RepertIA.

Formati riconosciuti da soli (CSV con `,` `;` o tabulazione, anche UTF-16):
- FTK Imager «Export File Hash List»       (MD5, SHA1, FileNames)
- FTK Imager «Export Directory Listing»    (Filename, Full Path, Size (bytes), …, Is Deleted)
- Autopsy, esportazione CSV di una tabella (Name, Location, Size, MD5 Hash, SHA-256 Hash, Flags(Dir)…)
- elenchi generici con una colonna di percorso (Path, Full Path, Location, FileNames, Percorso, Nome…)
  e colonne facoltative per dimensione, MD5, SHA-1, SHA-256, cancellato
- body file di Sleuth Kit (`fls -r -m /`, separato da |; MD5 se generato con `-h`)
"""
import codecs
import csv
import datetime as dt
import io
import json
import re
from pathlib import Path

import forense_agent as fa
from forense_lingua import tr, N_  # noqa: E402

PATH_COLS = ("full path", "fullpath", "location", "filenames", "file name with path", "path", "percorso",
             "percorso completo", "file path", "filepath", "full name", "item path", "source path", "original path")
NAME_COLS = ("filename", "file name", "name", "nome", "nome file")
SIZE_COLS = ("size (bytes)", "size", "file size", "logical size", "dimensione", "byte", "bytes")
MD5_COLS = ("md5", "md5 hash", "hash md5", "md5 checksum", "md5hash")
SHA1_COLS = ("sha1", "sha-1", "sha1 hash", "sha-1 hash", "hash sha1", "sha1 checksum")
SHA256_COLS = ("sha256", "sha-256", "sha256 hash", "sha-256 hash", "hash sha256")
DEL_COLS = ("is deleted", "deleted", "cancellato", "flags(dir)", "flags(meta)", "deleted?", "stato")
# componenti iniziali da togliere ai percorsi esterni (immagine, volume, radice)
SKIP_COMP = re.compile(r"(?i)^(\[root\]|\[orphan\]|vol_vol\d+|partition \d+|"
                       r"partizione \d+|[a-z]:|noname \[.*\]|.*\[(ntfs|fat\d*|exfat|ext\d|hfs\+?|apfs)\]|"
                       r"volume \d+|unallocated space|\[unallocated space\])$")
IMG_COMP = re.compile(r"(?i)\.(e\d\d|ex\d\d|dd|raw|img|001|aff4?|vmdk|vhdx?|dmg|iso|bin)$")
VIRTUAL = re.compile(r"(?i)(^|/)(\$orphanfiles|\$extend|\$badclus|\$secure|\$upcase|\$volume|\$logfile|\$mft|\$mftmirr|"
                     r"\$attrdef|\$bitmap|\$boot|\$fat\d*|\$mbr|\$ofat\d*|\$vbr|\$txf_data|\$tops|\$repair|\$quota|"
                     r"\$objid|\$reparse|\$rmmetadata|\$deleted)(/|:|$)")


def _read_text(path):
    raw = Path(path).read_bytes()
    for bom, enc in ((codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"), (codecs.BOM_UTF8, "utf-8-sig")):
        if raw.startswith(bom):
            return raw.decode(enc, "replace")
    if raw[:200].count(b"\0") > 20:
        return raw.decode("utf-16-le", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252", "replace")


def _col(header, names):
    low = [h.strip().strip('"').lower() for h in header]
    for n in names:
        if n in low:
            return low.index(n)
    return None


def _hex(v, n):
    v = (v or "").strip().lower()
    return v if re.fullmatch(r"[0-9a-f]{%d}" % n, v) and set(v) != {"0"} else None


def _deleted(v, colname):
    v = (v or "").strip().lower()
    if not v:
        return None
    if colname.startswith("flags"):
        return "unalloc" in v or "deleted" in v
    if v in ("yes", "si", "sì", "true", "1", "y", "deleted", "cancellato", "x"):
        return True
    if v in ("no", "false", "0", "n", "allocated", "allocato"):
        return False
    return None


def parse_external(path):
    """Righe {path, size, md5, sha1, sha256, deleted} e descrizione del formato riconosciuto."""
    text = _read_text(path)
    lines = text.splitlines()
    if lines and lines[0].count("|") >= 10 and lines[0].split("|")[0] in ("0", "") or \
            (lines and re.match(r"^[0-9a-f]{32}\|", lines[0])):
        rows = []
        for ln in lines:
            f = ln.split("|")
            if len(f) < 11 or not f[3].startswith(("r/", "-/")):
                continue
            p = f[1]
            dele = p.endswith(" (deleted)") or p.endswith(" (deleted-realloc)")
            p = re.sub(r" \(deleted(-realloc)?\)$", "", p)
            if " -> " in p:
                continue
            rows.append({"path": p, "size": int(f[6]) if f[6].isdigit() else None, "md5": _hex(f[0], 32),
                         "sha1": None, "sha256": None, "deleted": dele})
        return rows, tr("body file di Sleuth Kit (fls -m)")
    sample = "\n".join(lines[:20])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rd = list(csv.reader(io.StringIO(text), dialect))
    hi = next((i for i, r in enumerate(rd[:30]) if _col(r, PATH_COLS + NAME_COLS) is not None), None)
    if hi is None:
        raise ValueError(tr("Nessuna colonna di percorso riconosciuta (Path, Full Path, Location, FileNames…)."))
    header = rd[hi]
    low = [h.strip().lower() for h in header]
    cp, cn = _col(header, PATH_COLS), _col(header, NAME_COLS)
    cs, c5, c1, c2 = _col(header, SIZE_COLS), _col(header, MD5_COLS), _col(header, SHA1_COLS), _col(header, SHA256_COLS)
    cd = _col(header, DEL_COLS)
    fmt = (tr("FTK Imager, elenco hash") if low[:3] == ["md5", "sha1", "filenames"] else
           tr("FTK Imager, elenco della cartella") if "is deleted" in low and "full path" in low else
           tr("Autopsy (tabella esportata)") if "location" in low and ("flags(dir)" in low or "md5 hash" in low) else
           tr("elenco generico"))
    rows = []
    for r in rd[hi + 1:]:
        if not r or all(not x.strip() for x in r):
            continue
        g = lambda c: r[c] if c is not None and c < len(r) else ""
        p = g(cp)
        if fmt == tr("Autopsy (tabella esportata)") and cn is not None and p and not p.rstrip("/\\").lower().endswith(
                g(cn).lower()):
            p = p.rstrip("/\\") + "/" + g(cn)
        if not p:
            p = g(cn)
        if not p:
            continue
        size = re.sub(r"[^\d]", "", g(cs)) if cs is not None else ""
        rows.append({"path": p, "size": int(size) if size else None, "md5": _hex(g(c5), 32), "sha1": _hex(g(c1), 40),
                     "sha256": _hex(g(c2), 64), "deleted": _deleted(g(cd), low[cd]) if cd is not None else None})
    return rows, fmt


def norm_parts(p):
    """Componenti del percorso esterno senza immagine, volume e radice."""
    comps = [c for c in re.split(r"[\\/]+", p.strip()) if c and c != "."]
    while comps and (IMG_COMP.search(comps[0]) or SKIP_COMP.match(comps[0])):
        comps.pop(0)
    return [c for c in comps if c.lower() != "[root]"]


def _file_hashes(case, con, part, inode, path, deleted, cache):
    key = (part, str(inode))
    if key in cache:
        return cache[key]
    r = None
    try:
        r = con.execute("SELECT size, md5, sha1, sha256 FROM hashes WHERE part=? AND inode=? LIMIT 1",
                        (part, str(inode))).fetchone()
    except fa.sqlite3.Error:
        pass
    if not r:
        try:
            n, md5, sha1, sha256 = fa.hash_stream(fa.icat_stream(case, part, inode))
            r = (n, md5, sha1, sha256)
        except Exception:
            r = (None, None, None, None)
    cache[key] = r
    return r


def riscontro(case, ext_path, strumento="", progress=None):
    """Esegue il confronto e scrive riscontri/riscontro_<data>.{csv,md}. Restituisce il riepilogo."""
    say = progress or (lambda m: print(m, flush=True))
    rows, fmt = parse_external(ext_path)
    if not rows:
        raise ValueError(tr("Il file non contiene righe di file."))
    say(tr("Riscontro: {v1} righe ({fmt}) da {name}").format(v1=len(rows), fmt=fmt, name=Path(ext_path).name))
    con = fa.sqlite3.connect(case.db_path)
    ours, by_name = {}, {}
    for part, inode, dele, typ, path in con.execute("SELECT part, inode, deleted, type, path FROM files"):
        if not (str(typ).endswith("r") or str(typ).startswith("r")):
            continue
        k = path.lower()
        ours.setdefault(k, []).append((part, inode, dele, path))
        by_name.setdefault(k.rsplit("/", 1)[-1], []).append(k)
    used, cache = set(), {}
    out, stats = [], {"uguali": 0, "hash_diverso": 0, "senza_hash": 0, "solo_esterno": 0, "solo_repertia": 0,
                      "cancellato_discorde": 0, "dimensione_diversa": 0}
    for i, r in enumerate(rows, 1):
        comps = norm_parts(r["path"])
        match = None
        for k in range(0, min(4, len(comps))):
            cand = "/".join(comps[k:]).lower()
            if cand in ours:
                match = cand
                break
        if not match and comps:
            nm = comps[-1].lower()
            cands = [c for c in by_name.get(nm, []) if c.endswith("/".join(comps[-2:]).lower())]
            if len(cands) == 1:
                match = cands[0]
        if not match:
            if VIRTUAL.search("/".join(comps)):
                continue
            stats["solo_esterno"] += 1
            out.append((tr("solo nell'altro strumento"), r["path"], "", "", r["md5"] or r["sha1"] or r["sha256"] or "", "", ""))
            continue
        lst = ours[match]
        if r["deleted"] is not None:
            pick = next((x for x in lst if bool(x[2]) == r["deleted"]), lst[0])
        else:
            pick = lst[0]
        used.add((pick[0], str(pick[1])))
        part, inode, dele, fpath = pick
        size, md5, sha1, sha256 = _file_hashes(case, con, part, inode, fpath, dele, cache)
        notes = []
        if r["deleted"] is not None and bool(dele) != r["deleted"]:
            stats["cancellato_discorde"] += 1
            notes.append(tr("cancellato: RepertIA {v1}, altro strumento {v2}").format(v1=tr('sì') if dele else tr('no'), v2=tr('sì') if r['deleted'] else tr('no')))
        if r["size"] is not None and size is not None and r["size"] != size:
            stats["dimensione_diversa"] += 1
            notes.append(tr("dimensione {size} contro {size2}").format(size=size, size2=r['size']))
        cmp_ = [(a, x, y) for a, x, y in (("MD5", r["md5"], md5), ("SHA-1", r["sha1"], sha1), ("SHA-256", r["sha256"], sha256)) if x]
        if not cmp_:
            stats["senza_hash"] += 1
            esito = tr("presente in entrambi (l'altro strumento non dà hash)")
        elif all(x == y for _a, x, y in cmp_):
            stats["uguali"] += 1
            esito = tr("hash uguale")
        else:
            stats["hash_diverso"] += 1
            esito = tr("HASH DIVERSO")
            notes.append("; ".join(tr("{a} RepertIA {y} / altro {x}").format(a=a, y=y, x=x) for a, x, y in cmp_ if x != y))
        out.append((esito, r["path"], fpath, f"{part}/{inode}", ", ".join(a for a, _x, _y in cmp_), md5 or "", " · ".join(notes)))
        if i % 500 == 0:
            say(tr("Riscontro: {i} di {v1} righe confrontate").format(i=i, v1=len(rows)))
    for k, lst in ours.items():
        for part, inode, dele, fpath in lst:
            if (part, str(inode)) in used or VIRTUAL.search(fpath):
                continue
            stats["solo_repertia"] += 1
            out.append((tr("solo in RepertIA"), "", fpath, f"{part}/{inode}", "", "", tr("cancellato") if dele else ""))
    con.close()
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    d = case.root / "riscontri"
    d.mkdir(exist_ok=True)
    csvp = d / f"riscontro_{stamp}.csv"
    with open(csvp, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow([tr(h) for h in ["esito", "percorso_altro_strumento", "percorso_repertia", "partizione/inode", "hash_confrontati",
                    "md5_repertia", "note"]])
        w.writerows(sorted(out, key=lambda x: (x[0] != tr("HASH DIVERSO"), x[0], x[1] or x[2])))
    src_sha = fa.sha256_file(ext_path)
    summ = {"ts": fa.now(), "strumento": strumento or "", "formato": fmt, "file_esterno": str(ext_path),
            "sha256_file_esterno": src_sha, "righe": len(rows), **stats, "csv": str(csvp.relative_to(case.root))}
    summ["esito"] = ("concorde" if not stats["hash_diverso"] and not stats["cancellato_discorde"] else tr("con differenze"))
    md = d / f"riscontro_{stamp}.md"
    md.write_text("\n".join(riscontro_md(summ) + ["", tr("Dettaglio riga per riga: `") + summ["csv"] + "`."]), encoding="utf-8")
    summ["md"] = str(md.relative_to(case.root))
    case.meta.setdefault("riscontri", []).append(summ)
    case.save()
    case.log("riscontro", summ)
    say(tr("Riscontro: ") + testo(summ))
    return summ


def testo(s):
    return (tr("{uguali} file con hash uguale, {hash_diverso} con hash diverso, {senza_hash} presenti in "
               "entrambi senza hash, {solo_esterno} solo nell'altro strumento, {solo_repertia} solo in "
               "RepertIA, {cancellato_discorde} con stato «cancellato» discorde").format(uguali=s['uguali'], hash_diverso=s['hash_diverso'], senza_hash=s['senza_hash'], solo_esterno=s['solo_esterno'], solo_repertia=s['solo_repertia'], cancellato_discorde=s['cancellato_discorde']))


def riscontro_md(s):
    return [tr("### Riscontro con {v1} ({ts})").format(v1=s.get('strumento') or tr('altro strumento'), ts=s['ts']), "",
            tr("- File dell'altro strumento: `{file_esterno}` ({formato}, {righe} righe; SHA-256 del file "
               "`{sha256_file_esterno}`)").format(file_esterno=s['file_esterno'], formato=s['formato'], righe=s['righe'], sha256_file_esterno=s['sha256_file_esterno']),
            tr("- Esito: **{v1}**").format(v1=tr('CONCORDE') if s['esito'] == 'concorde' else tr('CON DIFFERENZE')),
            tr("- File trovati da entrambi con hash uguale: {uguali}").format(uguali=s['uguali']),
            tr("- File trovati da entrambi con hash DIVERSO: {hash_diverso}").format(hash_diverso=s['hash_diverso']),
            tr("- File trovati da entrambi, l'altro strumento non riporta hash: {senza_hash}").format(senza_hash=s['senza_hash']),
            tr("- Stato «cancellato» discorde: {cancellato_discorde}; dimensione diversa: {dimensione_diversa}").format(cancellato_discorde=s['cancellato_discorde'], dimensione_diversa=s['dimensione_diversa']),
            tr("- Solo nell'altro strumento: {solo_esterno}; solo in RepertIA: {solo_repertia} (voci "
               "virtuali di Sleuth Kit escluse; l'altro elenco può essere parziale, per esempio solo una "
               "cartella o solo i file con hash)").format(solo_esterno=s['solo_esterno'], solo_repertia=s['solo_repertia']),
            tr("- Dettaglio: `{csv}`").format(csv=s['csv'])]


def report_md(case):
    r = case.meta.get("riscontri") or []
    if not r:
        return []
    L = [tr("## Riscontro con altri strumenti"), "",
         tr("Elenchi esportati da altri strumenti forensi sulla stessa copia e confrontati con quello di RepertIA "
         "(un hash uguale è calcolato in modo indipendente dai due strumenti)."), ""]
    for s in r:
        L += riscontro_md(s) + [""]
    return L


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        sys.exit(tr("Uso: forense_riscontro.py CASO FILE_ESPORTATO [nome dello strumento]"))
    print(testo(riscontro(fa.load_case(sys.argv[1]), sys.argv[2], " ".join(sys.argv[3:]))))
