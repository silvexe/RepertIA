#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - interfaccia, immagine del disco, tracce e file di plaso.

(3.0.4) Codice spostato da forense_gui.py senza modifiche, per avere file più corti. Si carica tramite
forense_gui, che ne riesporta i nomi: gli altri moduli continuano a usare «G.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («G.<nome>»).
"""
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import threading
from collections import Counter
from pathlib import Path
from forense_lingua import tr
import forense_agent as fa
import forense_lingua as lg

import forense_gui as G
from forense_gui import (
    SES, altri_args, altri_where, audio_from, audio_where, bm_categories, cache_dir, clean_fs_path, file_ident, lp,
    media_contenuto, nav_db, photo_args, photo_where, reveal, trascr_where, video_args, video_where)

# ------------------------------------------------- immagine, tracce e file di plaso
#
# Le tracce di bulk_extractor hanno un offset nell'immagine; gli eventi di plaso un
# percorso (display_name). Qui si risale al file del file system per anteprima,
# esadecimale, albero ed Esplora file; l'immagine stessa si legge in esadecimale.

IMG_SIZE = {}
BSIZE = {}
IMG_SEARCH_WINDOW = 64 << 20


def image_ident(case):
    img = case.image
    if img not in IMG_SIZE:
        size = None
        cp = subprocess.run(["img_stat", img], capture_output=True, stdin=subprocess.DEVNULL)
        t = fa.dec(cp.stdout)
        m = re.search(r"Size in bytes:\s*(\d+)", t) or re.search(r"Size[^\n:]*:\s*(\d+)", t)
        if m:
            size = int(m.group(1))
        if not size and Path(img).exists():
            size = sum(p.stat().st_size for p in fa.image_segments(img))
        IMG_SIZE[img] = size or 0
    name = Path(img).name
    return {"source": "image", "part": None, "inode": None, "path": tr("Copia forense {name}").format(name=name),
            "name": name, "key": "image", "ext": "", "size": IMG_SIZE[img], "deleted": 0}


def image_read(case, off, n):
    """Byte della copia forense dall'offset `off` (raw: lettura diretta; E01: img_cat)."""
    img = case.image
    if not Path(img).exists():
        raise ValueError(tr("La copia forense non è raggiungibile: collega il disco che la contiene."))
    if not fa.is_e01(img):
        with open(img, "rb") as fh:
            fh.seek(off)
            return fh.read(n)
    s, e = off // 512, (off + n - 1) // 512
    cp = subprocess.run(["img_cat", "-s", str(s), "-e", str(e), img], capture_output=True,
                        stdin=subprocess.DEVNULL, timeout=120)
    return cp.stdout[off - s * 512:][:n]


def image_chunks(case, start, size=4 << 20):
    """Per la ricerca nell'esadecimale dell'immagine: solo una finestra dall'offset di partenza."""
    pos, end = start, start + IMG_SEARCH_WINDOW
    while pos < end:
        c = image_read(case, pos, min(size, end - pos))
        if not c:
            break
        yield pos, c
        pos += len(c)


def _fs_block_size(case, part):
    key = (case.image, part)
    if key not in BSIZE:
        t = fa.dec(fa.sh(case, ["fsstat", "-o", str(part), case.image], timeout=600).stdout)
        fs = next((p.get("fs") or "" for p in case.meta.get("partitions", []) if p["offset"] == part), "")
        keys = (["Sector Size"] if "FAT" in fs.upper() else []) + ["Block Size", "Cluster Size", "Sector Size"]
        BSIZE[key] = next((int(m.group(1)) for k in keys for m in [re.search(k + r":\s*(\d+)", t)] if m), 512)
    return BSIZE[key]


def _istat_blocks(text):
    """Blocchi del contenuto dall'output di istat (ext, FAT, NTFS $DATA non residente, HFS)."""
    out, on = [], False
    for line in text.splitlines():
        s = line.strip()
        if re.match(r"(Direct Blocks|Sectors|Blocks|Data Fork Blocks):", s) or \
                re.match(r"Type: \$DATA \(128-\d+\)\s+Name: N/A\s+Non-Resident", s):
            if out:
                break
            on = True
            continue
        if on:
            if s and re.fullmatch(r"[\d\s]+", s):
                out += [int(x) for x in s.split()]
            elif out:
                break
    return out


def trace_locate(case, b):
    """Il file che contiene un byte dell'immagine (offset di una traccia), con la posizione
    del byte dentro il file; altrimenti dove si trova (spazio libero, fuori partizione)."""
    m = re.match(r"\d+", str(b.get("offset") or "").strip())
    if not m:
        raise ValueError(tr("Offset non valido."))
    off = int(m.group())
    for p in case.meta.get("partitions", []):
        start = (p["apfs"]["real_offset"] if p.get("apfs") else p["offset"]) * 512
        end = start + p["length_sectors"] * 512 if p.get("length_sectors") else None
        if off < start or (end is not None and off >= end):
            continue
        if p.get("apfs"):
            return {"found": False, "offset": off,
                    "message": tr("Byte {off}: dentro il contenitore APFS (volume «{v1}»): la localizzazione del file da un "
                                  "byte non è supportata per APFS.").format(off=off, v1=p['apfs'].get('name'))}
        if not p.get("readable"):
            return {"found": False, "offset": off,
                    "message": tr("Byte {off}: partizione offset {offset} non leggibile da TSK.").format(off=off, offset=p['offset'])}
        bs = _fs_block_size(case, p["offset"])
        blk = (off - start) // bs
        cp = fa.sh(case, ["ifind", "-o", str(p["offset"]), "-d", str(blk), case.image], timeout=600)
        ino = fa.dec(cp.stdout).strip()
        where = tr("Byte {off}: partizione offset {offset}, blocco {blk} (da {bs} byte)").format(off=off, offset=p['offset'], blk=blk, bs=bs)
        if cp.returncode != 0 or not fa.INODE_RE.fullmatch(ino):
            return {"found": False, "offset": off,
                    "message": where + tr(": nessun file lo usa (spazio non allocato o metadati).")}
        it = file_ident(case, {"part": p["offset"], "inode": ino})
        fo = None
        if b.get("no_istat"):
            return {"found": True, "offset": off, "part": p["offset"], "inode": ino, "path": it["path"],
                    "deleted": it["deleted"], "file_offset": None, "message": where + tr(": inode {ino} {path}").format(ino=ino, path=it['path'])}
        try:
            blocks = _istat_blocks(fa.dec(fa.sh(case, ["istat", *fa.tsk_tz(case), "-o", str(p["offset"]), case.image, ino],
                                                timeout=600).stdout))
            if blk in blocks:
                fo = blocks.index(blk) * bs + (off - start) % bs
        except (subprocess.SubprocessError, OSError):
            pass
        return {"found": True, "offset": off, "part": p["offset"], "inode": ino, "path": it["path"],
                "deleted": it["deleted"], "file_offset": fo,
                "message": where + tr(": inode {ino} {path}").format(ino=ino, path=it['path']) + (tr(" (CANCELLATO)") if it["deleted"] else "")
                + (tr(", byte {fo} del file").format(fo=fo) if fo is not None else "")}
    return {"found": False, "offset": off, "message": tr("Byte {off}: fuori dalle partizioni.").format(off=off)}


def trace_paths(case, b):
    """Percorso del file che contiene ciascun offset (righe visibili delle evidenze di interesse).
    I risultati restano in cache nel caso, così ifind si esegue una volta sola per offset."""
    from concurrent.futures import ThreadPoolExecutor
    offs = []
    for o in (b.get("offsets") or [])[:400]:
        m = re.match(r"\d+", str(o))
        if m and m.group() not in offs:
            offs.append(m.group())
    db = sqlite3.connect(cache_dir(case, "evidenze") / "percorsi.sqlite", timeout=30)
    try:
        db.execute("CREATE TABLE IF NOT EXISTS pos(offset TEXT PRIMARY KEY, data TEXT)")
        out = {}
        for o in offs:
            r = db.execute("SELECT data FROM pos WHERE offset=?", (o,)).fetchone()
            if r:
                out[o] = json.loads(r[0])
        todo = [o for o in offs if o not in out]

        def one(o):
            try:
                x = trace_locate(case, {"offset": o, "no_istat": True})
            except Exception as e:      # noqa: BLE001 - una riga non deve fermare le altre
                return o, {"found": False, "message": str(e), "temp": True}
            return o, {k: x.get(k) for k in ("found", "part", "inode", "path", "deleted", "message")}
        if todo:
            with ThreadPoolExecutor(max_workers=4) as ex:
                for o, d in ex.map(one, todo):
                    out[o] = d
                    if not d.get("temp"):
                        db.execute("INSERT OR REPLACE INTO pos VALUES (?,?)", (o, json.dumps(d)))
            db.commit()
    finally:
        db.close()
    return {"paths": out}


def plaso_fs_path(p):
    """display_name di plaso (TSK:/..., NTFS:\\..., OS:C:\\...) -> percorso nel file system."""
    p = (p or "").strip()
    p = re.sub(r"^(?:[A-Za-z][\w\-]*:)+(?=[/\\])", "", p)
    p = re.sub(r"^(?:[A-Za-z][\w\-]*:)+[A-Za-z]:(?=[/\\])", "", p)
    p = re.sub(r"^[A-Za-z]:(?=[/\\])", "", p)
    return clean_fs_path(p)


def resolve_path(case, b):
    """(2.20) Un percorso citato (risposta dell'agente, testo di un evento): file della copia/estrazione con il metodo."""
    import forense_percorsi as fp
    r = fp.risolvi_testo(case, str(b.get("path") or ""), b.get("user") or None)
    out = G.cited_ref(dict(r, campo="", valore=b.get("path"), ruolo="file"), fa.is_mobile(case))
    out["found"] = r.get("stato") == "trovato"
    return out


def tl_resolve(case, b):
    """Il file del file system a cui si riferisce un evento di plaso (dal suo percorso): stessa ricerca dei file citati
    (forense_percorsi), poi il confronto diretto sull'albero."""
    p = plaso_fs_path(b.get("path"))
    if not p:
        raise ValueError(tr("L'evento non indica un file."))
    try:
        import forense_percorsi as fp
        r = fp.risolvi_testo(case, p)
        if r.get("stato") == "trovato" and r.get("inode") and not r.get("isdir"):
            return {"part": r["part"], "inode": str(r["inode"]), "path": r["path"], "deleted": r.get("deleted"),
                    "metodo": r.get("metodo"), "label": fp.etichetta_disco(r, fa.is_mobile(case))}
    except (ValueError, sqlite3.Error, OSError):
        pass
    con = nav_db(case)
    try:
        sql = ("SELECT part, inode, path, deleted FROM nav WHERE isdir=0 AND inode IS NOT NULL "
               "AND inode <> '' AND ")
        r = con.execute(sql + "path = ? ORDER BY deleted LIMIT 1", (p,)).fetchone() or \
            con.execute(sql + "lower(path) = lower(?) ORDER BY deleted LIMIT 1", (p,)).fetchone() or \
            con.execute(sql + "path LIKE ? ESCAPE '\\' ORDER BY deleted, length(path) LIMIT 1",
                        ("%/" + p.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_"),)).fetchone()
    finally:
        con.close()
    if not r:
        raise ValueError(tr("Il file «{p}» non è nell'albero del file system della copia.").format(p=p))
    return {"part": r[0], "inode": str(r[1]), "path": r[2], "deleted": r[3]}


def export_reveal(case, b):
    """Esporta il file (se non già esportato) e lo mostra in Esplora file / Finder."""
    o, i = int(b["part"]), str(b["inode"])
    if not fa.INODE_RE.fullmatch(i):
        raise ValueError(tr("inode non valido."))
    msg = SES.case_tools["export_file"](o, i)
    found = sorted(case.export_dir.glob(f"p{o}_i{i}_*"))
    if found:
        reveal(found[0])
    return {"message": msg}


def reveal_trace(case, kind):
    """Mostra il file di bulk_extractor con le tracce di quel tipo."""
    c = case.meta.get("carving") or {}
    d = Path(c.get("dir") or "carving")
    d = d if d.is_absolute() else case.root / d
    f = d / "bulk_extractor" / f"{re.sub(r'[^\w]', '', kind or '')}.txt"
    target = f if f.exists() else d / "bulk_extractor"
    if not target.exists():
        raise ValueError(tr("File di bulk_extractor non trovato nella cartella del caso."))
    reveal(target)
    return {"ok": True}


DOC_EXT_RE = re.compile(r"\.([A-Za-z0-9_+\-]{1,10})$")


def doc_ext_counts(con, limit=60):
    """Documenti indicizzati divisi per estensione: [(estensione, quanti)], dal più numeroso.
    «~posta» = messaggi di posta (non hanno un file), «~senza» = nome senza estensione."""
    cnt = Counter()
    try:
        for path, source in con.execute("SELECT path, source FROM doc_text"):
            if source == "posta":
                cnt["~posta"] += 1
                continue
            m = DOC_EXT_RE.search(re.split(r"[/\\]| › ", path or "")[-1])
            cnt[m.group(1).lower() if m else "~senza"] += 1
    except sqlite3.Error:
        return []
    return cnt.most_common(limit)


# (2.20) risposte lente ma stabili (albero dei Risultati, conteggi, grafico della Timeline) tenute in memoria finché non
# cambia nessun file della cartella del caso (data e dimensione): nei casi grandi la prima volta servono secondi, poi
# la stessa richiesta è immediata; un'analisi, una ricerca o un preferito nuovi cambiano i file e svuotano la memoria.
_MEMO = {}
_MEMO_LOCK = threading.Lock()


def case_stamp(case):
    out = []
    try:
        for f in sorted(Path(case.root).iterdir()):
            # database del caso e case.json; non il registro (cresce a ogni operazione) né l'indice della ricerca veloce
            if f.is_file() and (f.name == "case.json" or (".sqlite" in f.name and not f.name.startswith(("ricerca_veloce", "._")))):
                st = f.stat()
                out.append((f.name, st.st_mtime_ns, st.st_size))
    except OSError:
        pass
    return tuple(out)


_MEMO_KEYLOCK = {}

# (dopo la 3.0.2) le stesse risposte anche su disco, nella cache del caso (copie ricostruibili): prima si ricalcolavano a
# ogni avvio del programma e riaprire un caso grande già preparato costava minuti (caso iOS 17 di prova: conteggi 196 s,
# albero dei Risultati 20-46 s). Valgono finché non cambiano i database del caso, il contenuto di case.json (non la sua
# data: a ogni collegamento del server LLM viene riscritto con modello e server) e la versione del programma.
MEMO_DISCO_MAX = 300
_META_FIRMA = {}
META_VOLATILI = ("model", "llm", "llm_esterni")


def meta_firma(case):
    """Impronta di case.json senza le voci che cambiano a ogni apertura (modello e server LLM)."""
    try:
        st = os.stat(lp(case.meta_path))
        k = (str(case.meta_path), st.st_mtime_ns, st.st_size)
        if k not in _META_FIRMA:
            m = json.loads(case.meta_path.read_text())
            for x in META_VOLATILI:
                m.pop(x, None)
            _META_FIRMA.clear()
            _META_FIRMA[k] = hashlib.sha256(json.dumps(m, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()
        return _META_FIRMA[k]
    except (OSError, ValueError, AttributeError):
        return None


def memo_disco_stamp(case):
    return [fa.APP_VERSION, 1, meta_firma(case)] + [list(x) for x in case_stamp(case) if x[0] != "case.json"]


def memo_disco_file(case, k):
    return fa.cache_base(case) / "memo" / (hashlib.sha256(repr(k[1:]).encode()).hexdigest()[:32] + ".json")


def memo_disco_leggi(case, k):
    try:
        with open(lp(memo_disco_file(case, k)), encoding="utf-8") as fh:
            c = json.load(fh)
        if c.get("stamp") == memo_disco_stamp(case) and c.get("k") == repr(k[1:]):
            return c["v"]
    except (OSError, ValueError, KeyError, AttributeError):
        pass
    return None


def memo_disco_scrivi(case, k, v):
    try:
        f = memo_disco_file(case, k)
        f.parent.mkdir(parents=True, exist_ok=True)
        testo = json.dumps({"stamp": memo_disco_stamp(case), "k": repr(k[1:]), "v": v}, ensure_ascii=False)
        tmp = f.with_suffix(".tmp%d" % threading.get_ident())
        with open(lp(tmp), "w", encoding="utf-8") as fh:
            fh.write(testo)
        os.replace(lp(tmp), lp(f))
        vecchi = sorted(f.parent.glob("*.json"), key=lambda p: p.stat().st_mtime)
        for p in vecchi[:max(0, len(vecchi) - MEMO_DISCO_MAX)]:
            p.unlink()
    except (OSError, TypeError, ValueError):
        pass             # valore non scrivibile o disco pieno: resta solo la memoria


def memo(case, key, fn):
    """Risposta in memoria finché i file del caso non cambiano; due richieste uguali insieme la calcolano una volta."""
    k = (str(case.root), lg.lingua()) + tuple(key)
    with _MEMO_LOCK:
        kl = _MEMO_KEYLOCK.setdefault(k, threading.Lock())
    with kl:
        stamp = case_stamp(case)
        with _MEMO_LOCK:
            hit = _MEMO.get(k)
        if hit and hit[0] == stamp:
            return hit[1]
        v = memo_disco_leggi(case, k)
        if v is None:
            v = fn()
            memo_disco_scrivi(case, k, v)
        with _MEMO_LOCK:
            _MEMO[k] = (stamp, v)
            while len(_MEMO) > 200:
                old = next(iter(_MEMO))
                _MEMO.pop(old)
                _MEMO_KEYLOCK.pop(old, None)
        return v


def res_tree(case):
    """Voci e sottovoci per la vista ad albero dei Risultati."""
    con = fa.db_ro(case)
    try:
        has = lambda t: fa.table_exists(con, t)
        q = lambda sql: con.execute(sql).fetchall()
        out = {"tl": dict(q("SELECT origin, COUNT(*) FROM events GROUP BY 1")),
               "plaso": q("SELECT source, COUNT(*) FROM events WHERE origin='plaso' GROUP BY 1 "
                          "ORDER BY 2 DESC LIMIT 40"),
               "ram": q("SELECT source, COUNT(*) FROM events WHERE origin='ram' GROUP BY 1 "      # (3.0.4) timeline della memoria
                        "ORDER BY 2 DESC LIMIT 40"),
               "deleted": con.execute("SELECT COUNT(*) FROM files WHERE deleted>=1").fetchone()[0],
               "trace": q("SELECT kind, COUNT(*) FROM features GROUP BY 1 ORDER BY 2 DESC") if has("features") else [],
               "carved": q("SELECT type, COUNT(*) FROM carved GROUP BY 1 ORDER BY 2 DESC LIMIT 40") if has("carved") else [],
               "doc": q("SELECT kind, COUNT(*) FROM doc_text GROUP BY 1 ORDER BY 2 DESC LIMIT 20") if has("doc_text") else [],
               "docext": doc_ext_counts(con) if has("doc_text") else [],
               "gps": con.execute("SELECT COUNT(*) FROM meta WHERE lat IS NOT NULL").fetchone()[0] if has("meta") else 0,
               "video": con.execute("SELECT COUNT(*) FROM meta WHERE " + video_where(), video_args()).fetchone()[0]
               if has("meta") else 0,
               "foto": con.execute("SELECT COUNT(*) FROM meta WHERE " + photo_where(), photo_args()).fetchone()[0]
               if has("meta") else 0,
               "audio": con.execute("SELECT COUNT(*) FROM files WHERE type LIKE '%/r' AND " + audio_where()).fetchone()[0]}
        mf = media_contenuto(case, con) if has("meta") else None
        if mf:                                   # (3.0.1) riconosciuti dal contenuto, per app, programma o cartella
            out["video"] = con.execute("SELECT COUNT(*) FROM meta WHERE " + mf.filtro("video", col_source="source")).fetchone()[0]
            out["foto"] = con.execute("SELECT COUNT(*) FROM meta WHERE " + mf.filtro("foto", col_source="source")).fetchone()[0]
            out["audio"] = con.execute("SELECT COUNT(*) FROM files WHERE type LIKE '%/r' AND " + mf.filtro("audio")).fetchone()[0]
            out["mediaapp"] = mf.per_app(con)
        if has("meta"):                          # (3.0.1) gli altri file con metadati (PDF, documenti…): sottovoce propria
            out["altri"] = con.execute("SELECT COUNT(*) FROM meta WHERE " + altri_where(mf), [] if mf else altri_args()).fetchone()[0]
        if has("trascrizioni") or has("trascrizioni_analista"):    # (3.0.1) voci delle trascrizioni sotto Audio
            af = audio_from(bool(mf)) + " AS meta WHERE "
            out["trascr"] = {k: con.execute("SELECT COUNT(*) FROM " + af + trascr_where(con, k)).fetchone()[0] for k in ("conf", "auto")}
        if has("meta") and fa.is_mobile(case):   # (2.20) foto, video e audio allegati alle chat (in tutto e per tipo)
            import forense_mobile_gui as fmg
            out["chatmedia"] = fmg.meta_counts(con)
            if mf:
                out["chatmedia"]["foto"] = fmg.media_counts(con, "meta", mf.filtro("foto"), [], mf.filtro("foto", "t.part", "t.inode"))
                out["chatmedia"]["vid"] = fmg.media_counts(con, "meta", mf.filtro("video"), [], mf.filtro("video", "t.part", "t.inode"))
                out["chatmedia"]["aud"] = fmg.media_counts(con, "files", "type LIKE '%/r' AND " + mf.filtro("audio"), [],
                                                           "t.type LIKE '%/r' AND " + mf.filtro("audio", "t.part", "t.inode"))
            else:
                out["chatmedia"]["foto"] = fmg.media_counts(con, "meta", photo_where(), photo_args())
                out["chatmedia"]["vid"] = fmg.media_counts(con, "meta", video_where(), video_args())
                out["chatmedia"]["aud"] = fmg.media_counts(con, "files", "type LIKE '%/r' AND " + audio_where(), [])
    finally:
        con.close()
    out["searches"] = [{"sid": s["sid"], "title": s["title"], "total": s["total"]} for s in G.search_list(case)]
    out.update(G.ext_tree(case))
    try:
        import forense_mappe as fmp
        out["geo"], out["voli_n"] = fmp.riepilogo(case)
    except Exception as e:
        out["geo"], out["voli_n"] = [], 0
        case.log("posizioni_albero", {"errore": str(e)})
    out["bm"] = bm_categories(case) if (case.root / "ricerche.sqlite").exists() else []
    return out
