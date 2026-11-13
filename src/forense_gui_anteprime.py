#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - interfaccia, anteprime, miniature, esadecimale.

(3.0.4) Codice spostato da forense_gui.py senza modifiche, per avere file più corti. Si carica tramite
forense_gui, che ne riesporta i nomi: gli altri moduli continuano a usare «G.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («G.<nome>»).
"""
import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path
from forense_lingua import tr
import forense_agent as fa

import forense_gui as G
from forense_gui import (
    IS_MAC, IS_WIN, PAGE, SES, TOKEN, apfs_istat_to_zone, check_dest, exif_no_workcopy, exif_to_zone, istat_to_zone,
    lp, nav_db, tz_label, unique, yes)

# ------------------------------------------------- anteprime, miniature, esadecimale
#
# I file della copia vengono estratti una volta (icat, sola lettura) in <caso>/cache/file/
# e da lì si generano miniature, pagine dei PDF, conversioni e la vista esadecimale.
# La cache è ricostruibile e si può cancellare in qualsiasi momento.

import base64, hashlib, tempfile
CACHE_MAX = 2 << 30            # oltre questa dimensione il file non viene copiato in cache
THUMB_SEM = threading.Semaphore(3)
THUMB_GEN = f"{fa.APP_VERSION}-2"           # (2.20) versione dei segni «.nessuna»: cambiandola si riprovano
PAGE_SEM = threading.Semaphore(2)     # pagine PDF disegnate in parallelo al massimo
PAGE_BLOCK = 4                        # pagine disegnate con un solo pdftoppm
LO_LOCK = threading.Lock()            # LibreOffice: un profilo, una conversione alla volta
KEY_LOCKS, KEY_LOCK = {}, threading.Lock()
IMG_NATIVE = {".jpg", ".jpeg", ".jpe", ".jfif", ".png", ".gif", ".webp", ".bmp", ".ico", ".avif"}
IMG_CONVERT = {".heic", ".heif", ".tif", ".tiff", ".dng", ".cr2", ".cr3", ".nef", ".arw", ".orf",
               ".raf", ".psd", ".tga"}
IMG_ALL = IMG_NATIVE | IMG_CONVERT
WORD_EXT = {".doc", ".docx", ".docm", ".dot", ".dotx", ".rtf", ".odt", ".wpd", ".wps", ".pages"}
OFFICE_EXT = {".xls", ".xlsx", ".xlsm", ".xlsb", ".ods", ".ppt", ".pptx", ".pptm", ".pps", ".ppsx",
              ".odp", ".key", ".numbers", ".vsd", ".vsdx", ".pub"}
VIDEO_MIME = {".mp4": "video/mp4", ".m4v": "video/mp4", ".mov": "video/quicktime",
              ".webm": "video/webm", ".3gp": "video/3gpp"}
# (2.20) marchi «ftyp» delle foto HEIF/AVIF: con «ftyp» e un altro marchio un file senza estensione è un video MP4/MOV
HEIF_BRANDS = (b"heic", b"heix", b"hevc", b"heim", b"heis", b"mif1", b"msf1", b"avif", b"avis")


def video_brand(ext, head):
    """Estensione (.mp4/.mov) di un video senza estensione riconosciuto dall'intestazione, altrimenti None."""
    brand = head[8:12] if head[4:8] == b"ftyp" else b""
    if ext or not brand or brand in HEIF_BRANDS:
        return None
    return ".mov" if brand == b"qt  " else ".mp4"


VIDEO_OTHER = {".avi", ".mkv", ".wmv", ".mpg", ".mpeg", ".flv", ".mts", ".m2ts"}
VIDEO_EXT = sorted(set(VIDEO_MIME) | VIDEO_OTHER)       # (2.20) sottovoce «Video» di Foto e metadati


def video_where(col="path"):
    return "(" + " OR ".join(f"lower({col}) LIKE ?" for _ in VIDEO_EXT) + ")"


def video_args():
    return ["%" + e for e in VIDEO_EXT]


PHOTO_EXT = sorted(IMG_ALL)         # (2.20) casella «Solo foto» di Foto e metadati


def photo_where(col="path"):
    return "(" + " OR ".join(f"lower({col}) LIKE ?" for _ in PHOTO_EXT) + ")"


def photo_args():
    return ["%" + e for e in PHOTO_EXT]
AUDIO_MIME = {".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".aac": "audio/aac", ".wav": "audio/wav",
              ".ogg": "audio/ogg", ".oga": "audio/ogg", ".opus": "audio/ogg", ".flac": "audio/flac",
              ".amr": "audio/amr"}
# (2.20) sottovoce «Audio» di Foto/Video/Audio: i file audio non sono nella tabella meta (l'indicizzazione dei metadati
# guarda foto, video e documenti) e si prendono dall'elenco dei file del caso, anche nei casi già preparati
AUDIO_EXT = sorted(set(AUDIO_MIME) | {".caf", ".aif", ".aiff", ".wma", ".3ga", ".m4r", ".awb"})


def audio_where(col="path"):
    """Condizione SQL (estensioni costanti, senza parametri: si usa anche dentro una sottoquery)."""
    return "(" + " OR ".join(f"lower({col}) LIKE '%{e}'" for e in AUDIO_EXT) + ")"


def audio_from(contenuto=False):
    """Righe «come meta» dei file audio: dalla tabella files, con i metadati se l'indicizzazione li ha letti.
    `contenuto` (3.0.1, telefoni): gli audio riconosciuti dal contenuto (tabella media_file) invece che per estensione."""
    import forense_mobile_media as fmm
    return ("(SELECT f.rowid AS rowid, COALESCE(m.source, 'fs') AS source, f.part AS part, f.inode AS inode, "
            "f.deleted AS deleted, f.path AS path, m.make AS make, m.model AS model, m.taken AS taken, m.lat AS lat, "
            "m.lon AS lon, m.author AS author, m.data AS data FROM files f LEFT JOIN meta m "
            "ON m.part = f.part AND m.inode = f.inode WHERE f.type LIKE '%/r' AND "
            + (fmm.filtro("audio", "f.part", "f.inode") if contenuto else audio_where("f.path")) + ")")


def altri_where(mf=None):
    """(3.0.1) Righe di meta che non sono foto, video o audio (con `mf` riconosciuti dal contenuto, altrimenti per estensione;
    parametri da altri_args() solo senza `mf`)."""
    if mf:
        return "NOT " + mf.filtro("foto", col_source="source") + " AND NOT " + mf.filtro("video", col_source="source") \
            + " AND NOT " + mf.filtro("audio", col_source="source")
    return "NOT " + photo_where() + " AND NOT " + video_where() + " AND NOT " + audio_where()


def altri_args():
    return photo_args() + video_args()


def media_tutti_from(contenuto=False):
    """(3.0.1) Voce principale di Foto/Video/Audio: le righe di meta (foto, video e gli altri file con metadati) più gli audio
    che non vi sono già, così il numero accanto alla voce è quello dei file che apre e comprende le sottovoci. Gli audio presi
    dall'elenco dei file hanno l'id negativo (rowid di files) per non confondersi con quelli di meta."""
    cols = "source, part, inode, deleted, path, make, model, taken, lat, lon, author, data"
    return (f"(SELECT rowid AS rowid, {cols} FROM meta UNION ALL SELECT -f.rowid AS rowid, 'fs' AS source, f.part AS part, "
            "f.inode AS inode, f.deleted AS deleted, f.path AS path, NULL AS make, NULL AS model, NULL AS taken, NULL AS lat, "
            "NULL AS lon, NULL AS author, NULL AS data FROM " + audio_senza_meta(contenuto) + ")")


def audio_senza_meta(contenuto=False):
    """(dopo la 3.0.2) «FROM … WHERE …» degli audio dell'elenco dei file che non hanno una riga in meta. Prima era un
    NOT EXISTS su meta per ogni audio: nei casi senza indice su meta(part, inode) SQLite rileggeva tutta la tabella ogni
    volta (sul caso iOS 17 grande 196 s per il solo conteggio); con l'unione esterna la legge una volta sola."""
    import forense_mobile_media as fmm
    return ("files f LEFT JOIN meta m ON m.part = f.part AND m.inode = f.inode WHERE f.type LIKE '%/r' AND "
            + (fmm.filtro("audio", "f.part", "f.inode") if contenuto else audio_where("f.path")) + " AND m.rowid IS NULL")


def media_tutti_conta(con, contenuto=False):
    """Numero di righe di media_tutti_from senza costruirle: le righe di meta più gli audio che non vi sono già."""
    return (con.execute("SELECT COUNT(*) FROM meta").fetchone()[0]
            + con.execute("SELECT COUNT(*) FROM " + audio_senza_meta(contenuto)).fetchone()[0])


def trascr_where(con, mtr):
    """(3.0.1) Condizione SQL (colonne part, inode) per le trascrizioni confermate o automatiche ancora da confermare."""
    import forense_trascrizione as ftr
    conf = ftr.confermate_sql() if fa.table_exists(con, "trascrizioni_analista") else "0"
    if mtr == "conf":
        return conf
    auto = "(part, inode) IN (SELECT part, inode FROM trascrizioni)" if fa.table_exists(con, "trascrizioni") else "0"
    return f"({auto} AND NOT {conf})"


def media_contenuto(case, con):
    """(3.0.1) Il modulo forense_mobile_media se il caso (telefono o memoria di massa) ha l'elenco di foto, video e audio
    riconosciuti dal contenuto (indicizzazione dalla 3.0.1); altrimenti None e le sezioni restano per estensione."""
    import forense_mobile_media as fmm
    return fmm if fmm.presente(con) else None
TEXT_LIKE = set(fa.TEXT_EXT) | {".ini", ".cfg", ".conf", ".yaml", ".yml", ".js", ".py", ".sh",
                                ".bat", ".ps1", ".vbs", ".sql", ".tsv", ".srt", ".vcf", ".ics",
                                ".plist", ".reg", ".inf", ".css", ".php", ".c", ".h", ".java",
                                ".mbox", ".svg"}
RAW_MIME = {**{e: "image/jpeg" for e in (".jpg", ".jpeg", ".jpe", ".jfif")}, ".png": "image/png",
            ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
            ".ico": "image/x-icon", ".avif": "image/avif", **VIDEO_MIME, **AUDIO_MIME}
IS_LINUX = platform.system() == "Linux"


def tool(name):
    """Percorso di un programma esterno, anche fuori dal PATH (LibreOffice su Mac)."""
    p = shutil.which(name)
    if not p and name == "soffice" and IS_MAC:
        app = Path("/Applications/LibreOffice.app/Contents/MacOS/soffice")
        p = str(app) if app.exists() else None
    if not p and name == "convert":
        p = shutil.which("magick")
    return p


def run_quiet(cmd, timeout=60):
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout,
                              stdin=subprocess.DEVNULL).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def safe_key(s):
    return re.sub(r"[^\w.\-]+", "_", str(s))[:120]


def safe_ext(e):
    e = (e or "").lower()
    return e if re.fullmatch(r"\.[a-z0-9]{1,8}", e) else ".bin"


def cache_dir(case, sub):
    d = fa.cache_base(case) / sub
    d.mkdir(parents=True, exist_ok=True)
    return d


CACHE_LIMIT = int(float(os.environ.get("REPERTIA_CACHE_MAX_GB", "5")) * (1 << 30))


def prune_cache(case, limit=None):
    """Tiene la cache delle anteprime entro un tetto (predefinito 5 GB, variabile
    REPERTIA_CACHE_MAX_GB): se lo supera, elimina i file meno recenti fino al 70%.
    Sono solo copie ricostruibili: il caso (database, reperti, esportazioni) non si tocca.
    Si esegue all'apertura del caso, quando nessuna anteprima è in corso."""
    if limit is None:
        g = (case.meta or {}).get("cache_gb")
        try:
            limit = int(float(g) * (1 << 30)) if g not in (None, "") else CACHE_LIMIT
        except (TypeError, ValueError):
            limit = CACHE_LIMIT
    if limit <= 0:                 # 0 = nessun limite
        return 0
    base = fa.cache_base(case)
    files, total = [], 0
    # (2.20) le miniature (pochi KB l'una) non si tolgono: prima finivano via insieme alle copie dei video da cui erano
    # state fatte, e a ogni apertura di un caso con molti video si rifacevano tutte
    for sub in ("file", "pdf", "pagine", "conv", "tmp"):
        d = base / sub
        if not d.is_dir():
            continue
        for f in d.rglob("*"):
            try:
                if f.is_file():
                    st = f.stat()
                    files.append((max(st.st_atime, st.st_mtime), st.st_size, f))
                    total += st.st_size
            except OSError:
                pass
    if total <= limit:
        return 0
    freed = 0
    for _, size, f in sorted(files, key=lambda x: x[0]):
        if total - freed <= limit * 0.7:
            break
        try:
            f.chmod(0o644)
            f.unlink()
            freed += size
        except OSError:
            pass
    if freed:
        case.log("cache_ridotta", {"liberati": freed, "limite": limit})
    return freed


CACHE_SUBS = ("file", "pdf", "pagine", "conv", "miniature", "testo2", "evidenze", "libreoffice", "tmp")


def _tree_size(d):
    total, n = 0, 0
    for f in d.rglob("*"):
        try:
            if f.is_file():
                total += f.stat().st_size
                n += 1
        except OSError:
            pass
    return total, n


def cache_info(case):
    """Stato della cache del caso: dove sta, quanto occupa, qual è il limite."""
    base = fa.cache_base(case)
    total, files = (_tree_size(base) if base.is_dir() else (0, 0))
    g = case.meta.get("cache_gb")
    custom = bool(case.meta.get("cache_dir"))
    return {"path": str(base), "size": total, "files": files, "custom": custom,
            "custom_ok": (not custom) or base != case.root / "cache",
            "limit_gb": float(g) if g not in (None, "") else CACHE_LIMIT / (1 << 30),
            "limit_default": g in (None, ""), "free": fa.free_bytes(base)}


def _rm_force(path):
    import stat as _st

    def onerr(func, p, exc):
        try:
            os.chmod(p, _st.S_IRWXU)
            func(p)
        except OSError:
            pass
    shutil.rmtree(path, onerror=onerr)


def cache_clear(case):
    """Svuota la cache (copie ricostruibili delle anteprime). Non tocca il caso."""
    base = fa.cache_base(case)
    freed = 0
    if base.is_dir():
        for d in list(base.iterdir()):
            try:
                if d.is_dir():
                    freed += _tree_size(d)[0]
                    _rm_force(d)
                elif d.is_file():
                    freed += d.stat().st_size
                    d.unlink()
            except OSError:
                pass
    case.log("cache_svuotata", {"liberati": freed})
    return freed


def cache_set(case, b):
    """Imposta il limite di spazio (GB, 0 = nessun limite) e/o la cartella della cache del caso."""
    if "gb" in b and b["gb"] not in (None, ""):
        try:
            g = float(str(b["gb"]).replace(",", "."))
        except ValueError:
            raise ValueError(tr("Il limite deve essere un numero di GB (0 = nessun limite)."))
        if g < 0 or g > 100000:
            raise ValueError(tr("Limite non valido."))
        case.meta["cache_gb"] = g
    elif b.get("gb_default"):
        case.meta.pop("cache_gb", None)
    moved = None
    if b.get("reset_dir") and case.meta.get("cache_dir"):
        old = fa.cache_base(case)
        case.meta.pop("cache_dir", None)
        if old.is_dir() and old != case.root / "cache":
            _rm_force(old)
        moved = str(case.root / "cache")
    elif b.get("dir"):
        p, _free = check_dest(b["dir"])
        new = p if p.name.lower().startswith("repertia_cache") else p / ("RepertIA_cache_" + case.root.name)
        if str(new) != str(fa.cache_base(case)):
            old = fa.cache_base(case)
            new.mkdir(parents=True, exist_ok=True)
            case.meta["cache_dir"] = str(new)
            if old.is_dir() and old != new:     # la vecchia cache si elimina: è ricostruibile
                _rm_force(old)
            moved = str(new)
    case.save()
    case.log("cache_impostata", {"gb": case.meta.get("cache_gb"), "dir": case.meta.get("cache_dir")})
    prune_cache(case)
    return moved


def copy_case(case, dest, progress):
    """Copia il caso (senza la cache, ricostruibile) in un'altra posizione e la registra tra le
    cartelle dei casi. L'originale resta dov'è."""
    destp, free = check_dest(dest)
    src = case.root
    if destp == src or src in destp.parents:
        raise ValueError(tr("La destinazione non può stare dentro il caso stesso."))
    target = destp / src.name
    n = 2
    while target.exists():
        target = destp / f"{src.name}_{n}"
        n += 1
    cache_p = src / "cache"
    files = []
    for f in src.rglob("*"):
        try:
            if f.is_file() and cache_p not in f.parents and not f.name.endswith((".tmp", ".parziale")):
                files.append((f, f.stat().st_size))
        except OSError:
            pass
    total = sum(s for _, s in files)
    if free is not None and free < total * 1.05 + (50 << 20):
        raise ValueError(tr("Spazio insufficiente nella destinazione: servono {v1}, disponibili {v2}.").format(v1=fa.gb(total), v2=fa.gb(free)))
    case.log("copia_caso", {"destinazione": str(target), "file": len(files), "byte": total})
    done = 0
    last = 0.0
    import time as _t
    try:
        for f, size in files:
            rel = f.relative_to(src)
            out = target / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, out)
            done += size
            if _t.time() - last > 1:
                last = _t.time()
                progress(tr("Copia in corso… {v1} di {v2}").format(v1=fa.gb(done), v2=fa.gb(total)))
        # verifica: stesso numero di file e stessa dimensione
        got = sum(1 for _ in target.rglob("*") if _.is_file())
        if got < len(files):
            raise ValueError(tr("La copia risulta incompleta: controlla lo spazio e riprova."))
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise
    meta = target / "case.json"
    try:                      # la copia non eredita una cartella di cache scelta per l'originale
        m = json.loads(meta.read_text())
        if m.pop("cache_dir", None) is not None:
            meta.write_text(json.dumps(m, indent=2, ensure_ascii=False))
    except (OSError, ValueError):
        pass
    fa.register_case_home(destp)
    return {"path": str(target), "root": str(target), "files": len(files), "bytes": total}


UA_ID_BASE = 10 ** 12           # id delle righe dei tratti non allocati nell'elenco (non si sovrappongono a quelli di nav)
UA_CACHE_MAX = 64 << 20         # i tratti fino a questa dimensione si copiano in cache (anteprima, testo, SHA-256)
UA_JOBS, UA_LOCK = {}, threading.Lock()


def ua_cache_file(case, part):
    return fa.cache_base(case) / "non_allocato" / f"p{part}.json"


def ua_runs(case, part, wait=True):
    """Tratti non allocati della partizione. wait=False: se non sono ancora calcolati avvia il calcolo in background e
    restituisce None (lo stato si legge con ua_job)."""
    try:
        d = json.loads(ua_cache_file(case, part).read_text())
        if d.get("image") == str(case.image):
            return d
    except (OSError, ValueError):
        pass
    if wait:
        return fa.unalloc_runs(case, part)
    key = (str(case.root), part)
    with UA_LOCK:
        job = UA_JOBS.get(key)
        if job and job["state"] == "building":
            return None
        job = UA_JOBS[key] = {"state": "building", "msg": tr("Calcolo lo spazio non allocato con Sleuth Kit…")}

    def run():
        try:
            fa.unalloc_runs(case, part, progress=lambda m: job.update(msg=m))
            job["state"] = "ready"
        except Exception as e:
            job.update(state="error", msg=str(e))
    threading.Thread(target=run, daemon=True).start()
    return None


def ua_job(case, part):
    return UA_JOBS.get((str(case.root), part)) or {"state": "building", "msg": tr("Calcolo lo spazio non allocato…")}


def ua_name(part, start, ln):
    s, e = start // 512, (start + ln) // 512 - 1
    return f"Unalloc_{part}_{s}_{e}" if part >= 0 else f"Disco_{s}_{e}"


def ua_ident(case, part, inode):
    """Tratto di spazio non allocato (inode «u<byte iniziale>-<lunghezza>»): di una partizione (part = offset) o
    del disco fuori dalle partizioni (part = -1, righe «Unallocated» o volumi non leggibili della tabella)."""
    m = fa.UA_RE.fullmatch(inode)
    start, ln = int(m.group(1)), int(m.group(2))
    if part < 0:
        lay = fa.layout_volumi(case) or {}
        ok = next((v for v in lay.get("voci", []) if v["start"] * 512 == start and v["length"] * 512 >= ln
                   and (v["kind"] == "unalloc" or (v["kind"] == "vol" and not v.get("parts")))), None)
        if not ok:
            raise ValueError(tr("Area del disco non valida."))
        what = (tr("spazio non allocato del disco") if ok["kind"] == "unalloc"
                else tr("volume che Sleuth Kit non legge (contenuto grezzo)"))
        path = f"vol{ok['n']} ({ok['desc']}: {ok['start']}-{ok['end']})"
    else:
        if part not in {p["offset"] for p in case.meta.get("partitions", []) if p.get("readable")}:
            raise ValueError(tr("Partizione non valida."))
        d = ua_runs(case, part)
        if not any(r[0] == start and r[1] == ln for r in d["runs"]):
            raise ValueError(tr("Tratto di spazio non allocato non valido."))
        what = tr("spazio non allocato del file system")
        path = "$Unalloc/" + ua_name(part, start, ln)
    name = ua_name(part, start, ln)
    return {"source": "ua", "part": part, "inode": inode, "start": start, "path": path, "name": name,
            "key": f"ua_{start}_{ln}", "ext": "", "size": ln, "deleted": 0, "what": what}


def ua_stream(case, it, start=0, size=4 << 20):
    """Byte del tratto (dalla posizione `start` nel tratto), letti dalla copia forense."""
    pos, end = start, it["size"]
    while pos < end:
        c = G.image_read(case, it["start"] + pos, min(size, end - pos))
        if not c:
            break
        yield pos, c
        pos += len(c)


def item_stream(case, part, inode):
    """Contenuto di un elemento della copia: file (icat) o tratto non allocato (letto dall'immagine)."""
    if fa.UA_RE.fullmatch(str(inode)):
        for _, c in ua_stream(case, ua_ident(case, int(part), str(inode))):
            yield c
        return
    yield from fa.icat_stream(case, part, inode)


def export_ua(case, part, inode):
    it = ua_ident(case, part, inode)
    if not Path(case.image).exists():
        raise ValueError(tr("La copia forense non è raggiungibile: collega il disco che la contiene."))
    dest = unique(case.export_dir / "non_allocato" / (it["name"] + ".bin"))
    dest.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    with open(lp(dest), "wb") as f:
        for _, c in ua_stream(case, it):
            f.write(c)
            h.update(c)
    os.chmod(lp(dest), 0o444)
    case.log("export_non_allocato", {"partizione": part, "byte_iniziale": it["start"], "byte": it["size"],
                                     "sha256": h.hexdigest(), "dest": str(dest)})
    n = lambda v: f"{v:,}".replace(",", ".")
    return (tr("Esportato {v1} ({v2} byte, dal byte {v3} al {v4} della copia), SHA-256 {v5}").format(v1=dest.relative_to(case.root), v2=n(it['size']), v3=n(it['start']), v4=n(it['start'] + it['size'] - 1), v5=h.hexdigest()))


def ua_list(case, q, ids=None, limit=PAGE):
    """Contenuto della cartella virtuale $Unalloc: un elemento per tratto contiguo di spazio non allocato."""
    part = int(q.get("part") or 0)
    off = int(q.get("offset", 0))
    d = ua_runs(case, part, wait=ids is not None or limit is None)
    if d is None:
        job = ua_job(case, part)
        if job["state"] == "error":
            raise ValueError(job["msg"])
        return {"kind": "explore", "total": 0, "offset": 0, "page": PAGE, "rows": [], "building": job["msg"]}
    rows = []
    for i, (st, ln) in enumerate(d["runs"]):
        nm = ua_name(part, st, ln)
        rows.append({"id": UA_ID_BASE + i, "part": part, "parent": "$Unalloc", "name": nm, "path": "$Unalloc/" + nm,
                     "isdir": 0, "deleted": 0, "type": "r/r", "inode": f"u{st}-{ln}", "fid": None, "size": ln,
                     "mtime": None, "atime": None, "ctime": None, "crtime": None, "ndirs": 0, "nitems": 0,
                     "known": None, "ua": 1, "start": st, "s0": st // 512, "s1": (st + ln) // 512 - 1})
    if ids is not None:
        want = {int(x) for x in ids if str(x).isdigit()}
        rows = [r for r in rows if r["id"] in want]
    text = (q.get("q") or "").strip().lower()
    if text:
        rows = [r for r in rows if text in r["name"].lower()]
    if q.get("sk") == "size":
        rows.sort(key=lambda r: r["size"], reverse=q.get("sd") == "desc")
    elif q.get("sk") == "name" and q.get("sd") == "desc":
        rows.reverse()
    total = len(rows)
    page = rows[off:off + limit] if limit else rows
    return {"kind": "explore", "total": total, "offset": off, "page": PAGE, "rows": page,
            "ua": {"blocco": d["block_size"], "byte": d["byte"], "tratti": len(d["runs"])}}


def file_ident(case, b):
    """Identifica un file della copia (offset+inode) o recuperato col carving (nome)."""
    if fa.UA_RE.fullmatch(str(b.get("inode") or "")):     # tratto di spazio non allocato
        return ua_ident(case, int(b.get("part")), str(b.get("inode")))
    if b.get("source") == "x":            # estratto da archivio, allegato, copia shadow
        return G.x_ident(case, b)
    if b.get("source") == "image":          # la copia forense stessa (esadecimale delle tracce)
        return G.image_ident(case)
    if (b.get("source") or "fs") == "carving":
        name = Path(str(b.get("name") or "")).name
        con = fa.db_ro(case)
        try:
            r = con.execute("SELECT relpath FROM carved WHERE name=? OR name LIKE ? ESCAPE '\\' LIMIT 1", (name, "%/" + fa.like(name)[1:-1])).fetchone()
        finally:
            con.close()
        if not r or not (case.root / r[0]).exists():
            raise ValueError(tr("File recuperato non trovato."))
        p = case.root / r[0]
        return {"source": "carving", "name": name, "path": name, "key": "c_" + safe_key(name),
                "ext": Path(name).suffix.lower(), "size": p.stat().st_size, "file": p,
                "deleted": 0, "part": None, "inode": None}
    part, inode = int(b.get("part")), str(b.get("inode") or "").strip()
    if not fa.INODE_RE.fullmatch(inode):
        raise ValueError(tr("inode non valido."))
    if part not in {p["offset"] for p in case.meta.get("partitions", []) if p.get("readable")}:
        raise ValueError(tr("Partizione non valida."))
    path, size, deleted = None, None, 0
    try:
        con = nav_db(case)
        r = con.execute("SELECT path, size, deleted FROM nav WHERE part=? AND inode=? AND isdir=0 "
                        "ORDER BY deleted LIMIT 1", (part, inode)).fetchone()
        con.close()
        if r:
            path, size, deleted = r
    except (ValueError, sqlite3.Error):
        pass
    if not path:
        con = fa.db_ro(case)
        r = con.execute("SELECT path, deleted FROM files WHERE part=? AND inode=? LIMIT 1",
                        (part, inode)).fetchone()
        con.close()
        path, deleted = (r[0], r[1]) if r else (f"inode_{inode}", 0)
    ext = Path(path.split(":")[0]).suffix.lower()      # NTFS: file.txt:Zone.Identifier
    return {"source": "fs", "part": part, "inode": inode, "path": path, "name": Path(path).name,
            "key": f"p{part}_i{safe_key(inode)}", "ext": ext, "size": size, "deleted": deleted}


def key_lock(key):
    with KEY_LOCK:
        return KEY_LOCKS.setdefault(key, threading.Lock())


def cached_file(case, it, limit=CACHE_MAX):
    """Copia del file nella cache del caso (con la sua estensione, utile agli strumenti
    di anteprima). None se il file è più grande di `limit`."""
    if it["source"] in ("carving", "x"):
        return it["file"]
    if it["source"] == "ua":
        limit = min(limit, UA_CACHE_MAX)
    dest = cache_dir(case, "file") / (it["key"] + safe_ext(it["ext"]))
    if dest.exists():
        return dest
    if it.get("size") and it["size"] > limit:
        return None
    if not Path(case.image).exists():
        raise ValueError(tr("La copia forense non è raggiungibile: collega il disco che la contiene."))
    with key_lock(it["key"]):
        if dest.exists():
            return dest
        tmp = dest.with_name(dest.name + ".parziale")
        n = 0
        with open(tmp, "wb") as f:
            for chunk in item_stream(case, it["part"], it["inode"]):
                f.write(chunk)
                n += len(chunk)
                if n > limit:
                    break
        if n > limit:
            tmp.unlink()
            return None
        tmp.replace(dest)
        dest.chmod(0o444)
    return dest


def file_size(case, it):
    f = cached_file(case, it)
    return (f.stat().st_size if f else it.get("size") or 0), f


def read_range(case, it, off, n):
    if it["source"] == "image":
        return G.image_read(case, off, n), it["size"]
    if it["source"] == "x" and not it.get("file"):
        raise ValueError(tr("File non estratto: ") + (it["rec"].get("note") or tr("contenuto non disponibile")))
    size, f = file_size(case, it)
    if f:
        with open(f, "rb") as fh:
            fh.seek(off)
            return fh.read(n), size
    if it["source"] == "ua":                 # tratto non allocato grande: lettura diretta dalla copia
        n = max(0, min(n, it["size"] - off))
        return (G.image_read(case, it["start"] + off, n) if n else b""), it["size"]
    # file enorme: si legge in streaming fino al punto richiesto (più lento)
    out, pos = bytearray(), 0
    gen = fa.icat_stream(case, it["part"], it["inode"])
    try:
        for chunk in gen:
            if pos + len(chunk) > off:
                out += chunk[max(0, off - pos):]
                if len(out) >= n:
                    break
            pos += len(chunk)
    finally:
        gen.close()
    return bytes(out[:n]), size


def iter_chunks(case, it, start=0, size=4 << 20):
    if it["source"] == "image":
        yield from G.image_chunks(case, start, size)
        return
    if it["source"] == "x" and not it.get("file"):
        raise ValueError(tr("File non estratto."))
    _, f = file_size(case, it)
    if f:
        with open(f, "rb") as fh:
            fh.seek(start)
            pos = start
            while chunk := fh.read(size):
                yield pos, chunk
                pos += len(chunk)
        return
    if it["source"] == "ua":
        yield from ua_stream(case, it, start, size)
        return
    pos = 0
    gen = fa.icat_stream(case, it["part"], it["inode"])
    try:
        for chunk in gen:
            if pos + len(chunk) > start:
                s = max(0, start - pos)
                yield pos + s, chunk[s:]
            pos += len(chunk)
    finally:
        gen.close()


def hex_page(case, b):
    it = file_ident(case, b)
    off = max(0, int(b.get("offset") or 0))
    n = max(16, min(int(b.get("length") or 4096), 1 << 16))
    data, size = read_range(case, it, off, n)
    return {"offset": off, "size": size, "data": base64.b64encode(data).decode(),
            "title": it["path"]}


def hex_search(case, b, max_hits=500):
    """Cerca testo (ASCII/UTF-8 o UTF-16LE) o una sequenza esadecimale dentro il file."""
    it = file_ident(case, b)
    mode, pat = b.get("mode") or "text", b.get("pattern") or ""
    nocase = mode in ("text", "utf16") and not yes(b.get("case"))
    if mode == "hex":
        h = re.sub(r"[^0-9a-fA-F]", "", pat)
        if len(h) < 2 or len(h) % 2:
            raise ValueError(tr("Sequenza esadecimale non valida (es. FF D8 FF oppure 504B0304)."))
        needle = bytes.fromhex(h)
    elif mode == "utf16":
        needle = (pat.lower() if nocase else pat).encode("utf-16-le")
    else:
        needle = (pat.lower() if nocase else pat).encode("utf-8")
    if not needle:
        raise ValueError(tr("Scrivi cosa cercare."))
    start = max(0, int(b.get("from") or 0))
    hits, tail, tail_pos = [], b"", start
    for pos, chunk in iter_chunks(case, it, start):
        buf = tail + chunk
        base_pos = pos - len(tail)
        hay = buf.lower() if nocase else buf      # minuscole ASCII (vale anche per UTF-16LE)
        i = hay.find(needle)
        while i != -1:
            if base_pos + i >= start and (not hits or hits[-1] != base_pos + i):
                hits.append(base_pos + i)
                if len(hits) >= max_hits:
                    return {"hits": hits, "more": True}
            i = hay.find(needle, i + 1)
        tail = buf[-(len(needle) - 1):] if len(needle) > 1 else b""
    return {"hits": hits, "more": False}


def sniff_mime(data):
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[:2] == b"BM":
        return "image/bmp"
    return None


def to_jpeg(src, out, size):
    """Converte/riduce un'immagine in JPEG con gli strumenti disponibili."""
    if IS_MAC and shutil.which("sips"):
        if run_quiet(["sips", "-s", "format", "jpeg", "-s", "formatOptions", "80", "-Z", str(size),
                      str(src), "--out", str(out)]) and out.exists():
            return True
    conv = tool("convert")
    if conv and not IS_WIN:          # su Windows "convert" è un comando di sistema diverso
        if run_quiet([conv, str(src) + "[0]", "-auto-orient", "-thumbnail", f"{size}x{size}>",
                      "-quality", "80", "jpeg:" + str(out)]) and out.exists():
            return True
    try:
        from PIL import Image, ImageOps
        with Image.open(src) as im:
            im = ImageOps.exif_transpose(im)
            im.thumbnail((size, size))
            if im.mode not in ("RGB", "L"):
                im = im.convert("RGB")
            im.save(out, "JPEG", quality=80)
        return out.exists()
    except Exception:
        return False


def make_thumb(case, it, f, size, out):
    head = open(f, "rb").read(16)
    ext = ext_contenuto(it["ext"], head)
    with tempfile.TemporaryDirectory(dir=cache_dir(case, "tmp")) as td:
        td = Path(td)
        if ext != it["ext"]:            # (3.0.1) formato dal contenuto: collegamento con l'estensione giusta, come per i video sotto
            vf = td / ("m" + ext)
            try:
                os.link(f, vf)
            except OSError:
                shutil.copyfile(f, vf)
            f = vf
        if ext in IMG_ALL or sniff_mime(head):
            if to_jpeg(f, out, size):
                return True
            if (ext in IMG_NATIVE or sniff_mime(head)) and f.stat().st_size < (8 << 20):
                shutil.copyfile(f, out)          # il browser la ridimensiona da sé
                return True
        if (ext == ".pdf" or head[:4] == b"%PDF") and tool("pdftoppm"):
            if run_quiet([tool("pdftoppm"), "-f", "1", "-l", "1", "-scale-to", str(size), "-jpeg",
                          "-singlefile", str(f), str(out.with_suffix(""))], 60) and out.exists():
                return True
        # (2.20) video senza estensione (es. allegati di Telegram): riconosciuto dall'intestazione MP4/MOV («ftyp», non le
        # foto HEIC/AVIF) e passato a Quick Look e ffmpeg con un collegamento temporaneo con l'estensione giusta: senza
        # estensione Quick Look non riconosce il file e resta bloccato
        vext = video_brand(ext, head)
        if vext:
            ext = vext
            vf = td / ("v" + ext)
            try:
                os.link(f, vf)          # collegamento fisico: con un collegamento simbolico Quick Look risale al file
            except OSError:
                shutil.copyfile(f, vf)
            f = vf
        if IS_MAC and shutil.which("qlmanage"):  # Quick Look: Office, Pages, video, testo...
            # (2.20) un video che Quick Look sa leggere esce in meno di un secondo; uno che non sa leggere lo teneva
            # fermo 30 s, occupando uno dei tre posti delle miniature (poi il fotogramma lo ricava il browser)
            vid = ext in VIDEO_MIME or ext in VIDEO_OTHER
            if run_quiet(["qlmanage", "-t", "-s", str(size), "-o", str(td), str(f)], 10 if vid else 30):
                png = next(td.glob("*.png"), None)
                if png:
                    shutil.move(str(png), out)
                    return True
        if (ext in VIDEO_MIME or ext in VIDEO_OTHER) and tool("ffmpeg"):
            if run_quiet([tool("ffmpeg"), "-v", "quiet", "-ss", "1", "-i", str(f), "-frames:v", "1",
                          "-vf", f"scale={size}:-2", "-y", str(td / "v.jpg")], 60) \
                    and (td / "v.jpg").exists():
                shutil.move(str(td / "v.jpg"), out)
                return True
        if ext in WORD_EXT | OFFICE_EXT:
            pdf = office_pdf(case, it, f)
            if pdf and tool("pdftoppm") and run_quiet(
                    [tool("pdftoppm"), "-f", "1", "-l", "1", "-scale-to", str(size), "-jpeg",
                     "-singlefile", str(pdf), str(out.with_suffix(""))], 60) and out.exists():
                return True
    return False


def thumb_bytes(case, b):
    """Miniatura (JPEG/PNG) di un file; None se non si può generare."""
    it = file_ident(case, b)
    size = max(64, min(int(b.get("size") or 256), 1600))
    out = cache_dir(case, "miniature") / f"{it['key']}_{size}.jpg"
    none = out.with_suffix(".nessuna")
    if out.exists():
        data = out.read_bytes()
        return data, sniff_mime(data) or "image/jpeg"
    # (2.20) il segno «miniatura non riuscita» vale solo per la versione che l'ha scritto: con una versione nuova (es. le
    # miniature dei video senza estensione) si riprova; i segni vuoti delle versioni precedenti si riprovano una volta
    try:
        if none.read_text(encoding="ascii", errors="replace") == THUMB_GEN:
            return None
    except OSError:
        pass
    if it.get("size") and it["size"] > (512 << 20) and it["ext"] not in IMG_ALL:
        return None
    with THUMB_SEM:
        if not out.exists():
            f = cached_file(case, it)
            ok = bool(f) and make_thumb(case, it, f, size, out)
            if not ok:
                none.write_text(THUMB_GEN, encoding="ascii")
                return None
    data = out.read_bytes()
    return data, sniff_mime(data) or "image/jpeg"


def thumb_put(case, b, data):
    """(2.20) Fotogramma di un video ricavato dal browser quando il server non ha la miniatura (Quick Look non legge il
    file, su Windows/Linux manca ffmpeg): diventa la miniatura del video nella cache del caso, così la volta dopo arriva
    subito. Solo JPEG, solo per i video, mai sopra una miniatura già fatta (è una copia ricostruibile, come le altre)."""
    if data[:3] != b"\xff\xd8\xff" or len(data) > (2 << 20):
        raise ValueError(tr("Miniatura non valida."))
    it = file_ident(case, b)
    ext = it["ext"]
    if not (ext in VIDEO_MIME or ext in VIDEO_OTHER):
        f = cached_file(case, it, limit=0) if not ext else None
        if not (f and video_brand(ext, open(f, "rb").read(16))):
            raise ValueError(tr("Miniatura accettata solo per i video."))
    size = max(64, min(int(b.get("size") or 256), 1600))
    out = cache_dir(case, "miniature") / f"{it['key']}_{size}.jpg"
    if out.exists():
        return False
    tmp = out.with_name(out.name + ".parziale")
    tmp.write_bytes(data)
    tmp.replace(out)
    out.with_suffix(".nessuna").unlink(missing_ok=True)
    return True


def office_pdf(case, it, f):
    """Converte un documento Office/OpenDocument in PDF con LibreOffice, se installato."""
    soffice = tool("soffice")
    if not soffice:
        return None
    out = cache_dir(case, "pdf") / (it["key"] + ".pdf")
    if out.exists():
        return out
    with key_lock(it["key"] + "_pdf"), LO_LOCK:
        if out.exists():
            return out
        # profilo di LibreOffice conservato nel caso: crearlo ogni volta costa diversi secondi
        prof = cache_dir(case, "libreoffice")
        with tempfile.TemporaryDirectory(dir=cache_dir(case, "tmp")) as td:
            ok = run_quiet([soffice, f"-env:UserInstallation={prof.as_uri()}", "--headless",
                            "--norestore", "--convert-to", "pdf", "--outdir", td, str(f)], 180)
            pdf = next(Path(td).glob("*.pdf"), None)
            if ok and pdf:
                shutil.move(str(pdf), out)
                return out
    return None


def pdf_pages(pdf):
    try:
        r = subprocess.run([tool("pdfinfo"), str(pdf)], capture_output=True, timeout=30)
        m = re.search(r"^Pages:\s+(\d+)", fa.dec(r.stdout), re.M)
        return int(m.group(1)) if m else 1
    except (OSError, subprocess.TimeoutExpired, TypeError):
        return 1


def page_png(case, b):
    """Una pagina di un PDF (o di un documento convertito in PDF) come immagine JPEG:
    nessun contenuto attivo del documento arriva al browser. Le pagine si disegnano a
    blocchi (un solo pdftoppm per più pagine) e al massimo due blocchi alla volta."""
    it = file_ident(case, b)
    n = max(1, int(b.get("n") or 1))
    stem = f"{it['key']}{'_c' if yes(b.get('conv')) else ''}"
    d = cache_dir(case, "pagine")
    out = d / f"{stem}_{n}.jpg"
    if out.exists():
        return out.read_bytes()
    f = cached_file(case, it)
    if yes(b.get("conv")):
        f = office_pdf(case, it, f)
    if not f or not tool("pdftoppm"):
        raise ValueError(tr("Pagina non disponibile."))
    first = (n - 1) // PAGE_BLOCK * PAGE_BLOCK + 1
    with key_lock(f"{stem}_pg{first}"):
        if not out.exists():
            with PAGE_SEM, tempfile.TemporaryDirectory(dir=cache_dir(case, "tmp")) as td:
                run_quiet([tool("pdftoppm"), "-f", str(first), "-l", str(first + PAGE_BLOCK - 1),
                           "-r", "110", "-jpeg", "-jpegopt", "quality=88", str(f),
                           str(Path(td) / "p")], 120)
                for img in Path(td).glob("p-*.jpg"):
                    m = re.search(r"-(\d+)\.jpg$", img.name)
                    if m:
                        dest = d / f"{stem}_{int(m.group(1))}.jpg"
                        if not dest.exists():
                            shutil.move(str(img), dest)
    if not out.exists():
        raise ValueError(tr("Impossibile disegnare la pagina."))
    return out.read_bytes()


def converted_image(case, b):
    """Immagini che il browser non mostra (HEIC, TIFF, RAW...) convertite in JPEG."""
    it = file_ident(case, b)
    out = cache_dir(case, "conv") / f"{it['key']}.jpg"
    if not out.exists():
        f = cached_file(case, it)
        if not f or not to_jpeg(f, out, 2400):
            raise ValueError(tr("Conversione dell'immagine non disponibile su questo computer."))
    return out.read_bytes()


CSP_DOC = ("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
           "img-src data:; style-src 'unsafe-inline'; font-src data:\">")


def word_html(f):
    """Documento Word/RTF/ODT in HTML con textutil (macOS), ripulito da script e risorse esterne."""
    if not (IS_MAC and shutil.which("textutil")):
        return None
    try:
        r = subprocess.run(["textutil", "-convert", "html", "-stdout", str(f)],
                           capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0 or not r.stdout:
        return None
    h = fa.dec(r.stdout)
    h = re.sub(r"(?is)<(script|style\b[^>]*>\s*@import|iframe|object|embed)\b.*?</\1\s*>", "", h)
    h = re.sub(r"(?is)<(script|iframe|object|embed|link|base|meta)\b[^>]*>", "", h)
    h = re.sub(r"(?i)\son\w+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", "", h)
    m = re.search(r"(?i)<head[^>]*>", h)       # la regola che blocca risorse esterne va nell'intestazione
    return h[:m.end()] + CSP_DOC + h[m.end():] if m else CSP_DOC + h


def printable_ratio(data):
    if not data:
        return 0
    try:
        t = data.decode("utf-8")
        return sum(c.isprintable() or c in "\r\n\t" for c in t) / len(t)
    except UnicodeDecodeError:
        return sum(32 <= c < 127 or c in (9, 10, 13) for c in data) / len(data)


def decode_text(data):
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    # UTF-16LE senza BOM: zeri nei byte dispari ma NON nei pari. (3.0.4) Un file con molti zeri in entrambe le posizioni
    # (es. riempimento in coda ai file letti dalla memoria) non è UTF-16: prima veniva mostrato come ideogrammi
    corpo = data.rstrip(b"\0")                 # gli zeri in coda non contano (e non dicono nulla sulla codifica)
    if len(corpo) > 8 and corpo[1::2].count(0) > len(corpo) / 4 and corpo[0::2].count(0) < len(corpo) / 16:
        return (corpo + b"\0" * (len(corpo) % 2)).decode("utf-16-le", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", "replace")


def media_url(kind, it, **extra):
    q = {"source": it["source"], "t": TOKEN, **extra}
    if it["source"] == "carving":
        q["name"] = it["name"]
    elif it["source"] == "x":
        q["id"] = it["id"]
    else:
        q.update(part=it["part"], inode=it["inode"])
    from urllib.parse import urlencode
    return f"/api/{kind}?" + urlencode(q)


def ext_contenuto(ext, head):
    """(3.0.1) Estensione dal contenuto (foto, video, audio) per i file senza l'estensione di un formato multimediale, come
    le cache delle app («.0», «.cnt», senza estensione); altrimenti l'estensione del nome."""
    if ext in RAW_MIME or ext in IMG_ALL or ext in VIDEO_OTHER or ext in AUDIO_EXT:
        return ext
    import forense_mobile_media as fmm
    f = fmm.firma(head)
    return "." + f[1] if f else ext


def view_info(case, b):
    """Come mostrare un file nel riquadro di anteprima."""
    if b.get("source") == "mail":
        return G.mail_view(case, b)
    if b.get("source") == "art":
        return G.art_view(case, b)
    if b.get("source") == "chat":               # messaggio di una chat nei Preferiti (2.20)
        import forense_mobile_gui as fmg
        return fmg.msg_view(G, case, b)
    if b.get("source") == "rub":                # voce delle rubriche dalla ricerca veloce (2.20)
        import forense_mobile_gui as fmg
        return fmg.rub_view(G, case, b)
    it = file_ident(case, b)
    size, f = file_size(case, it)
    ext = it["ext"]
    head = b""
    if f:
        with open(f, "rb") as fh:
            head = fh.read(8192)
        ext = ext_contenuto(ext, head)
    base = {"title": it["path"], "name": it["name"], "size": size, "deleted": it["deleted"],
            "ext": ext, "source": it["source"], "part": it["part"], "inode": it["inode"],
            "carved_name": it["name"] if it["source"] == "carving" else None,
            "id": it.get("id"), "magic": head[:16].hex(" ")}
    if it["source"] == "x" and (it["rec"].get("kind") == "cache_web"):    # (3.0.1) indirizzo web e offset nella voce di cache
        base["xnote"] = it["rec"].get("note")
    if it["source"] == "x" and not f:
        return {**base, "type": "none", "note": tr("File non estratto: ") + (it["rec"].get("note") or tr("contenuto non disponibile"))}
    if it["source"] == "ua":
        base["title"] = it["path"]
        if not f:
            return {**base, "type": "none", "note": tr("Spazio non allocato ({what}): non è un file. Usa Testo (stringhe leggibili dei primi 50 "
                                                       "MB) o Esadecimale (tutto il tratto).").format(what=it['what'])}
    if not f:
        return {**base, "type": "none", "note": tr("File molto grande: usa la vista esadecimale.")}
    if not size:
        if case.meta.get("ram_dump"):          # (3.0.4) dump della RAM: del file resta solo il nome con le date
            return {**base, "type": "none", "note": tr("Nessun contenuto: di questo file nel dump della memoria restano solo nome, date "
                                                       "e dimensione (vedi Metadati).")}
        return {**base, "type": "none", "note": tr("File vuoto (0 byte): per i file cancellati il "
                "contenuto può non essere più recuperabile.")}
    if head.startswith(b"SQLite format 3\x00"):
        if fa.is_mobile(case) and it["source"] == "fs":     # (2.20) telefoni: con i file -wal/-shm/-journal accanto
            import forense_mobile_gui as fmg
            try:
                html, nota = fmg.sqlite_preview(G, case, it)
                return {**base, "type": "html", "sqlite": True, "html": html, "note": tr("Database SQLite: tabelle e prime righe (sola lettura).") + " " + nota}
            except (sqlite3.Error, OSError):
                pass
        try:
            return {**base, "type": "html", "sqlite": True, "html": G.sqlite_view(f), "note": tr("Database SQLite: tabelle e prime righe (sola lettura).")}
        except sqlite3.Error:
            pass
    mime = sniff_mime(head)
    if ext in IMG_NATIVE or mime:
        return {**base, "type": "image", "src": media_url("raw", it)}
    if ext in IMG_CONVERT:
        return {**base, "type": "image", "src": media_url("conv", it)}
    if ext == ".pdf" or head[:4] == b"%PDF":
        if tool("pdftoppm"):
            return {**base, "type": "pdf", "pages": pdf_pages(f), "src": media_url("page", it)}
    if ext in WORD_EXT | OFFICE_EXT:
        pdf = office_pdf(case, it, f)
        if pdf and tool("pdftoppm"):
            return {**base, "type": "pdf", "pages": pdf_pages(pdf), "src": media_url("page", it, conv=1),
                    "note": tr("Impaginazione ricostruita con LibreOffice.")}
        if ext in WORD_EXT:
            h = word_html(f)
            if h:
                return {**base, "type": "html", "html": h,
                        "note": tr("Impaginazione semplificata (textutil di macOS).")}
        t = thumb_bytes(case, {**b, "size": 1400})
        if t:
            return {**base, "type": "image", "src": media_url("thumb", it, size=1400),
                    "note": tr("Prima pagina (anteprima di sistema). Il testo completo è nella scheda Testo.")}
        return {**base, "type": "text", "text": "", "note": tr("Anteprima visuale non disponibile: "
                "apri la scheda Testo (installando LibreOffice si vedono le pagine).")}
    if ext in VIDEO_MIME:
        return {**base, "type": "video", "src": media_url("raw", it), "mime": VIDEO_MIME[ext]}
    vext = video_brand(ext, head)               # (2.20) video senza estensione (es. allegati di Telegram)
    if vext:
        return {**base, "type": "video", "src": media_url("raw", it), "mime": VIDEO_MIME[vext],
                "note": tr("Video riconosciuto dall'intestazione del file (il file non ha estensione).")}
    if ext in AUDIO_MIME:
        return {**base, "type": "audio", "src": media_url("raw", it), "mime": AUDIO_MIME[ext]}
    if ext in TEXT_LIKE or printable_ratio(head) > 0.92:
        with open(f, "rb") as fh:
            data = fh.read(300_000)
        return {**base, "type": "text", "text": decode_text(data), "truncated": size > len(data)}
    if ext in VIDEO_OTHER:
        t = thumb_bytes(case, {**b, "size": 900})
        if t:
            return {**base, "type": "image", "src": media_url("thumb", it, size=900),
                    "note": tr("Fotogramma del video (il formato non si riproduce nel browser).")}
    t = thumb_bytes(case, {**b, "size": 1200}) if IS_MAC else None
    if t:
        return {**base, "type": "image", "src": media_url("thumb", it, size=1200)}
    return {**base, "type": "none", "note": tr("Nessuna anteprima visuale per questo tipo di file: "
            "guarda Testo, Esadecimale o Metadati.")}


def file_details(case, b):
    """Scheda Metadati: istat (date, attributi, cluster) ed exiftool."""
    if b.get("source") in ("mail", "art", "chat"):
        v = view_info(case, b)
        return {"istat": v.get("headers") or "", "exif": "", "sha256": ""}
    tz = b.get("tz")
    it = file_ident(case, b)
    t = SES.case_tools
    if it["source"] == "x":
        istat = G.x_details(case, it, tz)
        exif = ""
        if it["file"] and shutil.which("exiftool"):
            r = subprocess.run(["exiftool", "-G", "-s", str(it["file"])], capture_output=True, timeout=60)
            exif = exif_no_workcopy(fa.dec(r.stdout))
    elif it["source"] == "ua":
        S, L = it["start"], it["size"]
        istat = (tr("Spazio non allocato — {what}\n\nElemento:            {path}\n").format(what=it['what'], path=it['path'])
                 + (tr("Partizione (offset): {part} settori\n").format(part=it['part']) if it["part"] >= 0 else "")
                 + tr("Byte nella copia:    {S:,} – {v1:,}\nSettori (512 byte):  {v2:,} – {v3:,}\nDimensione:      "
                      "    {L:,} byte\n\nNon è un file: sono i blocchi che il file system segna come liberi "
                      "(Sleuth Kit, blkls), letti direttamente dalla copia forense. Possono contenere resti di "
                      "file cancellati.").format(S=S, v1=S + L - 1, v2=S // 512, v3=(S + L) // 512 - 1, L=L)).replace(",", ".")
        exif = ""
        if L > UA_CACHE_MAX:
            istat += tr("\n\nLo SHA-256 di un tratto così grande si calcola all'esportazione (Esporta).")
    elif it["source"] == "carving":
        istat = tr("File recuperato col carving: {name} ({size} byte).").format(name=it['name'], size=it['size'])
        exif = ""
        if shutil.which("exiftool"):
            r = subprocess.run(["exiftool", "-G", "-s", str(it["file"])], capture_output=True,
                               timeout=60)
            exif = exif_no_workcopy(fa.dec(r.stdout))
    else:
        istat = t["file_metadata"](it["part"], it["inode"])
        if fa.ap.is_apfs_part(int(it["part"])):
            istat, note = apfs_istat_to_zone(case, istat, tz)
        elif fa.is_mobile(case):        # estrazione di un telefono: date UTC come APFS
            istat, _n = apfs_istat_to_zone(case, istat, tz)
            note = (tr("Orari scritti in: {v1} (le date vengono dai record MFT trovati in memoria, in UTC).") if case.meta.get("ram_dump")
                    else tr("Orari scritti in: {v1} (zip e tar registrano le date in UTC, salvo le date DOS dichiarate "
                            "sotto).")).format(v1=tz_label(case, tz))
        else:
            istat, note = istat_to_zone(case, istat, tz)
        if re.search(r"^Directory Entry:", istat, re.M) and re.search(r"^Accessed:", istat, re.M):
            note += (tr(" FAT/exFAT: l'ultimo accesso è solo una data (nel disco l'ora non c'è, TSK scrive 00:00:00 ora locale): "
                     "l'ora che compare dopo la conversione NON è significativa, vale la data nel fuso del dispositivo."))
        istat = note + "\n\n" + istat
        exif = t["file_exif"](it["part"], it["inode"]) if "file_exif" in t else ""
    if exif:
        exif = exif_to_zone(case, exif, tz)
        exif = (tr("Date scritte nel file così come sono; dove il file indica il fuso, a destra c'è l'orario "
                   "in: {v1}.\n\n").format(v1=tz_label(case, tz))) + exif
    sha = ""
    _, f = file_size(case, it)
    if f:
        h = hashlib.sha256()
        with open(f, "rb") as fh:
            while c := fh.read(1 << 20):
                h.update(c)
        sha = h.hexdigest()
    return {"istat": istat, "exif": exif, "sha256": sha}


FULL_TEXT_MAX = 2_000_000       # caratteri mostrati al massimo nella scheda Testo


def carved_full_text(case, name):
    con = fa.db_ro(case)
    try:
        r = con.execute("SELECT relpath, img_offset, sha256 FROM carved WHERE name = ?",
                        (name.strip(),)).fetchone()
        m = con.execute("SELECT data FROM meta WHERE source='carving' AND inode = ?",
                        (name.strip(),)).fetchone()
    finally:
        con.close()
    if not r:
        return tr("Nessun file recuperato con nome {name}.").format(name=name)
    f = case.root / r[0]
    head = tr("File {v1} (byte {v2} nell'immagine, SHA-256 {v3})\n").format(v1=r[0], v2=r[1], v3=r[2])
    if m:
        head += tr("Metadati: ") + m[0][:2000] + "\n"
    return head + fa.show_text(f.read_bytes()[:50 << 20], f.name, cache_dir(case, "tmp"),
                               FULL_TEXT_MAX, more_hint=False)


def file_text(case, b):
    """Testo del file per la scheda Testo, conservato in cache dopo la prima estrazione.
    Si mostra il testo intero (fino a FULL_TEXT_MAX caratteri), non la porzione dell'agente."""
    if b.get("source") == "mail":
        v = G.mail_view(case, b)
        h = v["head"]
        con = fa.db_ro(case)
        body = con.execute("SELECT body FROM mail WHERE id=?", (v["id"],)).fetchone()[0]
        con.close()
        return {"text": "\n".join(f"{k}: {x}" for k, x in h.items() if x) + "\n\n" + (body or "")}
    if b.get("source") in ("art", "chat"):
        v = view_info(case, b)
        return {"text": v.get("headers") or re.sub(r"<[^<>]+>", " ", v["html"].split("</style>")[-1])}
    it = file_ident(case, b)
    if it["source"] == "x":
        return {"text": G.x_text(case, it)}
    out = cache_dir(case, "testo2") / f"{it['key']}.txt"
    if out.exists():
        return {"text": out.read_text(encoding="utf-8", errors="replace")}
    if it["source"] == "carving":
        text = carved_full_text(case, it["name"])
    else:
        local = None
        if (it.get("size") or 0) <= (50 << 20):
            try:
                local = cached_file(case, it)      # copia locale: il testo si estrae da lì
            except ValueError:
                local = None
        data = (Path(local).read_bytes()[:50 << 20] if local
                else G.image_read(case, it["start"], min(it["size"], 50 << 20)) if it["source"] == "ua"
                else fa.icat_read(case, it["part"], it["inode"], 50 << 20))
        if it["source"] == "ua" and data:
            text = (tr("Spazio non allocato: {path} — byte {start:,}–{v1:,} della copia ({size:,} byte). Stringhe "
                       "leggibili (ASCII e UTF-16)").format(path=it['path'], start=it['start'], v1=it['start'] + it['size'] - 1, size=it['size'])
                    + (tr(" dei primi 50 MB") if it["size"] > 50 << 20 else "") + ":\n\n").replace(",", ".") + \
                fa.show_text(data, "non_allocato.bin", cache_dir(case, "tmp"), FULL_TEXT_MAX, more_hint=False)
            try:
                out.write_text(text, encoding="utf-8")
            except OSError:
                pass
            return {"text": text}
        text = (fa.show_text(data, it["name"], cache_dir(case, "tmp"), FULL_TEXT_MAX,
                             more_hint=False) if data else tr("File vuoto o non recuperabile."))
    try:
        out.write_text(text, encoding="utf-8")
    except OSError:
        pass
    return {"text": text}
