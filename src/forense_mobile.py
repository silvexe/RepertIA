# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - estrazioni di smartphone (iOS e Android), dalla 2.20.

Un caso «smartphone» nasce da un'ESTRAZIONE DEL FILE SYSTEM COMPLETO del telefono, come la producono gli
strumenti di acquisizione: zip (Cellebrite FFS, GrayKey, altri), tar (Magnet ACQUIRE, estrazioni Android,
XRY esportato come file system…) oppure una cartella già estratta. Non è un disco: non ci sono partizioni né
Sleuth Kit. Questo modulo è caricato SOLO per i casi smartphone; i casi dei dischi non lo usano.

Come si inserisce nel resto del programma (stesso schema di forense_apfs.py)
- L'estrazione diventa una «partizione» del caso con un offset sintetico (MOBILE_BASE + n): così albero,
  filtri, elenchi, ricerche, indice del testo, hash, anteprime, report e report portatile la trattano come
  un file system qualunque. Nei punti del programma che chiamano Sleuth Kit c'è una riga che, per questi
  offset, delega a questo modulo (`is_mobile_part`).
- L'«inode» di un file è il numero della voce nell'indice dell'estrazione (tabella `mobile_files` di
  `estrazione.sqlite`, un database a parte nella cartella del caso: le scritture lunghe su caso.sqlite, come
  l'indicizzazione del testo, non devono bloccare la lettura dei file).
- I file NON si estraggono: si leggono dall'estrazione quando servono. Zip: l'indice centrale è letto
  direttamente e ogni voce si decomprime per conto suo dalla sua posizione. Tar: si legge alla posizione
  dei dati. Cartella: si apre il file.
- Un tar compresso (.tar.gz, .tgz) non si può leggere in un punto qualsiasi senza decomprimere tutto quello
  che lo precede: con `--decomprimi` si crea una COPIA DERIVATA decompressa nel caso (cartella
  `decompressa/`, con SHA-256 e riferimento all'originale, come per i volumi decifrati); l'originale non cambia.
- Date: zip con campi estesi (UT/NTFS) e tar = UTC. Le voci zip con la sola data DOS hanno l'ora locale senza
  fuso (spesso è l'ora dell'estrazione, non del telefono): sono convertite con il fuso del dispositivo e il caso
  lo dichiara. Una cartella già estratta ha le date del computer su cui è stata copiata: dichiarato.
- File cancellati: un'estrazione del file system contiene solo i file presenti (deleted = 0); i record
  cancellati DENTRO i database (chat, SMS) sono un'altra cosa e non sono recuperati in questa fase.
"""
import datetime as dt
import hashlib
import json
import os
import re
import stat
import struct
import sys
import tarfile
import threading
import zlib
from pathlib import Path

from forense_lingua import tr, N_  # noqa: E402

# offset sintetici delle estrazioni: subito sotto quelli dei volumi APFS (2**40, vedi forense_apfs.APFS_STEP), cioè
# oltre i 500 TB di un disco vero, dove nessuna partizione reale può iniziare; numeri esatti anche in JavaScript
MOBILE_BASE = (1 << 40) - (1 << 20)
MOBILE_MAX = 1 << 16
TIPO_CASO = "smartphone"
INSERT_MF = "INSERT INTO mobile_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
SCHEMA = """
CREATE TABLE IF NOT EXISTS mobile_files(id INTEGER PRIMARY KEY, part INTEGER, path TEXT, isdir INTEGER,
    size INTEGER, mode INTEGER, mtime TEXT, atime TEXT, ctime TEXT, crtime TEXT, datesrc TEXT,
    kind TEXT, loc INTEGER, csize INTEGER, method INTEGER, link TEXT);
CREATE INDEX IF NOT EXISTS idx_mf_path ON mobile_files(part, path);
"""
FORMATI = {"zip": N_("zip"), "tar": N_("tar"), "cartella": N_("cartella già estratta")}
DATESRC = {"utc": N_("UTC (dal campo esteso dello zip o dal tar)"),
           "dos": N_("ora locale senza fuso (data DOS dello zip), convertita con il fuso del dispositivo"),
           "copia": N_("date della cartella sul computer (possono essere quelle della copia, non del telefono)")}
ZIP_METHODS = {0: "stored", 8: "deflate", 9: "deflate64", 12: "bzip2", 14: "lzma", 93: "zstd", 95: "xz"}
_lock = threading.Lock()


def is_mobile_part(part):
    try:
        return MOBILE_BASE <= int(part) < MOBILE_BASE + MOBILE_MAX
    except (TypeError, ValueError):
        return False


def is_mobile_case(case):
    m = getattr(case, "meta", None) or {}
    return m.get("tipo_caso") == TIPO_CASO


def part_key(n):
    return MOBILE_BASE + int(n)


def _iso(t):
    """Secondi epoch (anche float) → 'AAAA-MM-GGTHH:MM:SS' UTC; None se assente o fuori scala."""
    try:
        if t is None or t <= 0:
            return None
        return dt.datetime.fromtimestamp(float(t), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    except (ValueError, OverflowError, OSError):
        return None


def _filetime(v):
    return (v - 116444736000000000) / 1e7 if v else None


# ------------------------------------------------------------------------------------------- zip

class ZipError(Exception):
    pass


def _zip_eocd(fh, size):
    """(offset dell'indice centrale, numero di voci, correzione) leggendo la fine dello zip (anche Zip64)."""
    tail = min(size, 65557 + 20)
    fh.seek(size - tail)
    buf = fh.read(tail)
    i = buf.rfind(b"PK\x05\x06")
    if i < 0:
        raise ZipError(tr("non è uno zip (manca la fine dell'indice centrale)"))
    eocd_pos = size - tail + i
    (_sig, _d, _dcd, _n_here, n_tot, cd_size, cd_off, _cl) = struct.unpack("<4s4H2LH", buf[i:i + 22])
    if n_tot == 0xFFFF or cd_size == 0xFFFFFFFF or cd_off == 0xFFFFFFFF:
        j = buf.rfind(b"PK\x06\x07", 0, i)
        if j < 0:
            raise ZipError(tr("zip64 senza localizzatore"))
        _s, _disk, z64_off, _tot_disks = struct.unpack("<4sLQL", buf[j:j + 20])
        fh.seek(z64_off)
        z = fh.read(56)
        if z[:4] != b"PK\x06\x06":
            raise ZipError(tr("zip64: fine dell'indice centrale non trovata"))
        (_s, _sz, _vm, _vn, _dn, _dcd, _nh, n_tot, cd_size, cd_off) = struct.unpack("<4sQ2H2L4Q", z)
        eocd_pos = z64_off
    # zip con dati davanti (es. autoestraenti): la posizione reale dell'indice è subito prima della sua fine
    corr = eocd_pos - cd_size - cd_off
    return cd_off + corr, n_tot, corr


def _zip_extra(extra, usize, csize, hoff):
    """Campi extra: Zip64 (dimensioni e posizione), UT (date UNIX UTC), NTFS (FILETIME UTC)."""
    t = {}
    i = 0
    while i + 4 <= len(extra):
        tag, ln = struct.unpack("<2H", extra[i:i + 4])
        d = extra[i + 4:i + 4 + ln]
        i += 4 + ln
        if tag == 0x0001:
            k = 0
            vals = []
            while k + 8 <= len(d):
                vals.append(struct.unpack("<Q", d[k:k + 8])[0])
                k += 8
            if usize == 0xFFFFFFFF and vals:
                usize = vals.pop(0)
            if csize == 0xFFFFFFFF and vals:
                csize = vals.pop(0)
            if hoff == 0xFFFFFFFF and vals:
                hoff = vals.pop(0)
        elif tag == 0x5455 and ln >= 5:
            fl = d[0]
            k = 1
            for bit, key in ((1, "M"), (2, "A"), (4, "C")):
                if fl & bit and k + 4 <= len(d):
                    t[key] = struct.unpack("<l", d[k:k + 4])[0]
                    k += 4
        elif tag == 0x000A and ln >= 32:
            k = 4
            while k + 4 <= len(d):
                at, al = struct.unpack("<2H", d[k:k + 4])
                if at == 1 and al >= 24:
                    m, a, c = struct.unpack("<3Q", d[k + 4:k + 28])
                    t.update({"M": _filetime(m), "A": _filetime(a), "B": _filetime(c)})
                k += 4 + al
    return usize, csize, hoff, t


def _dos_time(date, time):
    try:
        return dt.datetime(1980 + (date >> 9), (date >> 5) & 0xF, date & 0x1F,
                           time >> 11, (time >> 5) & 0x3F, (time & 0x1F) * 2)
    except ValueError:
        return None


def zip_entries(path):
    """Voci dello zip lette dall'indice centrale, una alla volta (anche milioni, senza tenerle in memoria):
    dict con path, isdir, size, csize, method, loc (posizione dell'intestazione locale), mode, times, dos, flags."""
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        cd_pos, n_tot, corr = _zip_eocd(fh, size)
        fh.seek(cd_pos)
        buf, bpos = b"", 0
        n = 0
        while n < n_tot:
            if len(buf) - bpos < 46 + 65535 * 3:
                buf = buf[bpos:] + fh.read(8 << 20)
                bpos = 0
            if buf[bpos:bpos + 4] != b"PK\x01\x02":
                break
            (_s, made, _need, flags, method, mt, md, _crc, csize, usize, fnl, exl, cml, _disk, _ia, ea,
             hoff) = struct.unpack("<4s6H3L5H2L", buf[bpos:bpos + 46])
            raw = buf[bpos + 46:bpos + 46 + fnl]
            extra = buf[bpos + 46 + fnl:bpos + 46 + fnl + exl]
            bpos += 46 + fnl + exl + cml
            n += 1
            name = raw.decode("utf-8" if flags & 0x800 else "cp437", "replace")
            usize, csize, hoff, times = _zip_extra(extra, usize, csize, hoff)
            mode = (ea >> 16) if (made >> 8) == 3 else 0
            isdir = name.endswith("/") or stat.S_ISDIR(mode) or bool(ea & 0x10 and (made >> 8) == 0)
            yield {"path": name, "isdir": isdir, "size": usize, "csize": csize, "method": method,
                   "loc": hoff + corr, "mode": mode, "times": times, "dos": _dos_time(md, mt), "flags": flags}


def zip_open(path, loc, csize, method):
    """Flusso dei dati decompressi di una voce dello zip, dalla sua intestazione locale."""
    fh = open(path, "rb")
    try:
        fh.seek(loc)
        h = fh.read(30)
        if h[:4] != b"PK\x03\x04":
            raise ZipError(tr("intestazione locale non trovata alla posizione {loc}").format(loc=loc))
        flags = struct.unpack("<H", h[6:8])[0]
        if flags & 1:
            raise ZipError(tr("voce dello zip cifrata"))
        fnl, exl = struct.unpack("<2H", h[26:30])
        fh.seek(loc + 30 + fnl + exl)
        left = csize
        if method == 0:
            while left > 0:
                b = fh.read(min(1 << 20, left))
                if not b:
                    break
                left -= len(b)
                yield b
            return
        if method == 8:
            d = zlib.decompressobj(-15)
        elif method == 12:
            import bz2
            d = bz2.BZ2Decompressor()
        elif method == 14:
            import lzma
            pre = fh.read(4)
            left -= 4
            psize = struct.unpack("<H", pre[2:4])[0]
            props = fh.read(psize)
            left -= psize
            d = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[lzma._decode_filter_properties(lzma.FILTER_LZMA1, props)])
        else:
            raise ZipError(tr("metodo di compressione dello zip non supportato: {m}").format(m=ZIP_METHODS.get(method, method)))
        while left > 0:
            b = fh.read(min(1 << 20, left))
            if not b:
                break
            left -= len(b)
            out = d.decompress(b)
            if out:
                yield out
        if method == 8:
            out = d.flush()
            if out:
                yield out
    finally:
        fh.close()


# ------------------------------------------------------------------------------------------- tar

def tar_entries(path):
    """Voci del tar (non compresso) in ordine, senza tenerle tutte in memoria: posizione dei dati inclusa."""
    with tarfile.open(path, "r:") as tf:
        k = 0
        while True:
            try:
                ti = tf.next()
            except tarfile.ReadError:
                break
            if ti is None:
                break
            k += 1
            if k % 1000 == 0:
                tf.members = []          # niente elenco in memoria: servono solo posizione e attributi
            ph = ti.pax_headers or {}
            times = {"M": ti.mtime}
            for key, kk in (("atime", "A"), ("ctime", "C"), ("LIBARCHIVE.creationtime", "B"), ("SCHILY.birthtime", "B")):
                if key in ph:
                    try:
                        times[kk] = float(ph[key])
                    except ValueError:
                        pass
            name = ti.name
            if name.startswith("./"):
                name = name[2:]
            yield {"path": name, "isdir": ti.isdir(), "size": ti.size if ti.isreg() else 0, "csize": ti.size,
                   "method": 0, "loc": ti.offset_data, "mode": ti.mode | (stat.S_IFDIR if ti.isdir() else
                                                                          stat.S_IFLNK if ti.issym() else stat.S_IFREG),
                   "times": times, "dos": None, "link": ti.linkname if (ti.issym() or ti.islnk()) else None,
                   "hardlink": ti.islnk(), "sparse": ti.issparse()}


def tar_open(path, loc, size):
    fh = open(path, "rb")
    try:
        fh.seek(loc)
        left = size
        while left > 0:
            b = fh.read(min(1 << 20, left))
            if not b:
                break
            left -= len(b)
            yield b
    finally:
        fh.close()


# -------------------------------------------------------------------------------------- cartella

def dir_entries(root):
    root = Path(root)
    for base, dirs, files in os.walk(root):
        dirs.sort()
        rel = os.path.relpath(base, root)
        rel = "" if rel == "." else rel.replace(os.sep, "/")
        for nm in dirs + sorted(files):
            p = os.path.join(base, nm)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            isdir = stat.S_ISDIR(st.st_mode)
            times = {"M": st.st_mtime, "A": st.st_atime, "C": st.st_ctime}
            if hasattr(st, "st_birthtime"):
                times["B"] = st.st_birthtime
            yield {"path": f"{rel}/{nm}" if rel else nm, "isdir": isdir, "size": 0 if isdir else st.st_size,
                   "csize": st.st_size, "method": 0, "loc": 0, "mode": st.st_mode, "times": times, "dos": None,
                   "link": os.readlink(p) if stat.S_ISLNK(st.st_mode) else None}


# ------------------------------------------------------------------------------- riconoscimento

def formato(path):
    """'zip', 'tar', 'targz' (da decomprimere), 'cartella' oppure None, guardando il contenuto (non il nome)."""
    p = Path(path)
    if p.is_dir():
        return "cartella"
    try:
        with open(p, "rb") as fh:
            head = fh.read(512)
    except OSError:
        return None
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if head[:2] == b"\x1f\x8b":
        return "targz"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    return None


IOS_RE = re.compile(r"(^|/)(mobile/Library/|private/var/mobile/|System/Library/CoreServices/SystemVersion\.plist$)")
ANDROID_RE = re.compile(r"(^|/)(data/data/[^/]+/|data/user/0/|data/user_de/0/|system/build\.prop$|data/system/packages\.xml$)")
SYSVER_RE = re.compile(r"(^|/)System/Library/CoreServices/SystemVersion\.plist$")
BUILDPROP_RE = re.compile(r"(^|/)(system/build\.prop|system/system/build\.prop|vendor/build\.prop)$")
TZ_IOS_RE = re.compile(r"(^|/)(private/var|var|filesystem2)?/?db/timezone/localtime$")
ANDROID_TZ_RE = re.compile(r"(^|/)data/property/persistent_properties$")


def piattaforma(paths_sample):
    ios = sum(1 for p in paths_sample if IOS_RE.search(p))
    andr = sum(1 for p in paths_sample if ANDROID_RE.search(p))
    if ios == andr == 0:
        return None
    return "ios" if ios >= andr else "android"


def produttore(img, paths_sample):
    """Strumento che ha prodotto l'estrazione, se si riconosce dalla struttura (solo indicazione)."""
    nm = Path(img).name.lower()
    top = {p.split("/", 1)[0] for p in paths_sample[:5000]}
    if any(re.fullmatch(r"filesystem\d+", t, re.I) for t in top) or "extraction_ffs" in nm or "clbx" in nm:
        return "Cellebrite (FFS)"
    if "files_full" in nm or "graykey" in nm:
        return "GrayKey"
    if "magnet" in nm or "full image" in nm:
        return "Magnet ACQUIRE"
    return None


# ------------------------------------------------------------------------------------- l'indice

def ensure_schema(con):
    con.executescript(SCHEMA)


def mx_path(case):
    return case.root / "estrazione.sqlite"


def mx(case, write=False):
    """Connessione all'indice dell'estrazione (estrazione.sqlite); in sola lettura salvo che per l'indicizzazione."""
    import sqlite3
    if write:
        return sqlite3.connect(mx_path(case))
    return sqlite3.connect(mx_path(case).as_uri() + "?mode=ro", uri=True, timeout=30)


def sorgenti(case):
    return [p for p in case.meta.get("partitions", []) if is_mobile_part(p.get("offset"))]


def _sorgente(case, part):
    for p in sorgenti(case):
        if int(p["offset"]) == int(part):
            return p["mobile"]
    raise ValueError(tr("estrazione {part} non presente nel caso").format(part=part))


def _local_to_utc(naive, tz):
    try:
        from zoneinfo import ZoneInfo
        return naive.replace(tzinfo=ZoneInfo(tz)).timestamp()
    except Exception:
        return naive.replace(tzinfo=dt.timezone.utc).timestamp()


def index(case, part, con, say=print):
    """Legge l'indice dell'estrazione e scrive mobile_files, files ed events (origin 'tsk', stesso formato dei
    dischi: albero, colonne delle date e timeline funzionano senza cambiamenti). Restituisce (voci, eventi, stats)."""
    import forense_agent as fa
    w = mx(case, True)
    ensure_schema(w)
    src = _sorgente(case, part)
    img, kind = src["file"], src["formato"]
    tz = ((case.meta.get("fuso_dispositivo") or {}).get("tz")) or "Europe/Rome"
    gen = (zip_entries(img) if kind == "zip" else tar_entries(img) if kind == "tar" else dir_entries(img))
    mf, files, evs = [], [], []
    n = nev = 0
    stats = {"voci": 0, "cartelle": 0, "byte": 0, "date": {}, "collegamenti": 0, "sparsi": 0, "cifrate": 0,
             "metodi": {}}
    seen_dirs, have_dirs = set(), set()
    nid = w.execute("SELECT IFNULL(MAX(id), 0) FROM mobile_files").fetchone()[0]
    hard = []
    for e in gen:
        path = e["path"].replace("\\", "/").strip("/")
        while path.startswith("./"):
            path = path[2:]
        if not path:
            continue
        nid += 1
        times = {k: v for k, v in (e.get("times") or {}).items() if v}
        if kind == "zip" and not times and e.get("dos"):
            times = {"M": _local_to_utc(e["dos"], tz)}
            dsrc = "dos"
        else:
            dsrc = "copia" if kind == "cartella" else "utc"
        stats["date"][dsrc] = stats["date"].get(dsrc, 0) + 1
        if kind == "zip":
            stats["metodi"][e["method"]] = stats["metodi"].get(e["method"], 0) + 1
            if e.get("flags", 0) & 1:
                stats["cifrate"] += 1
        isdir = bool(e["isdir"])
        mode = e.get("mode") or 0
        islink = stat.S_ISLNK(mode) or bool(e.get("link") and not e.get("hardlink"))
        typ = "d/d" if isdir else "l/l" if islink else "r/r"
        if e.get("hardlink"):
            hard.append((nid, e["link"]))
        if islink or e.get("hardlink"):
            stats["collegamenti"] += 1
        if e.get("sparse"):
            stats["sparsi"] += 1
        size = int(e.get("size") or 0)
        iso = {k: _iso(times.get(k)) for k in "MACB"}
        mf.append((nid, int(part), path, int(isdir), size, mode, iso["M"], iso["A"], iso["C"], iso["B"], dsrc,
                   kind, int(e.get("loc") or 0), int(e.get("csize") or 0), int(e.get("method") or 0), e.get("link")))
        files.append((int(part), str(nid), 0, typ, path))
        if isdir:
            have_dirs.add(path)
            stats["cartelle"] += 1
        else:
            stats["byte"] += size
        par = path.rpartition("/")[0]
        if par:
            seen_dirs.add(par)
        for k in "AMCB":
            if iso[k]:
                evs.append((iso[k], k, "FILE", path, tr("{v1} | {path} | inode {ident} | {size} B").format(
                    v1=tr(fa.KIND[k]), path=path, ident=nid, size=size), "tsk", int(part)))
        n += 1
        if len(mf) >= 20000:
            w.executemany(INSERT_MF, mf)
            con.executemany(fa.INSERT_FILE, files)
            mf.clear()
            files.clear()
        if len(evs) >= 50000:
            con.executemany(fa.INSERT_EV, evs)
            nev += len(evs)
            evs.clear()
        if say and n % 100000 == 0:
            say(tr("  {n} voci dell'estrazione lette...").format(n=n))
    w.executemany(INSERT_MF, mf)
    con.executemany(fa.INSERT_FILE, files)
    con.executemany(fa.INSERT_EV, evs)
    nev += len(evs)
    # cartelle presenti solo nei percorsi (zip senza voci per le cartelle): le aggiunge l'albero da solo
    for nid_h, target in hard:          # tar: un collegamento fisico ha i dati della voce a cui rimanda
        t = target.strip("/")
        t = t[2:] if t.startswith("./") else t
        r = w.execute("SELECT loc, csize, size FROM mobile_files WHERE part=? AND path=? AND isdir=0 LIMIT 1",
                        (int(part), t)).fetchone()
        if r:
            w.execute("UPDATE mobile_files SET loc=?, csize=?, size=?, link=NULL WHERE id=?", (r[0], r[1], r[2], nid_h))
            con.execute("UPDATE files SET type='r/r' WHERE part=? AND inode=?", (int(part), str(nid_h)))
    con.commit()
    w.commit()
    w.close()
    stats["voci"] = n
    stats["cartelle_implicite"] = len(seen_dirs - have_dirs)
    stats["metodi"] = {ZIP_METHODS.get(k, str(k)): v for k, v in stats["metodi"].items()}
    return n, nev, stats


# ------------------------------------------------------------------------------ lettura dei file

def _row(case, part, inode):
    con = mx(case)
    try:
        r = con.execute("SELECT path, isdir, size, mode, mtime, atime, ctime, crtime, datesrc, kind, loc, csize, "
                        "method, link FROM mobile_files WHERE id=? AND part=?", (int(inode), int(part))).fetchone()
    finally:
        con.close()
    if not r:
        raise FileNotFoundError(tr("voce {inode} non presente nell'estrazione").format(inode=inode))
    keys = ("path", "isdir", "size", "mode", "mtime", "atime", "ctime", "crtime", "datesrc", "kind", "loc", "csize",
            "method", "link")
    return dict(zip(keys, r))


def stream(case, part, inode, chunk=1 << 20):
    """Contenuto di un file dell'estrazione, a blocchi (sola lettura, nessuna copia)."""
    src = _sorgente(case, part)
    r = _row(case, part, inode)
    if r["isdir"]:
        return
    if stat.S_ISLNK(r["mode"] or 0) and r["kind"] == "zip":
        pass                              # nello zip il contenuto di un collegamento è il percorso di destinazione
    elif r["link"] and r["kind"] != "zip":
        yield (r["link"] or "").encode("utf-8")
        return
    img = src["file"]
    if r["kind"] == "zip":
        yield from zip_open(img, r["loc"], r["csize"], r["method"])
    elif r["kind"] == "tar":
        yield from tar_open(img, r["loc"], r["size"])
    else:
        with open(os.path.join(img, *r["path"].split("/")), "rb") as fh:
            while b := fh.read(chunk):
                yield b


def head_tail(case, part, inode, n=4096, tail=0):
    """(dimensione, primi n byte, ultimi `tail` byte) come HeadReader.read delle analisi estese."""
    r = _row(case, part, inode)
    size = r["size"]
    head, end = bytearray(), b""
    last = bytearray()
    for b in stream(case, part, inode):
        if len(head) < n:
            head += b[:n - len(head)]
        if tail:
            last = (last + b)[-tail:]
        elif len(head) >= n:
            break
    if tail:
        end = bytes(last)
    return size, bytes(head), end


def istat_text(case, part, inode):
    """Scheda Metadati di un file dell'estrazione (equivalente di istat per i dischi)."""
    src = _sorgente(case, part)
    r = _row(case, part, inode)
    mode = r["mode"] or 0
    L = [tr("Voce dell'estrazione: {inode}").format(inode=inode),
         tr("Estrazione: {file} ({fmt})").format(file=src["file"], fmt=tr(FORMATI.get(r["kind"], r["kind"]))),
         tr("Percorso nell'estrazione: {path}").format(path=r["path"]),
         tr("Tipo: {t}").format(t=tr("cartella") if r["isdir"] else tr("collegamento") if stat.S_ISLNK(mode) else tr("file")),
         tr("Dimensione: {size} byte").format(size=r["size"])]
    if mode:
        L.append(tr("Permessi: {m}").format(m=stat.filemode(mode)))
    if r["link"]:
        L.append(tr("Destinazione del collegamento: {l}").format(l=r["link"]))
    L.append("")
    L.append(tr("Date (fonte: {s}):").format(s=tr(DATESRC.get(r["datesrc"], r["datesrc"] or "-"))))
    for k, lab in (("mtime", N_("Modifica")), ("atime", N_("Accesso")), ("ctime", N_("Modifica metadati")),
                   ("crtime", N_("Creazione"))):
        if r[k]:
            L.append(f"  {tr(lab)}: {r[k].replace('T', ' ')} UTC")
    L.append("")
    if r["kind"] == "zip":
        L.append(tr("Posizione nello zip: intestazione locale al byte {loc}; {cs} byte compressi ({m})").format(
            loc=r["loc"], cs=r["csize"], m=ZIP_METHODS.get(r["method"], r["method"])))
    elif r["kind"] == "tar":
        L.append(tr("Posizione nel tar: dati dal byte {loc}").format(loc=r["loc"]))
    return "\n".join(L)


def detect_os(case, part, con):
    """Sistema e versione del telefono: SystemVersion.plist (iOS), build.prop (Android)."""
    import plistlib
    info = {}
    m = mx(case)
    for (path, ino) in m.execute("SELECT path, id FROM mobile_files WHERE part=? AND isdir=0 AND "
                                   "(path LIKE '%SystemVersion.plist' OR path LIKE '%build.prop')", (int(part),)):
        try:
            data = b"".join(stream(case, part, ino))[:4 << 20]
        except Exception:
            continue
        if SYSVER_RE.search(path):
            try:
                d = plistlib.loads(data)
                info.update({"os": "iOS", "versione": d.get("ProductVersion"), "build": d.get("ProductBuildVersion")})
            except Exception:
                pass
        elif BUILDPROP_RE.search(path):
            t = data.decode("utf-8", "replace")
            props = dict(m.groups() for m in re.finditer(r"^([\w.]+)=(.*)$", t, re.M))
            info.setdefault("os", "Android")
            for k, key in (("versione", "ro.build.version.release"), ("modello", "ro.product.model"),
                           ("produttore", "ro.product.manufacturer"), ("build", "ro.build.display.id"),
                           ("patch", "ro.build.version.security_patch")):
                if props.get(key) and not info.get(k):
                    info[k] = props[key].strip()
    return info


def rileva_fuso(case, part, con):
    """Fuso del telefono: iOS dal collegamento /private/var/db/timezone/localtime, Android da
    persist.sys.timezone (proprietà persistenti). {tz, origine} o None."""
    m = mx(case)
    for path, ino, link in m.execute("SELECT path, id, link FROM mobile_files WHERE part=? AND "
                                       "(path LIKE '%db/timezone/localtime' OR path LIKE '%property/persistent_properties')",
                                       (int(part),)):
        try:
            if path.endswith("localtime"):
                tgt = link or b"".join(stream(case, part, ino))[:512].decode("utf-8", "replace")
                m = re.search(r"zoneinfo/(.+)$", tgt.strip())
                if m:
                    return {"tz": m.group(1), "origine": path}
            else:
                data = b"".join(stream(case, part, ino))[:1 << 20]
                m = re.search(rb"persist\.sys\.timezone.{1,4}?([A-Z][A-Za-z_]+/[A-Za-z_/+-]+)", data, re.S)
                if m:
                    return {"tz": m.group(1).decode(), "origine": path}
        except Exception:
            continue
    return None


SKIP_MOBILE_PREFIX = ("system/", "usr/", "bin/", "sbin/", "apex/", "vendor/", "product/", "odm/", "proc/", "sys/",
                      "dev/", "cores/", "applications/")
SKIP_MOBILE_PART = ("/system/library/", "/library/caches/", "/caches/com.apple.", "/.cache/", "/code_cache/",
                    "/containers/bundle/application/", "/data/app/", "/data/dalvik-cache/", "/system/framework/",
                    "/node_modules/")


def skip_for_text(path):
    """Cartelle escluse dall'indice del testo per le estrazioni di telefoni: sistema e codice delle app, non i dati
    dell'utente (che stanno in private/var/mobile e data/data, esclusi invece per i dischi)."""
    p = path.lower()
    p2 = re.sub(r"^(filesystem\d+|dump|extraction|fs)/", "", p)
    return p2.startswith(SKIP_MOBILE_PREFIX) or any(s in "/" + p for s in SKIP_MOBILE_PART)


def fs_info_text(case, part):
    """Descrizione dell'estrazione per l'agente (equivalente di fsstat)."""
    p = next(x for x in sorgenti(case) if int(x["offset"]) == int(part))
    m = dict(p["mobile"])
    return json.dumps({"estrazione": m.get("nome"), "formato": m.get("formato"), "piattaforma": m.get("piattaforma"),
                       "prodotta_da": m.get("produttore"), "sistema": m.get("sistema"),
                       "statistiche": m.get("statistiche")}, ensure_ascii=False, indent=1)


def list_dir_text(case, part, inode=""):
    """Contenuto di una cartella dell'estrazione per l'agente (equivalente di fls): «tipo id:<TAB>nome»."""
    import forense_agent as fa
    con = mx(case)
    try:
        base = ""
        if str(inode or "").strip():
            r = con.execute("SELECT path FROM mobile_files WHERE id=? AND part=?", (int(inode), int(part))).fetchone()
            if not r:
                return tr("voce {inode} non presente nell'estrazione").format(inode=inode)
            base = r[0] + "/"
        rows = con.execute("SELECT isdir, mode, id, path FROM mobile_files WHERE part=? AND path LIKE ? ESCAPE '\\' "
                           "AND instr(substr(path, ?), '/') = 0 ORDER BY path LIMIT 5000",
                           (int(part), fa.like(base)[1:] if base else "%", len(base) + 1)).fetchall()
    finally:
        con.close()
    out = []
    for isdir, mode, i, path in rows:
        if base and not path.startswith(base):
            continue
        t = "d/d" if isdir else "l/l" if stat.S_ISLNK(mode or 0) else "r/r"
        out.append(f"{t} {i}:\t{path[len(base):]}")
    if not out and not base:
        return tr("La radice dell'estrazione non ha voci proprie: usa find_files per cercare per percorso.")
    return "\n".join(out)


# ------------------------------------------------------------------------------ copia derivata

def decomprimi(case, gz, say=print):
    """Copia derivata decompressa di un .tar.gz nella cartella del caso (decompressa/), con SHA-256
    dell'originale e della copia e il riferimento all'originale (file .json accanto). L'originale non cambia."""
    import gzip
    import shutil
    import forense_agent as fa
    gz = Path(gz)
    out_dir = case.root / "decompressa"
    out_dir.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"\.(tar\.gz|tgz|gz)$", "", gz.name, flags=re.I) + ".tar"
    out = out_dir / name
    # spazio: la dimensione decompressa si legge in fondo al gzip (modulo 4 GB): non basta, quindi si controlla
    # durante la scrittura che restino almeno 2 GB liberi
    tmp = out.with_suffix(".tar.parziale")
    h_in, h_out = hashlib.sha256(), hashlib.sha256()
    done = 0
    say(tr("Decompressione di {gz} in una copia derivata (il file originale non cambia)…").format(gz=gz.name))
    fa.avanz("decomp")

    class _Tee:
        def __init__(self, f):
            self.f = f

        def read(self, n=-1):
            b = self.f.read(n)
            h_in.update(b)
            return b

    with open(gz, "rb") as raw, open(tmp, "wb") as fo:
        with gzip.GzipFile(fileobj=_Tee(raw)) as g:
            nxt = 0
            while b := g.read(8 << 20):
                fo.write(b)
                h_out.update(b)
                done += len(b)
                if done >= nxt:
                    nxt += 2 << 30
                    if shutil.disk_usage(out_dir).free < (2 << 30):
                        fo.close()
                        tmp.unlink()
                        raise OSError(tr("spazio su disco esaurito durante la decompressione"))
                    say(tr("  {v:.1f} GB decompressi…").format(v=done / 1e9))
        h_in.update(raw.read())
    os.chmod(tmp, 0o444)
    tmp.replace(out)
    rif = {"origine": str(gz), "sha256_origine": h_in.hexdigest(), "sha256": h_out.hexdigest(), "byte": done,
           "operazione": "gzip -d", "creata": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    Path(str(out) + ".json").write_text(json.dumps(rif, indent=1), encoding="utf-8")
    return out, rif


# ------------------------------------------------------------------------------ preparazione

def cmd_prepara(args):
    """Prepara un caso smartphone: hash dell'estrazione, indice dei file, timeline, sistema e fuso del telefono;
    poi (facoltativi) indice del testo, chat, iLEAPP/ALEAPP."""
    import sqlite3
    import forense_agent as fa
    import forense_lingua as lg
    case = fa.Case(args.case)
    img = Path(args.image).expanduser().resolve()
    if not img.exists():
        sys.exit(tr("Estrazione non trovata: {img}").format(img=img))
    if case.meta_path.exists():
        sys.exit(tr("Il caso {root} esiste già: usa un'altra cartella.").format(root=case.root))
    kind = formato(img)
    if kind is None:
        sys.exit(tr("Formato non riconosciuto: servono uno zip, un tar (anche .tar.gz) o una cartella con "
                    "l'estrazione del file system del telefono."))
    case.root.mkdir(parents=True, exist_ok=True)
    case.export_dir.mkdir(exist_ok=True)
    lingua = lg.imposta(getattr(args, "lingua", None) or lg.lingua())
    case.meta = {"created": fa.now(), "tipo_caso": TIPO_CASO, "image": str(img), "evidence": str(img),
                 "tool_versions": {}, "lingua": lingua}
    try:
        case.meta["ambiente"] = fa.ambiente()
    except Exception as e:
        print(tr("Versioni degli strumenti non rilevate: {e}").format(e=e))
    case.log("prepara_smartphone", {"image": str(img), "formato": kind})
    if getattr(args, "info", None):
        try:
            info = fa.info_caso_clean(json.loads(args.info))
        except ValueError:
            info = {}
        if info:
            case.meta["info_caso"] = info
            case.log("info_caso", info)
    fz = fa.fuso_valido(getattr(args, "fuso", None))
    if getattr(args, "fuso", None) and not fz:
        sys.exit(tr("Fuso orario non riconosciuto: {fuso} (usa un nome come Europe/Rome o UTC).").format(fuso=args.fuso))
    case.meta["fuso_dispositivo"] = {"tz": fz or fa.FUSO_PREDEFINITO,
                                     "origine": tr("scelto dall'operatore") if fz else tr("predefinito (Italia)"),
                                     "auto": not fz}
    case.save()
    if kind != "cartella":
        if args.no_hash:
            case.meta["sha256_rinviato"] = True
            case.log("hash_copia_rinviato", tr("analisi speditiva"))
        else:
            fa.hash_evidence(case)
    else:
        print(tr("Estrazione in una cartella: l'hash di ogni file si calcola con «Hash dei file» (non c'è un file unico "
                 "dell'estrazione da verificare)."))
    work = img
    if kind == "targz":
        if not getattr(args, "decomprimi", False):
            sys.exit(tr("L'estrazione è un tar compresso (.tar.gz): per leggerne i file senza decomprimere ogni volta "
                        "tutto quello che li precede serve una copia derivata decompressa nella cartella del caso "
                        "(stessa dimensione dei dati). Ripeti con --decomprimi (nell'interfaccia: «Crea la copia "
                        "decompressa») oppure decomprimi tu il file e scegli il .tar."))
        work, rif = decomprimi(case, img)
        case.meta["decompressa"] = rif       # non «derivata»: quella è dei volumi decifrati (altri campi)
        case.meta["image"] = str(work)
        case.log("copia_derivata_decompressa", rif)
        kind = "tar"
    part = part_key(0)
    case.meta["partitions"] = [{"offset": part, "readable": True, "fs": tr("Estrazione ({fmt})").format(
        fmt=tr(FORMATI[kind])), "desc": img.name, "length_sectors": 0,
        "mobile": {"file": str(work), "formato": kind, "nome": img.name}}]
    case.save()
    db = case.db_path
    if db.exists():
        db.unlink()
    if mx_path(case).exists():
        mx_path(case).unlink()
    con = sqlite3.connect(db)
    con.executescript(fa.SCHEMA)
    print(tr("Elenco dei file dell'estrazione…"), flush=True)
    fa.avanz("list")               # (2.20) passi della pagina di preparazione
    n, nev, stats = index(case, part, con)
    p = case.meta["partitions"][0]
    p["files"], p["deleted"] = n, 0
    m = mx(case)
    sample = [r[0] for r in m.execute("SELECT path FROM mobile_files WHERE part=? LIMIT 200000", (part,))]
    m.close()
    plat = piattaforma(sample)
    prod = produttore(img, sample)
    osinfo = detect_os(case, part, con)
    if osinfo.get("os") == "iOS":
        plat = "ios"
    elif osinfo.get("os") == "Android":
        plat = plat or "android"
    p["os"] = " ".join(x for x in (osinfo.get("os") or {"ios": "iOS", "android": "Android"}.get(plat) or "",
                                   osinfo.get("versione") or "") if x) or None
    p["mobile"].update({"piattaforma": plat, "produttore": prod, "sistema": osinfo, "statistiche": stats})
    case.meta["mobile"] = {"piattaforma": plat, "produttore": prod, "sistema": osinfo, "formato": kind}
    case.meta["disk_type"] = (tr("estrazione di uno smartphone {os}").format(os=p["os"]) if p["os"] else
                              tr("estrazione di uno smartphone (sistema non riconosciuto)"))
    fd = case.meta["fuso_dispositivo"]
    det = rileva_fuso(case, part, con)
    fd["rilevato"] = det
    if det and det.get("tz"):
        if fd.get("auto"):
            fd["tz"], fd["origine"], fd["stato"] = det["tz"], tr("rilevato nel telefono"), "rilevato"
        else:
            fd["stato"] = "confermato" if fa.fuso_equivalenti(det["tz"], fd["tz"]) else "discordante"
    else:
        fd["stato"] = "non_verificabile" if fd.get("auto") else "scelto_non_verificato"
    case.meta["timeline"] = {"tsk_events": nev, "plaso_events": 0}
    case.log("estrazione_indicizzata", {"voci": n, "eventi": nev, "piattaforma": plat, "produttore": prod,
                                        "sistema": osinfo, "statistiche": stats})
    if stats["date"].get("dos"):
        print(tr("ATTENZIONE: {n} voci dello zip hanno solo la data DOS (ora locale senza fuso, spesso l'ora "
                 "dell'estrazione): convertite con il fuso {tz}.").format(n=stats["date"]["dos"], tz=fd["tz"]), flush=True)
    case.save()
    print(tr("Telefono: {v1}; estrazione {fmt}{prod}; {n} voci, {nev} eventi.").format(
        v1=p["os"] or tr("sistema non riconosciuto"), fmt=tr(FORMATI[kind]),
        prod=(" " + tr("(prodotta da {p})").format(p=prod)) if prod else "", n=n, nev=nev), flush=True)
    if getattr(args, "keychain", None):
        import forense_mobile_portachiavi as fmk
        if p["os"] and (case.meta.get("mobile") or {}).get("piattaforma") != "ios":
            print(tr("Portachiavi ignorato: serve solo per gli iPhone (iOS)."), flush=True)
            case.log("portachiavi_ignorato", {"file": args.keychain, "motivo": "non iOS"})
        else:
            try:
                fmk.imposta(case, args.keychain, lambda m: print(m, flush=True))
            except ValueError as e:
                print(tr("Portachiavi non registrato: {e}").format(e=e), flush=True)
                case.log("portachiavi_non_registrato", {"file": args.keychain, "motivo": str(e)})
    for sd in getattr(args, "sysdiagnose", None) or []:      # (2.20) sysdiagnose acquisiti a parte
        import forense_mobile_sysdiagnose as fms
        if p["os"] and (case.meta.get("mobile") or {}).get("piattaforma") != "ios":
            print(tr("Sysdiagnose ignorato: è dei dispositivi Apple (iOS)."), flush=True)
            case.log("sysdiagnose_ignorato", {"file": sd, "motivo": "non iOS"})
            continue
        try:
            fms.aggiungi(case, sd, lambda m: print(m, flush=True))
        except ValueError as e:
            print(tr("Sysdiagnose non registrato: {e}").format(e=e), flush=True)
            case.log("sysdiagnose_non_registrato", {"file": sd, "motivo": str(e)})
    if getattr(args, "wa_backup", False):     # (2.20) decifra i backup WhatsApp con la chiave dell'estrazione
        case.meta["wa_backup_attivo"] = True
        case.log("wa_backup_attivato", {"da": "prepara"})
        case.save()
    if getattr(args, "chat", True):
        try:
            import forense_mobile_chat as fmc
            # con iLEAPP/ALEAPP dopo, le chiamate si scrivono una volta sola alla fine (numeri di riga invariati)
            fa.avanz("chat")
            fmc.run(case, con, chiamate=not getattr(args, "leapp", False))
        except Exception as e:
            print(tr("Chat: non completate ({vname}: {e})").format(vname=type(e).__name__, e=e), flush=True)
    if not args.no_indice:
        fa.run_addon(case, con, "indice")
    if args.hash_file:
        fa.run_addon(case, con, "hash")
    if getattr(args, "leapp", False):
        try:
            import forense_mobile_leapp as fml
            fml.run(case, con)
        except Exception as e:
            print(tr("iLEAPP/ALEAPP: non completato ({vname}: {e})").format(vname=type(e).__name__, e=e), flush=True)
    if case.meta.get("sysdiagnose"):
        try:
            import forense_mobile_sysdiagnose as fms
            fms.run(case, con, lambda m: print(m, flush=True))
        except Exception as e:
            print(tr("Sysdiagnose: iLEAPP non completato ({vname}: {e})").format(vname=type(e).__name__, e=e), flush=True)
    if getattr(args, "trascrizione", None):       # (2.20) scelta alla creazione del caso: dopo chat e indice
        import forense_trascrizione as ftr
        ftr.da_preparazione(case, con, args.trascrizione)
    con.close()
    case.save()
    print(tr("Pronto."))


def main(argv=None):
    import argparse
    import forense_lingua as lg
    ap = argparse.ArgumentParser(description=tr("RepertIA - estrazioni di smartphone (iOS, Android)"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepara", help=tr("nuovo caso da un'estrazione del file system di un telefono"))
    p.add_argument("--image", required=True, help=tr("zip, tar, tar.gz o cartella dell'estrazione"))
    p.add_argument("--case", required=True)
    p.add_argument("--no-hash", action="store_true", help=tr("analisi speditiva: SHA-256 dell'estrazione calcolato dopo"))
    p.add_argument("--no-indice", action="store_true", help=tr("non indicizza testo dei documenti e metadati"))
    p.add_argument("--hash-file", action="store_true", help=tr("calcola MD5, SHA-1 e SHA-256 di tutti i file"))
    p.add_argument("--no-chat", dest="chat", action="store_false", help=tr("non legge le chat (WhatsApp, SMS, iMessage)"))
    p.add_argument("--leapp", action="store_true", help=tr("artefatti con iLEAPP (iOS) o ALEAPP (Android)"))
    p.add_argument("--decomprimi", action="store_true",
                   help=tr("per un .tar.gz: crea nella cartella del caso la copia derivata decompressa"))
    p.add_argument("--info", help=tr("dati del caso in JSON: nome, operatore, reperto, note"))
    p.add_argument("--lingua", choices=sorted(lg.LINGUE), help=tr("lingua dei testi del caso: it o en"))
    p.add_argument("--fuso", help=tr("fuso orario del telefono (es. Europe/Rome); predefinito: rilevato nell'estrazione"))
    p.add_argument("--keychain", help=tr("portachiavi (keychain) di iOS acquisito a parte (es. GrayKey): SHA-256 nel registro, "
                                         "non copiato nel caso, passato a iLEAPP"))
    p.add_argument("--wa-backup", action="store_true",
                   help=tr("decifra i backup di WhatsApp (.crypt14) se nell'estrazione c'è la chiave e li legge come chat"))
    p.add_argument("--trascrizione", metavar="JSON",
                   help=tr("trascrizione degli audio con Whisper (ultimo passo): opzioni in JSON, es. "
                           "{\"scope\": \"chat\", \"modello\": \"small\", \"lingua\": \"auto\"}; il modello va installato prima"))
    p.add_argument("--sysdiagnose", action="append", metavar="FILE",
                   help=tr("sysdiagnose di iOS (.tar.gz) acquisito a parte, anche più di uno: SHA-256 nel registro, non copiato "
                           "nel caso, letto con un secondo giro di iLEAPP"))
    a = sub.add_parser("aggiungi", help=tr("analisi aggiuntive su un caso smartphone"))
    a.add_argument("--case", required=True)
    a.add_argument("cosa", nargs="+", choices=["chat", "leapp", "leapp-import", "sysdiagnose", "wa-backup"],
                   help=tr("leapp-import: rilegge le tabelle dell'ultimo rapporto di iLEAPP/ALEAPP senza rieseguirlo; "
                           "sysdiagnose: registra i file di --file e rilegge con iLEAPP i sysdiagnose del caso"))
    a.add_argument("--file", action="append", metavar="FILE", help=tr("sysdiagnose da aggiungere al caso (con «sysdiagnose»)"))
    a.add_argument("--sha256", help=tr("con «sysdiagnose»: legge solo il sysdiagnose con questo SHA-256"))
    args = ap.parse_args(argv)
    if args.cmd == "prepara":
        return cmd_prepara(args)
    import sqlite3
    import forense_agent as fa
    case = fa.load_case(args.case)
    con = sqlite3.connect(case.db_path)
    for what in args.cosa:
        if what == "chat":
            import forense_mobile_chat as fmc
            fmc.run(case, con)
        elif what == "wa-backup":          # (2.20) attiva la decifratura dei backup WhatsApp e rilegge le chat
            import forense_mobile_chat as fmc
            case.meta["wa_backup_attivo"] = True
            case.log("wa_backup_attivato", {"da": "aggiungi"})
            fmc.run(case, con)
        elif what == "leapp-import":
            import forense_mobile_leapp as fml
            fml.reimporta(case, con)
        elif what == "sysdiagnose":
            import forense_mobile_sysdiagnose as fms
            nuovi = []
            for f in args.file or []:
                try:
                    nuovi.append(fms.aggiungi(case, f, lambda m: print(m, flush=True))["sha256"])
                except ValueError as e:
                    print(tr("Sysdiagnose non registrato: {e}").format(e=e), flush=True)
                    case.log("sysdiagnose_non_registrato", {"file": f, "motivo": str(e)})
            if args.file and not nuovi:
                continue
            for sel in ([args.sha256] if args.sha256 else nuovi or [None]):
                fms.run(case, con, lambda m: print(m, flush=True), solo=sel)
        else:
            import forense_mobile_leapp as fml
            fml.run(case, con)
    con.close()
    case.save()
    print(tr("Pronto."))


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    main()
