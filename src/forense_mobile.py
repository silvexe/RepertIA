# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
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
  cancellati DENTRO i database (chat, SMS) sono un'altra cosa: si recuperano solo per WhatsApp Android (3.0.1, in
  forense_mobile_chat.recuperati_wa).
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
CREATE TABLE IF NOT EXISTS logica_hash(id INTEGER PRIMARY KEY, md5 TEXT, sha1 TEXT);
"""
FORMATI = {"zip": N_("zip"), "tar": N_("tar"), "cartella": N_("cartella già estratta"),
           "7z": N_("7z"), "rar": N_("rar"), "estratto": N_("copia estratta dall'archivio"),
           "ad1": N_("AD1, immagine logica di FTK"), "targz": N_("tar.gz"),
           "iso": N_("immagine di CD/DVD ISO 9660 o UDF"),
           "ram": N_("dump della memoria RAM")}            # (3.0.4) forense_ram.py
DB_LBL = {"imessage": N_("iMessage/SMS (iPhone)"), "whatsapp_ios": N_("WhatsApp (iPhone)"),
          "whatsapp_android": N_("WhatsApp (Android)"), "sms_android": N_("SMS/MMS (Android)"),
          "ab_ios": N_("rubrica (iPhone)"), "contacts_android": N_("rubrica (Android)"),
          "wa_contacts_android": N_("contatti WhatsApp (Android)"), "wa_contacts_ios": N_("contatti WhatsApp (iPhone)")}
# (3.0.2) formati letti solo come «sorgente logica» (non sono estrazioni di telefoni)
LOGICI = ("7z", "rar", "ad1", "iso")
ESTRATTI = ("7z", "rar", "iso")          # letti con 7-Zip in una copia derivata estratta
DATESRC = {"utc": N_("UTC (dal campo esteso dello zip o dal tar)"),
           "dos": N_("ora locale senza fuso (data DOS dello zip), convertita con il fuso del dispositivo"),
           "copia": N_("date della cartella sul computer (possono essere quelle della copia, non del telefono)"),
           "archivio": N_("UTC (dall'archivio 7z o RAR 5)"),
           "memoria": N_("UTC, dai record MFT trovati in memoria (il contenuto viene dalla memoria e può essere incompleto)"),
           "mft": N_("UTC, dal record MFT trovato in memoria (del file restano nome, date e dimensione: il contenuto non è nel dump)"),
           "mft_res": N_("UTC, dal record MFT trovato in memoria (file piccolo: anche il contenuto viene dal record)"),
           "locale": N_("ora locale senza fuso (archivio RAR 4), convertita con il fuso indicato"),
           "ad1": N_("date registrate nell'AD1 dallo strumento di acquisizione (UTC)"),
           "disco": N_("UTC (dal file system del CD/DVD, ISO 9660 o UDF, che registra lo scostamento)"),
           "disco_locale": N_("ora locale senza fuso (CD/DVD UDF senza scostamento), convertita con il fuso indicato")}
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


# ------------------------------------------------------------------- AD1 (3.0.2, sorgente logica)
# Immagine logica di FTK Imager (AD1 v4, anche in più segmenti .ad1 .ad2 …), letta con dissect.evidence
# (Fox-IT, AGPL-3.0-or-later). Ogni voce si legge dalla sua posizione nell'immagine; gli hash MD5/SHA-1 registrati
# da FTK per ogni file si confrontano con quelli ricalcolati (verifica_ad1). AD1 cifrati (ADCRYPT): non gestiti.

def ad1_segmenti(path):
    p = Path(path)
    segs = [q for q in p.parent.iterdir() if q.stem == p.stem and re.fullmatch(r"\.ad\d+", q.suffix.lower())]
    return sorted(segs, key=lambda q: int(q.suffix[3:])) or [p]


def _ad1_apri(path):
    from dissect.evidence.ad1.ad1 import AD1
    fhs = [open(q, "rb") for q in ad1_segmenti(path)]
    try:
        a = AD1(fhs)
        if a.is_adcrypt():
            raise ValueError(tr("AD1 cifrato (ADCRYPT): non ancora supportato"))
    except Exception:
        for f in fhs:
            f.close()
        raise
    return a, fhs


def ad1_entries(path):
    from dissect.evidence.ad1.ad1 import MetaType, convert_ts
    a, fhs = _ad1_apri(path)

    def t(e, mt):
        m = e.meta.get(mt)
        try:
            return convert_ts(m.data).timestamp() if m else None
        except (ValueError, UnicodeDecodeError):
            return None

    def giro(e, base):
        for c in e.children:
            path = f"{base}/{c.name}" if base else c.name
            isdir = c.is_dir()
            times = {"M": t(c, MetaType.DateModified), "A": t(c, MetaType.DateAccessed), "B": t(c, MetaType.DateCreated)}
            yield {"path": path, "isdir": isdir, "size": 0 if isdir else c.size, "csize": 0 if isdir else c.size,
                   "method": 0, "loc": c.offset, "mode": 0, "times": times, "dos": None, "dsrc": "ad1",
                   "md5": None if isdir else c.md5, "sha1": None if isdir else c.sha1}
            if isdir:
                yield from giro(c, path)

    try:
        yield from giro(a.root, "")
    finally:
        for f in fhs:
            f.close()


class AD1SenzaDati(ValueError):
    """(3.0.2) Voce dell'AD1 che FTK ha registrato (nome, dimensione, date, a volte hash) senza metterne i dati: nella voce
    dimensione dei dati 0 e nessun indice dei blocchi. Succede per esempio con file cancellati di un FAT e con i file FVE2
    di BitLocker. dissect.evidence andava a leggere l'indice all'offset 0 e falliva con «total struct size too long»."""
    motivo = "senza_dati"


def ad1_open(path, loc, chunk=1 << 20):
    from dissect.evidence.ad1.ad1 import FileEntry
    a, fhs = _ad1_apri(path)          # una lettura alla volta: l'immagine si riapre (le letture non sono concorrenti)
    try:
        fe = FileEntry(a, int(loc))
        if not fe.entry.size and not fe.entry.zlib_meta:
            if fe.size:
                raise AD1SenzaDati(tr("contenuto non presente nell'AD1: FTK ha registrato il file ({n} byte) senza i dati").format(
                    n=fe.size))
            return                                  # file vuoto: niente da leggere
        fs = fe.open()
        while b := fs.read(chunk):
            yield b
    finally:
        for f in fhs:
            f.close()


def verifica_ad1(case, part, say=print):
    """MD5 e SHA-1 di ogni file ricalcolati e confrontati con quelli registrati da FTK nell'AD1."""
    import forense_agent as fa
    m = mx(case)
    righe = m.execute("SELECT h.id, h.md5, h.sha1, f.path FROM logica_hash h JOIN mobile_files f ON f.id = h.id "
                      "WHERE f.part=? ORDER BY h.id", (int(part),)).fetchall()
    m.close()
    res = {"controllati": 0, "uguali": 0, "diversi": [], "illeggibili": [], "senza_dati": [], "ts": fa.now()}
    say(tr("Verifica degli hash registrati nell'AD1: {n} file…").format(n=len(righe)))
    fa.avanz("hashad1")
    for i, (nid, md5, sha1, path) in enumerate(righe, 1):
        hm, hs = hashlib.md5(), hashlib.sha1()
        try:
            for b in stream(case, part, nid):
                hm.update(b)
                hs.update(b)
        except AD1SenzaDati:                # (3.0.2) registrato da FTK senza dati: niente da verificare, non è un errore
            res["senza_dati"].append(path)
            continue
        except Exception as e:
            res["illeggibili"].append({"percorso": path, "errore": f"{type(e).__name__}: {e}"})
            continue
        res["controllati"] += 1
        ok = (not md5 or hm.hexdigest() == md5.lower()) and (not sha1 or hs.hexdigest() == sha1.lower())
        if ok:
            res["uguali"] += 1
        else:
            res["diversi"].append({"percorso": path, "md5_ad1": md5, "md5": hm.hexdigest(), "sha1_ad1": sha1,
                                   "sha1": hs.hexdigest()})
        if i % 500 == 0:
            fa.avanz(fatti=i, totale=len(righe))
    res["n_senza_dati"] = len(res["senza_dati"])
    res["diversi"], res["illeggibili"], res["senza_dati"] = res["diversi"][:200], res["illeggibili"][:200], res["senza_dati"][:200]
    return res


# ------------------------------------------------------------- 7z e rar (3.0.2, sorgente logica)
# Gli archivi 7z e rar (spesso «solid») non si leggono voce per voce: 7-Zip li estrae una volta in una COPIA DERIVATA
# nella cartella del caso (estratta/), con SHA-256 dell'archivio e riferimento, come la copia decompressa dei tar.gz.
# Date ed elenco vengono dall'archivio (7z l -slt), non dai file estratti.

def _data_7z(s, locale, tz, scarto=0):
    m = re.match(r"(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)(?:\.(\d{1,6}))?", (s or "").strip())
    if not m:
        return None
    try:
        d = dt.datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    d = d.replace(microsecond=int((m.group(3) or "0").ljust(6, "0")))
    return _local_to_utc(d, tz) if locale else d.replace(tzinfo=dt.timezone.utc).timestamp() - scarto


def archivio_voci(exe, f, tz):
    """Elenco tecnico del 7z o rar: voci con date (UTC; RAR 4 in ora locale, convertita con tz e dichiarata)."""
    import subprocess
    import forense_agent as fa
    import forense_estesa as fx
    with open(f, "rb") as fh:
        locale = fh.read(7) == b"Rar!\x1a\x07\x00"          # RAR 4: date DOS in ora locale senza fuso
    disco = formato(f) == "iso"
    scarto = 0 if locale else fx.z_scarto()                # Windows: 7-Zip scrive l'ora locale anche con TZ=UTC
    cp = subprocess.run([exe, "l", "-slt", "-ba", fx.NOPASS, str(f)], capture_output=True, timeout=3600,
                        stdin=subprocess.DEVNULL, env=dict(os.environ, TZ="UTC"))
    voci, cur = [], {}
    for line in fa.dec(cp.stdout).splitlines() + [""]:
        if not line.strip():
            if cur.get("Path") is not None:
                voci.append(cur)
            cur = {}
            continue
        k, sep, v = line.partition(" = ")
        if sep:
            cur[k.strip()] = v
    out = []
    for e in voci:
        isdir = e.get("Folder") == "+" or (e.get("Attributes") or "")[:1] == "D"
        try:
            size = int(e.get("Size") or 0)
        except ValueError:
            size = 0
        times = {"M": _data_7z(e.get("Modified"), locale, tz, scarto), "B": _data_7z(e.get("Created"), locale, tz, scarto),
                 "A": _data_7z(e.get("Accessed"), locale, tz, scarto)}
        out.append({"path": e["Path"].replace("\\", "/"), "isdir": isdir, "size": 0 if isdir else size,
                    "csize": size, "method": 0, "loc": 0, "mode": 0, "times": {k: v for k, v in times.items() if v},
                    "dos": None, "dsrc": "locale" if locale else "disco" if disco else "archivio", "cifrato": e.get("Encrypted") == "+",
                    "crc": e.get("CRC") or None})
    return out, cp.returncode, fa.dec(cp.stderr)


def estrai(case, f, tz, say=print):
    """Copia derivata estratta di un 7z, rar o immagine di CD/DVD (estratta/<nome>/, sola lettura) + elenco con le date
    (.voci.json)."""
    import shutil
    import forense_agent as fa
    import forense_estesa as fx
    exe = fx.seven_zip()
    if not exe:
        raise OSError(tr("Per leggere 7z e rar serve 7-Zip (incluso nei pacchetti di RepertIA)."))
    f = Path(f)
    settori = None
    if (cd_dvd(f) or "").endswith("_2352"):           # CD a settori grezzi (BIN/CUE): prima i soli dati, poi 7-Zip
        orig = f
        f, settori = settori_2048(case, orig, say)
    if (cd_dvd(f) or "").startswith("udf") and udf_speciale(f):   # VAT o metadati: 7-Zip non li legge
        return estrai_udf(case, f, tz, say, settori)
    voci, rc, err = archivio_voci(exe, f, tz)
    if not voci:
        if re.search(r"(?i)wrong password|encrypted|can not open encrypted", err or ""):
            raise ValueError(tr("Archivio protetto da password (anche i nomi dei file sono cifrati): non ancora supportato."))
        raise ValueError(tr("7-Zip non riesce a leggere l'archivio: {e}").format(e=(err or "").strip()[-300:]))
    tot = sum(v["size"] for v in voci)
    dest = case.root / "estratta"
    dest.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(dest).free < tot * 1.1 + (2 << 30):
        raise OSError(tr("Spazio insufficiente per la copia estratta: servono circa {v:.1f} GB.").format(v=tot * 1.1 / 1e9))
    out = dest / re.sub(r"[^\w.-]+", "_", f.name)[:120]
    say(tr("Estrazione di {f} in una copia derivata con 7-Zip (l'archivio originale non cambia)…").format(f=f.name))
    fa.avanz("decomp")
    rc, err = fx.z_extract(exe, f, out)
    n_cif = sum(1 for v in voci if v["cifrato"])
    rif = {"origine": str(f), "sha256_origine": fa.sha256_file(f), "operazione": "7-Zip x",
           "strumento": fa.tool_version([exe]) or "7-Zip", "voci": len(voci), "byte": tot, "cifrate": n_cif,
           "esito_7zip": rc, "creata": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    if settori:
        rif.update({"origine": settori["origine"], "sha256_origine": settori["sha256_origine"], "settori_2048": settori,
                    "copia_intermedia": str(f)})
    for base, dirs, files in os.walk(out):            # sola lettura, come le altre copie derivate
        for nm in files:
            try:
                os.chmod(os.path.join(base, nm), 0o444)
            except OSError:
                pass
    Path(str(out) + ".json").write_text(json.dumps(rif, indent=1), encoding="utf-8")
    Path(str(out) + ".voci.json").write_text(json.dumps(voci, ensure_ascii=False), encoding="utf-8")
    if rc not in (0, 1):
        say(tr("ATTENZIONE: 7-Zip ha segnalato errori ({rc}); i file non estratti risulteranno illeggibili.").format(rc=rc))
    return out, rif


def udf_speciale(f):
    """(3.0.2) UDF con partizione virtuale (VAT, CD-R/DVD-R di Windows «come una chiavetta») o di metadati (UDF 2.50+):
    si legge col lettore di RepertIA (forense_udf) invece che con 7-Zip."""
    import forense_udf as fu
    try:
        u = fu.UDF(f)
    except Exception:
        return False
    try:
        return any(m["tipo"] in ("virtuale", "metadati") for m in u.mappe)
    finally:
        u.close()


def estrai_udf(case, f, tz, say=print, settori=None):
    """(3.0.2) Copia derivata dei file di un CD/DVD UDF letto con forense_udf: lo stato attivo del disco più i file che
    compaiono solo nelle VAT precedenti (cancellati, rinominati o sostituiti), in una cartella a parte e segnati come
    cancellati, ciascuno col percorso dell'ultima VAT che lo elenca; i nomi precedenti restano nel .voci.json."""
    import shutil
    import forense_agent as fa
    import forense_udf as fu
    f = Path(f)
    u = fu.UDF(f)
    try:
        gens = u.generazioni()
        att_g, attive = gens[-1]
        chiavi_att = {v["pos"] for v in attive if v["fe"] and not v["cancellato"]}
        prec_lbl = tr("[file solo nelle VAT precedenti]")
        canc_lbl = tr("[voci cancellate]")
        scelte, nomi = {}, {}
        for i, (g, voci) in enumerate(gens):
            for v in voci:
                if not v["fe"]:
                    continue
                k = v["pos"]
                nomi.setdefault(k, [])
                if v["percorso"] not in nomi[k]:
                    nomi[k].append(v["percorso"])
                if i == len(gens) - 1:
                    scelte[k] = (v, g, canc_lbl if v["cancellato"] else None)
                elif k not in chiavi_att:
                    scelte[k] = (v, g, prec_lbl)     # vince l'ultima VAT precedente che lo elenca
        tot = sum(v["fe"]["size"] for v, _g, _l in scelte.values() if not v["cartella"])
        dest = case.root / "estratta"
        dest.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(dest).free < tot * 1.1 + (2 << 30):
            raise OSError(tr("Spazio insufficiente per la copia estratta: servono circa {v:.1f} GB.").format(v=tot * 1.1 / 1e9))
        nome0 = Path(settori["origine"]).name if settori else f.name      # non la copia intermedia a 2048 byte
        out = dest / re.sub(r"[^\w.-]+", "_", nome0)[:120]
        say(tr("Lettura del CD/DVD UDF con il lettore di RepertIA ({n} VAT trovate) e copia derivata dei file…").format(
            n=len(u.vat_gen)))
        fa.avanz("decomp")
        voci_out, n_prec = [], 0
        for k, (v, g, lbl) in sorted(scelte.items(), key=lambda x: (x[1][2] or "", x[1][0]["percorso"])):
            rel = v["percorso"] if not lbl else f"{lbl}/{v['percorso']}"
            parti = [re.sub(r'[\x00-\x1f<>:"|?*\\]', "_", q) or "_" for q in rel.split("/")]
            rel = "/".join(q for q in parti if q not in (".", ".."))
            fe = v["fe"]
            times, dsrc = {}, "disco_locale" if fe["locale"] else "disco"
            for kk, d in fe["times"].items():
                times[kk] = _local_to_utc(d, tz) if fe["locale"] else d.replace(tzinfo=dt.timezone.utc).timestamp()
            dst = out.joinpath(*rel.split("/"))
            if v["cartella"]:
                dst.mkdir(parents=True, exist_ok=True)
            else:
                dst.parent.mkdir(parents=True, exist_ok=True)
                u.vat = g["tabella"] if g else u.vat
                with open(dst, "wb") as fh:
                    for x in u.pezzi(fe):
                        fh.write(x)
                os.chmod(dst, 0o444)
            if lbl == prec_lbl and not v["cartella"]:
                n_prec += 1
            voci_out.append({"path": rel, "isdir": v["cartella"], "size": 0 if v["cartella"] else fe["size"],
                             "csize": fe["size"], "method": 0, "loc": 0, "mode": 0,
                             "times": {kk: x for kk, x in times.items() if x}, "dos": None, "dsrc": dsrc, "cifrato": False,
                             "crc": None, "cancellato": bool(lbl), "nomi": nomi.get(k, []),
                             "vat": g["modifica"].strftime("%Y-%m-%dT%H:%M:%S") if g and g.get("modifica") else None})
        u.vat = att_g["tabella"] if att_g else u.vat
        vat = [{"settore": g["settore"], "modifica_utc": g["modifica"].strftime("%Y-%m-%dT%H:%M:%S") if g.get("modifica") else None,
                "file": g["file"], "cartelle": g["cartelle"], "voci_elencate": len(vv)} for g, vv in gens if g]
        rif = {"origine": str(settori["origine"] if settori else f),
               "sha256_origine": settori["sha256_origine"] if settori else fa.sha256_file(f),
               "operazione": tr("lettura UDF con forense_udf (RepertIA)"), "strumento": "forense_udf (RepertIA)",
               "volume": u.nome, "mappe": [m["tipo"] for m in u.mappe], "vat": vat, "avvisi": u.avvisi,
               "voci": len(voci_out), "byte": tot, "cifrate": 0, "solo_vat_precedenti": n_prec, "cartella_vat": prec_lbl,
               "esito_7zip": None, "creata": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
        if settori:
            rif.update({"settori_2048": settori, "copia_intermedia": str(f)})
    finally:
        u.close()
    Path(str(out) + ".json").write_text(json.dumps(rif, indent=1, ensure_ascii=False), encoding="utf-8")
    Path(str(out) + ".voci.json").write_text(json.dumps(voci_out, ensure_ascii=False), encoding="utf-8")
    say(tr("CD/DVD UDF «{nome}»: {n} voci, {p} solo nelle VAT precedenti (cancellate, rinominate o sostituite), {g} VAT.").format(
        nome=rif["volume"], n=len(voci_out), p=n_prec, g=len(vat)))
    return out, rif


# ------------------------------------------------------------------------------- riconoscimento

def formato(path):
    """'zip', 'tar', 'targz' (da decomprimere), 'cartella', '7z', 'rar', 'ad1', 'iso' (questi solo come sorgente logica)
    oppure None, guardando il contenuto (non il nome)."""
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
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:7] == b"Rar!\x1a\x07\x00" or head[:8] == b"Rar!\x1a\x07\x01\x00":
        return "rar"
    if head[:16] == b"ADSEGMENTEDFILE\x00" or head[:8] == b"ADCRYPT\x00":
        return "ad1"
    if cd_dvd(p):
        return "iso"
    return None


def cd_dvd(path):
    """(3.0.2) Immagine di CD/DVD: descrittori di volume ISO 9660 («CD001») o UDF («BEA01», «NSR02», «NSR03») dal settore
    16. -> 'udf', 'iso9660', con «_2352» se i settori sono grezzi da 2352 byte (BIN/CUE, «RAW ISO» di FTK Imager: sincronismo,
    intestazione e correzione d'errore attorno ai 2048 byte di dati), altrimenti None. Sleuth Kit non legge UDF (NIST Data
    Leakage, CD-R RM#3); 7-Zip sì, ma solo a settori da 2048 byte."""
    try:
        with open(path, "rb") as fh:
            fh.seek(16 * 2048)
            area = fh.read(2048 * 16)
            fh.seek(0)
            grezzo = fh.read(2352 * 32)
    except OSError:
        return None

    def tipo(ids):
        return "udf" if ids & {b"BEA01", b"NSR02", b"NSR03"} else "iso9660" if b"CD001" in ids else None
    t = tipo({area[i + 1:i + 6] for i in range(0, len(area) - 6, 2048)})
    if t:
        return t
    if grezzo[:12] == CD_SYNC:
        ids = set()
        for n in range(16, 32):
            b = grezzo[n * 2352:(n + 1) * 2352]
            o = 16 if b[15:16] == b"\x01" else 24          # mode 1: dati dal byte 16; mode 2 form 1: dal byte 24
            ids.add(b[o + 1:o + 6])
        t = tipo(ids)
        return t + "_2352" if t else None
    return None


CD_SYNC = b"\x00" + b"\xff" * 10 + b"\x00"


def settori_2048(case, f, say=print):
    """(3.0.2) Copia derivata a settori da 2048 byte di un'immagine di CD a settori grezzi da 2352 (solo i dati di ogni
    settore, come bchunk): serve a 7-Zip. SHA-256 e riferimento all'originale, che non cambia; settori anomali contati."""
    import forense_agent as fa
    dest = case.root / "estratta"
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / (re.sub(r"[^\w.-]+", "_", Path(f).stem)[:100] + ".settori_2048.iso")
    say(tr("Immagine di CD a settori grezzi da 2352 byte: copia derivata a settori da 2048 byte (solo i dati)…"))
    cont = {"settori": 0, "mode1": 0, "mode2_form1": 0, "mode2_form2": 0, "senza_sincronismo": 0, "vuoti": 0}
    # MD5 e SHA-1 dei dati a 2048 byte: sono quelli che gli acquisitori (FTK Imager…) e NIST pubblicano per i CD
    h_md5, h_sha1 = hashlib.md5(), hashlib.sha1()
    with open(f, "rb") as src, open(out, "wb") as dst:
        while True:
            b = src.read(2352 * 512)
            if not b:
                break
            buf = bytearray()
            for i in range(0, len(b) - 2351, 2352):
                x = b[i:i + 2352]
                cont["settori"] += 1
                if x[:12] != CD_SYNC:
                    if not any(x):                     # settore non scritto (zeri): dati vuoti, niente da segnalare
                        cont["vuoti"] += 1
                        buf += bytes(2048)
                        continue
                    cont["senza_sincronismo"] += 1
                if x[15] == 1:
                    cont["mode1"] += 1
                    buf += x[16:16 + 2048]
                else:
                    cont["mode2_form2" if x[18] & 0x20 else "mode2_form1"] += 1
                    buf += x[24:24 + 2048]
            dst.write(buf)
            h_md5.update(buf)
            h_sha1.update(buf)
    os.chmod(out, 0o444)
    rif = {"origine": str(f), "sha256_origine": fa.sha256_file(Path(f)), "operazione": tr("settori da 2352 a 2048 byte"),
           "sha256": fa.sha256_file(out), "md5": h_md5.hexdigest(), "sha1": h_sha1.hexdigest(), **cont}
    Path(str(out) + ".json").write_text(json.dumps(rif, indent=1), encoding="utf-8")
    if cont["mode2_form2"] or cont["senza_sincronismo"]:
        say(tr("ATTENZIONE: {a} settori Mode 2 Form 2 e {b} senza sincronismo: i loro dati potrebbero non essere completi.").format(
            a=cont["mode2_form2"], b=cont["senza_sincronismo"]))
    return out, rif


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
            mob = p["mobile"]
            # (3.0) casi collegati con la 2.21: «Collega copia forense» non aggiornava questo percorso
            img = case.meta.get("image")
            if not os.path.exists(mob.get("file") or "") and img and os.path.exists(img) and len(sorgenti(case)) == 1:
                return {**mob, "file": img}
            return mob
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
    if kind == "estratto":            # (3.0.2) 7z/rar: elenco e date dall'archivio, file dalla copia estratta
        gen = json.loads(Path(str(img) + ".voci.json").read_text(encoding="utf-8"))
    else:
        gen = (zip_entries(img) if kind == "zip" else tar_entries(img) if kind == "tar" else
               ad1_entries(img) if kind == "ad1" else dir_entries(img))
    mf, files, evs, hs = [], [], [], []
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
            dsrc = e.get("dsrc") or ("copia" if kind == "cartella" else "utc")
        if e.get("md5") or e.get("sha1"):
            hs.append((nid, e.get("md5"), e.get("sha1")))
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
        files.append((int(part), str(nid), 1 if e.get("cancellato") else 0, typ, path))
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
    w.executemany("INSERT INTO logica_hash VALUES (?,?,?)", hs)
    con.executemany(fa.INSERT_FILE, files)
    con.executemany(fa.INSERT_EV, evs)
    nev += len(evs)
    stats["hash_registrati"] = len(hs)
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
    elif r["kind"] == "ad1":
        yield from ad1_open(img, r["loc"], chunk)
    else:
        p = os.path.join(img, *r["path"].split("/"))
        if r["kind"] == "estratto" and not os.path.realpath(p).startswith(os.path.realpath(img) + os.sep):
            raise FileNotFoundError(tr("percorso fuori dalla copia estratta: {p}").format(p=r["path"]))
        if r["datesrc"] == "mft" and not r["size"] and not os.path.exists(p):
            return                        # (3.0.4) dump della RAM: del file c'è solo il record MFT, senza contenuto
        with open(p, "rb") as fh:
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


IOS_CONT_RE = re.compile(r"^(.*?/[Cc]ontainers/(?:Shared/AppGroup|Data/Application|Bundle/Application|Data/PluginKitPlugin)/"
                         r"[0-9A-Fa-f-]{36})/")
IOS_META = ".com.apple.mobile_container_manager.metadata.plist"
_contenitori = {}


def contenitore_ios(case, part, path):
    """(3.0.1) Identificativo dell'app o del gruppo di un contenitore iOS (…/Containers/Shared/AppGroup/<UUID>/…,
    Data/Application, Bundle/Application), letto da MCMMetadataIdentifier nel file di metadati del contenitore;
    None se il percorso non è in un contenitore o il file manca. Un valore per contenitore, ricordato."""
    import plistlib
    m = IOS_CONT_RE.match(path or "")
    if not m:
        return None
    k = (str(case.root), int(part), m.group(1))
    if k not in _contenitori:
        val = None
        con = mx(case)
        try:
            r = con.execute("SELECT id FROM mobile_files WHERE part=? AND path=? AND isdir=0",
                            (int(part), m.group(1) + "/" + IOS_META)).fetchone()
        finally:
            con.close()
        if r:
            try:
                d = plistlib.loads(b"".join(stream(case, part, r[0])))
                val = str(d.get("MCMMetadataIdentifier") or "") or None
            except Exception:
                val = None
        _contenitori[k] = val
    return _contenitori[k]


def istat_text(case, part, inode):
    """Scheda Metadati di un file dell'estrazione (equivalente di istat per i dischi)."""
    src = _sorgente(case, part)
    r = _row(case, part, inode)
    mode = r["mode"] or 0
    L = [tr("Voce dell'estrazione: {inode}").format(inode=inode),
         tr("Estrazione: {file} ({fmt})").format(file=src["file"], fmt=tr(FORMATI["ram"]) if r["datesrc"] in (
             "memoria", "mft", "mft_res") else tr(FORMATI.get(r["kind"], r["kind"]))),
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
    elif r["kind"] == "ad1":
        L.append(tr("Posizione nell'AD1: voce al byte {loc} dei dati logici").format(loc=r["loc"]))
    elif r["datesrc"] in ("memoria", "mft", "mft_res"):      # (3.0.4) dump della RAM
        L.append(tr("Dimensione registrata (cache di Windows o record MFT): {cs} byte; contenuto disponibile: {size} byte").format(
            cs=r["csize"], size=r["size"]))
        L.append(tr("Del file in memoria c'è solo il record MFT (nome, date, dimensione): il contenuto non è recuperabile dal dump.")
                 if r["datesrc"] == "mft" else
                 tr("Contenuto letto dal record MFT (file piccolo, salvato dentro il record).") if r["datesrc"] == "mft_res" else
                 tr("Contenuto letto dalla memoria con MemProcFS: può essere incompleto (parti mancanti o a zero)."))
        if r["size"]:
            L.append(tr("Copia derivata: {p}").format(p=os.path.join(src["file"], *r["path"].split("/"))))
    elif r["kind"] == "estratto":
        L.append(tr("Letto dalla copia estratta con 7-Zip: {p}").format(p=os.path.join(src["file"], *r["path"].split("/"))))
    m = mx(case)
    try:
        h = m.execute("SELECT md5, sha1 FROM logica_hash WHERE id=?", (int(inode),)).fetchone()
    except Exception:
        h = None
    finally:
        m.close()
    if h:
        L.append(tr("Hash registrati dallo strumento di acquisizione: MD5 {md5}, SHA-1 {sha1}").format(
            md5=h[0] or "-", sha1=h[1] or "-"))
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
    ram = bool(getattr(args, "ram", False))      # (3.0.4) dump della RAM: sorgente logica dei file ancora in memoria
    kind = "ram" if ram else formato(img)
    logica = bool(getattr(args, "logica", False))
    if kind is None:
        sys.exit(tr("Formato non riconosciuto: servono zip, tar, tar.gz, 7z, rar, AD1, un'immagine di CD/DVD o una cartella.") if logica else
                 tr("Formato non riconosciuto: servono uno zip, un tar (anche .tar.gz) o una cartella con "
                    "l'estrazione del file system del telefono."))
    if kind in LOGICI and not logica:
        sys.exit(tr("7z, rar, AD1 e immagini di CD/DVD si aprono come «Sorgente logica» (nella Home), non come estrazione di un telefono."))
    kind0 = kind
    case.root.mkdir(parents=True, exist_ok=True)
    case.export_dir.mkdir(exist_ok=True)
    lingua = lg.imposta(getattr(args, "lingua", None) or lg.lingua())
    case.meta = {"created": fa.now(), "tipo_caso": TIPO_CASO, "image": str(img), "evidence": str(img),
                 "tool_versions": {}, "lingua": lingua}
    if getattr(args, "drone", False):       # (3.0) si legge come un'estrazione; le chat e iLEAPP/ALEAPP sull'insieme non servono
        case.meta["drone"] = True
    if logica:                              # (3.0.2) archivio, AD1 o cartella di file: niente analisi del telefono
        case.meta["logica"] = True
    if ram:
        case.meta["ram_dump"] = True
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
            # AD1: l'hash complessivo di FTK non è quello dei file .ad1; si verificano gli hash dei singoli file
            fa.hash_evidence(case, dati=kind != "ad1")
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
    elif kind == "ram":                     # (3.0.4) i file ancora in memoria, copiati nel caso da MemProcFS
        import forense_ram as fr
        try:
            work, rif = fr.estrai(case, img, lambda x: print(x, flush=True))
        except (OSError, fr.RamNonDisponibile) as e:
            fr.chiudi()
            sys.exit(str(e))
        case.meta["estratta"] = rif
        case.meta["image"] = str(work)
        case.log("copia_derivata_file_in_memoria", rif)
        kind = "estratto"
    elif kind in ESTRATTI:
        work, rif = estrai(case, img, case.meta["fuso_dispositivo"]["tz"], lambda x: print(x, flush=True))
        case.meta["estratta"] = rif
        case.meta["image"] = str(work)
        case.log("copia_derivata_estratta", rif)
        kind = "estratto"
    part = part_key(0)
    case.meta["partitions"] = [{"offset": part, "readable": True, "fs": (tr("Sorgente logica ({fmt})") if logica else
        tr("Estrazione ({fmt})")).format(fmt=tr(FORMATI[kind0 if logica else kind])), "desc": img.name, "length_sectors": 0,
        "mobile": {"file": str(work), "formato": kind, "nome": img.name, "formato_originale": kind0}}]
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
    # (3.0.2) cancellate: solo le voci dei CD/DVD UDF presenti nelle VAT precedenti o segnate cancellate
    p["files"], p["deleted"] = n, con.execute("SELECT count(*) FROM files WHERE part=? AND deleted=1", (int(part),)).fetchone()[0]
    if logica:
        _prepara_logica(case, args, con, part, p, n, nev, stats, kind0)
        return
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
    case.meta["disk_type"] = (tr("scheda o cartella di un drone") if case.meta.get("drone") else
                              tr("estrazione di uno smartphone {os}").format(os=p["os"]) if p["os"] else
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
    if case.meta.get("drone"):
        import forense_droni as fdr
        fdr.run(case, lambda x: print(x, flush=True))
    if getattr(args, "chat", True) and not case.meta.get("drone"):
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


def _prepara_logica(case, args, con, part, p, n, nev, stats, kind0):
    """(3.0.2) Seguito della preparazione per una sorgente logica (archivio, AD1, cartella di file): niente
    riconoscimento del telefono, chat, iLEAPP/ALEAPP; per l'AD1 la verifica degli hash registrati da FTK."""
    import forense_agent as fa
    p["os"] = None
    p["mobile"].update({"statistiche": stats})
    case.meta["mobile"] = {"formato": p["mobile"]["formato"], "logica": True}
    case.meta["disk_type"] = (tr("dump della memoria RAM") if case.meta.get("ram_dump") else
                              tr("sorgente logica ({fmt})").format(fmt=tr(FORMATI[kind0])))
    fd = case.meta["fuso_dispositivo"]
    fd["stato"] = "non_verificabile" if fd.get("auto") else "scelto_non_verificato"
    case.meta["timeline"] = {"tsk_events": nev, "plaso_events": 0}
    case.log("sorgente_logica_indicizzata", {"voci": n, "eventi": nev, "formato": kind0, "statistiche": stats})
    for k, msg in (("dos", N_("ATTENZIONE: {n} voci dello zip hanno solo la data DOS (ora locale senza fuso): convertite "
                              "con il fuso {tz}.")),
                   ("locale", N_("ATTENZIONE: {n} voci del RAR 4 hanno date in ora locale senza fuso: convertite con il "
                                 "fuso {tz}."))):
        if stats["date"].get(k):
            print(tr(msg).format(n=stats["date"][k], tz=fd["tz"]), flush=True)
    case.save()
    print(tr("Sorgente logica {fmt}: {n} voci, {nev} eventi.").format(fmt=tr(FORMATI[kind0]), n=n, nev=nev), flush=True)
    if case.meta.get("ram_dump"):          # (3.0.4) processi, rete, timeline e fuso letti dalla memoria
        import forense_ram as fr
        fr.dopo_elenco(case, con, lambda x: print(x, flush=True))
    if kind0 == "ad1" and stats.get("hash_registrati"):
        if args.no_hash:
            print(tr("Verifica degli hash dell'AD1 rinviata (analisi speditiva)."), flush=True)
        else:
            v = verifica_ad1(case, part, lambda x: print(x, flush=True))
            case.meta["verifica_ad1"] = v
            case.log("verifica_hash_ad1", {k: v[k] for k in ("controllati", "uguali", "diversi", "illeggibili", "n_senza_dati")})
            case.save()
            print(tr("Hash dei file nell'AD1: {u} uguali su {c} controllati, {d} diversi, {i} illeggibili.").format(
                u=v["uguali"], c=v["controllati"], d=len(v["diversi"]), i=len(v["illeggibili"])), flush=True)
            if v["n_senza_dati"]:
                print(tr("File registrati da FTK senza i dati (contenuto non presente nell'AD1): {n}.").format(n=v["n_senza_dati"]),
                      flush=True)
    tel = riconosci_telefono(case, part)
    if tel["database"]:
        print(tr("Database di telefoni trovati: {d}{p}.").format(
            d=", ".join(f"{tr(DB_LBL.get(k, k))} ({v})" for k, v in sorted(tel["database"].items())),
            p=(" — " + tr("piattaforma {p}").format(p=tel["piattaforma"])) if tel["piattaforma"] else ""), flush=True)
        if getattr(args, "chat", True):
            try:
                import forense_mobile_chat as fmc
                fa.avanz("chat")
                fmc.run(case, con)
            except Exception as e:
                print(tr("Chat: non completate ({vname}: {e})").format(vname=type(e).__name__, e=e), flush=True)
    try:
        import forense_mappe as fmp
        fmp.livelli_dalla_sorgente(case, lambda x: print(x, flush=True))
    except Exception as e:
        print(tr("Mappa: KML/GPX della sorgente non letti ({vname}: {e})").format(vname=type(e).__name__, e=e), flush=True)
    if not args.no_indice:
        fa.run_addon(case, con, "indice")
    if args.hash_file:
        fa.run_addon(case, con, "hash")
    if getattr(args, "trascrizione", None):
        import forense_trascrizione as ftr
        ftr.da_preparazione(case, con, args.trascrizione)
    con.close()
    case.save()
    print(tr("Pronto."))


def riconosci_telefono(case, part):
    """(3.0.2) Sorgente logica: database noti di telefoni (per nome del file) e piattaforma che ne segue. La piattaforma
    serve a «Chat e rubriche» e a iLEAPP/ALEAPP, che per una sorgente logica si avviano come analisi aggiuntive."""
    import forense_mobile_chat as fmc
    m = mx(case)
    try:
        found, cifrati = fmc.trova_db(m, int(part), logica=True)
        sample = [r[0] for r in m.execute("SELECT path FROM mobile_files WHERE part=? LIMIT 200000", (int(part),))]
    finally:
        m.close()
    voti = {}
    for k, xs in found.items():
        voti[fmc.DB_PIATTAFORMA[k]] = voti.get(fmc.DB_PIATTAFORMA[k], 0) + len(xs)
    strutt = piattaforma(sample)
    plat = strutt or (max(voti, key=voti.get) if voti else None)
    tel = {"piattaforma": plat, "database": {k: len(v) for k, v in found.items()}, "cifrati": len(cifrati),
           "struttura_telefono": bool(strutt)}
    case.meta["logica_telefono"] = tel
    if plat:
        case.meta["mobile"]["piattaforma"] = plat
        case.meta["partitions"][0]["mobile"]["piattaforma"] = plat
    case.log("logica_database_telefono", tel)
    case.save()
    return tel


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
    p.add_argument("--drone", action="store_true", help=tr("scheda o cartella di un drone: cerca i registri di volo"))
    p.add_argument("--logica", action="store_true",
                   help=tr("sorgente logica: archivio (zip, tar, tar.gz, 7z, rar), immagine AD1, immagine di CD/DVD (ISO 9660 o UDF) o cartella di file"))
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
