#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""
forense_estesa.py - Analisi estese di RepertIA (By silvexe).

Completano l'analisi del file system con il contenuto che TSK da solo non mostra:
  archivi   ZIP, RAR, 7z, tar, gz, cab, iso... (7-Zip) e posta elettronica (PST/OST con
            libpff, mbox, EML, EMLX, MSG): elenco, testo ricercabile, hash, allegati
  anomalie  estensione che non corrisponde al contenuto, file protetti da password,
            possibili contenitori cifrati, volumi cifrati (BitLocker, LUKS, FileVault)
  artefatti registro di Windows (sistema, utenti, USB, programmi, reti), prefetch, Amcache,
            collegamenti e jump list, cestino, cronologia web; macOS e Linux essenziali
  vss       copie shadow di Windows: file cancellati o versioni precedenti
  ocr       testo dentro immagini e PDF scansionati (Tesseract)

Tutto si legge dalla copia in sola lettura; i file estratti vanno in <caso>/estratti/ in
sola lettura, con MD5, SHA-1 e SHA-256, e ogni operazione è registrata in audit_log.jsonl.
"""
import datetime as dt
import email
import email.policy
import email.utils
import hashlib
import html
import io
import json
import mailbox
import math
import os
import plistlib
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tarfile
import time
import zipfile
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
import base64
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import forense_agent as fa  # noqa: E402
import forense_apfs as ap  # noqa: E402
from forense_lingua import tr, N_  # noqa: E402

ADDONS_EXT = {
    "archivi": N_("archivi e posta elettronica"),
    "anomalie": N_("estensioni false, file e volumi cifrati"),
    "artefatti": N_("artefatti di sistema e cronologia web"),
    "vss": N_("copie shadow di Windows e snapshot APFS"),
    "ocr": N_("testo nelle immagini (OCR)"),
    "phash": N_("hash percettivi delle immagini (immagini simili)"),
    "trascrizione": N_("trascrizione automatica degli audio"),
}
# moduli Python (inclusi nei pacchetti di RepertIA) necessari a ciascuna analisi
NEEDS = {"archivi": ("pypff",), "artefatti": ("pyregf", "pyscca", "pylnk", "pyolecf"),
         "vss": ("pyvshadow", "pytsk3"), "anomalie": (), "ocr": (), "phash": ("PIL",),
         "trascrizione": ()}

SCHEMA = """
CREATE TABLE IF NOT EXISTS xitems(id INTEGER PRIMARY KEY, kind TEXT, part INTEGER, inode TEXT,
    src_path TEXT, parent INTEGER, mail INTEGER, inner TEXT, path TEXT, name TEXT, size INTEGER,
    mtime TEXT, encrypted INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0, relpath TEXT, md5 TEXT,
    sha1 TEXT, sha256 TEXT, note TEXT, store TEXT);
CREATE INDEX IF NOT EXISTS idx_x_kind ON xitems(kind);
CREATE INDEX IF NOT EXISTS idx_x_mail ON xitems(mail);
CREATE INDEX IF NOT EXISTS idx_x_sha ON xitems(sha256);
CREATE TABLE IF NOT EXISTS mail(id INTEGER PRIMARY KEY, part INTEGER, inode TEXT, src_path TEXT,
    xid INTEGER, fmt TEXT, folder TEXT, sender TEXT, recipients TEXT, cc TEXT, subject TEXT,
    date TEXT, body TEXT, html TEXT, n_att INTEGER, headers TEXT);
CREATE INDEX IF NOT EXISTS idx_mail_date ON mail(date);
CREATE TABLE IF NOT EXISTS anomalies(id INTEGER PRIMARY KEY, kind TEXT, source TEXT, part INTEGER,
    inode TEXT, path TEXT, detail TEXT, ext TEXT, real TEXT, size INTEGER, deleted INTEGER,
    sev INTEGER);
CREATE INDEX IF NOT EXISTS idx_anom_kind ON anomalies(kind);
CREATE TABLE IF NOT EXISTS artifacts(id INTEGER PRIMARY KEY, cat TEXT, ts TEXT, title TEXT,
    detail TEXT, user TEXT, src_path TEXT, part INTEGER, inode TEXT, data TEXT);
CREATE INDEX IF NOT EXISTS idx_art_cat ON artifacts(cat, ts);
CREATE TABLE IF NOT EXISTS known(source TEXT, part INTEGER, inode TEXT, path TEXT, kind TEXT,
    list TEXT, hash TEXT);
CREATE INDEX IF NOT EXISTS idx_known ON known(part, inode);
"""

ART_CATS = {"sistema": N_("Sistema"), "utenti": N_("Account utente"), "usb": N_("Dispositivi USB"),
            "programmi": N_("Programmi installati"), "esecuzioni": N_("Programmi eseguiti"),
            "recenti": N_("File e cartelle recenti"), "reti": N_("Reti"), "cestino": N_("Cestino"),
            "web": N_("Cronologia web"), "download": N_("Download"), "ricerche": N_("Ricerche"),
            "comandi": N_("Comandi (shell)"), "messaggi": N_("Messaggi (iMessage/SMS)"), "avvio": N_("Avvio automatico"),
            "permessi": N_("Permessi alle app (TCC)"), "uso": N_("Uso delle app"), "dispositivi": N_("Dispositivi e volumi"),
            "backup": N_("Backup (Time Machine)"), "cartelle": N_("Cartelle aperte (ShellBags)"),
            "journal": N_("Journal NTFS (creati, cancellati, rinominati)"), "eventi": N_("Eventi di sistema"),
            "leapp": N_("Artefatti iLEAPP/ALEAPP (smartphone)"), "chiamate": N_("Chiamate (smartphone)"),
            "cloud": N_("Servizi cloud (Google Drive)"), "indice": N_("Indice di Ricerca di Windows"),
            "note": N_("Note (Sticky Notes)"),
            # (3.0.4) dump della memoria RAM (forense_ram.py)
            "processi": N_("Processi (RAM)"), "connessioni": N_("Connessioni di rete (RAM)"),
            "moduli": N_("Moduli caricati (RAM)"), "driver": N_("Driver (RAM)"),
            "attivita": N_("Attività pianificate (RAM)"), "servizi": N_("Servizi (RAM)")}
ANOM_KINDS = {"volume": N_("Volume cifrato"), "estensione": N_("Estensione falsa"),
              "cifrato": N_("File protetto da password"), "contenitore": N_("Possibile contenitore cifrato"),
              "segnalato": N_("Hash in lista da segnalare")}

ARCH_EXT = {".zip", ".zipx", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".tbz", ".tbz2",
            ".xz", ".txz", ".cab", ".iso", ".lzh", ".lha", ".arj", ".wim", ".z", ".lzma",
            ".zst", ".cpio", ".rpm", ".deb", ".apk", ".jar", ".dmg", ".img.gz"}
MAIL_EXT = {".pst", ".ost", ".mbox", ".mbx", ".eml", ".emlx", ".msg"}
X_ROOT = "estratti"
ENTRY_MAX = 500 << 20          # singolo file estratto
ARCHIVE_MAX = 8 << 30          # contenuto complessivo di un archivio
TOTAL_MAX = 40 << 30           # tutto ciò che viene estratto in una passata
DEPTH_MAX = 4                  # archivi dentro archivi
NOPASS = "-prepertia-senza-password"


# ------------------------------------------------------------------ comuni

def now():
    return fa.now()


def ensure_schema(con):
    con.executescript(SCHEMA)
    fa.ensure_index_schema(con)


def safe_name(s, n=90):
    s = re.sub(r"[^\w.\- ]+", "_", str(s or "file")).strip(" .") or "file"
    if len(s) > n:
        stem, dot, ext = s.rpartition(".")
        s = (stem[:n - len(ext) - 1] + "." + ext) if dot and len(ext) <= 8 else s[:n]
    return s


def iso(d):
    """datetime (UTC, anche ingenuo) -> 'YYYY-MM-DDTHH:MM:SS', None se assente o assurdo."""
    if d is None:
        return None
    try:
        if d.tzinfo is not None:
            d = d.astimezone(dt.timezone.utc).replace(tzinfo=None)
        if d.year < 1971 or d.year > 2100:
            return None
        return d.strftime("%Y-%m-%dT%H:%M:%S")
    except (ValueError, OverflowError, AttributeError):
        return None


def filetime(n):
    try:
        n = int(n)
        if n <= 0:
            return None
        return iso(dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=n // 10))
    except (ValueError, OverflowError):
        return None


def unixtime(n):
    try:
        n = float(n)
        if n <= 0:
            return None
        return iso(dt.datetime(1970, 1, 1) + dt.timedelta(seconds=n))
    except (ValueError, OverflowError, TypeError):      # (3.0.2) anche None
        return None


def decode_bytes(b):
    if b is None:
        return ""
    if isinstance(b, str):
        return b
    for enc in ("utf-8", "cp1252"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            continue
    return b.decode("latin-1", "replace")


def html_to_text(h):
    h = re.sub(r"(?is)<(script|style|head)\b.*?</\1>", " ", h or "")
    h = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</li>", "\n", h)
    t = html.unescape(re.sub(r"<[^<>]+>", " ", h))
    return re.sub(r"[ \t\r\f\v]+", " ", re.sub(r"\n\s*\n+", "\n\n", t)).strip()


def entropy(data):
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def fs_rows(con, where, args=()):
    return con.execute("SELECT part, inode, deleted, path FROM files WHERE type LIKE '%r' "
                       "AND type NOT LIKE 'v/%' AND " + where, args).fetchall()


def free_space(p):
    try:
        return shutil.disk_usage(p).free
    except OSError:
        return 1 << 60


def togli(f):
    """(3.0.4) Cancella un file temporaneo. Se è ancora aperto lo lascia: su Windows succede quando la lettura di un file
    danneggiato o incompleto (frequente nei dump della RAM) si interrompe a metà, e l'errore della cancellazione faceva
    saltare tutto il passo (collegamenti, jump list, cronologia dei browser). La cartella temporanea si svuota a fine analisi."""
    try:
        Path(f).unlink(missing_ok=True)
    except OSError:
        pass


def copy_fs_file(case, part, inode, dest, limit=None):
    """Copia un file della copia forense (icat, o la copia già in cache) in `dest`.
    None se supera `limit` byte."""
    c = fa.cached_copy(case, part, inode)
    if c:
        if limit and c.stat().st_size > limit:
            return None
        shutil.copyfile(c, dest)
        return dest.stat().st_size
    n = 0
    with open(dest, "wb") as fh:
        gen = fa.icat_stream(case, part, inode)
        try:
            for ch in gen:
                fh.write(ch)
                n += len(ch)
                if limit and n > limit:
                    break
        finally:
            gen.close()
    if limit and n > limit:
        dest.unlink(missing_ok=True)
        return None
    return n


def lp(p):
    """Percorso lungo su Windows (oltre 260 caratteri, archivi con cartelle profonde)."""
    if fa.IS_WIN:
        s = os.path.abspath(str(p))
        return s if s.startswith("\\\\?\\") else "\\\\?\\" + s
    return str(p)


def dentro(base, p):
    """(3.0.1) La voce estratta resta nella cartella dell'archivio: niente «../» né collegamenti che portano fuori.
    Il percorso viene dall'archivio (dato della copia, quindi ostile): senza controllo si leggerebbe e si sposterebbe
    nel caso un file del computer dell'analista."""
    b = os.path.normcase(os.path.abspath(str(base)))
    q = os.path.normcase(os.path.abspath(str(p)))
    if not q.startswith(b + os.sep):
        return False
    try:
        rb = os.path.normcase(os.path.realpath(lp(base)))
        rq = os.path.normcase(os.path.realpath(lp(p)))
    except (OSError, ValueError):
        return False
    return rq.startswith(rb + os.sep) and not os.path.islink(lp(p))


def hashes_of(path):
    with open(path, "rb") as fh:
        n, md5, sha1, sha256 = fa.hash_stream(iter(lambda: fh.read(1 << 20), b""))
    return n, md5, sha1, sha256


def store_extracted(case, src, sub, xid, name):
    """Sposta un file estratto in <caso>/estratti/<sub>/ in sola lettura: percorso relativo."""
    d = case.root / X_ROOT / sub
    d.mkdir(parents=True, exist_ok=True)
    dest = d / f"{xid:07d}_{safe_name(name)}"
    if dest.exists():
        dest.chmod(0o644)
        dest.unlink()
    shutil.move(str(src), dest)
    dest.chmod(0o444)
    return dest.relative_to(case.root).as_posix()


def index_text(con, case, path, data, name, source, part, inode, deleted, tmp):
    """Testo ricercabile di un file estratto (stesse regole dell'indice dei documenti)."""
    ext = Path(name).suffix.lower()
    if ext not in fa.DOC_EXT and ext not in SQLITE_EXT:
        return False
    try:
        r = fa.extract_text(data, name, tmp) if ext not in SQLITE_EXT else sqlite_text_bytes(data, tmp)
    except Exception:
        r = None
    if r and r[1].strip():
        fa.store_text(con, path, r[1], source, part, str(inode), deleted, r[0])
        return True
    return False


SQLITE_EXT = {".sqlite", ".sqlite3", ".db", ".db3", ".sqlitedb"}


def sqlite_text_bytes(data, tmp):
    if not data.startswith(b"SQLite format 3\x00"):
        return None
    f = Path(tmp) / f"sq_{os.getpid()}_{time.time_ns()}.sqlite"
    f.write_bytes(data)
    try:
        return tr("database SQLite"), sqlite_dump(f, 400_000)
    finally:
        togli(f)


def sqlite_dump(path, limit=400_000, rows_per_table=2000):
    """Contenuto testuale di un database SQLite (tabelle e righe), per indice e anteprima."""
    out, n = [], 0
    con = sqlite3.connect(f"file:{Path(path).as_posix()}?mode=ro&immutable=1", uri=True)
    try:
        tabs = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' "
                                          "ORDER BY name")]
        for t in tabs:
            out.append(f"## {t}")
            try:
                cur = con.execute(f'SELECT * FROM "{t}" LIMIT {rows_per_table}')
            except sqlite3.Error:
                continue
            cols = [c[0] for c in cur.description or []]
            out.append(" | ".join(cols))
            for row in cur:
                vals = []
                for v in row:
                    if isinstance(v, bytes):
                        s = v.decode("utf-8", "ignore") if len(v) < 400 else ""
                        vals.append(re.sub(r"[^\x20-\x7e\u00a0-\uffff]", "", s)[:200])
                    elif v is not None:
                        vals.append(str(v)[:500])
                    else:
                        vals.append("")
                line = " | ".join(vals)
                out.append(line)
                n += len(line)
                if n > limit:
                    return "\n".join(out)
    except sqlite3.Error as e:
        out.append(tr("(database non leggibile: {e})").format(e=e))
    finally:
        con.close()
    return "\n".join(out)


class Ctx:
    """Contesto di una passata: limiti, contatori, file temporanei."""
    def __init__(self, case, con, label):
        self.case, self.con, self.label = case, con, label
        self.tmp = case.root / "tmp_estesa"
        fa.rmtree_force(lp(self.tmp))
        self.tmp.mkdir(parents=True)
        self.extracted = 0
        self.t_last = 0
        self.c = Counter()

    def say(self, msg, force=False):
        if force or time.time() - self.t_last > 2:
            self.t_last = time.time()
            print(f"{tr(self.label)}: {msg}", flush=True)

    def close(self):
        try:
            fa.rmtree_force(lp(self.tmp))
        except OSError:              # un file temporaneo ancora aperto: si toglie alla prossima analisi (__init__)
            pass


def new_xitem(con, **kw):
    cols = ("kind", "part", "inode", "src_path", "parent", "mail", "inner", "path", "name", "size",
            "mtime", "encrypted", "deleted", "relpath", "md5", "sha1", "sha256", "note", "store")
    vals = [kw.get(c) for c in cols]
    return con.execute(f"INSERT INTO xitems({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                       vals).lastrowid


def add_anomaly(con, kind, source, part, inode, path, detail, ext="", real="", size=None,
                deleted=0, sev=1):
    con.execute("INSERT INTO anomalies(kind, source, part, inode, path, detail, ext, real, size, "
                "deleted, sev) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (kind, source, part, str(inode) if inode is not None else None, path, detail, ext,
                 real, size, deleted, sev))


# ------------------------------------------------------------------ archivi  → forense_archivi.py (3.0.4)
from forense_archivi import (  # noqa: E402,F401
    seven_zip, LOCALE, zip_dates, z_scarto, z_list, z_extract, py_list_extract, is_archive_name, ARCH_FAM,
    archive_by_content, is_mail_name, process_container, process_archive, origin_source, origin_ref, origin_deleted)


# ------------------------------------------------------------------ posta  → forense_posta.py (3.0.4)
from forense_posta import (  # noqa: E402,F401
    addr_list, add_message, parse_email_bytes, process_eml_file, process_mbox, pff_text, pff_recipients, process_pst,
    process_msg_file, run_archivi)


# ------------------------------------------------------------------ lettura della copia

class ImageFile:
    """La copia forense come file (raw diretto, E01 con pyewf o img_cat)."""
    def __init__(self, path):
        self.path = str(path)
        self.ewf = None
        self.fh = None
        if fa.is_e01(self.path):
            try:
                import pyewf
                h = pyewf.handle()
                h.open(pyewf.glob(self.path))
                self.ewf = h
                self.size = h.get_media_size()
            except Exception:
                self.size = None
        else:
            self.fh = open(self.path, "rb")
            self.size = os.path.getsize(self.path)

    def pread(self, off, n):
        if self.fh:
            self.fh.seek(off)
            return self.fh.read(n)
        if self.ewf:
            self.ewf.seek(off)
            return self.ewf.read(n)
        s, e = off // 512, (off + n - 1) // 512
        cp = subprocess.run(["img_cat", "-s", str(s), "-e", str(e), self.path], capture_output=True,
                            timeout=600, stdin=subprocess.DEVNULL)
        return cp.stdout[off - s * 512:][:n]

    def close(self):
        if self.fh:
            self.fh.close()
        if self.ewf:
            self.ewf.close()


class Region:
    """Porzione della copia (una partizione) come oggetto file per le librerie libyal."""
    def __init__(self, img, start, length):
        self.img, self.start, self.length, self.pos = img, start, length, 0

    def read(self, size=-1):
        if size is None or size < 0:
            size = self.length - self.pos
        size = max(0, min(size, self.length - self.pos))
        b = self.img.pread(self.start + self.pos, size) if size else b""
        self.pos += len(b)
        return b

    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else self.pos + off if whence == 1 else self.length + off
        return self.pos

    def tell(self):
        return self.pos

    def get_offset(self):
        return self.pos

    def get_size(self):
        return self.length


def part_bounds(case, p, img):
    start = (p["apfs"]["real_offset"] if p.get("apfs") else p["offset"]) * 512
    if p.get("length_sectors"):
        length = p["length_sectors"] * 512
    else:
        length = (img.size or 0) - start
    return start, max(0, length)


# ------------------------------------------------------------------ anomalie

# (prefisso, posizione, famiglia, descrizione)
SIGS = [
    (b"\xff\xd8\xff", 0, "jpg", N_("immagine JPEG")), (b"\x89PNG\r\n\x1a\n", 0, "png", N_("immagine PNG")),
    (b"GIF87a", 0, "gif", N_("immagine GIF")), (b"GIF89a", 0, "gif", N_("immagine GIF")),
    (b"%PDF-", 0, "pdf", N_("documento PDF")), (b"PK\x03\x04", 0, "zip", N_("archivio ZIP o documento Office/OpenDocument")),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole", N_("file OLE (Office 97-2003, Outlook .msg, .msi)")),
    (b"Rar!\x1a\x07", 0, "rar", N_("archivio RAR")), (b"7z\xbc\xaf\x27\x1c", 0, "7z", N_("archivio 7-Zip")),
    (b"\x1f\x8b\x08", 0, "gz", N_("archivio gzip")), (b"\xfd7zXZ\x00", 0, "xz", N_("archivio xz")),
    (b"\x7fELF", 0, "elf", N_("eseguibile Linux (ELF)")), (b"SQLite format 3\x00", 0, "sqlite", N_("database SQLite")),
    (b"!BDN", 0, "pst", N_("archivio di posta Outlook (PST/OST)")), (b"regf", 0, "reg", N_("registro di Windows")),
    (b"{\\rtf", 0, "rtf", N_("documento RTF")), (b"ID3", 0, "mp3", N_("audio MP3")), (b"OggS", 0, "ogg", N_("audio/video Ogg")),
    (b"fLaC", 0, "flac", N_("audio FLAC")), (b"\x1aE\xdf\xa3", 0, "mkv", N_("video Matroska/WebM")),
    (b"II*\x00", 0, "tif", N_("immagine TIFF")), (b"MM\x00*", 0, "tif", N_("immagine TIFF")), (b"MSCF", 0, "cab", N_("archivio CAB")),
    (b"8BPS", 0, "psd", N_("immagine Photoshop")), (b"conectix", 0, "vhd", N_("disco virtuale VHD")),
    (b"vhdxfile", 0, "vhdx", N_("disco virtuale VHDX")), (b"KDMV", 0, "vmdk", N_("disco virtuale VMDK")),
    (b"LUKS\xba\xbe", 0, "luks", N_("contenitore cifrato LUKS")), (b"EVF\x09\x0d\x0a\xff\x00", 0, "e01", N_("immagine forense E01")),
    (b"encrcdsa", 0, "dmgenc", N_("immagine disco Apple cifrata")), (b"bplist00", 0, "plist", N_("property list Apple")),
    (b"BZh", 0, "bz2", N_("archivio bzip2")),
    # (3.0.2) audio AMR (note vocali): senza, un documento rinominato .amr non era segnalato (caso NIST «Data Leakage»)
    (b"#!AMR", 0, "amr", N_("audio AMR")),
]
FAMILY_EXT = {
    "jpg": "jpg jpeg jpe jfif jif", "png": "png", "gif": "gif", "pdf": "pdf ai",
    "zip": "zip zipx docx docm dotx dotm xlsx xlsm xltx xltm xlsb pptx pptm potx ppsx ppsm odt ods odp "
           "odg odf ott jar apk aab epub xpi kmz pages numbers key ipa vsdx 3mf whl nupkg crx appx msix "
           "cbz xps oxps idml sketch",
    "ole": "doc dot xls xlt xla ppt pot pps msg msi msp mst vsd pub mpp db wps xlw one sldprt",
    "rar": "rar cbr", "7z": "7z", "gz": "gz tgz gzip svgz emz", "xz": "xz txz", "bz2": "bz2 tbz tbz2",
    "exe": "exe dll sys scr com ocx cpl drv efi mui ax acm pyd node winmd tlb rll tsp fon mun ime "
           "msstyles xll wll olb vxd bpl dpl cpx",
    "elf": "so ko o bin elf axf prx", "sqlite": "sqlite sqlite3 db db3 sqlitedb",
    "pst": "pst ost", "reg": "dat hve", "rtf": "rtf doc", "mp3": "mp3", "ogg": "ogg oga ogv opus",
    "flac": "flac", "wav": "wav", "avi": "avi", "webp": "webp", "heic": "heic heif avif",
    "mov": "mov qt mp4 m4v", "mp4": "mp4 m4v m4a mov 3gp 3g2 m4b f4v", "m4a": "m4a mp4 m4b",
    "3gp": "3gp 3g2 mp4", "mkv": "mkv webm mka", "tif": "tif tiff dng cr2 nef arw srw pef 3fr",
    "cab": "cab msu", "psd": "psd psb", "vhd": "vhd", "vhdx": "vhdx", "vmdk": "vmdk", "luks": "luks img",
    "e01": "e01", "dmgenc": "dmg", "plist": "plist", "macho": "dylib bundle jnilib kext so o",
    "amr": "amr 3ga",
}
FAMILY_EXT = {k: set(v.split()) for k, v in FAMILY_EXT.items()}
KNOWN_EXT = set().union(*FAMILY_EXT.values()) | {"txt", "csv", "html", "htm", "xml", "json", "log",
                                                   "ini", "md", "eml", "vcf", "ics", "bmp", "ico", "svg"}
MEDIA_FAM = {"jpg", "png", "gif", "tif", "psd", "webp", "heic", "mp3", "ogg", "flac", "wav", "avi",
             "mov", "mp4", "m4a", "3gp", "mkv", "amr"}
DOC_FAM = {"pdf", "zip", "ole", "rtf"}
OOXML = {"docx", "docm", "dotx", "xlsx", "xlsm", "xltx", "pptx", "pptm", "potx", "ppsx"}
SUSPECT_EXT = {"", "dat", "bin", "tc", "hc", "vc", "img", "raw", "tmp", "bak", "dmp", "enc", "crypt",
               "vol", "container", "data", "iso"}
# estensioni «generiche»: il contenuto può essere qualunque cosa (cache, dump, database interni…), quindi un
# formato diverso non è un'anomalia; resta segnalato solo un eseguibile, con gravità media
GENERIC_EXT = {"dat", "bin", "db", "img", "raw", "tmp", "bak", "data", "dmp", "dump", "old", "orig", "cache",
               "temp", "log1", "log2", "blf", "regtrans-ms", "pf0", "swp", "part", "crdownload", "download"}
# formati immagine: uno scambio jpg/png/webp… (frequente con file scaricati dal web) è una nota, non un allarme
IMAGE_FAM = {"jpg", "png", "gif", "tif", "webp", "heic", "psd"}
IMAGE_EXT = set().union(*(FAMILY_EXT[f] for f in IMAGE_FAM if f in FAMILY_EXT)) | {"bmp", "ico"}


def detect_sig(head):
    """(famiglia, descrizione) del contenuto, o (None, None)."""
    if len(head) >= 12 and head[:4] == b"RIFF":
        sub = head[8:12]
        return {b"WAVE": ("wav", tr("audio WAV")), b"AVI ": ("avi", tr("video AVI")),
                b"WEBP": ("webp", tr("immagine WebP"))}.get(sub, (None, None))
    if len(head) >= 12 and head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in (b"heic", b"heix", b"mif1", b"msf1", b"hevc", b"avif"):
            return "heic", tr("immagine HEIC/AVIF")
        if brand == b"qt  ":
            return "mov", tr("video QuickTime")
        if brand.startswith(b"M4A"):
            return "m4a", tr("audio M4A")
        if brand.startswith(b"3g"):
            return "3gp", tr("video 3GP")
        return "mp4", tr("video MP4")
    if head[:2] == b"MZ" and len(head) >= 0x40:
        lfa = struct.unpack_from("<I", head, 0x3C)[0]
        if lfa + 4 <= len(head) and head[lfa:lfa + 4] == b"PE\x00\x00":
            return "exe", tr("eseguibile Windows (PE)")
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "macho", tr("eseguibile macOS (Mach-O)")
    for sig, off, fam, label in SIGS:
        if head[off:off + len(sig)] == sig:
            if fam == "bz2" and not (len(head) > 3 and 0x31 <= head[3] <= 0x39):
                continue
            return fam, tr(label)
    return None, None


# ------------------------------------------------------------------ MFT: chi usa un cluster (verifica dei cancellati)  → forense_mft.py (3.0.4)
from forense_mft import (  # noqa: E402,F401
    ntfs_runlist, mft_fixup, mft_record_info, mft_cluster_owners, pe_raw_end, content_fits, VENDOR_PE_EXT, USER_EXT,
    SOFTWARE_PATH, INSTALLER_ICON, REG_LOG_EXT, VIDEO_FAM, HeadReader, check_volumes, quick_encrypted, run_anomalie)


# ------------------------------------------------------------------ artefatti  → forense_art_windows.py (3.0.4)
from forense_art_windows import (  # noqa: E402,F401
    KNOWN_FOLDERS, JUMP_APPS, Art, find_files, fetch, user_of, rk, rv, subkeys, lw, sz, local_to_utc, open_hive,
    _M32_SEED, _marvin32, hive_log_entries, _regf_checksum, apply_hive_logs, fetch_hive, systemtime, devprop_time,
    win_system, win_software, EVTX_DATA_RE, EVTX_PROVIDER_RE, LOGON_TIPI, evtx_records, evtx_stato, win_logons,
    sam_machine_sid, win_sam, rot13, known_folder, win_ntuser, win_prefetch, win_amcache, lnk_info, fs_time, win_lnk,
    parse_destlist, win_recycle)


# ---- browser (tutti i sistemi)  → forense_art_mac_linux.py (3.0.4)
from forense_art_mac_linux import (  # noqa: E402,F401
    chrome_time, browser_history, read_small, _part_meta, is_mac_volume, cocoa, plist_of, fetch_sqlite,
    bookmark_paths, _keyed_objects, _attributed_text, mac_artifacts, mac_sistema, mac_quarantena, mac_avvio,
    TCC_AUTH, mac_tcc, mac_messaggi, mac_recenti, mac_safari_download, mac_knowledgec, mac_dispositivi,
    mac_timemachine, linux_artifacts, shell_history)


# ------------------------------------------------------------------ Windows: parser di formati binari (2.18)  → forense_art_windows_altri.py (3.0.4)
from forense_art_windows_altri import (  # noqa: E402,F401
    KNOWN_SHELL_GUIDS, _guid, dos_datetime, _beef0004, shell_item, shimcache_entries, USN_REASONS, usn_reason_text,
    usn_records, thumbcache_entries, dhash_image, dhash_dist, win_roots, hive_rows, like_lit, fw, shellbags,
    win_usrclass, win_shim_bam, win_activities, GDRIVE_LOG_RE, GDRIVE_EV_RE, GDRIVE_DIR_RE, GDRIVE_SIZE_RE,
    GDRIVE_MTIME_RE, GDRIVE_MAIL_RE, GDRIVE_MAX, GDRIVE_CONFIG, _gdrive_ora, _gdrive_val, win_gdrive, gdrive_vss,
    _gdrive_log, _gdrive_db, WS_EDB, WS_SID_RE, WS_UTENTE_RE, _ws_utente, _ws_persona, win_ricerca, MOTORI_RICERCA,
    termine_ricerca, win_webcache, _plum_ora, _plum_testo, win_sticky, _ole_date, _sid_from_bytes, _nb, SRUM_APP,
    SRUM_NET, win_srum, EVTX_USERDATA_RE, EVTX_DATA_NONAME_RE, EVTX_LEAF_RE, EVT_LOGS, EVT_RULES, evtx_fields,
    win_eventi, win_usn, usn_dirs, USN_KEEP, usn_to_artifacts, win_thumbcache)


# ------------------------------------------------------------------ hash percettivi (2.18)

PHASH_SCHEMA = """CREATE TABLE IF NOT EXISTS phash(source TEXT, part INTEGER, inode TEXT, path TEXT, dhash INTEGER,
    w INTEGER, h INTEGER);
CREATE INDEX IF NOT EXISTS idx_phash ON phash(dhash);"""
PHASH_IMG = {".jpg", ".jpeg", ".jpe", ".jfif", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".heic", ".heif"}
PHASH_NEAR = 10             # bit diversi su 64: oltre non si considera «simile»


def run_phash(case, con):
    """Hash percettivo (dHash a 64 bit) di ogni immagine del caso: file della copia (anche cancellati), file estratti
    (archivi, allegati, miniature) e recuperati col carving. Serve a trovare immagini uguali anche se ridimensionate o
    ricompresse e a confrontarle con cartelle di immagini di riferimento (Liste di hash)."""
    try:
        import PIL  # noqa: F401
    except ImportError:
        print(tr("Manca Pillow: hash percettivi non calcolati."), flush=True)
        return None
    try:
        from pillow_heif import register_heif_opener
        register_heif_opener()
    except Exception:
        pass
    ctx = Ctx(case, con, "Hash percettivi")
    con.executescript(PHASH_SCHEMA)
    con.execute("DELETE FROM phash")
    con.commit()
    todo = []
    for part, inode, deleted, path in fs_rows(con, "1=1"):
        if Path(path).suffix.lower() in PHASH_IMG:
            todo.append(("fs", part, inode, path, None))
    if fa.table_exists(con, "xitems"):
        for xid, rel, path, name in con.execute("SELECT id, relpath, path, name FROM xitems WHERE relpath IS NOT NULL"):
            if Path(name or "").suffix.lower() in PHASH_IMG:
                todo.append(("x", None, str(xid), path, rel))
    if fa.table_exists(con, "carved"):
        for name, rel in con.execute("SELECT name, relpath FROM carved"):
            if Path(name).suffix.lower() in PHASH_IMG:
                todo.append(("carving", None, name, name, rel))
    print(tr("Hash percettivi: {v1} immagini...").format(v1=len(todo)), flush=True)

    def job(t):
        src, part, inode, path, rel = t
        if rel:
            fp = case.root / rel
            return t, dhash_image(fp) if fp.exists() else None
        f = ctx.tmp / f"p_{safe_name(str(inode), 40)}{Path(path).suffix.lower()[:6]}"
        try:
            n = copy_fs_file(case, part, inode, f, 80 << 20)
            return t, dhash_image(f) if n else None
        except Exception:
            return t, None
        finally:
            togli(f)
    ok = 0
    with ThreadPoolExecutor(max_workers=max(1, min(4, (os.cpu_count() or 2)))) as ex:
        for k, (t, r) in enumerate(ex.map(job, todo), 1):
            if r:
                con.execute("INSERT INTO phash VALUES (?,?,?,?,?,?,?)", (t[0], t[1], str(t[2]), t[3], r[0], r[1], r[2]))
                ok += 1
            fa.avanz(fatti=k, totale=len(todo))
            if k % 500 == 0:
                con.commit()
                ctx.say(tr("{k} di {v1} · {ok} calcolati").format(k=k, v1=len(todo), ok=ok))
    con.commit()
    ctx.close()
    print(tr("Hash percettivi: {ok} immagini su {v1} (le altre non si aprono o sono danneggiate)").format(ok=ok, v1=len(todo)), flush=True)
    return {"immagini": len(todo), "calcolati": ok, "algoritmo": "dHash 64 bit", "soglia": PHASH_NEAR, "ts": now()}


def phash_similar(con, h, maxd=PHASH_NEAR, limit=500):
    """Immagini del caso con hash percettivo entro maxd bit da h: [(distanza, source, part, inode, path)]."""
    out = []
    for src, part, inode, path, d in con.execute("SELECT source, part, inode, path, dhash FROM phash"):
        dd = dhash_dist(h, d)
        if dd <= maxd:
            out.append((dd, src, part, inode, path))
    out.sort(key=lambda x: (x[0], x[4] or ""))
    return out[:limit]


def phash_reference(folder):
    """Hash percettivi delle immagini di una cartella di riferimento: [(hash, nome del file)]."""
    out = []
    for fp in sorted(Path(folder).rglob("*")):
        if fp.is_file() and fp.suffix.lower() in PHASH_IMG:
            r = dhash_image(fp)
            if r:
                out.append((r[0], str(fp.relative_to(folder))))
    return out


def run_artefatti(case, con):
    ctx = Ctx(case, con, "Artefatti")
    # (3.0.4) gli artefatti letti dalla memoria RAM (processi, connessioni...) vengono da un'altra analisi: restano
    con.execute("DELETE FROM artifacts WHERE src_path IS NULL OR src_path NOT LIKE 'RAM:%'")
    if fa.table_exists(con, "xitems"):
        con.execute("DELETE FROM xitems WHERE kind='miniatura'")
    fa.rmtree_force(case.root / X_ROOT / "miniature")
    con.commit()
    A = Art(ctx)
    parts = [p for p in case.meta.get("partitions", []) if p.get("readable")]
    installazioni = []
    for p in parts:
        part = p["offset"]
        roots = win_roots(con, part)
        if roots:
            users_all = {}
            for root in roots:
                # ogni installazione di Windows (anche Windows.old) ha il proprio registro, i propri utenti e registri eventi
                ctx.win_root, ctx.win_inst = root, root.rstrip("/")
                for k in ("profili", "accessi"):
                    ctx.__dict__.pop(k, None)
                users = {}
                lbl = ctx.win_inst or "principale"
                installazioni.append({"offset": part, "radice": root or "/"})
                print(tr("Artefatti: registro di Windows (offset {part}, installazione {lbl})...").format(part=part, lbl=lbl), flush=True)
                for fn in (win_software, win_system, win_logons, win_sam):
                    try:
                        fn(A, ctx, part, users)
                    except Exception as e:
                        print(f"  {fn.__name__}: {type(e).__name__}: {e}", flush=True)
                    con.commit()
                for row in fw(ctx, part, "users/%/ntuser.dat") + fw(ctx, part, "documents and settings/%/ntuser.dat"):
                    if row[3].lower().count("/") > root.count("/") + 2:
                        continue
                    try:
                        win_ntuser(A, ctx, part, row)
                    except Exception as e:
                        print(tr("  NTUSER {v1}: {vname}: {e}").format(v1=row[3], vname=type(e).__name__, e=e), flush=True)
                for row in fw(ctx, part, "users/%/appdata/local/microsoft/windows/usrclass.dat"):
                    try:
                        win_usrclass(A, ctx, part, row)
                    except Exception as e:
                        print(tr("  UsrClass {v1}: {vname}: {e}").format(v1=row[3], vname=type(e).__name__, e=e), flush=True)
                con.commit()
                print(tr("Artefatti: prefetch, Amcache, SRUM e registri eventi ({lbl})...").format(lbl=lbl), flush=True)
                for fn, args in ((win_prefetch, ()), (win_amcache, ()), (win_srum, (users,)), (win_eventi, ())):
                    try:
                        fn(A, ctx, part, *args)
                    except Exception as e:
                        print(f"  {fn.__name__}: {type(e).__name__}: {e}", flush=True)
                    con.commit()
                users_all.update(users)
            ctx.win_root, ctx.win_inst = "", ""
            print(tr("Artefatti: collegamenti, jump list, cestino, Cronologia attività, miniature, Ricerca di Windows, "
                     "Internet Explorer, Sticky Notes..."), flush=True)
            for fn, args in ((win_lnk, ()), (win_recycle, (users_all,)), (win_activities, ()), (win_thumbcache, ()),
                             (win_gdrive, ()), (win_ricerca, (users_all,)), (win_webcache, ()), (win_sticky, ())):
                try:
                    fn(A, ctx, part, *args)
                except Exception as e:
                    print(f"  {fn.__name__}: {type(e).__name__}: {e}", flush=True)
                con.commit()
        else:
            try:
                mac_artifacts(A, ctx, part) or linux_artifacts(A, ctx, part)
            except Exception as e:
                print(tr("  sistema: {vname}: {e}").format(vname=type(e).__name__, e=e), flush=True)
            shell_history(A, ctx, part)
        if not fa.ap.is_apfs_part(part):
            try:
                hr = getattr(ctx, "hr", None) or HeadReader(case)
                ctx.hr = hr
                if hr.is_ntfs(part):
                    print(tr("Artefatti: journal NTFS $UsnJrnl (offset {part})...").format(part=part), flush=True)
                    n = win_usn(A, ctx, part, progress=lambda b: ctx.say(tr("journal: {v1} MB letti").format(v1=b >> 20)))
                    print(tr("  journal: {n} operazioni su file (create, cancellate, rinominate)").format(n=n), flush=True)
                    con.commit()
            except Exception as e:
                print(tr("  journal: {vname}: {e}").format(vname=type(e).__name__, e=e), flush=True)
                A.add("sistema", None, tr("Journal NTFS non letto"), tr("lettura interrotta: {vname}: {e}; le operazioni del journal mancano o sono incomplete").format(vname=type(e).__name__, e=e), "", (part, None, "/$Extend/$UsnJrnl:$J"),
                      {"journal": "non_letto", "errore": str(e)[:300]})
                con.commit()
        print(tr("Artefatti: cronologia dei browser (offset {part})...").format(part=part), flush=True)
        try:
            browser_history(A, ctx, part)
        except Exception as e:
            print(tr("  browser: {vname}: {e}").format(vname=type(e).__name__, e=e), flush=True)
        con.commit()
    # (3.0.2) gli artefatti rifatti dopo le copie shadow: Google Drive delle copie si rilegge dai file già estratti
    if con.execute("SELECT 1 FROM xitems WHERE kind='vss' AND lower(src_path) LIKE '%/google/drive/user_default/%' LIMIT 1").fetchone():
        try:
            gdrive_vss(case, con, ctx)
        except Exception as e:
            print(f"  gdrive_vss: {type(e).__name__}: {e}", flush=True)
    ctx.close()
    res = dict(A.n)
    res["ts"] = now()
    if installazioni:
        case.meta["installazioni_windows"] = installazioni
    print(tr("Artefatti: ") + (", ".join(f"{tr(ART_CATS.get(k, k))} {v}" for k, v in A.n.items()) or tr("nessun artefatto trovato")),
          flush=True)
    return res


# ------------------------------------------------------------------ copie shadow (VSS)  → forense_snapshot.py (3.0.4)
from forense_snapshot import (  # noqa: E402,F401
    VSS_SKIP, VSS_FILE_MAX, _vss_files, VSS_TOTAL_MAX, run_vss, SNAP_SKIP, SNAP_RE, _tsk_apfs_args,
    apfs_snapshot_list, parse_snapshots, _fls_map, run_apfs_snapshots)


# ------------------------------------------------------------------ OCR

OCR_IMG = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp", ".gif", ".webp", ".jfif"}


def tessdata_dir():
    for d in (Path(os.environ.get("REPERTIA_STRUMENTI", HERE.parent / "strumenti")) / "tessdata",
              HERE.parent / "tessdata"):
        if (d / "eng.traineddata").exists():
            return d
    return None


def tesseract():
    p = shutil.which("tesseract")
    if p:
        return p
    for c in (Path("/opt/homebrew/bin/tesseract"), Path("/usr/local/bin/tesseract")):
        if c.exists():
            return str(c)
    return None


def ocr_langs(exe, tdir):
    try:
        cmd = [exe, "--list-langs"] + (["--tessdata-dir", str(tdir)] if tdir else [])
        out = fa.dec(subprocess.run(cmd, capture_output=True, timeout=60).stdout)
        have = set(out.split())
    except Exception:
        have = set()
    langs = [l for l in ("ita", "eng") if l in have]
    return "+".join(langs) or "eng"


def ocr_file(exe, tdir, langs, f):
    cmd = [exe, str(f), "stdout", "-l", langs, "--psm", "3"] + (["--tessdata-dir", str(tdir)] if tdir else [])
    try:
        cp = subprocess.run(cmd, capture_output=True, timeout=300, stdin=subprocess.DEVNULL)
        return fa.dec(cp.stdout)
    except subprocess.TimeoutExpired:
        return ""


def useful_text(t):
    words = re.findall(r"[A-Za-zÀ-ÿ]{3,}", t or "")
    return len(words) >= 3


def run_ocr(case, con):
    exe = tesseract()
    if not exe:
        print(tr("Tesseract non trovato: ") + fa.install_hint("tesseract"), flush=True)
        return None
    tdir = tessdata_dir()
    langs = ocr_langs(exe, tdir)
    case.meta.setdefault("tool_versions", {})["tesseract"] = fa.tool_version([exe, "--version"]) or exe
    ctx = Ctx(case, con, "OCR")
    con.execute("DELETE FROM doc_text WHERE kind LIKE 'OCR%'")
    con.commit()
    todo = []
    for part, inode, deleted, path in fs_rows(con, "1=1"):
        ext = Path(path).suffix.lower()
        if ext in OCR_IMG and not fa.skip_for_text(path):
            todo.append(("fs", part, inode, deleted, path))
    for path, part, inode, deleted in con.execute(
            "SELECT path, part, inode, deleted FROM doc_text WHERE source='fs' AND kind LIKE 'PDF senza testo%'"):
        todo.append(("pdf", part, inode, deleted, path))
    if fa.table_exists(con, "xitems"):
        for xid, rel, path, name in con.execute("SELECT id, relpath, path, name FROM xitems WHERE relpath IS NOT NULL"):
            if Path(name).suffix.lower() in OCR_IMG:
                todo.append(("x", None, xid, 0, path, rel))
    if fa.table_exists(con, "carved"):
        for name, rel in con.execute("SELECT name, relpath FROM carved"):
            if Path(name).suffix.lower() in OCR_IMG:
                todo.append(("carving", None, name, 0, name, rel))
    todo = todo[:50000]
    print(tr("OCR: {v1} immagini e PDF senza testo da leggere (lingue {langs})...").format(v1=len(todo), langs=langs), flush=True)
    workers = max(1, (os.cpu_count() or 2) // 2)

    def job(t):
        kind, part, inode, deleted, path = t[:5]
        f = ctx.tmp / f"o_{safe_name(str(inode), 40)}{Path(path).suffix.lower()[:6] or '.bin'}"
        try:
            if kind in ("x", "carving"):
                src = case.root / t[5]
                if not src.exists() or src.stat().st_size < 8000 or src.stat().st_size > 60 << 20:
                    return t, ""
                f = src
            else:
                n = copy_fs_file(case, part, inode, f, 60 << 20)
                if not n or (kind == "fs" and n < 8000):
                    return t, ""
            if kind == "pdf":
                out = ctx.tmp / f"pg_{safe_name(str(inode), 40)}"
                subprocess.run(["pdftoppm", "-r", "200", "-l", "30", "-png", str(f), str(out)],
                               capture_output=True, timeout=600)
                texts = []
                for pg in sorted(ctx.tmp.glob(out.name + "*.png")):
                    texts.append(ocr_file(exe, tdir, langs, pg))
                    pg.unlink(missing_ok=True)
                return t, "\n\f".join(texts)
            return t, ocr_file(exe, tdir, langs, f)
        except Exception:
            return t, ""
        finally:
            if kind not in ("x", "carving"):
                togli(f)

    n_ok = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for k, (t, text) in enumerate(ex.map(job, todo), 1):
            if useful_text(text):
                kind, part, inode, deleted, path = t[:5]
                src = {"fs": "ocr", "pdf": "ocr", "x": "x", "carving": "carving"}[kind]
                fa.store_text(con, path, text.replace("\r\n", "\n"), src, part, str(inode), deleted,
                              tr("OCR (testo letto da immagine)") if kind != "pdf" else tr("OCR (PDF scansionato)"))
                n_ok += 1
            fa.avanz(fatti=k, totale=len(todo))
            if k % 50 == 0:
                con.commit()
                ctx.say(tr("{k} di {v1} · {n_ok} con testo").format(k=k, v1=len(todo), n_ok=n_ok))
    con.commit()
    ctx.close()
    print(tr("OCR: {n_ok} file con testo riconosciuto su {v1}").format(n_ok=n_ok, v1=len(todo)), flush=True)
    return {"file": len(todo), "con_testo": n_ok, "lingue": langs, "ts": now()}


# ------------------------------------------------------------------ esecuzione

def missing_modules(what):
    import importlib.util
    return [m for m in NEEDS.get(what, ()) if importlib.util.find_spec(m) is None]


def bundled_python_with(mods):
    for py in fa._bundled_pythons():
        if os.path.realpath(py) == os.path.realpath(sys.executable):
            continue
        try:
            r = subprocess.run([py, "-c", "import " + ", ".join(mods)], capture_output=True, timeout=60)
            if r.returncode == 0:
                return py
        except (OSError, subprocess.SubprocessError):
            continue
    return None


def run(case, con, what):
    """Esegue un'analisi estesa. True se riuscita, False se no, 'altro' se l'ha eseguita il
    Python incluso nell'app (il caso va ricaricato)."""
    miss = missing_modules(what)
    if miss:
        py = None if os.environ.get("REPERTIA_NO_REEXEC") else bundled_python_with(miss)
        if py:
            print(tr("Uso il Python incluso in RepertIA ({py}) per {v1}.").format(py=py, v1=tr(ADDONS_EXT[what])), flush=True)
            con.commit()
            r = subprocess.run([py, "-u", str(HERE / "forense_agent.py"), "prepara", "--case", str(case.root),
                                "--aggiungi", what], env=dict(os.environ, REPERTIA_NO_REEXEC="1"))
            return "altro" if r.returncode == 0 else False
        if what != "archivi":
            print(tr("Mancano i moduli Python {v1}: avvia RepertIA dall'app (Mac) o dall'installazione "
                     "(Windows), che li includono.").format(v1=', '.join(miss)), flush=True)
            return False
        print(tr("libpff non disponibile: i PST/OST non verranno aperti (archivi, mbox ed EML sì)."), flush=True)
    ensure_schema(con)
    con.commit()
    if what == "trascrizione":           # (2.20) forense_trascrizione.py (Whisper)
        import forense_trascrizione as ftr
        fn = ftr.run
    else:
        fn = {"archivi": run_archivi, "anomalie": run_anomalie, "artefatti": run_artefatti,
              "vss": run_vss, "ocr": run_ocr, "phash": run_phash}[what]
    res = fn(case, con)
    if res is None:
        return False
    case.meta.setdefault("estese", {})[what] = res
    case.log("analisi_estesa", {"analisi": what, "esito": res})
    return True


# ------------------------------------------------------------------ volumi cifrati: decifratura

def decrypt_volume(case, offset, secret, kind_secret, progress):
    """Crea una copia derivata con il volume all'offset indicato decifrato (BitLocker con
    password o chiave di ripristino, LUKS con password). La copia originale non viene toccata."""
    vol = next((v for v in case.meta.get("volumi_cifrati", []) if int(v["offset"]) == int(offset)), None)
    if not vol and any(x.get("apfs") and int(x["offset"]) == int(offset) for x in case.meta.get("partitions", [])):
        vol = {"apfs": True}
    if not vol:
        raise ValueError(tr("Volume cifrato non trovato: esegui prima l'analisi delle anomalie."))
    if vol.get("apfs"):          # APFS: nessuna copia decifrata, il volume si legge direttamente con la chiave
        return fa.ap.unlock_and_index(case, int(offset), secret, kind_secret, progress)
    img = ImageFile(case.image)
    parts = case.meta.get("partitions") or [{"offset": 0}]
    p = next((x for x in parts if int(x["offset"]) == int(offset)), {"offset": int(offset), "length_sectors": None})
    start, length = part_bounds(case, p, img)
    reg = Region(img, start, length)
    secret = (secret or "").strip()
    if vol["tipo"] == "BitLocker":
        import pybde
        v = pybde.volume()
        if kind_secret == "recovery" or re.fullmatch(r"(\d{6}-){7}\d{6}", secret):
            v.set_recovery_password(secret)
        else:
            v.set_password(secret)
        try:
            v.open_file_object(reg)
        except Exception as e:
            raise ValueError(tr("Impossibile aprire il volume BitLocker: {e}").format(e=e))
        if v.is_locked():
            v.close()
            raise ValueError(tr("Chiave o password non corretta: il volume resta bloccato."))
    elif vol["tipo"] == "LUKS":
        import pyluksde
        v = pyluksde.volume()
        v.set_password(secret)
        try:
            v.open_file_object(reg)
        except Exception as e:
            raise ValueError(tr("Impossibile aprire il volume LUKS: {e}").format(e=e))
        if v.is_locked():
            v.close()
            raise ValueError(tr("Password non corretta: il volume resta bloccato."))
    else:
        raise ValueError(tr("Decifratura non disponibile per {tipo}.").format(tipo=vol['tipo']))
    vsize = v.get_size()
    outd = case.root / "decifrata"
    outd.mkdir(exist_ok=True)
    out = outd / f"{Path(case.meta.get('evidence', case.image)).stem}_decifrata_offset{offset}.raw"
    if out.exists():
        out.chmod(0o644)
        out.unlink()
    total = (img.size or (start + length))
    if free_space(outd) < total + (1 << 30):
        v.close()
        raise ValueError(tr("Spazio insufficiente: servono circa {v1:.1f} GB liberi nella cartella del caso.").format(v1=total / 1e9))
    h = hashlib.sha256()
    done = 0
    t0 = time.time()

    def put(fh, b):
        nonlocal done
        fh.write(b)
        h.update(b)
        done += len(b)
        if time.time() - put.t > 1:
            put.t = time.time()
            el = time.time() - t0
            progress(tr("Decifratura: {v1:.2f} di {v2:.2f} GB ({v3:.0f} MB/s)").format(v1=done / 1e9, v2=total / 1e9, v3=done / 1e6 / max(el, 0.1)))
    put.t = 0
    with open(out, "wb") as fh:
        pos = 0
        while pos < start:           # tutto ciò che precede la partizione, invariato
            b = img.pread(pos, min(8 << 20, start - pos))
            if not b:
                break
            put(fh, b)
            pos += len(b)
        v.seek(0)
        got = 0
        while got < vsize:
            b = v.read(min(8 << 20, vsize - got))
            if not b:
                break
            put(fh, b)
            got += len(b)
        if got < length:              # LUKS: il contenuto è più corto della partizione
            pad = length - got
            while pad > 0:
                z = min(8 << 20, pad)
                put(fh, b"\x00" * z)
                pad -= z
        pos = start + length
        while img.size and pos < img.size:
            b = img.pread(pos, min(8 << 20, img.size - pos))
            if not b:
                break
            put(fh, b)
            pos += len(b)
    v.close()
    img.close()
    out.chmod(0o444)
    sha = h.hexdigest()
    side = {"derivata_da": case.meta.get("evidence", case.image), "sha256_originale": case.meta.get("sha256"),
            "volume": vol["tipo"], "offset": int(offset), "credenziale": tr("chiave di ripristino") if kind_secret == "recovery" else "password",
            "creata": now(), "sha256": sha, "byte": done, "caso_origine": str(case.root),
            "strumento": f"{fa.APP_NAME} {fa.APP_VERSION} (libbde/libluksde)"}
    Path(str(out) + ".json").write_text(json.dumps(side, indent=2, ensure_ascii=False), encoding="utf-8")
    case.meta.setdefault("decifrate", []).append({"file": str(out), **side})
    case.save()
    case.log("decifratura_volume", {k: v for k, v in side.items()})
    return {"path": str(out), "sha256": sha, "size": done}


# ------------------------------------------------------------------ liste di hash (NSRL e altre)  → forense_liste_hash.py (3.0.4)
from forense_liste_hash import (  # noqa: E402,F401
    HEX, hash_lists, save_hash_lists, iter_list_hashes, HEX_FULL, iter_list_entries, phash_index, phash_nearest,
    compare_phash_folder, compare_lists)


# ------------------------------------------------------------------ report

def report_md(case):
    """Sezioni del report sulle analisi estese (markdown)."""
    L = []
    m = case.meta
    est = m.get("estese") or {}
    if not est and not m.get("volumi_cifrati") and not m.get("liste_hash") and not m.get("ram"):
        return L
    con = fa.db_ro(case)
    cell = lambda v: str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")
    try:
        if m.get("volumi_cifrati"):
            L += [tr("## Volumi cifrati"), "", tr("| Offset | Tipo | Dimensione | Note |"), "|---|---|---|---|"]
            for v in m["volumi_cifrati"]:
                L.append(f"| {v['offset']} | {v['tipo']} | {v['byte'] / 1e9:.2f} GB | "
                         + tr("**NON ANALIZZATO**: contenuto non accessibile senza la chiave")
                         + (tr("; si sblocca con la chiave di ripristino o la password") if v.get("decifrabile") else "") + " |")
            L.append(tr("\n> Le partizioni cifrate elencate sopra non sono state analizzate: i risultati del caso "
                     "riguardano solo le altre partizioni."))
            for d in m.get("decifrate", []):
                L.append(tr("\nCopia derivata decifrata: `{file}` (volume {volume} all'offset {offset}, con "
                            "{credenziale}), SHA-256 `{sha256}`, creata il {creata}.").format(file=d['file'], volume=d['volume'], offset=d['offset'], credenziale=d['credenziale'], sha256=d['sha256'], creata=d['creata']))
            L.append("")
        if m.get("ram") and fa.table_exists(con, "artifacts"):       # (3.0.4) dump della memoria RAM
            r = m["ram"]
            L += [tr("## Memoria RAM"), "",
                  tr("- Dump letto con {motore}, in sola lettura e senza server dei simboli (nessuna richiesta di rete{nota}).").format(
                      motore=r.get("motore"), nota=tr("; ATTENZIONE: il server dei simboli risultava attivo") if r.get("simboli_da_rete") else ""),
                  tr("- I dati vengono dalle strutture del sistema ancora presenti in memoria al momento dell'acquisizione: un processo o "
                     "una connessione possono essere residui di strutture già liberate, e l'acquisizione di una memoria in uso non è "
                     "istantanea. Vanno trattati come elementi da verificare.")]
            L += [f"- {a}" for a in r.get("avvisi") or []]
            for cat, lim in (("processi", 400), ("connessioni", 200)):
                rows = con.execute("SELECT ts, title, detail, user FROM artifacts WHERE cat=? ORDER BY ts LIMIT ?", (cat, lim)).fetchall()
                if rows:
                    L += ["", f"### {tr(ART_CATS[cat])}", "", tr("| Data (UTC) | Elemento | Dettagli | Utente |"), "|---|---|---|---|"]
                    L += [f"| {cell((ts or '').replace('T', ' '))} | {cell(t)} | {cell(d)} | {cell(u)} |" for ts, t, d, u in rows]
                    tot = con.execute("SELECT COUNT(*) FROM artifacts WHERE cat=?", (cat,)).fetchone()[0]
                    if tot > len(rows):
                        L.append(tr("| … altre {v1} | | | |").format(v1=tot - len(rows)))
            L.append("")
        if fa.table_exists(con, "artifacts") and ("artefatti" in est or m.get("ram")):
            L += [tr("## Artefatti di sistema"), ""]
            sysrows = con.execute("SELECT title, detail FROM artifacts WHERE cat='sistema' ORDER BY id").fetchall()
            for t, d in sysrows:
                L.append(f"- {t}" + (f" ({d})" if d else ""))
            if m.get("fuso_dispositivo") and any(t.startswith("Fuso orario:") for t, _ in sysrows):
                L.append(tr("- Fuso usato in RepertIA per le date FAT/exFAT e per i valori in ora locale del registro: "
                            "{v1}. Controllare che coincida con il «Fuso orario» del sistema indicato sopra.").format(v1=fa.fuso_testo(m)))
            if m.get("installazioni_windows") and len(m["installazioni_windows"]) > 1:
                L.append(tr("- Installazioni di Windows analizzate: ") + ", ".join(
                    f"{x['radice']} (offset {x['offset']})" for x in m["installazioni_windows"]) +
                    tr(". Gli artefatti delle installazioni diverse da quella principale hanno il nome della cartella tra "
                    "parentesi quadre (es. «[Windows.old]»)."))
            for cat, lim in (("utenti", 50), ("usb", 100), ("eventi", 100)):
                rows = con.execute("SELECT ts, title, detail FROM artifacts WHERE cat=? ORDER BY ts DESC LIMIT ?",
                                   (cat, lim)).fetchall()
                if rows:
                    L += ["", f"### {tr(ART_CATS[cat])}", "", tr("| Data (UTC) | Elemento | Dettagli |"), "|---|---|---|"]
                    L += [f"| {cell((ts or '').replace('T', ' '))} | {cell(t)} | {cell(d)} |" for ts, t, d in rows]
            cnt = dict(con.execute("SELECT cat, COUNT(*) FROM artifacts GROUP BY cat").fetchall())
            lbl = dict(ART_CATS, messaggi=N_("Messaggi delle chat")) if fa.is_mobile(case) else ART_CATS   # smartphone (2.20)
            L += ["", tr("Elementi raccolti: ") + ", ".join(f"{tr(lbl.get(k, k))} {v}" for k, v in cnt.items()) +
                  tr(". L'elenco completo è nella sezione Artefatti di sistema di RepertIA e nel report portatile."), ""]
        if "archivi" in est:
            a = est["archivi"]
            L += [tr("## Archivi e posta elettronica"), "",
                  tr("- Archivi aperti: {v1}, file contenuti: {v2}").format(v1=a.get('archivi', 0), v2=a.get('file in archivi', 0))
                  + (tr(", archivi protetti da password: {v1}").format(v1=a['archivi cifrati']) if a.get("archivi cifrati") else ""),
                  tr("- Messaggi di posta: {v1}, allegati: {v2}").format(v1=a.get('messaggi', 0), v2=a.get('allegati', 0)),
                  tr("- I file estratti sono in `estratti/` in sola lettura, con MD5, SHA-1 e SHA-256 nel database del caso."), ""]
        if fa.table_exists(con, "anomalies"):
            rows = con.execute("SELECT kind, path, detail FROM anomalies WHERE kind <> 'volume' ORDER BY sev DESC, kind, path LIMIT 300").fetchall()
            if rows:
                L += [tr("## Anomalie"), "", tr("| Tipo | File | Dettaglio |"), "|---|---|---|"]
                L += [f"| {tr(ANOM_KINDS.get(k, k))} | {cell(p)} | {cell(d)} |" for k, p, d in rows]
                tot = con.execute("SELECT COUNT(*) FROM anomalies WHERE kind <> 'volume'").fetchone()[0]
                if tot > len(rows):
                    L.append(tr("| … altre {v1} | | |").format(v1=tot - len(rows)))
                L.append("")
        if "vss" in est:
            v = est["vss"]
            L += [tr("## Copie shadow (VSS) e snapshot APFS"), "", tr("- Copie trovate: {v1}").format(v1=v.get('copie', 0))
                  + (tr(" (di cui snapshot APFS: {snapshot_apfs})").format(snapshot_apfs=v['snapshot_apfs']) if v.get("snapshot_apfs") else "")
                  + tr("; file cancellati o in versione precedente recuperati: {v1}").format(v1=v.get('file', 0))]
            L += [tr("  - {v1} (offset {offset}): ").format(v1=d.get('copia') or tr('volume APFS «{v}»').format(v=d.get('volume')), offset=d['offset'])
                  + (f"{d['file']} file" if "file" in d else f"{d.get('snapshot', 0)} snapshot")
                  + (f" — {d['nota']}" if d.get("nota") else "") for d in v.get("dettaglio", [])]
            L.append("")
        if "ocr" in est:
            o = est["ocr"]
            L += [tr("## Testo nelle immagini (OCR)"), "", tr("- Immagini e PDF scansionati letti con Tesseract: {v1}, con testo riconosciuto: {v2} "
                                                          "(lingue {v3}).").format(v1=o.get('file', 0), v2=o.get('con_testo', 0), v3=o.get('lingue', '')),
                  tr("- Testo OCR automatico: può contenere errori di lettura e va verificato sull'immagine originale."), ""]
        if "trascrizione" in est:            # (2.20) trascrizione automatica degli audio (Whisper)
            t = est["trascrizione"]
            amb = {"chat": tr("audio allegati alle chat"), "tutti": tr("tutti gli audio"), "selezione": tr("audio selezionati")}
            L += [tr("## Trascrizione automatica degli audio"), "",
                  tr("- Audio trascritti con Whisper ({motore}) su questo computer, senza rete: {n} ({amb}), con parlato riconosciuto "
                     "{ok}, senza parlato {v}, non riusciti {e}, oltre la durata massima {s}; {mi} minuti di audio.").format(
                      motore=t.get("motore", ""), n=t.get("audio", 0), amb=amb.get(t.get("ambito"), t.get("ambito") or ""),
                      ok=t.get("con_testo", 0), v=t.get("senza_parlato", 0), e=t.get("non_riusciti", 0), s=t.get("oltre_durata", 0),
                      mi=t.get("minuti_audio", 0)),
                  tr("- Modello `{m}` (SHA-256 `{ms}`), motore SHA-256 `{es}`, lingua {l}.").format(
                      m=t.get("modello", ""), ms=t.get("modello_sha256", ""), es=t.get("motore_sha256", ""),
                      l=tr("riconosciuta automaticamente") if t.get("lingua") in (None, "", "auto") else t.get("lingua")),
                  tr("- Le trascrizioni sono automatiche e vanno verificate ascoltando l'audio: non sostituiscono una trascrizione "
                     "certificata. Il testo è nella ricerca nel testo del caso, nell'anteprima di ogni audio e nelle chat; gli "
                     "audio originali non sono stati modificati."), ""]
        if m.get("liste_hash"):
            L += [tr("## Liste di hash"), ""]
            for x in m["liste_hash"]["liste"]:
                tipo = tr("file noti, da escludere dall'esame") if x.get("tipo") == "noti" else tr("da segnalare")
                L.append(f"- «{x['nome']}» ({tipo}): "
                         + (x["errore"] if x.get("errore") else tr("{file} file corrispondenti su {hash:,} hash").format(file=x['file'], hash=x['hash']).replace(",", ".")))
            L.append("")
    finally:
        con.close()
    return L


# ------------------------------------------------------------------ strumenti per l'agente IA

def _agent_cited(case, rows):
    """(2.20) Per ogni riga (cat, ts, title, detail, user, src_path, part, inode, data): « | file citato: …» con il file
    trovato nella copia/estrazione (o «non presente»), così l'agente cita il file vero e non solo il percorso indicato."""
    out = [""] * len(rows)
    try:
        import forense_percorsi as fp
        idx = fp.Indice(case)
    except Exception:
        return out
    mobile = fa.is_mobile(case)
    try:
        for i, (c, t, ti, d, u, s, part, inode, data) in enumerate(rows):
            try:
                r = fp.file_citati(case, {"cat": c, "title": ti, "user": u, "src_path": s, "part": part, "inode": inode,
                                          "data": data}, veloce=True, idx=idx)
            except Exception:
                continue
            fs = [fp.etichetta_disco(x, mobile) for x in r["file"] if x["ruolo"] == "file"][:3]
            if fs:
                out[i] = " | " + tr("file citato: {f}").format(f="; ".join(fs))
    finally:
        idx.close()
    return out


def agent_tools(case):
    est = case.meta.get("estese") or {}
    tools = []

    def _db():
        return fa.db_ro(case)

    def query_artifacts(category: str = "", contains: str = "", limit: int = 100, offset: int = 0, group: str = "", item: str = "") -> str:
        """Artefatti di sistema già estratti (registro di Windows, prefetch, Amcache, collegamenti,
        jump list, cestino, cronologia web, account, dispositivi USB, reti...). Orari UTC salvo
        indicazione contraria.

        Args:
            category: sistema, utenti, usb, programmi, esecuzioni, recenti, cartelle (ShellBags), journal (file creati/cancellati/rinominati dal journal NTFS), eventi (registri eventi: servizi, accensioni, Desktop remoto, Defender), uso (Cronologia attività, SRUM), reti, cestino, web, download, ricerche, comandi; per un dump della memoria RAM anche processi, connessioni, moduli (librerie caricate dai processi), driver, attivita (attività pianificate); vuoto per tutte
            contains: testo da cercare in elemento, dettagli o utente
            limit: righe massime (max 300)
            offset: righe da saltare, per proseguire dopo una risposta incompleta
            group: gruppo della categoria (app delle chiamate, categoria di iLEAPP/ALEAPP); solo smartphone
            item: voce del gruppo (artefatto di iLEAPP/ALEAPP); solo smartphone
        """
        con = _db()
        w, a = ["1=1"], []
        if group or item:
            if "grp" not in {r[1] for r in con.execute("PRAGMA table_info(artifacts)")}:
                con.close()
                return tr("Gruppo e voce esistono solo negli artefatti degli smartphone.")
            if group:
                w.append("grp = ?"); a.append(group)
            if item:
                w.append("sub = ?"); a.append(item)
        if category:
            w.append("cat = ?"); a.append(category.strip().lower())
        if contains:
            w.append("(title LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\' OR user LIKE ? ESCAPE '\\' OR data LIKE ? ESCAPE '\\')")
            a += [fa.like(contains)] * 4
        lim = max(1, min(int(limit), 300))
        try:
            tot = con.execute(f"SELECT COUNT(*) FROM artifacts WHERE {' AND '.join(w)}", a).fetchone()[0]
            rows = con.execute(f"SELECT cat, ts, title, detail, user, src_path, part, inode, data FROM artifacts WHERE "
                               f"{' AND '.join(w)} ORDER BY ts IS NULL, ts DESC, id LIMIT {lim} OFFSET {max(0, int(offset))}", a).fetchall()
            cnt = con.execute("SELECT cat, COUNT(*) FROM artifacts GROUP BY cat").fetchall()
        finally:
            con.close()
        cited = _agent_cited(case, rows)
        testa = tr("Per categoria: ")+ ", ".join(f"{k} {v}" for k, v in cnt)
        out = [tr("- [{c}] {v1} | {ti} | {d} | utente {v2} | fonte {s}").format(c=c, v1=(t or '').replace('T', ' '), ti=ti, d=d, v2=u or '-', s=s)
                + cited[i] for i, (c, t, ti, d, u, s, *_r) in enumerate(rows)]
        return fa.pagina(out, tot, offset, testa)

    def count_artifacts(by: str = "categoria", category: str = "", group: str = "", contains: str = "") -> str:
        """Conta gli artefatti senza leggerli: da usare per primo quando i dati sono molti. Es. le chiamate per numero
        (category 'chiamate', by 'numero'), o le voci di iLEAPP/ALEAPP (category 'leapp', by 'voce').

        Args:
            by: categoria, gruppo, voce, titolo, numero (solo chiamate), giorno o mese
            category: categoria da contare; vuoto per tutte
            group: gruppo da contare; solo smartphone
            contains: testo da cercare in elemento, dettagli o dati
        """
        con = _db()
        try:
            ha_grp = "grp" in {r[1] for r in con.execute("PRAGMA table_info(artifacts)")}
            exprs = {"categoria": "cat", "titolo": "title", "giorno": "substr(ts, 1, 10)", "mese": "substr(ts, 1, 7)",
                     "numero": "json_extract(data, '$.numero')"}
            if ha_grp:
                exprs.update({"gruppo": "grp", "voce": "sub"})
            e = exprs.get(str(by).strip().lower())
            if not e:
                return tr("Valori possibili per by: {v}").format(v=", ".join(exprs))
            w, a = ["1=1"], []
            if category:
                w.append("cat = ?"); a.append(category.strip().lower())
            if group and ha_grp:
                w.append("grp = ?"); a.append(group)
            if contains:
                w.append("(title LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\' OR data LIKE ? ESCAPE '\\')"); a += [fa.like(contains)] * 3
            cond = " AND ".join(w)
            tot = con.execute(f"SELECT COUNT(*) FROM artifacts WHERE {cond}", a).fetchone()[0]
            rows = con.execute(f"SELECT {e}, COUNT(*) FROM artifacts WHERE {cond} GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 200", a).fetchall()
        finally:
            con.close()
        return fa.clip("\n".join([tr("{tot} artefatti in {n} valori (ne sono elencati al massimo 200):").format(tot=tot, n=len(rows))]
                                  + [f"{v if v not in (None, '') else '-'}: {n}" for v, n in rows]))

    def search_emails(contains: str = "", sender: str = "", limit: int = 50, offset: int = 0) -> str:
        """Messaggi di posta estratti da PST/OST, mbox, EML e MSG (anche dentro archivi):
        data, mittente, destinatari, oggetto, numero di allegati.

        Args:
            contains: testo da cercare in oggetto, corpo, destinatari
            sender: testo da cercare nel mittente
            limit: righe massime (max 200)
            offset: righe da saltare, per proseguire dopo una risposta incompleta
        """
        con = _db()
        w, a = ["1=1"], []
        if contains:
            w.append("(subject LIKE ? ESCAPE '\\' OR body LIKE ? ESCAPE '\\' OR recipients LIKE ? ESCAPE '\\')")
            a += [fa.like(contains)] * 3
        if sender:
            w.append("sender LIKE ? ESCAPE '\\'"); a.append(fa.like(sender))
        try:
            tot = con.execute(f"SELECT COUNT(*) FROM mail WHERE {' AND '.join(w)}", a).fetchone()[0]
            rows = con.execute(f"SELECT id, date, sender, recipients, subject, n_att, src_path, folder FROM mail "
                               f"WHERE {' AND '.join(w)} ORDER BY date DESC, id LIMIT {max(1, min(int(limit), 200))} OFFSET {max(0, int(offset))}", a).fetchall()
        finally:
            con.close()
        out = [tr("- id {i} | {v1} | da {s} | a {r} | «{o}» | allegati {n} | {p} › {fo}").format(i=i, v1=(d or '').replace('T', ' '), s=s, r=r, o=o, n=n, p=p, fo=fo)
                for i, d, s, r, o, n, p, fo in rows]
        return fa.pagina(out, tot, offset, tr("Leggi il testo con read_email(email_id)."))

    def read_email(email_id: int, max_chars: int = 8000) -> str:
        """Testo completo di un messaggio di posta (intestazioni, corpo, elenco allegati).

        Args:
            email_id: id del messaggio (da search_emails)
            max_chars: caratteri massimi
        """
        con = _db()
        try:
            r = con.execute("SELECT date, sender, recipients, cc, subject, body, headers, src_path, folder FROM mail "
                            "WHERE id=?", (int(email_id),)).fetchone()
            att = con.execute("SELECT id, name, size, sha256 FROM xitems WHERE mail=?", (int(email_id),)).fetchall()
        finally:
            con.close()
        if not r:
            return tr("Messaggio non trovato.")
        d, s, to, cc, subj, body, hdr, src, folder = r
        txt = (tr("Fonte: {src} › {folder}\nData (UTC): {d}\nDa: {s}\nA: {to}\nCc: {cc}\nOggetto: "
                  "{subj}\nAllegati: ").format(src=src, folder=folder, d=d, s=s, to=to, cc=cc, subj=subj) + ("; ".join(f"[id {i}] {n} ({z} byte, SHA-256 {h})" for i, n, z, h in att) or "nessuno")
               + f"\n\n{(body or '')[:max(500, min(int(max_chars), 60000))]}")
        return fa.clip(txt)

    def list_extracted(contains: str = "", kind: str = "", limit: int = 100, offset: int = 0) -> str:
        """File estratti da archivi (ZIP, RAR, 7z...), allegati di posta, copie shadow e foto/video
        dalla cache dei browser (con l'indirizzo web d'origine nella nota): percorso, dimensione, data,
        cifratura, hash. Leggili con read_extracted.

        Args:
            contains: testo da cercare nel percorso o nella nota (es. un indirizzo web)
            kind: archivio, allegato, vss o cache_web; vuoto per tutti
            limit: righe massime (max 300)
            offset: righe da saltare, per proseguire dopo una risposta incompleta
        """
        con = _db()
        w, a = ["1=1"], []
        if contains:
            w.append("(path LIKE ? ESCAPE '\\' OR note LIKE ? ESCAPE '\\')"); a += [fa.like(contains)] * 2
        if kind:
            w.append("kind = ?"); a.append(kind)
        try:
            tot = con.execute(f"SELECT COUNT(*) FROM xitems WHERE {' AND '.join(w)}", a).fetchone()[0]
            rows = con.execute(f"SELECT id, kind, path, size, mtime, encrypted, sha256, note FROM xitems WHERE "
                               f"{' AND '.join(w)} ORDER BY path, id LIMIT {max(1, min(int(limit), 300))} OFFSET {max(0, int(offset))}", a).fetchall()
        finally:
            con.close()
        out = [tr("- id {i} [{k}] {p} | {z} B | {v1}{v2} | SHA-256 {v3}").format(i=i, k=k, p=p, z=z, v1=(m or '').replace('T', ' '), v2=tr(' | CIFRATO') if e else '', v3=h or '-')
                + (f" | {n}" if n else "") for i, k, p, z, m, e, h, n in rows]
        return fa.pagina(out, tot, offset)

    def read_extracted(item_id: int, max_chars: int = 8000) -> str:
        """Testo di un file estratto (da archivio, allegato, copia shadow o cache dei browser).

        Args:
            item_id: id del file estratto (da list_extracted o read_email)
            max_chars: caratteri massimi
        """
        con = _db()
        try:
            r = con.execute("SELECT path, relpath, name FROM xitems WHERE id=?", (int(item_id),)).fetchone()
        finally:
            con.close()
        if not r or not r[1]:
            return tr("File non estratto o inesistente.")
        f = case.root / r[1]
        data = f.read_bytes()[:50 << 20]
        tmp = case.root / "tmp"
        tmp.mkdir(exist_ok=True)
        t = None
        try:
            t = fa.extract_text(data, r[2], tmp)
        except Exception:
            pass
        txt = t[1] if t else fa.binary_strings(data)
        return fa.clip(tr("{v1} ({v2} byte; {v3})\n").format(v1=r[0], v2=len(data), v3=t[0] if t else tr('stringhe')) + txt[:max(500, min(int(max_chars), 60000))])

    def list_anomalies(kind: str = "", limit: int = 100, offset: int = 0) -> str:
        """Anomalie: estensioni che non corrispondono al contenuto (anche eseguibili mascherati),
        file protetti da password, possibili contenitori cifrati, volumi cifrati, hash segnalati.

        Args:
            kind: estensione, cifrato, contenitore, volume, segnalato; vuoto per tutte
            limit: righe massime (max 300)
            offset: righe da saltare, per proseguire dopo una risposta incompleta
        """
        con = _db()
        w, a = ["1=1"], []
        if kind:
            w.append("kind = ?"); a.append(kind)
        try:
            tot = con.execute(f"SELECT COUNT(*) FROM anomalies WHERE {' AND '.join(w)}", a).fetchone()[0]
            rows = con.execute(f"SELECT kind, path, detail, part, inode, sev FROM anomalies WHERE {' AND '.join(w)} "
                               f"ORDER BY sev DESC, path, rowid LIMIT {max(1, min(int(limit), 300))} OFFSET {max(0, int(offset))}", a).fetchall()
        finally:
            con.close()
        return fa.pagina([tr("- [{k}] {p} | {d} | offset {pt} inode {i} | gravità {s}").format(k=k, p=p, d=d, pt=pt, i=i, s=s)
                          for k, p, d, pt, i, s in rows], tot, offset)

    if "artefatti" in est or case.meta.get("ram"):      # (3.0.4) anche i casi da dump della RAM
        tools += [query_artifacts, count_artifacts]
    if "archivi" in est:
        tools += [search_emails, read_email]
    # (3.0.1) secondo i dati presenti: anche gli estratti dalla cache dei browser («Testo e media») e le anomalie scritte
    # senza l'analisi «anomalie» (es. volume BitLocker alla preparazione)
    if "archivi" in est or "vss" in est or _righe(case, "xitems"):
        tools += [list_extracted, read_extracted]
    if "anomalie" in est or case.meta.get("liste_hash") or _righe(case, "anomalies"):
        tools.append(list_anomalies)
    return tools


def _righe(case, tabella):
    """Numero di righe di una tabella del caso (0 se manca)."""
    try:
        con = fa.db_ro(case)
        try:
            return con.execute(f"SELECT COUNT(*) FROM {tabella}").fetchone()[0] if fa.table_exists(con, tabella) else 0
        finally:
            con.close()
    except sqlite3.Error:
        return 0


def prompt_extra(case):
    est = case.meta.get("estese") or {}
    out = []
    if case.meta.get("ram"):            # (3.0.4) dump della memoria RAM
        out.append(tr("- Questo caso è un dump della memoria RAM di un computer Windows, letto con MemProcFS: processi, connessioni "
                      "di rete, moduli caricati, driver, attività pianificate e utenti sono nella tabella artifacts (categorie "
                      "processi, connessioni, moduli, driver, attivita, utenti, sistema): usa query_artifacts e count_artifacts. "
                      "Non c'è un file system. Sono dati letti dalla memoria: un processo o una connessione possono essere "
                      "residui di strutture già liberate, quindi presentali come DA VERIFICARE."))
    if "artefatti" in est:
        out.append(tr("- Artefatti di sistema già estratti (account, USB, programmi installati ed eseguiti con ShimCache e BAM, file "
                   "recenti, cartelle aperte (ShellBags), journal NTFS, registri eventi, Cronologia attività e SRUM, reti "
                   "Wi-Fi, cestino, cronologia web, download, ricerche; anche di Windows.old): query_artifacts. "
                   "Parti da qui per le domande su chi ha usato il computer, cosa e quando."))
    if "archivi" in est:
        a = est["archivi"]
        out.append(tr("- Posta: {v1} messaggi (search_emails, read_email); archivi aperti: {v2} con {v3} file "
                      "(list_extracted, read_extracted).").format(v1=a.get('messaggi', 0), v2=a.get('archivi', 0), v3=a.get('file in archivi', 0)))
    if "vss" in est:
        out.append(tr("- Copie shadow: {v1} file cancellati o in versione precedente (list_extracted kind='vss').").format(v1=est['vss'].get('file', 0)))
    if "anomalie" in est or _righe(case, "anomalies"):
        out.append(tr("- Anomalie (estensioni false, file e volumi cifrati): list_anomalies."))
    if "archivi" not in est and "vss" not in est and _righe(case, "xitems"):
        out.append(tr("- File estratti: list_extracted, read_extracted."))
    try:
        con = fa.db_ro(case)
        try:
            n_cw = con.execute("SELECT COUNT(*) FROM xitems WHERE kind = 'cache_web'").fetchone()[0] \
                if fa.table_exists(con, "xitems") else 0
        finally:
            con.close()
    except sqlite3.Error:
        n_cw = 0
    if n_cw:
        out.append(tr("- Foto e video estratti dalla cache dei browser: {n} (list_extracted kind='cache_web'); la nota dà "
                      "l'indirizzo web d'origine e l'offset nel file di cache.").format(n=n_cw))
    if case.meta.get("volumi_cifrati"):
        out.append(tr("- ATTENZIONE: volumi cifrati presenti: ") + ", ".join(tr("{tipo} all'offset {offset}").format(tipo=v['tipo'], offset=v['offset'])
                                                                    for v in case.meta["volumi_cifrati"]))
    return out
