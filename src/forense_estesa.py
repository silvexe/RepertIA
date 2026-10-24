#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
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
}
# moduli Python (inclusi nei pacchetti di RepertIA) necessari a ciascuna analisi
NEEDS = {"archivi": ("pypff",), "artefatti": ("pyregf", "pyscca", "pylnk", "pyolecf"),
         "vss": ("pyvshadow", "pytsk3"), "anomalie": (), "ocr": (), "phash": ("PIL",)}

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
            "journal": N_("Journal NTFS (creati, cancellati, rinominati)"), "eventi": N_("Eventi di sistema")}
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
    except (ValueError, OverflowError):
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
    t = html.unescape(re.sub(r"<[^>]+>", " ", h))
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
        f.unlink(missing_ok=True)


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
        fa.rmtree_force(lp(self.tmp))


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


# ------------------------------------------------------------------ archivi

def seven_zip():
    for n in ("7zz", "7z", "7za"):
        p = shutil.which(n)
        if p:
            return p
    return None


LOCALE = " locale"      # suffisso delle date in ora locale del dispositivo, senza fuso (es. DOS dei file ZIP)


def zip_dates(f):
    """Date dei file di uno ZIP, per percorso. Il campo DOS è ora locale del computer che ha creato lo ZIP, senza
    fuso: si marca con LOCALE. Se c'è il campo esteso 'UT' (0x5455) la data è un istante UTC esatto."""
    out = {}
    try:
        with zipfile.ZipFile(f) as z:
            for i in z.infolist():
                mt, ex = None, i.extra or b""
                p = 0
                while p + 4 <= len(ex):
                    hid, sz_ = struct.unpack("<HH", ex[p:p + 4])
                    body = ex[p + 4:p + 4 + sz_]
                    if hid == 0x5455 and len(body) >= 5 and body[0] & 1:
                        mt = unixtime(struct.unpack("<i", body[1:5])[0])
                        break
                    p += 4 + sz_
                if not mt:
                    try:
                        mt = dt.datetime(*i.date_time).strftime("%Y-%m-%dT%H:%M:%S") + LOCALE
                    except ValueError:
                        mt = None
                out[i.filename.replace("\\", "/")] = mt
    except Exception:
        pass
    return out


def z_list(exe, f):
    """Elenco tecnico (7z l -slt): [{path, size, mtime, encrypted, dir}], codice, errore."""
    try:
        # TZ=UTC: per i formati con date assolute (tar, 7z…) 7-Zip le scrive nel fuso del computer; così sono UTC
        cp = subprocess.run([exe, "l", "-slt", "-ba", NOPASS, str(f)], capture_output=True,
                            timeout=900, stdin=subprocess.DEVNULL, env=dict(os.environ, TZ="UTC"))
    except subprocess.TimeoutExpired:
        return [], 1, tr("tempo scaduto")
    out = fa.dec(cp.stdout)
    items, cur = [], {}
    for line in out.splitlines() + [""]:
        if not line.strip():
            if cur.get("Path") is not None:
                items.append(cur)
            cur = {}
            continue
        k, sep, v = line.partition(" = ")
        if sep:
            cur[k.strip()] = v
    res = []
    for e in items:
        p = e.get("Path", "").replace("\\", "/")
        isdir = e.get("Folder") == "+" or "D" in (e.get("Attributes") or "")[:1]
        try:
            size = int(e.get("Size") or 0)
        except ValueError:
            size = 0
        m = (e.get("Modified") or "").strip()
        res.append({"path": p, "size": size, "dir": isdir, "encrypted": e.get("Encrypted") == "+",
                    "mtime": m[:19].replace(" ", "T") if re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", m) else None})
    if zipfile.is_zipfile(f):          # per gli ZIP la data DOS è ora locale senza fuso: la libreria la distingue
        zd = zip_dates(f)
        for r in res:
            if r["path"] in zd:
                r["mtime"] = zd[r["path"]]
    return res, cp.returncode, fa.dec(cp.stderr) + out[-600:]


def z_extract(exe, f, dest):
    try:
        cp = subprocess.run([exe, "x", "-y", NOPASS, f"-o{dest}", "-bsp0", "-bso0", str(f)],
                            capture_output=True, timeout=7200, stdin=subprocess.DEVNULL)
        return cp.returncode, fa.dec(cp.stderr)
    except subprocess.TimeoutExpired:
        return 1, tr("tempo scaduto")


def py_list_extract(f, dest, do_extract):
    """Senza 7-Zip: ZIP e tar con la libreria standard."""
    res = []
    if zipfile.is_zipfile(f):
        zd = zip_dates(f)
        with zipfile.ZipFile(f) as z:
            for i in z.infolist():
                mt = zd.get(i.filename.replace("\\", "/"))
                enc = bool(i.flag_bits & 1)
                res.append({"path": i.filename, "size": i.file_size, "dir": i.is_dir(),
                            "encrypted": enc, "mtime": mt})
                if do_extract and not i.is_dir() and not enc and i.file_size <= ENTRY_MAX:
                    try:
                        z.extract(i, dest)
                    except Exception:
                        pass
        return res, 0
    try:
        with tarfile.open(f) as t:
            for m in t.getmembers():
                res.append({"path": m.name, "size": m.size, "dir": m.isdir(), "encrypted": False,
                            "mtime": unixtime(m.mtime)})
            if do_extract:
                try:
                    t.extractall(dest, filter="data")
                except TypeError:
                    t.extractall(dest)
                except Exception:
                    pass
        return res, 0
    except (tarfile.TarError, OSError):
        return [], 1


def is_archive_name(name):
    n = name.lower()
    return Path(n).suffix in ARCH_EXT or n.endswith(".tar.gz") or n.endswith(".tar.bz2")


ARCH_FAM = ("zip", "rar", "7z", "gz", "xz", "bz2", "cab")


def archive_by_content(name, head):
    """2.15.2: archivio riconosciuto dal contenuto anche se l'estensione è un'altra (es. un ZIP chiamato
    .boo, DFTT 8, o un archivio rinominato .jpg per nasconderlo). Restituisce la descrizione o None.
    I formati che sono ZIP per costruzione (docx, xlsx, odt, jar, apk…) non si aprono come archivi."""
    if not head or is_archive_name(name):
        return None
    ext = Path(name.lower()).suffix.lstrip(".")
    if len(head) >= 262 and head[257:262] == b"ustar":
        return tr("archivio tar")
    fam, label = detect_sig(head[:4096])
    if fam in ARCH_FAM and ext not in FAMILY_EXT.get(fam, set()) and not (fam == "zip" and ext in KNOWN_EXT - {"jpg", "jpeg", "png", "gif", "pdf", "txt", "dat", "bin"}):
        return label
    return None


def is_mail_name(name):
    return Path(name.lower()).suffix in MAIL_EXT


def process_container(ctx, f, disp, origin, depth, parent=None):
    """Apre un archivio o un file di posta (già copiato in `f`) e ne registra il contenuto.
    origin: (part, inode, src_path) del file della copia da cui tutto proviene."""
    name = Path(disp.split(" › ")[-1]).name
    low = name.lower()
    head = open(f, "rb").read(16)
    try:
        if low.endswith((".pst", ".ost")) or head.startswith(b"!BDN"):
            return process_pst(ctx, f, disp, origin, depth, parent)
        if low.endswith(".msg") or (head.startswith(b"\xd0\xcf\x11\xe0") and low.endswith(".msg")):
            return process_msg_file(ctx, f, disp, origin, depth, parent)
        if low.endswith((".eml", ".emlx")):
            return process_eml_file(ctx, f, disp, origin, depth, parent)
        if low.endswith((".mbox", ".mbx")) or (head.startswith(b"From ") and "." not in name):
            return process_mbox(ctx, f, disp, origin, depth, parent)
        return process_archive(ctx, f, disp, origin, depth, parent)
    except Exception as e:     # un file danneggiato non deve fermare la passata
        ctx.c["errori"] += 1
        print(tr("  {disp}: non elaborato ({vname}: {e})").format(disp=disp, vname=type(e).__name__, e=e), flush=True)
        return 0


def process_archive(ctx, f, disp, origin, depth, parent):
    con, case = ctx.con, ctx.case
    exe = seven_zip()
    if exe:
        entries, rc, err = z_list(exe, f)
    else:
        entries, rc = py_list_extract(f, None, False)
        err = ""
    files = [e for e in entries if not e["dir"]]
    if not entries:
        if re.search(r"(?i)wrong password|encrypted|can not open encrypted", err or ""):
            add_anomaly(con, "cifrato", origin_source(parent), *origin_ref(origin, parent), disp,
                        tr("archivio protetto da password (anche i nomi dei file sono cifrati)"),
                        sev=2)
            ctx.c["archivi cifrati"] += 1
        elif exe is None and Path(f).suffix.lower() not in (".zip", ".tar", ".gz", ".tgz", ".jar", ".apk"):
            ctx.c["senza 7-Zip"] += 1
        return 0
    ctx.c["archivi"] += 1
    total = sum(e["size"] for e in files)
    extract = total <= ARCHIVE_MAX and ctx.extracted + total <= TOTAL_MAX and \
        free_space(case.root) > total * 1.2 + (2 << 30)
    out = ctx.tmp / f"x{time.time_ns()}"
    out.mkdir()
    if extract:
        if exe:
            z_extract(exe, f, out)
        else:
            py_list_extract(f, out, True)
    n_enc = 0
    for e in files:
        inner = e["path"].strip("/")
        path = f"{disp} › {inner}"
        p = out / inner
        rel = md5 = sha1 = sha256 = None
        note = None
        size = e["size"]
        if e["encrypted"]:
            n_enc += 1
            note = tr("protetto da password")
        elif not extract:
            note = tr("non estratto (archivio troppo grande o spazio insufficiente)")
        elif not os.path.isfile(lp(p)):
            note = tr("non estratto (errore di 7-Zip o percorso non valido)")
        elif os.path.getsize(lp(p)) > ENTRY_MAX:
            note = tr("non estratto (oltre {v1} MB)").format(v1=ENTRY_MAX >> 20)
        xid = new_xitem(con, kind="archivio", part=origin[0], inode=origin[1], src_path=origin[2],
                        parent=parent, inner=inner, path=path, name=Path(inner).name, size=size,
                        mtime=e["mtime"], encrypted=1 if e["encrypted"] else 0, note=note,
                        deleted=origin_deleted(ctx, origin))
        ctx.c["file in archivi"] += 1
        if note is None:
            data = open(lp(p), "rb").read(fa.MAX_EXTRACT)
            if index_text(con, case, path, data, inner, "x", None, xid, 0, ctx.tmp):
                ctx.c["testi"] += 1
            by_content = archive_by_content(inner, data[:4096])
            if by_content:
                ctx.c["archivi riconosciuti dal contenuto"] += 1
            nested = depth < DEPTH_MAX and (is_archive_name(inner) or is_mail_name(inner) or bool(by_content))
            n, md5, sha1, sha256 = hashes_of(lp(p))
            rel = store_extracted(case, lp(p), "archivi", xid, Path(inner).name)
            ctx.extracted += n
            con.execute("UPDATE xitems SET relpath=?, md5=?, sha1=?, sha256=?, size=? WHERE id=?",
                        (rel, md5, sha1, sha256, n, xid))
            if nested:
                process_container(ctx, case.root / rel, path, origin, depth + 1, parent=xid)
        if ctx.c["file in archivi"] % 200 == 0:
            con.commit()
            ctx.say(tr("{archivi} archivi, {v1} file contenuti, {messaggi} messaggi").format(archivi=ctx.c['archivi'], v1=ctx.c['file in archivi'], messaggi=ctx.c['messaggi']))
    if n_enc:
        add_anomaly(con, "cifrato", origin_source(parent), *origin_ref(origin, parent), disp,
                    tr("archivio con {n_enc} file protetti da password").format(n_enc=n_enc), sev=2)
        ctx.c["archivi cifrati"] += 1
    fa.rmtree_force(lp(out))
    con.commit()
    return len(files)


def origin_source(parent):
    return "x" if parent else "fs"


def origin_ref(origin, parent):
    return (None, parent) if parent else (origin[0], origin[1])


def origin_deleted(ctx, origin):
    r = ctx.con.execute("SELECT deleted FROM files WHERE part=? AND inode=? LIMIT 1",
                        (origin[0], origin[1])).fetchone()
    return r[0] if r else 0


# ------------------------------------------------------------------ posta

def addr_list(v):
    if not v:
        return ""
    try:
        return ", ".join(f"{n} <{a}>" if n and a else (a or n)
                         for n, a in email.utils.getaddresses([str(v)]))
    except Exception:
        return str(v)


def add_message(ctx, origin, parent, fmt, folder, disp, sender, to, cc, subject, date, body,
                html_body, headers, attachments, depth):
    """Registra un messaggio con i suoi allegati: [(nome, bytes)]."""
    con, case = ctx.con, ctx.case
    subject = (subject or "").strip() or tr("(senza oggetto)")
    mid = con.execute("INSERT INTO mail(part, inode, src_path, xid, fmt, folder, sender, recipients, "
                      "cc, subject, date, body, html, n_att, headers) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (origin[0], origin[1], origin[2], parent, fmt, folder, sender, to, cc, subject,
                       date, (body or "")[:fa.MAX_TEXT], (html_body or "")[:2_000_000] or None,
                       len(attachments), (headers or "")[:20000])).lastrowid
    mpath = f"{disp} › {folder + ' › ' if folder else ''}{subject[:100]}"
    txt = (f"Da: {sender}\nA: {to}\n" + (f"Cc: {cc}\n" if cc else "") +
           tr("Oggetto: {subject}\nData: {v1}\n\n{v2}").format(subject=subject, v1=date or '', v2=body or ''))
    fa.store_text(con, mpath, txt, "posta", None, str(mid), 0, "email")
    ctx.c["messaggi"] += 1
    for name, data in attachments:
        name = (name or "allegato").strip() or "allegato"
        apath = f"{mpath} › 📎 {name}"
        xid = new_xitem(con, kind="allegato", part=origin[0], inode=origin[1], src_path=origin[2],
                        parent=parent, mail=mid, inner=name, path=apath, name=Path(name).name,
                        size=len(data), mtime=date, deleted=origin_deleted(ctx, origin))
        ctx.c["allegati"] += 1
        if len(data) > ENTRY_MAX or ctx.extracted + len(data) > TOTAL_MAX:
            con.execute("UPDATE xitems SET note=? WHERE id=?", (tr("non estratto (troppo grande)"), xid))
            continue
        tmpf = ctx.tmp / f"a{xid}"
        tmpf.write_bytes(data)
        if index_text(con, case, apath, data[:fa.MAX_EXTRACT], name, "x", None, xid, 0, ctx.tmp):
            ctx.c["testi"] += 1
        n, md5, sha1, sha256 = hashes_of(tmpf)
        rel = store_extracted(case, tmpf, "posta", xid, name)
        ctx.extracted += n
        enc = 0
        if data[:4] == b"PK\x03\x04" and len(data) > 8 and data[6] & 1:
            enc = 1
        con.execute("UPDATE xitems SET relpath=?, md5=?, sha1=?, sha256=?, encrypted=? WHERE id=?",
                    (rel, md5, sha1, sha256, enc, xid))
        by_content = archive_by_content(name, data[:4096])
        if by_content:
            ctx.c["archivi riconosciuti dal contenuto"] += 1
        if depth < DEPTH_MAX and (is_archive_name(name) or is_mail_name(name) or bool(by_content)):
            process_container(ctx, case.root / rel, apath, origin, depth + 1, parent=xid)
    if ctx.c["messaggi"] % 200 == 0:
        con.commit()
        ctx.say(tr("{messaggi} messaggi, {allegati} allegati").format(messaggi=ctx.c['messaggi'], allegati=ctx.c['allegati']))
    return mid


def parse_email_bytes(raw):
    """Messaggio RFC 822 -> campi principali, testo, html, allegati."""
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    body = htm = ""
    atts = []
    try:
        b = msg.get_body(preferencelist=("plain",))
        if b is not None:
            body = b.get_content()
        h = msg.get_body(preferencelist=("html",))
        if h is not None:
            htm = h.get_content()
    except Exception:
        pass
    if not body and htm:
        body = html_to_text(htm)
    if not body and not msg.is_multipart():
        try:
            body = msg.get_content() if isinstance(msg.get_content(), str) else ""
        except Exception:
            body = decode_bytes(msg.get_payload(decode=True))
    try:
        for part in msg.iter_attachments():
            data = part.get_payload(decode=True)
            if data is None and part.get_content_type() == "message/rfc822":
                inner = part.get_payload()
                inner = inner[0] if isinstance(inner, list) and inner else inner
                data = inner.as_bytes() if hasattr(inner, "as_bytes") else b""
                atts.append(((part.get_filename() or tr("messaggio inoltrato")) + ".eml", data))
                continue
            atts.append((part.get_filename() or f"allegato.{part.get_content_subtype()}", data or b""))
    except Exception:
        pass
    date = None
    try:
        d = msg["date"].datetime if msg["date"] is not None else None
        date = iso(d)
    except Exception:
        pass
    hdr = "\n".join(f"{k}: {v}" for k, v in list(msg.items())[:60])
    return {"sender": addr_list(msg["from"]), "to": addr_list(msg["to"]), "cc": addr_list(msg["cc"]),
            "subject": str(msg["subject"] or ""), "date": date, "body": body, "html": htm,
            "headers": hdr, "atts": atts}


def process_eml_file(ctx, f, disp, origin, depth, parent):
    raw = Path(f).read_bytes()
    fmt = "EML"
    if disp.lower().endswith(".emlx"):      # Apple Mail: lunghezza, messaggio, plist
        m = re.match(rb"\s*(\d+)\s*\n", raw)
        if m:
            raw = raw[m.end():m.end() + int(m.group(1))]
        fmt = "EMLX"
    p = parse_email_bytes(raw)
    add_message(ctx, origin, parent, fmt, "", disp, p["sender"], p["to"], p["cc"], p["subject"],
                p["date"], p["body"], p["html"], p["headers"], p["atts"], depth)
    return 1


def process_mbox(ctx, f, disp, origin, depth, parent):
    box = mailbox.mbox(str(f), create=False)
    n = 0
    try:
        for key in box.iterkeys():
            try:
                raw = box.get_bytes(key)
            except Exception:
                continue
            p = parse_email_bytes(raw)
            add_message(ctx, origin, parent, "mbox", "", disp, p["sender"], p["to"], p["cc"],
                        p["subject"], p["date"], p["body"], p["html"], p["headers"], p["atts"], depth)
            n += 1
    finally:
        box.close()
    return n


def pff_text(m):
    body = ""
    for getter, conv in ((lambda: m.plain_text_body, decode_bytes),
                         (lambda: m.html_body, lambda b: html_to_text(decode_bytes(b))),
                         (lambda: m.rtf_body, lambda b: fa.rtf_text(decode_bytes(b)))):
        try:
            v = getter()
        except Exception:
            v = None
        if v:
            body = conv(v)
            if body.strip():
                break
    try:
        h = m.html_body
    except Exception:
        h = None
    return body, decode_bytes(h) if h else ""


def pff_recipients(m):
    to = []
    try:
        rc = m.recipients
        n = rc.number_of_sub_items if rc is not None else 0
        for i in range(n):
            it = rc.get_sub_item(i)
            name = addr = None
            for rsi in range(it.number_of_record_sets):
                r = it.get_record_set(rsi)
                for e in range(r.number_of_entries):
                    en = r.get_entry(e)
                    try:
                        if en.entry_type == 0x3001:
                            name = en.get_data_as_string()
                        elif en.entry_type in (0x39FE, 0x3003) and not addr:
                            addr = en.get_data_as_string()
                    except Exception:
                        pass
            if name or addr:
                to.append(f"{name} <{addr}>" if name and addr and name != addr else (addr or name))
    except Exception:
        pass
    return ", ".join(to)


def process_pst(ctx, f, disp, origin, depth, parent):
    try:
        import pypff
    except ImportError:
        ctx.c["PST non letti (manca libpff)"] += 1
        return 0
    pf = pypff.file()
    pf.open(str(f))
    n = 0
    try:
        stack = [(pf.get_root_folder(), "")]
        while stack:
            fo, path = stack.pop()
            try:
                for i in range(fo.number_of_sub_folders):
                    sf = fo.get_sub_folder(i)
                    stack.append((sf, (path + "/" + (sf.name or "")).strip("/")))
            except Exception:
                pass
            try:
                nm = fo.number_of_sub_messages
            except Exception:
                nm = 0
            for i in range(nm):
                try:
                    m = fo.get_sub_message(i)
                    headers = m.transport_headers or ""
                    hp = email.message_from_string(headers, policy=email.policy.default) if headers else None
                    sender = (addr_list(hp["from"]) if hp is not None and hp["from"] else "") or (m.sender_name or "")
                    to = (addr_list(hp["to"]) if hp is not None and hp["to"] else "") or pff_recipients(m)
                    cc = addr_list(hp["cc"]) if hp is not None and hp["cc"] else ""
                    date = iso(m.delivery_time) or iso(m.client_submit_time) or iso(m.creation_time)
                    body, htm = pff_text(m)
                    atts = []
                    for k in range(m.number_of_attachments):
                        try:
                            a = m.get_attachment(k)
                            size = a.size or 0
                            data = a.read_buffer(size) if size else b""
                            atts.append((a.long_filename or f"allegato_{k + 1}", data))
                        except Exception:
                            continue
                    folder = re.sub(r"^Top of (Outlook data file|Personal Folders)/?", "", path) or path
                    add_message(ctx, origin, parent, "PST/OST", folder, disp, sender, to, cc,
                                m.subject, date, body, htm, headers, atts, depth)
                    n += 1
                except Exception:
                    ctx.c["messaggi non leggibili"] += 1
    finally:
        pf.close()
    return n


def process_msg_file(ctx, f, disp, origin, depth, parent):
    """Messaggio Outlook .msg (OLE): proprietà MAPI principali e allegati."""
    try:
        import pyolecf
    except ImportError:
        return 0
    of = pyolecf.file()
    of.open(str(f))
    try:
        root = of.root_item
        props = {}

        def read_item(it):
            try:
                return it.read(it.size)
            except Exception:
                return b""

        def strval(name, data):
            if name.endswith("001F"):
                return data.decode("utf-16-le", "replace").rstrip("\x00")
            if name.endswith("001E"):
                return decode_bytes(data).rstrip("\x00")
            return data
        atts = []
        for i in range(root.number_of_sub_items):
            it = root.get_sub_item(i)
            nm = it.name or ""
            if nm.startswith("__substg1.0_"):
                props[nm[12:16].upper()] = strval(nm.upper(), read_item(it))
            elif nm.startswith("__attach_version1.0_"):
                ap = {}
                for j in range(it.number_of_sub_items):
                    s = it.get_sub_item(j)
                    sn = s.name or ""
                    if sn.startswith("__substg1.0_"):
                        ap[sn[12:16].upper()] = strval(sn.upper(), read_item(s))
                aname = ap.get("3707") or ap.get("3704") or "allegato"
                data = ap.get("3701") if isinstance(ap.get("3701"), bytes) else b""
                atts.append((aname if isinstance(aname, str) else "allegato", data))
        g = lambda k: props.get(k) if isinstance(props.get(k), str) else ""
        headers = g("007D")
        hp = email.message_from_string(headers, policy=email.policy.default) if headers else None
        sender = (addr_list(hp["from"]) if hp is not None and hp["from"] else "") or \
            " ".join(x for x in (g("0C1A"), f"<{g('0C1F') or g('5D01')}>" if (g('0C1F') or g('5D01')) else "") if x)
        to = (addr_list(hp["to"]) if hp is not None and hp["to"] else "") or g("0E04")
        cc = (addr_list(hp["cc"]) if hp is not None and hp["cc"] else "") or g("0E03")
        date = None
        if hp is not None and hp["date"] is not None:
            try:
                date = iso(hp["date"].datetime)
            except Exception:
                pass
        body = g("1000")
        htm = props.get("1013")
        htm = decode_bytes(htm) if isinstance(htm, bytes) else (htm or "")
        if not body and htm:
            body = html_to_text(htm)
        add_message(ctx, origin, parent, "MSG", "", disp, sender, to, cc, g("0037"), date, body, htm,
                    headers, atts, depth)
        return 1
    finally:
        of.close()


def run_archivi(case, con):
    ctx = Ctx(case, con, "Archivi e posta")
    con.execute("DELETE FROM xitems WHERE kind IN ('archivio','allegato')")
    con.execute("DELETE FROM mail")
    con.execute("DELETE FROM doc_text WHERE source IN ('posta') OR (source='x' AND inode IN "
                "(SELECT CAST(id AS TEXT) FROM xitems WHERE kind IN ('archivio','allegato')))")
    con.execute("DELETE FROM anomalies WHERE kind='cifrato' AND detail LIKE 'archivio%'")
    for sub in ("archivi", "posta"):
        fa.rmtree_force(case.root / X_ROOT / sub)
    con.commit()
    rows = []
    for part, inode, deleted, path in fs_rows(con, "1=1"):
        n = Path(path).name
        low = n.lower()
        if is_archive_name(n) or is_mail_name(n) or \
                (not Path(low).suffix and re.search(r"(?i)(^|/)(mail|imapmail|local folders)/", path)):
            if ":" in n:          # flussi NTFS alternativi
                continue
            rows.append((part, inode, deleted, path))
    # archivi con un'altra estensione: si riconoscono dai primi byte (stessa lettura delle anomalie)
    chosen = {(r[0], str(r[1])) for r in rows}
    hr = HeadReader(case)
    n_scan = 0
    for part, inode, deleted, path in fs_rows(con, "1=1"):
        n = Path(path).name
        if ":" in n or (part, str(inode)) in chosen:
            continue
        n_scan += 1
        try:
            _size, head, _t = hr.read(part, inode, 512)
        except Exception:
            continue
        if archive_by_content(n, head):
            rows.append((part, inode, deleted, path))
            chosen.add((part, str(inode)))
            ctx.c["archivi riconosciuti dal contenuto"] += 1
        if n_scan % 20000 == 0:
            ctx.say(tr("controllo del contenuto: {n_scan} file").format(n_scan=n_scan))
    exe = seven_zip()
    if not exe:
        print(tr("7-Zip non trovato: apro solo ZIP e tar (reinstalla RepertIA o 'Aggiorna strumenti')."),
              flush=True)
    else:
        case.meta.setdefault("tool_versions", {})["7-zip"] = fa.tool_version([exe]) or exe
    print(tr("Archivi e posta: {v1} file da esaminare...").format(v1=len(rows)), flush=True)
    for k, (part, inode, deleted, path) in enumerate(rows, 1):
        d = ctx.tmp / f"src_{k}"
        d.mkdir(exist_ok=True)
        f = d / safe_name(Path(path).name, 120)      # 7-Zip ricava dal nome quello del contenuto (.tar.gz)
        try:
            size = copy_fs_file(case, part, inode, f)
        except Exception:
            size = None
        if not size:
            f.unlink(missing_ok=True)
            continue
        head = open(f, "rb").read(512)
        name = Path(path).name.lower()
        if not Path(name).suffix and not head.startswith(b"From ") and not archive_by_content(name, head):
            f.unlink(missing_ok=True)
            continue
        process_container(ctx, f, path, (part, inode, path), 1)
        shutil.rmtree(d, ignore_errors=True)
        ctx.say(tr("{k} di {v1} file · {archivi} archivi, {v2} file contenuti, {messaggi} messaggi, "
                   "{allegati} allegati").format(k=k, v1=len(rows), archivi=ctx.c['archivi'], v2=ctx.c['file in archivi'], messaggi=ctx.c['messaggi'], allegati=ctx.c['allegati']))
    con.commit()
    ctx.close()
    res = {k: v for k, v in ctx.c.items()}
    res.update({"ts": now(), "estratti_byte": ctx.extracted})
    print(tr("Archivi e posta: ") + (", ".join(f"{v} {tr(k)}" for k, v in ctx.c.items()) or tr("nessun archivio o file di posta")),
          flush=True)
    try:
        import pypff
        case.meta.setdefault("tool_versions", {})["libpff"] = str(pypff.get_version())
    except Exception:
        pass
    return res


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
}
FAMILY_EXT = {k: set(v.split()) for k, v in FAMILY_EXT.items()}
KNOWN_EXT = set().union(*FAMILY_EXT.values()) | {"txt", "csv", "html", "htm", "xml", "json", "log",
                                                   "ini", "md", "eml", "vcf", "ics", "bmp", "ico"}
MEDIA_FAM = {"jpg", "png", "gif", "tif", "psd", "webp", "heic", "mp3", "ogg", "flac", "wav", "avi",
             "mov", "mp4", "m4a", "3gp", "mkv"}
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


# ------------------------------------------------------------------ MFT: chi usa un cluster (verifica dei cancellati)

def ntfs_runlist(rec, pos, end):
    """Decodifica una runlist NTFS: [(lcn o None se sparsa, lunghezza in cluster)]."""
    out, lcn = [], 0
    while pos < end:
        h = rec[pos]
        if h == 0:
            break
        nl, no = h & 0x0F, h >> 4
        if not nl or pos + 1 + nl + no > end:
            break
        length = int.from_bytes(rec[pos + 1:pos + 1 + nl], "little")
        if no:
            lcn += int.from_bytes(rec[pos + 1 + nl:pos + 1 + nl + no], "little", signed=True)
            out.append((lcn, length))
        else:
            out.append((None, length))
        pos += 1 + nl + no
    return out


def mft_fixup(rec, sector=512):
    """Record MFT con l'array di aggiornamento applicato; None se non è un record valido («FILE»)."""
    if rec[:4] != b"FILE":
        return None
    uo, uc = struct.unpack_from("<HH", rec, 4)
    if uc < 2 or uo + 2 * uc > len(rec):
        return None
    b = bytearray(rec)
    usn = b[uo:uo + 2]
    for i in range(1, uc):
        p = i * sector - 2
        if p + 2 > len(b) or b[p:p + 2] != usn:
            return None                 # settore scritto a metà: record non affidabile
        b[p:p + 2] = b[uo + 2 * i:uo + 2 * i + 2]
    return b


def mft_record_info(b):
    """(in_uso, record base o 0, sequenza, nome, [(lcn, lunghezza)] di tutti gli attributi non residenti)."""
    seq, = struct.unpack_from("<H", b, 0x10)
    first, flags = struct.unpack_from("<HH", b, 0x14)
    base = struct.unpack_from("<Q", b, 0x20)[0] & 0xFFFFFFFFFFFF
    pos, runs, name, name_ns = first, [], "", 9
    while pos + 16 <= len(b):
        typ, alen = struct.unpack_from("<II", b, pos)
        if typ == 0xFFFFFFFF or alen < 16 or pos + alen > len(b):
            break
        if b[pos + 8]:                                          # non residente
            ro = struct.unpack_from("<H", b, pos + 0x20)[0]
            runs.extend(r for r in ntfs_runlist(b, pos + ro, pos + alen) if r[0] is not None)
        elif typ == 0x30:                                       # $FILE_NAME residente
            vo = struct.unpack_from("<H", b, pos + 0x14)[0]
            v = pos + vo
            if v + 0x42 <= pos + alen:
                nl, ns = b[v + 0x40], b[v + 0x41]
                if not name or (name_ns == 2 and ns != 2):          # preferisce il nome lungo al nome DOS 8.3
                    name = bytes(b[v + 0x42:v + 0x42 + 2 * nl]).decode("utf-16-le", "replace")
                    name_ns = ns
        pos += alen
    return bool(flags & 1), base, seq, name, runs


def mft_cluster_owners(read, mft_size, rec_size, targets, progress=None, step=4 << 20):
    """Una passata sulla MFT: per ogni cluster di `targets` l'elenco dei record (anche liberi, cioè di file cancellati)
    che lo hanno nelle proprie runlist. `read(offset, n)` legge il file $MFT. Restituisce
    {cluster: [(record, in_uso, base, sequenza, nome)]}."""
    import bisect
    tg = sorted(set(targets))
    out = {}
    if not tg or rec_size <= 0:
        return out
    step -= step % rec_size
    off = 0
    while off < mft_size:
        buf = read(off, min(step, mft_size - off))
        if not buf:
            break
        for k in range(0, len(buf) - rec_size + 1, rec_size):
            raw = buf[k:k + rec_size]
            if raw[:4] != b"FILE":
                continue
            b = mft_fixup(raw)
            if b is None:
                continue
            try:
                in_use, base, seq, name, runs = mft_record_info(b)
            except (struct.error, IndexError):
                continue
            hit = None
            for lcn, n in runs:
                i = bisect.bisect_left(tg, lcn)
                while i < len(tg) and tg[i] < lcn + n:
                    hit = hit or []
                    hit.append(tg[i])
                    i += 1
            if hit:
                num = (off + k) // rec_size
                for c in hit:
                    out.setdefault(c, []).append((num, in_use, base, seq, name))
        off += len(buf)
        if progress:
            progress(off, mft_size)
    return out


def pe_raw_end(head):
    """Dove finisce un eseguibile PE secondo le sue intestazioni: (fine dell'ultima sezione, fine della firma
    Authenticode o 0), oppure None. Un PE vero è lungo esattamente così (salvo pochi byte di allineamento o dati
    aggiunti in coda, come negli installatori)."""
    try:
        lfa = struct.unpack_from("<I", head, 0x3C)[0]
        if head[lfa:lfa + 4] != b"PE\x00\x00":
            return None
        nsec, = struct.unpack_from("<H", head, lfa + 6)
        opt, = struct.unpack_from("<H", head, lfa + 20)
        st = lfa + 24 + opt
        if not 0 < nsec <= 96 or st + 40 * nsec > len(head):
            return None
        end = 0
        for i in range(nsec):
            rsz, rptr = struct.unpack_from("<II", head, st + 40 * i + 16)
            if rsz and rptr:
                end = max(end, rptr + rsz)
        magic, = struct.unpack_from("<H", head, lfa + 24)
        dd = lfa + 24 + (96 if magic == 0x10B else 112)
        cert = 0
        if opt >= (dd - lfa - 24) + 5 * 8:
            co, cs = struct.unpack_from("<II", head, dd + 4 * 8)        # directory 4: certificati (offset nel file)
            cert = co + cs if co and cs else 0
        return (end, cert) if end else None
    except struct.error:
        return None


def content_fits(fam, size, head, read_at):
    """Il formato riconosciuto all'inizio di un file è coerente con la sua dimensione e con la sua fine?
    Serve per i file CANCELLATI: se i primi cluster sono stati riusati, l'inizio è di un altro file e la fine (o le
    lunghezze scritte nelle intestazioni) non tornano. `read_at(offset, n)` legge il file. Restituisce
    True (coerente), False (non coerente: il contenuto non è di questo file) o None (formato senza controllo)."""
    if not size:
        return None

    def tail(n):
        try:
            return read_at(max(0, size - n), min(n, size)) or b""
        except Exception:
            return b""

    try:
        if fam == "exe":
            pe = pe_raw_end(head)
            if pe is None:
                return None
            end = max(pe)
            return end <= size <= end + 4096          # dati aggiunti oltre 4 KB (installatori): non dimostrabile
        if fam == "jpg":                              # il JPEG finisce con FF D9 (poi al più zeri o il blocco Samsung «SEFT»)
            t = tail(65536)
            return t.rstrip(b"\0").endswith(b"\xff\xd9") or (b"SEFT" in t[-64:] and b"\xff\xd9" in t)
        if fam == "png":
            return b"IEND\xaeB`\x82" in tail(4096)
        if fam == "gif":
            return tail(4096).rstrip(b"\0").endswith(b"\x3b")
        if fam == "pdf":
            return b"%%EOF" in tail(65536)
        if fam == "zip":
            return b"PK\x05\x06" in tail(65536 + 22)
        if fam in ("wav", "avi", "webp") and head[:4] == b"RIFF":
            n = struct.unpack_from("<I", head, 4)[0] + 8
            return n <= size + 1 and n >= size - 65536
        if fam == "reg" and head[:4] == b"regf" and len(head) >= 0x2C:
            end = 4096 + struct.unpack_from("<I", head, 0x28)[0]
            return end <= size <= end + (1 << 20)
        if fam == "7z" and head[:6] == b"7z\xbc\xaf\x27\x1c" and len(head) >= 32:
            off, ln = struct.unpack_from("<QQ", head, 12)
            return 32 + off + ln <= size
        if fam in ("mp4", "mov", "m4a", "3gp", "heic") and head[4:8] == b"ftyp":
            # scatole di primo livello: devono susseguirsi fino alla fine del file
            pos, k = 0, 0
            while pos < size and k < 64:
                h = head[pos:pos + 16] if pos + 16 <= len(head) else read_at(pos, 16)
                if len(h) < 8:
                    return False
                n = struct.unpack_from(">I", h, 0)[0]
                if n == 1:
                    if len(h) < 16:
                        return False
                    n = struct.unpack_from(">Q", h, 8)[0]
                elif n == 0:                                     # ultima scatola: fino alla fine del file
                    return True
                if n < 8 or not re.fullmatch(rb"[\x20-\x7e]{4}", h[4:8]):
                    return False
                pos += n
                k += 1
            return pos == size if k < 64 else None
    except (struct.error, OSError):
        return None
    return None


# moduli di programmi che usano un'estensione propria ma sono eseguibili PE (risorse di Office .odf, plug-in di Adobe
# .mpp/.api, filtri di Photoshop .8b?, dizionari .lex…): un PE con queste estensioni è normale, non un eseguibile mascherato
VENDOR_PE_EXT = {"odf", "mpp", "api", "lex", "ppi", "flt", "aex", "8bf", "8bi", "8be", "8bx", "8ba", "8by", "8bc", "8li",
                 "8bs", "aip", "apl", "dlu", "bpi", "plugin", "xpt", "x3d", "spi", "vst", "vst3", "ax", "ime", "nls", "tsp"}
# estensioni «da utente» (foto, video, audio, documenti): un eseguibile qui dentro è sempre da segnalare
USER_EXT = (set().union(*(FAMILY_EXT[f] for f in MEDIA_FAM | {"pdf", "rtf"} if f in FAMILY_EXT)) | OOXML |
            {"doc", "xls", "ppt", "txt", "csv", "jpg", "jpeg", "png", "gif", "bmp", "pdf", "mp3", "mp4", "mov", "avi",
             "mkv", "wav", "zip", "rar", "7z", "html", "htm", "eml", "msg", "odt", "ods", "odp", "rtf"}) - VENDOR_PE_EXT
# cartelle di programmi e del sistema (anche dentro Windows.old e le copie nel Cestino): qui un modulo PE con
# un'estensione insolita fa parte di un programma installato
SOFTWARE_PATH = re.compile(r"(?i)(?:^|/)(?:program files(?: \(x86\))?|programdata/(?:microsoft|package cache)|"
                           r"windows/(?:installer|system32|syswow64|winsxs|servicing|softwaredistribution|"
                           r"serviceprofiles/[^/]+/appdata/local/microsoft/windows/deliveryoptimization|microsoft\.net|"
                           r"assembly|immersivecontrolpanel|systemapps)|windowsapps|appdata/local/(?:microsoft|packages)|"
                           r"appdata/roaming/microsoft|root/office\d+|common files|microsoft office)/")
# icone degli installatori: Windows Installer conserva le icone dei programmi come file .exe/.dll rinominati .ico
INSTALLER_ICON = re.compile(r"(?i)(?:^|/)windows/installer/\{[0-9a-f-]{36}\}/[^/]+\.ico$")
# log delle transazioni del registro: iniziano con «regf» come l'alveare
REG_LOG_EXT = {"log", "log1", "log2", "sav", "tm", "blf"}
VIDEO_FAM = {"mov", "mp4", "m4a", "3gp", "mkv", "avi", "ogg"}


class HeadReader:
    """Primi byte (e ultimi, se serve) dei file: pytsk3 se disponibile, altrimenti icat."""
    def __init__(self, case):
        self.case = case
        self.fs = {}
        self.ok = False
        try:
            import pytsk3
            self.pytsk3 = pytsk3
            self.ok = True
        except ImportError:
            self.pytsk3 = None
        self.img = None

    def _fs(self, part):
        if part not in self.fs:
            try:
                pt = self.pytsk3
                if fa.is_e01(self.case.image):
                    import pyewf
                    h = pyewf.handle()
                    h.open(pyewf.glob(self.case.image))

                    class EwfImg(pt.Img_Info):
                        def __init__(s, hh):
                            s._h = hh
                            super().__init__(url="", type=pt.TSK_IMG_TYPE_EXTERNAL)

                        def read(s, off, size):
                            s._h.seek(off)
                            return s._h.read(size)

                        def get_size(s):
                            return s._h.get_media_size()
                    img = EwfImg(h)
                else:
                    img = pt.Img_Info(self.case.image)
                self.fs[part] = pt.FS_Info(img, offset=part * 512)
            except Exception:
                self.fs[part] = None
        return self.fs[part]

    @staticmethod
    def _ntfs_names(f, pt):
        """Nomi ($FILE_NAME) memorizzati nel record MFT, in minuscolo; None se non è un record NTFS."""
        names = None
        try:
            for a in f:
                if int(a.info.type) != int(pt.TSK_FS_ATTR_TYPE_NTFS_FNAME):
                    continue
                names = names or set()
                d = f.read_random(0, a.info.size, a.info.type, a.info.id)
                if len(d) >= 66:
                    names.add(d[66:66 + d[64] * 2].decode("utf-16-le", "replace").lower())
        except Exception:
            return names
        return names

    def _first_block(self, f, pt):
        """Primo blocco (in unità del file system) con dati veri del file; None se i dati sono residenti."""
        try:
            for a in f:
                if int(a.info.type) not in (int(pt.TSK_FS_ATTR_TYPE_NTFS_DATA), int(pt.TSK_FS_ATTR_TYPE_DEFAULT)):
                    continue
                if not int(a.info.flags) & int(pt.TSK_FS_ATTR_NONRES):
                    continue
                for r in a:
                    if int(r.flags) & (int(pt.TSK_FS_ATTR_RUN_FLAG_SPARSE) | int(pt.TSK_FS_ATTR_RUN_FLAG_FILLER)):
                        continue
                    return int(r.addr)
        except Exception:
            pass
        return None

    def _block_allocated(self, part, block):
        """True se il blocco è oggi assegnato a un file, False se libero, None se non lo si capisce."""
        try:
            r = subprocess.run(["blkstat", "-o", str(part), str(self.case.image), str(block)],
                               capture_output=True, timeout=120, stdin=subprocess.DEVNULL,
                               env=fa.tsk_env(self.case, ["blkstat"]))
        except (OSError, subprocess.TimeoutExpired):
            return None
        m = re.search(r"(?m)^(Not )?Allocated\b", r.stdout.decode("utf-8", "replace"))
        return None if not m else not m.group(1)

    def verify_deleted(self, part, inode, name):
        """Una voce CANCELLATA dell'elenco ha ancora il contenuto del proprio file?
        Il nome resta nella cartella anche dopo che il record (inode, MFT) è stato dato a un altro file e i suoi
        cluster a file nuovi: leggere «per inode» darebbe allora il contenuto di un altro file (un .png che
        «contiene» un eseguibile). Risposte:
          ok               record libero (o con lo stesso nome) e primo blocco non riutilizzato
          riassegnato      il record oggi appartiene a un altro file (nome diverso)
          sovrascritto     il primo blocco dei dati oggi è assegnato a un altro file
          non_verificabile mancano gli strumenti per controllare (il risultato va preso con cautela)"""
        if fa.ap.is_apfs_part(part) or not self.ok:
            return "non_verificabile"
        fs = self._fs(part)
        if fs is None:
            return "non_verificabile"
        pt = self.pytsk3
        try:
            f = fs.open_meta(inode=int(str(inode).split("-")[0]))
            meta = f.info.meta
        except Exception:
            return "non_verificabile"
        if meta is None:
            return "non_verificabile"
        alloc = bool(int(meta.flags) & int(pt.TSK_FS_META_FLAG_ALLOC))
        names = self._ntfs_names(f, pt)
        if names:
            if Path(name).name.lower() not in names:
                return "riassegnato"
        elif alloc:
            return "riassegnato"
        if self.is_ntfs(part):
            return "ok"                 # NTFS: i cluster si controllano tutti insieme con una passata sulla MFT (mft_owners)
        blk = self._first_block(f, pt)
        if blk is not None and self._block_allocated(part, blk):
            return "sovrascritto"
        return "ok"

    def is_ntfs(self, part):
        if fa.ap.is_apfs_part(part) or not self.ok:
            return False
        fs = self._fs(part)
        try:
            return fs is not None and bool(int(fs.info.ftype) & int(getattr(self.pytsk3, "TSK_FS_TYPE_NTFS_DETECT", 1)))
        except Exception:
            return False

    def first_cluster(self, part, inode):
        """Primo cluster dei dati del file (None se residenti o non leggibili)."""
        fs = self._fs(part) if self.ok and not fa.ap.is_apfs_part(part) else None
        if fs is None:
            return None
        try:
            return self._first_block(fs.open_meta(inode=int(str(inode).split("-")[0])), self.pytsk3)
        except Exception:
            return None

    def reader(self, part, inode):
        """read(offset, n) sul contenuto del file, anche cancellato (segue le runlist del record); None se non si può."""
        fs = self._fs(part) if self.ok and not fa.ap.is_apfs_part(part) else None
        if fs is None:
            return None
        try:
            f = fs.open_meta(inode=int(str(inode).split("-")[0]))
        except Exception:
            return None

        def rd(off, n):
            try:
                return f.read_random(off, n)
            except Exception:
                return b""
        return rd

    def mft_owners(self, part, clusters, progress=None):
        """Una passata sulla $MFT del volume NTFS: {cluster: [(record, in_uso, base, sequenza, nome)]} per i cluster
        chiesti, compresi i record LIBERI (file cancellati). None se la MFT non si legge."""
        fs = self._fs(part) if self.is_ntfs(part) else None
        if fs is None:
            return None
        try:
            boot = fs.open_meta(inode=7).read_random(0, 512)          # $Boot
            bps, spc = struct.unpack_from("<HB", boot, 11)
            cpr = struct.unpack_from("<b", boot, 0x40)[0]
            rs = 1 << -cpr if cpr < 0 else cpr * bps * spc
            mft = fs.open_meta(inode=0)
            size = int(mft.info.meta.size)
            if not 256 <= rs <= 65536 or not size:
                return None
            return mft_cluster_owners(lambda o, n: mft.read_random(o, n), size, rs, clusters, progress)
        except Exception:
            return None

    def read(self, part, inode, n=4096, tail=0):
        """(dimensione, inizio, fine) del file; dimensione None se sconosciuta."""
        if fa.ap.is_apfs_part(part):
            try:
                return fa.ap.head_tail(self.case, part, inode, n, tail)
            except Exception:
                return None, b"", b""
        if self.ok:
            fs = self._fs(part)
            if fs is not None:
                try:
                    num = int(str(inode).split("-")[0])
                    f = fs.open_meta(inode=num)
                    size = f.info.meta.size if f.info.meta else 0
                    head = f.read_random(0, min(n, size)) if size else b""
                    end = f.read_random(max(0, size - tail), min(tail, size)) if tail and size else b""
                    return size, head, end
                except Exception:
                    pass
        cmd = ["icat", "-o", str(part), self.case.image, str(inode)]
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 stdin=subprocess.DEVNULL)
            head = p.stdout.read(n)
            p.kill()
            p.wait()
        except OSError:
            return None, b"", b""
        return None, head, b""


def check_volumes(case, con):
    """Volumi cifrati: BitLocker (anche To Go), LUKS, FileVault/CoreStorage, APFS cifrato,
    possibili volumi VeraCrypt/TrueCrypt (partizione non leggibile ad alta entropia)."""
    out = []
    try:
        img = ImageFile(case.image)
    except OSError:
        print(tr("Copia forense non raggiungibile: controllo dei volumi saltato."), flush=True)
        return out
    parts = case.meta.get("partitions") or [{"offset": 0, "length_sectors": None, "readable": False}]
    for p in parts:
        if p.get("apfs"):       # volume APFS: cifrato e senza chiave -> si può sbloccare dal caso
            if p["apfs"].get("encrypted") and fa.ap.is_locked(case, p["offset"]):
                v = {"offset": p["offset"], "tipo": tr("APFS cifrato (FileVault)"), "decifrabile": True, "apfs": True,
                     "byte": (p.get("length_sectors") or 0) * 512, "desc": p.get("desc", ""),
                     "nome": p["apfs"].get("name")}
                out.append(v)
                add_anomaly(con, "volume", "volume", p["offset"], None,
                            tr("volume APFS «{v1}» (offset {offset})").format(v1=p['apfs'].get('name'), offset=p['offset']),
                            tr("volume APFS cifrato (FileVault): si sblocca con la password o la chiave di ripristino"),
                            real=tr("APFS cifrato"), size=v["byte"], sev=3)
                print(tr("Anomalie: volume APFS cifrato «{v1}»").format(v1=p['apfs'].get('name')), flush=True)
            continue
        start, length = part_bounds(case, p, img)
        if length <= 0:
            continue
        head = img.pread(start, 65536)
        kind = None
        region = Region(img, start, length)
        try:
            import pybde
            if pybde.check_volume_signature_file_object(region):
                kind = "BitLocker"
        except Exception:
            if head[3:11] == b"-FVE-FS-":
                kind = "BitLocker"
        if not kind and head[:6] == b"LUKS\xba\xbe":
            kind = "LUKS" if head[6:8] == b"\x00\x01" else "LUKS2"
        if not kind:
            try:
                import pyfvde
                region.seek(0)
                if pyfvde.check_volume_signature_file_object(region):
                    kind = "FileVault (CoreStorage)"
            except Exception:
                pass
        if not kind and p.get("apfs"):
            enc = [v for v in p["apfs"].get("volumes", []) if v.get("encrypted")]
            if enc:
                kind = tr("APFS cifrato (FileVault)")
        if not kind and not p.get("readable") and len(head) >= 65536 and entropy(head[512:]) > 7.95:
            kind = tr("possibile VeraCrypt/TrueCrypt")
        if kind:
            dec_ok = kind in ("BitLocker", "LUKS")      # LUKS2 non è supportato da libluksde
            v = {"offset": p["offset"], "tipo": kind, "byte": length, "desc": p.get("desc", ""),
                 "decifrabile": dec_ok}
            out.append(v)
            add_anomaly(con, "volume", "volume", p["offset"], None,
                        tr("partizione all'offset {offset} ({v1})").format(offset=p['offset'], v1=p.get('desc') or '').strip(),
                        f"volume {kind}" + (tr(": si può decifrare con la chiave di ripristino o la password")
                                            if dec_ok else ""), real=kind, size=length, sev=3)
            print(tr("Anomalie: volume cifrato {kind} all'offset {offset}").format(kind=kind, offset=p['offset']), flush=True)
    img.close()
    return out


def quick_encrypted(case):
    """Controllo rapido (solo le firme) dei volumi cifrati NON APFS, fatto già alla preparazione del caso:
    un BitLocker To Go, per esempio, viene letto da Sleuth Kit come un FAT senza contenuto utile e senza
    questo controllo l'operatore non se ne accorgerebbe."""
    out = []
    img = ImageFile(case.image)
    try:
        for p in case.meta.get("partitions") or [{"offset": 0, "length_sectors": None}]:
            if p.get("apfs"):
                continue
            start, length = part_bounds(case, p, img)
            if length <= 0:
                continue
            head = img.pread(start, 65536)
            region = Region(img, start, length)
            kind = None
            try:
                import pybde
                if pybde.check_volume_signature_file_object(region):
                    kind = "BitLocker"
            except Exception:
                if head[3:11] == b"-FVE-FS-":
                    kind = "BitLocker"
            if not kind and head[:6] == b"LUKS\xba\xbe":
                kind = "LUKS" if head[6:8] == b"\x00\x01" else "LUKS2"
            if not kind:
                try:
                    import pyfvde
                    region.seek(0)
                    if pyfvde.check_volume_signature_file_object(region):
                        kind = "FileVault (CoreStorage)"
                except Exception:
                    pass
            if kind:
                out.append({"offset": p["offset"], "tipo": kind, "byte": length, "desc": p.get("desc", ""),
                            "decifrabile": kind in ("BitLocker", "LUKS")})
    finally:
        img.close()
    return out


def run_anomalie(case, con):
    ctx = Ctx(case, con, "Anomalie")
    con.execute("DELETE FROM anomalies WHERE kind IN ('volume','estensione','contenitore') OR "
                "(kind='cifrato' AND detail NOT LIKE 'archivio%')")
    con.commit()
    vols = check_volumes(case, con)
    case.meta["volumi_cifrati"] = vols
    hr = HeadReader(case)
    sizes = {}
    nav = case.root / "navigazione.sqlite"
    if nav.exists():
        try:
            nc = sqlite3.connect(f"file:{nav.as_posix()}?mode=ro", uri=True)
            for part, inode, size in nc.execute("SELECT part, inode, size FROM nav WHERE isdir=0"):
                sizes[(part, str(inode))] = size
            nc.close()
        except sqlite3.Error:
            pass
    # prima i file con nome attuale, poi i cancellati: se un inode è già stato guardato come file «vero», la voce
    # cancellata con lo stesso inode è un nome vecchio (record riassegnato) e si salta
    rows = sorted(fs_rows(con, "1=1"), key=lambda r: r[2] or 0)
    if not hr.ok:
        print(tr("pytsk3 non disponibile: leggo l'inizio dei file con icat (più lento); "
              "per i file cancellati il contenuto non è verificabile."), flush=True)
    print(tr("Anomalie: controllo il contenuto di {v1} file...").format(v1=len(rows)), flush=True)
    seen = set()
    c = Counter()
    pending = []                # cancellati NTFS da confermare con la passata sulla MFT

    def flag(kind, part, inode, path, detail, ext, label, size, deleted, sev, fam=None, head=b""):
        """Registra l'anomalia. Per un file CANCELLATO prima verifica che il contenuto letto sia ancora il suo:
        record non riassegnato, contenuto coerente con dimensione e fine del file (content_fits) e, su NTFS, primo
        cluster non usato da nessun altro record della MFT, nemmeno di un altro file cancellato (mft_owners)."""
        if deleted:
            v = hr.verify_deleted(part, inode, Path(path).name)
            if v in ("riassegnato", "sovrascritto"):
                c["ignorati_" + v] += 1
                return False
            if v == "ok" and fam:
                rd = hr.reader(part, inode)
                fit = content_fits(fam, size, head, rd) if rd else None
                if fit is False:
                    c["ignorati_incoerente"] += 1
                    return False
                if hr.is_ntfs(part):
                    blk = hr.first_cluster(part, inode)
                    if blk is not None:
                        pending.append((blk, int(str(inode).split("-")[0]),
                                        (kind, "fs", part, inode, path, detail + tr(" · file cancellato"), ext, label, size,
                                         deleted, sev)))
                        return True
            if v == "ok":
                detail += tr(" · file cancellato")
            else:
                detail += tr(" · file cancellato: contenuto non verificabile")
                sev = min(sev, 1)
        add_anomaly(con, kind, "fs", part, inode, path, detail, ext, label, size, deleted, sev)
        c[kind] += 1
        return True

    for k, (part, inode, deleted, path) in enumerate(rows, 1):
        name = Path(path).name
        if ":" in name or (part, inode) in seen:
            continue
        seen.add((part, inode))
        ext = Path(name).suffix.lower().lstrip(".")
        want_tail = ext == "pdf" and hr.ok
        size, head, tail = hr.read(part, inode, 65536 if ext in SUSPECT_EXT or ext not in KNOWN_EXT else 4096,
                                   tail=65536 if want_tail else 0)
        if size is None:
            size = sizes.get((part, str(inode)))
        if not head:
            continue
        fam, label = detect_sig(head)
        if fam:
            fam_ok = ext in FAMILY_EXT.get(fam, set())
            if fam == "ole" and ext in OOXML:
                flag("cifrato", part, inode, path, tr("documento Office protetto da "
                     "password (contenitore cifrato al posto del formato .%s)") % ext,
                     ext, label, size, deleted, 2, fam, head)
            elif fam == "zip" and len(head) > 8 and head[6] & 1 and ext not in OOXML and not con.execute(
                    "SELECT 1 FROM anomalies WHERE kind='cifrato' AND source='fs' AND part=? AND inode=?",
                    (part, str(inode))).fetchone():
                flag("cifrato", part, inode, path, tr("archivio ZIP protetto da password"),
                     ext, label, size, deleted, 2, fam, head)
            elif fam == "pdf" and (b"/Encrypt" in head or b"/Encrypt" in tail):
                flag("cifrato", part, inode, path, tr("PDF protetto da password o con "
                     "restrizioni"), ext, label, size, deleted, 1, fam, head)
            elif fam in ("dmgenc", "luks"):
                flag("cifrato", part, inode, path, label, ext, label, size, deleted, 3, fam, head)
            if not fam_ok and ext in KNOWN_EXT and not (fam == "ole" and ext in OOXML):
                exe_like = fam in ("exe", "elf", "macho")
                user_ext = ext in USER_EXT
                soft = bool(SOFTWARE_PATH.search(path))
                if ext in GENERIC_EXT and not exe_like:
                    continue        # estensione generica (dat, bin, db, tmp…): il contenuto può essere qualunque cosa
                if fam == "exe" and (ext in VENDOR_PE_EXT or INSTALLER_ICON.search(path)):
                    c["normali_moduli"] += 1        # modulo di un programma (Office .odf, Adobe .mpp, icone degli installatori)
                    continue
                if exe_like and soft and not user_ext:
                    c["normali_moduli"] += 1        # modulo PE nelle cartelle dei programmi o di Windows
                    continue
                if fam == "reg" and ext in REG_LOG_EXT:
                    c["normali_registro"] += 1      # log delle transazioni del registro (BCD.LOG, ….LOG1)
                    continue
                sev = (2 if ext in GENERIC_EXT else 3) if exe_like else \
                    2 if (fam in MEDIA_FAM | DOC_FAM | {"rar", "7z", "gz", "pst", "sqlite"}) else 1
                note = ""
                ext_fam = next((f for f, es in FAMILY_EXT.items() if ext in es), None)
                if fam == "zip" and ext in FAMILY_EXT["ole"] or fam == "ole" and ext in FAMILY_EXT["zip"]:
                    sev = 1
                elif fam in IMAGE_FAM and ext in IMAGE_EXT:
                    sev, note = 1, tr(" (formato immagine diverso da quello indicato)")
                elif fam in MEDIA_FAM and ext_fam in MEDIA_FAM:
                    sev, note = 1, tr(" (foto/video/audio con l'estensione di un altro formato multimediale)")
                elif exe_like and ext in GENERIC_EXT:
                    sev, note = (1 if soft else 2), tr(" (eseguibile in un file con estensione generica)")
                elif exe_like:
                    note = tr(" (eseguibile mascherato)")
                elif ext_fam == "exe" and fam in MEDIA_FAM:
                    note = tr(" (foto/video/audio con l'estensione di un programma: possibile occultamento)")
                elif ext_fam == "exe":
                    sev, note = 1, tr(" (non è un eseguibile)")
                flag("estensione", part, inode, path, tr("estensione .{ext} ma il contenuto è {label}{note}").format(ext=ext, label=label, note=note),
                     ext, label, size, deleted, sev, fam, head)
        elif ext in SUSPECT_EXT and size and size >= (1 << 20) and size % 512 == 0 and \
                len(head) >= 65536 and entropy(head) > 7.995:
            flag("contenitore", part, inode, path,
                 tr("{v1} MB di dati casuali senza formato riconoscibile: possibile contenitore cifrato "
                    "(VeraCrypt/TrueCrypt)").format(v1=size >> 20), ext, tr("dati ad alta entropia"),
                 size, deleted, 2)
        if k % 2000 == 0:
            con.commit()
            ctx.say(tr("{k} di {v1} file · {estensione} estensioni false, {cifrato} protetti, {contenitore} "
                       "possibili contenitori").format(k=k, v1=len(rows), estensione=c['estensione'], cifrato=c['cifrato'], contenitore=c['contenitore']))
    # cancellati su NTFS: il primo cluster non deve comparire nelle runlist di nessun altro record della MFT
    # (nemmeno libero: un file creato e poi cancellato a sua volta dopo il nostro lascia lì i propri dati)
    by_part = {}
    for blk, rec, args in pending:
        by_part.setdefault(args[2], []).append((blk, rec, args))
    for part, items in by_part.items():
        print(tr("Anomalie: controllo nella MFT (offset {part}) i cluster di {v1} file cancellati...").format(part=part, v1=len(items)), flush=True)
        owners = hr.mft_owners(part, [x[0] for x in items],
                               progress=lambda done, tot: ctx.say(tr("MFT {v1}%").format(v1=done * 100 // max(tot, 1))))
        for blk, rec, args in items:
            if owners is None:                  # MFT non leggibile: si ripiega sullo stato del cluster nel volume
                if hr._block_allocated(part, blk):
                    c["ignorati_sovrascritto"] += 1
                    continue
            elif any(o[0] != rec and o[2] != rec for o in owners.get(blk, [])):
                c["ignorati_riusato"] += 1
                continue
            add_anomaly(con, *args)
            c[args[0]] += 1
    con.commit()
    ctx.close()
    ign = sum(c[k] for k in ("ignorati_riassegnato", "ignorati_sovrascritto", "ignorati_riusato", "ignorati_incoerente"))
    res = {"file": len(seen), "estensione": c["estensione"], "cifrato": c["cifrato"],
           "contenitore": c["contenitore"], "volumi": len(vols), "ts": now(),
           "cancellati_ignorati": ign, "ignorati_riassegnato": c["ignorati_riassegnato"],
           "ignorati_sovrascritto": c["ignorati_sovrascritto"], "ignorati_riusato": c["ignorati_riusato"],
           "ignorati_incoerente": c["ignorati_incoerente"], "normali_moduli": c["normali_moduli"],
           "normali_registro": c["normali_registro"]}
    print(tr("Anomalie: {estensione} estensioni false, {cifrato} file protetti, {contenitore} possibili "
             "contenitori cifrati, {v1} volumi cifrati").format(estensione=c['estensione'], cifrato=c['cifrato'], contenitore=c['contenitore'], v1=len(vols)), flush=True)
    if ign:
        print(tr("Anomalie: {ign} voci di file cancellati non considerate perché il contenuto letto non è "
                 "più quello del file ({ignorati_riassegnato} con record riassegnato a un altro file, "
                 "{ignorati_sovrascritto} con dati riscritti da file presenti, {ignorati_riusato} con dati "
                 "riusati da un altro file cancellato, {ignorati_incoerente} con contenuto non coerente con "
                 "la dimensione o la fine del file).").format(ign=ign, ignorati_riassegnato=c['ignorati_riassegnato'], ignorati_sovrascritto=c['ignorati_sovrascritto'], ignorati_riusato=c['ignorati_riusato'], ignorati_incoerente=c['ignorati_incoerente']), flush=True)
    if c["normali_moduli"] or c["normali_registro"]:
        print(tr("Anomalie: non segnalati {normali_moduli} moduli di programmi con estensione propria (es. "
                 ".odf di Office, .mpp di Adobe, icone degli installatori) e {normali_registro} log del "
                 "registro.").format(normali_moduli=c['normali_moduli'], normali_registro=c['normali_registro']), flush=True)
    return res


# ------------------------------------------------------------------ artefatti

KNOWN_FOLDERS = {
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "C:\\Windows\\System32",
    "{6D809377-6AF0-444B-8957-A3773F02200E}": "C:\\Program Files",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "C:\\Program Files (x86)",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "C:\\Windows",
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": "C:\\Windows\\SysWOW64",
    "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": N_("Menu Start (comune)"),
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": N_("Menu Start (utente)"),
    "{9E3995AB-1F9C-4F13-B827-48B24B6C7174}": N_("Barra delle applicazioni"),
}
JUMP_APPS = {"1b4dd67f29cb1962": N_("Esplora file"), "9b9cdc69c1c24e2b": N_("Blocco note (64 bit)"),
             "a7bd71699cd38d1c": "Word", "adecfb853d77462a": "Word", "d00655d2aa12ff6d": "PowerPoint",
             "b8ab77100df80ab2": "Excel", "fb3b0dbfee58fac8": "Word", "5f7b5f1e01b83767": N_("Accesso rapido"),
             "f01b4d95cf55d32a": N_("Esplora file"), "918e0ecb43d17e23": N_("Blocco note"),
             "9839aec31243a928": "Microsoft Excel", "f5ac5390b9115fdb": "PowerPoint",
             "6824f4a902c78fbd": "Firefox", "5d696d521de238c3": "Chrome", "7e4dca80246863e3": N_("Pannello di controllo")}


class Art:
    def __init__(self, ctx):
        self.ctx, self.con = ctx, ctx.con
        self.n = Counter()

    def add(self, cat, ts, title, detail="", user="", src=None, data=None):
        part, inode, path = src if src else (None, None, None)
        inst = getattr(self.ctx, "win_inst", "")
        if inst:            # artefatto di un'installazione di Windows diversa da quella principale (Windows.old…)
            title = f"[{inst}] {title}"
            data = dict(data or {}, installazione=inst)
        self.con.execute("INSERT INTO artifacts(cat, ts, title, detail, user, src_path, part, inode, "
                         "data) VALUES (?,?,?,?,?,?,?,?,?)",
                         (cat, ts, str(title)[:500], str(detail or "")[:4000], user or "", path, part,
                          str(inode) if inode is not None else None,
                          json.dumps(data, ensure_ascii=False, default=str) if data else None))
        self.n[cat] += 1


def find_files(con, part, like, deleted_ok=False):
    return con.execute("SELECT part, inode, deleted, path FROM files WHERE part=? AND type LIKE '%r' "
                       "AND lower(path) LIKE ? ESCAPE '\\' " + ("" if deleted_ok else "AND deleted=0 ") +
                       "ORDER BY path", (part, like)).fetchall()


def fetch(ctx, part, inode, path, limit=1 << 30):
    f = ctx.tmp / f"a_{part}_{safe_name(str(inode), 40)}_{safe_name(Path(path).name, 60)}"
    if f.exists():
        return f
    try:
        n = copy_fs_file(ctx.case, part, inode, f, limit)
    except Exception:
        return None
    return f if n else None


def user_of(path):
    m = re.match(r"(?i)(?:[^/]+/){0,3}?(?:users|documents and settings|home)/([^/]+)/", path)
    if m:
        return m.group(1)
    if re.match(r"(?i)root/", path):
        return "root"
    return ""


def rk(root, path):
    try:
        return root.get_sub_key_by_path(path) if root is not None else None
    except Exception:
        return None


def rv(key, name, default=None):
    """Valore del registro con il tipo giusto (stringa, intero, lista, byte)."""
    if key is None:
        return default
    try:
        v = key.get_value_by_name(name)
    except Exception:
        return default
    if v is None:
        return default
    try:
        t = v.type
        if t in (1, 2):
            return v.get_data_as_string()
        if t in (4, 5, 11):
            return v.get_data_as_integer()
        if t == 7:
            return v.get_data_as_multi_string()
        return v.data
    except Exception:
        try:
            return v.data
        except Exception:
            return default


def subkeys(k):
    try:
        return list(k.sub_keys) if k is not None else []
    except Exception:
        return []


def lw(k):
    try:
        return iso(k.last_written_time)
    except Exception:
        return None


def sz(v):
    if isinstance(v, bytes):
        try:
            return v.decode("utf-16-le").split("\x00")[0]
        except UnicodeDecodeError:
            return ""
    return v if isinstance(v, str) else ("" if v is None else str(v))


def local_to_utc(case, naive):
    """Data in ora locale del dispositivo ('AAAA-MM-GGTHH:MM:SS', senza fuso) in UTC, con il fuso del dispositivo
    registrato nel caso; senza fuso resta com'è con il suffisso LOCALE, così l'interfaccia non la spaccia per UTC."""
    if not naive:
        return naive
    tz = (case.meta.get("fuso_dispositivo") or {}).get("tz")
    if tz:
        try:
            from zoneinfo import ZoneInfo
            d = dt.datetime.strptime(naive, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=ZoneInfo(tz))
            return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        except Exception:
            pass
    return naive + LOCALE


def open_hive(path):
    import pyregf
    f = pyregf.file()
    f.open(str(path))
    return f, f.get_root_key()


# ------------------------------------------------------------------ registro: file di log delle transazioni
#
# Windows non scrive subito le modifiche nel file principale dell'alveare (SAM, SYSTEM, SOFTWARE, NTUSER.DAT…):
# le mette prima nei file .LOG1/.LOG2 (o .LOG) accanto e li "riversa" nell'alveare solo ogni tanto. In una copia
# forense l'alveare è quindi spesso indietro rispetto a ciò che il sistema vedeva (contatori e date di accesso del
# SAM, programmi e chiavi recenti). libregf non legge i log: qui si applicano a una copia di lavoro dell'alveare.
# Formato: Maxim Suhanov, «Windows registry file format specification» (log nuovo HvLE, Windows 8.1+, e vecchio DIRT).

_M32_SEED = 0x82EF4D887A4E55C5


def _marvin32(buf):
    """Marvin32 (hash 1 e 2 dei record HvLE), con il seme usato dal registro."""
    lo, hi = _M32_SEED & 0xFFFFFFFF, (_M32_SEED >> 32) & 0xFFFFFFFF
    m = 0xFFFFFFFF

    def rotl(v, n):
        return ((v << n) | (v >> (32 - n))) & m

    def mix(v):
        nonlocal lo, hi
        lo = (lo + v) & m
        hi ^= lo
        lo = (rotl(lo, 20) + hi) & m
        hi = (rotl(hi, 9) ^ lo) & m
        lo = (rotl(lo, 27) + hi) & m
        hi = rotl(hi, 19)

    n = len(buf)
    for i in range(0, n - n % 4, 4):
        mix(struct.unpack_from("<I", buf, i)[0])
    r = n % 4
    last = 0x80 << (8 * r)                      # byte 0x80 dopo gli ultimi 0-3 byte (little endian)
    for j, byte in enumerate(buf[n - r:] if r else b""):
        last |= byte << (8 * j)
    mix(last & m)
    mix(0)
    return (hi << 32) | lo


def hive_log_entries(data):
    """Record validi di un log nuovo (HvLE) già letto in memoria: [(sequenza, dimensione bin, [(offset, dati)])].
    Si ferma al primo record non valido (hash 1 e 2 non corrispondono, troncato): quelli dopo non sono affidabili."""
    out, off = [], 512
    while off + 40 <= len(data) and data[off:off + 4] == b"HvLE":
        size, _flags, seq, bins, npages = struct.unpack_from("<5I", data, off + 4)
        end = off + size
        if size < 40 + 8 * npages or end > len(data) or bins % 4096:
            break
        h1, h2 = struct.unpack_from("<QQ", data, off + 24)
        if _marvin32(data[off + 40:end]) != h1 or _marvin32(data[off:off + 32]) != h2:
            break
        refs = [struct.unpack_from("<II", data, off + 40 + 8 * i) for i in range(npages)]
        pos = off + 40 + 8 * npages
        if pos + sum(n for _, n in refs) > end:
            break
        pages = []
        for po, pn in refs:
            pages.append((po, data[pos:pos + pn]))
            pos += pn
        out.append((seq, bins, pages))
        off = end
    return out


def _regf_checksum(head):
    x = 0
    for i in range(0, 508, 4):
        x ^= struct.unpack_from("<I", head, i)[0]
    if x == 0xFFFFFFFF:
        x = 0xFFFFFFFE
    elif x == 0:
        x = 1
    return x


def apply_hive_logs(hive_path, log_paths, out_path):
    """Applica i log delle transazioni a una COPIA dell'alveare e la scrive in `out_path`.
    Restituisce un dizionario: {"applicato": bool, "formato": "HvLE"|"DIRT"|None, "record": n, "pagine": n,
    "sequenza_alveare": (primaria, secondaria), "ultima_sequenza": n, "nota": testo}.
    L'alveare originale non si tocca. Se i log non servono o non sono applicabili, "applicato" è False."""
    data = bytearray(Path(hive_path).read_bytes())
    info = {"applicato": False, "formato": None, "record": 0, "pagine": 0, "log": [Path(x).name for x in log_paths]}
    if len(data) < 4096 or data[:4] != b"regf":
        info["nota"] = tr("alveare non valido")
        return info
    prim, sec = struct.unpack_from("<II", data, 4)
    info["sequenza_alveare"] = (prim, sec)
    logs = []
    for lp in log_paths:
        try:
            b = Path(lp).read_bytes()
        except OSError:
            continue
        if len(b) > 520 and b[:4] == b"regf":
            logs.append(b)
    new = {}
    for b in logs:
        if b[512:516] == b"HvLE":
            for seq, bins, pages in hive_log_entries(b):
                new.setdefault(seq, (bins, pages))
    if new:
        info["formato"] = "HvLE"
        todo = sorted(s for s in new if s >= sec)
        if not todo:
            info["nota"] = tr("i log contengono solo record già riportati nell'alveare")
            return info
        if todo[0] != sec:
            info["nota"] = (tr("i log non partono dal punto giusto (alveare alla sequenza {sec}, primo record {v1}): non "
                               "applicati").format(sec=sec, v1=todo[0]))
            return info
        expected, last_bins, pagine, nrec = sec, None, 0, 0
        for seq in todo:
            if seq != expected:
                break
            bins, pages = new[seq]
            for po, pd in pages:
                end = 4096 + po + len(pd)
                if end > len(data):
                    if bins % 4096 or end > 4096 + bins or bins > 0x7FFFFFFF or bins > len(data) + (64 << 20):
                        info["nota"] = tr("pagina fuori dall'alveare: log non coerente, non applicati")
                        return {**info, "applicato": False}
                    data.extend(b"\0" * (4096 + bins - len(data)))
                data[4096 + po:end] = pd
                pagine += 1
            expected, last_bins, nrec = seq + 1, bins, nrec + 1
        struct.pack_into("<II", data, 4, expected, expected)
        struct.pack_into("<I", data, 40, last_bins)
        info.update(applicato=True, record=nrec, pagine=pagine, ultima_sequenza=expected - 1)
    else:
        for b in logs:                                  # log vecchio (Windows XP-8): bitmap DIRT + settori da 512 byte
            if b[512:516] != b"DIRT" or prim == sec:
                continue
            lp, ls = struct.unpack_from("<II", b, 4)
            if lp != ls:
                continue
            hbins = struct.unpack_from("<I", data, 40)[0]
            vlen = hbins // 4096
            area = ((4 + vlen + 511) // 512) * 512
            pos, n = 512 + area, 0
            vec = b[516:516 + vlen]
            for bit in range(vlen * 8):
                if vec[bit // 8] >> (bit % 8) & 1:
                    if pos + 512 > len(b) or 4096 + bit * 512 + 512 > len(data):
                        break
                    data[4096 + bit * 512:4096 + bit * 512 + 512] = b[pos:pos + 512]
                    pos += 512
                    n += 1
            if n:
                struct.pack_into("<II", data, 4, max(prim, sec), max(prim, sec))
                info.update(applicato=True, formato="DIRT", record=1, pagine=n, ultima_sequenza=max(prim, sec))
                break
        if not info["applicato"]:
            info["nota"] = tr("nessun log applicabile") if logs else tr("nessun file di log")
    if info["applicato"]:
        struct.pack_into("<I", data, 508, _regf_checksum(data))
        Path(out_path).write_bytes(bytes(data))
    return info


def fetch_hive(A, ctx, part, inode, path):
    """Copia un alveare del registro e, se accanto ci sono i suoi log delle transazioni (.LOG1/.LOG2/.LOG), li
    applica alla copia di lavoro: così si legge lo stato aggiornato (SAM, NTUSER.DAT…) e non quello dell'ultimo
    riversamento sul file principale. L'originale nella copia forense non cambia; l'operazione viene dichiarata
    tra gli artefatti di sistema. Se i log non servono, non sono applicabili o l'alveare risultante non si apre,
    resta la copia originale."""
    f = fetch(ctx, part, inode, path)
    if not f:
        return f
    deleted = bool(ctx.con.execute("SELECT 1 FROM files WHERE part=? AND inode=? AND deleted=1", (part, str(inode))).fetchone())
    if deleted:
        with open(f, "rb") as fh:
            head = fh.read(4096 + 4)
        ok = head[:4] == b"regf" and head[4096:4100] == b"hbin"
        A.add("sistema", None, tr("Registro: {name} cancellato ").format(name=Path(path).name) + (tr("RECUPERATO") if ok else tr("non recuperabile")),
              tr("{path}: il file risulta cancellato; ").format(path=path) + (tr("il contenuto è ancora un alveare integro (firma regf e primo hbin): "
                                                         "i dati mostrati vengono da questo file cancellato") if ok else
                                                         tr("i suoi cluster contengono altri dati (sovrascritto): non si legge")),
              "", (part, inode, path), {"cancellato": True, "recuperato": ok})
        if not ok:
            f.unlink(missing_ok=True)
            return None
    done = ctx.__dict__.setdefault("hive_logs", {})
    if str(f) in done:
        return done[str(f)]
    done[str(f)] = f
    logs, lognames = [], []
    for suf in (".log1", ".log2", ".log"):
        ino = fa.lookup(ctx.con, part, path.lower() + suf)
        if ino:
            g = fetch(ctx, part, ino, path + suf.upper())
            if g:
                logs.append(g)
                lognames.append(Path(path).name + suf.upper())
    if not logs:
        return f
    out = f.with_name(f.name + ".recuperato")
    try:
        info = apply_hive_logs(f, logs, out)
    except Exception as e:
        info = {"applicato": False, "nota": f"{type(e).__name__}: {e}"}
    info["log"] = lognames
    name = Path(path).name
    if info.get("applicato"):
        try:
            hv, root = open_hive(out)
            ok = root is not None and root.number_of_sub_keys is not None
            hv.close()
        except Exception:
            ok = False
        if not ok:
            info.update(applicato=False, nota=tr("l'alveare aggiornato con i log non si apre: si usa quello originale"))
    if info.get("applicato"):
        done[str(f)] = out
        A.add("sistema", None, tr("Registro: log applicati a {name}").format(name=name),
              tr("{record} record di log ({pagine} pagine) di {v1} sono stati applicati a una copia di "
                 "lavoro di {name} (formato {formato}, sequenza dell'alveare {v2}/{v3} → {v4}). I valori "
                 "mostrati sono quelli aggiornati; il file nella copia forense non è stato modificato.").format(record=info['record'], pagine=info['pagine'], v1=', '.join(info['log']), name=name, formato=info['formato'], v2=info['sequenza_alveare'][0], v3=info['sequenza_alveare'][1], v4=info['ultima_sequenza'] + 1),
              "", (part, inode, path), info)
        return out
    if info.get("nota") and info.get("formato"):
        A.add("sistema", None, tr("Registro: log di {name} non applicati").format(name=name), info["nota"], "", (part, inode, path), info)
    return f


def systemtime(b):
    try:
        y, mo, _, d, h, mi, s, ms = struct.unpack("<8H", b[:16])
        return dt.datetime(y, mo, d, h, mi, s).strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None


def devprop_time(key):
    """Data di un'altra proprietà del dispositivo (USBSTOR Properties\\...\\0064 ecc.)."""
    if key is None:
        return None
    for v in (rv(key, ""), rv(key, "Data")):
        if isinstance(v, bytes) and len(v) >= 8:
            return filetime(struct.unpack("<Q", v[:8])[0])
    for s in subkeys(key):
        t = devprop_time(s)
        if t:
            return t
    return None


def win_system(A, ctx, part, users):
    rows = hive_rows(ctx, part, "windows/system32/config/system")
    if not rows:
        return None
    part, inode, _, path = rows[0]
    f = fetch_hive(A, ctx, part, inode, path)
    if not f:
        return None
    hv, root = open_hive(f)
    src = (part, inode, path)
    cur = rv(rk(root, "Select"), "Current") or 1
    cs = f"ControlSet{int(cur):03d}"
    info = {}
    name = rv(rk(root, f"{cs}\\Control\\ComputerName\\ComputerName"), "ComputerName")
    if name:
        A.add("sistema", None, tr("Nome del computer: {name}").format(name=name), "", "", src, {"nome": name})
        info["nome"] = name
    tz = rk(root, f"{cs}\\Control\\TimeZoneInformation")
    tzn = rv(tz, "TimeZoneKeyName") or rv(tz, "StandardName")
    if tzn:
        A.add("sistema", None, tr("Fuso orario: {v1}").format(v1=sz(tzn)), tr("scostamento {v1} minuti").format(v1=rv(tz, 'Bias')), "", src)
    sd = rv(rk(root, f"{cs}\\Control\\Windows"), "ShutdownTime")
    if isinstance(sd, bytes) and len(sd) >= 8:
        A.add("sistema", filetime(struct.unpack("<Q", sd[:8])[0]), tr("Ultimo spegnimento registrato"), "", "", src)
    # dispositivi USB di memoria
    letters = {}
    md = rk(root, "MountedDevices")
    try:
        for v in (md.values if md is not None else []):
            d = v.data or b""
            try:
                s = d.decode("utf-16-le", "ignore")
            except Exception:
                s = ""
            if v.name.startswith("\\DosDevices\\") and "USBSTOR" in s.upper():
                m = re.search(r"#([^#]+)#\{", s)
                if m:
                    letters[m.group(1).lower()] = v.name[-2:]
    except Exception:
        pass
    for dev in subkeys(rk(root, f"{cs}\\Enum\\USBSTOR")):
        m = re.search(r"Ven_([^&]*)&Prod_([^&]*)(?:&Rev_(.*))?", dev.name)
        vend, prod, rev = (m.group(1), m.group(2), m.group(3)) if m else ("", dev.name, "")
        for ser in subkeys(dev):
            fn = sz(rv(ser, "FriendlyName")) or f"{vend} {prod}".strip()
            props = rk(ser, "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}")
            first = devprop_time(rk(props, "0064")) if props is not None else None
            last_in = devprop_time(rk(props, "0066")) if props is not None else None
            last_out = devprop_time(rk(props, "0067")) if props is not None else None
            serial = ser.name.split("&")[0] if ser.name.endswith("&0") else ser.name
            letter = letters.get(ser.name.lower()) or letters.get(serial.lower(), "")
            det = "; ".join(x for x in (
                tr("numero di serie {serial}").format(serial=serial), f"produttore {vend}" if vend else "", f"modello {prod}",
                f"lettera {letter}" if letter else "", tr("primo collegamento {v1}").format(v1=first.replace('T', ' ')) if first else "",
                tr("ultimo collegamento {v1}").format(v1=last_in.replace('T', ' ')) if last_in else "",
                tr("ultima rimozione {v1}").format(v1=last_out.replace('T', ' ')) if last_out else "") if x)
            A.add("usb", last_in or first or lw(ser), fn, det, "", src,
                  {"seriale": serial, "produttore": vend, "modello": prod, "revisione": rev,
                   "primo": first, "ultimo": last_in, "rimozione": last_out, "lettera": letter,
                   "chiave_scritta": lw(ser)})
    for dev in subkeys(rk(root, f"{cs}\\Enum\\USB")):
        if not dev.name.upper().startswith("VID_"):
            continue
        for ser in subkeys(dev):
            desc = sz(rv(ser, "FriendlyName")) or sz(rv(ser, "DeviceDesc"))
            desc = desc.split(";")[-1] if desc else ""
            svc = sz(rv(ser, "Service"))
            if svc.upper() in ("USBSTOR", "USBHUB", "USBHUB3", "HIDUSB") and not re.search(r"(?i)mtp|phone|apple|android|iphone", desc):
                continue
            mfg = sz(rv(ser, "Mfg")).split(";")[-1]
            A.add("usb", lw(ser), desc or dev.name, tr("{name} · seriale {name2}").format(name=dev.name, name2=ser.name) +
                  (f" · {mfg}" if mfg else "") + (tr(" · servizio {svc}").format(svc=svc) if svc else ""), "", src,
                  {"id": dev.name, "seriale": ser.name, "servizio": svc})
    for itf in subkeys(rk(root, f"{cs}\\Services\\Tcpip\\Parameters\\Interfaces")):
        ip = sz(rv(itf, "DhcpIPAddress")) or ", ".join(x for x in (rv(itf, "IPAddress") or []) if x)
        if not ip or ip == "0.0.0.0":
            continue
        lease = rv(itf, "LeaseObtainedTime")
        A.add("reti", unixtime(lease) if isinstance(lease, int) else lw(itf), tr("Interfaccia di rete: {ip}").format(ip=ip),
              "; ".join(x for x in (f"DHCP {sz(rv(itf, 'DhcpServer'))}" if rv(itf, "DhcpServer") else "",
                                     f"gateway {', '.join(rv(itf, 'DhcpDefaultGateway') or [])}" if rv(itf, "DhcpDefaultGateway") else "",
                                     f"dominio {sz(rv(itf, 'DhcpDomain'))}" if rv(itf, "DhcpDomain") else "",
                                     itf.name) if x), "", src)
    try:
        win_shim_bam(A, root, cs, src)
    except Exception as e:
        print(tr("  ShimCache/BAM: {vname}: {e}").format(vname=type(e).__name__, e=e), flush=True)
    hv.close()
    return info


def win_software(A, ctx, part, users):
    rows = hive_rows(ctx, part, "windows/system32/config/software")
    if not rows:
        return
    part, inode, _, path = rows[0]
    f = fetch_hive(A, ctx, part, inode, path)
    if not f:
        return
    hv, root = open_hive(f)
    src = (part, inode, path)
    cv = rk(root, "Microsoft\\Windows NT\\CurrentVersion")
    if cv is not None:
        prod = sz(rv(cv, "ProductName"))
        ver = sz(rv(cv, "DisplayVersion")) or sz(rv(cv, "ReleaseId"))
        build = sz(rv(cv, "CurrentBuild")) or sz(rv(cv, "CurrentBuildNumber"))
        if prod:
            try:
                if build and int(build) >= 22000 and "Windows 10" in prod:
                    prod = prod.replace("Windows 10", "Windows 11")
            except ValueError:
                pass
            A.add("sistema", unixtime(rv(cv, "InstallDate")) if isinstance(rv(cv, "InstallDate"), int) else None,
                  tr("Sistema operativo: {prod} {ver}").format(prod=prod, ver=ver).strip(),
                  "; ".join(x for x in (f"build {build}" if build else "", f"edizione {sz(rv(cv, 'EditionID'))}" if rv(cv, "EditionID") else "",
                                         tr("proprietario registrato {v1}").format(v1=sz(rv(cv, 'RegisteredOwner'))) if rv(cv, "RegisteredOwner") else "",
                                         f"organizzazione {sz(rv(cv, 'RegisteredOrganization'))}" if rv(cv, "RegisteredOrganization") else "",
                                         tr("data: installazione")) if x), "", src)
    profili = ctx.__dict__.setdefault("profili", {})
    for sidk in subkeys(rk(root, "Microsoft\\Windows NT\\CurrentVersion\\ProfileList")):
        p = sz(rv(sidk, "ProfileImagePath"))
        if p:
            users[sidk.name] = p.replace("/", "\\").split("\\")[-1]

        def ft(hi, lo):
            hi, lo = rv(sidk, hi), rv(sidk, lo)
            return filetime((int(hi) << 32) | int(lo)) if isinstance(hi, int) and isinstance(lo, int) else None
        profili[sidk.name] = {"percorso": p, "caricato": ft("LocalProfileLoadTimeHigh", "LocalProfileLoadTimeLow"),
                              "scaricato": ft("LocalProfileUnloadTimeHigh", "LocalProfileUnloadTimeLow"),
                              "utente": users.get(sidk.name, ""), "origine": (src[0], src[1], src[2])}
    seen = set()
    for base in ("Microsoft\\Windows\\CurrentVersion\\Uninstall",
                 "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"):
        for k in subkeys(rk(root, base)):
            name = sz(rv(k, "DisplayName"))
            if not name or rv(k, "SystemComponent") == 1 or name.lower() in seen:
                continue
            seen.add(name.lower())
            d = sz(rv(k, "InstallDate"))
            ts = f"{d[:4]}-{d[4:6]}-{d[6:8]}T00:00:00" if re.fullmatch(r"\d{8}", d or "") else lw(k)
            A.add("programmi", ts, name, "; ".join(x for x in (
                f"versione {sz(rv(k, 'DisplayVersion'))}" if rv(k, "DisplayVersion") else "",
                sz(rv(k, "Publisher")), f"in {sz(rv(k, 'InstallLocation'))}" if rv(k, "InstallLocation") else "") if x),
                  "", src, {"versione": sz(rv(k, "DisplayVersion")), "editore": sz(rv(k, "Publisher"))})
    for base, lbl in (("Microsoft\\Windows\\CurrentVersion\\Run", "Run"),
                      ("Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce"),
                      ("WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "Run (32 bit)")):
        k = rk(root, base)
        try:
            for v in (k.values if k is not None else []):
                A.add("programmi", lw(k), tr("Avvio automatico: {name}").format(name=v.name), tr("{v1} ({lbl}, tutti gli utenti)").format(v1=sz(rv(k, v.name)), lbl=lbl), "", src)
        except Exception:
            pass
    gw = {}
    for grp in ("Unmanaged", "Managed"):
        for s in subkeys(rk(root, f"Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\{grp}")):
            g = sz(rv(s, "ProfileGuid"))
            mac = rv(s, "DefaultGatewayMac")
            if g and isinstance(mac, bytes) and len(mac) >= 6:
                gw[g.lower()] = ":".join(f"{b:02X}" for b in mac[:6])
    for p in subkeys(rk(root, "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles")):
        name = sz(rv(p, "ProfileName"))
        typ = {0x47: "Wi-Fi", 0x06: "cablata", 0x17: tr("rete mobile"), 0xF3: tr("rete mobile")}.get(rv(p, "NameType"), "rete")
        first = systemtime(rv(p, "DateCreated") or b"")
        last = systemtime(rv(p, "DateLastConnected") or b"")
        ts_net = local_to_utc(ctx.case, last or first)
        mac = gw.get(p.name.lower(), "")
        A.add("reti", ts_net, tr("Rete {typ}: {name}").format(typ=typ, name=name), "; ".join(x for x in (
            tr("primo collegamento {v1} (ora locale)").format(v1=first.replace('T', ' ')) if first else "",
            tr("ultimo collegamento {v1} (ora locale)").format(v1=last.replace('T', ' ')) if last else "",
            tr("MAC del gateway {mac}").format(mac=mac) if mac else "", sz(rv(p, "Description")) if rv(p, "Description") != name else "") if x),
              "", src, {"tipo": typ, "primo": first, "ultimo": last, "gateway_mac": mac, "ora": "locale"})
    for d in subkeys(rk(root, "Microsoft\\Windows Portable Devices\\Devices")):
        fn = sz(rv(d, "FriendlyName"))
        if fn:
            m = re.search(r"(?i)USBSTOR#[^#]+#([^#]+)#", d.name)
            A.add("usb", lw(d), tr("Volume esterno «{fn}»").format(fn=fn), f"seriale {m.group(1)}" if m else d.name, "", src)
    hv.close()


EVTX_DATA_RE = re.compile(r'<Data Name="([^"]+)"[^>]*>([^<]*)</Data>')
EVTX_PROVIDER_RE = re.compile(r'<Provider Name="([^"]+)"')
LOGON_TIPI = {2: N_("interattivo"), 7: N_("sblocco"), 10: N_("remoto (Desktop remoto)"), 11: N_("interattivo con credenziali in cache")}


def evtx_records(path, ids, raw=False, stats=None):
    """Eventi di un file .evtx con l'identificativo in `ids`: [(id, FILETIME, provider, {campo: valore}, recuperato)].
    `recuperato` è True per i record ricavati dallo spazio libero del file (non più tra quelli attivi del registro);
    quelli identici a un record attivo (stesso numero di record, evento e data) si scartano. In `stats` (dict) i
    conteggi: attivi, recuperati, recuperati_doppi, illeggibili, illeggibili_recuperati (record di qualsiasi evento:
    un record illeggibile può essere uno di quelli cercati). Richiede pyevtx (libevtx, incluso con plaso)."""
    import pyevtx
    with open(path, "rb") as fh:
        if fh.read(8) != b"ElfFile\0":
            raise ValueError(tr("non è un registro eventi (file cancellato e sovrascritto?)"))
    st = stats if stats is not None else {}
    for k in ("attivi", "recuperati", "recuperati_doppi", "illeggibili", "illeggibili_recuperati"):
        st.setdefault(k, 0)
    out, attivi = [], set()
    f = pyevtx.file()
    f.open(str(path))
    try:
        groups = ((False, f.number_of_records, f.get_record),
                  (True, getattr(f, "number_of_recovered_records", 0), getattr(f, "get_recovered_record", None)))
        for rec, n, get in groups:
            if get is None:
                continue
            for i in range(n or 0):
                try:
                    r = get(i)
                    eid = int(r.event_identifier) & 0xFFFF
                    t = r.get_written_time_as_integer()
                    key = (getattr(r, "identifier", None), eid, t)
                    if rec and key in attivi:
                        st["recuperati_doppi"] += 1
                        continue
                    if eid not in ids:
                        if not rec:
                            attivi.add(key)
                        st["recuperati" if rec else "attivi"] += 1
                        continue
                    xml = r.xml_string or ""
                    fields = xml if raw else {k: html.unescape(v) for k, v in EVTX_DATA_RE.findall(xml)}
                    m = EVTX_PROVIDER_RE.search(xml)
                    prov = m.group(1) if m else (getattr(r, "source_name", "") or "")
                except Exception:
                    st["illeggibili_recuperati" if rec else "illeggibili"] += 1
                    continue
                if not rec:
                    attivi.add(key)
                st["recuperati" if rec else "attivi"] += 1
                out.append((eid, t, prov, fields, rec))
    finally:
        f.close()
    return out


def evtx_stato(st):
    """Frase sui record di un registro eventi (attivi, recuperati, illeggibili) per la dichiarazione negli artefatti."""
    s = tr("record attivi {v1}").format(v1=st.get('attivi', 0))
    if st.get("recuperati"):
        s += (tr(", record recuperati dallo spazio libero del file {recuperati} (eventi non più nel "
                 "registro, indicati come «recuperato»)").format(recuperati=st['recuperati']))
    if st.get("recuperati_doppi"):
        s += tr(", {recuperati_doppi} recuperati identici a un record attivo e non contati due volte").format(recuperati_doppi=st['recuperati_doppi'])
    ill, ill_r = st.get("illeggibili", 0), st.get("illeggibili_recuperati", 0)
    if ill or ill_r:
        s += (tr("; RECORD ILLEGGIBILI {v1} (attivi {ill}, recuperati {ill_r}): gli eventi che contenevano "
                 "non sono contati").format(v1=ill + ill_r, ill=ill, ill_r=ill_r))
    return s


def win_logons(A, ctx, part, users):
    """Accessi degli utenti dai registri eventi di Windows. Il contatore del SAM non conta gli accessi con account
    Microsoft, PIN o Windows Hello (resta 0): qui si contano gli eventi 4624 di Security.evtx (accesso riuscito:
    tipi 2 interattivo, 10 remoto, 11 con credenziali in cache; 7 = sblocco), 4625 (accesso fallito) e gli eventi
    Winlogon 7001/7002 di System.evtx (inizio/fine della sessione, di solito conservati più a lungo).
    Il risultato va in ctx.accessi ed è usato da win_sam; ogni file letto è dichiarato tra gli artefatti di sistema."""
    acc = ctx.__dict__.setdefault("accessi", {"per_sid": {}, "falliti": {}, "fonti": []})
    try:
        import pyevtx  # noqa: F401
    except ImportError:
        A.add("sistema", None, tr("Accessi dai registri eventi non letti"),
              tr("manca il modulo pyevtx (libevtx): gli accessi degli account restano quelli del SAM"), "", None)
        return
    per = acc["per_sid"]
    for fname, ids in (("security.evtx", {4624, 4625}), ("system.evtx", {7001, 7002})):
        rows = hive_rows(ctx, part, "windows/system32/winevt/logs/" + fname)
        if not rows:
            continue
        p, inode, _, path = rows[0]
        f = fetch(ctx, p, inode, path)
        if not f:
            continue
        st = {}
        try:
            evs = evtx_records(f, ids, stats=st)
        except Exception as e:
            A.add("sistema", None, tr("Registro eventi {name} non leggibile").format(name=Path(path).name), f"{type(e).__name__}: {e}", "",
                  (p, inode, path))
            continue
        tss = [ev[1] for ev in evs if ev[1]]
        dal, al = (filetime(min(tss)), filetime(max(tss))) if tss else (None, None)
        visti, n_ok, n_rec = set(), 0, 0
        for eid, t, prov, d, recuperato in sorted(evs, key=lambda x: x[1] or 0):
            ts = filetime(t)
            if eid == 4624:
                sid = (d.get("TargetUserSid") or "").upper()
                try:
                    tipo = int(d.get("LogonType") or 0)
                except ValueError:
                    continue
                if tipo not in LOGON_TIPI or not sid.startswith("S-1-5-21-"):
                    continue
                # un amministratore con UAC genera due eventi per lo stesso accesso (token normale ed elevato)
                key = (sid, tipo, (t or 0) // 20_000_000)
                if key in visti:
                    continue
                visti.add(key)
                n_ok += 1
                u = per.setdefault(sid, {})
                k = "sblocchi" if tipo == 7 else "accessi"
                u[k] = u.get(k, 0) + 1
                if tipo != 7:
                    u.setdefault("tipi", {})
                    u["tipi"][tr(LOGON_TIPI[tipo])] = u["tipi"].get(tr(LOGON_TIPI[tipo]), 0) + 1
                    if recuperato:
                        u["accessi_recuperati"] = u.get("accessi_recuperati", 0) + 1
                        n_rec += 1
                    u["primo"] = u.get("primo") or ts
                    u["ultimo"] = ts
                    u["nome"] = d.get("TargetUserName") or u.get("nome")
            elif eid == 4625:
                nome = (d.get("TargetUserName") or "").lower()
                if nome and nome != "-":
                    fl = acc["falliti"].setdefault(nome, {"n": 0})
                    fl["n"] += 1
                    fl["recuperati"] = fl.get("recuperati", 0) + bool(recuperato)
                    fl["ultimo"] = ts
            elif eid in (7001, 7002) and "winlogon" in prov.lower():
                sid = (d.get("UserSid") or "").upper()
                if not sid.startswith("S-1-5-21-"):
                    continue
                n_ok += eid == 7001
                u = per.setdefault(sid, {})
                if eid == 7001:
                    u["sessioni"] = u.get("sessioni", 0) + 1
                    if recuperato:
                        u["sessioni_recuperate"] = u.get("sessioni_recuperate", 0) + 1
                        n_rec += 1
                    u["sess_primo"] = u.get("sess_primo") or ts
                    u["sess_ultimo"] = ts
                else:
                    u["sess_fine"] = ts
        acc["fonti"].append({"file": path, "dal": dal, "al": al, "eventi": len(evs), "record": st})
        A.add("sistema", al, tr("Registro eventi {name}: accessi letti").format(name=Path(path).name),
              tr("{v1} eventi utili ({v2}) dal {v3} al {v4} (UTC)").format(v1=len(evs), v2=', '.join(str(i) for i in sorted(ids)), v3=(dal or '?').replace('T', ' '), v4=(al or '?').replace('T', ' '))
              + (tr(", di cui {n_rec} accessi o sessioni da record recuperati").format(n_rec=n_rec) if n_rec else "")
              + tr("; {v1}. Il file conserva solo il periodo più recente, gli accessi precedenti non sono "
                   "contati.").format(v1=evtx_stato(st)), "", (p, inode, path),
              {"dal": dal, "al": al, "eventi": len(evs), "da_record_recuperati": n_rec, **st})


def sam_machine_sid(root):
    """SID del computer (S-1-5-21-a-b-c) dal valore V di SAM\\Domains\\Account; None se non si trova."""
    v = rv(rk(root, "SAM\\Domains\\Account"), "V")
    if not isinstance(v, bytes):
        return None
    i = v.rfind(b"\x01\x04\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00")
    if i < 0 or i + 24 > len(v):
        return None
    return "S-1-5-21-" + "-".join(str(x) for x in struct.unpack_from("<III", v, i + 12))


def win_sam(A, ctx, part, users):
    rows = hive_rows(ctx, part, "windows/system32/config/sam")
    if not rows:
        return
    part, inode, _, path = rows[0]
    f = fetch_hive(A, ctx, part, inode, path)
    if not f:
        return
    hv, root = open_hive(f)
    src = (part, inode, path)
    names = {}
    for k in subkeys(rk(root, "SAM\\Domains\\Account\\Users\\Names")):
        try:
            v = k.get_value_by_name("") or (k.get_value(0) if k.number_of_values else None)
            if v is not None:
                names[v.type] = k.name
        except Exception:
            pass
    msid = sam_machine_sid(root)
    ev = getattr(ctx, "accessi", None) or {}
    fonti = ev.get("fonti") or []
    for k in subkeys(rk(root, "SAM\\Domains\\Account\\Users")):
        if not re.fullmatch(r"[0-9A-Fa-f]{8}", k.name):
            continue
        rid = int(k.name, 16)
        F = rv(k, "F")
        if not isinstance(F, bytes) or len(F) < 68:
            continue
        q = lambda o: filetime(struct.unpack_from("<Q", F, o)[0])
        last, pwd, failed = q(8), q(24), q(40)
        acb = struct.unpack_from("<H", F, 56)[0]
        bad = struct.unpack_from("<H", F, 64)[0]
        logins = struct.unpack_from("<H", F, 66)[0]
        name = names.get(rid, f"RID {rid}")
        # il profilo dell'utente (SOFTWARE\\...\\ProfileList) è una seconda fonte: il SAM non conta tutti gli accessi
        # (account Microsoft/online, PIN, Windows Hello) e, se non è stato riversato dai log, resta indietro
        prof = next((v for sid, v in (getattr(ctx, "profili", None) or {}).items()
                     if sid.rsplit("-", 1)[-1] == str(rid)), None)
        loaded = prof and prof.get("caricato")
        unloaded = prof and prof.get("scaricato")
        # registri eventi: SID del computer + RID (se il SID del computer non si legge, l'unico SID locale con quel RID)
        sid = f"{msid}-{rid}" if msid else None
        evu = (ev.get("per_sid") or {}).get(sid) if sid else None
        if evu is None and not msid:
            cand = [v for s_, v in (ev.get("per_sid") or {}).items() if s_.rsplit("-", 1)[-1] == str(rid)]
            evu = cand[0] if len(cand) == 1 else None
        evu = evu or {}
        n_ev, n_sess, n_sbl = evu.get("accessi", 0), evu.get("sessioni", 0), evu.get("sblocchi", 0)
        n_rec_acc, n_rec_sess = evu.get("accessi_recuperati", 0), evu.get("sessioni_recuperate", 0)
        ms = sz(rv(k, "InternetUserName"))
        fail = (ev.get("falliti") or {}).get(name.lower()) or {}
        ultimo_ev = max(x for x in (evu.get("ultimo"), evu.get("sess_ultimo"), "") if x is not None) or None
        usato = bool(last or loaded or n_ev or n_sess)
        periodo = "; ".join(tr("{name} dal {v1} al {v2}").format(name=Path(f['file']).name, v1=(f['dal'] or '?')[:10], v2=(f['al'] or '?')[:10])
                            for f in fonti if f.get("eventi"))
        if fonti:
            if n_ev or n_sess:
                acc = (tr("accessi {v1} secondo i registri eventi (").format(v1=max(n_ev, n_sess))
                       + ", ".join(x for x in (
                           tr("{n_ev} accessi riusciti 4624").format(n_ev=n_ev) + (" — " + ", ".join(f"{v} {t}" for t, v in
                                                                            sorted(evu.get('tipi', {}).items())) if evu.get('tipi') else "")
                           if n_ev else "",
                           tr("{n_rec_acc} accessi da record recuperati dallo spazio libero del registro").format(n_rec_acc=n_rec_acc) if n_rec_acc else "",
                           tr("{n_sess} sessioni Winlogon 7001").format(n_sess=n_sess) if n_sess else "",
                           tr("{n_rec_sess} sessioni da record recuperati").format(n_rec_sess=n_rec_sess) if n_rec_sess else "",
                           f"{n_sbl} sblocchi" if n_sbl else "") if x)
                       + tr("; periodo conservato: {periodo}; gli accessi più vecchi non sono più registrati)").format(periodo=periodo))
            else:
                acc = tr("nessun accesso nei registri eventi (periodo conservato: {v1})").format(v1=periodo or tr('nessun evento'))
            acc += tr("; contatore del SAM {logins}").format(logins=logins)
            if not logins and (n_ev or n_sess or usato):
                acc += tr(" (Windows non lo aggiorna per gli accessi con account Microsoft, PIN o Windows Hello)")
        elif logins:
            acc = tr("accessi {logins} (contatore del SAM)").format(logins=logins)
        elif usato:
            acc = tr("accessi: il contatore del SAM è 0 ma l'account risulta usato (il SAM non conta tutti gli accessi, " \
                  "p. es. account Microsoft, PIN o Windows Hello): non vale come «mai acceduto»")
        else:
            acc = tr("accessi 0 (contatore del SAM; nessun ultimo accesso né profilo caricato registrato)")
        n_tot = max(logins, n_ev, n_sess)
        ts = last or ultimo_ev or loaded
        A.add("utenti", ts, tr("Account {name}").format(name=name) + (tr(" · {n_tot} accessi").format(n_tot=n_tot) if n_tot else
                                                   tr(" · usato (accessi non contati)") if usato else
                                                   tr(" · nessun accesso registrato")),
              "; ".join(x for x in (
                  f"RID {rid}", tr("account Microsoft {ms}").format(ms=ms) if ms else "", acc,
                  tr("ultimo accesso {v1} (SAM)").format(v1=last.replace('T', ' ')) if last else "",
                  tr("ultimo accesso {v1} (registro eventi)").format(v1=ultimo_ev.replace('T', ' ')) if ultimo_ev else "",
                  tr("primo accesso conservato {v1}").format(v1=evu['primo'].replace('T', ' ')) if evu.get("primo") else "",
                  "" if last or ultimo_ev else tr("ultimo accesso non registrato"),
                  tr("ultimo caricamento del profilo {v1}").format(v1=loaded.replace('T', ' ')) if loaded else "",
                  tr("ultimo scaricamento del profilo {v1}").format(v1=unloaded.replace('T', ' ')) if unloaded else "",
                  tr("password errate {bad} (SAM)").format(bad=bad) if bad else "",
                  tr("accessi falliti 4625: {n}, ultimo {v1}").format(n=fail['n'], v1=fail['ultimo'].replace('T', ' ')) if fail.get("n") else "",
                  tr("password impostata {v1}").format(v1=pwd.replace('T', ' ')) if pwd else "",
                  tr("ultimo tentativo fallito {v1}").format(v1=failed.replace('T', ' ')) if failed else "",
                  f"SID {sid}" if sid else "",
                  "disabilitato" if acb & 1 else "attivo") if x), name, src,
              {"rid": rid, "sid": sid, "accessi": n_tot, "accessi_sam": logins, "accessi_eventi": n_ev,
               "sessioni_winlogon": n_sess, "sblocchi": n_sbl, "tipi_accesso": evu.get("tipi"),
               "accessi_da_record_recuperati": n_rec_acc, "sessioni_da_record_recuperati": n_rec_sess,
               "ultimo_accesso": last or ultimo_ev, "ultimo_accesso_sam": last, "ultimo_accesso_eventi": ultimo_ev,
               "account_microsoft": ms or None, "profilo_caricato": loaded, "profilo_scaricato": unloaded,
               "password_errate": bad, "accessi_falliti": fail.get("n", 0), "periodo_eventi": fonti or None,
               "disabilitato": bool(acb & 1)})
    hv.close()


def rot13(s):
    return s.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                     "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))


def known_folder(s):
    for g, p in KNOWN_FOLDERS.items():
        s = s.replace(g, tr(p))
    return s


def win_ntuser(A, ctx, part, row):
    part, inode, _, path = row
    user = user_of(path)
    f = fetch_hive(A, ctx, part, inode, path)
    if not f:
        return
    try:
        hv, root = open_hive(f)
    except Exception:
        return
    src = (part, inode, path)
    lwr = lw(root)
    if lwr and user:
        A.add("utenti", lwr, tr("Profilo {user}: ultima attività nel registro dell'utente").format(user=user),
              tr("ultima scrittura della chiave radice di NTUSER.DAT: {v1} (UTC). Indica che l'utente ha "
                 "avuto una sessione aperta fino a quel momento o poco prima (altra prova d'uso, "
                 "indipendente dal contatore degli accessi del SAM)").format(v1=lwr.replace('T', ' ')), user, src, {"ultima_scrittura": lwr})
    ex = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
    for g in subkeys(rk(root, f"{ex}\\UserAssist")):
        cnt = rk(g, "Count")
        try:
            vals = list(cnt.values) if cnt is not None else []
        except Exception:
            vals = []
        for v in vals:
            name = known_folder(rot13(v.name or ""))
            d = v.data or b""
            if name.startswith("UEME_") or not name:
                continue
            runs, last = None, None
            if len(d) >= 68:
                runs = struct.unpack_from("<I", d, 4)[0]
                last = filetime(struct.unpack_from("<Q", d, 60)[0])
            elif len(d) >= 16:
                runs = max(0, struct.unpack_from("<I", d, 4)[0] - 5)
                last = filetime(struct.unpack_from("<Q", d, 8)[0])
            if not runs and not last:
                continue
            A.add("esecuzioni", last, name, tr("UserAssist: avviato {runs} volte dall'utente").format(runs=runs), user, src,
                  {"fonte": "UserAssist", "volte": runs})
    rd = rk(root, f"{ex}\\RecentDocs")
    if rd is not None:
        order = rv(rd, "MRUListEx")
        idx = [i for i in struct.unpack(f"<{len(order) // 4}I", order) if i != 0xFFFFFFFF] if isinstance(order, bytes) else []
        for pos, i in enumerate(idx[:400]):
            d = rv(rd, str(i))
            if isinstance(d, bytes):
                nm = d.decode("utf-16-le", "ignore").split("\x00")[0]
                if nm:
                    A.add("recenti", lw(rd) if pos == 0 else None, nm,
                          tr("RecentDocs: documento o cartella aperti di recente") + (tr(" (il più recente)") if pos == 0 else tr(" (posizione {v1})").format(v1=pos + 1)),
                          user, src, {"fonte": "RecentDocs", "posizione": pos + 1})
    for key, cat, lbl in ((f"{ex}\\TypedPaths", "recenti", tr("percorso digitato in Esplora file")),
                          (f"{ex}\\RunMRU", "esecuzioni", tr("comando digitato in Esegui (Win+R)")),
                          (f"{ex}\\WordWheelQuery", "ricerche", tr("ricerca in Esplora file")),
                          ("Software\\Microsoft\\Internet Explorer\\TypedURLs", "web", tr("indirizzo digitato in Internet Explorer"))):
        k = rk(root, key)
        try:
            vals = list(k.values) if k is not None else []
        except Exception:
            vals = []
        for v in vals:
            if v.name in ("MRUList", "MRUListEx"):
                continue
            val = sz(rv(k, v.name))
            if val:
                A.add(cat, lw(k), val.rstrip("\\1"), f"{lbl} ({v.name})", user, src, {"fonte": key.split("\\")[-1]})
    for mp in subkeys(rk(root, f"{ex}\\MountPoints2")):
        nm = mp.name.replace("#", "\\")
        A.add("usb" if nm.startswith("{") else "reti", lw(mp),
              tr("Volume montato dall'utente") if nm.startswith("{") else tr("Condivisione di rete aperta: {nm}").format(nm=nm),
              mp.name, user, src)
    office = rk(root, "Software\\Microsoft\\Office")
    for ver in subkeys(office):
        for app in subkeys(ver):
            for sub in ("File MRU", "Place MRU"):
                k = rk(app, sub)
                try:
                    vals = list(k.values) if k is not None else []
                except Exception:
                    vals = []
                for v in vals:
                    s = sz(rv(k, v.name))
                    m = re.search(r"\[T([0-9A-F]{16})\].*\*(.+)$", s or "")
                    if m:
                        A.add("recenti", filetime(int(m.group(1), 16)), m.group(2),
                              tr("Office {name} {name2}: {v1} aperto di recente").format(name=app.name, name2=ver.name, v1='file' if sub == 'File MRU' else 'cartella'),
                              user, src, {"fonte": "Office MRU"})
    for base in ("Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"):
        k = rk(root, base)
        try:
            for v in (k.values if k is not None else []):
                A.add("programmi", lw(k), tr("Avvio automatico: {name}").format(name=v.name), tr("{v1} (solo per {user})").format(v1=sz(rv(k, v.name)), user=user), user, src)
        except Exception:
            pass
    for base in ("Software\\Microsoft\\Windows\\Shell\\BagMRU", "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU"):
        try:
            shellbags(A, root, base, user, src, "ShellBags (NTUSER.DAT)")
        except Exception as e:
            print(tr("  ShellBags {path}: {vname}: {e}").format(path=path, vname=type(e).__name__, e=e), flush=True)
    hv.close()


def win_prefetch(A, ctx, part):
    try:
        import pyscca
    except ImportError:
        return
    for p, inode, _, path in fw(ctx, part, "windows/prefetch/%.pf"):
        f = fetch(ctx, p, inode, path, 50 << 20)
        if not f:
            continue
        try:
            sf = pyscca.file()
            sf.open(str(f))
            exe = sf.executable_filename
            runs = sf.run_count
            times = []
            for i in range(8):
                try:
                    t = iso(sf.get_last_run_time(i))
                except Exception:
                    t = None
                if t:
                    times.append(t)
            full = ""
            for i in range(sf.number_of_filenames):
                fn = sf.get_filename(i) or ""
                if fn.upper().endswith("\\" + (exe or "").upper()):
                    full = re.sub(r"(?i)^\\DEVICE\\HARDDISKVOLUME\d+", "", fn)
                    break
            sf.close()
            A.add("esecuzioni", times[0] if times else None, exe or Path(path).stem,
                  tr("Prefetch: eseguito {runs} volte").format(runs=runs) + (tr("; ultime esecuzioni: {v1}").format(v1=', '.join(t.replace('T', ' ') for t in times)) if times else "") +
                  (tr("; percorso {full}").format(full=full) if full else ""), "", (p, inode, path),
                  {"fonte": "Prefetch", "volte": runs, "esecuzioni": times, "percorso": full})
        except Exception:
            continue
        finally:
            f.unlink(missing_ok=True)


def win_amcache(A, ctx, part):
    rows = fw(ctx, part, "windows/appcompat/programs/amcache.hve")
    if not rows:
        return
    p, inode, _, path = rows[0]
    f = fetch_hive(A, ctx, p, inode, path)
    if not f:
        return
    try:
        hv, root = open_hive(f)
    except Exception:
        return
    src = (p, inode, path)
    for k in subkeys(rk(root, "Root\\InventoryApplicationFile")):
        lp = sz(rv(k, "LowerCaseLongPath"))
        if not lp:
            continue
        sha1 = sz(rv(k, "FileId"))
        sha1 = sha1[4:] if sha1.startswith("0000") else sha1
        A.add("esecuzioni", lw(k), lp, "; ".join(x for x in (
            tr("Amcache: programma presente o eseguito"), sz(rv(k, "ProductName")), sz(rv(k, "Publisher")),
            f"SHA-1 {sha1}" if sha1 else "", f"compilato {sz(rv(k, 'LinkDate'))}" if rv(k, "LinkDate") else "") if x),
              "", src, {"fonte": "Amcache", "sha1": sha1})
    for vol in subkeys(rk(root, "Root\\File")):
        for k in subkeys(vol):
            lp = sz(rv(k, "15"))
            if lp:
                sha1 = sz(rv(k, "101"))
                A.add("esecuzioni", lw(k), lp, tr("Amcache: programma presente o eseguito") +
                      (tr("; SHA-1 {v1}").format(v1=sha1[4:] if sha1.startswith('0000') else sha1) if sha1 else ""), "", src,
                      {"fonte": "Amcache"})
    hv.close()


def lnk_info(lf):
    target = lf.local_path or lf.network_path or ""
    if not target and lf.relative_path:
        target = lf.relative_path
    det = []
    for lbl, val in ((tr("creazione destinazione"), iso(lf.file_creation_time)),
                     (tr("modifica destinazione"), iso(lf.file_modification_time)),
                     (tr("accesso destinazione"), iso(lf.file_access_time))):
        if val:
            det.append(f"{lbl} {val.replace('T', ' ')}")
    if lf.volume_label:
        det.append(tr("volume «{volume_label}»").format(volume_label=lf.volume_label))
    if lf.drive_serial_number:
        det.append(tr("seriale volume {drive_serial_number:08X}").format(drive_serial_number=lf.drive_serial_number))
    if lf.machine_identifier:
        det.append(f"computer {lf.machine_identifier}")
    if lf.file_size:
        det.append(f"{lf.file_size} byte")
    return target, det


def fs_time(ctx, part, inode):
    """Date (modifica, creazione) di un file della copia, da pytsk3 se disponibile."""
    hr = getattr(ctx, "hr", None)
    if hr is None:
        hr = ctx.hr = HeadReader(ctx.case)
    if not hr.ok:
        return None, None
    fs = hr._fs(part)
    if fs is None:
        return None, None
    try:
        m = fs.open_meta(inode=int(str(inode).split("-")[0])).info.meta
        return unixtime(m.mtime), unixtime(getattr(m, "crtime", 0))
    except Exception:
        return None, None


def win_lnk(A, ctx, part):
    try:
        import pylnk
    except ImportError:
        return
    rows = find_files(ctx.con, part, "%/appdata/roaming/microsoft/windows/recent/%.lnk") + \
        find_files(ctx.con, part, "%/appdata/roaming/microsoft/office/recent/%.lnk") + \
        find_files(ctx.con, part, "documents and settings/%/recent/%.lnk")
    for p, inode, _, path in rows[:20000]:
        f = fetch(ctx, p, inode, path, 4 << 20)
        if not f:
            continue
        try:
            lf = pylnk.file()
            lf.open(str(f))
            target, det = lnk_info(lf)
            lf.close()
            mt, ct = fs_time(ctx, p, inode)
            if mt:
                det.insert(0, tr("ultima apertura (collegamento modificato) {v1}").format(v1=mt.replace('T', ' ')))
            if ct and ct != mt:
                det.insert(1, tr("prima apertura (collegamento creato) {v1}").format(v1=ct.replace('T', ' ')))
            A.add("recenti", mt, target or Path(path).stem, tr("Collegamento recente (LNK): ") + "; ".join(det),
                  user_of(path), (p, inode, path), {"fonte": "LNK"})
        except Exception:
            pass
        finally:
            f.unlink(missing_ok=True)
    try:
        import pyolecf
    except ImportError:
        return
    for p, inode, _, path in find_files(ctx.con, part, "%/recent/automaticdestinations/%"):
        f = fetch(ctx, p, inode, path, 20 << 20)
        if not f:
            continue
        app = Path(path).name.split(".")[0].lower()
        appname = tr(JUMP_APPS.get(app, "")) or tr("applicazione {app}").format(app=app)
        try:
            of = pyolecf.file()
            of.open(str(f))
            r = of.root_item
            dl = {}
            for i in range(r.number_of_sub_items):
                it = r.get_sub_item(i)
                if (it.name or "").lower() == "destlist" and it.size:
                    dl = parse_destlist(it.read(it.size))
            for i in range(r.number_of_sub_items):
                it = r.get_sub_item(i)
                if (it.name or "").lower() == "destlist" or not it.size:
                    continue
                lf = pylnk.file()
                lf.open_file_object(io.BytesIO(it.read(it.size)))
                target, det = lnk_info(lf)
                lf.close()
                try:
                    num = int(it.name, 16)
                except (TypeError, ValueError):
                    num = None
                acc, host, cnt = dl.get(num, (None, "", None))
                if acc:
                    det.insert(0, tr("ultimo accesso {v1}").format(v1=acc.replace('T', ' ')))
                if cnt:
                    det.insert(1, tr("aperto {cnt} volte").format(cnt=cnt))
                if host:
                    det.append(tr("nome NetBIOS {host}").format(host=host))
                if target:
                    A.add("recenti", acc, target, tr("Jump list di {appname}: ").format(appname=appname) + "; ".join(det), user_of(path),
                          (p, inode, path), {"fonte": "Jump list", "app": appname})
            of.close()
        except Exception:
            pass
        finally:
            f.unlink(missing_ok=True)


def parse_destlist(d):
    """DestList delle jump list: {numero voce: (ultimo accesso, nome NetBIOS, volte aperto)}."""
    out = {}
    if len(d) < 32:
        return out
    ver, n = struct.unpack_from("<II", d, 0)
    pos = 32
    for _ in range(min(n, 5000)):
        try:
            host = d[pos + 72:pos + 88].split(b"\x00")[0].decode("ascii", "ignore")
            num = struct.unpack_from("<I", d, pos + 88)[0]
            acc = filetime(struct.unpack_from("<Q", d, pos + 100)[0])
            if ver >= 3:
                cnt = struct.unpack_from("<I", d, pos + 116)[0]
                ln = struct.unpack_from("<H", d, pos + 128)[0]
                pos += 130 + ln * 2 + 4
            else:
                cnt = None
                ln = struct.unpack_from("<H", d, pos + 112)[0]
                pos += 114 + ln * 2
            out[num] = (acc, host, cnt)
        except struct.error:
            break
    return out


def win_recycle(A, ctx, part, users):
    for p, inode, deleted, path in find_files(ctx.con, part, "$recycle.bin/%/$i%", deleted_ok=True):
        f = fetch(ctx, p, inode, path, 1 << 16)
        if not f:
            continue
        try:
            d = f.read_bytes()
            ver, size, t = struct.unpack_from("<QQQ", d, 0)
            if ver == 1:
                orig = d[24:24 + 520].decode("utf-16-le", "ignore").split("\x00")[0]
            else:
                n = struct.unpack_from("<I", d, 24)[0]
                orig = d[28:28 + n * 2].decode("utf-16-le", "ignore").split("\x00")[0]
            sid = path.split("/")[1] if path.count("/") >= 2 else ""
            rname = "$R" + Path(path).name[2:]
            has_r = ctx.con.execute("SELECT 1 FROM files WHERE part=? AND lower(path)=? AND deleted=0",
                                    (p, (str(Path(path).parent) + "/" + rname).lower())).fetchone()
            A.add("cestino", filetime(t), orig, tr("{size} byte · contenuto nel cestino: ").format(size=size) +
                  (tr("presente (") + rname + ")" if has_r else tr("non più presente")) + (tr(" · indice già eliminato") if deleted else ""),
                  users.get(sid, sid), (p, inode, path), {"dimensione": size, "sid": sid, "contenuto_presente": bool(has_r)})
        except Exception:
            pass
        finally:
            f.unlink(missing_ok=True)


# ---- browser (tutti i sistemi)

def chrome_time(us):
    try:
        us = int(us)
        return filetime(us * 10) if us > 0 else None
    except (TypeError, ValueError):
        return None


def browser_history(A, ctx, part):
    con = ctx.con
    cands = []
    for p, inode, d, path in con.execute(
            "SELECT part, inode, deleted, path FROM files WHERE part=? AND type LIKE '%r' AND deleted=0 AND "
            "(lower(path) LIKE '%/history' OR lower(path) LIKE '%/places.sqlite' OR lower(path) LIKE '%/history.db')",
            (part,)):
        low = path.lower()
        if low.endswith("/history") and re.search(r"chrome|chromium|edge|brave|opera|vivaldi|yandex|coccoc", low):
            cands.append(("chrome", p, inode, path))
        elif low.endswith("/places.sqlite"):
            cands.append(("firefox", p, inode, path))
        elif low.endswith("/history.db") and "safari" in low:
            cands.append(("safari", p, inode, path))
    for kind, p, inode, path in cands:
        f = fetch(ctx, p, inode, path, 2 << 30)
        if not f or open(f, "rb").read(16) != b"SQLite format 3\x00":
            continue
        user = user_of(path)
        m = re.search(r"(?i)(google/chrome|microsoft/edge|bravesoftware|opera software|vivaldi|chromium|firefox|safari)", path)
        br = {"google/chrome": "Chrome", "microsoft/edge": "Edge", "bravesoftware": "Brave", "opera software": "Opera",
              "vivaldi": "Vivaldi", "chromium": "Chromium", "firefox": "Firefox", "safari": "Safari"}.get(
            (m.group(1).lower() if m else ""), kind.capitalize())
        src = (p, inode, path)
        try:
            db = sqlite3.connect(f"file:{f.as_posix()}?mode=ro&immutable=1", uri=True)
            if kind == "chrome":
                for url, title, n, t in db.execute("SELECT url, title, visit_count, last_visit_time FROM urls "
                                                   "ORDER BY last_visit_time DESC LIMIT 50000"):
                    A.add("web", chrome_time(t), title or url, tr("{br}: {url} · {n} visite").format(br=br, url=url, n=n), user, src,
                          {"browser": br, "url": url, "visite": n})
                try:
                    for target, st, total, url in db.execute(
                            "SELECT d.target_path, d.start_time, d.total_bytes, "
                            "(SELECT url FROM downloads_url_chains c WHERE c.id=d.id ORDER BY chain_index DESC LIMIT 1) "
                            "FROM downloads d"):
                        A.add("download", chrome_time(st), target or url, tr("{br}: scaricato da {url} · {total} byte").format(br=br, url=url, total=total),
                              user, src, {"browser": br, "url": url})
                except sqlite3.Error:
                    pass
                try:
                    for term, url, t in db.execute("SELECT k.term, u.url, u.last_visit_time FROM keyword_search_terms k "
                                                   "JOIN urls u ON u.id=k.url_id"):
                        A.add("ricerche", chrome_time(t), term, tr("{br}: ricerca web ({v1})").format(br=br, v1=url[:200]), user, src,
                              {"browser": br})
                except sqlite3.Error:
                    pass
            elif kind == "firefox":
                for url, title, n, t in db.execute("SELECT url, title, visit_count, last_visit_date FROM moz_places "
                                                   "WHERE visit_count > 0 ORDER BY last_visit_date DESC LIMIT 50000"):
                    A.add("web", unixtime((t or 0) / 1e6), title or url, tr("Firefox: {url} · {n} visite").format(url=url, n=n), user, src,
                          {"browser": "Firefox", "url": url, "visite": n})
                try:
                    for content, added, url in db.execute(
                            "SELECT a.content, a.dateAdded, p.url FROM moz_annos a JOIN moz_anno_attributes n "
                            "ON n.id=a.anno_attribute_id JOIN moz_places p ON p.id=a.place_id "
                            "WHERE n.name='downloads/destinationFileURI'"):
                        A.add("download", unixtime((added or 0) / 1e6), content, tr("Firefox: scaricato da {url}").format(url=url), user,
                              src, {"browser": "Firefox", "url": url})
                except sqlite3.Error:
                    pass
            else:
                for url, n, t, title in db.execute(
                        "SELECT i.url, i.visit_count, MAX(v.visit_time), v.title FROM history_items i "
                        "JOIN history_visits v ON v.history_item=i.id GROUP BY i.id ORDER BY 3 DESC LIMIT 50000"):
                    A.add("web", unixtime((t or 0) + 978307200), title or url, tr("Safari: {url} · {n} visite").format(url=url, n=n), user,
                          src, {"browser": "Safari", "url": url, "visite": n})
            db.close()
        except sqlite3.Error:
            pass
        finally:
            f.unlink(missing_ok=True)


# ---- macOS e Linux

def read_small(ctx, p, inode, path, n=8 << 20):
    try:
        return fa.icat_read(ctx.case, p, inode, n)
    except Exception:
        return b""


def _part_meta(ctx, part):
    return next((p for p in ctx.case.meta.get("partitions", []) if p.get("offset") == part), {}) or {}


def is_mac_volume(ctx, part):
    """Volume macOS: di sistema (SystemVersion.plist), Dati (dslocal, Users, ruolo APFS Data) o HFS+ completo."""
    con = ctx.con
    if find_files(con, part, "system/library/coreservices/systemversion.plist"):
        return "sistema"
    if find_files(con, part, "private/var/db/dslocal/nodes/default/users/%.plist"):
        return "dati"
    a = _part_meta(ctx, part).get("apfs") or {}
    if (a.get("role") or "").lower() == "data":
        return "dati"
    if a and con.execute("SELECT 1 FROM files WHERE part=? AND lower(path) LIKE 'users/%/library/%' LIMIT 1",
                         (part,)).fetchone():
        return "dati"
    return None


def cocoa(t):
    """Secondi (o nanosecondi) dal 2001-01-01 UTC (date di Apple) -> ISO."""
    try:
        t = float(t)
    except (TypeError, ValueError):
        return None
    if not t:
        return None
    if abs(t) > 1e14:          # nanosecondi (chat.db di macOS recenti)
        t /= 1e9
    return unixtime(t + 978307200)


def plist_of(ctx, p, inode, path, n=16 << 20):
    try:
        return plistlib.loads(read_small(ctx, p, inode, path, n))
    except Exception:
        return None


def fetch_sqlite(ctx, part, inode, path):
    """Copia un database SQLite con i file -wal/-journal accanto (i messaggi più recenti stanno
    spesso solo nel -wal) e lo apre: la copia temporanea può essere modificata da SQLite,
    l'originale no."""
    f = fetch(ctx, part, inode, path, 2 << 30)
    if not f or open(f, "rb").read(16) != b"SQLite format 3\x00":
        return None, None
    d = ctx.tmp / f"db_{part}_{safe_name(str(inode), 40)}"
    d.mkdir(exist_ok=True)
    main = d / "db.sqlite"
    shutil.copyfile(f, main)
    wal = False
    for suf in ("-wal", "-journal"):
        ino = fa.lookup(ctx.con, part, path.lower() + suf)
        if ino:
            g = fetch(ctx, part, ino, path + suf, 2 << 30)
            if g:
                shutil.copyfile(g, d / ("db.sqlite" + suf))
                wal = wal or suf == "-wal"
    try:
        db = sqlite3.connect(str(main))
        db.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except sqlite3.Error:
        return None, None
    return db, wal


def bookmark_paths(data):
    """Percorso di un bookmark Apple ('book…', usato da .sfl2/.sfl3, login items, Dock):
    componenti del percorso (chiave 0x1004) e volume (0x2002). Restituisce (percorso, volume)."""
    import struct
    try:
        if data[:4] not in (b"book", b"alis") or len(data) < 0x40:
            return None, None
        hdr = struct.unpack_from("<I", data, 12)[0]
        base = hdr
        toc = struct.unpack_from("<I", data, base)[0] + base
        vals = {}
        guard = 0
        while toc and toc + 20 <= len(data) and guard < 16:
            guard += 1
            _sz, _magic, _ident, nxt, cnt = struct.unpack_from("<IIIII", data, toc)
            for i in range(min(cnt, 512)):
                k, off, _r = struct.unpack_from("<III", data, toc + 20 + i * 12)
                vals[k] = off + base
            toc = nxt + base if nxt else 0

        def item(off):
            ln, typ = struct.unpack_from("<II", data, off)
            raw = data[off + 8: off + 8 + ln]
            if typ == 0x0101:
                return raw.decode("utf-8", "replace")
            if typ == 0x0601:
                return [item(struct.unpack_from("<I", raw, j)[0] + base) for j in range(0, ln, 4)]
            return None
        comps = item(vals[0x1004]) if 0x1004 in vals else None
        vol = item(vals[0x2002]) if 0x2002 in vals else None
        path = "/" + "/".join(c for c in comps if isinstance(c, str)) if isinstance(comps, list) else None
        return path, vol if isinstance(vol, str) else None
    except Exception:
        return None, None


def _keyed_objects(d):
    """Oggetti di un NSKeyedArchiver con riferimenti risolti in modo semplice."""
    objs = d.get("$objects") or []

    def res(x, depth=0):
        if depth > 8:
            return x
        if isinstance(x, plistlib.UID):
            return res(objs[x.data], depth + 1) if x.data < len(objs) else None
        if isinstance(x, dict):
            if "NS.objects" in x and "NS.keys" in x:
                return {str(res(k, depth + 1)): res(v, depth + 1) for k, v in zip(x["NS.keys"], x["NS.objects"])}
            if "NS.objects" in x:
                return [res(v, depth + 1) for v in x["NS.objects"]]
            if "NS.string" in x:
                return x["NS.string"]
            if "NS.data" in x:
                return x["NS.data"]
            if "NS.time" in x:
                return cocoa(x["NS.time"])
            return {k: res(v, depth + 1) for k, v in x.items() if k != "$class"}
        return x
    top = d.get("$top") or {}
    return res(top.get("root")) if "root" in top else None, objs


def _attributed_text(blob):
    """Testo di un messaggio salvato solo come NSAttributedString (attributedBody, macOS 13+)."""
    if not blob:
        return ""
    try:
        i = blob.find(b"NSString")
        if i < 0:
            return ""
        j = blob.find(b"+", i)
        if j < 0:
            return ""
        n = blob[j + 1]
        k = j + 2
        if n == 0x81:
            n = int.from_bytes(blob[k:k + 2], "little")
            k += 2
        elif n == 0x82:
            n = int.from_bytes(blob[k:k + 4], "little")
            k += 4
        return blob[k:k + n].decode("utf-8", "replace")
    except Exception:
        return ""


def mac_artifacts(A, ctx, part):
    """macOS. Dalla 2.14 riconosce anche il volume Dati dei Mac recenti (Catalina e successivi): lì ci
    sono utenti, reti, programmi installati dall'utente e tutti gli artefatti dell'utente, mentre il
    volume di sistema (sigillato) ha solo la versione di macOS."""
    con = ctx.con
    kind = is_mac_volume(ctx, part)
    if not kind:
        return False
    rows = find_files(con, part, "system/library/coreservices/systemversion.plist")
    if rows:
        p, inode, _, path = rows[0]
        try:
            d = plistlib.loads(read_small(ctx, p, inode, path))
            A.add("sistema", None, tr("Sistema operativo: {v1} {v2}").format(v1=d.get('ProductName', 'macOS'), v2=d.get('ProductVersion', '')),
                  f"build {d.get('ProductBuildVersion', '')}", "", (p, inode, path))
        except Exception:
            pass
    for p, inode, _, path in find_files(con, part, "private/var/db/dslocal/nodes/default/users/%.plist"):
        try:
            d = plistlib.loads(read_small(ctx, p, inode, path))
            name = (d.get("name") or [Path(path).stem])[0]
            uid = int((d.get("uid") or ["0"])[0])
            if uid < 500 and name != "root":
                continue
            real = (d.get("realname") or [""])[0]
            A.add("utenti", None, tr("Account {name}").format(name=name), tr("{real} · UID {uid} · home {v1}").format(real=real, uid=uid, v1=(d.get('home') or [''])[0]),
                  name, (p, inode, path))
        except Exception:
            continue
    for p, inode, _, path in find_files(con, part, "applications/%.app/contents/info.plist"):
        if path.lower().count(".app/") > 1:
            continue
        try:
            d = plistlib.loads(read_small(ctx, p, inode, path, 2 << 20))
            A.add("programmi", None, d.get("CFBundleName") or Path(path).parts[1],
                  tr("versione {v1} · {v2}").format(v1=d.get('CFBundleShortVersionString', ''), v2=d.get('CFBundleIdentifier', '')), "",
                  (p, inode, path))
        except Exception:
            continue
    for p, inode, _, path in find_files(con, part, "library/receipts/installhistory.plist"):
        try:
            for it in plistlib.loads(read_small(ctx, p, inode, path)):
                A.add("programmi", iso(it.get("date")), it.get("displayName", ""),
                      tr("installazione {v1} con {v2}").format(v1=it.get('displayVersion', ''), v2=it.get('processName', '')), "", (p, inode, path))
        except Exception:
            pass
    for p, inode, _, path in find_files(con, part, "library/preferences/com.apple.wifi.known-networks.plist"):
        try:
            d = plistlib.loads(read_small(ctx, p, inode, path))
            for k, v in d.items():
                ssid = k.replace("wifi.network.ssid.", "")
                t = v.get("JoinedByUserAt") or v.get("JoinedBySystemAt") or v.get("AddedAt")
                A.add("reti", iso(t), tr("Rete Wi-Fi: {ssid}").format(ssid=ssid), f"aggiunta {iso(v.get('AddedAt')) or ''}", "", (p, inode, path))
        except Exception:
            pass
    for p, inode, _, path in find_files(con, part, "library/preferences/systemconfiguration/com.apple.airport.preferences.plist"):
        try:
            d = plistlib.loads(read_small(ctx, p, inode, path))
            for k, v in (d.get("KnownNetworks") or {}).items():
                A.add("reti", iso(v.get("LastConnected")), tr("Rete Wi-Fi: {v1}").format(v1=v.get('SSIDString', k)), "", "", (p, inode, path))
        except Exception:
            pass
    for fn in (mac_sistema, mac_quarantena, mac_avvio, mac_tcc, mac_messaggi, mac_recenti, mac_safari_download,
               mac_knowledgec, mac_dispositivi, mac_timemachine):
        try:
            fn(A, ctx, part)
        except Exception as e:
            print(f"  {fn.__name__}: {type(e).__name__}: {e}", flush=True)
        con.commit()
    return True


def mac_sistema(A, ctx, part):
    con = ctx.con
    for p, inode, _, path in find_files(con, part, "library/preferences/systemconfiguration/preferences.plist"):
        d = plist_of(ctx, p, inode, path) or {}
        s = ((d.get("System") or {}).get("System") or {})
        for k, lab in (("ComputerName", tr("Nome del computer")), ("HostName", tr("Nome host"))):
            if s.get(k):
                A.add("sistema", None, f"{lab}: {s[k]}", "", "", (p, inode, path))
        lh = ((d.get("System") or {}).get("Network") or {}).get("HostNames", {}).get("LocalHostName")
        if lh:
            A.add("sistema", None, tr("Nome nella rete locale: {lh}.local").format(lh=lh), "", "", (p, inode, path))
    for p, inode, _, path in find_files(con, part, "library/preferences/com.apple.loginwindow.plist"):
        d = plist_of(ctx, p, inode, path) or {}
        if d.get("lastUserName"):
            A.add("sistema", None, tr("Ultimo utente che ha effettuato l'accesso: {lastUserName}").format(lastUserName=d['lastUserName']), "", d["lastUserName"],
                  (p, inode, path))
        if d.get("autoLoginUser"):
            A.add("sistema", None, tr("Accesso automatico attivo per: {autoLoginUser}").format(autoLoginUser=d['autoLoginUser']), "", d["autoLoginUser"],
                  (p, inode, path))
        if d.get("GuestEnabled") is not None:
            A.add("sistema", None, tr("Utente ospite: ") + (tr("attivo") if d.get("GuestEnabled") else tr("disattivato")), "", "",
                  (p, inode, path))
    for p, inode, _, path in find_files(con, part, "library/preferences/.globalpreferences.plist"):
        d = plist_of(ctx, p, inode, path) or {}
        city = d.get("com.apple.TimeZonePref.Last_Selected_City")
        if isinstance(city, list) and len(city) > 3:
            A.add("sistema", None, tr("Fuso orario scelto: {v1}").format(v1=city[3]), tr("città {v1} ({v2})").format(v1=city[5] if len(city) > 5 else '', v2=city[4] if len(city) > 4 else ''), "", (p, inode, path))
    for p, inode, _, path in find_files(con, part, "library/preferences/com.apple.timezone.auto.plist"):
        d = plist_of(ctx, p, inode, path) or {}
        if "Active" in d:
            A.add("sistema", None, tr("Fuso orario automatico (dalla posizione): ") + (tr("sì") if d["Active"] else tr("no")), "", "",
                  (p, inode, path))


def mac_quarantena(A, ctx, part):
    """Eventi di quarantena: ogni file scaricato o ricevuto, con URL di origine e programma."""
    for p, inode, _, path in find_files(ctx.con, part, "users/%/library/preferences/com.apple.launchservices.quarantineeventsv%"):
        if path.lower().endswith(("-wal", "-shm", "-journal")):
            continue
        db, _ = fetch_sqlite(ctx, p, inode, path)
        if not db:
            continue
        user = user_of(path)
        try:
            for t, agent, bid, url, origin, sender, addr in db.execute(
                    "SELECT LSQuarantineTimeStamp, LSQuarantineAgentName, LSQuarantineAgentBundleIdentifier, "
                    "LSQuarantineDataURLString, LSQuarantineOriginURLString, LSQuarantineSenderName, "
                    "LSQuarantineSenderAddress FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp"):
                det = tr("con {v1}").format(v1=agent or bid or '?') + (tr(" · pagina {origin}").format(origin=origin) if origin else "") + \
                      (tr(" · mittente {v1} {v2}").format(v1=sender or '', v2=addr or '').rstrip() if sender or addr else "")
                A.add("download", cocoa(t), url or origin or tr("(senza URL)"), tr("Quarantena macOS: ") + det, user,
                      (p, inode, path), {"programma": agent, "bundle": bid, "url": url, "origine": origin})
        except sqlite3.Error:
            pass
        db.close()


def mac_avvio(A, ctx, part):
    """Avvio automatico: LaunchAgents e LaunchDaemons (sistema e utenti)."""
    pats = ("library/launchagents/%.plist", "library/launchdaemons/%.plist", "users/%/library/launchagents/%.plist",
            "system/library/launchagents/%.plist", "system/library/launchdaemons/%.plist")
    for pat in pats:
        apple = pat.startswith("system/")
        for p, inode, _, path in find_files(ctx.con, part, pat):
            if path.lower().count("/") > pat.count("/"):
                continue
            d = plist_of(ctx, p, inode, path, 1 << 20)
            if not isinstance(d, dict):
                continue
            label = d.get("Label") or Path(path).stem
            if apple and str(label).startswith("com.apple."):
                continue
            prog = d.get("Program") or " ".join(str(x) for x in (d.get("ProgramArguments") or []))
            flags = [k for k in ("RunAtLoad", "KeepAlive") if d.get(k)]
            when = tr("all'accesso dell'utente") if "launchagents" in pat else tr("all'avvio del sistema")
            A.add("avvio", None, label, f"{prog or '(programma non indicato)'} · {when}"
                  + (f" · {', '.join(flags)}" if flags else "") + (tr(" · disattivato") if d.get("Disabled") else ""),
                  user_of(path), (p, inode, path), {"programma": prog})
    # elementi di login gestiti da macOS 13+ (Background Task Management): si elencano i percorsi
    for p, inode, _, path in find_files(ctx.con, part, "private/var/db/com.apple.backgroundtaskmanagement/backgrounditems-v%.btm"):
        d = plist_of(ctx, p, inode, path) or {}
        try:
            _root, objs = _keyed_objects(d)
        except Exception:
            objs = []
        seen = set()
        for o in objs:
            if isinstance(o, bytes) and o[:4] == b"book":
                pth, _v = bookmark_paths(o)
                if pth and pth not in seen:
                    seen.add(pth)
                    A.add("avvio", None, Path(pth).name, tr("elemento di login / in background: {pth}").format(pth=pth), "",
                          (p, inode, path))
            elif isinstance(o, str) and o.startswith("file:///") and o not in seen:
                seen.add(o)
                A.add("avvio", None, Path(o).name, tr("elemento di login / in background: {o}").format(o=o), "", (p, inode, path))


TCC_AUTH = {0: "negato", 1: "sconosciuto", 2: "consentito", 3: "limitato"}


def mac_tcc(A, ctx, part):
    """Permessi concessi alle app (TCC): disco completo, fotocamera, microfono, schermo, accessibilità…"""
    for pat in ("library/application support/com.apple.tcc/tcc.db", "users/%/library/application support/com.apple.tcc/tcc.db"):
        for p, inode, _, path in find_files(ctx.con, part, pat):
            db, _ = fetch_sqlite(ctx, p, inode, path)
            if not db:
                continue
            cols = {r[1] for r in db.execute("PRAGMA table_info(access)")}
            auth = "auth_value" if "auth_value" in cols else "allowed"
            when = "last_modified" if "last_modified" in cols else "NULL"
            try:
                for svc, client, val, t in db.execute(f"SELECT service, client, {auth}, {when} FROM access"):
                    s = str(svc).replace("kTCCService", "")
                    stato = TCC_AUTH.get(val, str(val)) if auth == "auth_value" else (tr("consentito") if val else tr("negato"))
                    A.add("permessi", unixtime(t), f"{s}: {client}", f"{stato} · "
                          + (tr("per tutti gli utenti") if not path.lower().startswith("users/") else tr("per l'utente")),
                          user_of(path), (p, inode, path), {"servizio": s, "app": client, "stato": stato})
            except sqlite3.Error:
                pass
            db.close()


def mac_messaggi(A, ctx, part):
    """iMessage/SMS (chat.db), compresi i messaggi ancora solo nel -wal e quelli in attributedBody."""
    for p, inode, _, path in find_files(ctx.con, part, "users/%/library/messages/chat.db"):
        db, wal = fetch_sqlite(ctx, p, inode, path)
        if not db:
            continue
        user = user_of(path)
        cols = {r[1] for r in db.execute("PRAGMA table_info(message)")}
        ab = "m.attributedBody" if "attributedBody" in cols else "NULL"
        try:
            q = ("SELECT m.ROWID, m.date, m.text, " + ab + ", m.is_from_me, h.id, m.service, "
                 "(SELECT c.chat_identifier || COALESCE(' «' || NULLIF(c.display_name, '') || '»', '') FROM chat_message_join j "
                 " JOIN chat c ON c.ROWID=j.chat_id WHERE j.message_id=m.ROWID LIMIT 1), "
                 "(SELECT group_concat(COALESCE(a.transfer_name, a.filename), ' | ') FROM message_attachment_join x "
                 " JOIN attachment a ON a.ROWID=x.attachment_id WHERE x.message_id=m.ROWID) "
                 "FROM message m LEFT JOIN handle h ON h.ROWID=m.handle_id ORDER BY m.date")
            n = 0
            for rid, t, text, body, me, who, svc, chat, att in db.execute(q):
                txt = text or _attributed_text(body)
                verso = tr("inviato a") if me else tr("ricevuto da")
                A.add("messaggi", cocoa(t), (txt or (tr("(allegato) ") + att if att else tr("(senza testo)")))[:500],
                      f"{svc or 'iMessage'} · {verso} {who or '?'}" + (tr(" · conversazione {chat}").format(chat=chat) if chat else "")
                      + (tr(" · allegati: {att}").format(att=att) if att else ""), user, (p, inode, path),
                      {"id": rid, "da_me": bool(me), "contatto": who, "servizio": svc, "allegati": att, "testo": txt})
                n += 1
            if wal:
                A.add("messaggi", None, tr("chat.db di {user}: letti anche i messaggi nel file -wal").format(user=user), tr("{n} messaggi in tutto").format(n=n),
                      user, (p, inode, path))
        except sqlite3.Error as e:
            print(tr("  chat.db {path}: {e}").format(path=path, e=e), flush=True)
        db.close()


def mac_recenti(A, ctx, part):
    """Documenti, cartelle, app e server recenti (.sfl2/.sfl3 di com.apple.sharedfilelist)."""
    for p, inode, _, path in find_files(ctx.con, part, "users/%/library/application support/com.apple.sharedfilelist/%.sfl%"):
        d = plist_of(ctx, p, inode, path)
        if not isinstance(d, dict):
            continue
        user = user_of(path)
        lista = Path(path).stem.replace("com.apple.LSSharedFileList.", "")
        try:
            root, objs = _keyed_objects(d)
        except Exception:
            continue
        items = root.get("items") if isinstance(root, dict) else None
        done = set()
        for it in items or []:
            if not isinstance(it, dict):
                continue
            bm = it.get("Bookmark")
            pth, vol = bookmark_paths(bm) if isinstance(bm, bytes) else (None, None)
            name = it.get("Name") or (Path(pth).name if pth else "")
            if not (pth or name):
                continue
            done.add(pth or name)
            A.add("recenti", None, name or pth, f"{lista}: {pth or ''}" + (tr(" · volume {vol}").format(vol=vol) if vol else ""), user,
                  (p, inode, path), {"elenco": lista, "percorso": pth, "volume": vol})
        for o in objs:
            if isinstance(o, bytes) and o[:4] == b"book":
                pth, vol = bookmark_paths(o)
                if pth and pth not in done:
                    done.add(pth)
                    A.add("recenti", None, Path(pth).name, f"{lista}: {pth}" + (tr(" · volume {vol}").format(vol=vol) if vol else ""), user,
                          (p, inode, path), {"elenco": lista, "percorso": pth, "volume": vol})


def mac_safari_download(A, ctx, part):
    for p, inode, _, path in find_files(ctx.con, part, "users/%/library/%safari/downloads.plist"):
        d = plist_of(ctx, p, inode, path) or {}
        for it in d.get("DownloadHistory") or []:
            t = it.get("DownloadEntryDateFinishedKey") or it.get("DownloadEntryDateAddedKey")
            A.add("download", iso(t), it.get("DownloadEntryPath") or it.get("DownloadEntryURL"),
                  tr("Safari: scaricato da {v1} · {v2} byte").format(v1=it.get('DownloadEntryURL', ''), v2=it.get('DownloadEntryProgressTotalToLoad', '')),
                  user_of(path), (p, inode, path), {"browser": "Safari", "url": it.get("DownloadEntryURL")})


def mac_knowledgec(A, ctx, part):
    """Uso delle app e dello schermo (knowledgeC.db, fino a macOS 13; poi Biome, non letto)."""
    for pat in ("private/var/db/coreduet/knowledge/knowledgec.db", "users/%/library/application support/knowledge/knowledgec.db"):
        for p, inode, _, path in find_files(ctx.con, part, pat):
            db, _ = fetch_sqlite(ctx, p, inode, path)
            if not db:
                continue
            try:
                for stream, val, s, e in db.execute(
                        "SELECT ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE, ZENDDATE FROM ZOBJECT WHERE ZSTREAMNAME IN "
                        "('/app/inFocus','/app/usage','/app/webUsage','/display/isBacklit','/device/isLocked',"
                        "'/media/nowPlaying','/safari/history') ORDER BY ZSTARTDATE LIMIT 200000"):
                    dur = (e - s) if (e and s) else None
                    A.add("uso", cocoa(s), f"{stream}: {val or ''}".strip(),
                          tr("fino a {v1}").format(v1=(cocoa(e) or '').replace('T', ' ')) + (f" · {int(dur)} s" if dur is not None else ""),
                          user_of(path), (p, inode, path), {"flusso": stream, "valore": val, "fine": cocoa(e)})
            except sqlite3.Error:
                pass
            db.close()


def mac_dispositivi(A, ctx, part):
    """Dispositivi Bluetooth associati e volumi esterni visti dal Finder (chiavette, dischi, immagini)."""
    for p, inode, _, path in find_files(ctx.con, part, "library/preferences/com.apple.bluetooth.plist"):
        d = plist_of(ctx, p, inode, path) or {}
        for mac, v in (d.get("DeviceCache") or {}).items():
            if isinstance(v, dict):
                A.add("dispositivi", iso(v.get("LastInquiryUpdate") or v.get("LastNameUpdate")),
                      tr("Bluetooth: {v1}").format(v1=v.get('Name') or v.get('displayName') or mac), f"indirizzo {mac}", "", (p, inode, path))
        for mac in d.get("PairedDevices") or []:
            A.add("dispositivi", None, tr("Bluetooth associato: {mac}").format(mac=mac), "", "", (p, inode, path))
    for p, inode, _, path in find_files(ctx.con, part, "users/%/library/preferences/com.apple.finder.plist"):
        d = plist_of(ctx, p, inode, path) or {}
        for k in (d.get("FXDesktopVolumePositions") or {}):
            nm = re.sub(r"_0x[0-9a-f]+$|_-?[0-9.e+]+$", "", str(k))
            A.add("dispositivi", None, tr("Volume mostrato sulla Scrivania: {nm}").format(nm=nm), f"chiave {k}", user_of(path), (p, inode, path))
        for it in d.get("FXRecentFolders") or []:
            if isinstance(it, dict):
                bm = it.get("file-bookmark")
                pth, vol = bookmark_paths(bm) if isinstance(bm, bytes) else (None, None)
                A.add("recenti", None, it.get("name") or pth, tr("Finder, cartelle recenti: {v1}").format(v1=pth or '')
                      + (tr(" · volume {vol}").format(vol=vol) if vol else ""), user_of(path), (p, inode, path))


def mac_timemachine(A, ctx, part):
    for p, inode, _, path in find_files(ctx.con, part, "library/preferences/com.apple.timemachine.plist"):
        d = plist_of(ctx, p, inode, path) or {}
        A.add("backup", None, tr("Time Machine: backup automatico ") + ("attivo" if d.get("AutoBackup") else tr("non attivo")),
              "", "", (p, inode, path))
        for dst in d.get("Destinations") or []:
            dates = [iso(x) for x in (dst.get("SnapshotDates") or [])]
            nm = dst.get("LastKnownVolumeName") or dst.get("NetworkURL") or dst.get("DestinationID")
            A.add("backup", dates[-1] if dates else None, tr("Disco di backup: {nm}").format(nm=nm),
                  f"{len(dates)} backup" + (tr(", dal {v1} al {v2}").format(v1=dates[0], v2=dates[-1]) if dates else "")
                  + (f" · {dst.get('NetworkURL')}" if dst.get("NetworkURL") else ""), "", (p, inode, path),
                  {"backup": dates})


def linux_artifacts(A, ctx, part):
    con = ctx.con
    rows = find_files(con, part, "etc/passwd")
    if not rows:
        return False
    p, inode, _, path = rows[0]
    for line in decode_bytes(read_small(ctx, p, inode, path)).splitlines():
        f = line.split(":")
        if len(f) >= 7 and (f[2] == "0" or (f[2].isdigit() and 1000 <= int(f[2]) < 65000)):
            A.add("utenti", None, tr("Account {v1}").format(v1=f[0]), tr("UID {v1} · {v2} · home {v3} · shell {v4}").format(v1=f[2], v2=f[4], v3=f[5], v4=f[6]), f[0], (p, inode, path))
    for nm in ("etc/hostname", "etc/timezone"):
        for p, inode, _, path in find_files(con, part, nm):
            v = decode_bytes(read_small(ctx, p, inode, path, 4096)).strip()
            if v:
                A.add("sistema", None, (tr("Nome del computer: ") if "hostname" in nm else tr("Fuso orario: ")) + v, "", "", (p, inode, path))
    for p, inode, _, path in find_files(con, part, "etc/networkmanager/system-connections/%"):
        t = decode_bytes(read_small(ctx, p, inode, path, 65536))
        m = re.search(r"(?m)^ssid=(.+)$", t) or re.search(r"(?m)^id=(.+)$", t)
        if m:
            A.add("reti", None, tr("Rete: {v1}").format(v1=m.group(1).strip()), "NetworkManager", "", (p, inode, path))
    return True


def shell_history(A, ctx, part):
    for pat in ("home/%/.bash_history", "root/.bash_history", "home/%/.zsh_history", "users/%/.zsh_history",
                "users/%/.bash_history", "root/.zsh_history"):
        for p, inode, _, path in find_files(ctx.con, part, pat):
            lines = decode_bytes(read_small(ctx, p, inode, path, 4 << 20)).splitlines()
            user = user_of(path)
            for ln in lines[-5000:]:
                ts = None
                m = re.match(r"^: (\d+):\d+;(.*)$", ln)
                if m:
                    ts, ln = unixtime(m.group(1)), m.group(2)
                if ln.strip():
                    A.add("comandi", ts, ln.strip()[:400], Path(path).name, user, (p, inode, path))


# ------------------------------------------------------------------ Windows: parser di formati binari (2.18)
# Funzioni pure (byte -> dati): ShellBags (shell item), ShimCache, BAM, journal USN, thumbcache, hash percettivi.

KNOWN_SHELL_GUIDS = {
    "20d04fe0-3aea-1069-a2d8-08002b30309d": N_("Questo PC"), "59031a47-3f72-44a7-89c5-5595fe6b30ee": N_("Cartella utente"),
    "031e4825-7b94-4dc3-b131-e946b44c8dd5": N_("Raccolte"), "645ff040-5081-101b-9f08-00aa002f954e": N_("Cestino"),
    "f02c1a0d-be21-4350-88b0-7367fc96ef3c": N_("Rete"), "208d2c60-3aea-1069-a2d7-08002b30309d": N_("Risorse di rete"),
    "679f85cb-0220-4080-b29b-5540cc05aab6": N_("Accesso rapido"), "26ee0668-a00a-44d7-9371-beb064c98683": N_("Pannello di controllo"),
    "21ec2020-3aea-1069-a2dd-08002b30309d": N_("Pannello di controllo"), "018d5c66-4533-4307-9b53-224de2ed1fe6": "OneDrive",
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop", "374de290-123f-4565-9164-39c4925e467b": "Download",
    "088e3905-0323-4b02-9826-5d99428e115f": "Download", "d3162b92-9365-467a-956b-92703aca08af": N_("Documenti"),
    "a8cdff1c-4878-43be-b5fd-f8091c1c60d0": N_("Documenti"), "24ad3ad4-a569-4530-98e1-ab02f9417aa8": N_("Immagini"),
    "3add1653-eb32-4cb0-bbd7-dfa0abb5acca": N_("Immagini"), "3dfdf296-dbec-4fb4-81d1-6a3438bcf4de": N_("Musica"),
    "1cf1260c-4dd0-4ebb-811f-33c572699fde": N_("Musica"), "f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a": "Video",
    "a0953c92-50dc-43bf-be83-3742fed03c9c": "Video", "0db7e03f-fc29-4dc6-9020-ff41b59e513a": N_("Oggetti 3D"),
    "5e6c858f-0e22-4760-9afe-ea3317b67173": N_("Cartella utente"), "9e3995ab-1f9c-4f13-b827-48b24b6c7174": N_("Cartella utente"),
    "e88865ea-0e1c-4e20-9aa6-edcd0212c87c": N_("Galleria"), "f874310e-b6b7-47dc-bc84-b9e6b38f5903": "Home",
    "a52bba46-e9e1-435f-b3d9-28daa648c0f6": "OneDrive", "f42ee2d3-909f-4907-8871-4c22fc0bf756": N_("Documenti"),
    "7d83ee9b-2244-4e70-b1f5-5393042af1e4": "Download", "33e28130-4e1e-4676-835a-98395c3bc3bb": N_("Immagini"),
    "18989b1d-99b5-455b-841c-ab7c74e4ddfc": "Video", "4bd8d571-6d19-48d3-be97-422220080e43": N_("Musica"),
    "b7bede81-df94-4682-a7d8-57a52620b86f": "Screenshot", "ab5fb87b-7ce2-4f83-915d-550846c9537b": N_("Rullino"),
}


def _guid(b):
    import uuid
    try:
        return str(uuid.UUID(bytes_le=bytes(b[:16])))
    except ValueError:
        return ""


def dos_datetime(b, off=0):
    """Data/ora FAT (data a 16 bit, ora a 16 bit) -> ISO; None se nulla o non valida."""
    if len(b) < off + 4:
        return None
    d, t = struct.unpack_from("<HH", b, off)
    if not d:
        return None
    try:
        return dt.datetime(1980 + (d >> 9), (d >> 5) & 15, d & 31, t >> 11, (t >> 5) & 63, (t & 31) * 2).strftime("%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def _beef0004(d):
    """Blocco di estensione 0xBEEF0004 di uno shell item: (nome lungo, creazione, accesso, record MFT) o None."""
    i = d.find(b"\x04\x00\xef\xbe")
    if i < 4:
        return None
    e = i - 4
    try:
        size, ver = struct.unpack_from("<HH", d, e)
        blk = d[e:e + size] if size >= 20 else d[e:]
        ctime, atime = dos_datetime(blk, 8), dos_datetime(blk, 12)
        mft = None
        off = 18
        if ver >= 7:
            ref = struct.unpack_from("<Q", blk, 20)[0]
            mft = (ref & 0xFFFFFFFFFFFF, ref >> 48)
            off = 36
        if ver >= 3:
            off += 2
        if ver >= 9:
            off += 4
        if ver >= 8:
            off += 4
        end = off
        while end + 1 < len(blk) and blk[end:end + 2] != b"\0\0":
            end += 2
        name = blk[off:end].decode("utf-16-le", "replace") if end > off else None
        return name, ctime, atime, mft
    except struct.error:
        return None


def shell_item(d):
    """Uno shell item (ShellBags, LNK): (nome, {modifica, creazione, accesso, mft, tipo}). d comprende i 2 byte di
    dimensione iniziali."""
    info = {}
    if len(d) < 3:
        return None, info
    t = d[2]
    info["tipo"] = t
    if t in (0x1F, 0x2E) and len(d) >= 20:                      # cartella radice (GUID)
        g = _guid(d[4:20])
        return tr(KNOWN_SHELL_GUIDS.get(g, "{" + g + "}")), info
    if 0x20 <= t <= 0x2F:                                       # volume (lettera di unità)
        s = d[3:3 + 20].split(b"\0")[0].decode("ascii", "ignore")
        return (s.rstrip("\\") or "volume"), dict(info, volume=True)
    if (t & 0x70) == 0x40:                                      # percorso di rete (0x41-0x4F, 0xC1-0xCF)
        s = d[5:].split(b"\0")[0].decode("latin-1", "ignore")
        return (s or "rete"), dict(info, rete=True)
    if t == 0x01 and len(d) >= 12:                              # categoria del Pannello di controllo
        return tr("Pannello di controllo (categoria {v1})").format(v1=struct.unpack_from('<I', d, 8)[0]), info
    if t == 0x00 and len(d) >= 30 and d[6:10] == b"\xee\xbb\xfe\x23":     # cartella nota (GUID)
        g = _guid(d[14:30])
        return tr(KNOWN_SHELL_GUIDS.get(g, "{" + g + "}")), info
    if t == 0x00 and len(d) > 8:                                # elementi con property store: computer di rete, ricerche
        strs = [x.decode("utf-16-le") for x in re.findall(rb"(?:[\x20-\x7e]\x00){3,}", d)]
        prov = next((i for i, x in enumerate(strs) if x.startswith("Provider\\")), None)
        if prov is not None and prov + 1 < len(strs):           # computer trovato in rete (WSD/NetBIOS)
            extra = [x for x in strs[prov + 2:prov + 4]]
            info["rete_dettagli"] = ", ".join(extra)
            return "\\\\" + strs[prov + 1], dict(info, rete=True)
        full = next((x for x in strs if re.match(r"^[A-Za-z]:\\|^\\\\", x)), None)
        if full:
            return full, dict(info, volume=True)
        if strs and not _beef0004(d):
            return strs[0], info
    if 0x30 <= t <= 0x3F:                                       # file o cartella
        info["modifica"] = dos_datetime(d, 8)
        short = d[14:].split(b"\0")[0].decode("latin-1", "ignore")
        ext = _beef0004(d)
        if ext:
            name, info["creazione"], info["accesso"], info["mft"] = ext
            return (name or short), info
        return short or None, info
    if t == 0x71 and len(d) >= 30:                              # elemento del Pannello di controllo
        g = _guid(d[14:30])
        return tr(KNOWN_SHELL_GUIDS.get(g, "")) or tr("Pannello di controllo {") + g + "}", info
    ext = _beef0004(d)                                          # elementi «delegati» (0x74, 0x00 con proprietà)
    if ext and ext[0]:
        info["creazione"], info["accesso"], info["mft"] = ext[1], ext[2], ext[3]
        return ext[0], info
    return tr("[elemento di tipo 0x{t:02X}]").format(t=t), info


def shimcache_entries(d):
    """Voci di AppCompatCache (ShimCache): [(percorso, ultima modifica del file, eseguito o None)] in ordine
    (la prima è la più recente). Formati: Windows 10/11 («10ts» con intestazione 0x30/0x34), 8/8.1 (0x80),
    7 / Server 2008 R2 (0xBADC0FEE, 32 e 64 bit)."""
    out = []
    if len(d) < 8:
        return out, None
    sig = struct.unpack_from("<I", d, 0)[0]
    if sig in (0x30, 0x34) or (sig == 0x80 and d[0x80:0x84] in (b"10ts", b"00ts")):
        fmt = "Windows 10/11" if sig != 0x80 else "Windows 8/8.1"
        pos = sig
        while pos + 12 <= len(d) and d[pos:pos + 4] in (b"10ts", b"00ts"):
            dlen = struct.unpack_from("<I", d, pos + 8)[0]
            body = pos + 12
            plen = struct.unpack_from("<H", d, body)[0]
            path = d[body + 2:body + 2 + plen].decode("utf-16-le", "replace")
            q = body + 2 + plen
            if sig == 0x80:                     # 8.1: nome del pacchetto, flag
                if fmt and d[pos:pos + 4] == b"10ts" and q + 2 <= len(d):
                    pk = struct.unpack_from("<H", d, q)[0]
                    q += 2 + pk + 8
                else:
                    q += 8
            ft = struct.unpack_from("<Q", d, q)[0] if q + 8 <= body + dlen else 0
            out.append((path, filetime(ft), None))
            pos = body + dlen
        return out, fmt
    if sig == 0xBADC0FEE:
        n = struct.unpack_from("<I", d, 4)[0]
        # 64 bit: voci da 48 byte con offset a 64 bit; 32 bit: voci da 32 byte
        def try_x64():
            r = []
            for i in range(n):
                e = 128 + 48 * i
                plen, _, poff, ft, flags = struct.unpack_from("<HHxxxxQQI", d, e)
                if not 0 < poff < len(d) or poff + plen > len(d):
                    return None
                r.append((d[poff:poff + plen].decode("utf-16-le", "replace"), filetime(ft), bool(flags & 2)))
            return r
        def try_x86():
            r = []
            for i in range(n):
                e = 128 + 32 * i
                plen, _, poff, ft, flags = struct.unpack_from("<HHIQI", d, e)
                if not 0 < poff < len(d) or poff + plen > len(d):
                    return None
                r.append((d[poff:poff + plen].decode("utf-16-le", "replace"), filetime(ft), bool(flags & 2)))
            return r
        try:
            r = try_x64()
        except struct.error:
            r = None
        if r is None:
            try:
                r = try_x86()
            except struct.error:
                r = None
        return (r or []), "Windows 7"
    return out, None


USN_REASONS = [(0x1, N_("dati sovrascritti")), (0x2, N_("dati aggiunti")), (0x4, N_("dati troncati")), (0x10, N_("flusso con nome sovrascritto")),
               (0x20, N_("flusso con nome esteso")), (0x40, N_("flusso con nome troncato")), (0x100, N_("creato")), (0x200, N_("cancellato")),
               (0x400, N_("attributi estesi cambiati")), (0x800, N_("permessi cambiati")), (0x1000, N_("rinominato (nome vecchio)")),
               (0x2000, N_("rinominato (nome nuovo)")), (0x4000, N_("indicizzazione cambiata")), (0x8000, N_("attributi cambiati")),
               (0x10000, N_("collegamento fisico")), (0x20000, N_("compressione cambiata")), (0x40000, N_("cifratura cambiata")),
               (0x80000, N_("ID oggetto cambiato")), (0x100000, N_("reparse point cambiato")), (0x200000, N_("flusso cambiato")),
               (0x400000, N_("transazione")), (0x800000, N_("integrità cambiata")), (0x80000000, N_("chiuso"))]


def usn_reason_text(r):
    return ", ".join(tr(t) for b, t in USN_REASONS if r & b and b != 0x80000000)


def usn_records(buf):
    """Record del journal NTFS ($UsnJrnl:$J) in un blocco di dati: dict con usn, file (record MFT, sequenza),
    padre (record, sequenza), ts, reason, attr, nome. Accetta le versioni 2 e 3; salta zeri e dati non validi."""
    pos, n = 0, len(buf)
    while pos + 60 <= n:
        rl = struct.unpack_from("<I", buf, pos)[0]
        if rl == 0:
            pos += 8
            continue
        if rl < 60 or rl > 65536 or pos + rl > n:
            pos += 8
            continue
        major = struct.unpack_from("<H", buf, pos + 4)[0]
        try:
            if major == 2:
                fref, pref, usn, ts, reason = struct.unpack_from("<QQQQI", buf, pos + 8)
                attr = struct.unpack_from("<I", buf, pos + 52)[0]
                fnlen, fnoff = struct.unpack_from("<HH", buf, pos + 56)
                f = (fref & 0xFFFFFFFFFFFF, fref >> 48)
                p = (pref & 0xFFFFFFFFFFFF, pref >> 48)
            elif major == 3:
                f_lo, f_hi, p_lo, p_hi, usn, ts, reason = struct.unpack_from("<QQQQQQI", buf, pos + 8)
                attr = struct.unpack_from("<I", buf, pos + 68)[0]
                fnlen, fnoff = struct.unpack_from("<HH", buf, pos + 72)
                f = (f_lo & 0xFFFFFFFFFFFF, f_lo >> 48)
                p = (p_lo & 0xFFFFFFFFFFFF, p_lo >> 48)
            else:
                pos += 8
                continue
        except struct.error:
            break
        if fnoff + fnlen > rl or not fnlen or fnlen % 2:
            pos += 8
            continue
        name = buf[pos + fnoff:pos + fnoff + fnlen].decode("utf-16-le", "replace")
        yield {"usn": usn, "file": f, "padre": p, "ts": filetime(ts), "reason": reason, "attr": attr, "nome": name}
        pos += (rl + 7) & ~7


def thumbcache_entries(data):
    """Miniature di un file thumbcache_*.db (Windows 7-11): [(hash, estensione, dati, larghezza, altezza)]."""
    out = []
    if data[:4] != b"CMMM":
        return out
    ver = struct.unpack_from("<I", data, 4)[0]
    pos = 24 if ver >= 21 else 24
    n = len(data)
    while True:
        i = data.find(b"CMMM", pos)
        if i < 0 or i + 48 > n:
            break
        size = struct.unpack_from("<I", data, i + 4)[0]
        h = struct.unpack_from("<Q", data, i + 8)[0]
        ok = False
        fnlen, padlen, dlen = struct.unpack_from("<III", data, i + 16)
        # varianti dell'intestazione: 56 byte (Windows 8-11; nella versione 32 la dimensione comprende 4 byte dopo i dati),
        # 48 (Windows 7), 60; si sceglie quella in cui i dati cominciano con la firma di un'immagine
        cands = []
        for hdr, extra, wh in ((56, 0, True), (56, 4, True), (48, 0, False), (60, 0, True)):
            if i + hdr <= n and hdr + fnlen + padlen + dlen + extra == size:
                d0 = i + hdr + fnlen + padlen
                blob = data[d0:d0 + dlen]
                sig = blob[:3] == b"\xff\xd8\xff" or blob[:4] == b"\x89PNG" or blob[:2] == b"BM"
                cands.append((not sig, hdr, wh, blob))
        if cands:
            cands.sort(key=lambda x: x[0])
            _, hdr, wh, blob = cands[0]
            w, ht = struct.unpack_from("<II", data, i + 28) if wh else (0, 0)
            if dlen and blob:
                ext = ("jpg" if blob[:3] == b"\xff\xd8\xff" else "png" if blob[:4] == b"\x89PNG" else
                       "bmp" if blob[:2] == b"BM" else "bin")
                out.append((f"{h:016x}", ext, blob, w, ht))
            ok = True
        pos = i + (size if ok and size >= 48 else 4)
    return out


def dhash_image(fp):
    """Hash percettivo (differenza, 64 bit) di un'immagine: resiste a ridimensionamento, ricompressione e piccoli
    ritocchi, non a ritagli o rotazioni diverse da quella indicata nell'EXIF. None se l'immagine non si apre."""
    from PIL import Image, ImageOps
    try:
        with Image.open(fp) as im:
            im.draft("L", (64, 64))
            try:
                im = ImageOps.exif_transpose(im)
            except Exception:
                pass
            g = im.convert("L").resize((9, 8), Image.LANCZOS)
            px = list(g.getdata())
            w, h = im.size
    except Exception:
        return None
    if max(px) - min(px) < 8:
        return None             # immagine quasi uniforme (tutta di un colore): l'hash non distingue nulla
    v = 0
    for r in range(8):
        for c in range(8):
            v = (v << 1) | (px[r * 9 + c] > px[r * 9 + c + 1])
    return v - (1 << 64) if v >= (1 << 63) else v, w, h      # con segno: SQLite memorizza interi a 64 bit


def dhash_dist(a, b):
    return bin((a ^ b) & 0xFFFFFFFFFFFFFFFF).count("1")


# ------------------------------------------------------------------ Windows: installazioni, nuovi artefatti (2.18)

def win_roots(con, part):
    """Radici delle installazioni di Windows nel volume ('' = quella principale, 'Windows.old/'…): ogni cartella che
    contiene Windows/System32/config/SYSTEM (anche cancellato) o profili utente con NTUSER.DAT. La principale per prima."""
    out = set()
    for (path,) in con.execute("SELECT path FROM files WHERE part=? AND type LIKE '%r' "
                               "AND lower(path) LIKE '%windows/system32/config/system'", (part,)):
        if path.lower().endswith("windows/system32/config/system"):
            out.add(path[:len(path) - len("windows/system32/config/system")])
    for (path,) in con.execute("SELECT path FROM files WHERE part=? AND type LIKE '%r' AND deleted=0 "
                               "AND (lower(path) LIKE '%users/%/ntuser.dat' OR lower(path) LIKE '%documents and settings/%/ntuser.dat')",
                               (part,)):
        m = re.match(r"(?i)^((?:[^/]+/){0,2}?)(?:users|documents and settings)/[^/]+/ntuser\.dat$", path)
        if m:
            out.add(m.group(1))
    return sorted(out, key=lambda r: (r != "", r.count("/"), r.lower()))


def hive_rows(ctx, part, like):
    """Come fw, ma se l'alveare (o il registro eventi) non c'è fra i file presenti prova la voce cancellata: il contenuto
    si verifica all'apertura (firma) e l'esito è dichiarato tra gli artefatti di sistema."""
    return fw(ctx, part, like) or fw(ctx, part, like, deleted_ok=True)


def like_lit(s):
    """Testo letterale dentro un modello LIKE con ESCAPE '\\'."""
    return s.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def fw(ctx, part, like, deleted_ok=False):
    """find_files dentro l'installazione di Windows in esame (ctx.win_root)."""
    return find_files(ctx.con, part, like_lit(getattr(ctx, "win_root", "") or "") + like, deleted_ok)


def shellbags(A, root_key, base, user, src, fonte):
    """Cartelle aperte in Esplora file (ShellBags): BagMRU di NTUSER.DAT o UsrClass.dat. Restano anche dopo che la
    cartella o il disco (chiavetta, disco esterno, rete) non esistono più."""
    top = rk(root_key, base)
    if top is None:
        return 0
    n = [0]

    def walk(key, prefix, depth):
        if key is None or depth > 40 or n[0] > 200000:
            return
        mru = rv(key, "MRUListEx")
        order = [i for i in struct.unpack(f"<{len(mru) // 4}I", mru) if i != 0xFFFFFFFF] \
            if isinstance(mru, bytes) and len(mru) >= 4 else []
        names = sorted({int(v.name) for v in (key.values if key is not None else []) if (v.name or "").isdigit()})
        for i in order + [x for x in names if x not in order]:
            d = rv(key, str(i))
            if not isinstance(d, bytes) or len(d) < 3:
                continue
            name, info = shell_item(d)
            if not name:
                continue
            path = name if info.get("volume") or info.get("rete") or not prefix else prefix + "\\" + name
            sub = rk(key, str(i))
            first = bool(order) and i == order[0]
            det = [tr("{fonte}: cartella aperta in Esplora file").format(fonte=fonte)]
            if first:
                det.append(tr("ultima aperta in questo livello (chiave scritta {v1})").format(v1=lw(key).replace('T', ' ')) if lw(key) else
                           tr("ultima aperta in questo livello"))
            for k, lbl in (("modifica", "modifica"), ("creazione", "creazione"), ("accesso", "accesso")):
                if info.get(k):
                    det.append(tr("{lbl} della cartella {v1}").format(lbl=lbl, v1=info[k].replace('T', ' ')))
            if info.get("mft"):
                det.append(tr("record MFT {v1} (sequenza {v2})").format(v1=info['mft'][0], v2=info['mft'][1]))
            if info.get("volume") or info.get("rete"):
                det.append(tr("unità o percorso completo") if info.get("volume") else tr("percorso di rete"))
            if info.get("rete_dettagli"):
                det.append(tr("computer in rete ({rete_dettagli})").format(rete_dettagli=info['rete_dettagli']))
            A.add("cartelle", lw(key) if first else None, path, "; ".join(det), user, src,
                  {"fonte": fonte, "tipo_elemento": info.get("tipo"), "modifica": info.get("modifica"),
                   "creazione": info.get("creazione"), "accesso": info.get("accesso"),
                   "mft": info.get("mft"), "chiave": f"{base}\\{prefix}"[:300]})
            n[0] += 1
            if sub is not None:
                walk(sub, path, depth + 1)

    walk(top, "", 0)
    return n[0]


def win_usrclass(A, ctx, part, row):
    """UsrClass.dat (Windows 7 e successivi): ShellBags della shell."""
    p, inode, _, path = row
    user = user_of(path)
    f = fetch_hive(A, ctx, p, inode, path)
    if not f:
        return
    try:
        hv, root = open_hive(f)
    except Exception:
        return
    try:
        shellbags(A, root, "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", user, (p, inode, path),
                  "ShellBags (UsrClass.dat)")
    finally:
        hv.close()


def win_shim_bam(A, root, cs, src):
    """Dal SYSTEM: ShimCache (AppCompatCache) e BAM/DAM (ultima esecuzione per utente)."""
    v = rv(rk(root, f"{cs}\\Control\\Session Manager\\AppCompatCache"), "AppCompatCache")
    if isinstance(v, bytes):
        ents, fmt = shimcache_entries(v)
        for pos, (path, mt, ex) in enumerate(ents[:5000], 1):
            A.add("esecuzioni", None, path, "; ".join(x for x in (
                tr("ShimCache ({fmt}): posizione {pos} (1 = la più recente)").format(fmt=fmt, pos=pos),
                tr("ultima modifica del file {v1}").format(v1=mt.replace('T', ' ')) if mt else "",
                (tr("eseguito (flag di inserimento)") if ex else tr("non risulta eseguito")) if ex is not None else
                tr("da Windows 8 la presenza in ShimCache NON prova l'esecuzione: il file è stato visto dal sistema")) if x),
                  "", src, {"fonte": "ShimCache", "posizione": pos, "modifica_file": mt, "eseguito": ex, "formato": fmt})
        if v and not ents:
            A.add("sistema", None, tr("ShimCache in formato non riconosciuto"), tr("intestazione 0x{v1:08X}").format(v1=struct.unpack_from('<I', v, 0)[0]),
                  "", src)
    for svc in ("bam", "dam"):
        for base in (f"{cs}\\Services\\{svc}\\State\\UserSettings", f"{cs}\\Services\\{svc}\\UserSettings"):
            for sk in subkeys(rk(root, base)):
                try:
                    vals = list(sk.values)
                except Exception:
                    vals = []
                for val in vals:
                    d = val.data if hasattr(val, "data") else None
                    if not isinstance(d, bytes) or len(d) < 8 or (val.name or "") in ("Version", "SequenceNumber"):
                        continue
                    t = filetime(struct.unpack_from("<Q", d, 0)[0])
                    A.add("esecuzioni", t, val.name, tr("{v1} (Background/Desktop Activity Moderator): ultima esecuzione per l'utente {name}").format(v1=svc.upper(), name=sk.name), sk.name, src, {"fonte": svc.upper(), "sid": sk.name})


def win_activities(A, ctx, part):
    """Cronologia attività di Windows 10/11 (ActivitiesCache.db): app usate, file aperti, appunti."""
    rows = find_files(ctx.con, part, "%/appdata/local/connecteddevicesplatform/%/activitiescache.db")
    for p, inode, _, path in rows:
        db, _wal = fetch_sqlite(ctx, p, inode, path)
        if db is None:
            continue
        user = user_of(path)
        try:
            cols = {c[1].lower() for c in db.execute("PRAGMA table_info(Activity)")}
            if "payload" not in cols:
                continue
            sel = [c for c in ("AppId", "Payload", "ActivityType", "StartTime", "EndTime", "LastModifiedTime",
                               "ClipboardPayload") if c.lower() in cols]
            for r in db.execute(f"SELECT {', '.join(sel)} FROM Activity"):
                x = dict(zip(sel, r))
                try:
                    pl = json.loads(x.get("Payload") or "{}") if isinstance(x.get("Payload"), (str, bytes)) else {}
                except ValueError:
                    pl = {}
                try:
                    app = json.loads(x.get("AppId") or "[]")
                    app = next((a.get("application") for a in app if a.get("platform") in ("windows_win32", "x_exe_path", "packageId")), None) \
                        or (app[0].get("application") if app else "")
                except (ValueError, AttributeError, TypeError):
                    app = str(x.get("AppId") or "")[:200]
                typ = x.get("ActivityType")
                start, end = unixtime(x.get("StartTime")), unixtime(x.get("EndTime"))
                what = {5: tr("app o file aperto"), 6: tr("app in uso"), 10: "appunti", 16: "copia/incolla"}.get(typ, tr("attività tipo {typ}").format(typ=typ))
                title = (tr("Appunti (testo copiato)") if typ == 10 else pl.get("displayText") or pl.get("appDisplayName") or app
                         or tr("attività"))
                extra = []
                if pl.get("description"):
                    extra.append(str(pl["description"])[:300])
                if pl.get("contentUri"):
                    extra.append(str(pl["contentUri"])[:300])
                if pl.get("activeDurationSeconds"):
                    extra.append(tr("attiva per {activeDurationSeconds} s").format(activeDurationSeconds=pl['activeDurationSeconds']))
                if typ == 10 and x.get("ClipboardPayload"):
                    try:
                        cp = json.loads(x["ClipboardPayload"])
                        txt = next((base64.b64decode(c.get("content", "")).decode("utf-8", "replace") for c in cp
                                    if c.get("formatName") == "Text"), "")
                        if txt:
                            extra.append(tr("testo copiato: ") + txt[:500])
                    except Exception:
                        pass
                A.add("uso", start, title, "; ".join(x for x in [tr("Cronologia attività: {what}").format(what=what), f"app {app}" if app else ""] +
                                                     ([f"fine {end.replace('T', ' ')}"] if end else []) + extra if x),
                      user, (p, inode, path), {"fonte": "ActivitiesCache", "tipo": typ, "app": app, "inizio": start, "fine": end})
        except sqlite3.Error:
            pass
        finally:
            db.close()


def _ole_date(b):
    try:
        v = struct.unpack("<d", b[:8])[0]
        return iso(dt.datetime(1899, 12, 30) + dt.timedelta(days=v)) if 0 < v < 2958465 else None
    except (struct.error, OverflowError, ValueError, TypeError):
        return None


def _sid_from_bytes(b):
    try:
        rev, n = b[0], b[1]
        auth = int.from_bytes(b[2:8], "big")
        subs = struct.unpack_from(f"<{n}I", b, 8)
        return f"S-{rev}-{auth}" + "".join(f"-{s}" for s in subs)
    except (IndexError, struct.error):
        return None


def _nb(n):
    return f"{int(n):,} byte".replace(",", ".")


SRUM_APP = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
SRUM_NET = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"


def win_srum(A, ctx, part, users):
    """SRUM (SRUDB.dat, Windows 8+): uso delle app e traffico di rete per app e utente negli ultimi ~30-60 giorni.
    Richiede pyesedb (libesedb, incluso con plaso). Si riporta un riepilogo per app e utente."""
    rows = fw(ctx, part, "windows/system32/sru/srudb.dat")
    if not rows:
        return
    try:
        import pyesedb
    except ImportError:
        A.add("sistema", None, tr("SRUM non letto"), tr("manca il modulo pyesedb (libesedb)"), "", None)
        return
    p, inode, _, path = rows[0]
    f = fetch(ctx, p, inode, path, 4 << 30)
    if not f:
        return
    src = (p, inode, path)
    db = pyesedb.file()
    try:
        db.open(str(f))
    except Exception as e:
        A.add("sistema", None, tr("SRUM non leggibile"), f"{type(e).__name__}: {e}", "", src)
        return
    try:
        tables = {}
        for i in range(db.number_of_tables):
            t = db.get_table(i)
            tables[t.name] = t

        def records(t):
            cols = [(t.get_column(j).name, t.get_column(j).type) for j in range(t.number_of_columns)]
            for i in range(t.number_of_records):
                try:
                    r = t.get_record(i)
                except Exception:
                    continue
                out = {}
                for j, (cn, ct) in enumerate(cols):
                    try:
                        if ct in (7, 8):                       # double / data OLE
                            out[cn] = r.get_value_data(j)
                        elif ct in (1, 2, 3, 4, 5, 14, 15, 17):
                            out[cn] = r.get_value_data_as_integer(j)
                        else:
                            out[cn] = r.get_value_data(j)
                    except Exception:
                        out[cn] = None
                yield out
        ids = {}
        if "SruDbIdMapTable" in tables:
            for r in records(tables["SruDbIdMapTable"]):
                blob = r.get("IdBlob")
                if r.get("IdIndex") is None or not isinstance(blob, (bytes, bytearray)):
                    continue
                ids[r["IdIndex"]] = _sid_from_bytes(blob) if r.get("IdType") == 3 else \
                    blob.decode("utf-16-le", "replace").rstrip("\x00")
        agg = {}
        for tname, kind in ((SRUM_APP, "app"), (SRUM_NET, "rete")):
            t = tables.get(tname)
            if t is None:
                continue
            for r in records(t):
                ts = _ole_date(r.get("TimeStamp") or b"") if isinstance(r.get("TimeStamp"), (bytes, bytearray)) else None
                app, sid = ids.get(r.get("AppId"), f"id {r.get('AppId')}"), ids.get(r.get("UserId"), f"id {r.get('UserId')}")
                a = agg.setdefault((app, sid), {"campioni": 0, "primo": None, "ultimo": None, "letti": 0, "scritti": 0,
                                                "inviati": 0, "ricevuti": 0})
                a["campioni"] += 1
                if ts:
                    a["primo"] = min(a["primo"] or ts, ts)
                    a["ultimo"] = max(a["ultimo"] or ts, ts)
                if kind == "app":
                    a["letti"] += (r.get("ForegroundBytesRead") or 0) + (r.get("BackgroundBytesRead") or 0)
                    a["scritti"] += (r.get("ForegroundBytesWritten") or 0) + (r.get("BackgroundBytesWritten") or 0)
                else:
                    a["inviati"] += r.get("BytesSent") or 0
                    a["ricevuti"] += r.get("BytesRecvd") or 0
        for (app, sid), a in agg.items():
            user = users.get(sid, sid) if sid else ""
            A.add("uso", a["ultimo"], app, "; ".join(x for x in (
                tr("SRUM: {campioni} rilevazioni orarie dal {v1} al {v2}").format(campioni=a['campioni'], v1=(a['primo'] or '?').replace('T', ' '), v2=(a['ultimo'] or '?').replace('T', ' ')),
                tr("disco: letti {v1}, scritti {v2}").format(v1=_nb(a['letti']), v2=_nb(a['scritti'])) if a["letti"] or a["scritti"] else "",
                tr("rete: inviati {v1}, ricevuti {v2}").format(v1=_nb(a['inviati']), v2=_nb(a['ricevuti'])) if a["inviati"] or a["ricevuti"] else "",
                tr("utente {user}").format(user=user) if user else "") if x), user, src, {"fonte": "SRUM", **a, "sid": sid})
    finally:
        db.close()


EVTX_USERDATA_RE = re.compile(r"<UserData>(.*?)</UserData>", re.S)
EVTX_LEAF_RE = re.compile(r"<(\w+)>([^<]*)</\1>")
EVT_LOGS = "windows/system32/winevt/logs/"
# (file, {id: (categoria, descrizione)}, provider richiesto o None)
EVT_RULES = [
    ("security.evtx", {1102: ("eventi", N_("registro di sicurezza CANCELLATO"))}, None),
    ("system.evtx", {104: ("eventi", N_("registro eventi cancellato")), 7045: ("eventi", N_("servizio installato")),
                     6005: ("eventi", N_("avvio del servizio registro eventi (accensione)")),
                     6006: ("eventi", N_("arresto del servizio registro eventi (spegnimento)")),
                     1074: ("eventi", N_("spegnimento o riavvio richiesto")),
                     6008: ("eventi", N_("spegnimento imprevisto"))}, None),
    ("microsoft-windows-terminalservices-localsessionmanager\\%4operational.evtx",
     {21: ("eventi", N_("sessione aperta (anche Desktop remoto)")), 24: ("eventi", N_("sessione disconnessa")),
      25: ("eventi", N_("sessione riconnessa"))}, None),
    ("microsoft-windows-terminalservices-remoteconnectionmanager\\%4operational.evtx",
     {1149: ("eventi", N_("Desktop remoto: autenticazione di rete riuscita"))}, None),
    ("microsoft-windows-windows defender\\%4operational.evtx",
     {1116: ("eventi", N_("Defender: minaccia rilevata")), 1117: ("eventi", N_("Defender: azione sulla minaccia")),
      5001: ("eventi", N_("Defender: protezione in tempo reale DISATTIVATA"))}, None),
    ("microsoft-windows-partition\\%4diagnostic.evtx", {1006: ("usb", N_("disco collegato o scollegato"))}, None),
]


def evtx_fields(xml):
    d = {k: html.unescape(v) for k, v in EVTX_DATA_RE.findall(xml)}
    m = EVTX_USERDATA_RE.search(xml)
    if m:
        for k, v in EVTX_LEAF_RE.findall(m.group(1)):
            d.setdefault(k, html.unescape(v))
    return d


def win_eventi(A, ctx, part):
    """Eventi di interesse dai registri di Windows: cancellazione dei registri, servizi installati, accensioni e
    spegnimenti, sessioni e Desktop remoto (con indirizzo), rilevamenti di Defender, dischi collegati."""
    try:
        import pyevtx  # noqa: F401
    except ImportError:
        A.add("sistema", None, tr("Eventi di sistema non letti"),
              tr("manca il modulo pyevtx (libevtx): servizi, accensioni, sessioni, Defender e dischi USB dai registri "
              "eventi non sono negli artefatti"), "", None)
        return
    for fname, rules, _prov in EVT_RULES:
        rows = hive_rows(ctx, part, EVT_LOGS + fname)
        if not rows:
            continue
        p, inode, _, path = rows[0]
        f = fetch(ctx, p, inode, path)
        if not f:
            A.add("sistema", None, tr("Registro eventi {name} non estratto").format(name=Path(path).name),
                  tr("il file non si legge dalla copia: i suoi eventi non sono negli artefatti"), "", (p, inode, path))
            continue
        st = {}
        try:
            evs = evtx_records(f, set(rules), raw=True, stats=st)
        except Exception as e:
            A.add("sistema", None, tr("Registro eventi {name} non leggibile").format(name=Path(path).name), f"{type(e).__name__}: {e}", "",
                  (p, inode, path))
            continue
        n_rec = sum(1 for ev in evs if ev[4])
        A.add("sistema", None, tr("Registro eventi {name}: eventi di sistema letti").format(name=Path(path).name),
              tr("{v1} eventi utili ({v2})").format(v1=len(evs), v2=', '.join(str(i) for i in sorted(rules)))
              + (tr(", di cui {n_rec} da record recuperati").format(n_rec=n_rec) if n_rec else "") + f"; {evtx_stato(st)}"
              + (tr("; LIMITE RAGGIUNTO: negli artefatti i primi 20000 eventi in ordine di record, {v1} esclusi").format(v1=len(evs) - 20000) if len(evs) > 20000 else ""), "", (p, inode, path),
              {"eventi": len(evs), "da_record_recuperati": n_rec, "esclusi_per_limite": max(0, len(evs) - 20000), **st})
        for eid, t, prov, xml, recuperato in evs[:20000]:
            d = evtx_fields(xml)
            cat, desc = rules[eid]
            desc = tr(desc)
            if eid in (6005, 6006, 104) and "eventlog" not in prov.lower():
                continue
            if eid == 1074 and "user32" not in prov.lower():
                continue
            ts = filetime(t)
            if eid == 7045:
                title = tr("Servizio installato: {v1}").format(v1=d.get('ServiceName', '?'))
                det = tr("{v1} · avvio {v2} · account {v3}").format(v1=d.get('ImagePath', ''), v2=d.get('StartType', ''), v3=d.get('AccountName', ''))
            elif eid == 1074:
                title = tr("Spegnimento/riavvio richiesto")
                det = "; ".join(x for x in (d.get("param1"), d.get("param3"), d.get("param5"), d.get("param7"),
                                            d.get("param6")) if x)
            elif eid in (21, 24, 25):
                title = tr("Sessione {v1}: {v2}").format(v1=d.get('User', '?'), v2=desc.split(' (')[0].replace(tr('sessione '), ''))
                det = tr("indirizzo {v1} · sessione {v2}").format(v1=d.get('Address', ''), v2=d.get('SessionID', ''))
            elif eid == 1149:
                title = tr("Desktop remoto: {v1}").format(v1=d.get('Param1', '?'))
                det = tr("dominio {v1} · indirizzo di origine {v2}").format(v1=d.get('Param2', ''), v2=d.get('Param3', ''))
            elif eid in (1116, 1117):
                title = f"{desc}: {d.get('Threat Name', '?')}"
                det = "; ".join(x for x in (d.get("Path"), d.get("Detection User"), d.get("Action Name"),
                                            d.get("Process Name")) if x)
            elif eid == 1006:
                title = tr("Disco {v1} {v2}").format(v1=(d.get('Manufacturer') or '').strip(), v2=(d.get('Model') or '').strip()).strip()
                det = "; ".join(x for x in (f"seriale {d.get('SerialNumber')}" if d.get("SerialNumber") else "",
                                            tr("capacità {v1} byte").format(v1=d.get('Capacity')) if d.get("Capacity") not in (None, "0") else
                                            tr("capacità 0 (scollegato)"), d.get("ParentId") or "") if x)
            else:
                title = desc[0].upper() + desc[1:]
                det = "; ".join(f"{k} {v}" for k, v in list(d.items())[:6] if v)
            A.add(cat, ts, title + (tr(" (record recuperato)") if recuperato else ""),
                  tr("{name} evento {eid}: {desc}").format(name=Path(path).name, eid=eid, desc=desc) + (f"; {det}" if det else "")
                  + (tr("; record recuperato dallo spazio libero del registro (non più tra gli eventi attivi)")
                     if recuperato else ""), "",
                  (p, inode, path), {"fonte": Path(path).name, "evento": eid, "recuperato": bool(recuperato),
                                     **{k: v for k, v in list(d.items())[:20]}})


def win_usn(A, ctx, part, progress=None):
    """Journal NTFS ($Extend/$UsnJrnl:$J): file creati, cancellati e rinominati con data, anche se il record MFT è
    stato riutilizzato. I percorsi delle cartelle si ricostruiscono dalla MFT e dal journal stesso. Un journal assente
    o non leggibile è dichiarato tra gli artefatti di sistema: «nessuna operazione» non vale come «journal vuoto»."""
    hr = getattr(ctx, "hr", None) or HeadReader(ctx.case)
    ctx.hr = hr
    if not hr.is_ntfs(part):
        return 0
    src = (part, None, "/$Extend/$UsnJrnl:$J")
    fs = hr._fs(part)
    if fs is None:
        A.add("sistema", None, tr("Journal NTFS non letto"),
              tr("il volume non si apre con Sleuth Kit (pytsk3): le operazioni del journal $UsnJrnl non sono state lette"),
              "", src, {"journal": "non_letto"})
        return 0
    try:
        f = fs.open("/$Extend/$UsnJrnl")
    except Exception as e:
        if "not found" in str(e).lower() or "unable to find" in str(e).lower():
            A.add("sistema", None, tr("Journal NTFS assente"),
                  tr("nel volume non c'è $Extend/$UsnJrnl (journal disattivato o cancellato): nessuna operazione su file "
                  "ricavabile dal journal"), "", src, {"journal": "assente"})
        else:
            A.add("sistema", None, tr("Journal NTFS non letto"), tr("$Extend/$UsnJrnl non si apre: {vname}: {e}").format(vname=type(e).__name__, e=e),
                  "", src, {"journal": "non_letto", "errore": str(e)[:300]})
        return 0
    pt = hr.pytsk3
    attr = None
    for a in f:
        nm = a.info.name
        nm = nm.decode("utf-8", "ignore") if isinstance(nm, bytes) else (nm or "")
        if nm == "$J" and int(a.info.type) == int(pt.TSK_FS_ATTR_TYPE_NTFS_DATA):
            attr = a
            break
    if attr is None:
        A.add("sistema", None, tr("Journal NTFS assente"),
              tr("$Extend/$UsnJrnl esiste ma non ha il flusso $J (journal disattivato): nessuna operazione su file "
              "ricavabile dal journal"), "", src, {"journal": "assente"})
        return 0
    bs = fs.info.block_size
    size = int(attr.info.size)
    runs = []
    for r in attr:
        if int(r.flags) & (int(pt.TSK_FS_ATTR_RUN_FLAG_SPARSE) | int(pt.TSK_FS_ATTR_RUN_FLAG_FILLER)) or not r.len:
            continue
        runs.append((int(r.offset) * bs, int(r.len) * bs))

    def read(off, n):
        return f.read_random(off, n, attr.info.type, attr.info.id)

    def seq_of(rec):
        try:
            m = fs.open_meta(inode=rec).info.meta
            return int(m.seq), bool(int(m.flags) & int(pt.TSK_FS_META_FLAG_ALLOC))
        except Exception:
            return None
    return usn_to_artifacts(A, ctx, part, runs, size, read, progress, seq_of=seq_of)


def usn_dirs(con, part):
    """{record MFT: percorso} delle cartelle del volume (dall'elenco dei file); a parità di record vince la voce
    presente, non quella cancellata (il nome cancellato può puntare a un record poi riutilizzato)."""
    out = {}
    for inode, path in con.execute("SELECT inode, path FROM files WHERE part=? AND type LIKE 'd%' "
                                   "ORDER BY deleted", (part,)):
        try:
            out.setdefault(int(str(inode).split("-")[0]), path)
        except ValueError:
            pass
    out.setdefault(5, "")
    return out


USN_KEEP = 0x100 | 0x200 | 0x2000


def usn_to_artifacts(A, ctx, part, runs, size, read, progress=None, limit=500000, seq_of=None):
    """Operazioni del journal come artefatti. Le cartelle si cercano per riferimento completo (record MFT e numero di
    sequenza): il percorso attuale della MFT vale solo se il record è ancora quella cartella (`seq_of(record)` →
    (sequenza, allocato) o None; un record libero ha la sequenza aumentata di 1 alla cancellazione), altrimenti il
    nome registrato nel journal per quel riferimento, altrimenti «cartella MFT n» dichiarando il riutilizzo.
    Oltre `limit` operazioni si tengono le più recenti e il taglio è dichiarato tra gli artefatti di sistema."""
    dirs = usn_dirs(ctx.con, part)
    jdirs = {}                  # cartelle viste nel journal: (record, sequenza) -> (nome, (record, sequenza) del padre)
    old = {}                    # (record, sequenza) -> ultimo nome vecchio (rinomina)
    rows = deque(maxlen=limit)
    seqs = {}
    st = {"totale": 0, "riutilizzati": set(), "non_verificati": set(), "letti": 0}

    def same(rec, seq):
        """True se il record `rec` è oggi la stessa cartella del riferimento con sequenza `seq`; None se non si sa."""
        if rec == 5:
            return True
        if seq_of is None or not seq:
            return None
        if rec not in seqs:
            seqs[rec] = seq_of(rec)
        c = seqs[rec]
        if c is None:
            return None
        cur, alloc = c
        return cur == seq or (not alloc and cur == (seq + 1) & 0xFFFF)

    def resolve(ref, depth=0):
        rec, seq = ref
        ok = same(rec, seq) if rec in dirs else False
        if ok:
            return dirs[rec]
        if ref in jdirs and depth < 64:
            nm, par = jdirs[ref]
            base = resolve(par, depth + 1)
            return (base + "/" if base else "") + nm
        if rec in dirs and ok is None:          # sequenza non verificabile: percorso della MFT, dichiarato
            st["non_verificati"].add(ref)
            return dirs[rec]
        if rec in dirs:
            st["riutilizzati"].add(ref)
            return tr("<cartella MFT {rec} sequenza {seq}: record poi riutilizzato da {v1}>").format(rec=rec, seq=seq, v1=dirs[rec] or '/')
        return tr("<cartella MFT {rec}>").format(rec=rec)
    done = 0
    for off, ln in runs:
        pos = off
        end = min(off + ln, size)
        while pos < end:
            n = min(16 << 20, end - pos)
            buf = read(pos, n)
            if not buf:
                break
            for r in usn_records(buf):
                st["letti"] += 1
                if r["attr"] & 0x10:
                    jdirs[r["file"]] = (r["nome"], r["padre"])
                if r["reason"] & 0x1000:
                    old[r["file"]] = (r["nome"], r["padre"])
                if r["reason"] & 0x80000000 and r["reason"] & USN_KEEP:
                    st["totale"] += 1
                    rows.append(r)
            pos += n
            done += n
            if progress:
                progress(done)
    for r in rows:
        parent = resolve(r["padre"])
        path = (parent + "/" if parent else "") + r["nome"]
        what = []
        if r["reason"] & 0x100:
            what.append("creato")
        if r["reason"] & 0x200:
            what.append("cancellato")
        if r["reason"] & 0x2000:
            o = old.get(r["file"])
            if o:
                b = resolve(o[1])
            what.append("rinominato" + (tr(" (prima: {v1})").format(v1=(b + '/' if b else '') + o[0]) if o else ""))
        A.add("journal", r["ts"], path, "; ".join(what) + tr(" · {v1} · motivi registrati: {v2} · record MFT {v3} (sequenza {v4}) · USN {usn}").format(v1='cartella' if r['attr'] & 0x10 else 'file', v2=usn_reason_text(r['reason']), v3=r['file'][0], v4=r['file'][1], usn=r['usn']),
              user_of(path), None, {"fonte": "$UsnJrnl", "usn": r["usn"], "mft": r["file"], "padre": r["padre"],
                                     "reason": r["reason"], "attr": r["attr"]})
    tss = [r["ts"] for r in rows if r["ts"]]
    dal, al = (min(tss), max(tss)) if tss else (None, None)
    esclusi = st["totale"] - len(rows)
    det = [tr("{v1} operazioni su file (create, cancellate, rinominate) dal {v2} al {v3} (UTC), su "
              "{letti} record del journal").format(v1=len(rows), v2=(dal or '?').replace('T', ' '), v3=(al or '?').replace('T', ' '), letti=st['letti'])]
    if esclusi:
        det.append(tr("LIMITE RAGGIUNTO: le operazioni erano {totale}, tenute le {v1} più recenti; le {esclusi} "
                      "più vecchie (prima del {v2}) non sono negli artefatti").format(totale=st['totale'], v1=len(rows), esclusi=esclusi, v2=(dal or '?').replace('T', ' ')))
    if st["riutilizzati"]:
        det.append(tr("{v1} cartelle con il record MFT poi riutilizzato da un'altra cartella: indicate come "
                      "«cartella MFT n sequenza s», non con il percorso attuale").format(v1=len(st['riutilizzati'])))
    if st["non_verificati"]:
        det.append(tr("{v1} cartelle con il numero di sequenza non verificabile: percorso preso dalla MFT, da "
                      "confermare").format(v1=len(st['non_verificati'])))
    A.add("sistema", al, tr("Journal NTFS $UsnJrnl letto"), "; ".join(det), "", (part, None, "/$Extend/$UsnJrnl:$J"),
          {"journal": "letto", "operazioni": len(rows), "operazioni_totali": st["totale"], "escluse_per_limite": esclusi,
           "limite": limit, "dal": dal, "al": al, "cartelle_record_riutilizzato": len(st["riutilizzati"]),
           "cartelle_sequenza_non_verificata": len(st["non_verificati"])})
    return len(rows)


def win_thumbcache(A, ctx, part):
    """Miniature della cache di Esplora file (thumbcache_*.db): restano anche dopo la cancellazione delle immagini.
    Si estraggono in estratti/miniature, in sola lettura e con gli hash, tra i file estratti (tipo «miniatura»)."""
    rows = find_files(ctx.con, part, "%/appdata/local/microsoft/windows/explorer/thumbcache\\_%.db")
    case, con = ctx.case, ctx.con
    n_tot = 0
    for p, inode, deleted, path in rows:
        if Path(path).name.lower() in ("thumbcache_idx.db",):
            continue
        f = fetch(ctx, p, inode, path, 2 << 30)
        if not f:
            continue
        try:
            ents = thumbcache_entries(f.read_bytes())
        except Exception:
            ents = []
        user = user_of(path)
        for h, ext, blob, w, ht in ents:
            name = f"{h}.{ext}"
            vpath = f"{path}/{name}"
            xid = new_xitem(con, kind="miniatura", part=p, inode=inode, src_path=path, path=vpath, name=name,
                            size=len(blob), note=tr("miniatura {w}x{ht}").format(w=w, ht=ht) if w else "miniatura", store=user, deleted=deleted)
            tmp = ctx.tmp / f"t_{xid}"
            tmp.write_bytes(blob)
            n, md5, sha1, sha256 = hashes_of(tmp)
            rel = store_extracted(case, tmp, "miniature", xid, name)
            con.execute("UPDATE xitems SET relpath=?, md5=?, sha1=?, sha256=?, size=? WHERE id=?",
                        (rel, md5, sha1, sha256, n, xid))
            n_tot += 1
        if ents:
            A.add("recenti", None, tr("Cache delle miniature: {name}").format(name=Path(path).name),
                  tr("{v1} miniature estratte (in File estratti, tipo «miniatura»): immagini e video visti in "
                     "Esplora file, anche se poi cancellati").format(v1=len(ents)), user, (p, inode, path), {"fonte": "thumbcache", "miniature": len(ents)})
        f.unlink(missing_ok=True)
    return n_tot


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
            f.unlink(missing_ok=True)
    ok = 0
    with ThreadPoolExecutor(max_workers=max(1, min(4, (os.cpu_count() or 2)))) as ex:
        for k, (t, r) in enumerate(ex.map(job, todo), 1):
            if r:
                con.execute("INSERT INTO phash VALUES (?,?,?,?,?,?,?)", (t[0], t[1], str(t[2]), t[3], r[0], r[1], r[2]))
                ok += 1
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
    con.execute("DELETE FROM artifacts")
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
            print(tr("Artefatti: collegamenti, jump list, cestino, Cronologia attività, miniature..."), flush=True)
            for fn, args in ((win_lnk, ()), (win_recycle, (users_all,)), (win_activities, ()), (win_thumbcache, ())):
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
    ctx.close()
    res = dict(A.n)
    res["ts"] = now()
    if installazioni:
        case.meta["installazioni_windows"] = installazioni
    print(tr("Artefatti: ") + (", ".join(f"{tr(ART_CATS.get(k, k))} {v}" for k, v in A.n.items()) or tr("nessun artefatto trovato")),
          flush=True)
    return res


# ------------------------------------------------------------------ copie shadow (VSS)

VSS_SKIP = re.compile(r"(?i)^(\$|system volume information/|windows/winsxs/|windows/softwaredistribution/|"
                      r"windows/installer/|windows/servicing/|programdata/microsoft/windows defender/|"
                      r"(pagefile|hiberfil|swapfile)\.sys$)")
VSS_FILE_MAX = 200 << 20
VSS_TOTAL_MAX = 20 << 30


def run_vss(case, con):
    import pytsk3
    import pyvshadow
    ctx = Ctx(case, con, "Copie shadow")
    con.execute("DELETE FROM doc_text WHERE source='x' AND inode IN (SELECT CAST(id AS TEXT) FROM xitems WHERE kind='vss')")
    con.execute("DELETE FROM xitems WHERE kind='vss'")
    fa.rmtree_force(case.root / X_ROOT / "vss")
    con.commit()
    img = ImageFile(case.image)

    class StoreImg(pytsk3.Img_Info):
        def __init__(self, store):
            self._s = store
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, off, size):
            self._s.seek(off)
            return self._s.read(size)

        def get_size(self):
            return self._s.volume_size

    class RegionImg(pytsk3.Img_Info):
        def __init__(self, reg):
            self._r = reg
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, off, size):
            self._r.seek(off)
            return self._r.read(size)

        def get_size(self):
            return self._r.length

    stores_found, files_found, total = 0, 0, 0
    report = []
    for p in case.meta.get("partitions", []):
        if not p.get("readable") or "NTFS" not in (p.get("fs") or "").upper():
            continue
        start, length = part_bounds(case, p, img)
        reg = Region(img, start, length)
        vol = pyvshadow.volume()
        try:
            vol.open_file_object(reg)
        except Exception:
            continue
        n = vol.number_of_stores
        if not n:
            vol.close()
            continue
        print(tr("Copie shadow: {n} nella partizione all'offset {offset}").format(n=n, offset=p['offset']), flush=True)
        cur_fs = pytsk3.FS_Info(RegionImg(Region(img, start, length)))
        cur = {}
        for path, d in con.execute("SELECT path, deleted FROM files WHERE part=? AND type LIKE '%r'", (p["offset"],)):
            k = path.lower()
            cur[k] = min(cur.get(k, 1), d)
        for si in range(n):
            st = vol.get_store(si)
            when = iso(st.creation_time)
            label = tr("copia shadow {v1} del {v2}").format(v1=si + 1, v2=when.replace('T', ' ') if when else '?')
            stores_found += 1
            try:
                fs = pytsk3.FS_Info(StoreImg(st))
            except Exception as e:
                print(tr("  {label}: file system non leggibile ({e})").format(label=label, e=e), flush=True)
                continue
            found = 0
            stack = [("", fs.open_dir(path="/"))]
            while stack:
                base, d = stack.pop()
                for ent in d:
                    try:
                        nm = ent.info.name.name.decode("utf-8", "replace")
                    except Exception:
                        continue
                    if nm in (".", "..") or ent.info.meta is None:
                        continue
                    rel = (base + "/" + nm).lstrip("/")
                    if VSS_SKIP.search(rel):
                        continue
                    if int(ent.info.name.flags) & int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC):
                        continue
                    t = ent.info.meta.type
                    if t == pytsk3.TSK_FS_META_TYPE_DIR:
                        try:
                            stack.append((rel, ent.as_directory()))
                        except Exception:
                            pass
                        continue
                    if t != pytsk3.TSK_FS_META_TYPE_REG or ent.info.meta.size <= 0:
                        continue
                    m = ent.info.meta
                    size, mtime = m.size, unixtime(m.mtime)
                    state = cur.get(rel.lower())
                    if state == 0:      # ancora presente: conta solo se è una versione diversa
                        try:
                            cm = cur_fs.open(path="/" + rel).info.meta
                            if cm.size == size and cm.mtime == m.mtime:
                                continue
                        except Exception:
                            pass
                        note = tr("versione precedente (nella copia attuale il file è diverso)")
                    elif state == 1:
                        note = tr("nella copia attuale il file risulta cancellato")
                    else:
                        note = tr("presente solo nella copia shadow")
                    xid = new_xitem(con, kind="vss", part=p["offset"], inode=str(m.addr), src_path=rel,
                                    inner=rel, path=f"[{label}] {rel}", name=nm, size=size, mtime=mtime,
                                    note=note, store=label)
                    found += 1
                    if size <= VSS_FILE_MAX and ctx.extracted + size <= VSS_TOTAL_MAX:
                        tmpf = ctx.tmp / f"v{xid}"
                        try:
                            with open(tmpf, "wb") as fh:
                                fo = ent.read_random
                                off = 0
                                while off < size:
                                    b = fo(off, min(4 << 20, size - off))
                                    if not b:
                                        break
                                    fh.write(b)
                                    off += len(b)
                            data = open(tmpf, "rb").read(fa.MAX_EXTRACT)
                            index_text(con, case, f"[{label}] {rel}", data, nm, "x", None, xid, 0, ctx.tmp)
                            nb, md5, sha1, sha256 = hashes_of(tmpf)
                            relp = store_extracted(case, tmpf, f"vss/{si + 1}", xid, nm)
                            ctx.extracted += nb
                            con.execute("UPDATE xitems SET relpath=?, md5=?, sha1=?, sha256=? WHERE id=?",
                                        (relp, md5, sha1, sha256, xid))
                        except Exception:
                            tmpf.unlink(missing_ok=True)
                    else:
                        con.execute("UPDATE xitems SET note=? WHERE id=?", (note + tr("; non estratto (troppo grande)"), xid))
                    if found % 200 == 0:
                        con.commit()
                        ctx.say(tr("{label}: {found} file diversi dalla copia attuale").format(label=label, found=found))
            con.commit()
            files_found += found
            total += 1
            report.append({"offset": p["offset"], "copia": label, "file": found})
            print(tr("Copie shadow: {label}: {found} file cancellati o in versione precedente").format(label=label, found=found), flush=True)
        vol.close()
    img.close()
    snap = {}
    if any(p.get("apfs") for p in case.meta.get("partitions", [])):
        fa.rmtree_force(case.root / X_ROOT / "snapshot")
        try:
            snap = run_apfs_snapshots(case, con, ctx)
        except Exception as e:
            print(tr("Snapshot APFS: {vname}: {e}").format(vname=type(e).__name__, e=e), flush=True)
            snap = {"errore": str(e)}
        stores_found += snap.get("snapshot", 0)
        files_found += snap.get("file", 0)
        report += snap.get("dettaglio", [])
    ctx.close()
    print(tr("Copie shadow: {stores_found} copie, {files_found} file recuperati o in versione precedente").format(stores_found=stores_found, files_found=files_found), flush=True)
    return {"copie": stores_found, "file": files_found, "dettaglio": report, "ts": now(),
            **({"snapshot_apfs": snap.get("snapshot", 0)} if snap else {})}


# ------------------------------------------------------------------ snapshot APFS (2.14)

SNAP_SKIP = re.compile(r"(?i)^(\.spotlight-v100/|\.documentrevisions-v100/|\.mobilebackups|private/var/vm/|"
                       r"private/var/folders/|private/var/db/uuidtext/|private/var/db/diagnostics/|"
                       r"system/library/caches/|library/caches/|users/[^/]+/library/caches/|"
                       r"\.fseventsd/|private/var/db/spindump/)")
SNAP_RE = re.compile(r"^\[(\d+)\]\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?)\s+\(([^)]*)\)\s+(.*?)\s*(\(dataless\))?\s*$")


def _tsk_apfs_args(case, p):
    """Argomenti comuni di Sleuth Kit per un volume APFS (offset del contenitore, blocco APSB, chiave)."""
    a = p["apfs"]
    base = ["-o", str(a["real_offset"]), "-P", "apfs"]
    env = dict(os.environ, TZ="UTC")
    try:
        out = subprocess.run(["pstat", *base, str(case.image)], capture_output=True, timeout=600, env=env,
                             stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    txt = fa.dec(out.stdout)
    blk = None
    for blkm in re.finditer(r"Volume ([0-9a-fA-F-]{36})\s*\n[|\s=]*\n?\|?\s*APSB Block Number:\s*(\d+)", txt):
        if blkm.group(1).lower() == (a.get("uuid") or "").lower():
            blk = blkm.group(2)
    if blk is None:
        vols = re.findall(r"APSB Block Number:\s*(\d+)", txt)
        if len(vols) > a.get("vol", 0):
            blk = vols[a.get("vol", 0)]
    if blk is None:
        return None
    args = base + ["-B", blk]
    if a.get("encrypted"):
        pw = next((s.get("valore") for s in ap.secrets() if (s.get("tipo") or "auto") in ("password", "auto")
                   and not re.match(r"^[A-Z0-9]{4}(-[A-Z0-9]{4}){5}$", (s.get("valore") or "").upper())), None)
        if not pw:
            return "cifrato"
        args += ["-f", "apfs", "-k", pw]
    return args


def apfs_snapshot_list(case, p):
    """Snapshot di un volume APFS letti con Sleuth Kit (fsstat): [{xid, data, nome, dataless}]."""
    args = _tsk_apfs_args(case, p)
    if not isinstance(args, list):
        return args
    out = subprocess.run(["fsstat", *args, str(case.image)], capture_output=True, timeout=600,
                         env=dict(os.environ, TZ="UTC"), stdin=subprocess.DEVNULL)
    if out.returncode:
        return tr("illeggibile: ") + (fa.dec(out.stderr).strip().splitlines() or [tr("errore di Sleuth Kit")])[0][:200]
    return parse_snapshots(fa.dec(out.stdout)), args


def parse_snapshots(txt):
    res, on = [], False
    for line in txt.splitlines():
        if line.strip() == "Snapshots":
            on = True
            continue
        if on:
            m = SNAP_RE.match(line.strip())
            if m:
                res.append({"xid": int(m.group(1)), "data": m.group(2).replace(" ", "T")[:19],
                            "nome": m.group(4).strip(), "dataless": bool(m.group(5))})
            elif line.strip() and not line.startswith("-") and res:
                on = False
    return res


def _fls_map(case, args, snap=None):
    """{percorso minuscolo: (inode, dimensione, mtime, percorso)} dei file regolari (fls -m)."""
    cmd = ["fls", *args, *(["-S", str(snap)] if snap is not None else []), "-r", "-m", "/", str(case.image)]
    out = subprocess.run(cmd, capture_output=True, env=dict(os.environ, TZ="UTC"), stdin=subprocess.DEVNULL)
    res = {}
    for line in fa.dec(out.stdout).splitlines():
        f = line.split("|")
        if len(f) < 11 or not f[3].startswith("r/"):
            continue
        path = f[1].lstrip("/")
        if " -> " in path or path.endswith(" (deleted)"):
            continue
        try:
            res[path.lower()] = (f[2].split("-")[0], int(f[6]), int(f[8]), path)
        except ValueError:
            continue
    return res


def run_apfs_snapshots(case, con, ctx):
    """Snapshot dei volumi APFS (es. snapshot locali di Time Machine): file presenti nello snapshot ma
    cancellati o diversi nel volume attuale, come per le copie shadow di Windows. Il volume di sistema
    sigillato è saltato (il suo snapshot è il sistema operativo stesso)."""
    if not shutil.which("fls"):
        return {"snapshot": 0, "file": 0, "dettaglio": [], "nota": tr("Sleuth Kit non disponibile")}
    tot_s, tot_f, report = 0, 0, []
    for p in case.meta.get("partitions", []):
        a = p.get("apfs")
        if not a or not p.get("readable"):
            continue
        if (a.get("role") or "").lower() in ("preboot", "recovery", "vm", "update"):
            continue
        if fa.lookup(con, p["offset"], "system/library/coreservices/systemversion.plist") and not \
                fa.lookup(con, p["offset"], "users"):
            print(tr("Snapshot APFS: volume di sistema «{v1}» saltato (sigillato: il suo snapshot è macOS stesso).").format(v1=a.get('name')),
                  flush=True)
            continue
        try:
            r = apfs_snapshot_list(case, p)
        except Exception as e:
            print(tr("Snapshot APFS: volume «{v1}»: {vname}: {e}").format(v1=a.get('name'), vname=type(e).__name__, e=e), flush=True)
            continue
        if r == "cifrato":
            report.append({"offset": p["offset"], "volume": a.get("name"), "nota": tr("cifrato: serve la password per gli snapshot")})
            print(tr("Snapshot APFS: volume «{v1}» cifrato: Sleuth Kit richiede la password dell'utente (la "
                     "chiave di ripristino non basta) per leggere gli snapshot.").format(v1=a.get('name')), flush=True)
            continue
        if isinstance(r, str):
            report.append({"offset": p["offset"], "volume": a.get("name"), "nota": tr("snapshot non letti: ") + r})
            print(tr("Snapshot APFS: volume «{v1}»: Sleuth Kit non riesce a leggerlo ({r}).").format(v1=a.get('name'), r=r), flush=True)
            continue
        if not r:
            continue
        snaps, args = r
        print(tr("Snapshot APFS: volume «{v1}»: {v2} snapshot").format(v1=a.get('name'), v2=len(snaps)), flush=True)
        if not snaps:
            report.append({"offset": p["offset"], "volume": a.get("name"), "snapshot": 0})
            continue
        cur = _fls_map(case, args)
        for sn in snaps:
            tot_s += 1
            label = tr("snapshot APFS {nome} del {v1} UTC").format(nome=sn['nome'], v1=sn['data'].replace('T', ' '))
            if sn["dataless"]:
                report.append({"offset": p["offset"], "volume": a.get("name"), "copia": label, "file": 0,
                               "nota": tr("snapshot senza dati (dataless)")})
                continue
            found = 0
            for k, (ino, size, mtime, rel) in _fls_map(case, args, sn["xid"]).items():
                if SNAP_SKIP.search(rel) or size <= 0:
                    continue
                c = cur.get(k)
                if c and c[1] == size and c[2] == mtime:
                    continue
                note = (tr("versione precedente (nel volume attuale il file è diverso)") if c
                        else tr("presente solo nello snapshot (cancellato o spostato nel volume attuale)"))
                nm = Path(rel).name
                xid = new_xitem(con, kind="vss", part=p["offset"], inode=str(ino), src_path=rel,
                                inner=rel, path=f"[{label}] {rel}", name=nm, size=size, mtime=unixtime(mtime),
                                note=note, store=label)
                found += 1
                if size <= VSS_FILE_MAX and ctx.extracted + size <= VSS_TOTAL_MAX:
                    tmpf = ctx.tmp / f"s{xid}"
                    try:
                        with open(tmpf, "wb") as fh:
                            subprocess.run(["icat", *args, "-S", str(sn["xid"]), str(case.image), ino], stdout=fh,
                                           stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, check=True)
                        data = open(tmpf, "rb").read(fa.MAX_EXTRACT)
                        index_text(con, case, f"[{label}] {rel}", data, nm, "x", None, xid, 0, ctx.tmp)
                        nb, md5, sha1, sha256 = hashes_of(tmpf)
                        relp = store_extracted(case, tmpf, f"snapshot/{sn['xid']}", xid, nm)
                        ctx.extracted += nb
                        con.execute("UPDATE xitems SET relpath=?, md5=?, sha1=?, sha256=? WHERE id=?",
                                    (relp, md5, sha1, sha256, xid))
                    except Exception:
                        tmpf.unlink(missing_ok=True)
                else:
                    con.execute("UPDATE xitems SET note=? WHERE id=?", (note + tr("; non estratto (troppo grande)"), xid))
                if found % 200 == 0:
                    con.commit()
                    ctx.say(tr("{label}: {found} file diversi dal volume attuale").format(label=label, found=found))
            con.commit()
            tot_f += found
            report.append({"offset": p["offset"], "volume": a.get("name"), "copia": label, "file": found})
            print(tr("Snapshot APFS: {label}: {found} file cancellati o in versione precedente").format(label=label, found=found), flush=True)
    return {"snapshot": tot_s, "file": tot_f, "dettaglio": report}


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
                f.unlink(missing_ok=True)

    n_ok = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for k, (t, text) in enumerate(ex.map(job, todo), 1):
            if useful_text(text):
                kind, part, inode, deleted, path = t[:5]
                src = {"fs": "ocr", "pdf": "ocr", "x": "x", "carving": "carving"}[kind]
                fa.store_text(con, path, text.replace("\r\n", "\n"), src, part, str(inode), deleted,
                              tr("OCR (testo letto da immagine)") if kind != "pdf" else tr("OCR (PDF scansionato)"))
                n_ok += 1
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


# ------------------------------------------------------------------ liste di hash (NSRL e altre)

HEX = re.compile(rb"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])")


def hash_lists():
    return fa.load_settings().get("liste_hash", [])


def save_hash_lists(lists):
    d = fa.load_settings()
    d["liste_hash"] = lists
    fa.save_settings(d)


def iter_list_hashes(path, wanted_lens=(32, 40, 64)):
    """Hash contenuti in una lista: testo/CSV (NSRLFile.txt, HashKeeper, elenchi) o NSRL RDS
    in formato SQLite."""
    p = Path(path)
    with open(p, "rb") as fh:
        head = fh.read(16)
    if head == b"SQLite format 3\x00":
        con = sqlite3.connect(f"file:{p.as_posix()}?mode=ro&immutable=1", uri=True)
        try:
            for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')").fetchall():
                cols = [c[1] for c in con.execute(f'PRAGMA table_info("{t}")')]
                hc = [c for c in cols if c.lower() in ("md5", "sha1", "sha256", "sha-1", "sha-256", "hash")]
                if not hc:
                    continue
                for row in con.execute(f'SELECT {", ".join(chr(34) + c + chr(34) for c in hc)} FROM "{t}"'):
                    for v in row:
                        if v:
                            yield str(v).strip().lower()
                break
        finally:
            con.close()
        return
    with open(p, "rb") as fh:
        for line in fh:
            for m in HEX.findall(line):
                yield m.decode().lower()


HEX_FULL = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}")


def iter_list_entries(path):
    """(hash, categoria o None) di una lista. I file JSON in formato Project VIC (VICS) o CAID si leggono per campi
    (MD5/SHA1/SHA256 e Category); gli altri formati come iter_list_hashes, senza categoria."""
    p = Path(path)
    if p.suffix.lower() == ".json" and p.stat().st_size < (3 << 30):
        try:
            with open(p, encoding="utf-8-sig") as fh:
                data = json.load(fh)
        except (ValueError, OSError, UnicodeDecodeError):
            data = None
        found = False
        stack = [data] if data is not None else []
        while stack:
            x = stack.pop()
            if isinstance(x, dict):
                keys = {str(k).lower(): k for k in x}
                cat = next((x[keys[k]] for k in ("category", "categoria", "classification") if k in keys), None)
                for k in ("md5", "sha1", "sha-1", "sha256", "sha-256"):
                    v = x.get(keys[k]) if k in keys else None
                    if isinstance(v, str) and HEX_FULL.fullmatch(v.strip().lower()):
                        found = True
                        yield v.strip().lower(), (str(cat) if cat not in (None, "") else None)
                stack.extend(v for v in x.values() if isinstance(v, (dict, list)))
            elif isinstance(x, list):
                stack.extend(x)
        if found:
            return
    for h in iter_list_hashes(path):
        yield h, None


def phash_index(refs):
    """Indice per la ricerca dei vicini entro PHASH_NEAR bit: 64 bit in PHASH_NEAR+1 pezzi; due hash a distanza
    <= PHASH_NEAR coincidono in almeno un pezzo (principio dei cassetti)."""
    k = PHASH_NEAR + 1
    bounds = [(64 * i // k, 64 * (i + 1) // k) for i in range(k)]
    idx = {}
    for j, (h, nm) in enumerate(refs):
        u = h & 0xFFFFFFFFFFFFFFFF
        for i, (a, b) in enumerate(bounds):
            idx.setdefault((i, (u >> a) & ((1 << (b - a)) - 1)), []).append(j)
    return bounds, idx


def phash_nearest(h, refs, index):
    bounds, idx = index
    u = h & 0xFFFFFFFFFFFFFFFF
    cand = set()
    for i, (a, b) in enumerate(bounds):
        cand.update(idx.get((i, (u >> a) & ((1 << (b - a)) - 1)), ()))
    best = None
    for j in cand:
        d = dhash_dist(h, refs[j][0])
        if d <= PHASH_NEAR and (best is None or d < best[0]):
            best = (d, refs[j][1])
    return best


def compare_phash_folder(con, L, progress):
    """Lista «cartella di immagini di riferimento»: immagini del caso simili (hash percettivo) a quelle della cartella."""
    if not fa.table_exists(con, "phash") or not con.execute("SELECT 1 FROM phash LIMIT 1").fetchone():
        return {"nome": L["nome"], "errore": tr("esegui prima «Hash percettivi» tra le analisi aggiuntive")}
    progress(tr("Lista «{nome}»: calcolo gli hash percettivi delle immagini di riferimento…").format(nome=L['nome']))
    refs = phash_reference(L["path"])
    if not refs:
        return {"nome": L["nome"], "errore": tr("nessuna immagine leggibile nella cartella")}
    index = phash_index(refs)
    hits = 0
    for src, part, inode, path, d in con.execute("SELECT source, part, inode, path, dhash FROM phash").fetchall():
        best = phash_nearest(d, refs, index)
        if not best:
            continue
        hits += 1
        source = src if src in ("x", "carving") else "fs"
        con.execute("INSERT INTO known VALUES (?,?,?,?,?,?,?)",
                    (source, part, inode, path, L["tipo"], L["nome"], f"dhash:{d & 0xFFFFFFFFFFFFFFFF:016x}"))
        if L["tipo"] == "segnalati":
            add_anomaly(con, "segnalato", source, part, inode, path,
                        tr("immagine simile a «{v1}» della cartella di riferimento «{nome}» (hash percettivo: {v2} "
                           "bit diversi su 64{v3}): da verificare a vista").format(v1=best[1], nome=L['nome'], v2=best[0], v3=tr(', quasi identica') if best[0] <= 4 else ''),
                        real=f"dhash:{d & 0xFFFFFFFFFFFFFFFF:016x}", sev=3 if best[0] <= 4 else 2)
    return {"nome": L["nome"], "tipo": L["tipo"], "immagini_riferimento": len(refs), "file": hits, "percettivo": True}


def compare_lists(case, progress):
    lists = hash_lists()
    if not lists:
        raise ValueError(tr("Nessuna lista di hash: aggiungine una (NSRL, elenco di hash noti o da segnalare)."))
    con = sqlite3.connect(case.db_path, timeout=60)
    ensure_schema(con)
    idx = {}
    warn = None
    if fa.table_exists(con, "hashes"):
        for part, inode, path, md5, sha1, sha256 in con.execute("SELECT part, inode, path, md5, sha1, sha256 FROM hashes"):
            for h in (md5, sha1, sha256):
                if h:
                    idx.setdefault(h.lower(), []).append(("fs", part, inode, path))
    else:
        warn = (tr("Hash dei file della copia non ancora calcolati: confrontati solo i file estratti. "
                "Per tutti i file esegui Analisi aggiuntive → Hash dei file."))
    for xid, path, md5, sha1, sha256 in con.execute("SELECT id, path, md5, sha1, sha256 FROM xitems WHERE sha256 IS NOT NULL"):
        for h in (md5, sha1, sha256):
            if h:
                idx.setdefault(h.lower(), []).append(("x", None, str(xid), path))
    if not idx and not all(Path(L["path"]).is_dir() for L in lists):
        con.close()
        raise ValueError(tr("Calcola prima gli hash dei file (Analisi aggiuntive → Hash dei file)."))
    con.execute("DELETE FROM known")
    con.execute("DELETE FROM anomalies WHERE kind='segnalato'")
    res = []
    for L in lists:
        if not Path(L["path"]).exists():
            res.append({"nome": L["nome"], "errore": tr("file della lista non trovato")})
            continue
        if Path(L["path"]).is_dir():
            res.append(compare_phash_folder(con, L, progress))
            con.commit()
            continue
        n = hits = 0
        seen = set()
        for h, cat in iter_list_entries(L["path"]):
            n += 1
            if n % 500000 == 0:
                progress(tr("Lista «{nome}»: {n:,} hash letti, {hits:,} file trovati").format(nome=L['nome'], n=n, hits=hits).replace(",", "."))
            for src, part, inode, path in idx.get(h, ()):
                key = (src, part, inode)
                if key in seen:
                    continue
                seen.add(key)
                hits += 1
                con.execute("INSERT INTO known VALUES (?,?,?,?,?,?,?)", (src, part, inode, path, L["tipo"], L["nome"], h))
                if L["tipo"] == "segnalati":
                    add_anomaly(con, "segnalato", src, part, inode, path,
                                tr("hash presente nella lista «{nome}»").format(nome=L['nome']) + (tr(", categoria {cat}").format(cat=cat) if cat else ""),
                                real=h, sev=3)
        res.append({"nome": L["nome"], "tipo": L["tipo"], "hash": n, "file": hits})
        con.commit()
    con.close()
    out = {"liste": res, "ts": now(), **({"avviso": warn} if warn else {})}
    case.meta["liste_hash"] = out
    case.save()
    case.log("confronto_liste_hash", out)
    return out


# ------------------------------------------------------------------ report

def report_md(case):
    """Sezioni del report sulle analisi estese (markdown)."""
    L = []
    m = case.meta
    est = m.get("estese") or {}
    if not est and not m.get("volumi_cifrati") and not m.get("liste_hash"):
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
        if fa.table_exists(con, "artifacts") and "artefatti" in est:
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
            L += ["", tr("Elementi raccolti: ") + ", ".join(f"{tr(ART_CATS.get(k, k))} {v}" for k, v in cnt.items()) +
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
                                                          "(lingue {v3}).").format(v1=o.get('file', 0), v2=o.get('con_testo', 0), v3=o.get('lingue', '')), ""]
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

def agent_tools(case):
    est = case.meta.get("estese") or {}
    tools = []

    def _db():
        return fa.db_ro(case)

    def query_artifacts(category: str = "", contains: str = "", limit: int = 100) -> str:
        """Artefatti di sistema già estratti (registro di Windows, prefetch, Amcache, collegamenti,
        jump list, cestino, cronologia web, account, dispositivi USB, reti...). Orari UTC salvo
        indicazione contraria.

        Args:
            category: sistema, utenti, usb, programmi, esecuzioni, recenti, cartelle (ShellBags), journal (file creati/cancellati/rinominati dal journal NTFS), eventi (registri eventi: servizi, accensioni, Desktop remoto, Defender), uso (Cronologia attività, SRUM), reti, cestino, web, download, ricerche, comandi; vuoto per tutte
            contains: testo da cercare in elemento, dettagli o utente
            limit: righe massime (max 300)
        """
        con = _db()
        w, a = ["1=1"], []
        if category:
            w.append("cat = ?"); a.append(category.strip().lower())
        if contains:
            w.append("(title LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\' OR user LIKE ? ESCAPE '\\')")
            a += [fa.like(contains)] * 3
        lim = max(1, min(int(limit), 300))
        try:
            tot = con.execute(f"SELECT COUNT(*) FROM artifacts WHERE {' AND '.join(w)}", a).fetchone()[0]
            rows = con.execute(f"SELECT cat, ts, title, detail, user, src_path FROM artifacts WHERE {' AND '.join(w)} "
                               f"ORDER BY ts IS NULL, ts DESC LIMIT {lim}", a).fetchall()
            cnt = con.execute("SELECT cat, COUNT(*) FROM artifacts GROUP BY cat").fetchall()
        finally:
            con.close()
        out = [tr("{tot} artefatti (mostrati {v1}). Per categoria: ").format(tot=tot, v1=len(rows)) + ", ".join(f"{k} {v}" for k, v in cnt)]
        out += [tr("- [{c}] {v1} | {ti} | {d} | utente {v2} | fonte {s}").format(c=c, v1=(t or '').replace('T', ' '), ti=ti, d=d, v2=u or '-', s=s) for c, t, ti, d, u, s in rows]
        return fa.clip("\n".join(out))

    def search_emails(contains: str = "", sender: str = "", limit: int = 50) -> str:
        """Messaggi di posta estratti da PST/OST, mbox, EML e MSG (anche dentro archivi):
        data, mittente, destinatari, oggetto, numero di allegati.

        Args:
            contains: testo da cercare in oggetto, corpo, destinatari
            sender: testo da cercare nel mittente
            limit: righe massime (max 200)
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
                               f"WHERE {' AND '.join(w)} ORDER BY date DESC LIMIT {max(1, min(int(limit), 200))}", a).fetchall()
        finally:
            con.close()
        out = [tr("{tot} messaggi (mostrati {v1}); leggi il testo con read_email(email_id)").format(tot=tot, v1=len(rows))]
        out += [tr("- id {i} | {v1} | da {s} | a {r} | «{o}» | allegati {n} | {p} › {fo}").format(i=i, v1=(d or '').replace('T', ' '), s=s, r=r, o=o, n=n, p=p, fo=fo)
                for i, d, s, r, o, n, p, fo in rows]
        return fa.clip("\n".join(out))

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

    def list_extracted(contains: str = "", kind: str = "", limit: int = 100) -> str:
        """File estratti da archivi (ZIP, RAR, 7z...), allegati di posta e copie shadow:
        percorso, dimensione, data, cifratura, hash. Leggili con read_extracted.

        Args:
            contains: testo da cercare nel percorso
            kind: archivio, allegato o vss; vuoto per tutti
            limit: righe massime (max 300)
        """
        con = _db()
        w, a = ["1=1"], []
        if contains:
            w.append("path LIKE ? ESCAPE '\\'"); a.append(fa.like(contains))
        if kind:
            w.append("kind = ?"); a.append(kind)
        try:
            tot = con.execute(f"SELECT COUNT(*) FROM xitems WHERE {' AND '.join(w)}", a).fetchone()[0]
            rows = con.execute(f"SELECT id, kind, path, size, mtime, encrypted, sha256, note FROM xitems WHERE "
                               f"{' AND '.join(w)} ORDER BY path LIMIT {max(1, min(int(limit), 300))}", a).fetchall()
        finally:
            con.close()
        out = [tr("{tot} file estratti (mostrati {v1})").format(tot=tot, v1=len(rows))]
        out += [tr("- id {i} [{k}] {p} | {z} B | {v1}{v2} | SHA-256 {v3}").format(i=i, k=k, p=p, z=z, v1=(m or '').replace('T', ' '), v2=tr(' | CIFRATO') if e else '', v3=h or '-')
                + (f" | {n}" if n else "") for i, k, p, z, m, e, h, n in rows]
        return fa.clip("\n".join(out))

    def read_extracted(item_id: int, max_chars: int = 8000) -> str:
        """Testo di un file estratto (da archivio, allegato o copia shadow).

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

    def list_anomalies(kind: str = "", limit: int = 100) -> str:
        """Anomalie: estensioni che non corrispondono al contenuto (anche eseguibili mascherati),
        file protetti da password, possibili contenitori cifrati, volumi cifrati, hash segnalati.

        Args:
            kind: estensione, cifrato, contenitore, volume, segnalato; vuoto per tutte
            limit: righe massime (max 300)
        """
        con = _db()
        w, a = ["1=1"], []
        if kind:
            w.append("kind = ?"); a.append(kind)
        try:
            rows = con.execute(f"SELECT kind, path, detail, part, inode, sev FROM anomalies WHERE {' AND '.join(w)} "
                               f"ORDER BY sev DESC, path LIMIT {max(1, min(int(limit), 300))}", a).fetchall()
        finally:
            con.close()
        return fa.clip("\n".join([f"{len(rows)} anomalie"] + [tr("- [{k}] {p} | {d} | offset {pt} inode {i} | gravità {s}").format(k=k, p=p, d=d, pt=pt, i=i, s=s)
                                                               for k, p, d, pt, i, s in rows]))

    if "artefatti" in est:
        tools.append(query_artifacts)
    if "archivi" in est:
        tools += [search_emails, read_email]
    if "archivi" in est or "vss" in est:
        tools += [list_extracted, read_extracted]
    if "anomalie" in est or case.meta.get("liste_hash"):
        tools.append(list_anomalies)
    return tools


def prompt_extra(case):
    est = case.meta.get("estese") or {}
    out = []
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
    if "anomalie" in est:
        out.append(tr("- Anomalie (estensioni false, file e volumi cifrati): list_anomalies."))
    if case.meta.get("volumi_cifrati"):
        out.append(tr("- ATTENZIONE: volumi cifrati presenti: ") + ", ".join(tr("{tipo} all'offset {offset}").format(tipo=v['tipo'], offset=v['offset'])
                                                                    for v in case.meta["volumi_cifrati"]))
    return out
