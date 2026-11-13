#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - archivi (7-Zip) e contenitori.

(3.0.4) Codice spostato da forense_estesa.py senza modifiche, per avere file più corti. Si carica tramite
forense_estesa, che ne riesporta i nomi: gli altri moduli continuano a usare «fe.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fe.<nome>»).
"""
import datetime as dt
import os
import re
import shutil
import struct
import subprocess
import tarfile
import time
import zipfile
from pathlib import Path
from forense_lingua import tr
import forense_agent as fa

import forense_estesa as fe
from forense_estesa import (
    ARCHIVE_MAX, ARCH_EXT, DEPTH_MAX, ENTRY_MAX, MAIL_EXT, NOPASS, TOTAL_MAX, add_anomaly, dentro, free_space,
    hashes_of, index_text, lp, new_xitem, store_extracted, unixtime)

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


def z_scarto():
    """Secondi da togliere alle date di «7z l» per averle in UTC. Su Mac e Linux basta TZ=UTC (0); su Windows 7-Zip
    ignora TZ e converte con FileTimeToLocalFileTime, cioè con lo scarto ATTUALE del computer (ora legale compresa,
    anche per date di un'altra stagione): si toglie lo stesso scarto. Le date DOS dei RAR 4 escono invece invariate."""
    if os.name != "nt":
        return 0
    return int(dt.datetime.now().astimezone().utcoffset().total_seconds())


def z_list(exe, f):
    """Elenco tecnico (7z l -slt): [{path, size, mtime, encrypted, dir}], codice, errore."""
    try:
        # TZ=UTC: per i formati con date assolute (tar, 7z…) 7-Zip le scrive nel fuso del computer; così sono UTC
        cp = subprocess.run([exe, "l", "-slt", "-ba", NOPASS, str(f)], capture_output=True,
                            timeout=900, stdin=subprocess.DEVNULL, env=dict(os.environ, TZ="UTC"))
    except subprocess.TimeoutExpired:
        return [], 1, tr("tempo scaduto")
    with open(f, "rb") as fh:
        scarto = 0 if fh.read(7) == b"Rar!\x1a\x07\x00" else z_scarto()
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
        mt = m[:19].replace(" ", "T") if re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", m) else None
        if mt and scarto:
            mt = (dt.datetime.strptime(mt, "%Y-%m-%dT%H:%M:%S") - dt.timedelta(seconds=scarto)).strftime("%Y-%m-%dT%H:%M:%S")
        res.append({"path": p, "size": size, "dir": isdir, "encrypted": e.get("Encrypted") == "+", "mtime": mt})
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
                # (3.0.1) una voce per volta: una voce rifiutata dal filtro («../», collegamento esterno) non ferma le altre
                for m in t.getmembers():
                    try:
                        t.extract(m, dest, filter="data")
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
    fam, label = fe.detect_sig(head[:4096])
    if fam in ARCH_FAM and ext not in fe.FAMILY_EXT.get(fam, set()) and not (fam == "zip" and ext in fe.KNOWN_EXT - {"jpg", "jpeg", "png", "gif", "pdf", "txt", "dat", "bin", "amr", "3ga", "svg"}):
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
            return fe.process_pst(ctx, f, disp, origin, depth, parent)
        if low.endswith(".msg") or (head.startswith(b"\xd0\xcf\x11\xe0") and low.endswith(".msg")):
            return fe.process_msg_file(ctx, f, disp, origin, depth, parent)
        if low.endswith((".eml", ".emlx")):
            return fe.process_eml_file(ctx, f, disp, origin, depth, parent)
        if low.endswith((".mbox", ".mbx")) or (head.startswith(b"From ") and "." not in name):
            return fe.process_mbox(ctx, f, disp, origin, depth, parent)
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
        elif not dentro(out, p):
            note = tr("non estratto (percorso che esce dall'archivio o collegamento)")
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
