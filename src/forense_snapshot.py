#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - copie shadow di Windows (VSS) e snapshot APFS.

(3.0.4) Codice spostato da forense_estesa.py senza modifiche, per avere file più corti. Si carica tramite
forense_estesa, che ne riesporta i nomi: gli altri moduli continuano a usare «fe.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fe.<nome>»).
"""
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from forense_lingua import tr
import forense_agent as fa
import forense_apfs as ap

import forense_estesa as fe
from forense_estesa import (
    Ctx, ImageFile, Region, X_ROOT, gdrive_vss, hashes_of, index_text, iso, new_xitem, now, part_bounds,
    store_extracted, unixtime)

# ------------------------------------------------------------------ copie shadow (VSS)

VSS_SKIP = re.compile(r"(?i)^(\$|system volume information/|windows/winsxs/|windows/softwaredistribution/|"
                      r"windows/installer/|windows/servicing/|programdata/microsoft/windows defender/|"
                      r"(pagefile|hiberfil|swapfile)\.sys$)")
VSS_FILE_MAX = 200 << 20


def _vss_files(fs):
    """(2.20) File regolari allocati (non vuoti) di un file system pytsk3: (percorso relativo, nome, voce).
    Salta VSS_SKIP e non rientra due volte nella stessa cartella (giri infiniti in copie incoerenti)."""
    import pytsk3
    seen_dirs = set()
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
                a = ent.info.meta.addr
                if a in seen_dirs:
                    continue
                seen_dirs.add(a)
                try:
                    stack.append((rel, ent.as_directory()))
                except Exception:
                    pass
                continue
            if t != pytsk3.TSK_FS_META_TYPE_REG or ent.info.meta.size <= 0:
                continue
            yield rel, nm, ent
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
        # (2.20) dimensione e data dei file della copia attuale lette UNA volta: prima ogni file presente in una copia
        # shadow si cercava per percorso nella copia forense (ore per copia su un disco di sistema)
        cur_meta = {}
        try:
            for rel, _nm, ent in _vss_files(cur_fs):
                cur_meta.setdefault(rel.lower(), (ent.info.meta.size, ent.info.meta.mtime))
                if len(cur_meta) % 5000 == 0:
                    ctx.say(tr("lettura della copia attuale: {n} file").format(n=len(cur_meta)))
                    fa.avanz(fatti=len(cur_meta))
        except Exception as e:
            print(tr("Copie shadow: copia attuale non leggibile per intero ({e})").format(e=e), flush=True)
        cur = {}
        for path, d in con.execute("SELECT path, deleted FROM files WHERE part=? AND type LIKE '%r'", (p["offset"],)):
            k = path.lower()
            cur[k] = min(cur.get(k, 1), d)
        for si in range(n):
            st = vol.get_store(si)
            when = iso(st.creation_time)
            label = tr("copia shadow {v1} del {v2} UTC").format(v1=si + 1, v2=when.replace('T', ' ') if when else '?')
            stores_found += 1
            try:
                fs = pytsk3.FS_Info(StoreImg(st))
            except Exception as e:
                print(tr("  {label}: file system non leggibile ({e})").format(label=label, e=e), flush=True)
                continue
            found = seen = 0
            est = max(len(cur_meta) or len(cur), 1)     # (2.20) per la barra: i file della copia attuale come stima
            for rel, nm, ent in _vss_files(fs):
                m = ent.info.meta
                seen += 1
                fa.avanz(fatti=si * est + min(seen, est - 1), totale=n * est)
                if time.time() - ctx.t_last > 2:       # (2.20) segno di vita anche quando i file sono tutti uguali
                    ctx.say(tr("{label}: {seen} file esaminati, {found} diversi dalla copia attuale").format(label=label, seen=seen, found=found))
                size, mtime = m.size, unixtime(m.mtime)
                state = cur.get(rel.lower())
                if state == 0:      # ancora presente: conta solo se è una versione diversa
                    if cur_meta.get(rel.lower()) == (size, m.mtime):
                        continue
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
    try:                    # (3.0.2) Google Drive nelle copie shadow
        n_gd = gdrive_vss(case, con, ctx)
        if n_gd:
            print(tr("Copie shadow: Google Drive letto da {n} file delle copie (Servizi cloud)").format(n=n_gd), flush=True)
    except Exception as e:
        print(tr("Copie shadow: Google Drive non letto ({vname}: {e})").format(vname=type(e).__name__, e=e), flush=True)
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
