#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - interfaccia, albero del file system.

(3.0.4) Codice spostato da forense_gui.py senza modifiche, per avere file più corti. Si carica tramite
forense_gui, che ne riesporta i nomi: gli altri moduli continuano a usare «G.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («G.<nome>»).
"""
import json
import re
import sqlite3
import threading
from forense_lingua import tr
import forense_agent as fa
import forense_lingua as lg

import forense_gui as G
from forense_gui import (
    PAGE, cf_apply, cf_order, cf_values, is_dir_type, yes)

# ------------------------------------------------- albero del file system

NAV_LOCK = threading.Lock()
NAV_STATE = {}
EV_RE = re.compile(r"\| inode (\S+) \| (-?\d+) B$")
NAV_COLS = ("id", "part", "parent", "name", "path", "isdir", "deleted", "type", "inode", "fid",
            "size", "mtime", "atime", "ctime", "crtime", "ndirs", "nitems")


def nav_file(case):
    return case.root / "navigazione.sqlite"


def nav_stamp(case):
    con = fa.db_ro(case)
    try:
        return "v2:%d:%d:%d:%d" % (con.execute("SELECT COUNT(*), IFNULL(MAX(rowid),0) FROM files").fetchone()
                                   + con.execute("SELECT COUNT(*), IFNULL(MAX(rowid),0) FROM events WHERE origin='tsk'").fetchone())
    finally:
        con.close()


def ensure_nav(case):
    """Avvia (una volta) la costruzione dell'indice di navigazione; restituisce lo stato."""
    key = str(case.root)
    with NAV_LOCK:
        st = NAV_STATE.get(key)
        if st and (st["state"] == "building" or (st["state"] == "ready" and nav_file(case).exists())):
            return st                   # pronto ma cancellato (es. ricalcolo delle date dopo il cambio del fuso): si rifà
        ok = False
        if nav_file(case).exists():
            try:
                c = sqlite3.connect(nav_file(case).as_uri() + "?mode=ro", uri=True)
                ok = c.execute("SELECT v FROM info WHERE k='stamp'").fetchone()[0] == nav_stamp(case)
                c.close()
            except Exception:
                ok = False
        if ok:
            NAV_STATE[key] = {"state": "ready"}
        else:
            NAV_STATE[key] = {"state": "building", "msg": tr("Preparo l'albero del file system…")}
            threading.Thread(target=build_nav, args=(case,), daemon=True).start()
        return NAV_STATE[key]


def build_nav(case):
    """Ricava dall'elenco dei file (fls) l'albero delle cartelle con dimensioni e date.
    È un indice di comodo, ricostruibile: sta in navigazione.sqlite, accanto a caso.sqlite,
    che resta invariato."""
    key = str(case.root)
    st = NAV_STATE[key]
    tmp = case.root / "navigazione.sqlite.tmp"
    try:
        if tmp.exists():
            tmp.unlink()
        stamp = nav_stamp(case)
        src = fa.db_ro(case)
        out = sqlite3.connect(tmp)
        out.executescript("""
            PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
            CREATE TABLE info(k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE ev(part INTEGER, inode TEXT, size INTEGER, kind TEXT, ts TEXT);
            CREATE TABLE f(part INTEGER, parent TEXT, name TEXT, path TEXT, isdir INTEGER,
                           deleted INTEGER, type TEXT, inode TEXT, fid INTEGER);
        """)
        st["msg"] = tr("Albero: leggo date e dimensioni…")
        batch = []
        for ts, kind, msg, part in src.execute(
                "SELECT ts, kind, message, part FROM events WHERE origin='tsk'"):
            m = EV_RE.search(msg or "")
            if m:
                batch.append((part, m.group(1), int(m.group(2)), kind, ts))
            if len(batch) >= 50000:
                out.executemany("INSERT INTO ev VALUES (?,?,?,?,?)", batch)
                batch.clear()
        out.executemany("INSERT INTO ev VALUES (?,?,?,?,?)", batch)
        out.executescript("""
            CREATE TABLE info2 AS SELECT part, inode, MAX(size) size,
                MAX(CASE WHEN kind='M' THEN ts END) m, MAX(CASE WHEN kind='A' THEN ts END) a,
                MAX(CASE WHEN kind='C' THEN ts END) c, MAX(CASE WHEN kind='B' THEN ts END) b
                FROM ev GROUP BY part, inode;
            CREATE INDEX i2 ON info2(part, inode);
            DROP TABLE ev;
        """)
        st["msg"] = tr("Albero: ricostruisco le cartelle…")
        dirs, parents, batch, n = set(), set(), [], 0
        for fid, part, inode, deleted, typ, path in src.execute(
                "SELECT rowid, part, inode, deleted, type, path FROM files"):
            path = (path or "").strip("/")
            if not path:
                continue
            isdir = 1 if is_dir_type(typ) else 0
            parent, _, name = path.rpartition("/")
            batch.append((part, parent, name, path, isdir, deleted, typ, inode, fid))
            if isdir:
                dirs.add((part, path))
            parents.add((part, parent))
            n += 1
            if len(batch) >= 50000:
                out.executemany("INSERT INTO f VALUES (?,?,?,?,?,?,?,?,?)", batch)
                batch.clear()
                st["msg"] = tr("Albero: {n:,} voci…").format(n=n).replace(",", ".")
        src.close()
        # cartelle presenti solo come percorso (es. genitori di file orfani)
        for part, p in list(parents):
            while p and (part, p) not in dirs:
                dirs.add((part, p))
                par, _, name = p.rpartition("/")
                batch.append((part, par, name, p, 1, 0, "d/d", None, None))
                p = par
        out.executemany("INSERT INTO f VALUES (?,?,?,?,?,?,?,?,?)", batch)
        out.executescript("""
            CREATE TABLE nav(id INTEGER PRIMARY KEY, part INTEGER, parent TEXT, name TEXT,
                path TEXT, isdir INTEGER, deleted INTEGER, type TEXT, inode TEXT, fid INTEGER,
                size INTEGER, mtime TEXT, atime TEXT, ctime TEXT, crtime TEXT,
                ndirs INTEGER DEFAULT 0, nitems INTEGER DEFAULT 0);
            INSERT INTO nav(part, parent, name, path, isdir, deleted, type, inode, fid,
                            size, mtime, atime, ctime, crtime)
                SELECT f.part, f.parent, f.name, f.path, f.isdir, f.deleted, f.type, f.inode, f.fid,
                       CASE WHEN f.isdir THEN NULL ELSE i.size END, i.m, i.a, i.c, i.b
                FROM f LEFT JOIN info2 i ON i.part = f.part AND i.inode = f.inode
                ORDER BY f.part, f.parent, f.isdir DESC, f.name COLLATE NOCASE;
            DROP TABLE f; DROP TABLE info2;
            CREATE INDEX nav_parent ON nav(part, parent, isdir);
            CREATE INDEX nav_path ON nav(part, path);
            CREATE INDEX nav_inode ON nav(part, inode);
            CREATE TABLE cnt AS SELECT part, parent, COUNT(*) n,
                COUNT(DISTINCT CASE WHEN isdir THEN path END) nd FROM nav GROUP BY part, parent;
            CREATE INDEX cnt_i ON cnt(part, parent);
            UPDATE nav SET nitems = IFNULL((SELECT n FROM cnt WHERE cnt.part = nav.part
                                                AND cnt.parent = nav.path), 0),
                           ndirs = IFNULL((SELECT nd FROM cnt WHERE cnt.part = nav.part
                                                AND cnt.parent = nav.path), 0)
                WHERE isdir = 1;
        """)
        out.execute("INSERT INTO info VALUES ('stamp', ?)", (stamp,))
        out.commit()
        out.close()
        tmp.replace(nav_file(case))
        st.clear()
        st["state"] = "ready"
    except Exception as e:
        st.clear()
        st.update({"state": "error", "msg": tr("Albero non disponibile: {e}").format(e=e)})
        try:
            tmp.unlink()
        except OSError:
            pass


def nav_attach(con, case):
    """Collega all'archivio del caso l'indice di navigazione (dimensioni e date), se è pronto."""
    try:
        if ensure_nav(case).get("state") != "ready":
            return False
        con.execute("ATTACH DATABASE ? AS nv", (nav_file(case).as_uri() + "?mode=ro",))
        return True
    except sqlite3.Error:
        return False


def nav_db(case):
    st = ensure_nav(case)
    if st["state"] != "ready":
        raise ValueError(st.get("msg") or tr("Albero in preparazione…"))
    return sqlite3.connect(nav_file(case).as_uri() + "?mode=ro", uri=True)


def nav_tree(case, q):
    """Sottocartelle di una cartella (o le partizioni, se part è vuoto)."""
    st = ensure_nav(case)
    if st["state"] != "ready":
        return {"state": st["state"], "msg": st.get("msg")}
    con = nav_db(case)
    try:
        if q.get("part") in (None, ""):
            out = []
            enc = {int(v["offset"]): v.get("tipo") or "cifrato"
                   for v in case.meta.get("volumi_cifrati") or []}
            for p in case.meta.get("partitions", []):
                if not p.get("readable") and p["offset"] not in enc:
                    continue
                r = (con.execute("SELECT n, nd FROM cnt WHERE part=? AND parent=''",
                                 (p["offset"],)).fetchone() if p.get("readable") else None) or (0, 0)
                out.append({"part": p["offset"], "path": "",
                            "name": (tr("Volume APFS «{v1}»").format(v1=p['apfs'].get('name')) if p.get("apfs")
                                     else tr("Estrazione «{v1}»").format(v1=p.get('desc')) if p.get("mobile")
                                     else tr("Partizione {offset}").format(offset=p['offset'])),
                            "fs": lg.valore(p.get("fs")), "os": p.get("os"), "nitems": r[0], "ndirs": r[1],
                            "enc": enc.get(p["offset"])})
            lay = None
            try:
                lay = fa.layout_volumi(case)
            except Exception:
                lay = None
            if lay:
                lay = {"tipo": lay["tipo"], "unita": lay["unita"], "voci": [
                    dict(v, label=f"vol{v['n']} ({v['desc']}: {v['start']}-{v['end']})") for v in lay["voci"]]}
            return {"state": "ready", "parts": out, "layout": lay}
        rows = con.execute(
            "SELECT path, name, MIN(deleted), MAX(ndirs), MAX(nitems) FROM nav "
            "WHERE part=? AND parent=? AND isdir=1 GROUP BY path ORDER BY name COLLATE NOCASE "
            "LIMIT 5000", (int(q["part"]), q.get("path") or "")).fetchall()
    finally:
        con.close()
    dirs = [{"path": p, "name": n, "deleted": d, "ndirs": nd, "nitems": ni} for p, n, d, nd, ni in rows]
    part = int(q["part"])
    if not (q.get("path") or "") and not fa.ap.is_apfs_part(part) and not fa.is_mobile(case):
        # cartella virtuale con lo spazio non allocato del file system (come $Unalloc di Autopsy)
        dirs.append({"path": "$Unalloc", "name": "$Unalloc", "deleted": 0, "ndirs": 0, "nitems": None, "virtual": "ua"})
    return {"state": "ready", "dirs": dirs}


def nav_list(case, q, ids=None, limit=PAGE):
    """Contenuto di una cartella (o dell'intero sottoalbero) per la sezione Esplora."""
    if (q.get("dir") or "").strip("/") == "$Unalloc" and not yes(q.get("sub")):
        return G.ua_list(case, q, ids, limit)
    con = nav_db(case)
    off = int(q.get("offset", 0))
    w, a = [], []
    try:
        if ids is not None:
            w.append("id IN (SELECT value FROM json_each(?))")
            a.append(json.dumps([int(x) for x in ids if str(x).isdigit()]))
        else:
            part, d = int(q.get("part") or 0), (q.get("dir") or "").strip("/")
            w.append("part = ?"); a.append(part)
            if yes(q.get("sub")):
                if d:
                    w.append("substr(path, 1, ?) = ?"); a += [len(d) + 1, d + "/"]
            else:
                w.append("parent = ?"); a.append(d)
            text = (q.get("q") or "").strip()
            if text:
                w.append("name LIKE ? ESCAPE '\\'"); a.append(fa.like(text))
            if yes(q.get("deleted")):
                w.append("deleted >= 1")
            cf_apply(q, {"name": ("path" if yes(q.get("sub")) else "name", "t"), "size": ("size", "n"),
                         "mtime": ("mtime", "d"), "crtime": ("crtime", "d"), "atime": ("atime", "d"),
                         "ctime": ("ctime", "d")},
                     w, a)
        kn = known_attach(case, con)
        if kn and yes(q.get("noti")):
            w.append("NOT EXISTS (SELECT 1 FROM k.known WHERE k.known.part = nav.part AND k.known.inode = nav.inode "
                     "AND k.known.kind = 'noti')")
        if q.get("cfv"):
            cf_values(con, q, "nav", w, a)
        cond = " WHERE " + " AND ".join(w)
        order = ("path COLLATE NOCASE, deleted" if yes(q.get("sub")) and ids is None
                 else "isdir DESC, name COLLATE NOCASE, deleted")
        if ids is None:
            order = cf_order(q, order, "" if yes(q.get("sub")) else "isdir DESC, ")
        total = con.execute(f"SELECT COUNT(*) FROM nav{cond}", a).fetchone()[0]
        lim = f" LIMIT {int(limit)} OFFSET {off}" if limit else ""
        kcol = (", (SELECT k.known.kind || ':' || k.known.list FROM k.known WHERE k.known.part = nav.part "
                "AND k.known.inode = nav.inode LIMIT 1)") if kn else ", NULL"
        rows = con.execute(f"SELECT {', '.join(NAV_COLS)}{kcol} FROM nav{cond} "
                           f"ORDER BY {order}{lim}", a).fetchall()
    finally:
        con.close()
    return {"kind": "explore", "total": total, "offset": off, "page": PAGE,
            "rows": [dict(zip(NAV_COLS + ("known",), r)) for r in rows]}


def known_attach(case, con):
    """Collega i risultati del confronto con le liste di hash (tabella known del caso)."""
    if not case.meta.get("liste_hash"):
        return False
    try:
        con.execute("ATTACH DATABASE ? AS k", (case.db_path.as_uri() + "?mode=ro",))
        return bool(con.execute("SELECT name FROM k.sqlite_master WHERE name='known'").fetchone())
    except sqlite3.Error:
        return False


def clean_fs_path(p):
    p = (p or "").strip().strip("`'\"")
    p = re.sub(r" \((deleted|deleted-realloc|\$FILE_NAME)\)$", "", p)
    return p.replace("\\", "/").strip("/")


def _sysdiag_di(case, path):
    """(2.20) Sysdiagnose registrato da cui viene il percorso (nome dell'archivio o della sua cartella in testa), o None."""
    p = str(path or "").replace("\\", "/").lstrip("/")
    for v in (case.meta.get("sysdiagnose") or []) if fa.is_mobile(case) else []:
        if p and (p.startswith(v.get("nome") or "\0") or (v.get("cartella") and p.startswith(v["cartella"] + "/"))):
            return v
    return None


def nav_locate(case, b):
    """Dove si trova un file nell'albero: per offset+inode, per percorso, o per id di Esplora."""
    con = nav_db(case)
    try:
        r = None
        if b.get("inode") not in (None, ""):
            r = con.execute("SELECT part, path, isdir, deleted FROM nav WHERE part=? AND inode=? "
                            "ORDER BY deleted, length(path) LIMIT 1",
                            (int(b.get("part") or 0), str(b["inode"]))).fetchone()
        if not r and b.get("path"):
            p = clean_fs_path(b["path"])
            parts = [int(b["part"])] if b.get("part") not in (None, "") else None
            sql = "SELECT part, path, isdir, deleted FROM nav WHERE path = ?"
            r = con.execute(sql + (" AND part = ?" if parts else "") + " LIMIT 1",
                            [p] + (parts or [])).fetchone()
            if not r and p:
                r = con.execute("SELECT part, path, isdir, deleted FROM nav WHERE path LIKE ? "
                                "ESCAPE '\\' ORDER BY length(path) LIMIT 1",
                                ("%" + p.replace("\\", "\\\\").replace("%", "\\%")
                                 .replace("_", "\\_"),)).fetchone()
    finally:
        con.close()
    if not r:
        sd = _sysdiag_di(case, b.get("path"))
        if sd:                              # (2.20) fonte dentro un sysdiagnose acquisito a parte: non è nell'albero
            raise ValueError(tr("La fonte è dentro il sysdiagnose «{n}», acquisito a parte e non copiato nel caso: non è "
                                "nell'albero dell'estrazione. Il file letto da iLEAPP è nel suo rapporto ({r}).").format(
                n=sd.get("nome"), r=(sd.get("ileapp") or {}).get("rapporto") or "leapp/"))
        raise ValueError(tr("File non trovato nell'albero del file system."))
    part, path, isdir, deleted = r
    parent = path.rpartition("/")[0]
    index = 0
    if not isdir:   # posizione nella cartella, per aprire la pagina giusta
        con = nav_db(case)
        try:
            for i, (p, dl) in enumerate(con.execute(
                    "SELECT path, deleted FROM nav WHERE part=? AND parent=? "
                    "ORDER BY isdir DESC, name COLLATE NOCASE, deleted", (part, parent))):
                if p == path and dl == deleted:
                    index = i
                    break
        finally:
            con.close()
    return {"part": part, "path": path, "isdir": isdir, "deleted": deleted, "index": index,
            "dir": path if isdir else parent, "select": None if isdir else path}
