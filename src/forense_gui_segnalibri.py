#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - interfaccia, segnalibri (categorie di file).

(3.0.4) Codice spostato da forense_gui.py senza modifiche, per avere file più corti. Si carica tramite
forense_gui, che ne riesporta i nomi: gli altri moduli continuano a usare «G.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («G.<nome>»).
"""
import hashlib
import json
import sqlite3
from pathlib import Path
from forense_lingua import tr
import forense_agent as fa

import forense_gui as G
from forense_gui import (
    HIT_COLS, PAGE, cf_apply, cf_hits, cf_order, cf_values, export_targets, fmt_ts, item_stream, nav_db, search_db,
    selected_rows, tz_label, unique, yes)

# ------------------------------------------------- segnalibri (categorie di file)
#
# Stanno in ricerche.sqlite accanto alle ricerche salvate; ogni categoria si apre come
# scheda (kind "hits" con cid) e riusa elenco, miniature, anteprima ed esportazioni.

BM_MAX = 200_000


def bm_categories(case):
    con = search_db(case)
    try:
        return [{"cid": c, "name": n, "created": cr, "note": nt or "", "in_report": bool(r), "n": k}
                for c, n, cr, nt, r, k in con.execute(
                    "SELECT c.cid, c.name, c.created, c.note, c.in_report, "
                    "(SELECT COUNT(*) FROM bm WHERE bm.cid = c.cid) FROM bm_cat c ORDER BY c.name COLLATE NOCASE")]
    finally:
        con.close()


def _oid(it):
    """Identificativo di un elemento non-file (artefatto, messaggio, posta, file estratto): id, o inode per le righe
    delle ricerche; errore chiaro se manca."""
    v = it.get("id") if it.get("id") not in (None, "") else it.get("inode")
    if v in (None, "") or not str(v).lstrip("-").isdigit():
        raise ValueError(tr("Elemento non valido: manca il riferimento."))
    return int(v)


def item_ref(case, b):
    """Riferimento testuale di un elemento per Preferiti, Reperto e registro: i file per offset e inode (nei casi
    smartphone per percorso nell'estrazione), messaggi e artefatti per database, tabella e riga; per gli artefatti
    anche i file citati (2.20) con il modo in cui sono stati trovati."""
    t = _item_ref(case, b)
    if (b.get("source") or "fs") == "art":
        try:
            c = G.cited_info(case, {"id": _oid(b)})
            fs = [x["label"] for x in c["file"] if x.get("ruolo") == "file"]
            if fs:
                t += "; " + tr("file citati: {f}").format(f="; ".join(fs))
        except (ValueError, sqlite3.Error, OSError, TypeError):
            pass
    return t


def _item_ref(case, b):
    src = b.get("source") or "fs"
    if fa.is_mobile(case) and src in ("fs", "art", "chat"):
        import forense_mobile_gui as fmg
        cx = fa.db_ro(case)
        try:
            return fmg.ref(case, cx, src, _oid(b) if src != "fs" else None, b.get("part"), b.get("inode"), b.get("path"))
        finally:
            cx.close()
    if src == "fs":
        return tr("{path} (offset {part}, inode {inode})").format(path=b.get("path") or "", part=b.get("part"), inode=b.get("inode"))
    if src == "carving":
        return tr("file recuperato {v1}").format(v1=b.get("name") or b.get("path") or "")
    if src == "ua":
        return tr("spazio non allocato {v1}").format(v1=b.get("path") or b.get("inode") or "")
    if src == "image":
        return tr("byte {v1} della copia forense").format(v1=b.get("at"))
    oid = _oid(b)
    cx = fa.db_ro(case)
    try:
        if src == "art":
            r = cx.execute("SELECT title, cat, src_path, part, inode FROM artifacts WHERE id=?", (oid,)).fetchone()
            return (tr("artefatto «{t}»").format(t=r[0]) + ("" if not r[2] else tr(" — fonte {p}").format(p=r[2]) if r[4] in (None, "") else
                                                            tr(" — fonte {src_path} (offset {part}, inode {inode})").format(
                src_path=r[2], part=r[3], inode=r[4])) + ", " + tr("riga {id} della tabella artifacts del caso").format(id=oid)
                    if r else tr("artefatto {id}").format(id=oid))
        if src == "mail":
            r = cx.execute("SELECT subject, src_path, part, inode FROM mail WHERE id=?", (oid,)).fetchone()
            return (tr("messaggio «{subject}» ({src_path}, offset {part}, inode {inode})").format(subject=r[0], src_path=r[1], part=r[2], inode=r[3])
                    if r else tr("messaggio di posta {id}").format(id=oid))
        if src == "x":
            r = cx.execute("SELECT path FROM xitems WHERE id=?", (oid,)).fetchone()
            return tr("file estratto {path} (id {inode})").format(path=r[0] if r else "", inode=oid)
    finally:
        cx.close()
    return str(oid)


def bm_add(case, b):
    """Aggiunge i file selezionati (cartelle comprese, con il loro contenuto) a una categoria,
    creata se non esiste."""
    name = " ".join(str(b.get("cat") or "").split())[:80]
    if not name:
        raise ValueError(tr("Indica il nome della categoria."))
    it = b.get("item")
    xs, others = {}, []
    if it and (it.get("source") in ("x", "mail", "art", "chat")):
        fs, carved, skipped = {}, [], 0
        if it["source"] == "x":
            xs = {_oid(it): (it.get("path"), None)}
        else:
            others = [(it["source"], _oid(it))]
    elif it:                                   # un solo file (riga o anteprima)
        if (it.get("source") or "fs") == "carving":
            fs, carved, skipped = {}, [Path(str(it.get("name") or "")).name], 0
        else:
            if not (fa.INODE_RE.fullmatch(str(it.get("inode") or "")) or fa.UA_RE.fullmatch(str(it.get("inode") or ""))):
                raise ValueError(tr("File non valido."))
            fs, carved, skipped = {(int(it["part"]), str(it["inode"]), str(it.get("path") or "")): 0}, [], 0
    else:
        kind, rows = selected_rows(case, b.get("sel") or {})
        fs, carved, skipped = export_targets(case, kind, rows)
        xs = G.x_targets(case, kind, rows)
        if kind in ("mail", "art"):
            others = [(kind, int(x["id"])) for x in rows]
        elif kind == "hits":
            others = [(x["source"], int(x["inode"])) for x in rows if x.get("source") == "mail"]
    if len(fs) + len(carved) + len(xs) + len(others) > BM_MAX:
        raise ValueError(tr("Troppi file ({v1:,}): restringi la selezione.").format(v1=len(fs) + len(carved)).replace(",", "."))
    note = str(b.get("note") or "").strip()[:2000]
    hashes = {}
    cs = fa.db_ro(case)
    try:
        if fa.table_exists(cs, "hashes") and fs:
            for part, inode, md5, sha1, sha256 in cs.execute("SELECT part, inode, md5, sha1, sha256 FROM hashes"):
                hashes[(part, inode)] = (md5, sha1, sha256)
        cinfo = {}
        if carved and fa.table_exists(cs, "carved"):
            for nm, size, sha in cs.execute("SELECT name, size, sha256 FROM carved"):
                cinfo[Path(nm.replace("\\", "/")).name] = (size, sha)
    finally:
        cs.close()
    nav = None
    try:
        nav = nav_db(case)
    except (ValueError, sqlite3.Error):
        pass
    con = search_db(case)
    now = fa.now()
    try:
        r = con.execute("SELECT cid FROM bm_cat WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
        if r:
            cid = r[0]
        else:
            cid = con.execute("INSERT INTO bm_cat(name, created, note, in_report) VALUES (?,?,?,1)",
                              (name, now, "")).lastrowid
        batch = []
        for (part, inode, path), deleted in fs.items():
            size = mtime = None
            if nav is not None:
                x = nav.execute("SELECT path, size, mtime, deleted FROM nav WHERE part=? AND inode=? "
                                "AND isdir=0 ORDER BY deleted LIMIT 1", (part, inode)).fetchone()
                if x:
                    path, size, mtime, deleted = x[0] if not path else path, x[1], x[2], x[3]
            path = (path or f"inode_{inode}").strip("/")
            sha_ua = None
            if fa.UA_RE.fullmatch(inode):           # tratto non allocato: dimensione e SHA-256 (fino a 256 MB)
                size = int(fa.UA_RE.fullmatch(inode).group(2))
                if size <= 256 << 20:
                    h = hashlib.sha256()
                    for c in item_stream(case, part, inode):
                        h.update(c)
                    sha_ua = h.hexdigest()
            batch.append((cid, "ua" if fa.UA_RE.fullmatch(inode) else "fs", part, inode, path, path.rsplit("/", 1)[-1],
                          deleted, size, mtime,
                          *(hashes.get((part, inode)) or (None, None, sha_ua)), note, now))
        for nm in carved:
            nm = Path(str(nm).replace("\\", "/")).name
            size, sha = cinfo.get(nm, (None, None))
            batch.append((cid, "carving", None, nm, f"[recuperato] {nm}", nm, 0, size, None,
                          None, None, sha, note, now))
        if xs or others:
            cx = fa.db_ro(case)
            try:
                for xid in xs:
                    r = cx.execute("SELECT path, name, deleted, size, mtime, md5, sha1, sha256 FROM xitems WHERE id=?",
                                   (xid,)).fetchone()
                    if r:
                        batch.append((cid, "x", None, str(xid), r[0], r[1], r[2] or 0, r[3], r[4], r[5], r[6], r[7], note, now))
                for src, oid in others:
                    if src == "mail":
                        r = cx.execute("SELECT subject, sender, date FROM mail WHERE id=?", (oid,)).fetchone()
                        if r:
                            batch.append((cid, "mail", None, str(oid), f"✉ {r[0]} — {r[1]}", r[0], 0, None, r[2],
                                          None, None, None, note, now))
                    elif src == "chat":                 # messaggio di una chat (2.20)
                        import forense_mobile_gui as fmg
                        r = fmg.msg_item(cx, oid)
                        if r:
                            batch.append((cid, "chat", None, str(oid), r[0], r[1], 0, None, r[2],
                                          None, None, None, note, now))
                    else:
                        r = cx.execute("SELECT title, cat, ts FROM artifacts WHERE id=?", (oid,)).fetchone()
                        if r:
                            batch.append((cid, "art", None, str(oid), f"[{r[1]}] {r[0]}", r[0], 0, None, r[2],
                                          None, None, None, note, now))
            finally:
                cx.close()
        before = con.execute("SELECT COUNT(*) FROM bm WHERE cid=?", (cid,)).fetchone()[0]
        con.executemany("INSERT OR IGNORE INTO bm(cid, source, part, inode, path, name, deleted, size, "
                        "mtime, md5, sha1, sha256, note, ts) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
        con.commit()
        total = con.execute("SELECT COUNT(*) FROM bm WHERE cid=?", (cid,)).fetchone()[0]
    finally:
        con.close()
        if nav is not None:
            nav.close()
    refs = []                      # riferimenti degli elementi nel registro a catena (al massimo 20)
    for x in ([it] if it else [{"source": s, "id": o} for s, o in others[:20]]):
        try:
            refs.append(item_ref(case, x))
        except (ValueError, sqlite3.Error):
            pass
    case.log("preferiti", {"categoria": name, "aggiunti": total - before, "saltati": skipped,
                           **({"riferimenti": refs} if refs else {})})
    return {"cid": cid, "name": name, "added": total - before, "total": total, "skipped": skipped}


def trascr_categoria(case, r, part, inode):
    """(3.0.1) Categoria dei Preferiti «Trascrizioni confermate»: il messaggio della chat a cui l'audio è allegato (o il
    file, se non è allegato a una chat), con il testo confermato nella nota; una bozza successiva lo toglie."""
    import forense_trascrizione as ftr
    name = tr(ftr.CAT_CONF)
    items = [{"source": "chat", "id": m} for m in r["messaggi"][:20]] or [{"source": "fs", "part": int(part), "inode": str(inode), "path": r["path"]}]
    if r["stato"] == "confermata":
        nota = tr("Trascrizione confermata da {o} il {t} (SHA-256 del testo {h})").format(o=r["operatore"], t=r["ts"], h=r["testo_sha256"][:16])
        for it in items:
            bm_add(case, {"cat": name, "item": it, "note": nota[:2000]})
        con = search_db(case)
        try:
            con.execute("UPDATE bm_cat SET note = ? WHERE name = ? COLLATE NOCASE AND IFNULL(note, '') = ''",
                        (tr("Audio con la trascrizione rivista e confermata dall'analista (il testo è nell'anteprima dell'audio)."), name))
            cid = con.execute("SELECT cid FROM bm_cat WHERE name = ? COLLATE NOCASE", (name,)).fetchone()[0]
            for it in items:
                k = (str(it["id"]),) if it["source"] == "chat" else (str(it["inode"]),)
                con.execute("UPDATE bm SET note = ? WHERE cid = ? AND source = ? AND inode = ?" + ("" if it["source"] == "chat" else " AND part = ?"),
                            (nota[:2000], cid, it["source"], *k) + (() if it["source"] == "chat" else (int(part),)))
            con.commit()
        finally:
            con.close()
        return
    con = search_db(case)
    try:
        c = con.execute("SELECT cid FROM bm_cat WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
        if c:
            n = 0
            for it in items:
                n += con.execute("DELETE FROM bm WHERE cid = ? AND source = ? AND inode = ?" + ("" if it["source"] == "chat" else " AND part = ?"),
                                 (c[0], it["source"], str(it.get("id") if it["source"] == "chat" else it["inode"]))
                                 + (() if it["source"] == "chat" else (int(part),))).rowcount
            con.commit()
            if n:
                case.log("preferiti_tolti", {"categoria": name, "tolti": n, "motivo": tr("trascrizione tornata in bozza")})
    finally:
        con.close()


def bm_list(case, q, ids=None, limit=PAGE):
    con = search_db(case)
    off = int(q.get("offset", 0))
    w, a = ["bm.cid = ?"], [int(q.get("cid") or 0)]
    if ids is not None:
        w.append("bm.id IN (SELECT value FROM json_each(?))")
        a.append(json.dumps([int(x) for x in ids if str(x).isdigit()]))
    text = (q.get("q") or "").strip()
    if text:
        w.append("(bm.path LIKE ? ESCAPE '\\' OR bm.note LIKE ? ESCAPE '\\')"); a += [fa.like(text)] * 2
    if yes(q.get("deleted")):
        w.append("bm.deleted >= 1")
    cf_apply(q, cf_hits(True), w, a)
    cond = " WHERE " + " AND ".join(w)
    try:
        if q.get("cfv"):
            cf_values(con, q, "bm", w, a)
        total = con.execute(f"SELECT COUNT(*) FROM bm{cond}", a).fetchone()[0]
        lim = f" LIMIT {int(limit)} OFFSET {off}" if limit else ""
        rows = con.execute("SELECT bm.id, bm.source, bm.part, bm.inode, bm.path, bm.name, bm.deleted, "
                           "bm.size, bm.mtime, c.name, '', bm.note, bm.md5, bm.sha1, bm.sha256 "
                           f"FROM bm JOIN bm_cat c ON c.cid = bm.cid{cond} "
                           f"ORDER BY {cf_order(q, 'bm.path COLLATE NOCASE')}{lim}", a).fetchall()
    finally:
        con.close()
    return {"kind": "hits", "total": total, "offset": off, "page": PAGE,
            "rows": [dict(zip(HIT_COLS, r)) for r in rows]}


def bm_timeline_csv(case, b):
    """(2.21) Cronologia dei preferiti in CSV nella cartella export del caso."""
    import csv
    righe = fa.bookmarks_timeline(case, False, b.get("cid"))
    if not righe:
        raise ValueError(tr("Nessun preferito ancora."))
    f = unique(case.export_dir / f"cronologia_preferiti_{G.stamp_now()}.csv")
    f.parent.mkdir(parents=True, exist_ok=True)
    tz = b.get("tz")
    with open(f, "w", newline="", encoding="utf-8-sig") as fo:
        w = csv.writer(fo, delimiter=";")
        w.writerow([tr("Data ({v1})").format(v1=tz_label(case, tz)), tr("Fino a"), tr("Data (registrata nel caso)"), tr("Evento"), tr("Elemento"),
                    tr("Categorie"), tr("Nota"), "SHA-256"])
        for x in righe:
            w.writerow([fmt_ts(case, tz, x["ts"]) if x["ts"] else tr("senza data"), fmt_ts(case, tz, x["fine"]) if x["fine"] else "", x["ts"],
                        x["evento"], x["path"], ", ".join(x["categorie"]), x["note"], x["sha256"] or ""])
    case.log("export_cronologia_preferiti", {"file": f.name, "elementi": len(righe), "sha256": fa.sha256_file(f)})
    return {"rel": str(f.relative_to(case.root)), "n": len(righe)}


def bm_remove(case, b):
    kind, rows = selected_rows(case, b)
    ids = [int(x["id"]) for x in rows]
    con = search_db(case)
    try:
        con.executemany("DELETE FROM bm WHERE id=?", [(i,) for i in ids])
        con.commit()
    finally:
        con.close()
    case.log("preferiti_rimossi", {"n": len(ids)})
    return {"removed": len(ids)}


def bm_cat_update(case, b):
    cid = int(b.get("cid") or 0)
    con = search_db(case)
    try:
        if b.get("name") is not None:
            name = " ".join(str(b["name"]).split())[:80]
            if not name:
                raise ValueError(tr("Il nome non può essere vuoto."))
            if con.execute("SELECT 1 FROM bm_cat WHERE name = ? COLLATE NOCASE AND cid <> ?",
                           (name, cid)).fetchone():
                raise ValueError(tr("Esiste già una categoria con questo nome."))
            con.execute("UPDATE bm_cat SET name=? WHERE cid=?", (name, cid))
        if b.get("note") is not None:
            con.execute("UPDATE bm_cat SET note=? WHERE cid=?", (str(b["note"])[:4000], cid))
        if b.get("in_report") is not None:
            con.execute("UPDATE bm_cat SET in_report=? WHERE cid=?", (1 if b["in_report"] else 0, cid))
        con.commit()
    finally:
        con.close()
    case.log("preferiti_categoria", {k: v for k, v in b.items()})
    return {"ok": True}


def bm_cat_delete(case, cid):
    con = search_db(case)
    try:
        name = (con.execute("SELECT name FROM bm_cat WHERE cid=?", (int(cid),)).fetchone() or [""])[0]
        con.execute("DELETE FROM bm WHERE cid=?", (int(cid),))
        con.execute("DELETE FROM bm_cat WHERE cid=?", (int(cid),))
        con.commit()
    finally:
        con.close()
    case.log("preferiti_categoria_eliminata", {"cid": int(cid), "nome": name})
    return {"ok": True}
