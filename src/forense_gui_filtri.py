#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - interfaccia, filtri per colonna.

(3.0.4) Codice spostato da forense_gui.py senza modifiche, per avere file più corti. Si carica tramite
forense_gui, che ne riesporta i nomi: gli altri moduli continuano a usare «G.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («G.<nome>»).
"""
import json
import re
from forense_lingua import N_
from forense_lingua import tr
import forense_agent as fa
import forense_lingua as lg

import forense_gui as G
from forense_gui import (
    PAGE, TL_KIND, yes)

# ------------------------------------------------- filtri per colonna
#
# Ogni colonna degli elenchi può essere filtrata: q["cf"] è un JSON {colonna: {...}} con
#   testo   {"v": "rossi -bianchi \"via roma\""}  tutte le parole devono comparire (contiene,
#           senza distinguere maiuscole); con "-" davanti una parola deve NON comparire
#   numero  {"min": byte, "max": byte}               dimensioni
#   data    {"from": "2024-03-01", "to": "2024-03-31"}  (già in UTC per le colonne con orario)
# Ogni elenco dichiara le sue colonne come {chiave: (espressione SQL, tipo)}, tipo t|n|d|D
# (d: data e ora UTC 'AAAA-MM-GGTHH:MM:SS'; D: solo data 'AAAA-MM-GG').

def cf_parse(q):
    raw = q.get("cf")
    if not raw:
        return {}
    try:
        d = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return d if isinstance(d, dict) else {}


def cf_terms(text):
    out = []
    for m in re.finditer(r'(-?)"([^"]+)"|(-?)(\S+)', text or ""):
        neg, term = (m.group(1), m.group(2)) if m.group(2) is not None else (m.group(3), m.group(4))
        if term:
            out.append((bool(neg), term))
    return out[:8]


class CfValues(Exception):
    """Segnale interno: la richiesta chiedeva l'elenco dei valori presenti in una colonna."""
    def __init__(self, rows):
        Exception.__init__(self)
        self.rows = rows


CALL_VERSI = {"in": N_("in arrivo"), "out": N_("in uscita"), "persa": N_("persa"), "rifiutata": N_("rifiutata"), "segreteria": N_("segreteria")}


def cf_apply(q, spec, w, a):
    """Aggiunge a w/a le condizioni dei filtri di colonna attivi. Ricorda le colonne dell'elenco
    (per l'ordinamento e per l'elenco dei valori). Con q["cfv"] il filtro di quella colonna è
    escluso, come nel menu a tendina di Excel."""
    q["_spec"] = spec
    skip = q.get("cfv")
    for key, v in list(cf_parse(q).items())[:16]:
        if key not in spec or not isinstance(v, dict) or key == skip:
            continue
        expr, typ = spec[key]
        if typ == "t":
            sel = v.get("sel")
            if isinstance(sel, list) and sel:
                w.append(f"IFNULL({q.get('_cfsel', {}).get(key, expr)}, '') IN (SELECT value FROM json_each(?))")
                a.append(json.dumps([str(x) for x in sel[:500]]))
            for neg, term in cf_terms(str(v.get("v") or "")[:300]):
                w.append(f"IFNULL({expr}, '') {'NOT ' if neg else ''}LIKE ? ESCAPE '\\'")
                a.append(fa.like(term))
        elif typ == "n":
            for op, k in ((">=", "min"), ("<=", "max")):
                x = v.get(k)
                if x in (None, ""):
                    continue
                try:
                    x = int(float(x))
                except (TypeError, ValueError):
                    continue
                w.append(f"{expr} {op} ?"); a.append(x)
        elif typ in ("d", "D"):
            lo, hi = str(v.get("from") or "")[:19], str(v.get("to") or "")[:19]
            if lo:
                w.append(f"{expr} >= ?"); a.append(lo)
            if hi:
                if typ == "d" and len(hi) == 10:
                    hi += "T23:59:59"
                w.append(f"{expr} <= ?"); a.append(hi)


def cf_order(q, default, pre=""):
    """ORDER BY: la colonna scelta con un clic sull'intestazione (q["sk"], q["sd"] = asc|desc),
    poi l'ordine normale dell'elenco per rendere stabile la paginazione."""
    spec = q.get("_spec") or {}
    k = q.get("sk")
    if k not in spec:
        return default
    expr, typ = spec[k]
    d = "DESC" if q.get("sd") == "desc" else "ASC"
    o = f"{expr} COLLATE NOCASE {d}" if typ == "t" else f"({expr}) IS NULL, {expr} {d}"
    return f"{pre}{o}, {default}"


def cf_values(con, q, sql_from, w, a):
    """Valori distinti (con quante righe) della colonna q["cfv"], con gli altri filtri attivi."""
    spec = q.get("_spec") or {}
    k = q.get("cfv")
    if k not in spec or spec[k][1] != "t":
        raise CfValues([])
    expr = q.get("_cfsel", {}).get(k, spec[k][0])
    cond = " WHERE " + " AND ".join(list(w) + [f"length(IFNULL({expr}, '')) <= 200"])
    raise CfValues(con.execute(
        f"SELECT IFNULL({expr}, '') v, COUNT(*) c FROM {sql_from}{cond} GROUP BY v "
        "ORDER BY c DESC, v COLLATE NOCASE LIMIT 301", a).fetchall())


def _sql_lit(s):
    return "'" + s.replace("'", "''") + "'"


def cf_timeline():
    """Colonne filtrabili della timeline: le etichette dei tipi di evento sono nella lingua dell'interfaccia."""
    lab = "CASE kind " + " ".join(f"WHEN '{k}' THEN {_sql_lit(tr(v))}" for k, v in TL_KIND.items()) + " ELSE kind END"
    return {"ts": ("ts", "d"), "kind": (lab, "t"),
            "source": (f"CASE WHEN origin='tsk' THEN {_sql_lit(tr('file system'))} ELSE source END", "t"),
            "detail": ("CASE WHEN origin='tsk' THEN path ELSE message END", "t")}
CF_META = {"path": ("path", "t"), "device": ("(IFNULL(make,'') || ' ' || IFNULL(model,''))", "t"),
           "taken": ("replace(substr(taken, 1, 10), ':', '-')", "D"), "author": ("author", "t")}
CF_CARVED = {"name": ("name", "t"), "type": ("type", "t"), "size": ("size", "n"),
             "img_offset": ("img_offset", "n"), "sha256": ("sha256", "t")}
CF_DOC = {"path": ("path", "t")}


def file_dati(con, nv, tab):
    """(3.0) Dimensione e date di Documenti e Foto/Video/Audio: dall'indice di navigazione per i file del file system,
    dall'elenco degli estratti (archivi, allegati, copie shadow) e dei recuperati per gli altri; NULL se non si conoscono."""
    fonti = {"size": [], "mtime": [], "crtime": []}
    if nv:
        for c in fonti:
            fonti[c].append(f"(SELECT n.{c} FROM nv.nav n WHERE n.part = {tab}.part AND n.inode = {tab}.inode LIMIT 1)")
    if fa.table_exists(con, "xitems"):
        for c in ("size", "mtime"):
            fonti[c].append(f"CASE WHEN {tab}.source = 'x' THEN (SELECT x.{c} FROM xitems x "
                            f"WHERE x.id = CAST({tab}.inode AS INTEGER)) END")
    if fa.table_exists(con, "carved"):
        fonti["size"].append(f"CASE WHEN {tab}.source = 'carving' THEN (SELECT c.size FROM carved c "
                             f"WHERE c.name = {tab}.inode LIMIT 1) END")
    return {c: "COALESCE(" + ", ".join(v + ["NULL", "NULL"]) + ")" for c, v in fonti.items()}


def cf_file_dati(dati):
    return {"size": (dati["size"], "n"), "mtime": (dati["mtime"], "d"), "crtime": (dati["crtime"], "d")}


def cf_hits(bm=False):
    p = "bm." if bm else ""
    spec = {"path": (p + "path", "t"), "size": (p + "size", "n"), "mtime": (p + "mtime", "d")}
    if bm:
        spec.update({"note": ("bm.note", "t"), "sha256": ("bm.sha256", "t")})
    else:
        spec.update({"wheres": ("wheres", "t"), "terms": ("terms", "t"), "detail": ("detail", "t")})
    return spec


def tl_where(q, w, a):
    """Filtri della timeline, comuni a tabella e grafico."""
    L = fa.like
    cf_apply(q, cf_timeline(), w, a)
    text = (q.get("q") or "").strip()
    if text:
        w.append("(path LIKE ? ESCAPE '\\' OR message LIKE ? ESCAPE '\\' OR "
                 "source LIKE ? ESCAPE '\\')"); a += [L(text)] * 3
    if q.get("start"):
        w.append("ts >= ?"); a.append(q["start"])
    if q.get("end"):
        e = q["end"]
        if "T" not in e:
            e += {4: "-12-31T23:59:59", 7: "-31T23:59:59"}.get(len(e), "T23:59:59")
        w.append("ts <= ?"); a.append(e)
    if q.get("origin"):
        w.append("origin = ?"); a.append(q["origin"])
    if q.get("ekind"):
        w.append("kind = ?"); a.append(q["ekind"])


def results(case, q, ids=None, limit=PAGE, full=False):
    """Una pagina di risultati (limit=None: tutte le righe, per esportazioni e selezioni).
    ids: solo le righe con questi identificativi (colonna `id`). Con q["cfv"]: l'elenco dei valori
    presenti nella colonna indicata ({"values": [[valore, righe], ...], "more": bool})."""
    try:
        return _results(case, q, ids, limit, full)
    except CfValues as e:
        return {"kind": q.get("kind", "file"), "values": [list(r) for r in e.rows[:300]],
                "more": len(e.rows) > 300}


def _results(case, q, ids=None, limit=PAGE, full=False):
    kind, text, off = q.get("kind", "file"), (q.get("q") or "").strip(), int(q.get("offset", 0))
    if kind == "explore":
        return G.nav_list(case, q, ids, limit)
    if kind == "hits":
        return G.bm_list(case, q, ids, limit) if q.get("cid") else G.hits_list(case, q, ids, limit)
    if kind in G.EXT_KINDS:
        return G.ext_results(case, q, ids, limit)
    if kind == "timeline" and str(q.get("origin") or "")[:3] in ("ev:", "msg"):
        return G.tl_evidenze_pagina(case, q, ids, off, limit)
    if kind == "timeline" and G.tl_e_preferiti(q):
        righe, _s = G.tl_preferiti(case, q)
        if q.get("cfv"):
            G.tl_preferiti_valori(righe, q["cfv"])
        if ids is not None:
            vuoi = {str(x) for x in ids}
            righe = [x for x in righe if str(x["id"]) in vuoi]
        k = q.get("sk") if q.get("sk") in ("kind", "source", "detail") else ""
        righe = sorted(righe, key=lambda x: (G.tl_preferito_campi(x)[k] if k else str(x["ts"] or "")).lower(), reverse=q.get("sd") == "desc")
        pag = righe[off:off + limit] if limit else righe
        return {"kind": kind, "total": len(righe), "offset": off, "page": PAGE,
                "rows": [{"id": x["id"], "ts": x["ts"], "kind": x["evento"], "source": ", ".join(x["categorie"]), "path": x["path"],
                          "message": x["note"] or x["name"] or "", "origin": "preferiti", "part": x["part"], "inode": None,
                          "bm": x} for x in pag]}
    con = fa.db_ro(case)
    w, a = [], []
    L = fa.like
    lim = f" LIMIT {int(limit)} OFFSET {int(off)}" if limit else ""
    idcol = "rowid"

    def restrict():
        if ids is not None:
            w.append(f"{idcol} IN (SELECT value FROM json_each(?))")
            a.append(json.dumps([int(x) for x in ids if str(x).lstrip("-").isdigit()]))

    def page(sql_from, cols, order):
        restrict()
        if q.get("cfv"):
            cf_values(con, q, sql_from, w, a)
        order = cf_order(q, order)
        cond = (" WHERE " + " AND ".join(w)) if w else ""
        total = con.execute(f"SELECT COUNT(*) FROM {sql_from}{cond}", a).fetchone()[0]
        rows = con.execute(f"SELECT rowid, {cols} FROM {sql_from}{cond} ORDER BY {order}{lim}",
                           a).fetchall()
        return total, rows

    try:
        if kind == "file":
            if text:
                w.append("path LIKE ? ESCAPE '\\'"); a.append(L(text))
            if yes(q.get("deleted")):
                w.append("deleted >= 1")
            if q.get("ext"):
                w.append("lower(path) LIKE ?"); a.append("%." + q["ext"].lower().lstrip("."))
            # dimensione e date vengono dall'indice di navigazione (se pronto)
            nv = G.nav_attach(con, case)

            def nvc(c):
                return (f"(SELECT n.{c} FROM nv.nav n WHERE n.part = files.part "
                        "AND n.inode = files.inode LIMIT 1)") if nv else "NULL"
            cf_apply(q, {"path": ("path", "t"), "type": ("type", "t"), "inode": ("inode", "t"),
                         "size": (nvc("size"), "n"), "mtime": (nvc("mtime"), "d"),
                         "crtime": (nvc("crtime"), "d"), "atime": (nvc("atime"), "d"), "ctime": (nvc("ctime"), "d")}, w, a)
            total, rows = page("files", "part, inode, deleted, type, path, " + ", ".join(
                nvc(c) for c in ("size", "mtime", "crtime", "atime", "ctime")), "path")
            data = [{"id": r, "part": p, "inode": i, "deleted": d, "type": t, "path": pa,
                     "size": sz, "mtime": mt, "crtime": ct, "atime": at, "ctime": cm}
                    for r, p, i, d, t, pa, sz, mt, ct, at, cm in rows]
        elif kind == "timeline":
            tl_where(q, w, a)
            total, rows = page("events", "ts, kind, source, path, message, origin, part", "ts")
            data = []
            for rid, ts, k, src, pa, msg, orig, part in rows:
                m = re.search(r"inode (\S+)", msg or "") if orig == "tsk" else None
                data.append({"id": rid, "ts": ts, "kind": tr(TL_KIND.get(k, k)), "source": src,
                             "path": pa, "message": (msg or "") if full else (msg or "")[:400],
                             "origin": orig, "part": part, "inode": m.group(1) if m else None})
        elif kind == "doc":
            fts = "fts5" in (con.execute("SELECT sql FROM sqlite_master WHERE name='doc_text'")
                             .fetchone() or [""])[0].lower()
            fd = file_dati(con, G.nav_attach(con, case), "doc_text")
            fdc = f"{fd['size']}, {fd['mtime']}, {fd['crtime']}"
            cf_apply(q, {**CF_DOC, **cf_file_dati(fd)}, w, a)
            dx = (q.get("dext") or "").strip().lower().lstrip(".")
            if dx == "~posta":
                w.append("source = 'posta'")
            elif dx == "~senza":          # nome senza punto: si guarda solo dopo l'ultimo «/» e l'ultimo «›» del percorso
                b1 = "replace(path, rtrim(path, replace(path, '/', '')), '')"
                b2 = f"replace({b1}, rtrim({b1}, replace({b1}, '›', '')), '')"
                w.append(f"source <> 'posta' AND {b2} NOT LIKE '%.%'")
            elif dx:
                w.append("source <> 'posta' AND lower(path) LIKE ? ESCAPE '\\'"); a.append("%." + fa.like(dx).strip("%"))
            if text and fts:
                terms = re.findall(r'"[^"]+"|[^\s"]+', text)
                mq = " ".join('"' + t.strip('"').replace('"', "") + '"' for t in terms)
                w.append("doc_text MATCH ?"); a.append(mq)
                restrict()
                if q.get("cfv"):
                    cf_values(con, q, "doc_text", w, a)
                cond = " WHERE " + " AND ".join(w)
                total = con.execute(f"SELECT COUNT(*) FROM doc_text{cond}", a).fetchone()[0]
                rows = con.execute("SELECT rowid, path, kind, source, part, inode, deleted, "
                                   f"snippet(doc_text, 1, '«', '»', ' … ', 18), {fdc} FROM doc_text"
                                   f"{cond} ORDER BY {cf_order(q, 'rank')}{lim}", a).fetchall()
            else:
                if text:
                    w.append("(body LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\')"); a += [L(text)] * 2
                total, rows = page("doc_text", "path, kind, source, part, inode, deleted, "
                                   f"substr(body, 1, 240), {fdc}", "path")
            data = [{"id": r, "path": p, "kind": lg.valore(k), "source": s, "part": pt, "inode": i,
                     "deleted": d, "snippet": " ".join((sn or "").split()), "size": sz, "mtime": mt, "crtime": ct}
                    for r, p, k, s, pt, i, d, sn, sz, mt, ct in rows]
        elif kind == "meta":
            aud = yes(q.get("aud"))             # (2.20) solo gli audio (dall'elenco dei file)
            mf = G.media_contenuto(case, con)     # (3.0.1) foto, video e audio riconosciuti dal contenuto
            if text:
                w.append("(data LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\')"); a += [L(text)] * 2
            if yes(q.get("gps")):
                w.append("lat IS NOT NULL")
            if yes(q.get("vid")) and not aud:    # (2.20) solo i video (per estensione)
                w.append(mf.filtro("video", col_source="source") if mf else G.video_where()); a += [] if mf else G.video_args()
            if yes(q.get("foto")) and not aud:   # (2.20) solo le foto (per estensione)
                w.append(mf.filtro("foto", col_source="source") if mf else G.photo_where()); a += [] if mf else G.photo_args()
            if yes(q.get("altri")) and not aud:  # (3.0.1) gli altri file con metadati
                w.append(G.altri_where(mf)); a += [] if mf else G.altri_args()
            if mf and q.get("mapp") == "~carving":     # (3.0.1) memorie di massa: recuperati dal carving
                w.append("source = 'carving'")
            elif mf and q.get("mapp"):             # (3.0.1) app o cartella a cui appartiene il file (cache a parte)
                w.append("(part, inode) IN (SELECT part, inode FROM media_file WHERE app = ?"
                         + (" AND area = 'cache'" if yes(q.get("mcache")) else "") + ")"); a.append(q["mapp"])
            elif mf and yes(q.get("mcache")):
                w.append("(part, inode) IN (SELECT part, inode FROM media_file WHERE area = 'cache')")
            if q.get("mtr") in ("conf", "auto"):   # (3.0.1) trascrizioni confermate dall'analista / automatiche da confermare
                w.append(G.trascr_where(con, q["mtr"]))
            if q.get("orig") and fa.is_mobile(case):    # (2.20) telefoni: solo i file allegati alle chat
                import forense_mobile_gui as fmg
                fmg.meta_filter(con, q, w, a)
            fd = file_dati(con, G.nav_attach(con, case), "meta")
            cf_apply(q, {**CF_META, **cf_file_dati(fd)}, w, a)
            base = G.audio_from(bool(mf)) + " AS meta" if aud else "meta" if yes(q.get("foto")) or yes(q.get("vid")) or yes(q.get("altri")) \
                else G.media_tutti_from(bool(mf)) + " AS meta"         # (3.0.1) voce principale: anche gli audio
            total, rows = page(base, "path, make, model, taken, lat, lon, author, source, "
                               f"part, inode, deleted, {fd['size']}, {fd['mtime']}, {fd['crtime']}",
                               "path" if aud else "taken IS NULL, taken")
            data = [dict(zip(("id", "path", "make", "model", "taken", "lat", "lon", "author",
                              "source", "part", "inode", "deleted", "size", "mtime", "crtime"), r)) for r in rows]
            xs = [d["inode"] for d in data if d["source"] == "x"]
            if xs and fa.table_exists(con, "xitems"):     # (3.0.1) estratti (cache dei browser): nome, file d'origine e nota
                info = {str(r[0]): r[1:] for r in con.execute(
                    "SELECT id, name, part, inode, src_path, note FROM xitems WHERE id IN (SELECT value FROM json_each(?))",
                    (json.dumps([int(x) for x in xs if str(x).isdigit()]),))}
                for d in data:
                    e = info.get(str(d["inode"])) if d["source"] == "x" else None
                    if e:
                        d.update(xname=e[0], xpart=e[1], xinode=e[2], xsrc=e[3], xnote=e[4])
            for d in data:
                d["taken_tz"] = G.taken_tz_text(d.get("taken"))
            if fa.is_mobile(case):           # (2.20) app delle chat in cui il file è allegato
                import forense_mobile_gui as fmg
                fmg.meta_origini(con, data)
            if mf:                           # (3.0.1) tipo dal contenuto e app o cartella del file
                mf.righe(con, data)
        elif kind == "carved":
            if text:
                w.append("name LIKE ? ESCAPE '\\'"); a.append(L(text))
            if q.get("type"):
                w.append("type = ?"); a.append(q["type"].lower().lstrip("."))
            cf_apply(q, CF_CARVED, w, a)
            total, rows = page("carved", "name, type, size, part, img_offset, sha256, relpath",
                               "img_offset")
            data = [dict(zip(("id", "name", "type", "size", "part", "img_offset", "sha256",
                              "relpath"), r)) for r in rows]
        elif kind == "trace":
            if q.get("tkind"):
                w.append("kind = ?"); a.append(q["tkind"])
            if text:
                w.append("(feature LIKE ? ESCAPE '\\' OR context LIKE ? ESCAPE '\\')"); a += [L(text)] * 2
            if yes(q.get("grouped", "1")):
                if ids is not None:
                    w.append("(kind || char(9) || feature) IN (SELECT value FROM json_each(?))")
                    a.append(json.dumps([str(x) for x in ids]))
                cond = (" WHERE " + " AND ".join(w)) if w else ""
                total = con.execute(f"SELECT COUNT(*) FROM (SELECT 1 FROM features{cond} "
                                    "GROUP BY kind, feature)", a).fetchone()[0]
                rows = con.execute(f"SELECT kind, feature, COUNT(*) n, MIN(pos), MIN(offset) "
                                   f"FROM features{cond} GROUP BY kind, feature "
                                   f"ORDER BY n DESC, feature{lim}", a).fetchall()
                data = [{"id": f"{k}\t{f}", "tkind": k, "feature": f, "count": n, "offset": o}
                        for k, f, n, _, o in rows]
            else:
                total, rows = page("features", "kind, offset, feature, context", "pos")
                data = [{"id": r, "tkind": k, "offset": o, "feature": f,
                         "context": c if full else c[:240]} for r, k, o, f, c in rows]
        else:
            raise ValueError(tr("Sezione sconosciuta."))
    finally:
        con.close()
    out = {"kind": kind, "total": total, "offset": off, "page": PAGE, "rows": data}
    if kind in ("doc", "meta") and G.ensure_nav(case)["state"] == "building":
        out["nav_attesa"] = True     # (3.0) dimensioni e date in arrivo: l'elenco non va ricordato e la pagina si aggiorna da sola
    return out
