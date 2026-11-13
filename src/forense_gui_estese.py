#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - interfaccia, analisi estese: risultati, anteprime, azioni.

(3.0.4) Codice spostato da forense_gui.py senza modifiche, per avere file più corti. Si carica tramite
forense_gui, che ne riesporta i nomi: gli altri moduli continuano a usare «G.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («G.<nome>»).
"""
import html as html_mod
import json
import os
import re
import shutil
import sqlite3
import sys
import threading
import time
from pathlib import Path
from forense_lingua import N_
from forense_lingua import tr
import forense_agent as fa
import forense_diagnostica as fd
import forense_lingua as lg

import forense_gui as G
from forense_gui import (
    CALL_VERSI, CSP_DOC, HASH_TOKEN, HIT_COLS, NAV_STATE, PAGE, PREP, SEARCH_STOP, SES, WHERE_LABEL, _sql_lit,
    cache_dir, cf_apply, cf_hits, cf_order, cf_values, clean_path, ensure_nav, fmt_ts, image_ident, image_read, lp,
    meta_firma, nav_db, reveal, safe_ext, safe_key, safe_part, search_db, tz_label, yes)

# ------------------------------------------------- analisi estese: risultati, anteprime, azioni
#
# Archivi e posta, artefatti di sistema, copie shadow e anomalie stanno in caso.sqlite
# (tabelle di forense_estesa). I file estratti hanno "source" = "x" e id numerico.

EXT_KINDS = ("art", "mail", "arch", "vss", "anom")
X_COLS = ("id", "kind", "part", "inode", "src_path", "parent", "mail", "inner", "path", "name", "size",
          "mtime", "encrypted", "deleted", "relpath", "md5", "sha1", "sha256", "note", "store")


def ext_counts(case, con):
    est = case.meta.get("estese") or {}
    has = lambda t: fa.table_exists(con, t)
    one = lambda sql: con.execute(sql).fetchone()[0]
    return {
        "art": one("SELECT COUNT(*) FROM artifacts") if has("artifacts") and ("artefatti" in est or case.meta.get("ram")) else None,
        "mail": one("SELECT COUNT(*) FROM mail") if has("mail") and "archivi" in est else None,
        "arch": one("SELECT COUNT(*) FROM xitems WHERE kind IN ('archivio','allegato','miniatura','cache_web')") if has("xitems") and (
            "archivi" in est or "artefatti" in est or one("SELECT COUNT(*) FROM xitems WHERE kind = 'cache_web'")) else None,
        "vss": one("SELECT COUNT(*) FROM xitems WHERE kind='vss'") if has("xitems") and "vss" in est else None,
        "anom": one("SELECT COUNT(*) FROM anomalies") if has("anomalies") and (
            "anomalie" in est or case.meta.get("liste_hash") or case.meta.get("volumi_cifrati")) else None,
    }


def ext_results(case, q, ids=None, limit=PAGE):
    kind, text, off = q.get("kind"), (q.get("q") or "").strip(), int(q.get("offset", 0))
    con = fa.db_ro(case)
    w, a = [], []
    L = fa.like
    lim = f" LIMIT {int(limit)} OFFSET {int(off)}" if limit else ""
    if ids is not None:
        w.append("id IN (SELECT value FROM json_each(?))")
        a.append(json.dumps([int(x) for x in ids if str(x).lstrip("-").isdigit()]))
    try:
        if kind == "art":
            if not fa.table_exists(con, "artifacts"):
                raise ValueError(tr("Artefatti non ancora estratti."))
            if q.get("cat"):
                w.append("cat = ?"); a.append(q["cat"])
            if fa.is_mobile(case):              # smartphone (2.20): sottovoci dell'albero
                import forense_mobile_gui as fmg
                fmg.art_filter(con, q, w, a)
            if text:
                w.append("(title LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\' OR user LIKE ? ESCAPE '\\' "
                         "OR src_path LIKE ? ESCAPE '\\')"); a += [L(text)] * 4
            if q.get("start"):
                w.append("ts >= ?"); a.append(q["start"])
            if q.get("end"):
                w.append("ts <= ?"); a.append(q["end"] + ("T23:59:59" if "T" not in q["end"] else ""))
            # (3.0) chiamate: verso, contatto (nome e numero) e app come colonne proprie, filtrabili
            versi = " ".join(f"WHEN {_sql_lit(k)} THEN {_sql_lit(tr(v))}" for k, v in CALL_VERSI.items())
            cf_apply(q, {"ts": ("ts", "d"), "cat": ("cat", "t"), "title": ("(title || ' ' || IFNULL(user,''))", "t"),
                         "detail": ("detail", "t"), "src_path": ("src_path", "t"),
                         "verso": (f"CASE json_extract(CASE WHEN json_valid(data) THEN data END, '$.verso') {versi} ELSE {_sql_lit(tr('verso non indicato'))} END", "t"),
                         "contatto": ("TRIM(COALESCE(json_extract(CASE WHEN json_valid(data) THEN data END, '$.nome_rubrica'), json_extract(CASE WHEN json_valid(data) THEN data END, '$.nome_app'), '') || ' ' || "
                                      "COALESCE(json_extract(CASE WHEN json_valid(data) THEN data END, '$.numero'), '') || ' ' || "
                                      "COALESCE(json_extract(CASE WHEN json_valid(data) THEN data END, '$.lid'), ''))", "t"),
                         "app": ("json_extract(CASE WHEN json_valid(data) THEN data END, '$.app_lbl')", "t"),
                         "durata": ("json_extract(CASE WHEN json_valid(data) THEN data END, '$.durata_s')", "n"),
                         "risposta": ("CASE json_extract(CASE WHEN json_valid(data) THEN data END, '$.risposta') WHEN 1 THEN "
                                      f"{_sql_lit(tr('sì'))} WHEN 0 THEN {_sql_lit(tr('no'))} ELSE {_sql_lit(tr('non indicata'))} END", "t")}, w, a)
            cols = ("id", "cat", "ts", "title", "detail", "user", "src_path", "part", "inode", "data")
            table, order = "artifacts", "ts IS NULL, ts DESC, id"
        elif kind == "mail":
            if not fa.table_exists(con, "mail"):
                raise ValueError(tr("Posta non ancora analizzata."))
            if text:
                w.append("(subject LIKE ? ESCAPE '\\' OR sender LIKE ? ESCAPE '\\' OR recipients LIKE ? ESCAPE '\\' "
                         "OR body LIKE ? ESCAPE '\\')"); a += [L(text)] * 4
            if yes(q.get("att")):
                w.append("n_att > 0")
            if q.get("fmt"):
                w.append("fmt = ?"); a.append(q["fmt"])
            if q.get("start"):
                w.append("date >= ?"); a.append(q["start"])
            if q.get("end"):
                w.append("date <= ?"); a.append(q["end"] + ("T23:59:59" if "T" not in q["end"] else ""))
            cf_apply(q, {"date": ("date", "d"), "sender": ("sender", "t"), "recipients": ("recipients", "t"),
                         "subject": ("subject", "t"),
                         "folder": ("(IFNULL(fmt,'') || ' ' || IFNULL(folder,'') || ' ' || IFNULL(src_path,''))", "t")}, w, a)
            cols = ("id", "date", "sender", "recipients", "cc", "subject", "n_att", "fmt", "folder", "src_path",
                    "part", "inode", "xid")
            table, order = "mail", "date IS NULL, date DESC, id"
        elif kind in ("arch", "vss"):
            if not fa.table_exists(con, "xitems"):
                raise ValueError(tr("Analisi non ancora eseguita."))
            if kind == "vss":
                w.append("kind = 'vss'")
                if q.get("store"):
                    w.append("store = ?"); a.append(q["store"])
            else:
                w.append("kind IN ('archivio','allegato','miniatura','cache_web')")
                if q.get("xk"):
                    w.append("kind = ?"); a.append(q["xk"])
            if text:
                w.append("path LIKE ? ESCAPE '\\'"); a.append(L(text))
            if yes(q.get("enc")):
                w.append("encrypted = 1")
            if q.get("ext"):
                w.append("lower(name) LIKE ?"); a.append("%." + q["ext"].lower().lstrip("."))
            cf_apply(q, {"path": ("path", "t"), "inner": ("path", "t"), "store": ("store", "t"),
                         "size": ("size", "n"), "mtime": ("mtime", "d"),
                         "note": ("(IFNULL(sha256,'') || ' ' || IFNULL(note,''))", "t")}, w, a)
            cols = X_COLS
            table, order = "xitems", "path COLLATE NOCASE"
        elif kind == "anom":
            if not fa.table_exists(con, "anomalies"):
                raise ValueError(tr("Anomalie non ancora cercate."))
            if q.get("akind"):
                w.append("kind = ?"); a.append(q["akind"])
            if text:
                w.append("(path LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\')"); a += [L(text)] * 2
            cf_apply(q, {"kind": ("kind", "t"), "path": ("path", "t"), "detail": ("detail", "t"),
                         "size": ("size", "n")}, w, a)
            cols = ("id", "kind", "source", "part", "inode", "path", "detail", "ext", "real", "size", "deleted", "sev")
            table, order = "anomalies", "sev DESC, kind, path COLLATE NOCASE"
        else:
            raise ValueError(tr("Sezione sconosciuta."))
        if q.get("cfv"):
            cf_values(con, q, table, w, a)
        order = cf_order(q, order)
        cond = (" WHERE " + " AND ".join(w)) if w else ""
        total = con.execute(f"SELECT COUNT(*) FROM {table}{cond}", a).fetchone()[0]
        rows = [dict(zip(cols, r)) for r in con.execute(
            f"SELECT {', '.join(cols)} FROM {table}{cond} ORDER BY {order}{lim}", a)]
    finally:
        con.close()
    for r in rows:
        if "data" in r and r["data"]:
            try:
                r["data"] = json.loads(r["data"])
            except ValueError:
                pass
    if kind == "art" and fa.is_mobile(case):        # smartphone (2.20): percorsi nell'estrazione, fonte di iLEAPP/ALEAPP
        import forense_mobile_gui as fmg
        fmg.fix_art_rows(case, rows)
    if kind == "art" and limit and len(rows) <= 1000:
        cited_rows(case, rows)
    return {"kind": kind, "total": total, "offset": off, "page": PAGE, "rows": rows}


def cited_ref(x, mobile):
    """(2.20) Esito di forense_percorsi per la pagina: campi utili, testo dell'esito e metodo."""
    import forense_percorsi as fp
    if not x:
        return None
    d = {k: x.get(k) for k in ("campo", "valore", "ruolo", "stato", "metodo", "part", "inode", "path", "size", "isdir",
                               "deleted", "copie", "verifica", "rapporto", "tipo", "percorso", "incorporato_in", "nota",
                               "candidati", "n_candidati", "copie_elenco", "cartelle", "sha256")}
    tc = lambda c: tr(fp.CAMPI_INTERNI[c]) if c in fp.CAMPI_INTERNI else c
    d["campi"] = [tc(c) for c in (x.get("campi") or [x.get("campo")]) if c]
    if d["campo"] in fp.CAMPI_INTERNI:
        d["campo"] = tc(d["campo"])
    d["livello"] = x.get("livello") or fp.livello(x)
    d["label"] = fp.etichetta_disco(x, mobile)
    d["metodo_lbl"] = tr(fp.METODI[x["metodo"]]) if x.get("metodo") in fp.METODI else ""
    d["metodi_lbl"] = fp.metodo_testo(x)
    return d


def cited_rows(case, rows):
    """(2.20) Righe della tabella degli artefatti: file citati (ricerca veloce, senza hash) per la miniatura e l'icona."""
    import forense_percorsi as fp
    mobile = fa.is_mobile(case)
    try:
        idx = fp.Indice(case)
    except (ValueError, sqlite3.Error, OSError):
        return
    try:
        for r in rows:
            try:
                c = fp.file_citati(case, r, veloce=True, idx=idx)
            except Exception:
                continue
            fs = [x for x in c["file"] if x["ruolo"] == "file"]
            if not fs:
                continue
            ok = [x for x in fs if x["stato"] in ("trovato", "rapporto")]
            img = next((x for x in ok if x.get("tipo") == "immagine"), None)
            lv = min((x.get("livello") or fp.livello(x) for x in fs), key=("certo", "probabile", "assente").index)
            r["cited"] = {"n": len(fs), "ok": len(ok), "img": cited_ref(img, mobile) if img else None,
                          "first": cited_ref(fs[0], mobile), "livello": lv,
                          "label": "\n".join(fp.etichetta_disco(x, mobile) for x in fs)}
    finally:
        idx.close()


def cited_info(case, b):
    """(2.20) File citati da un artefatto, con l'esito completo (anche per hash) e la fonte risolta."""
    import forense_percorsi as fp
    con = fa.db_ro(case)
    try:
        r = con.execute("SELECT id, cat, ts, title, detail, user, src_path, part, inode, data FROM artifacts WHERE id=?",
                        (int(b.get("id") or 0),)).fetchone()
    finally:
        con.close()
    if not r:
        raise ValueError(tr("Artefatto non trovato."))
    row = dict(zip(("id", "cat", "ts", "title", "detail", "user", "src_path", "part", "inode", "data"), r))
    mobile = fa.is_mobile(case)
    c = fp.file_citati(case, row)
    return {"fonte": cited_ref(c["fonte"], mobile), "file": [cited_ref(x, mobile) for x in c["file"]]}


def ext_tree(case):
    """Sottovoci per la vista ad albero: categorie, tipi, formati."""
    con = fa.db_ro(case)
    out = {}
    try:
        if fa.table_exists(con, "artifacts"):
            out["art"] = con.execute("SELECT cat, COUNT(*) FROM artifacts GROUP BY cat ORDER BY 2 DESC").fetchall()
            if fa.is_mobile(case):              # smartphone (2.20): categorie e artefatti di iLEAPP/ALEAPP, app delle chat
                import forense_mobile_gui as fmg
                out["artsub"] = fmg.art_tree(con)
            # (3.0) fonti della Timeline: solo ciò che ha una data
            ev = "cat, grp, sub" if "grp" in {r[1] for r in con.execute("PRAGMA table_info(artifacts)")} else "cat, NULL, NULL"
            out["tl_ev"] = con.execute(f"SELECT {ev}, COUNT(*) FROM artifacts WHERE cat <> 'messaggi' AND ts GLOB '[0-9][0-9][0-9][0-9]-*' "
                                       "GROUP BY 1, 2, 3 ORDER BY 1, 2 COLLATE NOCASE, 3 COLLATE NOCASE").fetchall()
        if fa.table_exists(con, "chat_messages"):
            import forense_mobile_chat as fmc
            out["tl_msg"] = [[app, tr(fmc.APP_LBL.get(app, app)), n] for app, n in con.execute(
                "SELECT app, COUNT(*) FROM chat_messages WHERE ts GLOB '[0-9][0-9][0-9][0-9]-*' GROUP BY app ORDER BY 1")]
        if fa.table_exists(con, "anomalies"):
            out["anom"] = con.execute("SELECT kind, COUNT(*) FROM anomalies GROUP BY kind ORDER BY MAX(sev) DESC").fetchall()
        if fa.table_exists(con, "xitems"):
            out["arch"] = con.execute("SELECT kind, COUNT(*) FROM xitems WHERE kind IN ('archivio','allegato','miniatura','cache_web') "
                                      "GROUP BY kind").fetchall()
            out["vss"] = con.execute("SELECT store, COUNT(*) FROM xitems WHERE kind='vss' GROUP BY store ORDER BY store").fetchall()
        if fa.table_exists(con, "mail"):
            out["mail"] = con.execute("SELECT fmt, COUNT(*) FROM mail GROUP BY fmt").fetchall()
    finally:
        con.close()
    return out


def x_ident(case, b):
    """Un file estratto (archivio, allegato, copia shadow)."""
    con = fa.db_ro(case)
    try:
        r = con.execute(f"SELECT {', '.join(X_COLS)} FROM xitems WHERE id=?", (int(b.get("id") or b.get("inode") or 0),)).fetchone()
    finally:
        con.close()
    if not r:
        raise ValueError(tr("File estratto non trovato."))
    x = dict(zip(X_COLS, r))
    f = case.root / x["relpath"] if x["relpath"] else None
    if f is not None and not f.exists():
        f = None
    return {"source": "x", "id": x["id"], "name": x["name"], "path": x["path"], "key": f"x_{x['id']}",
            "ext": Path(x["name"] or "").suffix.lower(), "size": f.stat().st_size if f else x["size"],
            "file": f, "deleted": x["deleted"] or 0, "part": None, "inode": None, "rec": x}


def phash_simili(case, b):
    """Immagini del caso simili (hash percettivo) a quella indicata."""
    fe = fe_mod()
    con = fa.db_ro(case)
    try:
        if not fa.table_exists(con, "phash"):
            raise ValueError(tr("Esegui prima l'analisi «Hash percettivi» (Analisi aggiuntive)."))
        src = b.get("source") or "fs"
        key = str(b.get("id")) if src == "x" else str(b.get("name")) if src == "carving" else str(b.get("inode"))
        sql, args = "SELECT dhash FROM phash WHERE source=? AND inode=?", [src, key]
        if src == "fs":
            sql += " AND part=?"
            args.append(int(b.get("part")))
        r = con.execute(sql, args).fetchone()
        if not r:
            raise ValueError(tr("Questa immagine non ha un hash percettivo (non si apre o non era tra le immagini analizzate)."))
        out = []
        for d, s, p, i, pa in fe.phash_similar(con, r[0]):
            if s == src and str(i) == key and (src != "fs" or p == int(b.get("part"))):
                continue
            out.append({"dist": d, "source": s, "part": p, "inode": i, "path": pa})
        return {"simili": out, "soglia": fe.PHASH_NEAR}
    finally:
        con.close()


X_KIND_LBL = {"archivio": N_("contenuto di un archivio"), "allegato": N_("allegato di posta"), "vss": N_("copia shadow"),
              "miniatura": N_("miniatura della cache di Esplora file (thumbcache)"),
              "cache_web": N_("foto o video dalla cache di un browser (Chrome, Samsung Internet, Edge, …)")}


def x_details(case, it, tz=None):
    x = it["rec"]
    lines = [tr("File estratto: {path}").format(path=x['path']),
             tr("Tipo: ") + tr(X_KIND_LBL.get(x["kind"], x["kind"])),
             tr("File di origine nella copia: {src_path} (offset {part}, inode {inode})").format(src_path=x['src_path'], part=x['part'], inode=x['inode']) if x["kind"] != "vss"
             else (tr("Snapshot APFS: {store} (volume all'offset {part}, identificatore nello snapshot {inode})").format(store=x['store'], part=x['part'], inode=x['inode'])
                   if str(x["store"] or "").startswith("snapshot APFS") else
                   tr("Copia shadow: {store} (partizione all'offset {part}, inode nella copia shadow {inode})").format(store=x['store'], part=x['part'], inode=x['inode'])),
             tr("Dimensione: {size} byte").format(size=x['size']), tr("Data indicata ({v1}): {v2}").format(v1=tz_label(case, tz), v2=fmt_ts(case, tz, x['mtime']) or '-'),
             tr("Protetto da password: {v1}").format(v1=tr('sì') if x['encrypted'] else tr('no')),
             f"MD5: {x['md5'] or '-'}", f"SHA-1: {x['sha1'] or '-'}", f"SHA-256: {x['sha256'] or '-'}",
             tr("Copia nel caso: {v1}").format(v1=x['relpath'] or tr('non estratto')) + (f" ({x['note']})" if x["note"] else "")]
    return "\n".join(lines)


def x_text(case, it):
    f = it.get("file")
    if not f:
        return tr("File non estratto: ") + (it["rec"].get("note") or tr("contenuto non disponibile"))
    data = f.read_bytes()[:50 << 20]
    tmp = cache_dir(case, "tmp")
    try:
        r = fa.extract_text(data, it["name"], tmp)
    except Exception:
        r = None
    if not r and data.startswith(b"SQLite format 3\x00"):
        return fe_mod().sqlite_dump(f, 60000)
    return r[1] if r else fa.binary_strings(data)


def fe_mod():
    import forense_estesa as fe
    return fe


def mail_view(case, b):
    """Messaggio di posta per il riquadro di anteprima: intestazioni, testo o HTML (senza
    contenuti esterni), allegati apribili."""
    con = fa.db_ro(case)
    try:
        r = con.execute("SELECT id, date, sender, recipients, cc, subject, body, html, headers, src_path, folder, fmt, "
                        "part, inode FROM mail WHERE id=?", (int(b.get("id") or b.get("inode") or 0),)).fetchone()
        atts = con.execute("SELECT id, name, size, encrypted, relpath, note FROM xitems WHERE mail=? ORDER BY id",
                           (int(b.get("id") or b.get("inode") or 0),)).fetchall()
    finally:
        con.close()
    if not r:
        raise ValueError(tr("Messaggio non trovato."))
    mid, date, snd, to, cc, subj, body, htm, hdr, src, folder, fmt, part, inode = r
    page = htm if htm else f"<pre style='white-space:pre-wrap;font:13px/1.5 -apple-system,Segoe UI,sans-serif'>{html_mod.escape(body or '')}</pre>"
    page = re.sub(r"(?is)<(script|iframe|object|embed|link|meta)\b.*?(</\1>|>)", "", page)
    return {"type": "mail", "title": subj, "name": subj, "source": "mail", "id": mid, "size": len(body or ""),
            "deleted": 0, "part": part, "inode": inode, "magic": "",
            "head": {"Da": snd, "A": to, "Cc": cc, f"Data ({tz_label(case, b.get('tz'))})": fmt_ts(case, b.get("tz"), date), "Oggetto": subj,
                     "Fonte": f"{src} › {folder}" if folder else src, "Formato": fmt},
            "html": CSP_DOC + "<base target='_blank'>" + page, "headers": hdr or "",
            "atts": [{"id": i, "name": n, "size": z, "enc": e, "ok": bool(rel), "note": nt} for i, n, z, e, rel, nt in atts]}


def art_view(case, b):
    con = fa.db_ro(case)
    try:
        r = con.execute("SELECT id, cat, ts, title, detail, user, src_path, part, inode, data FROM artifacts WHERE id=?",
                        (int(b.get("id") or b.get("inode") or 0),)).fetchone()
    finally:
        con.close()
    if not r:
        raise ValueError(tr("Artefatto non trovato."))
    aid, cat, ts, title, detail, user, src, part, inode, data = r
    chat = None
    if cat == "messaggi" and data:               # (2.21) scheda di una chat: dai Preferiti si deve poter aprire la conversazione
        try:
            chat = (json.loads(data) or {}).get("chat_thread")
        except (ValueError, AttributeError):
            pass
    cited = None
    try:                                         # (2.20) file citati dalla riga e fonte risolta nella copia/estrazione
        import forense_percorsi as fp
        mobile = fa.is_mobile(case)
        c = fp.file_citati(case, dict(zip(("id", "cat", "ts", "title", "detail", "user", "src_path", "part", "inode", "data"), r)))
        cited = {"fonte": cited_ref(c["fonte"], mobile), "file": [cited_ref(x, mobile) for x in c["file"]]}
    except (ValueError, sqlite3.Error, OSError):
        pass
    title, rows, segreti = _art_campi(case, b, r)
    h = "<table style='border-collapse:collapse;font:13px/1.5 -apple-system,Segoe UI,sans-serif;width:100%'>" + "".join(
        f"<tr><th style='text-align:left;vertical-align:top;padding:5px 10px;border-bottom:1px solid #ddd;white-space:nowrap'>"
        f"{html_mod.escape(k)}</th><td style='padding:5px 10px;border-bottom:1px solid #ddd;word-break:break-word'>"
        f"{html_mod.escape(str(v or ''))}</td></tr>" for k, v in rows) + "</table>"
    return {"type": "html", "title": title, "name": title, "source": "art", "id": aid, "size": 0, "deleted": 0,
            "part": part, "inode": inode, "magic": "", "html": CSP_DOC + h, "src_path": src, "cited": cited,
            "segreti": segreti, "chat": chat}


def art_campi(case, b):
    """(3.0.1) Titolo, campi e conversazione di un artefatto, come nel pannello di dettaglio (per il report illustrato)."""
    con = fa.db_ro(case)
    try:
        r = con.execute("SELECT id, cat, ts, title, detail, user, src_path, part, inode, data FROM artifacts WHERE id=?",
                        (int(b.get("id") or b.get("inode") or 0),)).fetchone()
    finally:
        con.close()
    if not r:
        raise ValueError(tr("Artefatto non trovato."))
    title, rows, _seg = _art_campi(case, b, r)
    chat = None
    if r[1] == "messaggi" and r[9]:
        try:
            chat = (json.loads(r[9]) or {}).get("chat_thread")
        except (ValueError, AttributeError):
            pass
    return title, [(k, v) for k, v in rows if v not in (None, "")], chat


def _art_campi(case, b, r):
    aid, cat, ts, title, detail, user, src, part, inode, data = r
    fe = fe_mod()
    segreti = None
    rows = [(tr("Categoria"), tr(fe.ART_CATS.get(cat, cat))), (tr("Data ({v1})").format(v1=tz_label(case, b.get('tz'))), fmt_ts(case, b.get("tz"), ts)), (tr("Elemento"), title),
            (tr("Dettagli"), G.testo_fuso(case, b.get("tz"), detail)), (tr("Utente"), user), (tr("Fonte"), f"{src} (offset {part}, inode {inode})" if src and inode not in (None, "") else src or "")]
    try:
        dd = json.loads(data) if data else {}
        segreti = dd.get("segreti") if isinstance(dd, dict) and cat == "leapp" else None
        mrows = None
        if fa.is_mobile(case):                  # smartphone (2.20): campi di iLEAPP/ALEAPP, conversazioni
            import forense_mobile_gui as fmg
            mrows = fmg.art_rows(G, case, dd, b.get("tz"))
        if mrows is not None:
            fonte = (fmg.leapp_src(case, dd.get("artefatto") or src, dd.get("campi")) if cat == "leapp" and inode is None
                     else src)
            rows = [(k, tr("Messaggi delle chat") if k == tr("Categoria") and cat == "messaggi" else
                     tr("{p} (percorso nell'estrazione)").format(p=fonte) if k == tr("Fonte") and fonte else
                     "" if k == tr("Fonte") else v)
                    for k, v in rows if k not in (tr("Dettagli"), tr("Utente"))] + [(k, v) for k, v in mrows if v not in (None, "", [])]
        else:
            # (3.0.4) i campi con data e ora sono in UTC: nel fuso scelto con la sigla, come la riga «Data»; quelli che
            # la fonte dà in ora locale (campo "ora": "locale") lo dichiarano e non vengono spostati
            locale = dd.get("ora") == "locale"

            def campo(x):
                x = str(x)
                if not G.TS_RE.fullmatch(x):
                    return x
                return x.replace("T", " ") + tr(" (ora locale, fuso non indicato)") if locale else fmt_ts(case, b.get("tz"), x)
            for k, v in dd.items():
                if v not in (None, "", []) and not (k == "ora" and locale):
                    rows.append((k.replace("_", " "), ", ".join(campo(x) for x in v) if isinstance(v, list) else campo(v)))
    except ValueError:
        pass
    return title, rows, segreti


def sqlite_view(f, copia=False):
    """Tabelle e prime righe. `copia` (2.20): f è una copia di lavoro con -wal/-journal accanto, da aprire normalmente
    (il file -wal entra nella lettura); senza, il file si apre immutabile e il -wal NON viene letto."""
    con = (sqlite3.connect(str(f)) if copia else
           sqlite3.connect(f"file:{Path(f).as_posix()}?mode=ro&immutable=1", uri=True))
    parts = []
    try:
        tabs = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")][:60]
        for t in tabs:
            try:
                n = con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                cur = con.execute(f'SELECT * FROM "{t}" LIMIT 300')
            except sqlite3.Error:
                continue
            cols = [c[0] for c in cur.description or []]
            body = []
            for row in cur:
                cells = []
                for v in row:
                    if isinstance(v, bytes):
                        s = f"[{len(v)} byte] " + v[:24].hex(" ")
                    else:
                        s = "" if v is None else str(v)
                    cells.append(f"<td>{html_mod.escape(s[:400])}</td>")
                body.append("<tr>" + "".join(cells) + "</tr>")
            parts.append(f"<h3>{html_mod.escape(t)} <small>({n} righe{', mostrate le prime 300' if n > 300 else ''})</small></h3>"
                         f"<div class='w'><table><tr>{''.join(f'<th>{html_mod.escape(c)}</th>' for c in cols)}</tr>{''.join(body)}</table></div>")
    finally:
        con.close()
    css = ("<style>body{font:12.5px/1.4 -apple-system,Segoe UI,sans-serif;margin:10px}h3{font-size:14px;margin:16px 0 6px}"
           "small{color:#777;font-weight:400}.w{overflow:auto;max-height:420px;border:1px solid #ddd}"
           "table{border-collapse:collapse;font-size:12px}td,th{border:1px solid #e3e3e3;padding:3px 6px;vertical-align:top;"
           "text-align:left;white-space:nowrap;max-width:420px;overflow:hidden;text-overflow:ellipsis}th{background:#f2f3f5;position:sticky;top:0}</style>")
    return CSP_DOC + css + ("".join(parts) or tr("<p>Nessuna tabella.</p>"))


def export_x(case, b):
    """Copia un file estratto (archivio, allegato, copia shadow) in export/ e lo mostra."""
    it = x_ident(case, b)
    if not it["file"]:
        raise ValueError(tr("Il file non è stato estratto: ") + (it["rec"].get("note") or ""))
    d = case.export_dir / "estratti"
    d.mkdir(parents=True, exist_ok=True)
    dest = d / f"x{it['id']}_{safe_part(it['name'] or 'file')}"
    if not dest.exists():
        shutil.copyfile(it["file"], dest)
        dest.chmod(0o444)
    case.log("export_estratto", {"id": it["id"], "origine": it["path"], "dest": str(dest), "sha256": it["rec"]["sha256"]})
    if b.get("reveal"):
        reveal(dest)
    return {"message": tr("Esportato in {dest} (SHA-256 {sha256})").format(dest=dest, sha256=it['rec']['sha256']), "path": str(dest)}


def x_targets(case, kind, rows):
    """File estratti (source x) presenti nelle righe selezionate: {id: (percorso, relpath)}."""
    ids = []
    for x in rows:
        if kind in ("arch", "vss"):
            ids.append(x["id"])
        elif kind in ("hits", "doc") and x.get("source") == "x":
            ids.append(int(x["inode"]))
        elif kind == "anom" and x.get("source") == "x":
            ids.append(int(x["inode"]))
        elif kind == "mail":
            pass
    if not ids:
        return {}
    con = fa.db_ro(case)
    try:
        return {i: (p, rel) for i, p, rel in con.execute(
            "SELECT id, path, relpath FROM xitems WHERE id IN (SELECT value FROM json_each(?))", (json.dumps(ids),))}
    finally:
        con.close()


def ext_ref_label(kind, x):
    if kind == "art":
        return (tr("artefatto «{title}» ({cat}, {v1}): {detail}").format(title=x['title'], cat=x['cat'], v1=(x['ts'] + ' UTC') if x['ts'] else tr('senza data'), detail=x['detail'])
                + (tr(" — fonte {p} (percorso nell'estrazione)").format(p=x['src_path']) if x.get("estrazione") and x.get("src_path") else
                   tr(" — fonte {p}").format(p=x['src_path']) if x.get("src_path") and x.get("inode") in (None, "") else
                   tr(" — fonte {src_path} (offset {part}, inode {inode})").format(src_path=x['src_path'], part=x['part'], inode=x['inode']) if x.get("src_path") else ""))
    if kind == "mail":
        return (tr("messaggio «{subject}» del {v1} da {sender} a {recipients} ({src_path} › {folder}, offset "
                   "{part}, inode {inode})").format(subject=x['subject'], v1=(x['date'] + ' UTC') if x['date'] else '?', sender=x['sender'], recipients=x['recipients'], src_path=x['src_path'], folder=x['folder'], part=x['part'], inode=x['inode']))
    if kind in ("arch", "vss"):
        return (tr("{path} ({size} byte").format(path=x['path'], size=x['size']) + (f", SHA-256 {x['sha256']}" if x.get("sha256") else "")
                + (tr(", protetto da password") if x.get("encrypted") else "") + (f"; {x['note']}" if x.get("note") else "")
                + (tr("; file di origine offset {part}, inode {inode}").format(part=x['part'], inode=x['inode']) if kind == "arch" else "") + ")")
    if kind == "anom":
        return tr("anomalia: {path} — {detail}").format(path=x['path'], detail=x['detail']) + (f" (offset {x['part']}, inode {x['inode']})" if x.get("part") is not None else "")
    return str(x)


EXT_CSV = {
    "art": [("cat", "categoria"), ("ts", "data_utc"), ("title", "elemento"), ("detail", "dettagli"), ("user", "utente"),
            ("src_path", "fonte"), ("part", "partizione_offset"), ("inode", "inode")],
    "mail": [("date", "data_utc"), ("sender", "mittente"), ("recipients", "destinatari"), ("cc", "cc"),
             ("subject", "oggetto"), ("n_att", "allegati"), ("fmt", "formato"), ("folder", "cartella"),
             ("src_path", "file_di_posta"), ("part", "partizione_offset"), ("inode", "inode")],
    "arch": [("path", "percorso"), ("kind", "tipo"), ("size", "byte"), ("mtime", "data_utc"), ("encrypted", "cifrato"),
             ("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256"), ("src_path", "file_di_origine"),
             ("part", "partizione_offset"), ("inode", "inode"), ("relpath", "copia_nel_caso"), ("note", "note")],
    "vss": [("path", "percorso"), ("store", "copia_shadow"), ("size", "byte"), ("mtime", "modifica_utc"), ("note", "stato"),
            ("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256"), ("relpath", "copia_nel_caso")],
    "anom": [("kind", "tipo"), ("path", "file"), ("detail", "dettaglio"), ("ext", "estensione"), ("real", "contenuto"),
             ("size", "byte"), ("deleted", "cancellato"), ("part", "partizione_offset"), ("inode", "inode")],
}


def x_search_items(case):
    con = fa.db_ro(case)
    try:
        if not fa.table_exists(con, "xitems"):
            return []
        return con.execute("SELECT id, path, name, relpath, size, mtime, md5, sha1, sha256 FROM xitems").fetchall()
    finally:
        con.close()


def raw_image_search(case, terms, match, cs, encs, progress, stop, cap=3000):
    """Cerca le parole nei byte grezzi di tutta la copia (spazio non allocato, slack, file
    cancellati sovrascritti, metadati): [(offset, termine, codifica, estratto)]."""
    brx = [(t, enc, rx) for t in terms for enc, rx in byte_regexes(t, match, cs, encs)]
    # caso più comune (contiene, senza distinguere maiuscole): ricerca diretta dei byte, molto più veloce
    fast = None
    if match == "contains" and all(t.isascii() for t in terms):
        fast = [(t, enc, (t if cs else t.lower()).encode("utf-16-le" if enc == "utf16" else "utf-8"))
                for t in terms for enc in encs]
    maxlen = max(len(t.encode("utf-16-le")) for t in terms) + 64
    it = image_ident(case)
    total = it["size"] or 0
    out, pos, tail, tlast = [], 0, b"", 0
    step = 16 << 20
    while not stop.is_set():
        chunk = image_read(case, pos, step)
        if not chunk:
            break
        buf = tail + chunk
        base = pos - len(tail)
        if fast:
            hay = buf if cs else buf.lower()
            for t, enc, needle in fast:
                i = hay.find(needle)
                while i != -1:
                    if i + len(needle) > len(tail):     # non già trovata nel blocco precedente
                        out.append((base + i, t, enc, byte_snippet(buf, i, i + len(needle), enc)))
                        if len(out) >= cap:
                            return out, True
                    i = hay.find(needle, i + 1)
        else:
            for t, enc, rx in brx:
                for m in rx.finditer(buf):
                    if m.end() <= len(tail):        # già trovata nel blocco precedente
                        continue
                    o = base + m.start()
                    out.append((o, t, enc, byte_snippet(buf, m.start(), m.end(), enc)))
                    if len(out) >= cap:
                        return out, True
        pos += len(chunk)
        tail = buf[-maxlen:]
        if time.time() - tlast > 0.5:
            tlast = time.time()
            progress(tr("Byte grezzi della copia: {v1:.2f} di {v2:.2f} GB · {v3} occorrenze").format(v1=pos / 1e9, v2=total / 1e9, v3=len(out)))
        if len(chunk) < step:
            break
    return out, False


def decrypt_task(root, b, progress):
    case = fa.Case(root)
    return fe_mod().decrypt_volume(case, int(b["offset"]), b.get("secret") or "", b.get("kind") or "password", progress)


def hashlist_add(b):
    fe = fe_mod()
    lists = fe.hash_lists()
    name = " ".join(str(b.get("nome") or "").split())[:80]
    tipo = "segnalati" if b.get("tipo") == "segnalati" else "noti"
    if b.get("testo"):
        found = sorted({m.decode().lower() for m in fe.HEX.findall(str(b["testo"]).encode())})
        if not found:
            raise ValueError(tr("Nessun hash valido nel testo incollato."))
        d = fa.CASES_HOME / "liste_hash"
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{safe_part(name or 'lista')}_{G.stamp_now()}.txt"
        path.write_text("\n".join(found) + "\n", encoding="utf-8")
    else:
        path = Path(clean_path(b.get("path") or ""))
        if not (path.is_file() or path.is_dir()):
            raise ValueError(tr("File o cartella della lista non trovato."))
    if not name:
        name = path.stem
    if any(x["nome"].lower() == name.lower() for x in lists):
        raise ValueError(tr("Esiste già una lista con questo nome."))
    if path.is_dir():               # cartella di immagini di riferimento: confronto per somiglianza (hash percettivi)
        n_img = sum(1 for x in path.rglob("*") if x.is_file() and x.suffix.lower() in fe.PHASH_IMG)
        if not n_img:
            raise ValueError(tr("La cartella non contiene immagini."))
        lists.append({"nome": name, "path": str(path), "tipo": tipo, "aggiunta": fa.now(), "cartella": True,
                      "immagini": n_img, "byte": 0})
    else:
        lists.append({"nome": name, "path": str(path), "tipo": tipo, "aggiunta": fa.now(),
                      "byte": path.stat().st_size})
    fe.save_hash_lists(lists)
    return {"liste": lists}


def term_regex(term, match, case_sens, target):
    """Espressione per confrontare un termine con nome, percorso o testo."""
    t = term if match == "regex" else re.escape(term)
    if match == "word" or (match in ("starts", "exact") and target == "text"):
        t = rf"(?<!\w){t}" + ("" if match == "starts" else r"(?!\w)")
    elif match == "starts":
        t = "^" + t
    elif match == "exact":
        t = f"^{t}$"
    try:
        return re.compile(t, 0 if case_sens else re.I)
    except re.error as e:
        raise ValueError(tr("Espressione regolare non valida «{term}»: {e}").format(term=term, e=e))


def byte_regexes(term, match, case_sens, encs):
    """Espressioni sui byte grezzi: UTF-8 e/o UTF-16LE (le stringhe di Windows)."""
    out, fl = [], 0 if case_sens else re.I
    for enc in encs:
        if match == "regex":
            if enc != "utf8":
                continue
            out.append((enc, re.compile(term.encode("utf-8"), fl)))
            continue
        raw = term.encode("utf-8" if enc == "utf8" else "utf-16-le")
        pat = re.escape(raw)
        if match in ("word", "exact") and enc == "utf8":
            pat = rb"(?<![A-Za-z0-9_])" + pat + rb"(?![A-Za-z0-9_])"
        elif match == "starts" and enc == "utf8":
            pat = rb"(?<![A-Za-z0-9_])" + pat
        out.append((enc, re.compile(pat, fl)))
    return out


def snippet(text, s, e, width=70):
    a, b = max(0, s - width), min(len(text), e + width)
    return ("…" if a else "") + " ".join(text[a:b].split()) + ("…" if b < len(text) else "")


def byte_snippet(buf, s, e, enc, width=48):
    a, b = max(0, s - width), min(len(buf), e + width)
    if enc == "utf16":
        a -= (a - s) % 2
        txt = buf[a:b].decode("utf-16-le", "replace")
    else:
        txt = buf[a:b].decode("utf-8", "replace")
    return " ".join("".join(c if c.isprintable() else "·" for c in txt).split())


def search_universe(case, f):
    """File della copia che rientrano nei filtri: (part, inode, path, name, deleted, size, mtime)."""
    con = nav_db(case)
    w, a = ["isdir = 0", "inode IS NOT NULL", "type NOT LIKE 'v/%'"], []
    if f.get("deleted") == "only":
        w.append("deleted >= 1")
    elif f.get("deleted") == "no":
        w.append("deleted = 0")
    exts = [e.strip().lower().lstrip(".*") for e in re.split(r"[,;\s]+", f.get("ext") or "") if e.strip()]
    if exts:
        w.append("(" + " OR ".join("lower(name) LIKE ?" for _ in exts) + ")")
        a += ["%." + e for e in exts]
    d = (f.get("dir") or "").strip().strip("/")
    if d:
        w.append("(lower(path) LIKE ? ESCAPE '\\' OR lower(path) LIKE ? ESCAPE '\\')")
        a += [fa.like(d.lower()).strip("%") + "/%", "%/" + fa.like(d.lower()).strip("%") + "/%"]
    if f.get("part") not in (None, ""):
        w.append("part = ?"); a.append(int(f["part"]))
    if f.get("size_min") not in (None, ""):
        w.append("size >= ?"); a.append(int(float(f["size_min"])))
    if f.get("size_max") not in (None, ""):
        w.append("size <= ?"); a.append(int(float(f["size_max"])))
    if f.get("date_from"):
        w.append("mtime >= ?"); a.append(f["date_from"])
    if f.get("date_to"):
        w.append("mtime <= ?"); a.append(f["date_to"] + "T23:59:59")
    try:
        return [r for r in con.execute(
            f"SELECT part, inode, path, name, deleted, size, mtime FROM nav WHERE {' AND '.join(w)} "
            "ORDER BY part, path", a)]
    finally:
        con.close()


def carved_universe(case, f):
    con = fa.db_ro(case)
    try:
        if not fa.table_exists(con, "carved"):
            return []
        rows = con.execute("SELECT name, relpath, size, sha256 FROM carved").fetchall()
    finally:
        con.close()
    exts = [e.strip().lower().lstrip(".*") for e in re.split(r"[,;\s]+", f.get("ext") or "") if e.strip()]
    out = []
    for name, rel, size, sha in rows:
        if exts and not any(name.lower().endswith("." + e) for e in exts):
            continue
        if f.get("size_min") not in (None, "") and size < int(float(f["size_min"])):
            continue
        if f.get("size_max") not in (None, "") and size > int(float(f["size_max"])):
            continue
        out.append((name, rel, size, sha))
    return out


def file_chunks(case, part, inode, ext):
    """Contenuto di un file: dalla cache se già estratto, altrimenti in streaming con icat."""
    p = fa.cache_base(case) / "file" / (f"p{part}_i{safe_key(inode)}" + safe_ext(ext))
    if p.exists():
        with open(p, "rb") as fh:
            while c := fh.read(1 << 20):
                yield c
    else:
        yield from fa.icat_stream(case, part, inode)


def local_chunks(p):
    with open(p, "rb") as fh:
        while c := fh.read(1 << 20):
            yield c


def run_search(case, b, progress):
    """Esegue una ricerca e ne salva gli esiti. Restituisce {sid, title, total}."""
    t0 = time.time()
    SEARCH_STOP.clear()
    mode = b.get("mode") or "kw"
    f = b.get("filters") or {}
    inc_carved = yes(f.get("carved")) and bool((case.meta.get("carving") or {}).get("photorec"))
    if not Path(case.image).exists() and (mode == "hash" or "raw" in (b.get("where") or [])):
        pass   # i file già in cache o con hash calcolato restano utilizzabili
    progress(tr("Preparo l'elenco dei file…"))
    ensure_nav(case)
    for _ in range(600):
        if NAV_STATE.get(str(case.root), {}).get("state") != "building":
            break
        time.sleep(0.5)
    uni = search_universe(case, f)
    carved = carved_universe(case, f) if inc_carved else []
    # file estratti da archivi, allegati e copie shadow (con gli stessi filtri di estensione e dimensione)
    xit = []
    if f.get("estratti", True) not in (False, "0", 0, "false"):
        exts_x = [e.strip().lower().lstrip(".*") for e in re.split(r"[,;\s]+", f.get("ext") or "") if e.strip()]
        for r in x_search_items(case):
            if exts_x and not any((r[2] or "").lower().endswith("." + e) for e in exts_x):
                continue
            if f.get("size_min") not in (None, "") and (r[4] or 0) < int(float(f["size_min"])):
                continue
            if f.get("size_max") not in (None, "") and (r[4] or 0) > int(float(f["size_max"])):
                continue
            xit.append(r)
    xinfo = lambda r: (None, str(r[0]), r[1], r[2], 0, r[4], r[5])
    H = {}
    known = {}
    try:
        cr = fa.db_ro(case)
        if fa.table_exists(cr, "hashes"):
            for p, i, md5, sha1, sha256 in cr.execute("SELECT part, inode, md5, sha1, sha256 FROM hashes"):
                known[(p, i)] = (md5, sha1, sha256)
        cr.close()
    except sqlite3.Error:
        pass

    def hit(key, info, where, term, detail):
        h = H.get(key)
        if not h:
            h = H[key] = {"info": info, "wheres": [], "terms": [], "details": []}
        if where not in h["wheres"]:
            h["wheres"].append(where)
        if term not in h["terms"]:
            h["terms"].append(term)
        if detail and len(h["details"]) < 6:
            h["details"].append(detail)

    stopped = False
    note = {}
    if mode == "hash":
        wanted = {t.lower() for t in HASH_TOKEN.findall(b.get("hashes") or "")}
        if not wanted:
            raise ValueError(tr("Nessun hash valido: servono MD5 (32), SHA-1 (40) o SHA-256 (64) "
                             "caratteri esadecimali."))
        compute = (b.get("hash_compute") or "missing") == "missing"
        missing = [r for r in uni if (r[0], r[1]) not in known]
        if missing and compute and not Path(case.image).exists():
            raise ValueError(tr("Per calcolare gli hash mancanti serve la copia forense: collega il disco."))
        wcon = None
        if missing and compute:
            wcon = sqlite3.connect(case.db_path, timeout=60)
            wcon.executescript(fa.HASH_SCHEMA)
        batch, nbytes, tlast = [], 0, 0
        todo = missing if compute else []
        for k, (part, inode, path, name, deleted, size, mtime) in enumerate(todo, 1):
            if SEARCH_STOP.is_set():
                stopped = True
                break
            try:
                n, md5, sha1, sha256 = fa.hash_stream(file_chunks(case, part, inode, Path(name).suffix))
            except Exception:
                continue
            nbytes += n
            known[(part, inode)] = (md5, sha1, sha256)
            batch.append((part, inode, path, deleted, n, md5, sha1, sha256, fa.now()))
            if time.time() - tlast > 0.5:
                tlast = time.time()
                progress(tr("Calcolo gli hash mancanti: {k} di {v1} file · {v2:.0f} MB").format(k=k, v1=len(todo), v2=nbytes / 1e6))
            if len(batch) >= 200:
                wcon.executemany("INSERT OR REPLACE INTO hashes VALUES (?,?,?,?,?,?,?,?,?)", batch)
                wcon.commit()
                batch.clear()
        if wcon:
            wcon.executemany("INSERT OR REPLACE INTO hashes VALUES (?,?,?,?,?,?,?,?,?)", batch)
            wcon.commit()
            wcon.close()
            case.log("hash_file_al_volo", {"file": len(todo)})
        progress(tr("Confronto gli hash…"))
        found = set()
        for part, inode, path, name, deleted, size, mtime in uni:
            hs = known.get((part, inode))
            if not hs:
                continue
            for label, v in zip(("MD5", "SHA-1", "SHA-256"), hs):
                if v and v in wanted:
                    found.add(v)
                    hit(("fs", part, inode, path), (part, inode, path, name, deleted, size, mtime, hs),
                        "hash", v, f"{label} {v}")
        for name, rel, size, sha in carved:
            hs = (None, None, sha)
            if wanted - {sha}:
                if any(len(x) in (32, 40) for x in wanted):
                    try:
                        _, md5, sha1, _s = fa.hash_stream(open(case.root / rel, "rb"))
                        hs = (md5, sha1, sha)
                    except OSError:
                        pass
            for label, v in zip(("MD5", "SHA-1", "SHA-256"), hs):
                if v and v in wanted:
                    found.add(v)
                    hit(("carving", None, name, name), (None, name, name, name, 0, size, None, hs),
                        "hash", v, tr("{label} {v1} (file recuperato)").format(label=label, v1=v))
        for r in xit:
            for label, v in zip(("MD5", "SHA-1", "SHA-256"), r[6:9]):
                if v and v in wanted:
                    found.add(v)
                    hit(("x", None, str(r[0]), r[1]), (*xinfo(r), r[6:9]), "hash", v, tr("{label} {v1} (file estratto)").format(label=label, v1=v))
        note = {"cercati": len(wanted), "trovati": len(found),
                "non_trovati": sorted(wanted - found)[:2000],
                "senza_hash": 0 if compute else len(missing)}
        terms_all = sorted(wanted)
    else:
        terms = [t.strip() for t in (b.get("terms") or "").splitlines() if t.strip()]
        if not terms:
            raise ValueError(tr("Scrivi almeno una parola da cercare."))
        where = [w for w in (b.get("where") or []) if w in WHERE_LABEL and w != "hash"]
        if not where:
            raise ValueError(tr("Scegli dove cercare."))
        match, cs = b.get("match") or "contains", yes(b.get("case"))
        terms_all = terms
        allowed = {(r[0], r[1]) for r in uni}
        # nome e percorso
        if "name" in where or "path" in where:
            progress(tr("Cerco nei nomi dei file…"))
            rx_n = [(t, term_regex(t, match, cs, "name")) for t in terms]
            rx_p = [(t, term_regex(t, match, cs, "path")) for t in terms]
            for r in uni:
                part, inode, path, name = r[:4]
                for t, rx in rx_n:
                    if "name" in where and rx.search(name):
                        hit(("fs", part, inode, path), r, "name", t, None)
                for t, rx in rx_p:
                    if "path" in where and rx.search(path):
                        hit(("fs", part, inode, path), r, "path", t, None)
            for name, rel, size, sha in carved:
                for t, rx in rx_n:
                    if rx.search(name):
                        hit(("carving", None, name, name), (None, name, name, name, 0, size, None),
                            "name", t, None)
            for r in xit:
                for t, rx in rx_n:
                    if "name" in where and rx.search(r[2] or ""):
                        hit(("x", None, str(r[0]), r[1]), xinfo(r), "name", t, None)
                for t, rx in rx_p:
                    if "path" in where and rx.search(r[1] or ""):
                        hit(("x", None, str(r[0]), r[1]), xinfo(r), "path", t, None)
        rinfo = {(r[0], r[1]): r for r in uni}
        # testo dei documenti e metadati indicizzati
        for wkey, table, col in (("doc", "doc_text", "body"), ("doc", "doc_text_extra", "body"),
                                 ("meta", "meta", "data")):
            if wkey not in where or SEARCH_STOP.is_set():
                continue
            con = fa.db_ro(case)
            try:
                if not fa.table_exists(con, table):
                    continue
                progress(tr("Cerco nel testo dei documenti…") if wkey == "doc" else tr("Cerco nei metadati…"))
                rxs = [(t, term_regex(t, match, cs, "text")) for t in terms]
                cond, args = "", []
                if match in ("contains", "word", "starts", "exact"):
                    cond = " WHERE " + " OR ".join(f"{col} LIKE ? ESCAPE '\\'" for _ in terms)
                    args = [fa.like(t) for t in terms]
                for src, part, inode, deleted, path, body in con.execute(
                        f"SELECT source, part, inode, deleted, path, {col} FROM {table}{cond}", args):
                    if SEARCH_STOP.is_set():
                        stopped = True
                        break
                    body = body or ""
                    if src == "x":
                        key, info = ("x", None, str(inode), path), (None, str(inode), path, Path(str(path)).name.split(" › ")[-1], 0, None, None)
                    elif src == "posta":
                        key, info = ("mail", None, str(inode), path), (None, str(inode), path, path.split(" › ")[-1], 0, None, None)
                    elif src == "carving":
                        if not inc_carved:
                            continue
                        name = Path(str(inode)).name
                        key, info = ("carving", None, name, name), (None, name, name, name, 0, None, None)
                    else:
                        r = rinfo.get((part, str(inode)))
                        if r is None:
                            continue
                        key, info = ("fs", part, r[1], r[2]), r
                    for t, rx in rxs:
                        m = rx.search(body)
                        if m:
                            hit(key, info, wkey, t, f"{tr(WHERE_LABEL[wkey])}: {snippet(body, m.start(), m.end())}")
            finally:
                con.close()
        # contenuto grezzo, byte per byte
        if "raw" in where and not SEARCH_STOP.is_set():
            encs = [e for e in (b.get("enc") or ["utf8", "utf16"]) if e in ("utf8", "utf16")] or ["utf8"]
            brx = [(t, enc, rx) for t in terms for enc, rx in byte_regexes(t, match, cs, encs)]
            maxlen = max(len(t.encode("utf-16-le")) for t in terms) + 64
            items = [("fs", r) for r in uni] + [("carving", c) for c in carved] + \
                [("x", r) for r in xit if r[3]]
            if any(s == "fs" for s, _ in items) and not Path(case.image).exists():
                note["avviso"] = tr("Copia forense non collegata: contenuto cercato solo nei file in cache.")
            total_b, done_b, tlast = sum((x[5] if s == "fs" else x[4] if s == "x" else x[2]) or 0 for s, x in items), 0, 0
            for k, (src, x) in enumerate(items, 1):
                if SEARCH_STOP.is_set():
                    stopped = True
                    break
                if src == "fs":
                    part, inode, path, name = x[:4]
                    key, info = ("fs", part, inode, path), x
                    if not Path(case.image).exists() and not (fa.cache_base(case) / "file" / (
                            f"p{part}_i{safe_key(inode)}" + safe_ext(Path(name).suffix))).exists():
                        continue
                    gen = file_chunks(case, part, inode, Path(name).suffix)
                elif src == "x":
                    key, info = ("x", None, str(x[0]), x[1]), xinfo(x)
                    gen = local_chunks(case.root / x[3])
                else:
                    name, rel, size, sha = x
                    key, info = ("carving", None, name, name), (None, name, name, name, 0, size, None)
                    gen = local_chunks(case.root / rel)
                seen, tail, pos = set(), b"", 0
                try:
                    for chunk in gen:
                        buf = tail + chunk
                        base = pos - len(tail)
                        for t, enc, rx in brx:
                            if (t, enc) in seen:
                                continue
                            m = rx.search(buf)
                            if m:
                                seen.add((t, enc))
                                hit(key, info, "raw", t, tr("contenuto{v1} all'offset {v2}: {v3}").format(v1=' UTF-16' if enc == 'utf16' else '', v2=base + m.start(), v3=byte_snippet(buf, m.start(), m.end(), enc)))
                        pos += len(chunk)
                        done_b += len(chunk)
                        tail = buf[-maxlen:]
                        if len(seen) == len(brx) or SEARCH_STOP.is_set():
                            break
                        if time.time() - tlast > 0.5:
                            tlast = time.time()
                            progress(tr("Contenuto dei file: {k} di {v1} · {v2:.0f} di {v3:.0f} MB").format(k=k, v1=len(items), v2=done_b / 1e6, v3=total_b / 1e6))
                finally:
                    if hasattr(gen, "close"):
                        gen.close()
        # byte grezzi di tutta la copia: spazio non allocato, slack, file sovrascritti
        if "img" in where and not SEARCH_STOP.is_set():
            if not Path(case.image).exists():
                note["avviso"] = tr("Copia forense non collegata: ricerca nei byte grezzi non eseguita.")
            else:
                encs = [e for e in (b.get("enc") or ["utf8", "utf16"]) if e in ("utf8", "utf16")] or ["utf8"]
                occ, more = raw_image_search(case, terms, match, cs, encs, progress, SEARCH_STOP)
                stopped = stopped or SEARCH_STOP.is_set()
                for off, t, enc, snip in occ:
                    lab = tr("Copia forense · byte {off:,}").format(off=off).replace(",", ".")
                    hit(("image", None, str(off), lab), (None, str(off), lab, f"byte {off}", 0, None, None),
                        "img", t, f"{'UTF-16 ' if enc == 'utf16' else ''}{snip}")
                if more:
                    note["avviso"] = tr("Molte occorrenze nei byte grezzi: mostrate le prime 3.000.")
        if b.get("combine") == "all" and len(terms) > 1:
            H = {k: v for k, v in H.items() if len(v["terms"]) == len(terms)}
    # file il cui testo non è nell'indice (o solo in parte): la ricerca nel testo non li copre per intero
    try:
        con_n = fa.db_ro(case)
        try:
            if fa.table_exists(con_n, "doc_skipped") and "doc" in (b.get("where") or []):
                nn = con_n.execute("SELECT COUNT(*) FROM doc_skipped").fetchone()[0]
                if nn:
                    note["non_indicizzati"] = nn
        finally:
            con_n.close()
    except Exception:
        pass
    # salvataggio
    progress(tr("Salvo i risultati…"))
    title = (b.get("title") or "").strip() or (
        (tr("Hash: 1 valore") if len(terms_all) == 1 else tr("Hash: {v1} valori").format(v1=len(terms_all))) if mode == "hash"
        else tr("Parole: ") + ", ".join(terms_all[:4]) + ("…" if len(terms_all) > 4 else ""))
    if stopped:
        title += tr(" (interrotta)")
    con = search_db(case)
    try:
        cur = con.execute("INSERT INTO searches(title, created, params, total, elapsed, note) "
                          "VALUES (?,?,?,?,?,?)", (title, fa.now(), json.dumps(b, ensure_ascii=False),
                                                    len(H), round(time.time() - t0, 1),
                                                    json.dumps(note, ensure_ascii=False)))
        sid = cur.lastrowid
        rows = []
        for (src, part, inode, path), h in sorted(H.items(), key=lambda kv: str(kv[0][3]).lower()):
            info = h["info"]
            hs = info[7] if len(info) > 7 else (known.get((part, inode)) if src == "fs" else None)
            hs = hs or (None, None, None)
            rows.append((sid, src, part, str(inode), path, info[3], info[4], info[5], info[6],
                         ", ".join(tr(WHERE_LABEL[w]) for w in h["wheres"]), "; ".join(h["terms"]),
                         " · ".join(h["details"])[:900], *hs))
        con.executemany("INSERT INTO hits(sid, source, part, inode, path, name, deleted, size, mtime, "
                        "wheres, terms, detail, md5, sha1, sha256) VALUES "
                        "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        con.commit()
    finally:
        con.close()
    case.log("ricerca", {"sid": sid, "titolo": title, "parametri": b, "risultati": len(H),
                         "interrotta": stopped})
    return {"sid": sid, "title": title, "total": len(H), "stopped": stopped, "note": note}


def hits_list(case, q, ids=None, limit=PAGE):
    con = search_db(case)
    off = int(q.get("offset", 0))
    w, a = ["sid = ?"], [int(q.get("sid") or 0)]
    if ids is not None:
        w.append("id IN (SELECT value FROM json_each(?))")
        a.append(json.dumps([int(x) for x in ids if str(x).isdigit()]))
    text = (q.get("q") or "").strip()
    if text:
        w.append("(path LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\')"); a += [fa.like(text)] * 2
    if q.get("hwhere"):
        w.append("wheres LIKE ?"); a.append("%" + q["hwhere"] + "%")
    if (q.get("term") or "").strip():
        w.append("terms LIKE ? ESCAPE '\\'"); a.append(fa.like(q["term"].strip()))
    if yes(q.get("deleted")):
        w.append("deleted >= 1")
    cf_apply(q, cf_hits(), w, a)
    cond = " WHERE " + " AND ".join(w)
    try:
        if q.get("cfv"):
            cf_values(con, q, "hits", w, a)
        total = con.execute(f"SELECT COUNT(*) FROM hits{cond}", a).fetchone()[0]
        lim = f" LIMIT {int(limit)} OFFSET {off}" if limit else ""
        rows = con.execute(f"SELECT {', '.join(HIT_COLS)} FROM hits{cond} ORDER BY {cf_order(q, 'path COLLATE NOCASE')}{lim}",
                           a).fetchall()
    finally:
        con.close()
    return {"kind": "hits", "total": total, "offset": off, "page": PAGE,
            "rows": [dict(zip(HIT_COLS, r)) for r in rows]}


def _occupato(e):
    """(3.0.1) Errore di SQLite perché un'analisi sta scrivendo nel caso: passa da solo, si riprova."""
    return isinstance(e, sqlite3.OperationalError) and ("locked" in str(e) or "busy" in str(e))


def fast_search(case, q):
    """(2.20) Ricerca veloce nei risultati del caso (forense_ricerca_veloce): stato dell'indice o risultati raggruppati.
    (3.0.1) Se il caso è occupato da un'analisi che sta scrivendo, «occupato» (l'interfaccia riprova da sola)."""
    try:
        return _fast_search(case, q)
    except sqlite3.OperationalError as e:
        if _occupato(e):
            return {"stato": "occupato"}
        raise


def _fast_search(case, q):
    import forense_ricerca_veloce as rv
    con = fa.db_ro(case)
    con.execute("PRAGMA busy_timeout = 3000")     # caso occupato: l'avviso compare subito e l'interfaccia riprova
    try:
        if not rv.aggiornato(case, con):
            st = rv.stato(case)
            if not st or "fine" in st:
                if st and st.get("errore") and ("locked" in st["errore"] or "busy" in st["errore"]) and not q.get("riprova"):
                    if time.time() - st.get("fine", 0) < 5:           # indice fallito perché il caso era occupato: si riprova da soli
                        return {"stato": "occupato"}
                    st = rv.avvia(case, fa.db_ro)
                    return {"stato": "costruzione", "fatte": 0, "totale": 0, "secondi": 0}
                if st and st.get("errore") and not q.get("riprova"):
                    return {"stato": "errore", "errore": st["errore"]}
                st = rv.avvia(case, fa.db_ro)
            return {"stato": "costruzione", "fatte": st.get("fatte", 0), "totale": st.get("totale", 0),
                    "secondi": round(time.time() - st.get("inizio", time.time()))}
        testo = (q.get("q") or "").strip()
        if not testo:
            return {"stato": "pronto"}
        lbl = {}
        if fa.is_mobile(case):
            import forense_mobile_chat as fmc
            lbl = {k: tr(v) for k, v in fmc.APP_LBL.items()}
        t0 = time.time()
        r = rv.risultati(case, con, testo, lbl)
        nav = None
        try:
            nav = nav_db(case)
        except ValueError:
            pass
        try:
            gr, non = rv.altri(con, nav, testo)
        finally:
            if nav:
                nav.close()
        r["gruppi"] += gr                       # (3.0) un solo punto di ricerca: file, documenti, metadati, recuperati, tracce
        r["totale"] += sum(g["n"] for g in gr)
        r["mostrati"] += sum(len(g["righe"]) for g in gr)
        r["non_cercato"] = [tr(x) for x in non]
        if not fa.table_exists(con, "doc_text") or not con.execute("SELECT 1 FROM doc_text LIMIT 1").fetchone():
            r["non_cercato"].append(tr("testo dei documenti (indicizzazione non eseguita o nessun documento)"))
        rub = [x for g in r["gruppi"] if g["chiave"] == "rub" for x in g["righe"]]
        if rub and fa.is_mobile(case):          # database della rubrica nell'estrazione (per «Fonte» nell'anteprima)
            import forense_mobile as fm
            m = fm.mx(case)
            try:
                for x in rub:
                    y = m.execute("SELECT id, part FROM mobile_files WHERE path=? AND isdir=0", (x["dove"],)).fetchone() \
                        if x.get("dove") else None
                    if y:
                        x["inode"], x["part"] = str(y[0]), y[1]
            finally:
                m.close()
        r.update(stato="pronto", q=testo, ms=round((time.time() - t0) * 1000))
        return r
    finally:
        con.close()


def fast_search_gruppo(case, con, testo, chiave):
    """(3.0) Le righe di un gruppo della ricerca veloce, nel formato dei risultati salvati: (righe, totale, titolo del gruppo)."""
    import forense_ricerca_veloce as rv
    lbl = {}
    if fa.is_mobile(case):
        import forense_mobile_chat as fmc
        lbl = {k: tr(v) for k, v in fmc.APP_LBL.items()}
    gruppi = rv.risultati(case, con, testo, lbl, rv.MAX_SALVA)["gruppi"]
    if not any(g["chiave"] == chiave for g in gruppi):
        nav = None
        try:
            nav = nav_db(case)
        except ValueError:
            pass
        try:
            gruppi += rv.altri(con, nav, testo, rv.MAX_SALVA)[0]
        finally:
            if nav:
                nav.close()
    g = next((x for x in gruppi if x["chiave"] == chiave), None)
    if not g:
        raise ValueError(tr("Gruppo non trovato: ripeti la ricerca."))
    rows = []
    for x in g["righe"]:
        f, ts = x["fonte"], x.get("ts")
        if f == "art":
            rows.append(("art", None, str(x["id"]), f"[{x.get('cat') or ''}] {x['titolo']}", x["titolo"], 0, None, ts))
        elif f == "msg" and fa.is_mobile(case):
            import forense_mobile_gui as fmg
            r = fmg.msg_item(con, int(x["id"]))
            if r:
                rows.append(("chat", None, str(x["id"]), r[0], r[1], 0, None, r[2]))
        elif f == "mail":
            rows.append(("mail", None, str(x["id"]), f"✉ {x['titolo']} — {x.get('estratto') or ''}", x["titolo"], 0, None, ts))
        elif f == "rub":
            rows.append(("rub", None, str(x["id"]), " · ".join(v for v in (x["titolo"], x.get("estratto")) if v), x["titolo"], 0, None, None))
        elif f == "thr":
            rows.append(("thr", None, str(x["id"]), x["titolo"], x["titolo"], 0, None, ts))
        elif f in ("fs", "doc") and (x.get("source") or "fs") == "fs":
            p = x.get("estratto") if f == "fs" else x["titolo"]
            rows.append(("fs", x["part"], str(x["inode"]), p, (p or "").rsplit("/", 1)[-1], x.get("deleted") or 0, None, ts))
        elif f == "x":
            rows.append(("x", None, str(x["id"]), x.get("estratto") or x.get("name"), x.get("name"), 0, None, ts))
        elif f == "carving":
            rows.append(("carving", None, x["name"], f"[recuperato] {x['name']}", x["name"], 0, None, None))
    return rows, len(rows), g["titolo"]


def fast_search_save(case, b):
    """(2.20) Salva una ricerca veloce come ricerca del caso (scheda e voce «🔎 Ricerca», Preferiti, CSV)."""
    import forense_ricerca_veloce as rv
    testo = (b.get("q") or "").strip()
    gruppo = str(b.get("gruppo") or "")
    con = fa.db_ro(case)
    try:
        if not rv.aggiornato(case, con):
            raise ValueError(tr("L'indice della ricerca veloce non è pronto."))
        if gruppo:          # (3.0) un solo gruppo dei risultati (es. Rubriche) in una scheda propria
            rows, tot, titolo_g = fast_search_gruppo(case, con, testo, gruppo)
            b = {**b, "title": (b.get("title") or "").strip() or f"{titolo_g}: {testo}"}
            ids = []
        else:
            ids, tot, extra = rv.cerca_id(case, testo, rv.MAX_SALVA)
            rows = []
        for fonte, rid, _tx in ids:
            rid = int(rid)
            if fonte == "art":
                r = con.execute("SELECT title, cat, ts FROM artifacts WHERE id=?", (rid,)).fetchone()
                if r:
                    rows.append(("art", None, str(rid), f"[{r[1]}] {r[0]}", r[0], 0, None, r[2]))
            elif fonte == "msg" and fa.is_mobile(case):
                import forense_mobile_gui as fmg
                r = fmg.msg_item(con, rid)
                if r:
                    rows.append(("chat", None, str(rid), r[0], r[1], 0, None, r[2]))
            elif fonte == "mail":
                r = con.execute("SELECT subject, sender, date FROM mail WHERE id=?", (rid,)).fetchone()
                if r:
                    rows.append(("mail", None, str(rid), f"✉ {r[0]} — {r[1]}", r[0], 0, None, r[2]))
        nav = None
        try:
            nav = nav_db(case) if not gruppo else None
        except ValueError:
            pass
        try:
            gr, _non = rv.altri(con, nav, testo, rv.MAX_SALVA) if not gruppo else ([], [])   # (3.0) i file e i documenti trovati, una volta sola
        finally:
            if nav:
                nav.close()
        visti = set()
        for g in gr:
            tot += g["n"]
            for x in g["righe"]:
                if x["fonte"] in ("fs", "doc") and (x.get("source") or "fs") == "fs" and (x["part"], x["inode"]) not in visti:
                    visti.add((x["part"], x["inode"]))
                    p = x.get("estratto") if x["fonte"] == "fs" else x["titolo"]
                    rows.append(("fs", x["part"], str(x["inode"]), p, (p or "").rsplit("/", 1)[-1], x.get("deleted") or 0, None, x.get("ts")))
    finally:
        con.close()
    title = (b.get("title") or "").strip() or tr("Risultati: ") + testo
    params = {"mode": "veloce", "terms": testo, "where": ["veloce"], **({"gruppo": gruppo} if gruppo else {})}
    note = {"non_salvati": tot - len(rows)} if tot > len(rows) else {}
    sc = search_db(case)
    try:
        sid = sc.execute("INSERT INTO searches(title, created, params, total, elapsed, note) VALUES (?,?,?,?,?,?)",
                         (title, fa.now(), json.dumps(params, ensure_ascii=False), len(rows), 0,
                          json.dumps(note, ensure_ascii=False))).lastrowid
        sc.executemany("INSERT INTO hits(sid, source, part, inode, path, name, deleted, size, mtime, wheres, terms, detail) "
                       "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                       [(sid, *r, tr("risultati del caso"), testo, "") for r in rows])
        sc.commit()
    finally:
        sc.close()
    case.log("ricerca", {"sid": sid, "titolo": title, "parametri": params, "risultati": len(rows)})
    return {"sid": sid, "title": title, "total": len(rows)}


def search_list(case):
    if not (case.root / "ricerche.sqlite").exists():
        return []
    con = search_db(case)
    try:
        return [{"sid": s, "title": t, "created": c, "total": n, "elapsed": e,
                 "note": json.loads(nt or "{}"), "params": json.loads(p or "{}")}
                for s, t, c, p, n, e, nt in con.execute(
                    "SELECT sid, title, created, params, total, elapsed, note FROM searches "
                    "ORDER BY sid DESC")]
    finally:
        con.close()


def search_delete(case, sid):
    con = search_db(case)
    try:
        con.execute("DELETE FROM hits WHERE sid=?", (int(sid),))
        con.execute("DELETE FROM searches WHERE sid=?", (int(sid),))
        con.commit()
    finally:
        con.close()
    case.log("ricerca_eliminata", {"sid": int(sid)})


def summary_cached(case, what):
    """Riepilogo del caso all'apertura: fa.summary_md legge tutto il database (sul caso iOS 17 grande 3–7 s a ogni
    apertura); si tiene nella cache del caso finché case.json, i database e le impostazioni non cambiano."""
    # (dopo la 3.0.2) di case.json conta il contenuto, non la data: con il server LLM collegato ogni apertura lo riscrive
    # (modello e server) e il riepilogo salvato non valeva mai
    sig = [what, lg.lingua(), 4, meta_firma(case)]
    for f in [fa.SETTINGS_PATH, *sorted(case.root.glob("*.sqlite*"))]:
        try:
            st = os.stat(lp(f))
            sig.append([f.name, st.st_mtime_ns, st.st_size])
        except OSError:
            sig.append([f.name, None])
    path = fa.cache_base(case) / "riepilogo_apertura.json"
    try:
        with open(lp(path), encoding="utf-8") as fh:
            c = json.load(fh)
        if c.get("sig") == sig:
            return c["text"], c["questions"]
    except (OSError, ValueError, KeyError):
        pass
    text, questions = fa.summary_md(case, what)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with open(lp(tmp), "w", encoding="utf-8") as fh:
            json.dump({"sig": sig, "text": text, "questions": questions}, fh, ensure_ascii=False)
        os.replace(lp(tmp), lp(path))
    except OSError:
        pass
    return text, questions


def diag_testo():
    """(2.21) Log diagnostico da consegnare: nessun dato dei casi (forense_diagnostica)."""
    st = {k: (fa.tool_version([k, o]) if shutil.which(k) else None) or tr("non trovato")
          for k, o in (("fls", "-V"), ("ewfinfo", "-V"), ("exiftool", "-ver"))}
    return fd.testo(fa.APP_VERSION, st)


def senza_caso():
    """(3.0) Ogni scaricamento passa da qui: nessun accesso alla rete con un caso aperto o in preparazione."""
    if SES.case or PREP.running:
        raise ValueError(tr("Con un caso aperto non si va in rete: chiudi il caso e riprova dalla pagina iniziale."))


def aggiornamenti_stato():
    """(3.0.1) Impostazione e ultimo esito del controllo delle versioni (nessuna richiesta in rete)."""
    import forense_aggiornamenti as fag
    a = fag.stato(fa._raw_settings(), fa.APP_VERSION)
    return {"modo": a["modo"], "chiesto": bool(a.get("chiesto")), "ultimo": a.get("ultimo"), "saltata": a.get("saltata"),
            "mostra": fag.da_mostrare(a), "attuale": fa.APP_VERSION, "pagina": fag.PAGINA,
            "pacchetto": fag.pacchetto_sistema()}


def aggiornamenti_post(b):
    """(3.0.1) azione «modo» (mano|avvio|mai), «controlla» (auto: solo in modo avvio, una volta al giorno; mai con un caso
    aperto), «salta» (non avvisare più per quella versione), «rimanda» (non mostrare l'avviso per un giorno)."""
    import datetime as dt
    import forense_aggiornamenti as fag
    st = fa._raw_settings()
    a = fag.stato(st, fa.APP_VERSION)
    az = b.get("azione")
    if az == "modo":
        if b.get("modo") not in fag.MODI:
            raise ValueError(tr("Scelta non valida."))
        a["modo"], a["chiesto"] = b["modo"], True
    elif az == "controlla":
        if a["modo"] == "mai":
            if b.get("auto"):
                return aggiornamenti_stato()
            raise ValueError(tr("Il controllo degli aggiornamenti è disattivato: cambia la scelta per usarlo."))
        if b.get("auto") and not fag.da_controllare_all_avvio(a, versione_app=fa.APP_VERSION):
            return aggiornamenti_stato()
        senza_caso()
        a["ultimo"] = fag.controlla(fa.APP_VERSION)
        fd.evento("aggiornamenti", esito=a["ultimo"].get("esito"), versione=a["ultimo"].get("versione"),
                  motivo=a["ultimo"].get("motivo"))
    elif az == "salta":
        a["saltata"] = str(b.get("versione") or "")[:20]
    elif az == "rimanda":
        a["rimanda_fino"] = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).replace(microsecond=0).isoformat()
    else:
        raise ValueError(tr("Azione sconosciuta."))
    st = fa._raw_settings()
    st["aggiornamenti"] = a
    fa.save_settings(st)
    return aggiornamenti_stato()


def run_task(name, fn, with_progress=False):
    """Operazione lunga in background; lo stato si legge con /api/task?name=..."""
    if SES.tasks.get(name, {}).get("done") is False:
        raise ValueError(tr("Operazione già in corso: attendi che finisca."))
    SES.tasks[name] = {"done": False, "progress": ""}
    lingua = lg.lingua()        # quella della richiesta: del caso per report ed esportazioni, dell'interfaccia per il resto

    def progress(msg):
        SES.tasks[name]["progress"] = msg

    def wrap():
        try:
            with lg.usa(lingua):
                res = fn(progress) if with_progress else fn()
            SES.tasks[name] = {"done": True, "result": res}
        except Exception as e:
            SES.tasks[name] = {"done": True, "error": str(e)}
            fd.errore("task " + name, e)
    threading.Thread(target=wrap, daemon=True).start()
