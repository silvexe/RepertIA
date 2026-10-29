# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - interfaccia dei casi smartphone (dalla 2.20): richieste /api/mobile/* del server di forense_gui.py
e dati aggiuntivi del riepilogo del caso. La pagina è forense_mobile.html, inserita dal server in forense_gui.html."""
import json
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from forense_lingua import tr, N_  # noqa: E402
import forense_mobile_wa as fmw  # noqa: E402
import forense_mobile_ricevute as fmr  # noqa: E402

HERE = Path(__file__).resolve().parent
PAGE = 200


def fragment():
    """Il frammento HTML/JS della parte smartphone, se c'è (in un pacchetto «solo dischi» manca)."""
    f = HERE / "forense_mobile.html"
    return f.read_text(encoding="utf-8") if f.exists() else ""


def summary(case):
    """Campi del riepilogo del caso (case_summary) per i casi smartphone."""
    import forense_mobile_leapp as fml
    m = case.meta
    import forense_mobile_portachiavi as fmk
    import forense_mobile_sysdiagnose as fms
    out = {"tipo_caso": m.get("tipo_caso"), "mobile": m.get("mobile"), "chat": m.get("chat"), "leapp": m.get("leapp"),
           "decompressa": m.get("decompressa"), "portachiavi": m.get("portachiavi"),
           "portachiavi_testo": fmk.testo_esito((m.get("leapp") or {}).get("portachiavi")),
           "sysdiagnose": fms.summary(case),
           "leapp_disponibile": bool(fml.tool_dir((m.get("mobile") or {}).get("piattaforma") or "ios")
                                     if (m.get("mobile") or {}).get("piattaforma") in fml.TOOLS else None)}
    return out


def _case(G):
    if not G.SES.case:
        raise ValueError(tr("Nessun caso aperto."))
    return G.SES.case


def _con(case):
    import forense_agent as fa
    return fa.db_ro(case)


def check(path, dest=None):
    """Estrazione scelta: formato, dimensione, caso esistente, spazio per l'eventuale copia decompressa."""
    import forense_agent as fa
    import forense_mobile as fm
    p = Path(path or "").expanduser()
    if not str(path or "").strip() or not p.exists():
        return {"ok": False, "error": tr("File o cartella non trovati. Controlla che il disco sia collegato.")}
    kind = fm.formato(p)
    if kind is None:
        return {"ok": False, "error": tr("Formato non riconosciuto: scegli lo zip o il tar dell'estrazione del file "
                                        "system (anche .tar.gz), oppure la cartella già estratta. Per un'acquisizione "
                                        "UFDR o XRY vedi il manuale.")}
    root, exists = fa.case_for_image(p, dest or None)
    size = p.stat().st_size if p.is_file() else None
    return {"ok": True, "path": str(p.resolve()), "formato": kind, "size": size, "case_root": str(root),
            "case_exists": exists, "free": fa.free_bytes(dest or fa.CASES_HOME), "decomprimere": kind == "targz"}


def start(G, root, args, add=None):
    """Avvia forense_mobile.py come sottoprocesso con la stessa macchina di Prep (registro a video, interruzione)."""
    import os
    import threading
    P = G.PREP
    cmd = [sys.executable, "-u", str(HERE / "forense_mobile.py"), *args]
    P.lines, P.root, P.rc, P.ask, P.next_image = [], root, None, None, None
    P.add = add or "all"
    t = time.time()
    P.av = {"t0": t, "t_out": t}         # (2.20) barra di avanzamento: tempi da zero
    env = dict(os.environ, FORENSE_DA_GUI="1", PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    extra = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if G.IS_WIN else {"start_new_session": True})
    P.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env,
                              **extra)
    threading.Thread(target=P._read, daemon=True).start()


def threads(case, q):
    con = _con(case)
    try:
        if not con.execute("SELECT name FROM sqlite_master WHERE name='chat_threads'").fetchone():
            return {"threads": [], "apps": {}}
        w, a = [], []
        if q.get("app"):
            w.append("app = ?")
            a.append(q["app"])
        if (q.get("q") or "").strip():
            import forense_agent as fa
            w.append("(title LIKE ? ESCAPE '\\' OR participants LIKE ? ESCAPE '\\' OR id IN (SELECT thread FROM "
                     "chat_messages WHERE text LIKE ? ESCAPE '\\' OR sender_name LIKE ? ESCAPE '\\'))")
            a += [fa.like(q["q"].strip())] * 4
        if q.get("from"):
            w.append("last_ts >= ?")
            a.append(q["from"])
        if q.get("to"):
            w.append("first_ts <= ?")
            a.append(q["to"] if "T" in q["to"] else q["to"] + "T23:59:59")
        import forense_mobile_chat as fmc
        has_origin = "origin" in {r[1] for r in con.execute("PRAGMA table_info(chat_threads)")}
        rows = con.execute("SELECT id, app, title, participants, is_group, n_msg, first_ts, last_ts, src_path, "
                           + ("origin" if has_origin else "NULL") + ", local, part, inode FROM chat_threads"
                           + (" WHERE " + " AND ".join(w) if w else "") + " ORDER BY last_ts DESC LIMIT 5000", a).fetchall()
        apps = dict(con.execute("SELECT app, COUNT(*) FROM chat_messages GROUP BY app").fetchall())
        out = []
        for i, app, t, p, g, n, f, l, src, origin, local, tpart, tinode in rows:
            last = con.execute("SELECT text, kind, direction, extra FROM chat_messages WHERE thread=? ORDER BY ts DESC, id DESC LIMIT 1",
                               (i,)).fetchone()
            out.append({"id": i, "app": app, "title": t, "participants": json.loads(p or "[]"), "group": bool(g), "n": n,
                        "first": f, "last": l, "src": src, "preview": (last[0] or "")[:120] if last else "",
                        "preview_kind": last[1] if last else "", "preview_out": bool(last and last[2] == "out"),
                        "preview_tipo": fmw.etichetta(last[1], last[3]) if last and last[1] == "non gestito" else None,
                        "origin": origin, "local": fmc.show_id(local) if local else None, "part": tpart, "inode": tinode})
        return {"threads": out, "apps": apps}
    finally:
        con.close()


ATT_EXTRA = ("metodo", "verifica", "sha256")
MINI_DB = N_("miniatura dal database – file non presente nell'estrazione")


def _att_cols(con):
    """(2.20) Colonne aggiunte agli allegati (casi importati prima: NULL)."""
    have = {r[1] for r in con.execute("PRAGMA table_info(chat_attachments)")}
    return ", ".join((f"a.{c}" if c in have else f"NULL AS {c}") for c in ATT_EXTRA) + (
        ", a.thumb IS NOT NULL" if "thumb" in have else ", 0")


def _attachments(con, ids):
    att = {}
    if ids:
        for mid, aid, name, mime, size, dev, part, inode, path, lat, lon, metodo, verifica, sha, th in con.execute(
                "SELECT a.msg, a.id, a.name, a.mime, a.size, a.device_path, a.part, a.inode, a.path, a.lat, a.lon, "
                + _att_cols(con) + " FROM chat_attachments a WHERE a.msg IN (SELECT value FROM json_each(?))", (json.dumps(ids),)):
            att.setdefault(mid, []).append({"id": aid, "name": name, "mime": mime, "size": size, "device_path": dev, "part": part,
                                            "inode": inode, "path": path, "lat": lat, "lon": lon, "metodo": metodo,
                                            "verifica": verifica, "sha256": sha, "thumb": bool(th)})
        _trascrizioni(con, [a for v in att.values() for a in v])
    return att


def _trascrizioni(con, atts):
    """(2.20) Trascrizione automatica (la più recente) dei file allegati, se c'è: testo, modello, lingua, data."""
    keys = [[a["part"], str(a["inode"])] for a in atts if a.get("inode") not in (None, "") and a.get("part") is not None]
    if not keys or not con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='trascrizioni'").fetchone():
        return
    tr_ = {}
    for part, inode, testo, modello, lingua, ts in con.execute(
            "SELECT part, inode, testo, modello, lingua, ts FROM trascrizioni WHERE (part, inode) IN "
            "(SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(?)) ORDER BY ts", (json.dumps(keys),)):
        tr_[(part, str(inode))] = {"testo": testo or "", "modello": modello, "lingua": lingua, "ts": ts}
    for a in atts:
        t = tr_.get((a.get("part"), str(a.get("inode"))))
        if t:
            a["trascrizione"] = t


def att_thumb(case, q):
    """Miniatura di un allegato salvata nel database dell'app (file non presente nell'estrazione)."""
    con = _con(case)
    try:
        if "thumb" not in {r[1] for r in con.execute("PRAGMA table_info(chat_attachments)")}:
            raise ValueError(tr("Miniatura non disponibile."))
        r = con.execute("SELECT thumb FROM chat_attachments WHERE id=?", (int(q.get("id") or 0),)).fetchone()
    finally:
        con.close()
    if not r or not r[0]:
        raise ValueError(tr("Miniatura non disponibile."))
    b = bytes(r[0])
    return b, "image/png" if b.startswith(b"\x89PNG") else "image/webp" if b[:4] == b"RIFF" else "image/jpeg"


def messages(case, q):
    """Messaggi di una conversazione (o di tutte, con una ricerca), a pagine; filtri testo, mittente, periodo."""
    import forense_agent as fa
    con = _con(case)
    try:
        w, a = [], []
        if q.get("thread"):
            w.append("m.thread = ?")
            a.append(int(q["thread"]))
        if q.get("app"):
            w.append("m.app = ?")
            a.append(q["app"])
        if (q.get("q") or "").strip():
            w.append("m.text LIKE ? ESCAPE '\\'")
            a.append(fa.like(q["q"].strip()))
        if (q.get("who") or "").strip():
            w.append("(m.sender LIKE ? ESCAPE '\\' OR m.sender_name LIKE ? ESCAPE '\\')")
            a += [fa.like(q["who"].strip())] * 2
        if q.get("from"):
            w.append("m.ts >= ?")
            a.append(q["from"])
        if q.get("to"):
            w.append("m.ts <= ?")
            a.append(q["to"] if "T" in q["to"] else q["to"] + "T23:59:59")
        if q.get("att") in ("1", "true"):
            w.append("m.n_att > 0")
        where = (" WHERE " + " AND ".join(w)) if w else ""
        tot = con.execute("SELECT COUNT(*) FROM chat_messages m" + where, a).fetchone()[0]
        off = max(0, int(q.get("offset") or 0))
        rows = con.execute("SELECT m.id, m.thread, m.app, m.ts, m.direction, m.sender, m.sender_name, m.text, m.kind, "
                           "m.n_att, m.status, m.read_ts, m.service, m.src_table, m.src_row, m.part, m.inode, m.extra, "
                           "t.title, t.src_path FROM chat_messages m JOIN chat_threads t ON t.id = m.thread" + where +
                           " ORDER BY m.ts, m.id LIMIT ? OFFSET ?", a + [PAGE, off]).fetchall()
        att = _attachments(con, [r[0] for r in rows])
        rc = fmr.per_messaggi(con, [r[0] for r in rows])        # stati di consegna/lettura (casi nuovi)
        keys = ("id", "thread", "app", "ts", "dir", "sender", "sender_name", "text", "kind", "n_att", "status", "read_ts",
                "service", "src_table", "src_row", "part", "inode", "extra", "thread_title", "src_path")
        out = []
        for r in rows:
            d = dict(zip(keys, r))
            d["extra"] = json.loads(d["extra"]) if d["extra"] else {}
            d["att"] = att.get(d["id"], [])
            d["rc"] = rc.get(d["id"], [])
            out.append(d)
        return {"total": tot, "offset": off, "page": PAGE, "messages": out}
    finally:
        con.close()


def thread_attachments(case, q):
    """Tutti gli allegati di una conversazione in ordine di data, con il messaggio a cui appartengono."""
    con = _con(case)
    try:
        rows = con.execute("SELECT a.id, a.msg, a.name, a.mime, a.size, a.device_path, a.part, a.inode, a.path, a.lat, a.lon, "
                           "m.ts, m.direction, m.sender, m.sender_name, m.text, m.kind, " + _att_cols(con) + " FROM chat_attachments a "
                           "JOIN chat_messages m ON m.id = a.msg WHERE m.thread=? ORDER BY m.ts, m.id, a.id LIMIT 20000",
                           (int(q.get("thread") or 0),)).fetchall()
    finally:
        con.close()
    keys = ("id", "mid", "name", "mime", "size", "device_path", "part", "inode", "path", "lat", "lon", "ts", "dir", "sender",
            "sender_name", "text", "kind") + ATT_EXTRA + ("thumb",)
    return {"att": [dict(zip(keys, r[:-1] + (bool(r[-1]),))) for r in rows]}


def leapp_media(case, q):
    """File copiato da iLEAPP/ALEAPP nel loro rapporto («media/…»), solo dentro la cartella del rapporto del caso:
    immagini, video e audio per l'anteprima delle chat ricavate."""
    import forense_gui as G
    rel = str(q.get("p") or "")
    if rel.startswith("leapp:"):
        rel = rel[6:]
    f = (case.root / rel).resolve()
    base = (case.root / "leapp").resolve()
    if base not in f.parents or not f.is_file():
        raise ValueError(tr("File non trovato."))
    if f.stat().st_size > (64 << 20):
        raise ValueError(tr("File troppo grande per l'anteprima."))
    ctype = G.RAW_MIME.get(f.suffix.lower())
    if not ctype:
        raise ValueError(tr("Tipo di file non mostrato nell'anteprima."))
    return f.read_bytes(), ctype


def contacts(case, q):
    import forense_agent as fa
    con = _con(case)
    try:
        if not con.execute("SELECT name FROM sqlite_master WHERE name='chat_contacts'").fetchone():
            return {"contacts": []}
        t = (q.get("q") or "").strip()
        rows = con.execute("SELECT name, value, source FROM chat_contacts" + (" WHERE name LIKE ? ESCAPE '\\' OR value LIKE ? "
                           "ESCAPE '\\'" if t else "") + " ORDER BY name LIMIT 2000",
                           [fa.like(t)] * 2 if t else []).fetchall()
        return {"contacts": [{"name": n, "value": v, "source": s} for n, v, s in rows]}
    finally:
        con.close()


def art_tree(con):
    """Sottovoci degli artefatti per l'albero: [categoria, gruppo, voce, righe] (iLEAPP/ALEAPP: categoria di
    iLEAPP/ALEAPP e nome dell'artefatto; messaggi: app). Conteggi con GROUP BY sull'indice (cat, grp, sub)."""
    if "grp" not in {r[1] for r in con.execute("PRAGMA table_info(artifacts)")}:
        return []
    return [list(r) for r in con.execute("SELECT cat, grp, sub, COUNT(*) FROM artifacts WHERE grp IS NOT NULL "
                                         "GROUP BY cat, grp, sub ORDER BY cat, grp COLLATE NOCASE, sub COLLATE NOCASE")]


def art_filter(con, q, w, a):
    """Filtri «grp»/«sub» della sezione Artefatti (clic su una sottovoce dell'albero)."""
    if not (q.get("grp") or q.get("sub")):
        return
    if "grp" not in {r[1] for r in con.execute("PRAGMA table_info(artifacts)")}:
        w.append("0")
        return
    for k in ("grp", "sub"):
        if q.get(k):
            w.append(f"{k} = ?")
            a.append(q[k])


def art_rows(G, case, data, tz):
    """Righe «campo: valore» della scheda di un artefatto smartphone (iLEAPP/ALEAPP o conversazione), con le date
    nel fuso scelto in alto. None se l'artefatto non è di questi tipi. G = modulo del server (forense_gui)."""
    import forense_mobile_leapp as fml
    import forense_mobile_chat as fmc
    when = lambda v: G.fmt_ts(case, tz, v) if v else ""
    if "campi" in data and data.get("leapp"):
        dates = set(data.get("date") or [])
        rows = [(tr("Strumento"), data.get("leapp")), (tr("Categoria di {s}").format(s=data.get("leapp")), data.get("categoria")),
                (tr("Artefatto"), data.get("artefatto"))]
        segreti = set(data.get("segreti") or [])
        for k, v in (data.get("campi") or {}).items():
            if k in segreti:                         # (2.20) valore segreto: si vede solo con «Mostra» (registrato)
                rows.append((k, "•••••• " + tr("(valore segreto nascosto: «Mostra» sopra la tabella)")))
                continue
            iso = fml._iso(v) if k in dates or fml.TS_HEAD.search(k) else None
            rows.append((k, f"{when(iso)}  ({v})" if iso and tz != "utc" else when(iso) if iso else v))
        return rows
    if "chat_thread" in data:
        lm = data.get("ultimo_msg") or {}
        loc = (data.get("locale") or {}).get("id")
        al = data.get("altro") or {}
        gr = data.get("gruppo")
        rows = [(tr("App"), fmc.APP_LBL.get(data.get("app"), data.get("app"))),
                (tr("Questo telefono"), tr("questo dispositivo") + (f" ({loc})" if loc else ""))]
        if gr:
            rows += [(tr("Gruppo"), gr.get("nome")), (tr("Partecipanti"), f"{gr.get('n')}: " + ", ".join(data.get("partecipanti") or []))]
        else:
            rows += [(tr("Interlocutore"), " ".join(x for x in (al.get("nome"), al.get("id")) if x) +
                      (" — " + tr("numero breve/servizio") if al.get("breve") else ""))]
        if data.get("fonte"):
            rows += [(tr("Ricavata da"), ", ".join(f"{k} ({v})" if v else k for k, v in (data["fonte"].get("artefatti") or {}).items()))]
        rows += [(tr("Periodo"), f"{when(data.get('primo'))} → {when(data.get('ultimo'))}"),
                 (tr("Messaggi"), tr("{n} in tutto: inviati {o}, ricevuti {i}").format(
                     n=data.get("n"), o=data.get("inviati"), i=data.get("ricevuti")) +
                  (", " + tr("eventi {e}").format(e=data.get("eventi")) if data.get("eventi") else "")),
                 (tr("Verso non indicato dalla fonte"), data.get("senza_verso") or ""),
                 (tr("Allegati"), data.get("allegati")),
                 (tr("Messaggi eliminati (segnaposto)"), data.get("eliminati") or ""),
                 (tr("Ultimo messaggio"), (f"{when(lm.get('ts'))} · " + (tr("inviato") if lm.get("dir") == "out" else tr("evento") if lm.get("dir") == "sys" else tr("ricevuto"))
                                          + ": " + (lm.get("testo") or "[" + (lm.get("tipo") or tr(lm.get("kind") or "")) + "]")) if lm else "")]
        return rows
    if data.get("chiamata"):
        import forense_mobile_leapp_chat as fmlc
        v = data.get("verso")
        rows = [(tr("App"), data.get("app_lbl") or data.get("app")),
                (tr("Data e ora di inizio"), when(data.get("ts"))), (tr("Fine"), when(data.get("fine")) if data.get("fine") else ""),
                (tr("Direzione"), tr(fmlc.VERSI[v]) if v in fmlc.VERSI else tr("non indicata dalla fonte")),
                (tr("Numero / identificativo"), data.get("numero") or ""), (tr("Nome in rubrica"), data.get("nome_rubrica") or ""),
                (tr("Nome nell'app"), data.get("nome_app") or ""),
                (tr("Durata"), fmlc.hms(data["durata_s"]) if data.get("durata_s") is not None else ""),
                (tr("Risposta"), "" if data.get("risposta") is None else tr("sì") if data["risposta"] else tr("no")),
                (tr("Tipo"), data.get("tipo") or ""), (tr("Esito"), data.get("esito") or ""), (tr("Nota"), data.get("nota") or ""),
                (tr("Questo telefono"), data.get("account") or ""),
                (tr("Fonti ({n})").format(n=len(data.get("fonti") or [])),
                 "; ".join(f"{f['strumento']} «{f['artefatto']}» {tr('riga')} {f['riga']}" for f in data.get("fonti") or []))]
        if data.get("discordanze"):
            rows.append((tr("Valori diversi tra le fonti"), "; ".join(f"{d['campo']}: {d['valore']} ({d['fonte']})" for d in data["discordanze"])))
        return rows
    return None


def leapp_src(case, sub, campi=None):
    """Percorso nell'estrazione del file da cui iLEAPP/ALEAPP ha letto un artefatto (vedi forense_percorsi.leapp_fonte:
    campo «Source…» della riga, altrimenti la riga del .lava con lo stesso nome o la prima). None se non c'è."""
    import forense_percorsi as fp
    return fp.leapp_fonte(case, sub, campi)


def fix_art_rows(case, rows):
    """Righe degli artefatti di un caso smartphone: `estrazione` (i file non hanno offset né inode: si cita il percorso
    nell'estrazione) e, per iLEAPP/ALEAPP, la fonte vera al posto del nome dell'artefatto."""
    for r in rows:
        r["estrazione"] = 1
        d = r.get("data") if isinstance(r.get("data"), dict) else {}
        if r.get("cat") == "leapp" and not r.get("inode"):
            r["src_path"] = leapp_src(case, d.get("artefatto") or r.get("src_path"), d.get("campi"))


def _mx_path(case, part, inode):
    import forense_mobile as fm
    if inode in (None, "") or not str(inode).isdigit():
        return None
    try:
        m = fm.mx(case)
        try:
            r = m.execute("SELECT path FROM mobile_files WHERE id=?", (int(inode),)).fetchone()
        finally:
            m.close()
    except sqlite3.Error:
        return None
    return r[0] if r else None


def ref(case, cx, src, oid=None, part=None, inode=None, path=None):
    """Riferimento di un elemento di un caso smartphone per Preferiti, Reperto e registro: percorso nell'estrazione per i
    file; database, tabella e riga per messaggi e artefatti (mai offset e inode, che qui non esistono)."""
    import forense_mobile_chat as fmc
    if src == "fs":
        p = path or _mx_path(case, part, inode) or ""
        return tr("{p} (percorso nell'estrazione)").format(p=p) if p else tr("file dell'estrazione")
    if src == "chat":
        r = cx.execute("SELECT m.app, m.ts, m.src_table, m.src_row, m.part, m.inode, t.src_path, t.title "
                       "FROM chat_messages m JOIN chat_threads t ON t.id = m.thread WHERE m.id=?", (int(oid),)).fetchone()
        if not r:
            return tr("messaggio {id}").format(id=oid)
        app, ts, tb, row, mp, mi, tsrc, title = r
        db = _mx_path(case, mp, mi) or tsrc or ""
        return (tr("messaggio {app} del {ts} UTC nella conversazione «{t}»").format(app=fmc.APP_LBL.get(app, app), ts=(ts or "?").replace("T", " "), t=title)
                + (" — " + tr("database {db}").format(db=db) if db else "")
                + (", " + tr("tabella {tb}, riga {row}").format(tb=tb, row=row) if tb else ""))
    r = cx.execute("SELECT cat, title, src_path, part, inode, data FROM artifacts WHERE id=?", (int(oid),)).fetchone()
    if not r:
        return tr("artefatto {id}").format(id=oid)
    cat, title, sp, ap, ai, data = r
    try:
        d = json.loads(data) if data else {}
    except ValueError:
        d = {}
    riga = tr("riga {id} della tabella artifacts del caso").format(id=oid)
    if cat == "leapp":
        p = leapp_src(case, d.get("artefatto") or sp, d.get("campi"))
        return (tr("{tool} «{a}»").format(tool=d.get("leapp") or "iLEAPP/ALEAPP", a=d.get("artefatto") or sp)
                + (" — " + tr("database {db}").format(db=p) if p else "") + ", " + riga)
    db = _mx_path(case, ap, ai) or sp or ""
    out = (" — " + tr("database {db}").format(db=db)) if db else ""
    if d.get("chiamata") and d.get("fonti"):
        out += "; " + tr("fonti: {f}").format(f="; ".join((tr("{tool} «{a}» (riga {r} della tabella)") if f.get("tabella") else
                                                              tr("{tool} «{a}» (riga {r} degli artefatti)")).format(
            tool=f.get("strumento"), a=f.get("artefatto"), r=f.get("riga")) for f in d["fonti"]))
    return tr("artefatto «{t}»").format(t=title) + out + ", " + riga


def msg_item(con, mid):
    """Un messaggio come elemento dei Preferiti: (testo della riga, nome, data)."""
    r = con.execute("SELECT m.app, m.ts, m.direction, m.sender, m.sender_name, m.text, m.kind, m.src_table, m.src_row, "
                    "t.title, m.extra FROM chat_messages m JOIN chat_threads t ON t.id = m.thread WHERE m.id=?", (int(mid),)).fetchone()
    if not r:
        return None
    import forense_mobile_chat as fmc
    app, ts, d, snd, sname, text, kind, tb, row, title, extra = r
    who = tr("inviato") if d == "out" else (sname or snd or tr("ricevuto"))
    body = " ".join((text or "[" + fmw.etichetta(kind, extra) + "]").split())[:120]
    return (f"{fmc.APP_LBL.get(app, app)} · {title} · {who}: {body} [{tb}#{row}]", f"{title}: {body}"[:200], ts)


def msg_view(G, case, b):
    """Anteprima di un messaggio salvato nei Preferiti: conversazione, mittente, data nel fuso scelto, stato, testo,
    allegati e riferimento al dato grezzo (database, tabella, riga)."""
    import html as H
    import forense_mobile_chat as fmc
    con = _con(case)
    try:
        mid = int(b.get("id") or b.get("inode") or 0)
        r = con.execute("SELECT m.id, m.app, m.ts, m.direction, m.sender, m.sender_name, m.text, m.kind, m.status, m.read_ts, "
                        "m.service, m.src_table, m.src_row, m.extra, t.title, t.src_path, t.local, t.id FROM chat_messages m "
                        "JOIN chat_threads t ON t.id = m.thread WHERE m.id=?", (mid,)).fetchone()
        if not r:
            raise ValueError(tr("Messaggio non trovato."))
        att = _attachments(con, [mid]).get(mid, [])
    finally:
        con.close()
    (mid, app, ts, d, snd, sname, text, kind, st, rts, svc, tb, row, extra, title, src, local, tid) = r
    tz = b.get("tz")
    rows = [(tr("Conversazione"), f"{fmc.APP_LBL.get(app, app)} · {title}"),
            (tr("Data ({v1})").format(v1=G.tz_label(case, tz)), G.fmt_ts(case, tz, ts)),
            (tr("Mittente"), (tr("questo dispositivo") + (f" ({fmc.show_id(local)})" if local else "")) if d == "out"
             else " ".join(x for x in (sname, fmc.show_id(snd)) if x) or "—"),
            (tr("Tipo"), fmw.etichetta(kind, extra)), (tr("Stato"), st or ""), (tr("Letto"), G.fmt_ts(case, tz, rts) if rts else ""),
            (tr("Servizio"), svc or ""), (tr("Testo"), text or ""),
            (tr("Allegati"), "; ".join(f"{a['name'] or ''} {a['path'] or a['device_path'] or ''}".strip() for a in att)),
            (tr("Dato grezzo"), f"{src} · {tb} {tr('riga')} {row} · {tr('messaggio')} {mid}")]
    h = "<table style='border-collapse:collapse;font:13px/1.5 -apple-system,Segoe UI,sans-serif;width:100%'>" + "".join(
        f"<tr><th style='text-align:left;vertical-align:top;padding:5px 10px;border-bottom:1px solid #ddd;white-space:nowrap'>"
        f"{H.escape(k)}</th><td style='padding:5px 10px;border-bottom:1px solid #ddd;white-space:pre-wrap;word-break:break-word'>"
        f"{H.escape(str(v or ''))}</td></tr>" for k, v in rows if v not in (None, "")) + "</table>"
    head = "\n".join(f"{k}: {v}" for k, v in rows if v not in (None, ""))
    return {"type": "html", "title": title, "name": title, "source": "chat", "id": mid, "size": 0, "deleted": 0,
            "part": None, "inode": None, "magic": "", "html": G.CSP_DOC + h, "src_path": src, "headers": head,
            "thread": tid}

def rub_view(G, case, b):
    """(2.20) Anteprima di una voce delle rubriche (tabella chat_contacts, dalla ricerca veloce): nome, valore, database di
    origine nell'estrazione, altre voci con lo stesso numero e conversazioni con quel numero."""
    import html as H
    import forense_mobile as fm
    import forense_mobile_chat as fmc
    con = _con(case)
    try:
        cid = int(b.get("id") or b.get("inode") or 0)
        r = con.execute("SELECT source, name, value, norm FROM chat_contacts WHERE id=?", (cid,)).fetchone()
        if not r:
            raise ValueError(tr("Voce della rubrica non trovata."))
        src, name, value, norm = r
        altre = con.execute("SELECT name, value, source FROM chat_contacts WHERE norm=? AND id<>? ORDER BY name LIMIT 30",
                            (norm, cid)).fetchall() if norm else []
        conv = con.execute("SELECT app, title, n_msg FROM chat_threads WHERE key LIKE ? OR participants LIKE ? "
                           "ORDER BY last_ts DESC LIMIT 30", (f"%{norm}%", f"%{norm}%")).fetchall() \
            if norm and len(norm) >= 6 else []
    finally:
        con.close()
    part = inode = None
    if src:
        m = fm.mx(case)
        try:
            x = m.execute("SELECT id, part FROM mobile_files WHERE path=? AND isdir=0", (src,)).fetchone()
        finally:
            m.close()
        if x:
            inode, part = str(x[0]), x[1]
    rows = [(tr("Nome"), name or ""), (tr("Valore"), value or ""), (tr("Chiave di confronto"), norm or ""),
            (tr("Fonte"), tr("{p} (percorso nell'estrazione)").format(p=src) if src else ""),
            (tr("Stesso numero nelle rubriche"), "; ".join(" · ".join(x for x in (n, v, Path(s_ or "").name) if x)
                                                          for n, v, s_ in altre)),
            (tr("Conversazioni con questo numero"), "; ".join(f"{fmc.APP_LBL.get(a_, a_)} · {t} ({n or 0})"
                                                              for a_, t, n in conv))]
    h = "<table style='border-collapse:collapse;font:13px/1.5 -apple-system,Segoe UI,sans-serif;width:100%'>" + "".join(
        f"<tr><th style='text-align:left;vertical-align:top;padding:5px 10px;border-bottom:1px solid #ddd;white-space:nowrap'>"
        f"{H.escape(k)}</th><td style='padding:5px 10px;border-bottom:1px solid #ddd;white-space:pre-wrap;word-break:break-word'>"
        f"{H.escape(str(v))}</td></tr>" for k, v in rows if v not in (None, "")) + "</table>"
    title = name or value or ""
    return {"type": "html", "title": title, "name": title, "source": "rub", "id": cid, "size": 0, "deleted": 0,
            "part": part, "inode": inode, "magic": "", "html": G.CSP_DOC + h, "src_path": src,
            "headers": "\n".join(f"{k}: {v}" for k, v in rows if v not in (None, "")), "valore": value or ""}


# ------------------------------------------------------------------------------ esportazione di una chat

EXPORT_CSS = """body{font:14px/1.45 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;margin:0;background:#f4f5f7;color:#1d2330}
header{background:#fff;border-bottom:1px solid #d8dbe2;padding:16px 22px}h1{font-size:19px;margin:0 0 8px}
table.h{border-collapse:collapse;font-size:12.5px}table.h th{text-align:left;color:#5b6475;font-weight:600;padding:2px 14px 2px 0;
vertical-align:top;white-space:nowrap}table.h td{padding:2px 0;word-break:break-word}.mono{font-family:Menlo,Consolas,monospace;font-size:11.5px}
main{max-width:900px;margin:0 auto;padding:16px;display:flex;flex-direction:column;gap:6px}
.day{align-self:center;font-size:11.5px;color:#5b6475;background:#e6e8ee;border-radius:99px;padding:2px 10px;margin:6px 0}
.b{max-width:74%;padding:7px 10px;border-radius:12px;background:#fff;border:1px solid #d8dbe2;white-space:pre-wrap;word-wrap:break-word}
.b.out{align-self:flex-end;background:#dbe8ff;border-color:transparent}.b.in{align-self:flex-start}
.b.sys{align-self:center;background:none;border:none;color:#5b6475;font-style:italic;font-size:12.5px;text-align:center}
.b.del{border:1px dashed #d97706;background:#fdf3e1}.w{font-size:12px;font-weight:600;color:#2456c7;margin-bottom:2px}
.m{font-size:11px;color:#5b6475;margin-top:3px;text-align:right}.k{font-style:italic;color:#5b6475}
.a{margin-top:6px;padding:6px;border:1px solid #d8dbe2;border-radius:8px;background:#f7f8fa;font-size:12.5px;white-space:normal}
.a img{display:block;max-width:240px;max-height:240px;border-radius:6px;margin-bottom:4px}
footer{max-width:900px;margin:10px auto 30px;padding:0 16px;font-size:11.5px;color:#5b6475}
@media print{body{background:#fff}.b{break-inside:avoid}}"""


def _safe(s):
    import re
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(s or ""))[:40].strip("_") or "chat"


def _sha_file(f):
    import hashlib
    h = hashlib.sha256()
    with open(f, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _db_sources(case, con, tid, tpart, tinode, tsrc):
    """Database di origine della conversazione con offset, voce (inode) e SHA-256 (anche dei file -wal/-shm accanto)."""
    import forense_mobile as fm
    import forense_mobile_chat as fmc
    pairs = {}
    if tinode not in (None, "", "None"):
        pairs[(tpart, str(tinode))] = tsrc
    for part, inode in con.execute("SELECT DISTINCT part, inode FROM chat_messages WHERE thread=? AND inode IS NOT NULL "
                                   "AND inode != 'None'", (tid,)):
        pairs.setdefault((part, str(inode)), None)
    out = []
    m = fm.mx(case)
    try:
        for (part, inode), src in pairs.items():
            r = m.execute("SELECT path FROM mobile_files WHERE id=?", (int(inode),)).fetchone()
            path = r[0] if r else src
            item = {"path": path, "offset": part, "inode": inode, "sha256": fmc._sha_db(case, part, inode), "accanto": []}
            for suf in ("-wal", "-shm", "-journal"):
                w = m.execute("SELECT id FROM mobile_files WHERE part=? AND path=? AND isdir=0", (part, (path or "") + suf)).fetchone()
                if w:
                    item["accanto"].append({"path": path + suf, "inode": str(w[0]), "sha256": fmc._sha_db(case, part, str(w[0]))})
            out.append(item)
    finally:
        m.close()
    return out


def export_chat(G, case, b):
    """Esporta una conversazione in export/chat/: HTML leggibile (fumetti, miniature delle immagini, allegati copiati
    accanto con SHA-256) e CSV; intestazione con caso, app, interlocutori, periodo, fuso, fonte con offset/inode e
    SHA-256 del database. Gli SHA-256 dei file esportati vanno nel registro a catena."""
    import base64
    import csv
    import datetime as dt
    import html as H
    import forense_agent as fa
    import forense_mobile_chat as fmc
    tid, tz = int(b.get("thread") or 0), b.get("tz")
    con = _con(case)
    try:
        t = con.execute("SELECT id, app, title, participants, is_group, n_msg, first_ts, last_ts, part, inode, src_path, local "
                        "FROM chat_threads WHERE id=?", (tid,)).fetchone()
        if not t:
            raise ValueError(tr("Conversazione non trovata."))
        _id, app, title, parts, grp, n, first, last, tpart, tinode, tsrc, local = t
        msgs = con.execute("SELECT id, ts, direction, sender, sender_name, text, kind, status, read_ts, service, src_table, "
                           "src_row, extra FROM chat_messages WHERE thread=? ORDER BY ts, id", (tid,)).fetchall()
        att = _attachments(con, [r[0] for r in msgs])
        fonti = _db_sources(case, con, tid, tpart, tinode, tsrc)
    finally:
        con.close()
    lbl = fmc.APP_LBL.get(app, app)
    when = lambda v: G.fmt_ts(case, tz, v) if v else ""
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    d = case.export_dir / "chat"
    d.mkdir(parents=True, exist_ok=True)
    stem = f"chat_{tid}_{_safe(lbl)}_{_safe(title)}_{stamp}"
    adir = d / (stem + "_allegati")
    copied, att_rows = [], {}
    for mid, lst in att.items():
        for a in lst:
            src = None
            if a.get("path") and str(a["path"]).startswith("leapp:"):
                f = (case.root / a["path"][6:]).resolve()
                src = ("file", f) if (case.root / "leapp").resolve() in f.parents and f.is_file() else None
            elif a.get("inode") not in (None, "", "None") and a.get("part") is not None:
                src = ("fs", (int(a["part"]), str(a["inode"])))
            a["_rel"] = a["_sha"] = a["_thumb"] = a["_dbthumb"] = None
            if not src:
                if a.get("thumb"):           # (2.20) miniatura salvata nel database: il file non c'è
                    try:
                        tb_, ct_ = att_thumb(case, {"id": a["id"]})
                        a["_dbthumb"] = f"data:{ct_};base64," + base64.b64encode(tb_).decode()
                    except ValueError:
                        pass
                continue
            adir.mkdir(exist_ok=True)
            ext = Path(str(a.get("path") or a.get("name") or "")).suffix[:10]
            astem = Path(str(a.get("name") or "allegato")).stem if ext else str(a.get("name") or "allegato")
            dest = adir / (_safe(f"{mid}_{astem}").rstrip(".") + ext)
            n2 = 1
            while dest.exists():
                n2 += 1
                dest = adir / (_safe(f"{mid}_{astem}").rstrip(".") + f"_{n2}" + ext)
            try:
                if src[0] == "file":
                    import shutil
                    shutil.copyfile(src[1], dest)
                else:
                    import forense_mobile as fm
                    with open(dest, "wb") as fo:
                        for chunk in fm.stream(case, src[1][0], src[1][1]):
                            fo.write(chunk)
            except Exception:
                continue
            a["_rel"], a["_sha"] = f"{adir.name}/{dest.name}", _sha_file(dest)
            copied.append({"file": a["_rel"], "sha256": a["_sha"], "origine": a.get("path") or a.get("device_path")})
            if dest.suffix.lower() in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif", ".bmp", ".tif", ".tiff"):
                try:
                    r = G.thumb_bytes(case, {"source": "fs", "part": src[1][0], "inode": src[1][1], "size": 320}) if src[0] == "fs" \
                        else (dest.read_bytes(), G.RAW_MIME.get(dest.suffix.lower(), "image/jpeg")) if dest.stat().st_size < (4 << 20) else None
                    if r:
                        a["_thumb"] = f"data:{r[1]};base64," + base64.b64encode(r[0]).decode()
                except Exception:
                    pass
    plist = [x for x in json.loads(parts or "[]") if x]
    meta = case.meta
    ic = meta.get("info_caso") or {}
    sha_ext = meta.get("sha256")
    sha_ext = ", ".join(f"{k}: {v}" for k, v in sha_ext.items()) if isinstance(sha_ext, dict) else sha_ext
    loc = tr("questo dispositivo") + (f" ({fmc.show_id(local)})" if local else "")
    other = (tr("gruppo «{g}»: ").format(g=title) + ", ".join(fmc.show_id(x) for x in plist)) if grp else \
        " ".join(x for x in (title, f"({fmc.show_id(plist[0])})" if plist and fmc.show_id(plist[0]) not in (title or "") else None) if x)
    head = [(tr("Caso"), ic.get("nome") or case.root.name), (tr("Operatore"), ic.get("operatore") or ""),
            (tr("App"), lbl), (tr("Interlocutori"), f"{loc} ↔ {other}"),
            (tr("Periodo"), f"{when(first)} → {when(last)}"), (tr("Fuso orario usato"), G.tz_label(case, tz)),
            (tr("Messaggi"), str(len(msgs))),
            (tr("Estrazione"), f"{meta.get('image') or ''}" + (f" · SHA-256 {sha_ext}" if sha_ext else ""))]
    for f in fonti:
        head.append((tr("Database di origine"), f"{f['path']} · offset {f['offset']}, inode {f['inode']} · SHA-256 {f['sha256']}"
                     + "".join(f"\n{x['path']} · inode {x['inode']} · SHA-256 {x['sha256']}" for x in f["accanto"])))
    if not fonti:
        head.append((tr("Database di origine"), tsrc or ""))
    head.append((tr("Esportata il"), f"{fa.now()} UTC · RepertIA {fa.APP_VERSION}"))
    # HTML
    E = lambda x: H.escape(str(x or ""))
    body, lastday = [], ""
    for mid, ts, dr, snd, sname, text, kind, st, rts, svc, tb, row, extra in msgs:
        ex = json.loads(extra) if extra else {}
        day = when(ts)[:10]
        if day and day != lastday:
            body.append(f'<div class="day">{E(day)}</div>')
            lastday = day
        cls = ("out" if dr == "out" else "sys" if dr == "sys" or kind == "sistema" else "in") + (" del" if kind == "eliminato" else "")
        who = f'<div class="w">{E(sname or fmc.show_id(snd))}</div>' if cls.startswith("in") and (grp or sname or snd) else ""
        txt = E(text) if text else f'<span class="k">[{E(fmw.etichetta(kind, ex) if kind and kind != "testo" else ex.get("tipo") or tr("senza testo"))}]</span>'
        aa = []
        for a in att.get(mid, []):
            link = f'<a href="{E(a["_rel"])}">{E(a.get("name") or tr("allegato"))}</a>' if a.get("_rel") else E(a.get("name") or tr("allegato"))
            import forense_percorsi as fpc
            how = (fpc.esito_metodo(a["metodo"], a.get("verifica")) if a.get("_rel") and a.get("metodo") not in (None, "percorso") else "")
            if a.get("verifica") == "uguale":
                how = "; ".join(x for x in (how, tr("SHA-256 uguale a quello registrato dall'app")) if x)
            elif a.get("verifica") == "diverso":
                how = "; ".join(x for x in (how, tr("ATTENZIONE: SHA-256 diverso da quello registrato dall'app")) if x)
            aa.append(f'<div class="a">' + (f'<a href="{E(a["_rel"])}"><img src="{a["_thumb"]}" alt=""></a>' if a.get("_thumb") else "")
                      + (f'<img src="{a["_dbthumb"]}" alt=""><div><b>{E(tr(MINI_DB))}</b></div>' if a.get("_dbthumb") else "")
                      + f'📎 {link}' + (f' · SHA-256 <span class="mono">{E(a["_sha"])}</span>' if a.get("_sha") else "")
                      + (f'<div>{E(how)}</div>' if how else "")
                      + (f'<div>📍 {E(a.get("lat"))}, {E(a.get("lon"))}</div>' if a.get("lat") is not None else "")
                      + (f'<div class="mono">{E(a.get("path") or a.get("device_path"))}</div>' if (a.get("path") or a.get("device_path")) else "")
                      + (f'<div class="tr"><b>{E(tr("Trascrizione automatica (da verificare ascoltando l\'audio)"))}:</b> {E(a["trascrizione"]["testo"])}'
                         f' <span class="mono">[{E(a["trascrizione"]["modello"] or "")}, {E(a["trascrizione"]["lingua"] or "?")}]</span></div>'
                         if a.get("trascrizione") else "") + "</div>")
        meta_l = " · ".join(x for x in (when(ts), st, svc, f"{tb} #{row}", f"{tr('messaggio')} {mid}") if x)
        body.append(f'<div class="b {cls}">{who}{txt}{"".join(aa)}<div class="m">{E(meta_l)}</div></div>')
    doc = (f'<!doctype html><html lang="{E(b.get("lingua") or "it")}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
           f'<title>{E(lbl)} · {E(title)}</title><style>{EXPORT_CSS}</style></head><body><header><h1>💬 {E(lbl)} · {E(title)}</h1>'
           f'<table class="h">' + "".join(f'<tr><th>{E(k)}</th><td{" class=mono" if "SHA-256" in str(v) else ""}>{E(v).replace(chr(10), "<br>")}</td></tr>' for k, v in head if v)
           + f'</table></header><main>{"".join(body)}</main><footer>{E(tr("Orari nel fuso indicato in alto; nel caso i dati sono in UTC. Ogni messaggio porta il riferimento al dato grezzo (tabella e riga). Gli allegati copiati sono nella cartella accanto a questo file, con il loro SHA-256."))}</footer></body></html>')
    fh = d / (stem + ".html")
    fh.write_text(doc, encoding="utf-8")
    fc = d / (stem + ".csv")
    with open(fc, "w", encoding="utf-8-sig", newline="") as fo:
        w = csv.writer(fo, delimiter=";")
        for k, v in head:
            if v:
                w.writerow([f"# {k}", v])
        w.writerow([tr("id"), tr("Data ({v1})").format(v1=G.tz_label(case, tz)), tr("Data (UTC)"), tr("Verso"), tr("Mittente"),
                    tr("Nome"), tr("Testo"), tr("Tipo"), tr("Stato"), tr("Letto"), tr("Servizio"), tr("Allegati"), tr("Dato grezzo")])
        for mid, ts, dr, snd, sname, text, kind, st, rts, svc, tb, row, extra in msgs:
            w.writerow([mid, when(ts), ts or "", {"out": tr("inviato"), "in": tr("ricevuto"), "sys": tr("evento")}.get(dr, tr("non indicato")),
                        fmc.show_id(snd) if dr != "out" else loc, sname or "", text or "", fmw.etichetta(kind, extra), st or "",
                        when(rts), svc or "", " | ".join(" ".join(x for x in (a.get("name"), a.get("_rel") or a.get("path") or a.get("device_path"),
                                                                             ("SHA-256 " + a["_sha"]) if a.get("_sha") else None,
                                                                             (tr("trascrizione automatica: «{t}»").format(t=a["trascrizione"]["testo"])
                                                                              if a.get("trascrizione") else None)) if x)
                                                         for a in att.get(mid, [])), f"{tb} #{row}"])
    files = [{"file": f"{fx.name}", "sha256": _sha_file(fx)} for fx in (fh, fc)]
    case.log("export_chat", {"thread": tid, "app": lbl, "titolo": title, "messaggi": len(msgs), "fuso": G.tz_label(case, tz),
                             "cartella": str(d.relative_to(case.root)), "file": files, "allegati": copied, "fonti": fonti})
    return {"rel": str(d.relative_to(case.root)), "files": files, "allegati": len(copied),
            "message": tr("Chat esportata in {d}: {f}").format(d=str(d.relative_to(case.root)), f=", ".join(x["file"] for x in files))}


def sqlite_preview(G, case, it):
    """(2.20) Anteprima di un database dell'estrazione letto da una copia di lavoro con i file -wal, -shm e -journal
    accanto (come per le chat): le righe ancora nel -wal compaiono. La copia si cancella subito dopo."""
    import forense_mobile_chat as fmc
    path = _mx_path(case, it["part"], it["inode"]) or it.get("path") or ""
    w = fmc.WorkDB(case, int(it["part"]), it["inode"], path, None)
    try:
        w.db.close()
        acc = [s for s in ("-wal", "-shm", "-journal") if (w.tmp / (w.file.name + s)).exists()]
        html = G.sqlite_view(w.file, copia=True)
    finally:
        w.close()
    nota = (tr("Letto con i file accanto nell'estrazione: {f} (copia di lavoro, l'originale non è toccato).").format(f=", ".join(acc))
            if acc else tr("Nessun file -wal/-journal accanto nell'estrazione."))
    return html, nota


# ------------------------------------------------------------------ (2.20) origine dei file: allegati delle chat
#
# Un file dell'estrazione «viene da una chat» se una riga di chat_attachments punta a lui (part, inode): il collegamento
# l'ha fatto la lettura delle chat (lettori propri o iLEAPP/ALEAPP) con il metodo registrato in chat_attachments.metodo.
# Si calcola al momento: nessuna tabella nuova, vale anche per i casi già preparati.

def _has_att(con):
    return bool(con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='chat_attachments'").fetchone())


def _att_media(app=None):
    """Sottoquery (part, inode) dei file allegati a messaggi delle chat (di un'app, se indicata)."""
    return ("SELECT c.part, c.inode FROM chat_attachments c" + (" JOIN chat_messages cm ON cm.id = c.msg" if app else "")
            + " WHERE c.inode IS NOT NULL AND c.inode != ''" + (" AND cm.app = ?" if app else ""))


def meta_filter(con, q, w, a):
    """Filtro «Origine» di Foto e metadati: «*» = allegati di qualunque chat, altrimenti l'app (chat_messages.app)."""
    if not _has_att(con):
        w.append("0")
        return
    app = q.get("orig")
    app = None if app in (None, "", "*") else str(app)
    w.append(f"(part, inode) IN ({_att_media(app)})")
    if app:
        a.append(app)


def meta_counts(con):
    """Conteggi per l'albero: file di Foto e metadati allegati alle chat, in tutto e per app."""
    if not _has_att(con):
        return {"n": 0, "app": []}
    n = con.execute(f"SELECT COUNT(*) FROM meta WHERE (part, inode) IN ({_att_media()})").fetchone()[0]
    app = con.execute("SELECT x.app, COUNT(*) FROM meta JOIN (SELECT DISTINCT c.part, c.inode, cm.app FROM chat_attachments c "
                      "JOIN chat_messages cm ON cm.id = c.msg WHERE c.inode IS NOT NULL AND c.inode != '') x "
                      "ON x.part = meta.part AND x.inode = meta.inode GROUP BY 1 ORDER BY 2 DESC").fetchall()
    return {"n": n, "app": [list(r) for r in app]}


def media_counts(con, table, where, args):
    """(2.20) Conteggi per l'albero di una sottovoce di Foto/Video/Audio (foto, video o audio): file di `table` che
    soddisfano `where` allegati alle chat, in tutto e per app."""
    if not _has_att(con):
        return {"n": 0, "app": []}
    n = con.execute(f"SELECT COUNT(*) FROM {table} WHERE {where} AND (part, inode) IN ({_att_media()})", args).fetchone()[0]
    app = con.execute(f"SELECT x.app, COUNT(*) FROM {table} t JOIN (SELECT DISTINCT c.part, c.inode, cm.app FROM "
                      "chat_attachments c JOIN chat_messages cm ON cm.id = c.msg WHERE c.inode IS NOT NULL AND c.inode != '') x "
                      f"ON x.part = t.part AND x.inode = t.inode WHERE {where.replace('path', 't.path')} GROUP BY 1 ORDER BY 2 DESC",
                      args).fetchall()
    return {"n": n, "app": [list(r) for r in app]}


def meta_origini(con, rows):
    """Aggiunge alle righe di Foto e metadati `chat` (app delle chat in cui il file è allegato) e `chat_mid` (il primo
    di quei messaggi, per «Apri nella chat»)."""
    keys = [[r.get("part"), str(r.get("inode"))] for r in rows if r.get("inode") not in (None, "") and r.get("part") is not None]
    if not keys or not _has_att(con):
        return
    import forense_mobile_chat as fmc
    found = {}
    for part, inode, app, mid in con.execute(
            "SELECT c.part, c.inode, cm.app, MIN(cm.id) FROM chat_attachments c JOIN chat_messages cm ON cm.id = c.msg "
            "WHERE (c.part, c.inode) IN (SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(?)) "
            "GROUP BY 1, 2, 3 ORDER BY 4", (json.dumps(keys),)):
        e = found.setdefault((part, str(inode)), {"app": [], "mid": mid})
        e["app"].append(fmc.APP_LBL.get(app, app))
    for r in rows:
        e = found.get((r.get("part"), str(r.get("inode"))))
        if e:
            r["chat"], r["chat_mid"] = ", ".join(e["app"]), e["mid"]


def origine(case, q):
    """Origine di un file dell'estrazione: i messaggi delle chat che lo hanno come allegato, ciascuno con conversazione,
    verso, data (UTC), fonte (database, tabella, riga) e come il file dell'allegato è stato trovato (certo/probabile)."""
    import forense_mobile_chat as fmc
    import forense_percorsi as fp
    inode = q.get("inode")
    try:
        part = int(q.get("part"))
    except (TypeError, ValueError):
        return {"origine": []}
    if inode in (None, ""):
        return {"origine": []}
    con = _con(case)
    try:
        if not _has_att(con):
            return {"origine": []}
        rows = con.execute(
            "SELECT m.id, m.app, m.ts, m.direction, m.sender, m.sender_name, m.src_table, m.src_row, m.part, m.inode, "
            "t.id, t.title, t.src_path, t.origin, a.name, " + _att_cols(con) +
            " FROM chat_attachments a JOIN chat_messages m ON m.id = a.msg JOIN chat_threads t ON t.id = m.thread "
            "WHERE a.part = ? AND a.inode = ? ORDER BY m.ts, m.id LIMIT 50", (part, str(inode))).fetchall()
    finally:
        con.close()
    out = []
    for (mid, app, ts, d, snd, sname, tb, row, mp, mi, tid, title, tsrc, torig, name, metodo, verifica, sha, _th) in rows:
        lv = fp.livello({"stato": "trovato", "metodo": metodo, "verifica": verifica})
        out.append({"mid": mid, "thread": tid, "app": app, "app_lbl": fmc.APP_LBL.get(app, app), "title": title, "ts": ts,
                    "dir": d, "who": sname or snd, "db": _mx_path(case, mp, mi) or tsrc or "", "tabella": tb, "riga": row,
                    "leapp": torig == "leapp", "nome": name, "livello": lv, "livello_lbl": tr(fp.LIVELLI[lv]),
                    "metodo": metodo, "metodo_lbl": tr(fp.METODI[metodo]) if metodo in fp.METODI else tr("metodo non registrato"),
                    "verifica": verifica})
    return {"origine": out}


def get(G, path, q):
    if path == "/api/mobile/origine":
        return origine(_case(G), q)
    if path == "/api/mobile/threads":
        return threads(_case(G), q)
    if path == "/api/mobile/messages":
        return messages(_case(G), q)
    if path == "/api/mobile/contacts":
        return contacts(_case(G), q)
    if path == "/api/mobile/thread_of":
        con = _con(_case(G))
        try:
            r = con.execute("SELECT thread FROM chat_messages WHERE id=?", (int(q.get("mid") or 0),)).fetchone()
        finally:
            con.close()
        if not r:
            raise ValueError(tr("Messaggio non trovato."))
        return {"thread": r[0]}
    if path == "/api/mobile/thread_art":
        con = _con(_case(G))
        try:
            r = con.execute("SELECT id, title, ts, detail FROM artifacts WHERE cat='messaggi' AND data LIKE '%\"chat_thread\"%' AND "
                            "json_extract(data, '$.chat_thread') = ?", (int(q.get("thread") or 0),)).fetchone()
        finally:
            con.close()
        if not r:
            raise ValueError(tr("Conversazione non trovata."))
        return {"id": r[0], "title": r[1], "ts": r[2], "detail": r[3]}
    if path == "/api/mobile/attachments":
        return thread_attachments(_case(G), q)
    if path == "/api/mobile/available":
        return {"ok": True}
    raise ValueError(tr("Richiesta sconosciuta: {path}").format(path=path))


def post(G, path, b):
    import forense_agent as fa
    import forense_lingua as lg
    if path == "/api/mobile/choose":
        if b.get("folder"):
            p = G.choose_folder(tr("Scegli la cartella con l'estrazione del telefono"))
        else:
            p = G.choose_file(tr("Scegli l'estrazione del telefono (zip, tar, tar.gz)"), kind="any", any_file=True)
        return {"path": p} if p else {"cancelled": True}
    if path == "/api/mobile/choose_keychain":
        p = G.choose_file(tr("Scegli il portachiavi (keychain) acquisito a parte"), kind="any", any_file=True)
        return {"path": p} if p else {"cancelled": True}
    if path == "/api/mobile/choose_sysdiagnose":
        p = G.choose_file(tr("Scegli il sysdiagnose (sysdiagnose_….tar.gz)"), kind="any", any_file=True)
        return {"path": p} if p else {"cancelled": True}
    if path == "/api/mobile/sysdiagnose_check":     # (2.20) controllo veloce: è un sysdiagnose? data e dispositivo
        import forense_mobile_sysdiagnose as fms
        p = Path(G.clean_path(b.get("path")))
        if not p.is_file():
            raise ValueError(tr("File del sysdiagnose non trovato: {p}").format(p=p))
        i = fms.esamina(p)
        return {**i, "path": str(p), "byte": p.stat().st_size, "dispositivo_testo": fms.descrivi_dispositivo(i)}
    if path == "/api/mobile/sysdiagnose":           # (2.20) sysdiagnose di un caso già creato: aggiungi, rileggi, togli
        import forense_mobile_sysdiagnose as fms
        case = _case(G)
        if G.PREP.running:
            raise ValueError(tr("Una preparazione è già in corso."))
        if b.get("remove"):
            con = sqlite3.connect(case.db_path)
            try:
                return {"ok": True, "righe": fms.togli(case, con, str(b["remove"]))}
            finally:
                con.close()
        if G.SES.busy:
            raise ValueError(tr("Attendi che l'agente finisca o interrompilo."))
        args = ["aggiungi", "--case", str(case.root), "sysdiagnose"]
        if b.get("add"):
            p = Path(G.clean_path(b.get("add")))
            if not p.is_file():
                raise ValueError(tr("File del sysdiagnose non trovato: {p}").format(p=p))
            fms.esamina(p)
            args += ["--file", str(p)]
        elif b.get("run"):
            args += ["--sha256", str(b["run"])]
        start(G, case.root, args, add="mobile_sysdiagnose")
        return {"root": str(case.root)}
    if path == "/api/mobile/keychain":              # (2.20) portachiavi di un caso già creato
        import forense_mobile_portachiavi as fmk
        case = _case(G)
        if G.PREP.running:
            raise ValueError(tr("Una preparazione è già in corso."))
        if b.get("remove"):
            fmk.togli(case)
            return {"ok": True}
        return {"ok": True, "portachiavi": fmk.imposta(case, G.clean_path(b.get("path")), lambda m: None)}
    if path == "/api/mobile/segreto":               # (2.20) un valore segreto, su richiesta (registrato)
        import forense_agent as fa
        import forense_mobile_portachiavi as fmk
        case = _case(G)
        con = fa.db_ro(case)
        try:
            return {"valore": fmk.segreto(case, con, b.get("id"), b.get("campo"))}
        finally:
            con.close()
    if path == "/api/mobile/check":
        dest = G.clean_path(b.get("dest")) if b.get("dest") else None
        if dest:
            G.check_dest(dest, create=False)
        return check(G.clean_path(b.get("path")), dest)
    if path == "/api/mobile/prepare":
        if G.PREP.running:
            raise ValueError(tr("Una preparazione è già in corso."))
        dest = None
        if b.get("dest"):
            dest, _free = G.check_dest(b.get("dest"))
        info = check(G.clean_path(b.get("path")), str(dest) if dest else None)
        if not info["ok"]:
            raise ValueError(info["error"])
        if info["case_exists"]:
            return {"root": info["case_root"], "existing": True}
        kc = G.clean_path(b.get("keychain")) if str(b.get("keychain") or "").strip() else None
        if kc:                                      # (2.20) portachiavi: controllato qui, registrato da «prepara»
            import forense_mobile_portachiavi as fmk
            if not Path(kc).is_file():
                raise ValueError(tr("File del portachiavi non trovato: {p}").format(p=kc))
            if not fmk.formato(kc)[0]:
                raise ValueError(tr("Il file non è un portachiavi leggibile da iLEAPP (plist con «genp»/«inet» o «keychainEntries»)."))
        sds = [G.clean_path(x) for x in (b.get("sysdiagnose") or []) if str(x or "").strip()]
        if sds:                                     # (2.20) sysdiagnose: controllati qui, registrati e letti da «prepara»
            import forense_mobile_sysdiagnose as fms
            for x in sds:
                if not Path(x).is_file():
                    raise ValueError(tr("File del sysdiagnose non trovato: {p}").format(p=x))
                fms.esamina(x)
        if info["decomprimere"] and not b.get("decomprimi"):
            raise ValueError(tr("L'estrazione è un tar compresso: per analizzarla serve la copia derivata decompressa "
                                "(spunta l'opzione)."))
        if dest:
            fa.register_case_home(dest)
            st = fa._raw_settings()
            st["ultima_cartella_casi"] = str(dest)
            fa.save_settings(st)
        else:
            fa.CASES_HOME.mkdir(parents=True, exist_ok=True)
        fuso = None
        if str(b.get("fuso") or "").strip():
            fuso = fa.fuso_valido(b.get("fuso"))
            if not fuso:
                raise ValueError(tr("Fuso orario non riconosciuto: usa un nome come Europe/Rome o UTC."))
        args = ["prepara", "--image", info["path"], "--case", info["case_root"],
                "--lingua", lg.valida(b.get("lingua") or lg.lingua())]
        tro = G.trascr_check(b.get("trascrizione"))         # (2.20) trascrizione scelta alla creazione del caso
        args += (["--trascrizione", json.dumps(tro)] if tro else [])
        args += (["--no-hash"] if b.get("no_hash") else []) + (["--hash-file"] if b.get("hash_file") else []) + \
                (["--leapp"] if b.get("leapp") else []) + (["--decomprimi"] if info["decomprimere"] else []) + \
                (["--fuso", fuso] if fuso else []) + (["--keychain", kc] if kc else []) + \
                (["--wa-backup"] if b.get("wa_backup") else []) + \
                [y for x in sds for y in ("--sysdiagnose", x)]
        inf = fa.info_caso_clean(b.get("info"))
        if inf:
            args += ["--info", json.dumps(inf, ensure_ascii=False)]
        start(G, Path(info["case_root"]), args)
        return {"root": info["case_root"], "existing": False}
    if path == "/api/mobile/addon":
        case = _case(G)
        what = b.get("what")
        if what not in ("chat", "leapp", "wa-backup"):
            raise ValueError(tr("Analisi sconosciuta."))
        if G.PREP.running:
            raise ValueError(tr("Una preparazione è già in corso."))
        if G.SES.busy:
            raise ValueError(tr("Attendi che l'agente finisca o interrompilo."))
        if not Path(case.meta.get("image", "")).exists():
            raise ValueError(tr("L'estrazione non è raggiungibile: collega il disco che la contiene."))
        start(G, case.root, ["aggiungi", "--case", str(case.root), what], add="mobile_" + what)
        return {"root": str(case.root)}
    if path == "/api/mobile/export_chat":
        return export_chat(G, _case(G), b)
    if path == "/api/mobile/leapp_folder":
        case = _case(G)
        rep = (case.meta.get("leapp") or {}).get("rapporto")
        if not rep:
            raise ValueError(tr("iLEAPP/ALEAPP non ancora eseguito."))
        G.reveal(case.root / rep)
        return {"ok": True}
    raise ValueError(tr("Richiesta sconosciuta: {path}").format(path=path))
