# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - chiamate lette direttamente dai database delle app (oltre a quelle ricavate da iLEAPP/ALEAPP).

Solo le fonti verificate sui dati di prova pubblici (immagini di Josh Hickman, attività documentate nei PDF):
- WhatsApp Android, `msgstore.db` tabella `call_log` (Android 10: le 2 chiamate del 08/02/2020 15:59 e 16:01 EST,
  video in arrivo ~1:10 e audio in uscita 1:10; ALEAPP non le estrae). Contatto certo: `jid_row_id` → tabella `jid`.
  Android 14 (WhatsApp 2.24, schema dal 2022): le 4 chiamate del 30/01/2024 con orari e durate come nel PDF; nella chat
  sono anche messaggi di tipo 90 collegati da `message_call_log` (il messaggio prende i dati della chiamata, nessun doppione).
- WhatsApp iOS, `CallHistory.sqlite` dell'app (ZWACDCALLEVENT + ZWAAGGREGATECALLEVENT + ZWACDCALLEVENTPARTICIPANT):
  estratto iOS 15 del collaudo, 4 chiamate con il JID dell'interlocutore della chat; nessuna documentazione delle
  attività per iOS 15, i campi (in arrivo, video, persa) si leggono dai nomi delle colonne. Le stesse righe sono anche
  in iLEAPP («WhatsApp - Call History»): la chiamata resta una, con le due fonti.
- Skype (iOS e Android), `s4l-*.db` tabella `calllogs` (JSON con inizio, risposta, fine, verso, esito): Android 10, 3
  chiamate con orari e durate uguali al PDF; iOS 13.4.1 2 chiamate (nessuna documentazione disponibile qui); iOS 17 8 e
  Android 14 4 chiamate, uguali al PDF.
- imo Android, `imofriends.db` tabella `calls_only`: una riga per contatto e tipo, l'elenco delle chiamate nel JSON di
  `imdata`. Android 10: 2 chiamate, Android 14: 4 chiamate, orario e tipo uguali al PDF; la durata non c'è.

Restano fuori (documentato nel manuale): registro di sistema ↔ app (nelle immagini di prova nessuna app VoIP compare
in CallHistory.storedata né in calllog.db), Threads (stesse chiamate dell'account Instagram già nelle Chiamate),
LINE iOS e Snapchat (nessun riscontro), app cifrate (Signal, Wickr).

Ogni chiamata ha la forma dei record di forense_mobile_leapp_chat.calls_from_leapp, che le unisce a quelle di
iLEAPP/ALEAPP (stesso numero entro pochi secondi = stessa chiamata, con le fonti di entrambe).
"""
import datetime as dt
import json
import re
from pathlib import Path

from forense_lingua import tr, N_  # noqa: E402

STRUMENTO = "RepertIA"
FONTI = {
    "wa_android": re.compile(r"(^|/)com\.whatsapp(\.w4b)?/databases/msgstore\.db$"),
    "wa_ios": re.compile(r"(^|/)(Shared/AppGroup|Data/Application)/[^/]+/(Documents/)?CallHistory\.sqlite$"),
    "skype": re.compile(r"(^|/)(com\.skype\.raider/databases|Library/LocalDatabase|Shared/AppGroup/[^/]+)/s4l-[^/]+\.db$"),
    "wa_ios_chat": re.compile(r"(^|/)Shared/AppGroup/[^/]+/ChatStorage\.sqlite$"),
    "imo_android": re.compile(r"(^|/)com\.imo\.android\.imous/databases/imofriends\.db$"),
}
APP = {"wa_android": "WhatsApp", "wa_ios": "WhatsApp", "wa_ios_chat": "WhatsApp", "skype": "Skype", "imo_android": "imo"}
# esito di call_log.call_result: 5 = chiamata avvenuta (le 2 chiamate documentate di Android 10, entrambe risposte)
WA_AND_ESITO = {5: N_("connessa")}
NOTA_IMO = N_("imo non registra la durata nella tabella calls_only")
NOTA_59 = N_("orario d'inizio dal messaggio WhatsApp di tipo 59 della chat")


def _iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S") if t else None


def _unix(v, div=1):
    try:
        v = float(v) / div
    except (TypeError, ValueError):
        return None
    return dt.datetime.fromtimestamp(v, dt.timezone.utc) if v > 0 else None


def _apple(v):
    try:
        return dt.datetime(2001, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=float(v))
    except (TypeError, ValueError):
        return None


def _iso8601(s):
    """«2020-02-01T21:09:43.8643568Z» (7 decimali di Skype) → datetime UTC."""
    if not s:
        return None
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?Z?$", str(s))
    if not m:
        return None
    t = dt.datetime.fromisoformat(m.group(1)).replace(tzinfo=dt.timezone.utc)
    return t + dt.timedelta(seconds=float(m.group(2) or 0))


def _rec(app, ts, verso, numero, fonte, src, durata=None, fine=None, tipo=None, esito=None, risposta=None,
         nome_app=None, nota=None, chat=None, toll=5.0):
    return {"app": app, "debole": False, "toll": toll, "ts": _iso(ts), "fine": _iso(fine), "verso": verso,
            "numero": numero, "nome_app": nome_app, "durata_s": durata, "tipo": tipo, "esito": esito, "account": None,
            "nota": nota, "risposta": risposta, "fonti": [fonte], "src": src, "chat": chat}


def meta59(blob):
    """Messaggio WhatsApp iOS di tipo 59 (chiamata): ZWAMEDIAITEM.ZMETADATA, protobuf campo 87 → 1 → {1: video,
    3: durata in secondi, 5: {1: JID}}. Verificato su iOS 17.3 (4 chiamate, valori uguali a CallHistory.sqlite).
    Restituisce {"video": bool, "durata_s": int, "jid": str} o None."""
    import forense_mobile_ricevute as fmr
    if not blob:
        return None
    try:
        f87 = next((v for f, v in fmr._campi(bytes(blob)) if f == 87 and isinstance(v, bytes)), None)
        f1 = next((v for f, v in fmr._campi(f87) if f == 1 and isinstance(v, bytes)), None) if f87 else None
        if not f1:
            return None
        c = dict(fmr._campi(f1))
        jid = None
        if isinstance(c.get(5), bytes):
            j = dict(fmr._campi(c[5])).get(1)
            jid = j.decode("utf-8", "replace") if isinstance(j, bytes) else None
        return {"video": bool(c.get(1)), "durata_s": c.get(3) if isinstance(c.get(3), int) else None, "jid": jid}
    except (IndexError, ValueError, TypeError):
        return None


def etichetta_chiamata(tipo, verso, durata, esito=None):
    import forense_mobile_leapp_chat as fmlc
    return " · ".join(x for x in (
        tr("chiamata {t} {v}").format(t=tipo or "", v=tr(fmlc.VERSI[verso]) if verso in fmlc.VERSI else "").replace("  ", " ").strip(),
        fmlc.hms(durata) if durata is not None else None, esito) if x)


def _fonte(db, tabella, riga):
    return {"strumento": STRUMENTO, "artefatto": f"{db} · {tabella}", "riga": riga, "tabella": tabella}


# ------------------------------------------------------------------------------------------- lettori

def wa_android(w, src):
    t = w.tables()
    if "call_log" not in t:
        return []
    jid = {r["_id"]: r["raw_string"] for r in w.db.execute("SELECT _id, raw_string FROM jid")} if "jid" in t else {}
    out = []
    for r in w.db.execute("SELECT * FROM call_log ORDER BY timestamp"):
        d = dict(r)
        j = jid.get(d.get("jid_row_id"))
        res = d.get("call_result")
        dur = d.get("duration")
        out.append(_rec("WhatsApp", _unix(d.get("timestamp"), 1000), "out" if d.get("from_me") else "in", j,
                        _fonte("msgstore.db", "call_log", d.get("_id")), src, float(dur) if dur is not None else None,
                        tipo=tr("video") if d.get("video_call") else tr("voce"),
                        esito=tr(WA_AND_ESITO[res]) if res in WA_AND_ESITO else (tr("esito {n}").format(n=res) if res is not None else None),
                        risposta=True if res == 5 else None,
                        chat={"jid": j, "id": d.get("call_id")}))
    return out


def wa_ios(w, src):
    t = w.tables()
    if "zwacdcallevent" not in t:
        return []
    agg = {r["Z_PK"]: dict(r) for r in w.db.execute("SELECT * FROM ZWAAGGREGATECALLEVENT")} if "zwaaggregatecallevent" in t else {}
    part = {}
    if "zwacdcalleventparticipant" in t:
        for r in w.db.execute("SELECT * FROM ZWACDCALLEVENTPARTICIPANT"):
            part.setdefault(r["Z1PARTICIPANTS"], []).append(r["ZJIDSTRING"])
    cols = {r[1].upper() for r in w.db.execute("PRAGMA table_info(ZWACDCALLEVENT)")}
    out = []
    for r in w.db.execute("SELECT * FROM ZWACDCALLEVENT ORDER BY ZDATE"):
        d = dict(r)
        a = agg.get(d.get("Z1CALLEVENTS")) if "Z1CALLEVENTS" in cols else None
        a = a or {}
        jids = [x for x in part.get(d.get("Z_PK"), []) if x]
        persa = bool(a.get("ZMISSED"))
        verso = ("persa" if persa else "in") if a.get("ZINCOMING") else "out" if a else "unk"
        dur = d.get("ZDURATION")
        out.append(_rec("WhatsApp", _apple(d.get("ZDATE")), verso, jids[0] if len(jids) == 1 else ", ".join(jids) or None,
                        _fonte("CallHistory.sqlite", "ZWACDCALLEVENT", d.get("Z_PK")), src,
                        int(float(dur)) if dur is not None else None,      # secondi interi, come iLEAPP
                        tipo=(tr("video") if a.get("ZVIDEO") else tr("voce")) if a else None,
                        risposta=(not persa) if a else None,
                        nota=tr("partecipanti: {p}").format(p=", ".join(jids)) if len(jids) > 1 else None,
                        chat={"jid": jids[0] if len(jids) == 1 else None, "id": d.get("Z_PK")}))
    return out


def skype(w, src):
    if "calllogs" not in w.tables():
        return []
    out = []
    for k, v in w.db.execute("SELECT nsp_pk, nsp_data FROM calllogs"):
        try:
            d = json.loads(v)
        except (TypeError, ValueError):
            continue
        ini, con, fin = _iso8601(d.get("startTime")), _iso8601(d.get("connectTime")), _iso8601(d.get("endTime"))
        out_ = (d.get("callDirection") or "").lower() == "outgoing"
        altro = d.get("target") if out_ else d.get("originator")
        pp = (d.get("targetParticipant") if out_ else d.get("originatorParticipant")) or {}
        stato = d.get("callState")
        out.append(_rec("Skype", ini, "out" if out_ else "in", altro, _fonte(Path(src[2]).name, "calllogs", k), src,
                        (fin - con).total_seconds() if con and fin else None, fine=fin,
                        tipo=d.get("callType"), esito=stato, risposta=True if con else (False if stato else None),
                        nome_app=pp.get("displayName")))
    return out


def imo_android(w, src):
    if "calls_only" not in w.tables():
        return []
    out = []
    for r in w.db.execute("SELECT * FROM calls_only ORDER BY timestamp"):
        d = dict(r)
        # una riga per contatto e tipo (l'ultima chiamata); l'elenco di tutte le chiamate è nel JSON di imdata
        # (Android 10: una voce uguale alla riga; Android 14: 2 voci per riga, uscita e arrivo, orari come nel PDF)
        try:
            voci = [v for v in json.loads(d.get("imdata") or "[]") if isinstance(v, dict) and v.get("timestamp")]
        except (TypeError, ValueError):
            voci = []
        for i, v in enumerate(voci or [{"chat_type": d.get("chat_type"), "timestamp": d.get("timestamp")}]):
            ct = (v.get("chat_type") or "").lower()
            verso = "out" if ct.startswith("outgoing") else "persa" if "missed" in ct else "in" if ct.startswith("incoming") else "unk"
            f = _fonte("imofriends.db", "calls_only", d.get("_id"))
            if voci:
                f["campo"] = f"imdata[{i}]"
            out.append(_rec("imo", _unix(v.get("timestamp"), 1e9), verso, d.get("buid"), f, src,
                            tipo=tr("video") if "video" in ct or (d.get("call_type") or "") == "video" else tr("voce"),
                            esito=v.get("chat_type"), nome_app=d.get("name"), nota=tr(NOTA_IMO)))
    out.sort(key=lambda r: r["ts"] or "")
    return out


def nella_chat(W, recs, tabella, names=None):
    """Chiamate WhatsApp come eventi della conversazione con lo stesso JID (solo se la conversazione esiste: contatto
    abbinato con certezza). W = Writer del database delle chiamate con le conversazioni del lettore della chat."""
    import forense_mobile_leapp_chat as fmlc
    import forense_mobile_chat as fmc
    import datetime as _dt
    import json as _json
    n = 0
    for r in recs:
        jid = (r.get("chat") or {}).get("jid")
        th = W.threads.get(jid) if jid else None
        if not th or not r.get("ts"):
            continue
        v = r["verso"]
        # stessa chiamata già nella chat come messaggio di tipo 59 (WhatsApp iOS recente): nessun doppione, al
        # messaggio si aggiunge la seconda fonte (e l'orario se diverso)
        t = _dt.datetime.fromisoformat(r["ts"])
        dup = None
        for mid, mts, ex in W.con.execute(
                "SELECT id, ts, extra FROM chat_messages WHERE thread=? AND kind='chiamata' AND src_table='ZWAMESSAGE' "
                "AND direction=?", (th, "out" if v == "out" else "in")):
            dd = (t - _dt.datetime.fromisoformat(mts)).total_seconds()
            if -15 <= dd <= (r.get("durata_s") or 0) + 15:
                dup = (mid, mts, _json.loads(ex or "{}"))
                break
        if dup:
            mid, mts, ex = dup
            ex["fonte_chiamata"] = " + ".join(x for x in (ex.get("fonte_chiamata"), r["fonti"][0]["artefatto"]) if x)
            if r["ts"] != mts:
                ex["orario_altra_fonte"] = {"fonte": r["fonti"][0]["artefatto"], "ts": r["ts"]}
            W.con.execute("UPDATE chat_messages SET extra=? WHERE id=?", (_json.dumps(ex, ensure_ascii=False), mid))
            continue
        lbl = etichetta_chiamata(r.get("tipo"), v, r.get("durata_s"), r.get("esito"))
        W.message(th, r["ts"], "out" if v == "out" else "in", "" if v == "out" else jid, None, "chiamata", tabella,
                  r["fonti"][0]["riga"], service="WhatsApp",
                  sender_name=None if v == "out" else (names or {}).get(fmc.norm_number(jid)),
                  extra={"tipo": lbl, "codice": "chiamata", "verificato": True, "durata_s": r.get("durata_s"),
                         "risposta": r.get("risposta"), "fonte_chiamata": r["fonti"][0]["artefatto"]})
        n += 1
    return n


def wa_ios_chat(w, src):
    """Chiamate dai messaggi WhatsApp iOS di tipo 59 (orario d'inizio come nella chat: per le chiamate in uscita di
    WhatsApp 24.x CallHistory.sqlite registra un orario più tardi di circa la durata — iOS 17.3, 2 chiamate)."""
    t = w.tables()
    if not {"zwamessage", "zwamediaitem", "zwachatsession"} <= t:
        return []
    out = []
    for r in w.db.execute("SELECT m.Z_PK, m.ZISFROMME, m.ZMESSAGEDATE, s.ZCONTACTJID, i.ZMETADATA FROM ZWAMESSAGE m "
                          "LEFT JOIN ZWAMEDIAITEM i ON i.Z_PK = m.ZMEDIAITEM LEFT JOIN ZWACHATSESSION s ON s.Z_PK = m.ZCHATSESSION "
                          "WHERE m.ZMESSAGETYPE = 59 ORDER BY m.ZMESSAGEDATE"):
        d = dict(r)
        m = meta59(d.get("ZMETADATA")) or {}
        jid = m.get("jid") or d.get("ZCONTACTJID")
        dur = m.get("durata_s")
        out.append(_rec("WhatsApp", _apple(d.get("ZMESSAGEDATE")), "out" if d.get("ZISFROMME") else "in", jid,
                        _fonte("ChatStorage.sqlite", "ZWAMESSAGE", d.get("Z_PK")), src, dur,
                        tipo=(tr("video") if m.get("video") else tr("voce")) if m else None,
                        risposta=True if dur else None, nota=tr(NOTA_59),
                        toll=float((dur or 0) + 15)))     # stessa chiamata in CallHistory.sqlite fino a durata + 15 s dopo
    return out


LETTORI = {"wa_ios_chat": wa_ios_chat, "wa_android": wa_android, "wa_ios": wa_ios, "skype": skype, "imo_android": imo_android}


def raccogli(case, con, avvisi=None):
    """Chiamate di tutte le fonti verificate dell'estrazione: (record, {fonte: righe})."""
    import forense_mobile as fm
    import forense_mobile_chat as fmc
    recs, usate, visti = [], {}, set()
    for p in fm.sorgenti(case):
        part = int(p["offset"])
        m = fm.mx(case)
        try:
            files = m.execute("SELECT id, path FROM mobile_files WHERE part=? AND isdir=0 AND (path LIKE '%.db' OR "
                              "path LIKE '%.sqlite')", (part,)).fetchall()
        finally:
            m.close()
        for inode, path in files:
            for kind, rx in FONTI.items():
                if not rx.search(path):
                    continue
                h = fmc._sha_db(case, part, inode)      # copie identiche (es. mirror di Magisk): una volta sola
                if h in visti:
                    break
                visti.add(h)
                try:
                    w = fmc.WorkDB(case, part, inode, path, con)
                except Exception as e:
                    if avvisi is not None:
                        avvisi.append(f"{path}: {type(e).__name__}: {e}")
                    break
                try:
                    rr = LETTORI[kind](w, (part, str(inode), path))
                except Exception as e:
                    rr = []
                    if avvisi is not None:
                        avvisi.append(f"{path}: {type(e).__name__}: {e}")
                finally:
                    w.close()
                if rr:
                    recs += rr
                    k = f"{STRUMENTO}|{rr[0]['fonti'][0]['artefatto']}"
                    usate[k] = usate.get(k, 0) + len(rr)
                break
    return recs, usate
