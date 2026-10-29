# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - tipi dei messaggi di WhatsApp: valore del database → genere del messaggio ed etichetta.

iOS: `ChatStorage.sqlite`, colonna `ZWAMESSAGE.ZMESSAGETYPE`. Android: `msgstore.db`, colonna `message.message_type`
(schema dal 2022) o `messages.media_wa_type` (schema precedente). WhatsApp non documenta questi valori e li cambia tra
le versioni: ogni voce dice su quali dati di prova pubblici è stata verificata; le voci senza verifica vengono dalla
letteratura e sono mostrate come «non verificate». Un valore che non è in tabella NON diventa «allegato»: il messaggio
compare come «[tipo N non gestito]», con il valore grezzo.

Genere (colonna `kind` di chat_messages): «allegato» solo per i file (immagine, video, audio, documento, GIF, sticker);
gli altri generi sono «testo», «sistema», «eliminato», «posizione», «contatto», «link», «sondaggio», «chiamata» e
«non gestito». Nel dettaglio (`extra`) restano l'etichetta (`tipo`), il valore grezzo (`codice`) e `verificato`.
"""
import json

from forense_lingua import tr, N_  # noqa: E402

# dati di prova pubblici usati per la verifica (immagini di Josh Hickman)
H_IOS13 = "iOS 13.4.1 (Hickman, WhatsApp 2020)"
H_IOS15 = "iOS 15 (Hickman, estratti dei test di iLEAPP, collaudo)"
H_AND10 = "Android 10 Pixel 3 (Hickman, WhatsApp 2.20.11)"
H_IOS17 = "iOS 17.3 (Hickman, WhatsApp 24.1)"
H_AND14 = "Android 14 Pixel 7a (Hickman, WhatsApp 2.24)"

# valore: (genere, etichetta, verificato su — None = non verificato sui dati di prova)
IOS = {
    0: ("testo", N_("testo"), H_IOS13 + "; " + H_IOS15),
    1: ("allegato", N_("immagine"), H_IOS13 + "; " + H_IOS15),        # .jpg in Message/Media, «Picture sent/received»
    2: ("allegato", N_("video"), None),
    3: ("allegato", N_("audio"), None),
    4: ("contatto", N_("contatto"), None),
    5: ("posizione", N_("posizione"), H_IOS13 + "; " + H_IOS15),       # ZLATITUDE/ZLONGITUDE nel media item
    6: ("sistema", N_("evento del gruppo"), H_IOS15),                   # solo nei gruppi, ZGROUPEVENTTYPE 2 e 12
    7: ("link", N_("link"), None),
    8: ("allegato", N_("documento"), None),
    # primo messaggio di OGNI conversazione (6 casi su 6, gruppi e singole), senza testo, non inviato, stesso istante
    # della creazione della chat: avviso di sistema di inizio conversazione (nelle versioni precedenti era «chiamata»)
    10: ("sistema", N_("avviso di sistema all'inizio della conversazione"), H_IOS13 + "; " + H_IOS15),
    11: ("allegato", N_("GIF"), None),
    14: ("eliminato", N_("messaggio eliminato"), None),
    15: ("allegato", N_("sticker"), None),
    46: ("sondaggio", N_("sondaggio"), None),
    # 4 righe agli orari esatti delle 4 chiamate del 30/01/2024 documentate, verso = ZISFROMME; nel media item
    # (ZMETADATA, protobuf campo 87.1) video sì/no e durata uguali a CallHistory.sqlite (forense_mobile_chiamate.meta59)
    59: ("chiamata", N_("chiamata"), H_IOS17),
}

# schema precedente (tabella messages, colonna media_wa_type); i messaggi di sistema si riconoscono da status = 6
ANDROID_VECCHIO = {
    0: ("testo", N_("testo"), H_AND10),
    1: ("allegato", N_("immagine"), H_AND10),                           # image/jpeg, «Picture received/sent»
    2: ("allegato", N_("audio"), None),
    3: ("allegato", N_("video"), None),
    4: ("contatto", N_("contatto"), None),
    5: ("posizione", N_("posizione"), H_AND10),                         # «Shared static location», latitude/longitude
    9: ("allegato", N_("documento"), None),
    # video/mp4 negli stati di WhatsApp (status@broadcast); che sia una GIF non è verificato, il formato sì
    13: ("allegato", N_("GIF"), None),
    15: ("eliminato", N_("messaggio eliminato"), None),
    16: ("posizione", N_("posizione in tempo reale"), H_AND10),         # «Shared live location», «Here I am!!»
    20: ("allegato", N_("sticker"), None),
}

# schema dal 2022 (tabella message, colonna message_type): nessun dato di prova pubblico con questa tabella piena
ANDROID = {
    0: ("testo", N_("testo"), H_AND14),
    1: ("allegato", N_("immagine"), H_AND14),          # foto inviata e ricevuta del 30/01/2024 (con message_media)
    2: ("allegato", N_("audio"), None),
    3: ("allegato", N_("video"), None),
    4: ("contatto", N_("contatto"), None),
    5: ("posizione", N_("posizione"), H_AND14),         # posizione inviata e ricevuta del 26/07/2024
    7: ("sistema", N_("evento di sistema"), H_AND14),
    9: ("allegato", N_("documento"), None),
    13: ("allegato", N_("GIF"), None),
    15: ("eliminato", N_("messaggio eliminato"), None),
    16: ("posizione", N_("posizione in tempo reale"), H_AND14),   # condivisione inviata e ricevuta del 26/07/2024
    20: ("allegato", N_("sticker"), None),
    42: ("allegato", N_("vista unica"), None),
    43: ("allegato", N_("vista unica"), None),
    64: ("eliminato", N_("messaggio eliminato dall'amministratore"), None),
    # chiamata: riga collegata a call_log da message_call_log (4 chiamate del 30/01/2024, orari e durate come nel PDF)
    90: ("chiamata", N_("chiamata"), H_AND14),
}

TABELLE = {"ios": IOS, "android": ANDROID, "android_vecchio": ANDROID_VECCHIO}
GENERI = ("testo", "allegato", "sistema", "eliminato", "posizione", "contatto", "link", "sondaggio", "chiamata",
          "non gestito")


def classifica(schema, codice, sistema=False):
    """(genere, extra) per il valore `codice` dello schema «ios», «android» o «android_vecchio».

    extra = {"tipo": etichetta tradotta, "codice": valore grezzo, "verificato": bool}. `sistema`: riga già riconosciuta
    come evento di sistema da un altro campo (schema precedente di Android: status = 6, verificato su H_AND10)."""
    if sistema:
        return "sistema", {"tipo": tr("evento di sistema"), "codice": codice, "verificato": True}
    try:
        c = int(codice or 0)
    except (TypeError, ValueError):
        c = codice
    v = TABELLE[schema].get(c)
    if v is None:
        return "non gestito", {"tipo": tr("tipo {n} non gestito").format(n=c), "codice": c, "verificato": False}
    genere, etichetta, verificato = v
    return genere, {"tipo": tr(etichetta), "codice": c, "verificato": bool(verificato)}


# (2.20) Avvisi di sistema di WhatsApp Android (schema dal 2022): message.message_type = 7 con una riga in message_system.
# Sono avvisi che l'app inserisce da sola nella conversazione (gruppo creato, persone aggiunte o uscite, nome o foto
# cambiati, codice di sicurezza, crittografia…): nessuno li ha scritti, anche se il database li segna from_me = 1.
# message_system.action_type dice di quale avviso si tratta, ma WhatsApp non ne pubblica il significato e non è stato
# verificato sui dati di prova (lo dichiara anche ALEAPP, modulo «WhatsApp - System Events»): si mostra il codice così
# com'è e solo i dettagli scritti nelle tabelle accessorie, senza interpretarli.
AVVISO = N_("avviso generato da WhatsApp (non scritto da una persona)")


# Interpretazione dei codici (message_system.action_type) dalle fonti pubbliche, con il livello:
#   «concorde»: le due fonti indipendenti dicono la stessa cosa (e, dove ci sono, i dati di prova sono coerenti);
#   «probabile»: una sola fonte (o le fonti non coincidono del tutto).
# Fonti: WAInsight (github.com/akhil-dara/WAInsight, MIT, backend/app/models/enums.py, SYSTEM_ACTION_LABELS: «verificata
# sull'APK di WhatsApp decompilato con JADX e confrontata con lo schermo del telefono»); WhatsApp-Chat-Exporter
# (github.com/KnugiHK/WhatsApp-Chat-Exporter, MIT, Whatsapp_Chat_Exporter/utility.py, determine_metadata). Nessuna delle
# due è una verifica su un telefono di prova documentato: per questo nessun codice è «verificato».
# Dati di prova (H_AND14): 11 = testo uguale al nome del gruppo e data uguale alla creazione della chat (3 su 3); 12 con
# is_me_joined = 1 indica il numero del telefono stesso; 67 è il primo messaggio di ogni chat (47 su 47). In 13, 14 e 20
# c'è solo la persona indicata, che non distingue un significato dall'altro: per loro nessuna «coerenza con i dati».
F_WAI = "WAInsight (enums.py)"
F_WCE = "WhatsApp-Chat-Exporter (utility.py)"
AZIONI_ANDROID = {
    # codice: (frase, livello, fonti, coerente con i dati di prova)
    1: (N_("nome del gruppo cambiato"), "concorde", (F_WAI, F_WCE), None),
    5: (N_("persona uscita dal gruppo"), "concorde", (F_WAI, F_WCE), None),
    6: (N_("immagine del gruppo cambiata"), "concorde", (F_WAI, F_WCE), None),
    10: (N_("numero di telefono cambiato"), "concorde", (F_WAI, F_WCE), None),
    11: (N_("gruppo creato"), "concorde", (F_WAI, F_WCE), H_AND14),
    12: (N_("persone aggiunte al gruppo"), "concorde", (F_WAI, F_WCE), H_AND14),
    13: (N_("persona uscita dal gruppo"), "concorde", (F_WAI, F_WCE), None),
    14: (N_("persone rimosse dal gruppo"), "concorde", (F_WAI, F_WCE), None),
    18: (N_("codice di sicurezza cambiato"), "concorde", (F_WAI, F_WCE), None),
    20: (N_("persona entrata nel gruppo con il link d'invito"), "concorde", (F_WAI, F_WCE), None),
    27: (N_("descrizione del gruppo cambiata"), "concorde", (F_WAI, F_WCE), None),
    28: (N_("numero di telefono cambiato"), "concorde", (F_WAI, F_WCE), None),
    58: (N_("contatto bloccato o sbloccato"), "concorde", (F_WAI, F_WCE), None),
    15: (N_("nominato amministratore"), "probabile", (F_WAI,), None),
    21: (N_("link d'invito del gruppo reimpostato"), "probabile", (F_WAI,), None),
    56: (N_("timer dei messaggi effimeri cambiato"), "concorde", (F_WAI, F_WCE), None),
    59: (N_("timer dei messaggi effimeri cambiato"), "probabile", (F_WAI,), None),
    67: (N_("avviso «messaggi e chiamate crittografati end-to-end»"), "probabile", (F_WAI,), H_AND14),
    83: (N_("richiesta di entrare nel gruppo"), "probabile", (F_WAI,), None),
    84: (N_("nominato amministratore"), "probabile", (F_WAI,), None),
    92: (N_("impostazione: solo gli amministratori possono aggiungere persone"), "probabile", (F_WAI,), None),
}
LIVELLI_AZIONE = {"concorde": N_("concorde in 2 fonti pubbliche"), "probabile": N_("probabile, 1 fonte")}


def interpreta_azione(a):
    """Frase, livello e fonti di un avviso (dizionario di avvisi_android); None per i codici non interpretati."""
    v = AZIONI_ANDROID.get(a.get("azione"))
    if not v:
        return None
    frase, livello, fonti, dati = v
    frase = tr(frase)
    if a.get("azione") == 12 and a.get("unito_io") == 1:
        frase = tr("questo telefono è stato aggiunto al gruppo")
    lv = tr(LIVELLI_AZIONE[livello]) + ((" " + tr("e coerente con i dati di prova")) if dati else "")
    return {"frase": frase, "livello": livello, "livello_lbl": lv, "fonti": list(fonti), "dati_prova": dati}


# (2.20) Avvisi di sistema di WhatsApp iOS (ChatStorage.sqlite, ZWAMESSAGE): ZMESSAGETYPE 6 (nei gruppi) e 10 (inizio della
# conversazione). Nessuna fonte pubblica spiega ZGROUPEVENTTYPE: WhatsApp-Chat-Exporter (ios_handler.py,
# process_metadata_message) usa solo il testo non numerico («nome del gruppo cambiato»); iLEAPP («WhatsApp - Group
# Events», 2026, 13 immagini di prova) dichiara che il valore non ha tabella di decodifica; WAInsight è solo per Android.
# Per questo si riportano i valori come registrati e solo FATTI ricavati dal database stesso. Dati di prova (H_IOS13,
# H_IOS15, H_IOS17): ZGROUPEVENTTYPE = 2 compare anche su TUTTI i messaggi ricevuti (non indica un evento); il tipo 6 con
# valore 12 è nello stesso secondo di ZWAGROUPINFO.ZCREATIONDATE in 4 gruppi su 4; il tipo 10 è il primo per ZSORT in
# ogni conversazione, anche quando il suo orario è più tardi (iOS 17, «Liz Dehner»: 30 minuti dopo il primo messaggio).
F_WCE_IOS = "WhatsApp-Chat-Exporter (ios_handler.py)"


def avviso_ios(d, creazione=None, pos=None):
    """Dettaglio di un avviso di WhatsApp iOS: valori registrati, fatti dal database, interpretazione (solo il cambio
    di nome del gruppo, 1 fonte). `creazione`: ZWAGROUPINFO.ZCREATIONDATE del gruppo; `pos`: (posizione per ZSORT,
    posizione per orario) nella conversazione, 1 = primo."""
    mt, txt = d.get("ZMESSAGETYPE"), d.get("ZTEXT")
    a = {"db": "ChatStorage.sqlite", "tabelle": ["ZWAMESSAGE"], "tipo_messaggio": mt, "evento": d.get("ZGROUPEVENTTYPE"),
         "fatti": []}
    if mt == 6 and txt and not txt.strip().isdigit():
        a["interpretazione"] = {"frase": tr("nome del gruppo cambiato in «{t}»").format(t=txt), "livello": "probabile",
                                "livello_lbl": tr(LIVELLI_AZIONE["probabile"]), "fonti": [F_WCE_IOS], "dati_prova": None}
    if creazione is not None and d.get("ZMESSAGEDATE") is not None and abs(d["ZMESSAGEDATE"] - creazione) < 1:
        a["fatti"].append(tr("registrato nello stesso secondo della creazione del gruppo (ZWAGROUPINFO.ZCREATIONDATE)"))
        a["tabelle"].append("ZWAGROUPINFO")
    if pos:
        s, o = pos
        if mt == 10 and s == 1:
            a["fatti"].append(tr("primo messaggio della conversazione nell'ordine di WhatsApp (ZSORT)"))
        if o is not None and s != o:
            a["fatti"].append(tr("nell'ordine di WhatsApp (ZSORT) è il n. {s} della conversazione, per orario il n. {o}")
                              .format(s=s, o=o))
    return a


def avvisi_android(db, jid, names=None, norm=None):
    """{message._id: {"azione": action_type, "persone": [...], "unito_io": is_me_joined, "valore_precedente": old_data,
    "numero_vecchio": …, "numero_nuovo": …, "tabelle": [...]}} dalle tabelle message_system* (quelle che ci sono)."""
    have = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'message_system%'")}
    if "message_system" not in have:
        return {}
    names = names or {}

    def chi(row_id):
        j = jid.get(row_id) or f"jid #{row_id}"
        n = names.get(norm(j)) if norm else None
        return f"{n} ({j})" if n else j
    out = {r[0]: {"azione": r[1], "tabelle": ["message_system"]}
           for r in db.execute("SELECT message_row_id, action_type FROM message_system")}
    if "message_system_chat_participant" in have:
        for mid, uj in db.execute("SELECT message_row_id, user_jid_row_id FROM message_system_chat_participant "
                                  "ORDER BY message_row_id, rowid"):
            if mid in out:
                e = out[mid]
                e.setdefault("persone", []).append(chi(uj))
                if "message_system_chat_participant" not in e["tabelle"]:
                    e["tabelle"].append("message_system_chat_participant")
    for tab, cols, conv in (("message_system_group", "is_me_joined", lambda r: {"unito_io": r[0]}),
                            ("message_system_value_change", "old_data", lambda r: {"valore_precedente": r[0]}),
                            ("message_system_number_change", "old_jid_row_id, new_jid_row_id",
                             lambda r: {"numero_vecchio": chi(r[0]) if r[0] else None, "numero_nuovo": chi(r[1]) if r[1] else None})):
        if tab in have:
            try:
                for r in db.execute(f"SELECT message_row_id, {cols} FROM {tab}"):
                    if r[0] in out:
                        out[r[0]].update({k: v for k, v in conv(r[1:]).items() if v is not None})
                        out[r[0]]["tabelle"].append(tab)
            except Exception:       # colonne diverse in altre versioni: si tiene quello che si è letto
                pass
    for e in out.values():
        i = interpreta_azione(e)
        if i:
            e["interpretazione"] = i
    return out


def etichetta(kind, extra=None):
    """Testo fra parentesi quadre di un messaggio senza testo: «tipo N non gestito» (dal dettaglio del messaggio) per
    i tipi non gestiti, altrimenti il genere tradotto come nelle versioni precedenti."""
    if kind == "non gestito":
        ex = extra
        if isinstance(ex, str):
            try:
                ex = json.loads(ex)
            except ValueError:
                ex = None
        if isinstance(ex, dict) and ex.get("tipo"):
            return ex["tipo"]
    return tr(kind or "")


def tabella_md(schema):
    """Tabella della mappa per il manuale e il report: valore, genere, etichetta, verifica."""
    L = ["| " + " | ".join((tr("Valore"), tr("Genere"), tr("Etichetta"), tr("Verificato su"))) + " |", "|---|---|---|---|"]
    for c, (g, e, v) in sorted(TABELLE[schema].items()):
        L.append(f"| {c} | {tr(g)} | {tr(e)} | {v or tr('non verificato')} |")
    return "\n".join(L)
