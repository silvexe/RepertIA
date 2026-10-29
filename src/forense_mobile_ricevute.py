# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - stati di consegna e lettura dei messaggi WhatsApp INVIATI da questo telefono.

Tabella `chat_receipts` del caso (una riga per stato e, dove la fonte lo dice, per destinatario): stato (inviato,
consegnato, letto, riprodotto, orario nella ricevuta), destinatario, data e ora (UTC) se il database le ha, fonte
(tabella/colonna o campo) e `verificato` (1 = significato verificato sui dati di prova pubblici, 0 = dalla
letteratura o dal nome della colonna). I casi analizzati prima non hanno la tabella: nessuna icona, nulla cambia.

Regole: solo i messaggi inviati (per i ricevuti il database non dice nulla di affidabile su chi li ha letti); nessuno
stato dedotto: se manca la data o il valore, lo stato non c'è. L'assenza di «letto» NON prova che il messaggio non
sia stato letto: le conferme di lettura si possono disattivare.

Verifiche sui dati di prova (immagini di Josh Hickman):
- Android 10 (WhatsApp 2.20.11, tabella `messages`): receipt_server_timestamp 0-1 s dopo l'invio, receipt_device_timestamp
  (uguale a `receipt_device`), read_device_timestamp presente su tutti i messaggi inviati con status 13.
- iOS 13.4.1 e iOS 15: ZMESSAGESTATUS = 8 su TUTTI i messaggi, inviati e ricevuti, in conversazioni con risposte: è
  compatibile con «consegnato» e con «letto», quindi si mostra solo «consegnato», come non verificato.
  ZWAMESSAGEINFO.ZRECEIPTINFO (protobuf): campo 2 = voci con un numero in BCD (in iOS 15 anche quello di questo
  telefono: non solo destinatari), campo 3 = un orario 0-3 s dopo l'invio (significato non verificato); gli altri
  campi delle voci sono a zero nei dati di prova, quindi non si interpretano.
- Schema Android dal 2022 (tabella `message`, `receipt_user`, `receipt_device`), Android 14 (WhatsApp 2.24): receipt_user
  receipt_timestamp = consegna (uguale a receipt_device_timestamp), read_timestamp = lettura (sempre dopo la consegna e
  prima della risposta), status 13 = letto, 5 = consegnato. Il primo messaggio inviato ha la consegna ma NON la lettura
  benché l'altra persona abbia risposto: esempio concreto di «assenza di letto» che non prova la mancata lettura.
  played_timestamp: nessun audio nei dati di prova (non verificato).
"""
import datetime as dt

from forense_lingua import tr, N_  # noqa: E402

SCHEMA = ("CREATE TABLE IF NOT EXISTS chat_receipts(id INTEGER PRIMARY KEY, msg INTEGER, destinatario TEXT, stato TEXT, "
          "ts TEXT, fonte TEXT, verificato INTEGER, nota TEXT);"
          "CREATE INDEX IF NOT EXISTS idx_cr_msg ON chat_receipts(msg);")
STATI = {"inviato": N_("inviato"), "consegnato": N_("consegnato"), "letto": N_("letto"), "riprodotto": N_("riprodotto"),
         "ricevuta": N_("orario nella ricevuta")}
LIVELLO = {"inviato": 1, "consegnato": 2, "letto": 3, "riprodotto": 4}
NOTA_IOS_8 = N_("valore 8 presente su tutti i messaggi, inviati e ricevuti, nei dati di prova: compatibile con "
                "«consegnato» e con «letto»; si indica solo «consegnato»")
NOTA_IOS_RICEVUTA = N_("campo 3 del protobuf: orario 0-3 s dopo l'invio nei dati di prova, significato non verificato")


def ensure(con):
    con.executescript(SCHEMA)


def svuota(con):
    ensure(con)
    con.execute("DELETE FROM chat_receipts")


def _ms(v):
    try:
        v = int(v or 0)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    if v > 10 ** 11:
        v = v / 1000
    return dt.datetime.fromtimestamp(v, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


class Scrittore:
    def __init__(self, con):
        self.con = con
        ensure(con)

    def add(self, msg, stato, ts, fonte, verificato, destinatario=None, nota=None):
        self.con.execute("INSERT INTO chat_receipts(msg, destinatario, stato, ts, fonte, verificato, nota) "
                         "VALUES (?,?,?,?,?,?,?)", (msg, destinatario, stato, ts, fonte, int(bool(verificato)), nota))


# ------------------------------------------------------------------------------------------- protobuf (iOS)

def _varint(b, i):
    r = s = 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7f) << s
        s += 7
        if not x & 0x80:
            return r, i


def _campi(b):
    """Campi di primo livello di un messaggio protobuf: [(numero, valore)]; valore int o bytes."""
    i, out = 0, []
    while i < len(b):
        k, i = _varint(b, i)
        f, w = k >> 3, k & 7
        if w == 0:
            v, i = _varint(b, i)
        elif w == 2:
            n, i = _varint(b, i)
            v = bytes(b[i:i + n])
            i += n
        elif w == 1:
            v, i = bytes(b[i:i + 8]), i + 8
        elif w == 5:
            v, i = bytes(b[i:i + 4]), i + 4
        else:
            raise ValueError(w)
        out.append((f, v))
    return out


def _bcd(b):
    """Numero in BCD come nei dati di prova: 0x81 + cifre, «f» di riempimento."""
    if not b or b[0] != 0x81:
        return None
    s = b[1:].hex().rstrip("f")
    return s if s.isdigit() else None


def ios(W, mid, frm, status, blob):
    if not frm:
        return
    if status == 8:
        W.add(mid, "consegnato", None, "ZWAMESSAGE.ZMESSAGESTATUS = 8", False, nota=tr(NOTA_IOS_8))
    if not blob:
        return
    try:
        campi = _campi(blob)
    except (IndexError, ValueError):
        return
    dest = []
    for f, v in campi:
        if f == 2 and isinstance(v, bytes):
            try:
                for f2, v2 in _campi(v):
                    if f2 == 1 and isinstance(v2, bytes):
                        n = _bcd(v2)
                        if n:
                            dest.append(n)
            except (IndexError, ValueError):
                pass
    for f, v in campi:
        if f == 3 and isinstance(v, int):
            nota = tr(NOTA_IOS_RICEVUTA)
            if dest:        # nei dati di iOS 15 c'è anche il numero di questo telefono: non sono solo destinatari
                nota += "; " + tr("numeri nel campo 2: {n}").format(n=", ".join("+" + x for x in dest))
            W.add(mid, "ricevuta", _ms(v), "ZWAMESSAGEINFO.ZRECEIPTINFO " + tr("campo 3"), False, None, nota)


# ------------------------------------------------------------------------------------------------ Android

def android_vecchio(W, mid, d, dispositivi, gruppo, jid):
    """Schema precedente (tabella messages). `dispositivi`: righe di receipt_device del messaggio; `gruppo`: righe
    di receipts con lo stesso key_id (ricevute per destinatario); `jid`: _id → raw_string."""
    if not d.get("key_from_me"):
        return
    for col, stato, ver in (("receipt_server_timestamp", "inviato", True), ("receipt_device_timestamp", "consegnato", True),
                            ("read_device_timestamp", "letto", True), ("played_device_timestamp", "riprodotto", False)):
        ts = _ms(d.get(col))
        if ts:
            W.add(mid, stato, ts, f"messages.{col}", ver)
    for r in dispositivi:
        ts = _ms(r.get("receipt_device_timestamp"))
        if ts:
            W.add(mid, "consegnato", ts, f"receipt_device #{r.get('_id')}", True,
                  jid.get(r.get("receipt_device_jid_row_id")) or f"jid #{r.get('receipt_device_jid_row_id')}")
    for r in gruppo:
        for col, stato in (("receipt_device_timestamp", "consegnato"), ("read_device_timestamp", "letto"),
                           ("played_device_timestamp", "riprodotto")):
            ts = _ms(r.get(col))
            if ts:
                W.add(mid, stato, ts, f"receipts.{col} #{r.get('_id')}", False, r.get("remote_resource"))
    if d.get("status") == 13 and not _ms(d.get("read_device_timestamp")):
        W.add(mid, "letto", None, "messages.status = 13", True)


def android(W, mid, d, utenti, dispositivi, jid):
    """Schema dal 2022 (tabella message): receipt_user e receipt_device del messaggio (verificato su Android 14)."""
    if not d.get("from_me"):
        return
    for r in utenti:
        dest = jid.get(r.get("receipt_user_jid_row_id")) or f"jid #{r.get('receipt_user_jid_row_id')}"
        for col, stato, ver in (("receipt_timestamp", "consegnato", True), ("read_timestamp", "letto", True),
                                ("played_timestamp", "riprodotto", False)):
            ts = _ms(r.get(col))
            if ts:
                W.add(mid, stato, ts, f"receipt_user.{col} #{r.get('_id')}", ver, dest)
    for r in dispositivi:
        ts = _ms(r.get("receipt_device_timestamp"))
        if ts:
            W.add(mid, "consegnato", ts, f"receipt_device #{r.get('_id')}", True,
                  jid.get(r.get("receipt_device_jid_row_id")) or f"jid #{r.get('receipt_device_jid_row_id')}")
    if d.get("status") == 13 and not utenti:
        W.add(mid, "letto", None, "message.status = 13", True)


# --------------------------------------------------------------------------------------------- lettura

def per_messaggi(con, ids):
    """{id messaggio: [{stato, etichetta, ts, destinatario, fonte, verificato, nota}]} (vuoto se il caso non ha la tabella)."""
    if not ids or not con.execute("SELECT 1 FROM sqlite_master WHERE name='chat_receipts'").fetchone():
        return {}
    import json
    out = {}
    for msg, dest, stato, ts, fonte, ver, nota in con.execute(
            "SELECT msg, destinatario, stato, ts, fonte, verificato, nota FROM chat_receipts WHERE msg IN "
            "(SELECT value FROM json_each(?)) ORDER BY msg, ts, id", (json.dumps(list(ids)),)):
        out.setdefault(msg, []).append({"stato": stato, "etichetta": tr(STATI.get(stato, stato)), "ts": ts,
                                        "destinatario": dest, "fonte": fonte, "verificato": bool(ver), "nota": nota})
    return out
