# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Riferimenti della validazione Android 14 (Pixel 7a) di Joshua Hickman, presi SOLO dai documenti allegati all'immagine:
- Android14-ImageCreation.pdf (documentazione di creazione di Hickman): ora locale, UTC-5 fino al 2024-03-10, poi UTC-4;
- EXTRACTION_FFS.ufd e SummaryReport.pdf (riepilogo dell'acquisizione allegato all'estrazione): identità e SHA-256.
Le ore sono convertite in UTC (minuto) per il confronto; i testi sono abbreviati a un frammento distintivo."""
from datetime import datetime, timedelta


def utc(data, ora):
    t = datetime.strptime(f"{data} {ora}", "%Y-%m-%d %H:%M")
    return (t + timedelta(hours=5 if t < datetime(2024, 3, 10, 2) else 4)).strftime("%Y-%m-%d %H:%M")


IDENTITA = {  # .ufd / SummaryReport.pdf
    "sha256_zip": "a9a2d881a81ab0cbb6ac8caa76457c2eb3ef00eeddec6892956cf21fa0a8464a",
    "modello": "Pixel 7a", "android": "14", "patch": "2024-01-05",
    "app_installate": 369,
}

# (data, ora locale, direzione, frammento del testo o None per allegati/eventi, nota)
SMS = [  # app Messaggi (RCS/SMS/MMS), pag. «Messages»
    ("2024-07-26", "15:03", "in", "Are you here yet?"),
    ("2024-07-26", "15:11", "out", "I had a small hiccup with your contact"),
    ("2024-07-26", "15:12", "in", "we are on RCS"),
    ("2024-07-26", "15:14", "out", "I wish more people used it"),
    ("2024-07-26", "15:16", "in", "They like killing off messenging"),
    ("2024-07-26", "15:23", "in", "good for that"),
    ("2024-07-26", "15:24", "out", "I think that was my line"),
    ("2024-07-26", "15:32", "in", "That was my fault"),
    ("2024-07-26", "15:33", "out", "It happens. Lol"),
    ("2024-07-26", "15:36", "in", "Want to send me a picture?"),
    ("2024-07-26", "15:37", "out", "Let me find one. Standby"),
    ("2024-07-26", "15:38", "out", None),      # foto (Predator)
    ("2024-07-26", "15:40", "in", "I guess I"),
    ("2024-07-26", "15:41", "in", None),       # foto (Keyboard and mouse)
    ("2024-07-26", "15:45", "out", "Got it."),
    ("2024-07-26", "15:47", "in", None),       # 3 foto MMS
    ("2024-07-27", "16:04", "in", None),       # allegato PDF iOS_Bug_Reporting_for_Forensic_Purposes_1.2.pdf
]
SMS_CANCELLATI = [("2024-07-26", "15:52", "in", "Here is your super bad message")]   # cancellato alle 16:11

WHATSAPP = [
    ("2024-01-30", "13:37", "out", "Hi there! How are you?"),
    ("2024-01-30", "14:10", "in", "Just busy. How are you?"),
    ("2024-01-30", "14:13", "out", "generating"),
    ("2024-01-30", "14:15", "in", "Sheesh. How?"),
    ("2024-01-30", "14:21", "out", "Each screen has"),
    ("2024-01-30", "14:23", "in", "cross the streams"),
    ("2024-01-30", "14:26", "out", "Ghostbusters reference"),
    ("2024-01-30", "14:27", "in", "Send me a picture please"),
    ("2024-01-30", "14:29", "out", None),
    ("2024-01-30", "14:31", "in", "Outstanding"),
    ("2024-01-30", "14:33", "in", None),
    ("2024-01-30", "14:36", "out", "I will audio call you in a minute"),
    ("2024-01-30", "14:57", "in", "My turn to audio call you"),
    ("2024-01-30", "15:01", "out", "Here comes a video call"),
    ("2024-01-30", "15:04", "in", "video call you now"),
    ("2024-01-30", "15:11", "out", "It"),        # «It's gone.»
    ("2024-01-30", "15:13", "out", "Now here is your bad message"),
    ("2024-01-30", "15:18", "in", "I deleted"),
]
WHATSAPP_CANCELLATI = [("2024-01-30", "15:09", "in", "Here is your bad message. Please delete it")]
WHATSAPP_CHIAMATE = [("2024-01-30", "14:38", "out", "audio"), ("2024-01-30", "14:58", "in", "audio"),
                     ("2024-01-30", "15:02", "out", "video"), ("2024-01-30", "15:06", "in", "video")]

CHIAMATE = [  # app Telefono
    ("2024-02-01", "15:07", "out", "8820"),
    ("2024-06-04", "15:28", "in", "8799"),
    ("2024-07-27", "17:39", "out", "9579"),
    ("2024-07-27", "17:40", "out", "4674"),
    ("2024-07-27", "17:45", "in", "4674"),
]

SIGNAL = [
    ("2024-01-31", "08:38", "out", "I moved to Signal"),
    ("2024-01-31", "08:41", "in", "Did you get a new phone?"),
    ("2024-01-31", "08:44", "out", "My Pixel 3 finally died"),
    ("2024-01-31", "08:46", "in", "need to upgrade, too"),
    ("2024-01-31", "08:51", "out", "Battery life could be better"),
    ("2024-01-31", "08:53", "in", "have everything"),
    ("2024-01-31", "09:00", "out", "I can always hope"),
    ("2024-01-31", "09:02", "in", "Sure. Give me a minute"),
    ("2024-01-31", "09:08", "out", "I’ll send one over"),
    ("2024-01-31", "09:18", "in", "audio call you momentarily"),
    ("2024-01-31", "10:25", "out", "Alright, my turn"),
    ("2024-01-31", "10:30", "in", "Video call time"),
    ("2024-01-31", "10:36", "out", "Here comes mine"),
    ("2024-01-31", "10:46", "out", "I am sending you this bad message"),
    ("2024-01-31", "10:49", "in", "deleted."),
    ("2024-01-31", "10:56", "out", "trashed it"),
]
SIGNAL_CANCELLATI = [("2024-01-31", "10:52", "in", "Please trash it")]

TELEGRAM = [
    ("2024-01-31", "11:00", "in", "Hi there. I moved"),
    ("2024-01-31", "11:48", "out", "I totally missed this"),
    ("2024-01-31", "11:50", "in", "diagnose a battery"),
    ("2024-01-31", "11:53", "out", "What’s wrong with it?"),
    ("2024-01-31", "11:56", "in", "dropped from 100 to about 20"),
    ("2024-01-31", "11:59", "out", "What were you doing?"),
    ("2024-01-31", "12:01", "in", "I was only using Signal"),
    ("2024-01-31", "12:03", "out", "You were on WiFi, right?"),
    ("2024-01-31", "12:05", "in", "completely stumped"),
    ("2024-01-31", "12:09", "out", "let me find"),
    ("2024-01-31", "12:15", "out", "I’ll send a picture"),
    ("2024-01-31", "12:34", "out", "audio call you shortly"),
    ("2024-01-31", "12:39", "in", "Here comes my call"),
    ("2024-01-31", "12:46", "in", "call you at all"),
    ("2024-01-31", "12:49", "out", "This app is garbage"),
    ("2024-01-31", "12:51", "out", "Nevermind"),
    ("2024-01-31", "12:56", "out", "gone now"),
    ("2024-01-31", "12:58", "out", "so you can delete it"),
    ("2024-01-31", "13:02", "in", "I canned it"),
]
TELEGRAM_CANCELLATI = [("2024-01-31", "12:53", "in", "Here is my bad message to you")]

CHROME = [  # visite documentate (frammento dell'indirizzo o del titolo)
    ("2024-07-13", "21:14", "mlb.com"), ("2024-07-13", "21:15", "Ohtani"), ("2024-07-13", "21:17", "Draft"),
    ("2024-07-13", "21:18", "rowing"), ("2024-07-13", "21:20", "mobile phone forensics"),
    ("2024-07-13", "21:21", "cellebrite.com"), ("2024-07-13", "21:23", "shelley duvall"),
]
CHROME_INCOGNITO = ["nfl.com", "sans.org", "when does Android 15"]   # non devono restare nella cronologia

WIFI = ["Stef0N", "ncsu-guest", "DNCR-Aquarium_Visitor", "RDU Free WiFi", "Free PHL Airport", "Happy Feet Planet_Guest",
        "Skyzone Guest", "Techno24", "Marina Grill Guest", "FAIRHAVEN-5G"]
BLUETOOTH = [("Rouge", "73:ff:93"), ("Pixel Buds", "d1:e5:05"), ("vivoactive 4", "f4:94:78"),
             ("Pixel Watch", "6e:0b:a9")]

# Differenze note tra il documento e i dati del telefono (verificate sul database originale, non errori dello strumento):
DIFFERENZE_DOCUMENTO = [
    "WhatsApp 2024-01-30: il documento riassume i testi («a document», «I deleted it»); nel telefono «the document», «I deleted.»",
    "Wi-Fi: il documento scrive «DNCR-Acquarium_Visitor»; la rete salvata è «DNCR-Aquarium_Visitor»",
    "Telegram 2024-01-31 12:15: il documento segna «I'll send a picture» come inviato; nel database il mittente è l'altra parte "
    "(coerente con la foto ricevuta alle 12:20)",
]
