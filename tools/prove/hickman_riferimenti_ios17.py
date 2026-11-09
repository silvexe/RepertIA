# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Riferimenti della validazione iOS 17 (iPhone 11) di Joshua Hickman, presi SOLO dai documenti allegati all'immagine:
- iOS17-ImageCreation.pdf (documentazione di creazione di Hickman), ore locali con i fusi indicati nel documento;
- EXTRACTION_FFS.ufd e SummaryReport.pdf (riepilogo dell'acquisizione allegato all'estrazione).
Stesse variabili di hickman_riferimenti_android14.py, così lo script di confronto è uno solo."""
from datetime import datetime, timedelta

SISTEMA = "iOS"


def utc(data, ora):
    """Fusi del documento: EDT fino al 2023-11-04, EST fino al 2023-11-21, CET 22-28/11/2023, poi EST fino al
    2024-03-10, poi EDT."""
    t = datetime.strptime(f"{data} {ora}", "%Y-%m-%d %H:%M")
    if t < datetime(2023, 11, 5):
        h = 4
    elif t < datetime(2023, 11, 22):
        h = 5
    elif t < datetime(2023, 11, 28, 13):
        h = -1
    elif t < datetime(2024, 3, 10, 7):
        h = 5
    else:
        h = 4
    return (t + timedelta(hours=h)).strftime("%Y-%m-%d %H:%M")


IDENTITA = {"sha256_zip": "7e603d016416a097fbe79704250130603af2599990ab2e395e428dbf3b9014fa",
            "versione": "17.3", "build": "21D50", "modello": "iPhone 11"}

# (nome nel documento, filtro dell'app nel caso, messaggi, cancellati)
SMS = [  # Messaggi (iMessage/SMS)
    ("2024-01-15", "14:13", "out", "I did! Thank you"),
    ("2024-01-15", "14:14", "in", "Are you working today"),
    ("2024-01-15", "14:17", "out", "few things off my plate"),
    ("2024-01-15", "14:19", "in", "that continues"),
    ("2024-01-15", "14:20", "out", "my kid cooperates"),
    ("2024-01-15", "14:23", "out", "Here comes a picture"),
    ("2024-01-15", "14:24", "out", None),
    ("2024-01-15", "14:25", "in", "send one now"),
    ("2024-01-15", "14:27", "in", None),
    ("2024-01-15", "14:32", "in", "Got it."),
    ("2024-01-15", "14:43", "out", "I moved it to Recently deleted"),
    ("2024-01-16", "14:52", "out", "using Siri"),
    ("2024-01-16", "14:53", "in", "I am using Siri to send it"),
    ("2024-07-28", "10:47", "in", "Last one, hopefully"),
    ("2024-07-28", "10:48", "out", "worn out"),
    ("2024-07-28", "10:50", "in", "I need a small break"),
    ("2024-07-28", "10:52", "out", "ready to be done"),
    ("2024-07-28", "10:54", "in", "You and me both"),
    ("2024-07-28", "10:59", "in", None),
    ("2024-07-28", "11:01", "out", "send one"),
    ("2024-07-28", "11:02", "out", None),
    ("2024-07-28", "11:09", "out", "Returning the favor"),
]
SMS_MODIFICATI = [  # (data, ora dell'invio, verso, testo finale dopo la modifica)
    ("2024-01-15", "14:30", "out", "I edited this message"),
    ("2024-01-15", "14:33", "in", "This is the edited version"),
    ("2024-07-28", "11:03", "in", "I edited this message"),
    ("2024-07-28", "11:05", "out", "This is my edited message"),
]
SMS_CANCELLATI = [
    ("2024-01-15", "14:39", "in", "super bad message"),            # cancellato alle 14:41
    ("2024-01-14", "10:41", "in", "Did you get the link I sent"),  # cancellato il 15/01 alle 14:42
    ("2024-07-28", "11:07", "in", "Here is your bad message. Please delete it"),
    ("2024-01-15", "14:36", "out", "going to unsend this message"),  # ritirato (unsend) alle 14:37
]

WHATSAPP = [
    ("2023-07-27", "15:55", "out", "You there?"), ("2023-07-27", "15:57", "in", "What"),
    ("2023-07-27", "15:58", "out", "Phone still doing ok"), ("2023-07-27", "15:59", "in", "using CarPlay"),
    ("2023-07-27", "16:03", "out", "I had to connect to power"), ("2023-07-27", "16:04", "in", "message history carry over"),
    ("2023-07-27", "16:05", "out", "My groups are there"), ("2023-07-27", "16:07", "in", "even have that"),
    ("2023-07-27", "16:10", "out", "this sucks"), ("2023-07-27", "16:11", "in", "Hang on"),
    ("2023-07-27", "16:12", "in", None), ("2023-07-27", "16:14", "out", "send you one"),
    ("2023-07-27", "16:15", "out", None), ("2023-07-27", "16:16", "in", "Classic"),
    ("2023-07-27", "16:19", "out", "audio call you"), ("2023-07-27", "16:22", "in", "Here comes a video call"),
    ("2023-07-27", "16:25", "out", "Here comes your video call"),
    ("2024-01-30", "13:37", "in", "How are you"), ("2024-01-30", "14:10", "out", "Just busy"),
    ("2024-01-30", "14:13", "in", "generating"), ("2024-01-30", "14:15", "out", "Sheesh"),
    ("2024-01-30", "14:21", "in", "Each screen has"), ("2024-01-30", "14:23", "out", "cross the streams"),
    ("2024-01-30", "14:26", "in", "Ghostbusters"), ("2024-01-30", "14:27", "out", "Send me a picture please"),
    ("2024-01-30", "14:29", "in", None), ("2024-01-30", "14:31", "out", "Outstanding"),
    ("2024-01-30", "14:33", "out", None), ("2024-01-30", "14:36", "in", "audio call you in a minute"),
    ("2024-01-30", "14:57", "out", "My turn to audio call"), ("2024-01-30", "15:01", "in", "Here comes a video call"),
    ("2024-01-30", "15:04", "out", "video call you now"), ("2024-01-30", "15:09", "out", "Here is your bad message"),
    ("2024-01-30", "15:11", "out", "gone"), ("2024-01-30", "15:18", "out", "I deleted"),
]
WHATSAPP_CANCELLATI = [("2024-01-30", "15:13", "in", "Now here is your bad message")]
WHATSAPP_CHIAMATE = [("2023-07-27", "16:17", "in", "audio"), ("2023-07-27", "16:20", "out", "audio"),
                     ("2023-07-27", "16:23", "in", "video"), ("2023-07-27", "16:26", "out", "video"),
                     ("2024-01-30", "14:38", "in", "audio"), ("2024-01-30", "14:58", "out", "audio"),
                     ("2024-01-30", "15:02", "in", "video"), ("2024-01-30", "15:06", "out", "video")]

CHIAMATE = [  # app Telefono
    ("2023-08-11", "16:53", "out", "5700"),
    ("2024-01-12", "10:12", "out", "1775"),
    ("2024-01-16", "14:46", "in", "7386"),
    ("2024-01-16", "14:48", "out", "7386"),
    ("2024-07-27", "17:40", "in", "4674"),
    ("2024-07-27", "17:45", "out", "4674"),
]

SIGNAL = [
    ("2023-07-27", "17:48", "in", "on Signal now"), ("2023-07-27", "17:51", "out", "barely keep up"),
    ("2023-07-27", "19:24", "in", "slower when they get older"), ("2023-07-27", "20:04", "out", "HomePod working"),
    ("2023-07-27", "20:05", "in", "set it up as new"), ("2023-07-28", "08:57", "out", "migrate it to the new Wi-Fi"),
    ("2023-07-28", "08:58", "in", "kept failing"), ("2023-07-28", "08:59", "out", "Apple would"),
    ("2023-07-28", "12:17", "in", "What do you do, ya know"), ("2023-07-28", "12:18", "out", "Standby and I"),
    ("2023-07-28", "12:19", "out", None), ("2023-07-28", "12:20", "in", "send one now"),
    ("2023-07-28", "12:21", "in", None), ("2023-07-28", "12:13", "out", "audio call you in a minute"),
    ("2023-07-28", "12:26", "in", "My turn"), ("2023-07-28", "12:30", "out", "I will video call you"),
    ("2023-07-28", "12:35", "in", "video call you momentarily"),
    ("2024-01-31", "08:38", "in", "I moved to Signal"), ("2024-01-31", "08:41", "out", "Did you get a new phone"),
    ("2024-01-31", "08:44", "in", "Pixel 3 finally died"), ("2024-01-31", "08:46", "out", "need to upgrade"),
    ("2024-01-31", "08:51", "in", "Battery life could be better"), ("2024-01-31", "08:53", "out", "have everything"),
    ("2024-01-31", "09:00", "in", "I can always hope"), ("2024-01-31", "09:02", "out", "Give me a minute"),
    ("2024-01-31", "09:05", "out", None), ("2024-01-31", "09:08", "in", "send one over"),
    ("2024-01-31", "09:10", "in", None), ("2024-01-31", "09:18", "out", "audio call you momentarily"),
    ("2024-01-31", "10:25", "in", "Alright, my turn"), ("2024-01-31", "10:30", "out", "Video call time"),
    ("2024-01-31", "10:36", "in", "Here comes mine"), ("2024-01-31", "10:49", "out", "deleted."),
    ("2024-01-31", "10:52", "out", "Please trash it"), ("2024-01-31", "10:56", "in", "trashed it"),
]
SIGNAL_CANCELLATI = [("2024-01-31", "10:46", "in", "I am sending you this bad message")]

TELEGRAM = [
    ("2023-07-27", "16:33", "out", "Just send me the malware"), ("2023-07-27", "16:35", "in", "over on Telegram now"),
    ("2023-07-27", "16:36", "out", "we forgot to"), ("2023-07-27", "16:38", "in", "go back later"),
    ("2023-07-27", "16:39", "out", "closer to the end"), ("2023-07-27", "16:41", "in", "charging is taking"),
    ("2023-07-27", "16:42", "out", "length of the cord"), ("2023-07-27", "16:44", "in", "How long is it"),
    ("2023-07-27", "16:45", "out", "Eight feet"), ("2023-07-27", "16:46", "in", "I want to see it"),
    ("2023-07-27", "16:49", "out", "Your turn"), ("2023-07-27", "16:53", "in", "Here comes an audio call"),
    ("2023-07-27", "17:10", "out", "Here comes your audio call"), ("2023-07-27", "17:40", "out", "Standby"),
    ("2023-07-27", "17:41", "out", None), ("2023-07-27", "17:42", "in", "My turn"),
    ("2024-01-31", "11:00", "out", "Hi there. I moved"), ("2024-01-31", "11:48", "in", "I totally missed this"),
    ("2024-01-31", "11:50", "out", "diagnose a battery"), ("2024-01-31", "11:53", "in", "wrong with it"),
    ("2024-01-31", "11:56", "out", "dropped from 100"), ("2024-01-31", "11:59", "in", "What were you doing"),
    ("2024-01-31", "12:01", "out", "only using Signal"), ("2024-01-31", "12:03", "in", "on WiFi, right"),
    ("2024-01-31", "12:05", "out", "completely stumped"), ("2024-01-31", "12:09", "in", "let me find"),
    ("2024-01-31", "12:11", "in", None), ("2024-01-31", "12:14", "out", "great"),
    ("2024-01-31", "12:15", "out", "send a picture"), ("2024-01-31", "12:20", "out", None),
    ("2024-01-31", "12:34", "in", "audio call you shortly"), ("2024-01-31", "12:39", "out", "Here comes my call"),
    ("2024-01-31", "12:46", "out", "call you at all"), ("2024-01-31", "12:51", "in", "Nevermind"),
    ("2024-01-31", "12:53", "out", "Here is my bad message to you"), ("2024-01-31", "12:56", "in", "gone now"),
    ("2024-01-31", "13:02", "out", "I canned it"),
]
TELEGRAM_CANCELLATI = [("2024-01-31", "12:58", "in", "so you can delete it")]

APP = {"sms": "imessage"}
WIFI_GRP = ("WiFi Connections", "Wi-Fi")
# Safari: History.db non ha più le visite di gennaio (una sola visita, 2024-07-28); restano le voci di Biome sulla
# cronologia di Safari cancellata, con l'ora ma senza indirizzo: il confronto è sull'ora.
WEB_SUB = ("Safari Browser - History", "Biome - Safari", "Biome - Safari Navigations")
WEB_SOLO_ORA = True
CHROME = [  # Safari (stessa struttura: data, ora, frammento)
    ("2024-01-11", "18:13", "nhl.com"), ("2024-01-11", "18:15", "Ovechkin"),
    ("2024-01-11", "19:37", "digitalcorpora"), ("2024-01-11", "19:38", "digitalcorpora.org"),
]
BROWSER = "Safari"
PRIVATA = (("2024-01-11", "19:40"), ("2024-01-11", "19:49"))
CHROME_INCOGNITO = ["sans.org", "espn", "coaches"]

WIFI = ["Matt_Foley", "Gene_Frenkle", "MarriottBonvoy", "My Way Tavern Guest", "12Oaks_Guest", "Stef0N", "DNCR-Aquarium_Visitor",
        "RDU Free WiFi", "Free PHL Airport", "Happy Feet Planet_Guest", "Skyzone Guest", "Techno24", "Marina Grill Guest",
        "FAIRHAVEN-5G"]
BLUETOOTH = [("Apple Watch", "4e:ff:6a"), ("vívoactive 4", "7f:d3:7a"), ("Versa 3", "86:0e:73")]
BT_NOME = True   # dispositivi LE di iOS: identificativo casuale, si confronta anche il nome

DIFFERENZE_DOCUMENTO = [
    "Wi-Fi: il documento scrive «DNCR-Acquarium_Visitor», «MarriotBonvoy», «MyWay Guest»; le reti salvate sono "
    "«DNCR-Aquarium_Visitor», «MarriottBonvoy», «My Way Tavern Guest»",
    "Messaggi 2024-01-15 14:19: il documento scrive «Hopefully, that continues»; nel telefono «Hopefully that continues»",
    "WhatsApp 2024-01-30 15:11: il documento segna «It's gone» come inviato; nel database è ricevuto (e il documento Android "
    "lo segna inviato dal Pixel alla stessa ora)",
    "Signal 2023-07-28: «Got it. I'll audio call you in a minute» è annotato alle 12:13 tra le 12:22 e le 12:24; nel database "
    "è delle 12:23",
    "Telefono 2024-07-27 17:40 e 17:45: il documento indica il numero dell'iPhone stesso; nel registro c'è "
    "il numero del Pixel del documento Android, che alle 17:40 chiama l'iPhone",
    "Bluetooth: iOS registra i dispositivi LE (Fitbit Versa 3) con un identificativo casuale, non con l'indirizzo MAC del documento",
]
