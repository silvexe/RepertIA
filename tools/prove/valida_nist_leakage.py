#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Validazione esterna di RepertIA sul caso pubblico NIST CFReDS «Data Leakage» (risposte NIST rev. 1.32).

Confronta i casi preparati dai sorgenti con i valori delle risposte ufficiali: dalla 3.0.2 tutte le 53 domande che non
sono di solo ragionamento (56 controlli; esito e differenze in docs/prove/nist-data-leakage.it.md).
Prima preparare i casi (immagini: tools/prove/scarica_nist_leakage.py):
  PC:    forense_agent.py prepara --image .../cfreds_2015_data_leakage_pc.E01 --case <casi>/pc --estese --vss --no-indice
  RM#2:  forense_agent.py prepara --image .../cfreds_2015_data_leakage_rm#2.E01 --case <casi>/rm2 --estese
  RM#3:  forense_mobile.py prepara --logica --image <rm#3_type1.iso estratto dal 7z> --case <casi>/rm3_win (o rm3_logica)
Uso: valida_nist_leakage.py <cartella dei casi> [nome del caso del PC, predefinito pc]
Esce con 1 se un controllo non torna. Orari NIST in UTC-4 (EDT): qui confrontati in UTC."""
import json
import os
import sqlite3
import sys
from pathlib import Path

if len(sys.argv) < 2:
    sys.exit(__doc__)
CASI = Path(sys.argv[1]).expanduser()
PC = sys.argv[2] if len(sys.argv) > 2 else "pc"          # nome della cartella del caso del PC (es. pc_win)
sys.stdout.reconfigure(encoding="utf-8")
esiti = []


def controlla(nome, ok, dett=""):
    esiti.append(ok)
    print(("OK  " if ok else "NO  ") + nome + ("" if ok else f"  → {dett}"))


def q(db, sql, *a):
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return con.execute(sql, a).fetchall()
    finally:
        con.close()


def art(db, cat, extra="", *a):
    """Artefatti di una categoria: (ts, title, detail, data come dizionario)."""
    return [(ts, t, d or "", json.loads(x) if x else {}) for ts, t, d, x in
            q(db, f"SELECT ts, title, detail, data FROM artifacts WHERE cat=? {extra}", cat, *a)]


# Hash pubblicati da NIST (risposta 1)
NIST_HASH = {"pc": ("a49d1254c873808c58e6f1bcd60b5bde", "afe5c9ab487bd47a8a9856b1371c2384d44fd785"),
             "rm2": ("b4644902acab4583a1d0f9f1a08faa77", "048961a85ca3eced8cc73f1517442d31d4dca0a3"),
             "rm3": ("858c7250183a44dd83eb706f3f178990", "471d3eedca9add872fc0708297284e1960ff44f8")}
# I 17 file copiati sulla chiavetta RM#2 e poi cancellati (risposte 53 e 55), con la cartella
NIST_RM2 = {"design/winter_storm.amr", "design/winter_whether_advisory.zip", "pricing decision/my_favorite_cars.db",
            "pricing decision/my_favorite_movies.7z", "pricing decision/new_years_day.jpg", "pricing decision/super_bowl.avi",
            "progress/my_friends.svg", "progress/my_smartphone.png", "progress/new_year_calendar.one",
            "proposal/a_gift_from_you.gif", "proposal/landscape.png", "technical review/diary_#1d.txt",
            "technical review/diary_#1p.txt", "technical review/diary_#2d.txt", "technical review/diary_#2p.txt",
            "technical review/diary_#3d.txt", "technical review/diary_#3p.txt"}


def hash_ok(caso_json, chiave):
    h = (json.loads(Path(caso_json).read_text(encoding="utf-8")).get("hash_dati") or {}).get("calcolati") or {}
    return (h.get("md5"), h.get("sha1")) == NIST_HASH[chiave], (h.get("md5"), h.get("sha1"))


def controlli_pc_base(db, caso_json):
    """(3.0.2) Domande 1-11, 17, 22-23, 25-26, 35-36, 38-39, 47, 51: quelle che nella stima della 3.0.1 risultavano
    coperte («A») ma non erano mai state confrontate con le immagini. Orari NIST convertiti in UTC: UTC-4 (EDT, il PC era
    in ora legale dal 08/03/2015) per tutte, tranne le tabelle delle domande 6 e 10, i cui orari tornano con UTC-5."""
    ok, h = hash_ok(caso_json, "pc")
    controlla("D.1 MD5 e SHA-1 del PC calcolati sui dati uguali a quelli NIST (A49D1254…, AFE5C9AB…)", ok, h)
    m = json.loads(Path(caso_json).read_text(encoding="utf-8"))
    parts = {(p["offset"], p["length_sectors"], p.get("fs")) for p in m.get("partitions", [])}
    controlla("D.2 partizioni: NTFS da 2.048 (204.800 settori) e NTFS da 206.848 (41.734.144 settori)",
              parts == {(2048, 204800, "NTFS"), (206848, 41734144, "NTFS")}, parts)
    sis = art(db, "sistema")
    so = next(((ts, t, d) for ts, t, d, _x in sis if t.startswith("Sistema operativo")), (None, "", ""))
    controlla("D.3 sistema: Windows 7 Ultimate, build 7601, proprietario informant, installato il 22/03/2015 14:34:26 UTC",
              so[0] == "2015-03-22T14:34:26" and "Windows 7 Ultimate" in so[1] and "7601" in so[2] and "informant" in so[2], so)
    fz = next((t + " " + d for _ts, t, d, _x in sis if t.startswith("Fuso orario")), "")
    controlla("D.4 fuso: Eastern Standard Time (UTC-05:00, scostamento 300 minuti) e ora legale",
              "Eastern Standard Time" in fz and "300" in fz and (m.get("fuso_dispositivo") or {}).get("tz") == "America/New_York", fz)
    controlla("D.5 nome del computer: INFORMANT-PC", any(x.get("nome") == "INFORMANT-PC" for *_r, x in sis))
    acc = {x.get("rid"): x for *_r, x in art(db, "utenti") if x.get("rid")}
    # risposta 6 (NIST, ora di New York senza ora legale): creato, ultimo accesso, ultimo tentativo fallito, accessi
    nist6 = {1000: ("2015-03-22T14:33:54", "2015-03-25T14:45:59", "2015-03-25T14:45:43", 10),
             1001: ("2015-03-22T15:51:54", "2015-03-22T15:57:02", "2015-03-22T15:53:02", 2),
             # ITechTeam: NIST scrive «-» come ultimo tentativo fallito, ma nel valore F grezzo del SAM c'è 15:53:02 con
             # 1 password errata (riletto a parte con pyewf+pytsk3+pyregf, senza il codice di RepertIA): omissione NIST
             1002: ("2015-03-22T15:52:30", None, "2015-03-22T15:53:02", 0),
             1003: ("2015-03-22T15:53:01", "2015-03-22T15:55:57", "2015-03-22T15:56:37", 1)}
    trov6 = {r: (x.get("creato"), x.get("ultimo_accesso_sam"), x.get("ultimo_tentativo_fallito"), x.get("accessi_sam"))
             for r, x in acc.items() if r in nist6}
    controlla("D.6 account informant, admin11, ITechTeam, temporary: creazione, ultimo accesso, ultimo tentativo fallito e "
              "numero di accessi del SAM (orari NIST letti in UTC-5)", trov6 == nist6,
              {r: (trov6.get(r), v) for r, v in nist6.items() if trov6.get(r) != v})
    ult = max((x for x in acc.values() if x.get("ultimo_accesso_sam")), key=lambda x: x["ultimo_accesso_sam"], default={})
    controlla("D.7 ultimo utente che ha fatto l'accesso: informant", ult.get("rid") == 1000, ult.get("rid"))
    controlla("D.8 ultimo spegnimento: 25/03/2015 11:31:05 (UTC-4)",
              any(t == "Ultimo spegnimento registrato" and ts == "2015-03-25T15:31:05" for ts, t, _d, _x in sis))
    reti = " ".join(t + " " + d for _ts, t, d, _x in art(db, "reti") if t.startswith("Interfaccia di rete"))
    controlla("D.9 interfaccia DHCP: 10.11.11.129, server DHCP 10.11.11.254, gateway 10.11.11.2, dominio localdomain",
              all(s in reti for s in ("10.11.11.129", "DHCP 10.11.11.254", "gateway 10.11.11.2", "localdomain")), reti)
    prog = {t: (ts, x.get("versione")) for ts, t, _d, x in art(db, "programmi") if not t.startswith(tr_avvio)}
    nist10 = {"Google Chrome": "41.0.2272.101", "Apple Application Support": "3.0.6", "Bonjour": "3.0.0.10",
              "Apple Software Update": "2.1.3.127", "Google Drive": "1.20.8672.3137", "Eraser 6.2.0.2962": "6.2.2962",
              "Microsoft Office Professional Plus 2013": "15.0.4420.1017"}
    controlla("D.10 programmi installati dall'utente: Office 2013, Chrome, Apple, Bonjour, Google Drive, Eraser, .NET 4, con le versioni NIST",
              all(prog.get(n, (0, 0))[1] == v for n, v in nist10.items())
              and any(n.startswith("Microsoft .NET Framework 4") for n in prog), {n: prog.get(n) for n in nist10})
    # ore della risposta 10 (ultima scrittura della chiave Uninstall), lette in UTC-5 come la risposta 6
    ore10 = {"Google Chrome": "2015-03-22T15:11:51", "Google Drive": "2015-03-23T20:02:46",
             "Apple Application Support": "2015-03-23T20:00:45", "Bonjour": "2015-03-23T20:00:58",
             "Apple Software Update": "2015-03-23T20:01:01", "Eraser 6.2.0.2962": "2015-03-25T14:57:31"}
    controlla("D.10 ora di installazione (scrittura della chiave Uninstall) uguale a quella NIST, letta in UTC-5",
              all(prog.get(n, (None,))[0] == v for n, v in ore10.items()), {n: (prog.get(n, (None,))[0], v) for n, v in ore10.items()})
    es = {(ts, x.get("fonte"), t.upper().rsplit("\\", 1)[-1]) for ts, t, _d, x in art(db, "esecuzioni") if ts}
    nist11 = [("2015-03-25T14:50:14", "Prefetch", "ERASER 6.2.0.2962.EXE"), ("2015-03-25T14:50:14", "UserAssist", "ERASER 6.2.0.2962.EXE"),
              ("2015-03-25T14:57:56", "Prefetch", "CCSETUP504.EXE"), ("2015-03-25T15:12:28", "UserAssist", "ERASER.EXE"),
              ("2015-03-25T15:13:30", "Prefetch", "ERASER.EXE"), ("2015-03-25T15:15:50", "UserAssist", "CCLEANER64.EXE"),
              ("2015-03-25T15:15:50", "Prefetch", "CCLEANER64.EXE"), ("2015-03-25T14:41:03", "Prefetch", "OUTLOOK.EXE"),
              ("2015-03-25T15:28:47", "Prefetch", "XPSRCHVW.EXE"), ("2015-03-24T18:31:55", "Prefetch", "STIKYNOT.EXE"),
              ("2015-03-24T18:31:55", "UserAssist", "MICROSOFT.WINDOWS.STICKYNOTES"), ("2015-03-25T15:24:48", "Prefetch", "WINWORD.EXE"),
              ("2015-03-25T15:21:31", "Prefetch", "GOOGLEDRIVESYNC.EXE"), ("2015-03-24T21:05:38", "Prefetch", "CHROME.EXE")]
    manca = [x for x in nist11 if x not in es]
    controlla(f"D.11 esecuzioni: {len(nist11)} voci NIST (Prefetch e UserAssist di Eraser, CCleaner, Outlook, XPS Viewer, "
              "Sticky Notes, Word, Google Drive, Chrome) con le stesse ore (UTC-4)", not manca, manca)
    ric = {(ts, t) for ts, t, _d, x in art(db, "ricerche") if x.get("fonte") == "WordWheelQuery"}
    controlla("D.17 ricerca in Esplora file «secret» alle 14:40:17 (UTC-4)", ("2015-03-23T18:40:17", "secret") in ric, ric)
    usb = {x.get("seriale"): ts for ts, t, _d, x in art(db, "usb") if x.get("seriale")}
    ev_usb = {t.rsplit("\\", 1)[-1].split("&")[0]: ts for ts, t, _d, x in art(db, "usb") if x.get("evento") == 20003 and "SANDISK" in t}
    controlla("D.22 chiavette SanDisk Cruzer Fit 4C530012450531101593 (prima 14:31:10, poi 09:38:00) e 4C530012550531106501 "
              "(09:58:33) (UTC-4)", usb.get("4C530012450531101593") == "2015-03-24T13:38:00"
              and usb.get("4C530012550531106501") == "2015-03-24T13:58:33"
              and ev_usb.get("4C530012450531101593", "")[:16] == "2015-03-23T18:31", (usb, ev_usb))
    ren = {(ts, t.rsplit("/", 1)[-1], d.split("(prima: ", 1)[1].split(") ·")[0].rsplit("/", 1)[-1])
           for ts, t, d, _x in art(db, "journal", "AND detail LIKE 'rinominato (prima:%' AND title LIKE 'Users/informant/Desktop/S data/%'")}
    nist23 = [("2015-03-23T18:41:40", "landscape.png", "[secret_project]_detailed_proposal.docx"),
              ("2015-03-23T18:41:55", "space_and_earth.mp4", "[secret_project]_design_concept.ppt"),
              ("2015-03-23T20:30:44", "happy_holiday.jpg", "(secret_project)_pricing_decision.xlsx"),
              ("2015-03-23T20:31:02", "do_u_wanna_build_a_snow_man.mp3", "[secret_project]_final_meeting.pptx"),
              ("2015-03-24T13:49:51", "winter_whether_advisory.zip", "[secret_project]_detailed_design.pptx"),
              ("2015-03-24T13:50:08", "winter_storm.amr", "[secret_project]_revised_points.ppt"),
              ("2015-03-24T13:50:49", "space_and_earth.mp4", "[secret_project]_design_concept.ppt"),
              ("2015-03-24T13:52:35", "do_u_wanna_build_a_snow_man.mp3", "[secret_project]_final_meeting.pptx"),
              ("2015-03-24T13:52:56", "new_years_day.jpg", "(secret_project)_market_analysis.xlsx")]
    manca = [x for x in nist23 if x not in ren]
    controlla(f"D.23 rinomine sul Desktop: le prime {len(nist23)} coppie nome vecchio/nuovo della tabella NIST, stesse ore (UTC-4)",
              not manca, manca)
    sb = {t for _ts, t, _d, _x in art(db, "cartelle") if t.startswith("E:\\Secret Project Data")}
    nist25 = {"E:\\Secret Project Data", "E:\\Secret Project Data\\technical review", "E:\\Secret Project Data\\proposal",
              "E:\\Secret Project Data\\progress", "E:\\Secret Project Data\\pricing decision", "E:\\Secret Project Data\\design"}
    controlla("D.25 cartelle aperte su RM#2 (ShellBags): Secret Project Data e le sue 5 sottocartelle", nist25 <= sb, sorted(nist25 - sb))
    rec = {(ts, t) for ts, t, _d, _x in art(db, "recenti") if ts}
    controlla("D.26 file aperti da RM#2: E:\\Secret Project Data\\design\\winter_whether_advisory.zip alle 10:01:23 (UTC-4)",
              ("2015-03-24T14:01:23", "E:\\Secret Project Data\\design\\winter_whether_advisory.zip") in rec)
    nist35 = [("2015-03-24T20:44:13", "D:\\de\\winter_whether_advisory.zip"), ("2015-03-24T20:44:18", "D:\\de\\winter_whether_advisory.zip"),
              ("2015-03-24T21:01:10", "D:\\Penguins.jpg"), ("2015-03-24T21:01:12", "D:\\Koala.jpg"), ("2015-03-24T21:01:14", "D:\\Tulips.jpg")]
    manca = [x for x in nist35 if x not in rec]
    controlla("D.35 file aperti dal CD-R: winter_whether_advisory.zip (jump list e LNK), Penguins, Koala, Tulips (UTC-4)", not manca, manca)
    ev = {k: ts for ts, k in q(db, "SELECT ts, kind FROM events WHERE path=?",
                                 "/Users/informant/Desktop/Resignation_Letter_(Iaman_Informant).docx")}
    controlla("D.36 date NTFS della lettera di dimissioni: creata 14:48:40, modificata/accesso/voce 14:59:30 (UTC-4)",
              ev == {"B": "2015-03-24T18:48:40", "M": "2015-03-24T18:59:30", "A": "2015-03-24T18:59:30", "C": "2015-03-24T18:59:30"}, ev)
    tc = {p.rsplit("/", 1)[-1] for (p,) in q(db, "SELECT path FROM files WHERE path LIKE 'Users/informant/AppData/Local/Microsoft/Windows/Explorer/thumbcache_%'")}
    controlla("D.38 file Thumbcache di informant: thumbcache_32, _256 e _idx (NIST scrive anche _64: in Windows 7 è _96)",
              {"thumbcache_32.db", "thumbcache_96.db", "thumbcache_256.db", "thumbcache_idx.db"} <= tc, tc)
    n256 = q(db, "SELECT count(*) FROM xitems WHERE kind='miniatura' AND src_path LIKE '%informant%thumbcache_256.db'")[0][0]
    controlla("D.39 miniature estratte da thumbcache_256.db di informant", n256 > 0, n256)
    vss = ((m.get("estese") or {}).get("vss") or {}).get("dettaglio") or []
    controlla("D.47 copia shadow creata il 25/03/2015 alle 10:57:27 (UTC-4)",
              any("2015-03-25 14:57:27" in v.get("copia", "") for v in vss), vss)
    cest = sorted((ts, t.rsplit("\\", 1)[-1]) for ts, t, _d, _x in art(db, "cestino"))
    nist51 = sorted([("2015-03-24T19:51:47", n) for n in ("prop", "prog", "pd", "tr")] +
                    [("2015-03-24T20:11:42", n) for n in ("Hydrangeas.jpg", "Jellyfish.jpg", "Tulips.jpg", "Penguins.jpg",
                     "Desert.jpg", "desktop.ini", "IE11-Windows6.1-x64-en-us.exe", "Chrysanthemum.jpg", "Koala.jpg", "Lighthouse.jpg")])
    controlla("D.51 cestino: le 14 voci NIST con le ore di cancellazione (UTC-4)", cest == nist51, sorted(set(cest) ^ set(nist51)))


tr_avvio = "Avvio automatico"


def controlli_pc_parziali(db):
    """(3.0.2) Domande 16, 18-21, 24, 27-29, 32, 37: nella stima della 3.0.1 «in parte» (P). Orari NIST in UTC-4."""
    ric = {(ts, t, x.get("browser")) for ts, t, _d, x in art(db, "ricerche") if x.get("browser")}
    nist16 = [("2015-03-23T18:02:09", "data leakage methods", "Chrome"), ("2015-03-23T18:02:44", "leaking confidential information", "Chrome"),
              ("2015-03-23T18:03:40", "information leakage cases", "Chrome"), ("2015-03-23T18:05:48", "intellectual property theft", "Chrome"),
              ("2015-03-23T18:06:27", "how to leak a secret", "Chrome")]
    chrome16 = {"cloud storage", "digital forensics", "how to delete data", "anti-forensics", "system cleaner",
                "how to recover data", "data recovery tools", "apple icloud", "google drive", "security checkpoint cd-r"}
    manca_c = sorted(chrome16 - {t for _ts, t, b in ric if b == "Chrome"})
    manca = [x for x in nist16 if x not in ric]
    controlla("D.16 parole cercate con Chrome: le 15 ricerche NIST (5 confrontate anche nell'ora, UTC-4)",
              not manca and not manca_c, manca + manca_c)
    ie = sorted({t for ts, t, b in ric if b == "Internet Explorer/Edge"})
    nist16ie = {"file sharing and tethering", "DLP DRM", "e-mail investigation", "Forensic Email Investigation",
                "what is windows system artifacts", "investigation on windows machine", "windows event logs",
                "cd burning method", "cd burning method in windows", "external device and forensics",
                "anti-forensic tools", "eraser", "ccleaner"}
    controlla("D.16 parole cercate con Internet Explorer 11 (Bing, da WebCacheV01.dat): le 13 ricerche NIST",
              nist16ie <= set(ie), sorted(nist16ie - set(ie)))
    ost = r"Users/informant/AppData/Local/Microsoft/Outlook/iaman.informant@nist.gov.ost"
    prog = {t for _ts, t, _d, _x in art(db, "programmi")}
    es = {t.upper() for _ts, t, _d, _x in art(db, "esecuzioni")}
    controlla("D.18-19 posta con Outlook 2013: Office 2013 installato, OUTLOOK.EXE eseguito e file OST in "
              "Users\\informant\\AppData\\Local\\Microsoft\\Outlook\\iaman.informant@nist.gov.ost",
              "Microsoft Office Professional Plus 2013" in prog and "OUTLOOK.EXE" in es
              and bool(q(db, "SELECT 1 FROM files WHERE path=?", ost)))
    posta = q(db, "SELECT date, folder, sender, recipients, subject FROM mail WHERE src_path=?", ost)
    controlla("D.20 account di posta: iaman.informant@nist.gov",
              any("iaman.informant@nist.gov" in (s or "") + (r or "") for _d, _f, s, r, _o in posta), len(posta))
    nist21 = [("2015-03-23T17:29:27", "Inbox", "Hello, Iaman"), ("2015-03-23T18:44:31", "Sent Items", "RE: Hello, Iaman"),
              ("2015-03-23T19:14:58", "Inbox", "Good job, buddy."), ("2015-03-23T19:20:41", "Inbox", "RE: Good job, buddy."),
              ("2015-03-23T19:26:22", "Inbox", "Important request"), ("2015-03-23T19:27:05", "Sent Items", "RE: Important request"),
              ("2015-03-23T20:41:19", "Deleted Items", "RE: It's me"), ("2015-03-24T13:25:57", "Inbox", "Last request"),
              ("2015-03-24T19:34:02", "Deleted Items", "RE: Watch out!"), ("2015-03-24T21:05:09", "Deleted Items", "Done")]
    trov = {(d, f.rsplit("/", 1)[-1], o) for d, f, _s, _r, o in posta}
    manca = [x for x in nist21 if x not in trov]
    controlla(f"D.21 messaggi dell'OST: i {len(nist21)} messaggi NIST nelle cartelle Inbox, Sent Items, Deleted Items con l'ora "
              "di invio (UTC-4); «It's me», recuperato da NIST dallo spazio non usato dell'OST, non è letto (limite dichiarato)",
              not manca, manca)
    reti = " ".join(t for _ts, t, _d, _x in art(db, "reti"))
    controlla("D.24 indirizzo del disco di rete aziendale: 10.11.11.128", "\\\\10.11.11.128\\secured_drive" in reti, reti[:160])
    sb = {}
    for ts, t, _d, _x in art(db, "cartelle"):
        if ts:
            sb.setdefault(t, set()).add(ts)
    nist27 = [("\\\\10.11.11.128\\secured_drive\\Secret Project Data\\pricing decision", "2015-03-23T20:28:17"),
              ("\\\\10.11.11.128\\secured_drive\\Past Projects", "2015-03-24T13:47:54"),
              ("V:\\Secret Project Data", "2015-03-23T20:27:24"), ("V:\\Secret Project Data\\final", "2015-03-23T20:27:29")]
    cart = {t for _ts, t, _d, _x in art(db, "cartelle")}
    dirs = {"\\\\10.11.11.128\\secured_drive\\" + d for d in ("Common Data", "Past Projects", "Secret Project Data\\design",
            "Secret Project Data\\pricing decision", "Secret Project Data\\final", "Secret Project Data\\technical review",
            "Secret Project Data\\proposal", "Secret Project Data\\progress")}
    manca = [x for x in nist27 if x[1] not in sb.get(x[0], ())] + sorted(dirs - cart)
    controlla("D.27 cartelle aperte sul disco di rete (ShellBags): le 8 cartelle NIST e le ore NIST dove la ShellBag le registra",
              not manca, manca)
    rec = {(ts, t.lower(), x.get("fonte")) for ts, t, _d, x in art(db, "recenti") if ts}
    base = "\\\\10.11.11.128\\secured_drive\\secret project data\\"
    nist28 = [("2015-03-23T20:26:53", base + "pricing decision\\(secret_project)_pricing_decision.xlsx", "Jump list"),
              ("2015-03-23T20:26:53", base + "pricing decision\\(secret_project)_pricing_decision.xlsx", "LNK"),
              ("2015-03-23T20:26:56", base + "pricing decision\\(secret_project)_pricing_decision.xlsx", "Office MRU"),
              ("2015-03-23T20:27:33", base + "final\\[secret_project]_final_meeting.pptx", "Jump list"),
              ("2015-03-23T20:27:33", base + "final\\[secret_project]_final_meeting.pptx", "LNK"),
              ("2015-03-23T20:27:37", "v:\\secret project data\\final\\[secret_project]_final_meeting.pptx", "Office MRU")]
    manca = [x for x in nist28 if x not in rec]
    controlla("D.28 file aperti dal disco di rete: jump list, LNK e Office MRU con le ore NIST (UTC-4)", not manca, manca)
    cloud = [x for *_r, x in art(db, "cloud")]
    dl = {t.rsplit("\\", 1)[-1] for _ts, t, _d, _x in art(db, "download")}
    controlla("D.29 tracce di servizi cloud: Google Drive (registro di sincronizzazione) e installatori di Google Drive e iCloud",
              bool(cloud) and {"googledrivesync.exe", "icloudsetup.exe"} <= dl, dl)
    burn = q(db, "SELECT count(*) FROM artifacts WHERE cat='journal' AND title LIKE 'Users/informant/AppData/Local/Microsoft/Windows/Burn/Burn/%'")[0][0]
    controlla("D.32 masterizzazione con Esplora file: file preparati nella cartella Burn (journal) ed eventi cdrom 133",
              burn > 0 and bool(q(db, "SELECT 1 FROM artifacts WHERE cat='dispositivi' AND json_extract(data,'$.evento')=133")), burn)
    xps = {k: ts for ts, k in q(db, "SELECT ts, kind FROM events WHERE path=?", "/Users/informant/Desktop/Resignation_Letter_(Iaman_Informant).xps")}
    controlla("D.37 stampa in XPS: Resignation_Letter_(Iaman_Informant).xps sul Desktop scritto alle 11:28:34 (UTC-4), "
              "poi aperto con il visualizzatore XPS", xps.get("M") == "2015-03-25T15:28:34" and "XPSRCHVW.EXE" in es, xps)


def controlli_rm2(caso):
    """(3.0.2) Chiavetta RM#2 (forense_agent.py prepara --image cfreds_2015_data_leakage_rm#2.E01 --estese)."""
    db = caso / "caso.sqlite"
    if not db.exists():
        print(f"(caso della chiavetta RM#2 non trovato: {caso})")
        return
    ok, h = hash_ok(caso / "case.json", "rm2")
    controlla("D.1 MD5 e SHA-1 di RM#2 uguali a quelli NIST (B4644902…, 048961A8…)", ok, h)
    canc = {p.split("/", 1)[1] for p, in q(db, "SELECT path FROM files WHERE deleted=1 AND type='r/r' AND path LIKE '$OrphanFiles/%/%'")}
    norm = {"PRICIN~1": "pricing decision", "TECHNI~1": "technical review"}
    canc = {norm.get(p.split("/")[0], p.split("/")[0]) + "/" + p.split("/", 1)[1] for p in canc}
    controlla("D.53 i 17 file cancellati dalla chiavetta (formattazione rapida) recuperati dalle voci FAT, con nome e cartella",
              canc == NIST_RM2, sorted(canc ^ NIST_RM2))
    fals = {p.rsplit("/", 1)[-1] for p, in q(db, "SELECT path FROM anomalies WHERE kind='estensione'")}
    attese = {p.rsplit("/", 1)[-1] for p in NIST_RM2} - {"winter_whether_advisory.zip", "my_favorite_cars.db"}
    controlla("D.55 formato vero dei file copiati (documenti Office rinominati): 15 su 17 segnalati; .zip (PPTX) e .db (XLS) "
              "hanno un'estensione coerente col contenuto", fals == attese, sorted(fals ^ attese))


pc = CASI / PC / "caso.sqlite"
if pc.exists():
    ev = {r[0]: r[1:] for r in q(pc, "SELECT json_extract(data,'$.evento'), count(*), group_concat(ts) FROM artifacts "
                                     "WHERE json_extract(data,'$.evento') IN (133, 4608, 1100, 4634, 4647, 20001, 20003) "
                                     "GROUP BY 1")}
    burn = sorted((ev.get(133) or (0, ""))[1].split(","))
    controlla("D.33 masterizzazioni: 4 eventi cdrom 133 alle 15:47:47, 15:56:11, 16:24:46, 16:41:21 (UTC-4)",
              burn == ["2015-03-24T19:47:47", "2015-03-24T19:56:11", "2015-03-24T20:24:46", "2015-03-24T20:41:21"], burn)
    controlla("D.12 accensioni/spegnimenti/uscite: eventi 4608, 1100, 4634, 4647 presenti",
              all(ev.get(k, (0,))[0] for k in (4608, 1100, 4634, 4647)), {k: ev.get(k, (0,))[0] for k in (4608, 1100, 4634, 4647)})
    controlla("D.22 dispositivi: eventi UserPnp 20001/20003 presenti", all(ev.get(k, (0,))[0] for k in (20001, 20003)))
    cl = q(pc, "SELECT ts, title, data FROM artifacts WHERE cat='cloud'")
    dati = [(ts, json.loads(d)) for ts, _t, d in cl if d]
    canc = sorted({(ts, x["percorso"].rsplit("\\", 1)[-1]) for ts, x in dati if x.get("azione") == "DELETE"
                   and x.get("percorso", "").endswith(("happy_holiday.jpg", "do_u_wanna_build_a_snow_man.mp3"))})
    controlla("D.30 file cancellati da Google Drive: happy_holiday.jpg e do_u_wanna_build_a_snow_man.mp3 alle 16:42:17 (UTC-4)",
              canc == [("2015-03-23T20:42:17", "do_u_wanna_build_a_snow_man.mp3"), ("2015-03-23T20:42:17", "happy_holiday.jpg")], canc)
    acc = {(ts, json.loads(d).get("account")) for ts, t, d in cl if d and json.loads(d).get("account")}
    controlla("D.31 account di Google Drive: iaman.informant.personal@gmail.com, accesso alle 16:05:32 (UTC-4)",
              ("2015-03-23T20:05:32", "iaman.informant.personal@gmail.com") in acc, acc)
    conf = [json.loads(d) for ts, t, d in cl if d and json.loads(d).get("fonte") == "Google Drive sync_config.db"]
    controlla("D.48 sync_config.db letto dalla copia shadow (nel disco attuale è cancellato e sovrascritto)",
              any(c.get("copia_shadow") and c.get("user_email") == "iaman.informant.personal@gmail.com" for c in conf), conf[:1])
    rec = [json.loads(d) for ts, t, d in cl if d and json.loads(d).get("fonte") == "Google Drive snapshot.db" and json.loads(d).get("recuperato")]
    controlla("D.49 record cancellato di cloud_entry nello snapshot.db della copia shadow: doc_id 0Bz0ye6gXtiZaVl8yVU5mWHlGbWc, "
              "do_u_wanna_build_a_snow_man.mp3, modified 1422636560",
              any(r.get("doc_id") == "0Bz0ye6gXtiZaVl8yVU5mWHlGbWc" and r.get("filename") == "do_u_wanna_build_a_snow_man.mp3"
                  and r.get("modified") == "1422636560" for r in rec), rec[:2])
    # (3.0.2) Internet Explorer 11 (WebCache), Sticky Notes, indice di Ricerca di Windows
    web = [(ts, json.loads(d)) for ts, d in q(pc, "SELECT ts, data FROM artifacts WHERE cat='web' AND data LIKE '%WebCacheV01%'")]
    controlla("D.13-15 Internet Explorer 11 (WebCacheV01.dat): go.microsoft.com/fwlink/?LinkId=69157 alle 13:27:36 (UTC-4)",
              ("2015-03-23T17:27:36", "http://go.microsoft.com/fwlink/?LinkId=69157") in {(ts, x.get("url")) for ts, x in web}, len(web))
    note = [json.loads(d) for (d,) in q(pc, "SELECT data FROM artifacts WHERE cat='note'")]
    controlla("D.40-41 Sticky Notes: StickyNotes.snt con la nota «Tomorrow… Everything will be OK…»",
              any(x.get("fonte") == "StickyNotes.snt" and "Tomorrow" in x.get("testo", "") and "Everything will be OK" in x.get("testo", "")
                  for x in note), note[:2])
    sis = [(t, json.loads(d) if d else {}) for t, d in q(pc, "SELECT title, data FROM artifacts WHERE cat='sistema'")]
    controlla("D.42 Ricerca di Windows attiva: servizio WSearch ad avvio automatico e Windows.edb presente",
              any(x.get("servizio") == "WSearch" and x.get("start") == 2 for _t, x in sis)
              and any(x.get("fonte") == "Windows Search" and x.get("elementi") for _t, x in sis), [t for t, _x in sis if "Ricerca" in t or "Search" in t])
    cont = next((x.get("contenuti") for _t, x in sis if x.get("fonte") == "Windows Search"), {}) or {}
    controlla("D.43 contenuti dell'indice: file, cronologia di IE, posta di Outlook, Sticky Notes",
              all(cont.get(k) for k in ("file", "iehistory", "mapi15", "StickyNotes")), cont)
    ind = [(ts, json.loads(d)) for ts, d in q(pc, "SELECT ts, data FROM artifacts WHERE cat='indice'")]
    urls = {(ts, x.get("url")) for ts, x in ind if x.get("url")}
    controlla("D.44 IE nell'indice: ie-8-welcome alle 11:09:22 e msn.com alle 11:09:23 (UTC-4)",
              {("2015-03-22T15:09:22", "http://windows.microsoft.com/en-us/internet-explorer/ie-8-welcome"),
               ("2015-03-22T15:09:23", "http://www.msn.com/?ocid=iehp")} <= urls, sorted(urls, key=str)[:4])
    posta = [(ts, x) for ts, x in ind if x.get("store") == "mapi15"]
    controlla("D.45 posta nell'indice: «RE: Good job, buddy.» ricevuta alle 15:20:41 (UTC-4) con «I’ll be in touch» e un messaggio "
              "inviato alle 15:19:22 con allegato space_and_earth.mp4",
              any(ts == "2015-03-23T19:20:41" and "be in touch" in x.get("testo", "") for ts, x in posta)
              and any(x.get("inviato") == "2015-03-23T19:19:22" and "space_and_earth.mp4" in (x.get("allegati") or "") for _ts, x in posta),
              [(ts, x.get("oggetto")) for ts, x in posta][:5])
    crea = {x.get("percorso"): x.get("creato") for _ts, x in ind if x.get("store") == "file"}
    controlla("D.46 Desktop nell'indice: Resignation_Letter creato alle 14:48:40, space_and_earth.mp4 alle 09:40:09 (UTC-4)",
              crea.get(r"C:\Users\informant\Desktop\Resignation_Letter_(Iaman_Informant).docx") == "2015-03-24T18:48:40"
              and crea.get(r"C:\Users\informant\Desktop\S data\Secret Project Data\Secret Project Data\design\space_and_earth.mp4")
              == "2015-03-24T13:40:09", len(crea))
    controlli_pc_base(pc, CASI / PC / "case.json")
    controlli_pc_parziali(pc)
else:
    print(f"(caso del PC non trovato: {pc})")
controlli_rm2(CASI / "rm2")

rm3 = CASI / "rm3_win" if (CASI / "rm3_win" / "estrazione.sqlite").exists() else CASI / "rm3_logica"
if (rm3 / "estrazione.sqlite").exists():
    m3 = json.loads((rm3 / "case.json").read_text(encoding="utf-8"))
    sett = (m3.get("estratta") or {}).get("settori_2048") or {}     # md5/sha1 registrati dalla 3.0.2
    controlla("D.1 MD5 e SHA-1 di RM#3 (dati a 2048 byte della copia derivata) uguali a quelli NIST (858C7250…, 471D3EED…)",
              (sett.get("md5"), sett.get("sha1")) == NIST_HASH["rm3"], (sett.get("md5"), sett.get("sha1")))
    righe = q(rm3 / "estrazione.sqlite", "SELECT path, size, crtime FROM mobile_files WHERE isdir=0")
    att = sorted(p for p, _s, _c in righe if "/" not in p)
    controlla("D.57 stato finale del CD-R: Koala.jpg, Penguins.jpg, Tulips.jpg", att == ["Koala.jpg", "Penguins.jpg", "Tulips.jpg"], att)
    nist34 = {"de/winter_storm.amr", "de/winter_whether_advisory.zip", "pd/my_favorite_cars.db", "pd/my_favorite_movies.7z",
              "pd/new_years_day.jpg", "pd/super_bowl.avi", "prog/my_friends.svg", "prog/my_smartphone.png",
              "prog/new_year_calendar.one", "prop/a_gift_from_you.gif", "prop/landscape.png", "tr/diary_#1d.txt",
              "tr/diary_#1p.txt", "tr/diary_#2d.txt", "tr/diary_#2p.txt", "tr/diary_#3d.txt", "tr/diary_#3p.txt"}
    prec = {p.split("/", 1)[1]: c for p, _s, c in righe if p.startswith("[")}
    controlla("D.34/56/57 i 17 file copiati sul CD-R e poi cancellati, coi nomi della domanda 34, dalle VAT precedenti",
              set(prec) == nist34, sorted(set(prec) ^ nist34))
    ore = sorted(prec.values())
    controlla("D.59 masterizzati il 24/03/2015 tra le 16:54 e le 16:58 (UTC-4)",
              bool(ore) and ore[0] >= "2015-03-24T20:54:00" and ore[-1] <= "2015-03-24T20:58:59", (ore[:1], ore[-1:]))
    canc = q(rm3 / "caso.sqlite", "SELECT count(*) FROM files WHERE deleted=1 AND type='r/r'")[0][0]
    controlla("i file delle VAT precedenti sono segnati come cancellati", canc == 17, canc)
else:
    print(f"(caso del CD-R non trovato: {rm3})")

print(f"\n{sum(esiti)}/{len(esiti)} controlli superati")
sys.exit(0 if all(esiti) else 1)
