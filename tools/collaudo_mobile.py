#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Costruisce le estrazioni di prova degli smartphone per il collaudo di RepertIA (2.20) e il file dei valori attesi.

Uso:  python3 collaudo_mobile.py <cartella iLEAPP> <cartella ALEAPP> <cartella di collaudo>
      python3 collaudo_mobile.py --aggiorna-android <cartella di collaudo>
      python3 collaudo_mobile.py --portachiavi <cartella di collaudo> <cartella iLEAPP>
      python3 collaudo_mobile.py --file-citati <cartella di collaudo>
      python3 collaudo_mobile.py --sysdiagnose <cartella di collaudo>
      (la quinta forma aggiunge la prova dei sysdiagnose: due archivi nella forma di un sysdiagnose costruiti con i
      ritagli PUBBLICI dei test di iLEAPP v2026.4.5 – ps.txt reale di un iPhone iOS 16 (20A362); BatteryUI e
      ManagedSettings reali di iOS 26.6 (23G71) con gli identificativi sostituiti dagli autori di iLEAPP – scaricati da
      GitHub e controllati con lo SHA-256; non sono sysdiagnose completi)
      (la quarta forma aggiunge solo la prova dei file citati: estrazione iOS FINTA ios_file_citati.zip e righe nello
      stile di iLEAPP con l'esito atteso: cartella + nome, omonimi, nome e dimensione, hash, copie, file assente)
      (la terza forma aggiunge solo la prova del portachiavi: estrazione iOS minima con un portachiavi FINTO in formato
      Cellebrite cifrato dentro extra/KeychainDump e un portachiavi FINTO decifrato da passare a iLEAPP con --keychain;
      serve pycryptodome, preso se manca dalla cartella site/ di iLEAPP)
      (la seconda forma ricostruisce solo WhatsApp e Google Photos dentro android_prova.tar.gz esistente, tenendo gli
      estratti di ALEAPP e i loro valori attesi già scritti in atteso_smartphone.json)

Scrive in <cartella di collaudo>/smartphone/:
- ios_prova.zip: zip in stile Cellebrite FFS (filesystem1 = radice, filesystem2 = /private/var) con gli estratti
  REALI dell'immagine pubblica iOS 15 di Josh Hickman usati nei test di iLEAPP (sms.db, ChatStorage.sqlite,
  ContactsV2.sqlite, CallHistory.sqlite di WhatsApp, allegati degli SMS), più SystemVersion.plist e il collegamento
  db/timezone/localtime aggiunti per provare il riconoscimento del sistema e del fuso;
- android_prova.tar.gz: tar compresso con gli estratti REALI dell'immagine pubblica Android 15 (Samsung, «anne_a15»)
  usati nei test di ALEAPP (mmssms.db con -wal e allegati) e un WhatsApp COSTRUITO qui con contenuto noto
  (msgstore.db con un messaggio rimasto solo nel -wal, wa.db, contacts2.db, foto: una al suo posto con file_hash,
  una spostata e rinominata che si trova solo per hash, una con la sola miniatura nel database, una assente), un
  gphotos-1.db di Google Photos costruito (un file al suo percorso, uno spostato che si trova per nome e dimensione,
  uno assente), build.prop e il fuso.
e in <cartella di collaudo>/atteso_smartphone.json i valori attesi: per gli estratti reali sono quelli pubblicati
nei risultati dei test di iLEAPP/ALEAPP (strumenti indipendenti da RepertIA), per WhatsApp Android quelli costruiti.
"""
import base64
import datetime as dt
import hashlib
import json
import plistlib
import shutil
import sqlite3
import struct
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

T0 = dt.datetime(2024, 3, 15, 9, 0, 0, tzinfo=dt.timezone.utc)


def ms(d):
    return int(d.timestamp() * 1000)


def iso(t):
    return dt.datetime.fromtimestamp(int(t), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def sha_list(ts):
    return hashlib.sha256("\n".join(sorted(ts)).encode()).hexdigest()


def results(base, sub, prefix):
    f = sorted((base / "admin" / "test" / "results" / sub).glob(prefix + "*.json"))[-1]
    return json.loads(f.read_text())


def unzip_into(z, dest, strip=""):
    with zipfile.ZipFile(z) as zf:
        for m in zf.infolist():
            if m.is_dir():
                continue
            name = m.filename[len(strip):] if strip and m.filename.startswith(strip) else m.filename
            out = dest / name
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(zf.read(m))


# ------------------------------------------------------------------------------------- iOS

def build_ios(ileapp, out):
    data = ileapp / "admin" / "test" / "cases" / "data"
    tmp = Path(tempfile.mkdtemp())
    for z in ["whatsApp/testdata.whatsApp.whatsAppMessages.josh_ios15_ffs.zip",
              "whatsApp/testdata.whatsApp.whatsAppContacts.josh_ios15_ffs.zip",
              "whatsApp/testdata.whatsApp.whatsAppCallHistory.josh_ios15_ffs.zip",
              "sms/testdata.sms.sms.josh_ios15_ffs.zip"]:
        unzip_into(data / z, tmp)
    sysver = plistlib.dumps({"ProductName": "iPhone OS", "ProductVersion": "15.3.1", "ProductBuildVersion": "19D52"})
    files = sorted(p for p in tmp.rglob("*") if p.is_file())
    zpath = out / "ios_prova.zip"
    mt = int(T0.timestamp())
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        def add(name, payload, mode=0o100644, ut=True):
            zi = zipfile.ZipInfo(name, date_time=(2024, 3, 15, 10, 0, 0))
            zi.create_system = 3
            zi.external_attr = mode << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            if ut:                                      # campo esteso UT: data UTC, come gli strumenti di estrazione
                zi.extra = struct.pack("<HHBl", 0x5455, 5, 1, mt)
            zf.writestr(zi, payload)
        add("filesystem1/System/Library/CoreServices/SystemVersion.plist", sysver)
        add("filesystem2/db/timezone/localtime", b"/usr/share/zoneinfo/America/New_York", 0o120755)
        for i, p in enumerate(files):
            add(str(p.relative_to(tmp)), p.read_bytes(), ut=(i % 2 == 0))   # metà con data UTC, metà solo DOS
    sha = {str(p.relative_to(tmp)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    shutil.rmtree(tmp)
    sms = results(ileapp, "sms", "sms.sms.josh_ios15_ffs.")
    wa = results(ileapp, "whatsApp", "whatsApp.whatsAppMessages.josh_ios15_ffs.")
    i_ts = [iso(r[0]) for r in sms["data"]]
    w_ts = [iso(r[0]) for r in wa["data"]]
    hm = sms["headers"].index("Message")
    sample = next(r for r in sms["data"] if r[hm] and "Google Fi" in r[hm])
    return {
        "nome": "20_smartphone_ios_zip",
        "tipo": "smartphone",
        "immagine": "smartphone/ios_prova.zip",
        "opzioni": ["--leapp"],
        "indipendente": True,
        "fonte": "estratti dell'immagine pubblica iOS 15 di Josh Hickman e risultati attesi pubblicati nei test di "
                 "iLEAPP (admin/test/results: sms, whatsAppMessages)",
        "descrizione": "Zip in stile Cellebrite FFS con sms.db (con -wal) e ChatStorage.sqlite di WhatsApp reali; "
                       "valori attesi = risultati di iLEAPP su questi stessi file.",
        "atteso": {
            "piattaforma": "ios", "sistema_versione": "15.3.1", "fuso": "America/New_York",
            "file_sha256": {k: v for k, v in sha.items() if k.endswith(("sms.db", "ChatStorage.sqlite", ".pdf"))},
            "chat_messaggi": {"imessage": len(i_ts), "whatsapp": len(w_ts)},
            "chat_orari_sha256": {"imessage": sha_list(i_ts), "whatsapp": sha_list(w_ts)},
            "chat_testi": [{"app": "imessage", "ts": iso(sample[0]), "contiene": "Google Fi"}],
            "allegati_collegati_min": 5,
            "leapp_righe_min": {"SMS": len(i_ts), "WhatsApp - Messages": len(w_ts)},
            "date_utc_min": 2, "date_dos_min": 2,
        },
    }


# ------------------------------------------------------------------------ portachiavi (finto)

# Valori INVENTATI: nessun dato reale. Il collaudo controlla che non compaiano mai in chiaro fuori da leapp_segreti.
KC_WIFI_ESTRAZIONE = ("Rete-Collaudo-RepertIA", "PasswordFinta-Estrazione-111")
KC_WEB_ESTRAZIONE = ("accesso.esempio.invalid", "utente.collaudo", "SegretoWeb-Finto-222")
KC_WIFI_FORNITO = ("Rete-Fornita-Collaudo", "PasswordFinta-Fornita-333")


def _aes(ileapp):
    try:
        from Crypto.Cipher import AES
    except ImportError:
        sys.path.insert(0, str(Path(ileapp) / "site"))
        from Crypto.Cipher import AES
    return AES


def _der(pairs):
    """Dizionario → DER come nei portachiavi di Cellebrite: SET di SEQUENCE (chiave UTF8String, valore)."""
    def ln(n):
        if n < 128:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(b)]) + b

    def tlv(tag, val):
        return bytes([tag]) + ln(len(val)) + val

    def val(v):
        if isinstance(v, bytes):
            return tlv(0x04, v)
        if isinstance(v, int):
            return tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big"))
        if isinstance(v, tuple) and v[0] == "tempo":
            return tlv(0x18, v[1].encode())
        return tlv(0x0c, str(v).encode())
    return tlv(0x31, b"".join(tlv(0x30, tlv(0x0c, k.encode()) + val(v)) for k, v in pairs.items()))


def _nska(iv, ct, tag):
    """Blob NSKeyedArchiver SFAuthenticatedCiphertext (vettore, testo cifrato, codice di autenticazione)."""
    U = plistlib.UID
    return plistlib.dumps({"$archiver": "NSKeyedArchiver", "$version": 100000, "$top": {"root": U(1)},
                           "$objects": ["$null", {"$class": U(5), "SFInitializationVector": U(2), "SFCiphertext": U(3),
                                                  "SFAuthenticationCode": U(4)}, iv, ct, tag,
                                        {"$classname": "SFAuthenticatedCiphertext",
                                         "$classes": ["SFAuthenticatedCiphertext", "NSObject"]}]},
                          fmt=plistlib.FMT_BINARY)


def portachiavi_cifrato(AES, voci):
    """backup_keychain_v2.plist FINTO nel formato cifrato di Cellebrite (keychainEntries, AES-GCM con chiavi inventate e
    derivate da un testo fisso: il file è sempre uguale)."""
    def k(nome, n=32):
        return hashlib.sha256(b"collaudo-RepertIA-" + nome.encode()).digest()[:n]

    def gcm(key, nome, dati):
        iv = k("iv-" + nome, 12)
        c = AES.new(key, AES.MODE_GCM, nonce=iv)
        ct, tag = c.encrypt_and_digest(dati)
        return _nska(iv, ct, tag)
    class_key = k("classe-6")
    entries = []
    for i, (tabella, meta, segreto) in enumerate(voci, 1):
        mk, dk = k(f"meta-{i}"), k(f"dati-{i}")
        entries.append({"rowID": i, "classKeyIdx": 6, "table": tabella,
                        "metadata": {"wrappedKey": gcm(class_key, f"wk-{i}", mk), "ciphertext": gcm(mk, f"mc-{i}", _der(meta))},
                        "data": {"unwrappedKey": dk, "ciphertext": gcm(dk, f"dc-{i}", _der({"v_Data": segreto}))}})
    return plistlib.dumps({"classKeyIdxToUnwrappedMetadataClassKey": {"6": class_key}, "keychainEntries": entries},
                          fmt=plistlib.FMT_BINARY)


def build_ios_portachiavi(ileapp, out):
    """Estrazione iOS minima (stile Cellebrite FFS) con un portachiavi FINTO cifrato in extra/KeychainDump e, a parte, un
    portachiavi FINTO decifrato (genp) da passare a iLEAPP con --keychain. Due prove: con il portachiavi fornito e senza
    (iLEAPP usa quello dell'estrazione)."""
    AES = _aes(ileapp)
    t0 = ("tempo", "20240315100000Z")
    cifrato = portachiavi_cifrato(AES, [
        ("genp", {"agrp": "apple", "svce": "AirPort", "acct": KC_WIFI_ESTRAZIONE[0], "cdat": t0, "mdat": t0,
                  "UUID": "00000000-0000-4000-8000-000000000001"}, KC_WIFI_ESTRAZIONE[1].encode()),
        ("inet", {"agrp": "com.apple.cfnetwork", "atyp": "form", "srvr": KC_WEB_ESTRAZIONE[0], "acct": KC_WEB_ESTRAZIONE[1],
                  "labl": "Sito di prova (inventato)", "cdat": t0, "mdat": t0, "UUID": "00000000-0000-4000-8000-000000000002"},
         KC_WEB_ESTRAZIONE[2].encode())])
    fornito = plistlib.dumps({"genp": [
        {"agrp": "apple", "svce": "AirPort", "acct": KC_WIFI_FORNITO[0], "v_Data": KC_WIFI_FORNITO[1].encode()},
        {"agrp": "ABCDE12345.org.whispersystems.signal", "svce": "GRDBKeyChainService", "acct": "GRDBDatabaseCipherKeySpec",
         "v_Data": hashlib.sha256(b"collaudo-RepertIA-signal-finto").digest() + b"\x00" * 16}]}, fmt=plistlib.FMT_XML)
    zpath = out / "ios_portachiavi.zip"
    mt = int(T0.timestamp())
    sysver = plistlib.dumps({"ProductName": "iPhone OS", "ProductVersion": "17.5.1", "ProductBuildVersion": "21F90"})
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        def add(name, payload, mode=0o100644):
            zi = zipfile.ZipInfo(name, date_time=(2024, 3, 15, 10, 0, 0))
            zi.create_system = 3
            zi.external_attr = mode << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.extra = struct.pack("<HHBl", 0x5455, 5, 1, mt)
            zf.writestr(zi, payload)
        add("filesystem1/System/Library/CoreServices/SystemVersion.plist", sysver)
        add("filesystem2/db/timezone/localtime", b"/usr/share/zoneinfo/America/New_York", 0o120755)
        add("filesystem2/mobile/Library/Preferences/.leggimi_collaudo.txt",
            "Estrazione FINTA per il collaudo di RepertIA: nessun dato reale.\n".encode())
        add("extra/KeychainDump/backup_keychain_v2.plist", cifrato)
    kpath = out / "portachiavi_finto.plist"
    kpath.write_bytes(fornito)
    zsha = hashlib.sha256(zpath.read_bytes()).hexdigest()
    ksha = hashlib.sha256(fornito).hexdigest()
    segreti = [KC_WIFI_ESTRAZIONE[1], KC_WEB_ESTRAZIONE[2], KC_WIFI_FORNITO[1]]
    comune = {"tipo": "smartphone", "immagine": "smartphone/ios_portachiavi.zip", "opzioni": ["--leapp"],
              "indipendente": False, "sha256_immagine": zsha,
              "fonte": "costruito per il collaudo di RepertIA con portachiavi FINTI (nessun dato reale)"}
    return [
        dict(comune, nome="22_smartphone_ios_portachiavi", portachiavi="smartphone/portachiavi_finto.plist",
             descrizione="Estrazione iOS minima con un portachiavi finto cifrato (formato Cellebrite) in extra/KeychainDump e "
                         "un portachiavi finto decifrato passato a iLEAPP con --keychain: SHA-256 nel registro, passaggio a "
                         "iLEAPP, artefatti del portachiavi, valori segreti nascosti nell'interfaccia, nel report portatile "
                         "e negli strumenti dell'agente.",
             atteso={"piattaforma": "ios", "sistema_versione": "17.5.1",
                     "portachiavi": {"sha256": ksha, "uso": "fornito", "voci_lette": 2, "anche_nell_estrazione": True},
                     "leapp_righe_min": {"Keychain Wifi Credentials": 1, "Keychain Web Passwords": 1},
                     "segreti": {"artefatto": "Keychain Wifi Credentials", "visibile": KC_WIFI_ESTRAZIONE[0],
                                 "valore": KC_WIFI_ESTRAZIONE[1], "mai_in_chiaro": segreti}}),
        dict(comune, nome="23_smartphone_ios_portachiavi_estrazione",
             descrizione="La stessa estrazione senza portachiavi fornito: iLEAPP usa quello dell'estrazione e il caso lo "
                         "dichiara.",
             atteso={"piattaforma": "ios",
                     "portachiavi": {"uso": "estrazione", "file_finisce": "extra/KeychainDump/backup_keychain_v2.plist"},
                     "leapp_righe_min": {"Keychain Wifi Credentials": 1},
                     "segreti": {"artefatto": "Keychain Wifi Credentials", "visibile": KC_WIFI_ESTRAZIONE[0],
                                 "valore": KC_WIFI_ESTRAZIONE[1], "mai_in_chiaro": segreti[:2]}}),
    ]


def _png(rgb):
    """PNG 2×2 valido di un colore (per le anteprime del collaudo)."""
    import zlib
    raw = b"".join(b"\x00" + bytes(rgb) * 2 for _ in range(2))
    ch = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    return (b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)) +
            ch(b"IDAT", zlib.compress(raw)) + ch(b"IEND", b""))


def build_ios_citati(out):
    """Estrazione iOS FINTA (stile Cellebrite FFS) per i file citati: IMG_0059.PNG nelle stesse posizioni del caso
    pubblico iOS 13.4.1 di Hickman (DCIM/100APPLE, copia in PhotoData/OutgoingTemp, cartella omonima delle miniature),
    due IMG_0100.JPG diverse in cartelle diverse, due verbale.pdf con lo stesso percorso finale in due app. Le righe da
    provare (campi come quelli di iLEAPP, es. «Photos.sqlite EXIF Analysis»: Directory + Filename) e l'esito atteso
    sono nel file dei valori attesi; il collaudo le valuta con la stessa ricerca del pannello «File citato»."""
    png = _png((40, 120, 200))
    jpg_a, jpg_b = THUMB, THUMB + b"\x00" * 100
    pdf_a = b"%PDF-1.4\n% verbale A (finto, collaudo RepertIA)\n%%EOF\n"
    pdf_b = b"%PDF-1.4\n% verbale B (finto, collaudo RepertIA), contenuto diverso\n%%EOF\n"
    m = "filesystem2/mobile/"
    app = m + "Containers/Data/Application/"
    files = {
        m + "Media/DCIM/100APPLE/IMG_0059.PNG": png,
        m + "Media/PhotoData/OutgoingTemp/83197365-FE97-4181-A0C0-10BAADC565B9/IMG_0059.PNG": png,
        m + "Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0059.PNG/5005.JPG": THUMB,
        m + "Media/PhotoData/Metadata/DCIM/100APPLE/IMG_0059.AAE": b"<?xml version=\"1.0\"?><plist/>",
        m + "Media/DCIM/100APPLE/IMG_0100.JPG": jpg_a,
        app + "0A1B2C3D-0000-4000-8000-00000000000A/Documents/IMG_0100.JPG": jpg_b,
        app + "0A1B2C3D-0000-4000-8000-00000000000B/Documents/Downloads/verbale.pdf": pdf_a,
        app + "0A1B2C3D-0000-4000-8000-00000000000C/Documents/Downloads/verbale.pdf": pdf_b,
    }
    zpath = out / "ios_file_citati.zip"
    mt = int(T0.timestamp())
    sysver = plistlib.dumps({"ProductName": "iPhone OS", "ProductVersion": "13.4.1", "ProductBuildVersion": "17E262"})
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        def add(name, payload, mode=0o100644):
            zi = zipfile.ZipInfo(name, date_time=(2024, 3, 15, 10, 0, 0))
            zi.create_system = 3
            zi.external_attr = mode << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.extra = struct.pack("<HHBl", 0x5455, 5, 1, mt)
            zf.writestr(zi, payload)
        add("filesystem1/System/Library/CoreServices/SystemVersion.plist", sysver)
        add("filesystem2/db/timezone/localtime", b"/usr/share/zoneinfo/America/New_York", 0o120755)
        add(m + "Library/Preferences/.leggimi_collaudo.txt", "Estrazione FINTA per il collaudo di RepertIA: nessun dato reale.\n".encode())
        for k, v in files.items():
            add(k, v)
    dcim = "mobile/Media/DCIM/100APPLE"
    righe = [
        {"nome": "Photos.sqlite EXIF Analysis: IMG_0059.PNG (cartella e nome in due campi)",
         "campi": {"Directory": "DCIM/100APPLE", "Filename": "IMG_0059.PNG", "Bundle Creator": "com.apple.springboard"},
         "atteso": [{"livello": "certo", "metodo": "percorso", "campi": ["Directory + Filename"],
                     "finisce": dcim + "/IMG_0059.PNG", "cartella_finisce": dcim, "copie": 0}]},
        {"nome": "IMG_0059.PNG: percorso completo, cartella e nome nella stessa riga",
         "campi": {"File Path": "/var/mobile/Media/DCIM/100APPLE/IMG_0059.PNG", "Directory": "DCIM/100APPLE",
                   "Filename": "IMG_0059.PNG"},
         "atteso": [{"livello": "certo", "metodo": "percorso", "campi": ["File Path", "Directory + Filename"],
                     "finisce": dcim + "/IMG_0059.PNG", "cartella_finisce": dcim, "copie": 0}]},
        {"nome": "IMG_0059.PNG con il nome originale di un altro file (come Photos.sqlite: «Original Filename»)",
         "campi": {"Directory": "DCIM/100APPLE", "Filename": "IMG_0059.PNG", "Original Filename": "verbale.pdf"},
         "atteso": [{"livello": "certo", "metodo": "percorso", "campi": ["Directory + Filename"],
                     "finisce": dcim + "/IMG_0059.PNG", "cartella_finisce": dcim},
                    {"livello": "probabile", "metodo": "nome", "campi": ["Original Filename"], "candidati": 2}]},
        {"nome": "IMG_0100.JPG: solo il nome, due file con lo stesso nome in cartelle diverse",
         "campi": {"Filename": "IMG_0100.JPG"},
         "atteso": [{"livello": "probabile", "metodo": "nome", "candidati": 2}]},
        {"nome": "IMG_0100.JPG: nome e dimensione",
         "campi": {"Filename": "IMG_0100.JPG", "File Size": len(jpg_a)},
         "atteso": [{"livello": "probabile", "metodo": "nome+dimensione", "candidati": 1, "finisce": dcim + "/IMG_0100.JPG"}]},
        {"nome": "IMG_0100.JPG: nome, dimensione e SHA-256 (hash verificato)",
         "campi": {"Filename": "IMG_0100.JPG", "File Size": len(jpg_b), "SHA256": hashlib.sha256(jpg_b).hexdigest()},
         "atteso": [{"livello": "certo", "metodo": "hash", "verifica": "uguale", "finisce": "Documents/IMG_0100.JPG"}]},
        {"nome": "verbale.pdf: stesso percorso finale in due app",
         "campi": {"File Path": "Documents/Downloads/verbale.pdf"},
         "atteso": [{"livello": "certo", "metodo": "percorso", "copie": 1}]},
        {"nome": "IMG_9999.JPG: non presente",
         "campi": {"Filename": "IMG_9999.JPG"},
         "atteso": [{"livello": "assente"}]},
    ]
    return {"nome": "24_smartphone_ios_file_citati", "tipo": "smartphone", "immagine": "smartphone/ios_file_citati.zip",
            "opzioni": [], "indipendente": False, "sha256_immagine": hashlib.sha256(zpath.read_bytes()).hexdigest(),
            "fonte": "costruito per il collaudo di RepertIA (file finti, nessun dato reale); posizioni di IMG_0059.PNG come "
                     "nell'immagine pubblica iOS 13.4.1 di Josh Hickman",
            "descrizione": "File citati: cartella e nome in due campi diventano un percorso completo, un solo file citato per "
                           "file diverso, esito in tre livelli (certo, probabile con i candidati, assente), copie con lo "
                           "stesso percorso finale.",
            "atteso": {"piattaforma": "ios", "sistema_versione": "13.4.1", "righe_citate": righe}}


def aggiungi_citati(base):
    spec_f = base / "atteso_smartphone.json"
    spec = json.loads(spec_f.read_text(encoding="utf-8"))
    t = build_ios_citati(base / "smartphone")
    spec["prove"] = [x for x in spec["prove"] if x["nome"] != t["nome"]] + [t]
    for x in spec["prove"]:                 # iLEAPP sugli allegati reali degli SMS: «Attachment File» + nome = un file
        if x["nome"] == "20_smartphone_ios_zip":
            x["atteso"]["file_citati_livelli"] = SMS_LIVELLI
    spec["nota"] = (spec.get("nota") or "") + f" File citati aggiunti il {time.strftime('%d/%m/%Y')}."
    spec_f.write_text(json.dumps(spec, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({t["nome"]: t["sha256_immagine"]}, indent=1))


# allegati degli SMS nei risultati di iLEAPP sugli estratti pubblici iOS 15: 11 righe con «Attachment File» (media/ del
# rapporto, collegato al file dell'estrazione nel database di iLEAPP), 8 anche con il nome dell'allegato
SMS_LIVELLI = {"SMS": {"certo": 11, "probabile": 0, "assente": 0, "uniti": 8}}


# ritagli di sysdiagnose dei test di iLEAPP (licenza MIT), alla release usata nei pacchetti
ILEAPP_TEST = "https://raw.githubusercontent.com/abrignoni/iLEAPP/v2026.4.5/admin/test/cases/data/"
SYSD_ZIP = {
    "sysdiagnoseProcess/testdata.sysdiagnoseProcess.sysdiagnoseProcess.case1.zip":
        "c088a21cfe584add54e5642dfcbc3c5e82cf329da019bbff33cd25761ece6881",
    "batteryUISysdiagnose/testdata.batteryUISysdiagnose.batteryUISysdiagnoseApps.case_ios26_sanitized.zip":
        "e11493c7401051e03ac88d045c96f81b411b01cb84c6fc8b31093846d2405f99",
    "managedSettings/testdata.managedSettings.managedSettings.case_ios26_sanitized.zip":
        "1c8348db1b7c882fe102dedc3ecba9e8ec6f4bab6121aab55930aba475be1972",
}


def _scarica(rel, sha, dest):
    import urllib.request
    p = dest / Path(rel).name
    if not p.is_file():
        try:
            with urllib.request.urlopen(ILEAPP_TEST + rel, timeout=120) as r:
                p.write_bytes(r.read())
        except OSError:                     # Python senza certificati (es. python.org su Mac): curl del sistema
            import subprocess
            subprocess.run(["curl", "-sfL", "-o", str(p), ILEAPP_TEST + rel], check=True, timeout=300)
    got = hashlib.sha256(p.read_bytes()).hexdigest()
    if got != sha:
        raise SystemExit(f"SHA-256 diverso per {rel}: {got}")
    return p


def _tar_gz(files, out):
    """tar.gz riproducibile (date fisse, gzip senza data): {nome nell'archivio: (byte, mtime)}."""
    import gzip
    import io
    dirs = sorted({str(Path(n).parents[i]) for n in files for i in range(len(Path(n).parts) - 1)})
    with open(out, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for d in dirs:
            ti = tarfile.TarInfo(d)
            ti.type, ti.mode, ti.mtime = tarfile.DIRTYPE, 0o755, min(m for _b, m in files.values())
            tf.addfile(ti)
        for n in sorted(files):
            b, m = files[n]
            ti = tarfile.TarInfo(n)
            ti.size, ti.mode, ti.mtime = len(b), 0o644, m
            tf.addfile(ti, io.BytesIO(b))
    return hashlib.sha256(out.read_bytes()).hexdigest()


def conta_ps(txt):
    """Righe di processo di ps.txt contate qui, senza iLEAPP: 18 campi o più, PID e PID padre numerici."""
    n = 0
    for ln in txt.splitlines():
        if ln.startswith("USER") or not ln.strip():
            continue
        p = ln.split(maxsplit=17)
        if len(p) >= 18 and p[3].isdigit() and p[4].isdigit():
            n += 1
    return n


def build_sysdiagnose(out):
    """Due archivi nella forma di un sysdiagnose dai ritagli pubblici dei test di iLEAPP; restituisce la prova."""
    out.mkdir(parents=True, exist_ok=True)
    dl = Path(tempfile.mkdtemp(prefix="sysd_"))
    zips = {rel: _scarica(rel, sha, dl) for rel, sha in SYSD_ZIP.items()}
    gruppi = {}
    for rel, z in zips.items():
        with zipfile.ZipFile(z) as zf:
            for zi in zf.infolist():
                if zi.is_dir():
                    continue
                radice = zi.filename.split("/")[0]
                m = int(dt.datetime(*zi.date_time, tzinfo=dt.timezone.utc).timestamp())
                gruppi.setdefault(radice, {})[zi.filename] = (zf.read(zi), m)
    shutil.rmtree(dl, ignore_errors=True)
    arch, attesi = [], []
    for radice, files in sorted(gruppi.items()):
        nome = radice + ".tar.gz"
        sha = _tar_gz(files, out / nome)
        ps = next((b for n, (b, _m) in files.items() if n.endswith("/ps.txt")), None)
        arch.append("smartphone/" + nome)
        a = {"file": nome, "sha256": sha, "cartella": radice}
        if radice.endswith("_20A362"):
            a.update({"creato_utc": "2025-04-07T15:06:18Z", "build": "20A362", "dispositivo": "iPhone",
                      "righe_min": {"Sysdiagnose Process": conta_ps(ps.decode("utf-8", "replace"))}, "righe_esatte": True})
        else:
            a.update({"creato_utc": "2027-07-19T14:18:09Z", "build": "23G71", "dispositivo": "iPhone",
                      "file_attesi": sorted(n.split("/", 1)[1] for n in files)})
        attesi.append(a)
    return {"nome": "25_smartphone_ios_sysdiagnose", "tipo": "smartphone", "immagine": "smartphone/ios_prova.zip",
            "opzioni": ["--no-chat", "--no-indice"], "sysdiagnose": arch, "indipendente": False,
            "fonte": "ritagli pubblici di sysdiagnose dai test di iLEAPP v2026.4.5 (ps.txt reale iOS 16 20A362; BatteryUI e "
                     "ManagedSettings reali di iOS 26.6 23G71 con identificativi sostituiti dagli autori), riuniti in "
                     "archivi nella forma di un sysdiagnose: NON sono sysdiagnose completi",
            "descrizione": "Due sysdiagnose forniti a parte: SHA-256 nel registro, nessuna copia nel caso, data di creazione e "
                           "dispositivo dal nome, secondo giro di iLEAPP, righe nel gruppo «Sysdiagnose» marcate «da "
                           "sysdiagnose <nome>», processi di ps.txt contati senza iLEAPP, sezione nel report.",
            "atteso": {"piattaforma": "ios", "sysdiagnose": attesi}}


def aggiungi_sysdiagnose(base):
    spec_f = base / "atteso_smartphone.json"
    spec = json.loads(spec_f.read_text(encoding="utf-8"))
    t = build_sysdiagnose(base / "smartphone")
    sha_img = next((x.get("sha256_immagine") for x in spec["prove"] if x.get("immagine") == t["immagine"]), None)
    if sha_img:
        t["sha256_immagine"] = sha_img
    spec["prove"] = [x for x in spec["prove"] if x["nome"] != t["nome"]] + [t]
    spec["nota"] = (spec.get("nota") or "") + f" Sysdiagnose aggiunti il {time.strftime('%d/%m/%Y')}."
    spec_f.write_text(json.dumps(spec, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({x["file"]: x["sha256"] for x in t["atteso"]["sysdiagnose"]}, indent=1))


def aggiungi_portachiavi(base, ileapp):
    spec_f = base / "atteso_smartphone.json"
    spec = json.loads(spec_f.read_text(encoding="utf-8"))
    nuove = build_ios_portachiavi(ileapp, base / "smartphone")
    nomi = {t["nome"] for t in nuove}
    spec["prove"] = [t for t in spec["prove"] if t["nome"] not in nomi] + nuove
    spec["nota"] = (spec.get("nota") or "") + f" Portachiavi finto aggiunto il {time.strftime('%d/%m/%Y')}."
    spec_f.write_text(json.dumps(spec, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({t["nome"]: t["sha256_immagine"] for t in nuove}, indent=1))


# --------------------------------------------------------------------------------- Android

WA = [  # (minuti da T0, chat, from_me, mittente nel gruppo, tipo, testo)
    (0, "390000000001@s.whatsapp.net", 1, None, 0, "Ciao Marco, ci vediamo domani alle 10?"),
    (3, "390000000001@s.whatsapp.net", 0, None, 0, "Sì, al bar della stazione."),
    (5, "390000000001@s.whatsapp.net", 0, None, 1, "Ecco la foto del documento"),
    (6, "390000000001@s.whatsapp.net", 1, None, 5, None),
    (60, "120000000000000001@g.us", 0, "390000000002@s.whatsapp.net", 0, "Riunione spostata a venerdì"),
    (61, "120000000000000001@g.us", 1, None, 0, "Va bene per me"),
    (62, "120000000000000001@g.us", 0, "390000000001@s.whatsapp.net", 15, None),
    (63, "120000000000000001@g.us", 0, None, 7, None),
    (90, "390000000001@s.whatsapp.net", 0, None, 1, "Foto spostata: si trova solo per hash"),
    (91, "390000000001@s.whatsapp.net", 0, None, 1, "Foto non scaricata: resta la miniatura"),
    (92, "390000000001@s.whatsapp.net", 1, None, 1, "Foto cancellata dal telefono"),
    (1440, "390000000001@s.whatsapp.net", 0, None, 0, "PAROLA-CHIAVE-COLLAUDO-WAL: questo messaggio è solo nel -wal"),
]
WA_MEDIA = "data/media/0/Android/media/com.whatsapp/WhatsApp/Media"
# miniatura JPEG 8×8 (azzurra), come quelle che WhatsApp salva nel database per i file non scaricati
THUMB = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAA0JCgsKCA0LCgsODg0PEyAVExISEyccHhcgLikxMC4pLSwzOko+MzZGNywtQFdBRkxOUlNSMj5aYV"
    "pQYEpRUk//2wBDAQ4ODhMREyYVFSZPNS01T09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0//wAARCAAI"
    "AAgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhBy"
    "JxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKT"
    "lJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAA"
    "AAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRom"
    "JygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExc"
    "bHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwCjRRRXvHiH/9k=")


def foto(n):
    """Contenuto JPEG finto e diverso per ogni foto di prova."""
    return b"\xff\xd8\xff\xe0" + f"JFIF-collaudo-RepertIA-{n}".encode() * 50 + b"\xff\xd9"


def build_whatsapp(dest):
    db = dest / "data/data/com.whatsapp/databases"
    db.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db / "msgstore.db")
    con.executescript("""
        PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
        CREATE TABLE jid(_id INTEGER PRIMARY KEY, user TEXT, server TEXT, raw_string TEXT);
        CREATE TABLE chat(_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT);
        CREATE TABLE message(_id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER, key_id TEXT,
            sender_jid_row_id INTEGER, status INTEGER, timestamp INTEGER, received_timestamp INTEGER,
            message_type INTEGER, text_data TEXT, starred INTEGER);
        CREATE TABLE message_media(message_row_id INTEGER PRIMARY KEY, file_path TEXT, mime_type TEXT,
            file_size INTEGER, media_name TEXT, file_hash TEXT);
        CREATE TABLE message_thumbnail(message_row_id INTEGER PRIMARY KEY, thumbnail BLOB);
        CREATE TABLE message_location(message_row_id INTEGER PRIMARY KEY, latitude REAL, longitude REAL, place_name TEXT);
        CREATE TABLE group_participant_user(_id INTEGER PRIMARY KEY, group_jid_row_id INTEGER, user_jid_row_id INTEGER);
    """)
    jids = {}
    for j in ["390000000001@s.whatsapp.net", "390000000002@s.whatsapp.net", "120000000000000001@g.us"]:
        jids[j] = con.execute("INSERT INTO jid(user, server, raw_string) VALUES (?,?,?)",
                              (j.split("@")[0], j.split("@")[1], j)).lastrowid
    chats = {"390000000001@s.whatsapp.net": con.execute("INSERT INTO chat(jid_row_id, subject) VALUES (?, NULL)",
                                                         (jids["390000000001@s.whatsapp.net"],)).lastrowid,
             "120000000000000001@g.us": con.execute("INSERT INTO chat(jid_row_id, subject) VALUES (?, ?)",
                                                     (jids["120000000000000001@g.us"], "Gruppo collaudo")).lastrowid}
    for u in ("390000000001@s.whatsapp.net", "390000000002@s.whatsapp.net"):
        con.execute("INSERT INTO group_participant_user(group_jid_row_id, user_jid_row_id) VALUES (?,?)",
                    (jids["120000000000000001@g.us"], jids[u]))
    photo = b"\xff\xd8\xff\xe0" + b"JFIF-collaudo-RepertIA" * 50 + b"\xff\xd9"
    # allegati: (file_path nel database, contenuto, dove sta davvero nell'estrazione o None, miniatura nel database)
    media = {3: ("Media/WhatsApp Images/IMG-20240315-WA0001.jpg", photo, "WhatsApp Images/IMG-20240315-WA0001.jpg", None),
             9: ("Media/WhatsApp Images/IMG-20240315-WA0002.jpg", foto(2), "WhatsApp Images/Private/spostata_0002.jpg", None),
             10: ("Media/WhatsApp Images/IMG-20240315-WA0003.jpg", foto(3), None, THUMB),
             11: ("Media/WhatsApp Images/Sent/IMG-20240315-WA0004.jpg", foto(4), None, None)}
    expected = []
    for k, (mins, chat, me, snd, ty, text) in enumerate(WA, 1):
        if k == len(WA):
            con.commit()          # l'ultimo messaggio resta solo nel file -wal (non riversato nel database)
        t = T0 + dt.timedelta(minutes=mins)
        mid = con.execute("INSERT INTO message(chat_row_id, from_me, key_id, sender_jid_row_id, status, timestamp, "
                          "received_timestamp, message_type, text_data, starred) VALUES (?,?,?,?,?,?,?,?,?,0)",
                          (chats[chat], me, f"KEY{k:04d}", jids.get(snd), 13 if me else 0, ms(t), ms(t) + 900, ty,
                           text)).lastrowid
        if ty == 1:
            fpth, data, _dove, th = media[k]
            con.execute("INSERT INTO message_media VALUES (?,?,?,?,?,?)",
                        (mid, fpth, "image/jpeg", len(data), Path(fpth).name,
                         base64.b64encode(hashlib.sha256(data).digest()).decode()))
            if th:
                con.execute("INSERT INTO message_thumbnail VALUES (?,?)", (mid, th))
        if ty == 5:
            con.execute("INSERT INTO message_location VALUES (?,?,?,?)", (mid, 41.9009, 12.5016, "Roma Termini"))
        expected.append(t.strftime("%Y-%m-%dT%H:%M:%S"))
        if k == len(WA) - 1:
            con.commit()
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")   # tutto nel database tranne l'ultimo
    con.commit()
    for suf in ("", "-wal", "-shm"):                      # copia mentre la connessione è aperta: il -wal resta
        shutil.copyfile(str(db / "msgstore.db") + suf, str(db / "msgstore.copia") + suf)
    con.close()
    for suf in ("", "-wal", "-shm"):
        Path(str(db / "msgstore.db") + suf).unlink(missing_ok=True)
        if Path(str(db / "msgstore.copia") + suf).exists():
            Path(str(db / "msgstore.copia") + suf).rename(str(db / "msgstore.db") + suf)
    wa = sqlite3.connect(db / "wa.db")
    wa.executescript("CREATE TABLE wa_contacts(_id INTEGER PRIMARY KEY, jid TEXT, display_name TEXT, wa_name TEXT, number TEXT);")
    wa.executemany("INSERT INTO wa_contacts(jid, display_name, wa_name, number) VALUES (?,?,?,?)",
                   [("390000000001@s.whatsapp.net", "Marco Rossi", "Marco", "+39 000 000 0001"),
                    ("390000000002@s.whatsapp.net", None, "Giulia B.", "+39 000 000 0002")])
    wa.commit()
    wa.close()
    cdb = dest / "data/data/com.android.providers.contacts/databases"
    cdb.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(cdb / "contacts2.db")
    c.executescript("""CREATE TABLE mimetypes(_id INTEGER PRIMARY KEY, mimetype TEXT);
        CREATE TABLE raw_contacts(_id INTEGER PRIMARY KEY, display_name TEXT);
        CREATE TABLE data(_id INTEGER PRIMARY KEY, raw_contact_id INTEGER, mimetype_id INTEGER, data1 TEXT);
        INSERT INTO mimetypes VALUES (1, 'vnd.android.cursor.item/phone_v2'), (2, 'vnd.android.cursor.item/name');
        INSERT INTO raw_contacts VALUES (1, 'Giulia Bianchi');
        INSERT INTO data VALUES (1, 1, 1, '000 000 0002'), (2, 1, 2, 'Giulia Bianchi');""")
    c.commit()
    c.close()
    shutil.rmtree(dest / WA_MEDIA, ignore_errors=True)
    for fpth, data, dove, th in media.values():
        if dove:
            f = dest / WA_MEDIA / dove
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
    esito = {"percorso": 1, "hash": 1, "miniatura": 1, "assente": 1}
    return expected, hashlib.sha256(photo).hexdigest(), esito


def build_gphotos(dest):
    """Google Photos costruito: gphotos-1.db (tabella local_media letta da ALEAPP) con tre file: uno al suo percorso,
    uno spostato in un'altra cartella (si trova per nome e dimensione), uno assente. Restituisce l'esito atteso."""
    db = dest / "data/data/com.google.android.apps.photos/databases"
    db.mkdir(parents=True, exist_ok=True)
    (db / "gphotos-1.db").unlink(missing_ok=True)
    con = sqlite3.connect(db / "gphotos-1.db")
    con.execute("CREATE TABLE local_media(_id INTEGER PRIMARY KEY, utc_timestamp INTEGER, filename TEXT, filepath TEXT, "
                "capture_timestamp INTEGER, timezone_offset INTEGER, width INTEGER, height INTEGER, size_bytes INTEGER, "
                "duration INTEGER, latitude REAL, longitude REAL, folder_name TEXT, media_store_id INTEGER, bucket_id INTEGER)")
    png = b"\x89PNG\r\n\x1a\n" + b"collaudo-RepertIA-screenshot" * 40
    jpg = foto(10)
    files = [("Screenshot_20240315-100000.png", "Pictures/Screenshots", png, "Pictures/Screenshots"),
             ("IMG_20240315_101500.jpg", "DCIM/Camera", jpg, "DCIM/Spostate"),
             ("IMG_20240315_103000.jpg", "DCIM/Camera", foto(11), None)]
    for i, (name, folder, data, dove) in enumerate(files, 1):
        t = ms(T0 + dt.timedelta(minutes=60 + 15 * i))
        con.execute("INSERT INTO local_media(utc_timestamp, filename, filepath, capture_timestamp, timezone_offset, width, "
                    "height, size_bytes, duration, latitude, longitude, folder_name, media_store_id, bucket_id) "
                    "VALUES (?,?,?,?,3600000,1080,2160,?,0,NULL,NULL,?,?,?)",
                    (t, name, f"/storage/emulated/0/{folder}/{name}", t, len(data), folder.split("/")[-1], 100 + i, i))
        if dove:
            f = dest / "data/media/0" / dove / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
    con.commit()
    con.close()
    return {"Google Photos - Local Media": {"percorso": 1, "nome+dimensione": 1, "assente": 1}}


def build_android(aleapp, out):
    data = aleapp / "admin" / "test" / "cases" / "data"
    tmp = Path(tempfile.mkdtemp())
    unzip_into(data / "smsmms/testdata.smsmms.get_sms_mms_combined.anne_a15.zip", tmp, strip="Dump/")
    wa_ts, photo_sha, wa_esito = build_whatsapp(tmp)
    gp = build_gphotos(tmp)
    sysd = tmp / "system"
    sysd.mkdir(exist_ok=True)
    (sysd / "build.prop").write_text("ro.build.version.release=15\nro.product.model=RepertIA-Prova\n"
                                     "ro.product.manufacturer=Collaudo\nro.build.display.id=TEST.240315\n")
    prop = tmp / "data/property"
    prop.mkdir(parents=True, exist_ok=True)
    (prop / "persistent_properties").write_bytes(b"\n\x16\n\x14persist.sys.timezone\x12\x0bEurope/Rome")
    write_tar(tmp, out / "android_prova.tar.gz")
    shutil.rmtree(tmp)
    sms = results(aleapp, "smsmms", "smsmms.get_sms_mms.anne_a15.")
    mms = results(aleapp, "smsmms", "smsmms.get_sms_mms_mms.anne_a15.")
    s_ts = [iso(r[0]) for r in sms["data"]]
    hid = mms["headers"].index("MSG ID")
    seen, m_ts = set(), []
    for r in mms["data"]:
        if r[hid] not in seen:
            seen.add(r[hid])
            m_ts.append(iso(r[0]))
    return {
        "nome": "21_smartphone_android_targz",
        "tipo": "smartphone",
        "immagine": "smartphone/android_prova.tar.gz",
        "opzioni": ["--decomprimi", "--leapp"],
        "indipendente": False,
        "fonte": "SMS/MMS: estratti dell'immagine pubblica Android 15 «anne_a15» e risultati attesi pubblicati nei test "
                 "di ALEAPP; WhatsApp: database costruito per il collaudo con contenuto noto",
        "descrizione": "tar.gz (copia derivata decompressa) con mmssms.db reale e WhatsApp costruito: un messaggio solo "
                       "nel -wal, foto collegata, posizione, gruppo, messaggio eliminato, nomi dalle rubriche.",
        "atteso": {
            "piattaforma": "android", "sistema_versione": "15", "fuso": "Europe/Rome", "decompressa": True,
            "chat_messaggi": {"sms": len(s_ts) + len(m_ts), "whatsapp": len(wa_ts)},
            "chat_orari_sha256": {"sms": sha_list(s_ts + m_ts), "whatsapp": sha_list(wa_ts)},
            "chat_testi": [{"app": "whatsapp", "ts": wa_ts[-1], "contiene": "PAROLA-CHIAVE-COLLAUDO-WAL"},
                           {"app": "whatsapp", "ts": wa_ts[4], "contiene": "Riunione spostata", "mittente": "Giulia"},
                           {"app": "whatsapp", "ts": wa_ts[1], "contiene": "bar della stazione", "mittente": "Marco Rossi"}],
            "chat_conversazioni": {"whatsapp": 2},
            "allegato_sha256": {"IMG-20240315-WA0001.jpg": photo_sha},
            "allegati_esito": {"whatsapp": wa_esito},
            "allegati_hash_verificati": {"whatsapp": 2},
            "file_citati": gp,
            "posizione": {"lat": 41.9009, "lon": 12.5016},
            "leapp_righe_min": {"SMS Messages": len(s_ts), "MMS Messages": len(mms["data"]),
                                "SMS and MMS Messages": len(s_ts) + len(mms["data"])},
            "date_utc_min": 10,
        },
    }


def write_tar(tmp, tpath):
    mt = T0.timestamp()
    with tarfile.open(tpath, "w:gz", format=tarfile.PAX_FORMAT) as tf:
        for p in sorted(tmp.rglob("*")):
            ti = tf.gettarinfo(str(p), arcname=str(p.relative_to(tmp)))
            ti.mtime = mt
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            ti.pax_headers = {"atime": str(mt + 60), "ctime": str(mt + 120)}
            if p.is_file():
                with open(p, "rb") as fh:
                    tf.addfile(ti, fh)
            else:
                tf.addfile(ti)


def aggiorna_android(base):
    """Ricostruisce WhatsApp e Google Photos dentro android_prova.tar.gz e aggiorna i loro valori attesi; gli estratti
    reali di ALEAPP (SMS/MMS) e i loro valori attesi restano quelli già scritti."""
    spec_f = base / "atteso_smartphone.json"
    spec = json.loads(spec_f.read_text(encoding="utf-8"))
    t = next(x for x in spec["prove"] if x["nome"] == "21_smartphone_android_targz")
    tpath = base / t["immagine"]
    tmp = Path(tempfile.mkdtemp())
    with tarfile.open(tpath) as tf:
        tf.extractall(tmp, filter="data")
    for x in ("data/data/com.whatsapp", "data/data/com.google.android.apps.photos",
              "data/data/com.android.providers.contacts"):         # costruiti qui: si rifanno
        shutil.rmtree(tmp / x, ignore_errors=True)
    wa_ts, photo_sha, wa_esito = build_whatsapp(tmp)
    gp = build_gphotos(tmp)
    write_tar(tmp, tpath)
    shutil.rmtree(tmp)
    a = t["atteso"]
    sms_ts = a["chat_orari_sha256"]["sms"]
    a["chat_messaggi"]["whatsapp"] = len(wa_ts)
    a["chat_orari_sha256"] = {"sms": sms_ts, "whatsapp": sha_list(wa_ts)}
    a["chat_testi"] = [{"app": "whatsapp", "ts": wa_ts[-1], "contiene": "PAROLA-CHIAVE-COLLAUDO-WAL"},
                       {"app": "whatsapp", "ts": wa_ts[4], "contiene": "Riunione spostata", "mittente": "Giulia"},
                       {"app": "whatsapp", "ts": wa_ts[1], "contiene": "bar della stazione", "mittente": "Marco Rossi"}]
    a["allegato_sha256"] = {"IMG-20240315-WA0001.jpg": photo_sha}
    a["allegati_esito"] = {"whatsapp": wa_esito}
    a["allegati_hash_verificati"] = {"whatsapp": 2}
    a["file_citati"] = gp
    t["descrizione"] = ("tar.gz (copia derivata decompressa) con mmssms.db reale e WhatsApp costruito: un messaggio solo nel -wal, "
                        "foto collegata (anche una solo per hash, una con la sola miniatura, una assente), posizione, gruppo, "
                        "messaggio eliminato, nomi dalle rubriche; Google Photos costruito per i file citati.")
    t["sha256_immagine"] = hashlib.sha256(tpath.read_bytes()).hexdigest()
    spec["nota"] = f"Costruito con tools/collaudo_mobile.py; android aggiornato il {time.strftime('%d/%m/%Y')}."
    spec_f.write_text(json.dumps(spec, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({t["nome"]: t["sha256_immagine"]}, indent=1))


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--aggiorna-android":
        return aggiorna_android(Path(sys.argv[2]).expanduser().resolve())
    if len(sys.argv) == 4 and sys.argv[1] == "--portachiavi":
        return aggiungi_portachiavi(Path(sys.argv[2]).expanduser().resolve(), Path(sys.argv[3]).expanduser().resolve())
    if len(sys.argv) == 3 and sys.argv[1] == "--sysdiagnose":
        return aggiungi_sysdiagnose(Path(sys.argv[2]).expanduser().resolve())
    if len(sys.argv) == 3 and sys.argv[1] == "--file-citati":
        return aggiungi_citati(Path(sys.argv[2]).expanduser().resolve())
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    ileapp, aleapp, base = (Path(x).expanduser().resolve() for x in sys.argv[1:])
    out = base / "smartphone"
    out.mkdir(parents=True, exist_ok=True)
    prove = [build_ios(ileapp, out), build_android(aleapp, out)]
    prove[0]["atteso"]["file_citati_livelli"] = SMS_LIVELLI
    portachiavi = build_ios_portachiavi(ileapp, out) + [build_ios_citati(out)]
    for t in prove:
        f = base / t["immagine"]
        t["sha256_immagine"] = hashlib.sha256(f.read_bytes()).hexdigest()
    spec = {"set": "RepertIA – estrazioni di smartphone (2.20)",
            "fonte": "estratti di immagini pubbliche (Josh Hickman iOS 15; Android 15 «anne_a15») dai test di iLEAPP e "
                     "ALEAPP (licenza MIT) e dati costruiti",
            "indipendente": False,
            "nota": f"Costruito con tools/collaudo_mobile.py il {time.strftime('%d/%m/%Y')}.",
            "prove": prove + portachiavi}
    (base / "atteso_smartphone.json").write_text(json.dumps(spec, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({t["nome"]: t["sha256_immagine"] for t in prove}, indent=1))


if __name__ == "__main__":
    main()
