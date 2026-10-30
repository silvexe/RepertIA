# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - backup locali di WhatsApp Android (.crypt14, .crypt15) decifrati con la chiave dell'estrazione (dalla 2.20).

WhatsApp salva ogni notte una copia cifrata del database dei messaggi (`WhatsApp/Databases/msgstore*.db.crypt14`). In
un'estrazione del file system completo c'è spesso anche la chiave, `com.whatsapp/files/key` (158 byte). Un backup è una
fotografia di un giorno precedente: può contenere messaggi poi cancellati dal database attuale.

Formato crypt14 (verificato sui dati di prova pubblici di Hickman, Android 14 / WhatsApp 2.24; riferimento per le posizioni:
WhatsApp-Chat-Exporter, github.com/KnugiHK/WhatsApp-Chat-Exporter, MIT, Whatsapp_Chat_Exporter/android_crypt.py):
- chiave: file serializzato Java; firma = byte 30-62, chiave AES-256 = byte 126-158;
- backup: lunghezza dell'intestazione (varint) + protobuf; nel campo 2 annidato il campo 3 è la firma (deve essere uguale
  a quella della chiave, altrimenti il backup è stato cifrato con un'ALTRA chiave) e il campo 5 è l'IV; poi i dati cifrati
  AES-GCM, con il tag di verifica nei 16 byte che precedono gli ultimi 16; il risultato è compresso zlib.
Si accetta solo un risultato con il tag GCM verificato e che sia un database SQLite: niente di «decifrato a metà».
Gli incrementali (`msgstore-increment-N.db.crypt14`) decifrati sono archivi ZIP in un formato interno non documentato: si
elencano, non si interpretano. crypt12 non è gestito.

Formato crypt15 (backup cifrati end-to-end; verificato sui file di prova pubblici di wa-crypt-tools, GPL-3.0, tests/res;
riferimento: WhatsApp-Chat-Exporter, android_crypt.py):
- chiave: `com.whatsapp/files/encrypted_backup.key` (array Java di 32 byte) oppure la chiave di 64 cifre esadecimali che
  l'utente ha salvato; la password dei backup da sola non basta (serve ai server di WhatsApp per restituire la chiave);
- chiave AES = HMAC-SHA256(HMAC-SHA256(32 zeri, chiave), «backup encryption» + 0x01);
- backup: lunghezza dell'intestazione + 1 byte, poi protobuf (campo 3 → campo 1 = IV); AES-GCM, tag nei 16 byte che
  precedono gli ultimi 16; il risultato è compresso zlib.
La chiave scritta dall'analista arriva dalla variabile FORENSIA_WA_CHIAVE, solo in memoria: mai su disco né nel registro.

Le librerie AES (pycryptodome) sono quelle che accompagnano iLEAPP/ALEAPP nella cartella `strumenti/` dei pacchetti.
"""
import hashlib
import hmac
import json
import os
import re
import sqlite3
import sys
import zlib
from pathlib import Path

from forense_lingua import tr, N_  # noqa: E402

KEY_RE = re.compile(r"(^|/)com\.whatsapp(\.w4b)?/files/key$")
KEY15_RE = re.compile(r"(^|/)com\.whatsapp(\.w4b)?/files/encrypted_backup\.key$")
ENV_CHIAVE = "FORENSIA_WA_CHIAVE"
BACKUP_RE = re.compile(r"(^|/)(msgstore[^/]*\.db)\.crypt(\d+)$", re.I)
INCREMENT_RE = re.compile(r"msgstore-increment-\d+\.db$", re.I)
CARTELLA = "backup_whatsapp"
DB_OFFSETS = (99, 158, 190, 191, 193, 194, 196)        # posizioni note dei dati cifrati (WhatsApp-Chat-Exporter)
ESITI = {"decifrato": N_("decifrato (tag GCM verificato, database SQLite)"),
         "incrementale": N_("decifrato, ma è un backup incrementale (archivio ZIP in un formato non documentato): non letto"),
         "altra_chiave": N_("cifrato con un'altra chiave (la firma non è quella della chiave nell'estrazione)"),
         "formato": N_("formato non gestito"),
         "errore": N_("non decifrato")}


def _aes():
    """AES (pycryptodome) dalla cartella delle librerie di iLEAPP/ALEAPP se non è già importabile."""
    try:
        from Crypto.Cipher import AES
        return AES
    except ImportError:
        pass
    import forense_mobile_leapp as fml
    for k in ("android", "ios"):
        d = fml.tool_dir(k)
        if d and (d / "site").is_dir() and str(d / "site") not in sys.path:
            sys.path.append(str(d / "site"))
    from Crypto.Cipher import AES
    return AES


def _varint(b, i):
    v = s = 0
    while True:
        c = b[i]
        i += 1
        v |= (c & 0x7F) << s
        s += 7
        if c < 0x80:
            return v, i


def _pb(b):
    """Campi «length-delimited» di un protobuf: {numero: [valori]} (gli altri tipi si saltano)."""
    i, out = 0, {}
    while i < len(b):
        tag, i = _varint(b, i)
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            _v, i = _varint(b, i)
        elif wt == 2:
            n, i = _varint(b, i)
            out.setdefault(fn, []).append(b[i:i + n])
            i += n
        elif wt == 1:
            i += 8
        elif wt == 5:
            i += 4
        else:
            raise ValueError(tr("intestazione non riconosciuta"))
    return out


def intestazione(data):
    """(firma, iv, fine dell'intestazione) di un backup crypt14."""
    n, i = _varint(data, 0)
    if data[i:i + 1] == b"\x01" and data[i + 1:i + 2] != b"\x08":   # byte facoltativo dopo la lunghezza
        i += 1
    top = _pb(data[i:i + n])
    inner = _pb(top[2][0])
    return inner[3][0], inner[5][0], i + n


def decifra(data, key_file):
    """Database decifrato (bytes) di un backup crypt14, oppure (esito, motivo)."""
    AES = _aes()
    firma_k, chiave = key_file[30:62], key_file[126:158]
    try:
        firma, iv, fine = intestazione(data)
    except (KeyError, IndexError, ValueError) as e:
        return None, ("formato", tr("intestazione crypt14 non riconosciuta ({e})").format(e=e))
    if firma != firma_k:
        return None, ("altra_chiave", tr("firma {a}… del backup, firma {b}… della chiave").format(a=firma[:4].hex(), b=firma_k[:4].hex()))
    for off in (fine,) + tuple(o for o in DB_OFFSETS if o != fine):
        ct = data[off:]
        if len(ct) <= 32:
            continue
        try:
            plain = AES.new(chiave, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct[:-32], ct[-32:-16])
        except ValueError:
            continue
        try:
            raw = zlib.decompress(plain)
        except zlib.error as e:
            return None, ("errore", tr("tag verificato ma dati non decomprimibili ({e})").format(e=e))
        return raw, ("decifrato", tr("dati cifrati dal byte {o}").format(o=off))
    return None, ("errore", tr("tag GCM non verificato a nessuna delle posizioni note"))


def chiave_digitata(s):
    """32 byte dalla chiave di 64 cifre esadecimali scritta dall'analista (spazi e trattini ammessi)."""
    t = re.sub(r"[\s-]", "", s or "")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", t):
        raise ValueError(tr("La chiave deve avere 64 cifre esadecimali (0-9, a-f)."))
    return bytes.fromhex(t)


def chiave_file15(b):
    """32 byte della chiave da encrypted_backup.key (array Java serializzato, oppure byte o esadecimale puri), o None."""
    if len(b) == 32:
        return bytes(b)
    if b[:2] == b"\xac\xed":
        i = b.find(b"\x78\x70")           # fine della descrizione della classe, poi la lunghezza dell'array
        if i >= 0 and int.from_bytes(b[i + 2:i + 6], "big") == 32 and len(b) >= i + 38:
            return bytes(b[i + 6:i + 38])
        return None
    try:
        return chiave_digitata(b.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return None


def deriva15(radice):
    """Chiave AES di un backup crypt15 dalla chiave di 32 byte."""
    k = hmac.new(bytes(32), radice, hashlib.sha256).digest()
    return hmac.new(k, b"backup encryption\x01", hashlib.sha256).digest()


def posizioni15(data):
    """[(iv, inizio dei dati cifrati)] di un crypt15: dall'intestazione, poi le posizioni fisse note."""
    out = []
    n, i = _varint(data, 0)
    try:
        for inizio in (i + 1, i):
            top = _pb(data[inizio:i + 1 + n if inizio > i else i + n])
            if 3 in top:
                iv = _pb(top[3][0])[1][0]
                if len(iv) == 16:
                    out.append((iv, i + 1 + n if inizio > i else i + n))
    except (KeyError, IndexError, ValueError):
        pass
    return out + [(data[8:24], data[0] + 2), (data[7:23], data[0] + 1)]


def decifra15(data, radice):
    """Database decifrato (bytes) di un backup crypt15, oppure (esito, motivo)."""
    AES = _aes()
    if len(data) < 131:
        return None, ("formato", tr("file troppo corto per un crypt15"))
    chiave = deriva15(radice)
    for iv, off in posizioni15(data):
        ct = data[off:]
        for coda in (32, 16):            # tag prima dell'hash finale, oppure in fondo al file
            try:
                plain = AES.new(chiave, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct[:-coda], ct[-coda:len(ct) - coda + 16])
            except ValueError:
                continue
            try:
                return zlib.decompress(plain), ("decifrato", tr("dati cifrati dal byte {o}").format(o=off))
            except zlib.error as e:
                return None, ("errore", tr("tag verificato ma dati non decomprimibili ({e})").format(e=e))
    return None, ("errore", tr("chiave non valida per questo backup o file danneggiato (tag GCM non verificato)"))


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def trova(case, part):
    """(chiavi, backup) dell'estrazione: [(id, percorso, byte)]."""
    import forense_mobile as fm
    m = fm.mx(case)
    try:
        rows = m.execute("SELECT id, path, size FROM mobile_files WHERE part=? AND isdir=0 AND (path LIKE '%/files/key' "
                         "OR path LIKE '%/files/encrypted_backup.key' OR path LIKE '%.crypt%')", (part,)).fetchall()
    finally:
        m.close()
    keys = [(str(i), p, s) for i, p, s in rows if KEY_RE.search(p) or KEY15_RE.search(p)]
    backups = [(str(i), p, s) for i, p, s in rows if BACKUP_RE.search(p)]
    return keys, sorted(backups, key=lambda x: x[1])


def leggi(case, part, inode):
    import forense_mobile as fm
    return b"".join(fm.stream(case, part, inode))


def run(case, part):
    """Decifra i backup msgstore*.crypt14/.crypt15 con la chiave trovata nell'estrazione o scritta dall'analista. Scrive i
    database decifrati in <caso>/backup_whatsapp/ (sola lettura) e restituisce l'elenco degli esiti; tutto va nel registro."""
    keys, backups = trova(case, part)
    out = {"chiavi": [], "backup": []}
    if not backups:
        return out
    kdata, k15 = [], []
    for i, p, _s in keys:
        b = leggi(case, part, i)
        out["chiavi"].append({"percorso": p, "byte": len(b), "sha256": _sha(b)})
        if KEY15_RE.search(p):
            r = chiave_file15(b)
            if r:
                k15.append((p, r))
        elif len(b) == 158:
            kdata.append((p, b))
    if os.environ.get(ENV_CHIAVE):              # solo in memoria: nel registro c'è il fatto, mai il valore
        k15.append((tr("chiave indicata dall'analista"), chiave_digitata(os.environ[ENV_CHIAVE])))
        out["chiave_analista"] = True
    dest = Path(case.root) / CARTELLA
    for i, p, size in backups:
        m = BACKUP_RE.search(p)
        e = {"percorso": p, "byte": size, "crypt": int(m.group(3))}
        data = leggi(case, part, i)
        e["sha256"] = _sha(data)
        if e["crypt"] not in (14, 15):
            e.update(esito="formato", motivo=tr("crypt{n}: formato non gestito in questa versione").format(n=e["crypt"]))
        elif e["crypt"] == 14 and not kdata:
            e.update(esito="errore", motivo=tr("nessuna chiave (com.whatsapp/files/key) nell'estrazione"))
        elif e["crypt"] == 15 and not k15:
            e.update(esito="errore", motivo=tr("nessuna chiave (encrypted_backup.key) nell'estrazione: indica la chiave di 64 cifre"))
        else:
            raw, (esito, motivo) = None, ("errore", "")
            for kp, kb in (kdata if e["crypt"] == 14 else k15):
                raw, (esito, motivo) = decifra(data, kb) if e["crypt"] == 14 else decifra15(data, kb)
                if raw is not None or (e["crypt"] == 14 and esito != "altra_chiave"):
                    e["chiave"] = kp
                    break
            if raw is not None and not raw.startswith(b"SQLite format 3\x00"):
                if raw[:2] == b"PK" and INCREMENT_RE.search(m.group(2)):
                    esito, motivo = "incrementale", tr("archivio ZIP di {n} byte").format(n=len(raw))
                else:
                    esito, motivo = "errore", tr("decifrato ma non è un database SQLite")
                raw = None
            e.update(esito=esito, motivo=motivo)
            if raw is not None:
                dest.mkdir(exist_ok=True)
                f = dest / f"{e['sha256'][:12]}_{m.group(2)}"
                if f.exists():
                    f.chmod(0o644)
                f.write_bytes(raw)
                f.chmod(0o444)
                e["decifrato"] = {"file": str(f.relative_to(case.root)), "byte": len(raw), "sha256": _sha(raw)}
                try:
                    c = sqlite3.connect(f"file:{f.as_posix()}?mode=ro&immutable=1", uri=True)
                    try:
                        t = "message" if c.execute("SELECT 1 FROM sqlite_master WHERE name='message'").fetchone() else "messages"
                        n, a, z = c.execute(f"SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM {t}").fetchone()
                        e["decifrato"].update(messaggi=n, primo_ms=a, ultimo_ms=z)
                    finally:
                        c.close()
                except sqlite3.Error:
                    pass
        out["backup"].append(e)
        print(tr("Backup WhatsApp {p}: {e}").format(p=Path(p).name, e=tr(ESITI.get(e["esito"], e["esito"]))), flush=True)
    case.log("wa_backup", out)
    return out


def testo_esito(e):
    """«msgstore.db.crypt14: decifrato … (motivo)» per avvisi e report."""
    return f"{Path(e['percorso']).name}: {tr(ESITI.get(e['esito'], e['esito']))}" + (f" ({e['motivo']})" if e.get("motivo") else "")
