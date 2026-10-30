# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - chat degli smartphone (dalla 2.20): lettori propri, indipendenti da iLEAPP/ALEAPP.

App lette in questa versione
- iOS: iMessage/SMS/RCS (`mobile/Library/SMS/sms.db`), WhatsApp (`ChatStorage.sqlite` nel gruppo di app condiviso).
- Android: SMS/MMS (`com.android.providers.telephony/databases/mmssms.db`, anche in user_de), WhatsApp
  (`com.whatsapp/databases/msgstore.db`, schema dal 2022 e schema precedente; nomi da `wa.db`).
- Rubriche per i nomi: iOS `AddressBook.sqlitedb`, Android `contacts2.db`, contatti di WhatsApp.

Metodo
- Ogni database si legge da una COPIA DI LAVORO (con i suoi file -wal/-shm, così SQLite applica le transazioni non
  ancora riversate, come fa il telefono); la copia si cancella a fine lettura. Nell'estrazione non si scrive nulla.
- Ogni messaggio porta il riferimento al dato grezzo: database (voce dell'estrazione), tabella e riga.
- Gli allegati si collegano al file dell'estrazione quando c'è (percorso cercato per suffisso).
- Orari in UTC. I messaggi entrano anche nella timeline (origine «chat»).

Limiti dichiarati: database cifrati (es. backup WhatsApp .crypt14/.crypt15, Signal) non si leggono senza chiave;
i messaggi cancellati ancora presenti nelle pagine libere dei database non sono recuperati in questa versione;
le app non elencate sopra si vedono con iLEAPP/ALEAPP (Artefatti) e nell'albero dei file.
"""
import datetime as dt
import json
import re
import shutil
import sqlite3
import tempfile
from pathlib import Path

from forense_lingua import tr, N_  # noqa: E402
import forense_mobile_wa as fmw  # noqa: E402
import forense_mobile_ricevute as fmr  # noqa: E402
import forense_mobile_chiamate as fmca  # noqa: E402

APP_LBL = {"imessage": "iMessage/SMS", "whatsapp": "WhatsApp", "sms": "SMS/MMS",
           "whatsapp_backup": "WhatsApp (backup decifrato)"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS chat_threads(id INTEGER PRIMARY KEY, app TEXT, key TEXT, title TEXT, participants TEXT,
    is_group INTEGER, n_msg INTEGER, first_ts TEXT, last_ts TEXT, part INTEGER, inode TEXT, src_path TEXT, local TEXT);
CREATE TABLE IF NOT EXISTS chat_messages(id INTEGER PRIMARY KEY, thread INTEGER, app TEXT, ts TEXT, direction TEXT,
    sender TEXT, sender_name TEXT, text TEXT, kind TEXT, n_att INTEGER, status TEXT, read_ts TEXT, service TEXT,
    src_table TEXT, src_row INTEGER, part INTEGER, inode TEXT, extra TEXT);
CREATE INDEX IF NOT EXISTS idx_cm_thread ON chat_messages(thread, ts);
CREATE INDEX IF NOT EXISTS idx_cm_ts ON chat_messages(ts);
CREATE TABLE IF NOT EXISTS chat_attachments(id INTEGER PRIMARY KEY, msg INTEGER, name TEXT, mime TEXT, size INTEGER,
    device_path TEXT, part INTEGER, inode TEXT, path TEXT, lat REAL, lon REAL);
CREATE INDEX IF NOT EXISTS idx_ca_msg ON chat_attachments(msg);
CREATE TABLE IF NOT EXISTS chat_contacts(id INTEGER PRIMARY KEY, source TEXT, name TEXT, value TEXT, norm TEXT);
CREATE INDEX IF NOT EXISTS idx_cc_norm ON chat_contacts(norm);
"""

DB_PATTERNS = {
    "imessage": re.compile(r"(^|/)mobile/Library/SMS/sms\.db$"),
    "whatsapp_ios": re.compile(r"(^|/)Shared/AppGroup/[^/]+/ChatStorage\.sqlite$"),
    "whatsapp_android": re.compile(r"(^|/)com\.whatsapp(\.w4b)?/databases/msgstore\.db$"),
    "sms_android": re.compile(r"(^|/)com\.android\.providers\.telephony/databases/mmssms\.db$"),
    "ab_ios": re.compile(r"(^|/)mobile/Library/AddressBook/AddressBook\.sqlitedb$"),
    "contacts_android": re.compile(r"(^|/)com\.(android|samsung\.android)\.providers\.contacts/databases/contacts2\.db$"),
    "wa_contacts_android": re.compile(r"(^|/)com\.whatsapp(\.w4b)?/databases/wa\.db$"),
    "wa_contacts_ios": re.compile(r"(^|/)Shared/AppGroup/[^/]+/ContactsV2\.sqlite$"),
}
ENCRYPTED_RE = re.compile(r"(^|/)(msgstore[^/]*\.db\.crypt\d+|signal\.db|.*\.crypt1[245])$", re.I)
WA_IOS_TYPES = {0: N_("testo"), 1: N_("immagine"), 2: N_("video"), 3: N_("audio"), 4: N_("contatto"),
                5: N_("posizione"), 6: N_("evento del gruppo"), 7: N_("link"), 8: N_("documento"), 10: N_("chiamata"),
                11: N_("GIF"), 14: N_("messaggio eliminato"), 15: N_("sticker"), 46: N_("sondaggio")}
WA_AND_TYPES = {0: N_("testo"), 1: N_("immagine"), 2: N_("audio"), 3: N_("video"), 4: N_("contatto"),
                5: N_("posizione"), 7: N_("evento di sistema"), 9: N_("documento"), 13: N_("GIF"),
                15: N_("messaggio eliminato"), 16: N_("posizione in tempo reale"), 20: N_("sticker"), 42: N_("vista unica"),
                43: N_("vista unica"), 64: N_("messaggio eliminato dall'amministratore")}
SMS_TYPES = {1: "in", 2: "out", 3: "out", 4: "out", 5: "out", 6: "out"}
SMS_STATUS = {3: N_("bozza"), 4: N_("in uscita"), 5: N_("invio non riuscito"), 6: N_("in coda")}
TAPBACK = {2000: "♥", 2001: "👍", 2002: "👎", 2003: "😂", 2004: "‼", 2005: "?", 2006: N_("emoji")}


def _iso_unix(t):
    try:
        t = float(t)
        if t <= 0:
            return None
        return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _iso_ms(t):
    try:
        return _iso_unix(float(t) / 1000.0)
    except (TypeError, ValueError):
        return None


def _iso_apple(t):
    """Secondi (o nanosecondi, sms.db da iOS 11) dal 2001-01-01 UTC."""
    try:
        t = float(t)
    except (TypeError, ValueError):
        return None
    if not t:
        return None
    if abs(t) > 1e14:
        t /= 1e9
    return _iso_unix(t + 978307200)


def norm_number(v):
    """Chiave di confronto per numeri di telefono e identificativi: ultime 9 cifre (prefissi internazionali e zeri
    iniziali diversi tra rubrica e app), altrimenti l'indirizzo in minuscolo (email, id WhatsApp senza numero)."""
    v = (v or "").strip().lower()
    if "@" in v and re.match(r"^\+?\d+@", v):
        v = v.split("@", 1)[0]
    d = re.sub(r"\D", "", v)
    if len(d) >= 7 and not re.search(r"[a-z]", v.split("@")[0]):
        return d[-9:]
    return v


def ensure_schema(con):
    con.executescript(SCHEMA)
    have = {r[1] for r in con.execute("PRAGMA table_info(chat_threads)")}
    if "local" not in have:      # casi preparati con la 2.20 di prova
        con.execute("ALTER TABLE chat_threads ADD COLUMN local TEXT")
    if "origin" not in have:     # NULL = lettori di RepertIA, «leapp» = ricavata dagli artefatti di iLEAPP/ALEAPP
        con.execute("ALTER TABLE chat_threads ADD COLUMN origin TEXT")
    have = {r[1] for r in con.execute("PRAGMA table_info(chat_attachments)")}
    for c, t in (("sha256", "TEXT"), ("metodo", "TEXT"), ("verifica", "TEXT"), ("thumb", "BLOB")):
        if c not in have:        # (2.20) come è stato trovato il file, hash registrato dall'app, miniatura del database
            con.execute(f"ALTER TABLE chat_attachments ADD COLUMN {c} {t}")


def ensure_art_cols(con):
    """Colonne «grp» e «sub» degli artefatti, per le sottovoci dell'albero (iLEAPP/ALEAPP: categoria e artefatto;
    messaggi: app). Solo nei casi smartphone: le tabelle dei casi dei dischi non cambiano."""
    import forense_estesa as fe
    fe.ensure_schema(con)
    have = {r[1] for r in con.execute("PRAGMA table_info(artifacts)")}
    for c in ("grp", "sub"):
        if c not in have:
            con.execute(f"ALTER TABLE artifacts ADD COLUMN {c} TEXT")
    con.execute("CREATE INDEX IF NOT EXISTS idx_art_grp ON artifacts(cat, grp, sub)")


SHORT_RE = re.compile(r"\d{3,6}")


def is_short(v):
    """Numero breve o di servizio (es. 32665, 22000): solo cifre, al più 6, senza prefisso internazionale."""
    v = (v or "").strip().split("@")[0]
    return bool(SHORT_RE.fullmatch(v))


def show_id(v):
    """Identificativo leggibile: «<numero>@s.whatsapp.net» → «+<numero>»; gli altri come sono."""
    v = (v or "").strip()
    m = re.fullmatch(r"(\d{7,15})@s\.whatsapp\.net", v)
    return "+" + m.group(1) if m else v


# ---------------------------------------------------------------------------- copia di lavoro

class WorkDB:
    """Copia di lavoro di un database dell'estrazione con i file -wal, -shm, -journal accanto."""

    def __init__(self, case, part, inode, path, con):
        import forense_mobile as fm
        self.tmp = Path(tempfile.mkdtemp(prefix="chat_", dir=str(case.root)))
        name = Path(path).name
        self.file = self.tmp / name
        with open(self.file, "wb") as fo:
            for b in fm.stream(case, part, inode):
                fo.write(b)
        self.wal = False
        for suf in ("-wal", "-shm", "-journal"):
            m = fm.mx(case)
            r = m.execute("SELECT id FROM mobile_files WHERE part=? AND path=? AND isdir=0", (part, path + suf)).fetchone()
            m.close()
            if r:
                with open(self.tmp / (name + suf), "wb") as fo:
                    for b in fm.stream(case, part, r[0]):
                        fo.write(b)
                self.wal = self.wal or (suf == "-wal" and (self.tmp / (name + suf)).stat().st_size > 0)
        self.db = sqlite3.connect(str(self.file))
        self.db.row_factory = sqlite3.Row

    def tables(self):
        return {r[0].lower() for r in self.db.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')")}

    def cols(self, table):
        return {r[1].lower() for r in self.db.execute(f"PRAGMA table_info({table})")}

    def close(self):
        try:
            self.db.close()
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)


class FileWorkDB(WorkDB):
    """(2.20) Copia di lavoro di un database che sta già nella cartella del caso (backup WhatsApp decifrato)."""

    def __init__(self, case, file):
        self.tmp = Path(tempfile.mkdtemp(prefix="chat_", dir=str(case.root)))
        self.file = self.tmp / Path(file).name
        shutil.copyfile(file, self.file)
        self.file.chmod(0o644)
        self.wal = False
        self.db = sqlite3.connect(str(self.file))
        self.db.row_factory = sqlite3.Row


# ------------------------------------------------------------------------------- scrittura

class Writer:
    def __init__(self, con, app, part, inode, src_path):
        self.con, self.app, self.part, self.inode, self.src = con, app, part, str(inode), src_path
        self.threads = {}
        self.local = {}                 # conversazione → {numero o account di questo telefono: messaggi}
        self.n_msg = self.n_att = 0

    def see_local(self, thread_id, value):
        if value:
            c = self.local.setdefault(thread_id, {})
            c[value] = c.get(value, 0) + 1

    def thread(self, key, title, participants=None, is_group=False):
        key = str(key)
        if key not in self.threads:
            cur = self.con.execute("INSERT INTO chat_threads(app, key, title, participants, is_group, n_msg, part, inode, "
                                   "src_path) VALUES (?,?,?,?,?,0,?,?,?)",
                                   (self.app, key, title or key, json.dumps(sorted(set(participants or [])),
                                                                              ensure_ascii=False), int(bool(is_group)),
                                    self.part, self.inode, self.src))
            self.threads[key] = cur.lastrowid
        return self.threads[key]

    def message(self, thread_id, ts, direction, sender, text, kind, table, row, status=None, read_ts=None,
                service=None, sender_name=None, extra=None):
        cur = self.con.execute(
            "INSERT INTO chat_messages(thread, app, ts, direction, sender, sender_name, text, kind, n_att, status, "
            "read_ts, service, src_table, src_row, part, inode, extra) VALUES (?,?,?,?,?,?,?,?,0,?,?,?,?,?,?,?,?)",
            (thread_id, self.app, ts, direction, sender, sender_name, text, kind, status, read_ts, service, table, row,
             self.part, self.inode, json.dumps(extra, ensure_ascii=False, default=str) if extra else None))
        self.n_msg += 1
        return cur.lastrowid

    def attachment(self, msg_id, name, mime, size, device_path, found=None, lat=None, lon=None, metodo=None, sha256=None,
                   verifica=None, thumb=None):
        part, inode, path = found or (None, None, None)
        if found and not metodo and inode:
            metodo = "percorso"
        self.con.execute("INSERT INTO chat_attachments(msg, name, mime, size, device_path, part, inode, path, lat, lon, "
                         "metodo, sha256, verifica, thumb) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (msg_id, name, mime, size, device_path, part, inode, path, lat, lon, metodo, sha256, verifica,
                          None if inode else thumb))
        self.con.execute("UPDATE chat_messages SET n_att = n_att + 1 WHERE id=?", (msg_id,))
        self.n_att += 1


class Resolver:
    """File dell'estrazione per suffisso del percorso, dopo un punto di ancoraggio (es. «Library/SMS/Attachments/»):
    una sola lettura dell'indice per tutti gli allegati di un'app."""

    def __init__(self, case, part, anchors):
        import forense_mobile as fm
        con = fm.mx(case)
        self.map = {}
        for anchor in anchors:
            a = anchor.lower()
            for i, path in con.execute("SELECT id, path FROM mobile_files WHERE part=? AND isdir=0 AND "
                                       "instr(lower(path), ?) > 0", (part, a)):
                lp = path.lower()
                self.map.setdefault(lp[lp.find(a):], (part, str(i), path))
        con.close()

    def find(self, device_path, anchor):
        if not device_path:
            return None
        lp = device_path.replace("\\", "/").lower()
        a = anchor.lower()
        k = lp.find(a)
        return self.map.get(lp[k:]) if k >= 0 else None


class Trova:
    """(2.20) File di un allegato con la ricerca comune dei file citati (forense_percorsi: tabella dei percorsi, hash,
    nome e dimensione), quando l'ancora nota dell'app (Resolver) non basta; verifica l'hash registrato dall'app.
    Restituisce gli argomenti per Writer.attachment: found, metodo, verifica, sha256."""

    def __init__(self, case, part):
        import forense_percorsi as fp
        self.fp, self.idx = fp, fp.IndiceEstrazione(case, part)

    def __call__(self, found=None, paths=(), sha256=None, size=None, name=None):
        fp = self.fp
        hint = {k: v for k, v in (("sha256", sha256), ("size", size)) if v}
        out = {"found": None, "metodo": None, "verifica": None, "sha256": sha256}
        if found and found[1]:
            out.update(found=found, metodo="percorso")
            if sha256:
                h = self.idx.hash_file(found[0], found[1], "sha256")
                if h:
                    out["verifica"] = "uguale" if h == sha256 else "diverso"
            return out
        ok = fp.univoco          # solo nome con omonimi di dimensioni diverse: l'allegato resta senza file
        for p in paths:
            if p:
                r = self.idx.risolvi(p, fp.forma(p) or "relativo", hint)
                if ok(r):
                    out.update(found=(r["part"], r["inode"], r["path"]), metodo=r["metodo"], verifica=r.get("verifica"))
                    return out
        if sha256 or (name and size):
            r = self.idx.risolvi(name or "-", "nome", dict(hint, nome=name) if name else hint)
            if ok(r):
                out.update(found=(r["part"], r["inode"], r["path"]), metodo=r["metodo"], verifica=r.get("verifica"))
        return out

    def leggi(self, found, limit=2 << 20):
        """Byte di un file piccolo dell'estrazione (miniature .thumb di WhatsApp iOS)."""
        import forense_mobile as fm
        buf = bytearray()
        try:
            for b in fm.stream(self.idx.case, found[0], found[1]):
                buf += b
                if len(buf) > limit:
                    return None
        except Exception:
            return None
        return bytes(buf)


def _immagine(b):
    """Miniatura salvata nel database: i byte dell'immagine (JPEG anche dentro un oggetto serializzato), o None."""
    if not isinstance(b, (bytes, bytearray)) or len(b) < 100:
        return None
    b = bytes(b)
    if b.startswith(b"\x89PNG") or (b[:4] == b"RIFF" and b[8:12] == b"WEBP"):
        return b
    i = b.find(b"\xff\xd8\xff")
    if i < 0:
        return None
    j = b.rfind(b"\xff\xd9")
    return b[i:j + 2] if j > i else b[i:]


def _hash_b64(v):
    """SHA-256 in esadecimale dal base64 di WhatsApp (file_hash, media_hash), o None."""
    import forense_percorsi as fp
    h = fp._hash_val(v) if v else None
    return h if h and len(h) == 64 else None


def _java_path(blob):
    """Percorso del file dentro thumb_image di WhatsApp Android (oggetto Java serializzato com.whatsapp.MediaData)."""
    if not isinstance(blob, (bytes, bytearray)):
        return None
    for m in re.finditer(rb"[\x20-\x7e]{8,}", bytes(blob)):
        t = m.group().decode("ascii", "ignore")
        if ("/" in t) and re.search(r"\.(jpe?g|png|gif|webp|mp4|3gp|opus|ogg|aac|m4a|amr|pdf|docx?|xlsx?|vcf|zip)$", t, re.I):
            k = t.find("WhatsApp")
            return t if t.startswith("/") or k < 0 else t[k:]
    return None


# -------------------------------------------------------------------------------- rubriche

def read_contacts(case, con, part, found):
    """Nomi da rubrica e contatti di WhatsApp: tabella chat_contacts (fonte, nome, valore, chiave normalizzata)."""
    n = 0
    for kind, (inode, path) in found:
        if kind not in ("ab_ios", "contacts_android", "wa_contacts_android", "wa_contacts_ios"):
            continue
        w = None
        rows = []
        try:
            w = WorkDB(case, part, inode, path, con)
            t = w.tables()
            if kind == "ab_ios" and {"abperson", "abmultivalue"} <= t:
                for r in w.db.execute("SELECT trim(IFNULL(p.First,'') || ' ' || IFNULL(p.Last,'')) n, p.Organization o, "
                                      "v.value v FROM ABPerson p JOIN ABMultiValue v ON v.record_id = p.ROWID "
                                      "WHERE v.value IS NOT NULL"):
                    rows.append((r["n"] or r["o"] or "", str(r["v"])))
            elif kind == "contacts_android" and {"raw_contacts", "data", "mimetypes"} <= t:
                for r in w.db.execute("SELECT rc.display_name n, d.data1 v FROM data d JOIN raw_contacts rc ON "
                                      "rc._id = d.raw_contact_id JOIN mimetypes m ON m._id = d.mimetype_id WHERE "
                                      "m.mimetype IN ('vnd.android.cursor.item/phone_v2', "
                                      "'vnd.android.cursor.item/email_v2') AND d.data1 IS NOT NULL"):
                    rows.append((r["n"] or "", str(r["v"])))
            elif kind == "wa_contacts_android" and "wa_contacts" in t:
                c = w.cols("wa_contacts")
                nm = "COALESCE(" + ", ".join(x for x in ("display_name", "wa_name") if x in c) + ", '')" if (
                    {"display_name", "wa_name"} & c) else "''"
                for r in w.db.execute(f"SELECT {nm} n, jid v FROM wa_contacts WHERE jid IS NOT NULL"):
                    rows.append((r["n"] or "", str(r["v"])))
            elif kind == "wa_contacts_ios" and "zwaaddressbookcontact" in t:
                c = w.cols("ZWAADDRESSBOOKCONTACT")
                for r in w.db.execute("SELECT * FROM ZWAADDRESSBOOKCONTACT"):
                    d = dict(r)
                    name = d.get("ZFULLNAME") or d.get("ZGIVENNAME") or ""
                    for k in ("ZWHATSAPPID", "ZPHONENUMBER", "ZLID"):
                        if k.lower() in c and d.get(k):
                            rows.append((name, str(d[k])))
        except Exception as e:
            print(tr("  Rubrica {path}: non letta ({e})").format(path=path, e=e), flush=True)
        finally:
            if w:
                w.close()
        con.executemany("INSERT INTO chat_contacts(source, name, value, norm) VALUES (?,?,?,?)",
                        [(path, nm.strip(), v, norm_number(v)) for nm, v in rows if (nm or "").strip()])
        n += len(rows)
    con.commit()
    return n


def name_map(con):
    out = {}
    for name, key in con.execute("SELECT name, norm FROM chat_contacts WHERE name != ''"):
        out.setdefault(key, [])
        if name not in out[key]:
            out[key].append(name)
    return {k: " / ".join(v[:3]) for k, v in out.items()}


# ------------------------------------------------------------------- proprietario del telefono

def _leggi(case, part, inode):
    import forense_mobile as fm
    return b"".join(fm.stream(case, part, inode))


def identita(case, part):
    """Numeri e account del telefono analizzato, solo se scritti nell'estrazione: numero della SIM (iOS CommCenter,
    Android telephony.db) e numero registrato in WhatsApp (Android, shared_prefs). Ogni valore con la sua fonte.
    Le copie sotto sbin/.magisk/mirror si guardano per ultime."""
    import plistlib
    import xml.etree.ElementTree as ET
    import forense_mobile as fm
    m = fm.mx(case)
    try:
        def files(*pats):
            rows = []
            for pat in pats:
                rows += m.execute("SELECT id, path FROM mobile_files WHERE part=? AND isdir=0 AND path LIKE ?",
                                  (part, pat)).fetchall()
            return sorted(rows, key=lambda r: (".magisk/" in r[1], r[1]))
        out = {}
        for i, path in files("%wireless/Library/Preferences/com.apple.commcenter.plist",
                             "%wireless/Library/Preferences/com.apple.commcenter.device_specific_nobackup.plist"):
            try:
                d = plistlib.loads(_leggi(case, part, i))
            except Exception:
                continue
            v = next((str(d[k]) for k in ("SIMPhoneNumber", "NetworkPhoneNumber", "PhoneNumber", "ReportedPhoneNumber")
                      if d.get(k)), None)
            if v:
                out.setdefault("telefono", {"id": v if v.startswith("+") or len(v) < 11 else "+" + v, "fonte": path})
                break
        for i, path in files("%com.android.providers.telephony/databases/telephony.db"):
            w = None
            try:
                w = WorkDB(case, part, i, path, None)
                if "siminfo" in w.tables():
                    nums = [r[0] for r in w.db.execute("SELECT DISTINCT number FROM siminfo WHERE IFNULL(number,'') != ''")]
                    if len(nums) == 1:
                        out.setdefault("telefono", {"id": nums[0], "fonte": path})
                    elif nums:
                        out.setdefault("telefono", {"id": " / ".join(nums), "fonte": path, "piu_sim": True})
            except Exception:
                pass
            finally:
                if w:
                    w.close()
            if "telefono" in out:
                break
        for i, path in files("%com.whatsapp/shared_prefs/com.whatsapp_preferences_light.xml",
                             "%com.whatsapp/shared_prefs/startup_prefs.xml"):
            try:
                root = ET.fromstring(_leggi(case, part, i))
            except Exception:
                continue
            kv = {e.get("name"): (e.text or "") for e in root if e.get("name")}
            num = ("+" + kv["cc"] + kv["ph"]) if kv.get("cc") and kv.get("ph") else show_id(kv.get("registration_jid"))
            if num:
                out["whatsapp"] = {"id": num, "nome": kv.get("push_name") or None, "fonte": path}
                break
        return out
    finally:
        m.close()


def _account(v):
    """account_login di sms.db: «E:indirizzo» o «P:+numero» → indirizzo/numero."""
    v = (v or "").strip()
    return v[2:] if re.match(r"^[EP]:", v) else v


# ------------------------------------------------------------------------ iMessage/SMS (iOS)

def read_imessage(case, con, part, inode, path, names):
    import forense_estesa as fe
    w = WorkDB(case, part, inode, path, con)
    W = Writer(con, "imessage", part, inode, path)
    try:
        t = w.tables()
        if not {"message", "handle"} <= t:
            return None
        mc = w.cols("message")
        handles = {r["ROWID"]: r["id"] for r in w.db.execute("SELECT ROWID, id FROM handle")}
        chats, chat_parts = {}, {}
        if "chat" in t:
            for r in w.db.execute("SELECT * FROM chat"):
                chats[r["ROWID"]] = dict(r)
        if "chat_handle_join" in t:
            for r in w.db.execute("SELECT chat_id, handle_id FROM chat_handle_join"):
                chat_parts.setdefault(r["chat_id"], []).append(handles.get(r["handle_id"], str(r["handle_id"])))
        msg_chat = {}
        if "chat_message_join" in t:
            for r in w.db.execute("SELECT chat_id, message_id FROM chat_message_join"):
                msg_chat[r["message_id"]] = r["chat_id"]
        atts = {}
        if {"attachment", "message_attachment_join"} <= t:
            for r in w.db.execute("SELECT j.message_id m, a.* FROM message_attachment_join j JOIN attachment a ON "
                                  "a.ROWID = j.attachment_id"):
                atts.setdefault(r["m"], []).append(dict(r))
        res = Resolver(case, part, ["Library/SMS/Attachments/"])
        tv = Trova(case, part)
        guid_text = {}
        sel = ["ROWID", "guid", "text", "handle_id", "date", "is_from_me", "service"] + [
            c for c in ("attributedbody", "date_read", "date_delivered", "is_read", "is_delivered", "is_sent",
                        "item_type", "associated_message_type", "associated_message_guid", "other_handle",
                        "group_title", "error", "destination_caller_id", "is_audio_message", "subject")
            if c in mc]
        for r in w.db.execute(f"SELECT {', '.join(sel)} FROM message ORDER BY date"):
            d = dict(r)
            d = {k.lower(): v for k, v in d.items()}
            text = d.get("text")
            if not text and d.get("attributedbody"):
                text = fe._attributed_text(d["attributedbody"])
            guid_text[d.get("guid")] = text
            cid = msg_chat.get(d["rowid"])
            ch = chats.get(cid) or {}
            who = handles.get(d.get("handle_id"), "")
            parts_ = chat_parts.get(cid) or ([who] if who else [])
            is_group = (ch.get("style") == 43) or len(parts_) > 1
            title = ch.get("display_name") or ", ".join(names.get(norm_number(x), x) for x in parts_) or \
                ch.get("chat_identifier") or who or tr("(sconosciuto)")
            th = W.thread(ch.get("guid") or ch.get("chat_identifier") or who or "?", title, parts_, is_group)
            frm = bool(d.get("is_from_me"))
            kind = "testo"
            at = d.get("associated_message_type") or 0
            if d.get("item_type"):
                kind = "sistema"
                text = text or tr("[evento della conversazione, tipo {t}]").format(t=d["item_type"]) + (
                    f": {d.get('group_title')}" if d.get("group_title") else "")
            elif 2000 <= at < 4000:
                kind = "reazione"
                target = (d.get("associated_message_guid") or "").split("/")[-1]
                sym = TAPBACK.get(at if at < 3000 else at - 1000, "")
                text = (tr("tolta la reazione {s}") if at >= 3000 else tr("reazione {s}")).format(s=tr(sym)) + (
                    f" → «{(guid_text.get(target) or '')[:80]}»" if guid_text.get(target) else "")
            status = None
            if frm:
                status = tr("non inviato") if d.get("error") else tr("consegnato") if d.get("is_delivered") else (
                    tr("inviato") if d.get("is_sent") else None)
            mid = W.message(th, _iso_apple(d.get("date")), "out" if frm else "in", "" if frm else who,
                            text, kind, "message", d["rowid"], status=status, read_ts=_iso_apple(d.get("date_read")),
                            service=d.get("service"), sender_name=None if frm else names.get(norm_number(who)),
                            extra={"guid": d.get("guid"), "chat": ch.get("chat_identifier")})
            # numero o account di questo telefono usato nella conversazione
            W.see_local(th, d.get("destination_caller_id") or ch.get("last_addressed_handle") or _account(ch.get("account_login")))
            for a in atts.get(d["rowid"], []):
                fp = a.get("filename") or ""
                fd = tv(res.find(fp, "Library/SMS/Attachments/"), [fp], size=a.get("total_bytes"),
                        name=a.get("transfer_name") or Path(fp).name)
                W.attachment(mid, a.get("transfer_name") or Path(fp).name, a.get("mime_type"), a.get("total_bytes"),
                             fp, fd["found"], metodo=fd["metodo"], verifica=fd["verifica"])
        return W
    finally:
        w.close()


# --------------------------------------------------------------------------- WhatsApp iOS

def read_whatsapp_ios(case, con, part, inode, path, names):
    w = WorkDB(case, part, inode, path, con)
    W = Writer(con, "whatsapp", part, inode, path)
    try:
        t = w.tables()
        if not {"zwamessage", "zwachatsession"} <= t:
            return None
        sess = {r["Z_PK"]: dict(r) for r in w.db.execute("SELECT * FROM ZWACHATSESSION")}
        members = {r["Z_PK"]: dict(r) for r in w.db.execute("SELECT * FROM ZWAGROUPMEMBER")} if "zwagroupmember" in t else {}
        media = {r["Z_PK"]: dict(r) for r in w.db.execute("SELECT * FROM ZWAMEDIAITEM")} if "zwamediaitem" in t else {}
        push = {}
        if "zwaprofilepushname" in t:
            for r in w.db.execute("SELECT ZJID, ZPUSHNAME FROM ZWAPROFILEPUSHNAME"):
                push[r["ZJID"]] = r["ZPUSHNAME"]
        gparts = {}
        for m in members.values():
            gparts.setdefault(m.get("ZCHATSESSION"), []).append(m.get("ZMEMBERJID"))
        res = Resolver(case, part, ["Message/Media/", "Media/"])
        tv = Trova(case, part)
        R = fmr.Scrittore(con)              # stati di consegna/lettura (ZRECEIPTINFO)
        info = {r["Z_PK"]: r["ZRECEIPTINFO"] for r in w.db.execute("SELECT Z_PK, ZRECEIPTINFO FROM ZWAMESSAGEINFO")} \
            if "zwamessageinfo" in t else {}
        mc = w.cols("ZWAMESSAGE")
        # (2.20) avvisi di WhatsApp (tipi 6 e 10): data di creazione del gruppo e posizione per ZSORT e per orario
        gcrea = {}
        if "zwagroupinfo" in t and "zcreationdate" in w.cols("ZWAGROUPINFO"):
            gi = {r[0]: r[1] for r in w.db.execute("SELECT Z_PK, ZCREATIONDATE FROM ZWAGROUPINFO")}
            gcrea = {k: gi.get(s.get("ZGROUPINFO")) for k, s in sess.items() if s.get("ZGROUPINFO")}
        pos = {}
        if "zsort" in mc:
            per = {}
            for pk, cs, so, md in w.db.execute("SELECT Z_PK, ZCHATSESSION, ZSORT, ZMESSAGEDATE FROM ZWAMESSAGE"):
                per.setdefault(cs, []).append((pk, so, md))
            for lst in per.values():
                ordz = {pk: i + 1 for i, (pk, so, _md) in enumerate(sorted(lst, key=lambda x: (x[1] is None, x[1] or 0, x[0])))}
                dates = sorted(x[2] or 0 for x in lst)
                for pk, _so, md in lst:
                    lo = sum(1 for x in dates if x < (md or 0)) + 1
                    hi = sum(1 for x in dates if x <= (md or 0))
                    pos[pk] = (ordz[pk], None if lo <= ordz[pk] <= hi else lo)   # stesso istante: nessuna differenza
        for r in w.db.execute("SELECT * FROM ZWAMESSAGE ORDER BY ZMESSAGEDATE"):
            d = dict(r)
            s = sess.get(d.get("ZCHATSESSION")) or {}
            jid = s.get("ZCONTACTJID") or ""
            is_group = jid.endswith("@g.us") or s.get("ZSESSIONTYPE") == 1
            title = s.get("ZPARTNERNAME") or names.get(norm_number(jid)) or jid
            th = W.thread(jid or f"sessione {d.get('ZCHATSESSION')}", title,
                          gparts.get(d.get("ZCHATSESSION")) if is_group else [jid], is_group)
            frm = bool(d.get("ZISFROMME"))
            if is_group and not frm:
                gm = members.get(d.get("ZGROUPMEMBER")) or {}
                sender = gm.get("ZMEMBERJID") or d.get("ZFROMJID") or ""
                sname = gm.get("ZCONTACTNAME") or names.get(norm_number(sender)) or push.get(sender) or d.get("ZPUSHNAME")
            else:
                sender = "" if frm else (d.get("ZFROMJID") or jid)
                sname = None if frm else (names.get(norm_number(sender)) or push.get(sender) or s.get("ZPARTNERNAME"))
            mt = d.get("ZMESSAGETYPE") or 0
            kind, tipo = fmw.classifica("ios", mt)
            av = mt in (6, 10)      # (2.20) avviso di WhatsApp: «di sistema», non un messaggio ricevuto dal contatto
            if av:
                sender, sname = "", None
                pz = pos.get(d.get("Z_PK"))
                tipo.update(tipo=tr(fmw.AVVISO), avviso=fmw.avviso_ios(d, gcrea.get(d.get("ZCHATSESSION")),
                                                                         (pz[0], pz[1] or pz[0]) if pz else None))
            if mt == 59:        # chiamata: video e durata dal media item (verificato su iOS 17.3)
                c59 = fmca.meta59((media.get(d.get("ZMEDIAITEM")) or {}).get("ZMETADATA"))
                if c59:
                    tipo.update(tipo=fmca.etichetta_chiamata(tr("video") if c59["video"] else tr("voce"),
                                                             "out" if d.get("ZISFROMME") else "in", c59["durata_s"]),
                                durata_s=c59["durata_s"], fonte_chiamata="ChatStorage.sqlite · ZWAMESSAGE")
            text = d.get("ZTEXT")
            if av and text and text.strip().isdigit():
                text = None             # valore numerico, non un testo (WhatsApp-Chat-Exporter scarta queste righe)
            st = d.get("ZMESSAGESTATUS")
            # (2.20) messaggi ricevuti: ZSENTDATE è l'ora in cui QUESTO telefono li ha letti (iOS 17.3 ↔ Android 14 di
            # Hickman: entro 1 s dal «letto» registrato dall'altro telefono in 8 casi su 10), non l'ora d'invio
            letto = _iso_apple(d.get("ZSENTDATE")) if not frm and not av and "zsentdate" in mc else None
            mid = W.message(th, _iso_apple(d.get("ZMESSAGEDATE")), "sys" if av else "out" if frm else "in",
                            sender, text, kind, "ZWAMESSAGE", d.get("Z_PK"),
                            status=(tr("letto") if frm and not av and st == 13 else tr("consegnato") if frm and not av and st == 8 else None),
                            read_ts=letto, service="WhatsApp", sender_name=sname,
                            extra={**tipo, "stanza": d.get("ZSTANZAID"),
                                   "inviato": _iso_apple(d.get("ZSENTDATE")) if frm and "zsentdate" in mc else None,
                                   "letto_fonte": "ZWAMESSAGE.ZSENTDATE" if letto else None,
                                   "preferito": bool(d.get("ZSTARRED"))})
            if not av:
                fmr.ios(R, mid, frm, st, info.get(d.get("ZMESSAGEINFO")))
            mi = media.get(d.get("ZMEDIAITEM"))
            if mi and (mi.get("ZMEDIALOCALPATH") or mi.get("ZTITLE") or mi.get("ZLATITUDE") or mt in (1, 2, 3, 4, 5, 8, 11, 15)):
                lp = mi.get("ZMEDIALOCALPATH") or ""
                found = res.find("Message/" + lp, "Message/Media/") or res.find(lp, "Media/") if lp else None
                fd = tv(found, ["Message/" + lp] if lp else [], size=mi.get("ZFILESIZE"), name=Path(lp).name if lp else None)
                thumb = None
                if not fd["found"] and mt != 5:     # miniatura indicata dal database (file .thumb accanto ai media)
                    tp = mi.get("ZXMPPTHUMBPATH") or mi.get("ZTHUMBNAILLOCALPATH") or ""
                    tf = (res.find("Message/" + tp, "Message/Media/") or res.find(tp, "Media/")) if tp else None
                    thumb = _immagine(tv.leggi(tf)) if tf else None
                # ZLATITUDE/ZLONGITUDE sono una posizione solo nei messaggi di posizione (tipo 5): nelle foto e nei
                # video WhatsApp ci tiene altri valori (es. le dimensioni dell'immagine)
                lat, lon = (mi.get("ZLATITUDE"), mi.get("ZLONGITUDE")) if mt == 5 else (None, None)
                W.attachment(mid, Path(lp).name if lp else (mi.get("ZTITLE") or mi.get("ZVCARDNAME") or
                                                              tr(WA_IOS_TYPES.get(mt, ""))),
                             None, mi.get("ZFILESIZE"), lp, fd["found"], lat if lat else None, lon if lon else None,
                             metodo=fd["metodo"], verifica=fd["verifica"], thumb=thumb)
        _wa_ios_chiamate(case, con, part, W, names)
        return W
    finally:
        w.close()


def _wa_ios_chiamate(case, con, part, W, names=None):
    """Chiamate del CallHistory.sqlite di WhatsApp nelle conversazioni lette da ChatStorage (stesso JID)."""
    import forense_mobile as fm
    m = fm.mx(case)
    try:
        dbs = [(i, p) for i, p in m.execute("SELECT id, path FROM mobile_files WHERE part=? AND isdir=0 AND "
                                            "path LIKE '%/CallHistory.sqlite'", (part,)) if fmca.FONTI["wa_ios"].search(p)]
    finally:
        m.close()
    for inode, path in dbs:
        wc = WorkDB(case, part, inode, path, con)
        try:
            recs = fmca.wa_ios(wc, (part, str(inode), path))
        finally:
            wc.close()
        if recs:
            W2 = Writer(con, "whatsapp", part, inode, path)
            W2.threads = W.threads
            W.n_msg += fmca.nella_chat(W2, recs, "ZWACDCALLEVENT", names)


# ------------------------------------------------------------------------ WhatsApp Android

class BackupWriter(Writer):
    """(2.20) Conversazioni di un backup decifrato: app «whatsapp_backup», chiave con il nome del backup davanti."""

    def __init__(self, con, part, inode, src_path, nome):
        super().__init__(con, "whatsapp_backup", part, inode, src_path)
        self.nome = nome

    def thread(self, key, title, participants=None, is_group=False):
        return super().thread(f"{self.nome}|{key}", title, participants, is_group)


def read_whatsapp_android(case, con, part, inode, path, names, backup=None):
    """`backup` (2.20): {"file": database decifrato nel caso, "nome": nome del backup}; part/inode/path sono allora quelli
    del file .crypt14 nell'estrazione (la fonte)."""
    w = WorkDB(case, part, inode, path, con) if backup is None else FileWorkDB(case, backup["file"])
    W = Writer(con, "whatsapp", part, inode, path) if backup is None else BackupWriter(con, part, inode, path, backup["nome"])
    try:
        t = w.tables()
        res = Resolver(case, part, ["WhatsApp/Media/", "WhatsApp Business/Media/"])
        tv = Trova(case, part)

        def wa_file(fp):
            # file_path è relativo alla cartella WhatsApp della memoria (sdcard/WhatsApp o
            # Android/media/com.whatsapp/WhatsApp): «Media/WhatsApp Images/…»
            if not fp:
                return None, []
            rel = fp if fp.lower().startswith("media/") else fp[fp.lower().find("media/"):] if "media/" in fp.lower() else fp
            found = res.find("WhatsApp/" + rel, "WhatsApp/Media/") or res.find(
                "WhatsApp Business/" + rel, "WhatsApp Business/Media/")
            return found, ([fp] if fp.startswith("/") else []) + ["WhatsApp/" + rel, "WhatsApp Business/" + rel]

        R = fmr.Scrittore(con)              # stati di consegna/lettura
        ru, rd, rg = {}, {}, {}             # receipt_user, receipt_device per messaggio; receipts per key_id
        if "receipt_user" in t:
            for r in w.db.execute("SELECT * FROM receipt_user"):
                ru.setdefault(r["message_row_id"], []).append(dict(r))
        if "receipt_device" in t:
            for r in w.db.execute("SELECT * FROM receipt_device"):
                rd.setdefault(r["message_row_id"], []).append(dict(r))
        if "receipts" in t:
            for r in w.db.execute("SELECT * FROM receipts"):
                rg.setdefault(r["key_id"], []).append(dict(r))
        rjid = {r["_id"]: r["raw_string"] for r in w.db.execute("SELECT _id, raw_string FROM jid")} if "jid" in t else {}
        thumbs = {}                     # miniature salvate nel database (2.20)
        if "message_thumbnail" in t:
            for r in w.db.execute("SELECT * FROM message_thumbnail"):
                d0 = dict(r)
                if d0.get("message_row_id") is not None:
                    thumbs[("row", d0["message_row_id"])] = d0.get("thumbnail")
        if "message_thumbnails" in t:
            for r in w.db.execute("SELECT * FROM message_thumbnails"):
                d0 = dict(r)
                thumbs[("key", d0.get("key_id"), d0.get("key_remote_jid"), d0.get("key_from_me"))] = d0.get("thumbnail")
                thumbs.setdefault(("key", d0.get("key_id")), d0.get("thumbnail"))
        # schema dal 2022 (tabella message); nelle versioni di passaggio (2020-2021) message c'è ma è vuota e i
        # messaggi stanno ancora in messages
        if {"message", "chat", "jid"} <= t and w.db.execute("SELECT EXISTS(SELECT 1 FROM message)").fetchone()[0]:
            jid = {r["_id"]: r["raw_string"] for r in w.db.execute("SELECT _id, raw_string FROM jid")}
            avvisi = fmw.avvisi_android(w.db, jid, names, norm_number)   # (2.20) avvisi di sistema (message_type 7)
            chats = {r["_id"]: dict(r) for r in w.db.execute("SELECT * FROM chat")}
            media = {}
            if "message_media" in t:
                for r in w.db.execute("SELECT * FROM message_media"):
                    media[r["message_row_id"]] = dict(r)
            loc = {}
            if "message_location" in t:
                for r in w.db.execute("SELECT * FROM message_location"):
                    loc[r["message_row_id"]] = dict(r)
            # chiamate già nella chat come messaggi di tipo 90 (message_call_log → call_log): niente doppioni
            cl90, cl_usate = {}, set()
            if {"message_call_log", "call_log"} <= t:
                cll = {r["_id"]: dict(r) for r in w.db.execute("SELECT * FROM call_log")}
                for r in w.db.execute("SELECT message_row_id, call_log_row_id FROM message_call_log"):
                    if r["call_log_row_id"] in cll:
                        cl90[r["message_row_id"]] = cll[r["call_log_row_id"]]
            gparts = {}
            if "group_participant_user" in t:
                for r in w.db.execute("SELECT group_jid_row_id g, user_jid_row_id u FROM group_participant_user"):
                    gparts.setdefault(r["g"], []).append(jid.get(r["u"]))
            mc = w.cols("message")
            for r in w.db.execute("SELECT * FROM message ORDER BY timestamp"):
                d = dict(r)
                c = chats.get(d.get("chat_row_id")) or {}
                cj = jid.get(c.get("jid_row_id"), "") or ""
                is_group = cj.endswith("@g.us")
                title = c.get("subject") or (tr("Stati di WhatsApp") if cj == "status@broadcast" else
                                             names.get(norm_number(cj)) or cj)
                th = W.thread(cj or f"chat {d.get('chat_row_id')}", title,
                              gparts.get(c.get("jid_row_id")) if is_group else [cj], is_group)
                frm = bool(d.get("from_me"))
                sender = "" if frm else (jid.get(d.get("sender_jid_row_id")) or cj) if is_group else ("" if frm else cj)
                mt = d.get("message_type") or 0
                kind, tipo = fmw.classifica("android", mt)
                cl = cl90.get(d.get("_id")) if mt == 90 else None
                if cl:              # chiamata: tipo, durata ed esito dalla riga di call_log (verificato su Android 14)
                    cl_usate.add(cl["_id"])
                    dur = cl.get("duration")
                    esito_cl = cl.get("call_result")
                    tipo.update(tipo=fmca.etichetta_chiamata(tr("video") if cl.get("video_call") else tr("voce"),
                                                             "out" if frm else "in", dur),
                                durata_s=dur, risposta=True if esito_cl == 5 else None,
                                fonte_chiamata=f"msgstore.db · message + call_log #{cl['_id']}")
                st = d.get("status")
                av = mt == 7          # (2.20) avviso di WhatsApp: mai «inviato», anche se il database lo segna from_me = 1
                if av:
                    sender = ""
                    tipo.update(tipo=tr(fmw.AVVISO), from_me=d.get("from_me"))
                    if d.get("_id") in avvisi:
                        tipo["avviso"] = avvisi[d["_id"]]
                mid = W.message(th, _iso_ms(d.get("timestamp")), "sys" if av else "out" if frm else "in", sender,
                                d.get("text_data"), kind, "message", d.get("_id"),
                                status=(tr("letto") if frm and not av and st == 13 else tr("consegnato") if frm and not av and st in (4, 5) else None),
                                service="WhatsApp", sender_name=None if frm else names.get(norm_number(sender)),
                                extra={**tipo, "key_id": d.get("key_id"),
                                       "ricevuto": _iso_ms(d.get("received_timestamp")) if "received_timestamp" in mc else None,
                                       "preferito": bool(d.get("starred"))})
                if not av:
                    fmr.android(R, mid, d, ru.get(d.get("_id"), []), rd.get(d.get("_id"), []), rjid)
                m = media.get(d.get("_id"))
                if m:
                    fp = m.get("file_path") or ""
                    found, paths = wa_file(fp)
                    sha = _hash_b64(m.get("file_hash"))
                    fd = tv(found, paths, sha, m.get("file_size"), m.get("media_name") or (Path(fp).name if fp else None))
                    thumb = None if fd["found"] else _immagine(thumbs.get(("row", d.get("_id"))) or thumbs.get(("key", d.get("key_id"))))
                    W.attachment(mid, m.get("media_name") or Path(fp).name, m.get("mime_type"), m.get("file_size"), fp,
                                 fd["found"], metodo=fd["metodo"], sha256=sha, verifica=fd["verifica"], thumb=thumb)
                lc = loc.get(d.get("_id"))
                if lc:
                    W.attachment(mid, lc.get("place_name") or tr("posizione"), None, None, None, None,
                                 lc.get("latitude"), lc.get("longitude"))
            fmca.nella_chat(W, [r for r in fmca.wa_android(w, (part, str(inode), path))
                                if r["fonti"][0]["riga"] not in cl_usate], "call_log", names)
            return W
        if "messages" in t:                                         # schema precedente (e di passaggio 2020-2021)
            mm = {}
            if "message_media" in t:        # nello schema di passaggio file_path e file_hash stanno già qui
                for r in w.db.execute("SELECT * FROM message_media"):
                    mm[r["message_row_id"]] = dict(r)
            for r in w.db.execute("SELECT * FROM messages ORDER BY timestamp"):
                d = dict(r)
                cj = d.get("key_remote_jid") or ""
                if cj == "-1":
                    continue
                is_group = cj.endswith("@g.us")
                th = W.thread(cj, tr("Stati di WhatsApp") if cj == "status@broadcast" else names.get(norm_number(cj)) or cj,
                              [cj], is_group)
                frm = bool(d.get("key_from_me"))
                sender = "" if frm else (d.get("remote_resource") or cj)
                mt = int(d.get("media_wa_type") or 0)
                system = d.get("status") == 6 or (mt == 0 and not d.get("data"))   # stato 6 = evento di sistema
                kind, tipo = fmw.classifica("android_vecchio", mt, system)
                mid = W.message(th, _iso_ms(d.get("timestamp")), "sys" if system else "out" if frm else "in", sender,
                                d.get("data"), kind,
                                "messages", d.get("_id"), service="WhatsApp",
                                sender_name=None if frm else names.get(norm_number(sender)),
                                extra={**tipo, "key_id": d.get("key_id")})
                if not system:
                    fmr.android_vecchio(R, mid, d, rd.get(d.get("_id"), []), rg.get(d.get("key_id"), []), rjid)
                m = mm.get(d.get("_id")) or {}
                if mt and (d.get("media_name") or d.get("media_mime_type") or m):
                    fp = m.get("file_path") or _java_path(d.get("thumb_image")) or ""
                    found, paths = wa_file(fp)
                    size = m.get("file_size") or d.get("media_size")
                    name = m.get("media_name") or d.get("media_name") or (Path(fp).name if fp else None)
                    sha = _hash_b64(m.get("file_hash") or d.get("media_hash"))
                    fd = tv(found, paths, sha, size, name)
                    thumb = None if fd["found"] else _immagine(
                        thumbs.get(("key", d.get("key_id"), cj, d.get("key_from_me"))) or thumbs.get(("key", d.get("key_id")))
                        or d.get("raw_data"))
                    W.attachment(mid, name, m.get("mime_type") or d.get("media_mime_type"), size, fp or None, fd["found"],
                                 d.get("latitude") or None, d.get("longitude") or None, metodo=fd["metodo"], sha256=sha,
                                 verifica=fd["verifica"], thumb=thumb)
            fmca.nella_chat(W, fmca.wa_android(w, (part, str(inode), path)), "call_log", names)
            return W
        return None
    finally:
        w.close()


# ------------------------------------------------------------------------- SMS/MMS Android

def read_sms_android(case, con, part, inode, path, names, done_keys):
    w = WorkDB(case, part, inode, path, con)
    W = Writer(con, "sms", part, inode, path)
    try:
        t = w.tables()
        if "sms" not in t and "pdu" not in t:
            return None
        res = Resolver(case, part, ["app_parts/"])
        tv = Trova(case, part)
        if "sms" in t:
            for r in w.db.execute("SELECT * FROM sms ORDER BY date"):
                d = dict(r)
                key = ("sms", d.get("_id"), d.get("date"), d.get("body"))
                if key in done_keys:                  # stesso messaggio nella copia user_de e in quella data/data
                    continue
                done_keys.add(key)
                addr = d.get("address") or ""
                th = W.thread(f"thread {d.get('thread_id')}" if d.get("thread_id") is not None else addr,
                              names.get(norm_number(addr)) or addr, [addr])
                ty = d.get("type")
                out = SMS_TYPES.get(ty, "in") == "out"
                W.message(th, _iso_ms(d.get("date")), "out" if out else "in", "" if out else addr, d.get("body"),
                          "testo", "sms", d.get("_id"), status=tr(SMS_STATUS[ty]) if ty in SMS_STATUS else None,
                          service="SMS", sender_name=None if out else names.get(norm_number(addr)),
                          extra={"inviato": _iso_ms(d.get("date_sent")), "letto": d.get("read")})
        if {"pdu", "part"} <= t:
            addrs = {}
            if "addr" in t:
                for r in w.db.execute("SELECT msg_id, address, type FROM addr"):
                    addrs.setdefault(r["msg_id"], []).append((r["address"], r["type"]))
            parts_ = {}
            for r in w.db.execute("SELECT * FROM part"):
                parts_.setdefault(r["mid"], []).append(dict(r))
            for r in w.db.execute("SELECT * FROM pdu ORDER BY date"):
                d = dict(r)
                key = ("mms", d.get("_id"), d.get("date"), d.get("m_id"))
                if key in done_keys:
                    continue
                done_keys.add(key)
                out = d.get("msg_box") == 2
                al = addrs.get(d["_id"], [])
                frm = next((a for a, ty in al if ty == 137), "")
                tos = [a for a, ty in al if ty in (151, 130, 129)]
                peers = tos if out else [frm]
                th = W.thread(f"thread {d.get('thread_id')}", ", ".join(names.get(norm_number(x)) or x for x in peers if x)
                              or str(d.get("thread_id")), [x for x in peers if x], len(peers) > 1)
                texts = [p.get("text") for p in parts_.get(d["_id"], []) if (p.get("ct") or "").startswith("text/plain")
                         and p.get("text")]
                body = "\n".join(texts) or (d.get("sub") or "")
                mid = W.message(th, _iso_unix(d.get("date")), "out" if out else "in", "" if out else frm, body, "testo",
                                "pdu", d["_id"], service="MMS", sender_name=None if out else names.get(norm_number(frm)),
                                extra={"oggetto": d.get("sub")})
                for p in parts_.get(d["_id"], []):
                    ct = p.get("ct") or ""
                    if ct.startswith("text/plain") or ct == "application/smil":
                        continue
                    fp = p.get("_data") or ""
                    fd = tv(res.find(fp, "app_parts/") if fp else None, [fp] if fp else [])
                    W.attachment(mid, p.get("cl") or p.get("name") or Path(fp).name, ct, None, fp, fd["found"],
                                 metodo=fd["metodo"])
        return W
    finally:
        w.close()


# -------------------------------------------------------------------------------- insieme

def _sha_db(case, part, inode):
    import hashlib
    import forense_mobile as fm
    h = hashlib.sha256()
    for b in fm.stream(case, part, inode):
        h.update(b)
    return h.hexdigest()


def trova_db(con, part):
    found, encrypted = {}, []
    for i, path in con.execute("SELECT id, path FROM mobile_files WHERE part=? AND isdir=0 AND ("
                               "path LIKE '%.db' OR path LIKE '%.sqlite' OR path LIKE '%.sqlitedb' OR path LIKE '%crypt%')",
                               (part,)):
        for kind, rx in DB_PATTERNS.items():
            if rx.search(path):
                found.setdefault(kind, []).append((str(i), path))
        if ENCRYPTED_RE.search(path):
            encrypted.append(path)
    return found, encrypted


def aggiorna_estese(case, con):
    """Conteggi degli artefatti per categoria in meta["estese"]["artefatti"]: così l'interfaccia mostra la sezione
    Artefatti (messaggi delle chat, righe di iLEAPP/ALEAPP) come per i dischi."""
    import forense_agent as fa
    try:
        cnt = dict(con.execute("SELECT cat, COUNT(*) FROM artifacts GROUP BY cat").fetchall())
    except sqlite3.Error:
        return
    case.meta.setdefault("estese", {})["artefatti"] = {**cnt, "ts": fa.now()}


def run(case, con, chiamate=True):
    """Legge chat e rubriche dell'estrazione e le scrive nel caso (tabelle chat_*, timeline, artefatti).
    `chiamate=False`: la sezione Chiamate la scrive il passaggio di iLEAPP/ALEAPP che segue (preparazione con --leapp)."""
    import forense_agent as fa
    import forense_mobile as fm
    import forense_estesa as fe
    ensure_schema(con)
    for tb in ("chat_threads", "chat_messages", "chat_attachments", "chat_contacts"):
        con.execute(f"DELETE FROM {tb}")
    fmr.svuota(con)
    con.execute("DELETE FROM events WHERE origin='chat'")
    fe.ensure_schema(con)
    ensure_art_cols(con)
    con.execute("DELETE FROM artifacts WHERE cat='messaggi' AND data LIKE '%\"chat_thread\"%'")
    out = {"app": {}, "rubriche": 0, "cifrati": [], "avvisi": [], "proprietario": {}}
    plat = (case.meta.get("mobile") or {}).get("piattaforma")
    names = {}
    for p in fm.sorgenti(case):
        part = int(p["offset"])
        try:
            out["proprietario"].update(identita(case, part))
        except Exception as e:
            out["avvisi"].append(tr("Numero del telefono non letto ({vname}: {e})").format(vname=type(e).__name__, e=e))
        m = fm.mx(case)
        found, encrypted = trova_db(m, part)
        m.close()
        out["cifrati"] += encrypted
        print(tr("Rubriche e contatti…"), flush=True)
        out["rubriche"] += read_contacts(case, con, part, [(k, x) for k, xs in found.items() for x in xs])
        names = name_map(con)
        done_sms, letti = set(), {}
        readers = (("imessage", read_imessage), ("whatsapp_ios", read_whatsapp_ios),
                   ("whatsapp_android", read_whatsapp_android), ("sms_android", None))
        for kind, fn in readers:
            for inode, path in found.get(kind, []):
                h = _sha_db(case, part, inode)          # copia identica di un database già letto (es. mirror di Magisk)
                if h in letti:
                    out["avvisi"].append(tr("{path}: copia identica di {orig} (SHA-256 uguale), non riletta").format(
                        path=path, orig=letti[h]))
                    continue
                letti[h] = path
                print(tr("Chat: {app} da {path}…").format(app=kind, path=path), flush=True)
                try:
                    W = (read_sms_android(case, con, part, inode, path, names, done_sms) if fn is None
                         else fn(case, con, part, inode, path, names))
                except Exception as e:
                    out["avvisi"].append(tr("{path}: non letto ({vname}: {e})").format(path=path, vname=type(e).__name__, e=e))
                    print("  " + out["avvisi"][-1], flush=True)
                    continue
                if W is None:
                    out["avvisi"].append(tr("{path}: struttura non riconosciuta").format(path=path))
                    continue
                for th, cnt in W.local.items():
                    con.execute("UPDATE chat_threads SET local=? WHERE id=?", (max(cnt, key=cnt.get), th))
                a = out["app"].setdefault(W.app, {"conversazioni": 0, "messaggi": 0, "allegati": 0, "fonti": []})
                a["conversazioni"] += len(W.threads)
                a["messaggi"] += W.n_msg
                a["allegati"] += W.n_att
                a["fonti"].append(path)
                con.commit()
        if case.meta.get("wa_backup_attivo"):        # (2.20) backup WhatsApp decifrati con la chiave dell'estrazione
            out["backup_whatsapp"] = leggi_backup(case, con, part, names, out)
    if out.get("backup_whatsapp") is not None:
        segna_backup(con)
    # chat delle app che RepertIA non legge, dagli artefatti di iLEAPP/ALEAPP (se eseguiti)
    try:
        import forense_mobile_leapp_chat as fmlc
        lapps, _u, _a = fmlc.chat_from_leapp(case, con, names)
        out["app"].update(lapps)
    except Exception as e:
        out["avvisi"].append(tr("Chat da iLEAPP/ALEAPP non ricavate ({vname}: {e})").format(vname=type(e).__name__, e=e))
    # riepilogo per conversazione, timeline e artefatti
    thread_stats(con)
    chat_events(con)
    # questo telefono nelle conversazioni senza un numero proprio: WhatsApp Android dalle shared_prefs, SMS e iMessage
    # dal numero della SIM (WhatsApp iOS: il numero non è in chiaro nell'estrazione → «questo dispositivo»)
    prop = out["proprietario"]
    if prop.get("whatsapp") and plat == "android":
        con.execute("UPDATE chat_threads SET local=? WHERE app='whatsapp' AND local IS NULL", (prop["whatsapp"]["id"],))
    if prop.get("telefono") and not prop["telefono"].get("piu_sim"):
        con.execute("UPDATE chat_threads SET local=? WHERE app IN ('sms', 'imessage') AND local IS NULL",
                    (prop["telefono"]["id"],))
    thread_artifacts(con, names)
    try:
        import forense_mobile_leapp_chat as fmlc
        cs = fmlc.calls_from_leapp(case, con, names) if chiamate else None
        if cs is not None:
            case.meta["chiamate"] = cs
    except Exception as e:
        out["avvisi"].append(tr("Chiamate da iLEAPP/ALEAPP non ricavate ({vname}: {e})").format(vname=type(e).__name__, e=e))
    con.commit()
    if out["cifrati"]:
        out["avvisi"] += avvisi_cifrati(case, out)
    out["ts"] = fa.now()
    case.meta["chat"] = out
    aggiorna_estese(case, con)
    case.log("chat", out)
    case.save()
    for app, a in out["app"].items():
        print(tr("  {app}: {c} conversazioni, {m} messaggi, {a} allegati").format(
            app=APP_LBL.get(app, app), c=a["conversazioni"], m=a["messaggi"], a=a["allegati"]), flush=True)
    if not out["app"]:
        print(tr("  Nessun database di chat riconosciuto nell'estrazione."), flush=True)
    return out


def leggi_backup(case, con, part, names, out):
    """(2.20) Decifra i backup WhatsApp (forense_mobile_wabackup) e legge quelli decifrati come conversazioni dell'app
    «whatsapp_backup»; restituisce gli esiti."""
    import forense_mobile_wabackup as fmwb
    try:
        res = fmwb.run(case, part)
    except Exception as e:
        out["avvisi"].append(tr("Backup WhatsApp non decifrati ({vname}: {e})").format(vname=type(e).__name__, e=e))
        return {"errore": str(e)}
    ids = {p: i for i, p, _s in fmwb.trova(case, part)[1]}
    for e in res["backup"]:
        if e.get("esito") != "decifrato":
            continue
        nome = Path(e["percorso"]).name
        print(tr("Chat: backup WhatsApp {n}…").format(n=nome), flush=True)
        try:
            W = read_whatsapp_android(case, con, part, ids[e["percorso"]], e["percorso"], names,
                                      backup={"file": Path(case.root) / e["decifrato"]["file"], "nome": nome})
        except Exception as ex:
            out["avvisi"].append(tr("{path}: non letto ({vname}: {e})").format(path=e["percorso"], vname=type(ex).__name__, e=ex))
            continue
        if W is None:
            continue
        con.execute("UPDATE chat_threads SET origin='backup' WHERE id IN (SELECT value FROM json_each(?))",
                    (json.dumps(list(W.threads.values())),))
        con.execute("UPDATE chat_messages SET extra = json_set(coalesce(extra, '{}'), '$.backup', ?) WHERE thread IN "
                    "(SELECT value FROM json_each(?))", (nome, json.dumps(list(W.threads.values()))))
        a = out["app"].setdefault("whatsapp_backup", {"conversazioni": 0, "messaggi": 0, "allegati": 0, "fonti": []})
        a["conversazioni"] += len(W.threads)
        a["messaggi"] += W.n_msg
        a["allegati"] += W.n_att
        a["fonti"].append(e["percorso"])
        con.commit()
    return res


def segna_backup(con):
    """(2.20) Messaggi dei backup che NON sono nel database attuale (stesso key_id assente dai messaggi WhatsApp letti
    da msgstore.db): extra.solo_nel_backup = true. Restituisce quanti sono."""
    con.execute("UPDATE chat_messages SET extra = json_set(extra, '$.solo_nel_backup', json('true')) WHERE app='whatsapp_backup' "
                "AND json_extract(extra, '$.key_id') IS NOT NULL AND json_extract(extra, '$.key_id') NOT IN "
                "(SELECT json_extract(extra, '$.key_id') FROM chat_messages WHERE app='whatsapp' "
                "AND json_extract(extra, '$.key_id') IS NOT NULL)")
    con.commit()
    return con.execute("SELECT COUNT(*) FROM chat_messages WHERE app='whatsapp_backup' AND "
                       "json_extract(extra, '$.solo_nel_backup')").fetchone()[0]


def avvisi_cifrati(case, out):
    """(2.20) Avvisi sui database cifrati: i backup WhatsApp con il loro esito (o la chiave presente nell'estrazione se
    la decifratura non è stata chiesta); gli altri (Signal…) come prima."""
    import forense_mobile_wabackup as fmwb
    bk = out.get("backup_whatsapp") or {}
    fatti = {e["percorso"]: e for e in bk.get("backup", [])}
    altri = [p for p in out["cifrati"] if p not in fatti]
    av = []
    wa = [p for p in altri if fmwb.BACKUP_RE.search(p)]
    if wa and not bk:
        chiavi = []
        for p in fm_sorgenti_offsets(case):
            chiavi += [k[1] for k in fmwb.trova(case, p)[0]]
        if chiavi:
            av.append(tr("Backup WhatsApp cifrati: la chiave è nell'estrazione ({k}); per leggerli attiva «Decifra i backup "
                         "WhatsApp»: ").format(k=", ".join(chiavi[:2])) + ", ".join(wa[:10]))
            altri = [p for p in altri if p not in wa]
    for e in fatti.values():
        av.append(tr("Backup WhatsApp: ") + fmwb.testo_esito(e))
    wa_altri = [p for p in altri if "/WhatsApp/" in p and not fmwb.BACKUP_RE.search(p)]
    if wa_altri:
        av.append(tr("Altri backup di WhatsApp (impostazioni, contatti, sticker: non contengono i messaggi), non letti: ")
                  + ", ".join(wa_altri[:10]))
        altri = [p for p in altri if p not in wa_altri]
    if altri:
        av.append(tr("Database cifrati non letti (serve la chiave): ") + ", ".join(altri[:10]))
    return av


def fm_sorgenti_offsets(case):
    import forense_mobile as fm
    return [int(p["offset"]) for p in fm.sorgenti(case)]


def _ids_where(ids, col="id"):
    return (f" WHERE {col} IN (SELECT value FROM json_each(?))", [json.dumps(list(ids))]) if ids is not None else ("", [])


def thread_stats(con, ids=None):
    """Numero di messaggi, primo e ultimo per conversazione; toglie le conversazioni vuote."""
    w, a = _ids_where(ids)
    con.execute("UPDATE chat_threads SET n_msg = (SELECT COUNT(*) FROM chat_messages m WHERE m.thread = chat_threads.id),"
                " first_ts = (SELECT MIN(ts) FROM chat_messages m WHERE m.thread = chat_threads.id),"
                " last_ts = (SELECT MAX(ts) FROM chat_messages m WHERE m.thread = chat_threads.id)" + w, a)
    con.execute("DELETE FROM chat_threads WHERE n_msg = 0" + (w.replace(" WHERE", " AND") if w else ""), a)


def chat_events(con, ids=None):
    """Messaggi nella timeline (origine «chat»)."""
    import forense_agent as fa
    w, a = _ids_where(ids, "t.id")
    evs = []
    for ts, app, d, sender, sname, text, title, src, kind, extra in con.execute(
            "SELECT m.ts, m.app, m.direction, m.sender, m.sender_name, m.text, t.title, t.src_path, m.kind, m.extra FROM chat_messages m "
            "JOIN chat_threads t ON t.id = m.thread" + (w + " AND" if w else " WHERE") + " m.ts IS NOT NULL", a):
        who = tr("inviato") if d == "out" else (sname or sender or tr("ricevuto"))
        evs.append((ts, "MSG", APP_LBL.get(app, app), src,
                    f"{APP_LBL.get(app, app)} | {title} | {who}: {(text or '[' + fmw.etichetta(kind, extra) + ']')[:300]}", "chat", None))
        if len(evs) >= 50000:
            con.executemany(fa.INSERT_EV, evs)
            evs.clear()
    con.executemany(fa.INSERT_EV, evs)


def thread_artifacts(con, names, ids=None):
    """Una riga di «Messaggi» per conversazione (gruppo = app): i due interlocutori (questo telefono e l'altro, o il
    gruppo con i partecipanti), periodo, messaggi inviati e ricevuti, allegati, ultimo messaggio. Il testo di titolo
    e dettagli serve a ricerca, CSV e report; l'interfaccia mostra i campi di «data» con le date nel fuso scelto."""
    w, wa = _ids_where(ids, "thread")
    stats = {r[0]: r[1:] for r in con.execute(
        "SELECT thread, SUM(direction='out'), SUM(direction='in' AND kind != 'sistema'), "
        "SUM(direction='sys' OR kind='sistema'), SUM(n_att), SUM(kind='eliminato'), "
        "SUM(direction='unk' AND kind != 'sistema') FROM chat_messages" + w + " GROUP BY thread", wa)}
    rows = []
    w, wa = _ids_where(ids)
    for tid, app, title, parts, grp, n, a, b, part, inode, src, local, origin in con.execute(
            "SELECT id, app, title, participants, is_group, n_msg, first_ts, last_ts, part, inode, src_path, local, origin "
            "FROM chat_threads" + w, wa).fetchall():
        out_n, in_n, sys_n, att_n, del_n, unk_n = (int(x or 0) for x in stats.get(tid, (0, 0, 0, 0, 0, 0)))
        last = con.execute("SELECT text, direction, kind, ts, extra FROM chat_messages WHERE thread=? AND kind != 'reazione' "
                           "ORDER BY ts DESC, id DESC LIMIT 1", (tid,)).fetchone()
        plist = [x for x in json.loads(parts or "[]") if x]
        loc = {"id": show_id(local) if local else None}
        lbl_loc = tr("questo dispositivo") + (f" ({loc['id']})" if loc["id"] else "")
        altro = gruppo = None
        if grp:
            gruppo = {"nome": title, "n": len(plist)}
            other = tr("gruppo «{g}» ({n} partecipanti)").format(g=title, n=len(plist))
        else:
            ident = plist[0] if plist else ""
            nome = names.get(norm_number(ident)) or (title if title and title not in (ident, show_id(ident)) else None)
            altro = {"nome": nome, "id": show_id(ident) or None, "breve": is_short(ident)}
            other = " ".join(x for x in (nome, (f"({altro['id']})" if nome else altro["id"]) if altro["id"] else None) if x) \
                or tr("(sconosciuto)")
            if altro["breve"]:
                other += " — " + tr("numero breve/servizio")
        lm = {"testo": (last[0] or "")[:200], "dir": last[1], "kind": last[2], "ts": last[3]} if last else None
        if lm and lm["kind"] == "non gestito":          # «tipo N non gestito» (la chiave c'è solo in questo caso)
            lm["tipo"] = fmw.etichetta(last[2], last[4])
        prev = " ".join((lm["testo"] or "[" + (lm.get("tipo") or tr(lm["kind"] or "")) + "]").split()) if lm else ""
        detail = (tr("dal {a} al {b} (UTC)").format(a=(a or "?").replace("T", " "), b=(b or "?").replace("T", " "))
                  + " · " + tr("inviati {o}, ricevuti {i}").format(o=out_n, i=in_n)
                  + (" · " + tr("verso non indicato {u}").format(u=unk_n) if unk_n else "")
                  + (" · " + tr("eventi {e}").format(e=sys_n) if sys_n else "")
                  + " · " + tr("allegati {a}").format(a=att_n)
                  + (" · " + tr("ultimo messaggio ({d}): «{t}»").format(
                      d=tr("inviato") if lm["dir"] == "out" else tr("evento") if lm["dir"] == "sys" else tr("ricevuto"),
                      t=prev[:120]) if lm else ""))
        rows.append(("messaggi", b, (tr("{app}: {loc} ↔ {other} · {n} messaggio") if n == 1 else
                                     tr("{app}: {loc} ↔ {other} · {n} messaggi")).format(
            app=APP_LBL.get(app, app), loc=lbl_loc, other=other, n=n), detail, "", src, part, inode,
            json.dumps({"chat_thread": tid, "app": app, "locale": loc, "altro": altro, "gruppo": gruppo,
                        "partecipanti": [show_id(x) for x in plist][:50], "n": n, "inviati": out_n, "ricevuti": in_n,
                        "eventi": sys_n, "allegati": att_n, "eliminati": del_n, "primo": a, "ultimo": b,
                        "ultimo_msg": lm, "senza_verso": unk_n,
                        "fonte": _fonte_leapp(con, tid) if origin == "leapp" else None}, ensure_ascii=False), app, None))
    con.executemany("INSERT INTO artifacts(cat, ts, title, detail, user, src_path, part, inode, data, grp, sub) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)


def _fonte_leapp(con, tid):
    """Artefatti di iLEAPP/ALEAPP da cui viene una conversazione ricavata (con il numero di messaggi)."""
    out = {}
    for (ex,) in con.execute("SELECT extra FROM chat_messages WHERE thread=?", (tid,)):
        try:
            e = json.loads(ex or "{}")
        except ValueError:
            continue
        k = f"{e.get('strumento')} «{e.get('artefatto')}»"
        out[k] = out.get(k, 0) + 1
        for r in e.get("altre_fonti") or []:
            k2 = f"{r.get('strumento')} «{r.get('artefatto')}»"
            out.setdefault(k2, 0)
    return {"strumento": next((k.split(" ")[0] for k in out), None), "artefatti": out}


# ------------------------------------------------------------------------------ riepilogo

def summary_md(case, what="all"):
    """Righe del riepilogo (chat e iLEAPP/ALEAPP) mostrato nella conversazione all'apertura del caso."""
    m = case.meta
    L, Q = [], []
    mob = m.get("mobile") or {}
    if what == "all":
        L.append(tr("#### Smartphone"))
        si = mob.get("sistema") or {}
        L.append("- " + (m.get("disk_type") or "") + (f" ({si.get('modello')})" if si.get("modello") else "")
                 + (tr(", estrazione prodotta da {p}").format(p=mob["produttore"]) if mob.get("produttore") else ""))
    c = m.get("chat") or {}
    if what in ("all", "mobile_chat"):
        L.append(tr("#### Chat"))
        if c.get("app"):
            for app, a in c["app"].items():
                L.append(tr("- {app}: {c} conversazioni, {n} messaggi, {a} allegati").format(
                    app=APP_LBL.get(app, app), c=a["conversazioni"], n=a["messaggi"], a=a["allegati"]))
            L.append(tr("- Le conversazioni si leggono con il pulsante «💬 Chat» nel pannello del caso."))
            Q += [tr("Elenca le conversazioni con più messaggi e i loro partecipanti"),
                  tr("Ci sono messaggi che parlano di appuntamenti, soldi o spostamenti?")]
        else:
            L.append(tr("- Nessun database di chat riconosciuto."))
        for w in c.get("avvisi") or []:
            L.append(tr("- Attenzione: {w}").format(w=w))
    lp = m.get("leapp")
    if lp and what in ("all", "mobile_leapp"):
        L.append(tr("#### iLEAPP/ALEAPP"))
        if lp.get("esito") == "ok":
            top = sorted((lp.get("artefatti") or {}).items(), key=lambda x: -x[1])[:12]
            L.append(tr("- {s} {v}: {n} artefatti, {r} righe (categoria «leapp» negli Artefatti)").format(
                s=lp["strumento"], v=lp.get("versione"), n=len(lp.get("artefatti") or {}), r=lp.get("righe")))
            if top:
                L.append(tr("- Più numerosi: ") + ", ".join(f"{k} {v}" for k, v in top))
        else:
            L.append(tr("- Non riuscito: vedi il registro nella cartella del caso."))
    return L, Q


# ------------------------------------------------------------------------------ report portatile

def export_portable(case, dati):
    """Chat per il report portatile in dati/chat.js: conversazioni, messaggi (testo fino a 20.000 caratteri) e
    allegati (con part/inode per aprirli se il loro contenuto è incluso nel report). False se non ci sono chat."""
    import forense_agent as fa
    import forense_portatile as fp
    con = fa.db_ro(case)
    try:
        if not fa.table_exists(con, "chat_threads"):
            return False
        has_o = "origin" in {r[1] for r in con.execute("PRAGMA table_info(chat_threads)")}
        rows = con.execute("SELECT id, app, title, participants, is_group, n_msg, first_ts, last_ts, src_path, local, part, "
                           "inode, " + ("origin" if has_o else "NULL") + " FROM chat_threads ORDER BY last_ts DESC").fetchall()
        if not rows:
            return False
        # database di origine di ogni conversazione (offset, voce, SHA-256), per l'intestazione di «Esporta chat»
        shas, threads = {}, []
        for r in rows:
            fonti = []
            pairs = [(r[10], r[11])] if r[11] not in (None, "", "None") else []
            pairs += [x for x in con.execute("SELECT DISTINCT part, inode FROM chat_messages WHERE thread=? AND inode IS NOT NULL "
                                             "AND inode != 'None'", (r[0],)) if tuple(x) not in pairs]
            for part, inode in pairs:
                k = (part, str(inode))
                if k not in shas:
                    try:
                        shas[k] = _sha_db(case, part, str(inode))
                    except Exception:
                        shas[k] = None
                fonti.append([part, str(inode), shas[k]])
            threads.append(list(r[:3]) + [", ".join(json.loads(r[3] or "[]"))] + list(r[4:9]) +
                           [fonti, show_id(r[9]) if r[9] else None, r[12]])
        att, by_msg = [], {}
        trs = {}                            # (2.20) trascrizione automatica più recente di ogni file
        if con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='trascrizioni'").fetchone():
            for part, inode, testo, modello, lingua in con.execute(
                    "SELECT part, inode, testo, modello, lingua FROM trascrizioni ORDER BY ts"):
                trs[(part, str(inode))] = [testo or "", f"{modello} · {lingua or '?'}"]
        have = {r[1] for r in con.execute("PRAGMA table_info(chat_attachments)")}
        extra = ", ".join(c if c in have else "NULL" for c in ("metodo", "verifica", "thumb"))
        import forense_percorsi as fpc
        for aid, mid, name, dev, part, inode, path, lat, lon, metodo, verifica, thumb in con.execute(
                "SELECT id, msg, name, device_path, part, inode, path, lat, lon, " + extra + " FROM chat_attachments ORDER BY id"):
            by_msg.setdefault(mid, []).append(len(att))
            how = ""                        # (2.20) come è stato trovato il file; miniatura del database se manca
            if inode not in (None, "") and metodo and metodo != "percorso":
                how = fpc.esito_metodo(metodo, verifica)
            if verifica == "uguale":
                how = "; ".join(x for x in (how, tr("SHA-256 uguale a quello registrato dall'app")) if x)
            elif verifica == "diverso":
                how = "; ".join(x for x in (how, tr("ATTENZIONE: SHA-256 diverso da quello registrato dall'app")) if x)
            th = ""
            if thumb and inode in (None, ""):
                d = Path(dati).parent / "citati"
                d.mkdir(parents=True, exist_ok=True)
                (d / f"att{aid}.jpg").write_bytes(bytes(thumb))
                th = f"citati/att{aid}.jpg"
            t_ = trs.get((part, str(inode))) if inode not in (None, "") else None
            att.append([name, dev, part, inode, path, lat, lon, how, th] + (t_ or []))
        msgs = []
        rcm = fmr.per_messaggi(con, [r[0] for r in con.execute("SELECT msg FROM chat_receipts")]) \
            if con.execute("SELECT 1 FROM sqlite_master WHERE name='chat_receipts'").fetchone() else {}
        for r in con.execute("SELECT id, thread, ts, direction, sender, sender_name, text, kind, status, service, "
                             "src_table, src_row, extra FROM chat_messages ORDER BY thread, ts, id"):
            ex = json.loads(r[12]) if r[12] else {}
            msgs.append([r[1], r[2], r[3], r[4], r[5], (r[6] or "")[:20000], r[7], r[8], r[9], r[10], r[11],
                         ex.get("tipo"), by_msg.get(r[0], []), r[0], ex.get("codice"), ex.get("verificato"),
                         [[x["stato"], x["etichetta"], x["ts"], x["destinatario"], x["fonte"], x["verificato"], x["nota"]]
                          for x in rcm.get(r[0], [])], 1 if ex.get("solo_nel_backup") else 0])   # (2.20) 17: solo nel backup
        apps = dict(con.execute("SELECT app, COUNT(*) FROM chat_messages GROUP BY app").fetchall())
    finally:
        con.close()
    fp.write_js(dati / "chat.js", "chat", {"threads": threads, "msgs": msgs, "att": att, "apps": apps})
    return True


# ------------------------------------------------------------------------------- report

def report_md(case):
    """Sezioni del report per i casi smartphone: estrazione, chat, iLEAPP/ALEAPP, limiti."""
    import forense_agent as fa
    import forense_mobile as fm

    def cell(x):
        return str(x if x is not None else "").replace("|", "/").replace("\n", " ")
    m = case.meta
    mob = m.get("mobile") or {}
    L = ["", tr("## Estrazione dello smartphone"), ""]
    for p in fm.sorgenti(case):
        s = p["mobile"]
        st = s.get("statistiche") or {}
        si = s.get("sistema") or {}
        L.append(tr("- Estrazione `{n}` ({fmt}){prod}: {v} voci, {c} cartelle, {b} byte di file").format(
            n=s.get("nome"), fmt=tr(fm.FORMATI.get(s.get("formato"), s.get("formato"))),
            prod=(", " + tr("prodotta da {p} (riconosciuto dalla struttura)").format(p=s["produttore"])) if s.get("produttore") else "",
            v=st.get("voci"), c=st.get("cartelle"), b=st.get("byte")))
        if si:
            L.append(tr("- Sistema del telefono: ") + ", ".join(f"{k} {v}" for k, v in si.items() if v))
        for k, n in (st.get("date") or {}).items():
            L.append(tr("- Date di {n} voci: {s}").format(n=n, s=tr(fm.DATESRC.get(k, k))))
        if st.get("metodi"):
            L.append(tr("- Compressione delle voci dello zip: ") + ", ".join(f"{k} {v}" for k, v in st["metodi"].items()))
    d = m.get("decompressa")
    if d:
        L.append(tr("- Copia derivata decompressa (il tar.gz non permette letture dirette): `{f}` creata il {c} da `{o}` "
                    "(SHA-256 dell'originale `{so}`, della copia `{sc}`, {b} byte). I file si leggono dalla copia "
                    "derivata; l'originale non è stato modificato.").format(
            f=m.get("image"), c=d.get("creata"), o=d.get("origine"), so=d.get("sha256_origine"), sc=d.get("sha256"),
            b=d.get("byte")))
    L.append(tr("- I file non sono stati estratti: si leggono dall'estrazione quando servono (posizione di ogni voce "
                "nella scheda Metadati). L'estrazione contiene solo i file presenti nel telefono al momento "
                "dell'acquisizione: non ci sono file cancellati del file system."))
    c = m.get("chat") or {}
    L += ["", tr("## Chat e messaggi"), ""]
    if c.get("app"):
        L.append(tr("Lettori propri di RepertIA (indipendenti da iLEAPP/ALEAPP); ogni database è letto da una copia di "
                    "lavoro con i suoi file -wal/-shm. Orari in UTC."))
        L += ["", tr("| App | Conversazioni | Messaggi | Allegati | Database |"), "|---|---|---|---|---|"]
        for app, a in c["app"].items():
            L.append(f"| {APP_LBL.get(app, app)} | {a['conversazioni']} | {a['messaggi']} | {a['allegati']} | "
                     f"{cell(', '.join(a.get('fonti') or []))} |")
        prop = c.get("proprietario") or {}
        L.append("")
        for k, lbl in (("telefono", tr("Numero del telefono analizzato")), ("whatsapp", tr("Numero registrato in WhatsApp"))):
            if prop.get(k):
                L.append(f"- {lbl}: {prop[k]['id']}" + (f" ({prop[k]['nome']})" if prop[k].get("nome") else "")
                         + " — " + tr("fonte: {f}").format(f=prop[k].get("fonte")))
        if not prop:
            L.append(tr("- Numero del telefono analizzato: non scritto in chiaro nell'estrazione («questo dispositivo»)."))
        try:
            con = fa.db_ro(case)
            rows = [json.loads(d) for (d,) in con.execute(
                "SELECT data FROM artifacts WHERE cat='messaggi' AND data LIKE '%\"chat_thread\"%'")]
            n_link = con.execute("SELECT COUNT(*), COUNT(inode) FROM chat_attachments").fetchone()
            con.close()
        except Exception:
            rows, n_link = [], (0, 0)
        rows = sorted(rows, key=lambda d: -(d.get("n") or 0))[:50]
        if rows:
            def other(d):
                if d.get("gruppo"):
                    return tr("gruppo «{g}» ({n} partecipanti)").format(g=d["gruppo"].get("nome"), n=d["gruppo"].get("n"))
                al = d.get("altro") or {}
                return " ".join(x for x in (al.get("nome"), al.get("id")) if x) + (
                    " — " + tr("numero breve/servizio") if al.get("breve") else "")
            L += ["", tr("Conversazioni con più messaggi (al massimo 50):"), "",
                  tr("| App | Questo telefono | Interlocutore | Messaggi (inviati/ricevuti) | Allegati | Primo (UTC) | Ultimo (UTC) |"),
                  "|---|---|---|---|---|---|---|"]
            L += [f"| {APP_LBL.get(d.get('app'), d.get('app'))} | {cell((d.get('locale') or {}).get('id') or tr('questo dispositivo'))} | "
                  f"{cell(other(d))} | {d.get('n')} ({d.get('inviati')}/{d.get('ricevuti')}) | {d.get('allegati')} | "
                  f"{cell((d.get('primo') or '').replace('T', ' '))} | {cell((d.get('ultimo') or '').replace('T', ' '))} |"
                  for d in rows]
        if n_link[0]:
            L.append("")
            L.append(tr("- Allegati collegati al file presente nell'estrazione: {b} su {a}.").format(a=n_link[0], b=n_link[1]))
        if c.get("rubriche"):
            L.append(tr("- Voci di rubrica usate per i nomi: {n}.").format(n=c["rubriche"]))
    else:
        L.append(tr("Nessun database di chat riconosciuto (o lettura non eseguita)."))
    for w in c.get("avvisi") or []:
        L.append(tr("- Attenzione: {w}").format(w=w))
    lp = m.get("leapp")
    if lp:
        L += ["", tr("## Artefatti con iLEAPP/ALEAPP"), ""]
        if lp.get("esito") == "ok":
            L.append(tr("- {s} {v} (impronta `{i}`), durata {d} s: {n} artefatti, {r} righe importate; rapporto completo "
                        "in `{rep}`.").format(s=lp["strumento"], v=lp.get("versione"), i=lp.get("impronta"), d=lp.get("durata_s"),
                                               n=len(lp.get("artefatti") or {}), r=lp.get("righe"), rep=lp.get("rapporto")))
            if lp.get("troncato"):
                L.append(tr("- Importate solo le prime righe: il rapporto di {s} le contiene tutte.").format(s=lp["strumento"]))
            if lp.get("portachiavi"):                # (2.20) portachiavi di iOS
                import forense_mobile_portachiavi as fmk
                L.append("- " + fmk.testo_esito(lp["portachiavi"]) + ".")
            if lp.get("valori_segreti"):
                L.append(tr("- {n} valori segreti (password, chiavi, token) nascosti negli artefatti: si vedono solo nell'interfaccia, "
                            "uno per volta, e ogni lettura è nel registro; il rapporto di {s} nella cartella del caso li contiene "
                            "in chiaro.").format(n=lp["valori_segreti"], s=lp["strumento"]))
            cats = lp.get("categorie") or {}
            if cats:
                L += ["", tr("| Categoria di {s} | Artefatti | Righe |").format(s=lp["strumento"]), "|---|---|---|"]
                L += [f"| {cell(k)} | {len(a)} | {sum(a.values())} |"
                      for k, a in sorted(cats.items(), key=lambda x: (-sum(x[1].values()), x[0]))]
        else:
            L.append(tr("- {s}: non riuscito (vedi `{log}`).").format(s=lp.get("strumento"), log=lp.get("log")))
    try:                                         # (2.20) sysdiagnose acquisiti a parte
        import forense_mobile_sysdiagnose as fms
        sd = fms.report_md(case)
        if sd:
            L += [""] + sd.rstrip("\n").split("\n")
    except ImportError:
        pass
    L += ["", tr("## Limiti dell'analisi dello smartphone"), "",
          tr("- Si vede solo quello che c'è nell'estrazione: un'estrazione non completa (logica, backup) non contiene i "
             "database delle app."),
          tr("- Database cifrati (es. backup di WhatsApp .crypt14/.crypt15, Signal) non si leggono senza la chiave."),
          tr("- I messaggi cancellati ancora presenti nelle pagine libere dei database non sono recuperati da RepertIA "
             "in questa versione (iLEAPP/ALEAPP ne segnalano alcuni)."),
          tr("- Le date DOS degli zip non hanno fuso: sono convertite con il fuso del dispositivo e dichiarate."), ""]
    return L


# --------------------------------------------------------------------------- strumenti e metodo (report)

def strumenti_usati(case):
    """(2.20) Strumenti realmente usati in QUESTO caso smartphone, con versione (e impronta o SHA-256 dove serve):
    [(nome, dettaglio)]. I casi dei dischi non passano di qui."""
    import forense_agent as fa
    m = case.meta
    tv = m.get("tool_versions") or {}
    amb = (m.get("ambiente") or {}).get("strumenti") or {}
    est = m.get("estese") or {}
    out = [("RepertIA", tr("{v} – lettura dell'estrazione (zip, tar o cartella) voce per voce, senza estrarla; SHA-256, "
                           "elenco dei file e date registrate nell'estrazione").format(v=(m.get("ambiente") or {}).get("versione") or fa.APP_VERSION))]
    if amb.get("python"):
        out.append(("Python", amb["python"]))
    if m.get("decompressa"):
        out.append((tr("Decompressione del tar.gz"), tr("gzip della libreria standard di Python (copia derivata)")))
    c = m.get("chat") or {}
    if c.get("ts") or c.get("app"):
        out.append((tr("Lettori di chat di RepertIA"), tr("WhatsApp, iMessage/SMS, SMS/MMS e rubriche (forense_mobile_chat.py, "
                                                          "versione del programma)")))
    lp = m.get("leapp") or {}
    if lp.get("esito") == "ok":
        out.append((lp.get("strumento"), tr("{v}, impronta {i}").format(v=lp.get("versione") or "?", i=lp.get("impronta") or "?")))
        if (m.get("leapp_chat") or {}).get("chat") is not None or (m.get("leapp_chat") or {}).get("chiamate") is not None:
            out.append((tr("Chat e chiamate da {s}").format(s=lp.get("strumento")), tr("ricavate da RepertIA dalle righe di {s} "
                                                                                       "(forense_mobile_leapp_mappa.json)").format(s=lp.get("strumento"))))
    elif lp:
        out.append((lp.get("strumento") or "iLEAPP/ALEAPP", tr("non riuscito")))
    if m.get("indice"):
        for k in ("exiftool", "pdftotext"):
            if tv.get(k) or amb.get(k):
                out.append((k, tv.get(k) or amb.get(k)))
    if "archivi" in est and amb.get("7-Zip"):
        out.append(("7-Zip", amb["7-Zip"]))
    if "ocr" in est and amb.get("tesseract"):
        out.append(("Tesseract", amb["tesseract"]))
    if m.get("hash_file"):
        out.append((tr("Hash dei file"), tr("MD5, SHA-1 e SHA-256 (hashlib di Python)")))
    pc = m.get("portachiavi")
    if pc:
        out.append((tr("Portachiavi"), tr("{n}, SHA-256 {s} (passato a iLEAPP)").format(n=pc.get("nome"), s=pc.get("sha256"))))
    try:
        import forense_mobile_sysdiagnose as fms
        for v in fms.elenco(case):
            il = v.get("ileapp") or {}
            out.append((tr("Sysdiagnose"), tr("{n}, SHA-256 {s}").format(n=v.get("nome"), s=v.get("sha256"))
                        + (" – " + tr("letto con iLEAPP {v}, impronta {i}").format(v=il.get("versione") or "?", i=il.get("impronta") or "?")
                           if il.get("esito") == "ok" else " – " + tr("non letto"))))
    except ImportError:
        pass
    return out


def strumenti_dict(case):
    """strumenti_usati come dizionario (nomi ripetuti numerati: più sysdiagnose)."""
    out = {}
    for k, v in strumenti_usati(case):
        kk, i = k, 2
        while kk in out:
            kk, i = f"{k} {i}", i + 1
        out[kk] = v
    return out


def metodo_md(case, llm_m):
    """(2.20) Note metodologiche dei casi smartphone: estrazione del file system, non immagine disco."""
    m = case.meta
    nomi = [k for k, _v in strumenti_usati(case) if k not in ("RepertIA", "Python")]
    return (tr("L'analisi è stata condotta sull'estrazione del file system del telefono (non su un'immagine disco: niente "
               "partizioni, spazio non allocato né file cancellati del file system), aperta in sola lettura e letta voce per "
               "voce senza estrarla; i database sono letti da copie di lavoro con i loro file -wal/-shm.")
            + " " + (tr("Strumenti usati: {s}.").format(s=", ".join(nomi)) if nomi else "")
            + tr(" Con il supporto di un modello linguistico ")
            + (tr("eseguito su un server della rete interna, senza servizi esterni. ") if llm_m.get("remoto")
               else tr("eseguito localmente. "))
            + tr("Ogni reperto è stato verificato dall'analista sugli strumenti forensi. "
                 "La traccia completa di comandi e risposte è in `audit_log.jsonl`."))


# --------------------------------------------------------------------------- per l'agente

def prompt_extra(case):
    m = case.meta
    L = [tr("- Questo caso è l'ESTRAZIONE DI UNO SMARTPHONE ({os}), non un disco: non ci sono partizioni né file "
            "cancellati del file system; l'«offset» {off} indica l'estrazione e l'«inode» è il numero della voce "
            "nell'estrazione.").format(os=m.get("disk_type"), off=(m.get("partitions") or [{}])[0].get("offset"))]
    c = m.get("chat") or {}
    if c.get("app"):
        L.append(tr("- Chat lette ({app}): list_chats elenca le conversazioni, read_chat legge una conversazione "
                    "(anche per periodo), search_messages cerca nel testo dei messaggi, find_contact trova un contatto "
                    "nelle rubriche. Ogni messaggio cita database, tabella e riga di origine: citali.").format(
            app=", ".join(f"{APP_LBL.get(k, k)} {v['messaggi']}" for k, v in c["app"].items())))
    if m.get("leapp"):
        L.append(tr("- Artefatti di iLEAPP/ALEAPP importati: query_artifacts con categoria «leapp»."))
    L.append(tr("- DOVE CERCARE su iPhone: private/var/mobile/Library (SMS, AddressBook, CallHistoryDB, Safari), "
                "Containers/Shared/AppGroup (WhatsApp), Media/DCIM (foto). Su Android: data/data/<app>/databases, "
                "data/media/0 (memoria interna: DCIM, WhatsApp/Media, Download)."))
    return L


def agent_tools(case):
    import forense_agent as fa

    def _db():
        return fa.db_ro(case)

    def _fmt(r):
        ts, d, sender, sname, text, kind, n_att, mid, table, row, src = r[:11]
        extra = r[11] if len(r) > 11 else None
        who = tr("TELEFONO→") if d == "out" else f"{sname or sender or '?'}→"
        return f"[{(ts or '?').replace('T', ' ')} UTC] {who} {text or '[' + fmw.etichetta(kind, extra) + ']'}" + (
            f" (+{n_att} " + tr("allegati") + ")" if n_att else "") + f"  ⟨msg {mid}; {src} {table}#{row}⟩"

    def list_chats(app: str = "", contains: str = "", limit: int = 100) -> str:
        """Elenca le conversazioni delle chat del telefono (WhatsApp, iMessage/SMS, SMS/MMS) con partecipanti, numero
        di messaggi e periodo.

        Args:
            app: 'whatsapp', 'imessage' o 'sms'; vuoto per tutte
            contains: testo nel titolo o nei partecipanti (nome o numero)
            limit: numero massimo di conversazioni (max 500)
        """
        con = _db()
        w, a = [], []
        if app:
            w.append("app = ?")
            a.append(app.lower())
        if contains:
            w.append("(title LIKE ? ESCAPE '\\' OR participants LIKE ? ESCAPE '\\')")
            a += [fa.like(contains)] * 2
        rows = con.execute("SELECT id, app, title, participants, is_group, n_msg, first_ts, last_ts FROM chat_threads"
                           + (" WHERE " + " AND ".join(w) if w else "") + " ORDER BY last_ts DESC LIMIT ?",
                           a + [max(1, min(int(limit), 500))]).fetchall()
        con.close()
        return fa.clip("\n".join(f"#{i} {APP_LBL.get(ap, ap)} | {t} | {'gruppo' if g else 'singola'} | {n} msg | "
                                 f"{(f or '?')[:16]} → {(l or '?')[:16]} | {p}" for i, ap, t, p, g, n, f, l in rows)
                       or tr("Nessuna conversazione."))

    def read_chat(chat_id: int, start: str = "", end: str = "", offset: int = 0, limit: int = 200) -> str:
        """Legge i messaggi di una conversazione in ordine di tempo (UTC), con mittente, testo, allegati e
        riferimento al dato grezzo.

        Args:
            chat_id: numero della conversazione (da list_chats)
            start: data/ora iniziale ISO (es. 2024-03-01), facoltativa
            end: data/ora finale ISO, facoltativa
            offset: messaggi da saltare (per proseguire)
            limit: messaggi da mostrare (max 500)
        """
        con = _db()
        w, a = ["m.thread = ?"], [int(chat_id)]
        if start:
            w.append("m.ts >= ?")
            a.append(start)
        if end:
            w.append("m.ts <= ?")
            a.append(end if "T" in end else end + "T23:59:59")
        tot = con.execute("SELECT COUNT(*) FROM chat_messages m WHERE " + " AND ".join(w), a).fetchone()[0]
        rows = con.execute("SELECT m.ts, m.direction, m.sender, m.sender_name, m.text, m.kind, m.n_att, m.id, "
                           "m.src_table, m.src_row, t.src_path, m.extra FROM chat_messages m JOIN chat_threads t ON t.id=m.thread "
                           "WHERE " + " AND ".join(w) + " ORDER BY m.ts, m.id LIMIT ? OFFSET ?",
                           a + [max(1, min(int(limit), 500)), max(0, int(offset))]).fetchall()
        att = {}
        ids = [r[7] for r in rows]
        if ids:
            for mid, name, path, lat, lon in con.execute(
                    "SELECT msg, name, path, lat, lon FROM chat_attachments WHERE msg IN (SELECT value FROM json_each(?))",
                    (json.dumps(ids),)):
                att.setdefault(mid, []).append(f"{name or ''}" + (f" [{path}]" if path else tr(" [file non presente "
                                                                                                "nell'estrazione]"))
                                               + (f" GPS {lat},{lon}" if lat else ""))
        con.close()
        out = [tr("{tot} messaggi; mostrati {a}-{b}").format(tot=tot, a=int(offset) + 1, b=int(offset) + len(rows))]
        for r in rows:
            out.append(_fmt(r))
            for x in att.get(r[7], []):
                out.append("    📎 " + x)
        if int(offset) + len(rows) < tot:
            out.append(tr("[... altri messaggi: richiama con offset={o}]").format(o=int(offset) + len(rows)))
        return fa.clip("\n".join(out))

    def search_messages(text: str, app: str = "", contact: str = "", start: str = "", end: str = "",
                        limit: int = 100) -> str:
        """Cerca parole nel testo dei messaggi di tutte le chat (senza distinzione maiuscole/minuscole).

        Args:
            text: parola o frase da cercare
            app: 'whatsapp', 'imessage' o 'sms'; vuoto per tutte
            contact: nome o numero del mittente o della conversazione, facoltativo
            start: data iniziale ISO, facoltativa
            end: data finale ISO, facoltativa
            limit: risultati massimi (max 500)
        """
        con = _db()
        w, a = ["m.text LIKE ? ESCAPE '\\'"], [fa.like(text)]
        if app:
            w.append("m.app = ?")
            a.append(app.lower())
        if contact:
            w.append("(m.sender LIKE ? ESCAPE '\\' OR m.sender_name LIKE ? ESCAPE '\\' OR t.title LIKE ? ESCAPE '\\' "
                     "OR t.participants LIKE ? ESCAPE '\\')")
            a += [fa.like(contact)] * 4
        if start:
            w.append("m.ts >= ?")
            a.append(start)
        if end:
            w.append("m.ts <= ?")
            a.append(end if "T" in end else end + "T23:59:59")
        rows = con.execute("SELECT m.ts, m.direction, m.sender, m.sender_name, m.text, m.kind, m.n_att, m.id, m.src_table, "
                           "m.src_row, t.src_path, t.id, t.title, m.extra FROM chat_messages m JOIN chat_threads t ON t.id=m.thread "
                           "WHERE " + " AND ".join(w) + " ORDER BY m.ts LIMIT ?",
                           a + [max(1, min(int(limit), 500))]).fetchall()
        con.close()
        return fa.clip("\n".join(f"chat #{r[11]} «{r[12]}»: " + _fmt(r[:11] + (r[13],)) for r in rows) or tr("Nessun messaggio."))

    def find_contact(text: str) -> str:
        """Cerca un contatto nelle rubriche del telefono e di WhatsApp (nome, numero o indirizzo).

        Args:
            text: parte del nome o del numero
        """
        con = _db()
        rows = con.execute("SELECT name, value, source FROM chat_contacts WHERE name LIKE ? ESCAPE '\\' OR value LIKE ? "
                           "ESCAPE '\\' OR norm = ? LIMIT 200", (fa.like(text), fa.like(text), norm_number(text))).fetchall()
        con.close()
        return fa.clip("\n".join(f"{n} | {v} | {s}" for n, v, s in rows) or tr("Nessun contatto."))

    tools = []
    try:
        con = _db()
        has = con.execute("SELECT name FROM sqlite_master WHERE name='chat_threads'").fetchone()
        con.close()
    except sqlite3.Error:
        has = None
    if has:
        tools += [list_chats, read_chat, search_messages, find_contact]
    return tools
