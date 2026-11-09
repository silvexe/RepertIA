# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (3.0.2): database ESE di Windows letti con pyesedb (libesedb, incluso con plaso).

- Indice di Ricerca di Windows (Windows.edb, Windows Vista-10): una riga per ogni elemento indicizzato (file e cartelle,
  cronologia di Internet Explorer, posta di Outlook, Sticky Notes…), che resta anche dopo la cancellazione del file.
  In Windows 7 i testi sono compressi (primo byte = tipo: 7 bit, 8 bit o UTF-16 a blocchi) e alcune colonne binarie
  sono mascherate con uno XOR che dipende dalla lunghezza; le date sono FILETIME scritte al contrario (big endian).
  Windows 11 usa un database SQLite (Windows.db): non letto qui.
- Cache di Internet Explorer 10/11 ed Edge legacy (WebCacheV01.dat): contenitori «History» e «MSHist01…» (cronologia).
  Nei contenitori MSHist l'ora «ModifiedTime» è locale: si usa sempre AccessedTime, che è UTC.

Solo lettura, nessuna scrittura nel file; il database non viene «riparato» con i suoi log (le ultime modifiche ancora
nei file .log/.jrs possono mancare, e lo si dichiara)."""
import datetime as dt
import os
import re

MAX_RIGHE = 300000

# proprietà di Windows Search lette (nome senza il prefisso numerico di Windows 8/10)
WS_TESTI = ("System_ItemPathDisplay", "System_ItemName", "System_ItemNameDisplay", "System_ItemFolderPathDisplay",
            "System_Search_Store", "System_ItemTypeText", "System_ItemType", "System_Kind", "System_KindText",
            "Microsoft_IE_TargetUrl", "Microsoft_IE_Title", "System_Title",
            "System_Subject", "System_Message_FromAddress", "System_Message_FromName", "System_Message_ToAddress",
            "System_Message_ToName", "System_Message_CcAddress", "System_Message_CcName", "System_Message_SenderAddress",
            "System_Message_SenderName", "System_Message_AttachmentNames", "System_ItemFolderNameDisplay",
            "System_Message_Store", "System_ItemAuthors", "System_ComputerName",
            "System_ItemUrl", "System_FileOwner", "System_Message_MessageClass")
WS_DATE = ("System_DateModified", "System_DateCreated", "System_DateAccessed", "System_Search_GatherTime",
           "System_Message_DateSent", "System_Message_DateReceived", "System_ItemDate")
WS_NUMERI = ("System_Size", "Microsoft_IE_VisitCount", "System_Message_HasAttachments", "System_IsAttachment")
WS_MASCHERATI = ("System_Search_AutoSummary",)          # binari con lo XOR di Windows 7
WS_TUTTI = WS_TESTI + WS_DATE + WS_NUMERI + WS_MASCHERATI


def _nome(n):
    return re.sub(r"^[0-9A-Fa-f]+-", "", n or "")


def _sette_bit(b):
    out, acc, n = bytearray(), 0, 0
    for x in b:
        acc |= x << n
        n += 8
        while n >= 7:
            out.append(acc & 0x7F)
            acc >>= 7
            n -= 7
    return out.decode("ascii", "replace")


def _utf16_blocchi(b):
    """UTF-16 «a blocchi»: [quanti][byte alto][byte bassi…] ripetuto."""
    out, i = [], 0
    while i + 1 < len(b):
        n, hi = b[i], b[i + 1]
        out.extend(chr((hi << 8) | lo) for lo in b[i + 2:i + 2 + n])
        i += 2 + n
    return "".join(out)


def smaschera(b):
    """XOR di Windows 7 sulle colonne binarie di Windows Search (chiave dalla lunghezza del dato)."""
    m = 0x05000113 ^ len(b)
    return bytes(c ^ (((m >> (8 * (i & 3))) & 0xFF) ^ (i & 0xFF)) for i, c in enumerate(b))


def ws_testo(b):
    """Testo di Windows Search: compresso (Windows 7) o UTF-16 semplice. None se vuoto o non decifrabile
    (compressione LZXPRESS, non gestita)."""
    if not b:
        return None
    t = b[0]
    try:
        if t == 0:
            s = _utf16_blocchi(b[1:])
        elif t == 1:
            s = b[1:].decode("latin-1")
        elif 0x10 <= t <= 0x17:
            s = _sette_bit(b[1:])
        elif 0x18 <= t <= 0x1F:
            return None
        elif len(b) % 2 == 0 and b[1:2] == b"\x00":
            s = b.decode("utf-16-le", "replace")
        else:
            s = b.decode("utf-8", "replace")
    except (ValueError, IndexError):
        return None
    s = s.replace("\x00", "").strip()
    return s or None


def _filetime(n):
    try:
        if not n or n <= 0:
            return None
        d = dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=n // 10)
        return d.strftime("%Y-%m-%dT%H:%M:%S") if 1980 <= d.year <= 2100 else None
    except (OverflowError, ValueError):
        return None


def ws_data(b):
    """Data di Windows Search: FILETIME di 8 byte, big endian in Windows 7 (si prova anche little endian)."""
    if not b or len(b) != 8:
        return None
    return _filetime(int.from_bytes(b, "big")) or _filetime(int.from_bytes(b, "little"))


def _tabella(db, colonna):
    for i in range(db.number_of_tables):
        t = db.get_table(i)
        if t.name.startswith("MSys"):
            continue
        nomi = {_nome(t.get_column(j).name) for j in range(t.number_of_columns)}
        if colonna in nomi:
            return t
    return None


def windows_search(percorso, max_righe=MAX_RIGHE):
    """Righe dell'indice di Ricerca di Windows come dizionari {proprietà: valore} (solo le proprietà con un valore).
    Restituisce (righe, avvisi). Solleva ImportError se manca pyesedb."""
    import pyesedb
    db = pyesedb.file()
    db.open(os.path.abspath(str(percorso)))      # libyal su Windows non accetta «/»
    try:
        return ws_righe(db, max_righe)
    finally:
        db.close()


def ws_righe(db, max_righe=MAX_RIGHE):
    """Lettura delle righe da un database già aperto (un pyesedb.file o un oggetto con la stessa interfaccia: il
    collaudo usa tabelle costruite con valori codificati come in Windows 7)."""
    avvisi = []
    t = _tabella(db, "System_ItemPathDisplay")
    if t is None:
        return [], ["tabella delle proprietà non trovata (SystemIndex_0A / SystemIndex_PropertyStore)"]
    cols = {}
    for j in range(t.number_of_columns):
        n = _nome(t.get_column(j).name)
        if n in WS_TUTTI or n == "WorkID":
            cols[j] = (n, t.get_column(j).type)
    righe, illeggibili = [], 0
    for i in range(t.number_of_records):
        if len(righe) >= max_righe:
            avvisi.append(f"letti solo i primi {max_righe} elementi su {t.number_of_records}")
            break
        try:
            r = t.get_record(i)
        except (IOError, OSError):
            illeggibili += 1
            continue
        d = {}
        for j, (n, tipo) in cols.items():
            try:
                v = r.get_value_data(j)
            except (IOError, OSError):
                continue
            if not v:
                continue
            if n in WS_DATE:
                v = ws_data(v)
            elif n in WS_NUMERI or n == "WorkID":
                # colonna binaria (Windows 7): intero big endian come le date, «********» = nessun valore;
                # colonne intere vere (Windows 8/10 e i contatori): little endian
                v = None if v == b"*" * 8 else int.from_bytes(v, "big" if tipo == 9 else "little")
            elif n in WS_MASCHERATI:
                v = ws_testo(smaschera(v))
            else:
                v = ws_testo(v)
            if v not in (None, ""):
                d[n] = v
        if d.get("System_ItemPathDisplay") or d.get("System_ItemName") or d.get("Microsoft_IE_TargetUrl"):
            righe.append(d)
    if illeggibili:
        avvisi.append(f"{illeggibili} righe non leggibili")
    return righe, avvisi


def webcache(percorso, max_righe=MAX_RIGHE):
    """Cronologia di Internet Explorer 10/11 ed Edge legacy da WebCacheV01.dat: (visite, avvisi).
    Ogni visita: url, utente del contenitore, ultima (AccessedTime, UTC), prima (ModifiedTime dei contenitori
    «History», UTC), numero di visite, contenitore."""
    import pyesedb
    db = pyesedb.file()
    db.open(os.path.abspath(str(percorso)))      # libyal su Windows non accetta «/»
    try:
        return wc_visite(db, max_righe)
    finally:
        db.close()


def wc_visite(db, max_righe=MAX_RIGHE):
    """Lettura delle visite da una WebCache già aperta (pyesedb.file o oggetto con la stessa interfaccia)."""
    avvisi, visite, visti = [], [], set()
    ct = db.get_table_by_name("Containers")
    if ct is None:
        return [], ["tabella Containers assente: non è una WebCache"]
    cc = {ct.get_column(j).name: j for j in range(ct.number_of_columns)}
    contenitori = []
    for i in range(ct.number_of_records):
        r = ct.get_record(i)
        try:
            nome = (r.get_value_data_as_string(cc["Name"]) or "").strip("\x00")
            cid = r.get_value_data_as_integer(cc["ContainerId"])
            cart = (r.get_value_data_as_string(cc["Directory"]) or "") if "Directory" in cc else ""
        except (IOError, OSError, KeyError):
            continue
        if nome == "History" or nome.startswith("MSHist"):
            contenitori.append((cid, nome, cart))
    for cid, nome, cart in contenitori:
        t = db.get_table_by_name(f"Container_{cid}")
        if t is None:
            continue
        tc = {t.get_column(j).name: j for j in range(t.number_of_columns)}

        def intero(r, c):
            try:
                return r.get_value_data_as_integer(tc[c]) if c in tc else None
            except (IOError, OSError):
                return None
        for i in range(t.number_of_records):
            if len(visite) >= max_righe:
                avvisi.append(f"lette solo le prime {max_righe} visite")
                return visite, avvisi
            try:
                r = t.get_record(i)
                url = (r.get_value_data_as_string(tc["Url"]) or "").strip("\x00")
            except (IOError, OSError, KeyError, UnicodeDecodeError):
                continue
            m = re.match(r"^(?:Visited|:\d{16}):\s*([^@]*)@(.+)$", url)
            if not m or m.group(2).startswith(":Host:"):
                continue
            ultima = _filetime(intero(r, "AccessedTime"))
            prima = _filetime(intero(r, "ModifiedTime")) if nome == "History" else None
            chiave = (m.group(2), ultima)
            if chiave in visti:
                continue
            visti.add(chiave)
            visite.append({"url": m.group(2), "utente": m.group(1), "ultima": ultima, "prima": prima,
                           "visite": intero(r, "AccessCount"), "contenitore": nome,
                           "bassa_integrita": "\\low\\" in cart.lower()})
    return visite, avvisi
