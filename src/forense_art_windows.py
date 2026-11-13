#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - artefatti: funzioni comuni e Windows (registro, accessi, SAM, NTUSER, prefetch, Amcache, collegamenti, cestino).

(3.0.4) Codice spostato da forense_estesa.py senza modifiche, per avere file più corti. Si carica tramite
forense_estesa, che ne riesporta i nomi: gli altri moduli continuano a usare «fe.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fe.<nome>»).
"""
import datetime as dt
import html
import io
import json
import re
import struct
from collections import Counter
from pathlib import Path
from forense_lingua import N_
from forense_lingua import tr
import forense_agent as fa

import forense_estesa as fe
from forense_estesa import (
    HeadReader, LOCALE, copy_fs_file, filetime, iso, safe_name, unixtime)

# ------------------------------------------------------------------ artefatti

KNOWN_FOLDERS = {
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "C:\\Windows\\System32",
    "{6D809377-6AF0-444B-8957-A3773F02200E}": "C:\\Program Files",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "C:\\Program Files (x86)",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "C:\\Windows",
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": "C:\\Windows\\SysWOW64",
    "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": N_("Menu Start (comune)"),
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": N_("Menu Start (utente)"),
    "{9E3995AB-1F9C-4F13-B827-48B24B6C7174}": N_("Barra delle applicazioni"),
}
JUMP_APPS = {"1b4dd67f29cb1962": N_("Esplora file"), "9b9cdc69c1c24e2b": N_("Blocco note (64 bit)"),
             "a7bd71699cd38d1c": "Word", "adecfb853d77462a": "Word", "d00655d2aa12ff6d": "PowerPoint",
             "b8ab77100df80ab2": "Excel", "fb3b0dbfee58fac8": "Word", "5f7b5f1e01b83767": N_("Accesso rapido"),
             "f01b4d95cf55d32a": N_("Esplora file"), "918e0ecb43d17e23": N_("Blocco note"),
             "9839aec31243a928": "Microsoft Excel", "f5ac5390b9115fdb": "PowerPoint",
             "6824f4a902c78fbd": "Firefox", "5d696d521de238c3": "Chrome", "7e4dca80246863e3": N_("Pannello di controllo")}


_TS_DETT = re.compile(r"\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?")
_GIA_FUSO = re.compile(r"\s?(?:UTC\b|Z\b|[+-]\d\d:?\d\d\b|\((?:[^()]*\b)?(?:ora locale|local time)\b)")
_PRIMA_LOCALE = re.compile(r"(?:ora locale|local time)\W{0,3}$")


def marca_utc(testo):
    """(3.0.4) Aggiunge la sigla UTC agli orari scritti nei Dettagli di un artefatto, che RepertIA calcola in UTC: la
    colonna Data segue il fuso scelto e un orario senza sigla nel dettaglio si confondeva con quello. Non tocca gli
    orari che hanno già un fuso o uno scostamento, quelli dichiarati «ora locale» e quelli dentro nomi e percorsi."""
    testo = re.sub(r"(" + _TS_DETT.pattern + r") \(UTC\)", r"\1 UTC", str(testo or ""))
    out, last = [], 0
    for m in _TS_DETT.finditer(testo):
        prima, dopo = testo[max(0, m.start() - 16):m.start()], testo[m.end():m.end() + 60]
        if _GIA_FUSO.match(dopo) or _PRIMA_LOCALE.search(prima) or (prima and (prima[-1].isalnum() or prima[-1] in "/\\_-.")) \
                or (dopo and (dopo[0].isalnum() or dopo[0] in "_-")) or re.match(r"\.\w", dopo):
            continue
        out.append(testo[last:m.end()] + " UTC")
        last = m.end()
    out.append(testo[last:])
    return "".join(out)


class Art:
    def __init__(self, ctx):
        self.ctx, self.con = ctx, ctx.con
        self.n = Counter()

    def add(self, cat, ts, title, detail="", user="", src=None, data=None):
        part, inode, path = src if src else (None, None, None)
        inst = getattr(self.ctx, "win_inst", "")
        if inst:            # artefatto di un'installazione di Windows diversa da quella principale (Windows.old…)
            title = f"[{inst}] {title}"
            data = dict(data or {}, installazione=inst)
        self.con.execute("INSERT INTO artifacts(cat, ts, title, detail, user, src_path, part, inode, "
                         "data) VALUES (?,?,?,?,?,?,?,?,?)",
                         (cat, ts, str(title)[:500], marca_utc(detail)[:4000], user or "", path, part,
                          str(inode) if inode is not None else None,
                          json.dumps(data, ensure_ascii=False, default=str) if data else None))
        self.n[cat] += 1


def find_files(con, part, like, deleted_ok=False):
    return con.execute("SELECT part, inode, deleted, path FROM files WHERE part=? AND type LIKE '%r' "
                       "AND lower(path) LIKE ? ESCAPE '\\' " + ("" if deleted_ok else "AND deleted=0 ") +
                       "ORDER BY path", (part, like)).fetchall()


def fetch(ctx, part, inode, path, limit=1 << 30):
    f = ctx.tmp / f"a_{part}_{safe_name(str(inode), 40)}_{safe_name(Path(path).name, 60)}"
    if f.exists():
        return f
    try:
        n = copy_fs_file(ctx.case, part, inode, f, limit)
    except Exception:
        return None
    return f if n else None


def user_of(path):
    m = re.match(r"(?i)(?:[^/]+/){0,3}?(?:users|documents and settings|home)/([^/]+)/", path)
    if m:
        return m.group(1)
    if re.match(r"(?i)root/", path):
        return "root"
    return ""


def rk(root, path):
    try:
        return root.get_sub_key_by_path(path) if root is not None else None
    except Exception:
        return None


def rv(key, name, default=None):
    """Valore del registro con il tipo giusto (stringa, intero, lista, byte)."""
    if key is None:
        return default
    try:
        v = key.get_value_by_name(name)
    except Exception:
        return default
    if v is None:
        return default
    try:
        t = v.type
        if t in (1, 2):
            return v.get_data_as_string()
        if t in (4, 5, 11):
            return v.get_data_as_integer()
        if t == 7:
            return v.get_data_as_multi_string()
        return v.data
    except Exception:
        try:
            return v.data
        except Exception:
            return default


def subkeys(k):
    try:
        return list(k.sub_keys) if k is not None else []
    except Exception:
        return []


def lw(k):
    try:
        return iso(k.last_written_time)
    except Exception:
        return None


def sz(v):
    if isinstance(v, bytes):
        try:
            return v.decode("utf-16-le").split("\x00")[0]
        except UnicodeDecodeError:
            return ""
    return v if isinstance(v, str) else ("" if v is None else str(v))


def local_to_utc(case, naive):
    """Data in ora locale del dispositivo ('AAAA-MM-GGTHH:MM:SS', senza fuso) in UTC, con il fuso del dispositivo
    registrato nel caso; senza fuso resta com'è con il suffisso LOCALE, così l'interfaccia non la spaccia per UTC."""
    if not naive:
        return naive
    tz = (case.meta.get("fuso_dispositivo") or {}).get("tz")
    if tz:
        try:
            from zoneinfo import ZoneInfo
            d = dt.datetime.strptime(naive, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=ZoneInfo(tz))
            return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        except Exception:
            pass
    return naive + LOCALE


HIVE_MEMORIA = None      # (3.0.4) dump della RAM: funzione percorso -> radice dell'hive letta dalla memoria (forense_ram.py)


class HiveMem(str):
    """Percorso di un hive la cui radice va letta dalla memoria (`radice`) invece che dal file."""
    radice = None


class _HiveChiuso:
    def close(self):
        pass


def open_hive(path):
    if isinstance(path, HiveMem):
        return _HiveChiuso(), path.radice
    import pyregf
    f = pyregf.file()
    f.open(str(path))
    return f, f.get_root_key()


# ------------------------------------------------------------------ registro: file di log delle transazioni
#
# Windows non scrive subito le modifiche nel file principale dell'alveare (SAM, SYSTEM, SOFTWARE, NTUSER.DAT…):
# le mette prima nei file .LOG1/.LOG2 (o .LOG) accanto e li "riversa" nell'alveare solo ogni tanto. In una copia
# forense l'alveare è quindi spesso indietro rispetto a ciò che il sistema vedeva (contatori e date di accesso del
# SAM, programmi e chiavi recenti). libregf non legge i log: qui si applicano a una copia di lavoro dell'alveare.
# Formato: Maxim Suhanov, «Windows registry file format specification» (log nuovo HvLE, Windows 8.1+, e vecchio DIRT).

_M32_SEED = 0x82EF4D887A4E55C5


def _marvin32(buf):
    """Marvin32 (hash 1 e 2 dei record HvLE), con il seme usato dal registro."""
    lo, hi = _M32_SEED & 0xFFFFFFFF, (_M32_SEED >> 32) & 0xFFFFFFFF
    m = 0xFFFFFFFF

    def rotl(v, n):
        return ((v << n) | (v >> (32 - n))) & m

    def mix(v):
        nonlocal lo, hi
        lo = (lo + v) & m
        hi ^= lo
        lo = (rotl(lo, 20) + hi) & m
        hi = (rotl(hi, 9) ^ lo) & m
        lo = (rotl(lo, 27) + hi) & m
        hi = rotl(hi, 19)

    n = len(buf)
    for i in range(0, n - n % 4, 4):
        mix(struct.unpack_from("<I", buf, i)[0])
    r = n % 4
    last = 0x80 << (8 * r)                      # byte 0x80 dopo gli ultimi 0-3 byte (little endian)
    for j, byte in enumerate(buf[n - r:] if r else b""):
        last |= byte << (8 * j)
    mix(last & m)
    mix(0)
    return (hi << 32) | lo


def hive_log_entries(data):
    """Record validi di un log nuovo (HvLE) già letto in memoria: [(sequenza, dimensione bin, [(offset, dati)])].
    Si ferma al primo record non valido (hash 1 e 2 non corrispondono, troncato): quelli dopo non sono affidabili."""
    out, off = [], 512
    while off + 40 <= len(data) and data[off:off + 4] == b"HvLE":
        size, _flags, seq, bins, npages = struct.unpack_from("<5I", data, off + 4)
        end = off + size
        if size < 40 + 8 * npages or end > len(data) or bins % 4096:
            break
        h1, h2 = struct.unpack_from("<QQ", data, off + 24)
        if _marvin32(data[off + 40:end]) != h1 or _marvin32(data[off:off + 32]) != h2:
            break
        refs = [struct.unpack_from("<II", data, off + 40 + 8 * i) for i in range(npages)]
        pos = off + 40 + 8 * npages
        if pos + sum(n for _, n in refs) > end:
            break
        pages = []
        for po, pn in refs:
            pages.append((po, data[pos:pos + pn]))
            pos += pn
        out.append((seq, bins, pages))
        off = end
    return out


def _regf_checksum(head):
    x = 0
    for i in range(0, 508, 4):
        x ^= struct.unpack_from("<I", head, i)[0]
    if x == 0xFFFFFFFF:
        x = 0xFFFFFFFE
    elif x == 0:
        x = 1
    return x


def apply_hive_logs(hive_path, log_paths, out_path):
    """Applica i log delle transazioni a una COPIA dell'alveare e la scrive in `out_path`.
    Restituisce un dizionario: {"applicato": bool, "formato": "HvLE"|"DIRT"|None, "record": n, "pagine": n,
    "sequenza_alveare": (primaria, secondaria), "ultima_sequenza": n, "nota": testo}.
    L'alveare originale non si tocca. Se i log non servono o non sono applicabili, "applicato" è False."""
    data = bytearray(Path(hive_path).read_bytes())
    info = {"applicato": False, "formato": None, "record": 0, "pagine": 0, "log": [Path(x).name for x in log_paths]}
    if len(data) < 4096 or data[:4] != b"regf":
        info["nota"] = tr("alveare non valido")
        return info
    prim, sec = struct.unpack_from("<II", data, 4)
    info["sequenza_alveare"] = (prim, sec)
    logs = []
    for lp in log_paths:
        try:
            b = Path(lp).read_bytes()
        except OSError:
            continue
        if len(b) > 520 and b[:4] == b"regf":
            logs.append(b)
    new = {}
    for b in logs:
        if b[512:516] == b"HvLE":
            for seq, bins, pages in hive_log_entries(b):
                new.setdefault(seq, (bins, pages))
    if new:
        info["formato"] = "HvLE"
        todo = sorted(s for s in new if s >= sec)
        if not todo:
            info["nota"] = tr("i log contengono solo record già riportati nell'alveare")
            return info
        if todo[0] != sec:
            info["nota"] = (tr("i log non partono dal punto giusto (alveare alla sequenza {sec}, primo record {v1}): non "
                               "applicati").format(sec=sec, v1=todo[0]))
            return info
        expected, last_bins, pagine, nrec = sec, None, 0, 0
        for seq in todo:
            if seq != expected:
                break
            bins, pages = new[seq]
            for po, pd in pages:
                end = 4096 + po + len(pd)
                if end > len(data):
                    if bins % 4096 or end > 4096 + bins or bins > 0x7FFFFFFF or bins > len(data) + (64 << 20):
                        info["nota"] = tr("pagina fuori dall'alveare: log non coerente, non applicati")
                        return {**info, "applicato": False}
                    data.extend(b"\0" * (4096 + bins - len(data)))
                data[4096 + po:end] = pd
                pagine += 1
            expected, last_bins, nrec = seq + 1, bins, nrec + 1
        struct.pack_into("<II", data, 4, expected, expected)
        struct.pack_into("<I", data, 40, last_bins)
        info.update(applicato=True, record=nrec, pagine=pagine, ultima_sequenza=expected - 1)
    else:
        for b in logs:                                  # log vecchio (Windows XP-8): bitmap DIRT + settori da 512 byte
            if b[512:516] != b"DIRT" or prim == sec:
                continue
            lp, ls = struct.unpack_from("<II", b, 4)
            if lp != ls:
                continue
            hbins = struct.unpack_from("<I", data, 40)[0]
            vlen = hbins // 4096
            area = ((4 + vlen + 511) // 512) * 512
            pos, n = 512 + area, 0
            vec = b[516:516 + vlen]
            for bit in range(vlen * 8):
                if vec[bit // 8] >> (bit % 8) & 1:
                    if pos + 512 > len(b) or 4096 + bit * 512 + 512 > len(data):
                        break
                    data[4096 + bit * 512:4096 + bit * 512 + 512] = b[pos:pos + 512]
                    pos += 512
                    n += 1
            if n:
                struct.pack_into("<II", data, 4, max(prim, sec), max(prim, sec))
                info.update(applicato=True, formato="DIRT", record=1, pagine=n, ultima_sequenza=max(prim, sec))
                break
        if not info["applicato"]:
            info["nota"] = tr("nessun log applicabile") if logs else tr("nessun file di log")
    if info["applicato"]:
        struct.pack_into("<I", data, 508, _regf_checksum(data))
        Path(out_path).write_bytes(bytes(data))
    return info


def fetch_hive(A, ctx, part, inode, path):
    """Come _fetch_hive_file; in un caso da un dump della RAM, se la radice dell'hive si legge dalla memoria restituisce
    un HiveMem: open_hive ne userà le chiavi lette da MemProcFS, che tollera le pagine mancanti."""
    f = _fetch_hive_file(A, ctx, part, inode, path)
    radice = HIVE_MEMORIA(path) if HIVE_MEMORIA else None
    if radice is None:
        return f
    h = HiveMem(str(f) if f else "memoria:" + str(path))
    h.radice = radice
    return h


def _fetch_hive_file(A, ctx, part, inode, path):
    """Copia un alveare del registro e, se accanto ci sono i suoi log delle transazioni (.LOG1/.LOG2/.LOG), li
    applica alla copia di lavoro: così si legge lo stato aggiornato (SAM, NTUSER.DAT…) e non quello dell'ultimo
    riversamento sul file principale. L'originale nella copia forense non cambia; l'operazione viene dichiarata
    tra gli artefatti di sistema. Se i log non servono, non sono applicabili o l'alveare risultante non si apre,
    resta la copia originale."""
    f = fe.fetch(ctx, part, inode, path)
    if not f:
        return f
    deleted = bool(ctx.con.execute("SELECT 1 FROM files WHERE part=? AND inode=? AND deleted>=1", (part, str(inode))).fetchone())
    if deleted:
        with open(f, "rb") as fh:
            head = fh.read(4096 + 4)
        ok = head[:4] == b"regf" and head[4096:4100] == b"hbin"
        A.add("sistema", None, tr("Registro: {name} cancellato ").format(name=Path(path).name) + (tr("RECUPERATO") if ok else tr("non recuperabile")),
              tr("{path}: il file risulta cancellato; ").format(path=path) + (tr("il contenuto è ancora un alveare integro (firma regf e primo hbin): "
                                                         "i dati mostrati vengono da questo file cancellato") if ok else
                                                         tr("i suoi cluster contengono altri dati (sovrascritto): non si legge")),
              "", (part, inode, path), {"cancellato": True, "recuperato": ok})
        if not ok:
            fe.togli(f)
            return None
    done = ctx.__dict__.setdefault("hive_logs", {})
    if str(f) in done:
        return done[str(f)]
    done[str(f)] = f
    logs, lognames = [], []
    for suf in (".log1", ".log2", ".log"):
        ino = fa.lookup(ctx.con, part, path.lower() + suf)
        if ino:
            g = fe.fetch(ctx, part, ino, path + suf.upper())
            if g:
                logs.append(g)
                lognames.append(Path(path).name + suf.upper())
    if not logs:
        return f
    out = f.with_name(f.name + ".recuperato")
    try:
        info = apply_hive_logs(f, logs, out)
    except Exception as e:
        info = {"applicato": False, "nota": f"{type(e).__name__}: {e}"}
    info["log"] = lognames
    name = Path(path).name
    if info.get("applicato"):
        try:
            hv, root = open_hive(out)
            ok = root is not None and root.number_of_sub_keys is not None
            hv.close()
        except Exception:
            ok = False
        if not ok:
            info.update(applicato=False, nota=tr("l'alveare aggiornato con i log non si apre: si usa quello originale"))
    if info.get("applicato"):
        done[str(f)] = out
        A.add("sistema", None, tr("Registro: log applicati a {name}").format(name=name),
              tr("{record} record di log ({pagine} pagine) di {v1} sono stati applicati a una copia di "
                 "lavoro di {name} (formato {formato}, sequenza dell'alveare {v2}/{v3} → {v4}). I valori "
                 "mostrati sono quelli aggiornati; il file nella copia forense non è stato modificato.").format(record=info['record'], pagine=info['pagine'], v1=', '.join(info['log']), name=name, formato=info['formato'], v2=info['sequenza_alveare'][0], v3=info['sequenza_alveare'][1], v4=info['ultima_sequenza'] + 1),
              "", (part, inode, path), info)
        return out
    if info.get("nota") and info.get("formato"):
        A.add("sistema", None, tr("Registro: log di {name} non applicati").format(name=name), info["nota"], "", (part, inode, path), info)
    return f


def systemtime(b):
    try:
        y, mo, _, d, h, mi, s, ms = struct.unpack("<8H", b[:16])
        return dt.datetime(y, mo, d, h, mi, s).strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None


def devprop_time(key):
    """Data di un'altra proprietà del dispositivo (USBSTOR Properties\\...\\0064 ecc.)."""
    if key is None:
        return None
    for v in (rv(key, ""), rv(key, "Data")):
        if isinstance(v, bytes) and len(v) >= 8:
            return filetime(struct.unpack("<Q", v[:8])[0])
    for s in subkeys(key):
        t = devprop_time(s)
        if t:
            return t
    return None


def win_system(A, ctx, part, users):
    rows = fe.hive_rows(ctx, part, "windows/system32/config/system")
    if not rows:
        return None
    part, inode, _, path = rows[0]
    f = fetch_hive(A, ctx, part, inode, path)
    if not f:
        return None
    hv, root = open_hive(f)
    src = (part, inode, path)
    cur = rv(rk(root, "Select"), "Current") or 1
    cs = f"ControlSet{int(cur):03d}"
    info = {}
    name = rv(rk(root, f"{cs}\\Control\\ComputerName\\ComputerName"), "ComputerName")
    if name:
        A.add("sistema", None, tr("Nome del computer: {name}").format(name=name), "", "", src, {"nome": name})
        info["nome"] = name
    tz = rk(root, f"{cs}\\Control\\TimeZoneInformation")
    tzn = rv(tz, "TimeZoneKeyName") or rv(tz, "StandardName")
    if tzn:
        A.add("sistema", None, tr("Fuso orario: {v1}").format(v1=sz(tzn)), tr("scostamento {v1} minuti").format(v1=rv(tz, 'Bias')), "", src)
    # (3.0.2) servizio di Ricerca di Windows (WSearch): indicizzazione attiva se l'avvio è automatico (NIST, domanda 42)
    ws = rv(rk(root, f"{cs}\\Services\\WSearch"), "Start")
    if isinstance(ws, int):
        A.add("sistema", None, tr("Servizio Ricerca di Windows (WSearch): {v1}").format(
            v1={2: tr("avvio automatico"), 3: tr("avvio manuale"), 4: tr("disattivato")}.get(ws, tr("avvio {v1}").format(v1=ws))),
            tr("indicizzazione dei file attiva") if ws == 2 else "", "", src, {"servizio": "WSearch", "start": ws})
    sd = rv(rk(root, f"{cs}\\Control\\Windows"), "ShutdownTime")
    if isinstance(sd, bytes) and len(sd) >= 8:
        A.add("sistema", filetime(struct.unpack("<Q", sd[:8])[0]), tr("Ultimo spegnimento registrato"), "", "", src)
    # dispositivi USB di memoria
    letters = {}
    md = rk(root, "MountedDevices")
    try:
        for v in (md.values if md is not None else []):
            d = v.data or b""
            try:
                s = d.decode("utf-16-le", "ignore")
            except Exception:
                s = ""
            if v.name.startswith("\\DosDevices\\") and "USBSTOR" in s.upper():
                m = re.search(r"#([^#]+)#\{", s)
                if m:
                    letters[m.group(1).lower()] = v.name[-2:]
    except Exception:
        pass
    for dev in subkeys(rk(root, f"{cs}\\Enum\\USBSTOR")):
        m = re.search(r"Ven_([^&]*)&Prod_([^&]*)(?:&Rev_(.*))?", dev.name)
        vend, prod, rev = (m.group(1), m.group(2), m.group(3)) if m else ("", dev.name, "")
        for ser in subkeys(dev):
            fn = sz(rv(ser, "FriendlyName")) or f"{vend} {prod}".strip()
            props = rk(ser, "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}")
            first = devprop_time(rk(props, "0064")) if props is not None else None
            last_in = devprop_time(rk(props, "0066")) if props is not None else None
            last_out = devprop_time(rk(props, "0067")) if props is not None else None
            serial = ser.name.split("&")[0] if ser.name.endswith("&0") else ser.name
            letter = letters.get(ser.name.lower()) or letters.get(serial.lower(), "")
            det = "; ".join(x for x in (
                tr("numero di serie {serial}").format(serial=serial), f"produttore {vend}" if vend else "", f"modello {prod}",
                f"lettera {letter}" if letter else "", tr("primo collegamento {v1}").format(v1=first.replace('T', ' ')) if first else "",
                tr("ultimo collegamento {v1}").format(v1=last_in.replace('T', ' ')) if last_in else "",
                tr("ultima rimozione {v1}").format(v1=last_out.replace('T', ' ')) if last_out else "") if x)
            A.add("usb", last_in or first or lw(ser), fn, det, "", src,
                  {"seriale": serial, "produttore": vend, "modello": prod, "revisione": rev,
                   "primo": first, "ultimo": last_in, "rimozione": last_out, "lettera": letter,
                   "chiave_scritta": lw(ser)})
    for dev in subkeys(rk(root, f"{cs}\\Enum\\USB")):
        if not dev.name.upper().startswith("VID_"):
            continue
        for ser in subkeys(dev):
            desc = sz(rv(ser, "FriendlyName")) or sz(rv(ser, "DeviceDesc"))
            desc = desc.split(";")[-1] if desc else ""
            svc = sz(rv(ser, "Service"))
            if svc.upper() in ("USBSTOR", "USBHUB", "USBHUB3", "HIDUSB") and not re.search(r"(?i)mtp|phone|apple|android|iphone", desc):
                continue
            mfg = sz(rv(ser, "Mfg")).split(";")[-1]
            A.add("usb", lw(ser), desc or dev.name, tr("{name} · seriale {name2}").format(name=dev.name, name2=ser.name) +
                  (f" · {mfg}" if mfg else "") + (tr(" · servizio {svc}").format(svc=svc) if svc else ""), "", src,
                  {"id": dev.name, "seriale": ser.name, "servizio": svc})
    for itf in subkeys(rk(root, f"{cs}\\Services\\Tcpip\\Parameters\\Interfaces")):
        ip = sz(rv(itf, "DhcpIPAddress")) or ", ".join(x for x in (rv(itf, "IPAddress") or []) if x)
        if not ip or ip == "0.0.0.0":
            continue
        lease = rv(itf, "LeaseObtainedTime")
        A.add("reti", unixtime(lease) if isinstance(lease, int) else lw(itf), tr("Interfaccia di rete: {ip}").format(ip=ip),
              "; ".join(x for x in (f"DHCP {sz(rv(itf, 'DhcpServer'))}" if rv(itf, "DhcpServer") else "",
                                     f"gateway {', '.join(rv(itf, 'DhcpDefaultGateway') or [])}" if rv(itf, "DhcpDefaultGateway") else "",
                                     f"dominio {sz(rv(itf, 'DhcpDomain'))}" if rv(itf, "DhcpDomain") else "",
                                     itf.name) if x), "", src)
    try:
        fe.win_shim_bam(A, root, cs, src)
    except Exception as e:
        print(tr("  ShimCache/BAM: {vname}: {e}").format(vname=type(e).__name__, e=e), flush=True)
    hv.close()
    return info


def win_software(A, ctx, part, users):
    rows = fe.hive_rows(ctx, part, "windows/system32/config/software")
    if not rows:
        return
    part, inode, _, path = rows[0]
    f = fetch_hive(A, ctx, part, inode, path)
    if not f:
        return
    hv, root = open_hive(f)
    src = (part, inode, path)
    cv = rk(root, "Microsoft\\Windows NT\\CurrentVersion")
    if cv is not None:
        prod = sz(rv(cv, "ProductName"))
        ver = sz(rv(cv, "DisplayVersion")) or sz(rv(cv, "ReleaseId"))
        build = sz(rv(cv, "CurrentBuild")) or sz(rv(cv, "CurrentBuildNumber"))
        if prod:
            try:
                if build and int(build) >= 22000 and "Windows 10" in prod:
                    prod = prod.replace("Windows 10", "Windows 11")
            except ValueError:
                pass
            A.add("sistema", unixtime(rv(cv, "InstallDate")) if isinstance(rv(cv, "InstallDate"), int) else None,
                  tr("Sistema operativo: {prod} {ver}").format(prod=prod, ver=ver).strip(),
                  "; ".join(x for x in (f"build {build}" if build else "", f"edizione {sz(rv(cv, 'EditionID'))}" if rv(cv, "EditionID") else "",
                                         tr("proprietario registrato {v1}").format(v1=sz(rv(cv, 'RegisteredOwner'))) if rv(cv, "RegisteredOwner") else "",
                                         f"organizzazione {sz(rv(cv, 'RegisteredOrganization'))}" if rv(cv, "RegisteredOrganization") else "",
                                         tr("data: installazione")) if x), "", src)
    profili = ctx.__dict__.setdefault("profili", {})
    for sidk in subkeys(rk(root, "Microsoft\\Windows NT\\CurrentVersion\\ProfileList")):
        p = sz(rv(sidk, "ProfileImagePath"))
        if p:
            users[sidk.name] = p.replace("/", "\\").split("\\")[-1]

        def ft(hi, lo):
            hi, lo = rv(sidk, hi), rv(sidk, lo)
            return filetime((int(hi) << 32) | int(lo)) if isinstance(hi, int) and isinstance(lo, int) else None
        profili[sidk.name] = {"percorso": p, "caricato": ft("LocalProfileLoadTimeHigh", "LocalProfileLoadTimeLow"),
                              "scaricato": ft("LocalProfileUnloadTimeHigh", "LocalProfileUnloadTimeLow"),
                              "utente": users.get(sidk.name, ""), "origine": (src[0], src[1], src[2])}
    seen = set()
    for base in ("Microsoft\\Windows\\CurrentVersion\\Uninstall",
                 "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"):
        for k in subkeys(rk(root, base)):
            name = sz(rv(k, "DisplayName"))
            if not name or rv(k, "SystemComponent") == 1 or name.lower() in seen:
                continue
            seen.add(name.lower())
            d = sz(rv(k, "InstallDate"))
            data_inst = f"{d[:4]}-{d[4:6]}-{d[6:8]}" if re.fullmatch(r"\d{8}", d or "") else None
            # (3.0.2) InstallDate ha solo la data (locale); l'ora viene dall'ultima scrittura della chiave (UTC), che
            # di solito è l'installazione: si usa quando cade entro un giorno da InstallDate, ed è sempre indicata
            scritta = lw(k)
            vicina = bool(data_inst and scritta) and abs((dt.date.fromisoformat(scritta[:10]) -
                                                          dt.date.fromisoformat(data_inst)).days) <= 1
            ts = scritta if vicina or not data_inst else f"{data_inst}T00:00:00"
            A.add("programmi", ts, name, "; ".join(x for x in (
                f"versione {sz(rv(k, 'DisplayVersion'))}" if rv(k, "DisplayVersion") else "",
                sz(rv(k, "Publisher")), f"in {sz(rv(k, 'InstallLocation'))}" if rv(k, "InstallLocation") else "",
                tr("data di installazione {v1} (InstallDate, ora locale)").format(v1=data_inst) if data_inst else "",
                tr("chiave scritta {v1} (UTC)").format(v1=scritta.replace('T', ' ')) if scritta else "") if x),
                  "", src, {"versione": sz(rv(k, "DisplayVersion")), "editore": sz(rv(k, "Publisher")),
                            "installato": data_inst, "chiave_scritta": scritta})
    for base, lbl in (("Microsoft\\Windows\\CurrentVersion\\Run", "Run"),
                      ("Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce"),
                      ("WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "Run (32 bit)")):
        k = rk(root, base)
        try:
            for v in (k.values if k is not None else []):
                A.add("programmi", lw(k), tr("Avvio automatico: {name}").format(name=v.name), tr("{v1} ({lbl}, tutti gli utenti)").format(v1=sz(rv(k, v.name)), lbl=lbl), "", src)
        except Exception:
            pass
    gw = {}
    for grp in ("Unmanaged", "Managed"):
        for s in subkeys(rk(root, f"Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\{grp}")):
            g = sz(rv(s, "ProfileGuid"))
            mac = rv(s, "DefaultGatewayMac")
            if g and isinstance(mac, bytes) and len(mac) >= 6:
                gw[g.lower()] = ":".join(f"{b:02X}" for b in mac[:6])
    for p in subkeys(rk(root, "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles")):
        name = sz(rv(p, "ProfileName"))
        typ = {0x47: "Wi-Fi", 0x06: "cablata", 0x17: tr("rete mobile"), 0xF3: tr("rete mobile")}.get(rv(p, "NameType"), "rete")
        first = systemtime(rv(p, "DateCreated") or b"")
        last = systemtime(rv(p, "DateLastConnected") or b"")
        ts_net = local_to_utc(ctx.case, last or first)
        mac = gw.get(p.name.lower(), "")
        A.add("reti", ts_net, tr("Rete {typ}: {name}").format(typ=typ, name=name), "; ".join(x for x in (
            tr("primo collegamento {v1} (ora locale)").format(v1=first.replace('T', ' ')) if first else "",
            tr("ultimo collegamento {v1} (ora locale)").format(v1=last.replace('T', ' ')) if last else "",
            tr("MAC del gateway {mac}").format(mac=mac) if mac else "", sz(rv(p, "Description")) if rv(p, "Description") != name else "") if x),
              "", src, {"tipo": typ, "primo": first, "ultimo": last, "gateway_mac": mac, "ora": "locale"})
    for d in subkeys(rk(root, "Microsoft\\Windows Portable Devices\\Devices")):
        fn = sz(rv(d, "FriendlyName"))
        if fn:
            m = re.search(r"(?i)USBSTOR#[^#]+#([^#]+)#", d.name)
            A.add("usb", lw(d), tr("Volume esterno «{fn}»").format(fn=fn), f"seriale {m.group(1)}" if m else d.name, "", src)
    hv.close()


EVTX_DATA_RE = re.compile(r'<Data Name="([^"]+)"[^>]*>([^<]*)</Data>')
EVTX_PROVIDER_RE = re.compile(r'<Provider Name="([^"]+)"')
LOGON_TIPI = {2: N_("interattivo"), 7: N_("sblocco"), 10: N_("remoto (Desktop remoto)"), 11: N_("interattivo con credenziali in cache")}


def evtx_records(path, ids, raw=False, stats=None):
    """Eventi di un file .evtx con l'identificativo in `ids`: [(id, FILETIME, provider, {campo: valore}, recuperato)].
    `recuperato` è True per i record ricavati dallo spazio libero del file (non più tra quelli attivi del registro);
    quelli identici a un record attivo (stesso numero di record, evento e data) si scartano. In `stats` (dict) i
    conteggi: attivi, recuperati, recuperati_doppi, illeggibili, illeggibili_recuperati (record di qualsiasi evento:
    un record illeggibile può essere uno di quelli cercati). Richiede pyevtx (libevtx, incluso con plaso)."""
    import pyevtx
    with open(path, "rb") as fh:
        if fh.read(8) != b"ElfFile\0":
            raise ValueError(tr("non è un registro eventi (file cancellato e sovrascritto?)"))
    st = stats if stats is not None else {}
    for k in ("attivi", "recuperati", "recuperati_doppi", "illeggibili", "illeggibili_recuperati"):
        st.setdefault(k, 0)
    out, attivi = [], set()
    f = pyevtx.file()
    f.open(str(path))
    try:
        groups = ((False, f.number_of_records, f.get_record),
                  (True, getattr(f, "number_of_recovered_records", 0), getattr(f, "get_recovered_record", None)))
        for rec, n, get in groups:
            if get is None:
                continue
            for i in range(n or 0):
                try:
                    r = get(i)
                    eid = int(r.event_identifier) & 0xFFFF
                    t = r.get_written_time_as_integer()
                    key = (getattr(r, "identifier", None), eid, t)
                    if rec and key in attivi:
                        st["recuperati_doppi"] += 1
                        continue
                    if eid not in ids:
                        if not rec:
                            attivi.add(key)
                        st["recuperati" if rec else "attivi"] += 1
                        continue
                    xml = r.xml_string or ""
                    fields = xml if raw else {k: html.unescape(v) for k, v in EVTX_DATA_RE.findall(xml)}
                    m = EVTX_PROVIDER_RE.search(xml)
                    prov = m.group(1) if m else (getattr(r, "source_name", "") or "")
                except Exception:
                    st["illeggibili_recuperati" if rec else "illeggibili"] += 1
                    continue
                if not rec:
                    attivi.add(key)
                st["recuperati" if rec else "attivi"] += 1
                out.append((eid, t, prov, fields, rec))
    finally:
        f.close()
    return out


def evtx_stato(st):
    """Frase sui record di un registro eventi (attivi, recuperati, illeggibili) per la dichiarazione negli artefatti."""
    s = tr("record attivi {v1}").format(v1=st.get('attivi', 0))
    if st.get("recuperati"):
        s += (tr(", record recuperati dallo spazio libero del file {recuperati} (eventi non più nel "
                 "registro, indicati come «recuperato»)").format(recuperati=st['recuperati']))
    if st.get("recuperati_doppi"):
        s += tr(", {recuperati_doppi} recuperati identici a un record attivo e non contati due volte").format(recuperati_doppi=st['recuperati_doppi'])
    ill, ill_r = st.get("illeggibili", 0), st.get("illeggibili_recuperati", 0)
    if ill or ill_r:
        s += (tr("; RECORD ILLEGGIBILI {v1} (attivi {ill}, recuperati {ill_r}): gli eventi che contenevano "
                 "non sono contati").format(v1=ill + ill_r, ill=ill, ill_r=ill_r))
    return s


def win_logons(A, ctx, part, users):
    """Accessi degli utenti dai registri eventi di Windows. Il contatore del SAM non conta gli accessi con account
    Microsoft, PIN o Windows Hello (resta 0): qui si contano gli eventi 4624 di Security.evtx (accesso riuscito:
    tipi 2 interattivo, 10 remoto, 11 con credenziali in cache; 7 = sblocco), 4625 (accesso fallito) e gli eventi
    Winlogon 7001/7002 di System.evtx (inizio/fine della sessione, di solito conservati più a lungo).
    Il risultato va in ctx.accessi ed è usato da win_sam; ogni file letto è dichiarato tra gli artefatti di sistema."""
    acc = ctx.__dict__.setdefault("accessi", {"per_sid": {}, "falliti": {}, "fonti": []})
    try:
        import pyevtx  # noqa: F401
    except ImportError:
        A.add("sistema", None, tr("Accessi dai registri eventi non letti"),
              tr("manca il modulo pyevtx (libevtx): gli accessi degli account restano quelli del SAM"), "", None)
        return
    per = acc["per_sid"]
    for fname, ids in (("security.evtx", {4624, 4625}), ("system.evtx", {7001, 7002})):
        rows = fe.hive_rows(ctx, part, "windows/system32/winevt/logs/" + fname)
        if not rows:
            continue
        p, inode, _, path = rows[0]
        f = fe.fetch(ctx, p, inode, path)
        if not f:
            continue
        st = {}
        try:
            evs = fe.evtx_records(f, ids, stats=st)
        except Exception as e:
            A.add("sistema", None, tr("Registro eventi {name} non leggibile").format(name=Path(path).name), f"{type(e).__name__}: {e}", "",
                  (p, inode, path))
            continue
        tss = [ev[1] for ev in evs if ev[1]]
        dal, al = (filetime(min(tss)), filetime(max(tss))) if tss else (None, None)
        visti, n_ok, n_rec = set(), 0, 0
        for eid, t, prov, d, recuperato in sorted(evs, key=lambda x: x[1] or 0):
            ts = filetime(t)
            if eid == 4624:
                sid = (d.get("TargetUserSid") or "").upper()
                try:
                    tipo = int(d.get("LogonType") or 0)
                except ValueError:
                    continue
                if tipo not in LOGON_TIPI or not sid.startswith("S-1-5-21-"):
                    continue
                # un amministratore con UAC genera due eventi per lo stesso accesso (token normale ed elevato)
                key = (sid, tipo, (t or 0) // 20_000_000)
                if key in visti:
                    continue
                visti.add(key)
                n_ok += 1
                u = per.setdefault(sid, {})
                k = "sblocchi" if tipo == 7 else "accessi"
                u[k] = u.get(k, 0) + 1
                if tipo != 7:
                    u.setdefault("tipi", {})
                    u["tipi"][tr(LOGON_TIPI[tipo])] = u["tipi"].get(tr(LOGON_TIPI[tipo]), 0) + 1
                    if recuperato:
                        u["accessi_recuperati"] = u.get("accessi_recuperati", 0) + 1
                        n_rec += 1
                    u["primo"] = u.get("primo") or ts
                    u["ultimo"] = ts
                    u["nome"] = d.get("TargetUserName") or u.get("nome")
            elif eid == 4625:
                nome = (d.get("TargetUserName") or "").lower()
                if nome and nome != "-":
                    fl = acc["falliti"].setdefault(nome, {"n": 0})
                    fl["n"] += 1
                    fl["recuperati"] = fl.get("recuperati", 0) + bool(recuperato)
                    fl["ultimo"] = ts
            elif eid in (7001, 7002) and "winlogon" in prov.lower():
                sid = (d.get("UserSid") or "").upper()
                if not sid.startswith("S-1-5-21-"):
                    continue
                n_ok += eid == 7001
                u = per.setdefault(sid, {})
                if eid == 7001:
                    u["sessioni"] = u.get("sessioni", 0) + 1
                    if recuperato:
                        u["sessioni_recuperate"] = u.get("sessioni_recuperate", 0) + 1
                        n_rec += 1
                    u["sess_primo"] = u.get("sess_primo") or ts
                    u["sess_ultimo"] = ts
                else:
                    u["sess_fine"] = ts
        acc["fonti"].append({"file": path, "dal": dal, "al": al, "eventi": len(evs), "record": st})
        A.add("sistema", al, tr("Registro eventi {name}: accessi letti").format(name=Path(path).name),
              tr("{v1} eventi utili ({v2}) dal {v3} al {v4} (UTC)").format(v1=len(evs), v2=', '.join(str(i) for i in sorted(ids)), v3=(dal or '?').replace('T', ' '), v4=(al or '?').replace('T', ' '))
              + (tr(", di cui {n_rec} accessi o sessioni da record recuperati").format(n_rec=n_rec) if n_rec else "")
              + tr("; {v1}. Il file conserva solo il periodo più recente, gli accessi precedenti non sono "
                   "contati.").format(v1=evtx_stato(st)), "", (p, inode, path),
              {"dal": dal, "al": al, "eventi": len(evs), "da_record_recuperati": n_rec, **st})


def sam_machine_sid(root):
    """SID del computer (S-1-5-21-a-b-c) dal valore V di SAM\\Domains\\Account; None se non si trova."""
    v = rv(rk(root, "SAM\\Domains\\Account"), "V")
    if not isinstance(v, bytes):
        return None
    i = v.rfind(b"\x01\x04\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00")
    if i < 0 or i + 24 > len(v):
        return None
    return "S-1-5-21-" + "-".join(str(x) for x in struct.unpack_from("<III", v, i + 12))


def win_sam(A, ctx, part, users):
    rows = fe.hive_rows(ctx, part, "windows/system32/config/sam")
    if not rows:
        return
    part, inode, _, path = rows[0]
    f = fetch_hive(A, ctx, part, inode, path)
    if not f:
        return
    hv, root = open_hive(f)
    src = (part, inode, path)
    names = {}
    creati = {}                 # (3.0.2) RID -> ultima scrittura di Names\<nome>: la creazione dell'account (come RegRipper)
    for k in subkeys(rk(root, "SAM\\Domains\\Account\\Users\\Names")):
        try:
            v = k.get_value_by_name("") or (k.get_value(0) if k.number_of_values else None)
            if v is not None:
                names[v.type] = k.name
                creati[v.type] = lw(k)
        except Exception:
            pass
    msid = sam_machine_sid(root)
    ev = getattr(ctx, "accessi", None) or {}
    fonti = ev.get("fonti") or []
    for k in subkeys(rk(root, "SAM\\Domains\\Account\\Users")):
        if not re.fullmatch(r"[0-9A-Fa-f]{8}", k.name):
            continue
        rid = int(k.name, 16)
        F = rv(k, "F")
        if not isinstance(F, bytes) or len(F) < 68:
            continue
        q = lambda o: filetime(struct.unpack_from("<Q", F, o)[0])
        last, pwd, failed = q(8), q(24), q(40)
        acb = struct.unpack_from("<H", F, 56)[0]
        bad = struct.unpack_from("<H", F, 64)[0]
        logins = struct.unpack_from("<H", F, 66)[0]
        name = names.get(rid, f"RID {rid}")
        # il profilo dell'utente (SOFTWARE\\...\\ProfileList) è una seconda fonte: il SAM non conta tutti gli accessi
        # (account Microsoft/online, PIN, Windows Hello) e, se non è stato riversato dai log, resta indietro
        prof = next((v for sid, v in (getattr(ctx, "profili", None) or {}).items()
                     if sid.rsplit("-", 1)[-1] == str(rid)), None)
        loaded = prof and prof.get("caricato")
        unloaded = prof and prof.get("scaricato")
        # registri eventi: SID del computer + RID (se il SID del computer non si legge, l'unico SID locale con quel RID)
        sid = f"{msid}-{rid}" if msid else None
        evu = (ev.get("per_sid") or {}).get(sid) if sid else None
        if evu is None and not msid:
            cand = [v for s_, v in (ev.get("per_sid") or {}).items() if s_.rsplit("-", 1)[-1] == str(rid)]
            evu = cand[0] if len(cand) == 1 else None
        evu = evu or {}
        n_ev, n_sess, n_sbl = evu.get("accessi", 0), evu.get("sessioni", 0), evu.get("sblocchi", 0)
        n_rec_acc, n_rec_sess = evu.get("accessi_recuperati", 0), evu.get("sessioni_recuperate", 0)
        ms = sz(rv(k, "InternetUserName"))
        fail = (ev.get("falliti") or {}).get(name.lower()) or {}
        ultimo_ev = max(x for x in (evu.get("ultimo"), evu.get("sess_ultimo"), "") if x is not None) or None
        usato = bool(last or loaded or n_ev or n_sess)
        periodo = "; ".join(tr("{name} dal {v1} al {v2}").format(name=Path(f['file']).name, v1=(f['dal'] or '?')[:10], v2=(f['al'] or '?')[:10])
                            for f in fonti if f.get("eventi"))
        if fonti:
            if n_ev or n_sess:
                acc = (tr("accessi {v1} secondo i registri eventi (").format(v1=max(n_ev, n_sess))
                       + ", ".join(x for x in (
                           tr("{n_ev} accessi riusciti 4624").format(n_ev=n_ev) + (" — " + ", ".join(f"{v} {t}" for t, v in
                                                                            sorted(evu.get('tipi', {}).items())) if evu.get('tipi') else "")
                           if n_ev else "",
                           tr("{n_rec_acc} accessi da record recuperati dallo spazio libero del registro").format(n_rec_acc=n_rec_acc) if n_rec_acc else "",
                           tr("{n_sess} sessioni Winlogon 7001").format(n_sess=n_sess) if n_sess else "",
                           tr("{n_rec_sess} sessioni da record recuperati").format(n_rec_sess=n_rec_sess) if n_rec_sess else "",
                           f"{n_sbl} sblocchi" if n_sbl else "") if x)
                       + tr("; periodo conservato: {periodo}; gli accessi più vecchi non sono più registrati)").format(periodo=periodo))
            else:
                acc = tr("nessun accesso nei registri eventi (periodo conservato: {v1})").format(v1=periodo or tr('nessun evento'))
            acc += tr("; contatore del SAM {logins}").format(logins=logins)
            if not logins and (n_ev or n_sess or usato):
                acc += tr(" (Windows non lo aggiorna per gli accessi con account Microsoft, PIN o Windows Hello)")
        elif logins:
            acc = tr("accessi {logins} (contatore del SAM)").format(logins=logins)
        elif usato:
            acc = tr("accessi: il contatore del SAM è 0 ma l'account risulta usato (il SAM non conta tutti gli accessi, " \
                  "p. es. account Microsoft, PIN o Windows Hello): non vale come «mai acceduto»")
        else:
            acc = tr("accessi 0 (contatore del SAM; nessun ultimo accesso né profilo caricato registrato)")
        n_tot = max(logins, n_ev, n_sess)
        ts = last or ultimo_ev or loaded
        A.add("utenti", ts, tr("Account {name}").format(name=name) + (tr(" · {n_tot} accessi").format(n_tot=n_tot) if n_tot else
                                                   tr(" · usato (accessi non contati)") if usato else
                                                   tr(" · nessun accesso registrato")),
              "; ".join(x for x in (
                  f"RID {rid}", tr("account Microsoft {ms}").format(ms=ms) if ms else "", acc,
                  tr("ultimo accesso {v1} (SAM)").format(v1=last.replace('T', ' ')) if last else "",
                  tr("ultimo accesso {v1} (registro eventi)").format(v1=ultimo_ev.replace('T', ' ')) if ultimo_ev else "",
                  tr("primo accesso conservato {v1}").format(v1=evu['primo'].replace('T', ' ')) if evu.get("primo") else "",
                  "" if last or ultimo_ev else tr("ultimo accesso non registrato"),
                  tr("ultimo caricamento del profilo {v1}").format(v1=loaded.replace('T', ' ')) if loaded else "",
                  tr("ultimo scaricamento del profilo {v1}").format(v1=unloaded.replace('T', ' ')) if unloaded else "",
                  tr("password errate {bad} (SAM)").format(bad=bad) if bad else "",
                  tr("accessi falliti 4625: {n}, ultimo {v1}").format(n=fail['n'], v1=fail['ultimo'].replace('T', ' ')) if fail.get("n") else "",
                  tr("password impostata {v1}").format(v1=pwd.replace('T', ' ')) if pwd else "",
                  tr("ultimo tentativo fallito {v1}").format(v1=failed.replace('T', ' ')) if failed else "",
                  tr("account creato {v1} (ultima scrittura della chiave del nome nel SAM)").format(
                      v1=creati[rid].replace('T', ' ')) if creati.get(rid) else "",
                  f"SID {sid}" if sid else "",
                  "disabilitato" if acb & 1 else "attivo") if x), name, src,
              {"rid": rid, "sid": sid, "accessi": n_tot, "accessi_sam": logins, "accessi_eventi": n_ev,
               "sessioni_winlogon": n_sess, "sblocchi": n_sbl, "tipi_accesso": evu.get("tipi"),
               "accessi_da_record_recuperati": n_rec_acc, "sessioni_da_record_recuperati": n_rec_sess,
               "ultimo_accesso": last or ultimo_ev, "ultimo_accesso_sam": last, "ultimo_accesso_eventi": ultimo_ev,
               "account_microsoft": ms or None, "profilo_caricato": loaded, "profilo_scaricato": unloaded,
               "password_errate": bad, "accessi_falliti": fail.get("n", 0), "periodo_eventi": fonti or None,
               "disabilitato": bool(acb & 1), "password_impostata": pwd, "ultimo_tentativo_fallito": failed,
               "creato": creati.get(rid)})
    hv.close()


def rot13(s):
    return s.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                     "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))


def known_folder(s):
    for g, p in KNOWN_FOLDERS.items():
        s = s.replace(g, tr(p))
    return s


def win_ntuser(A, ctx, part, row):
    part, inode, _, path = row
    user = user_of(path)
    f = fetch_hive(A, ctx, part, inode, path)
    if not f:
        return
    try:
        hv, root = open_hive(f)
    except Exception:
        return
    src = (part, inode, path)
    lwr = lw(root)
    if lwr and user:
        A.add("utenti", lwr, tr("Profilo {user}: ultima attività nel registro dell'utente").format(user=user),
              tr("ultima scrittura della chiave radice di NTUSER.DAT: {v1} (UTC). Indica che l'utente ha "
                 "avuto una sessione aperta fino a quel momento o poco prima (altra prova d'uso, "
                 "indipendente dal contatore degli accessi del SAM)").format(v1=lwr.replace('T', ' ')), user, src, {"ultima_scrittura": lwr})
    ex = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
    for g in subkeys(rk(root, f"{ex}\\UserAssist")):
        cnt = rk(g, "Count")
        try:
            vals = list(cnt.values) if cnt is not None else []
        except Exception:
            vals = []
        for v in vals:
            name = known_folder(rot13(v.name or ""))
            d = v.data or b""
            if name.startswith("UEME_") or not name:
                continue
            runs, last = None, None
            if len(d) >= 68:
                runs = struct.unpack_from("<I", d, 4)[0]
                last = filetime(struct.unpack_from("<Q", d, 60)[0])
            elif len(d) >= 16:
                runs = max(0, struct.unpack_from("<I", d, 4)[0] - 5)
                last = filetime(struct.unpack_from("<Q", d, 8)[0])
            if not runs and not last:
                continue
            A.add("esecuzioni", last, name, tr("UserAssist: avviato {runs} volte dall'utente").format(runs=runs), user, src,
                  {"fonte": "UserAssist", "volte": runs})
    rd = rk(root, f"{ex}\\RecentDocs")
    if rd is not None:
        order = rv(rd, "MRUListEx")
        idx = [i for i in struct.unpack(f"<{len(order) // 4}I", order) if i != 0xFFFFFFFF] if isinstance(order, bytes) else []
        for pos, i in enumerate(idx[:400]):
            d = rv(rd, str(i))
            if isinstance(d, bytes):
                nm = d.decode("utf-16-le", "ignore").split("\x00")[0]
                if nm:
                    A.add("recenti", lw(rd) if pos == 0 else None, nm,
                          tr("RecentDocs: documento o cartella aperti di recente") + (tr(" (il più recente)") if pos == 0 else tr(" (posizione {v1})").format(v1=pos + 1)),
                          user, src, {"fonte": "RecentDocs", "posizione": pos + 1})
    for key, cat, lbl in ((f"{ex}\\TypedPaths", "recenti", tr("percorso digitato in Esplora file")),
                          (f"{ex}\\RunMRU", "esecuzioni", tr("comando digitato in Esegui (Win+R)")),
                          (f"{ex}\\WordWheelQuery", "ricerche", tr("ricerca in Esplora file")),
                          ("Software\\Microsoft\\Internet Explorer\\TypedURLs", "web", tr("indirizzo digitato in Internet Explorer"))):
        k = rk(root, key)
        try:
            vals = list(k.values) if k is not None else []
        except Exception:
            vals = []
        for v in vals:
            if v.name in ("MRUList", "MRUListEx"):
                continue
            val = sz(rv(k, v.name))
            if val:
                A.add(cat, lw(k), val.rstrip("\\1"), f"{lbl} ({v.name})", user, src, {"fonte": key.split("\\")[-1]})
    for mp in subkeys(rk(root, f"{ex}\\MountPoints2")):
        nm = mp.name.replace("#", "\\")
        A.add("usb" if nm.startswith("{") else "reti", lw(mp),
              tr("Volume montato dall'utente") if nm.startswith("{") else tr("Condivisione di rete aperta: {nm}").format(nm=nm),
              mp.name, user, src)
    office = rk(root, "Software\\Microsoft\\Office")
    for ver in subkeys(office):
        for app in subkeys(ver):
            for sub in ("File MRU", "Place MRU"):
                k = rk(app, sub)
                try:
                    vals = list(k.values) if k is not None else []
                except Exception:
                    vals = []
                for v in vals:
                    s = sz(rv(k, v.name))
                    m = re.search(r"\[T([0-9A-F]{16})\].*\*(.+)$", s or "")
                    if m:
                        A.add("recenti", filetime(int(m.group(1), 16)), m.group(2),
                              tr("Office {name} {name2}: {v1} aperto di recente").format(name=app.name, name2=ver.name, v1='file' if sub == 'File MRU' else 'cartella'),
                              user, src, {"fonte": "Office MRU"})
    for base in ("Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"):
        k = rk(root, base)
        try:
            for v in (k.values if k is not None else []):
                A.add("programmi", lw(k), tr("Avvio automatico: {name}").format(name=v.name), tr("{v1} (solo per {user})").format(v1=sz(rv(k, v.name)), user=user), user, src)
        except Exception:
            pass
    for base in ("Software\\Microsoft\\Windows\\Shell\\BagMRU", "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU"):
        try:
            fe.shellbags(A, root, base, user, src, "ShellBags (NTUSER.DAT)")
        except Exception as e:
            print(tr("  ShellBags {path}: {vname}: {e}").format(path=path, vname=type(e).__name__, e=e), flush=True)
    hv.close()


def win_prefetch(A, ctx, part):
    try:
        import pyscca
    except ImportError:
        return
    for p, inode, _, path in fe.fw(ctx, part, "windows/prefetch/%.pf"):
        f = fe.fetch(ctx, p, inode, path, 50 << 20)
        if not f:
            continue
        try:
            sf = pyscca.file()
            sf.open(str(f))
            exe = sf.executable_filename
            runs = sf.run_count
            times = []
            for i in range(8):
                try:
                    t = iso(sf.get_last_run_time(i))
                except Exception:
                    t = None
                if t:
                    times.append(t)
            full = ""
            for i in range(sf.number_of_filenames):
                fn = sf.get_filename(i) or ""
                if fn.upper().endswith("\\" + (exe or "").upper()):
                    full = re.sub(r"(?i)^\\DEVICE\\HARDDISKVOLUME\d+", "", fn)
                    break
            sf.close()
            A.add("esecuzioni", times[0] if times else None, exe or Path(path).stem,
                  tr("Prefetch: eseguito {runs} volte").format(runs=runs) + (tr("; ultime esecuzioni: {v1}").format(v1=', '.join(t.replace('T', ' ') for t in times)) if times else "") +
                  (tr("; percorso {full}").format(full=full) if full else ""), "", (p, inode, path),
                  {"fonte": "Prefetch", "volte": runs, "esecuzioni": times, "percorso": full})
        except Exception:
            continue
        finally:
            fe.togli(f)


def win_amcache(A, ctx, part):
    rows = fe.fw(ctx, part, "windows/appcompat/programs/amcache.hve")
    if not rows:
        return
    p, inode, _, path = rows[0]
    f = fetch_hive(A, ctx, p, inode, path)
    if not f:
        return
    try:
        hv, root = open_hive(f)
    except Exception:
        return
    src = (p, inode, path)
    for k in subkeys(rk(root, "Root\\InventoryApplicationFile")):
        lp = sz(rv(k, "LowerCaseLongPath"))
        if not lp:
            continue
        sha1 = sz(rv(k, "FileId"))
        sha1 = sha1[4:] if sha1.startswith("0000") else sha1
        A.add("esecuzioni", lw(k), lp, "; ".join(x for x in (
            tr("Amcache: programma presente o eseguito"), sz(rv(k, "ProductName")), sz(rv(k, "Publisher")),
            f"SHA-1 {sha1}" if sha1 else "", f"compilato {sz(rv(k, 'LinkDate'))}" if rv(k, "LinkDate") else "") if x),
              "", src, {"fonte": "Amcache", "sha1": sha1})
    for vol in subkeys(rk(root, "Root\\File")):
        for k in subkeys(vol):
            lp = sz(rv(k, "15"))
            if lp:
                sha1 = sz(rv(k, "101"))
                A.add("esecuzioni", lw(k), lp, tr("Amcache: programma presente o eseguito") +
                      (tr("; SHA-1 {v1}").format(v1=sha1[4:] if sha1.startswith('0000') else sha1) if sha1 else ""), "", src,
                      {"fonte": "Amcache"})
    hv.close()


def lnk_info(lf):
    target = lf.local_path or lf.network_path or ""
    if not target and lf.relative_path:
        target = lf.relative_path
    det = []
    for lbl, val in ((tr("creazione destinazione"), iso(lf.file_creation_time)),
                     (tr("modifica destinazione"), iso(lf.file_modification_time)),
                     (tr("accesso destinazione"), iso(lf.file_access_time))):
        if val:
            det.append(f"{lbl} {val.replace('T', ' ')}")
    if lf.volume_label:
        det.append(tr("volume «{volume_label}»").format(volume_label=lf.volume_label))
    if lf.drive_serial_number:
        det.append(tr("seriale volume {drive_serial_number:08X}").format(drive_serial_number=lf.drive_serial_number))
    if lf.machine_identifier:
        det.append(f"computer {lf.machine_identifier}")
    if lf.file_size:
        det.append(f"{lf.file_size} byte")
    return target, det


def fs_time(ctx, part, inode):
    """Date (modifica, creazione) di un file della copia, da pytsk3 se disponibile."""
    hr = getattr(ctx, "hr", None)
    if hr is None:
        hr = ctx.hr = HeadReader(ctx.case)
    if not hr.ok:
        return None, None
    fs = hr._fs(part)
    if fs is None:
        return None, None
    try:
        m = fs.open_meta(inode=int(str(inode).split("-")[0])).info.meta
        return unixtime(m.mtime), unixtime(getattr(m, "crtime", 0))
    except Exception:
        return None, None


def win_lnk(A, ctx, part):
    try:
        import pylnk
    except ImportError:
        return
    rows = fe.find_files(ctx.con, part, "%/appdata/roaming/microsoft/windows/recent/%.lnk") + \
        fe.find_files(ctx.con, part, "%/appdata/roaming/microsoft/office/recent/%.lnk") + \
        fe.find_files(ctx.con, part, "documents and settings/%/recent/%.lnk")
    for p, inode, _, path in rows[:20000]:
        f = fe.fetch(ctx, p, inode, path, 4 << 20)
        if not f:
            continue
        try:
            lf = pylnk.file()
            lf.open(str(f))
            target, det = lnk_info(lf)
            lf.close()
            mt, ct = fs_time(ctx, p, inode)
            if mt:
                det.insert(0, tr("ultima apertura (collegamento modificato) {v1}").format(v1=mt.replace('T', ' ')))
            if ct and ct != mt:
                det.insert(1, tr("prima apertura (collegamento creato) {v1}").format(v1=ct.replace('T', ' ')))
            A.add("recenti", mt, target or Path(path).stem, tr("Collegamento recente (LNK): ") + "; ".join(det),
                  user_of(path), (p, inode, path), {"fonte": "LNK"})
        except Exception:
            pass
        finally:
            fe.togli(f)
    try:
        import pyolecf
    except ImportError:
        return
    for p, inode, _, path in fe.find_files(ctx.con, part, "%/recent/automaticdestinations/%"):
        f = fe.fetch(ctx, p, inode, path, 20 << 20)
        if not f:
            continue
        app = Path(path).name.split(".")[0].lower()
        appname = tr(JUMP_APPS.get(app, "")) or tr("applicazione {app}").format(app=app)
        try:
            of = pyolecf.file()
            of.open(str(f))
            r = of.root_item
            dl = {}
            for i in range(r.number_of_sub_items):
                it = r.get_sub_item(i)
                if (it.name or "").lower() == "destlist" and it.size:
                    dl = parse_destlist(it.read(it.size))
            for i in range(r.number_of_sub_items):
                it = r.get_sub_item(i)
                if (it.name or "").lower() == "destlist" or not it.size:
                    continue
                lf = pylnk.file()
                lf.open_file_object(io.BytesIO(it.read(it.size)))
                target, det = lnk_info(lf)
                lf.close()
                try:
                    num = int(it.name, 16)
                except (TypeError, ValueError):
                    num = None
                acc, host, cnt = dl.get(num, (None, "", None))
                if acc:
                    det.insert(0, tr("ultimo accesso {v1}").format(v1=acc.replace('T', ' ')))
                if cnt:
                    det.insert(1, tr("aperto {cnt} volte").format(cnt=cnt))
                if host:
                    det.append(tr("nome NetBIOS {host}").format(host=host))
                if target:
                    A.add("recenti", acc, target, tr("Jump list di {appname}: ").format(appname=appname) + "; ".join(det), user_of(path),
                          (p, inode, path), {"fonte": "Jump list", "app": appname})
            of.close()
        except Exception:
            pass
        finally:
            fe.togli(f)


def parse_destlist(d):
    """DestList delle jump list: {numero voce: (ultimo accesso, nome NetBIOS, volte aperto)}."""
    out = {}
    if len(d) < 32:
        return out
    ver, n = struct.unpack_from("<II", d, 0)
    pos = 32
    for _ in range(min(n, 5000)):
        try:
            host = d[pos + 72:pos + 88].split(b"\x00")[0].decode("ascii", "ignore")
            num = struct.unpack_from("<I", d, pos + 88)[0]
            acc = filetime(struct.unpack_from("<Q", d, pos + 100)[0])
            if ver >= 3:
                cnt = struct.unpack_from("<I", d, pos + 116)[0]
                ln = struct.unpack_from("<H", d, pos + 128)[0]
                pos += 130 + ln * 2 + 4
            else:
                cnt = None
                ln = struct.unpack_from("<H", d, pos + 112)[0]
                pos += 114 + ln * 2
            out[num] = (acc, host, cnt)
        except struct.error:
            break
    return out


def win_recycle(A, ctx, part, users):
    for p, inode, deleted, path in fe.find_files(ctx.con, part, "$recycle.bin/%/$i%", deleted_ok=True):
        f = fe.fetch(ctx, p, inode, path, 1 << 16)
        if not f:
            continue
        try:
            d = f.read_bytes()
            ver, size, t = struct.unpack_from("<QQQ", d, 0)
            if ver == 1:
                orig = d[24:24 + 520].decode("utf-16-le", "ignore").split("\x00")[0]
            else:
                n = struct.unpack_from("<I", d, 24)[0]
                orig = d[28:28 + n * 2].decode("utf-16-le", "ignore").split("\x00")[0]
            sid = path.split("/")[1] if path.count("/") >= 2 else ""
            rname = "$R" + Path(path).name[2:]
            has_r = ctx.con.execute("SELECT 1 FROM files WHERE part=? AND lower(path)=? AND deleted=0",
                                    (p, (str(Path(path).parent) + "/" + rname).lower())).fetchone()
            A.add("cestino", filetime(t), orig, tr("{size} byte · contenuto nel cestino: ").format(size=size) +
                  (tr("presente (") + rname + ")" if has_r else tr("non più presente")) + (tr(" · indice già eliminato") if deleted else ""),
                  users.get(sid, sid), (p, inode, path), {"dimensione": size, "sid": sid, "contenuto_presente": bool(has_r)})
        except Exception:
            pass
        finally:
            fe.togli(f)
