# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (3.0): voli dei droni in ogni caso: estrazioni (cartella, zip, tar) e copie forensi delle memorie.

Fonti: registri TXT delle app DJI letti da ALEAPP (versioni 1-12; dalla 13 la telemetria è cifrata e NON si legge: non si
contatta DJI e non si tocca la cifratura, resta solo il riepilogo), sottotitoli .SRT dei video DJI, CSV di Litchi e Airdata,
registri Autel (AUTEL_FR 1-3), PX4 ULog, ArduPilot tlog e DataFlash. Betaflight e .DAT DJI si segnalano senza leggerli.
Una traccia è un dato del registro: dice cosa il file riporta, non chi pilotava. Le date restano quelle della fonte."""
import csv
import hashlib
import io
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from forense_lingua import tr

MAX_PUNTI_VOLO = 5000
MAX_CSV = 200 << 20
MAX_SRT = 50 << 20
MAX_LOG = 1 << 30
_AUTEL = re.compile(r"^autel_", re.I)
_DATAFLASH = re.compile(r"^(\d+|log\w*)\.bin$", re.I)
_NON_LETTI = re.compile(r"(\.bbl|\.bfl|\.bbs|^fly\d+\.dat)$", re.I)
_CSV_DISCO = re.compile(r"litchi|airdata|dji|drone|autel|yuneec|flight|/voli?/", re.I)     # copie forensi: non tutti i CSV di un computer
_DJI = re.compile(r"^DJIFlightRecord.*\.txt$", re.I)
_SRT_LAT = re.compile(r"\[latitude\s*:\s*(-?\d+\.\d+)\]\s*\[lon(?:gitude|gtitude)?\s*:\s*(-?\d+\.\d+)\]", re.I)
_SRT_ALT = re.compile(r"(?:abs_alt|altitude)\s*:\s*(-?\d+(?:\.\d+)?)", re.I)
_SRT_GPS = re.compile(r"GPS\s*\(\s*(-?\d+\.\d+)\s*,\s*(-?\d+\.\d+)\s*(?:,\s*(-?\d+(?:\.\d+)?))?", re.I)
_SRT_ORA = re.compile(r"(\d{4}[-./]\d{2}[-./]\d{2}\s+\d{2}:\d{2}:\d{2})")
_C_LAT = ("latitude",)
_C_LON = ("longitude",)
_C_ALT = ("altitude(m)", "altitude_above_seaLevel(meters)".lower(), "altitude(meters)", "altitude(feet)", "height_above_takeoff(meters)".lower(), "altitude")
_C_ORA = ("datetime(utc)", "datetime", "time(utc)")


def _num(v):
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if x == x else None


def _ok(la, lo):
    return la is not None and lo is not None and -90 <= la <= 90 and -180 <= lo <= 180 and not (la == 0 and lo == 0)


def _metri(pt):
    tot = 0.0
    for a, b in zip(pt, pt[1:]):
        p1, p2 = math.radians(a[1]), math.radians(b[1])
        d = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(math.radians(b[0] - a[0]) / 2) ** 2
        tot += 2 * 6371000 * math.asin(min(1, math.sqrt(d)))
    return round(tot)


def _volo(nome, percorso, formato, lettore, pt, **extra):
    """pt: [lon, lat, quota o None, data o ""], in ordine di file."""
    tot = len(pt)
    lung = _metri(pt)
    if tot > MAX_PUNTI_VOLO:
        passo = tot / MAX_PUNTI_VOLO
        pt = [pt[int(i * passo)] for i in range(MAX_PUNTI_VOLO - 1)] + [pt[-1]]
    ore = [p[3] for p in pt if p[3]]
    quote = [p[2] for p in pt if p[2] is not None]
    return {"nome": nome, "file": percorso, "formato": formato, "lettore": lettore, "stato": "letto" if tot else "senza_posizioni", "punti_tot": tot, "punti": pt,
            "inizio": ore[0] if ore else "", "fine": ore[-1] if ore else "", "lunghezza_m": lung, "quota_max": max(quote) if quote else None, **extra}


INCERTI = [False]


def leggi_srt(testo):
    pt, ora = [], ""
    INCERTI[0] = False
    for blocco in re.split(r"\r?\n\r?\n", testo):
        m = _SRT_ORA.search(blocco)
        if m:
            ora = m[1].replace("/", "-").replace(".", "-")
        g = _SRT_LAT.search(blocco)
        if g:
            la, lo = _num(g[1]), _num(g[2])
            a = _SRT_ALT.search(blocco)
            q = _num(a[1]) if a else None
        else:
            g = _SRT_GPS.search(blocco)
            if not g:
                continue
            # alcuni modelli scrivono GPS(lon, lat, quota), altri GPS(lat, lon, quota): il formato del file non lo dichiara
            la, lo, q = _num(g[1]), _num(g[2]), _num(g[3])
            INCERTI[0] = True
        if _ok(la, lo):
            pt.append([lo, la, q, ora])
    return pt


def leggi_csv(testo):
    """CSV di Litchi e Airdata: solo se le colonne ci sono. -> (punti, formato) o (None, None)"""
    r = csv.reader(io.StringIO(testo))
    try:
        h = [x.strip().lower() for x in next(r)]
    except StopIteration:
        return None, None
    la = next((h.index(x) for x in _C_LAT if x in h), None)
    lo = next((h.index(x) for x in _C_LON if x in h), None)
    if la is None or lo is None:
        return None, None
    al = next((h.index(x) for x in _C_ALT if x in h), None)
    piedi = al is not None and "feet" in h[al]
    t = next((h.index(x) for x in _C_ORA if x in h), None)
    pt = []
    for x in r:
        if len(x) <= max(la, lo):
            continue
        a, o = _num(x[la]), _num(x[lo])
        if _ok(a, o):
            q = _num(x[al]) if al is not None and al < len(x) else None
            pt.append([o, a, round(q * .3048, 2) if q is not None and piedi else q, x[t].strip() if t is not None and t < len(x) else ""])
    return pt, ("csv_airdata" if "height_above_takeoff(feet)" in h or "height_above_takeoff(meters)" in h else "csv")


def _utc(sec):
    try:
        return datetime(1970, 1, 1, tzinfo=timezone.utc).__add__(timedelta(seconds=sec)).strftime("%Y-%m-%d %H:%M:%S") if 946684800 < sec < 4102444800 else ""
    except (OverflowError, OSError, ValueError):
        return ""


def _str(b):
    return b.split(b"\0", 1)[0].decode("utf-8", "replace").strip()


# Autel: magic, versione, lunghezza intestazione; poi record con un byte di tipo. Dimensioni per versione del formato
# (documentazione pubblica: research/aeflr.html e parser di autel-logger, MIT). Le posizioni sono solo nei record 0 e 1.
# Dimensioni dei record ricavate da autel-logger (https://github.com/MansfieldTX-MattR/autel-logger):
#   Copyright (c) 2024 Matt Reid
#   Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
#   documentation files (the "Software"), to deal in the Software without restriction, including without limitation
#   the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
#   permit persons to whom the Software is furnished to do so, subject to the following conditions:
#   The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
#   Software.
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
#   WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
#   COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
#   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
_AUTEL_DIM = {1: {0: 203, 1: 82, 2: 173, 3: 74, 14: 80, 15: 84}, 2: {0: 268, 1: 114, 2: 238, 3: 106, 14: 80, 15: 84}, 3: {0: 268, 1: 114, 2: 238, 3: 106, 14: 80, 15: 84}}
_AUTEL_TESTA = 157


def leggi_autel(d):
    """-> (punti, riepilogo, stato, troncato). Un file in cui i record non tornano si ferma lì e lo dice."""
    ver = struct.unpack_from("<I", d, 8)[0]
    if ver not in _AUTEL_DIM:
        return [], {"Log Version": str(ver)}, "versione_ignota", False
    if len(d) < 14 + _AUTEL_TESTA:
        return [], {"Log Version": str(ver)}, "senza_posizioni", True
    dim, o = _AUTEL_DIM[ver], 14
    dist, durata, q_max, _vt = struct.unpack_from("<fIfI", d, o + 115)
    t0 = struct.unpack_from("<Q", d, o + 131)[0]
    la0, lo0 = struct.unpack_from("<ff", d, o + 143)
    foto, vid, nfw = struct.unpack_from("<HHH", d, o + 151)
    rp = {"Log Version": str(ver), "Aircraft Serial Number": _str(d[o:o + 18]), "Battery Serial Number": _str(d[o + 18:o + 50]), "Location": _str(d[o + 50:o + 114]),
          "Firmware": _str(d[o + _AUTEL_TESTA:o + _AUTEL_TESTA + nfw]), "Total Distance (m)": round(dist, 1), "Total Time (s)": durata, "Maximum Height (m)": round(q_max, 1),
          "Images": foto, "Videos": vid}
    rp = {k: v for k, v in rp.items() if v not in ("", None)}
    p, pt, troncato = o + _AUTEL_TESTA + nfw, [], False
    sec0 = t0 / 1000 if t0 > 10 ** 11 else t0
    while p < len(d):
        n = dim.get(d[p])
        if n is None or p + 1 + n > len(d):
            troncato = True
            break
        if d[p] in (0, 1):
            ms, la, lo, q = struct.unpack_from("<Ifff", d, p + 1)
            if _ok(la, lo):
                pt.append([round(lo, 7), round(la, 7), round(q, 2), _utc(sec0 + ms / 1000)])
        p += n + 1
    if not pt and _ok(la0, lo0):
        pt = [[round(lo0, 7), round(la0, 7), None, _utc(sec0)]]
    return pt, rp, "letto" if pt else "senza_posizioni", troncato


_UL_T = {"int8_t": 1, "uint8_t": 1, "int16_t": 2, "uint16_t": 2, "int32_t": 4, "uint32_t": 4, "int64_t": 8, "uint64_t": 8, "float": 4, "double": 8, "bool": 1, "char": 1}
_UL_S = {"int32_t": "<i", "uint64_t": "<Q", "uint8_t": "<B", "float": "<f", "double": "<d"}
_UL_TOPIC = ("vehicle_gps_position", "sensor_gps", "vehicle_global_position")


def leggi_ulog(d):
    """PX4 ULog. -> (punti, riepilogo, argomento, troncato). Argomenti GPS nell'ordine di _UL_TOPIC, istanza 0."""
    fmt, ids, righe, rp, p = {}, {}, {}, {}, 16
    troncato = False

    def dim(t):
        if t in _UL_T:
            return _UL_T[t]
        return sum(c[2] for c in campi(t))

    def campi(t):
        out, off = [], 0
        for c in fmt.get(t, ()):
            if " " not in c:
                continue
            ty, nome = c.split(" ", 1)
            m = re.match(r"(.+)\[(\d+)\]$", ty)
            base, k = (m[1], int(m[2])) if m else (ty, 1)
            n = dim(base) * k
            out.append((nome, base, n, off))
            off += n
        return out

    while p + 3 <= len(d):
        n, t = struct.unpack_from("<HB", d, p)
        c = d[p + 3:p + 3 + n]
        if len(c) < n:
            troncato = True
            break
        if t == 70:        # F
            nome, _, resto = c.decode("utf-8", "replace").partition(":")
            fmt[nome] = [x for x in resto.split(";") if x]
        elif t == 73 and n > 1:    # I
            k = c[0]
            chiave = c[1:1 + k].decode("utf-8", "replace")
            if chiave.startswith("char[") and chiave.split(" ")[-1] in ("sys_name", "ver_hw", "sys_uuid", "ver_sw"):
                rp[chiave.split(" ")[-1]] = _str(c[1 + k:])
        elif t == 65 and n > 3:    # A
            multi, mid = struct.unpack_from("<BH", c)
            ids[mid] = (c[3:].decode("utf-8", "replace"), multi)
        elif t == 68 and n > 2:    # D
            mid = struct.unpack_from("<H", c)[0]
            x = ids.get(mid)
            if x and x[1] == 0 and x[0] in _UL_TOPIC:
                righe.setdefault(x[0], []).append(c[2:])
        p += 3 + n
    for tema in _UL_TOPIC:
        if tema not in righe:
            continue
        cs = {x[0]: x for x in campi(tema)}
        la, lo = cs.get("latitude_deg") or cs.get("lat"), cs.get("longitude_deg") or cs.get("lon")
        if not la or not lo:
            continue
        q = cs.get("altitude_msl_m") or cs.get("alt")
        fix, ora = cs.get("fix_type"), cs.get("time_utc_usec")

        def val(r, f):
            s = _UL_S.get(f[1])
            return struct.unpack_from(s, r, f[3])[0] if s and f[3] + f[2] <= len(r) else None

        pt = []
        for r in righe[tema]:
            a, o = val(r, la), val(r, lo)
            if a is None or o is None or (fix and (val(r, fix) or 0) < 2):
                continue
            if la[1] == "int32_t":
                a, o = a / 1e7, o / 1e7
            if not _ok(a, o):
                continue
            h = val(r, q) if q else None
            if h is not None and q[1] == "int32_t":
                h /= 1000
            u = val(r, ora) if ora else 0
            pt.append([round(o, 7), round(a, 7), round(h, 2) if h is not None else None, _utc(u / 1e6) if u else ""])
        if pt:
            return pt, rp, tema, troncato
    return [], rp, "", troncato


def _x25(b, extra):
    c = 0xffff
    for x in b + bytes([extra]):
        x ^= c & 0xff
        x = (x ^ (x << 4)) & 0xff
        c = ((c >> 8) ^ (x << 8) ^ (x << 3) ^ (x >> 4)) & 0xffff
    return c


def leggi_tlog(d):
    """MAVLink con la data davanti a ogni pacchetto. Si usano GLOBAL_POSITION_INT (33) o, se manca, GPS_RAW_INT (24), con CRC controllato."""
    gp, raw, p, n = {}, {}, 8, len(d)
    while p + 8 < n:
        m = d[p]
        if m == 0xfe:
            k, h, sysid, msg = d[p + 1], 6, d[p + 3], d[p + 5]
            pay = p + 6
            coda = 0
        elif m == 0xfd:
            k, h, sysid = d[p + 1], 10, d[p + 5]
            msg = d[p + 7] | d[p + 8] << 8 | d[p + 9] << 16
            pay = p + 10
            coda = 13 if d[p + 2] & 1 else 0
        else:
            p += 1
            continue
        fine = pay + k + 2
        if fine > n:
            break
        if msg in (33, 24):
            crc = struct.unpack_from("<H", d, pay + k)[0]
            if _x25(d[p + 1:pay + k], 104 if msg == 33 else 24) != crc:
                p += 1
                continue
            r = d[pay:pay + k].ljust(52, b"\0")
            us = struct.unpack_from(">Q", d, p - 8)[0]
            if msg == 33:
                la, lo, q = struct.unpack_from("<iii", r, 4)
                dest = gp
            else:
                la, lo, q = struct.unpack_from("<iii", r, 8)
                dest = raw if r[28] >= 2 else None
            if dest is not None and _ok(la / 1e7, lo / 1e7):
                dest.setdefault(sysid, []).append([round(lo / 1e7, 7), round(la / 1e7, 7), round(q / 1000, 2), _utc(us / 1e6)])
        p = fine + coda + 8
    fonte = gp or raw
    if not fonte:
        return [], {}
    s = max(fonte, key=lambda k: len(fonte[k]))
    return fonte[s], {"System ID": s, "Messaggio": "GLOBAL_POSITION_INT" if gp else "GPS_RAW_INT"}


_DF_T = {"b": 1, "B": 1, "h": 2, "H": 2, "i": 4, "I": 4, "f": 4, "d": 8, "n": 4, "N": 16, "Z": 64, "c": 2, "C": 2, "e": 4, "E": 4, "L": 4, "M": 1, "q": 8, "Q": 8, "a": 64}
_DF_S = {"b": "<b", "B": "<B", "h": "<h", "H": "<H", "i": "<i", "I": "<I", "f": "<f", "d": "<d", "c": "<h", "C": "<H", "e": "<i", "E": "<I", "L": "<i", "M": "<B", "q": "<q", "Q": "<Q"}


def leggi_dataflash(d):
    """ArduPilot .BIN: i formati stanno nel file (messaggi FMT). Posizioni dal messaggio GPS (prima istanza) con fix ≥ 2. Tempo GPS portato a UTC con 18 s."""
    fmt, pt, rp, p, n = {}, [], {}, 0, len(d)
    while p + 3 <= n:
        if d[p] != 0xa3 or d[p + 1] != 0x95:
            p += 1
            continue
        t = d[p + 2]
        if t == 128 and p + 89 <= n:
            ty, ln = d[p + 3], d[p + 4]
            nome, fm = _str(d[p + 5:p + 9]), _str(d[p + 9:p + 25])
            et = _str(d[p + 25:p + 89]).split(",")
            off, cs = 3, {}
            for c, e in zip(fm, et):
                cs[e] = (off, c)
                off += _DF_T.get(c, 0)
            fmt[ty] = (nome, ln, cs)
            p += 89
            continue
        f = fmt.get(t)
        if not f or f[1] < 3:
            p += 1
            continue
        if p + f[1] > n:
            break
        nome, ln, cs = f
        if nome == "MSG" and "programma" not in rp and "Message" in cs:
            rp["programma"] = _str(d[p + cs["Message"][0]:p + cs["Message"][0] + 64])
        elif nome == "GPS" and "Lat" in cs and "Lng" in cs:
            def v(k):
                c = cs.get(k)
                return struct.unpack_from(_DF_S[c[1]], d, p + c[0])[0] if c and c[1] in _DF_S else None
            if (v("I") or 0) == 0 and (v("Status") or 0) >= 2:
                la, lo = v("Lat"), v("Lng")
                if la is not None and lo is not None and _ok(la / 1e7, lo / 1e7):
                    q = v("Alt")
                    if q is not None and cs["Alt"][1] in "eEiI":
                        q /= 100
                    wk, ms = v("GWk"), v("GMS")
                    pt.append([round(lo / 1e7, 7), round(la / 1e7, 7), round(q, 2) if q is not None else None, _utc(315964800 + wk * 604800 + ms / 1000 - 18) if wk and ms is not None else ""])
        p += ln
    return pt, rp


NOTA_AUTEL = "Registro Autel letto secondo la documentazione pubblica del formato: lettore non ancora provato su registri reali. Coordinate a precisione ridotta nel file (float a 32 bit)."


def leggi_binario(nome, d):
    """Riconosce il registro dal contenuto. -> dict per _volo o None se il file non è un registro noto."""
    if d[:8] == b"AUTEL_FR":
        pt, rp, st, tr_ = leggi_autel(d)
        return {"formato": "autel", "punti": pt, "riepilogo": rp, "stato": st, "nota": tr(NOTA_AUTEL) + (" " + tr("File interrotto o con record non riconosciuti: letto fino a quel punto.") if tr_ else "")}
    if d[:7] == b"ULog\x01\x12\x35":
        pt, rp, tema, tr_ = leggi_ulog(d)
        return {"formato": "ulog", "punti": pt, "riepilogo": {**rp, **({"Topic": tema} if tema else {})}, "nota": tr("File interrotto o con record non riconosciuti: letto fino a quel punto.") if tr_ else ""}
    if d[:3] == b"\xa3\x95\x80":
        pt, rp = leggi_dataflash(d)
        return {"formato": "dataflash", "punti": pt, "riepilogo": rp, "nota": ""}
    if nome.lower().endswith(".tlog") and len(d) > 16:
        pt, rp = leggi_tlog(d)
        return {"formato": "tlog", "punti": pt, "riepilogo": rp, "nota": ""}
    return None


def _aleapp(case, dji, say):
    """I registri TXT si passano ad ALEAPP in una cartella con il percorso che si aspetta: il nome nel telefono o nella scheda non conta."""
    import forense_agent as fa
    import forense_mobile_leapp as fml
    d = fml.tool_dir("android")
    if not d:
        say(tr("{name} non trovato (cartella strumenti/{key} del pacchetto o variabile REPERTIA_{K}).").format(name="ALEAPP", key="aleapp", K="ALEAPP"))
        return {}
    lav = Path(tempfile.mkdtemp(prefix="droni_", dir=str(case.root)))
    try:
        ing = lav / "in" / "sdcard" / "DJI" / "dji.go.v4" / "FlightRecord"
        ing.mkdir(parents=True)
        mappa = {}
        for i, (part, fid, path) in enumerate(dji):
            nome = f"DJIFlightRecord_{i:05d}_{Path(path).name[:80]}"
            if not nome.lower().endswith(".txt"):
                nome += ".txt"
            with open(ing / nome, "wb") as fo:
                for b in fa.icat_stream(case, part, fid):
                    fo.write(b)
            mappa[nome] = (part, fid, path)
        out = lav / "out"
        out.mkdir()
        cmd = [sys.executable, str(d / "aleapp.py"), "-t", "fs", "-i", str(lav / "in"), "-o", str(out)]
        case.log("cmd", cmd)
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=fml._env(d), cwd=str(d), stdin=subprocess.DEVNULL, timeout=3600)
        tsv = list(out.glob("*/_TSV Exports/DJI Drone - TXT Flight Records.tsv"))
        som = list(out.glob("*/_TSV Exports/DJI Drone - TXT Flight Log Summary.tsv"))
        csv.field_size_limit(1 << 30)
        ris = {}
        if som:
            with open(som[0], encoding="utf-8-sig", newline="") as f:
                for r in csv.DictReader(f, delimiter="\t"):
                    n = Path(r.get("Source File") or "").name
                    if n in mappa:
                        ris[n] = {"riepilogo": {k: r.get(k) for k in ("Log Version", "Status", "Aircraft Name", "Product Type", "Aircraft Serial Number", "Camera Serial Number", "RC Serial Number", "Battery Serial Number", "App Platform", "App Version", "Total Distance (m)", "Total Time (s)", "Maximum Height (m)") if r.get(k)}, "ora": r.get("Timestamp") or "", "punti": []}
        if tsv:
            with open(tsv[0], encoding="utf-8-sig", newline="") as f:
                for r in csv.DictReader(f, delimiter="\t"):
                    n = Path(r.get("Source File") or "").name
                    a, o = _num(r.get("Latitude")), _num(r.get("Longitude"))
                    if n in mappa and _ok(a, o):
                        ris.setdefault(n, {"riepilogo": {}, "ora": "", "punti": []})["punti"].append([o, a, _num(r.get("Relative Height (m)")), r.get("Timestamp") or ""])
        return {mappa[n]: v for n, v in ris.items()}, fml.versione(d, "android")
    finally:
        shutil.rmtree(lav, ignore_errors=True)


def _candidati(case):
    """(part, inode, percorso, dimensione o None, cancellato) dei file che possono essere registri di volo: solo dai nomi, senza leggere il contenuto."""
    import forense_agent as fa
    cond = "lower(path) LIKE '%.txt' OR lower(path) LIKE '%.srt' OR lower(path) LIKE '%.csv' OR lower(path) LIKE '%.ulg' OR lower(path) LIKE '%.tlog' OR " \
           "lower(path) LIKE '%.bin' OR lower(path) LIKE '%.bbl' OR lower(path) LIKE '%.bfl' OR lower(path) LIKE '%.bbs' OR lower(path) LIKE '%.dat' OR lower(path) LIKE '%/autel\\_%' ESCAPE '\\'"
    if fa.is_mobile(case):
        import forense_mobile as fm
        m = fm.mx(case)
        try:
            return [(p, f, x, z, 0) for p, f, x, z in m.execute(f"SELECT part, id, path, size FROM mobile_files WHERE isdir=0 AND ({cond})")], True
        finally:
            m.close()
    con = fa.db_ro(case)
    try:
        if not fa.table_exists(con, "files"):
            return [], False
        return [(p, f, x, None, c or 0) for p, f, x, c in con.execute(f"SELECT DISTINCT part, inode, path, deleted FROM files WHERE (type IS NULL OR type NOT LIKE 'd%') AND ({cond})")], False
    finally:
        con.close()


def run(case, say=print):
    """Cerca i registri nel caso e scrive voli.json. Sola lettura dei file; i calcoli stanno nella cartella del caso."""
    import forense_agent as fa
    voli, dji, altri, binari, segnalati = [], [], [], [], []
    canc = {}
    righe, mobile = _candidati(case)
    for part, fid, path, size, cancellato in righe:
        nome = Path(path).name
        if nome.startswith("._"):
            continue
        canc[(part, str(fid))] = cancellato
        minuscolo, cartella = nome.lower(), path.lower()
        if _DJI.match(nome):
            dji.append((part, fid, path))
        elif minuscolo.endswith(".srt") and (size or 0) <= MAX_SRT:
            altri.append((part, fid, path, "srt"))
        elif minuscolo.endswith(".csv") and (size or 0) <= MAX_CSV and (mobile or _CSV_DISCO.search(cartella)):
            altri.append((part, fid, path, "csv"))
        elif _NON_LETTI.search(nome) or (minuscolo.endswith(".dat") and "flightrecord" in cartella):
            segnalati.append((part, fid, path))
        elif minuscolo.endswith((".ulg", ".tlog")) or _AUTEL.match(nome) or "/flightlog/" in cartella or _DATAFLASH.match(nome):
            binari.append((part, fid, path))

    def leggi(part, fid, massimo=None):
        h, b = hashlib.sha256(), bytearray()
        for x in fa.icat_stream(case, part, str(fid) if not mobile else fid):
            h.update(x)
            if massimo is None or len(b) <= massimo:
                b += x
        return bytes(b), h.hexdigest()

    versione = None
    if dji:
        say(tr("Voli: {n} registri DJI da leggere con ALEAPP…").format(n=len(dji)))
        r = _aleapp(case, dji, say)
        ris, versione = r if isinstance(r, tuple) else (r, None)
        for k in dji:
            _b, sha = leggi(k[0], k[1], 0)
            v = ris.get(k)
            rp = (v or {}).get("riepilogo") or {}
            pt = (v or {}).get("punti") or []
            st = str(rp.get("Status") or "")
            x = _volo(Path(k[2]).name, k[2], "dji_txt", f"ALEAPP {versione or ''}".strip(), pt, part=k[0], inode=str(k[1]), sha256=sha, riepilogo=rp)
            if "ncrypt" in st.lower() or "cifrat" in st.lower():
                x["stato"] = "cifrato"
            elif not v:
                x["stato"] = "non_letto"
            if not x["inizio"]:
                x["inizio"] = (v or {}).get("ora") or ""
            voli.append(x)
    for part, fid, path, tipo in altri:
        try:
            dati, sha = leggi(part, fid, MAX_CSV)
            t = dati.decode("utf-8-sig", "replace")
            if tipo == "srt":
                pt, fmt = leggi_srt(t), "srt"
                if not pt:
                    continue
            else:
                pt, fmt = leggi_csv(t)
                if not pt:
                    continue
        except OSError as e:
            say(tr("Voli: {f} non letto: {e}").format(f=Path(path).name, e=e))
            continue
        voli.append(_volo(Path(path).name, path, fmt, "RepertIA", pt, part=part, inode=str(fid), sha256=sha, riepilogo={},
                          nota=tr("Formato GPS(a, b, quota): il file non dichiara se a è la latitudine; letto come latitudine, longitudine.") if tipo == "srt" and INCERTI[0] else ""))
    for part, fid, path in binari:
        try:
            dati, sha = leggi(part, fid, MAX_LOG)
        except OSError as e:
            say(tr("Voli: {f} non letto: {e}").format(f=Path(path).name, e=e))
            continue
        nome = Path(path).name
        if len(dati) > MAX_LOG:
            if dati[:8] == b"AUTEL_FR" or dati[:7] == b"ULog\x01\x12\x35" or dati[:3] == b"\xa3\x95\x80" or nome.lower().endswith(".tlog"):
                voli.append({**_volo(nome, path, "registro", "RepertIA", [], part=part, inode=str(fid), sha256=sha, riepilogo={}), "stato": "non_letto", "nota": tr("File oltre 1 GB: non letto.")})
            continue
        r = leggi_binario(nome, dati)
        if not r:
            continue
        x = _volo(nome, path, r["formato"], "RepertIA", r["punti"], part=part, inode=str(fid), sha256=sha, riepilogo=r["riepilogo"], nota=r["nota"])
        if r.get("stato"):
            x["stato"] = r["stato"]
        voli.append(x)
    for part, fid, path in segnalati:
        try:
            _d, sha = leggi(part, fid, 0)
        except OSError:
            continue
        voli.append({**_volo(Path(path).name, path, "non_supportato", "", [], part=part, inode=str(fid), sha256=sha, riepilogo={}), "stato": "non_supportato"})
    for x in voli:
        x["cancellato"] = bool(canc.get((x["part"], x["inode"])))
    voli.sort(key=lambda x: (x["inizio"] or "9", x["nome"]))
    for i, x in enumerate(voli):
        x["id"] = i
    f = Path(case.root) / "voli.json"
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(voli, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, f)
    st = {}
    for x in voli:
        st[x["stato"]] = st.get(x["stato"], 0) + 1
    case.meta["voli"] = {"totale": len(voli), "stati": st, "aleapp": versione}
    case.save()
    case.log("voli", {"totale": len(voli), "stati": st, "lettore_dji": versione, "file": [{"file": x["file"], "sha256": x["sha256"], "stato": x["stato"], "punti": x["punti_tot"]} for x in voli[:500]]})
    say(tr("Voli trovati: {n}.").format(n=len(voli)))
    return {"totale": len(voli), "stati": st}


def voli(case):
    try:
        return json.loads((Path(case.root) / "voli.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
