#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - interfaccia, fuso orario (da UTC al fuso scelto o rilevato).

(3.0.4) Codice spostato da forense_gui.py senza modifiche, per avere file più corti. Si carica tramite
forense_gui, che ne riesporta i nomi: gli altri moduli continuano a usare «G.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («G.<nome>»).
"""
import json
import re
from forense_lingua import N_
from forense_lingua import tr
import forense_agent as fa

import forense_gui as G
from forense_gui import (
    CfValues, PAGE, _sql_lit, cf_apply, cf_order, cf_parse, cf_terms, cf_values, tl_where)

# ------------------------------------------------- fuso orario (UTC -> ora italiana / fuso rilevato)
#
# I dati del caso restano in UTC; la conversione serve solo a mostrarli. Si usa il database dei
# fusi di Python se c'è, altrimenti (solo per l'Italia) la regola europea dell'ora legale (dal 1996).
# Modalità di visualizzazione ("tz"): "utc", "rome" (ora italiana), "dev" (fuso del dispositivo rilevato
# o scelto per il caso) oppure direttamente un nome IANA (es. "America/New_York").

try:
    from zoneinfo import ZoneInfo
    _ROME = ZoneInfo("Europe/Rome")
except Exception:
    ZoneInfo = None
    _ROME = None
TS_RE = re.compile(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.\d+)?(?:Z|[+-]00:?00)?")
_ZCACHE = {}


def _zone_obj(name):
    if not name or name == "UTC" or ZoneInfo is None:
        return None
    if name not in _ZCACHE:
        try:
            _ZCACHE[name] = ZoneInfo(name)
        except Exception:
            _ZCACHE[name] = None
    return _ZCACHE[name]


def tz_zone(case, tz):
    """Nome IANA della modalità di visualizzazione richiesta: "UTC", "Europe/Rome", il fuso del dispositivo del
    caso ("dev") oppure un nome IANA valido. Per un valore non riconosciuto restituisce "UTC"."""
    if not tz or str(tz).lower() == "utc":
        return "UTC"
    if tz == "rome":
        return "Europe/Rome"
    if tz == "dev":
        z = ((case.meta.get("fuso_dispositivo") or {}).get("tz") if case is not None else None)
        return z if z and (z == "UTC" or _zone_obj(z) is not None) else "UTC"
    return tz if tz == "Europe/Rome" or _zone_obj(tz) is not None else "UTC"


def tz_label(case, tz):
    """Etichetta da scrivere accanto alle date ('UTC', 'ora italiana' o il fuso rilevato)."""
    z = tz_zone(case, tz)
    if z == "UTC":
        return "UTC"
    if tz == "rome":
        return tr("ora italiana")
    f = (case.meta.get("fuso_dispositivo") or {}) if case is not None else {}
    st = f.get("stato")
    return (tr("fuso rilevato {z}").format(z=z) if st in ("rilevato", "confermato") else tr("fuso impostato {z}").format(z=z)) if tz == "dev" else z


def _off_tag(zone, off):
    """Sigla dello scostamento: CET/CEST per l'Italia, altrimenti 'UTC+HH:MM' (le sigle dei fusi sono ambigue)."""
    if zone == "Europe/Rome":
        return "CEST" if off == 7200 else "CET" if off == 3600 else "UTC%+03d:%02d" % (int(off // 3600), abs(off) % 3600 // 60)
    if zone == "UTC":
        return "UTC"
    sign = "+" if off >= 0 else "-"
    return "UTC%s%02d:%02d" % (sign, abs(int(off)) // 3600, abs(int(off)) % 3600 // 60)


def _rome_dt(dt):
    import datetime as _dt
    if _ROME is not None:
        return dt.replace(tzinfo=_dt.timezone.utc).astimezone(_ROME).replace(tzinfo=None)

    def last_sunday(m):
        x = _dt.datetime(dt.year, m, 31, 1)
        return x - _dt.timedelta(days=(x.weekday() + 1) % 7)
    return dt + _dt.timedelta(hours=2 if last_sunday(3) <= dt < last_sunday(10) else 1)


def _zone_dt(dt, zone):
    """Data e ora UTC (naive) -> data e ora del fuso (naive)."""
    import datetime as _dt
    if zone == "UTC":
        return dt
    if zone == "Europe/Rome":
        return _rome_dt(dt)
    zo = _zone_obj(zone)
    if zo is None:
        raise ValueError(tr("fuso non disponibile"))
    return dt.replace(tzinfo=_dt.timezone.utc).astimezone(zo).replace(tzinfo=None)


def to_zone(ts, zone, sep=None, tag=False):
    """Data e ora UTC ('2024-03-01T10:00:00', anche con Z o +00:00) nel fuso indicato, stessa forma. Con tag=True
    aggiunge la sigla (CET/CEST per l'Italia, altrimenti UTC+HH:MM): nell'ora doppia del passaggio all'ora solare è
    l'unico modo per distinguere i due istanti. Se il fuso non è disponibile restituisce il testo com'è."""
    import datetime as _dt
    m = TS_RE.fullmatch((ts or "").strip()) if isinstance(ts, str) else None
    if not m:
        return ts
    try:
        utc = _dt.datetime(*map(int, m.groups()))
        loc = _zone_dt(utc, zone)
    except (ValueError, OverflowError):
        return ts
    out = loc.strftime(f"%Y-%m-%d{sep or ts[10]}%H:%M:%S")
    if tag:
        out += " " + _off_tag(zone, (loc - utc).total_seconds())
    return out


def to_rome(ts, sep=None, tag=False):
    return to_zone(ts, "Europe/Rome", sep, tag)


def local_to_utc_str(loc, zone):
    """Data e ora locali del fuso (naive) -> UTC; fold=0 (prima occorrenza) nell'ora doppia. None se non valida."""
    import datetime as _dt
    zo = _ROME if zone == "Europe/Rome" else _zone_obj(zone)
    if zone == "UTC":
        return loc
    if zo is None:
        return None
    return loc.replace(tzinfo=zo).astimezone(_dt.timezone.utc).replace(tzinfo=None)


_FILE_AFTER = re.compile(r"^(?:\.[A-Za-z0-9]{1,6}\b|[ \t]?[\w\-]+\.[A-Za-z0-9]{1,6}\b)")


def _ts_is_text(md, m):
    """True se l'orario trovato fa parte di un nome di file, di un percorso, di un testo tra apici inversi o di una
    cella di tabella con altro testo: in quel caso non è un orario del report e non va toccato."""
    s, e = m.span()
    ls = md.rfind("\n", 0, s) + 1
    le = md.find("\n", e)
    le = len(md) if le < 0 else le
    before, after = md[ls:s], md[e:le]
    if before.count("`") % 2 == 1:
        return True
    if before and (before[-1] in "/\\_-" or before[-1].isalnum()):
        return True
    if _FILE_AFTER.match(after):
        return True
    if before.lstrip().startswith("|"):
        a = before.rfind("|") + 1
        b = after.find("|")
        cell = (before[a:] + m.group(0) + (after[:b] if b >= 0 else after)).strip()
        if cell != m.group(0):
            return True
    return False


def md_to_zone_ex(md, zone):
    """Report in markdown con gli orari UTC convertiti nel fuso indicato (con la sigla). Non tocca nomi di
    file, percorsi, testo tra apici inversi né celle con altro testo. Restituisce (testo, convertiti, lasciati)."""
    out, last, conv, skip = [], 0, 0, 0
    for m in TS_RE.finditer(md):
        if md[m.end():m.end() + 4] == " UTC" and not md[m.end() + 4:m.end() + 5].isalnum():
            # (3.0.4) orario marcato UTC nel testo (Dettagli degli artefatti, messaggi): si converte sempre, sigla compresa
            out.append(md[last:m.start()])
            out.append(to_zone(m.group(0), zone, " ", tag=True))
            last = m.end() + 4
            conv += 1
            continue
        if _ts_is_text(md, m):
            skip += 1
            continue
        out.append(md[last:m.start()])
        out.append(to_zone(m.group(0), zone, m.group(0)[10], tag=True))
        last = m.end()
        conv += 1
    out.append(md[last:])
    return "".join(out), conv, skip


def md_to_rome_ex(md):
    return md_to_zone_ex(md, "Europe/Rome")


def md_to_rome(md):
    return md_to_rome_ex(md)[0]


def fmt_ts(case, tz, s):
    """Data e ora UTC del caso scritte nel fuso scelto, SEMPRE con la sigla (UTC, CET/CEST o UTC+HH:MM).
    Le date che non sono in UTC (ora locale senza fuso) restano come sono e lo dicono."""
    s = ("" if s is None else str(s)).strip()
    if not s:
        return ""
    if s.lower().endswith("locale"):
        return s.replace("T", " ") + tr(" (ora locale, fuso non indicato)")
    if TS_RE.fullmatch(s):
        z = tz_zone(case, tz)
        r = to_zone(s, z, " ", tag=True)
        return r if r != s else s.replace("T", " ") + " UTC"
    return s


UTC_NEL_TESTO = re.compile(r"(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(?:\.\d+)? UTC\b(?![+-]\d)")


def testo_fuso(case, tz, s):
    """(3.0.4) Orari scritti in un testo con la sigla UTC ('2024-03-01 10:00:00 UTC', come nei Dettagli degli
    artefatti) nel fuso scelto, con la sigla. Si convertono solo quelli marcati UTC: gli altri restano come sono."""
    z = tz_zone(case, tz)
    if not isinstance(s, str) or not s or z == "UTC":
        return s
    return UTC_NEL_TESTO.sub(lambda m: to_zone(f"{m.group(1)}T{m.group(2)}", z, " ", tag=True), s)


DATA_CON_SIGLA = re.compile(r"(\d{4})-(\d\d)-(\d\d)(?=[ T]\d\d:\d\d:\d\d(?:\.\d+)? (?:\(?(?:UTC|CES?T)\b|\((?:ora locale|local time)\b))")
MESI_BREVI = {"it": "gen feb mar apr mag giu lug ago set ott nov dic", "en": "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec"}


def data_fmt(s, dfmt):
    """(3.0.4) Formato della data scelto nell'interfaccia («gma» 31/01/2024, «mga» 01/31/2024, «esteso» 31 gen 2024)
    applicato alle date che il server scrive con la sigla del fuso (anteprime, metadati): prima restavano in ISO."""
    if not isinstance(s, str) or dfmt not in ("gma", "mga", "esteso"):
        return s

    def f(m):
        a, me, g = m.groups()
        if dfmt == "gma":
            return f"{g}/{me}/{a}"
        if dfmt == "mga":
            return f"{me}/{g}/{a}"
        import forense_lingua as lg
        mesi = MESI_BREVI.get(lg.lingua(), MESI_BREVI["it"]).split()
        return f"{int(g)} {mesi[int(me) - 1]} {a}" if 1 <= int(me) <= 12 else m.group(0)
    return DATA_CON_SIGLA.sub(f, s)


def date_vista(r, b):
    """(3.0.4) Risposta di anteprima o metadati con le date nel formato scelto (b["dfmt"]). Il contenuto dei file non
    si tocca: solo le schede composte dal server (artefatti, intestazioni della posta, metadati)."""
    f = (b or {}).get("dfmt")
    if f not in ("gma", "mga", "esteso") or not isinstance(r, dict):
        return r
    for k, v in list(r.items()):
        if k == "head" and isinstance(v, dict):
            r[k] = {a: data_fmt(x, f) for a, x in v.items()}
        elif isinstance(v, str) and k in ("istat", "exif") or (k == "html" and r.get("source") == "art"):
            r[k] = data_fmt(v, f)
    return r


ISTAT_TS = re.compile(r"(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)(\.\d+)? \(([^)\s]{1,12})\)")


def _istat_walk(case, text, fn):
    """Applica fn(utc_naive, frazione, originale) a ogni orario dell'istat di Sleuth Kit. Sleuth Kit li stampa nel fuso
    del dispositivo (-z): ogni orario si riporta all'istante assoluto (la sigla che stampa distingue le due ore
    dell'ora doppia). Restituisce (testo, n. convertiti, fuso del dispositivo) oppure (testo, 0, None) se il fuso non è
    registrato (casi preparati prima della 2.13.7)."""
    import datetime as _dt
    dev = (case.meta.get("fuso_dispositivo") or {}).get("tz")
    if not dev or (dev not in ("UTC", "Europe/Rome") and _zone_obj(dev) is None):
        return text, 0, None
    devo = _ROME if dev == "Europe/Rome" else (None if dev == "UTC" else _zone_obj(dev))
    n = [0]

    def conv(m):
        try:
            naive = _dt.datetime.fromisoformat(m.group(1) + " " + m.group(2))
            if devo is None:
                aware = naive.replace(tzinfo=_dt.timezone.utc)
            else:
                aware = None
                for fold in (0, 1):
                    c = naive.replace(tzinfo=devo, fold=fold)
                    if c.tzname() == m.group(4):
                        aware = c
                        break
                if aware is None:
                    aware = naive.replace(tzinfo=devo)
            utc = aware.astimezone(_dt.timezone.utc).replace(tzinfo=None)
            r = fn(utc, m.group(3) or "", m.group(0))
        except (ValueError, OverflowError):
            return m.group(0)
        n[0] += 1
        return r
    return ISTAT_TS.sub(conv, text), n[0], dev


NO_DEV_NOTE = N_("Caso preparato prima della 2.13.7: Sleuth Kit ha scritto gli orari nel fuso del computer usato per "
               "l'analisi, che non è registrato. Gli orari qui sotto NON sono stati convertiti.")


def istat_to_zone(case, text, tz):
    """Orari dell'istat nel fuso scelto, con la sigla. Restituisce (testo, nota)."""
    zone = tz_zone(case, tz)

    def f(utc, frac, orig):
        loc = _zone_dt(utc, zone)
        return f"{loc:%Y-%m-%d %H:%M:%S}{frac} ({_off_tag(zone, (loc - utc).total_seconds())})"
    out, n, dev = _istat_walk(case, text, f)
    if dev is None:
        return text, tr(NO_DEV_NOTE)
    return out, (tr("Orari del file system (Sleuth Kit) scritti in: {v1}. Sleuth Kit li ha letti nel fuso del "
                    "dispositivo ({dev}); NTFS/ext/HFS memorizzano UTC, FAT/exFAT memorizzano l'ora locale del "
                    "dispositivo. Orari convertiti: {n}.").format(v1=tz_label(case, tz), dev=dev, n=n))


TOK_A, TOK_B = "\u27e6", "\u27e7"


def istat_tokens(case, text):
    """Per il report portatile: ogni orario diventa ⟦AAAA-MM-GGTHH:MM:SS[.frazione]⟧ in UTC, che il browser riscrive
    nel fuso scelto. Con APFS (già UTC) vale lo stesso. Restituisce il testo (con una riga di avviso se il fuso del
    dispositivo non è registrato)."""
    out, n, dev = _istat_walk(case, text, lambda u, fr, o: f"{TOK_A}{u:%Y-%m-%dT%H:%M:%S}{fr}{TOK_B}")
    if dev is None:
        return tr(NO_DEV_NOTE) + "\n\n" + text
    return out


def apfs_istat_tokens(text):
    return re.sub(r"(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)(\.\d+)? UTC",
                  lambda m: f"{TOK_A}{m.group(1)}T{m.group(2)}{m.group(3) or ''}{TOK_B}", text)


def apfs_istat_to_zone(case, text, tz):
    """Date dell'istat APFS (sempre UTC, con nanosecondi) nel fuso scelto."""
    zone = tz_zone(case, tz)
    n = [0]

    def conv(m):
        r = to_zone(f"{m.group(1)}T{m.group(2)}", zone, " ", tag=True)
        n[0] += 1
        return r.replace(" ", " ", 1).rsplit(" ", 1)[0] + (m.group(3) or "") + " " + r.rsplit(" ", 1)[1]
    out = re.sub(r"(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)(\.\d+)? UTC", conv, text)
    out = out.replace(tr("Date (UTC):"), tr("Date ({v1}):").format(v1=tz_label(case, tz)))
    return out, (tr("Orari APFS scritti in: {v1} (APFS memorizza UTC). Orari convertiti: {v2}.").format(v1=tz_label(case, tz), v2=n[0]))


_EXIF_DT = re.compile(r"^(\d{4}):(\d\d):(\d\d) (\d\d:\d\d:\d\d)(\.\d+)?\s*(Z|[+-]\d\d:?\d\d)?$")


def exif_to_zone(case, text, tz):
    """Date di exiftool: restano come scritte nel file; accanto a quelle che hanno il fuso (o sono UTC per
    specifica, QuickTime) si aggiunge l'orario nel fuso scelto, per le altre si dice che il fuso non c'è."""
    import datetime as _dt
    zone = tz_zone(case, tz)
    out = []
    offs = {}       # scostamenti dichiarati a parte (OffsetTime*) per lo stesso gruppo
    for l in text.splitlines():
        m = re.match(r"^\[(\w+)\]\s+(OffsetTime\w*)\s*:\s*([+-]\d\d:?\d\d|Z)\s*$", l)
        if m:
            offs[(m.group(1), m.group(2))] = m.group(3)
    pair = {"DateTimeOriginal": "OffsetTimeOriginal", "CreateDate": "OffsetTimeDigitized", "ModifyDate": "OffsetTime"}
    for l in text.splitlines():
        m = re.match(r"^(\[(\w+)\]\s+)(\w*(?:Date|Time)\w*)(\s*:\s*)(.*?)\s*$", l)
        d = _EXIF_DT.match(m.group(5)) if m else None
        if not d or m.group(3).startswith("GPS") and "Stamp" in m.group(3):
            out.append(l)
            continue
        off = d.group(6)
        sep_off = None
        if not off and (m.group(2), pair.get(m.group(3), "")) in offs:
            off = sep_off = offs[(m.group(2), pair[m.group(3)])]
        if not off and m.group(2) == "QuickTime":
            off = "Z"
        try:
            if off:
                dt = _dt.datetime(int(d.group(1)), int(d.group(2)), int(d.group(3)), *map(int, d.group(4).split(":")))
                if off != "Z":
                    o = re.match(r"([+-])(\d\d):?(\d\d)", off)
                    dt -= (1 if o.group(1) == "+" else -1) * _dt.timedelta(hours=int(o.group(2)), minutes=int(o.group(3)))
                loc = _zone_dt(dt, zone)
                out.append(l + f"   → {loc:%Y-%m-%d %H:%M:%S} {_off_tag(zone, (loc - dt).total_seconds())}"
                           + (f"  [fuso da {pair[m.group(3)]}]" if sep_off else tr("  [UTC per specifica QuickTime]") if not d.group(6) else ""))
            else:
                out.append(l + tr("   [fuso non indicato nel file: ora locale del dispositivo]"))
        except (ValueError, OverflowError):
            out.append(l)
    return "\n".join(out) + ("\n" if out else "")


_WORKCOPY_TAGS = ("FileModifyDate", "FileAccessDate", "FileInodeChangeDate", "FileCreateDate", "FileName",
                  "Directory", "FilePermissions")


def exif_no_workcopy(text):
    """Toglie da exiftool i campi del file system della COPIA DI LAVORO (data di estrazione, cartella temporanea,
    permessi): non sono dati della prova e porterebbero la data di oggi nel fuso del computer."""
    keep = []
    for l in text.splitlines():
        m = re.match(r"\[(?:File|System)\]\s+(\w+)\s*:", l)
        if m and m.group(1) in _WORKCOPY_TAGS:
            continue
        keep.append(l)
    return "\n".join(keep) + ("\n" if keep else "")


def taken_tz_text(s):
    """Fuso della data dei metadati: quello scritto nel file oppure 'non indicato (ora locale del dispositivo)'."""
    s = str(s or "").strip()
    if not s:
        return ""
    m = re.search(r"(Z|[+-]\d\d:?\d\d)$", s)
    if not m:
        return tr("non indicato (ora locale del dispositivo)")
    return "UTC" if m.group(1) == "Z" else m.group(1)


def tl_e_preferiti(q):
    o = str(q.get("origin") or "")
    return o == "preferiti" or o.startswith("bm:")


def tl_evidenze_sql(q, con):
    """(3.0) Evidenze come fonte della Timeline: «ev:[categoria, gruppo, voce]» dagli artefatti (chiamate, iLEAPP/ALEAPP...),
    «msg:app» dai messaggi delle chat. Solo le righe con una data; il filtro non legge né cambia altro."""
    import forense_mobile_chat as fmc
    o, w, a = str(q.get("origin") or ""), [], []
    if o.startswith("msg:"):
        chi = "COALESCE(NULLIF(m.sender_name, ''), m.sender, '')"
        etichette = " ".join(f"WHEN {_sql_lit(k)} THEN {_sql_lit(tr(v))}" for k, v in fmc.APP_LBL.items())
        spec = {"ts": ("m.ts", "d"),
                "kind": (f"CASE WHEN m.direction = 'out' THEN {_sql_lit(tr('messaggio inviato'))} ELSE {_sql_lit(tr('messaggio'))} END", "t"),
                "source": (f"CASE m.app {etichette} ELSE m.app END", "t"),
                "detail": (f"rtrim(COALESCE(NULLIF(t.title, '') || ' · ', '') || COALESCE(NULLIF({chi}, '') || ' · ', '') || substr(COALESCE(m.text, ''), 1, 400), ' ·')", "t")}
        sql = ("SELECT m.id, m.ts, COALESCE(NULLIF(m.sender_name, ''), m.sender, ''), COALESCE(m.text, ''), t.src_path, m.part, m.inode, m.direction, m.app, t.title, m.thread "
               "FROM chat_messages m LEFT JOIN chat_threads t ON t.id = m.thread")
        tc, cols = "m.ts", "m.text"
        if o[4:]:
            w.append("m.app = ?"); a.append(o[4:])
        testo = "(m.text LIKE ? ESCAPE '\\' OR m.sender_name LIKE ? ESCAPE '\\' OR t.title LIKE ? ESCAPE '\\')"
    else:
        # gruppo e voce esistono solo negli artefatti degli smartphone
        grp, sub = ("grp", "sub") if "grp" in {r[1] for r in con.execute("PRAGMA table_info(artifacts)")} else ("NULL", "NULL")
        sql = f"SELECT id, ts, title, COALESCE(detail, ''), src_path, part, inode, cat, {grp}, {sub} FROM artifacts"
        spec = {"ts": ("ts", "d"), "kind": (f"COALESCE(NULLIF({sub}, ''), NULLIF({grp}, ''), cat)", "t"),
                "source": (f"COALESCE(NULLIF({grp}, ''), cat)", "t"),
                "detail": ("rtrim(COALESCE(NULLIF(title, '') || ' · ', '') || substr(COALESCE(detail, ''), 1, 400), ' ·')", "t")}
        tc = "ts"
        try:
            sc = json.loads(o[3:] or "[]")
        except ValueError:
            sc = []
        for col, v in zip(("cat", "grp", "sub"), sc):
            if v not in (None, ""):
                w.append(f"{col} = ?"); a.append(v)
        if not sc:
            w.append("cat <> 'messaggi'")
        testo = "(title LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\' OR src_path LIKE ? ESCAPE '\\')"
    w.append(f"{tc} GLOB '[0-9][0-9][0-9][0-9]-*'")
    # testi lunghi: l'elenco e la scelta usano i primi 200 caratteri (oltre, cf_values li toglierebbe); la ricerca legge tutto
    q["_cfsel"] = {"detail": f"substr({spec['detail'][0]}, 1, 200)"}
    cf_apply(q, spec, w, a)
    t = (q.get("q") or "").strip()
    if t:
        w.append(testo); a += [fa.like(t)] * 3
    if q.get("start"):
        w.append(f"{tc} >= ?"); a.append(q["start"])
    if q.get("end"):
        e = q["end"]
        if "T" not in e:
            e += {4: "-12-31T23:59:59", 7: "-31T23:59:59"}.get(len(e), "T23:59:59")
        w.append(f"{tc} <= ?"); a.append(e)
    return sql, " WHERE " + " AND ".join(w), a, tc


def tl_evidenze_pagina(case, q, ids, off, limit):
    import forense_mobile_chat as fmc
    msg = str(q.get("origin") or "").startswith("msg:")
    idc = "m.id" if msg else "id"
    con = fa.db_ro(case)
    try:
        sql, cond, a, tc = tl_evidenze_sql(q, con)
        if q.get("cfv"):
            cf_values(con, q, sql.split(" FROM ", 1)[1], [cond[len(" WHERE "):]], a)
        if ids is not None:
            vuoi = [int(x) for x in ids if str(x).lstrip("-").isdigit()]
            cond += f" AND {idc} IN ({','.join('?' * len(vuoi)) or 'NULL'})"
            a = a + vuoi
        tab = sql.split(" FROM ", 1)[1]
        total = con.execute(f"SELECT COUNT(*) FROM {tab}{cond}", a).fetchone()[0]
        ordine = "DESC" if q.get("sd") == "desc" else "ASC"
        lim = f" LIMIT {int(limit)} OFFSET {int(off)}" if limit else ""
        righe = con.execute(f"{sql}{cond} ORDER BY {cf_order(q, f'{tc} {ordine}')}{lim}", a).fetchall()
    finally:
        con.close()
    out = []
    for r in righe:
        if msg:
            rid, ts, chi, testo, src, part, inode, verso, app, titolo, thread = r
            out.append({"id": rid, "ts": ts, "kind": tr("messaggio inviato") if verso == "out" else tr("messaggio"), "source": tr(fmc.APP_LBL.get(app, app)), "path": src, "chat": thread,
                        "message": " · ".join(x for x in (titolo, chi, (testo or "")[:400]) if x), "origin": "evidenze", "part": part, "inode": None})
        else:
            rid, ts, titolo, det, src, part, inode, cat, grp, sub = r
            out.append({"id": rid, "ts": ts, "kind": sub or grp or cat, "source": grp or cat, "path": src,
                        "message": " · ".join(x for x in (titolo, (det or "")[:400]) if x), "origin": "evidenze", "part": part, "inode": None})
    return {"kind": "timeline", "total": total, "offset": off, "page": PAGE, "rows": out}


def tl_hist_da(ks, gran, **extra):
    """Grafico da un elenco di date già nel fuso scelto."""
    if gran == "auto":
        import datetime as _dt
        giorni = sorted(k[:10] for k in ks)
        try:
            span = (_dt.date.fromisoformat(giorni[-1]) - _dt.date.fromisoformat(giorni[0])).days if giorni else 0
        except ValueError:
            span = 10 ** 6
        gran = "day" if span <= 400 else "month" if len({k[:7] for k in ks}) <= 400 else "year"
    n = {"day": 10, "month": 7, "year": 4}[gran]
    tot = {}
    for k in ks:
        tot[k[:n]] = tot.get(k[:n], 0) + 1
    return {"gran": gran, **extra, "bins": [{"k": k, "n": v, "M": 0, "A": 0, "C": 0, "B": 0, "plaso": 0} for k, v in sorted(tot.items())]}


def tl_hist_evidenze(case, q):
    con = fa.db_ro(case)
    try:
        sql, cond, a, tc = tl_evidenze_sql(q, con)
        ts = [r[0] for r in con.execute(f"SELECT {tc} FROM {sql.split(' FROM ', 1)[1]}{cond}", a)]
    finally:
        con.close()
    zone = tz_zone(case, q.get("tz"))
    return tl_hist_da([(to_zone(x, zone) if zone != "UTC" else x) or x for x in ts], q.get("gran") or "auto", evidenze=True)


def tl_preferito_campi(x):
    """Il testo delle colonne di un preferito nella Timeline, uguale a quello mostrato."""
    return {"kind": x["evento"] or "", "source": ", ".join(x["categorie"]), "detail": x["note"] or x["name"] or ""}


def tl_preferiti_cf(righe, q):
    """Filtri di colonna sui preferiti, con le regole di cf_apply; il filtro della colonna di q["cfv"] è escluso."""
    for key, v in list(cf_parse(q).items())[:16]:
        if not isinstance(v, dict) or key == q.get("cfv"):
            continue
        if key == "ts":
            lo, hi = str(v.get("from") or "")[:19], str(v.get("to") or "")[:19]
            hi += "T23:59:59" if len(hi) == 10 else ""
            righe = [x for x in righe if (not lo or x["ts"] >= lo) and (not hi or x["ts"] <= hi)]
        elif key in ("kind", "source", "detail"):
            sel = v.get("sel")
            if isinstance(sel, list) and sel:
                vuoi = {str(y) for y in sel[:500]}
                righe = [x for x in righe if tl_preferito_campi(x)[key][:200] in vuoi]
            for neg, term in cf_terms(str(v.get("v") or "")[:300]):
                righe = [x for x in righe if (term.lower() in tl_preferito_campi(x)[key].lower()) != neg]
    return righe


def tl_preferiti_valori(righe, k):
    if k not in ("kind", "source", "detail"):
        raise CfValues([])
    tot = {}
    for x in righe:
        v = tl_preferito_campi(x)[k][:200]
        tot[v] = tot.get(v, 0) + 1
    raise CfValues(sorted(tot.items(), key=lambda r: (-r[1], r[0].lower()))[:301])


def tl_preferiti(case, q):
    """(3.0) I preferiti con una data come fonte della Timeline, con i filtri di testo e periodo: (righe, senza data)."""
    righe = fa.bookmarks_timeline(case, False)
    o = str(q.get("origin") or "")
    if o.startswith("bm:"):          # un solo gruppo di preferiti
        righe = [x for x in righe if o[3:] in x["categorie"]]
    con_data = [x for x in righe if x["ts"]]
    t = (q.get("q") or "").strip().lower()
    if t:
        con_data = [x for x in con_data if t in " ".join(str(x.get(k) or "") for k in ("path", "name", "note")).lower()
                    or any(t in c.lower() for c in x["categorie"])]
    if q.get("start"):
        con_data = [x for x in con_data if x["ts"] >= q["start"]]
    if q.get("end"):
        e = q["end"]
        if "T" not in e:
            e += {4: "-12-31T23:59:59", 7: "-31T23:59:59"}.get(len(e), "T23:59:59")
        con_data = [x for x in con_data if x["ts"] <= e]
    con_data = tl_preferiti_cf(con_data, q)
    return con_data, len(righe) - sum(1 for x in righe if x["ts"])


def tl_hist_preferiti(case, q):
    righe, senza = tl_preferiti(case, q)
    zone = tz_zone(case, q.get("tz"))
    ks = [(to_zone(x["ts"], zone) if zone != "UTC" else x["ts"]) or x["ts"] for x in righe]
    return tl_hist_da(ks, q.get("gran") or "auto", preferiti=True, senza_data=senza)


def tl_hist(case, q):
    """Eventi per giorno (o mese/anno) con gli stessi filtri della tabella."""
    if str(q.get("origin") or "")[:3] in ("ev:", "msg"):
        return tl_hist_evidenze(case, q)
    if tl_e_preferiti(q):
        return tl_hist_preferiti(case, q)
    gran = q.get("gran") or "auto"
    w, a = [], []
    tl_where(q, w, a)
    cond = (" WHERE " + " AND ".join(w)) if w else ""
    con = fa.db_ro(case)
    zone = tz_zone(case, q.get("tz"))
    try:
        if zone != "UTC":
            # (2.20) giorni e mesi nel fuso scelto: prima i conteggi per MINUTO in UTC (SQL), poi ogni minuto nel fuso
            # (i cambi di fuso cadono sempre al minuto); prima ogni evento passava da Python: 2,5 milioni di eventi
            # (iPhone di prova) 38 s, ora ~2 s, stessi risultati. Le date non standard restano come sono (come to_zone).
            std = "ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][T ][0-9][0-9]:[0-9][0-9]:[0-9][0-9]'"
            agg = con.execute(f"SELECT CASE WHEN {std} THEN substr(ts,1,16) ELSE ts END m, {std}, COUNT(*), "
                              f"SUM(kind='M'), SUM(kind='A'), SUM(kind='C'), SUM(kind='B'), SUM(origin='plaso') "
                              f"FROM events{cond} GROUP BY m, 2", a).fetchall()
            loc = [((to_zone(m + ":00", zone) if s_ else to_zone(m, zone)) if m is not None else None, v)
                   for m, s_, *v in agg]
            if gran == "auto":
                ks = [k for k, _v in loc if k]
                lo, hi = (min(k[:10] for k in ks), max(k[:10] for k in ks)) if ks else (None, None)
                nm = len({k[:7] for k in ks})
                span = 0
                if lo and hi:
                    import datetime as _dt
                    try:
                        span = (_dt.date.fromisoformat(hi) - _dt.date.fromisoformat(lo)).days
                    except ValueError:
                        span = 10 ** 6
                gran = "day" if span <= 400 else "month" if nm <= 400 else "year"
            n = {"day": 10, "month": 7, "year": 4}[gran]
            tot = {}
            for k, v in loc:
                k = k[:n] if isinstance(k, str) else k
                cur = tot.setdefault(k, [0] * 6)
                for i, x in enumerate(v):
                    cur[i] += x or 0
            rows = [(k, *v) for k, v in sorted(tot.items(), key=lambda kv: (kv[0] is not None, kv[0] or ""))]
        else:
            tsx = "ts"
            if gran == "auto":
                # giorni se il periodo è breve, poi mesi, poi anni (date anomale molto lontane)
                lo, hi, nm = con.execute(f"SELECT MIN(substr({tsx},1,10)), MAX(substr({tsx},1,10)), "
                                         f"COUNT(DISTINCT substr({tsx},1,7)) FROM events{cond}",
                                         a).fetchone()
                span = 0
                if lo and hi:
                    import datetime as _dt
                    try:
                        span = (_dt.date.fromisoformat(hi) - _dt.date.fromisoformat(lo)).days
                    except ValueError:
                        span = 10 ** 6
                gran = "day" if span <= 400 else "month" if nm <= 400 else "year"
            n = {"day": 10, "month": 7, "year": 4}[gran]
            rows = con.execute(
                f"SELECT substr({tsx},1,{n}) k, COUNT(*), SUM(kind='M'), SUM(kind='A'), SUM(kind='C'), "
                f"SUM(kind='B'), SUM(origin='plaso') FROM events{cond} GROUP BY k ORDER BY k",
                a).fetchall()
    finally:
        con.close()
    return {"gran": gran, "bins": [{"k": k, "n": t, "M": m, "A": ac, "C": c, "B": b, "plaso": p}
                                   for k, t, m, ac, c, b, p in rows if k]}
