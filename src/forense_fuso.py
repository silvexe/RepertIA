#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - fuso orario del caso: rilevamento, conversioni, date dei file system FAT.

(3.0.4) Codice spostato da forense_agent.py senza modifiche, per avere file più corti. Si carica tramite
forense_agent, che ne riesporta i nomi: gli altri moduli continuano a usare «fa.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fa.<nome>»).
"""
import datetime as dt
import os
import plistlib
import re
import sqlite3
from pathlib import Path
from forense_lingua import tr
import forense_apfs as ap

import forense_agent as fa
from forense_agent import (
    IS_WIN, catena_exfat_lettore, dec, tsk_timeline)

FUSO_PREDEFINITO = "Europe/Rome"


def fuso_valido(nome):
    """Nome IANA del fuso (es. Europe/Rome) se riconosciuto, altrimenti None."""
    nome = str(nome or "").strip()
    if not nome or len(nome) > 64 or not re.fullmatch(r"[A-Za-z0-9_+\-]+(/[A-Za-z0-9_+\-]+){0,2}", nome):
        return None
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(nome)
    except Exception:
        try:                # il database dei fusi c'è e il nome non esiste: respinto
            ZoneInfo("Europe/Rome")
            return None
        except Exception:   # senza database (es. Windows senza tzdata) basta il nome plausibile
            return nome if nome == "UTC" or "/" in nome else None
    return nome


TSK_FUSO_NEUTRO = "UTC0"
TSK_FUSO_MARCA = "TZ=UTC0"     # caso preparato con il fuso neutro nell'ambiente (2.16.1)


def _zona_dispositivo(case):
    """ZoneInfo del fuso del dispositivo registrato nel caso (None se non registrato o senza database dei fusi)."""
    z = (case.meta.get("fuso_dispositivo") or {}).get("tz")
    if not z:
        return None
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(z)
    except Exception:
        return None


def tsk_tz(case):
    """Fuso per Sleuth Kit (serve per le date di FAT/exFAT, che sono ora locale senza fuso: senza indicazioni
    Sleuth Kit userebbe il fuso del PC dell'analista). Nei casi preparati prima della 2.13.7 il fuso non è registrato
    e non si passa nulla (i dati restano coerenti).
    Sleuth Kit lavora con il fuso neutro «UTC0» (ora scritta sul disco riportata così com'è) e la conversione nel fuso
    del dispositivo la fa Python (zoneinfo: `tsk_epoch`, `istat_zona`). Il fuso neutro va nella variabile d'ambiente TZ
    del processo (`tsk_env`), NON con «-z»: in fls/istat 4.x «-z» passa a putenv un buffer locale che poi viene
    sovrascritto; su macOS il fuso viene riletto più tardi e Sleuth Kit ricade sul fuso del computer (collaudo DFTT 5
    del 20/10/2026). Su Windows (runtime Microsoft, TZ letto subito) «-z UTC0» funziona e si passa anche quello.
    Restituisce gli argomenti da aggiungere al comando; se manca il database dei fusi si usa «-z <nome del fuso>»."""
    z = (case.meta.get("fuso_dispositivo") or {}).get("tz")
    if not z:
        return []
    if not tsk_neutro(case):
        return ["-z", z]
    return ["-z", TSK_FUSO_NEUTRO] if IS_WIN else []


TSK_TZ_TOOLS = {"fls", "istat", "ils", "ifind", "ffind", "mactime", "fsstat", "blkls", "blkcat", "icat", "tsk_gettimes"}


def tsk_env(case, cmd):
    """Ambiente del processo per i comandi di Sleuth Kit: TZ=UTC0 quando si lavora con il fuso neutro."""
    try:
        name = Path(str(cmd[0])).stem.lower()
    except (IndexError, TypeError):
        return None
    if name not in TSK_TZ_TOOLS or not tsk_neutro(case):
        return None
    return dict(os.environ, TZ=TSK_FUSO_NEUTRO)


def tsk_neutro(case):
    """True se Sleuth Kit lavora con il fuso neutro (le date FAT vanno convertite da Python): il caso ha il fuso del
    dispositivo e il database dei fusi è disponibile."""
    z = (case.meta.get("fuso_dispositivo") or {}).get("tz")
    return bool(z) and (z == "UTC" or _zona_dispositivo(case) is not None)


def part_is_fat(case, offset):
    """La partizione è FAT/exFAT (date memorizzate come ora locale del dispositivo, senza fuso)?"""
    for p in case.meta.get("partitions", []):
        if str(p.get("offset")) == str(offset):
            return "fat" in (p.get("fs") or "").lower()
    return False


def _locale_a_utc(naive, zona):
    """Ora locale del dispositivo (senza fuso) → istante UTC. Ora doppia (fine dell'ora legale): la FAT non dice quale
    delle due; si prende la prima (fold=0), come fa zoneinfo. Ora che non esiste (inizio dell'ora legale): scostamento
    in vigore prima del cambio."""
    return naive.replace(tzinfo=zona, fold=0).astimezone(dt.timezone.utc)


def tsk_epoch(case, t, fat):
    """Data di `fls -m` (secondi) all'istante reale. Con il fuso neutro le date FAT/exFAT sono l'ora del disco letta
    come UTC: si riportano all'ora locale del dispositivo. Le altre (NTFS, ext, HFS) sono già UTC."""
    if not fat or not tsk_neutro(case):
        return t
    z = _zona_dispositivo(case)
    if z is None:
        return t
    naive = dt.datetime.fromtimestamp(t, dt.timezone.utc).replace(tzinfo=None)
    return int(_locale_a_utc(naive, z).timestamp())


_ISTAT_UTC = re.compile(r"(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)(\.\d+)? \((UTC|GMT)\)")


def istat_zona(case, offset, text, inode=None):
    """Testo di `istat` letto con il fuso neutro → orari nel fuso del dispositivo con la sigla (CET/CEST, …), cioè
    lo stesso testo che Sleuth Kit scrive su Mac/Linux con «-z <fuso>». FAT/exFAT: l'ora è quella del disco (ora
    locale del dispositivo); gli altri file system: istante UTC convertito. (3.0.2) exFAT con lo scostamento UTC
    scritto nella voce (vedi CatenaExfat.scostamenti): istante = ora del disco meno lo scostamento."""
    if not text or not tsk_neutro(case):
        return text
    z = _zona_dispositivo(case)
    if z is None:
        return text
    fat = part_is_fat(case, offset)
    sc = None
    if fat and inode is not None:
        try:
            xf = catena_exfat_lettore(case, offset)
            sc = xf.scostamenti(str(inode).split("-")[0]) if xf else None
        except Exception:
            sc = None
    righe = []
    for riga in text.split("\n"):
        k = "M" if riga.startswith("Written:") else "A" if riga.startswith("Accessed:") else \
            "B" if riga.startswith("Created:") else None
        s = sc.get(k) if sc and k else None

        def conv(m, s=s):
            try:
                naive = dt.datetime.fromisoformat(m.group(1) + " " + m.group(2))
                if s is not None:
                    loc = (naive.replace(tzinfo=dt.timezone.utc) - dt.timedelta(seconds=s)).astimezone(z)
                else:
                    loc = (_locale_a_utc(naive, z) if fat else naive.replace(tzinfo=dt.timezone.utc)).astimezone(z)
            except (ValueError, OverflowError):
                return m.group(0)
            return f"{loc:%Y-%m-%d %H:%M:%S}{m.group(3) or ''} ({loc.tzname()})"
        righe.append(_ISTAT_UTC.sub(conv, riga))
    return "\n".join(righe)


def ripara_date_fat(case):
    """Ricalcola le date FAT/exFAT della timeline (solo eventi di Sleuth Kit delle partizioni FAT/exFAT) nei casi
    preparati prima della 2.16.1, quando il fuso arrivava a Sleuth Kit con «-z»: su Windows (2.13.7-2.15.2) il nome
    del fuso non veniva capito, su Mac l'opzione veniva persa (vedi `tsk_tz`). Lo scrive nel registro. Ritorna True
    se ha ricalcolato."""
    m = case.meta
    if m.get("tsk_fuso") == TSK_FUSO_MARCA or not (m.get("fuso_dispositivo") or {}).get("tz"):
        return False
    if not tsk_neutro(case) or not case.db_path.exists():
        return False
    fat = [p for p in m.get("partitions", []) if p.get("readable") and not ap.is_apfs_part(p["offset"])
           and "fat" in (p.get("fs") or "").lower()]
    if not fat:
        m["tsk_fuso"] = TSK_FUSO_MARCA      # niente da ricalcolare: non ricontrollare a ogni apertura
        case.save()
        return False
    print(tr("Date FAT/exFAT: il caso è stato preparato con una versione che passava il fuso a Sleuth Kit in un modo non "
          "affidabile su tutti i sistemi; le ricalcolo."), flush=True)
    con = sqlite3.connect(case.db_path)
    try:
        rifai_timeline_fuso(case, con)
    finally:
        con.close()
    m["tsk_fuso"] = TSK_FUSO_MARCA
    case.log("date_fat_ricalcolate", {"motivo": tr("fuso passato a Sleuth Kit con -z (versioni fino alla 2.16.0)"),
                                      "partizioni": [p["offset"] for p in fat], "fuso": m["fuso_dispositivo"]["tz"]})
    case.save()
    return True


def fuso_testo(m):
    """Descrizione del fuso del dispositivo per report e interfaccia."""
    f = m.get("fuso_dispositivo") or {}
    if f.get("tz"):
        st = fuso_stato_testo(m)
        return f"{f['tz']} ({st or f.get('origine') or tr('scelto dall' + chr(39) + 'operatore')})"
    return None


WIN_TZ = {
    "Dateline Standard Time": "Etc/GMT+12", "UTC-11": "Etc/GMT+11", "Hawaiian Standard Time": "Pacific/Honolulu",
    "Alaskan Standard Time": "America/Anchorage", "Pacific Standard Time": "America/Los_Angeles",
    "Mountain Standard Time": "America/Denver", "US Mountain Standard Time": "America/Phoenix",
    "Central Standard Time": "America/Chicago", "Canada Central Standard Time": "America/Regina",
    "Central America Standard Time": "America/Guatemala", "Mexico Standard Time": "America/Mexico_City",
    "Eastern Standard Time": "America/New_York", "US Eastern Standard Time": "America/Indiana/Indianapolis",
    "SA Pacific Standard Time": "America/Bogota", "Atlantic Standard Time": "America/Halifax",
    "Venezuela Standard Time": "America/Caracas", "SA Western Standard Time": "America/La_Paz",
    "Pacific SA Standard Time": "America/Santiago", "Newfoundland Standard Time": "America/St_Johns",
    "E. South America Standard Time": "America/Sao_Paulo", "Argentina Standard Time": "America/Argentina/Buenos_Aires",
    "SA Eastern Standard Time": "America/Cayenne", "Greenland Standard Time": "America/Nuuk",
    "Azores Standard Time": "Atlantic/Azores", "Cape Verde Standard Time": "Atlantic/Cape_Verde",
    "UTC": "UTC", "GMT Standard Time": "Europe/London", "Greenwich Standard Time": "Atlantic/Reykjavik",
    "Morocco Standard Time": "Africa/Casablanca",
    # stesse regole di Roma, Berlino, Parigi, Madrid, Amsterdam, Vienna, Zurigo, Stoccolma, Oslo...
    "W. Europe Standard Time": "Europe/Rome", "Central Europe Standard Time": "Europe/Budapest",
    "Romance Standard Time": "Europe/Paris", "Central European Standard Time": "Europe/Warsaw",
    "W. Central Africa Standard Time": "Africa/Lagos", "Namibia Standard Time": "Africa/Windhoek",
    "GTB Standard Time": "Europe/Bucharest", "Middle East Standard Time": "Asia/Beirut",
    "Egypt Standard Time": "Africa/Cairo", "E. Europe Standard Time": "Europe/Chisinau",
    "Syria Standard Time": "Asia/Damascus", "Israel Standard Time": "Asia/Jerusalem",
    "South Africa Standard Time": "Africa/Johannesburg", "FLE Standard Time": "Europe/Kyiv",
    "Turkey Standard Time": "Europe/Istanbul", "Jordan Standard Time": "Asia/Amman",
    "Arabic Standard Time": "Asia/Baghdad", "Kaliningrad Standard Time": "Europe/Kaliningrad",
    "Arab Standard Time": "Asia/Riyadh", "E. Africa Standard Time": "Africa/Nairobi",
    "Russian Standard Time": "Europe/Moscow", "Belarus Standard Time": "Europe/Minsk",
    "Iran Standard Time": "Asia/Tehran", "Arabian Standard Time": "Asia/Dubai",
    "Azerbaijan Standard Time": "Asia/Baku", "Georgian Standard Time": "Asia/Tbilisi",
    "Caucasus Standard Time": "Asia/Yerevan", "Afghanistan Standard Time": "Asia/Kabul",
    "Pakistan Standard Time": "Asia/Karachi", "West Asia Standard Time": "Asia/Tashkent",
    "India Standard Time": "Asia/Kolkata", "Sri Lanka Standard Time": "Asia/Colombo",
    "Nepal Standard Time": "Asia/Kathmandu", "Bangladesh Standard Time": "Asia/Dhaka",
    "Myanmar Standard Time": "Asia/Yangon", "SE Asia Standard Time": "Asia/Bangkok",
    "China Standard Time": "Asia/Shanghai", "Singapore Standard Time": "Asia/Singapore",
    "W. Australia Standard Time": "Australia/Perth", "Taipei Standard Time": "Asia/Taipei",
    "Tokyo Standard Time": "Asia/Tokyo", "Korea Standard Time": "Asia/Seoul",
    "Cen. Australia Standard Time": "Australia/Adelaide", "AUS Central Standard Time": "Australia/Darwin",
    "E. Australia Standard Time": "Australia/Brisbane", "AUS Eastern Standard Time": "Australia/Sydney",
    "West Pacific Standard Time": "Pacific/Port_Moresby", "Tasmania Standard Time": "Australia/Hobart",
    "New Zealand Standard Time": "Pacific/Auckland", "Fiji Standard Time": "Pacific/Fiji",
    "Tonga Standard Time": "Pacific/Tongatapu", "Samoa Standard Time": "Pacific/Apia",
}


def fuso_equivalenti(a, b):
    """True se i due fusi danno lo stesso scostamento dal UTC (con ora legale) in tutti i mesi dal 1996 al 2035:
    Roma e Berlino, per esempio, sono equivalenti."""
    if a == b:
        return True
    try:
        from zoneinfo import ZoneInfo
        za, zb = ZoneInfo(a), ZoneInfo(b)
    except Exception:
        return False
    for y in range(1996, 2036):
        for m in range(1, 13):
            t = dt.datetime(y, m, 15, 12, tzinfo=dt.timezone.utc)
            if t.astimezone(za).utcoffset() != t.astimezone(zb).utcoffset():
                return False
    return True


def _fuso_windows(case, off, ino):
    """Fuso dal registro di Windows (SYSTEM, TimeZoneInformation): {'tz', 'nome', 'fonte'} o None."""
    import forense_estesa as fe
    tmp = case.root / "tmp_fuso.hive"
    try:
        tmp.write_bytes(fa.icat_read(case, off, ino, 400 << 20))
        hv, root = fe.open_hive(tmp)
        try:
            cur = fe.rv(fe.rk(root, "Select"), "Current") or 1
            tzk = fe.rk(root, f"ControlSet{int(cur):03d}\\Control\\TimeZoneInformation")
            name = (fe.sz(fe.rv(tzk, "TimeZoneKeyName")) or fe.sz(fe.rv(tzk, "StandardName")) or "").strip()
        finally:
            hv.close()
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    if not name:
        return None
    z = fuso_valido(WIN_TZ.get(name))
    return {"tz": z, "nome": name, "fonte": tr("registro di Windows"),
            **({} if z else {"nota": tr("nome del fuso non riconosciuto")})}


def _fuso_linux(case, off, con):
    ino = fa.lookup(con, off, "etc/timezone")
    if ino:
        v = dec(fa.icat_read(case, off, ino, 256)).strip().splitlines()
        z = fuso_valido(v[0]) if v else None
        if z:
            return {"tz": z, "nome": z, "fonte": "/etc/timezone"}
    ino = fa.lookup(con, off, "etc/localtime")
    if ino:
        v = dec(fa.icat_read(case, off, ino, 512)).strip()
        m = re.search(r"zoneinfo/(.+)$", v)
        z = fuso_valido(m.group(1)) if m else None
        if z:
            return {"tz": z, "nome": z, "fonte": "/etc/localtime"}
    return None


def _fuso_mac(case, off, con):
    """macOS: /private/etc/localtime (collegamento a …/zoneinfo/<fuso>, sul volume Dati dei Mac recenti),
    altrimenti la città scelta in .GlobalPreferences.plist."""
    for pth in ("private/etc/localtime", "etc/localtime"):
        r = con.execute("SELECT inode FROM files WHERE part=? AND deleted=0 AND lower(path)=? LIMIT 1",
                        (off, pth)).fetchone()
        if not r:
            continue
        tgt = ap.link_target(case, off, r[0]) if ap.is_apfs_part(off) else dec(fa.icat_read(case, off, r[0], 512)).strip()
        m = re.search(r"zoneinfo/(.+)$", tgt or "")
        z = fuso_valido(m.group(1)) if m else None
        if z:
            return {"tz": z, "nome": z, "fonte": "/private/etc/localtime (macOS)"}
    ino = fa.lookup(con, off, "library/preferences/.globalpreferences.plist")
    if ino:
        try:
            d = plistlib.loads(fa.icat_read(case, off, ino, 4 << 20))
            city = d.get("com.apple.TimeZonePref.Last_Selected_City")
            z = fuso_valido(city[3]) if isinstance(city, list) and len(city) > 3 else None
            if z:
                return {"tz": z, "nome": z, "fonte": ".GlobalPreferences.plist (macOS)"}
        except Exception:
            pass
    return None


def rileva_fuso(case, readable, con):
    """Fuso orario del sistema installato sul disco (Windows: registro; Linux: /etc/timezone; macOS:
    /private/etc/localtime), se c'è. Le date APFS sono già assolute: per i Mac il fuso serve alla
    modalità «fuso del dispositivo» e alle date FAT/exFAT di eventuali altre partizioni."""
    for p in readable:
        off = p["offset"]
        try:
            if ap.is_apfs_part(off):
                r = _fuso_mac(case, off, con)
            else:
                ino = fa.lookup(con, off, "windows/system32/config/system")
                r = (_fuso_windows(case, off, ino) if ino else
                     _fuso_linux(case, off, con) or _fuso_mac(case, off, con))
        except Exception as e:      # libreria del registro assente o file illeggibile: nessuna rilevazione
            case.log("rileva_fuso_errore", f"{type(e).__name__}: {e}")
            r = None
        if r:
            r["partizione"] = off
            return r
    return None


def fuso_stato_testo(m):
    """Descrizione dello stato di verifica del fuso, per report e interfaccia."""
    f = m.get("fuso_dispositivo") or {}
    det = f.get("rilevato") or {}
    st = f.get("stato")
    nome = det.get("nome") or det.get("tz") or ""
    if st == "rilevato":
        return tr("rilevato dal sistema del disco ({v1}: {nome})").format(v1=det.get('fonte'), nome=nome)
    if st == "confermato":
        return tr("scelto dall'operatore e confermato dal sistema del disco ({v1}: {nome})").format(v1=det.get('fonte'), nome=nome)
    if st == "discordante":
        return (tr("ATTENZIONE: il sistema del disco indica {v1} ({v2}: {nome}), diverso dal fuso usato").format(v1=det.get('tz'), v2=det.get('fonte'), nome=nome))
    if st == "non_verificabile":
        return tr("NON VERIFICABILE: nessun sistema operativo da cui leggere il fuso; assunto il predefinito (Italia)")
    if st == "scelto_non_verificato":
        return tr("scelto dall'operatore, NON VERIFICABILE: nel disco non c'è un sistema da cui leggere il fuso")
    return f.get("origine") or ""


def cambia_fuso(case, tz):
    """Registra un nuovo fuso del dispositivo (scelto dall'operatore) mantenendo ciò che il sistema ha indicato."""
    fd = dict(case.meta.get("fuso_dispositivo") or {})
    det = fd.get("rilevato") or {}
    prima = fd.get("tz")
    fd["tz"], fd["origine"], fd["auto"] = tz, tr("corretto dall'operatore"), False
    fd["stato"] = ("confermato" if det.get("tz") and fuso_equivalenti(det["tz"], tz)
                   else "discordante" if det.get("tz") else "scelto_non_verificato")
    case.meta["fuso_dispositivo"] = fd
    case.log("fuso_dispositivo_cambiato", {"da": prima, "a": tz, "stato": fd["stato"]})
    case.save()


def rifai_timeline_fuso(case, con):
    """Ricalcola le date FAT/exFAT della timeline del file system con il fuso del dispositivo registrato nel caso."""
    n_fat = 0
    for p in case.meta.get("partitions", []):
        if not p.get("readable") or ap.is_apfs_part(p["offset"]) or "fat" not in (p.get("fs") or "").lower():
            continue
        print(tr("Fuso orario: ricalcolo le date FAT/exFAT della partizione all'offset {offset} con {tz}...").format(offset=p['offset'], tz=case.meta['fuso_dispositivo']['tz']), flush=True)
        con.execute("DELETE FROM events WHERE origin='tsk' AND part=?", (p["offset"],))
        con.commit()
        tsk_timeline(case, p["offset"], con)
        n_fat += 1
    tot = con.execute("SELECT COUNT(*) FROM events WHERE origin='tsk'").fetchone()[0]
    case.meta.setdefault("timeline", {})["tsk_events"] = tot
    if n_fat:
        try:
            (case.root / "navigazione.sqlite").unlink()  # indice di comodo: si ricostruisce con le date nuove
        except OSError:
            pass
    else:
        print(tr("Fuso orario: nessuna partizione FAT/exFAT nel caso, nessuna data da ricalcolare."), flush=True)
    est = case.meta.get("estese") or {}
    if case.meta.get("timeline", {}).get("plaso_events") or "artefatti" in est:
        print(tr("Fuso orario: plaso e gli artefatti di sistema (reti Windows) usano il fuso scelto solo se li "
              "rifai con «Rifai» dal pannello delle analisi."), flush=True)
    return True
