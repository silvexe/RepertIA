# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (2.20) – sysdiagnose di iOS acquisiti a parte.

Un sysdiagnose (`sysdiagnose_<data>_<ora><fuso>_<sistema>_<dispositivo>_<build>.tar.gz`) è un archivio di registri e
stati del sistema che l'iPhone produce su richiesta: elenco dei processi (ps.txt), spegnimenti, Wi-Fi, Bluetooth,
batteria, impostazioni gestite, registri unificati… Di solito si acquisisce a parte rispetto all'estrazione del file
system. RepertIA non lo copia nel caso (si usa dal suo percorso, come l'estrazione): ne calcola lo SHA-256, lo registra
nel registro a catena e fa un secondo giro di iLEAPP sull'archivio (`-t gz`: iLEAPP estrae nel suo rapporto solo i
file che i suoi moduli leggono). Le righe ottenute diventano artefatti iLEAPP del gruppo «Sysdiagnose», marcate
«da sysdiagnose <nome del file>». Data di creazione e dispositivo si ricavano dal nome della cartella dell'archivio
(scritto dall'iPhone) e, se c'è, da remotectl_dumpstate.txt.
"""
import datetime as dt
import re
import subprocess
import sys
import tarfile
import time
from pathlib import Path

from forense_lingua import tr, N_  # noqa: E402

GRUPPO = "Sysdiagnose"
# nome della cartella principale: sysdiagnose_2025.04.07_08-06-18-0700_iPhone-OS_iPhone_20A362
NOME_RE = re.compile(r"^sysdiagnose_(\d{4})\.(\d\d)\.(\d\d)_(\d\d)-(\d\d)-(\d\d)([+-]\d{4})_(.+)_([A-Za-z0-9]+)$")
FILE_NOTI = ("ps.txt", "sysdiagnose.log", "remotectl_dumpstate.txt", "shutdown.log", "disks.txt")
REMOTECTL = {"ProductType": re.compile(r"ProductType\s*=>\s*(\S+)"), "HWModel": re.compile(r"HWModelStr\s*=>\s*(\S+)"),
             "ProductVersion": re.compile(r"ProductVersion\s*=>\s*(\S+)"), "BuildVersion": re.compile(r"BuildVersion\s*=>\s*(\S+)")}


def elenco(case):
    return list(case.meta.get("sysdiagnose") or [])


def _da_nome(nome):
    """Data di creazione (UTC e ora locale del telefono) e dispositivo dal nome della cartella del sysdiagnose."""
    m = NOME_RE.match(nome or "")
    if not m:
        return {}
    y, mo, d, h, mi, s, off, resto, build = m.groups()
    try:
        tz = dt.timezone(dt.timedelta(hours=int(off[:3]), minutes=int(off[0] + off[3:])))
        t = dt.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), tzinfo=tz)
    except ValueError:
        return {}
    sis, _, disp = resto.rpartition("_")
    return {"creato_utc": t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creato_locale": t.strftime("%Y-%m-%d %H:%M:%S") + f" {off[:3]}:{off[3:]}",
            "sistema": (sis or resto).replace("-", " "), "dispositivo": disp or None, "build": build}


def esamina(path):
    """Controlla che il file sia un sysdiagnose (archivio tar, anche compresso, con la cartella «sysdiagnose_…» o i suoi
    file tipici) e ne ricava cartella principale, data di creazione, dispositivo, numero di voci. ValueError se non lo è."""
    p = Path(str(path))
    try:
        tf = tarfile.open(p, "r:*")
    except (tarfile.TarError, EOFError):
        raise ValueError(tr("Il file non è un archivio tar (nemmeno compresso): il sysdiagnose è un .tar.gz."))
    except OSError as e:
        raise ValueError(tr("Il file non si può leggere: {e}").format(e=e))
    voci, radici, noti, rc = 0, {}, set(), {}
    try:
        for m in tf:
            voci += 1
            parti = m.name.lstrip("./").split("/")
            if parti and parti[0]:
                radici[parti[0]] = radici.get(parti[0], 0) + 1
            base = parti[-1] if parti else ""
            if base.startswith("._"):
                continue
            if base in FILE_NOTI:
                noti.add(base)
            if base == "remotectl_dumpstate.txt" and m.isreg() and m.size < 4_000_000 and not rc:
                f = tf.extractfile(m)
                txt = f.read().decode("utf-8", "replace") if f else ""
                for k, rx in REMOTECTL.items():
                    mm = rx.search(txt)
                    if mm:
                        rc[k] = mm.group(1)
    except (tarfile.TarError, OSError, EOFError) as e:
        raise ValueError(tr("Archivio danneggiato o incompleto ({e}).").format(e=e))
    finally:
        tf.close()
    radice = max(radici, key=radici.get) if radici else ""
    if not (radice.startswith("sysdiagnose") or p.name.startswith("sysdiagnose") or noti):
        raise ValueError(tr("L'archivio non sembra un sysdiagnose di iOS (nessuna cartella «sysdiagnose_…» né file come ps.txt)."))
    info = {"cartella": radice, "voci": voci, "file_noti": sorted(noti)}
    info.update(_da_nome(radice) or _da_nome(re.sub(r"\.(tar\.gz|tgz|tar)$", "", p.name)))
    if rc:
        info["remotectl"] = rc
        if rc.get("ProductType"):
            info["modello"] = rc["ProductType"]
    return info


def aggiungi(case, path, say=print):
    """Registra un sysdiagnose fornito dall'operatore (SHA-256, registro a catena). Il file non si copia nel caso."""
    import forense_agent as fa
    p = Path(str(path)).expanduser().resolve()
    if not p.is_file():
        raise ValueError(tr("File del sysdiagnose non trovato: {p}").format(p=p))
    plat = (case.meta.get("mobile") or {}).get("piattaforma")
    if plat and plat != "ios":
        raise ValueError(tr("Il sysdiagnose è dei dispositivi Apple (iOS): questa estrazione è {p}.").format(p=plat))
    info = esamina(p)
    say(tr("Sysdiagnose: calcolo SHA-256 di {p}…").format(p=p.name))
    sha = fa.sha256_file(p)
    voce = {"file": str(p), "nome": p.name, "byte": p.stat().st_size, "sha256": sha, "ts": fa.now(), **info}
    lst = [x for x in elenco(case) if x.get("sha256") != sha]
    if len(lst) != len(elenco(case)):
        say(tr("Sysdiagnose {nome} già registrato: aggiornato il percorso.").format(nome=p.name))
    lst.append(voce)
    case.meta["sysdiagnose"] = lst
    case.log("sysdiagnose", voce)
    case.save()
    say(tr("Sysdiagnose registrato: {nome}, {b} byte, SHA-256 {sha} (non copiato nel caso: si usa dal suo percorso).").format(
        nome=p.name, b=voce["byte"], sha=sha))
    if voce.get("creato_utc"):
        say(tr("Creato il {t} (ora del telefono {l}); dispositivo: {d}.").format(
            t=voce["creato_utc"], l=voce.get("creato_locale", ""), d=descrivi_dispositivo(voce)))
    return voce


def descrivi_dispositivo(v):
    parti = [v.get("modello") or v.get("dispositivo"), v.get("sistema"),
             (tr("versione {v}").format(v=(v.get("remotectl") or {})["ProductVersion"]) if (v.get("remotectl") or {}).get("ProductVersion") else None),
             (tr("build {b}").format(b=v["build"]) if v.get("build") else None)]
    return ", ".join(x for x in parti if x) or tr("non ricavabile")


def togli(case, con, sha):
    """Toglie un sysdiagnose dal caso: la registrazione e le righe di iLEAPP ricavate da lui (il rapporto di iLEAPP resta
    nella cartella del caso)."""
    lst = elenco(case)
    v = next((x for x in lst if x.get("sha256") == sha), None)
    if not v:
        raise ValueError(tr("Sysdiagnose non registrato in questo caso."))
    n = _cancella_righe(con, sha)
    case.meta["sysdiagnose"] = [x for x in lst if x.get("sha256") != sha]
    case.log("sysdiagnose_tolto", {"file": v.get("file"), "sha256": sha, "righe_tolte": n})
    _aggiorna(case, con)
    case.save()
    return n


def _cancella_righe(con, sha):
    import forense_mobile_chat as fmc
    fmc.ensure_art_cols(con)
    try:
        n = con.execute("DELETE FROM artifacts WHERE cat='leapp' AND (CASE WHEN json_valid(data) THEN json_extract(data, '$.sysdiagnose_sha256') END) = ?", (sha,)).rowcount
        con.execute("DELETE FROM leapp_segreti WHERE art NOT IN (SELECT id FROM artifacts)")
    except Exception:
        n = 0
    con.commit()
    return n


def _aggiorna(case, con):
    try:
        import forense_mobile_chat as fmc
        fmc.aggiorna_estese(case, con)
    except Exception:
        pass


def run(case, con, say=print, solo=None):
    """Secondo giro di iLEAPP su ciascun sysdiagnose registrato (o solo su quello con SHA-256 `solo`).
    Restituisce il numero di sysdiagnose letti."""
    import forense_agent as fa
    import forense_mobile as fm
    import forense_mobile_leapp as fml
    fa.avanz("sysdiag")            # (2.20) passo della pagina di preparazione
    lst = elenco(case)
    if not lst:
        return 0
    d = fml.tool_dir("ios")
    if not d:
        say(tr("iLEAPP non trovato: i sysdiagnose restano registrati ma non letti."))
        return 0
    ver, imp = fml.versione(d, "ios"), fml.impronta(d)
    try:
        part = int(fm.sorgenti(case)[0]["offset"])
    except Exception:
        part = None
    fatti = 0
    for v in lst:
        if solo and v.get("sha256") != solo:
            continue
        p = Path(v["file"])
        if not p.is_file():
            say(tr("Sysdiagnose non raggiungibile ({p}): non letto.").format(p=p))
            v["ileapp"] = {"esito": "non_raggiungibile", "ts": fa.now()}
            case.log("sysdiagnose_non_usato", {"file": str(p), "motivo": "non raggiungibile"})
            continue
        say(tr("Sysdiagnose {nome}: verifica dello SHA-256…").format(nome=p.name))
        sha = fa.sha256_file(p)
        if sha != v.get("sha256"):
            say(tr("ATTENZIONE: il sysdiagnose {p} è cambiato dopo la registrazione (SHA-256 diverso): non viene letto. "
                   "Toglilo e aggiungilo di nuovo.").format(p=p))
            v["ileapp"] = {"esito": "sha256_diverso", "ts": fa.now(), "attuale": sha}
            case.log("sysdiagnose_non_usato", {"file": str(p), "motivo": "SHA-256 diverso", "registrato": v.get("sha256"),
                                               "attuale": sha})
            continue
        base = case.root / "leapp"
        base.mkdir(exist_ok=True)
        out = base / ("sysdiagnose_" + dt.datetime.now().strftime("%Y%m%d_%H%M%S") + f"_{sha[:8]}")
        out.mkdir()
        t = "tar" if p.name.lower().endswith(".tar") else "gz"
        cmd = [sys.executable, str(d / "ileapp.py"), "-t", t, "-i", str(p), "-o", str(out)]
        case.log("cmd", cmd)
        say(tr("iLEAPP {ver}: lettura del sysdiagnose {nome}…").format(ver=ver or "", nome=p.name))
        t0 = time.time()
        log = out / "ileapp_console.log"
        with open(log, "w", encoding="utf-8") as lf:
            pr = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=fml._env(d),
                                  cwd=str(d), stdin=subprocess.DEVNULL, encoding="utf-8", errors="replace")
            last = 0.0
            for line in pr.stdout:
                lf.write(line)
                if time.time() - last > 5 and line.strip():
                    last = time.time()
                    say(f"  iLEAPP: {line.strip()[:150]}")
            rc = pr.wait()
        dur = round(time.time() - t0)
        rep = next((x for x in sorted(out.iterdir()) if x.is_dir() and x.name.lower().startswith("ileapp")), None)
        if rc != 0 or not rep:
            say(tr("iLEAPP sul sysdiagnose {nome} non riuscito (codice {rc}): vedi {log}").format(nome=p.name, rc=rc, log=log))
            v["ileapp"] = {"esito": "errore", "codice": rc, "log": str(log.relative_to(case.root)), "ts": fa.now()}
            case.log("sysdiagnose_ileapp", {"sha256": sha, **v["ileapp"]})
            continue
        _cancella_righe(con, sha)
        arts, cut, cats, _dcols = fml.import_tsv(con, rep, "iLEAPP", None, sysd={"nome": p.name, "sha256": sha, "part": part})
        v["ileapp"] = {"esito": "ok", "strumento": "iLEAPP", "versione": ver, "impronta": imp,
                       "comando": ["python", "ileapp.py", "-t", t, "-i", str(p), "-o", str(out)],
                       "rapporto": str(rep.relative_to(case.root)), "durata_s": dur, "artefatti": arts,
                       "categorie_ileapp": sorted(cats), "righe": sum(arts.values()), "troncato": cut, "ts": fa.now()}
        case.log("sysdiagnose_ileapp", {"sha256": sha, "file": p.name, **{k: v["ileapp"][k] for k in
                                        ("versione", "impronta", "rapporto", "durata_s", "righe", "artefatti")}})
        say(tr("Sysdiagnose {nome}: {n} artefatti, {r} righe di iLEAPP (gruppo «Sysdiagnose»).").format(
            nome=p.name, n=sum(1 for x in arts.values() if x), r=v["ileapp"]["righe"]))
        fatti += 1
    case.meta["sysdiagnose"] = lst
    case.meta.setdefault("tool_versions", {})["ileapp"] = ver
    _aggiorna(case, con)
    case.save()
    return fatti


def strumenti_md(case):
    """Righe per «Strumenti usati» del report: i sysdiagnose con lo SHA-256."""
    out = []
    for v in elenco(case):
        il = v.get("ileapp") or {}
        out.append(tr("Sysdiagnose {nome} (SHA-256 {sha}): {stato}").format(
            nome=v.get("nome"), sha=v.get("sha256"),
            stato=tr("letto con iLEAPP {v}, {r} righe").format(v=il.get("versione") or "", r=il.get("righe", 0)) if il.get("esito") == "ok"
            else tr("registrato, non letto ({e})").format(e=il.get("esito") or tr("iLEAPP non eseguito"))))
    return out


def report_md(case):
    """Sezione «Sysdiagnose» del report del caso."""
    lst = elenco(case)
    if not lst:
        return ""
    h = ["## " + tr("Sysdiagnose"), "",
         tr("Archivi di registri e stati del sistema prodotti dall'iPhone e acquisiti a parte. RepertIA non li copia nel caso: "
            "ne registra lo SHA-256 e li fa leggere a iLEAPP (righe nel gruppo «Sysdiagnose» degli artefatti, marcate "
            "«da sysdiagnose <nome del file>»)."), "",
         "| " + " | ".join([tr("File"), tr("Byte"), "SHA-256", tr("Creato (UTC)"), tr("Ora del telefono"), tr("Dispositivo"),
                            tr("iLEAPP")]) + " |", "|---|---:|---|---|---|---|---|"]
    for v in lst:
        il = v.get("ileapp") or {}
        st = (tr("{r} righe in {n} artefatti (iLEAPP {v}, rapporto {rep})").format(r=il.get("righe", 0), n=sum(1 for x in (il.get("artefatti") or {}).values() if x),
                                                                                     v=il.get("versione") or "", rep=il.get("rapporto") or "")
              if il.get("esito") == "ok" else tr("non letto ({e})").format(e=il.get("esito") or tr("iLEAPP non eseguito")))
        h.append("| " + " | ".join(str(x).replace("|", "\\|") for x in [
            v.get("nome"), v.get("byte"), v.get("sha256"), v.get("creato_utc") or tr("non ricavabile"),
            v.get("creato_locale") or "", descrivi_dispositivo(v), st]) + " |")
    h.append("")
    h.append(tr("Data e dispositivo vengono dal nome della cartella dell'archivio (scritto dall'iPhone al momento della "
                "creazione) e, se presente, da remotectl_dumpstate.txt; non sono verificati con altre fonti."))
    return "\n".join(h) + "\n"


def summary(case):
    return [{k: v.get(k) for k in ("nome", "file", "byte", "sha256", "creato_utc", "creato_locale", "dispositivo", "modello",
                                    "sistema", "build", "ts")} | {"dispositivo_testo": descrivi_dispositivo(v),
                                                                  "ileapp": {k: (v.get("ileapp") or {}).get(k) for k in ("esito", "righe", "versione", "rapporto")}}
            for v in elenco(case)]
