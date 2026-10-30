# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - iLEAPP (iOS) e ALEAPP (Android) per i casi smartphone (dalla 2.20).

iLEAPP e ALEAPP (Alexis Brignoni e collaboratori, licenza MIT) leggono centinaia di artefatti delle app dei
telefoni. RepertIA li usa come usa plaso per i dischi: programmi esterni, alla versione inclusa nel pacchetto,
eseguiti con il Python incluso e con le loro librerie in una cartella separata (non si mescolano con quelle di
RepertIA e di plaso).

- Ricevono l'estrazione originale (zip, tar o cartella) in sola lettura; scrivono nella cartella del caso
  `leapp/<strumento>_<data>/` il loro rapporto HTML e le tabelle (TSV, database LAVA). Copiano lì i file che
  leggono (cartella `data/` del loro rapporto): sono copie di lavoro.
- Le tabelle TSV diventano artefatti del caso (categoria «leapp»): una riga per riga di iLEAPP/ALEAPP, con il
  nome dell'artefatto, la data (se c'è una colonna di data) e tutti i campi.
- Versione, comando, durata e impronta (SHA-256 dei loro file .py) vanno nel caso, nel registro e nel report.

Cartelle cercate: variabili REPERTIA_ILEAPP / REPERTIA_ALEAPP, poi `strumenti/ileapp` e `strumenti/aleapp` accanto
ai sorgenti (pacchetti). In ognuna: il programma (ileapp.py / aleapp.py) e, in `site/`, le sue librerie.
"""
import csv
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from forense_lingua import tr, N_  # noqa: E402

TOOLS = {"ios": ("ileapp", "iLEAPP", "ileapp.py"), "android": ("aleapp", "ALEAPP", "aleapp.py")}
MAX_ROWS = 500_000
TS_HEAD = re.compile(r"(time|date|timestamp|data|created|modified|last|start|end)", re.I)
TS_VAL = re.compile(r"^(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:?\d\d)?$")


def tool_dir(kind):
    key, _name, script = TOOLS[kind]
    here = Path(__file__).resolve().parent
    cands = [os.environ.get(f"REPERTIA_{key.upper()}") or "", here.parent / "strumenti" / key,
             here.parent.parent / "strumenti" / key, here / "strumenti" / key]
    for c in cands:
        if c and (Path(c) / script).is_file():
            return Path(c)
    return None


def impronta(d):
    h = hashlib.sha256()
    for p in sorted(Path(d).rglob("*.py")):
        if "site" in p.relative_to(d).parts[:1] or "admin" in p.relative_to(d).parts[:1]:
            continue
        h.update(str(p.relative_to(d)).encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def _env(d):
    env = dict(os.environ)
    site = Path(d) / "site"
    env["PYTHONPATH"] = os.pathsep.join(x for x in (str(site) if site.is_dir() else "", str(d)) if x)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTHONHOME", None)
    return env


def versione(d, kind):
    script = Path(d) / TOOLS[kind][2]
    try:
        cp = subprocess.run([sys.executable, str(script), "--version"], capture_output=True, text=True, timeout=120,
                            env=_env(d), cwd=str(d), stdin=subprocess.DEVNULL)
        m = re.search(r"v?(\d{4}\.\d+\.\d+)", cp.stdout + cp.stderr)
        return m.group(1) if m else (cp.stdout + cp.stderr).strip()[:80]
    except (OSError, subprocess.SubprocessError):
        return None


def _iso(v):
    m = TS_VAL.match((v or "").strip())
    if not m:
        return None
    try:
        t = dt.datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}" + (m.group(4) or "+00:00").replace("Z", "+00:00"))
        return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def lava_info(out_dir):
    """Categoria e colonne di data di ogni artefatto, dal file .lava del rapporto (la categoria è quella che
    iLEAPP/ALEAPP mostrano nel loro rapporto): {nome dell'artefatto: (categoria, [intestazioni delle date])}."""
    out = {}
    for f in sorted(Path(out_dir).glob("*.lava")):
        if f.name.startswith("._"):
            continue
        try:
            d = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        for cat, arts in (d.get("artifacts") or {}).items():
            for a in arts or []:
                cmap = a.get("column_map") or {}
                dates = [cmap.get(c.get("name"), c.get("name")) for c in a.get("object_columns") or []
                         if c.get("type") in ("datetime", "date")]
                out.setdefault(a.get("name") or "", (cat, dates))
    return out


def lava_meta(out_dir):
    """Dal file .lava: database di origine di ogni artefatto ({nome: source_path}) e viste «conversazione» dichiarate da
    iLEAPP/ALEAPP con i nomi delle colonne come nelle tabelle TSV ({nome: {timeColumn: "Timestamp", ...}})."""
    fonti, viste = {}, {}
    for f in sorted(Path(out_dir).glob("*.lava")):
        if f.name.startswith("._"):
            continue
        try:
            d = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        for _cat, arts in (d.get("artifacts") or {}).items():
            for a in arts or []:
                name = a.get("name") or ""
                if a.get("source_path"):
                    fonti.setdefault(name, a["source_path"])
                cv = (a.get("data_views") or {}).get("conversation")
                if cv:
                    cmap = a.get("column_map") or {}
                    viste[name] = {k: (cmap.get(v, v) if k.endswith("Column") else v) for k, v in cv.items()}
    return fonti, viste


def _detail(rec, limit=2000):
    """Campi della riga come JSON valido entro `limit` caratteri (valori lunghi accorciati): la colonna Dettagli
    e il report portatile lo mostrano come tabella «campo: valore»; il campo intero resta nei dati della riga."""
    s = json.dumps(rec, ensure_ascii=False)
    cap = 400
    while len(s) > limit and cap > 20:
        s = json.dumps({k: (v if len(v) <= cap else v[:cap] + "…") for k, v in rec.items()}, ensure_ascii=False)
        cap //= 2
    return s if len(s) <= limit else json.dumps({k: rec[k][:20] for k in list(rec)[:40]}, ensure_ascii=False)


def import_tsv(con, out_dir, tool, part, sysd=None):
    """Tabelle TSV del rapporto → artefatti (cat 'leapp', gruppo = categoria di iLEAPP/ALEAPP, voce = artefatto).
    Restituisce ({artefatto: righe}, troncato, {categoria: {artefatto: righe}}, {artefatto: [colonne di data]}).
    (2.20) sysd = {nome, sha256}: rapporto di iLEAPP su un sysdiagnose → gruppo «Sysdiagnose», campo «Origine»
    «da sysdiagnose <nome>», nessuna partizione (il file non è nell'estrazione)."""
    import forense_mobile_chat as fmc
    import forense_mobile_portachiavi as fmk
    tsv_dir = next((p for p in Path(out_dir).glob("*TSV*") if p.is_dir()), None)
    csv.field_size_limit(min(sys.maxsize, 2 ** 31 - 1))      # campi lunghi (es. testi interi, plist): il limite è 128 KB
    MAX_FIELD = 20000                                        # nel caso si tiene l'inizio; il rapporto ha il campo intero
    res, total, cats, dcols = {}, 0, {}, {}
    n_seg = 0
    if not tsv_dir:
        return res, False, cats, dcols
    fmc.ensure_art_cols(con)
    fmk.ensure_schema(con)
    con.execute("DELETE FROM leapp_segreti WHERE art NOT IN (SELECT id FROM artifacts)")
    info = lava_info(out_dir)
    sysdiag_grp = "Sysdiagnose"
    batch = []
    cut = False
    sql = ("INSERT INTO artifacts(cat, ts, title, detail, user, src_path, part, inode, data, grp, sub) "
           "VALUES (?,?,?,?,?,?,?,?,?,?,?)")
    files = [f for f in sorted(tsv_dir.glob("*.tsv")) if not f.name.startswith(".")]   # «._nome.tsv»: AppleDouble di macOS
    # (2.20) oltre MAX_ROWS righe in tutto: prima le tabelle che servono a chat, chiamate, nomi e account (mappa), poi le
    # altre in ordine alfabetico; sotto il limite l'ordine resta quello di sempre (stessi id degli artefatti)
    nel_tsv = {f.stem: _righe_tsv(f) for f in files}
    if sum(nel_tsv.values()) > MAX_ROWS:
        prio = _tabelle_mappa()
        try:                        # anche le tabelle con una vista «conversazione» nel .lava (chat mappate in automatico)
            prio |= {k for k, v in (lava_meta(out_dir)[1] or {}).items() if (v or {}).get("textColumn")}
        except Exception:
            pass
        prio |= {f.stem for f in files if PRIO_RE.search(f.stem)}      # chiamate, messaggi, chat delle app
        files = [f for f in files if f.stem in prio] + [f for f in files if f.stem not in prio]
    for f in files:
        name = f.stem
        cat, dates = info.get(name, (tr("(senza categoria)"), []))
        try:
            fh = open(f, encoding="utf-8-sig", errors="replace", newline="")
        except OSError:
            continue
        with fh:
            rd = csv.reader(fh, delimiter="\t")
            head = next(rd, None)
            if not head:
                continue
            # colonne di data: quelle che iLEAPP/ALEAPP dichiarano (tipo datetime), altrimenti dal nome
            ts_cols = [i for i, h in enumerate(head) if h in dates] or [i for i, h in enumerate(head) if TS_HEAD.search(h or "")]
            n = 0
            for row in rd:
                if not row:                 # iLEAPP su Windows chiude le righe con \r\r\n: csv vede una riga vuota dopo ognuna
                    continue
                if total >= MAX_ROWS:
                    cut = True
                    break
                rec = {head[i] if i < len(head) else f"col{i}": (v if len(v) <= MAX_FIELD else v[:MAX_FIELD] + " […]")
                       for i, v in enumerate(row) if v not in ("", None)}
                ts = next((x for x in (_iso(row[i]) for i in ts_cols if i < len(row)) if x), None)
                # (2.20) valori segreti (password, chiavi, token): segnaposto nella riga, valore in leapp_segreti
                rec, seg = fmk.nascondi(cat, name, rec)
                if sysd:
                    rec = {tr("Origine"): tr("da sysdiagnose {n}").format(n=sysd["nome"]), **rec}
                vals = [str(v) for k, v in rec.items() if not TS_HEAD.search(k) and not (sysd and k == tr("Origine"))][:3]
                title = f"{name}: " + " · ".join(v[:80] for v in vals) if vals else name
                if sysd:
                    title = title[:180] + " · " + tr("da sysdiagnose {n}").format(n=sysd["nome"])
                src = rec.get("Source File Located") or rec.get("Source") or ""
                data = {"leapp": tool, "categoria": cat, "artefatto": name, "date": dates, "campi": rec}
                if sysd:
                    data.update({"sysdiagnose": sysd["nome"], "sysdiagnose_sha256": sysd["sha256"]})
                if seg:
                    data["segreti"] = [k for k, _v in seg]
                row_ = ("leapp", ts, title[:300], _detail(rec), "", src or (sysd["nome"] if sysd else name), None if sysd else part, None,
                        json.dumps(data, ensure_ascii=False), sysdiag_grp if sysd else cat, name)
                if seg:                     # riga con segreti: inserita subito per averne l'id
                    con.executemany(sql, batch)
                    batch.clear()
                    aid = con.execute(sql, row_).lastrowid
                    con.executemany("INSERT INTO leapp_segreti(art, campo, valore) VALUES (?,?,?)",
                                    [(aid, k, v) for k, v in seg])
                    n_seg += len(seg)
                else:
                    batch.append(row_)
                n += 1
                total += 1
                if len(batch) >= 5000:
                    con.executemany(sql, batch)
                    batch.clear()
            res[name] = n
            cats.setdefault(cat, {})[name] = n
            if dates:
                dcols[name] = dates
    con.executemany(sql, batch)
    con.commit()
    import_tsv.segreti = n_seg
    # (2.20) tabelle non importate o importate in parte per il limite: {artefatto: [righe importate, righe nel rapporto]}
    import_tsv.omesse = {k: [res.get(k, 0), v] for k, v in nel_tsv.items() if res.get(k, 0) < v}
    return res, cut, cats, dcols


PRIO_RE = re.compile(r"call|messag|chat|conversation|voicemail", re.I)


def _righe_tsv(f):
    """Righe di dati di una tabella TSV (senza l'intestazione), contate come le legge csv."""
    try:
        with open(f, encoding="utf-8-sig", errors="replace", newline="") as fh:
            return max(sum(1 for r in csv.reader(fh, delimiter="\t") if r) - 1, 0)
    except OSError:
        return 0


def righe_vuote(con):
    """Righe di iLEAPP/ALEAPP senza alcun campo (la riga «Origine» dei sysdiagnose la aggiunge RepertIA)."""
    return con.execute("SELECT COUNT(*) FROM artifacts WHERE cat='leapp' AND json_valid(data) AND "
                       "(SELECT COUNT(*) FROM json_each(data, '$.campi')) <= (json_extract(data, '$.sysdiagnose') IS NOT NULL)"
                       ).fetchone()[0]


def _tabelle_mappa():
    """Nomi delle tabelle di iLEAPP/ALEAPP usate da chat, chiamate, nomi e account (forense_mobile_leapp_mappa.json),
    comprese quelle escluse dalle chat perché lette da RepertIA (servono al riscontro)."""
    try:
        import forense_mobile_leapp_chat as fmlc
        m = fmlc.carica()
    except Exception:
        return set()
    out = set((m.get("escluse") or {}).get("artefatti") or [])
    for sez in ("chat", "chiamate"):
        out |= {k.split("|", 1)[-1] for k in (m.get(sez) or {})}
    for sez in ("nomi", "proprietari"):
        out |= {v["artefatto"].split("|", 1)[-1] for v in (m.get(sez) or {}).values()}
    return out


LEAPP_N = re.compile(r"\[(\d+)/(\d+)\]")


def run(case, con, say=print):
    """Esegue iLEAPP o ALEAPP sull'estrazione del caso e ne importa i risultati. True se riuscito."""
    import forense_agent as fa
    import forense_estesa as fe
    import forense_mobile as fm
    fa.avanz("leapp")              # (2.20) passo della pagina di preparazione
    plat = (case.meta.get("mobile") or {}).get("piattaforma")
    if plat not in TOOLS:
        say(tr("iLEAPP/ALEAPP: piattaforma del telefono non riconosciuta, non eseguito."))
        return False
    key, name, script = TOOLS[plat]
    d = tool_dir(plat)
    if not d:
        say(tr("{name} non trovato (cartella strumenti/{key} del pacchetto o variabile REPERTIA_{K}).").format(
            name=name, key=key, K=key.upper()))
        return False
    src = fm.sorgenti(case)[0]
    part = int(src["offset"])
    img = src["mobile"]["file"]
    t = {"zip": "zip", "tar": "tar", "cartella": "fs"}[src["mobile"]["formato"]]
    base = case.root / "leapp"
    base.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = base / f"{key}_{stamp}"
    out.mkdir()
    ver = versione(d, plat)
    cmd = [sys.executable, str(d / script), "-t", t, "-i", str(img), "-o", str(out)]
    kc = []
    if plat == "ios":                   # (2.20) portachiavi fornito dall'operatore: a iLEAPP con --keychain
        import forense_mobile_portachiavi as fmk
        kc = fmk.args_leapp(case, say)
        cmd += kc
    case.log("cmd", cmd)
    say(tr("{name} {ver}: lettura degli artefatti dell'estrazione (può durare a lungo)…").format(name=name, ver=ver or ""), )
    t0 = time.time()
    log = out / f"{key}_console.log"
    with open(log, "w", encoding="utf-8") as lf:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=_env(d), cwd=str(d),
                             stdin=subprocess.DEVNULL, encoding="utf-8", errors="replace")
        last = 0.0
        for line in p.stdout:
            lf.write(line)
            mm = LEAPP_N.search(line)      # «[445/1262] google_chat …»: artefatti fatti / totale per la barra
            if mm:
                fa.avanz(fatti=int(mm.group(1)), totale=int(mm.group(2)))
            if time.time() - last > 5 and line.strip():
                last = time.time()
                say(f"  {name}: {line.strip()[:150]}")
        rc = p.wait()
    dur = round(time.time() - t0)
    rep = next((x for x in sorted(out.iterdir()) if x.is_dir() and x.name.lower().startswith(key)), None)
    if rc != 0 or not rep:
        say(tr("{name} non riuscito (codice {rc}): vedi {log}").format(name=name, rc=rc, log=log))
        case.meta["leapp"] = {"strumento": name, "versione": ver, "esito": "errore", "codice": rc, "log": str(log)}
        case.log("leapp", case.meta["leapp"])
        case.save()
        return False
    info = {"strumento": name, "versione": ver, "impronta": impronta(d), "comando": [Path(x).name if i < 2 else x
                                                                                  for i, x in enumerate(cmd)],
            "rapporto": str(rep.relative_to(case.root)), "durata_s": dur}
    if plat == "ios":
        import forense_mobile_portachiavi as fmk
        try:
            log_text = log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            log_text = ""
        info["portachiavi"] = fmk.esito(case, log_text, bool(kc))
        case.log("portachiavi_ileapp", info["portachiavi"])
        say(fmk.testo_esito(info["portachiavi"]))
    _importa(case, con, rep, info, say)
    case.meta.setdefault("tool_versions", {})[key] = ver
    case.save()
    return True


def _importa(case, con, rep, info, say):
    """Importa le tabelle del rapporto `rep` negli artefatti (al posto delle righe iLEAPP/ALEAPP precedenti)."""
    import forense_agent as fa
    import forense_estesa as fe
    import forense_mobile as fm
    import forense_mobile_chat as fmc
    part = int(fm.sorgenti(case)[0]["offset"])
    fe.ensure_schema(con)
    fmc.ensure_art_cols(con)
    # le righe dei sysdiagnose (secondo giro di iLEAPP, 2.20) restano: hanno un rapporto a parte
    con.execute("DELETE FROM artifacts WHERE cat='leapp' AND (CASE WHEN json_valid(data) THEN json_extract(data, '$.sysdiagnose_sha256') END) IS NULL")
    arts, cut, cats, dcols = import_tsv(con, rep, info["strumento"], part)
    info.pop("omesse", None)
    if cut:
        info["omesse"] = getattr(import_tsv, "omesse", {})
    fonti, viste = lava_meta(rep)
    info.update({"artefatti": arts, "categorie": cats, "colonne_data": dcols, "righe": sum(arts.values()),
                 "troncato": cut, "ts": fa.now(), "esito": "ok", "fonti": fonti, "viste": viste,
                 "valori_segreti": getattr(import_tsv, "segreti", 0)})
    case.meta["leapp"] = info
    fmc.aggiorna_estese(case, con)
    case.log("leapp", info)
    case.save()
    say((tr("{name}: {n} artefatti in {c} categorie, {r} righe reimportate dal rapporto {rep}") if info.get("reimportato")
         else tr("{name}: {n} artefatti in {c} categorie, {r} righe importate in {s} s. Rapporto: {rep}")).format(
        name=info["strumento"], n=len(arts), c=len(cats), r=info["righe"], s=info.get("durata_s", 0), rep=rep))
    if cut:
        say(tr("ATTENZIONE: importate solo le prime {m} righe; il rapporto di {name} le contiene tutte.").format(
            m=MAX_ROWS, name=info["strumento"]))
    # chat delle app non lette da RepertIA e chiamate, ricavate dalle righe appena importate
    try:
        import forense_mobile_leapp_chat as fmlc
        fmlc.run(case, con, say)
    except Exception as e:
        say(tr("Chat e chiamate da {name} non ricavate ({vname}: {e})").format(name=info["strumento"], vname=type(e).__name__, e=e))


def reimporta(case, con, say=print):
    """Rilegge le tabelle dell'ultimo rapporto di iLEAPP/ALEAPP del caso senza rieseguire lo strumento (es. dopo un
    aggiornamento di RepertIA che cambia l'importazione). True se riuscito."""
    lp = case.meta.get("leapp") or {}
    rep = case.root / lp["rapporto"] if lp.get("rapporto") else None
    if lp.get("esito") != "ok" or not rep or not rep.is_dir():
        say(tr("iLEAPP/ALEAPP: nessun rapporto da reimportare (eseguire prima lo strumento)."))
        return False
    info = {k: lp[k] for k in ("strumento", "versione", "impronta", "comando", "rapporto", "durata_s", "portachiavi") if k in lp}
    info["reimportato"] = True
    _importa(case, con, rep, info, say)
    return True
