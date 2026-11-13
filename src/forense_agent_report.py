#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - preferiti nel tempo e report del caso (report.md).

(3.0.4) Codice spostato da forense_agent.py senza modifiche, per avere file più corti. Si carica tramite
forense_agent, che ne riesporta i nomi: gli altri moduli continuano a usare «fa.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fa.<nome>»).
"""
import json
import re
import sqlite3
from pathlib import Path
from forense_lingua import N_
from forense_lingua import tr
import forense_lingua as lg

import forense_agent as fa
from forense_agent import (
    APP_BY, APP_NAME, APP_VERSION, FINDING_ANALISTA, _ua_pos, ambiente, audit_testo, audit_verifica, finding_label,
    finding_verificato, fuso_testo, hash_dati_md, image_segments, is_mobile, now, sha256_file, table_exists)

# -------------------------------------------------------------------- report

def bm_threads(case):
    """(2.21) {id artefatto: id conversazione} degli artefatti «messaggi»: la scheda di una chat nei Preferiti."""
    if not is_mobile(case):
        return {}
    con = fa.db_ro(case)
    try:
        if not table_exists(con, "chat_threads"):
            return {}
        return {str(a): t for a, t in con.execute("SELECT id, json_extract(data, '$.chat_thread') FROM artifacts WHERE cat='messaggi' "
                                                  "AND json_valid(data) AND json_extract(data, '$.chat_thread') IS NOT NULL")}
    finally:
        con.close()


BM_EVENTO = {"mail": N_("data del messaggio"), "chat": N_("data del messaggio"), "art": N_("data dell'artefatto"),
             "fs": N_("ultima modifica del file"), "x": N_("ultima modifica del file")}


def bm_ts(v):
    """Data di un preferito in forma ordinabile, «» se manca o non si riconosce."""
    m = re.search(r"\d{4}-\d\d-\d\d(?:[T ]\d\d:\d\d(?::\d\d)?)?", str(v or ""))
    return m.group(0).replace(" ", "T") if m and not m.group(0).startswith("0000") else ""


def bookmarks_timeline(case, only_report=True, cid=None):
    """(2.21) Cronologia dei preferiti: un elemento una volta sola con tutte le sue categorie, in ordine di data
    dell'evento (quella salvata nel preferito, per le chat dal primo all'ultimo messaggio); in fondo quelli senza data."""
    p = case.root / "ricerche.sqlite"
    if not p.exists():
        return []
    con = sqlite3.connect(p.as_uri() + "?mode=ro", uri=True)
    try:
        if not table_exists(con, "bm_cat"):
            return []
        w, a = [], []
        if only_report:
            w.append("c.in_report")
        if cid:
            w.append("c.cid = ?")
            a.append(int(cid))
        rows = con.execute("SELECT b.id, b.source, b.part, b.inode, b.path, b.name, b.deleted, b.size, b.mtime, b.note, b.sha256, c.name "
                           "FROM bm b JOIN bm_cat c ON c.cid = b.cid" + (" WHERE " + " AND ".join(w) if w else ""), a).fetchall()
    finally:
        con.close()
    th, chats = bm_threads(case), {}
    if th:
        cx = fa.db_ro(case)
        try:
            chats = {r[0]: r[1:] for r in cx.execute("SELECT id, first_ts, last_ts FROM chat_threads")}
        finally:
            cx.close()
    out = {}
    for bid, src, part, inode, path, name, deleted, size, mt, note, sha, cat in rows:
        k = (src, part, str(inode))
        if k in out:
            x = out[k]
            x["categorie"].append(cat)
            if note and note not in x["note"]:
                x["note"] = "; ".join(y for y in (x["note"], note) if y)
            continue
        tid = th.get(str(inode)) if src == "art" else None
        ts, fine = bm_ts(mt), ""
        pos = re.match(r"⌖ (\S+(?: \d\d:\d\d(?::\d\d)?)?)", note or "")      # (3.0) punto preferito della mappa: conta la data della posizione
        if pos and bm_ts(pos.group(1)):
            ts = bm_ts(pos.group(1))
        if tid is not None and tid in chats:
            ts, fine = bm_ts(chats[tid][0]) or ts, bm_ts(chats[tid][1])
        out[k] = {"id": bid, "source": src, "part": part, "inode": inode, "path": path, "name": name, "deleted": deleted, "size": size,
                  "ts": ts, "fine": fine, "chat": tid, "sha256": sha, "note": note or "", "categorie": [cat],
                  "evento": tr("conversazione") if tid is not None else tr("data della posizione") if pos and ts else tr(BM_EVENTO[src]) if src in BM_EVENTO and ts else ""}
    return sorted(out.values(), key=lambda x: (not x["ts"], x["ts"], x["id"]))


def bookmarks_timeline_md(case):
    """Sezione del report: cronologia dei preferiti delle categorie «nel report»."""
    righe = bookmarks_timeline(case)
    if not righe:
        return []
    cell = lambda v: str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")
    L = [tr("### Cronologia dei preferiti"), "",
         tr("Elementi dei Preferiti in ordine di data dell'evento. Orari come registrati nel caso (UTC salvo indicazione diversa nel dato); "
            "la colonna Evento dice a che cosa si riferisce la data. Una data di modifica non prova da sola quando un fatto è avvenuto."), "",
         tr("| Data | Fino a | Evento | Elemento | Categorie | Nota |"), "|---|---|---|---|---|---|"]
    for x in righe[:5000]:
        L.append("| " + " | ".join(cell(v) for v in (x["ts"].replace("T", " ") or tr("senza data"), x["fine"].replace("T", " "), x["evento"],
                                                     x["path"], ", ".join(x["categorie"]), x["note"])) + " |")
    if len(righe) > 5000:
        L.append(tr("| … altri {v1} elementi | | | | | |").format(v1=len(righe) - 5000))
    return L + [""]


def collega_copia(case, nuovo, conferma=False, progress=None):
    """(2.21) Indica dove si trova ora la copia forense di un caso (altro computer, disco con un altro nome). La copia si
    accetta solo se il suo SHA-256 è quello del caso; senza hash nel caso serve `conferma` e il registro lo dichiara."""
    p = Path(nuovo).expanduser()
    if not p.exists():
        raise ValueError(tr("File non trovato. Controlla che il disco sia collegato."))
    m = case.meta
    da = m.get("evidence", m.get("image", ""))
    atteso = m.get("sha256") if isinstance(m.get("sha256"), dict) else None
    ottenuto = None
    if p.is_file() and atteso:
        segs, tot, fatti = image_segments(p), 0, 0
        tot = sum(s.stat().st_size for s in segs) or 1

        def pr(n):
            nonlocal fatti
            fatti += n
            if progress:
                progress(tr("Controllo SHA-256: {v1:.1f} di {v2:.1f} GB").format(v1=fatti / 1e9, v2=tot / 1e9))
        ottenuto = {s.name: sha256_file(s, pr) for s in segs}
        if sorted(ottenuto.values()) != sorted(atteso.values()):
            case.log("copia_non_collegata", {"da": da, "a": str(p), "motivo": "sha256_diverso"})
            raise ValueError(tr("Questa non è la copia del caso: lo SHA-256 è diverso. Nessuna modifica fatta."))
    elif not conferma:
        return {"serve_conferma": True}
    im = m.get("image", da)
    nuova = {"evidence": str(p.resolve())}
    if im == da:
        nuova["image"] = nuova["evidence"]
    else:                               # copia derivata nella cartella del caso: il percorso va riportato alla cartella di ora
        pezzi = [x for x in re.split(r"[\\/]+", str(im)) if x]
        cand = next((c for c in (case.root.joinpath(*pezzi[i:]) for i in range(len(pezzi))) if c.exists()), None)
        if cand is not None:
            nuova["image"] = str(cand)
    m.update(nuova)
    for x in m.get("partitions") or []:     # (3.0) smartphone: i file si leggono da qui, non da «image»
        if x.get("mobile"):
            x["mobile"]["file"] = m.get("image", nuova["evidence"])
    case.save()
    case.log("copia_collegata", {"da": da, "a": nuova["evidence"], "sha256": "uguale" if ottenuto else "non_confrontato"})
    return {"ok": True, "sha256": "uguale" if ottenuto else "non_confrontato",
            "image_ok": Path(m.get("image", "")).exists()}


def bookmarks(case, only_report=True):
    """Categorie di segnalibri con i loro file (da ricerche.sqlite), per report e report HTML."""
    p = case.root / "ricerche.sqlite"
    if not p.exists():
        return []
    con = sqlite3.connect(p.as_uri() + "?mode=ro", uri=True)
    try:
        if not table_exists(con, "bm_cat"):
            return []
        cats = []
        for cid, name, note, inr in con.execute("SELECT cid, name, note, in_report FROM bm_cat "
                                                "ORDER BY name COLLATE NOCASE"):
            if only_report and not inr:
                continue
            items = [dict(zip(("source", "part", "inode", "path", "deleted", "size", "mtime", "sha256",
                               "note"), r)) for r in con.execute(
                "SELECT source, part, inode, path, deleted, size, mtime, sha256, note FROM bm "
                "WHERE cid=? ORDER BY path COLLATE NOCASE", (cid,))]
            cats.append({"cid": cid, "name": name, "note": note or "", "in_report": bool(inr),
                         "items": items})
        return cats
    finally:
        con.close()


def cited_report_md(case, bms, limit=300):
    """(2.20) Righe del report: file citati dagli artefatti nei Preferiti, con esito (trovato con certezza / probabile,
    da verificare / non presente) e metodo per ogni campo, come nel pannello «File citato»."""
    ids = [int(it["inode"]) for cat in bms for it in cat["items"]
           if it["source"] == "art" and str(it["inode"] or "").isdigit()]
    ids = list(dict.fromkeys(ids))[:limit]
    if not ids:
        return []
    try:
        import forense_percorsi as fp
        idx = fp.Indice(case)
    except Exception:
        return []
    out = []
    mobile = is_mobile(case)
    con = fa.db_ro(case)
    try:
        for i in ids:
            r = con.execute("SELECT id, cat, ts, title, detail, user, src_path, part, inode, data FROM artifacts WHERE id=?",
                            (i,)).fetchone()
            if not r:
                continue
            try:
                c = fp.file_citati(case, dict(zip(("id", "cat", "ts", "title", "detail", "user", "src_path", "part",
                                                   "inode", "data"), r)), idx=idx)
            except Exception:
                continue
            fs = [x for x in c["file"] if x.get("ruolo") == "file"]
            if fs:
                out += [f"- **{r[3]}**"] + [
                    "  - " + tr("{e} — {p}; metodo: {m}{v}").format(
                        e=tr(fp.LIVELLI[x["livello"]]) if mobile or x["livello"] != "assente" else tr("non presente nella copia"),
                        p=fp.percorso_mostrato(x), m=fp.metodo_testo(x),
                        v=tr("; hash verificato") if x.get("verifica") == "uguale" else
                        tr("; ATTENZIONE: hash diverso da quello registrato nella riga") if x.get("verifica") == "diverso" else "")
                    + (tr("; {n} candidati: {l}").format(n=x["n_candidati"], l=", ".join(c2["path"] for c2 in x["candidati"]))
                       if x["livello"] == "probabile" and (x.get("n_candidati") or 0) > 1 else "")
                    for x in fs]
    finally:
        con.close()
        idx.close()
    if not out:
        return []
    return [tr("### File citati dagli artefatti nei Preferiti"), "",
            tr("Per ogni file nominato da un artefatto: esito della ricerca nella copia/estrazione e metodo, campo per "
               "campo. «Trovato con certezza» = percorso completo, hash o collegamento registrato da iLEAPP/ALEAPP; "
               "«probabile, da verificare» = solo nome o nome e dimensione; «non presente» = non trovato."), ""] + out + [""]


def info_caso_md(m):
    i = m.get("info_caso") or {}
    out = []
    for k, lab in (("nome", tr("Caso")), ("operatore", tr("Operatore")), ("reperto", tr("Tipo di reperto"))):
        if i.get(k):
            out.append(f"- {lab}: {i[k]}")
    if i.get("note"):
        out.append(tr("- Note: ") + " ".join(i["note"].split()))
    return out


def verifica_reperti_md(f):
    """(2.20.1) Frase sulla verifica dei reperti: «tutti verificati» solo se lo sono davvero."""
    if not f:
        return ""
    ok = sum(1 for x in f if finding_verificato(x))
    if ok == len(f):
        return tr("Ogni reperto è stato verificato dall'analista sugli strumenti forensi. ")
    return tr("Reperti verificati dall'analista sugli strumenti forensi: {ok} su {n}; {d} da verificare (generati dal "
              "modello IA o di origine non registrata). ").format(ok=ok, n=len(f), d=len(f) - ok)


def report_ia(case):
    """True se il report contiene testo generato da un modello IA (reperti dell'agente o di origine non registrata)."""
    return any(x.get("origine") != FINDING_ANALISTA for x in case.findings())


def modelli_usati(case):
    """(3.0) Modelli IA usati davvero in questo caso, dal registro: una «sessione» dice solo che il server era collegato;
    contano le domande e le risposte che la seguono. None se il registro non si può leggere."""
    usati, cur = {}, None
    try:
        with open(case.log_path, encoding="utf-8", errors="replace") as fh:
            for riga in fh:
                try:
                    r = json.loads(riga)
                except ValueError:
                    continue
                ev = r.get("event")
                if ev == "sessione":
                    cur = r.get("data") or {}
                elif ev in ("user", "assistant"):
                    c = cur or {}
                    u = usati.setdefault((c.get("model"), c.get("url")), {**c, "domande": 0, "risposte": 0, "dal": r.get("ts"), "al": None})
                    u["al"] = r.get("ts")
                    if ev == "user":
                        u["domande"] += 1
                    elif not (r.get("data") or {}).get("tool_calls"):
                        u["risposte"] += 1
    except OSError:
        return None
    return list(usati.values())


def modelli_report_md(case):
    """(3.0) Righe del report: quale modello IA è stato usato nel caso, oppure che non ne risulta nessuno."""
    usati = modelli_usati(case)
    if usati is None:
        return [tr("- Modello IA: non determinabile (registro del caso non leggibile).")]
    L = []
    for u in usati:
        dove = (tr("server esterno indicato dall'analista: {v1}").format(v1=u.get("url")) if u.get("esterno")
                else tr("eseguito sul server della rete interna {v1}").format(v1=u.get("url")) if u.get("remoto")
                else tr("eseguito localmente"))
        L.append(tr("- Modello IA usato: {m} ({backend}, {dove}): {d} domande, {r} risposte, dal {dal} al {al} (dal registro del caso).").format(
            m=u.get("model") or tr("nome non registrato"), backend=u.get("backend") or tr("server locale"), dove=dove,
            d=u["domande"], r=u["risposte"], dal=u["dal"], al=u["al"]))
    non_analista = [x for x in case.findings() if x.get("origine") != FINDING_ANALISTA]
    if not L:
        if not non_analista:
            return [tr("- Modello IA: nessuno. Dal registro del caso non risultano domande a un modello IA.")]
        return [tr("- Modello IA: il registro del caso non riporta domande a un modello, ma ci sono reperti attribuiti a un modello o "
                   "di origine non registrata: {n} (vedi le etichette dei reperti).").format(n=len(non_analista))]
    L.append(tr("- Reperti di questo report generati dal modello o di origine non registrata: {n}. Le conversazioni con il modello "
                "restano nel caso e non entrano nel report.").format(n=len(non_analista)))
    return L


def modello_metodo_md(case):
    """(3.0) Frase delle note metodologiche: il supporto del modello si dichiara solo se c'è stato davvero (dal registro)."""
    usati = modelli_usati(case)
    if usati is None:
        return tr("Uso di un modello linguistico non determinabile (registro del caso non leggibile). ")
    if not usati:
        return tr("Nessun modello linguistico risulta usato. ")
    if any(u.get("esterno") for u in usati):
        return tr("Con il supporto di un modello linguistico su un server esterno indicato dall'analista: {v1}. ").format(
            v1=", ".join(sorted({str(u.get("url")) for u in usati if u.get("esterno")})))
    if any(u.get("remoto") for u in usati):
        return tr("Con il supporto di un modello linguistico eseguito su un server della rete interna, senza servizi esterni. ")
    return tr("Con il supporto di un modello linguistico eseguito localmente. ")


def write_report(case):
    m, f = case.meta, case.findings()
    mob = is_mobile(case)
    tipo = fa.tipo_sorgente(case)        # (3.0.4) «ram» e «logica» si leggono come i telefoni ma non lo sono: testi propri
    if mob:                              # (2.20) smartphone: solo gli strumenti usati davvero in questo caso
        import forense_mobile_chat as fmc
        usati = fmc.strumenti_usati(case)
    L = [tr("# Report di analisi forense"), "",
         tr("- Generato: {v1} con {APP_NAME} {APP_VERSION} ({APP_BY})").format(v1=now(), APP_NAME=APP_NAME, APP_VERSION=APP_VERSION, APP_BY=APP_BY),
         *info_caso_md(m),
         (tr("- Dump della memoria RAM: `{v1}`") if tipo == "ram" else tr("- Sorgente logica: `{v1}`") if tipo == "logica" else
          tr("- Estrazione: `{v1}`") if mob else tr("- Copia forense: `{v1}`")).format(v1=m.get('evidence', m['image'])),
         *([tr("- Copia derivata creata da RepertIA: volume {v1} all'offset {v2} decifrato con {v3} il "
               "{v4} dalla copia `{v5}` (SHA-256 della copia derivata `{v6}`)").format(v1=m['derivata'].get('volume'), v2=m['derivata'].get('offset'), v3=m['derivata'].get('credenziale'), v4=m['derivata'].get('creata'), v5=m['derivata'].get('derivata_da'), v6=m['derivata'].get('sha256'))] if m.get("derivata") else []),
         *([tr("- Analizzata tramite conversione raw (ewfexport): `{image}`").format(image=m['image'])]
           if m.get("converted_from_e01") else []),
         tr("- Tipo di supporto: {v1}").format(v1=m.get('disk_type')),
         (_fuso_telefono_md(m) if mob else
          tr("- Fuso orario del dispositivo per le date in ora locale (FAT/exFAT): ") + fuso_testo(m)
          + tr(". Le altre date (NTFS, ext4, APFS, HFS+, registro, browser) sono già assolute e le tabelle le "
            "riportano in UTC.") if m.get("fuso_dispositivo") else
          tr("- Fuso orario del dispositivo: non registrato (caso preparato prima della 2.13.7). Le date di "
          "FAT/exFAT sono state convertite in UTC con il fuso del computer usato per la preparazione.")),
         *modelli_report_md(case),
         tr("- Strumenti usati nelle analisi: ") + "; ".join(f"{k}: {v}" for k, v in (usati if mob else (m.get("tool_versions") or {}).items())),
         "", tr("## Hash del dump della memoria (SHA-256)") if tipo == "ram" else tr("## Hash della sorgente logica (SHA-256)") if tipo == "logica" else
         tr("## Hash dell'estrazione (SHA-256)") if mob else tr("## Hash dei file della copia forense (SHA-256)"), ""]
    for k, v in (m.get("sha256") or {}).items():
        L.append(f"- `{k}`: `{v}`")
    if not m.get("sha256"):
        L.append(tr("- **Non calcolato**: analisi speditiva avviata senza il calcolo preliminare "
                 "dell'hash della copia forense, che va calcolato prima di chiudere l'analisi."))
    elif m.get("sha256_differito"):
        L.append(tr("- Calcolato il {v1}, dopo l'avvio dell'analisi (analisi speditiva avviata il {v2}); la "
                    "copia è stata comunque aperta sempre in sola lettura.").format(v1=m.get('sha256_ts', '-'), v2=m.get('created', '-')))
    elif m.get("sha256_ts"):
        L.append(tr("- Calcolato il {sha256_ts}, prima dell'analisi.").format(sha256_ts=m['sha256_ts']))
    if "hash_uguale_ad_acquisizione" in m:
        L.append(tr("- Corrispondenza con l'hash di acquisizione: {hash_uguale_ad_acquisizione}").format(hash_uguale_ad_acquisizione=m['hash_uguale_ad_acquisizione']))
    L += (["", tr("## Hash confrontato con quello dell'acquisizione"), "",
           tr("Hash del dump confrontato con quello registrato dal programma di acquisizione, se c'è un suo log accanto "
              "al file.") if tipo == "ram" else
           tr("Hash della sorgente confrontato con quello registrato dal programma di acquisizione, se c'è un suo log "
              "accanto al file.") if tipo == "logica" else
           tr("Hash dell'estrazione confrontato con quello registrato dal programma di acquisizione, se c'è un suo "
              "log accanto al file."), ""] if mob else
          ["", tr("## Hash dei dati acquisiti (contenuto del supporto originale)"), "",
           tr("Lo SHA-256 qui sopra è quello dei file della copia; questo è l'hash dei dati del supporto, "
           "confrontato con quello registrato dal programma di acquisizione (nell'E01 o nel suo log)."), ""])
    L += hash_dati_md(m.get("hash_dati"))
    if m.get("verifiche"):
        L += ["", tr("Verifiche successive:"), ""]
    for v in m.get("verifiche", []):
        L.append(tr("- Verifica {ts}: {v1}").format(ts=v['ts'], v1='OK' if v['ok'] else tr('NON CORRISPONDE'))
                 + (tr(" (file della copia {v1}").format(v1='uguali' if v.get('file') else 'DIVERSI')
                    + (tr("; dati {dati}").format(dati=v['dati']) if v.get("dati") else "") + ")" if "file" in v else "")
                 + (tr("; registro: {registro}").format(registro=v['registro']) if v.get("registro") else ""))
    L += [] if mob else ["", tr("## Partizioni"), "",
                         tr("| Offset | File system | Descrizione | OS | File | Cancellati |"),
                         "|---|---|---|---|---|---|"]
    for p in ([] if mob else m.get("partitions", [])):
        L.append(f"| {p['offset']} | {p.get('fs') or tr('non leggibile')} | {p['desc']} | "
                 f"{p.get('os') or '-'} | {p.get('files', '-')} | {p.get('deleted', '-')} |")
    tl = m.get("timeline") or {}
    L += ["", tr("## Analisi eseguite"), "",
          tr("- Timeline: {v1} eventi dai file trovati in memoria (date dei record MFT) e {v2} eventi della memoria letti "
             "da MemProcFS (processi, rete, registro, registri eventi)").format(v1=tl.get('tsk_events', 0), v2=tl.get('ram_events', 0))
          if tipo == "ram" else
          (tr("- Timeline dei file della sorgente (date registrate nell'archivio o nella cartella): {v1} eventi") if tipo == "logica" else
           tr("- Timeline dei file dell'estrazione (date registrate nello zip/tar): {v1} eventi") if is_mobile(case) else
           tr("- Timeline del file system (Sleuth Kit): {v1} eventi")).format(v1=tl.get('tsk_events', 0))]
    if not mob:
        L.append(tr("- Timeline di sistema (plaso): ") + (f"{tl['plaso_events']} eventi"
                                                        if tl.get("plaso_events") else tr("non eseguita")))
    i = m.get("indice")
    L.append(tr("- Testo dei documenti e media (exiftool): {documenti} documenti indicizzati, "
                "{metadati} file con metadati, {gps} con coordinate GPS").format(documenti=i['documenti'], metadati=i['metadati'], gps=i['gps'])
             if i else tr("- Testo dei documenti e media: non eseguito"))
    if i and i.get("non_indicizzati"):
        L.append(tr("  - File non indicizzati o indicizzati solo in parte: {non_indicizzati} (elenco con il "
                    "motivo in `non_indicizzati.csv`): la ricerca per parola nel testo dei documenti non li "
                    "copre per intero").format(non_indicizzati=i['non_indicizzati']))
    for w in (i or {}).get("avvisi", []):
        L.append(tr("  - Attenzione: {w}").format(w=w))
    hf = m.get("hash_file")
    L.append(tr("- Hash MD5, SHA-1 e SHA-256 dei file: {files} file").format(files=hf['files']) if hf
             else tr("- Hash dei singoli file: non calcolati"))
    c = m.get("carving") or {}
    if c:
        pr, be = c.get("photorec"), c.get("bulk_extractor")
        if pr:
            L.append(tr("- Carving con PhotoRec dello spazio libero: {files} file recuperati (").format(files=pr['files'])
                     + ", ".join(f"{k} {v}" for k, v in list(pr["by_type"].items())[:12])
                     + tr("), in `{dir}`; elenco con offset e SHA-256 di ciascun file in `{dir}/file_recuperati.csv`").format(dir=c['dir']))
            L += [tr("  - Attenzione: {w}").format(w=w) for w in pr.get("warnings", [])]
        if be:
            L.append(tr("- Evidenze di interesse (bulk_extractor): ")
                     + (", ".join(f"{k} {v}" for k, v in be["kinds"].items()) or "nessuna"))
    elif not mob:
        L.append(tr("- Carving dello spazio libero: non eseguito"))
    if is_mobile(case):                  # smartphone: estrazione, chat, iLEAPP/ALEAPP e limiti
        import forense_mobile_chat as fmc
        L += fmc.report_md(case)
    exp = sorted(case.export_dir.glob("selezione_*/manifest.csv")) if case.export_dir.exists() else []
    if exp:
        L += ["", tr("## File esportati"), ""]
        for mf in exp:
            n = max(0, sum(1 for _ in open(mf, encoding="utf-8-sig")) - 1)
            L.append(tr("- `{v1}`: {n} file, con percorso originale, inode e SHA-256 in `{v2}`").format(v1=mf.parent.relative_to(case.root), n=n, v2=mf.relative_to(case.root)))
    L += ["", tr("## Reperti"), ""]
    if not f:
        L.append(tr("Nessun reperto registrato."))
    bms = bookmarks(case)
    for x in f:
        L += [f"### {x['n']}. {x['title']}", "", f"**[{finding_label(x)}]**", "", x["description"], "",
              tr("**Riferimenti:** {references}").format(references=x['references']), ""]
    if bms:
        L += [tr("## Preferiti"), "",
              tr("File classificati dall'analista per categoria (offset della partizione, inode, stato)."), ""]
        for cat in bms:
            L += [tr("### {name} ({v1} file)").format(name=cat['name'], v1=len(cat['items'])), ""]
            if cat["note"]:
                L += [cat["note"], ""]
            L += [tr("| File | Offset | Inode | Stato | Dimensione | Modificato | SHA-256 | Nota |"),
                  "|---|---|---|---|---|---|---|---|"]
            cell = lambda v: str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")
            for it in cat["items"][:5000]:
                L.append("| " + " | ".join(cell(v) for v in (
                    it["path"], it["part"] if it["source"] in ("fs", "ua") and (it["part"] or 0) >= 0
                    else tr("disco") if it["source"] == "ua" else {"carving": tr("recuperato"), "x": tr("estratto"),
                                                                   "mail": tr("posta"), "art": tr("artefatto"),
                                                                   "chat": tr("messaggio")}.get(it["source"], ""),
                    it["inode"] if it["source"] == "fs" else _ua_pos(it["inode"]) if it["source"] == "ua" else "",
                    tr("non allocato") if it["source"] == "ua" else tr("cancellato") if it["deleted"] else tr("allocato"),
                    it["size"], (it["mtime"] or "").replace("T", " "), it["sha256"] or "", it["note"])) + " |")
            if len(cat["items"]) > 5000:
                L.append(tr("| … altri {v1} file (elenco completo nel report portatile) | | | | | | | |").format(v1=len(cat['items']) - 5000))
            L.append("")
        L += cited_report_md(case, bms)
        L += bookmarks_timeline_md(case)
        if is_mobile(case):
            import forense_mobile_chat as fmc
            L += fmc.preferiti_chat_md(case)
    try:
        import forense_estesa as fe
        L += fe.report_md(case)
    except ImportError:
        pass
    est = m.get("estese") or {}
    L += [tr("## Note metodologiche"), "", fmc.metodo_md(case)] if mob else [tr("## Note metodologiche"), "",
          tr("L'analisi è stata condotta su copia in sola lettura con The Sleuth Kit")
          + (tr(", plaso") if tl.get("plaso_events") else "")
          + (tr(", exiftool") if m.get("indice") else "")
          + (tr(", PhotoRec") if c.get("photorec") else "")
          + (tr(", bulk_extractor") if c.get("bulk_extractor") else "")
          + (tr(", 7-Zip e libpff (archivi e posta)") if "archivi" in est else "")
          + (tr(", libregf, libscca, liblnk e libolecf (artefatti di sistema)") if "artefatti" in est else "")
          + (tr(", libvshadow (copie shadow)") if "vss" in est else "")
          + (tr(", Sleuth Kit APFS (snapshot)") if (est.get("vss") or {}).get("snapshot_apfs") else "")
          + (tr(", Tesseract (OCR)") if "ocr" in est else "")
          + ". " + modello_metodo_md(case)
          + verifica_reperti_md(f)
          + tr("La traccia completa di comandi e risposte è in `audit_log.jsonl`.")]
    try:
        import forense_riscontro as fr
        L += [""] + fr.report_md(case) if m.get("riscontri") else []
    except ImportError:
        pass
    L += ambiente_md(m, usati if mob else None)
    av = audit_verifica(case)
    L += ["", tr("## Registro delle operazioni (audit_log.jsonl)"), "",
          tr("- Stato: {v1}").format(v1=audit_testo(av)),
          tr("- Voci nel registro al momento del report: {v1}").format(v1=av.get('righe', 0)),
          tr("- Hash finale del registro (SHA-256 dell'ultima riga) al momento del report: `{v1}`").format(v1=av.get('ultimo_hash') or '-'),
          tr("- Ogni riga contiene lo SHA-256 della precedente: una riga modificata, tolta o inserita dopo "
          "questa data rompe la catena; l'hash qui sopra fissa il registro a questo report (la riga "
          "«report» successiva vi si aggancia)."),
          tr("- Verifica successiva: «Verifica registro» in RepertIA, oppure da terminale `python3 forense_registro.py "
             "<cartella del caso> --hash-finale {h} --voci {n}` (il file è tra i sorgenti di RepertIA e usa solo Python): "
             "dice se il registro di allora è ancora tutto lì, quali righe sono state alterate o tolte e se i file esportati "
             "sono ancora uguali.").format(h=av.get('ultimo_hash') or '-', n=av.get('righe', 0))]
    path = case.root / "report.md"
    path.write_text("\n".join(L), encoding="utf-8")
    case.log("report", str(path))
    return path


def _fuso_telefono_md(m):
    """(2.20) Riga del fuso nei report dei casi smartphone (niente FAT/NTFS)."""
    f = m.get("fuso_dispositivo") or {}
    det = f.get("rilevato") or {}
    if m.get("ram_dump"):                 # (3.0.4) dump della memoria: il fuso è quello del computer acquisito
        return tr("- Fuso orario del computer acquisito: {tz} ({o}). Le date lette dalla memoria (processi, connessioni, "
                  "record MFT, registro, registri eventi) sono assolute e le tabelle le riportano in UTC.").format(
            tz=f.get("tz") or "-", o=f.get("origine") or "-")
    if m.get("logica"):                   # (3.0.4) archivio, AD1 o cartella: non è un telefono
        return tr("- Fuso orario usato per le date senza fuso (es. date DOS degli zip): {tz} ({o}{d}). Le altre date "
                  "della sorgente e dei database sono assolute e le tabelle le riportano in UTC.").format(
            tz=f.get("tz") or "-", o=f.get("origine") or "-",
            d=(", " + tr("letto da {p}").format(p=det["origine"])) if det.get("origine") and det.get("tz") else "")
    return tr("- Fuso orario del telefono, usato per le poche date senza fuso (es. date DOS degli zip): {tz} ({o}{d}). "
              "Le altre date dell'estrazione e dei database sono assolute e le tabelle le riportano in UTC.").format(
        tz=f.get("tz") or "-", o=f.get("origine") or "-",
        d=(", " + tr("letto da {p}").format(p=det["origine"])) if det.get("origine") and det.get("tz") else "")


def ambiente_md(m, usati=None):
    """Versioni degli strumenti e impronta del programma: alla preparazione e ora. (2.20) `usati` (casi smartphone):
    elenco degli strumenti usati nel caso; delle versioni installate si mostrano solo quelle."""
    L = []
    try:
        cur = ambiente()
    except Exception:
        cur = None
    prep = m.get("ambiente")
    L += ["", tr("## Ambiente di analisi"), "",
          tr("- Lingua dei testi del caso: {v1}").format(v1=lg.LINGUE[lg.valida(m.get("lingua"))])]
    same = bool(prep and cur and prep.get("impronta_programma") == cur.get("impronta_programma")
                and prep.get("strumenti") == cur.get("strumenti"))
    for lab, a in ((tr("alla preparazione del caso"), prep), (tr("alla stesura del report"), None if same else cur)):
        if not a:
            if lab == tr("alla preparazione del caso"):
                L.append(tr("- Ambiente alla preparazione: non registrato (caso preparato prima della 2.14)."))
            continue
        L.append(tr("- {APP_NAME} {v1} {lab} ({v2}); impronta del programma (SHA-256 dei file forense_* e lingua_*): "
                    "`{v3}`").format(APP_NAME=APP_NAME, v1=a.get('versione'), lab=lab, v2=a.get('ts'), v3=a.get('impronta_programma')))
        st = a.get("strumenti") or {}
        if usati is not None:
            nomi = {k.lower() for k, _v in usati}
            st = {k: v for k, v in st.items() if k in ("python", "sistema") or k.lower() in nomi}
        L.append("  - " + "; ".join(f"{k}: {v}" for k, v in st.items()))
    if same:
        L.append(tr("- Alla stesura del report programma e strumenti sono identici a quelli della preparazione."))
    if usati is not None:
        L.append(tr("- Strumenti usati in questo caso:"))
        L += [f"  - {k}: {v}" for k, v in usati]
    if prep and cur and prep.get("impronta_programma") != cur.get("impronta_programma"):
        L.append(tr("- Nota: il programma è cambiato tra la preparazione e il report (aggiornamento): i risultati "
                 "già presenti nel caso sono quelli prodotti dalla versione della preparazione."))
    return L
