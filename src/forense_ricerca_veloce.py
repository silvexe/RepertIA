# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (2.20) – ricerca veloce nei risultati del caso.

Cerca, mentre si scrive, in quello che il caso mostra come risultato: artefatti (di sistema dei dischi, iLEAPP/ALEAPP,
chiamate, riepiloghi delle chat), messaggi e conversazioni delle chat, nomi delle rubriche, posta. Non legge la copia
forense: per il contenuto dei file resta la ricerca per parole chiave.

L'indice è un file a parte nella cartella del caso, `ricerca_veloce.sqlite` (FTS5 con tokenizzatore «trigram»: trova
qualunque sottostringa di almeno 3 caratteri, senza distinguere maiuscole e minuscole). I database del caso non cambiano;
il file si può cancellare e viene ricostruito alla ricerca successiva. Si ricostruisce da solo quando cambiano i risultati
del caso (numero e ultimo identificativo delle righe di ogni tabella).

Numeri di telefono: per ogni testo si ricavano anche le sequenze che sembrano numeri («+1 (919) 928-2177»,
«19199282177@s.whatsapp.net», «0039 333 12 34 567») scritte solo come cifre; una ricerca fatta solo di cifre e separatori
(almeno 6 cifre) confronta le ultime 9 cifre, così lo stesso numero si trova in qualunque formato e con o senza prefisso
internazionale.
"""
import json
import re
import sqlite3
import threading
import time
from pathlib import Path

from forense_lingua import tr, N_  # noqa: E402

FILE = "ricerca_veloce.sqlite"
VERSIONE = 2
MIN_CAR = 3
MAX_RIGHE = 2000                # risultati restituiti a una ricerca dal vivo (il conteggio per gruppo è completo)
MAX_SALVA = 100000              # risultati salvati come ricerca
CIFRE_TEL = 9                   # cifre finali confrontate per i numeri di telefono
TEL_RX = re.compile(r"\+?\d[\d\s().\-/]{4,}\d")
NON_CIFRE = re.compile(r"\D")
TEL_Q = re.compile(r"^[+\d\s().\-/]+$")
FONTI = {"art": N_("artefatto"), "msg": N_("messaggio"), "thr": N_("conversazione"), "rub": N_("rubrica"), "mail": N_("posta")}

_STATO = {}                     # cartella del caso → {"fatte", "totale", "errore", "inizio"}
_LOCK = threading.Lock()


def percorso(case):
    return Path(case.root) / FILE


def _tel(testo):
    """Numeri (solo cifre) che compaiono nel testo, almeno 6 cifre ciascuno."""
    out = []
    for m in TEL_RX.findall(testo or ""):
        d = NON_CIFRE.sub("", m)
        if len(d) >= 6:
            out.append(d)
    return " ".join(out)


def _valori(data):
    """Testo di una colonna data JSON: i valori (non i nomi dei campi), anche dei «campi» di iLEAPP/ALEAPP."""
    if not data:
        return ""
    try:
        d = json.loads(data)
    except ValueError:
        return data
    out = []

    def giu(x):
        if isinstance(x, dict):
            for v in x.values():
                giu(v)
        elif isinstance(x, list):
            for v in x:
                giu(v)
        elif x not in (None, "", True, False):
            out.append(str(x))
    giu(d)
    return " ".join(out)


def _tabelle(con):
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def firma(con):
    """Impronta dei risultati del caso: per ogni tabella indicizzata numero di righe e ultimo id."""
    t = _tabelle(con)
    out = {}
    for tab in ("artifacts", "chat_messages", "chat_threads", "chat_contacts", "mail"):
        if tab in t:
            out[tab] = list(con.execute(f"SELECT COUNT(*), MAX(id) FROM {tab}").fetchone())
    return out


def _righe(con):
    """(testo, numeri, fonte, id) per tutte le righe da indicizzare."""
    t = _tabelle(con)
    if "artifacts" in t:
        # titolo e valori dei campi (i «Dettagli» ripetono gli stessi valori; il percorso della fonte, uguale su migliaia
        # di righe, raddoppierebbe l'indice senza servire alla ricerca)
        for i, title, user, data in con.execute("SELECT id, title, user, data FROM artifacts"):
            v = _valori(data)
            tx = " ".join(x for x in ((title if not (title and title in v) else None), user, v) if x)
            yield tx, _tel(tx), "art", i
    if "chat_messages" in t:
        for i, text, snd, sname, extra in con.execute(
                "SELECT id, text, sender, sender_name, extra FROM chat_messages"):
            tx = " ".join(x for x in (text, snd, sname) if x)
            if extra and '"avviso"' in extra:
                tx += " " + _valori(extra)
            yield tx, _tel(tx), "msg", i
    if "chat_threads" in t:
        for i, title, key, parts, local in con.execute(
                "SELECT id, title, key, participants, local FROM chat_threads"):
            tx = " ".join(x for x in (title, key, _valori(parts) if parts and parts[:1] in "[{" else parts, local) if x)
            yield tx, _tel(tx), "thr", i
    if "chat_contacts" in t:
        for i, src, name, value in con.execute("SELECT id, source, name, value FROM chat_contacts"):
            tx = " ".join(x for x in (name, value, src) if x)
            yield tx, _tel(tx), "rub", i
    if "mail" in t:
        for i, snd, rcp, cc, subj, folder in con.execute(
                "SELECT id, sender, recipients, cc, subject, folder FROM mail"):
            tx = " ".join(x for x in (subj, snd, rcp, cc, folder) if x)
            yield tx, _tel(tx), "mail", i


def _totale(con):
    t = _tabelle(con)
    return sum(con.execute(f"SELECT COUNT(*) FROM {tab}").fetchone()[0]
               for tab in ("artifacts", "chat_messages", "chat_threads", "chat_contacts", "mail") if tab in t)


def aggiornato(case, con):
    """True se l'indice esiste ed è dei risultati attuali del caso."""
    p = percorso(case)
    if not p.exists():
        return False
    try:
        ix = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)
        try:
            r = dict(ix.execute("SELECT k, v FROM info").fetchall())
        finally:
            ix.close()
    except sqlite3.Error:
        return False
    return r.get("versione") == str(VERSIONE) and r.get("firma") == json.dumps(firma(con), sort_keys=True)


def costruisci(case, db_ro):
    """Ricostruisce l'indice (in un file temporaneo, poi lo sostituisce). `db_ro(case)` apre caso.sqlite in lettura."""
    key = str(case.root)
    st = {"fatte": 0, "totale": 0, "errore": None, "inizio": time.time()}
    _STATO[key] = st
    p = percorso(case)
    tmp = p.with_name(FILE + ".tmp")
    try:
        con = db_ro(case)
        try:
            st["totale"] = _totale(con)
            f = firma(con)
            if tmp.exists():
                tmp.unlink()
            ix = sqlite3.connect(tmp)
            try:
                ix.executescript("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;"
                                 "CREATE TABLE info(k TEXT PRIMARY KEY, v TEXT);"
                                 "CREATE VIRTUAL TABLE r USING fts5(testo, tel, fonte UNINDEXED, rid UNINDEXED, "
                                 "tokenize='trigram');")
                buf = []
                for row in _righe(con):
                    buf.append(row)
                    if len(buf) >= 5000:
                        ix.executemany("INSERT INTO r VALUES (?,?,?,?)", buf)
                        st["fatte"] += len(buf)
                        buf = []
                if buf:
                    ix.executemany("INSERT INTO r VALUES (?,?,?,?)", buf)
                    st["fatte"] += len(buf)
                ix.execute("INSERT INTO r(r) VALUES ('optimize')")
                ix.executemany("INSERT INTO info VALUES (?,?)", [("versione", str(VERSIONE)),
                                                                  ("firma", json.dumps(f, sort_keys=True)),
                                                                  ("righe", str(st["fatte"]))])
                ix.commit()
            finally:
                ix.close()
        finally:
            con.close()
        tmp.replace(p)
        case.log("ricerca_veloce_indice", {"file": FILE, "righe": st["fatte"], "byte": p.stat().st_size,
                                           "secondi": round(time.time() - st["inizio"], 1)})
    except Exception as e:      # noqa: BLE001 - l'errore va all'interfaccia
        st["errore"] = str(e)
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
    finally:
        st["fine"] = time.time()


def avvia(case, db_ro):
    """Avvia la costruzione in un thread se non è già in corso. Restituisce lo stato."""
    key = str(case.root)
    with _LOCK:
        st = _STATO.get(key)
        if st and "fine" not in st:
            return st
        th = threading.Thread(target=costruisci, args=(case, db_ro), daemon=True)
        _STATO[key] = {"fatte": 0, "totale": 0, "errore": None, "inizio": time.time()}
        th.start()
        return _STATO[key]


def stato(case):
    return _STATO.get(str(case.root))


def interpreta(q):
    """(colonna, testo da cercare, descrizione) per una ricerca; None se troppo corta."""
    q = (q or "").strip()
    d = NON_CIFRE.sub("", q)
    if TEL_Q.match(q) and len(d) >= 6:
        k = d[-CIFRE_TEL:]
        return "tel", k, tr("numero (ultime {n} cifre: {c}, in qualunque formato)").format(n=len(k), c=k)
    if len(q) < MIN_CAR:
        return None
    return "testo", q, None


def _frase(s):
    return '"' + s.replace('"', '""') + '"'


def _estratto(testo, q, n=70):
    if not testo:
        return ""
    t = " ".join(testo.split())
    i = t.lower().find(q.lower())
    if i < 0:
        return t[:2 * n]
    a = max(0, i - n)
    return ("…" if a else "") + t[a:i + len(q) + n] + ("…" if i + len(q) + n < len(t) else "")


def cerca_id(case, q, limite=MAX_RIGHE):
    """[(fonte, id)] che corrispondono a q, e il totale."""
    it = interpreta(q)
    if not it:
        return [], 0, None
    col, testo, desc = it
    ix = sqlite3.connect(f"file:{percorso(case).as_posix()}?mode=ro", uri=True)
    try:
        tot = ix.execute(f"SELECT COUNT(*) FROM r WHERE {col} MATCH ?", (_frase(testo),)).fetchone()[0]
        rows = ix.execute(f"SELECT fonte, rid, testo FROM r WHERE {col} MATCH ? LIMIT ?",
                          (_frase(testo), limite)).fetchall()
        cnt = dict(ix.execute(f"SELECT fonte, COUNT(*) FROM r WHERE {col} MATCH ? GROUP BY fonte",
                              (_frase(testo),)).fetchall())
    finally:
        ix.close()
    return rows, tot, (desc, cnt, col, testo)


def risultati(case, con, q, app_lbl=None, limite=MAX_RIGHE):
    """Risultati raggruppati per sezione dei Risultati: {gruppi: [{chiave, titolo, n, righe: [...]}], totale, mostrati}."""
    rows, tot, extra = cerca_id(case, q, limite)
    if extra is None:
        return {"totale": 0, "gruppi": [], "corta": True}
    desc, cnt, col, testo = extra
    app_lbl = app_lbl or {}
    gruppi = {}

    def g(chiave, titolo):
        if chiave not in gruppi:
            gruppi[chiave] = {"chiave": chiave, "titolo": titolo, "righe": [], "n": 0}
        return gruppi[chiave]
    per = {}
    for fonte, rid, tx in rows:
        per.setdefault(fonte, []).append((int(rid), tx))
    mark = testo if col == "testo" else None
    if per.get("art"):
        ids = [r[0] for r in per["art"]]
        txt = dict(per["art"])
        cols = "id, cat, grp, sub, ts, title, src_path" if _ha_col(con, "artifacts", "grp") else \
            "id, cat, NULL, NULL, ts, title, src_path"
        for i in range(0, len(ids), 900):
            part = ids[i:i + 900]
            for aid, cat, grp, sub, ts, title, srcp in con.execute(
                    f"SELECT {cols} FROM artifacts WHERE id IN ({','.join('?' * len(part))})", part):
                if cat == "leapp":
                    k, tit = f"leapp|{grp}|{sub}", f"{tr('Artefatti iLEAPP/ALEAPP')} › {grp or ''} › {sub or ''}"
                elif cat == "chiamate":
                    k, tit = "chiamate", tr("Chiamate")
                elif cat == "messaggi":
                    k, tit = "messaggi", tr("Messaggi delle chat") + " (" + tr("riepilogo per conversazione") + ")"
                else:
                    k, tit = f"art|{cat}", tr("Artefatti di sistema") + f" › {cat}"
                g(k, tit)["righe"].append({"fonte": "art", "id": aid, "ts": ts, "titolo": title or "",
                                           "estratto": _estratto(txt.get(aid), mark) if mark else (title or ""),
                                           "dove": srcp or "", "cat": cat})
    if per.get("msg"):
        ids = [r[0] for r in per["msg"]]
        for i in range(0, len(ids), 900):
            part = ids[i:i + 900]
            for mid, app, ts, d, snd, sname, text, kind, tb, row, title in con.execute(
                    "SELECT m.id, m.app, m.ts, m.direction, m.sender, m.sender_name, m.text, m.kind, m.src_table, m.src_row, "
                    f"t.title FROM chat_messages m JOIN chat_threads t ON t.id = m.thread WHERE m.id IN ({','.join('?' * len(part))})",
                    part):
                who = tr("inviato") if d == "out" else (sname or snd or (tr("evento") if d == "sys" else tr("ricevuto")))
                body = text or f"[{kind}]"
                g(f"chat|{app}", tr("Chat") + f" › {app_lbl.get(app, app)}")["righe"].append(
                    {"fonte": "msg", "id": mid, "ts": ts, "titolo": f"{title} · {who}",
                     "estratto": _estratto(body, mark) if mark else body[:160], "dove": f"{tb} #{row}", "dir": d})
    if per.get("thr"):
        ids = [r[0] for r in per["thr"]]
        for i in range(0, len(ids), 900):
            part = ids[i:i + 900]
            for tid, app, title, n, last in con.execute(
                    f"SELECT id, app, title, n_msg, last_ts FROM chat_threads WHERE id IN ({','.join('?' * len(part))})", part):
                g("thr", tr("Conversazioni"))["righe"].append(
                    {"fonte": "thr", "id": tid, "ts": last, "titolo": f"{app_lbl.get(app, app)} · {title}",
                     "estratto": tr("{n} messaggi").format(n=n or 0), "dove": "", "app": app})
    if per.get("rub"):
        ids = [r[0] for r in per["rub"]]
        for i in range(0, len(ids), 900):
            part = ids[i:i + 900]
            for cid, src, name, value in con.execute(
                    f"SELECT id, source, name, value FROM chat_contacts WHERE id IN ({','.join('?' * len(part))})", part):
                g("rub", tr("Rubriche"))["righe"].append({"fonte": "rub", "id": cid, "ts": None, "titolo": name or "",
                                                          "estratto": value or "", "dove": src or ""})
    if per.get("mail"):
        ids = [r[0] for r in per["mail"]]
        for i in range(0, len(ids), 900):
            part = ids[i:i + 900]
            for mid, snd, subj, date, folder in con.execute(
                    f"SELECT id, sender, subject, date, folder FROM mail WHERE id IN ({','.join('?' * len(part))})", part):
                g("mail", tr("Posta"))["righe"].append({"fonte": "mail", "id": mid, "ts": date, "titolo": subj or "",
                                                        "estratto": snd or "", "dove": folder or ""})
    for x in gruppi.values():
        x["n"] = len(x["righe"])
        x["righe"].sort(key=lambda r: r.get("ts") or "", reverse=True)
    ordine = ("rub", "thr", "chat", "chiamate", "messaggi", "mail", "leapp", "art")
    out = sorted(gruppi.values(), key=lambda x: (next((i for i, o in enumerate(ordine) if x["chiave"].startswith(o)), 99),
                                                   x["titolo"].lower()))
    return {"totale": tot, "mostrati": len(rows), "gruppi": out, "per_fonte": cnt, "numero": desc}


def _ha_col(con, tab, col):
    return col in {r[1] for r in con.execute(f"PRAGMA table_info({tab})")}
