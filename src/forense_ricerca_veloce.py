# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (2.20) – ricerca veloce nei risultati del caso.

Cerca, mentre si scrive, in quello che il caso mostra come risultato: artefatti (di sistema dei dischi, iLEAPP/ALEAPP,
chiamate, riepiloghi delle chat), messaggi con i nomi degli allegati, conversazioni, rubriche, posta. (3.0) Cerca anche, senza
indice proprio, in nomi e percorsi dei file, testo dei documenti indicizzati, metadati, file recuperati ed estratti, tracce.
Non legge la copia forense: per i byte grezzi resta la ricerca per parole chiave, e ogni risposta dichiara cosa non ha coperto.

L'indice è un file a parte nella cartella del caso, `ricerca_veloce.sqlite` (FTS5 con tokenizzatore «trigram»: trova
qualunque sottostringa di almeno 3 caratteri). (3.0) Testi e ricerche passano da `_spazi` e `_piega`: spazi e a capo contano
come uno spazio, maiuscole, accenti e apostrofi tipografici non contano; sotto i 3 caratteri si scorre l'indice. I database del caso non cambiano;
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
import unicodedata
from functools import lru_cache
from pathlib import Path

from forense_lingua import tr, N_  # noqa: E402

FILE = "ricerca_veloce.sqlite"
VERSIONE = 3
MIN_CAR = 3
MAX_RIGHE = 2000                # risultati per fonte restituiti a una ricerca dal vivo: una fonte non nasconde le altre
MAX_ALTRI = 500                 # (3.0) righe per gruppo di file, documenti, metadati, recuperati, tracce
MAX_SALVA = 100000              # risultati salvati come ricerca
CIFRE_TEL = 9                   # cifre finali confrontate per i numeri di telefono
TEL_RX = re.compile(r"\+?\d[\d\s().\-/]{4,}\d")
NON_CIFRE = re.compile(r"\D")
TEL_Q = re.compile(r"^[+\d\s().\-/]+$")
FONTI = {"art": N_("artefatto"), "msg": N_("messaggio"), "thr": N_("conversazione"), "rub": N_("rubrica"), "mail": N_("posta")}

_STATO = {}                     # cartella del caso → {"fatte", "totale", "errore", "inizio"}
_LOCK = threading.Lock()


INVISIBILI = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"))
TIPOGRAFICI = {"’": "'", "‘": "'", "‚": "'", "“": '"', "”": '"', "„": '"', "«": '"', "»": '"', "–": "-", "—": "-"}


def _spazi(s):
    """Testo senza caratteri invisibili e con un solo spazio fra le parole."""
    return " ".join(str(s or "").translate(INVISIBILI).split())


@lru_cache(maxsize=4096)
def _car(c):
    if c in TIPOGRAFICI:
        return TIPOGRAFICI[c]
    b = unicodedata.normalize("NFKD", c)
    if len(b) > 1 and all(unicodedata.category(x) == "Mn" for x in b[1:]):
        c = b[0]
    b = c.lower()
    return b if len(b) == 1 else c


def _piega(s):
    """Maiuscole, accenti e apostrofi tipografici non contano. Stessa lunghezza del testo: le posizioni restano valide."""
    return "".join(_car(c) for c in s)


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
    for tab in ("artifacts", "chat_messages", "chat_threads", "chat_contacts", "chat_attachments", "mail"):
        if tab in t:
            out[tab] = list(con.execute(f"SELECT COUNT(*), MAX(id) FROM {tab}").fetchone())
    return out


def _testo_art(title, user, data):
    v = _valori(data)
    return " ".join(x for x in ((title if not (title and title in v) else None), user, v) if x)


def _righe(con):
    """(testo, numeri, fonte, id) per tutte le righe da indicizzare."""
    for tx, tel, fonte, i in _righe_grezze(con):
        yield _piega(_spazi(tx)), tel, fonte, i


def _blocchi(con, cols, tab, n=2000):
    """(3.0.1) Righe di una tabella a blocchi di `n` per id: tra un blocco e l'altro caso.sqlite resta libero, così
    un'analisi o la conferma di una trascrizione possono scrivere mentre l'indice si costruisce (prima una sola lettura
    di minuti sui casi grandi le bloccava fino a «database is locked»)."""
    ultimo = None
    while True:
        rows = con.execute(f"SELECT id, {cols} FROM {tab}" + (" WHERE id > ?" if ultimo is not None else "") +
                           " ORDER BY id LIMIT ?", ((ultimo, n) if ultimo is not None else (n,))).fetchall()
        if not rows:
            return
        yield from rows
        ultimo = rows[-1][0]


def _righe_grezze(con):
    t = _tabelle(con)
    if "artifacts" in t:
        # titolo e valori dei campi (i «Dettagli» ripetono gli stessi valori; il percorso della fonte, uguale su migliaia
        # di righe, raddoppierebbe l'indice senza servire alla ricerca)
        for i, title, user, data in _blocchi(con, "title, user, data", "artifacts"):
            tx = _testo_art(title, user, data)
            yield tx, _tel(tx), "art", i
    if "chat_messages" in t:
        alleg = {}
        if "chat_attachments" in t:     # nome e percorso degli allegati: si trovano dal messaggio che li porta
            for _i, msg, n, dp, p in _blocchi(con, "msg, name, device_path, path", "chat_attachments"):
                alleg.setdefault(msg, []).extend(x for x in (n, dp, p) if x)
        for i, text, snd, sname, extra in _blocchi(con, "text, sender, sender_name, extra", "chat_messages"):
            tx = " ".join(x for x in (text, snd, sname, *alleg.get(i, ())) if x)
            if extra and '"avviso"' in extra:
                tx += " " + _valori(extra)
            yield tx, _tel(tx), "msg", i
    if "chat_threads" in t:
        for i, title, key, parts, local in _blocchi(con, "title, key, participants, local", "chat_threads"):
            tx = " ".join(x for x in (title, key, _valori(parts) if parts and parts[:1] in "[{" else parts, local) if x)
            yield tx, _tel(tx), "thr", i
    if "chat_contacts" in t:
        for i, src, name, value in _blocchi(con, "source, name, value", "chat_contacts"):
            tx = " ".join(x for x in (name, value, src) if x)
            yield tx, _tel(tx), "rub", i
    if "mail" in t:
        for i, snd, rcp, cc, subj, folder in _blocchi(con, "sender, recipients, cc, subject, folder", "mail"):
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
    q = _spazi(q)
    d = NON_CIFRE.sub("", q)
    if TEL_Q.match(q) and len(d) >= 6:
        k = d[-CIFRE_TEL:]
        return "tel", k, tr("numero (ultime {n} cifre: {c}, in qualunque formato)").format(n=len(k), c=k)
    if len(q) < MIN_CAR:        # due caratteri, o uno solo se non è latino (你, 👍): si scorre l'indice
        return ("corto", _piega(q), None) if len(q) == 2 or (q and ord(q[0]) > 0x24f) else None
    return "testo", _piega(q), None


def _like(s):
    return "%" + s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _frase(s):
    return '"' + s.replace('"', '""') + '"'


def _estratto(testo, q, n=70):
    if not testo:
        return ""
    t = _spazi(testo)
    i = _piega(t).find(_piega(_spazi(q or "")))
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
    if col == "corto":
        cond, arg = "testo LIKE ? ESCAPE '\\'", _like(testo)
    elif col == "tel":          # le cifre possono essere anche un testo qualunque: un codice, una data, un numero di pratica
        cond, arg = "r MATCH ?", "tel : " + _frase(testo) + " OR testo : " + _frase(_piega(_spazi(q)))
    else:
        cond, arg = "r MATCH ?", "testo : " + _frase(testo)
    ix = sqlite3.connect(f"file:{percorso(case).as_posix()}?mode=ro", uri=True)
    try:
        cnt = dict(ix.execute(f"SELECT fonte, COUNT(*) FROM r WHERE {cond} GROUP BY fonte", (arg,)).fetchall())
        tot = sum(cnt.values())
        rows = []
        for fonte in cnt:       # il limite vale per fonte: migliaia di artefatti non devono nascondere i messaggi
            rows += ix.execute(f"SELECT fonte, rid, testo FROM r WHERE {cond} AND fonte = ? LIMIT ?",
                               (arg, fonte, limite)).fetchall()
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
    mark = testo if col != "tel" else None
    if per.get("art"):
        ids = [r[0] for r in per["art"]]
        cols = "id, cat, grp, sub, ts, title, src_path, user, data" if _ha_col(con, "artifacts", "grp") else \
            "id, cat, NULL, NULL, ts, title, src_path, user, data"
        for i in range(0, len(ids), 900):
            part = ids[i:i + 900]
            for aid, cat, grp, sub, ts, title, srcp, user, data in con.execute(
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
                                           "estratto": _estratto(_testo_art(title, user, data), mark) if mark else (title or ""),
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
                if mark and mark not in _piega(_spazi(body)) and _ha_tab(con, "chat_attachments"):   # trovato in un allegato
                    nomi = [x for r in con.execute("SELECT name, device_path, path FROM chat_attachments WHERE msg=?", (mid,))
                            for x in r if x and mark in _piega(_spazi(x))]
                    if nomi:
                        body = f"{body} · 📎 {nomi[0]}"
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


def altri(con, nav, q, limite=MAX_ALTRI):
    """(3.0) Gruppi delle fonti che non stanno nell'indice: file, documenti, metadati, recuperati, estratti, tracce.
    `nav` è l'albero dei file (None se non è pronto). Restituisce (gruppi, avvisi)."""
    q = _spazi(q)
    if len(q) < 2:
        return [], []
    like = _like(q)
    gruppi, avvisi = [], []

    def agg(chiave, titolo, n, righe):
        if n:
            gruppi.append({"chiave": chiave, "titolo": titolo, "n": n, "righe": righe})
    if nav is None:
        avvisi.append(N_("nomi e percorsi dei file (albero in preparazione)"))
    else:
        cond = "isdir = 0 AND type NOT LIKE 'v/%' AND path LIKE ? ESCAPE '\\'"
        agg("file", tr("Nomi e percorsi dei file"), nav.execute(f"SELECT COUNT(*) FROM nav WHERE {cond}", (like,)).fetchone()[0],
            [{"fonte": "fs", "part": p, "inode": i, "name": nm, "deleted": d, "ts": mt, "titolo": nm or "", "estratto": pa or "",
              "dove": tr("cancellato") if d else ""}
             for p, i, nm, pa, d, mt in nav.execute(f"SELECT part, inode, name, path, deleted, mtime FROM nav WHERE {cond} LIMIT ?",
                                                    (like, limite))])
    t = _tabelle(con)
    if "doc_text" in t:
        try:
            mq = _frase(q) + "*"        # indice per parole: trova parole intere e inizi di parola
            n = con.execute("SELECT COUNT(*) FROM doc_text WHERE doc_text MATCH ?", (mq,)).fetchone()[0]
            agg("doc", tr("Testo dei documenti"), n,
                [{"fonte": "doc", "source": s, "part": p, "inode": i, "deleted": d, "ts": None, "titolo": pa or "",
                  "estratto": _spazi(sn).replace("«", "").replace("»", ""), "dove": k or ""}
                 for pa, k, s, p, i, d, sn in con.execute(
                    "SELECT path, kind, source, part, inode, deleted, snippet(doc_text, 1, '«', '»', ' … ', 18) FROM doc_text "
                    "WHERE doc_text MATCH ? ORDER BY rank LIMIT ?", (mq, limite))])
        except sqlite3.OperationalError:
            cond = "(body LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\')"
            agg("doc", tr("Testo dei documenti"), con.execute(f"SELECT COUNT(*) FROM doc_text WHERE {cond}", (like, like)).fetchone()[0],
                [{"fonte": "doc", "source": s, "part": p, "inode": i, "deleted": d, "ts": None, "titolo": pa or "",
                  "estratto": _estratto(b, q), "dove": k or ""}
                 for pa, k, s, p, i, d, b in con.execute(
                    f"SELECT path, kind, source, part, inode, deleted, body FROM doc_text WHERE {cond} LIMIT ?", (like, like, limite))])
    if "meta" in t:
        cond = "(make LIKE ?1 ESCAPE '\\' OR model LIKE ?1 ESCAPE '\\' OR author LIKE ?1 ESCAPE '\\' OR data LIKE ?1 ESCAPE '\\')"
        agg("meta", tr("Metadati"), con.execute(f"SELECT COUNT(*) FROM meta WHERE {cond}", (like,)).fetchone()[0],
            [{"fonte": "doc", "source": s, "part": p, "inode": i, "deleted": d, "ts": tk, "titolo": pa or "",
              "estratto": _estratto(" ".join(x for x in (mk, md, au, _valori(dt)) if x), q), "dove": ""}
             for pa, s, p, i, d, tk, mk, md, au, dt in con.execute(
                f"SELECT path, source, part, inode, deleted, taken, make, model, author, data FROM meta WHERE {cond} LIMIT ?2",
                (like, limite))])
    if "carved" in t:
        cond = "name LIKE ? ESCAPE '\\'"
        agg("carved", tr("File recuperati col carving"), con.execute(f"SELECT COUNT(*) FROM carved WHERE {cond}", (like,)).fetchone()[0],
            [{"fonte": "carving", "name": nm, "ts": None, "titolo": nm or "", "estratto": tr("offset {o}").format(o=o), "dove": ty or ""}
             for nm, ty, o in con.execute(f"SELECT name, type, img_offset FROM carved WHERE {cond} LIMIT ?", (like, limite))])
    if "xitems" in t:
        cond = "(name LIKE ?1 ESCAPE '\\' OR path LIKE ?1 ESCAPE '\\')"
        agg("xitems", tr("File estratti da archivi, allegati e copie shadow"),
            con.execute(f"SELECT COUNT(*) FROM xitems WHERE {cond}", (like,)).fetchone()[0],
            [{"fonte": "x", "id": i, "name": nm, "ts": mt, "titolo": nm or "", "estratto": pa or "", "dove": k or ""}
             for i, nm, pa, k, mt in con.execute(f"SELECT id, name, path, kind, mtime FROM xitems WHERE {cond} LIMIT ?2", (like, limite))])
    if "features" in t:
        cond = "feature LIKE ? ESCAPE '\\'"
        agg("features", tr("Tracce trovate da bulk_extractor"), con.execute(f"SELECT COUNT(*) FROM features WHERE {cond}", (like,)).fetchone()[0],
            [{"fonte": "traccia", "ts": None, "titolo": f or "", "estratto": _spazi(c), "dove": f"{k} · {o}"}
             for k, o, f, c in con.execute(f"SELECT kind, offset, feature, context FROM features WHERE {cond} LIMIT ?", (like, limite))])
    return gruppi, avvisi


def _ha_tab(con, tab):
    return con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (tab,)).fetchone() is not None


def _ha_col(con, tab, col):
    return col in {r[1] for r in con.execute(f"PRAGMA table_info({tab})")}
