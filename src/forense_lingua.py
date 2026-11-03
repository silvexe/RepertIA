# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""forense_lingua.py - RepertIA by silvexe. Lingua dei testi (italiano o inglese).

I testi nel codice sono in italiano e fanno da chiave: `tr("testo")` restituisce la traduzione nella lingua attiva
(dizionario `lingua_<codice>.json` accanto al programma) oppure il testo stesso se la traduzione manca. I testi con
parti variabili sono modelli: `tr("{n} file letti").format(n=n)`. `N_("testo")` segna un testo da tradurre ma lo
lascia com'è (tabelle definite all'avvio): si traduce dove si usa, con `tr()`.

La lingua attiva è quella del processo (`imposta`) o, solo nel thread corrente, quella indicata con `usa(...)`:
l'interfaccia usa la lingua scelta dall'utente, la preparazione del caso, gli artefatti e i report quella del caso,
scelta alla creazione e salvata in case.json («lingua»). I casi senza lingua sono in italiano."""
import json
import os
import re
import threading
from contextlib import contextmanager
from pathlib import Path

LINGUE = {"it": "Italiano", "en": "English"}
PREDEFINITA = "it"
_HERE = Path(__file__).resolve().parent
_tls = threading.local()
_stato = {"lingua": PREDEFINITA}
_diz = {}
_mancanti = set()
_lock = threading.Lock()


def valida(codice):
    """Codice di lingua riconosciuto, altrimenti quello predefinito."""
    c = (codice or "").strip().lower()[:2]
    return c if c in LINGUE else PREDEFINITA


def dizionario(codice):
    """{testo italiano: traduzione} della lingua indicata (vuoto per l'italiano)."""
    codice = valida(codice)
    if codice == PREDEFINITA:
        return {}
    f = _HERE / f"lingua_{codice}.json"
    try:
        mt = f.stat().st_mtime
    except OSError:
        mt = None
    with _lock:
        if codice not in _diz or _diz[codice][0] != mt:          # si ricarica se il file cambia
            try:
                d = json.loads(f.read_text(encoding="utf-8"))
                _diz[codice] = (mt, {k: v for k, v in d.items() if isinstance(v, str) and v and k != "#"})  # «#»: nota
            except (OSError, ValueError):
                _diz[codice] = (mt, {})
        return _diz[codice][1]


def lingua():
    """Lingua attiva nel thread corrente."""
    return getattr(_tls, "lingua", None) or _stato["lingua"]


def imposta(codice):
    """Lingua del processo (vale in tutti i thread che non ne indicano una con `usa`)."""
    _stato["lingua"] = valida(codice)
    _stato["scelta"] = True
    return _stato["lingua"]


def imposta_predefinita(codice):
    """Lingua iniziale del processo, solo se nessuno l'ha ancora scelta: un modulo importato più volte (per esempio
    forense_agent eseguito come script e poi importato dagli altri moduli) non deve cambiare quella già impostata."""
    if not _stato.get("scelta"):
        _stato["lingua"] = valida(codice)
    return _stato["lingua"]


@contextmanager
def usa(codice):
    """Lingua del solo thread corrente per la durata del blocco (testi di un caso nella lingua del caso)."""
    prima = getattr(_tls, "lingua", None)
    _tls.lingua = valida(codice)
    try:
        yield _tls.lingua
    finally:
        _tls.lingua = prima


def tr(testo):
    """Traduzione di `testo` nella lingua attiva; il testo stesso se è in italiano o se la traduzione manca."""
    c = lingua()
    if c == PREDEFINITA or not testo or not isinstance(testo, str):
        return testo
    t = dizionario(c).get(testo)
    if t is None:
        if os.environ.get("REPERTIA_LINGUA_MANCANTI"):
            _mancanti.add(testo)
        return testo
    return t


# Testi che finiscono salvati nel caso (case.json, doc_text) nella lingua in cui il caso è stato creato. Non si riscrivono:
# `valore` li porta nella lingua attiva solo quando vengono mostrati. I testi esatti prima di quelli con segnaposto.
VALORI = ("estrazione di uno smartphone (sistema non riconosciuto)", "estrazione di uno smartphone {os}", "Estrazione ({fmt})",
          "disco di sistema: {v1}", "supporto dati (nessun sistema operativo rilevato, es. pendrive)",
          "nessun file system leggibile (supporto danneggiato o sconosciuto): solo carving e ricerca nei byte",
          "APFS (contenitore)", "rilevato nel telefono", "rilevato dal sistema del disco", "corretto dall'operatore",
          "scelto dall'operatore", "predefinito (Italia)", "testo UTF-8", "testo UTF-16", "testo (Windows-1252)",
          "PDF senza testo (forse una scansione)", "PDF (pdftotext non installato: stringhe)")


def valore(testo):
    """Testo salvato nel caso, nella lingua attiva; invariato se non è fra i VALORI (dati della prova, nomi di strumenti)."""
    if not testo or not isinstance(testo, str):
        return testo
    forme = [(c, dizionario(c)) for c in LINGUE if c != PREDEFINITA]
    for m in VALORI:
        for f in [m] + [d.get(m) for _, d in forme if d.get(m)]:
            r = re.fullmatch(re.sub(r"\\\{(\w+)\\\}", r"(?P<\1>.+)", re.escape(f)), testo)
            if r:
                return tr(m).format(**r.groupdict())
    return testo


def conta(n, uno, molti):
    """Numero con il nome al singolare o al plurale: `uno` e `molti` sono testi con {n}."""
    return tr(uno if n == 1 else molti).format(n=n)


def N_(testo):
    """Segna un testo da tradurre senza tradurlo (tabelle e valori predefiniti definiti all'avvio)."""
    return testo


def mancanti():
    """Testi chiesti e non tradotti (solo con la variabile REPERTIA_LINGUA_MANCANTI, per i controlli)."""
    return sorted(_mancanti)


def segna_gui():
    """Processo dell'interfaccia: la sua lingua è quella scelta dall'utente e aprire un caso non la cambia."""
    _stato["gui"] = True


def imposta_caso(case):
    """Fuori dall'interfaccia (preparazione, analisi da terminale, collaudo) la lingua del processo è quella del caso."""
    if not _stato.get("gui"):
        imposta(lingua_caso(case))


def lingua_caso(case):
    """Lingua dei testi di un caso: quella scelta alla creazione (case.json), italiano per i casi precedenti."""
    meta = getattr(case, "meta", None) or {}
    return valida(meta.get("lingua"))
