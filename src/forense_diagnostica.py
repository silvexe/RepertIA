# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (2.21): log tecnico per capire i malfunzionamenti, separato dal registro del caso (audit_log.jsonl).
Non è una prova del lavoro svolto e non deve contenere dati del caso: si scrivono solo eventi tecnici (versioni,
sistema, API che ha dato errore, tipo di eccezione, file e riga del programma) e ogni testo passa da `pulisci`.
Solo libreria standard; l'errore del log non deve mai fermare il programma."""
import json
import platform
import re
import sys
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path

MAX_BYTE = 2 << 20                  # oltre si ruota in .1 (una sola copia precedente)
MAX_TESTO = 300
LOCK = threading.Lock()
FILE = None

_SOSTITUZIONI = [
    (re.compile(r"""'[^'\n]*'|"[^"\n]*"|«[^»\n]*»|“[^”\n]*”"""), "<testo>"),      # testi tra virgolette: nomi, query, valori
    (re.compile(r"\b[a-z][a-z0-9+.\-]*://\S+", re.I), "<indirizzo>"),
    (re.compile(r"\b[A-Za-z]:[\\/][^\n]*"), "<percorso>"),                        # Windows: gli spazi fanno parte del nome
    (re.compile(r"\\\\[^\n]*"), "<percorso>"),
    (re.compile(r"(?<![\w<])(?:~|\.{1,2})?(?:/[^\s/:;,()\[\]]+){2,}[^\n]*"), "<percorso>"),   # gli spazi possono far parte del nome
    (re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+"), "<email>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<ip>"),
    (re.compile(r"\b[0-9a-fA-F]{8,}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<hash>"),
    (re.compile(r"\+?\d(?:[\s().\-/]?\d){6,}"), "<numero>"),                      # telefoni, identificativi lunghi
]


def pulisci(testo):
    """Toglie da un testo percorsi, virgolettati, indirizzi, email, numeri lunghi e hash; taglia i testi lunghi."""
    s = " ".join(str(testo or "").split())
    for rx, sost in _SOSTITUZIONI:
        s = rx.sub(sost, s)
    return s[:MAX_TESTO]


def installa(percorso):
    """Sceglie il file del log e cattura le eccezioni non gestite del programma e dei thread."""
    global FILE
    FILE = Path(percorso)
    vecchio = sys.excepthook

    def _hook(tipo, e, tb):
        errore("non_gestita", e, tb)
        vecchio(tipo, e, tb)

    def _hook_thread(a):
        errore("thread", a.exc_value, a.exc_traceback)

    sys.excepthook = _hook
    threading.excepthook = _hook_thread


def _scrivi(rec):
    if not FILE:
        return
    try:
        with LOCK:
            FILE.parent.mkdir(parents=True, exist_ok=True)
            if FILE.exists() and FILE.stat().st_size > MAX_BYTE:
                FILE.replace(FILE.with_suffix(FILE.suffix + ".1"))
            with open(FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps({"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), **rec},
                                   ensure_ascii=False) + "\n")
    except OSError:
        pass


def evento(tipo, **campi):
    """Evento tecnico: i testi passano da `pulisci`, numeri e booleani restano."""
    _scrivi({"evento": str(tipo), **{k: (v if isinstance(v, (int, float, bool)) or v is None else pulisci(v))
                                     for k, v in campi.items()}})


def errore(dove, e, tb=None):
    """Eccezione: tipo, messaggio ripulito e pila ridotta a file, riga e funzione (mai i percorsi completi)."""
    pila = [f"{Path(f.filename).name}:{f.lineno} {f.name}" for f in traceback.extract_tb(tb or e.__traceback__)][-8:]
    _scrivi({"evento": "errore", "dove": pulisci(dove), "tipo": type(e).__name__, "messaggio": pulisci(e), "pila": pila})


def errore_processo(fase, rc, righe):
    """Fine anomala di un sottoprocesso: dalla sua uscita si tengono solo la forma della pila e il tipo di errore,
    non il testo a video, che contiene nomi di file e percorsi del caso."""
    pila = []
    for r in righe[-400:]:
        m = re.match(r'\s*File ".*[\\/]([^\\/"]+)", line (\d+), in (\S+)', r)
        if m:
            pila.append(f"{m.group(1)}:{m.group(2)} {m.group(3)}")
    ultimo = next((m.group(1) for r in reversed(righe[-400:]) for m in [re.match(r"([A-Za-z_][\w.]*(?:Error|Exception|Interrupt))\b", r)] if m), None)
    _scrivi({"evento": "processo_terminato", "fase": pulisci(fase), "rc": rc, "tipo": ultimo, "pila": pila[-8:]})


def leggi():
    """Righe del log, dalla più vecchia (compresa la copia ruotata)."""
    out = []
    if FILE:
        for p in (FILE.with_suffix(FILE.suffix + ".1"), FILE):
            try:
                out += p.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                pass
    return out


def testo(versione, strumenti=None):
    """Testo da consegnare: intestazione tecnica più il log, ripassato da `pulisci` per sicurezza (`pila` e tipi restano)."""
    out = ["RepertIA - log diagnostico", f"Versione: {versione}", f"Creato (UTC): {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S}",
           f"Sistema: {platform.system()} {platform.release()} {platform.machine()}", f"Python: {platform.python_version()}"]
    for k, v in (strumenti or {}).items():
        out.append(f"Strumento {pulisci(k)}: {str(v)[:80]}")                     # solo la versione: i numeri servono
    out += ["", "Non contiene dati dei casi: solo eventi tecnici, con percorsi, nomi e numeri tolti.", ""]
    for r in leggi():
        try:
            d = json.loads(r)
        except ValueError:
            continue
        out.append(" | ".join(f"{k}={' < '.join(pulisci(x) for x in v) if isinstance(v, list) else v if isinstance(v, (int, float, bool)) or v is None or k == 'ts' else pulisci(v)}"
                              for k, v in d.items()))
    return "\n".join(out) + "\n"
