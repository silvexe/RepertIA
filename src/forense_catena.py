#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - registro delle operazioni a catena di hash (audit_log.jsonl).

(3.0.4) Codice spostato da forense_agent.py senza modifiche, per avere file più corti. Si carica tramite
forense_agent, che ne riesporta i nomi: gli altri moduli continuano a usare «fa.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fa.<nome>»).
"""
import hashlib
import json
import os
import time
from pathlib import Path
from forense_lingua import tr

import forense_agent as fa

# ------------------------------------------------------------ registro a catena di hash

AUDIT_GENESIS = "0" * 64


class _file_lock:
    """Blocco esclusivo su un file di appoggio (GUI e preparazione scrivono lo stesso registro)."""
    def __init__(self, path):
        self.path = Path(path)

    def __enter__(self):
        self.f = open(self.path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                self.f.seek(0)
                for _ in range(600):
                    try:
                        msvcrt.locking(self.f.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        time.sleep(0.05)
            else:
                import fcntl
                fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
        except Exception:
            pass
        return self

    def __exit__(self, *a):
        try:
            if os.name == "nt":
                import msvcrt
                self.f.seek(0)
                msvcrt.locking(self.f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        self.f.close()


def _audit_last(path):
    """(ultima riga in byte senza a capo, suo numero `n` o numero di righe se il registro è
    precedente alla 2.14)."""
    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        return b"", 0
    with open(path, "rb") as f:
        f.seek(0, 2)
        end = f.tell()
        buf, pos = b"", end
        while pos > 0:
            step = min(1 << 16, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            if buf.rstrip(b"\n").count(b"\n") >= 1:
                break
        last = buf.rstrip(b"\n").rsplit(b"\n", 1)[-1]
    try:
        n = json.loads(last.decode("utf-8")).get("n")
    except Exception:
        n = None
    if not isinstance(n, int):
        with open(path, "rb") as f:
            n = sum(1 for ln in f if ln.strip())
    return last, n


def audit_verifica(case_or_path):
    """Controlla la catena del registro. Restituisce righe, prima riga a catena, righe precedenti
    alla 2.14 (senza catena), interruzioni (numero di riga e motivo), hash dell'ultima riga."""
    path = Path(getattr(case_or_path, "log_path", case_or_path))
    res = {"righe": 0, "senza_catena": 0, "catena_da": None, "interruzioni": [], "ultimo_hash": None, "ok": True}
    if not path.exists():
        res["ok"] = None
        return res
    prev_line, expected_n = None, None
    with open(path, "rb") as f:
        for i, raw in enumerate(f, 1):
            line = raw.rstrip(b"\r\n")
            if not line.strip():
                continue
            res["righe"] += 1
            try:
                rec = json.loads(line.decode("utf-8"))
            except Exception:
                rec = None
            if not isinstance(rec, dict) or "prev" not in rec:
                if res["catena_da"] is not None:
                    res["interruzioni"].append({"riga": i, "motivo": tr("riga senza catena dopo l'inizio della catena")})
                else:
                    res["senza_catena"] += 1
            else:
                if res["catena_da"] is None:
                    res["catena_da"] = i
                want = hashlib.sha256(prev_line).hexdigest() if prev_line is not None else AUDIT_GENESIS
                if rec["prev"] != want:
                    res["interruzioni"].append({"riga": i, "motivo": tr("la riga precedente è stata modificata, tolta o inserita")})
                if expected_n is not None and rec.get("n") != expected_n:
                    res["interruzioni"].append({"riga": i, "motivo": tr("numero progressivo {v1} invece di {expected_n}").format(v1=rec.get('n'), expected_n=expected_n)})
                expected_n = (rec.get("n") or 0) + 1
            prev_line = line
    res["ultimo_hash"] = hashlib.sha256(prev_line).hexdigest() if prev_line is not None else None
    res["ok"] = not res["interruzioni"]
    return res


def audit_testo(v):
    if v.get("ok") is None:
        return tr("registro assente")
    s = (tr("{righe} righe; ").format(righe=v['righe']) + (tr("catena integra") if v["ok"] else
         tr("CATENA INTERROTTA alle righe ") + ", ".join(str(r) for r in sorted({x["riga"] for x in v["interruzioni"]})[:10])))
    if v.get("senza_catena"):
        s += tr(" (le prime {senza_catena} righe sono di versioni precedenti alla 2.14, senza catena)").format(senza_catena=v['senza_catena'])
    return s
