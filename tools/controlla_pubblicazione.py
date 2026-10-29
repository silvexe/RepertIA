#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Controllo prima della pubblicazione: cerca nei file del repository dati che non devono uscire
(dati di casi reali, percorsi personali, indirizzi, identificativi).

Uso:
    python3 tools/controlla_pubblicazione.py [cartella] [--parole parole_riservate.txt]

`parole_riservate.txt` (da NON pubblicare: è nel .gitignore) contiene, una per riga, nomi, indirizzi,
nomi di computer, numeri di procedimento o altre parole dei casi da cercare in più.
Esce con codice 1 se trova qualcosa: si può usare come controllo automatico prima di ogni «git push»."""
import argparse
import re
import sys
from pathlib import Path

# (nome della regola, espressione, spiegazione)
RULES = [
    ("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "indirizzo email"),
    ("sid", r"S-1-5-21-\d{6,}-\d+-\d+(?:-\d+)?", "SID di Windows di un computer reale"),
    ("percorso_mac", r"/Users/(?!<|\$|nome|utente|USER)[A-Za-z0-9._-]+", "cartella personale su Mac"),
    ("percorso_win", r"(?i)C:\\\\?Users\\\\?(?!<|%|nome|utente|Public|Default)[A-Za-z0-9._-]+", "cartella personale su Windows"),
    ("volume_esterno", r"/Volumes/(?!<|NomeDisco|Untitled\b)[A-Za-z0-9 ._-]+", "disco esterno con nome"),
    ("ip_privato", r"\b(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b", "indirizzo IP di una rete reale"),
    ("caso", r"(?i)\b(?:procura|rgnr|r\.g\.n\.r|proc\. pen|n\. ?\d+/\d{2,4} r\.?g)", "riferimento a un procedimento"),
    ("hash_e01", r"(?i)image\.E0[1-9]", "nome di una copia forense (verificare che non sia di un caso)"),
]
# eccezioni note e innocue (esempi nella documentazione, indirizzi di servizio)
ALLOW = [
    r"noreply@anthropic\.com", r"@example\.(?:com|org)", r"git@github\.com", r"192\.168\.1\.\d{1,3}",
    r"10\.0\.0\.\d{1,3}",
    r"10\.1\.2\.3", r"172\.16\.0\.5", r"172\.31\.255\.1",   # indirizzi di prova del collaudo (server LLM, 2.20.1)
    r"^/Users/mario$", r"^/Volumes/Reperti",          # utente di fantasia dei dati di collaudo, esempio nell'interfaccia
]
SKIP_DIRS = {".git", "__pycache__", "node_modules"}
TEXT_EXT = {".py", ".html", ".md", ".txt", ".json", ".nsi", ".bat", ".command", ".plist", ".cfg", ".toml", ".yml",
            ".yaml", ".csv", ".sh", ".js", ".css", ""}


def scan(root, extra):
    rules = [(n, re.compile(r), s) for n, r, s in RULES]
    rules += [("parola_riservata", re.compile(r"(?<![A-Za-z0-9])" + re.escape(w) + r"(?![A-Za-z0-9])", re.I),
               "parola dell'elenco riservato") for w in extra]
    allow = [re.compile(a) for a in ALLOW]
    found = 0
    for p in sorted(Path(root).rglob("*")):
        if not p.is_file() or set(p.parts) & SKIP_DIRS or p.suffix.lower() not in TEXT_EXT:
            continue
        if p.name in ("controlla_pubblicazione.py", "parole_riservate.txt"):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for ln, line in enumerate(text.splitlines(), 1):
            for name, rx, why in rules:
                for m in rx.finditer(line):
                    if any(a.search(m.group(0)) for a in allow):
                        continue
                    found += 1
                    print(f"{p.relative_to(root)}:{ln}: [{name}] {why}: «{m.group(0)}»")
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cartella", nargs="?", default=".")
    ap.add_argument("--parole", help="file con parole riservate da cercare (una per riga)")
    a = ap.parse_args()
    extra = []
    if a.parole:
        extra = [w.strip() for w in Path(a.parole).read_text(encoding="utf-8").splitlines() if w.strip() and not w.startswith("#")]
    n = scan(Path(a.cartella), extra)
    print(f"\n{n} possibili dati da controllare." if n else "Nessun dato sensibile trovato con le regole attuali.")
    sys.exit(1 if n else 0)


if __name__ == "__main__":
    main()
