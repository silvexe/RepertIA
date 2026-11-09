#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""File e cartelle ATTIVI elencati da RepertIA nelle immagini NIST CFTT DFR-16 e DFR-17 (tabella «Active Files and
Folders Listed» dei rapporti CFTT, §4.14): si contano le voci non cancellate sotto le cartelle di prova (DFR-16
«N-dir-NN», DFR-17 «X01…», «Y01…», «Z01…»), cartelle di prova comprese, escludendo gli oggetti del file system.
Uso: cftt_attivi_dfr.py <cartella dei casi>   → una riga JSON per caso: file e cartelle elencati."""
import json
import re
import sqlite3
import sys
from pathlib import Path

PROVA = re.compile(r"^(\d-dir-\d\d|[A-Z]\d\d)$")


def main():
    casi = Path(sys.argv[1]).expanduser()
    for d in sorted(casi.glob("dfr-1[67]-*")):
        if not (d / "caso.sqlite").exists() or d.name.endswith("osx"):
            continue
        con = sqlite3.connect(f"file:{d / 'caso.sqlite'}?mode=ro", uri=True)
        f = c = 0
        for t, pa in con.execute("SELECT type, path FROM files WHERE deleted=0"):
            if not PROVA.match(pa.split("/")[0]) or pa.endswith(("/.", "/..")):
                continue
            if t.endswith("d"):
                c += 1
            elif t.endswith("r"):
                f += 1
        print(json.dumps({"caso": d.name, "file": f, "cartelle": c}))


if __name__ == "__main__":
    main()
