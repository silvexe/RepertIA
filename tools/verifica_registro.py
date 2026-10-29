#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Verifica da terminale del registro a catena di un caso di RepertIA (2.20).

Uso:  python3 tools/verifica_registro.py <audit_log.jsonl | cartella del caso> [--hash-finale H] [--voci N]
                                         [--no-file] [--json] [--lingua it|en]

Ricalcola la catena di audit_log.jsonl (righe alterate, tolte in mezzo, inserite), confronta l'hash finale e il
numero di voci stampati nel report (righe tolte in fondo, registro riscritto) e ricontrolla gli SHA-256 dei file
esportati citati nel registro che si trovano nella cartella del caso. Esce con 0 se tutto torna, 1 se no, 2 se il
registro non c'è. Il lavoro lo fa src/forense_registro.py (solo libreria standard di Python: si può usare anche
senza RepertIA installato, copiando quel file). Cosa dimostra e cosa no: manuale, sezione «Verifica del registro».
"""
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

import forense_registro  # noqa: E402

if __name__ == "__main__":
    sys.exit(forense_registro.main())
