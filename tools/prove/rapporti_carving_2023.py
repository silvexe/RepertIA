#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Dai rapporti NIST CFTT «Test Results for Graphic File Carving Tool» del 2024-2025 (set «File Carving Graphic Files»
2023, testo estratto con pdftotext -layout): per ogni strumento, formato (HEIC, PNG, JPG, BMP, TIFF, GIF) e disposizione
(contiguo, non allineato, frammentato) quanti file recuperati sono giudicati «Complete no flaws» e quanti sono i
file recuperati in tutto. Uscita: JSON {strumento: {formato: {disposizione: [completi, recuperati]}}}.
Uso: rapporti_carving_2023.py <cartella dei .txt> <uscita .json>"""
import json
import re
import sys
from pathlib import Path

NUOVI = {"photorec_7.2": "PhotoRec 7.2-WIP", "xways_20.9": "X-Ways 20.9", "ftk_8.0": "FTK 8.0",
         "autopsy_4.21": "Autopsy 4.21", "axiom_7.5": "Magnet Axiom 7.5", "cellebrite_pa_7.62": "Cellebrite PA 7.62",
         "forensic_explorer_5.6.8": "Forensic Explorer 5.6.8", "dc3_advanced_carver_1.5": "DC3 Advanced Carver 1.5",
         "r-studio_9.3": "R-Studio 9.3", "scalpel_1.60": "Scalpel 1.60", "recover_my_files_6.4": "Recover My Files 6.4",
         "file_juicer_4.98": "File Juicer 4.98", "belkasoft_2.0": "Belkasoft 2.0"}
SEZ = re.compile(r"Inspection Results for (Contiguous|Non-Aligned on Clusters|Fragmented in Order) Image of (\w+) Files", re.I)
DISP = {"contiguous": "contiguo", "non-aligned on clusters": "non allineato", "fragmented in order": "frammentato"}
cart, out = Path(sys.argv[1]).expanduser(), {}
for f, nome in NUOVI.items():
    p = cart / f"{f}.txt"
    if not p.exists():
        continue
    t = p.read_text(encoding="utf-8", errors="replace")
    sez = list(SEZ.finditer(t))
    r = {}
    for i, m in enumerate(sez):
        fine = sez[i + 1].start() if i + 1 < len(sez) else len(t)
        corpo = t[m.end():fine]
        corpo = corpo[:corpo.find("Description of Carved Files")] if "Description of Carved Files" in corpo else corpo[:4000]
        # le celle vanno a capo in modo diverso da un rapporto all'altro: si conta sul testo con gli spazi uniti
        piatto = re.sub(r"\s+", " ", corpo)
        compl = len(re.findall(r"Complete no flaws", piatto, re.I))
        codici = set(re.findall(r"[A-Z]\d{3}", piatto))
        r.setdefault(m.group(2).upper(), {})[DISP[m.group(1).lower()]] = [compl, len(codici)]
    out[nome] = r
Path(sys.argv[2]).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
for nome, r in out.items():
    print(nome, {k: {d: v[0] for d, v in x.items()} for k, x in r.items()})
