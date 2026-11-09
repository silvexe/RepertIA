#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Confronto del carving di RepertIA con i rapporti NIST CFTT «Test Results for Graphic File Carving Tool» (DHS, 2014,
set di immagini graphic-images.tbz2). I valori degli altri strumenti sono trascritti dalle frasi di riepilogo di ogni prova
dei rapporti («Out of the N graphic files a total of T files were carved - C … Viewable - Complete»); quelli di RepertIA
vengono da valuta_carving_nist.py (uscita .json).
Uso: confronto_cftt_carving.py <valutazione RepertIA .json> <uscita .md>"""
import json
import sys
from pathlib import Path

PROVE = [("graphic-nofill", "Contigui, senza riempimento", 47), ("graphic-basic", "Contigui, con riempimento", 47),
         ("graphic-simple-frag", "Frammentati in ordine", 47), ("graphic-partials", "Incompleti", 45),
         ("graphic-disorder", "Frammentati fuori ordine", 41), ("graphic-braid", "Intrecciati a coppie", 23),
         ("graphic-shifted", "Non allineati ai settori", 47)]
# «Viewable - Complete/minor alteration» per prova, nell'ordine di PROVE (iLook 2.2.7: carving non supportato)
RAPPORTI = {
    "PhotoRec 7.0-WIP": [47, 47, 22, 16, 6, 13, 0],
    "X-Ways Forensics 17.6": [47, 47, 23, 16, 10, 13, 47],
    "FTK 4.1": [33, 33, 14, 13, 7, 9, 33],
    "EnCase 6.18": [30, 30, 17, 15, 16, 9, 30],
    "EnCase 7.09": [29, 21, 10, 9, 4, 6, 21],
    "Scalpel 2.0": [12, 12, 3, 4, 0, 3, 14],
    "R-Studio 6.2": [38, 38, 11, 14, 3, 9, 0],
    "Recover My Files 5.2": [32, 32, 10, 12, 2, 7, 0],
    "Adroit Photo Forensics 3.1d": [33, 35, 25, 11, 13, 11, 23],
}

rep = {r["immagine"].rsplit("_", 1)[0]: r for r in json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))}
L = ["# RepertIA e gli strumenti provati da NIST CFTT: carving di file grafici", "",
     "Stesse 8 immagini NIST (cfreds-archive.nist.gov, `graphic-images.tbz2`, 2014: GIF, BMP, PNG, JPG, TIFF e le "
     "miniature EXIF dei JPG). Valori degli altri strumenti trascritti dai rapporti DHS (2014-2015, «Viewable - "
     "Complete/minor alteration», giudizio a occhio); RepertIA misurato con `tools/prove/valuta_carving_nist.py`, più "
     "severo: **completo** solo se il file recuperato comincia con tutto l'originale, byte per byte. RepertIA usa "
     "PhotoRec 7.2 (incluso nel pacchetto) con i tipi di file predefiniti; iLook 2.2.7 non fa carving.", "",
     "| Prova | File | **RepertIA 3.0.2** | " + " | ".join(RAPPORTI) + " |",
     "|---|---|---|" + "---|" * len(RAPPORTI)]
for i, (img, nome, n) in enumerate(PROVE):
    r = rep.get(img)
    cel = f"**{r['completi']}**" + (f" (+{r['parziali']} parziali)" if r["parziali"] else "") if r else "—"
    L.append(f"| {nome} | {n} | {cel} | " + " | ".join(str(v[i]) for v in RAPPORTI.values()) + " |")
fp = sum(r["falsi_positivi"] for r in rep.values())
L += ["", f"Falsi positivi di RepertIA (file grafici senza nessun blocco di un originale): {fp} in tutto.", ""]
Path(sys.argv[2]).write_text("\n".join(L) + "\n", encoding="utf-8")
print("\n".join(L))

# --- set 2023 (rapporti DHS 2024-2025): argomenti facoltativi 3 e 4 ---
# confronto_cftt_carving.py <val. 2014 .json> <uscita .md> <rapporti_2023.json da rapporti_carving_2023.py> <val. 2023 .json>
if len(sys.argv) > 4:
    rap = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
    rep23 = json.loads(Path(sys.argv[4]).read_text(encoding="utf-8"))
    FORMATI = ["HEIC", "PNG", "JPG", "BMP", "TIFF", "GIF"]
    DISP = [("contig", "contiguo", "Contigui"), ("non", "non allineato", "Non allineati ai settori"),
            ("frag", "frammentato", "Frammentati")]
    L2 = ["", "## Set 2023 (rapporti DHS 2024-2025)", "",
          "18 immagini NIST (cfreds.nist.gov «File Carving Graphic Files», 2023): 6 file per formato (HEIC, PNG, JPG, BMP, "
          "TIFF, GIF) in tre disposizioni. Valori: file «Complete no flaws» per formato, nell'ordine "
          + ", ".join(FORMATI) + " (6 per formato; nei JPG i rapporti contano anche le 3 miniature EXIF, quindi fino a 9; "
          "«—» = formato non provato o nessun file recuperato). Per RepertIA lo stesso conteggio, con il metro byte per byte.", ""]
    nomi = list(rap)
    L2 += ["| Disposizione | **RepertIA 3.0.2** | " + " | ".join(nomi) + " |", "|---|---|" + "---|" * len(nomi)]
    for k, chiave, titolo in DISP:
        cel = []
        for f in FORMATI:
            r = next((x for x in rep23 if x["disposizione"] == k and x["formato"] == f.lower()), None)
            cel.append("—" if r is None else str(r["completi"] + (r["miniature"][0] if f == "JPG" else 0)))
        tot_r = sum(int(c) for c in cel if c != "—")
        riga = [f"**{tot_r}** ({' · '.join(cel)})"]
        for n in nomi:
            v = [rap[n].get(f, {}).get(chiave) for f in FORMATI]
            riga.append(f"{sum(x[0] for x in v if x)} ({' · '.join(str(x[0]) if x else '—' for x in v)})")
        L2.append(f"| {titolo} | " + " | ".join(riga) + " |")
    fp = sum(r["falsi_positivi"] for r in rep23)
    L2 += ["", f"Falsi positivi di RepertIA sul set 2023: {fp}.", ""]
    with open(sys.argv[2], "a", encoding="utf-8") as fh:
        fh.write("\n".join(L2) + "\n")
    print("\n".join(L2))
