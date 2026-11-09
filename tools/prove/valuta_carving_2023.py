#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Valutazione del carving di RepertIA sul set NIST CFTT «File Carving Graphic Files» (2023, cfreds.nist.gov): 18
immagini image-<contig|non|frag>-<bmp|gif|heic|jpg|png|tiff>.dd, ognuna con i 6 file sorgente del suo formato.
Stesso metro di valuta_carving_nist.py, a confronto con i rapporti DHS 2024-2025 («Complete no flaws»):
  - completo: un file recuperato comincia con tutto l'originale, byte per byte (coda in più ammessa);
  - parziale: almeno un blocco da 512 byte dell'originale nella posizione giusta rispetto all'inizio del recuperato;
  - miniature EXIF dei JPG (contate a parte, come nei rapporti): complete se un recuperato le contiene identiche;
  - falso positivo: file grafico recuperato senza nessun blocco degli originali.
Uso: valuta_carving_2023.py <cartella source> <cartella dei casi> [uscita .json]"""
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
SRC = Path(sys.argv[1]).expanduser()
CASI = Path(sys.argv[2]).expanduser()
GRAF = {"jpg", "jpeg", "gif", "png", "bmp", "tif", "tiff", "heic", "heif"}
FMT = {"bmp": {"bmp"}, "gif": {"gif"}, "heic": {"heic"}, "jpg": {"jpg"}, "png": {"png"}, "tiff": {"tiff", "tif"}}
B = 512
origini = {f.name: f.read_bytes() for f in SRC.iterdir() if f.is_file() and not f.name.startswith("._")}


def miniatura(d):
    """Miniatura EXIF di un JPG: il secondo SOI dentro APP1, fino al suo EOI."""
    if d[:2] != b"\xff\xd8" or d[2:4] != b"\xff\xe1":
        return None
    fine = 4 + int.from_bytes(d[4:6], "big")
    i = d.find(b"\xff\xd8\xff", 6, fine)
    j = d.find(b"\xff\xd9", i + 3, fine) if i > 0 else -1
    return d[i:j + 2] if i > 0 and j > 0 else None


def blocchi(d):
    return [hashlib.md5(d[i:i + B]).digest() for i in range(0, len(d) - B + 1, B)]


risultati = []
for caso in sorted(p for p in CASI.iterdir() if (p / "caso.sqlite").exists()):
    m = re.fullmatch(r"image-(contig|non|frag)-(\w+)", caso.name)
    if not m:
        continue
    disp, fmt = m.groups()
    sorg = {n: d for n, d in origini.items() if n.rsplit(".", 1)[-1].lower() in FMT[fmt]}
    mini = {n + "#miniatura": t for n, d in sorg.items() for t in [miniatura(d)] if t}
    indice = {h: (n, k) for n, d in sorg.items() for k, h in enumerate(blocchi(d))}
    stato = {n: "non recuperato" for n in list(sorg) + list(mini)}
    con = sqlite3.connect(f"file:{caso / 'caso.sqlite'}?mode=ro", uri=True)
    fp = graf = 0
    for _n, rel, t in con.execute("SELECT name, relpath, type FROM carved"):
        if str(t).lower() not in GRAF:
            continue
        graf += 1
        d = (caso / rel).read_bytes()
        trovato = False
        for n in stato:
            o = mini[n] if "#" in n else sorg[n]
            if d[:len(o)] == o:
                stato[n], trovato = "completo", True
        for k, h in enumerate(blocchi(d)):
            x = indice.get(h)
            if x:
                trovato = True
                if stato[x[0]] == "non recuperato" and x[1] == k:
                    stato[x[0]] = "parziale"
        if not trovato:
            fp += 1
    r = {"immagine": caso.name, "disposizione": disp, "formato": fmt, "recuperati_grafici": graf,
         "completi": sum(1 for n, v in stato.items() if v == "completo" and "#" not in n),
         "parziali": sum(1 for n, v in stato.items() if v == "parziale" and "#" not in n),
         "miniature": [sum(1 for n, v in stato.items() if "#" in n and v == "completo"), len(mini)],
         "falsi_positivi": fp, "dettaglio": {n: v for n, v in sorted(stato.items()) if v != "completo"}}
    risultati.append(r)
    print(f"{caso.name:22} recuperati {graf:3}  completi {r['completi']}/6  parziali {r['parziali']}  "
          f"miniature {r['miniature'][0]}/{r['miniature'][1]}  falsi positivi {fp}")
if len(sys.argv) > 3:
    Path(sys.argv[3]).write_text(json.dumps(risultati, ensure_ascii=False, indent=1), encoding="utf-8")
