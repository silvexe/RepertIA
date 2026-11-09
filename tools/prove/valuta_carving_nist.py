#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Valutazione del carving di RepertIA sulle immagini NIST CFTT di carving grafico (set 2014, graphic-images.tbz2), nel
formato dei rapporti CFTT («Test Results for Graphic File Carving Tool», DHS 2014-2015): per ogni immagine, file da
recuperare (immagini + miniature EXIF), e per ognuno Completo / Parziale / Non recuperato, più i falsi positivi.

Misura automatica al posto del giudizio a occhio dei rapporti («Viewable - Complete/minor alteration»):
  - Completo: un file recuperato comincia con tutto il file originale (byte per byte; coda in più ammessa);
  - Parziale: un file recuperato contiene almeno un blocco da 512 byte dell'originale, nella posizione giusta rispetto
    al suo inizio, ma non tutto (vale come «Viewable - Incomplete/major alteration» o «Not viewable»: la vista non si
    giudica qui);
  - Falso positivo: file recuperato di tipo grafico (jpg, gif, png, bmp, tif) senza nessun blocco di un originale.
Riferimento della disposizione: i profili NIST <immagine>-ip.txt (in graphic-src) e graphic-src-thumbs.txt.
Uso: valuta_carving_nist.py <cartella graphic-src> <cartella dei casi, o delle uscite di PhotoRec per immagine> [uscita .json]"""
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
SRC = Path(sys.argv[1]).expanduser()
CASI = Path(sys.argv[2]).expanduser()
GRAF = {"jpg", "jpeg", "gif", "png", "bmp", "tif", "tiff"}
B = 512


def blocchi(d):
    return [hashlib.md5(d[i:i + B]).digest() for i in range(0, len(d) - B + 1, B)]


origini = {f.name: f.read_bytes() for f in SRC.iterdir() if f.suffix.lower().lstrip(".") in GRAF and not f.name.startswith("._")}
indice = {}                                                    # md5 del blocco -> (file, numero del blocco)
for n, d in origini.items():
    for k, h in enumerate(blocchi(d)):
        indice.setdefault(h, (n, k))
miniature = {}                                                 # «SPQR.JPG#t» -> byte della miniatura
for m in re.finditer(r"Thumb \d+ for \S+/([^/\s]+) found at (\d+)\(\w+\):(\d+)\(\w+\)", (SRC / "graphic-src-thumbs.txt").read_text()):
    a, b = int(m.group(2)), int(m.group(3))
    miniature[m.group(1) + "#miniatura"] = origini[m.group(1)][a:b]


def profilo(nome):
    """{file: (blocchi presenti nell'immagine, blocchi totali)} dal profilo NIST dell'immagine."""
    out = {}
    p = SRC / f"{nome}-ip.txt"
    for r in p.read_text(errors="replace").splitlines():
        x = r.split(";")
        if len(x) >= 6 and x[0].isdigit() and x[3] in origini and x[4].isdigit():
            out.setdefault(x[3], set()).update(range(int(x[4]), int(x[5]) + 1))
    return {f: (len(v), len(blocchi(origini[f])) + (1 if len(origini[f]) % B else 0)) for f, v in out.items()}


risultati = []
for caso in sorted(p for p in CASI.iterdir() if p.is_dir() and (SRC / f"{p.name}-ip.txt").exists()):
    nome = caso.name
    prof = profilo(nome)
    if (caso / "caso.sqlite").exists():
        con = sqlite3.connect(f"file:{caso / 'caso.sqlite'}?mode=ro", uri=True)
        rec = [(n, caso / rel, t) for n, rel, t in con.execute("SELECT name, relpath, type FROM carved")]
    else:                                      # cartella con l'uscita di PhotoRec lanciato a mano (recup_dir.*)
        rec = [(f.name, f, f.suffix.lstrip(".")) for f in caso.rglob("*") if f.is_file() and f.name != "report.xml"]
    stato = {f: "non recuperato" for f in prof}
    # miniature: si cercano solo quelle dei JPG presenti per intero nell'immagine
    for t, d in miniature.items():
        f = t.split("#")[0]
        if f in prof and prof[f][0] == prof[f][1]:
            stato[t] = "non recuperato"
    fp, graf = 0, 0
    for n, path, t in rec:
        if t.lower() not in GRAF:
            continue
        graf += 1
        d = path.read_bytes()
        bl = blocchi(d)
        trovato = False
        for f in list(stato):
            o = origini.get(f) if "#" not in f else miniature[f]
            if d[:len(o)] == o:
                stato[f], trovato = "completo", True
        for k, h in enumerate(bl):
            x = indice.get(h)
            if x:
                trovato = True
                if x[0] in stato and stato[x[0]] == "non recuperato" and x[1] == k:
                    stato[x[0]] = "parziale"
        if not trovato and not any(d[:len(t)] == t for t in miniature.values()):
            fp += 1                            # una miniatura EXIF di un originale non è un falso positivo
    interi = sum(1 for f, (a, b) in prof.items() if a == b) + sum(1 for f in stato if "#" in f)
    r = {"immagine": nome, "da_recuperare": len(stato), "interi_nell_immagine": interi,
         "recuperati_grafici": graf,
         "completi": sum(1 for v in stato.values() if v == "completo"),
         "parziali": sum(1 for v in stato.values() if v == "parziale"),
         "non_recuperati": sum(1 for v in stato.values() if v == "non recuperato"),
         "falsi_positivi": fp,
         "dettaglio": {f: v for f, v in sorted(stato.items()) if v != "completo"}}
    risultati.append(r)
    print(f"{nome:34} file {r['da_recuperare']:3} (interi {interi:3})  recuperati {graf:3}  completi {r['completi']:3}  "
          f"parziali {r['parziali']:3}  non {r['non_recuperati']:3}  falsi positivi {fp}")
if len(sys.argv) > 3:
    Path(sys.argv[3]).write_text(json.dumps(risultati, ensure_ascii=False, indent=1), encoding="utf-8")
