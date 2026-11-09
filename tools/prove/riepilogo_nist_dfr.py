#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Riepilogo degli esiti di valida_nist_dfr.py (file <caso>.esito.txt nella cartella di lavoro): tabella caso × file
system come nei rapporti CFTT, con OK / LIM (limite noto, spiegato) / NO.
Uso: riepilogo_nist_dfr.py <cartella di lavoro> [file markdown di uscita]"""
import re
import sys
from collections import defaultdict
from pathlib import Path

W = Path(sys.argv[1]).expanduser()
FS = ["fat", "xfat", "ntfs", "ext", "osx"]
tab = defaultdict(lambda: defaultdict(lambda: [0, 0, 0, 0]))     # caso -> fs -> [ok, lim, rif, no]
dettagli = []
for f in sorted(W.glob("dfr-*.esito.txt")):
    m = re.fullmatch(r"dfr-(\d\d(?:-\w+?)?)-(fat|xfat|ntfs|ext|osx)\.esito\.txt", f.name)
    if not m:
        continue
    caso, fs = m.groups()
    b = f.read_bytes()                          # PowerShell annidato scrive UTF-16 con BOM
    for riga in b.decode("utf-16" if b[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig", errors="replace").splitlines():
        e = riga[:3].strip()
        if e in ("OK", "LIM", "RIF", "NO"):
            tab[caso][fs]["OK LIM RIF NO".split().index(e)] += 1
            if e != "OK":
                dettagli.append(riga)
out = ["| Caso | " + " | ".join(FS) + " |", "|---|" + "---|" * len(FS)]
tot = [0, 0, 0, 0]
for caso in sorted(tab):
    celle = []
    for fs in FS:
        ok, lim, rif, no = tab[caso][fs]
        tot = [tot[0] + ok, tot[1] + lim, tot[2] + rif, tot[3] + no]
        celle.append("—" if ok + lim + rif + no == 0 else f"{ok}" + (f" +{lim} LIM" if lim else "") + (f" +{rif} RIF" if rif else "") + (f" **{no} NO**" if no else ""))
    out.append(f"| DFR-{caso} | " + " | ".join(celle) + " |")
out.append(f"\nTotale asserzioni: {sum(tot)} — OK {tot[0]}, limiti noti {tot[1]}, riferimento NIST smentito dall'immagine {tot[2]}, NO {tot[3]}")
testo = "\n".join(out) + "\n\nRighe non OK:\n" + "\n".join(dettagli)
print(testo)
if len(sys.argv) > 2:
    Path(sys.argv[2]).write_text(testo + "\n", encoding="utf-8")
