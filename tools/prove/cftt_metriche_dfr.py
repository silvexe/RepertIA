#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Misura RepertIA sulle immagini NIST CFTT «Deleted File Recovery» con le stesse colonne dei rapporti CFTT pubblicati da
DHS (tabelle «Recovered File Analysis Summary»), per confrontarlo con FTK, EnCase, X-Ways, SMART, TSK/Autopsy e ILooKIX.

Per ogni caso preparato (con il .dd ancora presente: il contenuto si legge con icat_read, come nell'interfaccia), ogni
oggetto cancellato restituito da RepertIA (file normali cancellati, anche orfani) con contenuto si classifica dalle
etichette NIST dei settori («DFR File <nome>» = blocco 0, «Block N Segment S file <nome>»):
  Rec    oggetti restituiti (con almeno un settore etichettato o con il nome di un file di prova)
  SS     oggetti con blocchi di un solo file (come nei rapporti, First, Full, Match e Sigma contano solo questi)
  First  contiene il primo blocco di un file cancellato
  Full   completo e giusto: tutti i settori pieni del file stesso (nome = etichetta, o orfano senza nome), blocchi
         0,1,2… in ordine, nessun settore estraneo
  Match  nome dell'oggetto uguale a quello del file (DFR-04: anche l'alias ASCII delle etichette)
  Sigma  nome uguale tranne il primo carattere (FAT: primo carattere del nome breve cambiato alla cancellazione)
  Multi  blocchi di due o più file cancellati
  Other  settori pieni senza etichetta (origine non determinata)
  Active blocchi di file attivi (non cancellati)
  Seq    blocchi dello stesso file fuori sequenza
  Ovf    oggetti che lo strumento dichiara sovrascritti (RepertIA 3.0.2: inode riassegnato, deleted = 2, o blocchi
         riusati da altri file, deleted = 3)
Del, Intact/Meta e gli altri conteggi della verità di riferimento sono quelli dei rapporti CFTT (stesse immagini).
Uso: cftt_metriche_dfr.py <cartella dei casi> <caso> [caso …]  → una riga JSON per caso e famiglia di file system."""
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(os.environ.get("REPERTIA_SRC", Path(__file__).resolve().parents[2] / "src"))))
import forense_agent as fa  # noqa: E402

TAG = re.compile(rb"\nDFR\n(?:File (?P<f1>\S+) path|Block (?P<b>\d+) Segment \d+ file (?P<f2>\S+) path)")
FAM = {"fat12": "FAT", "fat16": "FAT", "fat32": "FAT", "exfat": "ExFAT", "ntfs": "NTFS",
       "ext2": "ext", "ext3": "ext", "ext4": "ext"}
COL = ("Rec", "SS", "First", "Full", "Match", "Sigma", "Multi", "Other", "Active", "Seq", "Ovf")


def famiglia(fs):
    fs = (fs or "").lower()
    return next((v for k, v in FAM.items() if fs.startswith(k)), None)


def main():
    casi = Path(sys.argv[1]).expanduser()
    for nome in sys.argv[2:]:
        d = casi / nome
        case = fa.Case(d)
        con = sqlite3.connect(f"file:{d / 'caso.sqlite'}?mode=ro", uri=True)
        fam = {int(p["offset"]): famiglia(p.get("fs")) for p in case.meta.get("partitions", [])}
        attivi = {}                                        # famiglia -> nomi dei file attivi
        for p, pa in con.execute("SELECT part, path FROM files WHERE deleted=0 AND type LIKE '%r'"):
            attivi.setdefault(fam.get(int(p)), set()).add(Path(pa).name.lower())
        tot = {}
        for p, i, ty, pa, canc in con.execute("SELECT part, inode, type, path, deleted FROM files WHERE deleted>=1"):
            f = fam.get(int(p))
            n = Path(pa).name
            if not f or not ty.endswith("r") or str(i) in ("0", "") or n.startswith("$") and "/$OrphanFiles" not in pa:
                continue
            data = fa.icat_read(case, p, i, 64 << 20)
            st = []
            for k in range(0, len(data) // 512 * 512, 512):
                m = TAG.match(data[k:k + 512])
                st.append(None if not m else ((m.group("f1") or m.group("f2")).decode("latin-1"),
                                              0 if m.group("f1") else int(m.group("b"))))
            etich = {x[0] for x in st if x}
            if not data or (not etich and not re.match(r"^[\w_][\w=\-.]*\.(txt|TXT)$", n)):
                continue                                   # file di sistema o dati non di prova (._ di macOS ecc.)
            r = dict.fromkeys(COL, 0)
            r["Rec"] = 1
            r["Ovf"] = int(canc in (2, 3))                 # RepertIA lo dichiara: inode o blocchi di un altro file
            r["SS"] = int(len(etich) == 1)                 # blocchi di un solo file: solo qui contano First, Match, Sigma
            r["First"] = int(r["SS"] and any(x and x[1] == 0 for x in st))
            r["Multi"] = int(len(etich) > 1)
            r["Other"] = int(any(x is None for x in st))
            r["Active"] = int(any(e.lower() in attivi.get(f, set()) and e.lower() != n.lower() for e in etich))
            blocchi = [x[1] for x in st if x]
            r["Seq"] = int(len(etich) == 1 and blocchi != sorted(blocchi))
            e = next(iter(etich)) if len(etich) == 1 else None
            # DFR-04: le etichette usano l'alias ASCII; il nome vero è diverso ma è lo stesso file (stesso blocco 0)
            r["Match"] = int(bool(e) and (n == e or (bool(re.search(r"[^\x00-\x7f]", n)) and r["First"] == 1)))
            r["Sigma"] = int(bool(e) and not r["Match"] and len(n) == len(e) and n[1:].upper() == e[1:].upper())
            # Full: il contenuto è quello del file stesso (non di un altro file, anche intatto e in ordine: nome cancellato
            # con l'inode passato a un file attivo, DFR-07-two), tutti i settori pieni suoi, blocchi 0,1,2… in ordine
            proprio = r["Match"] or r["Sigma"] or n.startswith("OrphanFile")
            r["Full"] = int(bool(proprio) and None not in st and blocchi == list(range(len(blocchi))))
            t = tot.setdefault(f, dict.fromkeys(COL, 0))
            for k in COL:
                t[k] += r[k]
        for f, t in sorted(tot.items()):
            print(json.dumps({"caso": nome, "fs": f, **t}, ensure_ascii=False))


if __name__ == "__main__":
    main()
