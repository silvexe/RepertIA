#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Confronto di RepertIA con gli strumenti provati da NIST CFTT sulle stesse immagini «Deleted File Recovery».

Strumenti: le tabelle «Recovered File Analysis By File System» dei rapporti CFTT pubblicati da DHS (testo estratto con
pdftotext -layout dai PDF dei rapporti: la prima tabella è dei 9 casi senza sovrascritture, la
seconda dei 7 con sovrascritture). RepertIA: le righe di cftt_metriche_dfr.py (stesse colonne, stesse immagini).
Riferimento (Del, Intact/Meta): tabelle «Available Metadata and File Block Summary» dei rapporti (uguali per tutti).
Uso: confronto_cftt_dfr.py <cartella dei rapporti .txt> <cftt_metriche.jsonl> <uscita .md> [cftt_attivi.jsonl]"""
import json
import re
import sys
from pathlib import Path

STRUMENTI = {   # file del rapporto: nome mostrato (versione provata da CFTT)
    "ftk_3.3": "FTK 3.3.0", "encase_6.18": "EnCase 6.18.0", "xways_16.0": "X-Ways 16.0 SR-4",
    "ilookix_2.2.3": "ILooKIX 2.2.3", "smart_linux_2011": "SMART for Linux 2011", "tsk_3.2.2_autopsy_2.24": "TSK 3.2.2/Autopsy 2.24"}
COL = ("Del", "Rec", "SS", "First", "Full", "Match", "Sigma", "Multi", "Other", "Active", "Seq", "Over", "Ovf")
FAM = {"fat": "FAT", "exfat": "ExFAT", "xfat": "ExFAT", "ntfs": "NTFS", "ext": "ext"}
GRUPPI = (("senza sovrascritture", ("01", "02", "03", "05", "05-braid", "05-nest", "06", "09", "11")),
          ("con sovrascritture", ("07", "07-one", "07-two", "08", "10", "12", "13")))



# (§3.7-3.14 dei rapporti) giudizi dei rapporti CFTT trascritti, e misura di RepertIA 3.0.2 sulle stesse immagini
GRIGLIA = [
    ("Date MAC, NTFS (DFR-01)", "giuste, UTC", ["giuste", "giuste", "giuste", "giuste", "giuste", "giuste"]),
    ("Date MAC, FAT (DFR-01)", "giuste (anche i secondi di XBEID)",
     ["giuste", "giuste", "giuste", "giuste", "XBEID: 1 s in meno", "XBEID: 1 s in meno; accesso 00:00:00"]),
    ("Date MAC, exFAT (DFR-01)", "giuste (scostamento UTC della voce, 3.0.2; prima 9 ore)",
     ["4 ore avanti", "9 ore di differenza", "giuste", "9 ore di differenza", "exFAT non letto", "exFAT non letto"]),
    ("Date MAC, ext2 (DFR-01)", "giuste: M, A, C = cancellazione",
     ["M e A giuste, niente ctime", "giuste", "M e A giuste, ora di cancellazione", "M e A giuste, ora di cancellazione",
      "non provato", "giuste sull'orfano, 0 sul nome"]),
    ("Nomi non latini (DFR-04)", "intatti su FAT, exFAT, NTFS ed ext",
     ["FAT: nomi 8.3; exFAT e NTFS giusti; ext non misurabile", "giusti", "giusti su tutti",
      "FAT, exFAT, NTFS giusti; ext nessun nome", "FAT e NTFS sbagliati; ext nessun nome", "FAT, NTFS, ext giusti"]),
    ("Cestino svuotato (DFR-01-recycle)", "FAT, NTFS, ext2 recuperati (NTFS: nome originale dal $I)",
     ["FAT, NTFS, ext2", "FAT, NTFS, ext (ext2 in parte)", "NTFS, ext2; FAT doppio", "NTFS, ext2; FAT doppio",
      "FAT, NTFS; ext2 contenuto ignoto", "FAT, NTFS, ext2"]),
    ("NTFS compresso e file nella MFT (DFR-11)", "entrambi recuperati",
     ["entrambi", "entrambi", "entrambi", "entrambi", "compresso sì, MFT no", "entrambi"]),
    ("Collegamenti e oggetti speciali (DFR-14)", "asserzioni DFR-14 tutte OK (FAT 13, NTFS 11 + 1 RIF, ext 5)",
     ["elencati tutti; recuperati in parte", "ext4 non elencato", "elencati tutti; recuperati in parte",
      "ADS NTFS non elencati", "link ext non elencati", "elencati; recuperati in parte"]),
    ("HFS+ (DFR-01, DFR-04)", "niente (nessun metadato dopo la cancellazione)",
     ["niente", "niente", "niente", "niente", "niente", "niente"]),
]


def tabelle(testo, intest):
    """Le tabelle per famiglia che seguono ogni intestazione: lista di {famiglia: {colonna: valore}}."""
    out = []
    for m in re.finditer(re.escape(intest), testo):
        t = {}
        for riga in testo[m.end():m.end() + 2500].splitlines()[1:12]:
            x = riga.split()
            if x and x[0].lower() in FAM and all(v.isdigit() for v in x[1:]) and len(x) > 2:
                t[FAM[x[0].lower()]] = dict(zip(COL if intest.startswith("Recovered") else
                                                ("Del", "Intact/Meta", "Partial/Meta", "None/Meta", "Intact/None",
                                                 "Partial/None", "None/None"), map(int, x[1:])))
            elif x and x[0] == "Totals":
                break
        if t:
            out.append(t)
    return out


def main():
    cart, metr, dest = Path(sys.argv[1]).expanduser(), Path(sys.argv[2]).expanduser(), Path(sys.argv[3])
    rif, prove = None, {}
    for f, nome in STRUMENTI.items():
        testo = (cart / f"{f}.txt").read_text(encoding="utf-8", errors="replace")
        prove[nome] = tabelle(testo, "Recovered File Analysis By File System")[:2]
        if f == "ftk_3.3":                     # FTK ha il riferimento con tutte e quattro le famiglie
            rif = tabelle(testo, "Available Metadata and File Block Summary")
            rif = [t for t in rif if "NTFS" in t and len(t) >= 4][:2]
    righe = [json.loads(r.lstrip("﻿")) for r in metr.read_text(encoding="utf-8").splitlines() if r.strip()]
    rep = []
    for _g, casi in GRUPPI:
        t = {}
        for r in righe:
            if re.fullmatch(r"dfr-(.+)-(fat|xfat|ntfs|ext)", r["caso"]).group(1) in casi:
                d = t.setdefault(r["fs"], dict.fromkeys(COL, 0))
                for k in r:
                    if k in d:
                        d[k] += r[k]
        rep.append(t)
    L = ["# RepertIA e gli strumenti provati da NIST CFTT: «Deleted File Recovery»", "",
         "Stesse immagini NIST (DFR-01…13), stesse colonne dei rapporti CFTT pubblicati da DHS (2014-2015). I valori degli "
         "altri strumenti sono copiati dai rapporti; quelli di RepertIA misurati con `tools/prove/cftt_metriche_dfr.py` "
         "(etichette NIST di ogni settore). **Full** = file restituiti completi e giusti; **Intact/Meta** = file cancellati "
         "con i metadati e nessun blocco sovrascritto, cioè quelli che uno strumento dovrebbe recuperare tutti; "
         "**Multi** = oggetti con blocchi di più file; **Active** = con blocchi di file attivi; **Other** = con blocchi "
         "di origine non determinata; **Ovf** = oggetti che lo strumento dichiara sovrascritti. Su ext3/ext4 e HFS+ "
         "nessuno strumento recupera il contenuto dai metadati (puntatori ai blocchi azzerati; nel giornale delle immagini "
         "NIST restano solo le copie degli inode già azzerate, controllato con `ext_journal_prova.py`).", "",
         "## In breve", "",
         "- File completi e giusti (**Full**): RepertIA è **primo o pari al primo su tutti e quattro i file system**, e "
         "l'unico a recuperarli tutti su exFAT (catena della FAT seguita per i cancellati frammentati, 3.0.2) e il primo su "
         "ext con sovrascritture (file ext2 in cartelle cancellate ritrovati con `ils`, che Sleuth Kit 4.15 non elenca più).",
         "- Trasparenza: un nome cancellato il cui inode è passato a un altro file («realloc» di Sleuth Kit) è segnato "
         "«inode riassegnato» e un cancellato con blocchi oggi assegnati a un altro file è segnato «blocchi riusati» (3.0.2, "
         "mappe di allocazione di NTFS, FAT, exFAT ed ext): **tutti** gli oggetti con dati di file attivi sono dichiarati "
         "(Ovf: FAT 40 su 40, exFAT 11 su 11 più Capella di DFR-07-one, NTFS 24 su 24, ext 330 su 330), senza toccare i "
         "file giusti (Full invariato). Degli altri strumenti solo EnCase ne dichiara una parte.",
         "- Su FAT la catena dei cluster è azzerata alla cancellazione: un file frammentato non torna intatto con nessuno "
         "strumento (Multi uguale a TSK e SMART).", ""]
    nomi = ["**RepertIA 3.0.2**"] + list(prove)
    for gi, (g, casi) in enumerate(GRUPPI):
        L += [f"## Casi {g} ({', '.join(casi)})", "",
              "| File system | Cancellati | Intact/Meta | " + " | ".join(nomi) + " |",
              "|---|---|---|" + "---|" * len(nomi)]
        for fam in ("FAT", "ExFAT", "NTFS", "ext"):
            ri = rif[gi].get(fam, {})
            vals = [rep[gi].get(fam)] + [prove[n][gi].get(fam) if len(prove[n]) > gi else None for n in prove]
            cel = [f"{v['Full']}" if v else "non supportato" for v in vals]
            cel[0] = f"**{cel[0]}**"
            L.append(f"| {fam} | {ri.get('Del', '')} | {ri.get('Intact/Meta', '')} | " + " | ".join(cel) + " |")
        L += ["", f"Oggetti con contenuto sbagliato (Multi / Active / Other) e, dopo «·», quanti lo strumento dichiara "
              f"sovrascritti (Ovf), casi {g}:", "",
              "| File system | " + " | ".join(nomi) + " |", "|---|" + "---|" * len(nomi)]
        for fam in ("FAT", "ExFAT", "NTFS", "ext"):
            vals = [rep[gi].get(fam)] + [prove[n][gi].get(fam) if len(prove[n]) > gi else None for n in prove]
            cel = [f"{v['Multi']} / {v['Active']} / {v['Other']} · {v.get('Ovf', 0)}" if v else "—" for v in vals]
            cel[0] = f"**{cel[0]}**"
            L.append(f"| {fam} | " + " | ".join(cel) + " |")
        L.append("")
    L += ["## RepertIA, tutte le colonne", ""]
    for gi, (g, _c) in enumerate(GRUPPI):
        L += [f"Casi {g}:", "", "| File system | " + " | ".join(c for c in COL if c not in ("Del", "Over", "Ovf")) + " |",
              "|---|" + "---|" * (len(COL) - 3)]
        for fam in ("FAT", "ExFAT", "NTFS", "ext"):
            v = rep[gi].get(fam)
            if v:
                L.append(f"| {fam} | " + " | ".join(str(v[c]) for c in COL if c not in ("Del", "Over", "Ovf")) + " |")
        L.append("")
    # §4.14: file e cartelle attivi di DFR-16 e DFR-17
    att = {}
    if len(sys.argv) > 4:
        for r in Path(sys.argv[4]).expanduser().read_text(encoding="utf-8").splitlines():
            if r.strip():
                x = json.loads(r.lstrip("\ufeff"))
                att[x["caso"]] = (x["file"], x["cartelle"])
    attivi = {}
    for f, nome in STRUMENTI.items():
        testo = (cart / f"{f}.txt").read_text(encoding="utf-8", errors="replace")
        for riga in testo[testo.rfind("Active Files and Folders Listed"):].splitlines()[1:14]:
            x = riga.split()
            if x and re.fullmatch(r"dfr-(ext|fat|ntfs|xfat)-1[67]", x[0]) and len(x) >= 4:
                attivi.setdefault(x[0], {})[nome] = x[1:]
    if attivi:
        L += ["## File e cartelle attivi elencati (DFR-16, DFR-17)", "",
              "Valori: file elencati / cartelle elencate (attesi nella seconda colonna). Il rapporto SMART non riporta "
              "le cartelle; TSK e SMART non leggevano exFAT.", "",
              "| Caso | Attesi | **RepertIA 3.0.2** | " + " | ".join(prove) + " |", "|---|---|---|" + "---|" * len(prove)]
        for caso in sorted(attivi):
            v = next(iter(attivi[caso].values()))
            _d, fsn, num = caso.split("-")
            rf = att.get(f"dfr-{num}-{fsn}")            # «dfr-ext-16» dei rapporti = caso «dfr-16-ext»
            cel = [f"{t[1]} / {t[3]}" if len(t) >= 4 else (f"{t[1]} / —" if len(t) >= 2 else "—")
                   for t in (attivi[caso].get(n, []) for n in prove)]
            L.append(f"| {caso} | {v[0]} / {v[2] if len(v) > 2 else '—'} | **{rf[0]} / {rf[1]}** | " if rf else
                     f"| {caso} | {v[0]} / {v[2] if len(v) > 2 else '—'} | — | ")
            L[-1] += " | ".join(cel) + " |"
        L.append("")
    L += ["## Altre voci dei rapporti (date, nomi, Cestino, casi speciali)", "",
          "Giudizi trascritti dai §3.7-3.13 di ogni rapporto; RepertIA misurato sulle stesse immagini (date confrontate con "
          "la tabella «Deleted File MAC Times» dei rapporti; FAT: valori NIST con l'ora in meno nota a tutti i rapporti).", "",
          "| Voce | **RepertIA 3.0.2** | " + " | ".join(prove) + " |", "|---|---|" + "---|" * len(prove)]
    for voce, rep_v, altri in GRIGLIA:
        L.append(f"| {voce} | **{rep_v}** | " + " | ".join(altri) + " |")
    L.append("")
    dest.write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()
