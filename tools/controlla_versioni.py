#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (2.21): confronta le versioni dei componenti indicate in THIRD_PARTY_LICENSES.md e nello script di iLEAPP/ALEAPP
con l'ultima release pubblicata. Si lancia PRIMA di fissare una versione e prima di costruire i pacchetti; non aggiorna nulla.
Solo libreria standard. Uso: python3 tools/controlla_versioni.py [cartella del repository]   Esce con 1 se qualcosa è indietro."""
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

GH = "https://api.github.com/repos/{}/releases/latest"
PYPI = "https://pypi.org/pypi/{}/json"
# nome nella tabella di THIRD_PARTY_LICENSES.md, fonte, repository o pacchetto, regola per ripulire l'etichetta della release
COMPONENTI = [("iLEAPP", "gh", "abrignoni/iLEAPP"), ("ALEAPP", "gh", "abrignoni/ALEAPP"),
              ("The Sleuth Kit", "gh", "sleuthkit/sleuthkit"), ("bulk_extractor", "gh", "simsong/bulk_extractor"),
              ("Tesseract OCR", "gh", "tesseract-ocr/tesseract"), ("plaso", "gh", "log2timeline/plaso"),
              ("pytsk3", "pypi", "pytsk3"), ("Pillow", "pypi", "Pillow"), ("yara-python", "pypi", "yara-python"),
              ("ExifTool", "gh", "exiftool/exiftool"), ("whisper.cpp", "gh", "ggml-org/whisper.cpp")]
NUM = re.compile(r"\d+(?:\.\d+)+|\d{6,}")


def ultima(fonte, nome):
    url = (GH if fonte == "gh" else PYPI).format(nome)
    h = {"User-Agent": "RepertIA-controlla-versioni", "Accept": "application/json"}
    if fonte == "gh" and os.environ.get("GITHUB_TOKEN"):        # senza token GitHub limita le richieste
        h["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    rq = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(rq, timeout=25) as r:
        d = json.load(r)
    t = d.get("tag_name") if fonte == "gh" else d["info"]["version"]
    m = NUM.search(t or "")
    return m.group(0) if m else t


def tabella(base):
    out = {}
    for riga in (base / "THIRD_PARTY_LICENSES.md").read_text(encoding="utf-8").splitlines():
        c = [x.strip() for x in riga.split("|")]
        if len(c) > 3:
            m = NUM.search(c[2])
            if m:
                out.setdefault(c[1], m.group(0))
    return out


def chiave(v):
    return tuple(int(x) for x in str(v).split("."))


def main():
    base = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent)
    tab, indietro, errori = tabella(base), [], 0
    print(f"{'Componente':<18}{'nel progetto':<16}{'ultima':<16}esito")
    for nome, fonte, rif in COMPONENTI:
        usata = next((v for k, v in tab.items() if k.startswith(nome)), None)
        try:
            ult = ultima(fonte, rif)
        except Exception as e:
            errori += 1
            print(f"{nome:<18}{usata or '?':<16}{'?':<16}non controllato: {getattr(e, 'code', '') or type(e).__name__}")
            continue
        if not usata:
            esito = "non nella tabella: controllare a mano"
        elif chiave(usata) >= chiave(ult):
            esito = "aggiornato"
        else:
            esito = "DA VALUTARE"
            indietro.append(nome)
        print(f"{nome:<18}{usata or '?':<16}{ult or '?':<16}{esito}")
    print(f"\nDa valutare: {', '.join(indietro) or 'nessuno'}. Non controllati: {errori}.")
    print("Una versione nuova va provata con il collaudo prima di entrare nei pacchetti.")
    return 1 if indietro else 0


if __name__ == "__main__":
    sys.exit(main())
