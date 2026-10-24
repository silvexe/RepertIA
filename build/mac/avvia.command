#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
# RepertIA - By silvexe (Mac Apple Silicon)
# Python, openai, Pillow e plaso sono inclusi nell'app; Sleuth Kit, libewf, exiftool,
# poppler, PhotoRec, bulk_extractor e Tesseract vengono da Homebrew (installati al primo avvio).
RES="$(cd "$(dirname "$0")" && pwd)"
cd "$RES" || exit 1
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1
printf '\033]0;RepertIA\007'
clear
echo "== RepertIA - By silvexe =="
echo "Analisi forense con IA locale: i dati restano su questo computer."
echo "Lascia aperta questa finestra mentre usi RepertIA; chiudila per uscire."
echo

if [ "$(uname -m)" != "arm64" ]; then
  echo "Questa versione di RepertIA è per Mac Apple Silicon (M1 o successivi)."
  read -r -p "Premi Invio per chiudere..." _; exit 1
fi

need=""
for pair in fls:sleuthkit ewfexport:libewf exiftool:exiftool pdftotext:poppler \
            photorec:testdisk bulk_extractor:bulk_extractor tesseract:tesseract; do
  command -v "${pair%%:*}" >/dev/null 2>&1 || need="$need ${pair##*:}"
done
if [ -n "$need" ]; then
  if command -v brew >/dev/null 2>&1; then
    echo "Installo gli strumenti mancanti con Homebrew:$need (serve internet)"
    brew install $need
  else
    echo "Mancano:$need"
    echo "Installa Homebrew da https://brew.sh e poi riapri RepertIA."
    echo "(Senza Sleuth Kit RepertIA non può analizzare le copie.)"
    read -r -p "Premi Invio per continuare comunque..." _
  fi
fi

exec "$RES/python/bin/python3" "$RES/RepertIA/forense_gui.py"
