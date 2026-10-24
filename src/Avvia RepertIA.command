#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
# RepertIA - By silvexe
# Doppio clic per avviare RepertIA nel browser (tutto in locale, nessun dato a terzi).
# La prima volta controlla e installa i requisiti (Homebrew necessario).
cd "$(dirname "$0")" || exit 1
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

echo "== RepertIA - By silvexe =="
echo "Analisi forense con IA locale: i dati restano su questo computer."

# programma -> pacchetto Homebrew
need=""
for pair in fls:sleuthkit ewfexport:libewf exiftool:exiftool pdftotext:poppler \
            photorec:testdisk bulk_extractor:bulk_extractor; do
  command -v "${pair%%:*}" >/dev/null 2>&1 || need="$need ${pair##*:}"
done
if [ -n "$need" ]; then
  if command -v brew >/dev/null 2>&1; then
    echo "Installo i requisiti mancanti:$need"
    brew install $need
  else
    echo "Mancano:$need"
    echo "Installa Homebrew da https://brew.sh e poi riapri questo file."
    read -r -p "Premi Invio per chiudere..." _
    exit 1
  fi
fi

if ! python3 -c "import openai" >/dev/null 2>&1; then
  echo "Installo il client Python 'openai'..."
  python3 -m pip install --user --quiet openai 2>/dev/null \
    || python3 -m pip install --user --quiet --break-system-packages openai
fi

python3 forense_gui.py
