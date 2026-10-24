#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
# RepertIA - By silvexe (Linux). Avvia l'interfaccia nel browser.
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR" || exit 1
export PYTHONDONTWRITEBYTECODE=1
printf '\033]0;RepertIA\007'
echo "== RepertIA - By silvexe =="
echo "Analisi forense con IA locale: i dati restano su questo computer."
echo "Lascia aperta questa finestra mentre usi RepertIA; chiudila per uscire."
echo
if [ ! -x "$DIR/python/bin/python3" ]; then
  echo "Primo avvio: eseguo l'installazione (installa.sh)."
  bash "$DIR/installa.sh" || exit 1
fi
need=""
for pair in fls:sleuthkit ewfexport:libewf-tools exiftool:libimage-exiftool-perl pdftotext:poppler-utils \
            photorec:testdisk tesseract:tesseract-ocr zenity:zenity; do
  command -v "${pair%%:*}" >/dev/null 2>&1 || need="$need ${pair##*:}"
done
if [ -n "$need" ]; then
  echo "Mancano alcuni strumenti:$need"
  echo "Installali con:  sudo apt install$need   (oppure rilancia installa.sh)"
  command -v fls >/dev/null 2>&1 || echo "(Senza Sleuth Kit RepertIA non può analizzare le copie.)"
  read -r -p "Premi Invio per continuare comunque..." _
fi
exec "$DIR/python/bin/python3" "$DIR/RepertIA/forense_gui.py"
