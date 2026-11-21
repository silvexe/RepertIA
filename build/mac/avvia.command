#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
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
echo "Lascia aperta questa finestra mentre usi RepertIA. Per uscire: pulsante Chiudi in alto a destra nella pagina (oppure chiudi questa finestra)."
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

"$RES/python/bin/python3" "$RES/RepertIA/forense_gui.py"
rc=$?
# (3.0.6) uscita pulita (pulsante «Chiudi» o Ctrl+C): si chiude anche questa finestra del Terminale, che da sola
# resterebbe aperta con «[Processo completato]». Si cerca la finestra dal suo terminale (tty), non la prima davanti;
# la chiusura parte un attimo dopo l'uscita dello script, così il Terminale non chiede di interrompere processi.
if [ $rc -eq 0 ] && T=$(tty 2>/dev/null); then
  nohup /bin/sh -c "sleep 1; /usr/bin/osascript -e 'tell application \"Terminal\"' \
    -e 'repeat with w in windows' -e 'if tty of selected tab of w is \"$T\" then' -e 'close w' -e 'exit repeat' \
    -e 'end if' -e 'end repeat' -e 'end tell'" >/dev/null 2>&1 &
fi
exit $rc
