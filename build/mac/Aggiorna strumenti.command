#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
# RepertIA - Aggiornamento strumenti (Mac Apple Silicon). Serve internet.
# Aggiorna con Homebrew Sleuth Kit, libewf, exiftool, poppler, PhotoRec, bulk_extractor e Tesseract.
# Python, openai e plaso sono inclusi nell'app: si aggiornano installando una nuova versione.
cd "$(dirname "$0")" || exit 1
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
APP=""
for a in "$(pwd)/RepertIA.app" "/Applications/RepertIA.app" "$HOME/Applications/RepertIA.app"; do
  [ -x "$a/Contents/Resources/python/bin/python3" ] && APP="$a" && break
done

versioni() {
  echo "  Sleuth Kit: $(fls -V 2>/dev/null || echo 'non installato')"
  echo "  libewf:     $(ewfexport -V 2>&1 | head -1 || echo 'non installato')"
  echo "  exiftool:   $(exiftool -ver 2>/dev/null || echo 'non installato')"
  echo "  pdftotext:  $(pdftotext -v 2>&1 | head -1 || echo 'non installato')"
  echo "  PhotoRec:   $(photorec /version 2>/dev/null | grep -m1 '^Version' || echo 'non installato')"
  echo "  bulk_extr.: $(bulk_extractor -V 2>/dev/null || echo 'non installato')"
  echo "  tesseract: $(tesseract --version 2>/dev/null | head -1 || echo 'non installato')"
  if [ -n "$APP" ]; then
    echo "  plaso:      $("$APP/Contents/Resources/python/bin/python3" -m plaso.scripts.log2timeline --version 2>&1 | tail -1) (incluso)"
  else
    echo "  plaso:      (RepertIA.app non trovata)"
  fi
}

echo "== RepertIA - Aggiornamento strumenti =="
echo "Versioni attuali:"
versioni
echo
if command -v brew >/dev/null 2>&1; then
  echo "Aggiorno Sleuth Kit, libewf, exiftool, poppler, PhotoRec, bulk_extractor e Tesseract..."
  brew update
  for f in sleuthkit libewf exiftool poppler testdisk bulk_extractor tesseract; do
    if brew list "$f" >/dev/null 2>&1; then brew upgrade "$f" 2>/dev/null; else brew install "$f"; fi
  done
else
  echo "Homebrew non trovato: installalo da https://brew.sh"
fi
echo
echo "Versioni dopo l'aggiornamento:"
versioni
echo
read -r -p "Fatto. Premi Invio per chiudere..." _
