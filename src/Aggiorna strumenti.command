#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
# Aggiorna Sleuth Kit, libewf, exiftool, poppler, PhotoRec, bulk_extractor,
# client openai e plaso (Docker). Serve internet.
# Meglio lanciarlo tra un caso e l'altro: ogni caso registra in case.json
# le versioni degli strumenti con cui è stato preparato.
cd "$(dirname "$0")" || exit 1
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

versioni() {
  echo "  Sleuth Kit: $(fls -V 2>/dev/null || echo 'non installato')"
  echo "  libewf:     $(ewfexport -V 2>&1 | head -1 || echo 'non installato')"
  echo "  exiftool:   $(exiftool -ver 2>/dev/null || echo 'non installato')"
  echo "  pdftotext:  $(pdftotext -v 2>&1 | head -1 || echo 'non installato')"
  echo "  PhotoRec:   $(photorec /version 2>/dev/null | grep -m1 '^Version' || echo 'non installato')"
  echo "  bulk_extr.: $(bulk_extractor -V 2>/dev/null || echo 'non installato')"
  echo "  openai:     $(python3 -c 'import openai;print(openai.__version__)' 2>/dev/null || echo 'non installato')"
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "  plaso:      $(docker run --rm --network none log2timeline/plaso log2timeline --version 2>&1 | tail -1 || echo 'immagine non scaricata')"
  else
    echo "  plaso:      (Docker Desktop chiuso o non installato)"
  fi
}

echo "== RepertIA - Aggiornamento strumenti =="
echo "Versioni attuali:"
versioni
echo

if command -v brew >/dev/null 2>&1; then
  echo "Aggiorno Sleuth Kit, libewf, exiftool, poppler, PhotoRec e bulk_extractor..."
  brew update
  for f in sleuthkit libewf exiftool poppler testdisk bulk_extractor; do
    if brew list "$f" >/dev/null 2>&1; then brew upgrade "$f" 2>/dev/null; else brew install "$f"; fi
  done
else
  echo "Homebrew non trovato: installalo da https://brew.sh"
fi

echo "Aggiorno il client openai..."
python3 -m pip install --user --quiet --upgrade openai 2>/dev/null \
  || python3 -m pip install --user --quiet --upgrade --break-system-packages openai

if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    echo "Aggiorno plaso (immagine Docker)..."
    docker pull log2timeline/plaso
  else
    echo "Docker Desktop è chiuso: aprilo e rilancia questo file per aggiornare plaso."
  fi
else
  echo "Docker non installato: plaso resta disattivato (vedi README.md)."
fi

echo
echo "Versioni dopo l'aggiornamento:"
versioni
echo
read -r -p "Fatto. Premi Invio per chiudere..." _
