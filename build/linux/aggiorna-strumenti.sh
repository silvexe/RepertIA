#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
# RepertIA - Versioni e aggiornamento degli strumenti (Linux). Serve internet.
# Gli strumenti forensi vengono dalla distribuzione (apt); plaso e i moduli Python stanno in python/
# e si aggiornano installando una nuova versione di RepertIA.
DIR="$(cd "$(dirname "$0")" && pwd)"
versioni() {
  echo "  Sleuth Kit: $(fls -V 2>/dev/null || echo 'non installato')"
  echo "  libewf:     $(ewfexport -V 2>&1 | head -1 || echo 'non installato')"
  echo "  exiftool:   $(exiftool -ver 2>/dev/null || echo 'non installato')"
  echo "  pdftotext:  $(pdftotext -v 2>&1 | head -1 || echo 'non installato')"
  echo "  PhotoRec:   $(photorec /version 2>/dev/null | grep -m1 '^Version' || echo 'non installato')"
  echo "  bulk_extr.: $(bulk_extractor -V 2>/dev/null || echo 'non installato')"
  echo "  tesseract:  $(tesseract --version 2>/dev/null | head -1 || echo 'non installato')"
  echo "  7-Zip:      $("$DIR/strumenti/7zip/7zz" 2>/dev/null | grep -m1 7-Zip || echo 'non incluso')"
  echo "  plaso:      $("$DIR/python/bin/python3" -m plaso.scripts.log2timeline --version 2>&1 | tail -1) (incluso)"
}
echo "== RepertIA - Aggiornamento strumenti =="
echo "Versioni attuali:"; versioni; echo
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update && sudo apt-get install --only-upgrade -y sleuthkit libewf-tools testdisk poppler-utils \
       libimage-exiftool-perl tesseract-ocr tesseract-ocr-ita bulk-extractor 2>/dev/null
  echo; echo "Versioni dopo l'aggiornamento:"; versioni
fi
echo
read -r -p "Fatto. Premi Invio per chiudere..." _
