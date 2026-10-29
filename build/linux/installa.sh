#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
# RepertIA - Installazione su Linux (Ubuntu 24.04 o successivo, Debian 13). Serve internet una volta.
# 1) installa con apt gli strumenti forensi (Sleuth Kit, libewf, PhotoRec, Poppler, ExifTool, Tesseract)
# 2) crea in python/ un ambiente Python con plaso, le librerie libyal e gli altri moduli, alle stesse
#    versioni dei pacchetti Mac e Windows (requirements-linux.txt); dalla 2.20 anche le librerie di iLEAPP e ALEAPP
#    in strumenti/ileapp/site e strumenti/aleapp/site
# 3) aggiunge RepertIA al menu delle applicazioni.
# Si può rieseguire: completa solo quello che manca.
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR" || exit 1
LOG="$DIR/installa.log"
echo "== RepertIA - Installazione su Linux ==" | tee "$LOG"

PY=""
for p in python3.13 python3.12 python3; do
  if command -v "$p" >/dev/null 2>&1 && "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'; then
    PY="$(command -v "$p")"; break
  fi
done

if command -v apt-get >/dev/null 2>&1; then
  PKGS="sleuthkit libewf-tools testdisk poppler-utils libimage-exiftool-perl tesseract-ocr tesseract-ocr-ita
        zenity xdg-utils python3 python3-venv python3-dev build-essential pkg-config zlib1g-dev"
  echo "Installo con apt (chiede la password di amministratore):" | tee -a "$LOG"
  echo "  $PKGS" | tr -s ' \n' ' ' | tee -a "$LOG"; echo
  sudo apt-get update && sudo apt-get install -y $PKGS 2>&1 | tee -a "$LOG"
  # facoltativi: non tutte le distribuzioni li hanno
  sudo apt-get install -y bulk-extractor 2>/dev/null | tail -1 || true
  if [ "$(uname -m)" != "x86_64" ]; then        # 7zz incluso è per Intel/AMD: su ARM quello della distribuzione
    sudo apt-get install -y 7zip 2>/dev/null || sudo apt-get install -y p7zip-full
  fi
  [ -z "$PY" ] && PY="$(command -v python3)"
else
  echo "apt non trovato: installa a mano con il gestore della tua distribuzione Sleuth Kit, libewf (strumenti ewf*),"
  echo "TestDisk/PhotoRec, Poppler (pdftotext), ExifTool, Tesseract con la lingua italiana, zenity, Python 3.12+"
  echo "con venv e intestazioni di sviluppo, compilatore C. Poi rilancia questo script."
fi

if [ -z "$PY" ] || ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'; then
  echo "Serve Python 3.12 o successivo (Ubuntu 24.04, Debian 13). Trovato: $(python3 --version 2>&1)" | tee -a "$LOG"
  read -r -p "Premi Invio per chiudere..." _; exit 1
fi

if [ ! -x "$DIR/python/bin/python3" ] || ! "$DIR/python/bin/python3" -c 'import plaso, pytsk3, pyewf' 2>/dev/null; then
  echo "Creo l'ambiente Python in $DIR/python con $("$PY" --version) (le librerie libyal si compilano:"
  echo "possono servire 10-20 minuti)..." | tee -a "$LOG"
  "$PY" -m venv "$DIR/python" || { echo "venv non riuscito: installa python3-venv"; exit 1; }
  "$DIR/python/bin/python3" -m pip install --prefer-binary -r "$DIR/requirements-linux.txt" 2>&1 | tee -a "$LOG"
fi
if "$DIR/python/bin/python3" -c 'import plaso, pytsk3, pyewf, PIL' 2>/dev/null; then
  echo "Ambiente Python pronto." | tee -a "$LOG"
else
  echo "ATTENZIONE: alcuni moduli non si sono installati (vedi $LOG)." | tee -a "$LOG"
fi

# 2.20: librerie di iLEAPP e ALEAPP (casi smartphone), ognuno nella sua cartella strumenti/<nome>/site, separate da
# quelle di RepertIA e di plaso. I lettori senza pacchetto binario (biplist, PGPy, mister_skinnylegs, ccl_*) sono in
# strumenti/wheels.
for T in ileapp aleapp; do
  if [ -f "$DIR/strumenti/$T/requirements-repertia.txt" ] && [ ! -d "$DIR/strumenti/$T/site" ]; then
    echo "Librerie di $T (smartphone)..." | tee -a "$LOG"
    "$DIR/python/bin/python3" -m pip install --prefer-binary --find-links "$DIR/strumenti/wheels" \
      --target "$DIR/strumenti/$T/site" -r "$DIR/strumenti/$T/requirements-repertia.txt" 2>&1 | tee -a "$LOG"
    if [ "$T" = "aleapp" ]; then
      "$DIR/python/bin/python3" -m pip install --no-deps --target "$DIR/strumenti/$T/site" \
        "$DIR"/strumenti/wheels/mister_skinnylegs-*.whl "$DIR"/strumenti/wheels/ccl_*.whl 2>&1 | tee -a "$LOG"
    fi
  fi
done

chmod +x "$DIR"/*.sh "$DIR/strumenti/7zip/7zz" 2>/dev/null
[ "$(uname -m)" != "x86_64" ] && rm -rf "$DIR/strumenti/7zip"
mkdir -p "$HOME/.local/share/applications"
cat > "$HOME/.local/share/applications/repertia.desktop" <<EOF2
[Desktop Entry]
Type=Application
Name=RepertIA
Comment=Analisi forense con IA locale
Exec="$DIR/RepertIA.sh"
Icon=$DIR/repertia.png
Terminal=true
Categories=Utility;Security;
EOF2
echo "RepertIA è nel menu delle applicazioni; si avvia anche con ./RepertIA.sh" | tee -a "$LOG"
read -r -p "Fatto. Premi Invio per chiudere..." _
