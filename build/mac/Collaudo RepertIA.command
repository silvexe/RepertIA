#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
# RepertIA - Collaudo con immagini di riferimento (Mac Apple Silicon).
# Serve la cartella RepertIA-collaudo (dallo zip RepertIA-collaudo.zip) accanto a questo file,
# sulla Scrivania o in Download; altrimenti trascinala in questa finestra quando richiesto.
cd "$(dirname "$0")" || exit 1
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1
APP=""
for a in "$(pwd)/RepertIA.app" "/Applications/RepertIA.app" "$HOME/Applications/RepertIA.app"; do
  [ -x "$a/Contents/Resources/python/bin/python3" ] && APP="$a" && break
done
if [ -z "$APP" ]; then echo "RepertIA.app non trovata."; read -r -p "Premi Invio per chiudere..." _; exit 1; fi
DIR=""
for d in "$(pwd)/RepertIA-collaudo" "$HOME/Desktop/RepertIA-collaudo" "$HOME/Downloads/RepertIA-collaudo"; do
  [ -f "$d/atteso.json" ] && DIR="$d" && break
done
if [ -z "$DIR" ]; then
  echo "Trascina qui la cartella RepertIA-collaudo e premi Invio:"
  read -r DIR; DIR="${DIR%\"}"; DIR="${DIR#\"}"; DIR="${DIR//\\ / }"; DIR="${DIR% }"
fi
if [ ! -f "$DIR/atteso.json" ]; then echo "Cartella di collaudo non valida: $DIR"; read -r -p "Premi Invio per chiudere..." _; exit 1; fi
echo "== Collaudo di RepertIA con le immagini di $DIR =="
"$APP/Contents/Resources/python/bin/python3" "$APP/Contents/Resources/RepertIA/forense_collaudo.py" "$DIR"
echo
echo "Il rapporto (collaudo_<data>.md) è in ~/CasiForensi/_collaudo/."
open "$HOME/CasiForensi/_collaudo" 2>/dev/null
read -r -p "Premi Invio per chiudere..." _
