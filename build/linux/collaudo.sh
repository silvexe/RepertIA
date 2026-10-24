#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
# RepertIA - Collaudo con immagini di riferimento (Linux).
# Serve la cartella RepertIA-collaudo (dallo zip RepertIA-collaudo.zip) accanto a questo file,
# sulla Scrivania o in Scaricati; altrimenti trascinala in questa finestra quando richiesto.
# Opzione: ./collaudo.sh --lingua en  (casi di prova in inglese)
DIR0="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR0" || exit 1
export PYTHONDONTWRITEBYTECODE=1
PY="$DIR0/python/bin/python3"
if [ ! -x "$PY" ]; then echo "RepertIA non è installato: esegui prima installa.sh"; exit 1; fi
DIR=""
for d in "$DIR0/RepertIA-collaudo" "$(xdg-user-dir DESKTOP 2>/dev/null)/RepertIA-collaudo" \
         "$(xdg-user-dir DOWNLOAD 2>/dev/null)/RepertIA-collaudo" "$HOME/Desktop/RepertIA-collaudo" \
         "$HOME/Scrivania/RepertIA-collaudo" "$HOME/Scaricati/RepertIA-collaudo" "$HOME/Downloads/RepertIA-collaudo"; do
  [ -f "$d/atteso.json" ] && DIR="$d" && break
done
if [ -z "$DIR" ]; then
  echo "Trascina qui la cartella RepertIA-collaudo e premi Invio:"
  read -r DIR; DIR="${DIR%\'}"; DIR="${DIR#\'}"; DIR="${DIR%\"}"; DIR="${DIR#\"}"; DIR="${DIR% }"
fi
if [ ! -f "$DIR/atteso.json" ]; then echo "Cartella di collaudo non valida: $DIR"; read -r -p "Premi Invio per chiudere..." _; exit 1; fi
echo "== Collaudo di RepertIA con le immagini di $DIR =="
"$PY" "$DIR0/RepertIA/forense_collaudo.py" "$DIR" "$@"
echo
echo "Il rapporto (collaudo_<data>.md) è in ~/CasiForensi/_collaudo/."
xdg-open "$HOME/CasiForensi/_collaudo" >/dev/null 2>&1 &
read -r -p "Premi Invio per chiudere..." _
