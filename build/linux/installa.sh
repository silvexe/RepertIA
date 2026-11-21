#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
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
  # (3.0.2) libewf: il pacchetto si chiama ewf-tools (Debian e Ubuntu; «libewf-tools» non esiste e faceva fallire
  # tutta l'installazione). bulk-extractor non è in Debian né in Ubuntu (c'è in Kali e in altre): se manca, si spiega.
  PKGS="sleuthkit ewf-tools testdisk poppler-utils libimage-exiftool-perl tesseract-ocr tesseract-ocr-ita
        zenity xdg-utils python3 python3-venv python3-dev build-essential pkg-config zlib1g-dev bulk-extractor
        libusb-1.0-0 libssl3t64"   # (3.0.5) librerie di sistema richieste da MemProcFS (analisi della RAM)
  # 7zz e ffmpeg inclusi sono per Intel/AMD: sulle altre architetture quelli della distribuzione;
  # libgomp1 serve al motore di trascrizione (whisper-cli)
  [ "$(uname -m)" != "x86_64" ] && PKGS="$PKGS 7zip ffmpeg libgomp1"
  echo "Aggiorno l'elenco dei pacchetti con apt (chiede la password di amministratore)..." | tee -a "$LOG"
  sudo apt-get update 2>&1 | tee -a "$LOG"
  # solo i pacchetti che la distribuzione ha: uno che manca non deve bloccare gli altri
  # (3.0.5) LC_ALL=C: su un sistema non in inglese apt traduce «Candidate:» e nessun pacchetto risultava disponibile
  OK=""; NO=""
  for p in $PKGS; do
    if [ -n "$(LC_ALL=C apt-cache policy "$p" 2>/dev/null | grep -m1 'Candidate:' | grep -v '(none)')" ]; then OK="$OK $p"
    else NO="$NO $p"; fi
  done
  # libssl3t64 è il nome in Debian 13 e Ubuntu 24.04; nelle distribuzioni precedenti si chiama libssl3
  case " $NO " in *" libssl3t64 "*) LC_ALL=C apt-cache policy libssl3 2>/dev/null | grep -q 'Candidate: [0-9]' && OK="$OK libssl3" ;; esac
  case " $NO " in *" 7zip "*) LC_ALL=C apt-cache policy p7zip-full 2>/dev/null | grep -q 'Candidate: [0-9]' && OK="$OK p7zip-full" ;; esac
  echo "Installo:$OK" | tee -a "$LOG"
  sudo apt-get install -y $OK 2>&1 | tee -a "$LOG"
  if [ -n "$NO" ]; then
    echo "Non disponibili in questa distribuzione:$NO" | tee -a "$LOG"
  fi
  if ! command -v bulk_extractor >/dev/null 2>&1 && [ ! -x "$DIR/strumenti/bulk_extractor/bulk_extractor" ]; then
    echo "bulk_extractor (facoltativo, ricerca di email, URL e altri elementi nei dati grezzi) non trovato." | tee -a "$LOG"
    echo "  Si compila da https://github.com/simsong/bulk_extractor (istruzioni nel suo README), poi:" | tee -a "$LOG"
    echo "  sudo make install   oppure copia il programma in $DIR/strumenti/bulk_extractor/" | tee -a "$LOG"
    echo "  e riavvia RepertIA. Controllo: which bulk_extractor" | tee -a "$LOG"
  fi
  [ -z "$PY" ] && PY="$(command -v python3)"
else
  echo "apt non trovato: installa a mano con il gestore della tua distribuzione Sleuth Kit, libewf (strumenti ewf*),"
  echo "TestDisk/PhotoRec, Poppler (pdftotext), ExifTool, Tesseract con la lingua italiana, zenity, Python 3.12+"
  echo "con venv e intestazioni di sviluppo, compilatore C; facoltativo bulk_extractor (nel PATH o in"
  echo "$DIR/strumenti/bulk_extractor/). Poi rilancia questo script."
fi

if [ -z "$PY" ] || ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'; then
  echo "Serve Python 3.12 o successivo (Ubuntu 24.04, Debian 13). Trovato: $(python3 --version 2>&1)" | tee -a "$LOG"
  read -r -p "Premi Invio per chiudere..." _; exit 1
fi

# (3.0.6) impronta dell'elenco delle librerie: dopo un aggiornamento del programma, se l'elenco è cambiato, pip
# installa solo le versioni diverse (python/.requisiti_repertia è l'impronta dell'ultima installazione riuscita)
impronta() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
REQ="$(impronta "$DIR/requirements-linux.txt")"
if [ ! -x "$DIR/python/bin/python3" ] || ! "$DIR/python/bin/python3" -c 'import plaso, pytsk3, pyewf' 2>/dev/null; then
  echo "Creo l'ambiente Python in $DIR/python con $("$PY" --version) (le librerie libyal si compilano:"
  echo "possono servire 10-20 minuti)..." | tee -a "$LOG"
  "$PY" -m venv "$DIR/python" || { echo "venv non riuscito: installa python3-venv"; exit 1; }
  "$DIR/python/bin/python3" -m pip install --prefer-binary -r "$DIR/requirements-linux.txt" 2>&1 | tee -a "$LOG"
elif [ -n "$REQ" ] && [ "$(cat "$DIR/python/.requisiti_repertia" 2>/dev/null)" != "$REQ" ]; then
  echo "Librerie Python cambiate con la versione nuova (requirements-linux.txt): aggiorno l'ambiente..." | tee -a "$LOG"
  "$DIR/python/bin/python3" -m pip install --prefer-binary -r "$DIR/requirements-linux.txt" 2>&1 | tee -a "$LOG"
fi
if "$DIR/python/bin/python3" -c 'import plaso, pytsk3, pyewf, PIL' 2>/dev/null; then
  echo "Ambiente Python pronto." | tee -a "$LOG"
  [ -n "$REQ" ] && echo "$REQ" > "$DIR/python/.requisiti_repertia"
else
  echo "ATTENZIONE: alcuni moduli non si sono installati (vedi $LOG)." | tee -a "$LOG"
fi

# 2.20: librerie di iLEAPP e ALEAPP (casi smartphone), ognuno nella sua cartella strumenti/<nome>/site, separate da
# quelle di RepertIA e di plaso. I lettori senza pacchetto binario (biplist, PGPy, mister_skinnylegs, ccl_*) sono in
# strumenti/wheels.
# (3.0.6) se l'elenco di iLEAPP/ALEAPP è cambiato con la versione nuova, la cartella site si rifà da capo
for T in ileapp aleapp; do
  RT="$DIR/strumenti/$T/requirements-repertia.txt"
  [ -f "$RT" ] || continue
  HT="$(impronta "$RT")"
  if [ -d "$DIR/strumenti/$T/site" ] && [ "$(cat "$DIR/strumenti/$T/site/.requisiti_repertia" 2>/dev/null)" != "$HT" ]; then
    echo "Librerie di $T cambiate con la versione nuova: le reinstallo..." | tee -a "$LOG"
    rm -rf "$DIR/strumenti/$T/site"
  fi
  if [ ! -d "$DIR/strumenti/$T/site" ]; then
    echo "Librerie di $T (smartphone)..." | tee -a "$LOG"
    "$DIR/python/bin/python3" -m pip install --prefer-binary --find-links "$DIR/strumenti/wheels" \
      --target "$DIR/strumenti/$T/site" -r "$RT" 2>&1 | tee -a "$LOG"
    ESITO=${PIPESTATUS[0]}
    if [ "$T" = "aleapp" ] && [ "$ESITO" = 0 ]; then
      "$DIR/python/bin/python3" -m pip install --no-deps --target "$DIR/strumenti/$T/site" \
        "$DIR"/strumenti/wheels/mister_skinnylegs-*.whl "$DIR"/strumenti/wheels/ccl_*.whl 2>&1 | tee -a "$LOG"
      ESITO=${PIPESTATUS[0]}
    fi
    [ "$ESITO" = 0 ] && [ -n "$HT" ] && echo "$HT" > "$DIR/strumenti/$T/site/.requisiti_repertia"
  fi
done

chmod +x "$DIR"/*.sh "$DIR/strumenti/7zip/7zz" "$DIR"/strumenti/whisper*/bin/whisper-cli 2>/dev/null
# (3.0.5) Programmi inclusi per Intel/AMD: sulle altre architetture si tolgono (un programma di un'altra architettura
# nel PATH non parte e ferma la trascrizione) e si usano quelli della distribuzione. Su ARM a 64 bit il motore di
# trascrizione incluso per ARM (strumenti/whisper_aarch64) prende il posto di quello per Intel/AMD.
if [ "$(uname -m)" != "x86_64" ]; then
  rm -rf "$DIR/strumenti/7zip" "$DIR/strumenti/ffmpeg"
  case "$(uname -m)" in
    aarch64|arm64)
      if [ -x "$DIR/strumenti/whisper_aarch64/bin/whisper-cli" ]; then
        rm -rf "$DIR/strumenti/whisper"
        mv "$DIR/strumenti/whisper_aarch64" "$DIR/strumenti/whisper"
        echo "Trascrizione degli audio: motore per ARM a 64 bit in strumenti/whisper." | tee -a "$LOG"
      fi ;;
    *) rm -rf "$DIR/strumenti/whisper" "$DIR/strumenti/whisper_aarch64" ;;
  esac
  command -v ffmpeg >/dev/null 2>&1 || echo "ffmpeg non trovato: serve alla trascrizione degli audio (sudo apt install ffmpeg)." | tee -a "$LOG"
fi
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
