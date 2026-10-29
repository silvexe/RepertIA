#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
# RepertIA 2.20 - prepara le cartelle strumenti/ileapp e strumenti/aleapp per i pacchetti Mac, Windows e Linux.
# Uso: ./prepara_leapp.sh <python 3.12 dell'app per Mac> <cartella di lavoro>
# Scarica iLEAPP v2026.4.5 e ALEAPP v2026.4.4 (GitHub, licenza MIT) e le loro librerie (PyPI), ciascuno con le sue in
# <strumento>/site (non si mescolano con quelle di RepertIA e di plaso). Risultato: <lavoro>/strum_mac, strum_win, strum_linux.
set -e
P="$1"; W="$2"; HERE="$(cd "$(dirname "$0")" && pwd)"
[ -x "$P" ] && [ -n "$W" ] || { echo "uso: $0 <python3.12> <cartella>"; exit 1; }
mkdir -p "$W/dl" "$W/wheels"; cd "$W"
curl -sL -o dl/ileapp.tar.gz https://codeload.github.com/abrignoni/iLEAPP/tar.gz/refs/tags/v2026.4.5
curl -sL -o dl/aleapp.tar.gz https://codeload.github.com/abrignoni/ALEAPP/tar.gz/refs/tags/v2026.4.4
shasum -a 256 dl/*.tar.gz
for t in ileapp aleapp; do rm -rf src_$t; mkdir src_$t; tar -xzf dl/$t.tar.gz -C src_$t --strip-components 1; done
# lettori senza pacchetto binario: wheel universali (puro Python), alle versioni/commit usati da iLEAPP/ALEAPP
"$P" -m pip wheel --no-deps -w wheels biplist PGPy==0.6.0 \
  "mister_skinnylegs @ git+https://github.com/cclgroupltd/mister-skinnylegs.git@v0.0.18" \
  "ccl_chromium_reader @ git+https://github.com/cclgroupltd/ccl_chrome_indexeddb.git@ef840de30221c4d65bc96d2f4d9057e9ef2f526d" \
  "ccl_mozilla_reader @ git+https://github.com/cclgroupltd/ccl_mozilla_reader.git@b3d0627f747a718e1e30ac02b92e82bdde354eb2" \
  "ccl_simplesnappy @ git+https://github.com/cclgroupltd/ccl_simplesnappy.git@3d085230baa8c46cf2090ebba29bf6e8eab31087"
EXCL=(--exclude admin --exclude tests --exclude packaging --exclude whl_files --exclude CLAUDE.md --exclude '*.whl' --exclude .github --exclude __pycache__)
for os in mac win linux; do rm -rf strum_$os; mkdir strum_$os; for t in ileapp aleapp; do rsync -a "${EXCL[@]}" src_$t/ strum_$os/$t/; done; done
# Mac (librerie del sistema su cui si costruisce: Apple Silicon)
"$P" -m pip install --prefer-binary --find-links wheels --target strum_mac/ileapp/site -r "$HERE/requirements-ileapp.txt"
grep -v mister_skinnylegs "$HERE/requirements-aleapp.txt" > /tmp/req_aleapp_mac.txt; printf "Brotli==1.2.0\nzstd==1.5.7.2\nlz4==4.3.3\n" >> /tmp/req_aleapp_mac.txt
"$P" -m pip install --prefer-binary --target strum_mac/aleapp/site -r /tmp/req_aleapp_mac.txt
"$P" -m pip install --no-deps --target strum_mac/aleapp/site wheels/mister_skinnylegs-*.whl wheels/ccl_*.whl
# Windows x64, Python 3.12 (wheel binarie da PyPI; pyliblzfse dalla cartella whl_files di iLEAPP)
cd src_ileapp
"$P" -m pip install --platform win_amd64 --python-version 3.12 --implementation cp --only-binary=:all: --find-links ../wheels \
  --target ../strum_win/ileapp/site -r "$HERE/requirements-ileapp-windows.txt" biplist PGPy==0.6.0
cd ..
"$P" -m pip install --platform win_amd64 --python-version 3.12 --implementation cp --only-binary=:all: \
  --target strum_win/aleapp/site -r "$HERE/requirements-aleapp-windows.txt"
"$P" -m pip install --no-deps --target strum_win/aleapp/site wheels/mister_skinnylegs-*.whl wheels/ccl_*.whl
# Linux: le librerie le installa installa.sh sul computer di destinazione
mkdir -p strum_linux/wheels; cp wheels/*.whl strum_linux/wheels/
cp "$HERE/requirements-ileapp.txt" strum_linux/ileapp/requirements-repertia.txt
cp "$HERE/requirements-aleapp-windows.txt" strum_linux/aleapp/requirements-repertia.txt
find strum_* -type d \( -name __pycache__ -o -path "*/site/bin" \) -prune -exec rm -rf {} +
du -sh strum_*
