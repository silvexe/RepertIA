# Componenti di terze parti

*English: [THIRD_PARTY_LICENSES.en.md](THIRD_PARTY_LICENSES.en.md).*

Il **codice di RepertIA** (cartelle `src/`, `build/`, `tools/`) è rilasciato con licenza AGPL-3.0-or-later.
I **pacchetti delle Releases** (zip per Mac, installer e zip per Windows, archivio per Linux) contengono anche i componenti elencati
qui sotto, ciascuno con la propria licenza. I componenti sono distribuiti senza modifiche e vengono eseguiti come
programmi o librerie separati; i testi delle licenze sono nelle cartelle dei componenti dentro i pacchetti
(`strumenti/…`, `python/…/*.dist-info/`).

Versioni riferite ai pacchetti **3.0.3**. Tesseract resta alla 5.4.0 su Windows perché UB Mannheim non pubblica una build più recente; Python resta alla 3.12.15.

## Componenti della mappa (tutti i pacchetti)

| Componente | Versione | Licenza | Sorgenti / sito |
|---|---|---|---|
| MapLibre GL JS | 6.16.0 (`src/mappa`, senza modifiche) | BSD-3-Clause (`mappa/LICENSE-maplibre.txt`) | https://github.com/maplibre/maplibre-gl-js |
| pmtiles (JavaScript) | 4.5.0 (`src/mappa`, senza modifiche) | BSD-3-Clause (`mappa/LICENSE-pmtiles.txt`) | https://github.com/protomaps/PMTiles |
| Noto Sans (Regular, Medium, Italic), glifi PBF | protomaps/basemaps-assets, commit `028c18f` del 31/10/2025 (`src/mappa/fonts`, senza modifiche) | SIL OFL 1.1 (`mappa/fonts/OFL.txt`) | https://github.com/protomaps/basemaps-assets |
| Natural Earth, confini 1:50m e 1:110m | geometrie in `src/mappa/ne_50m.geojson` e `ne_110m.geojson` (report portatile), coordinate arrotondate | pubblico dominio | https://www.naturalearthdata.com/about/terms-of-use/ |

**Dati delle mappe (non inclusi).** Gli estratti si scaricano solo su richiesta dell'analista da Protomaps: © OpenStreetMap contributors, licenza [ODbL](https://opendatacommons.org/licenses/odbl/1-0/), https://www.openstreetmap.org/copyright. Chi pubblica una mappa ottenuta da questi dati, anche in una relazione, deve citare OpenStreetMap e l'indirizzo qui sopra; chi pubblica l'estratto o una sua modifica lo fa con la stessa licenza.

**Video dimostrativo e `docs/media/repertia-demo.gif`.** Mostrano dati di prova e un volo simulato sopra Malta; sfondo © OpenStreetMap contributors, licenza ODbL (openstreetmap.org/copyright).

## Codice sorgente dei componenti GPL e LGPL

Per i componenti con licenza GPL o LGPL distribuiti in forma eseguibile, il codice sorgente corrispondente si ottiene
dai progetti originali agli indirizzi indicati, per la versione indicata, ed è **allegato a ogni Release**:
`RepertIA-2.19.0-sorgenti-terze-parti.tar` (Sleuth Kit con libewf/libvhdi/libvmdk, TestDisk/PhotoRec, bulk_extractor
con la libewf collegata e la ricetta di compilazione, 7-Zip, librerie libyal; elenco nel `LEGGIMI.txt` interno) e
`poppler-<versione>.tar.xz`; dalla 3.0.0 anche `7z2605-src.tar.xz` e `Image-ExifTool-13.61.tar.gz` (13.60 nella 3.0.0), per le versioni di 7-Zip ed ExifTool incluse; dalla 2.20 anche `ffmpeg-n9.0.2-36-g6882969ce9-sorgenti.tar.gz` (FFmpeg al commit
6882969ce9 da cui è costruito l'eseguibile di BtbN). Per le librerie di sistema incluse nelle distribuzioni originali di TestDisk e Poppler per
Windows (Cygwin, Qt, GLib, cairo, libiconv, gettext) e per qualunque altro sorgente corrispondente non allegato,
l'autore lo fornisce su richiesta, per almeno tre anni dalla pubblicazione del pacchetto, tramite le Issues del repository.

## Strumenti inclusi nel pacchetto Windows (`strumenti/`)

| Componente | Versione | Licenza | Sorgenti / sito |
|---|---|---|---|
| The Sleuth Kit | 4.15.0 (win32) | CPL-1.0, IPL-1.0, GPL-2.0 per alcune parti, vedi `README.txt` | https://github.com/sleuthkit/sleuthkit |
| libewf (in Sleuth Kit e libewf-python) | vedi sotto | LGPL-3.0-or-later | https://github.com/libyal/libewf |
| TestDisk / PhotoRec | 7.2 | GPL-2.0-or-later | https://www.cgsecurity.org/wiki/TestDisk_Download — https://github.com/cgsecurity/testdisk |
| Poppler (pdftotext, pdftoppm) | 26.09.0 (build per Windows) | GPL-2.0-or-later / GPL-3.0 | https://poppler.freedesktop.org — https://github.com/oschwartz10612/poppler-windows |
| ExifTool | 13.61 (64 bit, con Strawberry Perl) | Artistic-1.0-Perl OR GPL-1.0-or-later (licenze di Strawberry Perl in `exiftool_files/`) | https://exiftool.org |
| bulk_extractor | 2.2.0, compilato in proprio con MinGW-w64 (ricetta in `build/windows/COME_RICOSTRUIRE.txt`) | codice pubblico + LGPL-2.1, LGPL-3.0, GPL-3.0, CPL-1.0, OpenSSL (vedi `strumenti/bulk_extractor/licenses/`) | https://github.com/simsong/bulk_extractor (tag v2.2.0) |
| 7-Zip (7z.exe, 7z.dll) | 26.05 | LGPL-2.1-or-later + BSD-3-Clause; **restrizione unRAR**: il codice di decompressione RAR non può essere usato per ricreare l'algoritmo di compressione RAR (vedi `License.txt`) | https://www.7-zip.org |
| Tesseract OCR | 5.4.0 (build UB Mannheim) con le DLL che usa (Leptonica, libtiff, libpng, libjpeg, libwebp, OpenJPEG, zlib, zstd, libarchive…) | Apache-2.0; librerie con licenze proprie (BSD, MIT, libtiff, zlib, IJG, OpenSSL/Apache-2.0) | https://github.com/tesseract-ocr/tesseract — https://github.com/UB-Mannheim/tesseract |
| tessdata_fast (eng, ita, osd) | — | Apache-2.0 | https://github.com/tesseract-ocr/tessdata_fast |
| FFmpeg (solo `ffmpeg.exe`, anteprima dei video) | 9.0.2-36-g6882969ce9 (build LGPL di BtbN, autobuild-2026-10-27-18-38) | LGPL-3.0-or-later (`strumenti/ffmpeg/LICENSE.txt`); sorgente esatto allegato alla Release: `ffmpeg-n9.0.2-36-g6882969ce9-sorgenti.tar.gz` | https://ffmpeg.org — https://github.com/BtbN/FFmpeg-Builds |
| Python | 3.12.15 (python-build-standalone, install_only_stripped) | PSF-2.0 (con componenti BSD, MIT, OpenSSL, zlib, Tcl/Tk) | https://github.com/astral-sh/python-build-standalone |

## Pacchetto Mac

L'app contiene Python 3.12 (python-build-standalone), i moduli Python elencati sotto, 7-Zip (`7zz`, licenze come sopra)
i dati di Tesseract (licenza in `strumenti/tessdata/LICENSE.txt`) e, dalla 2.20, whisper.cpp e FFmpeg (vedi «Trascrizione degli audio»). Sleuth Kit, libewf, PhotoRec, Poppler, ExifTool, Tesseract e bulk_extractor **non sono inclusi**:
li installa Homebrew al primo avvio dai rispettivi progetti, con le loro licenze.

## Pacchetto Linux

L'archivio contiene i file di RepertIA, 7-Zip 26.05 per Linux x64 (`strumenti/7zip/7zz`, licenze come sopra, con
`License.txt`), i dati di Tesseract (`strumenti/tessdata`, Apache-2.0, licenza in `LICENSE.txt`) e FFmpeg (dalla 2.20, solo
`strumenti/ffmpeg/bin/ffmpeg`, build LGPL di BtbN come per Windows, LGPL-3.0-or-later, licenza in `strumenti/ffmpeg/LICENSE.txt`,
sorgente esatto allegato alla Release). **Python e i moduli non sono inclusi**: lo script
`installa.sh` li scarica da PyPI sul computer dell'utente, alle versioni elencate sotto (`requirements-linux.txt`, più
`xattr`, MIT). Sleuth Kit, libewf (`ewf-tools`), PhotoRec, Poppler, ExifTool e Tesseract vengono dalla distribuzione
Linux (apt), con le loro licenze. bulk_extractor non è tra i pacchetti di Debian e Ubuntu: chi lo vuole lo compila da
https://github.com/simsong/bulk_extractor (vedi `LEGGIMI.txt`).

## Moduli Python inclusi (Mac e Windows; installati da `installa.sh` su Linux)

| Modulo | Versione | Licenza |
|---|---|---|
| plaso | 20261027 | Apache-2.0 |
| dfvfs, dfdatetime, dfwinreg, dtfabric, artifacts, acstore | 20260924, 20260730, 20260411, 20260506, 20260421, 20260411 | Apache-2.0 |
| pytsk3 | 20260715 | Apache-2.0 (include The Sleuth Kit: CPL/IPL) |
| libyal (libbde, libcaes, libcreg, libesedb, libevt, libevtx, libewf, libfcrypto, libfsapfs, libfsext, libfsfat, libfshfs, libfsntfs, libfsxfs, libfvde, libfwnt, libfwsi, liblnk, libluksde, libmodi, libmsiecf, libolecf, libpff, libphdi, libqcow, libregf, libscca, libsigscan, libsmdev, libsmraw, libvhdi, libvmdk, libvsapm, libvsgpt, libvshadow, libvslvm) -python | 2026xxxx (versione nel nome della cartella `*.dist-info`) | LGPL-3.0-or-later — https://github.com/libyal |
| yara-python | 4.5.4 | Apache-2.0 |
| pefile | 2024.8.26 | MIT |
| Pillow | 13.0.0 | MIT-CMU |
| openai (client) | 3.42.0 | Apache-2.0 |
| grpcio, protobuf, opensearch-py, opensearch-protobufs | 1.84.0, 7.36.2, 3.2.0, 1.2.0 | Apache-2.0 / BSD-3-Clause |
| pydantic, pydantic_core, annotated-types, typing-inspection, jiter, anyio, h11, sniffio | — | MIT (sniffio: MIT OR Apache-2.0) |
| httpx2, httpcore2, idna, psutil, pycparser, pyzmq | — | BSD-3-Clause |
| requests, tzdata | 2.34.2, 2026.5 | Apache-2.0 |
| urllib3, charset-normalizer, six, pytz, PyYAML, pyparsing, redis, truststore, pip | — | MIT |
| certifi | 2026.10.23 | MPL-2.0 |
| cffi | 2.1.1 | MIT-0 |
| defusedxml, typing_extensions | 0.7.1, 4.16.0 | PSF-2.0 |
| python-dateutil | 2.9.0.post0 | Apache-2.0 OR BSD-3-Clause |
| lz4, zstd, Events, Flor | 4.4.5, 1.5.7.2, 0.5, 1.1.3 | BSD |
| XlsxWriter | 3.3.1 | BSD-2-Clause |
| bencode.py | 4.1.0 | BitTorrent Open Source License |
| dissect.evidence (dalla 3.0.2, lettura delle immagini logiche AD1 di FTK Imager) | 3.13 | AGPL-3.0-or-later — https://github.com/fox-it/dissect.evidence |
| dissect.cstruct, dissect.util (usati da dissect.evidence) | 4.7, 3.24 | Apache-2.0 — https://github.com/fox-it |

## iLEAPP e ALEAPP (casi smartphone, dalla 2.20)

Cartelle `strumenti/ileapp` e `strumenti/aleapp` dei pacchetti, eseguite come programmi separati con le loro librerie in
`strumenti/<nome>/site` (su Linux le librerie le installa `installa.sh`; i lettori senza pacchetto binario sono in
`strumenti/wheels`). Ricetta: `build/leapp/prepara_leapp.sh`.

| Componente | Versione | Licenza | Fonte |
|---|---|---|---|
| iLEAPP (Alexis Brignoni e collaboratori) | 2026.4.6 | MIT | https://github.com/abrignoni/iLEAPP |
| ALEAPP (Alexis Brignoni e collaboratori) | 2026.4.5 | MIT | https://github.com/abrignoni/ALEAPP |

Librerie Python di iLEAPP/ALEAPP (versioni dei pacchetti Mac e Windows; licenze dichiarate dai pacchetti, testi in
`site/*.dist-info/`):

| Modulo | Versione | Licenza |
|---|---|---|
| astc_decomp_faster | 1.1.5 | zlib/libpng License |
| bcrypt | 5.0.0 | Apache Software License |
| beautifulsoup4 | 4.15.0, 4.8.2 | MIT License |
| bencoding | 0.2.6 | MIT |
| biplist | 1.0.3 | BSD License |
| branca | 0.8.2 | MIT License |
| brotli | 1.2.1 | MIT |
| bs4 | 0.0.2 | MIT License |
| ccl_chromium_reader | 0.3.18 | MIT License |
| ccl_mozilla_reader | 0.0.12 | MIT License |
| ccl_simplesnappy | 0.4 | MIT License |
| certifi | 2026.10.23 | Mozilla Public License 2.0 (MPL 2.0) |
| cffi | 2.1.1 | MIT-0 |
| charset-normalizer | 3.5.2 | MIT |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause |
| fitdecode | 0.10.0 | MIT License |
| folium | 0.14.0 | MIT License |
| idna | 3.20 | BSD-3-Clause |
| ijson | 3.6.0 | BSD-3-Clause AND ISC |
| Jinja2 | 3.1.6 | BSD License |
| lz4 | 4.3.3 | BSD License |
| MarkupSafe | 3.0.4 | BSD-3-Clause |
| mdplistlib | 0.1.3 | MIT License |
| mister_skinnylegs | 0.0.18 | MIT License |
| mmh3 | 5.3.1 | MIT License |
| msgpack | 1.2.3 | Apache-2.0 |
| nska_deserialize | 1.5.1 | MIT License |
| numpy | 1.26.4 | BSD License |
| numpy | 2.5.4 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| pandas | 3.0.6 | BSD License |
| pathlib2 | 2.3.5 | MIT License |
| PGPy | 0.6.0 | BSD License |
| pillow | 13.0.0 | MIT-CMU |
| pillow_heif | 1.8.1 | BSD-3-Clause |
| polyline | 2.0.0 | MIT |
| protobuf | 5.29.6 | 3-Clause BSD License |
| pyahocorasick | 2.3.1 | BSD-3-Clause and Public-Domain |
| pyasn1 | 0.6.5 | BSD-2-Clause |
| pycparser | 3.12 | BSD-3-Clause |
| pycryptodome | 4.3.0 | BSD-2-Clause AND Unlicense AND MIT |
| pyliblzfse | 0.4.1 | MIT |
| python-dateutil | 4.0.0 | BSD-3-Clause |
| pytypedstream | 0.1.0 | GNU Lesser General Public License v3 or later (LGPLv3+) |
| pytz | 2026.6 | MIT License |
| requests | 2.34.2 | Apache Software License |
| simplekml | 1.3.5 | GNU Lesser General Public License v3 or later (LGPLv3+) |
| six | 1.17.0 | MIT License |
| soupsieve | 4.0 | MIT |
| sqlcipher3 | 0.6.2 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |
| tzdata | 2026.6 | Apache-2.0 |
| urllib3 | 2.8.0 | MIT |
| wheel | 0.48.0 | MIT |
| XlsxWriter | 3.1.1 | BSD License |
| xmltodict | 1.0.4 | MIT |
| zstd | 1.5.7.2 | BSD |

`pytypedstream` e `simplekml` (LGPL-3.0-or-later) sono in puro Python: il codice sorgente è nei file distribuiti. `bencoding` e `bs4` dichiarano la licenza MIT senza includerne il testo: nei pacchetti c'è `LICENSE-NOTA.txt` con il testo standard e il nome indicato dal progetto.

## Trascrizione degli audio (dalla 2.20)

Cartella `strumenti/whisper` dei pacchetti: il motore di trascrizione, eseguito come programma separato. **I modelli non
sono inclusi**: si scaricano solo con il consenso dell'analista (finestra con provenienza e SHA-256) o si indica un file
già scaricato, e restano accanto alle impostazioni (`modelli_trascrizione/`).

| Componente | Versione | Licenza | Fonte |
|---|---|---|---|
| whisper.cpp (`whisper-cli` e librerie ggml) – Mac | 1.9.5, compilato in proprio per Apple Silicon con Metal (ricetta in `build/mac/COME_RICOSTRUIRE.txt`) | MIT (`strumenti/whisper/LICENSE`) | https://github.com/ggml-org/whisper.cpp (tag v1.9.5) |
| whisper.cpp – Windows | 1.9.5, binari ufficiali `whisper-bin-x64.zip` (release b5454, stesso commit d1be6fde) | MIT | come sopra |
| whisper.cpp – Linux | 1.9.5, binari ufficiali `whisper-bin-ubuntu-x64.tar.gz` (release b5454) | MIT | come sopra |
| Librerie Visual C++ (`msvcp140.dll`, `vcruntime140.dll`, `vcruntime140_1.dll`) – Windows | ridistribuibili Microsoft | licenza dei ridistribuibili di Microsoft Visual Studio | https://learn.microsoft.com/cpp/windows/redistributing-visual-cpp-files |
| FFmpeg – Mac (solo `ffmpeg`, conversione degli audio e miniature dei video) | 9.0.2-36-g6882969ce9, compilato in proprio in versione LGPL minima (ricetta in `build/mac/COME_RICOSTRUIRE.txt`) | LGPL-2.1-or-later (`strumenti/ffmpeg/LICENSE.LGPLv2.1`); sorgente esatto allegato alla Release: `ffmpeg-n9.0.2-36-g6882969ce9-sorgenti.tar.gz` | https://ffmpeg.org |
| Modelli Whisper (`ggml-base-q5_1.bin`, `ggml-small-q5_1.bin`, `ggml-large-v3-turbo-q5_0.bin`) – non inclusi | repository `ggerganov/whisper.cpp` su Hugging Face, commit 5359861c | MIT (modelli Whisper di OpenAI, conversione di whisper.cpp) | https://huggingface.co/ggerganov/whisper.cpp |

## Dati di collaudo (`RepertIA-collaudo.zip`)

Provenienza e licenze anche nel `LEGGIMI.txt` dell'archivio, con i testi delle licenze in `LICENZE/`.

| Dati | Licenza | Fonte |
|---|---|---|
| Immagini DFTT (Digital Forensics Tool Testing) 5, 6, 7, 8, 11 | GPL (come indicato dal progetto DFTT) | https://dftt.sourceforge.net — https://sourceforge.net/projects/dftt/ |
| Immagini di prova di dfvfs (APFS, APFS cifrato, BitLocker To Go) | Apache-2.0 | https://github.com/log2timeline/dfvfs/tree/main/test_data |
| Immagini costruite per il collaudo (ext4 in E01, E01 alterato, chiavetta FAT, volume Dati di un Mac) | AGPL-3.0-or-later, come RepertIA | questo repository |
| Caso NIST CFReDS «Data Leakage», CD-R RM#3 (`nist/`, dalla 3.0.2, senza modifiche, SHA-1 pubblicato da NIST) | pubblico dominio (opera del governo degli Stati Uniti) | https://cfreds-archive.nist.gov/data_leakage_case/ |

Piccoli file di prova incorporati in `src/forense_collaudo.py` (dalla 3.0.2): l'AD1 compresso dei test di dissect.evidence
(Fox-IT, AGPL-3.0-or-later), i RAR 4 e RAR 5 dei test di libarchive (BSD-2-Clause) e lo `StickyNotes.snt` del PC del caso
NIST «Data Leakage» (pubblico dominio).

## Strumenti usati per costruire i pacchetti (non inclusi)

NSIS (zlib/libpng), python-build-standalone, Homebrew, MinGW-w64. Gli script `build/windows/nsis_x.py` e
`build/windows/nsis_patch.py` (AGPL-3.0-or-later) servono a ricostruire l'installer senza NSIS.

## Formati dei registri di volo (dalla 3.0)

I lettori di registri Autel, PX4 ULog, ArduPilot tlog e DataFlash sono scritti in RepertIA: nessun codice di terzi è incluso. Per il formato Autel ci si è basati sulla documentazione e sul parser di [autel-logger](https://github.com/MansfieldTX-MattR/autel-logger) (MIT, Copyright (c) 2024 Matt Reid): il programma non li include, ma le dimensioni dei record sono ricavate dal parser e la nota di copyright e di licenza MIT è riportata in `src/forense_droni.py`. autel-logger, pyulog (BSD-3) e pymavlink (LGPL-3) sono stati usati solo per il confronto dei risultati durante le prove, fuori dai pacchetti.
