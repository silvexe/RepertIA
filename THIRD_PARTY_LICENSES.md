# Componenti di terze parti

*English: [THIRD_PARTY_LICENSES.en.md](THIRD_PARTY_LICENSES.en.md).*

Il **codice di RepertIA** (cartelle `src/`, `build/`, `tools/`) è rilasciato con licenza GPL-3.0-or-later.
I **pacchetti delle Releases** (zip per Mac, installer e zip per Windows, archivio per Linux) contengono anche i componenti elencati
qui sotto, ciascuno con la propria licenza. I componenti sono distribuiti senza modifiche e vengono eseguiti come
programmi o librerie separati; i testi delle licenze sono nelle cartelle dei componenti dentro i pacchetti
(`strumenti/…`, `python/…/*.dist-info/`).

Versioni riferite ai pacchetti **2.18.0 – 2.19.0** (i componenti non sono cambiati).

## Codice sorgente dei componenti GPL e LGPL

Per i componenti con licenza GPL o LGPL distribuiti in forma eseguibile, il codice sorgente corrispondente si ottiene
dai progetti originali agli indirizzi indicati, per la versione indicata, ed è **allegato a ogni Release**:
`RepertIA-<versione>-sorgenti-terze-parti.tar` (Sleuth Kit con libewf/libvhdi/libvmdk, TestDisk/PhotoRec, bulk_extractor
con la libewf collegata e la ricetta di compilazione, 7-Zip, librerie libyal; elenco nel `LEGGIMI.txt` interno) e
`poppler-<versione>.tar.xz`. Per le librerie di sistema incluse nelle distribuzioni originali di TestDisk e Poppler per
Windows (Cygwin, Qt, GLib, cairo, libiconv, gettext) e per qualunque altro sorgente corrispondente non allegato,
l'autore lo fornisce su richiesta, per almeno tre anni dalla pubblicazione del pacchetto, tramite le Issues del repository.

## Strumenti inclusi nel pacchetto Windows (`strumenti/`)

| Componente | Versione | Licenza | Sorgenti / sito |
|---|---|---|---|
| The Sleuth Kit | 4.15.0 (win32) | CPL-1.0, IPL-1.0, GPL-2.0 per alcune parti, vedi `README.txt` | https://github.com/sleuthkit/sleuthkit |
| libewf (in Sleuth Kit e libewf-python) | vedi sotto | LGPL-3.0-or-later | https://github.com/libyal/libewf |
| TestDisk / PhotoRec | 7.2 | GPL-2.0-or-later | https://www.cgsecurity.org/wiki/TestDisk_Download — https://github.com/cgsecurity/testdisk |
| Poppler (pdftotext, pdftoppm) | 26.09.0 (build per Windows) | GPL-2.0-or-later / GPL-3.0 | https://poppler.freedesktop.org — https://github.com/oschwartz10612/poppler-windows |
| ExifTool | 13.59 (64 bit, con Strawberry Perl) | Artistic-1.0-Perl OR GPL-1.0-or-later (licenze di Strawberry Perl in `exiftool_files/`) | https://exiftool.org |
| bulk_extractor | 2.2.0, compilato in proprio con MinGW-w64 (ricetta in `build/windows/COME_RICOSTRUIRE.txt`) | codice pubblico + LGPL-2.1, LGPL-3.0, GPL-3.0, CPL-1.0, OpenSSL (vedi `strumenti/bulk_extractor/licenses/`) | https://github.com/simsong/bulk_extractor (tag v2.2.0) |
| 7-Zip (7z.exe, 7z.dll) | 26.01 | LGPL-2.1-or-later + BSD-3-Clause; **restrizione unRAR**: il codice di decompressione RAR non può essere usato per ricreare l'algoritmo di compressione RAR (vedi `License.txt`) | https://www.7-zip.org |
| Tesseract OCR | 5.4.0 (build UB Mannheim) con le DLL che usa (Leptonica, libtiff, libpng, libjpeg, libwebp, OpenJPEG, zlib, zstd, libarchive…) | Apache-2.0; librerie con licenze proprie (BSD, MIT, libtiff, zlib, IJG, OpenSSL/Apache-2.0) | https://github.com/tesseract-ocr/tesseract — https://github.com/UB-Mannheim/tesseract |
| tessdata_fast (eng, ita, osd) | — | Apache-2.0 | https://github.com/tesseract-ocr/tessdata_fast |
| Python | 3.12.15 (python-build-standalone, install_only_stripped) | PSF-2.0 (con componenti BSD, MIT, OpenSSL, zlib, Tcl/Tk) | https://github.com/astral-sh/python-build-standalone |

## Pacchetto Mac

L'app contiene Python 3.12 (python-build-standalone), i moduli Python elencati sotto, 7-Zip (`7zz`, licenze come sopra)
e i dati di Tesseract (licenza in `strumenti/tessdata/LICENSE.txt`). Sleuth Kit, libewf, PhotoRec, Poppler, ExifTool, Tesseract e bulk_extractor **non sono inclusi**:
li installa Homebrew al primo avvio dai rispettivi progetti, con le loro licenze.

## Pacchetto Linux

L'archivio contiene i file di RepertIA, 7-Zip 26.01 per Linux x64 (`strumenti/7zip/7zz`, licenze come sopra, con
`License.txt`) e i dati di Tesseract (`strumenti/tessdata`, Apache-2.0, licenza in `LICENSE.txt`). **Python e i moduli non sono inclusi**: lo script
`installa.sh` li scarica da PyPI sul computer dell'utente, alle versioni elencate sotto (`requirements-linux.txt`, più
`xattr`, MIT). Sleuth Kit, libewf, PhotoRec, Poppler, ExifTool, Tesseract e bulk_extractor vengono dalla distribuzione
Linux (apt), con le loro licenze.

## Moduli Python inclusi (Mac e Windows; installati da `installa.sh` su Linux)

| Modulo | Versione | Licenza |
|---|---|---|
| plaso | 20260720 | Apache-2.0 |
| dfvfs, dfdatetime, dfwinreg, dtfabric, artifacts, acstore | 20260924, 20260730, 20260411, 20260506, 20260421, 20260411 | Apache-2.0 |
| pytsk3 | 20260715 | Apache-2.0 (include The Sleuth Kit: CPL/IPL) |
| libyal (libbde, libcaes, libcreg, libesedb, libevt, libevtx, libewf, libfcrypto, libfsapfs, libfsext, libfsfat, libfshfs, libfsntfs, libfsxfs, libfvde, libfwnt, libfwsi, liblnk, libluksde, libmodi, libmsiecf, libolecf, libpff, libphdi, libqcow, libregf, libscca, libsigscan, libsmdev, libsmraw, libvhdi, libvmdk, libvsapm, libvsgpt, libvshadow, libvslvm) -python | 2026xxxx (versione nel nome della cartella `*.dist-info`) | LGPL-3.0-or-later — https://github.com/libyal |
| yara-python | 4.5.4 | Apache-2.0 |
| pefile | 2024.8.26 | MIT |
| Pillow | 12.3.0 | MIT-CMU |
| openai (client) | 3.28.0 | Apache-2.0 |
| grpcio, protobuf, opensearch-py, opensearch-protobufs | 1.84.0, 7.36.2, 3.2.0, 1.2.0 | Apache-2.0 / BSD-3-Clause |
| pydantic, pydantic_core, annotated-types, typing-inspection, jiter, anyio, h11, sniffio | — | MIT (sniffio: MIT OR Apache-2.0) |
| httpx2, httpcore2, idna, psutil, pycparser, pyzmq | — | BSD-3-Clause |
| requests, tzdata | 2.34.2, 2026.5 | Apache-2.0 |
| urllib3, charset-normalizer, six, pytz, PyYAML, pyparsing, redis, truststore, pip | — | MIT |
| certifi | 2026.7.22 | MPL-2.0 |
| cffi | 2.1.1 | MIT-0 |
| defusedxml, typing_extensions | 0.7.1, 4.16.0 | PSF-2.0 |
| python-dateutil | 2.9.0.post0 | Apache-2.0 OR BSD-3-Clause |
| lz4, zstd, Events, Flor | 4.4.5, 1.5.7.2, 0.5, 1.1.3 | BSD |
| XlsxWriter | 3.2.9 | BSD-2-Clause |
| bencode.py | 4.1.0 | BitTorrent Open Source License |

## Dati di collaudo (`RepertIA-collaudo.zip`)

Provenienza e licenze anche nel `LEGGIMI.txt` dell'archivio, con i testi delle licenze in `LICENZE/`.

| Dati | Licenza | Fonte |
|---|---|---|
| Immagini DFTT (Digital Forensics Tool Testing) 5, 6, 7, 8, 11 | GPL (come indicato dal progetto DFTT) | https://dftt.sourceforge.net — https://sourceforge.net/projects/dftt/ |
| Immagini di prova di dfvfs (APFS, APFS cifrato, BitLocker To Go) | Apache-2.0 | https://github.com/log2timeline/dfvfs/tree/main/test_data |
| Immagini costruite per il collaudo (ext4 in E01, E01 alterato, chiavetta FAT, volume Dati di un Mac) | GPL-3.0-or-later, come RepertIA | questo repository |

## Strumenti usati per costruire i pacchetti (non inclusi)

NSIS (zlib/libpng), python-build-standalone, Homebrew, MinGW-w64. Gli script `build/windows/nsis_x.py` e
`build/windows/nsis_patch.py` (GPL-3.0-or-later) servono a ricostruire l'installer senza NSIS.
