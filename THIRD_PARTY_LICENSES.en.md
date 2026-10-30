# Third-party components

*Translation of [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md); the Italian text prevails.*

**RepertIA's code** (folders `src/`, `build/`, `tools/`) is released under GPL-3.0-or-later.
The **Release packages** (Mac zip, Windows installer and zip, Linux archive) also contain the components listed below,
each under its own license. The components are distributed unmodified and run as separate programs or libraries; the
license texts are in the component folders inside the packages (`strumenti/…`, `python/…/*.dist-info/`).

Versions refer to the **2.18.0 – 2.20.3** packages (the disk components did not change; 2.20 adds iLEAPP, ALEAPP, FFmpeg and the whisper.cpp transcription engine).

## Source code of GPL and LGPL components

For the GPL- or LGPL-licensed components distributed in executable form, the corresponding source code can be obtained
from the original projects at the addresses given, for the version given, and it is **attached to every Release**:
`RepertIA-<version>-sorgenti-terze-parti.tar` (Sleuth Kit with libewf/libvhdi/libvmdk, TestDisk/PhotoRec, bulk_extractor
with the linked libewf and its build recipe, 7-Zip, libyal libraries; list in the `LEGGIMI.txt` inside) and
`poppler-<version>.tar.xz`; from 2.20 also `ffmpeg-n9.0.2-36-g6882969ce9-sorgenti.tar.gz` (FFmpeg at commit
6882969ce9, from which BtbN's executable is built). For the system libraries included in the original Windows distributions of TestDisk and
Poppler (Cygwin, Qt, GLib, cairo, libiconv, gettext) and for any other corresponding source not attached, the author
provides it on request, for at least three years from the publication of the package, through the repository's Issues.

## Tools included in the Windows package (`strumenti/`)

| Component | Version | License | Sources / website |
|---|---|---|---|
| The Sleuth Kit | 4.15.0 (win32) | CPL-1.0, IPL-1.0, GPL-2.0 for some parts, see `README.txt` | https://github.com/sleuthkit/sleuthkit |
| libewf (in Sleuth Kit and libewf-python) | see below | LGPL-3.0-or-later | https://github.com/libyal/libewf |
| TestDisk / PhotoRec | 7.2 | GPL-2.0-or-later | https://www.cgsecurity.org/wiki/TestDisk_Download — https://github.com/cgsecurity/testdisk |
| Poppler (pdftotext, pdftoppm) | 26.09.0 (Windows build) | GPL-2.0-or-later / GPL-3.0 | https://poppler.freedesktop.org — https://github.com/oschwartz10612/poppler-windows |
| ExifTool | 13.59 (64-bit, with Strawberry Perl) | Artistic-1.0-Perl OR GPL-1.0-or-later (Strawberry Perl licenses in `exiftool_files/`) | https://exiftool.org |
| bulk_extractor | 2.2.0, built by the author with MinGW-w64 (recipe in `build/windows/COME_RICOSTRUIRE.txt`) | public domain code + LGPL-2.1, LGPL-3.0, GPL-3.0, CPL-1.0, OpenSSL (see `strumenti/bulk_extractor/licenses/`) | https://github.com/simsong/bulk_extractor (tag v2.2.0) |
| 7-Zip (7z.exe, 7z.dll) | 26.01 | LGPL-2.1-or-later + BSD-3-Clause; **unRAR restriction**: the RAR decompression code may not be used to recreate the RAR compression algorithm (see `License.txt`) | https://www.7-zip.org |
| Tesseract OCR | 5.4.0 (UB Mannheim build) with the DLLs it uses (Leptonica, libtiff, libpng, libjpeg, libwebp, OpenJPEG, zlib, zstd, libarchive…) | Apache-2.0; libraries under their own licenses (BSD, MIT, libtiff, zlib, IJG, OpenSSL/Apache-2.0) | https://github.com/tesseract-ocr/tesseract — https://github.com/UB-Mannheim/tesseract |
| tessdata_fast (eng, ita, osd) | — | Apache-2.0 | https://github.com/tesseract-ocr/tessdata_fast |
| FFmpeg (`ffmpeg.exe` only, video previews) | 9.0.2-36-g6882969ce9 (BtbN LGPL build, autobuild-2026-10-27-18-38) | LGPL-3.0-or-later (`strumenti/ffmpeg/LICENSE.txt`); exact source attached to the Release: `ffmpeg-n9.0.2-36-g6882969ce9-sorgenti.tar.gz` | https://ffmpeg.org — https://github.com/BtbN/FFmpeg-Builds |
| Python | 3.12.15 (python-build-standalone, install_only_stripped) | PSF-2.0 (with BSD, MIT, OpenSSL, zlib, Tcl/Tk components) | https://github.com/astral-sh/python-build-standalone |

## Mac package

The app contains Python 3.12 (python-build-standalone), the Python modules listed below, 7-Zip (`7zz`, licenses as
above) the Tesseract data (license in `strumenti/tessdata/LICENSE.txt`) and, from 2.20, whisper.cpp and FFmpeg (see «Audio transcription»). Sleuth Kit, libewf, PhotoRec, Poppler,
ExifTool, Tesseract and bulk_extractor are **not included**: Homebrew installs them on first start from their
projects, under their own licenses.

## Linux package

The archive contains RepertIA's files, 7-Zip 26.01 for Linux x64 (`strumenti/7zip/7zz`, licenses as above, with
`License.txt`), the Tesseract data (`strumenti/tessdata`, Apache-2.0, license in `LICENSE.txt`) and FFmpeg (from 2.20,
only `strumenti/ffmpeg/bin/ffmpeg`, BtbN LGPL build as for Windows, LGPL-3.0-or-later, license in
`strumenti/ffmpeg/LICENSE.txt`, exact source attached to the Release). **Python and the
modules are not included**: the `installa.sh` script downloads them from PyPI on the user's computer, at the versions
listed below (`requirements-linux.txt`, plus `xattr`, MIT). Sleuth Kit, libewf, PhotoRec, Poppler, ExifTool, Tesseract
and bulk_extractor come from the Linux distribution (apt), under their own licenses.

## Python modules included (Mac and Windows; installed by `installa.sh` on Linux)

| Module | Version | License |
|---|---|---|
| plaso | 20260720 | Apache-2.0 |
| dfvfs, dfdatetime, dfwinreg, dtfabric, artifacts, acstore | 20260924, 20260730, 20260411, 20260506, 20260421, 20260411 | Apache-2.0 |
| pytsk3 | 20260715 | Apache-2.0 (includes The Sleuth Kit: CPL/IPL) |
| libyal (libbde, libcaes, libcreg, libesedb, libevt, libevtx, libewf, libfcrypto, libfsapfs, libfsext, libfsfat, libfshfs, libfsntfs, libfsxfs, libfvde, libfwnt, libfwsi, liblnk, libluksde, libmodi, libmsiecf, libolecf, libpff, libphdi, libqcow, libregf, libscca, libsigscan, libsmdev, libsmraw, libvhdi, libvmdk, libvsapm, libvsgpt, libvshadow, libvslvm) -python | 2026xxxx (version in the name of the `*.dist-info` folder) | LGPL-3.0-or-later — https://github.com/libyal |
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

## iLEAPP and ALEAPP (smartphone cases, from 2.20)

Folders `strumenti/ileapp` and `strumenti/aleapp` of the packages, run as separate programs with their libraries in
`strumenti/<name>/site` (on Linux the libraries are installed by `installa.sh`; the readers without a binary package are in
`strumenti/wheels`). Recipe: `build/leapp/prepara_leapp.sh`.

| Component | Version | Licence | Source |
|---|---|---|---|
| iLEAPP (Alexis Brignoni and contributors) | 2026.4.5 | MIT | https://github.com/abrignoni/iLEAPP |
| ALEAPP (Alexis Brignoni and contributors) | 2026.4.4 | MIT | https://github.com/abrignoni/ALEAPP |

Python libraries of iLEAPP/ALEAPP (versions of the Mac and Windows packages; licences declared by the packages, texts in
`site/*.dist-info/`):

| Module | Version | Licence |
|---|---|---|
| astc_decomp_faster | 1.1.5 | zlib/libpng License |
| bcrypt | 5.0.0 | Apache Software License |
| beautifulsoup4 | 4.15.0, 4.8.2 | MIT License |
| bencoding | 0.2.6 | MIT |
| biplist | 1.0.3 | BSD License |
| branca | 0.8.2 | MIT License |
| brotli | 1.2.0 | MIT |
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
| pyasn1 | 0.6.4 | BSD-2-Clause |
| pycparser | 3.12 | BSD-3-Clause |
| pycryptodome | 4.2.0 | BSD-2-Clause AND Unlicense AND MIT |
| pyliblzfse | 0.4.1 | MIT |
| python-dateutil | 3.0.0 | BSD License; Apache Software License |
| pytypedstream | 0.1.0 | GNU Lesser General Public License v3 or later (LGPLv3+) |
| pytz | 2026.5 | MIT License |
| requests | 2.34.2 | Apache Software License |
| simplekml | 1.3.5 | GNU Lesser General Public License v3 or later (LGPLv3+) |
| six | 1.17.0 | MIT License |
| soupsieve | 3.0.4 | MIT |
| sqlcipher3 | 0.6.2 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |
| tzdata | 2026.5 | Apache-2.0 |
| urllib3 | 2.8.0 | MIT |
| wheel | 0.48.0 | MIT |
| XlsxWriter | 3.1.1 | BSD License |
| xmltodict | 1.0.4 | MIT |
| zstd | 1.5.7.2 | BSD |

`pytypedstream` and `simplekml` (LGPL-3.0-or-later) are pure Python: the source code is in the distributed files.

## Audio transcription (from 2.20)

`strumenti/whisper` folder of the packages: the transcription engine, run as a separate program. **The models are not
included**: they are downloaded only with the analyst's consent (window with source and SHA-256) or an already
downloaded file is chosen, and they stay next to the settings (`modelli_trascrizione/`).

| Component | Version | License | Source |
|---|---|---|---|
| whisper.cpp (`whisper-cli` and ggml libraries) – Mac | 1.9.5, built in-house for Apple Silicon with Metal (recipe in `build/mac/COME_RICOSTRUIRE.txt`) | MIT (`strumenti/whisper/LICENSE`) | https://github.com/ggml-org/whisper.cpp (tag v1.9.5) |
| whisper.cpp – Windows | 1.9.5, official binaries `whisper-bin-x64.zip` (release b5454, same commit d1be6fde) | MIT | as above |
| whisper.cpp – Linux | 1.9.5, official binaries `whisper-bin-ubuntu-x64.tar.gz` (release b5454) | MIT | as above |
| Visual C++ libraries (`msvcp140.dll`, `vcruntime140.dll`, `vcruntime140_1.dll`) – Windows | Microsoft redistributables | Microsoft Visual Studio redistributable license | https://learn.microsoft.com/cpp/windows/redistributing-visual-cpp-files |
| FFmpeg – Mac (`ffmpeg` only, audio conversion and video thumbnails) | 9.0.2-36-g6882969ce9, built in-house as a minimal LGPL build (recipe in `build/mac/COME_RICOSTRUIRE.txt`) | LGPL-2.1-or-later (`strumenti/ffmpeg/LICENSE.LGPLv2.1`); exact source attached to the Release: `ffmpeg-n9.0.2-36-g6882969ce9-sorgenti.tar.gz` | https://ffmpeg.org |
| Whisper models (`ggml-base-q5_1.bin`, `ggml-small-q5_1.bin`, `ggml-large-v3-turbo-q5_0.bin`) – not included | `ggerganov/whisper.cpp` repository on Hugging Face, commit 5359861c | MIT (OpenAI Whisper models, whisper.cpp conversion) | https://huggingface.co/ggerganov/whisper.cpp |

## Test data (`RepertIA-collaudo.zip`)

Origin and licenses are also stated in the archive's `LEGGIMI.txt`, with the license texts in `LICENZE/`.

| Data | License | Source |
|---|---|---|
| DFTT (Digital Forensics Tool Testing) images 5, 6, 7, 8, 11 | GPL (as stated by the DFTT project) | https://dftt.sourceforge.net — https://sourceforge.net/projects/dftt/ |
| dfvfs test images (APFS, encrypted APFS, BitLocker To Go) | Apache-2.0 | https://github.com/log2timeline/dfvfs/tree/main/test_data |
| Images built for the test (ext4 in E01, altered E01, FAT USB drive, Mac Data volume) | GPL-3.0-or-later, like RepertIA | this repository |

## Tools used to build the packages (not included)

NSIS (zlib/libpng), python-build-standalone, Homebrew, MinGW-w64. The scripts `build/windows/nsis_x.py` and
`build/windows/nsis_patch.py` (GPL-3.0-or-later) rebuild the installer without NSIS.
