# Acceptance test (collaudo)

*Translation of [README.md](README.md); the Italian text prevails.*

`atteso.json` (images built for the test) and `atteso_dftt.json` (public DFTT images with results published by third
parties) contain the expected values. The images are in the **RepertIA-collaudo.zip** archive in the Releases (they are
not in the repository: they are large and some have their own licenses, see THIRD_PARTY_LICENSES.en.md and the
`LEGGIMI.txt` file inside the archive).

## Smartphones (from 2.20)

`atteso_smartphone.json` and the `smartphone/` folder of the zip: two extractions built with `tools/collaudo_mobile.py`
from the excerpts of the public images iOS 15 (Josh Hickman) and Android 15 («anne_a15») used in the iLEAPP and ALEAPP tests
(MIT licence), plus an Android WhatsApp and a Google Photos built with known content (attachments found by path, by hash,
thumbnail only and missing; cited files found by path, by name and size and missing). The expected chat values are the
results published by iLEAPP and ALEAPP; the iLEAPP/ALEAPP checks need the tools included in the package.
`tools/collaudo_mobile.py --aggiorna-android <folder>` rebuilds WhatsApp and Google Photos inside the existing Android
extraction without downloading the ALEAPP test data again. `--portachiavi <folder> <iLEAPP folder>` adds the minimal iOS
extraction `ios_portachiavi.zip` and `portachiavi_finto.plist`: **fake** keychains (no real data), an encrypted one in the
Cellebrite format inside the extraction and a decrypted one to pass to iLEAPP with `--keychain`.
`--file-citati <folder>` adds the **fake** iOS extraction `ios_file_citati.zip` (IMG_0059.PNG in the same locations as in
Hickman's public iOS 13.4.1 case, two different IMG_0100.JPG in different folders, two `verbale.pdf` with the same final
path) with the rows to test in the iLEAPP style and the expected cited-file results: folder + name = a single file found
with certainty, name only with two namesakes = probable with two candidates, hash verified, copies, missing.
`--sysdiagnose <folder>` adds two archives in the form of an iOS **sysdiagnose** built with the public excerpts of the
iLEAPP v2026.4.5 tests (downloaded from GitHub and checked with SHA-256: real `ps.txt` of iOS 16, BatteryUI and
ManagedSettings of iOS 26.6 with the identifiers replaced by the authors; they are not complete sysdiagnoses) and test 25:
SHA-256 in the log, no copy in the case, date and device from the name, rows in the «Sysdiagnose» group, processes of
`ps.txt` counted without iLEAPP. Every test also checks the **later verification of the log** (`forense_registro.py`):
chain intact and final hash of the report found; on the disk test with tampering a modified line, a line removed in the
middle, lines removed at the end without and with the final hash; on the tests with exported chats a modified exported file.

## Running it

1. Extract `RepertIA-collaudo.zip` to the Desktop (this creates the `RepertIA-collaudo` folder).
2. Mac: double-click *Collaudo RepertIA.command* next to the app. Windows: Start menu › RepertIA › Collaudo. Linux:
   `./collaudo.sh` in the RepertIA folder.
   From source: `python3 src/forense_collaudo.py <RepertIA-collaudo folder> <output folder>`.
3. The `collaudo_<date>.md` report lists the result of each check, the tool versions and the program fingerprint. Keep
   it; **do not publish** reports made on your computer if they contain personal paths.

## Adding tests

For a public image with known results (e.g. NIST CFReDS) create `atteso_<name>.json` following `atteso_dftt.json`, with
the values transcribed from the source and a reference to the page. Expected values must come from the source, not
from RepertIA.

## Language

The test prepares the test cases in the language set in RepertIA's settings; from the terminal choose it with
`--lingua it` or `--lingua en` (`python3 src/forense_collaudo.py <folder> --lingua en`). The expected values stay in
Italian: in English the test also recognises the translated form of the artifact titles.

## Navigation test (outside the acceptance test)

The interface tests in the browser are not part of the acceptance test (they need Playwright, which is not in the
packages). From a copy of the sources, with `pip install playwright` and `python -m playwright install chromium`:
`python3 tools/prova_navigazione.py --casi <folder with copies of the acceptance test cases> [--browser webkit] [--lingua en]`.
It tests Search, Back/Forward and breadcrumbs (see VALIDATION.md, paragraph (7)); the searches made stay in the cases:
use copies, never real cases.
