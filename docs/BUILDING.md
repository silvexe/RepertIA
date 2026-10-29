# Building the packages

*Translation of [COSTRUZIONE.md](COSTRUZIONE.md); the Italian text prevails.*

The packages are built from the sources in `src/` and the files in `build/`. Third-party components (Python, plaso,
libraries, tools) are **not in the repository**: they are downloaded from the original projects, at the versions given
in [THIRD_PARTY_LICENSES.en.md](../THIRD_PARTY_LICENSES.en.md).

## Before every version

1. Version number in: `src/forense_agent.py` (`APP_VERSION`), `build/windows/repertia.nsi` (`VER`),
   `build/windows/LEGGIMI.txt`, `build/mac/LEGGIMI.txt` and `build/linux/LEGGIMI.txt` (first line), the README_EN.txt
   files, `build/mac/Info.plist`, `src/README.md` (heading and package names), entry in `CHANGELOG.md`; the English
   translations (`README.md`, `CHANGELOG.en.md`, `VALIDATION.md`, `docs/MANUAL.md`) aligned with the Italian originals.
2. `python3 -m py_compile src/*.py` (Python 3.12) and a check of the JavaScript of the two HTML pages (extract
   `<script>` and run `node --check`). `python3 tools/lingua_controlla.py`: no text without a translation in
   `src/lingua_en.json` and no mismatched placeholders.
3. Acceptance test on Mac, Windows and Linux, in Italian and in English (`--lingua en`; see `collaudo/README.en.md`):
   all checks passed.
4. `python3 tools/controlla_pubblicazione.py . --parole <private list>`: no sensitive data.
5. **The packages contain `VALIDAZIONE.md`, `THIRD_PARTY_LICENSES.md` and the manual**: after any change to these
   documents the packages must be rebuilt, even if the program does not change.
6. "Download" / "Scarica" table at the top of `README.md` and `README.it.md`: update the version number in the direct
   links to the Release files (`releases/download/v<version>/RepertIA-<version>-…`), the same as in the Release text.

## iLEAPP and ALEAPP (from 2.20)

Smartphone cases use iLEAPP and ALEAPP, included in the packages in `strumenti/ileapp` and `strumenti/aleapp`, each with its
libraries in `site/` (separate from those of RepertIA and plaso). On the Mac, with the app's Python:

    build/leapp/prepara_leapp.sh RepertIA.app/Contents/Resources/python/bin/python3 <work folder>

produces `strum_mac` (arm64 libraries), `strum_win` (win_amd64 libraries for Python 3.12, downloaded from PyPI) and
`strum_linux` (only the programs, the `requirements-repertia.txt` lists and the `wheels` folder: the libraries are installed
by `installa.sh`). The versions are fixed in the script and in the `build/leapp/requirements-*.txt` lists. The smartphone
acceptance test (`atteso_smartphone.json`) also checks the rows imported by iLEAPP and ALEAPP.

## Mac (Apple Silicon)

Structure and components in [build/mac/COME_RICOSTRUIRE.txt](../build/mac/COME_RICOSTRUIRE.txt). In short:
`RepertIA.app/Contents/` with `Info.plist`, `MacOS/RepertIA` (= `RepertIA_eseguibile`), `Resources/avvia.command`,
`Resources/repertia.icns`, `Resources/RepertIA/` (the files of `src/`, including `forense_lingua.py` and
`lingua_en.json`), `Resources/python/` (python-build-standalone 3.12 aarch64 with plaso and the libyal modules),
`Resources/strumenti/` (7-Zip `7zz`, tessdata with `LICENSE.txt`); next to the app `Aggiorna strumenti.command`,
`Collaudo RepertIA.command`, `LEGGIMI.txt`, `README_EN.txt`, `VALIDAZIONE.md`.

```
zip -qry -X RepertIA-<version>-Mac.zip RepertIA      # -y keeps Python's symbolic links
```

For a new version it is enough to extract the previous zip, replace the files in `Resources/RepertIA/`, update
`Info.plist` and `LEGGIMI.txt` and compress again.

## Linux

Structure in [build/linux/COME_RICOSTRUIRE.txt](../build/linux/COME_RICOSTRUIRE.txt): a `RepertIA/` folder with the
scripts from `build/linux/` (`installa.sh`, `RepertIA.sh`, `collaudo.sh`, `aggiorna-strumenti.sh`,
`requirements-linux.txt`, `repertia.png`, `LEGGIMI.txt`, `README_EN.txt`), `LICENSE`, `THIRD_PARTY_LICENSES.md`,
`VALIDAZIONE.md`, `RepertIA/` (the files of `src/`), `strumenti/7zip/7zz` (7z2601-linux-x64.tar.xz) and
`strumenti/tessdata` (as in the Mac package, with `LICENSE.txt`). Python, plaso and the libraries are installed on the
target computer by `installa.sh`.

```
tar --owner=0 --group=0 -czf RepertIA-<version>-Linux.tar.gz RepertIA     # scripts and 7zz executable
```

## Windows

Installation layout and component recipes (Python, plaso, Sleuth Kit, ExifTool, Poppler, PhotoRec, 7-Zip, Tesseract,
bulk_extractor built with MinGW-w64) in [build/windows/COME_RICOSTRUIRE.txt](../build/windows/COME_RICOSTRUIRE.txt).
The installer's `app\` folder contains `RepertIA.bat`, `Aggiorna strumenti.bat`, `Collaudo.bat`, `LEGGIMI.txt`,
`README_EN.txt`, `repertia.ico`, `RepertIA\` (the files of `src/`, including `forense_lingua.py` and `lingua_en.json`),
`python\`, `strumenti\`. Also put `LICENSE`, `THIRD_PARTY_LICENSES.md` and `VALIDAZIONE.md` in `app\`:
`File /r app\*.*` includes them in the installer. The installer is bilingual: `LEGGIMI.txt` and `README_EN.txt` must be
next to `repertia.nsi` ("License" page in Italian or English). The Windows `LEGGIMI.txt` ends with the full text of the
GPL (the installer's "License" page).

**Installer** (with NSIS):

```
LC_ALL=en_US.UTF-8 makensis -DVER=<version> repertia.nsi        # -> RepertIA-<version>-Setup.exe
```

On macOS (Homebrew's makensis) `LC_ALL` must be set: with a shell without a locale (empty `LANG`) makensis 3.13 stops
immediately with `std::bad_alloc`. The `app\` folder is obtained by extracting the portable zip of the same version and
renaming `RepertIA\` to `app\`.

**Portable version:** the zip of the `app\` folder renamed `RepertIA\` (started with `RepertIA.bat`).

### Without NSIS: updating an existing installer

`build/windows/nsis_x.py` extracts an NSIS 3 installer (Unicode, solid LZMA) without 7-Zip;
`build/windows/nsis_patch.py` creates a new one replacing some files:

```
python3 nsis_patch.py RepertIA-<old>-Setup.exe RepertIA-<new>-Setup.exe <old> <new> \
    RepertIA/forense_agent.py=src/forense_agent.py  RepertIA/README.md=src/README.md  LEGGIMI.txt=build/windows/LEGGIMI.txt ...
```

Limitations: it can only **replace** files that are already present (not add new ones); the two version strings must
have the same number of characters (e.g. 2.17.2 → 2.18.0); the executable's version resource does not change (changing
it would break the uninstaller's CRC). The script recomputes the NSIS CRC (from byte 512) and the data offsets. Always
check the result: `python3 nsis_x.py <new>.exe test/` and compare with the expected folder.

## Publishing a version

1. Acceptance test on Mac, Windows and Linux and data check: `python3 tools/controlla_pubblicazione.py .` (with
   `--parole` and a private list, never in the repository) must report no sensitive data.
2. `git commit -s`, `git tag v<version>`, `git push origin main v<version>`.
3. Release from the tag with: the Mac, Windows and Linux packages, `RepertIA-collaudo.zip` (with `LEGGIMI.txt` and
   `LICENZE/`), the source archives of the GPL/LGPL components included in the packages (see
   THIRD_PARTY_LICENSES.en.md) and `SHA256SUMS.txt`
   (`shasum -a 256 *.zip *.exe *.tar.gz *.tar *.tar.xz > SHA256SUMS.txt`). GitHub lists the assets alphabetically: the
   intended order is given with a table of links in the Release text.
4. In the Release text: what's new (from the CHANGELOG), what was not tested, a reminder to run the acceptance test.
