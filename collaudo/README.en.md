# Acceptance test (collaudo)

*Translation of [README.md](README.md); the Italian text prevails.*

`atteso.json` (images built for the test) and `atteso_dftt.json` (public DFTT images with results published by third
parties) contain the expected values. The images are in the **RepertIA-collaudo.zip** archive in the Releases (they are
not in the repository: they are large and some have their own licenses, see THIRD_PARTY_LICENSES.en.md and the
`LEGGIMI.txt` file inside the archive).

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
