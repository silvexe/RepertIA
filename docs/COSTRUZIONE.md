# Costruire i pacchetti

I pacchetti si costruiscono partendo dai sorgenti di `src/` e dai file di `build/`. I componenti di terze parti
(Python, plaso, librerie, strumenti) **non sono nel repository**: si scaricano dai progetti originali, alle versioni
indicate in [THIRD_PARTY_LICENSES.md](../THIRD_PARTY_LICENSES.md).

## Prima di ogni versione

1. Numero di versione in: `src/forense_agent.py` (`APP_VERSION`), `build/windows/repertia.nsi` (`VER`),
   `build/windows/LEGGIMI.txt`, `build/mac/LEGGIMI.txt` e `build/linux/LEGGIMI.txt` (prima riga), i README_EN.txt, `build/mac/Info.plist`, `src/README.md`
   (intestazione e nomi dei pacchetti), voce in `CHANGELOG.md`.
2. `python3 -m py_compile src/*.py` (Python 3.12) e controllo del JavaScript dei due HTML
   (estrarre `<script>` e `node --check`). `python3 tools/lingua_controlla.py`: nessun testo senza traduzione in
   `src/lingua_en.json` e nessun segnaposto diverso.
3. Collaudo su Mac, Windows e Linux, in italiano e in inglese (`--lingua en`; vedi `collaudo/README.md`): tutti i controlli superati.
4. `python3 tools/controlla_pubblicazione.py . --parole <elenco privato>`: nessun dato sensibile.

## Mac (Apple Silicon)

Struttura e componenti in [build/mac/COME_RICOSTRUIRE.txt](../build/mac/COME_RICOSTRUIRE.txt). In breve:
`RepertIA.app/Contents/` con `Info.plist`, `MacOS/RepertIA` (= `RepertIA_eseguibile`), `Resources/avvia.command`,
`Resources/repertia.icns`, `Resources/RepertIA/` (i file di `src/`, compresi `forense_lingua.py` e `lingua_en.json`), `Resources/python/` (python-build-standalone
3.12 aarch64 con plaso e i moduli libyal), `Resources/strumenti/` (7-Zip `7zz`, tessdata); accanto all'app
`Aggiorna strumenti.command`, `Collaudo RepertIA.command`, `LEGGIMI.txt`, `README_EN.txt`, `VALIDAZIONE.md`.

```
zip -qry -X RepertIA-<versione>-Mac.zip RepertIA      # -y conserva i link simbolici di Python
```

Per una nuova versione basta estrarre lo zip precedente, sostituire i file di `Resources/RepertIA/`, aggiornare
`Info.plist` e `LEGGIMI.txt` e ricomprimere.

## Linux

Struttura in [build/linux/COME_RICOSTRUIRE.txt](../build/linux/COME_RICOSTRUIRE.txt): cartella `RepertIA/` con gli script
di `build/linux/` (`installa.sh`, `RepertIA.sh`, `collaudo.sh`, `aggiorna-strumenti.sh`, `requirements-linux.txt`,
`repertia.png`, `LEGGIMI.txt`, `README_EN.txt`), `LICENSE`, `THIRD_PARTY_LICENSES.md`, `VALIDAZIONE.md`, `RepertIA/`
(i file di `src/`), `strumenti/7zip/7zz` (7z2601-linux-x64.tar.xz) e `strumenti/tessdata` (come nel pacchetto Mac).
Python, plaso e le librerie si installano sul computer di destinazione con `installa.sh`.

```
tar --owner=0 --group=0 -czf RepertIA-<versione>-Linux.tar.gz RepertIA     # script e 7zz eseguibili
```

## Windows

Struttura dell'installazione e ricette dei componenti (Python, plaso, Sleuth Kit, ExifTool, Poppler, PhotoRec,
7-Zip, Tesseract, bulk_extractor compilato con MinGW-w64) in
[build/windows/COME_RICOSTRUIRE.txt](../build/windows/COME_RICOSTRUIRE.txt). La cartella `app\` dell'installer
contiene `RepertIA.bat`, `Aggiorna strumenti.bat`, `Collaudo.bat`, `LEGGIMI.txt`, `README_EN.txt`, `repertia.ico`, `RepertIA\`
(i file di `src/`, compresi `forense_lingua.py` e `lingua_en.json`), `python\`, `strumenti\`. Mettere in `app\` anche `LICENSE`, `THIRD_PARTY_LICENSES.md` e `VALIDAZIONE.md`: `File /r app\*.*` li
include nell'installer. L'installer è bilingue: accanto a `repertia.nsi` servono `LEGGIMI.txt` e `README_EN.txt`
(pagina «Licenza» in italiano o in inglese). Il `LEGGIMI.txt` di Windows contiene in fondo il testo completo della GPL (pagina «Licenza»
dell'installer).

**Installer** (con NSIS):

```
LC_ALL=en_US.UTF-8 makensis -DVER=<versione> repertia.nsi        # -> RepertIA-<versione>-Setup.exe
```

Su macOS (makensis di Homebrew) `LC_ALL` va impostato: con una shell senza lingua (`LANG` vuoto) makensis 3.13 si interrompe subito con `std::bad_alloc`. La cartella `app\` si ottiene estraendo lo zip portatile della stessa versione e rinominando `RepertIA\` in `app\`.

**Versione portatile:** lo zip della cartella `app\` rinominata `RepertIA\` (si avvia con `RepertIA.bat`).

### Senza NSIS: aggiornare un installer esistente

`build/windows/nsis_x.py` estrae un installer NSIS 3 (Unicode, LZMA solido) senza 7-Zip;
`build/windows/nsis_patch.py` ne crea uno nuovo sostituendo alcuni file:

```
python3 nsis_patch.py RepertIA-<vecchia>-Setup.exe RepertIA-<nuova>-Setup.exe <vecchia> <nuova> \
    RepertIA/forense_agent.py=src/forense_agent.py  RepertIA/README.md=src/README.md  LEGGIMI.txt=build/windows/LEGGIMI.txt ...
```

Limiti: può solo **sostituire** file già presenti (non aggiungerne); le due versioni devono avere lo stesso numero di
caratteri (es. 2.17.2 → 2.18.0); la risorsa di versione dell'eseguibile non cambia (cambiarla romperebbe il CRC del
disinstallatore). Lo script ricalcola il CRC di NSIS (dal byte 512) e gli offset dei dati. Verifica sempre il
risultato: `python3 nsis_x.py <nuovo>.exe prova/` e confronto con la cartella attesa.

## Pubblicare una versione

1. Collaudo su Mac, Windows e Linux e controllo dei dati: `python3 tools/controlla_pubblicazione.py .` (con `--parole` e un
   elenco privato, mai nel repository) deve dire «nessun dato sensibile».
2. `git commit -s`, `git tag v<versione>`, `git push origin main v<versione>`.
3. Release dal tag con: i pacchetti Mac, Windows e Linux, `RepertIA-collaudo.zip`, gli archivi dei sorgenti dei componenti
   GPL/LGPL inclusi nei pacchetti Windows (vedi THIRD_PARTY_LICENSES.md) e `SHA256SUMS.txt`
   (`shasum -a 256 *.zip *.exe > SHA256SUMS.txt`).
4. Nel testo della Release: le novità (dal CHANGELOG), cosa non è stato provato, il richiamo al collaudo.
