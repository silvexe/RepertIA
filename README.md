# RepertIA

**Analisi forense di copie di dischi e pendrive, con intelligenza artificiale locale e offline.**
*Forensic analysis of disk images with a local, offline AI assistant — Italian or English user interface (English summary below).*

RepertIA analizza copie forensi (E01, raw/dd, dmg) da un'unica interfaccia web locale, su Mac Apple Silicon, Windows o
Linux (sperimentale).
Usa strumenti forensi riconosciuti (The Sleuth Kit, libewf, plaso, PhotoRec, bulk_extractor, ExifTool, libyal) e ne
raccoglie i risultati in un caso consultabile con filtri, timeline e anteprime. Un modello linguistico che gira sul
computer dell'analista (facoltativo) risponde a domande in italiano citando file, offset e inode.
**Nessun dato lascia il computer**: niente cloud, account o telemetria; l'interfaccia ascolta solo su 127.0.0.1.

> **Avvertenza.** RepertIA è un progetto personale, non certificato né validato da un ente terzo e non collegato ad
> alcun ufficio o amministrazione. I risultati vanno confermati con un secondo strumento o sul dato originale prima di
> usarli in atti. Il software è fornito «così com'è», senza alcuna garanzia (vedi [LICENSE](LICENSE)). Le risposte del
> modello linguistico sono spunti investigativi, non conclusioni.

## Cosa fa

| Area | Funzioni |
|---|---|
| File system | NTFS, FAT/exFAT, ext, HFS+, APFS (anche FileVault con chiave); file cancellati, orfani, ADS; spazio non allocato; copie shadow e snapshot APFS |
| Volumi cifrati | Rilevamento di BitLocker, LUKS, FileVault, VeraCrypt (alta entropia); decifratura di BitLocker, LUKS1 e APFS con la chiave (mai salvata) |
| Artefatti Windows | Per ogni installazione (anche Windows.old): account e accessi (SAM e registri eventi), Prefetch, Amcache, UserAssist, ShimCache, BAM, SRUM, LNK e jump list, ShellBags, Cronologia attività, journal NTFS `$UsnJrnl`, eventi (servizi, accensioni, Desktop remoto, Defender, USB), reti, cestino, browser |
| Artefatti macOS | Volume Dati, quarantena, avvio automatico, TCC, iMessage, documenti recenti, Safari, KnowledgeC, Bluetooth, Time Machine |
| Timeline | File system + plaso; date in UTC, ora italiana o fuso del dispositivo (rilevato), FAT/exFAT convertiti correttamente |
| Contenuti | Testo dei documenti con ricerca full-text, OCR (Tesseract), metadati EXIF/GPS, archivi, posta PST/OST/MBOX/EML |
| Recupero | Carving con PhotoRec, tracce bulk_extractor, miniature della cache di Esplora file |
| Anomalie | Estensioni false ed eseguibili mascherati (con verifica dei file cancellati contro i falsi positivi), file e contenitori cifrati |
| Immagini e liste | Hash percettivi (immagini simili), liste di hash NSRL, Project VIC / CAID, cartelle di immagini di riferimento |
| Garanzie | Copia mai modificata, hash dei dati confrontati con quelli di acquisizione, registro delle operazioni a catena di hash, versioni e impronta del programma nel report |
| Report | Report del caso (Markdown, Word, PDF) e report portatile HTML per chi non ha la copia forense |

Interfaccia, report e testi dei casi **in italiano o in inglese** (la lingua di ogni caso si sceglie alla creazione).

Documentazione completa (in italiano): [src/README.md](src/README.md). Metodo, collaudi e limiti noti:
[VALIDAZIONE.md](VALIDAZIONE.md).

## Scaricare e installare

I pacchetti pronti sono nella sezione **Releases**:

| | Mac (Apple Silicon) | Windows 10/11 64 bit | Linux x86_64 (sperimentale) |
|---|---|---|---|
| Pacchetto | `RepertIA-<versione>-Mac.zip` (app con Python, plaso e librerie) | `RepertIA-<versione>-Setup.exe` (senza diritti di amministratore) oppure `RepertIA-<versione>-Windows.zip` portatile | `RepertIA-<versione>-Linux.tar.gz` + `./installa.sh` (Ubuntu 24.04+, Debian 13) |
| Strumenti esterni | installati al primo avvio con Homebrew | inclusi | installati con apt da `installa.sh`, che prepara anche Python, plaso e le librerie |
| Collaudo | `RepertIA-collaudo.zip` + *Collaudo RepertIA.command* | stesso zip, menu Start › RepertIA › Collaudo | stesso zip, `./collaudo.sh` |
| Modello IA (facoltativo) | LM Studio, llama-server o Ollama, sullo stesso computer o in rete interna | come Mac | come Mac |

**Consiglio:** subito dopo l'installazione esegui il collaudo e conserva il rapporto `collaudo_<data>.md`:
dimostra che su quel computer, con quelle versioni, il programma dà i risultati attesi.

### Dai sorgenti

```
git clone https://github.com/silvexe/RepertIA.git
cd RepertIA/src
python3 forense_gui.py          # Python 3.12; servono The Sleuth Kit, libewf e i moduli libyal (vedi src/README.md)
```

Come costruire i pacchetti: [docs/COSTRUZIONE.md](docs/COSTRUZIONE.md).

## Collaudo

`src/forense_collaudo.py` prepara un caso per ogni immagine di prova e confronta i risultati con i valori attesi di
[`collaudo/`](collaudo/): immagini pubbliche con risultati pubblicati da terzi (DFTT) e immagini costruite per il
collaudo. Le immagini sono nell'archivio `RepertIA-collaudo.zip` tra le Releases. Dettagli in
[collaudo/README.md](collaudo/README.md) e [VALIDAZIONE.md](VALIDAZIONE.md).

## Licenza

Copyright (C) 2026 silvexe.

RepertIA è software libero: puoi ridistribuirlo e/o modificarlo secondo i termini della **GNU General Public License**
pubblicata dalla Free Software Foundation, **versione 3 o (a tua scelta) qualsiasi versione successiva**
(SPDX: `GPL-3.0-or-later`). È distribuito nella speranza che sia utile, ma SENZA ALCUNA GARANZIA. Testo completo in
[LICENSE](LICENSE).

I pacchetti delle Releases includono componenti di terze parti con le loro licenze: elenco, versioni e fonti in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

## Come è stato sviluppato

Il codice è stato scritto con l'ausilio di Claude, modello di intelligenza artificiale di Anthropic. Scelte
progettuali, verifiche e collaudi sono dell'autore. Ogni versione è descritta in [CHANGELOG.md](CHANGELOG.md) con
cosa cambia, come è stata provata e cosa non è stato provato.

## Contribuire e segnalare problemi

- Problemi e proposte: sezione **Issues**. **Non allegare mai dati di casi reali** (copie, estratti, schermate con
  nomi o percorsi): usa immagini di prova pubbliche o costruite.
- Contributi: [CONTRIBUTING.md](CONTRIBUTING.md).
- Vulnerabilità: [SECURITY.md](SECURITY.md) (segnalazione privata).

---

## English summary

RepertIA is a desktop forensic analysis tool for disk images (E01, raw/dd, dmg) on Apple Silicon Macs, Windows and
Linux (experimental).
It wraps established open-source forensic tools (The Sleuth Kit, libewf, plaso, PhotoRec, bulk_extractor, ExifTool,
libyal) behind a local web interface and optionally lets an analyst ask questions to a **local** LLM (LM Studio,
llama-server, Ollama) that answers with references to files, offsets and inodes. Nothing leaves the machine.

Highlights: Windows artifacts for every installation on the disk (including Windows.old), NTFS journal, ShellBags,
ShimCache/BAM/SRUM, event logs, thumbcache, deleted-file verification against false positives, perceptual image
hashing, Project VIC / CAID hash sets, APFS/FileVault, hash-chained audit log, acquisition hash verification, a
built-in test suite based on public reference images (DFTT) and a validation document.

The user interface, the case texts (artifacts, reports, portable report) and the installer are available in Italian and English: each case keeps the language chosen when it is created. The full manual and the validation document are in Italian. It is a personal project, **not certified or independently
validated**: confirm results with a second tool before relying on them. Licensed under **GPL-3.0-or-later**.
