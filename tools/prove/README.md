# Script delle prove su dati di riferimento pubblici

*English below.*

Gli script con cui sono state misurate le prove descritte in [docs/prove](../../docs/prove/). Leggono soltanto i casi
preparati da RepertIA e i dati pubblici di riferimento: non modificano nulla. Servono Python 3.10 o successivo e, per gli
script che leggono il contenuto dei file, i sorgenti di RepertIA in `src/` (si trovano da soli; per usarne altri:
variabile `REPERTIA_SRC`) con Sleuth Kit nel `PATH`.

Le immagini e i documenti di riferimento non sono nel repository: si scaricano dai siti di chi li ha preparati (link
nelle pagine delle prove).

## NIST CFTT «Deleted File Recovery» (90 immagini)

1. Preparare un caso per ogni immagine:
   `forense_agent.py prepara --image dfr-NN-fs.dd --case <casi>/dfr-NN-fs --no-indice --fuso America/New_York`
2. `valida_nist_dfr.py <cartella delle immagini con setup.txt> <casi>`: confronta ogni file con il documento NIST che
   descrive le immagini (`setup.txt` è il testo di `setup-july-10-2012.pdf`, estratto con `pdftotext -layout`).
   Le immagini servono ancora: il contenuto dei cancellati si rilegge da lì.
3. `riepilogo_nist_dfr.py <cartella degli esiti>`: tabella riassuntiva.
4. Confronto con i rapporti pubblicati da DHS: `cftt_metriche_dfr.py <casi> <caso…>` e `cftt_attivi_dfr.py <casi>`
   misurano RepertIA con le colonne dei rapporti; `confronto_cftt_dfr.py <testi dei rapporti> <metriche.jsonl> <uscita.md>`
   mette i numeri accanto.

## NIST CFTT «Graphic File Carving» (2014 e 2023)

- Serie 2014: `valuta_carving_nist.py <graphic-src> <casi> [uscita.json]`, poi
  `confronto_cftt_carving.py <uscita.json> <uscita.md>`.
- Serie 2023: `valuta_carving_2023.py <source> <casi> [uscita.json]`; `rapporti_carving_2023.py <testi dei rapporti>
  <uscita.json>` legge i rapporti 2024-2025.
- Un file conta come recuperato solo se è identico byte per byte all'originale.

## NIST CFReDS «Data Leakage»

1. `scarica_nist_leakage.py <cartella>`: scarica le immagini (circa 8 GB) e controlla gli SHA-1 pubblicati da NIST.
2. Preparare i casi:
   - PC: `forense_agent.py prepara --image <cartella>/cfreds_2015_data_leakage_pc.E01 --case <casi>/pc --estese --vss --no-indice`
   - chiavetta RM#2: `forense_agent.py prepara --image "<cartella>/cfreds_2015_data_leakage_rm#2.E01" --case <casi>/rm2 --estese`
   - CD-R RM#3: dall'interfaccia, **Sorgente logica**, caso `<casi>/rm3_win`.
3. `valida_nist_leakage.py <casi> [nome del caso del PC]`: 56 controlli sulle risposte ufficiali NIST.

## Smartphone di Josh Hickman (Android 14, iOS 17)

1. Creare un caso per telefono: **Nuova analisi → Smartphone**, file `EXTRACTION_FFS.zip`, con SHA-256 e ALEAPP/iLEAPP
   (oppure `forense_mobile.py prepara --image EXTRACTION_FFS.zip --case <caso> --leapp`).
2. `hickman_confronto.py <caso> hickman_riferimenti_android14 <InstalledAppsList.txt> <uscita.json>`, e per l'iPhone
   `hickman_confronto.py <caso> hickman_riferimenti_ios17 - <uscita.json>`.
3. `hickman_cancellati.py <cartella dei database> <uscita.json>`: prova il recupero dei record cancellati di RepertIA
   sui database originali di Messaggi, WhatsApp e Telegram (estratti dallo zip in `bugle/`, `mmssms/`, `whatsapp/`,
   `telegram/`).

I riferimenti (`hickman_riferimenti_*.py`) sono presi solo dai documenti distribuiti con le immagini. Per non
ripubblicare identificativi, i numeri di telefono sono ridotti alle ultime 4 cifre e gli indirizzi Bluetooth agli ultimi
3 byte: il confronto li cerca come fine del numero e come parte dell'indirizzo.

---

# Scripts of the tests against public reference data

The scripts used to measure the tests described in [docs/prove](../../docs/prove/). They only read the cases prepared by
RepertIA and the public reference data: they change nothing. They need Python 3.10 or later and, for the scripts that
read file content, the RepertIA sources in `src/` (found automatically; `REPERTIA_SRC` to use others) with Sleuth Kit in
the `PATH`. Comments and messages are in Italian.

Images and reference documents are not in the repository: download them from their authors' sites (links in the test
pages).

- **NIST CFTT "Deleted File Recovery":** prepare one case per image
  (`forense_agent.py prepara --image dfr-NN-fs.dd --case <cases>/dfr-NN-fs --no-indice --fuso America/New_York`), then
  `valida_nist_dfr.py`, `riepilogo_nist_dfr.py`; comparison with the DHS reports: `cftt_metriche_dfr.py`,
  `cftt_attivi_dfr.py`, `confronto_cftt_dfr.py`.
- **NIST CFTT "Graphic File Carving":** `valuta_carving_nist.py` and `confronto_cftt_carving.py` (2014 set);
  `valuta_carving_2023.py` and `rapporti_carving_2023.py` (2023 set). A file counts as recovered only if it is
  byte-for-byte identical to the original.
- **NIST CFReDS "Data Leakage":** `scarica_nist_leakage.py` (download and SHA-1 check, about 8 GB), prepare the cases as
  above (PC with `--estese --vss --no-indice`, RM#2 with `--estese`, the RM#3 CD-R as a logical source), then
  `valida_nist_leakage.py <cases>` (56 checks against NIST's official answers).
- **Josh Hickman's smartphones:** create one case per phone (New analysis → Smartphone, `EXTRACTION_FFS.zip`, SHA-256
  and ALEAPP/iLEAPP), then `hickman_confronto.py` with `hickman_riferimenti_android14` or `hickman_riferimenti_ios17`,
  and `hickman_cancellati.py` on the original databases. Phone numbers are reduced to their last 4 digits and Bluetooth
  addresses to their last 3 bytes, so as not to republish identifiers.
