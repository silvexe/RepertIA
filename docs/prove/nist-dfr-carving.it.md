# RepertIA alla prova dei test pubblici di NIST

*RepertIA 3.0.2 — novembre 2026 · English: [nist-dfr-carving.md](nist-dfr-carving.md) · Altre prove: [indice](README.md)*

## In breve

RepertIA è uno strumento di analisi forense **gratuito e open source**. Lo abbiamo messo alla prova sulle stesse
immagini disco che il **NIST** (National Institute of Standards and Technology, l'ente americano per gli standard) usa
per provare gli strumenti forensi, e abbiamo messo i suoi risultati accanto al **miglior risultato pubblicato** nei
rapporti ufficiali del programma **CFTT** (Computer Forensics Tool Testing), diffusi dal Dipartimento della Sicurezza
Interna degli Stati Uniti (DHS). I rapporti riguardano strumenti commerciali e open source molto diffusi: i nomi e i
dettagli di ogni strumento sono nei rapporti stessi, che chiunque può consultare (fonti in fondo).

Il risultato, in tre righe:

- **Recupero dei file cancellati:** su FAT, exFAT, NTFS ed ext RepertIA recupera interi e corretti **tanti file quanti
  il miglior risultato pubblicato, o di più**. Su exFAT recupera **tutti** i file, più del miglior risultato pubblicato.
- **Ricostruzione di immagini dallo spazio libero (carving):** sui file interi RepertIA **raggiunge il miglior risultato
  pubblicato**, anche quando i file non cominciano all'inizio di un settore.
- **Onestà dei risultati:** quando un file cancellato contiene ormai dati di un altro file, RepertIA **lo dice, in tutti
  i casi**.

Tutto quello che serve per rifare le prove è pubblico: le immagini di NIST, i rapporti DHS, gli script di misura
([tools/prove](../../tools/prove/)).

## Perché questa prova conta

Uno strumento forense deve restituire **esattamente** ciò che c'è sul disco: un file sbagliato in un'indagine può
portare a conclusioni sbagliate. NIST ha costruito immagini disco in cui ogni settore di ogni file di prova porta scritto
il nome del file a cui appartiene. Così si può verificare, settore per settore, se uno strumento restituisce il file
giusto, un file incompleto o un miscuglio di file diversi.

**Come leggere le tabelle.** Per ogni prova: il numero di RepertIA; il **miglior risultato pubblicato da NIST** tra gli
strumenti provati, con il tipo di strumento che l'ha ottenuto (commerciale o open source); e chi è **il migliore in
questa prova**. Il dettaglio per strumento è nei rapporti indicati in fondo.

## 1. Recupero dei file cancellati

**Cosa si prova.** 90 immagini NIST «Deleted File Recovery» (DFR-01…17): file cancellati su FAT12/16/32, exFAT, NTFS,
ext2/3/4 e HFS+, in casi semplici e in casi difficili (file frammentati, file in parte sovrascritti da altri, cartelle
cancellate, nomi in cinese, arabo, russo…). Sei strumenti provati da NIST (rapporti 2014-2015).

**Il numero che conta: file restituiti completi e giusti** (la colonna «Full» dei rapporti NIST).

| Prova | File system | **RepertIA 3.0.2** | Miglior risultato pubblicato da NIST | In questa prova il migliore è |
|---|---|---|---|---|
| Senza sovrascritture | FAT | **807** | 807 (commerciale e open source) | pari: RepertIA, commerciale e open source |
| | exFAT | **273 su 273** | 270 (commerciale) | **RepertIA** |
| | NTFS | **273 su 273** | 273 (commerciale e open source) | pari: RepertIA, commerciale e open source |
| | ext | **273** | 273 (commerciale e open source) | pari: RepertIA, commerciale e open source |
| Con sovrascritture | FAT | **885** | 885 (commerciale e open source) | pari: RepertIA, commerciale e open source |
| | exFAT | **376 su 376** | 370 (commerciale) | **RepertIA** |
| | NTFS | **374** | 374 (commerciale e open source) | pari: RepertIA, commerciale e open source |
| | ext | **373** | 372 (commerciale e open source) | **RepertIA** |

*Su FAT un file frammentato non può tornare intatto con nessuno strumento (alla cancellazione FAT azzera la catena dei
cluster); su ext3/ext4 il sistema azzera i puntatori ai dati, quindi nessuno strumento recupera il contenuto dai
metadati. Per questo su FAT ed ext i numeri restano sotto il totale per tutti.*

**Cosa dice la tabella.** RepertIA **raggiunge o supera il miglior risultato pubblicato su tutti e quattro i file
system**. Su exFAT recupera tutti i file: quando un file cancellato è frammentato, RepertIA segue la catena di cluster
rimasta nella tabella FAT invece di leggere i cluster di seguito.

**Trasparenza.** Quando un file cancellato contiene ormai dati di un file attivo (perché quello spazio è stato riusato),
RepertIA lo segnala nell'interfaccia e nei report: «CANCELLATO · INODE RIASSEGNATO» o «CANCELLATO · BLOCCHI RIUSATI».
Sulle immagini NIST **tutti** questi casi sono dichiarati (FAT 40 su 40, exFAT 11 su 11, NTFS 24 su 24, ext 330 su
330). Nei rapporti, uno solo degli strumenti provati ne dichiara una parte.

**Le altre voci dei rapporti.**

| Voce | **RepertIA 3.0.2** | Miglior risultato pubblicato da NIST | In questa prova il migliore è |
|---|---|---|---|
| File e cartelle attivi (DFR-16, DFR-17) | **tutti elencati** su tutti i file system | tutti elencati (commerciale) | pari: RepertIA e commerciale |
| Date di creazione, modifica, accesso | **uguali alla tabella NIST** su NTFS, FAT, exFAT ed ext2 | uguali (commerciale) | pari: RepertIA e commerciale |
| Nomi non latini (cinese, giapponese, arabo, russo…) | **intatti** su FAT, exFAT, NTFS ed ext | intatti (commerciale) | pari: RepertIA e commerciale |
| Cestino svuotato, NTFS compresso, file dentro la MFT | **recuperati** | recuperati (commerciale e open source) | pari: RepertIA, commerciale e open source |
| File cancellati con dati di altri file dichiarati | **tutti** (405 su 405) | una parte (commerciale) | **RepertIA** |

**Verifica complessiva.** Oltre al confronto con i rapporti, abbiamo controllato ogni file di ogni immagine contro il
documento NIST che descrive come sono state costruite: **835 verifiche, nessuna aperta**. 643 danno il risultato atteso;
179 sono limiti noti dei file system, spiegati (come i due sopra); in 13 casi l'immagine mostra una situazione
diversa da quella descritta nel documento NIST (per esempio un file indicato come intatto che nell'immagine risulta in
parte sovrascritto da operazioni successive).

## 2. Ricostruzione di immagini dallo spazio libero (carving)

**Cosa si prova.** Quando l'indice del file system non c'è più, un file si può ancora ricostruire riconoscendone il
contenuto (si chiama «carving»). NIST ha preparato due serie di immagini con foto e grafica (JPG, PNG, GIF, BMP, TIFF,
HEIC) disposte in modi via via più difficili: una del 2014 (nove strumenti provati, rapporti 2014-2015) e una del 2023
(tredici strumenti provati, rapporti 2024-2025).

**Come abbiamo misurato.** Per RepertIA abbiamo usato un metro **più severo** di quello dei rapporti: un file conta come
recuperato solo se è **identico byte per byte** all'originale. I rapporti NIST invece valutano visivamente se l'immagine
recuperata è completa.

Serie 2014: file recuperati completi.

| Prova | File | **RepertIA 3.0.2** | Miglior risultato pubblicato da NIST | In questa prova il migliore è |
|---|---|---|---|---|
| Contigui | 47 | **47** | 47 (commerciale e open source) | pari: RepertIA, commerciale e open source |
| Contigui con altri dati in mezzo | 47 | **47** | 47 (commerciale e open source) | pari: RepertIA, commerciale e open source |
| Non allineati ai settori | 47 | **47** | 47 (commerciale) | pari: RepertIA e commerciale |
| Frammentati in ordine | 47 | **17** | 25 (commerciale) | strumento commerciale |
| Incompleti | 45 | **13** | 16 (commerciale e open source) | strumenti commerciale e open source |
| Frammentati fuori ordine | 41 | **6** | 16 (commerciale) | strumento commerciale |
| Intrecciati a coppie | 23 | **13** | 13 (commerciale e open source) | pari: RepertIA, commerciale e open source |

Serie 2023: file completi, miniature EXIF dei JPG comprese (39 possibili per disposizione).

| Disposizione | **RepertIA 3.0.2** | Miglior risultato pubblicato da NIST | In questa prova il migliore è |
|---|---|---|---|
| Contigui | **39 su 39** | 41* (commerciale); 39 a parità di conteggio (open source) | pari: RepertIA e open source* |
| Non allineati ai settori | **39 su 39** | 39* (commerciale); 36 a parità di conteggio (commerciale) | **RepertIA*** |
| Frammentati | **3** | 7* (commerciale); 3 a parità di conteggio (commerciale e open source) | pari: RepertIA, commerciale e open source* |

*\* Lo strumento con il miglior risultato pubblicato conta anche le 4 miniature contenute nei file HEIC, che il
conteggio di RepertIA non include. Contando allo stesso modo, il miglior risultato pubblicato è 39 per i contigui
(open source), 36 per i non allineati (commerciale) e 3 per i frammentati (commerciale e open source, pari): RepertIA
li raggiunge o li supera tutti e tre.*

**Falsi positivi** (file «recuperati» che non sono nessuno degli originali): **zero** su tutte le 26 immagini.

**Cosa dicono le tabelle.**

- Sui file interi, anche quando non cominciano all'inizio di un settore, RepertIA recupera **tutto**: raggiunge il
  miglior risultato pubblicato.
- Sui file **frammentati** della serie 2014 RepertIA è sotto il miglior risultato pubblicato (17 contro 25, 6 contro
  16); sulla serie 2023 lo raggiunge. È il caso più difficile per tutti gli strumenti, ed è il prossimo punto su cui
  lavoreremo.

**Due difetti trovati grazie a questa prova, e corretti.** RepertIA attivava in PhotoRec (il motore di carving che usa)
anche dei riconoscitori «rumorosi» che spezzavano i file BMP e TIFF; ora usa la configurazione raccomandata. E i file
non allineati ai settori non si trovavano: ora, dopo PhotoRec, RepertIA li cerca byte per byte e ne ricava la fine dalla
struttura del formato, scartando tutto ciò che non si chiude correttamente.

## 3. Cosa questa prova non dice

Per correttezza:

- I rapporti NIST sul recupero dei cancellati (2014-2015) e sul carving del 2014 riguardano versioni degli strumenti di
  quegli anni; quelle di oggi possono andare meglio. Per il carving abbiamo usato anche i rapporti del 2024-2025, su
  versioni recenti.
- Non è una certificazione: NIST non ha provato RepertIA. Abbiamo usato le sue immagini pubbliche e il suo metodo, e
  pubblichiamo tutto perché chiunque possa rifare le misure.
- Il metro di RepertIA (identità byte per byte) è più severo della valutazione visiva usata nei rapporti: dove c'è differenza, è
  a sfavore di RepertIA.

## 4. Fonti e come rifare le prove

- Rapporti sul recupero dei cancellati: DHS, «Deleted File Recovery and Active File Listing»,
  <https://www.dhs.gov/publication/deleted-file-recovery-and-active-file-listing>.
- Rapporti sul carving di file grafici: DHS, «Graphic File Carving»,
  <https://www.dhs.gov/publication/graphic-file-carving>.
- Programma NIST CFTT: <https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt>.
- Immagini NIST: «Deleted File Recovery» (<https://cfreds-archive.nist.gov/dfr-images/>), «File Carving» 2014
  (<https://cfreds-archive.nist.gov/filecarvingtestreports.html>) e «File Carving Graphic Files» 2023
  (<https://cfreds.nist.gov/all/NIST/FileCarvingGraphicFiles>).
- Script di misura: [tools/prove](../../tools/prove/) (`valida_nist_dfr.py`, `cftt_metriche_dfr.py`, `confronto_cftt_dfr.py`,
  `valuta_carving_nist.py`, `valuta_carving_2023.py`, `confronto_cftt_carving.py`).

*Segnalazioni: [issue del repository](https://github.com/silvexe/RepertIA/issues).*
