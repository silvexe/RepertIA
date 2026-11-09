# RepertIA alla prova di un caso completo: NIST «Data Leakage»

*RepertIA 3.0.2 — novembre 2026 · English: [nist-data-leakage.md](nist-data-leakage.md) · Altre prove: [indice](README.md)*

## In breve

Il **NIST** ha preparato un caso di prova completo e pubblico, **«Data Leakage Case»**. Un dipendente porta fuori
dall'azienda documenti riservati, usando una chiavetta USB, un CD-R, un servizio cloud e la posta, e poi cerca di
cancellare le tracce. Il caso contiene le immagini del suo **PC Windows 7**, di **due chiavette** e di un **CD-R**, insieme
a **60 domande con le risposte ufficiali NIST**.

Abbiamo aperto le immagini con RepertIA e confrontato i risultati con le risposte, domanda per domanda.

- **53 domande si verificano sulle immagini, e le risposte di RepertIA sono quelle di NIST.** Su un punto c'è un
  limite: un messaggio di posta rimasto nello spazio non usato dell'archivio di Outlook, che RepertIA non legge ancora.
- **In alcuni punti i dati delle immagini differiscono dalle risposte NIST,** e lo abbiamo verificato: il numero di un
  evento, due date invertite, il nome di un file di Windows 7, due tabelle con un'ora di differenza.
- **Le altre 7 domande sono di ragionamento** dell'analista (perché, come, la cronologia complessiva). RepertIA fornisce i
  fatti su cui ragionare, ma la conclusione resta all'analista.
- **La prova ha fatto emergere sette difetti o lacune di RepertIA, tutti corretti nella 3.0.2.**
- Uno script automatico ripete **56 controlli** sui casi preparati da RepertIA: **56 su 56 superati**.

## Il caso

| Supporto | Cosa contiene | Come è stato aperto con RepertIA |
|---|---|---|
| PC | Windows 7 Ultimate, un utente, Outlook, Chrome e Internet Explorer, Google Drive, copie shadow | Immagine E01, con le analisi estese e le copie shadow |
| Chiavetta RM#2 | File copiati e poi cancellati con una formattazione rapida | Immagine E01, con le analisi estese |
| CD-R RM#3 | Masterizzato più volte: i file scritti prima restano nelle sessioni precedenti | Sorgente logica |

Le immagini si scaricano dal sito NIST CFReDS. Le impronte SHA-1 delle copie usate coincidono con quelle pubblicate da
NIST.

## Come abbiamo controllato

- **Un caso per supporto**, preparato con RepertIA 3.0.2.
- **Ore in UTC.** Le risposte NIST danno le ore di New York, le abbiamo convertite in UTC. A marzo 2015 New York era già
  passata all'ora legale (UTC-4).
- **Confronto con uno script**, che legge i casi in sola lettura e li confronta con i valori delle risposte NIST.
- **Verifica alla fonte.** Dove RepertIA e NIST non coincidevano, abbiamo riletto i dati grezzi per capire chi aveva
  ragione.

## Risultati

| Argomento | Domande | Esito |
|---|---|---|
| Immagini, partizioni, sistema | 1-5 | Impronte, partizioni, versione di Windows, fuso orario e nome del computer uguali a NIST |
| Account e ultimo utente | 6-7 | Uguali; su un account RepertIA trova anche un tentativo di accesso fallito che NIST non indica |
| Spegnimento, rete, programmi, esecuzioni | 8-12 | Uguali, comprese le 14 esecuzioni con le loro ore |
| Navigazione e ricerche | 13-17 | Chrome e Internet Explorer 11; le parole cercate in Chrome, in Bing e in Esplora file |
| Posta | 18-21 | Programma, archivio e account uguali. Dei messaggi, 10 sono letti con l'ora di invio NIST, mentre quello nello spazio non usato dell'archivio non è letto |
| Chiavette USB | 22 | I due dispositivi, con numeri di serie e ore |
| Rinomine e cartelle aperte | 23-28 | 9 rinomine col nome vecchio giusto; cartelle e file aperti da chiavetta e disco di rete |
| Servizi cloud | 29-31 | Google Drive, i file cancellati e l'account |
| Masterizzazione e CD-R | 32-35 | La cartella di masterizzazione, l'evento, i 17 file nelle sessioni precedenti del CD-R, i file aperti dal CD |
| Documenti e stampa | 36-37 | Date della lettera di dimissioni, stampa su file XPS |
| Miniature, note, Ricerca di Windows | 38-46 | Uguali |
| Copie shadow e cestino | 47-51 | Uguali (la 50 è di ragionamento) |
| Anti-forense e chiavetta | 52-55 | I 17 file cancellati recuperati dalla chiavetta; 15 con l'estensione falsa segnalata, gli altri 2 coerenti col contenuto |
| CD-R e conclusioni | 56-60 | I file nascosti nel CD-R e l'ora della masterizzazione verificati; il resto è ragionamento |

**Totale: 53 domande verificate sulle immagini, 7 di ragionamento.**

## Dove i dati differiscono dalle risposte NIST

Lo segnaliamo perché chi rifà la prova non scambi queste differenze per errori dello strumento.

- **Account e programmi installati (domande 6 e 10): un'ora di differenza.** Le ore di queste due tabelle corrispondono
  all'ora solare, mentre tutte le altre risposte corrispondono all'ora legale, che a New York era già in vigore. Abbiamo
  riletto il registro degli account anche senza il codice di RepertIA, con librerie indipendenti, e i valori grezzi sono
  quelli di RepertIA.
- **Domanda 6:** per un account il registro contiene anche l'ultimo tentativo di accesso fallito, che la risposta NIST non
  riporta.
- **Domanda 33:** nelle immagini l'evento di Windows della masterizzazione ha numero **133** (nella risposta NIST 113).
- **Domanda 30:** nella tabella le date di modifica di due file risultano invertite rispetto al registro di Google Drive,
  che concorda con la risposta 49 e con RepertIA.
- **Domanda 38:** la risposta NIST cita `thumbcache_64`; in Windows 7 le cache delle miniature sono `_32`, `_96`, `_256` e
  `_1024`, e le miniature del caso sono in `thumbcache_256`.

## Difetti di RepertIA trovati con questa prova, e corretti

1. **Rinomine nel journal NTFS.** Per un file rinominato più volte, ogni rinomina mostrava come nome precedente quello
   dell'ultima. Ora ognuna ha il suo nome precedente.
2. **Estensioni false.** Un documento Office rinominato `.amr` o `.svg` non era segnalato. Ora lo è.
3. **Ora dei messaggi di Outlook.** Si usava l'ora di consegna, che per i messaggi inviati Outlook registra solo al minuto.
   Ora si usa l'ora di invio, e quella di consegna resta nel testo del messaggio.
4. **Parole cercate con Internet Explorer ed Edge.** Erano estratte solo quelle di Chrome e Firefox. Ora si leggono anche
   dalla cronologia di Internet Explorer (Bing, Google, Yahoo, DuckDuckGo…).
5. **Programmi installati.** C'era solo la data di installazione, senza ora. Ora c'è anche l'ora, dall'ultima scrittura
   della chiave di registro.
6. **Account.** Aggiunti la data di creazione, l'ultimo tentativo di accesso fallito e la data della password.
7. **CD con settori da 2352 byte.** Della copia derivata si registrava solo lo SHA-256. Ora si registrano anche MD5 e
   SHA-1, quelli che pubblicano gli strumenti di acquisizione e NIST.

Per i primi due, il collaudo automatico di RepertIA ha un controllo nuovo, provato anche al contrario: con il codice
vecchio fallisce.

## Cosa questa prova non dice

- **Non è una certificazione.** NIST non ha provato RepertIA: abbiamo usato il suo caso pubblico e le sue risposte.
- **Limiti che restano:**
  - i messaggi rimasti nello spazio non usato degli archivi di Outlook non vengono letti, perché la libreria usata da
    RepertIA non offre il recupero;
  - le stampanti configurate nel registro e le date interne dei documenti Office non sono state confrontate.
- **Le domande di ragionamento** restano all'analista: RepertIA fornisce i fatti, non le conclusioni.

## Come rifare la prova

1. Scaricare le immagini con `scarica_nist_leakage.py`, che controlla anche gli SHA-1 pubblicati da NIST.
2. Preparare i tre casi come indicato in [tools/prove](../../tools/prove/README.md).
3. Lanciare `valida_nist_leakage.py <cartella dei casi>`: 56 controlli, ognuno con la domanda NIST a cui si riferisce.

## Fonti

- NIST CFReDS, «Data Leakage Case»: <https://cfreds-archive.nist.gov/data_leakage_case/>
  (immagini, descrizione dello scenario, risposte rev. 1.32 del 2018).
- Script: [tools/prove](../../tools/prove/).

*Segnalazioni: [issue del repository](https://github.com/silvexe/RepertIA/issues).*
