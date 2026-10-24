# RepertIA – Documento di validazione

*English: [VALIDATION.md](VALIDATION.md).*

Versione del programma: 2.19.0 · Documento aggiornato al 24/10/2026

Questo documento descrive **come è stato verificato RepertIA, con quali dati, con quali risultati e con quali
limiti noti**. Serve a chi usa il programma in una consulenza per dichiarare l'affidabilità del metodo
(ISO/IEC 27041 «assicurazione dell'idoneità e dell'adeguatezza dei metodi di indagine», ISO/IEC 27042,
linee guida ENFSI per l'informatica forense; l'impostazione dei controlli segue quella del progetto NIST CFTT:
dati di prova con risultato noto, confronto automatico, rapporto ripetibile).

> RepertIA è un progetto personale, non certificato né accreditato. Il documento non sostituisce la validazione
> del laboratorio che lo usa: ne fornisce la base e indica come ripeterla. Per i risultati decisivi di ogni caso
> resta raccomandato il **riscontro con un secondo strumento** (sezione 4).

## 1. Cosa garantisce il metodo

| Requisito | Come è soddisfatto | Dove si verifica |
|---|---|---|
| La copia forense non viene modificata | Il caso è un database separato; la copia (E01, raw, dmg) è aperta in sola lettura da Sleuth Kit, libewf, libfsapfs. Le estrazioni vanno in `<caso>/estratti` ed `export`, in sola lettura | Hash della copia prima/dopo (Verifica hash) |
| Integrità dei dati acquisiti | MD5/SHA-1/SHA-256 dei dati del supporto confrontati con gli hash di acquisizione dell'E01 o dei log (FTK Imager, Guymager…) | Riga «Acquisizione» del caso; sezione del report |
| Tracciabilità delle operazioni | Registro `audit_log.jsonl` con ogni comando e analisi, concatenato con SHA-256 (ogni riga contiene l'hash della precedente) | «Verifica hash» controlla anche la catena; report: hash dell'ultima riga |
| Ripetibilità | Versioni degli strumenti, dei moduli e impronta SHA-256 dei sorgenti del programma salvate alla preparazione e nel report | Sezione «Ambiente» del report |
| Date corrette | Dati in UTC; FAT/exFAT convertiti dal fuso del dispositivo (rilevato dal registro o dal sistema, dichiarato); ora legale e ora doppia gestite; tre modalità di visualizzazione sempre etichettate | Collaudo DFTT 5 (FAT, ora legale) |
| Distinzione fra dato e interpretazione | I risultati vengono dal programma; il modello linguistico locale propone interpretazioni che vanno verificate sul dato (ogni risposta cita file, offset e inode) | — |

## 2. Collaudo automatico (`forense_collaudo.py`)

Il collaudo prepara un caso per ogni immagine di prova e confronta i risultati con quelli attesi scritti in
`atteso.json` / `atteso_dftt.json`. Si avvia con «Collaudo RepertIA» (Mac), dal menu Start > RepertIA > Collaudo
(Windows) o con `./collaudo.sh` (Linux) e produce `collaudo_<data>.md` con l'esito di ogni controllo, le versioni e l'impronta del programma.

**Immagini con risultato noto pubblicato da terzi** (Digital Forensics Tool Testing, dftt.sourceforge.net, risultati
trascritti dalle pagine del progetto e confermati dai `results.txt` degli archivi):
DFTT 5 (FAT12, date con ora legale), 6 (FAT16, immagine troncata), 7 (NTFS), 8 (archivi con estensione diversa),
9/10 (ricerca di parole chiave), 11 (carving: offset dei file pubblicati). Le immagini sono riconosciute dall'MD5
pubblicato. Controlli: MD5 dei file, file cancellati, file estratti dagli archivi, date nel fuso del dispositivo,
carving (MD5 e settore di inizio).

**Immagini costruite per il collaudo** (risultato noto perché costruito): ext4 in E01 con file cancellati; E01 con 4 byte
alterati (deve risultare DIVERSO dall'hash di acquisizione); chiavetta FAT con elenco hash FTK Imager; volume dati
di un Mac (plist, sqlite con WAL, bookmark); APFS (dfvfs) in chiaro e cifrato con password; BitLocker To Go (dfvfs).

**Risultati documentati** (dal registro delle modifiche del progetto):

| Versione | Dove | Esito |
|---|---|---|
| 2.15.1 | Mac dell'utente (PhotoRec 7.2, Sleuth Kit 4.15) | 111/111; 45/45 controlli indipendenti (DFTT); carving 13/15 identici agli offset pubblicati |
| 2.15.2 | Mac dell'utente | 112/112 |
| 2.15.2 | Windows 11 dell'utente | 110/112: 2 errori sulle date FAT con ora legale (DFTT 5) → corretti nella 2.15.3 |
| 2.15.3 | Windows dell'utente | tutti superati |
| 2.16.0 | Windows dell'utente | tutti superati |
| 2.16.0 | Mac dell'utente | 110/112: doppia conversione del fuso FAT (DFTT 5) dovuta a un errore di Sleuth Kit su macOS → corretto nella 2.16.1, verificato nel container (50/50 anche con simulazione Mac e Windows) |
| 2.17.x – 2.19.0 | Windows dell'utente | tutti superati |
| 2.19.0 | Linux: ambiente di sviluppo (Ubuntu 24.04, Python 3.13; Sleuth Kit 4.15.0, PhotoRec 7.2 e libewf 20140814 compilati dai sorgenti; senza bulk_extractor) | 112/112 in italiano e 112/112 in inglese (46/46 su immagini pubbliche); carving DFTT 11: 13/15 come sul Mac |

Carving DFTT 11: 2 file su 15 (enterprise.wav, haxor2.jpg) non vengono recuperati da PhotoRec: è un limite di
PhotoRec, dichiarato come «misura» e non come requisito.

**Da fare a ogni nuova versione:** eseguire il collaudo su Mac, Windows e Linux prima dell'uso in un caso e conservare
il rapporto `collaudo_<data>.md` con la consulenza. Collaudo completo sul Mac: 2.18.1 112/112; 2.19.0 112/112 in italiano e
112/112 in inglese. Collaudo completo eseguito dall'autore anche su Windows per le versioni dalla 2.17.x alla 2.19.0.
**Linux (sperimentale, 2.19.0)**: collaudo superato nell'ambiente Linux di sviluppo; da ripetere su un computer Linux
installato con `installa.sh` prima dell'uso in un caso.

## 3. Verifiche su copie reali

Oltre al collaudo, le funzioni nuove vengono provate su copie reali di casi (i dati restano sul computer
dell'utente). Esempi documentati:

- 2.17.3, «Anomalie» su una copia reale di un disco Windows (alcune centinaia di GB, NTFS, oltre un milione di file): segnalazioni ridotte da 566
  a 231 eliminando i falsi positivi su file cancellati (cluster riusati da altri file, verificati con una passata
  sulla MFT e con la coerenza del contenuto); 1.500 file presi a caso non danno segnalazioni nuove.
- 2.17.3, accessi degli account: confrontati con gli eventi 4624 / 7001 estratti da plaso dallo stesso disco.
- 2.18.0, artefatti sullo stesso disco (funzioni del programma eseguite sui dati reali; registro letto con un lettore
  indipendente in Python puro): riconosciute l'installazione principale e quelle precedenti in Windows.old (per una
  di queste gli alveari di sistema risultano cancellati e sovrascritti, dichiarato); 1.489 voci ShellBags tutte
  riconosciute (unità, percorsi di rete, computer in rete, cartelle note); ShimCache 479 voci, BAM 51; journal NTFS
  170.642 operazioni su un periodo di alcuni mesi, percorso ricostruito per tutte tranne una, letti solo i 33 MB di dati
  reali su 52 GB logici; 1.313 miniature estratte, tutte apribili; hash percettivi su 1.293 (20 immagini uniformi escluse).

## 4. Riscontro con un secondo strumento (per ogni caso)

«Riscontro con altro strumento» confronta l'elenco dei file e gli hash di RepertIA con quelli esportati da FTK
Imager, Autopsy o un body file di Sleuth Kit e scrive `riscontri/riscontro_<data>.{csv,md}`: file presenti solo in uno
dei due, hash diversi. È la verifica raccomandata per ogni caso in cui i risultati abbiano peso probatorio.
Per gli artefatti decisivi (accessi, esecuzioni, dispositivi USB, cartelle aperte) conviene confermare con un secondo
strumento (Registry Explorer, Autopsy, X-Ways, AXIOM…) o direttamente sul dato grezzo, che RepertIA indica sempre
(file di origine, offset, inode, chiave del registro).

## 5. Limiti noti

- **File system**: letti NTFS, FAT/exFAT, ext2/3/4, HFS+ (Sleuth Kit), APFS (libfsapfs, anche FileVault con chiave).
  Non letti: ReFS, Storage Spaces, RAID software, LVM, btrfs, XFS. VeraCrypt/TrueCrypt solo rilevati (alta entropia),
  non aperti. BitLocker e LUKS1 si aprono con la chiave (copia derivata).
- **APFS**: nessun recupero di file cancellati (salvo snapshot); non provato su E01 di Mac reali recenti (T2/Apple Silicon).
- **Registro di Windows**: i log delle transazioni (.LOG1/.LOG2) si applicano a una copia di lavoro solo se la sequenza
  è continua; altrimenti si legge l'alveare com'è (dichiarato tra gli artefatti).
- **Accessi**: il contatore del SAM non conta gli accessi con account Microsoft, PIN e Windows Hello; i registri eventi
  conservano solo il periodo più recente (dichiarato nella scheda).
- **ShimCache**: da Windows 8 la presenza di un programma non prova che sia stato eseguito; la data è quella di modifica
  del file. **ShellBags**: le date della cartella sono quelle registrate al momento (UTC, precisione 2 s); la data della
  chiave indica l'ultima apertura solo per la prima voce dell'elenco MRU.
- **Journal NTFS**: copre solo il periodo ancora presente in `$UsnJrnl:$J` (di solito giorni o settimane); i percorsi
  delle cartelle cancellate si ricostruiscono quando il journal le contiene, altrimenti «cartella MFT n». Dalla
  2.18.1 le cartelle si riconoscono per record e numero di sequenza (un record riutilizzato non dà più il percorso
  della cartella attuale); oltre 500.000 operazioni si tengono le più recenti, e il taglio, un journal assente o non
  letto sono dichiarati tra gli artefatti di sistema.
- **Registri eventi**: i record recuperati dallo spazio libero del file sono indicati come tali e non contati due
  volte se identici a un record attivo; i record illeggibili sono contati e dichiarati, non ricostruiti.
- **Anomalie su file cancellati**: segnalate solo se il contenuto è dimostrabilmente del file; un eseguibile con dati
  aggiunti (installatori) cancellato può quindi non essere segnalato.
- **Hash percettivi** (dHash a 64 bit): trovano immagini ridimensionate o ricompresse, non ritagliate o ruotate; le
  corrispondenze sono indizi da verificare sempre a vista; non sostituiscono PhotoDNA. Le liste Project VIC/CAID si
  usano per gli hash crittografici (MD5/SHA-1) e la categoria.
- **SRUM** (libesedb) e registri eventi (libevtx): letti con le librerie incluse in plaso; il database SRUM può essere
  «sporco» (non chiuso) e alcune righe illeggibili.
- **Modello linguistico**: le risposte non sono riproducibili alla lettera e non sono un risultato: ogni affermazione va
  verificata sul dato indicato.

## 6. Cosa è stato verificato nella 2.18.0 e come

| Funzione | Prova |
|---|---|
| Installazioni multiple (Windows.old) | Disco reale: 3 installazioni, alveari cancellati riconosciuti e dichiarati |
| ShellBags (NTUSER.DAT, UsrClass.dat) | Shell item costruiti (0xBEEF0004 v9, volume, GUID) e 1.489 voci reali, nessuna non riconosciuta |
| ShimCache / BAM | Formato Windows 10/11 costruito e alveare SYSTEM reale (479 + 51 voci) |
| Journal NTFS | Record USN v2 costruiti (creazione, cancellazione, rinomina, cartella ricostruita) e `$UsnJrnl:$J` reale (170.642 operazioni) |
| Miniature (thumbcache) | File costruito (versione 31) e file reali (versione 32 di Windows 11: trovata e corretta una variante dell'intestazione) |
| Cronologia attività | Database costruito e database reale (252 attività) |
| Registri eventi, SRUM | Librerie simulate sulla struttura documentata: da confermare sul caso reale con le librerie incluse (libevtx, libesedb) |
| Lettura del journal e dei cluster con Sleuth Kit (pytsk3) | Logica provata con un lettore indipendente; il collegamento a pytsk3 va confermato rifacendo «Artefatti» nel programma |
| Hash percettivi e cartelle di riferimento | Immagine ridimensionata e ricompressa = distanza 0; immagini diverse lontane; immagini uniformi escluse |
| Liste Project VIC / CAID | JSON VICS con MD5, SHA-1 e categoria |

Nella **2.18.1**: percorsi del journal con il numero di sequenza (journal costruito: cartella attuale, cartella riutilizzata nota e ignota al journal, cartella cancellata non riutilizzata, limite, sequenza non verificabile, journal assente, volume non apribile); registri eventi con record recuperati, recuperati doppi e illeggibili (libevtx simulato). Da confermare su una copia reale con pytsk3 e libevtx inclusi (confronto con MFTECmd / EvtxECmd).

Nella **2.19.0** (lingua): i testi prodotti dal programma si traducono con un dizionario (`lingua_en.json`), senza
toccare dati, hash, percorsi e valori letti dal disco; la lingua di un caso si sceglie alla creazione e resta quella.
Collaudo completo eseguito in entrambe le lingue sul Mac e anche su Windows. Sul Mac: 112/112 in italiano, 112/112 in inglese (il collaudo in
inglese riconosce i titoli attesi tradotti). Il dizionario è incluso nell'impronta del programma.

**Pacchetto Linux (2.19.0)**: stessi file del programma dei pacchetti Mac e Windows (impronta identica,
`6d5b05c9…`). Prove nell'ambiente Linux di sviluppo: collaudo 112/112 in italiano e in inglese; caso con plaso
(log2timeline 20260720, modalità multiprocesso con pyzmq), analisi estese e OCR su DFTT 7 (NTFS); interfaccia aperta nel
browser senza errori. **Non provati**: `installa.sh` con apt e PyPI su un computer reale (l'ambiente di sviluppo non
raggiunge PyPI: i moduli sono stati compilati dai sorgenti alle stesse versioni), bulk_extractor, finestre di scelta
dei file con zenity, il client openai (modello linguistico).


## 7. Controllo delle modifiche

Ogni versione è descritta nel registro delle modifiche (README, sezione Aggiornamenti) con cosa cambia, come è
stata provata e cosa NON è stato provato. L'impronta dei sorgenti nel report permette di dimostrare quale versione ha
prodotto un risultato.
