# RepertIA – Documento di validazione

*English: [VALIDATION.md](VALIDATION.md).*

Versione del programma: 2.20.2 · Documento aggiornato al 30/10/2026

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
| 2.20.0 | Mac dell'autore (Python dell'app; iLEAPP 2026.4.5, ALEAPP 2026.4.4) | 422/422 in italiano e 422/422 in inglese, dal pacchetto Mac assemblato: 173 dei dischi + 249 degli smartphone, di cui 18 su WhatsApp e foto/video/audio (backup WhatsApp finto con chiave inventata, avvisi di sistema, lettura su iPhone, Solo foto/Solo video, audio dell'estrazione e delle chat, origine dalle chat) e 17 sulla ricerca veloce nei risultati (indice costruito, messaggio ritrovato da una parte del testo, numero della rubrica ritrovato scritto in un altro formato, anteprima della voce della rubrica, nessun valore segreto del portachiavi nell'indice), 17 sul report portatile (timeline per giorno con tutti gli eventi una volta, righe di iLEAPP/ALEAPP nei file per artefatto, ricerca veloce presente), 33 sui pulsanti dell'interfaccia, 5 su file citati, allegati e riepilogo delle chat, 44 nelle due prove del portachiavi finto, 20 sui file citati in tre livelli (19 nella prova dell'estrazione finta, 8 dei quali sulle righe di prova, e 1 sulle righe SMS reali di iLEAPP), 45 sulla verifica a posteriori del registro, 36 su registro e strumenti nel report 11 sui sysdiagnose (prova 25 con ritagli pubblici dei test di iLEAPP) e 7 sulla trascrizione degli audio (elenco dei modelli, consenso obbligatorio, file non validi rifiutati, percorso del testo con un motore finto; la trascrizione vera con un modello installato è una misura) (77/77 su immagini pubbliche o su valori pubblicati da terzi) |
| 2.20.1 | Mac dell'autore (come la 2.20.0) | 427/427 in italiano e 427/427 in inglese, dal pacchetto Mac assemblato: 178 dei dischi + 249 degli smartphone; i 5 nuovi riguardano l'AI Act (reperto dell'agente «modello IA – da verificare» in findings.json e nel report, senza la frase «ogni reperto è stato verificato»; metadati IA di Word e PDF; dopo «Confermo, verificato» reperto verificato con operatore e data nel report e nel registro; server LLM locali e privati distinti da quelli esterni) (77/77 su immagini pubbliche o su valori pubblicati da terzi) |
| 2.20.1 | Windows 11 dell'autore | 417/426 (77/77 su immagini pubbliche): righe vuote importate da iLEAPP su Windows (5 errori) e confronto dei percorsi nel collaudo (4 errori) → corretti nella 2.20.2 |
| 2.20.2 | Mac dell'autore (come la 2.20.0) | 433/433 in italiano e 433/433 in inglese, dal pacchetto Mac assemblato: 178 dei dischi + 255 degli smartphone; i 6 nuovi controllano che nessuna riga vuota entri nel caso, anche con un TSV scritto come fa iLEAPP su Windows |
| 2.20.2 | Windows 11 dell'autore (pacchetto definitivo) | 433/433, 77/77 su immagini pubbliche |

Carving DFTT 11: 2 file su 15 (enterprise.wav, haxor2.jpg) non vengono recuperati da PhotoRec: è un limite di
PhotoRec, dichiarato come «misura» e non come requisito.

**Da fare a ogni nuova versione:** eseguire il collaudo su Mac, Windows e Linux prima dell'uso in un caso e conservare
il rapporto `collaudo_<data>.md` con la consulenza. Collaudo completo sul Mac: 2.18.1 112/112; 2.19.0 112/112 in italiano e
112/112 in inglese. Collaudo completo eseguito dall'autore anche su Windows per le versioni dalla 2.17.x alla 2.19.0.
**Linux (sperimentale, 2.19.0)**: collaudo superato nell'ambiente Linux di sviluppo; da ripetere su un computer Linux
installato con `installa.sh` prima dell'uso in un caso. **2.20.2**: collaudo sul Mac 433/433 in entrambe le lingue e su Windows 11 433/433 con il pacchetto definitivo;
da ripetere su Linux (pacchetto costruito sul Mac).

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
- **Smartphone (2.20)**: si vede solo quello che c'è nell'estrazione; database cifrati (Signal, backup di WhatsApp
  `.crypt*`) non letti senza chiave; messaggi cancellati nelle pagine libere dei database non recuperati; le estrazioni non
  hanno file cancellati del file system; le date DOS degli zip (senza fuso) sono convertite col fuso del dispositivo e
  dichiarate; lettori propri solo per WhatsApp, iMessage/SMS e SMS/MMS (le altre app con iLEAPP/ALEAPP, programmi di terzi
  di cui si registrano versione e impronta). Le chat delle altre app e le **Chiamate** sono ricavate dalle righe di
  iLEAPP/ALEAPP secondo `forense_mobile_leapp_mappa.json`: valgono quanto le righe di partenza (indicate per ogni
  messaggio e chiamata); il verso «non indicato» e i doppioni uniti sono dichiarati; gli allegati copiati da iLEAPP/ALEAPP
  nel loro rapporto sono copie di lavoro di quegli strumenti, non l'originale dell'estrazione. Le regole del verso per app
  sono verificate solo sulle versioni delle app delle immagini di Hickman (2024): con altre versioni il database può
  cambiare. **WhatsApp**: il significato dei tipi e dei codici degli avvisi non è pubblicato da WhatsApp; su Android i
  codici degli avvisi sono spiegati con fonti pubbliche e il loro livello (nessuno verificato su un telefono con azioni
  documentate); su iPhone nessuna fonte spiega i codici degli avvisi (si mostrano valori e fatti dal database) e lo stato
  di lettura dei messaggi inviati non è leggibile. Backup di WhatsApp: solo `.crypt14` con la chiave nell'estrazione
  (non crypt12/crypt15, non i backup incrementali). Oltre 500.000 righe di iLEAPP/ALEAPP alcune tabelle non sono
  importate (elencate nel caso; chat, messaggi e chiamate hanno la precedenza). La ricerca veloce cerca solo nei risultati
  del caso (non nel contenuto dei file né nella timeline). Chiamate: una riga di interactionC senza numero
  non si unisce alla riga del registro di sistema che le corrisponde (una su iOS 17 di Hickman) e compare come chiamata a sé.
- **File citati (2.20)**: il file nominato da una riga (percorso del telefono, di Windows o di macOS, «media/…» di
  iLEAPP/ALEAPP, allegato di una chat) si cerca per percorso con la tabella `forense_percorsi.json` (cartella e nome
  scritti in due campi della stessa riga si uniscono in un percorso completo), poi per hash se la riga lo dà, poi per
  nome e dimensione o solo nome. L'esito ha tre livelli: «trovato con certezza» (percorso completo, hash, collegamento
  registrato da iLEAPP/ALEAPP), «probabile, da verificare» (solo nome o nome e dimensione: può essere un altro file con
  lo stesso nome, per questo si elencano tutti i candidati), «non presente». «Certo» per percorso vuol dire che la parte
  finale del percorso indicato coincide: se la stessa parte finale c'è in più posizioni le altre copie sono elencate nei
  dettagli tecnici, da confrontare con lo SHA-256. Un file non trovato può essere fuori dall'estrazione (partizione di sistema del
  telefono, altro disco) o cancellato; i riferimenti `content://` di Android non si risolvono; la traduzione dei percorsi
  di Windows (unità, volumi, variabili d'ambiente) è provata con un indice di prova, non ancora su una copia reale. La
  miniatura di un allegato presa dal database dell'app è una rappresentazione ridotta salvata dall'app, non il file.
- **Portachiavi di iOS (2.20)**: RepertIA non decifra né legge il portachiavi: lo registra (SHA-256) e lo passa a
  iLEAPP con `--keychain`; decifratura e lettura sono di iLEAPP e valgono quanto iLEAPP. Il portachiavi fornito serve solo
  agli artefatti che cercano la chiave di un'app; gli artefatti del portachiavi (Wi-Fi, password web…) iLEAPP li ricava da
  quello dentro l'estrazione. Collaudato solo con portachiavi **finti**; **non provato su portachiavi GrayKey o Cellebrite
  reali** né sulla decifratura reale di Signal, Session o SimpleX. I valori segreti sono nascosti in RepertIA, ma il rapporto
  di iLEAPP nella cartella del caso li contiene in chiaro.
- **Sysdiagnose di iOS (2.20)**: RepertIA non interpreta il sysdiagnose: lo registra (SHA-256) e lo fa leggere a iLEAPP
  (`-t gz`); le righe valgono quanto i moduli di iLEAPP. Data di creazione e dispositivo vengono dal **nome** della cartella
  dell'archivio (e da `remotectl_dumpstate.txt` se c'è): un archivio rinominato darebbe valori sbagliati. Collaudato con
  archivi nella forma di un sysdiagnose costruiti con i ritagli pubblici dei test di iLEAPP (`ps.txt`, BatteryUI,
  ManagedSettings): **non provato su sysdiagnose completi** di un caso; i registri unificati (`system_logs.logarchive`)
  iLEAPP li legge solo con il suo programma esterno `unifiedlog_iterator`, non incluso.
- **Verifica del registro (2.20)**: dimostra che il registro, fino all'hash finale indicato, non ha righe cambiate, tolte o
  inserite dopo e che i file esportati ancora presenti sono quelli registrati; **non** dimostra chi ha usato il programma né
  che le operazioni descritte siano corrette o complete. Senza un hash finale conservato altrove (report consegnato,
  verbale) un registro riscritto per intero con una catena ricalcolata risulta integro e le righe tolte alla fine non si
  vedono; il contenuto originale di una riga alterata non si ricostruisce; i file esportati fuori dalla cartella del caso o
  cancellati non si ricontrollano.
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

Nella **2.20.0** (smartphone): moduli separati, caricati solo per i casi smartphone; i casi dei dischi del collaudo
producono database identici, riga per riga, a quelli della 2.19.0. Prove: (1) collaudo con due estrazioni costruite da
estratti di immagini pubbliche (iOS 15 di Josh Hickman, Android 15 «anne_a15») usati nei test di iLEAPP e ALEAPP: numero e
orari di tutti i messaggi iMessage/SMS (48), WhatsApp iOS (32) e SMS/MMS Android (91) uguali ai risultati pubblicati da quei
progetti; WhatsApp Android costruito con contenuto noto (messaggio solo nel file -wal, nomi dalle rubriche, foto collegata con
SHA-256, posizione); zip con date UTC e DOS, tar.gz con copia derivata verificata. (2) Immagini pubbliche complete di Josh
Hickman: iOS 13.4.1 (tar di Magnet ACQUIRE, 17 GB, 351.466 file) e Android 10 (zip, 5,2 GB, 76.403 file): i messaggi
WhatsApp, iMessage e SMS hanno gli orari indicati nei documenti dell'autore (convertiti da EDT/EST a UTC). Con iLEAPP
2026.4.5: i 48 messaggi iMessage/SMS della vista chat coincidono con quelli dell'artefatto «SMS» di iLEAPP conversazione per
conversazione (17 su 17, stessi messaggi e stessi orari) e la somma delle sotto-voci dell'albero (102 categorie, 323
artefatti) è uguale al totale delle righe (300.277); con ALEAPP 2026.4.4: 70 categorie, 207 artefatti, 78.370 righe.
Queste prove hanno trovato e fatto correggere cinque errori prima della pubblicazione (blocco del database con estrazioni
grandi, schema WhatsApp del 2020, copie dei database lasciate da Magisk, campi lunghi nei risultati di iLEAPP, file «._»
creati da macOS sui dischi exFAT contati come tabelle di iLEAPP/ALEAPP). Nota: il tar iOS 13.4.1
pubblicato ha un MD5 diverso da quello del log di acquisizione perché è stato rigenerato dall'autore dopo l'acquisizione.
(3) Pulsanti dell'interfaccia (dalla 2.20.0 nel collaudo, con le stesse richieste della pagina): Preferiti, Reperto, Fonte e
«Mostra nell'albero» su un file e un artefatto di un caso disco e, nei casi smartphone, su un file, un artefatto di
iLEAPP/ALEAPP, una chat e una chiamata (riferimenti senza valori mancanti, percorso aperto uguale a quello atteso); apertura di
tutte le cartelle dell'albero fino al secondo livello con il numero di elementi indicato; indice dell'albero cancellato a caso
aperto e ricostruito. Sono controlli interni e non entrano nel conteggio dei valori pubblicati da terzi.
(4) File citati e allegati (dalla 2.20.0 nel collaudo): estrazione Android di prova con Google Photos costruito
(`gphotos-1.db`: un file al percorso indicato, uno spostato in un'altra cartella, uno assente → trovati per percorso, per
nome e dimensione, assente) e allegati WhatsApp costruiti (uno al suo posto con `file_hash`, uno spostato e rinominato, uno
con la sola miniatura nel database, uno assente → per percorso, per hash, miniatura, assente; SHA-256 dei file trovati
uguale a `file_hash`); riepilogo delle chat salvato nel caso. Sulle immagini complete di Hickman: Google Photos – Local
Media del Pixel 3 trovati per percorso 108 su 108 (`/storage/emulated/0/…` → `data/media/0/…`); allegati WhatsApp dei
messaggi 14 e 16 trovati con SHA-256 uguale a `file_hash`; nel complesso degli artefatti di iLEAPP/ALEAPP trovati 7.925 file
citati su 9.956 (Pixel 3) e 11.803 su 14.346 (iOS 13.4.1), con il conteggio per modo e sezione prodotto da
`tools/file_citati_conta.py`. Queste prove hanno trovato e fatto correggere due errori già presenti (riepilogo delle chat
non salvato per un import mancante; dimensioni delle foto di WhatsApp iOS lette come posizione). File citati in tre livelli
(sempre nella 2.20.0): estrazione iOS **finta** `ios_file_citati.zip` (IMG_0059.PNG nelle stesse posizioni del caso pubblico
iOS 13.4.1 di Hickman: `DCIM/100APPLE`, copia in `PhotoData/OutgoingTemp`, cartella omonima delle miniature; due
IMG_0100.JPG diverse in cartelle diverse; due `verbale.pdf` con lo stesso percorso finale) e 8 righe nello stile di iLEAPP
con l'esito atteso: «Directory» + «Filename» → un solo file trovato con certezza per percorso con il collegamento alla
cartella; lo stesso con anche il percorso completo → un file, due campi; un «Original Filename» di un'altra cartella →
secondo file, probabile; solo il nome con due omonimi → probabile con due candidati; nome e dimensione → probabile, un
candidato; nome, dimensione e SHA-256 → certo, hash verificato; stesso percorso finale in due app → certo con una copia nei
dettagli; nome assente → non presente. Per ogni riga lo stesso esito nella ricerca veloce della tabella (una sola miniatura)
e nel report portatile. Sulle righe SMS reali di iLEAPP (prova 20): 11 allegati, tutti un solo file trovato con certezza, 8
indicati da due campi («Attachment File» e nome dell'allegato). Sulle immagini complete di Hickman, dopo l'unione dei campi:
iOS 13.4.1 12.941 file citati distinti (1.405 indicati da più campi della stessa riga): 10.060 certi, 382 probabili, 2.499
non presenti (161 con una copia nel rapporto di iLEAPP); Pixel 3 9.920 (25 uniti): 7.612 certi, 277 probabili, 2.031 non
presenti (1.124 con una copia nel rapporto di ALEAPP). La prova sul caso iOS ha fatto correggere un errore prima della
pubblicazione: con una cartella e due nomi la cartella veniva unita anche al nome originale («Original Filename»), che sta
altrove.
(5) Portachiavi di iOS (dalla 2.20.0 nel collaudo): estrazione iOS minima costruita con portachiavi **finti** (nessun dato
reale) — uno decifrato (`genp` con una rete Wi-Fi e una voce in stile Signal inventate) passato a iLEAPP con `--keychain`,
uno nel formato cifrato di Cellebrite (chiavi inventate) in `extra/KeychainDump` — in due prove, con e senza portachiavi
fornito: SHA-256 nel caso e nel registro a catena, `--keychain` nel comando di iLEAPP e voci lette da iLEAPP, portachiavi
dichiarato (fornito / trovato nell'estrazione), artefatti *Keychain Wifi Credentials* e *Keychain Web Passwords* ricavati da
iLEAPP, valori segreti mai in chiaro nelle tabelle del caso (solo in `leapp_segreti`), nascosti nei dettagli
dell'interfaccia, «Mostra» che rivela il valore e lo registra senza scriverlo, assenti dal report portatile senza la scelta
esplicita e presenti con la scelta, assenti dallo strumento degli artefatti dell'agente. Sono controlli interni.
(6) Sysdiagnose, report degli smartphone e verifica del registro (dalla 2.20.0 nel collaudo). Prova 25: l'estrazione iOS
di prova con due archivi nella forma di un sysdiagnose costruiti da `tools/collaudo_mobile.py --sysdiagnose` con i ritagli
pubblicati nei test di iLEAPP v2026.4.5 (licenza MIT; scaricati da GitHub e controllati con lo SHA-256): `ps.txt` reale di un
iPhone con iOS 16 (build 20A362) e BatteryUI e ManagedSettings di iOS 26.6 (build 23G71) con gli identificativi sostituiti
dagli autori di iLEAPP. Controllati: SHA-256 nel caso e nel registro a catena; nessuna copia nel caso; data di creazione
(2025-04-07 15:06:18 UTC e 2027-07-19 14:18:09 UTC) e dispositivo dal nome; righe nel gruppo «Sysdiagnose» marcate con il
nome del file; *Sysdiagnose Process* = 333 righe, uguale al numero di processi di `ps.txt` contato **senza iLEAPP** (righe con
almeno 18 campi e PID numerici); «Togli» che toglie solo le righe di quel file; *Fonte* su una riga del sysdiagnose con un
messaggio chiaro. Report: in ogni prova numero di voci e hash finale del registro uguali a quelli del registro prima della
riga «report»; nei casi dei dischi il metodo con The Sleuth Kit come prima (report di un caso disco confrontato riga per riga
con quello della versione precedente: cambiano solo le righe nuove del registro); nei casi smartphone nessuna menzione di
Sleuth Kit o plaso fuori dalla sezione di iLEAPP, metodo dell'estrazione del file system, iLEAPP con versione e impronta,
SHA-256 di portachiavi e sysdiagnose. Verifica del registro (`forense_registro.py`, la stessa di *Verifica registro* e di
`tools/verifica_registro.py`): in ogni prova catena integra, stesso hash finale del programma e hash finale del report
trovato; sulla prova 01 (E01 integro), su copie del registro: una riga modificata indicata con il suo numero, una riga tolta
in mezzo indicata con il numero della voce mancante, tre righe tolte alla fine non scopribili senza hash finale e scoperte con
hash finale e numero di voci, righe aggiunte dopo il report riconosciute come successive; sulle prove con chat esportate: file
esportati uguali e un file esportato modificato (su una copia) scoperto. Sono controlli interni tranne quelli sui valori
pubblicati (orari, processi di `ps.txt`).
(7) Navigazione dell'interfaccia (dalla 2.20.0, fuori dal collaudo: serve un browser comandato da Playwright, che non è nei
pacchetti): `tools/prova_navigazione.py --casi <copie dei casi del collaudo>` avvia l'interfaccia e, su ogni caso, prova
ricerca dal pulsante 🔎 in alto → risultati → clic su una voce dell'albero → Indietro fino alla pagina iniziale → Avanti,
lo stesso dall'etichetta della ricerca e dalla voce dell'albero, due sottovoci cliccate di seguito senza attendere e le voci madri dell'albero chiuse; dopo
ogni passo controlla che le briciole indichino la sezione aperta e che la tabella mostri proprio quella sezione. Sui casi
01, 20 e 25 del collaudo, finestra 1280×800: 66/66 in Chromium (italiano e inglese) e in WebKit.
(8) WhatsApp, chiamate e chat da iLEAPP/ALEAPP (dalla 2.20.0, fuori dal collaudo: servono le immagini pubbliche complete
di Josh Hickman, decine di GB). Immagini: iOS 13.4.1, iOS 17.3 (Cellebrite FFS), Android 10 (Pixel 3), Android 14
(Pixel 7a, Cellebrite FFS; SHA-256 dell'archivio e dell'estrazione uguali a quelli del file .ufd). **Non regressione**: i
quattro casi rifatti con i sorgenti finali e confrontati per contenuto con quelli preparati con i sorgenti della 2.20.0
precedente: nessun messaggio, allegato, conversazione o chiamata mancante; differenze solo volute (doppione WhatsApp di
ALEAPP tolto; orario delle chiamate trovate anche in interactionC preso dal registro di sistema *Call History*; su iOS 17
righe di iLEAPP importate con la nuova precedenza oltre il limite di 500.000). **Confronto con
le attività documentate** da Hickman (documenti delle immagini iOS 17 e Android 14: azione, data e ora locale con il fuso
dichiarato, testo): un messaggio documentato è «ritrovato» se nella stessa app c'è un messaggio con lo stesso testo
(normalizzato, prime 16 lettere) entro ±3 minuti, e se ne confronta il verso; una chiamata se nella stessa app c'è una
chiamata entro ±3 minuti. Chat ricavate da iLEAPP/ALEAPP: iOS 17.3 1.167 messaggi documentati, 766 ritrovati, 759 con
il verso uguale alla documentazione; Android 14 656, 272, 271. Gli 8 diversi non sono errori di RepertIA: 7 sono errori
della documentazione (lo stesso messaggio è segnato «Sent» nei documenti di entrambi i telefoni; dove l'app è letta anche
sull'altro telefono, Gettr, Google Chat, Viber e Messenger, il suo database dice che l'ha inviato quello, come indica
RepertIA, e il contesto lo conferma: per esempio «Video call time.» seguito da una videochiamata in arrivo) e 1 è un
abbinamento sbagliato dello script («Deleted.» abbinato a «This message was deleted»). Verso giusto quindi 766 su 766 e
272 su 272. Chiamate:
WhatsApp (iOS 17 8, Android 14 4), Skype (8 e 4), imo (Android 14 4), Signal (Android 14 4), Google Voice (2), Facebook
Messenger (8, inizio calcolato), TeleGuard (4, inizio calcolato) uguali alla documentazione; telefono Android 14 2.655 =
righe di `calls` in calllog.db. Stati di lettura: Android 14 22 consegne e 10 letture come nel database; iPhone, l'ora
di lettura dei messaggi ricevuti (`ZSENTDATE`) coincide entro 1 s con la conferma registrata dall'Android 14 nella stessa
conversazione in 8 casi su 10. Backup: `msgstore.db.crypt14` dell'Android 14 decifrato con tag verificato (197
messaggi, tutti presenti nel database attuale), 4 backup riconosciuti come cifrati con un'altra chiave, 2 incrementali
elencati. Questi riscontri valgono per il **metodo** sulle versioni delle app usate da Hickman, non per i messaggi di un
caso; il dettaglio per artefatto è nella sezione `verifiche` di `forense_mobile_leapp_mappa.json`. Script del confronto
fuori dal repository (contengono percorsi personali): ripetibili con le stesse immagini pubbliche.
Grafico della Timeline (calcolo per minuto, 2.20.0): confrontato con il calcolo precedente evento per evento, identico su
iOS 17.3, Android 14 e DFTT 05, nell'ora del telefono e in ora italiana, per giorno, mese, anno e scelta automatica, con e
senza filtri (testo, periodo); su iOS 17.3 da circa 40 s a 2-7 s.
**Non provati**: Windows e Linux, estrazioni GrayKey e Cellebrite reali con i loro metadati, sysdiagnose completi, backup
WhatsApp crypt12/crypt15, codici degli avvisi WhatsApp su un telefono con azioni di gruppo documentate.


## 7. Controllo delle modifiche

Ogni versione è descritta nel registro delle modifiche (README, sezione Aggiornamenti) con cosa cambia, come è
stata provata e cosa NON è stato provato. L'impronta dei sorgenti nel report permette di dimostrare quale versione ha
prodotto un risultato.
