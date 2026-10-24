# RepertIA — By silvexe

*English: [docs/MANUAL.md](../docs/MANUAL.md).*

**Analisi forense di copie di dischi e pendrive con intelligenza artificiale locale.**
Versione 2.19.0 · macOS, Windows e Linux (sperimentale) · interfaccia in italiano o in inglese

RepertIA prende una copia forense (raw, dd, img o E01), la indicizza con strumenti forensi
riconosciuti e permette di esaminarla in due modi complementari:

- **senza modello**, consultando direttamente i dati indicizzati: albero del file system,
  elenco dei file anche cancellati, timeline con grafico per giorno, testo dei documenti,
  metadati delle foto, file recuperati ed evidenze di interesse;
- **con un agente IA che gira sul tuo Mac** (LM Studio, llama-server od Ollama), a cui fai
  domande in italiano: usa solo strumenti in sola lettura, cita offset, inode e percorsi e
  registra i reperti per il report.

---

## Riservatezza: tutto resta sul tuo computer

RepertIA è progettato per lavorare **solo in locale**. I dati del caso **non vengono mai
comunicati a terzi**.

- **Nessun servizio esterno.** Non ci sono account, cloud, telemetria, statistiche d'uso o
  aggiornamenti automatici. Il programma non contatta nessun sito durante l'analisi.
- **Il modello IA è locale.** L'agente parla solo con il server LLM avviato sul tuo Mac
  (`localhost`: LM Studio porta 1234, llama-server 8080, Ollama 11434). Domande, risposte e
  contenuti letti dalla prova restano sulla macchina.
- **L'interfaccia non è raggiungibile dalla rete.** Il server web ascolta solo su
  `127.0.0.1`, accetta solo richieste con indirizzo locale e con un codice casuale generato a
  ogni avvio. Altri computer della rete non possono collegarsi.
- **La pagina non carica nulla da internet**: niente font, librerie o script esterni.
- **plaso è incluso** nell'app per Mac e nell'installazione per Windows e lavora in locale; se si usa
  l'alternativa con Docker, gira senza rete (`docker run --network none`).
- **Le anteprime non eseguono contenuti della prova.** Le pagine di PDF e documenti arrivano al
  browser come immagini; il testo come testo semplice; HTML/SVG non vengono mai aperti come
  pagine; i documenti Word convertiti stanno in un riquadro isolato che blocca script e
  qualsiasi caricamento dalla rete.
- **La copia forense non viene mai modificata**: è letta con The Sleuth Kit in sola lettura,
  il suo SHA-256 è registrato all'apertura (o dopo, nell'analisi speditiva) e si può
  riverificare in qualsiasi momento.

Internet serve solo, e solo quando lo chiedi tu, per **installare o aggiornare gli strumenti**
(Homebrew, il client Python `openai`, l'immagine Docker di plaso). In quei momenti non viene
trasmesso alcun dato dei casi. Nota: Homebrew, per conto suo, può inviare statistiche anonime
sulle installazioni; si disattivano con `brew analytics off`.

> Unica eccezione voluta: se scegli tu **Server in rete** nel riquadro *Server LLM* (o la
> variabile `FORENSE_URL` / l'opzione `--url`), le domande e i contenuti letti dall'agente
> andranno a quel server della rete interna; il report lo indica, con il suo indirizzo.
> La connessione al server LLM è sempre diretta, mai tramite proxy.
> Di default RepertIA usa solo server su questo computer (`localhost`).

---

## Requisiti

**Computer (senza IA)**
- **Sistema**: Mac con chip Apple Silicon (M1 o successivo), Windows 10/11 a 64 bit, oppure Linux x86_64 con Ubuntu 24.04
  o successivo (versione sperimentale).
- **Memoria (RAM)**: 8 GB bastano per pendrive e dischi piccoli; con 16 GB si lavora comodi.
- **Disco**: meglio un SSD. Il caso non è una copia del disco ma un database con gli indici; a questo si aggiunge lo spazio
  per i file esportati, il carving e la cache delle anteprime (al massimo circa 5 GB per caso). La copia forense può stare
  anche su un disco esterno, ma conviene USB 3 o Thunderbolt, perché il calcolo degli hash la rilegge tutta.
- **Processore**: più core accorciano soprattutto la timeline di plaso, che su dischi grandi può durare ore.

**Modello IA locale (facoltativo)**: serve un modello che supporti il *tool calling*, con un contesto di almeno 16k token
(meglio 32k). Indicativamente:

| Memoria per il modello | Modelli | Risultato |
|---|---|---|
| 16 GB di RAM (o GPU da 8 GB) | Qwen3.5-9B | solo domande semplici |
| 32 GB (o GPU da 16 GB) | gpt-oss-20b | già accettabile |
| 48–64 GB (o GPU da 24–32 GB) | Qwen3.8-27B, Qwen3.6-35B-A3B, Gemma 4 31B | consigliato |
| 128 GB | gpt-oss-120b | il massimo in locale |

Si carica il modello (LM Studio, llama-server od Ollama) con un contesto di circa 32768, si avvia il server e RepertIA lo
trova da solo. Sul Mac la memoria è condivisa: lasciate una decina di GB liberi per il sistema. Senza scheda video il
modello gira sul processore, ma è lento; con *Server in rete* un solo computer potente della rete interna può servire più
postazioni. Senza modello RepertIA funziona comunque: tutti i dati restano consultabili. Le indicazioni sui modelli vengono
da classifiche pubbliche (ottobre 2026): verificatele sui vostri casi.

---

## Avvio rapido

1. **Server LLM.** Apri LM Studio, carica un modello con contesto ampio (es. 32768) e avvia il
   server nella scheda *Developer*. Vanno bene anche llama-server od Ollama.
   *Senza server LLM RepertIA funziona lo stesso*: puoi consultare tutti i dati indicizzati.
2. **Avvia RepertIA.** Mac: doppio clic sull'app (o su `Avvia RepertIA.command`); la prima volta macOS
   potrebbe bloccarlo: tasto destro → *Apri* → *Apri*. Al primo avvio installa da solo (serve Homebrew e
   internet) Sleuth Kit, libewf, exiftool, poppler, testdisk (PhotoRec), bulk_extractor e Tesseract.
   Windows: menu Start → RepertIA. Linux: `./RepertIA.sh` (dopo `./installa.sh`).
3. Si apre il browser: **Scegli la copia forense…**, seleziona l'immagine (per gli E01 il
   primo segmento) e premi **Avvia l'analisi**. Hash, partizioni, elenco file, timeline,
   testo dei documenti e metadati vengono fatti in automatico.

Lascia aperta la finestra del Terminale finché lavori: chiudendola si ferma l'interfaccia.

---

## Come si usa

### Casi
Ogni copia forense diventa un caso in `~/CasiForensi/<nome immagine>`. Riscegliendo la stessa
immagine, o cliccando il caso nella pagina iniziale, **il caso si riapre senza rifare nulla**:
indicizzazione, analisi aggiuntive, reperti e conversazioni sono già lì.

### Riaprire un caso già trattato
- Tutti i dati indicizzati sono subito consultabili nella scheda **Risultati**, anche senza
  server LLM e anche senza rifare le operazioni con gli strumenti.
- **Le conversazioni con l'agente sono salvate** nella cartella del caso. Alla riapertura
  riprende l'ultima, con domande, passaggi e risposte: l'agente ricorda il contesto e puoi
  continuare da dove eri rimasto.
- **Nuova conversazione** ne apre una pulita; le precedenti restano in **Conversazioni**, da
  dove puoi riaprirle o eliminarle (restano comunque nel registro `audit_log.jsonl`).
- Se il server LLM non è attivo, RepertIA apre direttamente i Risultati; quando lo avvii,
  **Riprova** nel riquadro *Server LLM* ricollega l'agente senza perdere la conversazione.

### Server LLM su un altro computer
Nel riquadro *Server LLM* scegli **Questo computer** (predefinito: il server viene cercato da solo
sulle porte 8080, 1234 e 11434) oppure **Server in rete**: inserisci l'indirizzo del server
(es. `192.168.1.20`, oppure con la porta `http://192.168.1.20:8080`), se serve la chiave API, e
premi **Collega**. Senza porta vengono provate 8080, 1234 e 11434. La scelta resta salvata
(`~/Library/Application Support/RepertIA/impostazioni.json`) e vale per tutti i casi; si torna
al server locale con un clic su *Questo computer*. Il server deve accettare connessioni dalla rete:
llama-server con `--host 0.0.0.0`, LM Studio con *Serve on Local Network*, Ollama con
`OLLAMA_HOST=0.0.0.0`, e la porta aperta nel firewall. Per una prova: dal Mac apri
`http://INDIRIZZO:PORTA/v1/models` nel browser, deve comparire l'elenco dei modelli.

### Scheda Risultati

| Sezione | Cosa mostra |
|---|---|
| **File System** | Albero della copia a sinistra, contenuto della cartella a destra, con dimensione e date (modifica, creazione, accesso). In cima la **suddivisione del disco** come nella tabella delle partizioni (volumi, spazi non allocati, area della tabella). I file e le cartelle cancellati sono segnati in rosso; i file senza cartella sono in `$OrphanFiles`; lo **spazio non allocato** del file system è in `$Unalloc` (vedi sotto). Filtro per nome, ricerca in tutte le sottocartelle, solo cancellati. |
| **🔎 Ricerca** | Ricerca per **parole chiave** o per **hash** (singolo o lista) in tutti i file della copia, con opzioni e filtri; ogni esito si apre in una scheda a parte e resta salvato (vedi sotto). |
| **File** | Elenco completo dei file, anche cancellati, con ricerca nel percorso ed estensione. |
| **Timeline** | **Grafico a barre dell'attività** e tabella degli eventi (modifica, accesso, metadati, creazione; file system e plaso). |
| **Documenti** | Ricerca di parole e frasi *dentro* i documenti (Word, Excel, PowerPoint, PDF, OpenDocument, RTF, testo, email). Nella vista ad albero la voce si divide **per estensione** (`.docx · Word`, `.xlsx · Excel`, `.pdf · PDF`…, più *E-mail* e *Senza estensione*, con il numero di documenti): un clic mostra solo quella famiglia; lo stesso filtro è il campo *Estensione* della sezione. |
| **Foto e metadati** | Dispositivo, data di scatto, GPS e autori letti con exiftool. |
| **File recuperati** | File recuperati dallo spazio libero con PhotoRec (se eseguito). |
| **Evidenze di interesse** | Email, siti, ricerche, telefoni, GPS trovati da bulk_extractor (se eseguito). |
| **⭐ Preferiti** | Categorie di file create dall'analista (vedi *Preferiti*). |

**Spazio non allocato (`$Unalloc`).** In ogni volume leggibile (non APFS) c'è la cartella virtuale `$Unalloc`: un elemento per ogni tratto contiguo di blocchi che il file system segna come liberi (Sleuth Kit, `blkls`), con nome `Unalloc_<partizione>_<settore iniziale>_<settore finale>`, settori e byte nella copia. Non sono file: possono contenere resti di file cancellati. Si aprono come gli altri elementi in **Testo** (stringhe leggibili ASCII e UTF-16, primi 50 MB) ed **Esadecimale** (tutto il tratto, con ricerca), si **esportano** con SHA-256 in `export/non_allocato/` (anche in una selezione, con `manifest.csv`) e si mettono nei **Preferiti**: nel report compaiono con la posizione in byte e lo SHA-256. I byte si leggono dalla copia forense solo quando servono, nulla viene copiato nel caso. La prima apertura di `$Unalloc` calcola i tratti (su un disco da 1 TB un paio di minuti), poi restano nel caso. Anche le righe **Unallocated** della suddivisione del disco e i volumi che Sleuth Kit non legge si aprono così (Esadecimale, Testo, Esporta, Preferiti). Nel report portatile `$Unalloc` mostra l'elenco dei tratti già calcolati (posizione e dimensione).

**Vista ad albero (predefinita).** Le sezioni sono un albero laterale, con le sottovoci
indentate: file cancellati, timeline del file system e di plaso (con le singole fonti di plaso),
foto con GPS, tipi di file recuperati, tipi di evidenze di interesse, ricerche salvate, categorie
di preferiti e schede aperte. Una sottovoce apre la sezione con il filtro già impostato.
**☰ Vista a schede** passa alle schede orizzontali, **🌲 Vista ad albero** torna all'albero; la
scelta viene ricordata.

**Fuso orario.** In alto, accanto a *Riepilogo*, il selettore **🕒 UTC / Ora italiana / Fuso rilevato** mostra
date e orari in UTC oppure in ora italiana (Europe/Rome, con il passaggio all'ora legale):
elenchi, timeline (anche filtri *Dal/Al* e grafico per giorno), anteprime e interpretazioni delle
date nell'esadecimale. I dati del caso, il registro e `report.md` restano in UTC; il report in PDF
e Word si può salvare con gli orari in ora italiana (lo indica in testa). Lo stesso selettore c'è
nel report portatile (lì i mesi della barra della timeline restano in UTC).

**Plaso e bulk_extractor.** Negli eventi di plaso ci sono i pulsanti **Anteprima**, **⭐ Preferiti**,
**Esadecimale**, **Albero** ed **Esplora file** (Finder sul Mac): il file si ricava dal percorso
dell'evento (registro, evtx, prefetch, cronologia dei browser...), *Esplora file* lo esporta nella
cartella export del caso e lo mostra. Nelle **evidenze di interesse** sotto ogni valore c'è il
**Percorso** del file che lo contiene (cliccandolo si apre nell'albero; altrimenti è indicato se è
spazio non allocato o fuori dalle partizioni); i pulsanti sono **Anteprima** (il file, già
posizionato sul byte dell'evidenza in esadecimale), **⭐ Preferiti**, **Esadecimale** (la copia
forense proprio a quell'offset, anche nello spazio libero), **Albero** ed **Esporta** (esporta il
file nella cartella export del caso e lo mostra).

**Ricerca per parole chiave o hash.** Nella sezione **🔎 Ricerca**:
- **Parole chiave**: una o più parole o frasi (una per riga). Scegli **dove cercare**:
  - *nome del file* e/o *percorso completo* (anche i nomi delle cartelle);
  - *testo dei documenti indicizzati* (Word, Excel, PDF, email, testo: veloce);
  - *metadati* (autore, dispositivo, software, GPS);
  - *contenuto grezzo di ogni file, byte per byte*, in testo normale e/o **UTF-16** (le
    stringhe di Windows): trova la parola anche nei file non indicizzati, nei database e nei
    binari, ma legge tutti i file che rientrano nei filtri, quindi è lento sui dischi grandi.

  **Come confrontare**: *contiene*, *parola intera*, *inizia con*, *uguale* (nome o percorso
  esatto) o *espressione regolare* (es. IBAN `IT\d{2}[A-Z]\d{10}`); distinzione fra maiuscole e
  minuscole facoltativa; *basta una delle parole* oppure *tutte nello stesso file*.
- **Hash**: MD5, SHA-1 o SHA-256, anche misti, incollati o caricati da un file (`.txt`, `.csv`,
  `.md5`, liste di hash noti...): gli hash vengono riconosciuti da soli in qualsiasi formato di
  riga. L'esito dice anche **quali hash della lista non sono stati trovati**.
- **Filtri** (per tutte e due): solo presenti o solo cancellati, estensioni, cartella,
  dimensione, data di modifica, partizione, file recuperati col carving.

**Cosa copre ogni tipo di ricerca (da leggere prima di concludere che una parola "non c'è").**
Le tre scelte non cercano nello stesso modo:

| Dove cerchi | Cosa legge | Cosa può sfuggire |
|---|---|---|
| *testo dei documenti* | l'indice del testo, preparato con *Testo dei documenti e metadati*: è veloce e legge dentro PDF, Word, Excel, PowerPoint, OpenDocument, RTF, email, archivi | i file **non indicizzati o indicizzati solo in parte** (elenco sotto) |
| *contenuto grezzo di ogni file* | i byte di ogni file, anche quelli non indicizzati, in UTF-8 e UTF-16 | il testo dentro formati compressi: PDF, Word, Excel, PowerPoint e archivi **non** si leggono così; è lento |
| *immagine intera* | tutti i byte della copia, anche spazio non allocato e file sovrascritti | il testo compresso, i file frammentati |

Limiti dell'indice del testo, tutti **dichiarati** e non silenziosi:
- **Testi lunghi**: un file viene indicizzato **per intero, a blocchi** (da 200.000 caratteri, con una
  breve sovrapposizione perché una frase a cavallo di due blocchi non si perda), fino a **20 milioni di
  caratteri** per file. Oltre questo tetto il file è segnalato come *indicizzato solo in parte*.
- **PDF**: letti a blocchi di 500 pagine, fino a 20.000 pagine. I PDF di **sole immagini** (scansioni)
  non hanno testo da leggere: sono segnalati e si trattano con l'analisi *OCR*.
- **File grandi** (oltre 50 MB): i file di testo e i log si leggono **in flusso**, senza caricarli in
  memoria; i PDF si copiano su disco e si leggono a blocchi di pagine, fino a **1 GB** (si cambia con
  la variabile d'ambiente `REPERTIA_MAX_FILE_MB`, per esempio `2048`). I documenti Office e gli altri
  formati oltre 50 MB, e i PDF oltre il limite, **non vengono indicizzati** e sono segnalati.
- **Cartelle di sistema** (Windows, Program Files, ProgramData, `/usr`, `/Library`...) sono escluse
  dall'indice del testo di proposito; restano nei nomi, nei metadati e nella ricerca nel contenuto.

**File non indicizzati.** Alla fine dell'indicizzazione RepertIA scrive `non_indicizzati.csv` nella
cartella del caso: un file per riga, con il motivo (file troppo grande, testo parziale, PDF senza
testo, estrazione non riuscita, metadati letti solo dall'inizio). Il numero compare nel riepilogo
dell'analisi, nel report e **sopra i risultati di ogni ricerca nel testo** (⚠ N file non indicizzati);
l'agente lo conosce (`list_not_indexed`) e, se una ricerca non trova nulla, lo dice. Il programma
fa anche un **controllo di coerenza** e avvisa, per esempio, se nessuno dei PDF del caso ha testo
estratto (segno di uno strumento che non funziona), o se non è stato estratto alcun metadato.

**Per essere sicuri di non perdere nulla** in un caso con file non indicizzati: cerca nel *testo dei
documenti*, poi ripeti la ricerca con anche *contenuto grezzo* (filtrando per estensione o cartella
per contenere i tempi); per i PDF e i documenti Office esclusi apri il file e leggilo, oppure alza il
limite con `REPERTIA_MAX_FILE_MB` e ripreparare *Testo dei documenti e metadati*.

La ricerca gira in background con l'avanzamento e si può **interrompere** tenendo i risultati
trovati fin lì. **L'esito si apre in una nuova scheda 🔎** con un file per riga, dove trovato
(nome, contenuto, hash…), i termini, un estratto del testo intorno alla parola (o l'offset nel
file) e gli hash: lì lavori solo su quei file con tutte le funzioni (elenco o miniature,
anteprima ed esadecimale, selezione, *Esporta file* con manifest, CSV, reperto, *Mostra
nell'albero*), con filtri interni (trovato in, termine, solo cancellati). Le ricerche restano in
**Ricerche salvate**, anche riaprendo il caso: *Apri*, *Riusa* (ricarica i parametri), *Elimina*.
Ogni ricerca è annotata nel registro del caso.

**Hash dei file: quando calcolarli.** Calcolare MD5, SHA-1 e SHA-256 di tutti i file significa
leggere ogni file della copia: su una pendrive pochi minuti, su un disco di centinaia di GB anche
ore (dipende soprattutto dalla velocità del disco che contiene la copia). Per questo è una
scelta:
- **prima dell'analisi**: spunta *Calcola gli hash di tutti i file* nella pagina iniziale;
- **dopo**: *Hash dei file → Esegui* nel riquadro *Analisi aggiuntive* (o dal modulo di
  ricerca per hash). Se si interrompe, *Aggiorna* riprende dai file che mancano;
- **solo quando servono**: una ricerca per hash senza hash calcolati li calcola al volo solo
  per i file che rientrano nei filtri (es. solo `jpg` in una cartella) e li conserva per le
  ricerche successive.

Con gli hash calcolati il riepilogo segnala anche i **file con contenuto identico** e l'agente
può cercare per hash.

**Filtri per colonna.** In File System, File, Timeline, Documenti, Foto e metadati, File recuperati,
Archivi e allegati, Copie shadow, Anomalie, Posta, Artefatti, Preferiti e negli esiti delle ricerche, sotto
l'intestazione c'è una riga di filtri, uno per colonna:
- **testo** (nomi, percorsi, tipi, dispositivi, hash, oggetti…): contiene, senza distinguere maiuscole;
  più parole = devono esserci tutte; `-parola` = non deve esserci; le frasi vanno tra virgolette
  (es. `rossi -bianchi "via roma"`);
- **dimensione**: *min* e *max* con unità (`500KB`, `2MB`, `1,5GB`; un numero semplice = byte);
- **data**: *dal* e *al* (inclusi), nel fuso scelto in alto (UTC o ora italiana); per la timeline vale anche
  per il grafico.

I filtri valgono insieme tra loro e con quelli della barra sopra; **Seleziona tutti**, *Esporta file* ed
*Esporta elenco CSV* li rispettano. Ogni sezione ricorda i suoi; **✕ Azzera** li toglie. In File System i
filtri agiscono sulla cartella aperta: per cercare in tutto il sottoalbero spunta *Includi sottocartelle*.
La sezione **File** mostra ora anche dimensione e date (da quelle dell'indice di navigazione). Nella vista
a miniature i filtri restano attivi ma si modificano dalla vista *Elenco*.

**Vista: elenco o miniature.** In File System, File, Documenti, Foto e File recuperati il menu
**Vista** passa fra **☰ Elenco**, **▦ Miniature** e **▣ Miniature grandi** (la scelta viene
ricordata per ogni sezione). Le miniature mostrano le foto, la prima pagina di PDF e documenti
Office e un fotogramma dei video; gli altri file hanno un'icona per tipo. Selezione con le
caselle, Maiusc+clic e "seleziona la pagina" funzionano anche qui.

**Riquadro di anteprima.** Un clic su un file (riga o miniatura) apre a destra il riquadro di
anteprima; si allarga o stringe trascinando il bordo, si chiude con ✕ o Esc, e con le frecce
della tastiera si passa al file successivo o precedente. Ha quattro schede:
- **Anteprima**: il file com'è visivamente.
  - foto (anche HEIC, TIFF, RAW, convertite): clic per passare da adattata a dimensione reale;
  - PDF: tutte le pagine, una sotto l'altra;
  - Word, Excel, PowerPoint, OpenDocument: le pagine impaginate se è installato LibreOffice
    (facoltativo, consigliato); altrimenti su Mac il documento Word convertito con textutil
    o la prima pagina con l'anteprima di sistema (Quick Look);
  - testo, log, CSV, email, codice: il testo;
  - video e audio riproducibili dal browser (mp4, mov, mp3, m4a, wav…);
- **Testo**: il testo estratto (anche da documenti e file binari), **per intero** fino a due milioni
    di caratteri; oltre, la fine lo dice con quanti caratteri mancano. Per i file binari sono le stringhe leggibili;
- **Esadecimale**: il contenuto byte per byte (vedi sotto);
- **Metadati**: SHA-256 del file, date e attributi del file system (istat), metadati exiftool.

Dal riquadro ci sono anche *Mostra nell'albero*, *Esporta*, *Reperto* e *Chiedi all'agente*.

**Vista esadecimale.** Offset, byte in esadecimale e colonna ASCII, a pagine di 4 KB
(◀ ▶ o *Vai a offset*: decimale, `0x…` o relativo `+16`). Si cerca **testo**, **testo
UTF-16** (stringhe Windows) o una **sequenza di byte** (es. `FF D8 FF`, `50 4B 03 04`), con
scorrimento fra le occorrenze. Cliccando un byte (Maiusc+clic per un intervallo, frecce per
spostarsi) l'ispettore mostra: offset, valore e **bit**, interi a 8/16/32/64 bit little e big
endian, float, e la lettura come **data** Unix, Windows FILETIME, DOS/FAT, HFS+, Apple; più il
testo ASCII, UTF-8 e UTF-16. *Copia hex* e *Copia offset* portano i valori negli appunti.

**Mostra nell'albero, in una scheda a parte.** In File, Timeline, Documenti e Foto il
**percorso è cliccabile** (nelle miniature l'icona 📁): si apre una **nuova scheda** con
l'albero già aperto sulla cartella e il file evidenziato. La sezione da cui sei partito resta
com'era (filtri, pagina, punto di scorrimento, selezione): ci torni con la scheda **↩** in alto
a sinistra. Le schede si chiudono con ×; ne restano aperte al massimo otto. Lo stesso vale per i
percorsi citati dall'agente nelle risposte e per *Mostra nell'albero* nell'anteprima.

**Grafico della timeline.** Ogni barra è un giorno (o un mese / anno se il periodo è lungo;
puoi scegliere con *Giorno · Mese · Anno*). Passando sopra una barra vedi quanti eventi e di
che tipo; **cliccandola la tabella sotto mostra solo gli eventi di quel periodo**. Cliccando un
mese il grafico scende ai suoi giorni; *← Tutto il periodo* torna alla vista completa.
I *Periodi più attivi* sono scorciatoie ai picchi. Filtri di testo, tipo di evento e fonte
valgono sia per il grafico sia per la tabella.

**Selezione ed esportazione.** Ogni tabella ha una colonna di caselle:
- clic su una casella per un elemento; **Maiusc+clic** per un intervallo;
- la casella in intestazione seleziona tutta la pagina, poi *Seleziona tutti gli N risultati*
  estende la selezione a tutti i risultati dei filtri attuali (puoi togliere singoli elementi);
- in File System puoi selezionare file di cartelle diverse e anche cartelle intere.

Con la barra della selezione:
- **Esporta file** estrae i file (le cartelle con tutto il contenuto) in
  `export/selezione_<data>/`, **conservando l'albero delle cartelle originale**, in sola
  lettura, con `manifest.csv`: percorso originale, offset, inode, cancellato sì/no, byte e
  SHA-256 di ogni file. Le esportazioni compaiono nel report.
- **Esporta elenco CSV** salva le righe selezionate in `export/elenchi/` (separatore `;`, si
  apre con Excel o Numbers).
- **Reperto** registra un reperto con i riferimenti degli elementi scelti.
- **Chiedi all'agente** prepara una domanda sugli elementi selezionati.

Da ogni riga restano disponibili anche *Anteprima*, *Esporta*, *Reperto*, *Chiedi* e, per le
tracce, *Dove si trova* (in File System: *Anteprima* ed *Esporta*; reperto e domanda si fanno dalla
barra della selezione o dal riquadro di anteprima).

### Interfaccia
- **Tema chiaro / scuro**: pulsante ☾ / ☀ in alto a destra (la scelta viene ricordata).
- **◧** accanto al nome del caso nasconde o mostra il pannello laterale, per avere più spazio.
- La larghezza dell'albero si regola trascinando il suo angolo in basso a destra.
- Quando apri l'anteprima il pannello del caso si nasconde da solo per fare spazio e ricompare
  quando la chiudi.

### Lingua (italiano / inglese)
- **Interfaccia**: selettore in alto a destra (*Italiano* / *English*); la scelta si ricorda nelle impostazioni e la
  pagina si ricarica. Su Windows la prima volta vale la lingua scelta nell'installazione.
- **Testi del caso**: artefatti, riepiloghi, report (Markdown, Word, PDF) e report portatile sono nella **lingua del
  caso**, scelta nel modulo del nuovo caso (*Lingua dei testi del caso*) e salvata in `case.json`. Cambiare la lingua
  dell'interfaccia non cambia i testi già prodotti; i casi delle versioni precedenti sono in italiano. La lingua del
  caso è indicata nell'elenco dei casi e nella sezione *Ambiente di analisi* del report.
- Cambia solo il **testo**: dati, hash, percorsi, nomi dei file, date e i valori letti dal disco restano identici.
- Il collaudo si esegue in entrambe le lingue: `forense_collaudo.py <cartella> --lingua en`.
- Da terminale: `prepara ... --lingua en`; la variabile `REPERTIA_LINGUA` imposta la lingua del processo.
- Traduzioni: `src/lingua_en.json` (testo italiano → traduzione), incluso nell'impronta del programma;
  `python3 tools/lingua_controlla.py` segnala testi senza traduzione o con segnaposto diversi.

### Pannello del caso
Supporto, hash e ultima verifica, partizioni, stato del server LLM, pulsanti **Report** (anche
in **PDF** e **Word** .docx: `report.pdf` e `report.docx` nella cartella del caso, con lo SHA-256
nel registro), **Report portatile**,
**Verifica hash** (o **Calcola hash copia** se l'hash non è ancora stato calcolato), **Cartella caso**, **File esportati**, le **Analisi aggiuntive** da
eseguire o rifare e i **Reperti** registrati.

---

## Preferiti (categorie di file)

Nei Risultati seleziona i file con le caselle a sinistra (anche cartelle intere, con tutto il
contenuto) e premi **⭐ Preferiti**, oppure **⭐ Preferiti** sulla riga di un file (dopo
*Anteprima*) o nel riquadro dell'anteprima: scegli una categoria esistente o scrivi un nome nuovo, con
una nota facoltativa. La sezione **⭐ Preferiti** elenca le categorie (rinomina, descrizione,
elimina) e ognuna si apre in una scheda a parte, con anteprima, esportazione, reperto e
*Togli dalla categoria*. Le categorie con **«nel report»** spuntato entrano nel report (tabella
per categoria con offset, inode, stato, date, SHA-256 e nota) e nel report portatile, con il contenuto
e le anteprime complete dei loro file. I preferiti stanno nel caso (`ricerche.sqlite`) e ogni
operazione è registrata in `audit_log.jsonl`.

## Report portatile (per chi non ha la copia forense)

Dal pannello del caso, **Azioni → Report portatile** crea in `export/report_portatile_<data>/` una
cartella con `index.html` da consegnare (anche zippata): si apre con un doppio clic in qualsiasi
browser, **offline**, senza RepertIA, senza la copia forense e senza IA.

- **Contiene tutto il catalogo**: albero del file system con i file cancellati, date, dimensioni,
  hash (se calcolati), metadati (dispositivo, data, GPS, autore), testi estratti dei documenti,
  timeline (file system e plaso), file recuperati e tracce, reperti e report.
- **Contenuto dei file**, a scelta: solo i file dei reperti e delle selezioni esportate con
  *Esporta*; anche tutti i documenti e le immagini fino a una dimensione; oppure **tutti i file
  del supporto** (anche cancellati, a scelta), così chi riceve il report consulta tutto come se
  avesse la copia forense. La finestra mostra prima numero di file, dimensione e spazio libero.
  I file sono nella cartella `file/` con l'albero originale. Per reperti e selezioni: pagine di
  PDF e documenti Office (con LibreOffice) come immagini, esadecimale, exiftool e istat; per gli
  altri file anteprime più leggere (prime pagine dei PDF, primi 4 KB in esadecimale, metadati già
  indicizzati) e il pulsante *Apri il PDF originale*.
- **Analisi estese**, se eseguite: sezioni *Artefatti di sistema*, *Posta* (messaggi con
  allegati), *Archivi e allegati* e *Anomalie*, con esportazione CSV. I file estratti da
  archivi e posta sono inclusi secondo la stessa scelta del contenuto dei file.
- La creazione mostra una **barra di avanzamento** con percentuale, fase e tempo stimato.
- La **ricerca nel contenuto** copre il testo dei documenti indicizzati e, per tutti gli altri
  file inclusi, le stringhe leggibili (ASCII e UTF-16) estratte alla creazione; foto, video e
  audio si cercano nei metadati. Nel browser la ricerca scorre l'indice a blocchi, con
  avanzamento e pulsante *Interrompi*.
- **Preferiti anche nel report portatile**: chi lo riceve vede le categorie create in RepertIA e
  può crearne di sue, selezionando i file in qualsiasi elenco (caselle, Maiusc per intervalli) o
  con ⭐ nell'anteprima; restano nel suo browser. **Esporta preferiti** li salva in un file JSON
  che un altro analista carica con **Importa** nello stesso report.
- **Esporta CSV** in ogni elenco (cartella, ricerca, timeline, metadati, file inclusi,
  recuperati, evidenze di interesse, preferiti, selezione) e **📄 Nuovo report** in **PDF** (finestra di stampa
  del browser), **Word** (.docx) o **HTML**: dati del caso, reperti, categorie di preferiti scelte
  (con miniature, date, SHA-256 e note), note e, a scelta, il report completo.
- Ogni elenco (File system, ricerca, timeline, metadati, file recuperati, tracce, posta, anomalie, preferiti) ha la
  stessa **riga di filtri per colonna** del programma (testo, dimensione min/max, date dal/al); «✕ filtri» li azzera.
- Chi lo riceve può **navigare, cercare** (nome, contenuto, metadati, hash anche da lista),
  scorrere la **timeline** per mese e giorno e aggiungere **note** ai file (restano nel suo
  browser; si esportano in JSON o CSV e si reimportano).
- **Sicurezza**: il contenuto delle prove non viene mai eseguito né interpretato come pagina
  web; HTML, script e documenti attivi si vedono come testo o immagini.
- **Integrità**: `impronte.csv` ha lo SHA-256 di ogni file del report; l'impronta di
  `impronte.csv` (in `IMPRONTA_REPORT.txt` e nella finestra finale) va comunicata a chi riceve
  il report ed è registrata in `audit_log.jsonl`.

## Analisi aggiuntive

- **Hash dei file** (facoltativo): MD5, SHA-1 e SHA-256 di ogni file, anche cancellato, per
  confronti con liste di hash noti e ricerca dei duplicati. Riprende da dove si era fermato.
- **Testo e metadati** (sempre, in automatico): testo dei documenti anche cancellati ma ancora
  leggibili; metadati di foto, video e documenti con exiftool. Le cartelle di sistema sono
  escluse.
- **Timeline plaso** (facoltativa): registro, prefetch, log, browser; sui Mac anche FSEvents e altri
  artefatti di macOS. Utile per i dischi di sistema. È inclusa nell'app (Mac) e nell'installazione
  (Windows); su Linux la installa `installa.sh`: Docker serve solo se si avvia RepertIA dai sorgenti senza plaso. Può durare ore. Dalla 2.14,
  se nel caso c'è un volume APFS cifrato sbloccato, plaso riceve la stessa chiave (solo in memoria, mai nel
  registro: lì compare `password:***`) e analizza anche quel volume.
- **Carving** (facoltativo): PhotoRec recupera file dallo spazio libero in `<caso>/carving`;
  bulk_extractor cerca tracce in tutto il disco e sa dire a quale file appartengono.
  Se il PhotoRec installato non legge NTFS (succede con quello di Homebrew), lo spazio non
  allocato viene prima estratto con Sleuth Kit (`blkls`) e PhotoRec lavora solo su quello: così
  non vengono recuperati anche i file ancora presenti. Gli offset riportati sono sempre quelli
  dell'immagine.

### Analisi estese (novità 2.5)

- **Archivi e posta** (attiva per default): apre ZIP, RAR, 7z, tar/gz e gli archivi annidati
  con 7-Zip; legge le caselle di posta PST/OST (Outlook), MSG, EML/EMLX e mbox (anche
  Thunderbird senza estensione). Messaggi e allegati compaiono nelle sezioni *Posta* e
  *Archivi e allegati*, entrano nella ricerca e nella chat. I file estratti finiscono in
  `<caso>/estratti/` in sola lettura, con MD5, SHA-1 e SHA-256, e con il percorso di origine
  (archivio → file interno). Gli archivi protetti da password vengono segnalati.
- **Anomalie** (attiva per default): estensione che non corrisponde al contenuto (es. un JPEG
  chiamato `.txt`), documenti Office, PDF e ZIP cifrati, contenitori ad alta entropia
  (possibili volumi VeraCrypt/TrueCrypt), volumi BitLocker, LUKS, FileVault e APFS cifrati.
  Dalla 2.17.2 i **file cancellati** si segnalano solo se il contenuto letto è ancora il loro: se il record
  (inode, MFT) è stato dato a un altro file o i cluster sono stati riscritti, la voce non è un'anomalia (era
  il caso dei «PNG che sono eseguibili») e il riepilogo dell'analisi dice quante voci sono state escluse e perché.
  Dalla 2.17.3 la verifica è più severa: su NTFS una passata sulla MFT controlla che i cluster del file
  cancellato non compaiano nelle runlist di nessun altro record, nemmeno di un altro file cancellato dopo; e il
  contenuto deve essere coerente con la dimensione e la fine del file (un JPEG finisce con FF D9, un PDF con
  `%%EOF`, uno ZIP con la directory centrale, le scatole di un MP4 arrivano esattamente alla fine, un eseguibile
  finisce dove dicono le sue sezioni o la sua firma digitale). Non sono anomalie i moduli di programmi con
  estensione propria (`.odf` di Office, `.mpp`/`.api` di Adobe, filtri `.8bf`…), gli eseguibili nelle cartelle
  dei programmi e di Windows con estensioni non «da utente», le icone degli installatori (`Windows\Installer\{…}\*.ico`)
  e i log del registro (`BCD.LOG`). Un eseguibile dentro una foto, un video, un PDF o un documento resta di gravità alta.
  Un formato diverso in un file dall'estensione generica (`.dat`, `.bin`, `.db`, `.tmp`…) non è un'anomalia;
  uno scambio tra formati immagine (JPEG/PNG/WebP…) o tra foto e video è una nota di gravità bassa.
- **Artefatti di sistema** (attiva per default), in schede riassuntive:
  Windows — nome computer, fuso orario, ultimo spegnimento, utenti (SAM, con i file di log
  del registro applicati: vedi *Aggiornamenti*, 2.17.2; accessi contati anche dai registri eventi
  `Security.evtx` e `System.evtx`, 2.17.3), programmi installati
  ed esecuzione automatica, dispositivi USB collegati (con orari), reti Wi‑Fi note, UserAssist,
  documenti recenti, percorsi digitati, ricerche in Esplora file, Prefetch, Amcache,
  collegamenti `.lnk` e jump list, cestino; dalla 2.18 anche **cartelle aperte (ShellBags** di NTUSER.DAT e
  UsrClass.dat, comprese chiavette e dischi non più collegati), **ShimCache** e **BAM/DAM** (programmi visti ed
  eseguiti), **SRUM** (uso delle app e traffico di rete per app e utente), **Cronologia attività** (ActivitiesCache.db,
  anche il testo copiato negli appunti se sincronizzato), **journal NTFS** `$UsnJrnl` (file creati, cancellati e
  rinominati con data, anche se il record MFT è stato riutilizzato), **registri eventi** (servizi installati, accensioni
  e spegnimenti, sessioni e Desktop remoto con indirizzo, rilevamenti e disattivazioni di Defender, dischi USB collegati,
  registri cancellati) e **miniature** della cache di Esplora file (`thumbcache_*.db`, estratte tra i file estratti:
  restano anche dopo la cancellazione delle immagini). Tutte le **installazioni di Windows** del disco (anche
  `Windows.old`) si analizzano separatamente: i loro artefatti hanno il nome della cartella tra parentesi quadre;
  browser Chrome, Edge, Firefox e Safari (cronologia,
  download, ricerche); Linux (utenti, rete, cronologia della shell); macOS (vedi *Mac con APFS*:
  dalla 2.14 anche il volume Dati e gli artefatti principali).
- **Copie shadow (VSS) e snapshot APFS** (facoltativa): elenca le copie shadow di Windows e, dalla 2.14,
  gli **snapshot dei volumi APFS** (per esempio gli snapshot locali di Time Machine e i backup di Time
  Machine su dischi APFS) e recupera i file presenti in una copia ma cancellati o diversi nel disco
  attuale. Gli snapshot si leggono con Sleuth Kit (`fsstat`/`fls`/`icat -S`); il volume di sistema
  sigillato si salta (il suo snapshot è macOS stesso); per un volume cifrato serve la password
  dell'utente.
- **OCR** (facoltativa): con Tesseract (italiano e inglese) legge il testo di foto,
  scansioni e PDF senza testo, che diventa cercabile.
- **Hash percettivi** (facoltativa, dalla 2.18): calcola un hash «percettivo» (dHash a 64 bit) di ogni
  immagine (file della copia anche cancellati, file estratti, miniature, carving). Nell'anteprima di un'immagine
  *Immagini simili* trova le altre immagini del caso uguali all'occhio anche se ridimensionate o ricompresse
  (non ritagliate o ruotate): sono indizi da verificare a vista.
- **Liste di hash / NSRL**: dal riquadro del caso, *Liste di hash* carica liste di hash noti
  (file di testo, CSV, database SQLite NSRL RDS, **JSON Project VIC (VICS) / CAID** con la categoria, dalla
  2.18). I file *noti buoni* si possono nascondere nel File System; quelli in una lista *da segnalare*
  compaiono tra le anomalie. Richiede gli hash dei file. Dalla 2.18 una lista può essere anche una **cartella
  di immagini di riferimento**: le immagini del caso simili (hash percettivo) vengono segnalate con la
  distanza, gravità alta se quasi identiche (serve prima *Hash percettivi*).
- **Volumi cifrati**: se il disco è BitLocker, LUKS1 o FileVault e si conosce la password o
  la chiave di ripristino, *Decifra il volume* crea una copia decifrata nella cartella
  `<caso>/decifrata/` (con SHA-256 e il riferimento alla copia originale) e un nuovo caso su
  di essa. L'originale non viene toccato. LUKS2 viene riconosciuto ma non decifrato. I volumi
  **APFS cifrati** (FileVault dei Mac recenti) si sbloccano in un altro modo, senza copie: vedi
  *Mac con APFS* qui sotto.
- **Ricerca nei byte grezzi**: nella ricerca, l'opzione *Immagine intera* cerca il testo in
  tutto il disco, spazio non allocato e slack compresi, e dice a quale file appartiene ogni
  risultato quando è possibile.

Si attivano alla creazione del caso oppure dopo, dal riquadro *Analisi aggiuntive*, senza
perdere la conversazione. **Un E01 non viene più convertito in raw** (dalla 2.10): Sleuth Kit,
bulk_extractor e plaso lo leggono direttamente, e per il carving PhotoRec riceve solo lo spazio non
allocato in un file temporaneo *compatto* (vedi «Spazio su disco» sotto).

**plaso** è già incluso nell'app per Mac e nell'installer per Windows. Solo se si usa RepertIA dai
sorgenti senza plaso installato serve Docker Desktop con l'immagine `log2timeline/plaso`
(`docker pull log2timeline/plaso`); con la copia su disco esterno: *Docker Desktop → Settings →
Resources → File sharing* deve contenere `/Volumes`.

---

### Mac con APFS (novità 2.13)

The Sleuth Kit non legge APFS, il file system dei Mac recenti. Da questa versione RepertIA legge i
**contenitori APFS** con **libfsapfs** (`forense_apfs.py`), sempre in sola lettura e direttamente dalla
copia (raw o E01), senza creare copie.

- **Un volume APFS = una «partizione» del caso** (Macintosh HD, Data, Preboot, Recovery, VM…). Nell'albero
  compare come *Volume APFS «nome»*; elenco file, filtri, timeline, hash, indice del testo, anteprime, report
  portatile e analisi estese funzionano come per gli altri file system. Il numero di partizione interno
  (offset) è sintetico: offset del contenitore + (n. volume + 1) × 2⁴⁰ settori.
- **inode** = identificatore APFS del file (unico dentro il volume). La scheda *Metadati* mostra le date con
  i **nanosecondi** (creazione, modifica, cambio metadati, accesso, aggiunta alla cartella), permessi, uid/gid,
  collegamenti, destinazione dei link simbolici, **posizione fisica dei dati** nel contenitore e nella copia e
  gli **attributi estesi** (es. `com.apple.quarantine`, `com.apple.metadata:kMDItemWhereFroms`).
- **Volumi cifrati (FileVault)**: si sbloccano con la **password dell'utente** o la **chiave di ripristino**
  (XXXX-XXXX-XXXX-XXXX-XXXX-XXXX). Se il caso nasce con un volume cifrato, la preparazione si ferma con
  «VOLUME CIFRATO»: premi *Decifra / sblocca il volume…*, scrivi la chiave e la preparazione riparte. Se solo
  alcuni volumi sono cifrati, il caso si prepara con gli altri e il volume cifrato si aggiunge dopo da
  *Decifra…* (viene elencato in quel momento). Aprendo un caso con un volume cifrato già elencato, un avviso
  chiede di sbloccarlo per leggerne i **contenuti** (l'elenco dei file è già nel caso).
  **La chiave non viene mai scritta** nel caso, nei registri né su disco: resta solo in memoria finché
  RepertIA è aperto (da terminale: variabile `REPERTIA_APFS_SECRETS`, oppure viene chiesta senza mostrarla).
  Nel registro compare solo il tipo di credenziale usato.
- **Limiti da conoscere**:
  - **Mac con chip T2 o Apple Silicon**: il volume Dati di una copia *fisica* è protetto da chiavi legate
    all'hardware; la sola password non basta e fuori dal Mac non si decifra. Serve un'acquisizione logica
    del volume Dati fatta sul Mac acceso e sbloccato.
  - **File cancellati**: libfsapfs non li recupera: tutte le voci risultano non cancellate. Il carving
    (PhotoRec / bulk_extractor) lavora sull'immagine intera, non sullo spazio non allocato di APFS. Dalla
    2.14 i file cancellati ma ancora presenti in uno **snapshot** si recuperano con *Copie shadow e snapshot*.
  - Volumi *Fusion* non sono esplorati.
  - La **localizzazione di un file da un offset in byte** (tracce, carving) non è disponibile per APFS.
  - **Artefatti macOS (2.14)**, in *Artefatti*, letti dal volume Dati (o dal volume unico dei Mac più vecchi):
    account, nome del computer, ultimo utente, utente ospite, fuso scelto; reti Wi‑Fi; programmi installati
    e storico delle installazioni; **download in quarantena** (ogni file scaricato o ricevuto con URL, pagina
    e programma); **avvio automatico** (LaunchAgents/LaunchDaemons non Apple, elementi di login di macOS 13+);
    **permessi TCC** (accesso completo al disco, fotocamera, microfono, schermo…); **iMessage/SMS** da
    `chat.db`, compresi i messaggi ancora solo nel file `-wal` e il testo salvato come `attributedBody`
    (macOS 13+), con contatto, verso e allegati; **documenti, cartelle e app recenti** (`.sfl2/.sfl3` e
    cartelle recenti del Finder); download di Safari; **uso delle app** (knowledgeC.db, fino a macOS 13);
    dispositivi Bluetooth e volumi esterni visti dal Finder; **Time Machine** (dischi di backup e date);
    cronologia della shell; cronologia dei browser.
    Non letti direttamente: **FSEvents** e **log unificato** (li legge plaso, se eseguito), Biome (macOS 14+),
    portachiavi; i collegamenti USB dei Mac stanno solo nel log unificato.
  - **Fuso del Mac (2.14)**: letto da `/private/etc/localtime` o da `.GlobalPreferences.plist`, per la
    modalità «Fuso rilevato».
  - **Collaudo**: provato su immagini APFS di prova (non cifrata e cifrata con password, raw ed E01) e su una
    struttura sintetica del volume Dati; non ancora su un E01 reale di un Mac recente (volume di sistema
    sigillato, volume Dati, FileVault). Il percorso unito «firmlink» di macOS non viene ricostruito: Dati e
    Sistema restano volumi separati (nel volume Dati i percorsi sono quelli reali: `Users/…`, `private/var/…`).

---

## Cosa utilizza

| Componente | A cosa serve |
|---|---|
| **The Sleuth Kit** (`mmls`, `fsstat`, `fls`, `icat`, `istat`, `img_stat`) | partizioni, file system, elenco dei file anche cancellati, lettura dei file in sola lettura, timeline del file system |
| **libewf** (`ewfexport`) | lettura e conversione delle immagini E01 |
| **exiftool** | metadati di foto, video e documenti (dispositivo, data di scatto, GPS, autori) |
| **poppler** (`pdftotext`, `pdftoppm`, `pdfinfo`) | testo dei PDF; pagine e miniature dei PDF come immagini |
| **sips**, **Quick Look** (`qlmanage`), **textutil** — inclusi in macOS | miniature e conversione delle foto (HEIC, TIFF, RAW), anteprime di Office/Pages/video, Word in HTML |
| **LibreOffice** (facoltativo) | anteprima a pagine di Word, Excel, PowerPoint e OpenDocument |
| **ImageMagick**, **ffmpeg** (facoltativi) | alternative per immagini e fotogrammi dei video (usati se presenti, utili su Linux) |
| **PhotoRec** (testdisk) | recupero di file dallo spazio non allocato |
| **bulk_extractor** | tracce (email, URL, ricerche, telefoni, GPS, carte) in tutta l'immagine |
| **plaso** (`log2timeline`, `psort`), incluso (Docker solo in alternativa) | timeline degli artefatti di sistema |
| **7-Zip** (`7zz` / `7z.exe`) | apertura degli archivi (ZIP, RAR, 7z, tar, gz, …) |
| **libyal** (libpff, libolecf, libregf, libscca, liblnk, libvshadow, libbde, libluksde, libfvde, **libfsapfs**) | posta Outlook, registro di Windows, Prefetch, collegamenti, copie shadow, volumi cifrati, **volumi APFS dei Mac (anche cifrati)** |
| **Tesseract OCR** | testo di foto e scansioni |
| **Python 3** (libreria standard) + **SQLite** con ricerca full-text FTS5 | motore del programma, indici e ricerche |
| **client `openai`** per Python | solo come client verso il server LLM *locale* (stesso protocollo) |
| **LM Studio / llama-server / Ollama** | il modello linguistico, eseguito sul Mac |

L'interfaccia è una pagina HTML/JavaScript senza librerie esterne, servita dal programma
stesso. I file principali sono:

- `forense_agent.py` — preparazione del caso, strumenti dell'agente, report (anche da terminale);
- `forense_gui.py` — server locale dell'interfaccia, albero, timeline, selezioni, esportazioni,
  conversazioni salvate;
- `forense_gui.html` — l'interfaccia;
- `forense_estesa.py` — analisi estese: archivi, posta, anomalie, artefatti, VSS, OCR, liste di hash, volumi cifrati;
- `forense_apfs.py` — volumi APFS dei Mac (libfsapfs), anche cifrati;
- `forense_collaudo.py` — collaudo con le immagini di riferimento (2.14);
- `forense_riscontro.py` — riscontro con l'elenco file/hash di un altro strumento (2.15);
- `Avvia RepertIA.command`, `Aggiorna strumenti.command` — lanciatori per macOS.

---

## Cartella del caso

| File / cartella | Contenuto |
|---|---|
| `case.json` | immagine, hash, partizioni, versioni degli strumenti, analisi eseguite |
| `caso.sqlite` | elenco file, timeline, testo dei documenti, metadati, tracce, hash dei file |
| `non_indicizzati.csv` | file il cui testo non è nell'indice o solo in parte, con il motivo (si aggiorna a ogni indicizzazione) |
| `ricerche.sqlite` | ricerche salvate e i loro risultati |
| `navigazione.sqlite` | indice dell'albero per la sezione File System (si ricrea da solo se manca) |
| `cache/` | copie dei file aperti in anteprima o in esadecimale, miniature, pagine e conversioni; si ricrea da sola: puoi cancellarla quando vuoi per recuperare spazio |
| `conversazioni/` | conversazioni con l'agente, una per file |
| `findings.json` | reperti registrati |
| `audit_log.jsonl` | registro completo di comandi eseguiti, domande, risposte e risultati degli strumenti, a catena di hash (2.14) |
| `export/` | file esportati (singoli e `selezione_*/` con `manifest.csv`) ed `elenchi/` CSV |
| `carving/` | file recuperati con PhotoRec e risultati di bulk_extractor |
| `report.md` | report generato con il pulsante *Report* |

---

## Garanzie per l'attività forense

- La copia forense è sempre aperta in **sola lettura**; l'hash SHA-256 dell'originale (anche
  di tutti i segmenti E01) è calcolato alla creazione del caso e si riverifica con
  *Verifica hash*.
- **Hash dei dati acquisiti (2.14).** Oltre allo SHA-256 dei *file* della copia, RepertIA calcola MD5,
  SHA-1 e SHA-256 dei *dati* del supporto originale (per l'E01 il contenuto decompresso, letto con
  libewf) e li confronta con l'hash registrato dal programma di acquisizione: quello scritto
  **nell'E01** (FTK Imager, EnCase, Guymager, ewfacquire…) o nel **log di acquisizione** accanto
  all'immagine (FTK Imager `.txt`, Guymager `.info`, `.log`, `.md5/.sha1/.sha256`). L'esito
  (*corrisponde*, *DIVERSO*, *nessun hash di acquisizione*) è nel pannello del caso (riga
  *Acquisizione*), nel report, nel report portatile e nel registro; nel report compaiono anche i dati
  di acquisizione registrati nell'E01 (operatore, numero del caso e del reperto, programma, date,
  modello e numero di serie del supporto). *Verifica hash* ricontrolla file e dati. Il calcolo dei dati
  legge di nuovo tutta la copia (si può escludere con `REPERTIA_VERIFICA_DATI=0`).
- **Registro a prova di manomissione (2.14).** Ogni riga di `audit_log.jsonl` contiene il numero
  progressivo (`n`) e lo SHA-256 della riga precedente (`prev`): una riga modificata, tolta o inserita
  rompe la catena. *Verifica hash* controlla anche la catena; il report riporta lo stato e l'hash
  dell'ultima riga, che fissa il registro a quel report. I registri dei casi precedenti alla 2.14
  restano validi: la catena parte dalla prima riga scritta con la 2.14.
- **Ambiente di analisi (2.14).** Il caso registra alla preparazione, e il report riporta, la versione
  di RepertIA, l'**impronta del programma** (SHA-256 dei suoi file) e le versioni di tutti gli strumenti
  e librerie (Sleuth Kit, libewf, libfsapfs, exiftool, plaso, 7-Zip, Tesseract, Python…); se tra la
  preparazione e il report sono cambiati, il report lo dice.
- **Collaudo (2.14, immagini pubbliche dalla 2.15).** `Collaudo RepertIA.command` (Mac) o *Collaudo* nel menu
  Start (Windows), con la cartella `RepertIA-collaudo` (zip a parte), prepara un caso per ognuna delle immagini
  di riferimento e confronta i risultati con i valori attesi. Due gruppi, tenuti distinti nel rapporto:
  - **immagini pubbliche DFTT** (Digital Forensics Tool Testing, dftt.sourceforge.net, licenza GPL, incluse
    nello zip): i valori attesi sono **quelli pubblicati dal progetto**, non scelti da RepertIA, e ogni immagine
    è riconosciuta dal suo MD5 pubblicato. Provano: date FAT con l'ora legale (5), file cancellati su FAT (6) e
    NTFS anche residenti, ADS e frammentati (7), JPEG con estensione sbagliata, cancellati, in archivi ZIP e
    tar.gz e in un ADS (8), carving di un FAT32 con settore di avvio danneggiato, controllando MD5 **e offset**
    pubblicati (11). Sono queste le prove da citare;
  - **immagini preparate per RepertIA** (E01 integro e alterato, raw con log FTK, struttura di un Mac, APFS e
    BitLocker di dfvfs): controllano le funzioni che le immagini pubbliche non coprono; valgono come controllo
    interno.
  Le voci **«misura»** sono limiti noti che nessuno strumento basato sul file system supera per intero (file
  frammentati cancellati su FAT, carving di file danneggiati): sono riportate
  con il loro esito ma non contano. Il rapporto `collaudo_<data>.md` (in `CasiForensi/_collaudo/`) con
  versione, impronta e strumenti si allega come documentazione. Per aggiungere altre immagini (es. NIST
  CFReDS): un file `atteso_<nome>.json` nella cartella con i valori pubblicati e l'MD5 dell'immagine.
  Da terminale: `python3 forense_collaudo.py <cartella di collaudo>`.
- **Riscontro con un altro strumento (2.15).** *Riscontro con altro strumento* nel pannello del caso confronta
  i file del caso con l'elenco esportato da un secondo strumento sulla **stessa copia**: Autopsy (*Save table as
  CSV*), FTK Imager (*Export File Hash List* o *Export Directory Listing*), X-Ways, EnCase, AXIOM (CSV con
  percorso e hash), Sleuth Kit (`fls -r -m / -h`). Il formato si riconosce da solo. Risultato: file con hash
  uguale (conferma indipendente: ciascuno strumento ha letto la copia per conto suo), con hash **diverso**,
  presenti solo in uno dei due, stato «cancellato» o dimensione discordanti. L'esito va nel report (sezione
  *Riscontro con altri strumenti*, con lo SHA-256 del file esterno) e nel registro; il dettaglio riga per
  riga in `riscontri/` nel caso. Da terminale: `forense_agent.py riscontro --case CASO --file elenco.csv
  --strumento "Autopsy 4.21"`. È il modo consigliato di riscontrare i reperti prima di usarli.
- **Analisi speditiva**: togliendo *Calcola subito lo SHA-256 della copia forense* nella pagina
  iniziale l'analisi parte senza attendere il calcolo dell'hash, che si fa dopo dal pannello del
  caso con **Calcola hash copia** (da terminale `--no-hash`, poi `--aggiungi immagine`). Il
  report riporta data e ora del calcolo e che è avvenuto dopo l'avvio dell'analisi; finché non è
  calcolato, il report lo segnala come mancante.
- Ogni comando, domanda e risposta è registrato in `audit_log.jsonl`.
- Le password e le chiavi di ripristino dei volumi cifrati **non vengono mai salvate** (né nel caso né nei registri): restano in memoria durante la sessione.
- I file esportati sono in sola lettura, con SHA-256 calcolato durante l'estrazione.
- Anteprime ed esadecimale lavorano su una copia del file estratta con `icat` in `cache/`
  (in sola lettura), mai sulla copia forense; la scheda Metadati ne mostra lo SHA-256.
- Gli orari sono in **UTC**; su FAT/exFAT sono spesso l'ora locale del dispositivo.
- L'agente distingue fatti e ipotesi, ma **ogni reperto va verificato dall'analista** con gli
  strumenti forensi prima di essere usato.

---

## Aggiornamenti

Nulla si aggiorna da solo, di proposito: ogni caso registra le versioni degli strumenti usati.
Per aggiornare, tra un caso e l'altro e con internet: Mac `Aggiorna strumenti.command`, Windows *Aggiorna strumenti*
nel menu Start, Linux `./aggiorna-strumenti.sh`; mostrano le versioni prima e dopo.

**Versione 2.19.0 – pacchetto Linux (sperimentale)** - Nuovo pacchetto **`RepertIA-2.19.0-Linux.tar.gz`** per Linux x86_64 con Python 3.12 o successivo (Ubuntu 24.04+, Debian 13). Il programma non cambia: stessi file e stessa impronta dei pacchetti Mac e Windows 2.19.0. `installa.sh` installa con apt Sleuth Kit, libewf, PhotoRec, Poppler, ExifTool, Tesseract e zenity, crea in `python/` l'ambiente con plaso, libyal, pytsk3, Pillow e openai alle stesse versioni degli altri pacchetti (`requirements-linux.txt`) e aggiunge RepertIA al menu; `RepertIA.sh` avvia, `collaudo.sh` esegue il collaudo, `aggiorna-strumenti.sh` aggiorna gli strumenti di sistema. Inclusi 7-Zip 26.01 per Linux e i dati OCR. **Prova:** nell'ambiente Linux di sviluppo collaudo 112/112 in italiano e 112/112 in inglese, caso con plaso, analisi estese e OCR, interfaccia nel browser. **Non provato:** `installa.sh` su un computer reale (apt e PyPI), bulk_extractor, zenity, il client openai.

**Versione 2.19.0** - Interfaccia e testi del caso **in italiano o in inglese**. Selettore della lingua in alto a destra (la pagina si ricarica); nel modulo del nuovo caso si sceglie la **lingua dei testi del caso** (artefatti, riepiloghi, report Markdown/Word/PDF, report portatile, CSV esportati), salvata in `case.json` e indicata nell'elenco dei casi e nel report (*Ambiente di analisi*); i casi precedenti restano in italiano. Cambia solo il testo: dati, hash, percorsi e valori letti dal disco non cambiano. Tecnica: i testi restano in italiano nei sorgenti e fanno da chiave (`tr()` nel Python, `T()`/`TF()` nelle pagine) del dizionario `lingua_en.json` (2.400 testi), incluso nell'impronta del programma; nuovo `tools/lingua_controlla.py` per i controlli; date e numeri delle pagine nel formato della lingua. **Collaudo** con `--lingua it|en` (in inglese accetta i titoli attesi tradotti). **Windows**: installer bilingue (scelta della lingua all'avvio, che diventa quella predefinita di RepertIA), `README_EN.txt` accanto a `LEGGIMI.txt`; nel Mac `README_EN.txt` nello zip. Il modello linguistico riceve le istruzioni e risponde nella lingua dell'interfaccia. **Prova:** collaudo 112/112 in italiano e 112/112 in inglese sul Mac; interfaccia e report portatile in inglese controllati sezione per sezione su un caso di prova. Collaudo eseguito anche su Windows. Il manuale e VALIDAZIONE.md restano in italiano.

**Versione 2.18.1** - Correzioni di affidabilità su journal NTFS e registri eventi. **Journal NTFS: percorsi con il numero di sequenza.** La cartella di un'operazione si cercava solo per numero di record MFT: se quel record era stato riutilizzato da un'altra cartella, il file risultava nella cartella sbagliata (percorso plausibile ma falso). Ora il riferimento è completo (record e sequenza): il percorso attuale della MFT vale solo se il record è ancora quella cartella (sequenza uguale, o aumentata di 1 se il record è libero); altrimenti si usa il nome registrato nel journal per quel riferimento, altrimenti «cartella MFT n sequenza s: record poi riutilizzato da …». A parità di record vince la voce presente su quella cancellata. **Journal: limite e stato dichiarati.** Oltre 500.000 operazioni si tengono le più recenti e la nuova voce di sistema «Journal NTFS $UsnJrnl letto» dice quante, il periodo, quante sono state escluse e quante cartelle hanno il record riutilizzato o la sequenza non verificabile; un journal assente (disattivato) o non leggibile è dichiarato («Journal NTFS assente» / «non letto») invece di dare zero operazioni in silenzio. **Registri eventi: record recuperati e illeggibili.** I record ricavati dallo spazio libero del file .evtx sono indicati come «recuperato» (titolo, dettaglio e campo `recuperato`); quelli identici a un record attivo non si contano due volte (prima un accesso poteva risultare doppio); i record illeggibili si contano. La scheda dell'account dice quanti accessi e sessioni vengono da record recuperati; ogni registro letto ha una voce di sistema con record attivi, recuperati e illeggibili, e per gli eventi di sistema anche il limite di 20.000 se raggiunto; registri non estratti o non leggibili e modulo pyevtx mancante sono dichiarati. **Prova:** journal costruito (record v2 con cartella attuale, cartella riutilizzata nota e ignota al journal, cartella cancellata non riutilizzata, limite, sequenza non verificabile; journal assente e volume non apribile) e libevtx simulato (record attivi, recuperati, recuperati doppi, illeggibili) con accessi ed eventi di sistema. **Non provato:** pytsk3 reale (`open_meta(...).info.meta.seq`) e libevtx reale su un disco: rifare «Artefatti» su una copia reale e confrontare con MFTECmd / EvtxECmd.

**Versione 2.18.0** - Più copertura forense sui dischi Windows. **Tutte le installazioni di Windows**: registro, utenti, accessi, prefetch, Amcache, SRUM e registri eventi si leggono per ogni cartella che contiene `Windows/System32/config/SYSTEM` (anche `Windows.old`, `Windows.old.000`), con il nome tra parentesi quadre negli artefatti: su un disco aggiornato o reinstallato l'attività precedente era prima invisibile. **Nuovi artefatti**: cartelle aperte (ShellBags), ShimCache e BAM/DAM, SRUM, Cronologia attività, journal NTFS `$UsnJrnl` (file creati, cancellati e rinominati, con il percorso ricostruito), registri eventi (servizi installati, accensioni e spegnimenti, sessioni e Desktop remoto, Defender, dischi USB, registri cancellati), miniature `thumbcache` estratte con gli hash. Nuove categorie: *Cartelle aperte*, *Journal NTFS*, *Eventi di sistema*. **Hash percettivi**: nuova analisi facoltativa, ricerca *Immagini simili* e confronto con cartelle di immagini di riferimento nelle *Liste di hash*; le liste in formato **Project VIC / CAID** (JSON) si leggono con la categoria. **Validazione**: nuovo documento `VALIDAZIONE.md` (sezione *Validazione* qui sotto) con metodo, dati di prova, risultati del collaudo e limiti noti. Gli artefatti vanno rifatti (*Artefatti di sistema* → Rifai) per vedere le novità nei casi già preparati.

**Versione 2.17.3** - Due correzioni dopo una seconda prova sulla stessa copia reale. **Anomalie: restavano falsi positivi tra i file cancellati.** Il controllo della 2.17.2 guardava solo se il primo cluster era oggi assegnato a un file presente; ma se dopo la cancellazione quei cluster sono stati usati da un altro file, cancellato anche lui, risultano liberi e il contenuto letto è di quell'altro file (un `msedge.dll` che «contiene» un JPEG, un `image.pdf` che «contiene» un eseguibile). Ora: una sola passata sulla MFT trova ogni altro record (anche libero) che usa quei cluster, e il contenuto deve essere coerente con la dimensione e la fine del file; se non lo è la voce si esclude e il riepilogo dice quante e perché. Sulla copia reale: delle 293 segnalazioni su file cancellati ne restano 12, quasi tutte di gravità bassa. Inoltre non sono più anomalie i moduli di programmi con estensione propria (`office.odf`, `Flash.mpp` di Acrobat…), gli eseguibili nelle cartelle dei programmi, le icone degli installatori e i log del registro; lo scambio foto/video è di gravità bassa. **Account utente: accessi a 0.** Per un account collegato a un **account Microsoft** (o con accesso tramite PIN/Windows Hello) Windows non aggiorna il contatore e la data di accesso del SAM. Gli accessi si contano ora dai registri eventi: `Security.evtx` (4624 riusciti, per tipo: interattivo, con credenziali in cache, remoto; 7 = sblocchi, contati a parte; i due eventi che un amministratore genera per lo stesso accesso contano una volta; 4625 falliti) e `System.evtx` (Winlogon 7001, sessioni). La scheda dell'account mostra il numero di accessi nel titolo, il periodo coperto dai registri (gli accessi precedenti non sono più registrati), l'ultimo accesso, l'indirizzo dell'account Microsoft e il SID; il contatore del SAM resta indicato a parte.

**Versione 2.17.2** - Tre correzioni dopo l'uso su una copia reale. **Anomalie: falsi positivi.** Un `.png` poteva risultare «eseguibile Windows»: per una voce *cancellata* il programma leggeva il contenuto dal numero di inode, ma su NTFS (e FAT, ext) quel record può essere già stato assegnato a un altro file, o i suoi cluster riscritti. Ora, prima di segnalare un file cancellato, si controlla che il nome corrisponda a quello memorizzato nel record e che il primo blocco dei dati non sia stato riutilizzato; le voci non più attendibili si escludono (il numero è nel riepilogo). I file con nome attuale vengono guardati per primi, così un inode già letto non viene riletto con un nome vecchio. Più estensioni di eseguibili note (`.msstyles`, `.xll`, `.vxd`…), nessuna anomalia per un formato diverso in `.dat/.bin/.db/.tmp…` e gravità bassa per lo scambio tra formati immagine. **Account utente: accessi sempre a 0.** Windows scrive le modifiche del registro prima nei file di log (`SAM.LOG1`, `SAM.LOG2`, `NTUSER.DAT.LOG1`…) e solo ogni tanto nell'alveare: leggendo il solo `SAM` si vede uno stato vecchio. Ora i log accanto all'alveare (SAM, SYSTEM, SOFTWARE, NTUSER.DAT, Amcache) si applicano a una **copia di lavoro** (record verificati con gli hash Marvin32, solo se la sequenza è continua; l'originale non cambia) e l'operazione è dichiarata tra gli artefatti («Registro: log applicati a…»). Il contatore del SAM, inoltre, non conta tutti gli accessi (account Microsoft, PIN, Windows Hello): se è 0 ma l'account risulta usato non si scrive più «mai acceduto», e si aggiungono l'ultimo caricamento e scaricamento del profilo (SOFTWARE, ProfileList), le password errate e, per ogni utente, l'ultima scrittura di `NTUSER.DAT`. **Documenti per estensione**: nella vista ad albero la voce Documenti si divide per estensione, con filtro *Estensione* nella sezione.

**Versione 2.17.1** - Su Windows il pulsante **Scegli…** di *Riscontro con altro strumento* non apriva la finestra di scelta del file (l'apostrofo del titolo «Scegli l'elenco…» interrompeva il comando di Windows). Corretti anche il filtro della finestra *Scegli la copia forense* (mostrava gli elenchi CSV invece delle copie forensi) e la scelta del file della **lista di hash**, che non si apriva.

**Versione 2.17.0** - **Spazio non allocato consultabile** come in Autopsy: cartella `$Unalloc` in ogni volume con i tratti di spazio libero del file system, apribili in testo ed esadecimale, esportabili con SHA-256 e da mettere nei preferiti; lo stesso per gli spazi non allocati tra le partizioni e per i volumi che Sleuth Kit non legge. Verificato: i byte dei tratti coincidono con il flusso dello spazio non allocato di Sleuth Kit (`blkls -A`) su FAT12, FAT16, NTFS ed ext4 (anche da E01).

**Versione 2.16.2** - **Avvio più rapido su Windows**: prima di interrogare un server LLM si controlla in mezzo secondo che la porta sia aperta. Su Windows ogni tentativo verso una porta chiusa costava circa 2 secondi e, senza server LLM avviato, l'apertura poteva durare decine di secondi; ora è immediata. Un server in rete non raggiungibile si scarta in pochi secondi.

**Versione 2.16.1** - **Date FAT/exFAT corrette anche su Mac** con il dispositivo in un fuso diverso da quello del computer: Sleuth Kit su macOS perdeva l'indicazione del fuso e usava quello del computer (collaudo DFTT 5: orari spostati). Ora il fuso neutro arriva a Sleuth Kit dall'ambiente del processo, in modo identico su Mac, Windows e Linux, e la conversione nel fuso del dispositivo la fa RepertIA. I casi con partizioni FAT/exFAT preparati con le versioni precedenti vengono ricalcolati da soli alla prima apertura (voce `date_fat_ricalcolate` nel registro).

**Versione 2.16.0** - Nuovi pacchetti: app per Mac `RepertIA.app`, installazione Windows in `Programmi\RepertIA` con la voce «RepertIA» nel menu Start, cartella di collaudo `RepertIA-collaudo`. Variabili d'ambiente con il prefisso `REPERTIA_`.

**Versione 2.15.5** - **Suddivisione del disco in volumi** nell'albero del file system (come in Autopsy): sotto «Disco · <tipo di tabella>» compaiono tutte le righe della tabella delle partizioni lette con `mmls` — area della tabella, spazi non allocati e volumi — con indice (`vol<n>`), descrizione e settori in unità da 512 byte (es. «vol2 (Win95 FAT32 (0x0b): 32-15257599)»). I volumi leggibili si aprono come prima; quelli che Sleuth Kit non legge sono indicati come «file system non letto»; i volumi APFS stanno sotto la loro partizione. Un clic su una riga non apribile ne mostra posizione e dimensione in byte. La stessa vista è nel report portatile. Le immagini senza tabella delle partizioni (es. pendrive) restano come prima.

**Versione 2.15.4** - Nel modulo del nuovo caso l'esempio del campo *Operatore* è un nome di fantasia («John Doe»). Aggiunta la nota sul progetto personale e sullo sviluppo con l'ausilio di Claude (Anthropic).

**Versione 2.15.3** - **Date FAT/exFAT corrette anche su Windows**: su Windows Sleuth Kit non capiva il nome del fuso del dispositivo (es. `Europe/Rome`) e applicava «fuso 0 con l'ora legale degli Stati Uniti»: le date FAT/exFAT risultavano spostate di un'ora (collaudo DFTT 5 sul PC Windows: 2 controlli non superati). Ora Sleuth Kit legge sempre l'ora scritta sul disco così com'è (fuso neutro `UTC0`, capito allo stesso modo da Windows, macOS e Linux) e la conversione nel fuso del dispositivo la fa RepertIA con il database dei fusi (ora legale europea esatta, anche negli anni passati). Vale per timeline, albero, scheda Metadati e report portatile; le date NTFS/ext/HFS/APFS (già UTC) non cambiano. I casi con partizioni FAT/exFAT preparati su Windows con le versioni 2.13.7-2.15.2 vengono ricalcolati da soli alla prima apertura (voce `date_fat_ricalcolate` nel registro).

**Versione 2.15.2** - **Archivi riconosciuti dal contenuto**: un archivio (ZIP, RAR, 7z, tar, gzip, xz, bzip2, CAB) con un'altra
estensione, per esempio un ZIP rinominato `.jpg` o `.boo` per nasconderlo, ora si apre come gli altri, anche dentro altri archivi e negli
allegati di posta; i documenti che sono ZIP per costruzione (Word, Excel, OpenDocument, epub, jar, apk…) restano documenti. Il conteggio
«archivi riconosciuti dal contenuto» è nel riepilogo di *Archivi e posta*. Collaudo DFTT 8: `file9.jpg` dentro `file9.boo` ora estratto
(da misura a controllo superato): 112/112, 46/46 sulle immagini pubbliche.

**Versione 2.15.1** - **Due errori del carving trovati dal collaudo sul Mac** (DFTT 11):
- **File recuperati oltre il 500° persi**: PhotoRec mette al massimo 500 file per cartella (`recup.1`, `recup.2`…) ma elenca tutto in un
  solo `report.xml` senza cartella; RepertIA registrava solo quelli della prima. Con più di 500 file recuperati gli altri restavano sul
  disco ma non comparivano nel caso, nel report né nelle ricerche. Ora entrano tutti (provato: 651 su 651).
- **Falsi positivi «dovecot» di PhotoRec 7.2** (quello di Homebrew sul Mac e quello dell'installer Windows): centinaia di file da 80 KB
  che coprivano documenti e video veri (DFTT 11: 8 file identici su 15 invece di 13). Dalla 7.2 il tipo si disattiva (variabile
  `REPERTIA_PHOTOREC_ESCLUDI`, `nessuno` per riattivarlo); il report lo dichiara tra gli avvisi del carving.
- Le **miniature EXIF** che PhotoRec estrae dalle foto recuperate (`t….jpg`) entrano nel caso con l'offset della foto.
- Collaudo: nuovo controllo «tutti i file trovati da PhotoRec sono nel caso». Provato con PhotoRec 7.1 e 7.2 (compilato dai sorgenti):
  111/111, 45/45 sulle immagini pubbliche, carving 13/15 identici all'offset pubblicato con entrambi.

**Versione 2.15.0** - **Riscontro con altri strumenti e collaudo su immagini pubbliche**:
- **Riscontro con altro strumento** (Autopsy, FTK Imager, X-Ways, EnCase, AXIOM, Sleuth Kit): file con hash uguale/diverso,
  trovati da uno solo, stato «cancellato» discordante; nel report e nel registro.
- **Collaudo con le immagini DFTT** e i valori pubblicati dal progetto (incluse nello zip di collaudo): 44 controlli superati
  su 44; misure: 3 file frammentati su FAT non ricostruibili, 13 file su 15 recuperati identici e all'offset pubblicato dal
  carving di DFTT 11, ZIP con estensione diversa non aperto.
- **Supporti senza file system leggibile** (danneggiati o sconosciuti): prima la preparazione si fermava; ora il caso si crea e
  restano carving dell'intera immagine, bulk_extractor, ricerca nei byte e plaso (trovato con DFTT 11).

**Versione 2.14.0** - **Integrità verificabile e Mac completo**:
- **Hash dei dati acquisiti** confrontato con l'hash di acquisizione registrato nell'E01 o nel log del programma di acquisizione
  (FTK Imager, Guymager, ewfacquire…); E01 alterato o con blocchi illeggibili = **DIVERSO**; dati di acquisizione dell'E01 nel report.
- **Registro a catena di hash** (`audit_log.jsonl`): manomissioni scoperte da *Verifica hash* e dichiarate nel report.
- **Ambiente nel report**: impronta del programma e versioni di tutti gli strumenti, alla preparazione e al report.
- **Mac, errore corretto**: sui Mac da Catalina in poi gli artefatti del **volume Dati** (utenti, reti, programmi) non venivano letti
  perché `SystemVersion.plist` sta nel volume di sistema. Ora sì.
- **Mac, nuovi artefatti**: quarantena dei download, avvio automatico, permessi TCC, iMessage (anche dal `-wal`), documenti recenti,
  download di Safari, uso delle app (knowledgeC), Bluetooth e volumi, Time Machine, nome del computer e ultimo utente.
- **Snapshot APFS** nella sezione *Copie shadow*: file cancellati o in versione precedente recuperati dagli snapshot.
- **plaso sui volumi FileVault sbloccati** (riceve la chiave in memoria) e **fuso del Mac** rilevato da solo.
- **Collaudo con immagini di riferimento** (`forense_collaudo.py`, zip `RepertIA-collaudo.zip`).
- Provato: E01 integro/alterato, raw con log FTK, volume Dati sintetico, APFS normale/cifrato (anche con plaso), BitLocker To Go;
  GUI e report portatile con Playwright. Non provato su un E01 reale di Mac recente né su snapshot APFS reali (la lettura degli
  snapshot è provata con dati simulati) né su Windows.

**Versione 2.13.9** - **Date e orari: terzo fuso «del dispositivo» e etichette sempre corrette** (verifica forense):
- **Selettore a tre fusi** (GUI e report portatile): **UTC**, **Ora italiana** e **Fuso rilevato** (il fuso del dispositivo letto dal
  sistema del disco, oppure quello scelto per il caso: la voce dice «fuso rilevato Asia/Kolkata» o «fuso impostato …» se non è stato
  verificato sul disco). Vale in **tutte** le sezioni con data/ora: colonne, filtri «dal/al», istogramma della timeline (i giorni sono
  quelli del fuso scelto), anteprima e testo di posta e artefatti, riquadro esadecimale, report PDF/Word, CSV (l'intestazione dice il
  fuso: `data_utc`, `data_ora_italiana`, `data_fuso_…`). Ogni orario convertito porta la sigla: **CET/CEST** per l'Italia, **UTC±HH:MM** per
  gli altri fusi (le sigle di altri paesi sono ambigue).
- **Errore corretto: etichetta «Data (UTC)» con un orario in ora italiana.** Nell'anteprima di posta e artefatti l'etichetta era scritta
  nel codice e non seguiva il selettore: l'orario era giusto ma l'etichetta diceva UTC. Ora il server scrive etichetta e orario insieme.
- **Scheda Metadati.** Gli orari di **istat** (Sleuth Kit) sono riscritti nel fuso scelto (Sleuth Kit li stampa nel fuso del dispositivo:
  ogni orario si riporta all'istante assoluto, anche nell'ora doppia di ottobre, e poi si riscrive); una riga in testa dice in che fuso
  sono. APFS (già UTC) e file estratti dagli archivi idem. Le date di **exiftool** restano come scritte nel file e, dove il file indica
  il fuso (`+01:00`, `Z`, `OffsetTimeOriginal`, QuickTime = UTC), a destra compare l'orario nel fuso scelto; dove non c'è, la riga dice
  «fuso non indicato nel file: ora locale del dispositivo».
- **FAT/exFAT:** l'ultimo accesso è solo una data (nel disco non c'è l'ora): dopo la conversione l'ora non è significativa e la scheda lo scrive.
- **Casi preparati prima della 2.13.7:** il fuso del dispositivo non è registrato, quindi «Fuso rilevato» non è disponibile e gli orari di
  istat non si convertono (la scheda lo dice).
- **Report portatile:** stesso selettore; l'istat viaggia come istanti UTC e il browser li riscrive nel fuso scelto; le date del report
  in testo (markdown) sono convertite con una nota in testa; i CSV di timeline, artefatti, posta e archivi seguono il fuso scelto.
- Provato con: ext4 con `/etc/timezone` = Asia/Kolkata (+05:30), FAT con ora locale di New York, ora doppia/ora che salta dell'Italia,
  e-mail con `+01:00`, foto con e senza `OffsetTimeOriginal`; GUI e portatile con Playwright (browser in un altro fuso).

**Versione 2.13.8** - **Il fuso del dispositivo si ricava da solo** (l'operatore non deve pensarci):
- **Rilevamento automatico.** Se il disco contiene un sistema operativo, RepertIA legge il fuso da lì: registro di Windows
  (`SYSTEM`, `TimeZoneInformation`) o `/etc/timezone` / `/etc/localtime` su Linux, e lo usa per le date FAT/exFAT. Nel modulo del
  nuovo caso la scelta è «Automatico (consigliato)», «Italia», «UTC» o «Altro fuso…» (non viene più ricordata: un fuso sbagliato
  non deve passare da un caso all'altro).
- **Avviso se discordante.** Se il fuso scelto a mano non coincide con quello del sistema (fusi equivalenti come Roma e Berlino
  contano come uguali), il caso mostra un avviso con i pulsanti «Cambia fuso…» e «Usa … (dal sistema)». La correzione ricalcola le
  date FAT/exFAT della timeline (analisi aggiuntiva `fuso`, anche da riga di comando: `prepara --case X --aggiungi fuso --fuso Z`) e
  la scelta resta nel registro di audit.
- **Dispositivi senza sistema** (chiavette, schede): il fuso non è verificabile; si assume l'Italia e il caso, il report e il
  report portatile lo dichiarano come «NON VERIFICABILE».
- plaso e gli artefatti di sistema (reti Windows) usano il nuovo fuso solo se rifatti dal pannello delle analisi.
- Non provato su Windows reali né su E01 reali (testato con immagini FAT/ext4 e registro simulato).

**Versione 2.13.7** - **Date e orari a prova di perizia** (fuso del dispositivo, fuso mostrato ovunque, ora legale):
- **Fuso del dispositivo.** FAT/exFAT (chiavette, schede, fotocamere) salvano l'ora del muro senza dire in che fuso. Prima Sleuth
  Kit le convertiva con il fuso **del PC dell'analista**: lo stesso file diventava istanti UTC diversi su computer diversi.
  Ora «Dati del nuovo caso» chiede il **fuso orario del dispositivo** (predefinito Europe/Rome, ricordato), lo registra nel caso
  (`fuso_dispositivo`, anche nel registro di audit), lo passa a `fls -z`/`istat -z` e a plaso (`--timezone`) e lo scrive nel
  report, nel riquadro del caso e nel report portatile. Da riga di comando: `prepara --fuso Europe/Rome`. Nei casi vecchi il fuso
  risulta «non registrato» (i dati restano com'erano).
- **Date dei metadati (foto, video, documenti).** La data mostrata era la prima trovata nell'elenco di exiftool, quindi una
  foto ritoccata mostrava la data di modifica invece di quella di scatto. Ora si sceglie per priorità (scatto, creazione,
  modifica), si registra **da quale campo** viene (`RepertIA:DataScelta` tra i metadati) e si aggiunge il fuso **solo se il
  file lo contiene** (OffsetTimeOriginal, date XMP/PDF con offset, contenitori QuickTime che per specifica sono UTC). Senza
  fuso la data è mostrata com'è con la dicitura «ora locale, fuso n.d.»; i CSV hanno la colonna `fuso_della_data`.
- **Ora italiana con la sigla CET/CEST** in ogni cella (GUI, portatile, report): nell'ora doppia di ottobre due istanti diversi
  non appaiono più identici. I filtri per data in ora italiana gestiscono ora doppia e ora che salta. Le date con offset
  (es. +02:00) e quelle antecedenti al 1970 sono convertite; quelle non convertibili sono mostrate con il loro fuso o «UTC».
- **Report in ora italiana:** converte solo gli orari UTC riconosciuti e **non tocca** nomi di file, percorsi, testo tra
  apici inversi e celle con altro testo; indica quanti orari ha convertito e quanti lasciato invariati.
- **Archivi:** la data DOS degli ZIP è ora locale senza fuso e ora è marcata «locale» (se c'è il campo esteso UTC si usa
  quello); per tar/7z 7-Zip è lanciato con `TZ=UTC`, così l'elenco non dipende dal fuso del PC.
- **Reti Windows (registro):** i SYSTEMTIME in ora locale sono convertiti con il fuso del dispositivo (o marcati «locale»).
- **Metadati di file recuperati/allegati:** tolte le date della copia di lavoro (`FileModifyDate`, `FileAccessDate`…), che
  erano la data di estrazione nel fuso del PC.
- **Etichette:** «Creato», «Accesso» e tutte le date del portatile (Esplora, Cerca, Preferiti, scheda del file, CSV) dichiarano
  il fuso; «creato/generato/verifica» sono sempre in UTC; le date del browser (`when`, «Generato il») riportano CEST/CET o lo
  scostamento dal UTC.
- Prove: immagine FAT con lo stesso risultato UTC con host UTC e New York; foto con scatto 2024 e modifica 2025; ora doppia
  del 25/10/2026; nome di file con orario nel report; ZIP DOS/UT, tar con host a fusi diversi; GUI e portatile in Chromium con
  browser in un fuso diverso (nessun errore JS). Non provati: Windows (7-Zip e tzdata), E01 reali, registro con reti reali.

**Versione 2.13.6** - **Password APFS sbagliata riconosciuta davvero**:
- Su un E01 di Mac (Apple Silicon) la libreria APFS dichiarava «sbloccato» il volume Data anche con una password
  **sbagliata** (poi la radice non era leggibile e risultavano 0 file): l'analisi proseguiva e il volume restava con il
  lucchetto. Ora un volume nato cifrato è considerato sbloccato **solo se la radice si legge davvero**. Con chiave
  errata il popup lo dice (con l'avvertenza che i Mac T2/Apple Silicon possono usare chiavi dell'hardware) e permette di
  **riprovare** o di **proseguire senza**. Vale anche per «Sblocca…» dal caso aperto.

**Versione 2.13.5** - **BitLocker e LUKS decifrabili dal popup dei volumi cifrati**:
- Il popup che compare prima dell'analisi (2.13.4) ora permette di usare la chiave anche per **BitLocker** (password o
  chiave di ripristino) e **LUKS** (password): RepertIA calcola lo SHA-256 della copia originale, crea la **copia derivata
  decifrata** (come «Decifra…» del caso; il popup mostra spazio necessario e disponibile) e **avvia da sola l'analisi di
  quella copia come nuovo caso**, con gli stessi dati e opzioni e una nota sull'origine. Chiave errata: nuovo tentativo.
  Il caso sulla copia originale resta come registro della decifratura (non completato).
- Corretto: i volumi a offset 0 (pendrive senza tabella partizioni) nel popup.

**Versione 2.13.4** - **Avviso dei volumi cifrati prima dell'analisi**:
- Subito dopo l'apertura della copia, **prima del calcolo dell'hash e dell'analisi**, RepertIA cerca i volumi cifrati
  (APFS/FileVault, BitLocker, LUKS) e, se ne trova, mostra un popup: **Sblocca e continua** (volumi APFS: password
  dell'utente o chiave di ripristino, solo in memoria; chiave sbagliata = nuovo tentativo), **Prosegui senza i volumi
  cifrati** oppure **Annulla l'analisi** (il caso appena creato viene tolto). La scelta dell'operatore è nel registro
  di audit (senza la chiave). BitLocker e LUKS non si sbloccano in questa fase: restano esclusi e si decifrano dopo.
- **Versione 2.13.3**: un volume APFS la cui radice non è leggibile non ferma più la preparazione
  (`'NoneType' object has no attribute 'identifier'`): si provano percorsi alternativi, altrimenti il volume è saltato con avviso.

**Versione 2.13.2** - **Volumi cifrati esclusi dall'analisi**:
- Un volume cifrato riconosciuto alla preparazione (BitLocker anche To Go, LUKS, FileVault/CoreStorage) viene **escluso**
  dall'analisi: non si elenca nulla per esso, perché quello che Sleuth Kit legge senza chiave (per esempio il FAT finto
  di un BitLocker To Go) non è il suo contenuto e prima finiva mescolato alle prove delle altre partizioni. Le altre
  partizioni si analizzano normalmente; il volume cifrato resta tra i «Volumi cifrati» del caso e si analizza dopo
  con *Decifra…* (nuovo caso dalla copia derivata). Il **report** indica «NON ANALIZZATO» per ogni volume cifrato.
- Collaudo: disco MBR con una partizione ext4 e una BitLocker To Go (password nota): ext4 analizzata, BitLocker esclusa
  con avviso; decifrata → nuovo caso con entrambe le partizioni leggibili (FAT16, 18 voci).

**Versione 2.13.1** - **Avviso sui volumi cifrati**:
- Già alla preparazione del caso RepertIA controlla le firme dei volumi cifrati (BitLocker, anche To Go, LUKS,
  FileVault/CoreStorage). Prima un BitLocker To Go (chiavetta) veniva letto da Sleuth Kit come un FAT senza contenuto
  utile e il caso risultava «pronto» senza che l'operatore se ne accorgesse (il volume emergeva solo con l'analisi
  Anomalie). Ora la preparazione stampa un **avviso ben visibile**, il registro annota `volume_cifrato_rilevato` e il
  pannello del caso mostra «Volumi cifrati» con l'avvertenza che file e date elencati **non sono il contenuto reale**,
  con il pulsante *Decifra…*. Per APFS non cambia nulla (già gestito in 2.13.0).
- Collaudo: immagine BitLocker To Go di prova (password sbagliata → rifiutata; giusta → copia decifrata, nuovo caso
  FAT16 leggibile con la derivazione registrata).

**Versione 2.13.0** - **Mac con APFS**:
- **Lettura dei volumi APFS** con libfsapfs (nuovo `forense_apfs.py`), senza Sleuth Kit e senza copie: elenco file,
  albero, timeline (date al secondo, nanosecondi nei Metadati), hash, indice del testo, anteprime, esportazioni,
  report portatile, strumenti dell'agente (`list_directory`, `file_metadata`, `read_file_text`…) e analisi estese
  (artefatti macOS essenziali). Un volume APFS è una «partizione» del caso con offset sintetico (vedi *Mac con APFS*).
- **Sblocco dei volumi FileVault** con password o chiave di ripristino, dalla preparazione o dal caso già aperto;
  la chiave resta solo in memoria. Avviso nel pannello del caso se un volume cifrato non è sbloccato nella sessione.
- Preparazione: un caso fermato per «VOLUME CIFRATO» si può ripreparare con la chiave (prima rifiutava: «esiste già»).
- Invariato: tutto il resto (nessun cambiamento per NTFS, FAT, ext, HFS+). Limiti dichiarati nel README.

**Versione 2.12.0** - **Cache modificabile e casi dove vuoi**:
- **Cache e posizione** (pulsante nel riquadro «Azioni» del caso): mostra quanto occupa la cache delle anteprime
  e dove sta; permette di cambiare il **limite di spazio** (GB, 0 = nessun limite; predefinito 5), di scegliere
  una **cartella per la cache** anche su un altro disco (la cache attuale viene eliminata: si ricostruisce da
  sola; se il disco non è collegato si usa quella nel caso) e di **svuotarla**. Non tocca mai database, reperti
  ed esportazioni. Il limite e la cartella sono per caso (`cache_gb`, `cache_dir` in `case.json`);
- **Dove salvare i casi**: nella pagina dei dati del nuovo caso c'è «Salva il caso in» (cartella a scelta, anche
  su disco esterno o di rete), con il percorso finale e lo spazio libero. La cartella viene ricordata nelle
  impostazioni (`cartelle_casi`) e **tutti i casi di tutte le cartelle raggiungibili** compaiono nell'elenco;
  una cartella con il disco scollegato è segnalata come non raggiungibile. Dall'elenco si può **aggiungere una
  cartella di casi** già esistente (es. un disco con vecchi casi) o toglierla dall'elenco (✕, i casi restano);
- **Copia del caso in un'altra posizione** (da «Cache e posizione»): copia il caso, senza la cache, nella cartella
  scelta, con avanzamento e verifica del numero di file; controlla prima lo spazio libero; l'originale resta dov'è
  e la copia compare nell'elenco dei casi («Apri la copia»). L'operazione è annotata nel registro del caso.

**Versione 2.11.0** - **Dati del caso, volumi cifrati nell'albero, pulsante della vista ad albero**:
- **Pagina dei dati del caso**: scelta la copia forense e premuto «Avvia l'analisi», un nuovo caso apre prima una
  pagina con **nome del caso, operatore, tipo di reperto** (elenco o testo libero) e **note**. I dati entrano
  nel caso (`case.json`, chiave `info_caso`), si vedono in alto a sinistra, nel riquadro «Caso», e compaiono nel
  report e nel report portatile (riepilogo, titolo, esportazione Word). Il nome è quello mostrato nell'elenco
  dei casi e nel titolo; la cartella del caso non cambia. L'operatore viene ricordato per il caso successivo.
  Dal riquadro «Caso» si possono **modificare o inserire** anche per i casi già esistenti («Modifica dati del
  caso»);
- **Volumi cifrati**: nell'albero del file system compaiono anche le partizioni cifrate (🔒, es. «BitLocker
  (cifrato)»). Il clic su un volume nel riquadro «Volumi cifrati» del caso, o l'azione «Mostra nell'albero»
  della riga in Anomalie, apre il volume nell'albero: una scheda mostra tipo, offset, dimensione e il pulsante
  «Decifra…» (più eventuali copie già decifrate);
- il pulsante **Vista ad albero** è ora il primo a sinistra, prima di «File System», con un'icona ad albero di
  cartelle.

**Versione 2.10.1** - **Ordinamento e menu dei valori nelle colonne** (programma e report portatile):
- **clic sull'intestazione** di una colonna: ordina in modo crescente (A→Z, dal più piccolo, dal più vecchio),
  secondo clic decrescente, terzo clic torna all'ordine normale; la freccia ▲/▼ mostra la colonna ordinata.
  Nell'esplora file le cartelle restano sempre in cima. Nel programma si ordina l'intero elenco (non solo la
  pagina visibile) e l'ordine vale anche per selezione ed esportazioni;
- **▾ accanto al filtro delle colonne di testo**: elenco dei valori presenti con il numero di righe, come in
  Excel: ricerca, «Seleziona tutti», spunte, OK / Azzera colonna / Annulla. L'elenco tiene conto degli altri
  filtri attivi ma non di quello della colonna stessa e mostra i 300 valori più frequenti (per gli altri si
  usa il campo di testo). Il pulsante ▾ si colora quando ci sono valori scelti;
- il menu contiene anche i comandi di ordinamento della colonna.

**Versione 2.10.0** - **Spazio su disco**: un E01 da 40 GB non genera più un caso da 1 TB. Prima, il
carving (e, in casi particolari, l'apertura) convertiva tutto l'E01 in un file `immagine.raw` grande quanto
il disco originale (anche 1 TB). Ora:
- Sleuth Kit legge l'E01 direttamente e il caso resta fatto di database, report e file recuperati;
- per il carving, PhotoRec riceve un file temporaneo con il solo **spazio non allocato**, senza i blocchi da
  1 MiB interamente a zero (un disco quasi vuoto occupa poche decine di MB invece di centinaia di GB); una
  mappa riporta ogni file recuperato all'offset reale nell'immagine; il file temporaneo si cancella a fine
  lavoro; se non c'è spazio il passaggio si salta con un messaggio, senza riempire il disco;
- bulk_extractor legge l'E01 direttamente (lo si verifica con una prova su 1 MiB); se la versione non
  supporta gli E01 usa lo stesso file compatto, e gli offset delle tracce vengono rimappati;
- l'unico caso in cui serve ancora un raw è quando Sleuth Kit non sa leggere l'E01: il file è **sparso**
  (gli zeri non occupano spazio) e si controlla lo spazio libero prima;
- **casi già creati con la 2.9.x**: alla prima apertura la vecchia copia raw dell'E01 viene eliminata e il
  caso torna a usare l'E01 (gli offset sono identici, nulla va rifatto); il registro `audit_log.jsonl` annota
  l'operazione e lo spazio liberato;
- la cache delle anteprime è limitata a 5 GB (variabile `REPERTIA_CACHE_MAX_GB`): all'apertura del caso si
  eliminano i file meno recenti; sono solo copie ricostruibili.

**Filtri per colonna**: sotto l'intestazione di ogni elenco c'è una riga di filtri. Vedi «Filtri per colonna»
nella scheda Risultati. Funzionano anche nel report portatile.

**Versione 2.9.1** - Scheda *Testo* dell'anteprima: mostra il testo intero (prima era tagliato a circa
12.000 caratteri con la scritta «troncato», perché usava il limite pensato per la memoria del modello).
L'agente legge i documenti lunghi **a porzioni**: `read_file_text` e `read_carved` hanno il parametro
`start` e, quando c'è altro testo, lo dicono in fondo («altri N caratteri… richiama con start=…»); le
istruzioni all'agente gli dicono di proseguire invece di fermarsi al limite. Il testo di PDF e OCR ha gli
stessi ritorni a capo su Mac e Windows (prima su Windows aveva `\r\n`, quindi più caratteri). Il testo
già salvato nella cache dei casi aperti con la 2.9 si rigenera da solo alla prima apertura.

**Versione 2.9** - Indice del testo senza tagli silenziosi: i testi lunghi si indicizzano per intero a
blocchi (non solo i primi 200.000 caratteri), i PDF si leggono oltre le 500 pagine, i file di testo e i
PDF molto grandi si leggono in flusso o a blocchi; ogni file non indicizzato o parziale è elencato in
`non_indicizzati.csv` con il motivo, segnalato nei risultati di ricerca, nel riepilogo e nel report;
controllo di coerenza a fine indicizzazione; nuovo strumento `list_not_indexed` per l'agente. I casi
preparati con versioni precedenti restano utilizzabili: per avere i blocchi e l'elenco rifare
*Testo dei documenti e metadati*. L'indicizzazione può richiedere più tempo sui dischi con molti file grandi.

**Versione 2.8** - Windows: corretta l'estrazione del testo dei PDF (e dei metadati dallo strumento
esterno dell'agente), che prima non produceva testo. I casi analizzati con la 2.7 su Windows vanno
ripreparati per indicizzare i PDF.

## Pacchetto per Mac Apple Silicon

`RepertIA-2.19.0-Mac.zip` contiene **RepertIA.app** con Python 3.12, openai, Pillow e **plaso
già inclusi** (niente Docker). Trascina l'app in Applicazioni; la prima volta: tasto destro →
*Apri* (o *Impostazioni di Sistema → Privacy e sicurezza → Apri comunque*), perché non è firmata
con un certificato Apple. L'app apre il Terminale, installa con Homebrew gli strumenti che mancano
(Sleuth Kit, libewf, exiftool, poppler, PhotoRec, bulk_extractor, Tesseract) e poi il browser.
7-Zip, libpff e i dati dell'OCR italiano/inglese sono già nell'app. Per aggiornarli
c'è *Aggiorna strumenti.command* nello zip. Solo per Mac M1 o successivi.

## Versione Windows

`RepertIA-2.19.0-Setup.exe` installa RepertIA per l'utente corrente (senza diritti di
amministratore) in `%LOCALAPPDATA%\Programs\RepertIA`, con Python e gli strumenti già inclusi:
plaso, The Sleuth Kit (legge gli E01 direttamente), ExifTool, Poppler, PhotoRec, bulk_extractor, 7-Zip,
Tesseract OCR (italiano e inglese) e le librerie per posta Outlook, copie shadow e volumi cifrati. Si avvia dal menu
Start → **RepertIA**: si apre una finestra nera da lasciare aperta e il browser. I casi stanno
in `%USERPROFILE%\CasiForensi`, le impostazioni in `%APPDATA%\RepertIA`.

- **plaso** è incluso nell'installer (versione Python nativa, senza Docker).
- **bulk_extractor** (v2.2.0) è incluso nell'installer come programma nativo per Windows (senza
  Docker, senza internet). *Aggiorna strumenti* dal menu Start ne mostra la versione; per
  aggiornarlo si installa una nuova versione di RepertIA.
- **Anteprime Office**: installa LibreOffice, viene trovato da solo.
- **Differenze rispetto al Mac**: niente acquisizione da disco (usa un acquisitore dedicato);
  anteprime delle immagini con Pillow invece degli strumenti di macOS; per il carving di un E01
  la conversione in raw si fa con `img_cat` di Sleuth Kit.
- Windows SmartScreen può segnalare l'installer come «app non riconosciuta» perché non è
  firmato digitalmente: *Ulteriori informazioni* → *Esegui comunque*.
- Per ricostruire l'installer vedi `build/windows/COME_RICOSTRUIRE.txt` nel repository e `docs/COSTRUZIONE.md`.

## Versione Linux (sperimentale)

`RepertIA-2.19.0-Linux.tar.gz` è per **Linux x86_64** con Python 3.12 o successivo (Ubuntu 24.04 o
successivo, Debian 13). Il programma è lo stesso delle versioni Mac e Windows (stessa impronta dei sorgenti).

```
tar -xzf RepertIA-2.19.0-Linux.tar.gz
cd RepertIA
./installa.sh          # una volta, con internet: chiede la password di amministratore
./RepertIA.sh          # oppure dal menu delle applicazioni
```

- `installa.sh` installa con **apt** Sleuth Kit, libewf, PhotoRec, Poppler, ExifTool, Tesseract (con
  l'italiano), zenity (finestre di scelta dei file) e, se la distribuzione lo ha, bulk_extractor; poi crea
  in `python/` un ambiente con **plaso, le librerie libyal, pytsk3, Pillow e openai alle stesse versioni dei
  pacchetti Mac e Windows** (`requirements-linux.txt`; le librerie libyal si compilano, 10-20 minuti) e
  aggiunge RepertIA al menu. Il registro è in `installa.log`; lo script si può rieseguire.
- Inclusi nell'archivio: 7-Zip 26.01 (`strumenti/7zip`) e i dati OCR italiano/inglese (`strumenti/tessdata`).
- **Differenze rispetto a Mac e Windows**: gli strumenti forensi sono quelli della distribuzione, con le sue
  versioni (riportate come sempre nel report, sezione *Ambiente di analisi*); bulk_extractor può mancare
  in alcune distribuzioni (il carving usa allora PhotoRec); niente acquisizione da disco.
- `./collaudo.sh` esegue il collaudo con la cartella `RepertIA-collaudo` (anche `--lingua en`);
  `./aggiorna-strumenti.sh` mostra e aggiorna con apt le versioni degli strumenti.
- **Sperimentale**: collaudata dall'autore in un ambiente Linux di sviluppo; prima dell'uso in un caso esegui
  il collaudo sul tuo computer e conserva il rapporto.
- Per ricostruire il pacchetto vedi `build/linux/COME_RICOSTRUIRE.txt` nel repository.

## Da terminale

```
python3 forense_agent.py                 apre l'interfaccia grafica
python3 forense_agent.py avvia IMG       prepara se serve e apre la chat nel terminale
python3 forense_agent.py avvia IMG --no-hash   analisi speditiva: hash della copia rinviato
python3 forense_agent.py prepara --case CASO --aggiungi immagine   calcola dopo lo SHA-256 della copia
python3 forense_agent.py prepara --case CASO --aggiungi indice hash plaso carving
python3 forense_agent.py prepara --case CASO --aggiungi archivi anomalie artefatti vss ocr
python3 forense_agent.py report  --case CASO
python3 forense_agent.py verifica --case CASO      SHA-256 dei file, hash dei dati, catena del registro
python3 forense_collaudo.py CARTELLA_COLLAUDO     collaudo con le immagini di riferimento
python3 forense_agent.py riscontro --case CASO --file ELENCO.csv --strumento "Autopsy 4.21"
```

Variabili utili: `FORENSE_CASI` (cartella dei casi), `FORENSE_BACKEND`, `FORENSE_URL`,
`FORENSE_MODEL`, `FORENSE_CTX`.

## Problemi frequenti

- **«Server LLM non collegato»**: avvia il server in LM Studio (scheda Developer) e premi
  *Riprova*. Nel frattempo i Risultati funzionano. Con un server in rete il messaggio indica
  gli indirizzi provati: controlla indirizzo, porta, ascolto sulla rete e firewall.
- **«La copia forense non è raggiungibile»**: collega il disco che contiene l'immagine;
  elenchi, timeline e ricerche funzionano anche senza, mentre anteprime ed esportazioni no.
- **Nessuna anteprima per Word/Excel/PowerPoint o anteprima semplificata**: installa
  LibreOffice (gratuito) e riapri l'anteprima; nel frattempo usa la scheda Testo.
- **Il video non parte**: il browser riproduce mp4/mov/webm; per gli altri formati viene
  mostrato un fotogramma, oppure esporta il file.
- **Spazio su disco**: la cartella `cache/` del caso cresce con i file aperti in anteprima;
  si può cancellare senza perdere nulla. I file oltre 2 GB non vengono copiati: l'esadecimale
  li legge direttamente dalla copia (più lentamente).
- **Il testo di un file lungo non finisce nell'anteprima, o l'agente si ferma**: con la 2.9.1 l'anteprima
  mostra fino a due milioni di caratteri e l'agente prosegue a porzioni (`start`). Con versioni precedenti
  il testo era tagliato a circa 12.000 caratteri: aggiorna.
- **Una parola che so essere in un file non esce nella ricerca nel testo**: guarda `non_indicizzati.csv`
  (e il ⚠ sopra i risultati): il file potrebbe essere troppo grande, un PDF di sole immagini o in
  una cartella di sistema; prova la ricerca nel *contenuto grezzo* (non legge dentro PDF e Office)
  o apri il file. Se il caso è stato preparato con la 2.7 o la 2.8, rifai *Testo dei documenti e metadati*.
- **La ricerca nel contenuto grezzo è lenta**: restringi con estensioni, cartella o dimensione
  massima, oppure usa *Testo dei documenti indicizzati*, che è immediato. Puoi interromperla e
  tenere i risultati già trovati.
- **Ricerca per hash con pochi risultati**: se gli hash non erano calcolati e hai scelto di non
  calcolarli al volo, i file senza hash non vengono confrontati (l'esito lo segnala).
- **«VOLUME CIFRATO» su un Mac / il volume APFS non si apre**: usa *Decifra / sblocca il volume…* con la password
  dell'utente o la chiave di ripristino. Se è un Mac con chip T2 o Apple Silicon la password può non bastare
  (chiavi legate all'hardware): serve un'acquisizione logica fatta sul Mac acceso.
- **Albero in preparazione**: alla prima apertura di un caso RepertIA costruisce l'indice
  dell'albero (pochi secondi; circa 15 secondi ogni 500.000 file), poi resta pronto.

---

RepertIA — ideato e realizzato da **silvexe**.

Progetto personale di silvexe, realizzato a titolo privato e non collegato ad alcun ufficio o amministrazione. Sviluppato con l'ausilio di **Claude**, modello di intelligenza artificiale di Anthropic; scelte, verifiche e collaudi sono dell'autore.

---

## Licenza

Copyright (C) 2026 silvexe. RepertIA è software libero, rilasciato con licenza **GNU General Public License versione 3 o successiva** (GPL-3.0-or-later): si può usare, studiare, modificare e ridistribuire, anche modificato, purché con la stessa licenza e con il codice sorgente. È fornito senza alcuna garanzia. I componenti di terze parti inclusi nei pacchetti hanno le proprie licenze (THIRD_PARTY_LICENSES.md nel repository del progetto).

---

## Validazione

Versione del programma: 2.19.0 · Documento aggiornato al 24/10/2026

Questo documento descrive **come è stato verificato RepertIA, con quali dati, con quali risultati e con quali
limiti noti**. Serve a chi usa il programma in una consulenza per dichiarare l'affidabilità del metodo
(ISO/IEC 27041 «assicurazione dell'idoneità e dell'adeguatezza dei metodi di indagine», ISO/IEC 27042,
linee guida ENFSI per l'informatica forense; l'impostazione dei controlli segue quella del progetto NIST CFTT:
dati di prova con risultato noto, confronto automatico, rapporto ripetibile).

> RepertIA è un progetto personale, non certificato né accreditato. Il documento non sostituisce la validazione
> del laboratorio che lo usa: ne fornisce la base e indica come ripeterla. Per i risultati decisivi di ogni caso
> resta raccomandato il **riscontro con un secondo strumento** (sezione 4).

### 1. Cosa garantisce il metodo

| Requisito | Come è soddisfatto | Dove si verifica |
|---|---|---|
| La copia forense non viene modificata | Il caso è un database separato; la copia (E01, raw, dmg) è aperta in sola lettura da Sleuth Kit, libewf, libfsapfs. Le estrazioni vanno in `<caso>/estratti` ed `export`, in sola lettura | Hash della copia prima/dopo (Verifica hash) |
| Integrità dei dati acquisiti | MD5/SHA-1/SHA-256 dei dati del supporto confrontati con gli hash di acquisizione dell'E01 o dei log (FTK Imager, Guymager…) | Riga «Acquisizione» del caso; sezione del report |
| Tracciabilità delle operazioni | Registro `audit_log.jsonl` con ogni comando e analisi, concatenato con SHA-256 (ogni riga contiene l'hash della precedente) | «Verifica hash» controlla anche la catena; report: hash dell'ultima riga |
| Ripetibilità | Versioni degli strumenti, dei moduli e impronta SHA-256 dei sorgenti del programma salvate alla preparazione e nel report | Sezione «Ambiente» del report |
| Date corrette | Dati in UTC; FAT/exFAT convertiti dal fuso del dispositivo (rilevato dal registro o dal sistema, dichiarato); ora legale e ora doppia gestite; tre modalità di visualizzazione sempre etichettate | Collaudo DFTT 5 (FAT, ora legale) |
| Distinzione fra dato e interpretazione | I risultati vengono dal programma; il modello linguistico locale propone interpretazioni che vanno verificate sul dato (ogni risposta cita file, offset e inode) | — |

### 2. Collaudo automatico (`forense_collaudo.py`)

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

### 3. Verifiche su copie reali

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

### 4. Riscontro con un secondo strumento (per ogni caso)

«Riscontro con altro strumento» confronta l'elenco dei file e gli hash di RepertIA con quelli esportati da FTK
Imager, Autopsy o un body file di Sleuth Kit e scrive `riscontri/riscontro_<data>.{csv,md}`: file presenti solo in uno
dei due, hash diversi. È la verifica raccomandata per ogni caso in cui i risultati abbiano peso probatorio.
Per gli artefatti decisivi (accessi, esecuzioni, dispositivi USB, cartelle aperte) conviene confermare con un secondo
strumento (Registry Explorer, Autopsy, X-Ways, AXIOM…) o direttamente sul dato grezzo, che RepertIA indica sempre
(file di origine, offset, inode, chiave del registro).

### 5. Limiti noti

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
  delle cartelle cancellate si ricostruiscono quando il journal le contiene, altrimenti «cartella MFT n».
- **Anomalie su file cancellati**: segnalate solo se il contenuto è dimostrabilmente del file; un eseguibile con dati
  aggiunti (installatori) cancellato può quindi non essere segnalato.
- **Hash percettivi** (dHash a 64 bit): trovano immagini ridimensionate o ricompresse, non ritagliate o ruotate; le
  corrispondenze sono indizi da verificare sempre a vista; non sostituiscono PhotoDNA. Le liste Project VIC/CAID si
  usano per gli hash crittografici (MD5/SHA-1) e la categoria.
- **SRUM** (libesedb) e registri eventi (libevtx): letti con le librerie incluse in plaso; il database SRUM può essere
  «sporco» (non chiuso) e alcune righe illeggibili.
- **Modello linguistico**: le risposte non sono riproducibili alla lettera e non sono un risultato: ogni affermazione va
  verificata sul dato indicato.

### 6. Cosa è stato verificato nella 2.18.0 e come

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


### 7. Controllo delle modifiche

Ogni versione è descritta nel registro delle modifiche (README, sezione Aggiornamenti) con cosa cambia, come è
stata provata e cosa NON è stato provato. L'impronta dei sorgenti nel report permette di dimostrare quale versione ha
prodotto un risultato.
