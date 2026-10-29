# RepertIA — By silvexe

*English: [docs/MANUAL.md](../docs/MANUAL.md).*

**Analisi forense di copie di dischi e pendrive con intelligenza artificiale locale.**
Versione 2.20.1 · macOS, Windows e Linux (sperimentale) · interfaccia in italiano o in inglese

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

**Preparazione: avanzamento (2.20).** Durante la preparazione la pagina elenca i passi scelti (il pallino che gira è
quello in corso, i verdi sono finiti) e, sotto i *Dettagli tecnici* e prima di **Interrompi**, un riquadro con due barre:
**Avanzamento complessivo** (passo N di M, percentuale, da quanto tempo è in corso) e la barra del **passo in corso**, con
i numeri quando il passo li conosce (es. «412.000 di 1.640.000 file», l'hash in GB) e una stima del tempo che manca;
per i passi che non sanno in anticipo quanto lavoro resta (plaso, elenco dei file, PhotoRec) la barra scorre finché il
programma lavora. La riga **Ultimo segnale dal programma** dice quanti secondi sono passati dall'ultimo messaggio; se il
programma non scrive nulla da più di 20 minuti compare un avviso: alcune fasi (plaso, PhotoRec, copie shadow su dischi
grandi) lavorano a lungo senza messaggi; se resta così per ore si può interrompere e rifare il caso senza quella fase,
eseguendola dopo dalle *Analisi aggiuntive*. Prima della 2.20 l'elenco dei passi poteva mostrare tutti i passi in verde
e «Date FAT/exFAT col fuso del dispositivo» in corso già dopo l'elenco dei file, mentre il lavoro vero era ancora a metà
(per esempio nelle copie shadow): ora i passi arrivano dal programma stesso, uguali in italiano e in inglese.

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

**Server esterno (2.20.1).** Se l'indirizzo non è su questo computer né nella rete locale (non è un IP privato 10.x,
172.16–31.x, 192.168.x né un nome locale senza punti o con `.local`, `.lan`, `.internal`…), prima di usarlo RepertIA
mostra un **avviso esplicito**: domande e contenuti del caso letti dall'agente uscirebbero dalla rete locale. Se
l'analista conferma, l'uso resta nel registro del caso (`server_llm_esterno_confermato`, `server_llm_esterno`), il
riquadro mostra *(server esterno)* e il report scrive «server esterno indicato dall'analista: *indirizzo*» invece di
«rete interna, senza servizi esterni». All'apertura di un caso un server esterno non confermato non viene usato.
Vedi [AI_ACT.md](../AI_ACT.md).

### Scheda Risultati

| Sezione | Cosa mostra |
|---|---|
| **File System** | Albero della copia a sinistra, contenuto della cartella a destra, con dimensione e date (modifica, creazione, accesso). In cima la **suddivisione del disco** come nella tabella delle partizioni (volumi, spazi non allocati, area della tabella). I file e le cartelle cancellati sono segnati in rosso; i file senza cartella sono in `$OrphanFiles`; lo **spazio non allocato** del file system è in `$Unalloc` (vedi sotto). Filtro per nome, ricerca in tutte le sottocartelle, solo cancellati. |
| **🔎 Ricerca** | Ricerca per **parole chiave** o per **hash** (singolo o lista) in tutti i file della copia, con opzioni e filtri; ogni esito si apre in una scheda a parte e resta salvato (vedi sotto). |
| **File** | Elenco completo dei file, anche cancellati, con ricerca nel percorso ed estensione. |
| **Timeline** | **Grafico a barre dell'attività** e tabella degli eventi (modifica, accesso, metadati, creazione; file system e plaso). |
| **Documenti** | Ricerca di parole e frasi *dentro* i documenti (Word, Excel, PowerPoint, PDF, OpenDocument, RTF, testo, email). Nella vista ad albero la voce si divide **per estensione** (`.docx · Word`, `.xlsx · Excel`, `.pdf · PDF`…, più *E-mail* e *Senza estensione*, con il numero di documenti): un clic mostra solo quella famiglia; lo stesso filtro è il campo *Estensione* della sezione. |
| **Foto/Video/Audio** | Dispositivo, data di scatto, GPS e autori letti con exiftool (foto, video e documenti); sottovoci **Foto**, **Video** e **Audio** (gli audio dall'elenco dei file del caso, anche nei casi già preparati). |
| **File recuperati** | File recuperati dallo spazio libero con PhotoRec (se eseguito). |
| **Evidenze di interesse** | Email, siti, ricerche, telefoni, GPS trovati da bulk_extractor (se eseguito). |
| **⭐ Preferiti** | Categorie di file create dall'analista (vedi *Preferiti*). |

**Spazio non allocato (`$Unalloc`).** In ogni volume leggibile (non APFS) c'è la cartella virtuale `$Unalloc`: un elemento per ogni tratto contiguo di blocchi che il file system segna come liberi (Sleuth Kit, `blkls`), con nome `Unalloc_<partizione>_<settore iniziale>_<settore finale>`, settori e byte nella copia. Non sono file: possono contenere resti di file cancellati. Si aprono come gli altri elementi in **Testo** (stringhe leggibili ASCII e UTF-16, primi 50 MB) ed **Esadecimale** (tutto il tratto, con ricerca), si **esportano** con SHA-256 in `export/non_allocato/` (anche in una selezione, con `manifest.csv`) e si mettono nei **Preferiti**: nel report compaiono con la posizione in byte e lo SHA-256. I byte si leggono dalla copia forense solo quando servono, nulla viene copiato nel caso. La prima apertura di `$Unalloc` calcola i tratti (su un disco da 1 TB un paio di minuti), poi restano nel caso. Anche le righe **Unallocated** della suddivisione del disco e i volumi che Sleuth Kit non legge si aprono così (Esadecimale, Testo, Esporta, Preferiti). Nel report portatile `$Unalloc` mostra l'elenco dei tratti già calcolati (posizione e dimensione).

**Vista ad albero (predefinita).** Le sezioni sono un albero laterale, con le sottovoci
indentate: file cancellati, timeline del file system e di plaso (con le singole fonti di plaso),
foto con GPS, tipi di file recuperati, tipi di evidenze di interesse, ricerche salvate, categorie
di preferiti e schede aperte. Una sottovoce apre la sezione con il filtro già impostato.
**☰ Vista a schede** passa alle schede orizzontali, **🌲 Vista ad albero** torna all'albero; la
scelta viene ricordata. In cima all'albero il campo **Filtra le voci** (2.20) tiene solo le voci che contengono le
parole scritte, senza badare a maiuscole e accenti (es. «whatsapp», «biome», «whatsapp group»), con le voci madri
aperte; **Esc** toglie il filtro.

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
- **dopo**: *Hash dei file → Esegui* nel menu *Analisi aggiuntive* (o dal modulo di
  ricerca per hash). Se si interrompe, *Aggiorna* riprende dai file che mancano;
- **solo quando servono**: una ricerca per hash senza hash calcolati li calcola al volo solo
  per i file che rientrano nei filtri (es. solo `jpg` in una cartella) e li conserva per le
  ricerche successive.

Con gli hash calcolati il riepilogo segnala anche i **file con contenuto identico** e l'agente
può cercare per hash.

**Filtri per colonna.** In File System, File, Timeline, Documenti, Foto/Video/Audio, File recuperati,
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
- **Riquadri ridimensionabili** (2.20): un divisore sottile separa pannello del caso, albero dei Risultati, albero delle
  cartelle del File System, elenco, anteprima/dettagli a destra e, nella vista chat, elenco delle conversazioni. Si
  trascina col mouse; il **doppio clic** sul divisore rimette la larghezza predefinita. Le misure restano nella memoria
  del browser (se disponibile); **↔ Ripristina colonne** rimette anche i riquadri com'erano. Lo stesso nel report
  portatile (albero delle cartelle, categorie dei Preferiti, anteprima, elenco delle chat).
- **Divisori orizzontali** (2.20): dove una parte sta sopra l'altra si sposta col mouse anche il confine in su e in giù —
  grafico «Attività» della Timeline e tabella, intestazione e filtri sopra le tabelle (riepilogo della ricerca, percorso e
  filtri del File System, pannello dei filtri; misura diversa per ogni sezione), filtri ed elenco delle conversazioni e
  intestazione e messaggi della vista chat; nel report portatile grafico dei mesi/giorni della Timeline ed elenco. Il
  **doppio clic** rimette l'altezza predefinita; **▾ / ▸** a sinistra del divisore (e ▾ accanto al titolo del grafico)
  comprime il riquadro sopra in una riga sottile e lo riapre. Misure e riquadri compressi restano nella memoria del
  browser; **↔ Ripristina colonne** rimette anche questi.
- **Barra in alto compatta** (2.20): se non sta su una riga, gli strumenti trovati diventano un'unica etichetta
  **«✓ 8 strumenti»** (o «! 6 di 8 strumenti» se ne manca qualcuno) che al clic apre l'elenco completo con i soliti
  suggerimenti; poi restano le due ricerche più recenti con **«tutte (N)»**, che apre il pannello Ricerca (tutte le
  ricerche sono anche sotto *🔎 Ricerca* nell'albero), e il sottotitolo passa nel suggerimento del nome.
- **🔎 Ricerca** (2.20), in alto a destra sotto il selettore del tema, apre il pannello di ricerca (casi dei dischi e
  degli smartphone). Dopo una ricerca accanto compare un'**etichetta** con le parole e il numero di file trovati
  (es. «🔎 “bitcoin” · 37»): un clic ne riapre i risultati, come la voce nell'albero; ✕ toglie solo l'etichetta (la
  ricerca resta salvata). Si vedono le ultime quattro ricerche del caso; aprire il pannello o un'etichetta è un passo di
  *Indietro / Avanti*. La voce *🔎 Ricerca* resta anche nell'albero dei Risultati.
- **⚡ Risultati del caso: ricerca veloce** (2.20), prima scheda del pannello di ricerca (la predefinita nei casi
  smartphone): cerca **mentre scrivi** in quello che il caso mostra come risultato — artefatti di sistema, artefatti di
  iLEAPP/ALEAPP, chiamate, messaggi e conversazioni delle chat, rubriche, posta — e risponde in pochi millisecondi anche
  su un telefono con 500.000 righe di iLEAPP. I risultati sono raggruppati come nell'albero (*Rubriche*, *Conversazioni*,
  *Chat › WhatsApp*, *Chiamate*, *Artefatti iLEAPP/ALEAPP › categoria › artefatto*…) e **chiusi**: in cima c'è il totale,
  ogni gruppo mostra quanti risultati contiene e si apre con un clic, così si sceglie quello che serve. Ogni riga ha data,
  testo evidenziato e fonte; un clic apre l'elemento nell'anteprima (per i messaggi *💬 Apri chat*), una conversazione si
  apre nella vista chat, una **voce della rubrica** si apre nell'anteprima con nome, numero, database di origine (pulsante
  *Fonte* per vederlo nell'albero), le altre voci con lo stesso numero e le conversazioni con quel numero; *🔎 Cerca questo
  numero* lancia una nuova ricerca solo se lo si chiede. **Numeri di telefono in qualunque formato**: una ricerca fatta di cifre
  (almeno 6, con o senza +, spazi, parentesi, trattini) confronta le ultime 9 cifre, quindi «+1 (919) 928-2177»,
  «9199282177» e «19199282177@s.whatsapp.net» si trovano a vicenda. Per le parole servono almeno 3 caratteri; maiuscole e
  minuscole sono uguali. **Salva come ricerca** conserva tutti i risultati come ricerca del caso (scheda, voce *🔎 Ricerca*,
  Preferiti, CSV, registro). L'indice è il file `ricerca_veloce.sqlite` nella cartella del caso: si costruisce alla prima
  ricerca (una volta sola, con l'avanzamento: circa 1 minuto e 1 GB per un iPhone con 500.000 righe di iLEAPP), si rifà da
  solo quando cambiano i risultati, si può cancellare senza perdere nulla e la sua costruzione va nel registro. I valori
  segreti del portachiavi non entrano nell'indice. Non cerca nel contenuto dei file e nella timeline: per quelli resta la
  ricerca per *Parole chiave*.
- **Filtri delle colonne** (2.20): il riquadro dei valori (▾) non esce mai dalla finestra, nemmeno sui portatili da 13":
  si apre sotto o sopra il pulsante secondo lo spazio, l'altezza dipende da quella della finestra, l'elenco dei valori
  scorre al suo interno e ordinamento, campo di ricerca e pulsanti *OK / Azzera colonna / Annulla* restano sempre visibili.
  Il riquadro si **allarga** trascinando la maniglia sul bordo sinistro, per leggere i nomi lunghi dei file (doppio clic:
  larghezza predefinita; la misura resta nella memoria del browser); il nome intero compare anche passandoci sopra.
  **Ricerca nei valori**: scrivendo nel campo *Cerca nei valori…* restano visibili solo i valori che contengono il testo;
  con **OK** (o Invio nel campo) il filtro tiene **solo i valori trovati e spuntati**, come in Excel. Prima della 2.20 i
  valori nascosti dalla ricerca restavano spuntati, e «Seleziona tutti i trovati» + OK equivaleva a «tutti»: il filtro non
  si applicava. Vale anche nel report portatile.
- **Apertura del caso e sezioni pesanti** (2.20): all'apertura di un caso la finestra con la barra di avanzamento compare
  **subito, dal clic**, e segue l'apertura del caso con il collegamento al server LLM, poi prepara l'albero dei Risultati, i
  conteggi e il grafico della Timeline; il caso si usa quando è tutto pronto. Il **riepilogo del caso** mostrato
  all'apertura resta nella cache del caso finché il caso e i suoi database non cambiano (iPhone di prova con 830.000 file:
  riapertura da circa 14 s a meno di un secondo). Dopo l'apertura, in sottofondo, si prepara la prima pagina di ogni
  sezione con dati e il programma ricorda l'ultima pagina vista di ogni sezione: il primo clic su *Artefatti di sistema*,
  *Timeline*, *File*… non aspetta più la ricerca nel database (sullo stesso caso da 0,7–4,9 s a meno di 0,2 s) e tornando
  a una sezione la tabella compare subito (si aggiorna da sola se nel frattempo è cambiato qualcosa). Anche dopo
  *Avvia l'analisi* la pagina della preparazione compare subito. Il programma tiene queste risposte in memoria finché i
  database del caso non cambiano: lo spostamento tra le sezioni è immediato. Il **grafico della Timeline** nell'ora del telefono o in ora italiana
  si calcola molto più in fretta (iPhone di prova con 2,5 milioni di eventi: da circa 40 s a 2-7 s, stessi numeri di prima)
  e, mentre si prepara, al suo posto c'è un messaggio di attesa.
- **Cerca nel Testo** (2.20): nella scheda *Testo* dell'anteprima, accanto ad *Anteprima*, una casella di ricerca come
  quella dell'Esadecimale: evidenzia tutte le occorrenze (fino a 5.000), **◀ ▶** o **Invio / Maiusc+Invio** passano alla
  precedente o alla successiva, *maiuscole* distingue maiuscole e minuscole.
- Quando apri l'anteprima il pannello del caso si nasconde da solo per fare spazio e ricompare
  quando la chiudi.
- **Colonne ridimensionabili** (2.20) in tutte le tabelle dei Risultati, come in Excel: si trascina il bordo destro
  dell'intestazione; il **doppio clic** sul bordo adatta la colonna al testo. Le larghezze restano per ogni sezione
  (memoria del browser) finché le colonne sono le stesse; **↔ Ripristina colonne** nell'ultima intestazione torna alla
  disposizione automatica. L'intestazione resta sempre bloccata in alto, anche sopra i Dettagli «campo: valore».
- **← Indietro / → Avanti** (2.20), sotto la barra del caso: ogni apertura (sezione o sottovoce, file nel riquadro,
  *Mostra nell'albero*, scheda di ricerca o dei preferiti, percorso citato dall'agente, *Apri nei Risultati* del
  Riepilogo, chat, conversazione, allegato) è un passo. Indietro torna allo stato di prima: scheda, sezione, filtri e
  ricerca, ordinamento, pagina, scorrimento, riga, riquadro aperto e, per le chat, conversazione, messaggio e allegato.
  Funzionano anche il tasto Indietro del browser, **Alt+←** / **Alt+→** e **Cmd+[** / **Cmd+]**. Accanto, le **briciole**
  (es. *Artefatti di sistema › Messaggi delle chat › Telegram › Josh Hickman › 📎 foto.jpg*, *🔎 Ricerca › Parole: …*,
  *Timeline › File system*): ogni voce è cliccabile. Le briciole corrispondono sempre a quello che si vede: al cambio di
  sezione o di sottovoce la tabella mostra subito «Carico…» e, se arrivano in ritardo i dati di una voce cliccata prima,
  vengono scartati. Ogni clic è un passo anche se il caricamento precedente non è finito (sui casi grandi dura alcuni
  secondi). Riquadri e anteprime si chiudono con **Esc** senza ricaricare la tabella.

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

### Pannello del caso e barra dei menu
Il **pannello del caso** (a sinistra) mostra i dati del caso, supporto, hash e ultima verifica, partizioni, stato del
server LLM e i **Reperti** registrati.

**Barra dei menu (2.20).** Sotto la scritta RepertIA, nella vista del caso, quattro menu a tendina (prima erano i
riquadri *Azioni* e *Analisi aggiuntive* del pannello):
- **Caso**: *Modifica dati del caso*, **Cartella caso**, **File esportati**, **Cache e posizione**;
- **Report**: **Report** (anche in **PDF** e **Word** .docx: `report.pdf` e `report.docx` nella cartella del caso, con
  lo SHA-256 nel registro) e **Report portatile**;
- **Verifiche**: **Verifica hash** (o **Calcola hash copia** se l'hash non è ancora stato calcolato), **🔗 Verifica
  registro**, **Riscontro con altro strumento**, **Liste di hash**;
- **Analisi aggiuntive**: ogni analisi con il suo stato (✓ e i numeri, oppure «non eseguito») e **Esegui** / **Rifai**
  (negli smartphone anche chat, iLEAPP/ALEAPP e backup di WhatsApp).

A destra **← Tutti i casi**. Un clic apre il menu; con un menu aperto basta passare sugli altri; un clic su una voce,
fuori dal menu o Esc lo chiude.

**Reperti e verifica (2.20.1, AI Act).** Ogni reperto ha un'etichetta con l'origine: **«Generato da modello IA (*nome*)
– da verificare»** per quelli registrati dall'agente (in `findings.json`: `"origine": "modello IA"`, modello, server,
`"stato": "da verificare"`), **«Inserito dall'analista»** per quelli scritti con *Registra reperto*, «Origine non
registrata – da verificare» per quelli dei casi preparati con versioni precedenti. Dopo averlo controllato sugli strumenti
forensi, **✓ Confermo, verificato** chiede l'operatore (proposto quello dei dati del caso) e registra operatore e data nel
caso e nel registro (`finding_verificato`): l'etichetta diventa «Verificato da *operatore* il *data*». Il titolo del
riquadro indica quanti reperti restano da verificare. Nei report (Markdown, Word, PDF, portatile) ogni reperto porta la
sua etichetta; la frase «Ogni reperto è stato verificato dall'analista sugli strumenti forensi» compare **solo** se lo
sono tutti, altrimenti il report dice quanti sono verificati e quanti no; i metadati di Word e PDF indicano che il
documento contiene testo generato da IA. Sotto ogni risposta dell'agente c'è l'etichetta fissa «Risposta generata da
modello IA (*nome*): spunto da verificare». I testi automatici sono indicati come tali: «Trascrizione automatica» per gli
audio, «testo OCR automatico» nell'elenco dei documenti e nel report. Vedi [AI_ACT.md](../AI_ACT.md).

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

## Trascrizione degli audio (2.20)

RepertIA trascrive il parlato degli audio (note vocali delle chat, registrazioni, messaggi della segreteria…) con
**Whisper** (motore whisper.cpp 1.9.5), **su questo computer**: gli audio non vengono inviati a nessuno e non si usa
l'LLM. Il testo diventa ricercabile ed è sempre indicato come **«trascrizione automatica, da verificare ascoltando
l'audio»**: non sostituisce una trascrizione certificata.

- **Quando**: alla creazione del caso, con la casella **Trascrivi gli audio** (pagina della copia forense e pagina
  smartphone), come ultimo passo della preparazione; oppure dopo, dal caso: **Analisi aggiuntive → Trascrizione degli
  audio → Esegui**; per un solo audio, dalla sua anteprima: **📝 Trascrivi questo audio** (o **🔁 Ritrascrivi**, per esempio
  con un altro modello). Non parte mai da sola. Alla fine si torna ai Risultati (o all'anteprima dell'audio) con un
  avviso dell'esito, senza messaggi nella Conversazione.
- **Quali audio**: solo quelli allegati alle chat, tutti gli audio del caso, oppure solo quelli selezionati (per esempio
  dalla sezione *Foto/Video/Audio → Audio*). **Opzioni**: lingua (riconosciuta da sola o fissata), durata massima per
  audio (predefinita 30 minuti), rifare quelli già trascritti con lo stesso modello.
- **Modello**: tre modelli, *Veloce (base, 60 MB)*, *Bilanciato (small, 190 MB, consigliato)* e *Preciso (large-v3-turbo,
  574 MB)*. **Non sono nei pacchetti** e **non si scaricano da soli**: la prima volta una finestra mostra provenienza
  (repository ufficiale di whisper.cpp, versione fissata), licenza (MIT), dimensione e SHA-256 atteso; il download avviene
  solo con **Accetto e scarico**, poi l'impronta si ricontrolla (un file diverso viene eliminato). Su un computer senza rete
  **Ho già il file del modello…** accetta un file solo se il suo SHA-256 è quello dell'elenco. I modelli restano accanto
  alle impostazioni (`modelli_trascrizione/`, con `modelli.json`: chi, quando, da dove) e valgono per tutti i casi: la
  finestra mostra la cartella (**Apri la cartella**) e, accanto a ogni modello installato, **Rimuovi** (nel registro). Alla
  creazione del caso la finestra compare prima di avviare; annullando, il caso si prepara senza trascrizione.
- **Dove si vede il testo**: ricerca nel testo (tipo «Trascrizione automatica»); anteprima di ogni audio (scheda con le
  frasi e i loro orari: un clic fa partire l'audio da lì); vista chat, sotto la nota vocale; *Esporta chat* (HTML e CSV);
  report portatile (chat e ricerca); report del caso (sezione con numeri, modello e SHA-256, motore e SHA-256, lingua).
- **Registro**: l'installazione di ogni modello e ogni trascrizione (modello e impronta, versione e impronta del motore,
  opzioni, esito). L'audio originale non viene toccato: ffmpeg ne converte una copia di lavoro in WAV 16 kHz, poi tolta.
- **Velocità** (Mac Apple Silicon, modello small): un audio di 8 secondi in circa 1,5 secondi. Su Windows e Linux il
  motore gira sul processore, più lentamente.

## Report portatile (per chi non ha la copia forense)

Dal menu **Report → Report portatile** crea in `export/report_portatile_<data>/` una
cartella con `index.html` da consegnare (anche zippata): si apre con un doppio clic in qualsiasi
browser, **offline**, senza RepertIA, senza la copia forense e senza IA.

- **Contiene tutto il catalogo**: albero del file system con i file cancellati, date, dimensioni,
  hash (se calcolati), metadati (dispositivo, data, GPS, autore), testi estratti dei documenti,
  timeline (file system e plaso), file recuperati e tracce, reperti e report.
- **Contenuto dei file**, a scelta: solo i file dei reperti e delle selezioni esportate con
  *Esporta*; anche tutti i documenti e le immagini fino a una dimensione; oppure **tutti i file
  del supporto** (anche cancellati, a scelta), così chi riceve il report consulta tutto come se
  avesse la copia forense. La finestra mostra prima numero di file, dimensione, spazio libero e **spazio che il report
  occuperà davvero sul disco** (2.20): ogni file occupa almeno un cluster (128 KB su un disco exFAT da 1 TB, quindi
  con molti file piccoli il report occupa molto più della somma dei file), più cartelle, anteprime, dati e indici.
  Se non basta, lasciando liberi almeno 2 GB, *Crea il report* resta spento; durante la creazione lo spazio si
  ricontrolla e, se il disco si sta riempiendo, il report si ferma e toglie la cartella lasciata a metà (scritto nel
  registro del caso). Sul Mac, sui dischi exFAT/FAT, i file nascosti «._nome» che macOS crea accanto a ogni file si
  tolgono man mano; un file del supporto che si chiama già «._…» si salva come «_._…» (il nome originale resta nel
  catalogo).
  I file sono nella cartella `file/` con l'albero originale. Per reperti e selezioni: pagine di
  PDF e documenti Office (con LibreOffice) come immagini, esadecimale, exiftool e istat; per gli
  altri file anteprime più leggere (prime pagine dei PDF, primi 4 KB in esadecimale, metadati già
  indicizzati) e il pulsante *Apri il PDF originale*.
- **Analisi estese**, se eseguite: sezioni *Artefatti di sistema*, *Posta* (messaggi con
  allegati), *Archivi e allegati* e *Anomalie*, con esportazione CSV. I file estratti da
  archivi e posta sono inclusi secondo la stessa scelta del contenuto dei file.
- La creazione mostra una **barra di avanzamento** con percentuale, fase e tempo stimato. Durante la creazione la finestra
  **resta aperta** (un clic fuori o *Chiudi* non la nascondono più mentre il lavoro continua): si chiude da sola alla
  fine oppure con **Interrompi**, che ferma la creazione e toglie la cartella lasciata a metà (l'interruzione va nel
  registro del caso). Il report si apre più in fretta: i file del catalogo si scaricano insieme e gli indici dell'albero
  sono più leggeri (iPhone di prova con 830.000 voci: da circa 19 s a 5 s).
- La **ricerca nel contenuto** copre il testo dei documenti indicizzati e, per tutti gli altri
  file inclusi, le stringhe leggibili (ASCII e UTF-16) estratte alla creazione; foto, video e
  audio si cercano nei metadati. Nel browser la ricerca scorre l'indice a blocchi, con
  avanzamento e pulsante *Interrompi*.
- **⚡ Risultati del caso** (2.20), prima voce della Ricerca: come nel programma, cerca mentre scrivi negli
  artefatti (anche di iLEAPP/ALEAPP), nelle chiamate, nelle chat e nelle conversazioni inclusi nel report; risultati
  raggruppati e chiusi, un clic apre l'artefatto o il messaggio nella chat; i numeri di telefono si trovano in
  qualunque formato (ultime 9 cifre). Mentre scrivi cerca subito in tutto tranne le righe di iLEAPP/ALEAPP; con **Invio**
  o *Cerca* scorre anche quelle, un file alla volta, con l'avanzamento e *Interrompi* (iPhone con 500.000 righe: 1-4 s).
  Le rubriche non sono nel report portatile: i contatti si trovano negli artefatti di iLEAPP/ALEAPP.
- **Artefatti di iLEAPP/ALEAPP a richiesta** (2.20): le loro righe sono in file per artefatto (al massimo 20.000 righe
  ciascuno) e si caricano scegliendo la voce nel secondo menu della categoria *Artefatti iLEAPP/ALEAPP*; il numero
  totale resta nel menu. Prima erano tutte in un unico file caricato all'avvio (iPhone di prova: 618 MB, troppi per il
  browser); ora quel file pesa pochi KB.
- **Timeline per giorno** (2.20): gli eventi sono in file per giorno (in parti da 50.000 nei giorni molto pieni) e la
  tabella compare appena arriva il primo; nei mesi con più di 150.000 eventi si apre il giorno più ricco, gli altri giorni
  con un clic e il mese intero con *Carica tutto il mese*. Prova: iPhone con 2,5 milioni di eventi (1,07 milioni in un
  solo giorno), tabella in 0,4 s invece di caricare un file di centinaia di MB.
- **Indietro del browser e briciole** (2.20): ogni vista, categoria degli artefatti e conversazione aperta è un passo
  della cronologia del browser; in alto le briciole dicono dove si è (ogni voce è cliccabile) con ← →. Nella vista chat
  dei casi smartphone: ⭐ per la conversazione intera ed **⬇ Esporta chat** (HTML e CSV scaricati dal browser; lo SHA-256
  dei due file si mostra a video e va annotato, perché il report portatile non scrive nel registro del caso).
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
- **Liste di hash / NSRL**: dal menu *Verifiche*, *Liste di hash* carica liste di hash noti
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

Si attivano alla creazione del caso oppure dopo, dal menu *Analisi aggiuntive*, senza
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

### Smartphone (novità 2.20)

Dalla pagina iniziale, **📱 Smartphone** apre l'analisi di un'**estrazione del file system completo** di un iPhone o di un
telefono Android, con la stessa interfaccia, gli stessi report e lo stesso registro dei dischi. **💽 Memorie di massa** è il
percorso di sempre per E01, dd/raw e dmg. Nell'elenco dei casi l'icona indica il tipo.

- **Formati**: lo zip prodotto dagli strumenti di acquisizione (Cellebrite «Full File System», GrayKey, altri), un tar
  (Magnet ACQUIRE, estrazioni Android), un **tar.gz** o una **cartella** già estratta. Le estrazioni **XRY** si aprono se
  esportate come file system (cartella, zip o tar); il formato proprietario `.xry` non si legge. Un report **UFDR** non è
  un'estrazione del file system: arriverà in una versione successiva.
- **Nessuna copia**: i file si leggono dall'estrazione quando servono (dello zip si legge l'indice interno e ogni file si
  decomprime per conto suo). Lo SHA-256 dell'estrazione si calcola come per le copie dei dischi, e si confronta con l'hash
  di acquisizione se c'è un log accanto. Un **tar.gz** non permette di leggere un file senza decomprimere tutto quello che
  lo precede: RepertIA crea nella cartella del caso una **copia derivata decompressa** (`decompressa/`), con lo SHA-256
  dell'originale e della copia e il riferimento all'originale, che non viene modificato.
- **Albero, elenco dei file, timeline, ricerca, testo dei documenti, metadati delle foto, hash dei file, anteprime,
  report e report portatile** funzionano come per i dischi; l'estrazione compare nell'albero come «Estrazione «nome»».
  Sistema e versione (SystemVersion.plist, build.prop) e **fuso del telefono** si ricavano dall'estrazione.
- **Date**: zip con i campi estesi e tar registrano le date in UTC. Le voci di uno zip con la sola data DOS (ora locale
  senza fuso, spesso l'ora dell'estrazione e non quella del telefono) sono convertite con il fuso del dispositivo e il
  caso lo dichiara. Una cartella già estratta ha le date del computer su cui è stata copiata: dichiarato.
- **Chat**: lettori propri di RepertIA per **WhatsApp** (iPhone e Android), **iMessage/SMS** (iPhone) e **SMS/MMS**
  (Android), con i nomi presi dalle rubriche del telefono e di WhatsApp. Ogni database si legge da una copia di lavoro con
  i suoi file `-wal`/`-shm`, così compaiono anche i messaggi non ancora riversati nel database. Il pulsante **💬 Apri le
  chat** del pannello del caso apre la **vista chat**: conversazioni con filtri per app, nome o numero, testo e periodo;
  messaggi a fumetti con mittente, ora, stato (consegnato, letto), allegati con miniatura (*Anteprima*, *Mostra
  nell'albero*) e posizioni; ogni messaggio indica database, tabella e riga di origine (clic per copiare il riferimento).
  I messaggi entrano anche nella timeline e, uno per conversazione, negli Artefatti: la voce **Messaggi delle chat** è
  divisa per app nell'albero; ogni riga mostra i due interlocutori (📱 *questo dispositivo*, con il numero o l'account se
  è scritto nell'estrazione: sms.db, CommCenter, telephony.db, preferenze di WhatsApp; 👤 l'altro con il nome della rubrica
  e il numero o l'ID, *numero breve/servizio* per i numeri di 3-6 cifre come 32665; 👥 per i gruppi nome e partecipanti) e,
  nei Dettagli, periodo nel fuso scelto, messaggi inviati e ricevuti, allegati e anteprima dell'ultimo messaggio. Il
  pulsante **💬 Apri chat** della riga apre la vista chat su quella conversazione. Nella vista chat ogni messaggio si mette
  nei **⭐ Preferiti** o si registra come **📌 Reperto** (riferimento con database, tabella e riga); i segnaposto «messaggio
  eliminato» lasciati dalle app sono evidenziati. Il **report portatile** ha la stessa vista chat (voce *💬 Chat*), con gli
  allegati apribili se il loro contenuto è incluso nel report, ⭐ sui singoli messaggi e *💬 Apri chat* dagli Artefatti.
- **iLEAPP e ALEAPP** (Alexis Brignoni e collaboratori, licenza MIT): con l'opzione *Artefatti con iLEAPP/ALEAPP*
  RepertIA esegue la versione inclusa sull'estrazione; le loro tabelle diventano artefatti (categoria «Artefatti
  iLEAPP/ALEAPP»), divisi nell'albero per **categoria di iLEAPP/ALEAPP** e poi per **artefatto**, ciascuno con il numero
  di righe (un clic filtra la sezione; anche nel report portatile, con il secondo menu accanto alla categoria). La colonna
  Dettagli mostra i campi come tabella «campo: valore», con le date nel fuso scelto in alto. Il loro rapporto HTML resta
  nella cartella del caso (`leapp/`): si apre dal Finder o da Esplora file, non dentro RepertIA, perché contiene dati della
  prova. Versione e impronta sono nel caso e nel report.
- **Chat e chiamate da iLEAPP/ALEAPP** (2.20): le app di chat che RepertIA non legge con i propri lettori (Telegram,
  Discord, Instagram, Facebook Messenger, Google Messages, Snapchat Android, LINE, Viber, Kik, TikTok, X, Zoom, Wire,
  TextNow, Burner, IMO, MeWe, Skout, Houseparty, CoverMe; Wickr solo metadati) compaiono anche in **Messaggi delle chat**,
  una sottovoce per app, e nella vista chat (con «verso non indicato» quando la fonte non dice se il messaggio è inviato
  o ricevuto). La nuova sezione **Chiamate** ha una riga per chiamata: data, direzione (in arrivo, in uscita, persa,
  rifiutata, segreteria), numero, nome in rubrica, durata, risposta, app (telefono, FaceTime, WhatsApp, Duo, Instagram,
  LINE, Viber…), e tutte le fonti. Le righe uguali di fonti diverse sono unite: stessa chiamata se stesso numero entro 5
  secondi (30 per *interactionC*, che registra l'inizio dell'interazione qualche secondo prima); stesso messaggio se stesso
  identificativo, o stessa conversazione, ora, verso e testo (es. le copie dei database nel mirror di Magisk). I valori
  discordanti tra le fonti sono segnalati. Le righe originali restano negli *Artefatti iLEAPP/ALEAPP*. La corrispondenza
  tra colonne e campi è in `forense_mobile_leapp_mappa.json` (si estende senza toccare il codice); gli artefatti che
  iLEAPP/ALEAPP dichiarano come conversazione e che non sono nella mappa si leggono con la loro dichiarazione. Le
  conversazioni WhatsApp, iMessage/SMS e SMS/MMS restano quelle dei lettori di RepertIA (gli artefatti corrispondenti di
  iLEAPP/ALEAPP non si duplicano). Nel caso: `leapp_chat` con le righe usate e gli artefatti non mappati, `chiamate`.
- **Pulsanti delle chat** (2.20): **💬 Apri chat** nella tabella (icona) e nel pannello dei dettagli di una conversazione,
  accanto a Fonte, Reperto, Chiedi all'agente e Preferiti. Nella vista chat: ⭐ **Preferiti** e 📌 **Reperto** per il
  singolo messaggio e per l'**intera conversazione**; **⬇ Esporta chat** scrive in `export/chat/` un HTML leggibile
  (fumetti, miniature delle immagini, allegati copiati accanto con il loro SHA-256) e un CSV, con un'intestazione che
  riporta caso, app, interlocutori, periodo, fuso orario usato, estrazione con SHA-256, database di origine con offset,
  inode e SHA-256 (anche dei file `-wal`/`-shm`); gli SHA-256 dei file esportati vanno nel registro a catena.
- **Anteprima degli allegati** (2.20): le miniature nei fumetti mostrano già l'immagine; anche i **video** hanno la
  miniatura (un fotogramma: Quick Look sul Mac, ffmpeg su Windows e Linux), pure quando il file nell'estrazione non ha
  estensione (es. Telegram): il tipo si riconosce dal nome dell'allegato o dall'intestazione del file (MP4/MOV). Nelle miniature dei Risultati, se
  il programma non riesce a fare la miniatura di un video, il fotogramma lo ricava il browser (legge solo l'inizio del
  file, quando la casella è visibile) e lo salva come miniatura; le miniature non riuscite con una versione precedente si
  riprovano. Le miniature si caricano in coda, tre per volta e solo per le caselle visibili, così la pagina non si blocca
  anche con centinaia di video. Il clic apre l'anteprima **sopra la
  chat**, che resta dietro nella stessa posizione. Immagini (clic per ingrandire), video, audio, PDF e testo come nel
  riquadro di sempre, con le schede Testo, Esadecimale e Metadati e i pulsanti Mostra nell'albero, Esporta, Reperto,
  Preferiti e Chiedi all'agente; le frecce **← →** (anche da tastiera) passano all'allegato precedente o successivo della
  stessa chat, con data, mittente e testo del messaggio; **Esc** o ✕ chiudono e il messaggio resta evidenziato. Gli
  allegati delle chat ricavate da iLEAPP/ALEAPP che il loro rapporto ha copiato (`media/…`) si vedono come copia di
  lavoro di quello strumento, dichiarata.
- **Allegati: file trovato, verificato o solo miniatura** (2.20): gli allegati si cercano con la stessa ricerca dei
  *File citati* (sotto). WhatsApp registra `file_hash` (base64 dello SHA-256): serve a trovare il file anche se è stato
  spostato o rinominato e a **verificarlo** («SHA-256 uguale a quello registrato dall'app»; un hash diverso è segnalato).
  Se il file non è nell'estrazione si vede la **miniatura salvata nel database** (WhatsApp Android: `message_thumbnail`,
  `message_thumbnails`, `raw_data`; WhatsApp iOS: il file `.thumb` indicato dal database) con la scritta «miniatura dal
  database – file non presente nell'estrazione», anche in *Esporta chat* e nel report portatile. Gli allegati delle chat
  ricavate da iLEAPP/ALEAPP sono collegati al file originale dell'estrazione quando c'è.
- **Portachiavi (keychain) di iOS** (2.20): il portachiavi di un iPhone si acquisisce a parte (es. GrayKey). Nel modulo
  del nuovo caso smartphone (o nel pannello del caso, *Scegli il portachiavi…*) si indica il file: RepertIA ne calcola lo
  SHA-256 (nel registro a catena), **non lo copia nel caso** (lo usa dal suo percorso; se cambia dopo la registrazione non
  viene usato) e lo passa a **iLEAPP con `--keychain`**; dopo averlo scelto in un caso esistente si rifà iLEAPP. **La
  decifratura e la lettura sono di iLEAPP.** Il portachiavi fornito serve agli artefatti che cercano la chiave di un'app
  (Signal, Session, SimpleX, Snapchat, Wickr); gli artefatti del portachiavi (*Keychain Wifi Credentials*, *Keychain Web
  Passwords*, Bluetooth, account di posta) iLEAPP li ricava dal portachiavi che trova dentro l'estrazione (es.
  `extra/KeychainDump/backup_keychain_v2.plist` di Cellebrite). Il pannello e il report del caso dicono quale portachiavi
  è stato usato: *fornito dall'operatore*, *trovato nell'estrazione* o *nessuno*, con le voci lette da iLEAPP.
  **Valori segreti** (password, chiavi, token): nascosti («••••••») in tabelle, dettagli, ricerca, report e agente; nel
  pannello dei dettagli **🔒 Valori segreti** → **Mostra** rivela un valore alla volta e la lettura va nel registro
  (senza il valore); nel report portatile solo se si spunta *Includi i valori segreti del portachiavi* (scelta
  registrata). Il rapporto di iLEAPP nella cartella del caso li contiene in chiaro. Le chat che iLEAPP decifra con il
  portachiavi (Signal, Session, SimpleX) compaiono nella vista chat con «🔑 decifrato da iLEAPP con il portachiavi».
  Collaudato solo con portachiavi **finti**; non provato su portachiavi GrayKey o Cellebrite reali.
- **Sysdiagnose di iOS** (2.20): l'archivio `sysdiagnose_<data>_<ora><fuso>_<sistema>_<dispositivo>_<build>.tar.gz`
  che l'iPhone produce su richiesta (processi in esecuzione, spegnimenti, Wi-Fi, Bluetooth, batteria, impostazioni gestite,
  registri…) si acquisisce di solito a parte. Nel modulo del nuovo caso smartphone il campo facoltativo **Sysdiagnose
  (.tar.gz)** ne accetta uno o più (*Aggiungi* / *Scegli…*: ogni file è controllato subito e mostra data e dispositivo);
  in un caso esistente *Aggiungi un sysdiagnose…* nel pannello del caso. RepertIA ne calcola lo SHA-256 (nel registro a
  catena), **non lo copia nel caso** (se cambia dopo la registrazione non viene letto) e fa un **secondo giro di iLEAPP
  sull'archivio** (iLEAPP estrae nel suo rapporto solo i file che legge: moduli *Sysdiagnose Process*, *Shutdown Log*,
  *sdl_…* (Wi-Fi, Bluetooth, dischi, preferenze, account…), *Battery UI*, *ManagedSettings*, *Container Manager* e gli
  altri che trovano i loro file). Le righe vanno negli Artefatti, sottovoce **Sysdiagnose** di iLEAPP, con il campo
  *Origine* «da sysdiagnose <nome del file>» (anche nel titolo). **Data di creazione** (UTC e ora del telefono) e
  **dispositivo** (tipo, sistema, build; il modello se c'è `remotectl_dumpstate.txt`) vengono dal nome della cartella
  dell'archivio, scritto dall'iPhone: sono dichiarati nel pannello, nel report (sezione *Sysdiagnose*) e nel registro.
  Nel pannello ↻ rilegge un sysdiagnose e ✕ lo toglie dal caso con le sue righe (il rapporto di iLEAPP resta nella
  cartella del caso). *Fonte* su una di queste righe spiega che il file è dentro il sysdiagnose, fuori dall'estrazione.
  Collaudo: archivi nella forma di un sysdiagnose costruiti con i ritagli **pubblici** dei test di iLEAPP (non sono
  sysdiagnose completi); non provato su sysdiagnose completi di un caso.
- **Report dei casi smartphone** (2.20): elenca solo gli strumenti usati davvero in quel caso, con la versione — RepertIA
  (lettura dell'estrazione), lettori di chat, iLEAPP/ALEAPP con l'impronta, exiftool e pdftotext se si è indicizzato,
  7-Zip e Tesseract se usati, portachiavi e sysdiagnose con il loro SHA-256 — in testa al report, in *Ambiente di analisi*
  e nel report portatile; il metodo è descritto come lettura dell'estrazione del file system (niente Sleuth Kit,
  partizioni, spazio non allocato). Il report dei dischi non cambia.
- **Agente IA**: per i casi smartphone ha anche gli strumenti `list_chats`, `read_chat`, `search_messages` e
  `find_contact`, e cita sempre database, tabella e riga dei messaggi.
- Da terminale: `python3 forense_mobile.py prepara --image ESTRAZIONE --case CASO [--leapp] [--decomprimi]
  [--keychain FILE] [--sysdiagnose FILE …]` e `python3 forense_mobile.py aggiungi --case CASO chat leapp`
  (`leapp-import` rilegge le tabelle dell'ultimo rapporto di iLEAPP/ALEAPP senza rieseguirlo; `sysdiagnose --file FILE`
  aggiunge e legge un sysdiagnose, `sysdiagnose` da solo li rilegge tutti).
- **Tipi dei messaggi WhatsApp** (2.20): ogni messaggio ha il suo tipo (testo, immagine, video, audio, documento, GIF,
  sticker, posizione, contatto, link, sondaggio, chiamata, avviso, messaggio eliminato), preso dal valore del database
  (`ZWAMESSAGE.ZMESSAGETYPE` su iPhone, `message.message_type` o `messages.media_wa_type` su Android). WhatsApp non
  pubblica il significato di questi valori: quelli controllati sulle immagini pubbliche di Josh Hickman sono indicati come
  verificati, gli altri hanno «⚠ tipo non verificato». Un valore sconosciuto compare come **«[tipo N non gestito]»** con il
  numero del database, mai come un generico «allegato».
- **Stato di consegna e lettura** (2.20), solo per i messaggi **inviati**: ✓ inviato, ✓✓ consegnato, ✓✓ blu letto, ▶
  riprodotto, con data e ora quando il database le ha. Il clic sulle spunte apre la tabella con lo stato, il destinatario
  (nei gruppi uno per persona), la data, la **fonte** (tabella e colonna) e se il significato è verificato. Verificati:
  Android, schema precedente (Android 10) e schema dal 2022 (Android 14: `receipt_user`, status 13 = letto, 5 =
  consegnato). **L'assenza di «letto» non prova che il messaggio non sia stato letto**: le conferme di lettura si
  possono disattivare e nei dati di prova il primo messaggio inviato su Android 14 è consegnato ma senza lettura, benché
  l'altra persona abbia risposto. **iPhone**: lo stato di lettura dei messaggi inviati non è leggibile in questa
  versione (`ZMESSAGESTATUS` vale 8 su tutti i messaggi, inviati e ricevuti); la spunta grigia NON indica che il messaggio
  non è stato letto. Nei dati di prova le conferme di lettura erano attive su entrambi i telefoni della stessa
  conversazione (l'Android 14 ha ricevuto le conferme dall'iPhone). Per i messaggi **ricevuti** su iPhone, invece,
  RepertIA mostra **«letto …»: l'ora in cui questo telefono ha letto il messaggio** (`ZWAMESSAGE.ZSENTDATE`, che per i
  ricevuti non è l'ora d'invio): sui due telefoni di Hickman che si scrivevano coincide entro 1 secondo con la conferma di
  lettura registrata dall'altro telefono in 8 casi su 10 (negli altri due: 1 min 46 s durante una chiamata, e il primo
  messaggio di un numero non in rubrica).
- **Avvisi di WhatsApp** (2.20): gli avvisi che WhatsApp inserisce da solo nella conversazione (gruppo creato, persone
  aggiunte o uscite, crittografia end-to-end…) sono **«avviso generato da WhatsApp (non scritto da una persona)»**, mai
  inviati né ricevuti e senza spunte (su Android il database li segna `from_me = 1`: nella 2.20.0 prima di questa
  correzione risultavano «inviati»). Sotto l'avviso: il codice com'è registrato, le persone indicate dal database (con il
  nome della rubrica) e i dettagli (valore precedente, numero vecchio e nuovo). Il **?** spiega cosa sono questi valori.
  **Android** (`message_system.action_type`): dove fonti pubbliche spiegano il codice, RepertIA mostra anche la frase con
  il suo livello: «**concorde in 2 fonti pubbliche**» (WAInsight, `backend/app/models/enums.py`, ricavato dall'app
  decompilata, e WhatsApp-Chat-Exporter, `utility.py`, entrambi con licenza MIT) oppure «**probabile, 1 fonte**»; «e
  coerente con i dati di prova» quando l'immagine Android 14 di Hickman lo conferma (11 gruppo creato, 12 persone
  aggiunte, 67 avviso sulla crittografia). Nessun codice è «verificato»: servirebbe un telefono di prova con le azioni
  documentate. Concordi: 1, 5, 6, 10, 11, 12, 13, 14, 18, 20, 27, 28, 56, 58; probabili: 15, 21, 59, 67, 83, 84, 92; gli
  altri si mostrano solo come numero. **iPhone** (`ZMESSAGETYPE` 6 e 10, `ZGROUPEVENTTYPE`): **nessuna fonte pubblica**
  spiega questi numeri (lo dichiara anche iLEAPP, modulo *WhatsApp - Group Events*; i programmi commerciali usano
  ricerche interne non pubblicate). RepertIA riporta i valori come registrati e solo **fatti ricavati dal database**:
  «registrato nello stesso secondo della creazione del gruppo» (`ZWAGROUPINFO.ZCREATIONDATE`), «primo messaggio della
  conversazione nell'ordine di WhatsApp» (`ZSORT`) e la posizione nell'ordine di WhatsApp quando è diversa da quella per
  orario; «nome del gruppo cambiato in …» (testo dell'avviso; probabile, 1 fonte: WhatsApp-Chat-Exporter,
  `ios_handler.py`). Attenzione: `ZGROUPEVENTTYPE = 2` compare su **tutti** i messaggi ricevuti, anche quelli normali, e
  da solo non indica un evento. Per arrivare a un'interpretazione servono immagini pubbliche con azioni di gruppo
  documentate o una prova controllata su un iPhone di prova.
- **Chiamate** (2.20): oltre a quelle di iLEAPP/ALEAPP, RepertIA legge da sé le chiamate di **WhatsApp** (iPhone:
  `CallHistory.sqlite` dell'app e i messaggi di tipo 59 della chat; Android: `call_log` di `msgstore.db` e i messaggi di
  tipo 90), **Skype** (`s4l-*.db`, tabella `calllogs`) e **imo** Android (`imofriends.db`, elenco in `imdata`, senza
  durata). La stessa chiamata trovata in più fonti diventa **una sola riga** con tutte le fonti (tabella e riga) e le
  discordanze segnalate (l'orario di una chiamata trovata anche in *interactionC*, che segna l'inizio dell'interazione
  qualche secondo prima, è quello del registro di sistema *Call History*). **Limite**: una riga di interactionC **senza
  numero** non si unisce a nessuna chiamata, perché non si attribuisce un numero che la fonte non contiene: compare come
  chiamata a sé con «(non indicato)». Può quindi essere la stessa chiamata di una riga del registro di sistema (iOS 17 di
  Hickman, 22/02/2024: interactionC in arrivo dalle 14:59:45 alle 15:00:03 senza numero, Call History in arrivo rifiutata
  alle 15:00:03 dal +19787752806): controllare le fonti prima di contare le chiamate; nella chat la chiamata compare una volta sola. Da iLEAPP/ALEAPP si leggono anche Signal (quando
  ALEAPP decifra il database), Google Voice, Teams, Facebook Messenger e TeleGuard: per **Messenger** (msys) e
  **TeleGuard** l'orario scritto da ALEAPP/iLEAPP è la **fine** della chiamata, quindi RepertIA calcola l'inizio
  sottraendo la durata (verificato 4 su 4 e 4 su 4 con la documentazione). Nelle immagini di prova nessuna app VoIP
  compare nel registro delle chiamate di sistema: l'abbinamento app ↔ registro di sistema non è verificabile e non è fatto.
  **Copertura** (immagini pubbliche di Hickman; ✅ = confrontato con le chiamate documentate):

  | App | iPhone | Android |
  |---|---|---|
  | Telefono, FaceTime | ✅ CallHistory.storedata | ✅ calllog.db (Android 14: 2.655 = righe di `calls`) |
  | WhatsApp | ✅ lettore proprio (iOS 17: 8 = documentazione) | ✅ lettore proprio (Android 14: 4 = documentazione) |
  | Skype | ✅ lettore proprio (iOS 17: 8) | ✅ lettore proprio (Android 14: 4) |
  | imo | — | ✅ lettore proprio (Android 14: 4) |
  | Signal | iLEAPP, se decifrato con il portachiavi | ✅ ALEAPP (Android 14: 4 su 4) |
  | Google Voice | iLEAPP | ✅ ALEAPP (2 su 2) |
  | Facebook Messenger | iLEAPP (senza verso) | ✅ ALEAPP msys, inizio calcolato (8 su 8) |
  | TeleGuard | iLEAPP, inizio calcolato | ✅ ALEAPP, inizio calcolato (4 su 4) |
  | Teams | iLEAPP | — |
  | Instagram, Viber, LINE, Telegram, Zoom | iLEAPP | ALEAPP |

- **Chat di altre app da iLEAPP/ALEAPP: verso e affidabilità** (2.20): per ogni app la regola che dice se un messaggio è
  inviato o ricevuto è scritta in `forense_mobile_leapp_mappa.json`. Dove la colonna di iLEAPP/ALEAPP sbagliava, la regola
  è stata ricavata confrontando i messaggi con quelli documentati da Hickman (stesso testo, orario entro 3 minuti): **LINE**
  (Android) dalla presenza di «From ID» (la colonna «Direction» vale sempre 3), **imo** «0» = inviato, **Life360** e
  **Slack** dall'account del proprietario («Message Sent» di Life360 non è il verso). I messaggi WhatsApp di ALEAPP
  (*Group Messages*, *One To One Messages*) non si aggiungono: sono gli stessi letti da RepertIA. Risultato sulle immagini
  pubbliche: **iOS 17.3**, 1.167 messaggi documentati, 766 ritrovati, **tutti con il verso giusto**; **Android 14**,
  656 documentati, 272 ritrovati, **tutti con il verso giusto**. Sette messaggi (6 su iOS 17, 1 su Android 14) hanno un
  verso diverso da quello scritto nella documentazione, ma l'errore è nella documentazione: lo stesso messaggio vi è
  segnato «Sent» per **entrambi** i telefoni, e dove l'app è letta anche sull'altro telefono il suo database dice che l'ha
  inviato quello (come indica RepertIA); un ottavo era un abbinamento sbagliato dello script di confronto. I non ritrovati sono app che né iLEAPP né ALEAPP
  leggono (Zoom, Wickr solo metadati, Life360 su iPhone, Telegram e Teams su Android, Threema, Session, Truth Social,
  Mastodon, MEGA su Android, X) o messaggi cancellati apposta. Altri limiti trovati: Signal Android, le conversazioni di
  luglio 2024 documentate non sono nell'output di ALEAPP; Snapchat iPhone, nel database è rimasto solo il 27/07/2024;
  Messenger Android, i messaggi della «chat segreta» non sono nell'output di ALEAPP. Questi riscontri riguardano **il
  metodo** (le regole per app, sulle versioni delle app usate da Hickman nel 2024), non i messaggi di un caso: in un caso
  reale non c'è niente con cui confrontare, e l'interfaccia non mostra indicazioni di verifica. Il dettaglio per
  artefatto è nella sezione `verifiche` della mappa.
- **Limite di 500.000 righe di iLEAPP/ALEAPP** (2.20): se le tabelle di iLEAPP/ALEAPP superano il limite, RepertIA importa
  **prima** le tabelle di chat, messaggi e chiamate (quelle della mappa, quelle che iLEAPP/ALEAPP dichiarano come
  conversazione e quelle con *call*, *messag*, *chat*, *conversation*, *voicemail* nel nome), poi le altre. Le tabelle
  rimaste fuori sono elencate nel caso (`leapp.omesse`, con le righe importate e quelle del rapporto) e restano nel
  rapporto di iLEAPP/ALEAPP nella cartella del caso. Sotto il limite l'ordine non cambia. Nella 2.20.0 prima di questa
  correzione, su iOS 17 il limite si riempiva con FSEvents (325.922 righe) e le chat di 23 app non venivano importate.
- **Backup di WhatsApp decifrati** (2.20, Android): WhatsApp salva ogni notte una copia cifrata dei messaggi
  (`WhatsApp/Databases/msgstore*.db.crypt14`); in un'estrazione completa c'è spesso anche la chiave
  (`com.whatsapp/files/key`). Con la casella *Decifra i backup di WhatsApp (Android), se nell'estrazione c'è la chiave* (nuovo caso) o
  con l'analisi aggiuntiva *Backup di WhatsApp decifrati*, RepertIA decifra i `.crypt14` e li legge con il proprio
  lettore. Nella vista chat compare l'app **🗄 WhatsApp (backup decifrato)**, con il nome del backup su ogni
  conversazione; i messaggi che sono nel backup ma non nel database attuale (stesso identificativo assente) hanno **«⚠ solo
  nel backup»**: possono essere stati cancellati dopo il backup. Si accetta solo un risultato con il tag di verifica
  AES-GCM corretto e che sia un database SQLite; le copie decifrate restano nel caso (`backup_whatsapp/`, sola lettura)
  e SHA-256 di backup, chiave e copia decifrata vanno nel registro. Esiti dichiarati: *cifrato con un'altra chiave* (la
  firma del backup non è quella della chiave: tipico dei backup fatti prima di un nuovo accesso), *backup incrementale*
  (archivio in un formato non documentato: elencato, non letto), *formato non gestito* (crypt12, crypt15: per crypt15 la
  chiave non è nel telefono). Formato verificato sull'immagine Android 14 di Hickman (posizioni da
  WhatsApp-Chat-Exporter, `android_crypt.py`, MIT). Da terminale: `prepara … --wa-backup` o `aggiungi --case CASO wa-backup`.
- **Foto e video ↔ chat** (2.20): in Risultati, sotto **Foto/Video/Audio**, le sottovoci **🖼 Foto**, **🎞 Video** e **🎵 Audio** e i filtri
  **Solo foto**, **Solo video** e **Solo audio**; nei casi smartphone la voce **💬 Dalle chat** (una sottovoce per app),
  anche sotto ciascuna di Foto, Video e Audio, elenca i file che sono allegati a
  un messaggio e il filtro *Origine* sceglie l'app. Aprendo una foto o un video allegato, il riquadro **Origine** dice
  in quale chat è stato inviato o ricevuto, da chi, quando, con database, tabella e riga, se il file è certo o probabile e
  se lo SHA-256 coincide con quello registrato dall'app; **💬 Apri nella chat** porta al messaggio. Il CSV ha la colonna
  `origine_chat`. Anche nel report portatile.
- **Anteprima dei database dei telefoni** (2.20): un database SQLite del telefono si legge in anteprima con i suoi file
  `-wal`, `-shm` e `-journal` (su una copia di lavoro), come fanno i lettori di chat, e la nota lo dice. Prima si leggeva il
  solo file principale: su Android 14, 383 dei 508 database con un `-wal` mostravano dati incompleti.
- **Avvisi dell'importazione** (2.20): gli avvisi della lettura delle chat (database cifrati, chiavi trovate, backup) sono
  nel pulsante **⚠ Avvisi dell'importazione (N)** del pannello, che apre una finestra ridimensionabile.
- **Limiti**: si vede solo quello che c'è nell'estrazione (un'estrazione logica o un backup non contengono i database delle
  app); i database cifrati (Signal se ALEAPP/iLEAPP non lo decifra, backup di WhatsApp `.crypt15` o fatti con un'altra
  chiave) non si leggono; i messaggi cancellati ancora presenti nelle pagine libere dei database non sono recuperati in
  questa versione; le estrazioni non hanno file cancellati del file system.
- **Collaudo**: due estrazioni di prova in `RepertIA-collaudo/smartphone/` costruite con estratti delle immagini pubbliche
  di Josh Hickman (iOS 15) e «anne_a15» (Android 15) usati nei test di iLEAPP e ALEAPP: gli orari di tutti i messaggi
  devono coincidere con i risultati pubblicati da quei progetti; più un WhatsApp Android costruito con contenuto noto.
  Dalla 2.20 anche portachiavi finti, file citati e due **sysdiagnose** nella forma di un archivio vero costruiti con i
  ritagli pubblici dei test di iLEAPP (il numero di processi di `ps.txt` è contato senza iLEAPP e deve coincidere).

### File citati (novità 2.20)

Molte righe nominano un file senza esserlo: «File Path /storage/emulated/0/Pictures/…» di Google Photos, il documento a
cui punta un collegamento LNK o una jump list, il file scaricato dal browser, il contenuto nel Cestino, il programma di
Prefetch e Amcache, «media/…» di iLEAPP/ALEAPP, l'allegato di una chat, un percorso scritto dall'agente. RepertIA
riconosce questi campi e cerca il file nella copia o nell'estrazione, con la stessa funzione in tutto il programma
(`forense_percorsi.py`):

1. **per percorso**, con la tabella di corrispondenza `forense_percorsi.json`: Android `/storage/emulated/0`, `/sdcard`,
   `/mnt/sdcard` → `data/media/0`, `/data/user/0` → `data/data`; iOS `/var/mobile` ↔ `/private/var/mobile` (e
   `filesystem2/mobile` delle estrazioni in stile Cellebrite), `~/`, `file://` e percorsi relativi ai container delle app; Windows lettere di unità, `\\?\Volume{…}`,
   `\Device\HarddiskVolumeN`, `%USERPROFILE%`, `%APPDATA%`, `%SystemRoot%`…; macOS `/Users`, `/Volumes/<nome>`,
   `/private/var`. Si confronta la parte finale del percorso senza distinguere maiuscole e minuscole e, a parità, vince la
   partizione da cui viene la riga (utile con più installazioni di Windows). Per «media/…» di iLEAPP/ALEAPP il percorso
   originale viene dal loro database (`_lava_media_items`). La tabella si estende aggiungendo righe al file JSON.
2. **per hash**, se la riga lo fornisce (SHA-256, SHA-1, MD5, anche in base64): nella tabella degli hash del caso o tra i
   file con la stessa dimensione;
3. **per nome e dimensione**, o **per solo nome**: con più file dello stesso nome si elencano tutti come candidati.

**Cartella e nome nella stessa riga.** Molti artefatti scrivono la cartella e il nome in due campi (es. *Photos.sqlite
EXIF Analysis* di iLEAPP: «Directory: DCIM/100APPLE», «Filename: IMG_0059.PNG»): RepertIA li unisce in un percorso
completo (`DCIM/100APPLE/IMG_0059.PNG`) e lo cerca **per percorso**, non per solo nome. Se il percorso unito non porta a un
file (es. «Original Filename», il nome che la foto aveva prima, in un'altra cartella) il nome resta da solo. Un campo che
indica solo una cartella non è un file citato: diventa il collegamento **📁 cartella** nel riquadro del file (la cartella
che contiene il file trovato).

**Un riquadro per ogni file diverso.** Se più campi della stessa riga portano allo stesso file (es. «Media» di iLEAPP, cioè
la copia nel suo rapporto collegata all'originale, e «Directory + Filename») c'è un solo **📎 File citato**, con sotto
«indicato nei campi: Media, Directory + Filename».

**L'esito, in tre livelli** (il pulsante **?** accanto all'esito li spiega):

| Esito | Quando | Cosa fare |
|---|---|---|
| ✅ **trovato con certezza** | percorso completo, hash, o collegamento registrato da iLEAPP/ALEAPP; se la riga dà l'hash e coincide: «**hash verificato**» | niente: il file è quello indicato dalla riga |
| ⚠️ **probabile, da verificare** | solo il nome, o nome e dimensione; anche un file trovato per percorso con un hash **diverso** da quello della riga | controllare l'elenco dei **candidati** (tutti i file con quel nome, con dimensione, anteprima e albero): la riga non dice quale sia |
| ❌ **non presente nell'estrazione** (nei dischi «nella copia») | nessun file corrispondente; se iLEAPP/ALEAPP ne ha solo una copia nel suo rapporto o l'ha ricavato dall'interno di un database, è scritto e si vede quella copia | il file è stato cancellato, non è stato acquisito o non è mai stato salvato sul supporto |

Se più campi indicano lo stesso file vale il metodo più forte (un esito per solo nome il cui candidato è già il file
trovato con certezza da un altro campo si unisce a quello). Il metodo, campo per campo, è sempre scritto.

- **Pannello dei dettagli** di un artefatto (anche aperto da Ricerca, Preferiti o Chiamate): sopra la tabella dei campi,
  per ogni file diverso un riquadro **📎 File citato** con il percorso trovato (clic = albero), l'esito con il colore
  (verde, arancione, rosso) e il metodo, i campi che lo indicano, il collegamento 📁 cartella, l'**anteprima** (immagine,
  video, audio, prima pagina del PDF, testo) e i pulsanti *Anteprima*, *Mostra nell'albero*, *Esporta*, *⭐ Preferiti*;
  per un esito «probabile» con più file, l'elenco dei candidati. **▸ Dettagli tecnici** (chiuso) contiene il metodo per
  ogni campo, il valore scritto nella riga, lo SHA-256 se già calcolato e, se nella copia/estrazione la stessa parte finale
  del percorso c'è in più posizioni, le **altre copie con lo stesso percorso finale** (percorso, dimensione, SHA-256 se
  calcolato) con la spiegazione: la riga indica la parte finale del percorso, il file mostrato è quello col percorso più
  vicino, gli SHA-256 dicono se il contenuto è uguale. Sotto, distinta, la **Fonte**: il database o file da cui viene la
  riga (es. `gphotos-1.db`) con il percorso completo nell'estrazione e il suo pulsante.
- **Tabella degli artefatti**: una sola miniatura per riga (la prima immagine trovata), bordata di arancione o rosso se
  l'esito non è certo; 📎 per gli altri file (grigio se nessuno è stato trovato); al passaggio del mouse l'esito di ogni
  file citato.
- **Timeline**: *Anteprima*, *Albero* ed *Esporta* sulle righe di plaso usano la stessa ricerca. **Agente IA**: lo
  strumento degli artefatti riporta il file citato trovato; i percorsi scritti nelle risposte (anche di Windows o del
  telefono) si aprono con un clic (anteprima e albero). **Preferiti, Reperto e registro**: il riferimento di un artefatto
  elenca i file citati con esito e metodo per campo. **Report del caso (Markdown, Word, PDF)**: dopo le tabelle dei
  Preferiti, «File citati dagli artefatti nei Preferiti» scrive per ogni file citato l'esito (trovato con certezza /
  probabile, da verificare / non presente), il percorso e il metodo per campo; per gli esiti probabili anche i candidati.
- **Report portatile**: per ogni artefatto un riquadro per file diverso con l'esito a colori, il «?», i campi, la
  cartella, i candidati, i *Dettagli tecnici* con le copie, la fonte risolta, una miniatura delle immagini trovate (al
  massimo 3.000 per report) e *Apri il file citato* se il contenuto del file è incluso nel report; il CSV ha l'esito in
  parole nella colonna `file_citati`.
- La ricerca usa l'indice dell'albero (`navigazione.sqlite`), a cui aggiunge la prima volta un indice per nome e
  dimensione; nelle tabelle e nel report portatile si usa la ricerca veloce (percorso e nome; l'hash della riga si
  verifica solo se c'è un solo file e fino a 16 MB, così l'esito è lo stesso del pannello), nel pannello quella completa. `tools/file_citati_conta.py <caso>` conta per sezione le righe con un file citato e i file trovati e non trovati.
- **Limiti**: un percorso della partizione di sistema del telefono (`/system/…`) o di un altro disco non è
  nell'estrazione o nella copia; i riferimenti `content://` di Android non si risolvono; un file trovato per solo nome può
  essere un altro file con lo stesso nome: va verificato.

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
| **iLEAPP / ALEAPP** (2.20, licenza MIT) | artefatti delle app di iPhone e Android, nei casi smartphone |
| **whisper.cpp** 1.9.5 (2.20, licenza MIT; nei pacchetti) + modelli Whisper (scaricati solo con il consenso) | trascrizione automatica degli audio, sul computer |
| **ffmpeg** (nei pacchetti; sul Mac una build LGPL minima dalla 2.20) | conversione degli audio per la trascrizione e fotogrammi dei video |

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
- `forense_mobile.py`, `forense_mobile_chat.py`, `forense_mobile_leapp.py`, `forense_mobile_gui.py`,
  `forense_mobile.html` — casi smartphone (2.20): estrazioni, chat, iLEAPP/ALEAPP, interfaccia; caricati solo per i casi
  smartphone;
- `Avvia RepertIA.command`, `Aggiorna strumenti.command` — lanciatori per macOS.

---

## Cartella del caso

| File / cartella | Contenuto |
|---|---|
| `case.json` | immagine, hash, partizioni, versioni degli strumenti, analisi eseguite |
| `caso.sqlite` | elenco file, timeline, testo dei documenti, metadati, tracce, hash dei file |
| `non_indicizzati.csv` | file il cui testo non è nell'indice o solo in parte, con il motivo (si aggiorna a ogni indicizzazione) |
| `ricerche.sqlite` | ricerche salvate e i loro risultati |
| `ricerca_veloce.sqlite` | (2.20) indice della ricerca veloce nei risultati del caso; si può cancellare, si ricostruisce alla prima ricerca |
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
- **Verifica del registro a posteriori (2.20).** Il report (Markdown, Word, PDF, report portatile) stampa il **numero di
  voci** e l'**hash finale** del registro (SHA-256 dell'ultima riga) al momento del report. **🔗 Verifica registro** —
  nella pagina iniziale per un `audit_log.jsonl` qualsiasi o per la cartella di un caso (anche copiati da un altro
  computer), nel menu *Verifiche* per il caso aperto — ricalcola la catena e dice: *integro*; oppure la **prima riga
  alterata** (numero di riga e di voce, SHA-256 atteso e attuale, contenuto attuale); le **righe mancanti** in mezzo
  (salto dei numeri progressivi); righe inserite o fuori ordine. Con il campo facoltativo **hash finale atteso** (e il
  numero di voci) copiati dal report scopre anche **righe tolte alla fine** e un **registro riscritto per intero**: se
  l'hash è trovato, il registro di allora è ancora tutto lì e le righe successive sono operazioni fatte dopo (la prima è
  di solito la voce «report»). Ricontrolla inoltre gli **SHA-256 dei file esportati** citati nel registro (esportazioni,
  chat esportate, report Word/PDF; per le selezioni il `manifest.csv`) se sono nella cartella del caso. La verifica del
  caso aperto resta nel suo registro. Stesso controllo da terminale, anche senza RepertIA installato (serve solo Python):
  `python3 tools/verifica_registro.py <audit_log.jsonl | cartella del caso> [--hash-finale H] [--voci N] [--json]`
  (oppure `python3 forense_registro.py …` dai sorgenti del pacchetto); esce con 0 se tutto torna, 1 se no.
  **Cosa dimostra**: che il registro (fino all'hash finale indicato) è quello scritto da RepertIA riga dopo riga, senza
  righe cambiate, tolte o inserite dopo, e che i file esportati sono ancora quelli registrati. **Cosa non dimostra**: chi
  ha usato il programma, né che le operazioni descritte siano corrette o complete (il registro dice cosa RepertIA ha
  fatto, non se il risultato è giusto); senza un hash finale conservato altrove (report consegnato, verbale) un registro
  riscritto per intero con una catena ricalcolata risulta integro; le righe tolte alla fine si vedono solo con l'hash
  finale; il contenuto originale di una riga alterata non si ricostruisce; i file esportati fuori dalla cartella del
  caso o cancellati non si possono ricontrollare.
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
- **Riscontro con un altro strumento (2.15).** *Riscontro con altro strumento* (menu *Verifiche*) confronta
  i file del caso con l'elenco esportato da un secondo strumento sulla **stessa copia**: Autopsy (*Save table as
  CSV*), FTK Imager (*Export File Hash List* o *Export Directory Listing*), X-Ways, EnCase, AXIOM (CSV con
  percorso e hash), Sleuth Kit (`fls -r -m / -h`). Il formato si riconosce da solo. Risultato: file con hash
  uguale (conferma indipendente: ciascuno strumento ha letto la copia per conto suo), con hash **diverso**,
  presenti solo in uno dei due, stato «cancellato» o dimensione discordanti. L'esito va nel report (sezione
  *Riscontro con altri strumenti*, con lo SHA-256 del file esterno) e nel registro; il dettaglio riga per
  riga in `riscontri/` nel caso. Da terminale: `forense_agent.py riscontro --case CASO --file elenco.csv
  --strumento "Autopsy 4.21"`. È il modo consigliato di riscontrare i reperti prima di usarli.
- **Analisi speditiva**: togliendo *Calcola subito lo SHA-256 della copia forense* nella pagina
  iniziale l'analisi parte senza attendere il calcolo dell'hash, che si fa dopo dal menu
  *Verifiche* con **Calcola hash copia** (da terminale `--no-hash`, poi `--aggiungi immagine`). Il
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

**Versione 2.20.1** - **Conformità all'AI Act (Reg. UE 2024/1689).** **Reperti dell'agente**: in `findings.json` ogni reperto registrato dall'agente porta `"origine": "modello IA"`, il nome del modello, il server e `"stato": "da verificare"`; quelli scritti con *Registra reperto* sono «inserito dall'analista»; quelli dei casi precedenti «origine non registrata». Nel riquadro dei reperti l'etichetta di origine e il pulsante **✓ Confermo, verificato**, che registra operatore e data in `findings.json` e nel registro a catena (`finding_verificato`). Nei report (Markdown, Word, PDF, portatile) accanto a ogni reperto «Generato da modello IA (*nome*) – da verificare» oppure «Verificato da *operatore* il *data*»; la frase «Ogni reperto è stato verificato dall'analista sugli strumenti forensi» solo se lo sono tutti, altrimenti quanti sono verificati e quanti no; nei metadati di Word e PDF «contiene testo generato da un modello di IA» e la parola chiave «AI-generated content». **Server LLM esterno**: un indirizzo che non è su questo computer né nella rete locale (IP privati 10.x, 172.16–31.x, 192.168.x, IPv6 locali, nomi senza punti o con `.local`, `.lan`, `.internal`…) chiede un'esplicita conferma prima dell'uso, che resta nel caso e nel registro; il report scrive «server esterno indicato dall'analista: *indirizzo*» invece di «rete interna, senza servizi esterni»; un server esterno non confermato non si collega da solo all'apertura del caso. **Chat**: sotto ogni risposta «Risposta generata da modello IA (*nome*): spunto da verificare» (anche da riga di comando). **OCR**: «testo OCR automatico» nell'elenco dei documenti e avvertenza nel report (le trascrizioni erano già «trascrizione automatica»). Nuovi **AI_ACT.md** e **AI_ACT.en.md** (scopo previsto, usi esclusi, valutazione ai sensi dell'art. 6, par. 3, obblighi dell'art. 50, nota per gli uffici: deployer, legge 132/2025, valutazione d'impatto, supervisione umana, art. 25; non è un parere legale), collegati dal README. Collaudo +5 controlli (reperto dell'agente «da verificare» in findings.json e nel report, metadati di Word e PDF, verificato con operatore e data dopo la conferma anche nel registro, server locali/privati ed esterni): **427/427 in italiano e in inglese** (178 dei dischi + 249 degli smartphone), dai sorgenti e dal pacchetto Mac; prova della navigazione 66/66; interfaccia provata nel browser (etichette, conferma con operatore, avviso del server esterno annullato e confermato). **Non provato:** Windows e Linux dei pacchetti ricostruiti; un server LLM esterno reale (provato un indirizzo che non risponde).

**Versione 2.20.0** - **Smartphone (iPhone e Android).** Nella pagina iniziale si sceglie fra **💽 Memorie di massa** (come prima) e **📱 Smartphone**. Un caso smartphone nasce da un'**estrazione del file system completo**: zip (Cellebrite FFS, GrayKey, altri), tar (Magnet ACQUIRE, estrazioni Android), tar.gz (letto da una **copia derivata decompressa** nella cartella del caso, con SHA-256 e riferimento all'originale) o cartella già estratta. I file si leggono dall'estrazione senza copiarli; albero, elenco, timeline, ricerche, testo dei documenti, metadati, hash, anteprime, report e report portatile funzionano come per i dischi; sistema, versione e fuso del telefono si ricavano dall'estrazione. **Chat**: lettori propri per WhatsApp (iPhone e Android, anche lo schema del 2020), iMessage/SMS e SMS/MMS Android, con i nomi delle rubriche, i messaggi ancora solo nel file `-wal`, gli allegati collegati al file dell'estrazione e il riferimento a database, tabella e riga; le copie identiche dei database (es. lasciate da Magisk) si saltano e i database cifrati (Signal, backup .crypt) sono dichiarati. **Vista chat** a fumetti con filtri per app, contatto, testo e periodo, ⭐ Preferiti e 📌 Reperto sul singolo messaggio e i segnaposto «messaggio eliminato» evidenziati, anche nel report portatile. Negli Artefatti i **Messaggi delle chat** sono divisi per app: ogni conversazione mostra i due interlocutori (questo dispositivo, con il suo numero o account se scritto nell'estrazione; l'altro con il nome della rubrica e il numero, «numero breve/servizio» per i codici brevi; per i gruppi nome e partecipanti), messaggi inviati e ricevuti, allegati e ultimo messaggio, con il pulsante **💬 Apri chat**. **iLEAPP 2026.4.5 e ALEAPP 2026.4.4** (licenza MIT) inclusi: i loro artefatti entrano nel caso (categoria «Artefatti iLEAPP/ALEAPP»), divisi nell'albero per categoria di iLEAPP/ALEAPP e per artefatto, ciascuno con il numero di righe (anche nel report portatile); i Dettagli mostrano i campi come «campo: valore» con le date nel fuso scelto; il loro rapporto HTML resta nella cartella del caso. Nuovi strumenti dell'agente: `list_chats`, `read_chat`, `search_messages`, `find_contact`. Il codice per gli smartphone è in moduli separati (`forense_mobile*.py`, `forense_mobile*.html`) caricati solo per questi casi: i casi dei dischi non cambiano (stesse tabelle, riga per riga, sui casi del collaudo). **Collaudo**: due estrazioni di prova (`smartphone/`) con estratti delle immagini pubbliche iOS 15 di Josh Hickman e Android 15 «anne_a15» usati nei test di iLEAPP e ALEAPP: gli orari di tutti i messaggi devono coincidere con i loro risultati pubblicati; più un WhatsApp Android costruito con contenuto noto (anche un messaggio solo nel -wal). **Prova:** collaudo 155/155 in italiano e in inglese sul Mac (112 di prima + 43 smartphone); immagini pubbliche complete di Hickman iOS 13.4.1 (tar di 17 GB, 351.466 file, iLEAPP 300.277 righe in 323 artefatti) e Android 10 (zip di 5,2 GB, ALEAPP 78.370 righe in 207 artefatti): messaggi WhatsApp, iMessage e SMS con gli orari documentati dall'autore; sul caso iOS i 48 messaggi iMessage/SMS della vista chat coincidono con l'artefatto «SMS» di iLEAPP in tutte le 17 conversazioni. **Non provato:** Windows e Linux (pacchetti costruiti sul Mac), estrazioni GrayKey e Cellebrite reali con i loro metadati, report UFDR (fase successiva). **Chat e chiamate da iLEAPP/ALEAPP, navigazione e colonne.** Le app di chat che RepertIA non legge con i propri lettori (Telegram, Discord, Instagram, Facebook Messenger, Google Messages, Snapchat, LINE, Viber, Kik, TikTok, X, Zoom, Wire, TextNow, Burner, IMO, MeWe, Skout, Houseparty, CoverMe; Wickr solo metadati) entrano in *Messaggi delle chat*, una sottovoce per app, e nella vista chat; nuova sezione **Chiamate**, una riga per chiamata (data, direzione, numero, nome in rubrica, durata, risposta, app) con tutte le fonti: le righe uguali di fonti diverse sono unite e i valori discordanti segnalati; le righe originali restano negli artefatti di iLEAPP/ALEAPP. La corrispondenza tra colonne e campi è in `forense_mobile_leapp_mappa.json`. **💬 Apri chat** anche nel pannello dei dettagli della conversazione (nella tabella è un'icona); ⭐ Preferiti, 📌 Reperto ed **⬇ Esporta chat** per l'intera conversazione (HTML leggibile e CSV in `export/chat/`, intestazione con caso, app, interlocutori, periodo, fuso, database di origine con offset, inode e SHA-256; SHA-256 dei file esportati nel registro a catena). **Anteprima degli allegati sopra la chat**, con frecce ← → tra gli allegati della conversazione, schede Testo/Esadecimale/Metadati e i pulsanti di sempre; Esc torna al messaggio. **← Indietro / → Avanti** con briciole in tutto il programma (anche il tasto Indietro del browser, Alt+←, Cmd+[) e, con Indietro del browser e briciole, nel report portatile. **Colonne ridimensionabili** in tutte le tabelle dei Risultati e nel report portatile (trascinare il bordo, doppio clic per adattare, *Ripristina colonne*); la colonna Dettagli si legge meglio (nome del campo piccolo e grigio, a capo solo tra le parole) e l'intestazione bloccata resta sempre sopra. **Prova:** collaudo 159/159 in italiano e in inglese (4 controlli nuovi: ogni riga di iLEAPP/ALEAPP in un solo messaggio e in una sola chiamata, durate uguali a quelle della fonte, *Esporta chat* con SHA-256 uguale a quello del registro). Hickman iOS 13.4.1: 304 righe di 18 artefatti di chat → 283 messaggi (21 doppioni uniti: le 11 righe di Burner Cache sono messaggi di Burner, Instagram Threads ha ogni riga due volte); 129 righe di 8 artefatti di chiamate → 48 chiamate (le tre tabelle di Call History, 37 righe ciascuna, sono le stesse 37 chiamate). Android 10: 203 righe → 120 messaggi (83 doppioni: copie dei database nel mirror di Magisk); 82 righe → 50 chiamate (Call logs 28 = Google Dialer 24 + 4 di segreteria). Interfaccia nel browser: chat → allegato → Mostra nell'albero → Indietro → Indietro (stessa chat, stesso messaggio e scorrimento), lo stesso partendo da una ricerca filtrata e da un percorso citato dall'agente; report portatile con Indietro del browser. **Non provato:** le prove nel browser (navigazione Indietro/Avanti, anteprime) non sono nel collaudo automatico; artefatti di chat delle app assenti dalle due immagini (si leggono solo se iLEAPP/ALEAPP li dichiarano come conversazione). **Correzioni dopo la prova sul caso iOS 13.4.1 (prima della pubblicazione).** ⭐ *Preferiti* su artefatti, chat e chiamate dava «int() argument must be … not 'NoneType'» (la pagina non mandava l'identificativo dell'elemento; difetto presente anche negli artefatti dei dischi) e la finestra scriveva «offset undefined, inode undefined». Ora Preferiti, *Reperto* e registro a catena usano il riferimento giusto: nei casi smartphone il percorso nell'estrazione per i file e database, tabella e riga per messaggi, conversazioni, chiamate e artefatti di iLEAPP/ALEAPP (mai offset e inode, che lì non esistono); la voce «preferiti» del registro elenca i riferimenti. *Fonte* degli artefatti di iLEAPP/ALEAPP apre il file da cui sono stati letti (prima cercava il nome dell'artefatto). «unable to open database file» su *Fonte*, *Mostra nell'albero* e cartelle dell'albero: dopo il cambio del fuso il ricalcolo cancellava l'indice dell'albero (`navigazione.sqlite`) mentre il programma lo considerava pronto (difetto presente anche nei casi dei dischi); ora l'indice si cancella solo se ci sono date FAT da ricalcolare e, se manca, si ricostruisce da solo. Nella sottovoce di un'app di *Messaggi delle chat* il menu *Categoria* mostrava «Messaggi (iMessage/SMS)»: nei casi smartphone ora elenca le categorie dei telefoni. Collaudo: nuove prove dei pulsanti con le stesse richieste della pagina (Preferiti, Reperto, Fonte, Mostra nell'albero su file, artefatto, artefatto di iLEAPP/ALEAPP, chat e chiamata; cartelle dell'albero fino al secondo livello; indice dell'albero cancellato a caso aperto) e rapporto inglese con l'esito tradotto («passed»/«FAILED»). **Prova:** collaudo 192/192 in italiano e in inglese; casi del T7 e del collaudo provati anche nell'interfaccia. **File citati e allegati delle chat (prima della pubblicazione).** Le righe che nominano un file (es. «File Path /storage/emulated/0/Pictures/Screenshots/…» di Google Photos) mostravano i campi ma non l'oggetto: nessun codice risaliva dal campo al file, i percorsi del telefono non corrispondono a quelli dell'estrazione (`/storage/emulated/0/…` è `<radice>/data/media/0/…`), i «media/…» di iLEAPP/ALEAPP (copie nel loro rapporto) non erano collegati al file originale e nelle righe salvate la fonte di iLEAPP/ALEAPP era il solo nome del database («gphotos-1.db»). Nuovo modulo **`forense_percorsi.py`** con la tabella di corrispondenza **`forense_percorsi.json`** (Android `/storage/emulated/0`, `/sdcard`, `/mnt/sdcard` → `data/media/0`, `/data/user/0` → `data/data`; iOS `/var/mobile` ↔ `/private/var/mobile`, `~/`, `file://`, percorsi relativi ai container; Windows: unità, `\\?\Volume{…}`, `\Device\HarddiskVolumeN`, `%USERPROFILE%` e altre variabili; macOS `/Users`, `/Volumes/<nome>`, `/private/var`): riconosce i campi che contengono un percorso o un nome di file e cerca il file **per percorso** (confronto della parte finale, «media/…» col percorso originale preso dal database di iLEAPP/ALEAPP), poi **per hash** se la riga lo fornisce (anche in base64), poi **per nome e dimensione** o **solo nome** (sempre «da verificare»); il modo è sempre indicato, l'hash della riga si ricontrolla sul file trovato e un file assente è scritto chiaramente («file non presente nell'estrazione», nei dischi «nella copia»). Usato in tutto il programma: **pannello dei dettagli** con **📎 File citato** (anteprima di immagini, video, audio, PDF e testo; *Anteprima*, *Mostra nell'albero*, *Esporta*, *⭐ Preferiti*) distinto dalla **Fonte** risolta col percorso completo; **miniatura nella tabella** per le righe che puntano a un'immagine; artefatti dei dischi (LNK, jump list, documenti recenti, download, Cestino con il file `$R…`, Prefetch, Amcache, avvio automatico); righe di plaso nella timeline; percorsi citati dall'agente (un clic apre file e albero) e file citati nello strumento degli artefatti dell'agente; Preferiti, Reperto e registro; **report portatile** (esito, fonte risolta, miniature delle immagini trovate fino a 3.000, *Apri il file citato*). **Allegati delle chat**: WhatsApp Android nello schema di passaggio 2020-2021 (messaggi in `messages`, file in `message_media`) non collegava nessun file: ora usa `file_path` e `file_hash` (base64 dello SHA-256) per trovare e **verificare** il file e, se manca, mostra la **miniatura salvata nel database** con la scritta «miniatura dal database – file non presente nell'estrazione» (anche in *Esporta chat* e nel report portatile); WhatsApp iOS la miniatura `.thumb` indicata dal database; iMessage e SMS/MMS con la stessa ricerca come ripiego; gli allegati delle chat ricavate da iLEAPP/ALEAPP sono collegati al file originale dell'estrazione. **Altre correzioni**: la lettura delle chat si interrompeva alla fine (in `fmc.run` mancava l'import di `forense_agent`): messaggi salvati, ma riepilogo del caso e conteggi assenti, anche in *aggiungi chat*; nelle foto di WhatsApp iOS `ZLATITUDE/ZLONGITUDE` (lì non sono una posizione) erano mostrati come posizione. Nuovo `tools/file_citati_conta.py` (righe con file citato, trovati e non trovati per sezione). **Prova:** collaudo 197/197 in italiano e in inglese (5 controlli nuovi: riepilogo delle chat salvato; allegati WhatsApp trovati per percorso, per hash, con la sola miniatura, assenti; SHA-256 uguali a quelli registrati dall'app; file citati da Google Photos trovati per percorso, per nome e dimensione, assenti; estrazione Android di prova aggiornata con `tools/collaudo_mobile.py --aggiorna-android`). Casi di Josh Hickman: Pixel 3, 9.897 righe di 39 artefatti di iLEAPP/ALEAPP citano 9.956 file: 7.925 trovati (1.200 per percorso, 6.445 tramite iLEAPP/ALEAPP, 280 per nome da verificare), 1.124 solo nel rapporto di ALEAPP, 907 non presenti; Google Photos – Local Media 108 su 108 per percorso; WhatsApp: i file dei messaggi 14 e 16 trovati con SHA-256 uguale a `file_hash`, 5 allegati con la sola miniatura. iOS 13.4.1, 12.689 righe di 49 artefatti, 14.346 file: 11.803 trovati, 161 solo nel rapporto di iLEAPP, 2.382 non presenti (soprattutto partizione di sistema, non estratta, e file cancellati). Interfaccia provata nel browser (pannello, miniature, vista chat, anteprima della miniatura, report portatile) su casi smartphone e disco. **Non provato:** percorsi di Windows su una copia reale (logica provata con un indice di prova: unità, `\Device\HarddiskVolume`, `\\?\Volume{…}`, `%USERPROFILE%`; nel collaudo non c'è un disco Windows); i riferimenti `content://` di Android non si risolvono. **Portachiavi di iOS tramite iLEAPP (prima della pubblicazione).** Nel modulo del nuovo caso smartphone e, per un caso già creato, nel pannello del caso c'è il campo facoltativo **«Portachiavi (keychain) – file acquisito a parte, es. GrayKey»** (solo iPhone). RepertIA ne calcola lo SHA-256, lo scrive nel registro a catena, **non lo copia nel caso** (si usa dal suo percorso, come l'estrazione; se cambia dopo la registrazione non viene usato) e lo passa a **iLEAPP 2026.4.5 con `--keychain`**. **La decifratura e la lettura sono di iLEAPP** (`scripts/ios_keychain.py` e `scripts/artifacts/keychain.py`): il portachiavi fornito serve agli artefatti che cercano la chiave di un'app (Signal, Session, SimpleX, Snapchat, Wickr), mentre gli artefatti del portachiavi (*Keychain Wifi Credentials*, *Keychain Web Passwords*, Bluetooth, account di posta) iLEAPP li legge dal portachiavi che trova **dentro l'estrazione** (es. `extra/KeychainDump/backup_keychain_v2.plist` di Cellebrite). Il riepilogo e il report del caso dicono quale portachiavi è stato usato: **fornito dall'operatore / trovato nell'estrazione / nessuno**, con le voci lette da iLEAPP. **Valori segreti** (password, chiavi, token): all'importazione si sostituiscono con «••••••» nelle righe e il valore va nella tabella `leapp_segreti`; nel pannello dei dettagli **🔒 Valori segreti** con **Mostra** rivela un valore alla volta e scrive la lettura nel registro (senza il valore); esclusi dal report portatile salvo la casella al momento della creazione (scelta registrata); l'agente IA riceve solo il segnaposto. Le regole dei campi segreti sono in `forense_mobile_leapp_mappa.json` (sezione «segreti»). Le chat che iLEAPP decifra con il portachiavi (Signal, Session, SimpleX) entrano nella vista chat come le altre app ricavate, con l'indicazione **«decifrato da iLEAPP con il portachiavi»**. Nuovo modulo `forense_mobile_portachiavi.py`; da terminale `forense_mobile.py prepara … --keychain FILE`. **Prova:** collaudo 241/241 in italiano e in inglese, con due prove nuove (44 controlli) su un'estrazione iOS minima costruita con **portachiavi FINTI** (nessun dato reale): uno decifrato (`genp` con una rete Wi-Fi e una voce in stile Signal inventate) passato con `--keychain`, uno nel formato cifrato di Cellebrite (chiavi inventate) dentro `extra/KeychainDump`; controllati SHA-256 nel registro, passaggio a iLEAPP e voci lette, portachiavi dichiarato (fornito / trovato nell'estrazione), artefatti Wi-Fi e password web presenti, valori mai in chiaro nelle tabelle del caso, nascosti nell'interfaccia, «Mostra» registrato, assenti dal report portatile senza la scelta e presenti con la scelta, assenti dagli strumenti dell'agente. **Non provato:** portachiavi GrayKey o Cellebrite reali; decifratura reale di Signal, Session o SimpleX (nessun database cifrato nel collaudo); il rapporto di iLEAPP nella cartella del caso contiene i valori in chiaro (è il rapporto dello strumento). **File citati più chiari: un riquadro per file, esito in tre livelli (prima della pubblicazione).** Nel pannello «File citato» la stessa foto compariva più volte (caso pubblico iOS 13.4.1, *Photos.sqlite EXIF Analysis*, IMG_0059.PNG: tre riquadri per «Media» di iLEAPP, «Directory» con «altre 3 copie…» e «Filename» «trovato per solo nome, da verificare», tutti sullo stesso file). Ora: **cartella e nome** scritti in due campi della stessa riga si uniscono in un percorso completo (`DCIM/100APPLE/IMG_0059.PNG`, cercato per percorso; se non porta a un file, es. «Original Filename» di un'altra cartella, il nome resta da solo); **un riquadro per ogni file diverso**, con «indicato nei campi: Media, Directory + Filename»; un campo che indica solo una cartella diventa il collegamento **📁 cartella** nel riquadro del file; esito in parole semplici e a colori: ✅ **trovato con certezza** (percorso completo, hash, collegamento registrato da iLEAPP/ALEAPP; «hash verificato» se l'hash della riga coincide), ⚠️ **probabile, da verificare** (solo nome o nome e dimensione, con l'elenco dei **candidati**: prima il solo nome valeva solo se tutti gli omonimi avevano la stessa dimensione), ❌ **non presente nell'estrazione** (nei dischi «nella copia»); se più campi concordano vale il metodo più forte; «altre N copie con lo stesso percorso finale» in **▸ Dettagli tecnici** (chiuso) con l'elenco delle copie (percorso, dimensione, SHA-256 se già calcolato) e una frase che spiega cosa vuol dire; pulsante **?** con i tre livelli. Stesse regole nella tabella degli artefatti (una sola miniatura per riga, bordata se l'esito non è certo; l'hash della riga si verifica anche nella ricerca veloce quando c'è un solo file fino a 16 MB, così l'esito è lo stesso del pannello), nel report portatile (anche il CSV), in Preferiti, Reperto e registro, nello strumento degli artefatti dell'agente e negli allegati delle chat; nel **report del caso (Markdown, Word, PDF)** la nuova sezione «File citati dagli artefatti nei Preferiti» scrive esito e metodo, campo per campo, di ogni file citato. Gli allegati delle chat si collegano come prima. Tabella dei percorsi: `/var/…` di iOS anche come `filesystem2/…` delle estrazioni in stile Cellebrite (prima un percorso completo `/var/mobile/…` lì non si trovava). `tools/file_citati_conta.py` conta anche i tre livelli e i file indicati da più campi; `tools/collaudo_mobile.py --file-citati` costruisce la nuova prova. **Prova:** collaudo 261/261 in italiano e in inglese (20 controlli nuovi: estrazione iOS finta `ios_file_citati.zip` con IMG_0059.PNG nelle posizioni del caso di Hickman → un solo file citato ✅ con la cartella; due file con lo stesso nome in cartelle diverse e il solo nome nella riga → ⚠️ con due candidati; nome e dimensione, hash verificato, copie, file assente, nome originale di un altro file; stesso esito nella tabella e nel report portatile; sulle righe SMS reali di iLEAPP 11 allegati, ognuno un solo file ✅, 8 con due campi uniti). Casi di Hickman: iOS 13.4.1, riga di IMG_0059.PNG → un solo file ✅ con «Media, Directory + Filename» e la cartella `DCIM/100APPLE`; nel complesso 12.941 file citati distinti (prima 14.346 riquadri; 1.405 file indicati da più campi): 10.060 certi, 382 probabili, 2.499 non presenti; Pixel 3, 9.920: 7.612 certi, 277 probabili, 2.031 non presenti. Pannello, report Word/PDF e report portatile provati nel browser e sui file prodotti. **Filtri, riquadri, Ricerca, sysdiagnose, report degli smartphone e verifica del registro (ultimo giro prima della pubblicazione).** Il **riquadro dei filtri delle colonne** (▾) usciva dallo schermo sui portatili da 13" con molti valori e i pulsanti per applicare non si vedevano: ora si apre sotto o sopra il pulsante secondo lo spazio, l'altezza dipende da quella della finestra, l'elenco dei valori scorre al suo interno e ordinamento, campo di ricerca e *OK / Azzera colonna / Annulla* restano sempre visibili (GUI e report portatile). **Riquadri ridimensionabili col mouse**: pannello del caso, albero dei Risultati, albero delle cartelle del File System, anteprima/dettagli a destra, elenco delle conversazioni della vista chat e, nel report portatile, albero delle cartelle, categorie dei Preferiti, anteprima ed elenco delle chat; doppio clic sul divisore = larghezza predefinita, misure ricordate nel browser, *Ripristina colonne* rimette anche i riquadri. **🔎 Ricerca** in alto a destra, sotto il selettore del tema, apre il pannello di ricerca; dopo ogni ricerca resta un'**etichetta** («🔎 “bitcoin” · 37», le ultime quattro del caso) che ne riapre i risultati; casi dei dischi e degli smartphone; fa parte di Indietro/Avanti; la voce resta nell'albero. **Sysdiagnose di iOS** (`sysdiagnose_….tar.gz`, anche più di uno) nel modulo del nuovo caso smartphone e nel pannello di un caso esistente: SHA-256 nel registro a catena, nessuna copia nel caso, **secondo giro di iLEAPP** sull'archivio (`-t gz`: iLEAPP estrae solo i file che legge), righe nella sottovoce **Sysdiagnose** degli artefatti di iLEAPP marcate «da sysdiagnose <nome del file>», data di creazione (UTC e ora del telefono) e dispositivo ricavati dal nome della cartella dell'archivio (e da `remotectl_dumpstate.txt` se c'è), sezione nel report; ↻ rilegge, ✕ toglie con le sue righe; *Fonte* su una di queste righe spiega che il file è dentro il sysdiagnose. Nuovo modulo `forense_mobile_sysdiagnose.py`; da terminale `prepara … --sysdiagnose FILE` e `aggiungi --case CASO sysdiagnose --file FILE`. **Report dei casi smartphone**: non dicono più che l'analisi è fatta con Sleuth Kit e gli strumenti dei dischi; elencano solo gli strumenti usati in quel caso con la versione (RepertIA, lettori di chat, iLEAPP/ALEAPP con l'impronta, exiftool e pdftotext se si è indicizzato, 7-Zip e Tesseract se usati, portachiavi e sysdiagnose con lo SHA-256) in testa al report, in *Ambiente di analisi* e nel report portatile, e il metodo è quello dell'estrazione del file system (niente partizioni, spazio non allocato, plaso, carving); il report dei dischi è invariato (confrontato riga per riga, cambiano solo le righe nuove del registro). **Verifica del registro a posteriori**: il report (tutti i formati) stampa numero di voci e **hash finale** di `audit_log.jsonl`; **🔗 Verifica registro** nella pagina iniziale (un `audit_log.jsonl` qualsiasi o la cartella di un caso) e nel caso aperto ricalcola la catena e dice integro / prima riga alterata (numero, SHA-256 atteso e attuale, contenuto) / righe mancanti in mezzo / righe inserite; con il campo facoltativo «hash finale atteso» (e le voci) dal report scopre anche righe tolte alla fine e un registro riscritto; ricontrolla gli SHA-256 dei file esportati citati nel registro presenti nella cartella del caso; da terminale `tools/verifica_registro.py <file o cartella> [--hash-finale …] [--voci …]` (nuovo modulo `forense_registro.py`, solo libreria standard di Python). Il manuale spiega cosa dimostra la verifica e cosa no. Corretti anche: l'intestazione del caso a 1280 px («Nuova conversazione» tagliata), ora va a capo. **Prova:** collaudo **363/363 in italiano e in inglese** (77/77 su immagini pubbliche o valori pubblicati da terzi), dal pacchetto Mac assemblato: 102 controlli nuovi — 45 sulla verifica del registro (ogni prova: catena integra e hash finale del report trovato; prova del disco con manomissione: riga modificata indicata con il suo numero, riga tolta in mezzo indicata con il numero della voce, righe tolte alla fine non scopribili senza hash finale e scoperte con hash finale e voci, righe aggiunte dopo il report non scambiate per manomissione; prove con chat esportate: file esportati uguali, un file esportato modificato scoperto), 18 su voci e hash finale nel report, 18 sugli strumenti del report (dischi con Sleuth Kit come prima, smartphone senza), 11 sui sysdiagnose (nuova prova 25 con due archivi nella forma di un sysdiagnose costruiti con i ritagli **pubblici** dei test di iLEAPP: `ps.txt` reale di iOS 16 20A362, 333 processi contati senza iLEAPP = 333 righe di *Sysdiagnose Process*; BatteryUI e ManagedSettings di iOS 26.6 23G71; SHA-256 nel registro, nessuna copia, data e dispositivo, righe marcate, «Togli» che toglie solo le righe di quel file, *Fonte* con il messaggio chiaro). Nel browser a 1280×800 e a 1024×560: riquadro dei filtri dentro la finestra, divisori (trascinamento, memoria dopo il ricaricamento, doppio clic, *Ripristina colonne*), Ricerca con etichetta e Indietro/Avanti, sysdiagnose nel modulo e nel caso, *Verifica registro* dalla pagina iniziale; report portatile (divisori, filtri, strumenti); nessun errore JS. **Non provato:** sysdiagnose completi di un caso (solo ritagli pubblici), Windows e Linux dei pacchetti ricostruiti. **Navigazione dopo una Ricerca, divisori orizzontali e barra in alto (ultime correzioni prima della pubblicazione).** Sul caso iOS 13.4.1, dopo una ricerca dal pulsante **🔎 Ricerca**, *← Indietro* sembrava non funzionare e i clic nell'albero cambiavano le briciole (es. «Artefatti di sistema › … › Accounts») ma non il contenuto (restava la Timeline); sui risultati le briciole dicevano «Documenti». Causa principale (trovata con l'errore della Console dopo il primo giro di correzioni): nell'albero dei Risultati il controllo delle voci da tenere aperte (`renderResTree`) dava per scontato che ogni voce avesse sottovoci; le ricerche salvate sotto «🔎 Ricerca», le categorie dei Preferiti e le «Schede aperte» non le hanno, e con la voce madre chiusa (▸) ogni cambio di sezione si fermava con un errore JavaScript dopo aver aggiornato sezione e briciole e prima di caricare la tabella (difetto della 2.20.0, assente nella finestra in incognito perché lì l'albero riparte con «Ricerca» aperta). Concausa: la tabella accettava la risposta del server anche se arrivava dopo una richiesta più recente della stessa sezione (es. «Artefatti iLEAPP/ALEAPP», 300.277 righe, circa 6 s la prima volta, poi «Bluetooth» subito dopo: Bluetooth compariva e veniva sovrascritto dalle 300.277 righe), mentre le briciole si aggiornavano al clic; Indietro ripristinava lo stato giusto ma una risposta in ritardo lo copriva; i clic fatti mentre un caricamento lento era ancora in corso non erano registrati come passi; il pannello Ricerca mostrava le briciole della sezione di partenza. Ora ogni caricamento ha un numero d'ordine e vale solo l'ultimo (anche per il grafico della Timeline), al cambio di sezione o di sottovoce la tabella mostra subito «Carico…», ogni clic dell'utente è un passo anche durante un caricamento, ← → funzionano anche se il browser non segnala il passo (cronologia di un caricamento precedente della pagina) e le briciole sono complete (*🔎 Ricerca*, *🔎 Ricerca › Parole: …*, *⭐ Preferiti › categoria*, *Timeline › File system*, *Documenti › .pdf*). Dopo una ricerca la voce *🔎 Ricerca* dell'albero si aggiorna subito (prima solo riaprendo il caso). **Divisori orizzontali**: il confine fra grafico «Attività» della Timeline e tabella, fra intestazione/filtri e tabella (misura per sezione: riepilogo della ricerca, percorso e filtri del File System, pannello dei filtri) e, nella vista chat, fra filtri ed elenco delle conversazioni e fra intestazione e messaggi si trascina in su e in giù; doppio clic = altezza predefinita; **▾/▸** comprime il riquadro sopra in una riga (anche ▾ accanto al titolo del grafico); misure ricordate nel browser, *Ripristina colonne* rimette anche queste; nel report portatile lo stesso per il grafico dei mesi/giorni della Timeline. **Barra in alto compatta**: se non sta su una riga gli strumenti diventano un'unica etichetta «✓ 8 strumenti» (o «! 6 di 8 strumenti») che apre l'elenco completo, poi restano le due ricerche più recenti con «tutte (N)» e il sottotitolo passa nel suggerimento del nome (a 1280×800 la barra è alta 55 px invece di 87-116). Nuovo **`tools/prova_navigazione.py`** (Playwright, non nei pacchetti): avvia l'interfaccia sui casi indicati e prova ricerca dal pulsante in alto → risultati → clic su una voce dell'albero → Indietro → risultati → Indietro → pannello → Indietro → sezione di partenza → Indietro → pagina iniziale → Avanti, lo stesso dall'etichetta della ricerca e dalla voce dell'albero, due sottovoci cliccate di seguito e le voci madri chiuse; dopo ogni passo controlla che briciole e tabella indichino la stessa sezione. **Prova:** `tools/prova_navigazione.py` sui casi 01 (disco), 20 e 25 (smartphone) del collaudo, finestra 1280×800: **66/66** (anche con «Ricerca», «Preferiti» e «Schede aperte» chiusi) in Chromium (italiano e inglese) e in WebKit (motore di Safari); sul caso iOS 13.4.1 di Hickman la sequenza «iLEAPP» → «Bluetooth» resta su Bluetooth (107 righe); divisori, ▾/▸, doppio clic, memoria dopo il ricaricamento e *Ripristina colonne* provati nel browser (interfaccia, vista chat e report portatile); barra in alto su una riga a 1024, 1280, 1440 e 1920 px; nessun errore JS; collaudo 363/363 in italiano e in inglese dal pacchetto Mac assemblato (invariato: le correzioni sono nelle pagine). **Non provato:** Safari vero (provato il motore WebKit di Playwright), Windows e Linux dei pacchetti ricostruiti. **WhatsApp, chiamate di tutte le app, foto e video ↔ chat, backup decifrati e affidabilità delle chat da iLEAPP/ALEAPP (ultimo giro prima della pubblicazione).** *Tipi dei messaggi WhatsApp*: ogni messaggio ha il suo tipo dal valore del database (`ZMESSAGETYPE`, `message_type`, `media_wa_type`), con «⚠ tipo non verificato» dove il significato non è stato controllato sulle immagini pubbliche di Josh Hickman; un valore sconosciuto è «[tipo N non gestito]», mai un generico «allegato» (nuovo `forense_mobile_wa.py`). *Stato di consegna e lettura* dei messaggi inviati (✓, ✓✓, ✓✓ blu, ▶) con destinatario, data, fonte e verifica (nuovo `forense_mobile_ricevute.py`, tabella `chat_receipts` nei casi nuovi); su iPhone lo stato di lettura dei messaggi inviati non è leggibile (`ZMESSAGESTATUS` = 8 su tutto) e la spunta grigia lo dice; per i messaggi ricevuti su iPhone «letto …» = ora in cui questo telefono li ha letti (`ZSENTDATE`, entro 1 s dalla conferma registrata dall'altro telefono in 8 casi su 10). *Avvisi di WhatsApp*: su Android gli avvisi (`message_type` 7, segnati `from_me = 1`) risultavano **inviati** (difetto della 2.20.0): ora sono «avviso generato da WhatsApp», con codice, persone e dettagli dal database e, dove fonti pubbliche lo spiegano, la frase con il livello «concorde in 2 fonti pubbliche» (WAInsight, WhatsApp-Chat-Exporter) o «probabile, 1 fonte»; su iPhone nessuna fonte pubblica spiega `ZGROUPEVENTTYPE`: solo valori e fatti dal database (creazione del gruppo, ordine di WhatsApp), e il tipo 10 non risulta più ricevuto dal contatto. *Chiamate*: lettori propri per WhatsApp (iPhone `CallHistory.sqlite` e messaggi di tipo 59; Android `call_log` e messaggi di tipo 90), Skype (`s4l-*.db`) e imo Android (`imdata`), unite senza doppioni a quelle di iLEAPP/ALEAPP; nuove da iLEAPP/ALEAPP Signal (se decifrato), Google Voice, Teams, Facebook Messenger e TeleGuard, con l'inizio calcolato dove l'orario scritto è la fine (nuovo `forense_mobile_chiamate.py`). *Chat da iLEAPP/ALEAPP*: verso corretto per LINE, imo, Life360 e Slack con regole ricavate dalla documentazione di Hickman; nuove chat Signal, Life360, Slack, Google Voice; i messaggi WhatsApp di ALEAPP non si aggiungono più come seconda app (erano un doppione). *Limite di 500.000 righe*: oltre il limite si importano prima chat, messaggi e chiamate e le tabelle omesse sono elencate (su iOS 17 le chat di 23 app restavano fuori). *Backup di WhatsApp* `.crypt14` decifrati con la chiave dell'estrazione (opzione del nuovo caso e analisi aggiuntiva; nuovo `forense_mobile_wabackup.py`): app «WhatsApp (backup decifrato)» e «⚠ solo nel backup» sui messaggi assenti dal database attuale. *Foto e video ↔ chat*: sottovoce **🎞 Video**, filtri **Solo foto** e **Solo video**, voce **💬 Dalle chat**, riquadro **Origine** con **Apri nella chat**, colonna `origine_chat` nel CSV, anche nel report portatile. *Anteprima dei database dei telefoni* con i file `-wal`/`-shm` (prima i dati potevano essere incompleti). *Ricerca veloce nei risultati del caso* (**⚡ Risultati del caso**, prima scheda del pannello di ricerca): cerca mentre si scrive in artefatti, artefatti di iLEAPP/ALEAPP, chiamate, chat, conversazioni, rubriche e posta, con i risultati raggruppati come nell'albero e apribili con un clic, i numeri di telefono trovati in qualunque formato (ultime 9 cifre) e *Salva come ricerca*; indice `ricerca_veloce.sqlite` nella cartella del caso, costruito alla prima ricerca e rifatto quando cambiano i risultati (nuovo `forense_ricerca_veloce.py`). *Apertura dei casi grandi*: finestra con la barra di avanzamento finché albero dei Risultati, conteggi e grafico della Timeline non sono pronti, poi risposte tenute in memoria finché il caso non cambia; *miniature dei video* negli allegati delle chat (prima solo le immagini), anche per i video senza estensione come quelli di Telegram (riconosciuti dal nome o dall'intestazione MP4/MOV; sul Mac Quick Look si bloccava su questi file); *report portatile*: timeline in file per giorno (la tabella compare subito anche con 1 milione di eventi in un giorno: 0,4 s invece di un file da centinaia di MB), ricerca veloce *⚡ Risultati del caso* anche nel portatile e righe di iLEAPP/ALEAPP in file per artefatto caricati a richiesta (prima 618 MB caricati all'avvio, troppi per il browser); *grafico della Timeline* nell'ora del telefono o italiana calcolato per minuto invece che evento per evento (2,5 milioni di eventi: da circa 40 s a 2-7 s, stessi numeri) e messaggio di attesa al suo posto. *Interfaccia*: ricerca nella scheda **Testo**, riquadro dei filtri allargabile, partecipanti dei gruppi grandi in un elenco a scomparsa, avvisi dell'importazione in una finestra. **Prova:** immagini pubbliche di Hickman iOS 13.4.1, iOS 17.3, Android 10 e Android 14 rifatte e confrontate per contenuto con i casi della 2.20.0 precedente (nessun messaggio, allegato, conversazione o chiamata mancante; differenze solo volute: il doppione WhatsApp di ALEAPP tolto, l'orario delle chiamate trovate anche in interactionC ora preso dal registro di sistema *Call History*, 3-19 s dopo, e su iOS 17 le righe di iLEAPP importate secondo la nuova precedenza oltre il limite); chat da iLEAPP/ALEAPP confrontate con le attività documentate da Hickman: verso giusto per tutti i messaggi ritrovati (iOS 17.3 766, Android 14 272; gli 8 diversi dalla documentazione sono 7 errori della documentazione, che segna lo stesso messaggio come inviato da entrambi i telefoni, e 1 abbinamento sbagliato dello script di confronto); chiamate WhatsApp, Skype, imo, Signal, Messenger e TeleGuard uguali alla documentazione; backup `msgstore.db.crypt14` dell'Android 14 decifrato (197 messaggi); collaudo con 50 controlli nuovi (backup WhatsApp finto con chiave inventata, avvisi, foto/video, lettura su iPhone, ricerca veloce: messaggio ritrovato da una parte del testo, numero della rubrica ritrovato in un altro formato, anteprima della voce della rubrica, nessun valore segreto nell'indice; report portatile: timeline per giorno con tutti gli eventi una volta, righe di iLEAPP/ALEAPP nei file per artefatto, ricerca veloce presente); grafico della Timeline confrontato con il calcolo precedente: identico su iOS 17.3, Android 14 e DFTT 05, nell'ora del telefono e in ora italiana, per giorno, mese e anno, con e senza filtri; ricerca veloce sull'iPhone iOS 17.3 di Hickman: indice di 502.843 righe in 1 minuto e 1,0 GB, risposte in 4-51 ms. **Finestre d'attesa e fluidità:** la finestra del report portatile resta aperta durante la creazione, con *Interrompi* (cartella a metà tolta, voce nel registro); la finestra «Apertura del caso» e la pagina della preparazione compaiono subito; riepilogo di apertura in cache, prima pagina di ogni sezione preparata in sottofondo, ultima pagina vista in memoria; report portatile più rapido all'avvio (iPhone con 830.000 voci da circa 19 s a 5 s); report portatile: spazio reale sul disco stimato (cluster, cartelle, anteprime, dati) con *Crea il report* spento se non basta, arresto e cartella tolta se il disco si riempie, dettagli raggruppati, file «._» di macOS tolti sui dischi exFAT/FAT; campo **Filtra le voci** in cima all'albero dei Risultati; miniature dei video ricavate dal browser quando il programma non riesce a farle, e miniature non riuscite con versioni precedenti riprovate; sezione **Foto/Video/Audio** (prima *Foto e metadati*) con sottovoci Foto, Video e Audio, ciascuna con «Dalle chat» per app; miniature non più tolte dalla pulizia della cache; **trascrizione degli audio** con Whisper sul computer (alla creazione del caso o dopo, modello scaricato solo con il consenso dell'analista, testo nella ricerca, nell'anteprima, nelle chat e nei report); **barra di avanzamento** nella preparazione del caso (passo N di M, numeri del passo in corso, tempo stimato, ultimo segnale dal programma) con i passi comunicati dal programma stesso (prima risultavano tutti finiti già dopo l'elenco dei file), **copie shadow** molto più rapide sui dischi di sistema, barra del download del modello di trascrizione, filtri delle colonne con la ricerca nei valori applicati davvero, menu **Caso / Report / Verifiche / Analisi aggiuntive** sotto la scritta RepertIA; prova della navigazione 66/66 (Chromium it/en, WebKit). **Non provato:** backup crypt12/crypt15, codici degli avvisi su un telefono con azioni di gruppo documentate, Windows e Linux dei pacchetti ricostruiti.

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

`RepertIA-2.20.1-Mac.zip` contiene **RepertIA.app** con Python 3.12, openai, Pillow e **plaso
già inclusi** (niente Docker). Trascina l'app in Applicazioni; la prima volta: tasto destro →
*Apri* (o *Impostazioni di Sistema → Privacy e sicurezza → Apri comunque*), perché non è firmata
con un certificato Apple. L'app apre il Terminale, installa con Homebrew gli strumenti che mancano
(Sleuth Kit, libewf, exiftool, poppler, PhotoRec, bulk_extractor, Tesseract) e poi il browser.
7-Zip, libpff e i dati dell'OCR italiano/inglese sono già nell'app. Per aggiornarli
c'è *Aggiorna strumenti.command* nello zip. Solo per Mac M1 o successivi.

## Versione Windows

`RepertIA-2.20.1-Setup.exe` installa RepertIA per l'utente corrente (senza diritti di
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

`RepertIA-2.20.1-Linux.tar.gz` è per **Linux x86_64** con Python 3.12 o successivo (Ubuntu 24.04 o
successivo, Debian 13). Il programma è lo stesso delle versioni Mac e Windows (stessa impronta dei sorgenti).

```
tar -xzf RepertIA-2.20.1-Linux.tar.gz
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
- **«Contesto del modello pieno»** (2.20; prima compariva come errore 500 del server, per esempio con Qwen su Ollama
  «no user query found in messages»): dopo alcune ricerche dell'agente i risultati degli strumenti superano il contesto
  del modello (il valore *Contesto* nel riquadro del server LLM) e il server taglia l'inizio della conversazione, domanda
  compresa. Alza il contesto (Ollama: Impostazioni → *Context length* oppure `OLLAMA_CONTEXT_LENGTH=32768`; LM Studio:
  carica il modello con un contesto di 32768 o più), premi *Ricollega* e controlla il nuovo valore; oppure fai domande
  più mirate (un termine, una fonte). RepertIA non accorcia di più i risultati da solo, per non togliere elementi utili.
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

Versione del programma: 2.20.1 · Documento aggiornato al 29/10/2026

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
| 2.20.0 | Mac dell'autore (Python dell'app; iLEAPP 2026.4.5, ALEAPP 2026.4.4) | 422/422 in italiano e 422/422 in inglese, dal pacchetto Mac assemblato: 173 dei dischi + 249 degli smartphone, di cui 18 su WhatsApp e foto/video/audio (backup WhatsApp finto con chiave inventata, avvisi di sistema, lettura su iPhone, Solo foto/Solo video, audio dell'estrazione e delle chat, origine dalle chat) e 17 sulla ricerca veloce nei risultati (indice costruito, messaggio ritrovato da una parte del testo, numero della rubrica ritrovato scritto in un altro formato, anteprima della voce della rubrica, nessun valore segreto del portachiavi nell'indice), 17 sul report portatile (timeline per giorno con tutti gli eventi una volta, righe di iLEAPP/ALEAPP nei file per artefatto, ricerca veloce presente), 33 sui pulsanti dell'interfaccia, 5 su file citati, allegati e riepilogo delle chat, 44 nelle due prove del portachiavi finto, 20 sui file citati in tre livelli (19 nella prova dell'estrazione finta, 8 dei quali sulle righe di prova, e 1 sulle righe SMS reali di iLEAPP), 45 sulla verifica a posteriori del registro, 36 su registro e strumenti nel report 11 sui sysdiagnose (prova 25 con ritagli pubblici dei test di iLEAPP) e 7 sulla trascrizione degli audio (elenco dei modelli, consenso obbligatorio, file non validi rifiutati, percorso del testo con un motore finto; la trascrizione vera con un modello installato è una misura) (77/77 su immagini pubbliche o su valori pubblicati da terzi) |
| 2.20.1 | Mac dell'autore (come la 2.20.0) | 427/427 in italiano e 427/427 in inglese, dal pacchetto Mac assemblato: 178 dei dischi + 249 degli smartphone; i 5 nuovi riguardano l'AI Act (reperto dell'agente «modello IA – da verificare» in findings.json e nel report, senza la frase «ogni reperto è stato verificato»; metadati IA di Word e PDF; dopo «Confermo, verificato» reperto verificato con operatore e data nel report e nel registro; server LLM locali e privati distinti da quelli esterni) (77/77 su immagini pubbliche o su valori pubblicati da terzi) |

Carving DFTT 11: 2 file su 15 (enterprise.wav, haxor2.jpg) non vengono recuperati da PhotoRec: è un limite di
PhotoRec, dichiarato come «misura» e non come requisito.

**Da fare a ogni nuova versione:** eseguire il collaudo su Mac, Windows e Linux prima dell'uso in un caso e conservare
il rapporto `collaudo_<data>.md` con la consulenza. Collaudo completo sul Mac: 2.18.1 112/112; 2.19.0 112/112 in italiano e
112/112 in inglese. Collaudo completo eseguito dall'autore anche su Windows per le versioni dalla 2.17.x alla 2.19.0.
**Linux (sperimentale, 2.19.0)**: collaudo superato nell'ambiente Linux di sviluppo; da ripetere su un computer Linux
installato con `installa.sh` prima dell'uso in un caso. **2.20.1**: collaudo sul Mac 427/427 in entrambe le lingue; da
ripetere su Windows e Linux (pacchetti costruiti sul Mac).

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


### 7. Controllo delle modifiche

Ogni versione è descritta nel registro delle modifiche (README, sezione Aggiornamenti) con cosa cambia, come è
stata provata e cosa NON è stato provato. L'impronta dei sorgenti nel report permette di dimostrare quale versione ha
prodotto un risultato.
