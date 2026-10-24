# Registro delle modifiche

*English: [CHANGELOG.en.md](CHANGELOG.en.md).*

Estratto dalla sezione «Aggiornamenti» del manuale (src/README.md). Per ogni versione: cosa cambia, come è stata provata, cosa non è stato provato.

## 2.19.0 – pacchetto Linux (sperimentale)

Nuovo pacchetto **`RepertIA-2.19.0-Linux.tar.gz`** per Linux x86_64 con Python 3.12 o successivo (Ubuntu 24.04+, Debian 13). Il programma non cambia: stessi file e stessa impronta dei pacchetti Mac e Windows 2.19.0. `installa.sh` installa con apt Sleuth Kit, libewf, PhotoRec, Poppler, ExifTool, Tesseract e zenity, crea in `python/` l'ambiente con plaso, libyal, pytsk3, Pillow e openai alle stesse versioni degli altri pacchetti (`requirements-linux.txt`) e aggiunge RepertIA al menu; `RepertIA.sh` avvia, `collaudo.sh` esegue il collaudo, `aggiorna-strumenti.sh` aggiorna gli strumenti di sistema. Inclusi 7-Zip 26.01 per Linux e i dati OCR. **Prova:** nell'ambiente Linux di sviluppo collaudo 112/112 in italiano e 112/112 in inglese, caso con plaso, analisi estese e OCR, interfaccia nel browser. **Non provato:** `installa.sh` su un computer reale (apt e PyPI), bulk_extractor, zenity, il client openai.

## 2.19.0

Interfaccia e testi del caso **in italiano o in inglese**. Selettore della lingua in alto a destra (la pagina si ricarica); nel modulo del nuovo caso si sceglie la **lingua dei testi del caso** (artefatti, riepiloghi, report Markdown/Word/PDF, report portatile, CSV esportati), salvata in `case.json` e indicata nell'elenco dei casi e nel report (*Ambiente di analisi*); i casi precedenti restano in italiano. Cambia solo il testo: dati, hash, percorsi e valori letti dal disco non cambiano. Tecnica: i testi restano in italiano nei sorgenti e fanno da chiave (`tr()` nel Python, `T()`/`TF()` nelle pagine) del dizionario `lingua_en.json` (2.400 testi), incluso nell'impronta del programma; nuovo `tools/lingua_controlla.py` per i controlli; date e numeri delle pagine nel formato della lingua. **Collaudo** con `--lingua it|en` (in inglese accetta i titoli attesi tradotti). **Windows**: installer bilingue (scelta della lingua all'avvio, che diventa quella predefinita di RepertIA), `README_EN.txt` accanto a `LEGGIMI.txt`; nel Mac `README_EN.txt` nello zip. Il modello linguistico riceve le istruzioni e risponde nella lingua dell'interfaccia. **Prova:** collaudo 112/112 in italiano e 112/112 in inglese sul Mac; interfaccia e report portatile in inglese controllati sezione per sezione su un caso di prova. Collaudo eseguito anche su Windows. Il manuale e VALIDAZIONE.md restano in italiano.

## 2.18.1

Correzioni di affidabilità su journal NTFS e registri eventi. **Journal NTFS: percorsi con il numero di sequenza.** La cartella di un'operazione si cercava solo per numero di record MFT: se quel record era stato riutilizzato da un'altra cartella, il file risultava nella cartella sbagliata (percorso plausibile ma falso). Ora il riferimento è completo (record e sequenza): il percorso attuale della MFT vale solo se il record è ancora quella cartella (sequenza uguale, o aumentata di 1 se il record è libero); altrimenti si usa il nome registrato nel journal per quel riferimento, altrimenti «cartella MFT n sequenza s: record poi riutilizzato da …». A parità di record vince la voce presente su quella cancellata. **Journal: limite e stato dichiarati.** Oltre 500.000 operazioni si tengono le più recenti e la nuova voce di sistema «Journal NTFS $UsnJrnl letto» dice quante, il periodo, quante sono state escluse e quante cartelle hanno il record riutilizzato o la sequenza non verificabile; un journal assente (disattivato) o non leggibile è dichiarato («Journal NTFS assente» / «non letto») invece di dare zero operazioni in silenzio. **Registri eventi: record recuperati e illeggibili.** I record ricavati dallo spazio libero del file .evtx sono indicati come «recuperato» (titolo, dettaglio e campo `recuperato`); quelli identici a un record attivo non si contano due volte (prima un accesso poteva risultare doppio); i record illeggibili si contano. La scheda dell'account dice quanti accessi e sessioni vengono da record recuperati; ogni registro letto ha una voce di sistema con record attivi, recuperati e illeggibili, e per gli eventi di sistema anche il limite di 20.000 se raggiunto; registri non estratti o non leggibili e modulo pyevtx mancante sono dichiarati. **Prova:** journal costruito (record v2 con cartella attuale, cartella riutilizzata nota e ignota al journal, cartella cancellata non riutilizzata, limite, sequenza non verificabile; journal assente e volume non apribile) e libevtx simulato (record attivi, recuperati, recuperati doppi, illeggibili) con accessi ed eventi di sistema. **Non provato:** pytsk3 reale (`open_meta(...).info.meta.seq`) e libevtx reale su un disco: rifare «Artefatti» su una copia reale e confrontare con MFTECmd / EvtxECmd.

## 2.18.0

Più copertura forense sui dischi Windows. **Tutte le installazioni di Windows**: registro, utenti, accessi, prefetch, Amcache, SRUM e registri eventi si leggono per ogni cartella che contiene `Windows/System32/config/SYSTEM` (anche `Windows.old`, `Windows.old.000`), con il nome tra parentesi quadre negli artefatti: su un disco aggiornato o reinstallato l'attività precedente era prima invisibile. **Nuovi artefatti**: cartelle aperte (ShellBags), ShimCache e BAM/DAM, SRUM, Cronologia attività, journal NTFS `$UsnJrnl` (file creati, cancellati e rinominati, con il percorso ricostruito), registri eventi (servizi installati, accensioni e spegnimenti, sessioni e Desktop remoto, Defender, dischi USB, registri cancellati), miniature `thumbcache` estratte con gli hash. Nuove categorie: *Cartelle aperte*, *Journal NTFS*, *Eventi di sistema*. **Hash percettivi**: nuova analisi facoltativa, ricerca *Immagini simili* e confronto con cartelle di immagini di riferimento nelle *Liste di hash*; le liste in formato **Project VIC / CAID** (JSON) si leggono con la categoria. **Validazione**: nuovo documento `VALIDAZIONE.md` (sezione *Validazione* qui sotto) con metodo, dati di prova, risultati del collaudo e limiti noti. Gli artefatti vanno rifatti (*Artefatti di sistema* → Rifai) per vedere le novità nei casi già preparati.

## 2.17.3

Due correzioni dopo una seconda prova sulla stessa copia reale. **Anomalie: restavano falsi positivi tra i file cancellati.** Il controllo della 2.17.2 guardava solo se il primo cluster era oggi assegnato a un file presente; ma se dopo la cancellazione quei cluster sono stati usati da un altro file, cancellato anche lui, risultano liberi e il contenuto letto è di quell'altro file (un `msedge.dll` che «contiene» un JPEG, un `image.pdf` che «contiene» un eseguibile). Ora: una sola passata sulla MFT trova ogni altro record (anche libero) che usa quei cluster, e il contenuto deve essere coerente con la dimensione e la fine del file; se non lo è la voce si esclude e il riepilogo dice quante e perché. Sulla copia reale: delle 293 segnalazioni su file cancellati ne restano 12, quasi tutte di gravità bassa. Inoltre non sono più anomalie i moduli di programmi con estensione propria (`office.odf`, `Flash.mpp` di Acrobat…), gli eseguibili nelle cartelle dei programmi, le icone degli installatori e i log del registro; lo scambio foto/video è di gravità bassa. **Account utente: accessi a 0.** Per un account collegato a un **account Microsoft** (o con accesso tramite PIN/Windows Hello) Windows non aggiorna il contatore e la data di accesso del SAM. Gli accessi si contano ora dai registri eventi: `Security.evtx` (4624 riusciti, per tipo: interattivo, con credenziali in cache, remoto; 7 = sblocchi, contati a parte; i due eventi che un amministratore genera per lo stesso accesso contano una volta; 4625 falliti) e `System.evtx` (Winlogon 7001, sessioni). La scheda dell'account mostra il numero di accessi nel titolo, il periodo coperto dai registri (gli accessi precedenti non sono più registrati), l'ultimo accesso, l'indirizzo dell'account Microsoft e il SID; il contatore del SAM resta indicato a parte.

## 2.17.2

Tre correzioni dopo l'uso su una copia reale. **Anomalie: falsi positivi.** Un `.png` poteva risultare «eseguibile Windows»: per una voce *cancellata* il programma leggeva il contenuto dal numero di inode, ma su NTFS (e FAT, ext) quel record può essere già stato assegnato a un altro file, o i suoi cluster riscritti. Ora, prima di segnalare un file cancellato, si controlla che il nome corrisponda a quello memorizzato nel record e che il primo blocco dei dati non sia stato riutilizzato; le voci non più attendibili si escludono (il numero è nel riepilogo). I file con nome attuale vengono guardati per primi, così un inode già letto non viene riletto con un nome vecchio. Più estensioni di eseguibili note (`.msstyles`, `.xll`, `.vxd`…), nessuna anomalia per un formato diverso in `.dat/.bin/.db/.tmp…` e gravità bassa per lo scambio tra formati immagine. **Account utente: accessi sempre a 0.** Windows scrive le modifiche del registro prima nei file di log (`SAM.LOG1`, `SAM.LOG2`, `NTUSER.DAT.LOG1`…) e solo ogni tanto nell'alveare: leggendo il solo `SAM` si vede uno stato vecchio. Ora i log accanto all'alveare (SAM, SYSTEM, SOFTWARE, NTUSER.DAT, Amcache) si applicano a una **copia di lavoro** (record verificati con gli hash Marvin32, solo se la sequenza è continua; l'originale non cambia) e l'operazione è dichiarata tra gli artefatti («Registro: log applicati a…»). Il contatore del SAM, inoltre, non conta tutti gli accessi (account Microsoft, PIN, Windows Hello): se è 0 ma l'account risulta usato non si scrive più «mai acceduto», e si aggiungono l'ultimo caricamento e scaricamento del profilo (SOFTWARE, ProfileList), le password errate e, per ogni utente, l'ultima scrittura di `NTUSER.DAT`. **Documenti per estensione**: nella vista ad albero la voce Documenti si divide per estensione, con filtro *Estensione* nella sezione.

## 2.17.1

Su Windows il pulsante **Scegli…** di *Riscontro con altro strumento* non apriva la finestra di scelta del file (l'apostrofo del titolo «Scegli l'elenco…» interrompeva il comando di Windows). Corretti anche il filtro della finestra *Scegli la copia forense* (mostrava gli elenchi CSV invece delle copie forensi) e la scelta del file della **lista di hash**, che non si apriva.

## 2.17.0

**Spazio non allocato consultabile** come in Autopsy: cartella `$Unalloc` in ogni volume con i tratti di spazio libero del file system, apribili in testo ed esadecimale, esportabili con SHA-256 e da mettere nei preferiti; lo stesso per gli spazi non allocati tra le partizioni e per i volumi che Sleuth Kit non legge. Verificato: i byte dei tratti coincidono con il flusso dello spazio non allocato di Sleuth Kit (`blkls -A`) su FAT12, FAT16, NTFS ed ext4 (anche da E01).

## 2.16.2

**Avvio più rapido su Windows**: prima di interrogare un server LLM si controlla in mezzo secondo che la porta sia aperta. Su Windows ogni tentativo verso una porta chiusa costava circa 2 secondi e, senza server LLM avviato, l'apertura poteva durare decine di secondi; ora è immediata. Un server in rete non raggiungibile si scarta in pochi secondi.

## 2.16.1

**Date FAT/exFAT corrette anche su Mac** con il dispositivo in un fuso diverso da quello del computer: Sleuth Kit su macOS perdeva l'indicazione del fuso e usava quello del computer (collaudo DFTT 5: orari spostati). Ora il fuso neutro arriva a Sleuth Kit dall'ambiente del processo, in modo identico su Mac, Windows e Linux, e la conversione nel fuso del dispositivo la fa RepertIA. I casi con partizioni FAT/exFAT preparati con le versioni precedenti vengono ricalcolati da soli alla prima apertura (voce `date_fat_ricalcolate` nel registro).

## 2.16.0

Nuovi pacchetti: app per Mac `RepertIA.app`, installazione Windows in `Programmi\RepertIA` con la voce «RepertIA» nel menu Start, cartella di collaudo `RepertIA-collaudo`. Variabili d'ambiente con il prefisso `REPERTIA_`.

## 2.15.5

**Suddivisione del disco in volumi** nell'albero del file system (come in Autopsy): sotto «Disco · <tipo di tabella>» compaiono tutte le righe della tabella delle partizioni lette con `mmls` — area della tabella, spazi non allocati e volumi — con indice (`vol<n>`), descrizione e settori in unità da 512 byte (es. «vol2 (Win95 FAT32 (0x0b): 32-15257599)»). I volumi leggibili si aprono come prima; quelli che Sleuth Kit non legge sono indicati come «file system non letto»; i volumi APFS stanno sotto la loro partizione. Un clic su una riga non apribile ne mostra posizione e dimensione in byte. La stessa vista è nel report portatile. Le immagini senza tabella delle partizioni (es. pendrive) restano come prima.

## 2.15.4

Nel modulo del nuovo caso l'esempio del campo *Operatore* è un nome di fantasia («John Doe»). Aggiunta la nota sul progetto personale e sullo sviluppo con l'ausilio di Claude (Anthropic).

## 2.15.3

**Date FAT/exFAT corrette anche su Windows**: su Windows Sleuth Kit non capiva il nome del fuso del dispositivo (es. `Europe/Rome`) e applicava «fuso 0 con l'ora legale degli Stati Uniti»: le date FAT/exFAT risultavano spostate di un'ora (collaudo DFTT 5 sul PC Windows: 2 controlli non superati). Ora Sleuth Kit legge sempre l'ora scritta sul disco così com'è (fuso neutro `UTC0`, capito allo stesso modo da Windows, macOS e Linux) e la conversione nel fuso del dispositivo la fa RepertIA con il database dei fusi (ora legale europea esatta, anche negli anni passati). Vale per timeline, albero, scheda Metadati e report portatile; le date NTFS/ext/HFS/APFS (già UTC) non cambiano. I casi con partizioni FAT/exFAT preparati su Windows con le versioni 2.13.7-2.15.2 vengono ricalcolati da soli alla prima apertura (voce `date_fat_ricalcolate` nel registro).

## 2.15.2

**Archivi riconosciuti dal contenuto**: un archivio (ZIP, RAR, 7z, tar, gzip, xz, bzip2, CAB) con un'altra
estensione, per esempio un ZIP rinominato `.jpg` o `.boo` per nasconderlo, ora si apre come gli altri, anche dentro altri archivi e negli
allegati di posta; i documenti che sono ZIP per costruzione (Word, Excel, OpenDocument, epub, jar, apk…) restano documenti. Il conteggio
«archivi riconosciuti dal contenuto» è nel riepilogo di *Archivi e posta*. Collaudo DFTT 8: `file9.jpg` dentro `file9.boo` ora estratto
(da misura a controllo superato): 112/112, 46/46 sulle immagini pubbliche.

## 2.15.1

**Due errori del carving trovati dal collaudo sul Mac** (DFTT 11):
- **File recuperati oltre il 500° persi**: PhotoRec mette al massimo 500 file per cartella (`recup.1`, `recup.2`…) ma elenca tutto in un
  solo `report.xml` senza cartella; RepertIA registrava solo quelli della prima. Con più di 500 file recuperati gli altri restavano sul
  disco ma non comparivano nel caso, nel report né nelle ricerche. Ora entrano tutti (provato: 651 su 651).
- **Falsi positivi «dovecot» di PhotoRec 7.2** (quello di Homebrew sul Mac e quello dell'installer Windows): centinaia di file da 80 KB
  che coprivano documenti e video veri (DFTT 11: 8 file identici su 15 invece di 13). Dalla 7.2 il tipo si disattiva (variabile
  `REPERTIA_PHOTOREC_ESCLUDI`, `nessuno` per riattivarlo); il report lo dichiara tra gli avvisi del carving.
- Le **miniature EXIF** che PhotoRec estrae dalle foto recuperate (`t….jpg`) entrano nel caso con l'offset della foto.
- Collaudo: nuovo controllo «tutti i file trovati da PhotoRec sono nel caso». Provato con PhotoRec 7.1 e 7.2 (compilato dai sorgenti):
  111/111, 45/45 sulle immagini pubbliche, carving 13/15 identici all'offset pubblicato con entrambi.

## 2.15.0

**Riscontro con altri strumenti e collaudo su immagini pubbliche**:
- **Riscontro con altro strumento** (Autopsy, FTK Imager, X-Ways, EnCase, AXIOM, Sleuth Kit): file con hash uguale/diverso,
  trovati da uno solo, stato «cancellato» discordante; nel report e nel registro.
- **Collaudo con le immagini DFTT** e i valori pubblicati dal progetto (incluse nello zip di collaudo): 44 controlli superati
  su 44; misure: 3 file frammentati su FAT non ricostruibili, 13 file su 15 recuperati identici e all'offset pubblicato dal
  carving di DFTT 11, ZIP con estensione diversa non aperto.
- **Supporti senza file system leggibile** (danneggiati o sconosciuti): prima la preparazione si fermava; ora il caso si crea e
  restano carving dell'intera immagine, bulk_extractor, ricerca nei byte e plaso (trovato con DFTT 11).

## 2.14.0

**Integrità verificabile e Mac completo**:
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

## 2.13.9

**Date e orari: terzo fuso «del dispositivo» e etichette sempre corrette** (verifica forense):
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

## 2.13.8

**Il fuso del dispositivo si ricava da solo** (l'operatore non deve pensarci):
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

## 2.13.7

**Date e orari a prova di perizia** (fuso del dispositivo, fuso mostrato ovunque, ora legale):
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

## 2.13.6

**Password APFS sbagliata riconosciuta davvero**:
- Su un E01 di Mac (Apple Silicon) la libreria APFS dichiarava «sbloccato» il volume Data anche con una password
  **sbagliata** (poi la radice non era leggibile e risultavano 0 file): l'analisi proseguiva e il volume restava con il
  lucchetto. Ora un volume nato cifrato è considerato sbloccato **solo se la radice si legge davvero**. Con chiave
  errata il popup lo dice (con l'avvertenza che i Mac T2/Apple Silicon possono usare chiavi dell'hardware) e permette di
  **riprovare** o di **proseguire senza**. Vale anche per «Sblocca…» dal caso aperto.

## 2.13.5

**BitLocker e LUKS decifrabili dal popup dei volumi cifrati**:
- Il popup che compare prima dell'analisi (2.13.4) ora permette di usare la chiave anche per **BitLocker** (password o
  chiave di ripristino) e **LUKS** (password): RepertIA calcola lo SHA-256 della copia originale, crea la **copia derivata
  decifrata** (come «Decifra…» del caso; il popup mostra spazio necessario e disponibile) e **avvia da sola l'analisi di
  quella copia come nuovo caso**, con gli stessi dati e opzioni e una nota sull'origine. Chiave errata: nuovo tentativo.
  Il caso sulla copia originale resta come registro della decifratura (non completato).
- Corretto: i volumi a offset 0 (pendrive senza tabella partizioni) nel popup.

## 2.13.4

**Avviso dei volumi cifrati prima dell'analisi**:
- Subito dopo l'apertura della copia, **prima del calcolo dell'hash e dell'analisi**, RepertIA cerca i volumi cifrati
  (APFS/FileVault, BitLocker, LUKS) e, se ne trova, mostra un popup: **Sblocca e continua** (volumi APFS: password
  dell'utente o chiave di ripristino, solo in memoria; chiave sbagliata = nuovo tentativo), **Prosegui senza i volumi
  cifrati** oppure **Annulla l'analisi** (il caso appena creato viene tolto). La scelta dell'operatore è nel registro
  di audit (senza la chiave). BitLocker e LUKS non si sbloccano in questa fase: restano esclusi e si decifrano dopo.
- **Versione 2.13.3**: un volume APFS la cui radice non è leggibile non ferma più la preparazione
  (`'NoneType' object has no attribute 'identifier'`): si provano percorsi alternativi, altrimenti il volume è saltato con avviso.

## 2.13.2

**Volumi cifrati esclusi dall'analisi**:
- Un volume cifrato riconosciuto alla preparazione (BitLocker anche To Go, LUKS, FileVault/CoreStorage) viene **escluso**
  dall'analisi: non si elenca nulla per esso, perché quello che Sleuth Kit legge senza chiave (per esempio il FAT finto
  di un BitLocker To Go) non è il suo contenuto e prima finiva mescolato alle prove delle altre partizioni. Le altre
  partizioni si analizzano normalmente; il volume cifrato resta tra i «Volumi cifrati» del caso e si analizza dopo
  con *Decifra…* (nuovo caso dalla copia derivata). Il **report** indica «NON ANALIZZATO» per ogni volume cifrato.
- Collaudo: disco MBR con una partizione ext4 e una BitLocker To Go (password nota): ext4 analizzata, BitLocker esclusa
  con avviso; decifrata → nuovo caso con entrambe le partizioni leggibili (FAT16, 18 voci).

## 2.13.1

**Avviso sui volumi cifrati**:
- Già alla preparazione del caso RepertIA controlla le firme dei volumi cifrati (BitLocker, anche To Go, LUKS,
  FileVault/CoreStorage). Prima un BitLocker To Go (chiavetta) veniva letto da Sleuth Kit come un FAT senza contenuto
  utile e il caso risultava «pronto» senza che l'operatore se ne accorgesse (il volume emergeva solo con l'analisi
  Anomalie). Ora la preparazione stampa un **avviso ben visibile**, il registro annota `volume_cifrato_rilevato` e il
  pannello del caso mostra «Volumi cifrati» con l'avvertenza che file e date elencati **non sono il contenuto reale**,
  con il pulsante *Decifra…*. Per APFS non cambia nulla (già gestito in 2.13.0).
- Collaudo: immagine BitLocker To Go di prova (password sbagliata → rifiutata; giusta → copia decifrata, nuovo caso
  FAT16 leggibile con la derivazione registrata).

## 2.13.0

**Mac con APFS**:
- **Lettura dei volumi APFS** con libfsapfs (nuovo `forense_apfs.py`), senza Sleuth Kit e senza copie: elenco file,
  albero, timeline (date al secondo, nanosecondi nei Metadati), hash, indice del testo, anteprime, esportazioni,
  report portatile, strumenti dell'agente (`list_directory`, `file_metadata`, `read_file_text`…) e analisi estese
  (artefatti macOS essenziali). Un volume APFS è una «partizione» del caso con offset sintetico (vedi *Mac con APFS*).
- **Sblocco dei volumi FileVault** con password o chiave di ripristino, dalla preparazione o dal caso già aperto;
  la chiave resta solo in memoria. Avviso nel pannello del caso se un volume cifrato non è sbloccato nella sessione.
- Preparazione: un caso fermato per «VOLUME CIFRATO» si può ripreparare con la chiave (prima rifiutava: «esiste già»).
- Invariato: tutto il resto (nessun cambiamento per NTFS, FAT, ext, HFS+). Limiti dichiarati nel README.

## 2.12.0

**Cache modificabile e casi dove vuoi**:
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

## 2.11.0

**Dati del caso, volumi cifrati nell'albero, pulsante della vista ad albero**:
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

## 2.10.1

**Ordinamento e menu dei valori nelle colonne** (programma e report portatile):
- **clic sull'intestazione** di una colonna: ordina in modo crescente (A→Z, dal più piccolo, dal più vecchio),
  secondo clic decrescente, terzo clic torna all'ordine normale; la freccia ▲/▼ mostra la colonna ordinata.
  Nell'esplora file le cartelle restano sempre in cima. Nel programma si ordina l'intero elenco (non solo la
  pagina visibile) e l'ordine vale anche per selezione ed esportazioni;
- **▾ accanto al filtro delle colonne di testo**: elenco dei valori presenti con il numero di righe, come in
  Excel: ricerca, «Seleziona tutti», spunte, OK / Azzera colonna / Annulla. L'elenco tiene conto degli altri
  filtri attivi ma non di quello della colonna stessa e mostra i 300 valori più frequenti (per gli altri si
  usa il campo di testo). Il pulsante ▾ si colora quando ci sono valori scelti;
- il menu contiene anche i comandi di ordinamento della colonna.

## 2.10.0

**Spazio su disco**: un E01 da 40 GB non genera più un caso da 1 TB. Prima, il
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

## 2.9.1

Scheda *Testo* dell'anteprima: mostra il testo intero (prima era tagliato a circa
12.000 caratteri con la scritta «troncato», perché usava il limite pensato per la memoria del modello).
L'agente legge i documenti lunghi **a porzioni**: `read_file_text` e `read_carved` hanno il parametro
`start` e, quando c'è altro testo, lo dicono in fondo («altri N caratteri… richiama con start=…»); le
istruzioni all'agente gli dicono di proseguire invece di fermarsi al limite. Il testo di PDF e OCR ha gli
stessi ritorni a capo su Mac e Windows (prima su Windows aveva `\r\n`, quindi più caratteri). Il testo
già salvato nella cache dei casi aperti con la 2.9 si rigenera da solo alla prima apertura.

## 2.9

Indice del testo senza tagli silenziosi: i testi lunghi si indicizzano per intero a
blocchi (non solo i primi 200.000 caratteri), i PDF si leggono oltre le 500 pagine, i file di testo e i
PDF molto grandi si leggono in flusso o a blocchi; ogni file non indicizzato o parziale è elencato in
`non_indicizzati.csv` con il motivo, segnalato nei risultati di ricerca, nel riepilogo e nel report;
controllo di coerenza a fine indicizzazione; nuovo strumento `list_not_indexed` per l'agente. I casi
preparati con versioni precedenti restano utilizzabili: per avere i blocchi e l'elenco rifare
*Testo dei documenti e metadati*. L'indicizzazione può richiedere più tempo sui dischi con molti file grandi.

## 2.8

Windows: corretta l'estrazione del testo dei PDF (e dei metadati dallo strumento
esterno dell'agente), che prima non produceva testo. I casi analizzati con la 2.7 su Windows vanno
ripreparati per indicizzare i PDF.
