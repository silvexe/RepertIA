# RepertIA alla prova di due smartphone documentati: Android 14 e iOS 17

*RepertIA 3.0.2 — novembre 2026 · English: [smartphone-hickman.md](smartphone-hickman.md) · Altre prove: [indice](README.md)*

## In breve

Abbiamo analizzato con RepertIA le immagini pubbliche di due telefoni preparate da **Joshua Hickman** per la comunità
forense:

- un **Google Pixel 7a con Android 14**;
- un **iPhone 11 con iOS 17.3**.

Hickman ha usato i telefoni come una persona qualsiasi e ha annotato **ogni azione con data e ora**: messaggi inviati e
ricevuti, chiamate, siti visitati, reti Wi-Fi, dispositivi Bluetooth. Ha pubblicato queste annotazioni insieme alle
immagini. A ogni estrazione è allegato anche il riepilogo dell'acquisizione, con l'impronta SHA-256 e i dati del telefono.

Abbiamo controllato una per una **264 azioni documentate**.

- **RepertIA ritrova tutte le 262 azioni presenti nei dati dei telefoni.**
- **In 257 casi** testo, verso (inviato o ricevuto) e ora coincidono con il documento.
- **In 5 casi è il documento a sbagliare un dettaglio,** e RepertIA riporta quello giusto, verificato sui database
  originali. Ci sono due versi invertiti: la stessa risposta è annotata come «inviata» da tutte e due le parti. C'è un'ora
  annotata dieci minuti prima, e ci sono due chiamate con il numero del telefono stesso.
- **2 chiamate annotate nel documento non sono nel registro del telefono:** nessuno strumento può ritrovarle.
- **Concordanza tra i due telefoni.** Hickman ha fatto parlare i due telefoni tra loro su WhatsApp, Signal e Telegram. Su
  47 messaggi presenti su entrambi, RepertIA dà sul Pixel e sull'iPhone **la stessa ora, con uno scarto massimo di un
  secondo**.
- **Identità dei telefoni:** l'impronta SHA-256 coincide con il riepilogo allegato, e così versione, patch e build. Su
  Android anche l'elenco delle app installate coincide app per app (369 su 369).
- **Nessun risultato inventato.** I messaggi che Hickman ha cancellato e che non esistono più nei file del telefono
  (verificato byte per byte) non vengono presentati come recuperati.
- **Un limite trovato e corretto con questa prova:** un iMessage cancellato da meno di 30 giorni resta in «Eliminati di
  recente». RepertIA ne mostrava il testo senza dire che era stato cancellato. Dalla 3.0.2 lo segnala come «cancellato
  dall'utente», con la data della cancellazione (vedi sotto).

## Le fonti di riferimento

Tutti i riferimenti vengono dai documenti distribuiti **insieme alle immagini**. Chiunque scarichi le immagini li ha:

| Telefono | Documentazione di creazione (Hickman) | Riepilogo dell'acquisizione allegato all'estrazione |
|---|---|---|
| Pixel 7a, Android 14 | `Android14-ImageCreation.pdf` | `EXTRACTION_FFS.ufd`, `SummaryReport.pdf`, `InstalledAppsList.txt` |
| iPhone 11, iOS 17.3 | `iOS17-ImageCreation.pdf` | `EXTRACTION_FFS.ufd`, `SummaryReport.pdf` |

Le ore del documento sono locali: costa est degli Stati Uniti, con l'ora legale e con una settimana in Europa per l'iPhone,
come indicato nel documento stesso. Le abbiamo convertite in UTC.

## Come abbiamo controllato

- **Un caso nuovo per ogni telefono**, creato con RepertIA 3.0.2 dallo zip dell'estrazione, con la SHA-256 e l'analisi
  degli artefatti attiva (ALEAPP 2026.4.5 su Android, iLEAPP su iOS).
- **Confronto con uno script.** Ogni azione è stata cercata con uno script, senza scelte a mano. Il messaggio deve avere lo
  stesso verso e un frammento del testo del documento, entro due minuti dall'ora annotata. Le ore del documento sono
  scritte a mano e al minuto.
- **Verifica alla fonte.** Quando un'azione non si trova, si apre il database originale del telefono, estratto dallo
  stesso zip, per capire se il dato c'è davvero.

## Risultati

| Cosa si controlla | Android: azioni | **Android: trovate** | iOS: azioni | **iOS: trovate** |
|---|---|---|---|---|
| Messaggi (RCS/SMS/MMS, iMessage) | 17 | **17** | 22 | **22** |
| WhatsApp: messaggi | 18 | **18** | 35 | **34** ¹ |
| WhatsApp: chiamate audio e video | 4 | **4** | 8 | **8** |
| Signal: messaggi | 16 | **16** | 35 | **34** ² |
| Telegram: messaggi | 19 | **18** ³ | 37 | **37** |
| Chiamate (app Telefono) | 5 | **3** ⁴ | 6 | **4** ⁵ |
| Navigazione (Chrome, Safari) | 7 | **7** | 4 | **4** ⁶ |
| Reti Wi-Fi | 10 | **10** | 14 | **14** |
| Dispositivi Bluetooth associati | 4 | **4** | 3 | **3** ⁷ |
| **Totale** | **100** | **97** | **164** | **160** |

Su iOS, in più, i **messaggi modificati** dopo l'invio (4 su 4) compaiono con il testo finale. Su entrambi i telefoni le
schede in **navigazione privata** e in incognito, correttamente, non lasciano tracce nella cronologia.

*Note sulle azioni non trovate (le verifiche sono alla sezione successiva):*
1. WhatsApp iOS, 30/01 alle 15:11: verso indicato al contrario nel documento.
2. Signal iOS, 28/07/2023: ora annotata 12:13 invece di 12:23.
3. Telegram Android, 31/01 alle 12:15: verso indicato al contrario nel documento.
4. Chiamate Android del 1° febbraio e del 4 giugno: non sono nel registro del telefono.
5. Chiamate iOS del 27 luglio: il documento indica il numero dell'iPhone stesso.
6. Safari: confronto sull'ora, perché la cronologia era stata svuotata (vedi sotto).
7. Fitbit: confronto sul nome, perché iOS non registra l'indirizzo MAC dei dispositivi Bluetooth LE.

| Identità del telefono | Android: riferimento | **RepertIA** | iOS: riferimento | **RepertIA** |
|---|---|---|---|---|
| SHA-256 dello zip | `a9a2d881…0a8464a` | **uguale** | `7e603d01…b9014fa` | **uguale** |
| Versione | Android 14 | **14** | iOS 17.3 | **17.3** |
| Build | UQ1A.240105.004 | **uguale** | 21D50 | **uguale** |
| Patch | 2024-01-05 | **2024-01-05** | — | — |
| App installate | 369 | **369, stesso elenco** | non indicato | — |
| IMEI | indicato | non mostrato | non indicato | — |

## Le azioni non trovate, verificate alla fonte

- **Il verso di due messaggi.** Il documento Android segna come inviato il «I'll send a picture» delle 12:15 su
  Telegram. Il documento iOS segna come inviato lo stesso messaggio dall'iPhone, e nel database di Telegram il mittente
  è l'iPhone. Lo stesso succede per «It's gone» su WhatsApp alle 15:11: per il Pixel è inviato, per l'iPhone è ricevuto.
  In tutti e due i casi RepertIA riporta il verso registrato dall'app.
- **Un'ora sbagliata.** Su Signal, nel documento iOS, «Got it. I'll audio call you in a minute» è annotato alle 12:13, in
  mezzo ad azioni delle 12:22 e delle 12:24. Nel database è delle 12:23.
- **Chiamate Android del 1° febbraio e del 4 giugno.** Nel registro delle chiamate del telefono (`calllog.db`, 2655 voci)
  non ci sono. Per il primo numero c'è solo una chiamata del 29 gennaio, che RepertIA mostra.
- **Chiamate iOS del 27 luglio.** Il documento indica come numero quello dell'iPhone stesso. Nel registro c'è il numero
  del Pixel, che secondo il documento Android alle 17:40 chiama proprio l'iPhone. RepertIA mostra le
  due chiamate con l'ora e il verso giusti.

## Messaggi cancellati

Hickman ha cancellato su ciascun telefono alcuni messaggi, in Messaggi, WhatsApp, Signal e Telegram. Abbiamo applicato
ai database originali il recupero dei record cancellati di RepertIA, quello del pulsante «Record cancellati». Poi abbiamo
cercato i testi **byte per byte** in tutti i file dei database, compresi i file WAL, tollerando anche gli spazi doppi.

- **Testi spariti** (Android: Messaggi, WhatsApp e Telegram; iOS: tre messaggi di Messaggi e uno di WhatsApp). Non ci
  sono più in nessun file: nessuno strumento potrebbe recuperarli da queste estrazioni. **RepertIA non li inventa.**
- **Un iMessage in «Eliminati di recente»** (iOS, 28 luglio, ore 11:07). iOS conserva per 30 giorni i messaggi
  cancellati, e questo era stato cancellato poco prima dell'acquisizione. Con questa prova abbiamo visto che RepertIA
  ne mostrava il testo nella conversazione giusta, ma **senza segnalarlo come cancellato**. L'abbiamo corretto. Ora
  il messaggio compare come **«cancellato dall'utente il 28/07/2024 alle 11:08»**, nella vista chat, nel filtro dei
  cancellati e nel report. L'ora è quella che Hickman annota per la cancellazione, letta dalla tabella
  `chat_recoverable_message_join` di `sms.db`.
- **Signal e Telegram su iOS:** i database delle due app sono cifrati, quindi il controllo byte per byte non è
  possibile.

## Altre osservazioni

- **Safari (iOS).** La cronologia di Safari non contiene più le visite documentate: `History.db` ha una sola visita, del
  28 luglio. RepertIA mostra però, dagli artefatti Biome di iOS, le voci di cronologia Safari **cancellate**, alle stesse
  ore delle visite documentate (18:13, 18:15, 19:37, 19:38). Il confronto è quindi sull'ora; l'indirizzo non è più nei
  dati.
- **Righe di iLEAPP.** Su questo iPhone iLEAPP produce oltre 21 milioni di righe. RepertIA ne importa al massimo 2 milioni,
  e lo dice nel registro. Abbiamo controllato riga per riga che **tutti gli artefatti sono importati per intero**,
  tranne gli FSEvents, i registri di basso livello delle modifiche al file system. Questi restano consultabili per intero
  nel rapporto di iLEAPP allegato al caso.

## Piccole differenze nei documenti

I documenti sono scritti a mano e in alcuni punti riassumono o sbagliano di poco. Lo diciamo per chi vuole rifare la
prova.

- **Testi riassunti:** il documento scrive «a document», «I deleted it», «Hopefully, that continues». Nei telefoni ci
  sono «the document», «I deleted.», «Hopefully that continues».
- **Nomi delle reti Wi-Fi:** nei documenti «DNCR-Acquarium_Visitor», «MarriotBonvoy», «MyWay Guest». Le reti salvate
  sono «DNCR-Aquarium_Visitor», «MarriottBonvoy», «My Way Tavern Guest».
- **Versi, ore e numeri** indicati sopra.

## Limiti

- **Copertura:** abbiamo controllato le app più usate nelle indagini (messaggistica, chiamate, navigazione, reti,
  Bluetooth). I documenti descrivono più di 50 app per telefono: le altre restano da controllare in una prova successiva.
- **IMEI del Pixel:** RepertIA non lo mostra, e il numero non compare nei dati letti dall'estrazione. Il riepilogo
  dell'acquisizione lo ha letto dal telefono acceso.
- **Tolleranza sull'ora:** è di due minuti. Delle 230 azioni trovate con un'ora (83 Android, 147 iOS), 224 cadono dentro il minuto annotato.
  Le altre sei sono a meno di un minuto e mezzo:
  - due chiamate iOS iniziate poco prima del minuto annotato;
  - un messaggio Telegram;
  - due tracce Biome di Safari;
  - mlb.com su Chrome. Qui la cronologia conserva l'ultima visita (21:16, quando Hickman è tornato sulla pagina), non
    la prima delle 21:14.

## Come rifare la prova

1. Scaricare le immagini «Android 14» e «iOS 17» dal sito di Joshua Hickman (thebinaryhick.blog), con i documenti
   allegati.
2. In RepertIA: **Nuova analisi → Smartphone**, scegliere `EXTRACTION_FFS.zip`, con SHA-256 e ALEAPP/iLEAPP.
3. Lanciare gli script di confronto di [tools/prove](../../tools/prove/README.md), tutti in sola lettura:
   - `hickman_riferimenti_android14.py` e `hickman_riferimenti_ios17.py`: i riferimenti presi dai documenti;
   - `hickman_confronto.py <caso> <riferimenti> <elenco app o -> <uscita>`: il confronto;
   - `hickman_cancellati.py`: il recupero dei record cancellati sui database originali.

   Negli script i numeri di telefono sono ridotti alle ultime 4 cifre e gli indirizzi Bluetooth agli ultimi 3 byte,
   per non ripubblicare identificativi.

## Fonti

- Joshua Hickman, *Android 14 Image* e *iOS 17 Image*, con `Android14-ImageCreation.pdf` e `iOS17-ImageCreation.pdf`:
  https://thebinaryhick.blog
- Riepiloghi dell'acquisizione allegati alle estrazioni: `EXTRACTION_FFS.ufd`, `SummaryReport.pdf`,
  `InstalledAppsList.txt`.

*Segnalazioni: [issue del repository](https://github.com/silvexe/RepertIA/issues).*
