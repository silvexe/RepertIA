# RepertIA e il Regolamento europeo sull'intelligenza artificiale (AI Act)

*English: [AI_ACT.en.md](AI_ACT.en.md).*

> **Non è un parere legale.** Questo documento descrive come è fatto RepertIA e la valutazione dell'autore rispetto al
> Regolamento (UE) 2024/1689 («AI Act»). Chi adotta lo strumento deve fare la propria valutazione, con il proprio
> responsabile della protezione dei dati e il proprio ufficio legale, e controllare eventuali modifiche successive del
> Regolamento e delle norme nazionali.

Versione del programma a cui si riferisce: **2.21.0**.

## 1. Che cosa fa RepertIA e dove c'è l'IA

RepertIA è uno strumento di analisi forense di copie forensi (dischi, chiavette, schede) e di estrazioni di smartphone.
Quasi tutto il lavoro **non usa l'intelligenza artificiale**: elenco dei file anche cancellati, timeline, hash, carving,
artefatti di sistema, chat, ricerche e report sono prodotti da strumenti deterministici (The Sleuth Kit, plaso,
PhotoRec, bulk_extractor, iLEAPP/ALEAPP, lettori propri) e restano tracciati nel registro a catena di hash
(`audit_log.jsonl`).

L'IA compare in tre punti, tutti **facoltativi**:

| Funzione | Componente | Dove gira |
|---|---|---|
| Domande in linguaggio naturale all'agente, che consulta i dati del caso con strumenti in sola lettura e può proporre «reperti» | modello linguistico scelto dall'analista (LM Studio, llama-server, Ollama) | sul computer dell'analista o su un server indicato da lui |
| Trascrizione automatica degli audio | Whisper (whisper.cpp), modello scaricato solo con il consenso dell'analista | sul computer dell'analista, senza rete |
| Testo nelle immagini (OCR) | Tesseract (riconoscimento ottico dei caratteri) | sul computer dell'analista |

Nessun modello linguistico è incluso nei pacchetti. Senza modello tutte le analisi, le ricerche e i report funzionano.

## 2. Scopo previsto

RepertIA è destinato a **supportare l'analista forense**:

- nella ricerca, nell'indicizzazione e nella consultazione dei dati di una copia forense o di un'estrazione;
- come **compito preparatorio**: l'agente aiuta a trovare elementi e a formulare ipotesi, che l'analista verifica sugli
  strumenti forensi e sui dati originali.

**Le conclusioni restano all'analista.** Ogni risposta dell'agente è indicata come «spunto da verificare» e ogni reperto
proposto dall'agente resta «da verificare» finché l'analista non lo conferma (operatore e data nel caso e nel registro).

## 3. Usi esclusi

RepertIA **non è progettato né destinato** a:

- **valutare l'affidabilità delle prove** nel corso di indagini o procedimenti penali;
- **profilare persone fisiche** o valutarne il rischio, la personalità, i comportamenti o la probabilità di commettere
  reati;
- **prendere decisioni automatiche** o sostituire la valutazione dell'analista, del pubblico ministero o del giudice;
- **riconoscimento biometrico** (volti, voci, impronte) o categorizzazione biometrica delle persone;
- interpretare il diritto o applicarlo ai fatti.

Un uso per questi scopi è fuori dallo scopo previsto: chi lo fa se ne assume la responsabilità e, secondo il
Regolamento, può diventare «fornitore» di un sistema ad alto rischio (vedi il punto 6).

## 4. Valutazione del rischio (art. 6, par. 3)

L'Allegato III del Regolamento elenca i settori in cui un sistema di IA può essere ad alto rischio. Quelli vicini
all'uso di RepertIA sono:

- **punto 6 (attività di contrasto)**, in particolare la lettera c): sistemi destinati a essere usati dalle autorità di
  contrasto, o per loro conto, per **valutare l'affidabilità degli elementi probatori** nel corso delle indagini o
  dell'azione penale; e la lettera e): **profilazione** delle persone fisiche durante l'accertamento, le indagini o il
  perseguimento dei reati;
- **punto 8 (amministrazione della giustizia)**, lettera a): sistemi destinati ad assistere un'autorità giudiziaria
  nella **ricerca e nell'interpretazione dei fatti e del diritto** e nell'applicazione della legge ai fatti.

L'art. 6, par. 3 prevede che un sistema dell'Allegato III **non sia considerato ad alto rischio** se non presenta un
rischio significativo di danno per la salute, la sicurezza o i diritti fondamentali, anche perché non influenza in modo
sostanziale l'esito del processo decisionale; questo vale, tra l'altro, quando il sistema esegue un **compito
procedurale limitato** (lettera a) o un **compito preparatorio** a una valutazione rilevante per gli scopi
dell'Allegato III (lettera d). La deroga **non vale mai** se il sistema effettua profilazione di persone fisiche.

Valutazione dell'autore:

- RepertIA **non valuta l'affidabilità delle prove**: estrae, indicizza e mostra i dati con il loro riferimento
  verificabile (offset, inode, percorso, database, tabella, riga, hash); la valutazione resta all'analista;
- l'agente esegue un **compito preparatorio** (ricerca, sintesi, ipotesi) e il suo risultato non entra nel report come
  verificato senza la conferma esplicita dell'analista;
- **non effettua profilazione** e non attribuisce punteggi a persone;
- la trascrizione e l'OCR sono **compiti procedurali limitati** (convertire audio e immagini in testo ricercabile),
  sempre indicati come automatici e da verificare.

Per questi motivi l'autore ritiene che RepertIA, **usato secondo lo scopo previsto**, rientri nell'art. 6, par. 3 e
non sia un sistema ad alto rischio.

Note:

- l'art. 6, par. 4 chiede al fornitore che si avvale della deroga di **documentare la valutazione** prima
  dell'immissione sul mercato o della messa in servizio (questo documento ne fa parte) e di metterla a disposizione delle
  autorità che la chiedono; l'art. 49, par. 2 prevede inoltre la **registrazione nella banca dati dell'UE** per i sistemi
  dell'Allegato III ritenuti non ad alto rischio;
- RepertIA è distribuito con **licenza libera** (GPL-3.0-or-later): l'art. 2, par. 12 esclude dal Regolamento i sistemi
  rilasciati con licenze libere e open source, **salvo** che siano immessi sul mercato o messi in servizio come sistemi
  ad alto rischio o rientrino negli articoli 5 o 50. Gli obblighi di trasparenza dell'art. 50 restano quindi rispettati
  (punto 5); chi adotta lo strumento valuti comunque, con il proprio ufficio legale, come queste disposizioni si
  applicano al proprio caso.

## 5. Obblighi di trasparenza (art. 50) e come sono rispettati

| Obbligo | Come lo rispetta RepertIA |
|---|---|
| **Art. 50, par. 1** – le persone che interagiscono con un sistema di IA devono saperlo | Sotto **ogni risposta** dell'agente c'è l'etichetta fissa «Risposta generata da modello IA (*nome del modello*): spunto da verificare» (anche da riga di comando). Il riquadro del server LLM mostra modello, server e contesto in uso. |
| **Art. 50, par. 2** – i contenuti testuali generati dall'IA devono essere riconoscibili come tali, anche in formato leggibile da una macchina | **Reperti dell'agente**: in `findings.json` ogni reperto ha `"origine": "modello IA"`, il nome del modello, il server e `"stato": "da verificare"`; nei report (Markdown, Word, PDF, report portatile) accanto a ogni reperto c'è l'etichetta «Generato da modello IA (*nome*) – da verificare» oppure «Verificato da *operatore* il *data*»; la frase «Ogni reperto è stato verificato dall'analista» compare **solo** se tutti i reperti sono stati confermati, altrimenti il report dice quanti sono verificati e quanti no; i **metadati** del file Word e del PDF indicano che il documento contiene testo generato da IA (descrizione/oggetto e parola chiave «AI-generated content»). **Trascrizioni** e **OCR**: sempre indicati come «trascrizione automatica» e «testo OCR automatico» nell'interfaccia e nei report. |
| **Server LLM esterno** (riservatezza, non è un obbligo dell'art. 50) | Se l'indirizzo del server non è su questo computer né nella rete locale (IP privati 10.x, 172.16–31.x, 192.168.x, nomi locali), RepertIA mostra un **avviso esplicito prima di usarlo**, lo registra nel caso e nel registro, e il report scrive «server esterno indicato dall'analista: *indirizzo*» invece di «rete interna». |

La conferma di un reperto («Confermo, verificato») registra operatore e data in `findings.json` e nel registro a catena
`audit_log.jsonl` (voce `finding_verificato`). Il collaudo automatico controlla che un reperto creato dall'agente
risulti «da verificare» nel report e verificato dopo la conferma.

## 6. Nota per gli uffici che lo adottano

- Chi usa RepertIA sotto la propria autorità nell'ambito della propria attività professionale è un **«deployer»**
  (utilizzatore) ai sensi dell'art. 3. Deve valutarne l'uso nel proprio contesto, garantire un'adeguata
  **alfabetizzazione in materia di IA** del personale (art. 4) e una **supervisione umana** effettiva: i reperti
  proposti dall'agente vanno verificati sugli strumenti forensi prima di entrare in una relazione.
- In Italia la **legge 23 settembre 2025, n. 132** (disposizioni in materia di intelligenza artificiale) ribadisce che
  nella pubblica amministrazione e nell'attività giudiziaria l'IA è un **supporto** e che le decisioni, la valutazione
  dei fatti e delle prove restano alla persona responsabile. Gli uffici valutino le proprie regole interne di
  conseguenza.
- **Valutazione d'impatto**: le copie forensi contengono di solito dati personali, anche di categorie particolari.
  Valutare la necessità di una valutazione d'impatto sulla protezione dei dati (art. 35 GDPR o, per le autorità di
  polizia e giudiziarie, la normativa di recepimento della direttiva (UE) 2016/680, in Italia il d.lgs. 51/2018) e, se
  si usasse lo strumento per finalità ad alto rischio, la valutazione d'impatto sui diritti fondamentali dell'art. 27.
- **Server LLM**: preferire un modello sul computer dell'analista o su un server della rete interna. Un server esterno
  fa uscire domande e contenuti letti dall'agente: va autorizzato caso per caso.
- **Quando si diventa «fornitore» (art. 25)**: chi **modifica** RepertIA in modo sostanziale, lo distribuisce con il
  **proprio nome o marchio**, oppure lo usa o lo adatta per uno **scopo ad alto rischio** (per esempio valutare
  l'affidabilità delle prove o profilare persone) può assumere gli obblighi del fornitore di un sistema ad alto rischio.

## 7. Riferimenti

- Regolamento (UE) 2024/1689 del Parlamento europeo e del Consiglio, del 13 giugno 2024 (AI Act): art. 2, par. 12;
  art. 3; art. 4; art. 6, par. 3 e 4; art. 25; art. 27; art. 49, par. 2; art. 50; Allegato III, punti 6 e 8.
- Legge 23 settembre 2025, n. 132, disposizioni e deleghe al Governo in materia di intelligenza artificiale.
- Regolamento (UE) 2016/679 (GDPR), art. 35; direttiva (UE) 2016/680 e d.lgs. 18 maggio 2018, n. 51.
- Documentazione di RepertIA: [README](README.it.md), [manuale](src/README.md), [validazione](VALIDAZIONE.md),
  [registro delle modifiche](CHANGELOG.md).
