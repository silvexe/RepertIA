# Contributing to RepertIA

*Italiano più sotto.*

Thank you for your interest. RepertIA is a forensic tool: every change must be **verifiable** and must never put the
integrity of the images or the confidentiality of the data at risk.

## Rules

1. **Never use data from real cases** in issues, pull requests, tests or screenshots: no forensic images, extracts,
   names of people, accounts, computers, paths or case numbers. Use public images (DFTT, NIST CFReDS, dfvfs test data)
   or purpose-built images.
2. **The forensic image is never modified**: every read goes through read-only tools; whatever is extracted goes to
   `<case>/estratti` or `export` with its hashes.
3. **Every functional change has a test**: a check in the acceptance test (`collaudo/atteso*.json` and
   `src/forense_collaudo.py`) or at least a test described in the pull request with its result.
4. **Every change is described in CHANGELOG.md** (and in CHANGELOG.en.md): what changes, how it was tested, what was
   NOT tested.
5. The source texts of the program are in Italian and act as keys of the English dictionary `src/lingua_en.json`: a new
   or changed text needs its translation (`python3 tools/lingua_controlla.py`). Code comments are in Italian. The Italian
   documents are the originals; keep the English translations aligned.
6. Before submitting: `python3 tools/controlla_pubblicazione.py .` must not find sensitive data.

## License of contributions (DCO)

Contributions are accepted under the project's license (GPL-3.0-or-later). Every commit must be signed off with
`git commit -s`, which adds the line `Signed-off-by: Name Surname <email>` and means you agree to the
[Developer Certificate of Origin 1.1](https://developercertificate.org/): you state that you have the right to submit
the code under this license.

## How to propose a change

1. Open an issue describing the problem or the feature.
2. Create a branch, make the change with its test, update the CHANGELOG.
3. Run the acceptance test and attach the result to the pull request (the report only, never case data).

---

# Contribuire a RepertIA

Grazie dell'interesse. RepertIA è uno strumento forense: ogni modifica deve essere **verificabile** e non deve mai
mettere a rischio l'integrità delle copie o la riservatezza dei dati.

## Regole

1. **Mai dati di casi reali** in issue, pull request, test o schermate: niente copie forensi, estratti, nomi di persone,
   account, computer, percorsi o numeri di procedimento. Usa immagini pubbliche (DFTT, NIST CFReDS, dati di prova di
   dfvfs) o immagini costruite apposta.
2. **La copia forense non si modifica mai**: ogni lettura passa da strumenti in sola lettura; quello che si estrae va in
   `<caso>/estratti` o `export` con gli hash.
3. **Ogni modifica funzionale ha una prova**: un controllo nel collaudo (`collaudo/atteso*.json` e
   `src/forense_collaudo.py`) o almeno una prova descritta nella pull request con l'esito.
4. **Ogni modifica è descritta in CHANGELOG.md** (e in CHANGELOG.en.md): cosa cambia, come è stata provata, cosa NON è
   stato provato.
5. I testi del programma sono in italiano nei sorgenti e fanno da chiave del dizionario inglese `src/lingua_en.json`:
   un testo nuovo o cambiato richiede la traduzione (`python3 tools/lingua_controlla.py`). Commenti nel codice in
   italiano. La documentazione italiana è l'originale; le traduzioni inglesi vanno tenute allineate.
6. Prima di proporre: `python3 tools/controlla_pubblicazione.py .` non deve trovare dati sensibili.

## Licenza dei contributi (DCO)

I contributi sono accettati con la stessa licenza del progetto (GPL-3.0-or-later). Ogni commit va firmato con
`git commit -s`, che aggiunge la riga `Signed-off-by: Nome Cognome <email>` e vale come adesione al
[Developer Certificate of Origin 1.1](https://developercertificate.org/): dichiari di avere il diritto di proporre il
codice con questa licenza.

## Come proporre una modifica

1. Apri una issue che descrive il problema o la funzione.
2. Crea un ramo, fai la modifica con la sua prova, aggiorna il CHANGELOG.
3. Esegui il collaudo e allega l'esito alla pull request (solo il rapporto, mai dati di casi).
