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
4. **Ogni modifica è descritta in CHANGELOG.md**: cosa cambia, come è stata provata, cosa NON è stato provato.
5. Interfaccia e documentazione in italiano; commenti nel codice in italiano.
6. Prima di proporre: `python3 tools/controlla_pubblicazione.py .` non deve trovare dati sensibili.

## Licenza dei contributi (DCO)

I contributi sono accettati con la stessa licenza del progetto (GPL-3.0-or-later). Ogni commit va firmato con
`git commit -s`, che aggiunge la riga `Signed-off-by: Nome Cognome <email>` e vale come adesione al
[Developer Certificate of Origin 1.1](https://developercertificate.org/): dichiari di avere il diritto di proporre il
codice con questa licenza.

## Come proporre una modifica

1. Apri una issue che descrive il problema o la funzione.
2. Crea un ramo, fai la modifica con la sua prova, aggiorna CHANGELOG.md.
3. Esegui il collaudo e allega l'esito alla pull request (solo il rapporto, mai dati di casi).
