# Collaudo

*English: [README.en.md](README.en.md).*

`atteso.json` (immagini costruite per il collaudo) e `atteso_dftt.json` (immagini pubbliche DFTT con risultati
pubblicati da terzi) contengono i valori attesi. Le immagini stanno nell'archivio **RepertIA-collaudo.zip** tra le
Releases (le immagini non vanno nel repository: sono grandi e alcune hanno licenze proprie, vedi
THIRD_PARTY_LICENSES.md e il file `LEGGIMI.txt` dentro l'archivio).

## Smartphone (dalla 2.20)

`atteso_smartphone.json` e la cartella `smartphone/` dello zip: due estrazioni costruite con `tools/collaudo_mobile.py`
dagli estratti delle immagini pubbliche iOS 15 (Josh Hickman) e Android 15 («anne_a15») usati nei test di iLEAPP e ALEAPP
(licenza MIT), più un WhatsApp Android e un Google Photos costruiti con contenuto noto (allegati trovati per percorso, per
hash, con la sola miniatura e assenti; file citati trovati per percorso, per nome e dimensione e assenti). I valori attesi
delle chat sono i risultati pubblicati da iLEAPP e ALEAPP; per i controlli su iLEAPP/ALEAPP servono gli strumenti inclusi
nel pacchetto. `tools/collaudo_mobile.py --aggiorna-android <cartella>` ricostruisce WhatsApp e Google Photos
nell'estrazione Android esistente senza riscaricare i dati di prova di ALEAPP. `--portachiavi <cartella> <cartella iLEAPP>`
aggiunge l'estrazione iOS minima `ios_portachiavi.zip` e `portachiavi_finto.plist`: portachiavi **finti** (nessun dato
reale), uno cifrato nel formato di Cellebrite dentro l'estrazione e uno decifrato da passare a iLEAPP con `--keychain`.
`--file-citati <cartella>` aggiunge l'estrazione iOS **finta** `ios_file_citati.zip` (IMG_0059.PNG nelle stesse posizioni
del caso pubblico iOS 13.4.1 di Hickman, due IMG_0100.JPG diverse in cartelle diverse, due `verbale.pdf` con lo stesso
percorso finale) con le righe da provare nello stile di iLEAPP e l'esito atteso dei file citati: cartella + nome = un
solo file trovato con certezza, solo nome con due omonimi = probabile con due candidati, hash verificato, copie, assente.
`--sysdiagnose <cartella>` aggiunge due archivi nella forma di un **sysdiagnose** di iOS costruiti con i ritagli pubblici dei
test di iLEAPP v2026.4.5 (scaricati da GitHub e controllati con lo SHA-256: `ps.txt` reale di iOS 16, BatteryUI e
ManagedSettings di iOS 26.6 con gli identificativi sostituiti dagli autori; non sono sysdiagnose completi) e la prova 25:
SHA-256 nel registro, nessuna copia nel caso, data e dispositivo dal nome, righe nel gruppo «Sysdiagnose», processi di
`ps.txt` contati senza iLEAPP. Ogni prova controlla anche la **verifica del registro a posteriori** (`forense_registro.py`):
catena integra e hash finale del report trovato; sulla prova del disco con manomissione una riga modificata, una tolta in
mezzo, righe tolte alla fine senza e con l'hash finale; sulle prove con chat esportate un file esportato modificato.

## Eseguirlo

1. Estrai `RepertIA-collaudo.zip` sul Desktop (si crea la cartella `RepertIA-collaudo`).
2. Mac: doppio clic su *Collaudo RepertIA.command* accanto all'app. Windows: menu Start › RepertIA › Collaudo. Linux: `./collaudo.sh` nella cartella di RepertIA.
   Dai sorgenti: `python3 src/forense_collaudo.py <cartella RepertIA-collaudo> <cartella di uscita>`.
3. Il rapporto `collaudo_<data>.md` riporta l'esito di ogni controllo, le versioni degli strumenti e l'impronta del
   programma. Conservalo; **non pubblicare** i rapporti fatti sul tuo computer se contengono percorsi personali.

## Aggiungere prove

Per un'immagine pubblica con risultati noti (es. NIST CFReDS) crea `atteso_<nome>.json` sul modello di
`atteso_dftt.json`, con i valori trascritti dalla fonte e il riferimento alla pagina. I valori attesi devono venire
dalla fonte, non da RepertIA.

## Lingua

Il collaudo prepara i casi di prova nella lingua delle impostazioni di RepertIA; da terminale si sceglie con
`--lingua it` o `--lingua en` (`python3 src/forense_collaudo.py <cartella> --lingua en`). I valori attesi restano in
italiano: in inglese il collaudo riconosce anche la forma tradotta dei titoli degli artefatti.

## Prova della navigazione (fuori dal collaudo)

Le prove dell'interfaccia nel browser non sono nel collaudo (serve Playwright, che non è nei pacchetti). Da una copia
dei sorgenti, con `pip install playwright` e `python -m playwright install chromium`:
`python3 tools/prova_navigazione.py --casi <cartella con copie dei casi del collaudo> [--browser webkit] [--lingua en]`.
Prova Ricerca, Indietro/Avanti e briciole (vedi VALIDAZIONE.md, paragrafo (7)); le ricerche fatte restano nei casi:
usare copie, mai casi reali.
