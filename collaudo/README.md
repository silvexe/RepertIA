# Collaudo

`atteso.json` (immagini costruite per il collaudo) e `atteso_dftt.json` (immagini pubbliche DFTT con risultati
pubblicati da terzi) contengono i valori attesi. Le immagini stanno nell'archivio **RepertIA-collaudo.zip** tra le
Releases (le immagini non vanno nel repository: sono grandi e alcune hanno licenze proprie, vedi
THIRD_PARTY_LICENSES.md).

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
