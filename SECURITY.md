# Security

*Italiano più sotto.*

## Reporting a vulnerability

Do not open a public issue. Use GitHub's private reporting: **Security › Report a vulnerability** tab of this
repository. Describe the problem, the version and how to reproduce it **without attaching data from real cases**.

## In scope

- The local web interface (`src/forense_gui.py`): it listens only on 127.0.0.1 and every request needs a token
  generated at start-up; any way of reaching it from another computer, or from a web page open in the browser without
  the token, is a security issue.
- Reading hostile files inside forensic images (archives, documents, registry, databases): a crafted file must not be
  able to write outside the case folder, run commands or modify the image.
- Handling of passwords and encryption keys: they must stay in memory only, never in case files or logs.
- The language model uses read-only tools only: any way of making it modify files is an issue.

## Supported versions

Issues are fixed in the latest published version.

---

# Sicurezza

## Segnalare una vulnerabilità

Non aprire una issue pubblica. Usa la segnalazione privata di GitHub: scheda **Security › Report a vulnerability**
di questo repository. Descrivi il problema, la versione e come riprodurlo **senza allegare dati di casi reali**.

## Cosa è in ambito

- L'interfaccia web locale (`src/forense_gui.py`): ascolta solo su 127.0.0.1 e ogni richiesta richiede un token
  generato all'avvio; è un problema di sicurezza qualunque modo di raggiungerla da un altro computer o da una pagina web
  aperta nel browser senza il token.
- Lettura di file ostili dentro le copie forensi (archivi, documenti, registro, database): un file costruito apposta
  non deve poter scrivere fuori dalla cartella del caso, eseguire comandi o modificare la copia.
- Gestione di password e chiavi di cifratura: devono restare solo in memoria, mai nei file del caso o nei registri.
- Il modello linguistico usa solo strumenti in sola lettura: è un problema qualunque modo di fargli modificare file.

## Versioni supportate

Si correggono i problemi nell'ultima versione pubblicata.
