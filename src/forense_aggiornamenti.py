# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (3.0.1): avviso di nuove versioni.

Nulla si aggiorna da solo: si legge soltanto quale è l'ultima versione pubblicata su GitHub e, se è più nuova di questa,
la pagina lo dice; scaricare e installare resta una scelta dell'analista, dal browser.
- Una richiesta HTTPS all'API delle release di GitHub (più, se c'è, il file SHA256SUMS.txt della release): non si manda
  nessun dato dei casi; GitHub vede l'indirizzo IP e la versione del programma (User-Agent).
- Solo senza un caso aperto (lo controlla il server con `senza_caso`), mai nel registro di un caso.
- Impostazione `aggiornamenti` in impostazioni.json: modo «mano» (predefinito: solo con «Controlla ora»), «avvio» (alla
  pagina iniziale, al massimo una volta al giorno) o «mai»; data ed esito dell'ultimo controllo, versione saltata.
- Si scartano bozze e versioni in prova; il testo delle note è solo testo (la pagina lo mostra senza HTML).
Solo libreria standard (più certifi, se c'è, per i certificati)."""
import datetime as dt
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

from forense_lingua import tr

REPO = "silvexe/RepertIA"
PAGINA = f"https://github.com/{REPO}/releases"
# REPERTIA_AGGIORNAMENTI_URL serve solo al collaudo (finto server locale)
URL = os.environ.get("REPERTIA_AGGIORNAMENTI_URL") or f"https://api.github.com/repos/{REPO}/releases/latest"
MODI = ("mano", "avvio", "mai")
GIORNO_S = 24 * 3600
MAX_JSON = 1 << 20
MAX_SUMS = 64 << 10
NOTE_MAX = 1500
TAG_RE = re.compile(r"^v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})$")
SICUREZZA_RE = re.compile(r"\[(sicurezza|security)\]", re.I)


def versione(s):
    """«v3.0.1» o «3.0.1» → (3, 0, 1); None se il formato non è quello delle release di RepertIA."""
    m = TAG_RE.match(str(s or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


def pacchetto_sistema():
    """Nome (senza versione) del pacchetto adatto a questo computer."""
    if sys.platform == "darwin":
        return "Mac.zip"
    if os.name == "nt":
        return "Setup.exe"
    return "Linux.tar.gz"


def _ctx():
    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx.load_verify_locations(certifi.where())
    except Exception:
        pass
    return ctx


def _leggi(url, massimo, versione_app):
    u = urllib.parse.urlparse(url)
    locale = u.hostname in ("127.0.0.1", "localhost") and "REPERTIA_AGGIORNAMENTI_URL" in os.environ
    if u.scheme != "https" and not locale:
        raise ValueError(tr("indirizzo non sicuro"))
    req = urllib.request.Request(url, headers={"User-Agent": f"RepertIA/{versione_app}",
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=10, context=None if locale else _ctx()) as r:
        dati = r.read(massimo + 1)
    if len(dati) > massimo:
        raise ValueError(tr("risposta troppo grande"))
    return dati


def _url_github(url):
    """Solo collegamenti alla pagina del progetto su GitHub (le note non scelgono dove mandare l'analista)."""
    u = urllib.parse.urlparse(str(url or ""))
    return u.scheme == "https" and u.hostname == "github.com" and u.path.startswith(f"/{REPO}/")


def controlla(versione_app):
    """Ultima release pubblicata. Esito: «nuova», «aggiornato» o «errore» (con `motivo`)."""
    ora = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    base = {"controllato_il": ora, "attuale": versione_app, "pagina": PAGINA}
    try:
        rel = json.loads(_leggi(URL, MAX_JSON, versione_app))
    except urllib.error.HTTPError as e:
        return {**base, "esito": "errore", "motivo": tr("GitHub ha risposto {c}").format(c=e.code)}
    except (urllib.error.URLError, OSError) as e:
        motivo = getattr(e, "reason", e)
        return {**base, "esito": "errore", "motivo": tr("nessuna connessione a GitHub ({m})").format(m=motivo)}
    except ValueError as e:
        return {**base, "esito": "errore", "motivo": tr("risposta non valida ({m})").format(m=e)}
    if not isinstance(rel, dict) or rel.get("draft") or rel.get("prerelease") or not versione(rel.get("tag_name")):
        return {**base, "esito": "errore", "motivo": tr("risposta non valida (nessuna versione pubblicata riconosciuta)")}
    nuova, mia = versione(rel["tag_name"]), versione(versione_app)
    v = ".".join(map(str, nuova))
    note = str(rel.get("body") or "").replace("\r\n", "\n").strip()
    out = {**base, "versione": v, "data": str(rel.get("published_at") or "")[:10],
           "esito": "nuova" if mia is None or nuova > mia else "aggiornato",
           "note": note[:NOTE_MAX] + ("…" if len(note) > NOTE_MAX else ""),
           "sicurezza": bool(SICUREZZA_RE.search(note)),
           "url": rel.get("html_url") if _url_github(rel.get("html_url")) else PAGINA}
    if out["esito"] != "nuova":
        return out
    assets = [a for a in rel.get("assets") or [] if isinstance(a, dict)]
    nome = f"RepertIA-{v}-{pacchetto_sistema()}"
    pk = next((a for a in assets if a.get("name") == nome), None)
    if pk:
        out["pacchetto"] = nome
        out["dimensione"] = pk.get("size")
    sums = next((a for a in assets if a.get("name") == "SHA256SUMS.txt"), None)
    if pk and sums and _url_github(sums.get("browser_download_url")):
        try:
            testo = _leggi(sums["browser_download_url"], MAX_SUMS, versione_app).decode("utf-8", "replace")
            for riga in testo.splitlines():
                m = re.match(r"^([0-9a-fA-F]{64})\s+\*?(.+)$", riga.strip())
                if m and m.group(2).strip() == nome:
                    out["sha256"] = m.group(1).lower()
        except Exception:
            pass
    return out


# ---------------------------------------------------------------- impostazioni (dentro impostazioni.json)

def stato(st):
    a = st.get("aggiornamenti")
    a = dict(a) if isinstance(a, dict) else {}
    if a.get("modo") not in MODI:
        a["modo"] = "mano"
    return a


def da_controllare_all_avvio(a, adesso=None):
    """Controllo automatico: solo in modo «avvio» e al massimo una volta al giorno."""
    if a.get("modo") != "avvio":
        return False
    try:
        ultimo = dt.datetime.fromisoformat(a.get("ultimo", {}).get("controllato_il"))
    except (TypeError, ValueError, AttributeError):
        return True
    adesso = adesso or dt.datetime.now(dt.timezone.utc)
    return (adesso - ultimo).total_seconds() >= GIORNO_S


def da_mostrare(a, adesso=None):
    """L'avviso nella pagina iniziale: c'è una versione nuova, non saltata, non rimandata."""
    u = a.get("ultimo") or {}
    if a.get("modo") == "mai" or u.get("esito") != "nuova" or u.get("versione") == a.get("saltata"):
        return False
    try:
        fino = dt.datetime.fromisoformat(a.get("rimanda_fino"))
    except (TypeError, ValueError):
        return True
    return (adesso or dt.datetime.now(dt.timezone.utc)) >= fino
