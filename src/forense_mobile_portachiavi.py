"""RepertIA (2.20) – portachiavi (keychain) di iOS per iLEAPP.

Il portachiavi di un iPhone si acquisisce a parte rispetto all'estrazione del file system (es. GrayKey): alcune app
(Signal, Session, SimpleX…) tengono lì la chiave del loro database. RepertIA non lo legge e non lo decifra: ne
calcola lo SHA-256, lo registra nel registro a catena, NON lo copia nel caso (si usa dal suo percorso, come
l'estrazione) e lo passa a iLEAPP con --keychain. La decifratura e la lettura sono di iLEAPP (scripts/ios_keychain.py
e scripts/artifacts/keychain.py).

Gli artefatti che ne derivano (es. «Keychain Wifi Credentials») contengono valori segreti (password, chiavi, token):
all'importazione si sostituiscono con un segnaposto e il valore va nella tabella `leapp_segreti`; la pagina li mostra
uno per volta su richiesta (registrato), il report portatile li include solo per scelta esplicita, l'agente non li
riceve mai.
"""
import plistlib
import re
from pathlib import Path

from forense_lingua import tr, N_  # noqa: E402

MASK = "••••••"                    # segnaposto dei valori segreti nelle righe importate
# portachiavi che iLEAPP cerca da sé dentro l'estrazione (stesse posizioni di scripts/ios_keychain.py e keychain.py)
IN_ESTRAZIONE = re.compile(r"(^|/)(extra/KeychainDump/backup_keychain_v2\.plist|keychain-backup\.plist)$", re.I)
USO = {"fornito": N_("fornito dall'operatore"), "estrazione": N_("trovato nell'estrazione"), "nessuno": N_("nessuno")}
SCHEMA_SEGRETI = ("CREATE TABLE IF NOT EXISTS leapp_segreti(id INTEGER PRIMARY KEY, art INTEGER, campo TEXT, valore TEXT);"
                  "CREATE INDEX IF NOT EXISTS idx_ls_art ON leapp_segreti(art);")


def formato(path):
    """Formato del plist: «decifrato (genp/inet)», «cifrato (keychainEntries di Cellebrite)», None se non è un portachiavi."""
    try:
        with open(path, "rb") as fh:
            d = plistlib.load(fh)
    except Exception:
        return None, 0
    if not isinstance(d, dict):
        return None, 0
    if isinstance(d.get("genp"), list) or isinstance(d.get("inet"), list):
        return "decifrato", sum(len(d.get(k) or []) for k in ("genp", "inet", "keys") if isinstance(d.get(k), list))
    if isinstance(d.get("keychainEntries"), list):
        return "cifrato", len(d["keychainEntries"])
    return None, 0


def imposta(case, path, say=print):
    """Registra il portachiavi fornito dall'operatore (SHA-256, registro a catena). Il file non si copia."""
    import forense_agent as fa
    p = Path(str(path)).expanduser().resolve()
    if not p.is_file():
        raise ValueError(tr("File del portachiavi non trovato: {p}").format(p=p))
    plat = (case.meta.get("mobile") or {}).get("piattaforma")
    if plat and plat != "ios":
        raise ValueError(tr("Il portachiavi serve solo per gli iPhone (iOS): questa estrazione è {p}.").format(p=plat))
    fmt, n = formato(p)
    if not fmt:
        raise ValueError(tr("Il file non è un portachiavi leggibile da iLEAPP (plist con «genp»/«inet» o «keychainEntries»)."))
    say(tr("Portachiavi: calcolo SHA-256 di {p}…").format(p=p.name))
    sha = fa.sha256_file(p)
    info = {"file": str(p), "nome": p.name, "byte": p.stat().st_size, "sha256": sha, "formato": fmt, "voci": n,
            "ts": fa.now()}
    case.meta["portachiavi"] = info
    case.log("portachiavi", info)
    case.save()
    say(tr("Portachiavi registrato: {nome}, {b} byte, SHA-256 {sha} (non copiato nel caso: si usa dal suo percorso).").format(
        nome=p.name, b=info["byte"], sha=sha))
    return info


def togli(case):
    pc = case.meta.pop("portachiavi", None)
    if pc:
        case.log("portachiavi_tolto", {"file": pc.get("file"), "sha256": pc.get("sha256")})
        case.save()


def args_leapp(case, say=print):
    """Argomenti per iLEAPP: ["--keychain", file] se l'operatore ha fornito un portachiavi ancora uguale a quello
    registrato. Se il file manca o è cambiato non si usa (dichiarato)."""
    import forense_agent as fa
    pc = case.meta.get("portachiavi") or {}
    if not pc.get("file") or (case.meta.get("mobile") or {}).get("piattaforma") != "ios":
        return []
    p = Path(pc["file"])
    if not p.is_file():
        say(tr("Portachiavi non raggiungibile ({p}): iLEAPP userà solo quello eventualmente presente nell'estrazione.").format(p=p))
        case.log("portachiavi_non_usato", {"file": str(p), "motivo": "non raggiungibile"})
        return []
    sha = fa.sha256_file(p)
    if sha != pc.get("sha256"):
        say(tr("ATTENZIONE: il portachiavi {p} è cambiato dopo la registrazione (SHA-256 diverso): non viene usato. "
               "Sceglilo di nuovo nel caso.").format(p=p))
        case.log("portachiavi_non_usato", {"file": str(p), "motivo": "SHA-256 diverso", "registrato": pc.get("sha256"),
                                           "attuale": sha})
        return []
    return ["--keychain", str(p)]


def in_estrazione(case):
    """Portachiavi che l'estrazione contiene (percorsi nell'estrazione)."""
    import forense_mobile as fm
    try:
        m = fm.mx(case)
        try:
            return [r[0] for r in m.execute("SELECT path FROM mobile_files WHERE isdir=0 AND (path LIKE '%backup_keychain_v2.plist' "
                                            "OR path LIKE '%keychain-backup.plist')") if IN_ESTRAZIONE.search(r[0])]
        finally:
            m.close()
    except Exception:
        return []


def esito(case, log_text, usato):
    """Quale portachiavi è stato usato nell'esecuzione di iLEAPP: fornito / trovato nell'estrazione / nessuno, con le
    righe «Keychain: …» del registro di iLEAPP (voci lette o decifrate)."""
    righe = [ln.strip() for ln in (log_text or "").splitlines() if "Keychain:" in ln][:20]
    est = in_estrazione(case)
    pc = case.meta.get("portachiavi") or {}
    if usato:
        out = {"uso": "fornito", "file": pc.get("file"), "sha256": pc.get("sha256")}
    elif est:
        out = {"uso": "estrazione", "file": est[0]}
    else:
        out = {"uso": "nessuno"}
    if est and usato:
        out["anche_nell_estrazione"] = est
    lette = [int(m.group(1)) for ln in righe for m in [re.search(r"(?:read|decrypted) (\d+) entries", ln)] if m]
    if lette:
        out["voci_lette"] = max(lette)
    out["registro_ileapp"] = righe
    return out


def testo_esito(pk):
    """Riga per riepilogo e report: «Portachiavi usato da iLEAPP: …»."""
    if not pk:
        return ""
    u = pk.get("uso")
    s = tr("Portachiavi usato da iLEAPP: {u}").format(u=tr(USO.get(u, u or "")))
    if u in ("fornito", "estrazione") and pk.get("file"):
        s += f" ({pk['file']}" + (f", SHA-256 {pk['sha256']}" if pk.get("sha256") else "") + ")"
    if pk.get("voci_lette"):
        s += "; " + tr("{n} voci lette da iLEAPP").format(n=pk["voci_lette"])
    if pk.get("anche_nell_estrazione"):
        s += "; " + tr("anche nell'estrazione: {p} (usato dagli artefatti del portachiavi di iLEAPP)").format(
            p=", ".join(pk["anche_nell_estrazione"]))
    return s


# ------------------------------------------------------------------------------------------ valori segreti

_regole = None


def regole():
    """Regole dei valori segreti (sezione «segreti» di forense_mobile_leapp_mappa.json)."""
    global _regole
    if _regole is None:
        import json
        m = json.loads((Path(__file__).resolve().parent / "forense_mobile_leapp_mappa.json").read_text(encoding="utf-8"))
        s = m.get("segreti") or {}
        _regole = {"campi": re.compile(s.get("campi") or r"(?!)", re.I),
                   "categorie": {x.lower() for x in s.get("categorie") or []},
                   "campi_portachiavi": re.compile(s.get("campi_portachiavi") or r"(?!)", re.I),
                   "decifrate": set(s.get("app_decifrate_col_portachiavi") or [])}
    return _regole


def campo_segreto(categoria, artefatto, campo):
    """True se il campo di una riga di iLEAPP/ALEAPP contiene un valore segreto da nascondere."""
    r = regole()
    if r["campi"].search(str(campo)):
        return True
    keychain = str(categoria or "").lower() in r["categorie"] or "keychain" in str(artefatto or "").lower()
    return keychain and bool(r["campi_portachiavi"].search(str(campo)))


def nascondi(categoria, artefatto, rec):
    """(rec con i segnaposto, [(campo, valore)…] dei valori nascosti)."""
    seg = [(k, v) for k, v in rec.items() if v not in (None, "") and campo_segreto(categoria, artefatto, k)]
    if not seg:
        return rec, []
    rec = dict(rec)
    for k, _v in seg:
        rec[k] = MASK
    return rec, seg


def ensure_schema(con):
    con.executescript(SCHEMA_SEGRETI)


def segreto(case, con, art_id, campo, mostra_da="interfaccia"):
    """Valore di un campo segreto: si legge solo qui e la lettura va nel registro a catena (senza il valore)."""
    r = con.execute("SELECT valore FROM leapp_segreti WHERE art=? AND campo=?", (int(art_id), str(campo))).fetchone() \
        if con.execute("SELECT name FROM sqlite_master WHERE name='leapp_segreti'").fetchone() else None
    if not r:
        raise ValueError(tr("Valore non disponibile."))
    a = con.execute("SELECT sub, title FROM artifacts WHERE id=?", (int(art_id),)).fetchone()
    case.log("segreto_mostrato", {"artefatto": int(art_id), "voce": a[0] if a else None, "campo": str(campo),
                                  "da": mostra_da})
    return r[0]


def valori_segreti(con):
    """{art_id: {campo: valore}} (solo per il report portatile con la scelta esplicita)."""
    if not con.execute("SELECT name FROM sqlite_master WHERE name='leapp_segreti'").fetchone():
        return {}
    out = {}
    for art, campo, valore in con.execute("SELECT art, campo, valore FROM leapp_segreti"):
        out.setdefault(art, {})[campo] = valore
    return out
