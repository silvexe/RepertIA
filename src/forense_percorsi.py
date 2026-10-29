"""RepertIA (2.20) – file citati.

Una riga (artefatto di sistema, riga di iLEAPP/ALEAPP, evento della timeline, allegato di una chat, percorso citato
dall'agente) spesso nomina un file: «File Path /storage/emulated/0/Pictures/…», un LNK che punta a «C:\\Users\\…»,
«media/…jpg» di iLEAPP. Qui si riconoscono quei campi e si cerca il file nella copia forense o nell'estrazione:

1. per percorso, con la tabella di corrispondenza `forense_percorsi.json` (Android /storage/emulated/0 → data/media/0,
   iOS /var/mobile → private/var/mobile, unità e variabili di Windows, macOS…) e confronto sul suffisso del percorso;
2. per hash, se la riga lo fornisce (SHA-256, SHA-1, MD5; anche in base64 come WhatsApp), tra i file con la stessa
   dimensione o nella tabella degli hash del caso;
3. per nome e dimensione, o per solo nome (da verificare, con l'elenco dei candidati).

Il risultato dice sempre come è stato trovato. L'indice dei nomi è quello dell'albero (navigazione.sqlite), con un
indice in più sul nome e sulla dimensione creato qui la prima volta.

Dalla stessa riga (2.20): cartella + nome nello stesso artefatto («Directory» + «Filename») diventano un percorso
completo; i campi che portano allo stesso file diventano UN file citato («indicato nei campi: …»), con un esito in tre
livelli: certo (percorso completo, hash, collegamento registrato da iLEAPP/ALEAPP), probabile (solo nome o nome e
dimensione), assente. Se più campi concordano vale il metodo più forte. Un campo che indica solo una cartella diventa
un collegamento «cartella» nel file citato.
"""
import base64
import binascii
import hashlib
import json
import re
import sqlite3
import threading
import time
import urllib.parse
from pathlib import Path, PurePosixPath

from forense_lingua import tr, N_  # noqa: E402

HERE = Path(__file__).resolve().parent
CONF_FILE = HERE / "forense_percorsi.json"
MAX_CITATI = 8                    # file citati per riga
CAMPI_INTERNI = {"Elemento": N_("Elemento"), "contenuto nel cestino": N_("contenuto nel cestino"), "Fonte": N_("Fonte"),
                 "nome del file": N_("nome del file")}       # nomi dei campi aggiunti qui: tradotti solo nella pagina
NO_TITOLO = {"leapp", "messaggi", "chiamate", "web", "ricerche", "reti", "utenti", "sistema", "usb", "eventi", "permessi",
             "comandi", "uso", "dispositivi", "backup", "avvio"}
MAX_HASH_CAND = 300               # file della stessa dimensione da confrontare per hash
MAX_VERIFY = 512 << 20            # oltre questa dimensione non si ricalcola l'hash per verificare
MAX_VERIFY_VELOCE = 16 << 20      # ricerca veloce: si verifica l'hash della riga solo con un file e fino a 16 MB
IMG_EXT = {".jpg", ".jpeg", ".jpe", ".jfif", ".png", ".gif", ".bmp", ".webp", ".heic", ".heif", ".tif", ".tiff"}
VID_EXT = {".mp4", ".m4v", ".mov", ".3gp", ".avi", ".mkv", ".webm"}
AUD_EXT = {".mp3", ".m4a", ".aac", ".amr", ".opus", ".ogg", ".wav", ".caf", ".flac"}
METODI = {"percorso": N_("per percorso"),
          "percorso_leapp": N_("per percorso, registrato da iLEAPP/ALEAPP"),
          "hash": N_("per hash"),
          "nome+dimensione": N_("per nome e dimensione"),
          "nome": N_("per solo nome")}
METODI_CERTI = ("hash", "percorso_leapp", "percorso")          # in ordine di forza
METODI_PROBABILI = ("nome+dimensione", "nome")
LIVELLI = {"certo": N_("trovato con certezza"), "probabile": N_("probabile, da verificare"),
           "assente": N_("non presente nell'estrazione")}
MAX_ELENCO = 20                   # candidati o copie elencati per file citato
_conf = None
_lock = threading.Lock()
_idx_done = set()
_hash_cache = {}
_lava_cache = {}


def conf():
    """Tabella di corrispondenza e regole dei campi (forense_percorsi.json), con le espressioni già compilate."""
    global _conf
    if _conf is None:
        c = json.loads(CONF_FILE.read_text(encoding="utf-8"))
        c["_campi"] = {k: re.compile(v, re.I) for k, v in c["campi"].items()}
        c["_inclusi"] = re.compile(c["campi_inclusi"], re.I)
        c["_nome"] = re.compile(c["estensioni_nome"], re.I)
        c["_radici"] = re.compile(c["radici_assolute"], re.I)
        c["_winpre"] = [re.compile("^" + _win_rx(p), re.I) for p in c["windows_prefissi"]]
        _conf = c
    return _conf


def _win_rx(p):
    """Prefisso di Windows della tabella → espressione regolare: le parti tra [] e {[^}]*} restano espressioni,
    il resto (barre rovesciate, punti interrogativi) è letterale."""
    out, i = "", 0
    while i < len(p):
        if p[i] == "[":
            j = p.index("]", i)
            out += p[i:j + 1]
            i = j + 1
            if i < len(p) and p[i] in "+*":
                out += p[i]
                i += 1
        elif p.startswith("{[^}]*}", i):
            out += r"\{[^}]*\}"
            i += 7
        else:
            out += re.escape(p[i])
            i += 1
    return out


# ------------------------------------------------------------------------------------- riconoscimento

def valore_percorso(v):
    """Testo di un campo → percorso da cercare (prima riga, senza «>> …» dei file dentro un archivio, file:// decodificato)
    oppure None se non è un percorso di file (URL di rete, testo libero)."""
    if v is None:
        return None
    s = str(v).strip().strip("\"'`")
    s = (s.splitlines() or [""])[0].split(" >> ")[0].strip()
    if not s or len(s) > 1000:
        return None
    low = s.lower()
    if low.startswith("file://"):
        s = urllib.parse.unquote(s[7:])
        if s.startswith("localhost/"):
            s = s[9:]
        if re.match(r"^/[A-Za-z]:/", s):         # file:///C:/Users/… (Firefox)
            s = s[1:]
        low = s.lower()
    elif re.match(r"^[a-z][a-z0-9+.\-]{1,15}://", low) or low.startswith(("content:", "data:", "mailto:", "tel:",
                                                                              "javascript:", "about:", "blob:")):
        return None
    # programma con argomenti («/usr/local/bin/evil --quiet», «C:\\x\\a.exe /s»): solo il percorso
    m = re.match(r'^("?)((?:[A-Za-z]:[\\/]|/|~/|\\\\)[^"]*?)\1(?:\s+(?:--?|/)[A-Za-z].*)$', s)
    if m:
        s = m.group(2)
    # più percorsi separati da virgola (es. «a/appops.xml, mirror/a/appops.xml»): il primo
    if ", " in s and "/" in s.split(", ")[0] and "/" in s.split(", ")[1]:
        s = s.split(", ")[0]
    return s


def forma(s):
    """Forma di un percorso: windows | assoluto | relativo | nome. None se non sembra un file né una cartella."""
    if not s:
        return None
    c = conf()
    if re.match(r"^[A-Za-z]:[\\/]", s) or s.startswith("\\\\") or s.startswith("\\") or re.match(r"^%[A-Za-z_()0-9]+%", s):
        return "windows"
    if s.startswith("/") or s.startswith("~/"):
        return "assoluto"
    if "/" in s:
        first = s.split("/")[0]
        if (" " in first and len(first) > 40) or s.count(" ") > 12 or ":" in first or "=" in first:
            return None             # frase, elenco o identificativo con barre, non un percorso
        return "relativo"
    if "\\" in s and re.search(r"\\[^\\]+\.[A-Za-z0-9]{1,6}$", s):
        return "windows"
    if c["_nome"].match(s):
        return "nome"
    return None


def _ruolo(campo):
    c = conf()["_campi"]
    k = str(campo or "")
    if c["fonte"].search(k):
        return "fonte"
    if c["cartella"].search(k):
        return "cartella"
    return "file"


def _hash_val(v):
    """Hash in esadecimale (MD5/SHA-1/SHA-256) da un valore esadecimale o base64 (WhatsApp: base64 dello SHA-256)."""
    s = str(v or "").strip()
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", s):
        return s.lower()
    try:
        b = base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    return b.hex() if len(b) in (16, 20, 32) and re.fullmatch(r"[A-Za-z0-9+/=_-]{20,60}", s) else None


def _num(v):
    try:
        n = int(float(str(v).replace(",", "").strip()))
        return n if n > 0 else None
    except (TypeError, ValueError):
        return None


def campi_piatti(data):
    """Campi «nome: valore» di una riga: i campi di iLEAPP/ALEAPP o le chiavi dei dati degli artefatti dei dischi
    (le liste diventano più campi con lo stesso nome)."""
    if not isinstance(data, dict):
        return []
    src = data.get("campi") if isinstance(data.get("campi"), dict) else data
    out = []
    for k, v in src.items():
        if isinstance(v, (list, tuple)):
            out += [(k, x) for x in v[:20] if isinstance(x, (str, int, float))]
        elif isinstance(v, (str, int, float)) and not isinstance(v, bool):
            out.append((k, v))
    return out


def candidati(campi):
    """Dai campi di una riga: ([{campo, valore, percorso, forma, ruolo}], suggerimenti {size, sha256, sha1, md5, nome})."""
    c = conf()
    rx = c["_campi"]
    hint, cand, seen = {}, [], set()
    for k, v in campi:
        kk = str(k)
        if rx["dimensione"].search(kk) and _num(v) and "size" not in hint:
            hint["size"] = _num(v)
            continue
        for alg in ("sha256", "sha1", "md5"):
            if rx["hash_" + alg].search(kk):
                h = _hash_val(v)
                if h and alg not in hint and len(h) == {"sha256": 64, "sha1": 40, "md5": 32}[alg]:
                    hint[alg] = h
        if rx["nome"].search(kk) and isinstance(v, str) and c["_nome"].match(v.strip()):
            hint.setdefault("nome", v.strip())
        if rx["esclusi"].search(kk) and not c["_inclusi"].search(kk):
            continue
        s = valore_percorso(v) if isinstance(v, str) else None
        f = forma(s)
        if not f:
            continue
        ruolo = _ruolo(kk)
        if f == "nome" and ruolo != "fonte" and not (rx["nome"].search(kk) or rx["file"].search(kk)):
            continue                       # un nome con estensione in un campo qualsiasi: troppo vago da solo
        if f != "nome" and not s.replace("\\", "/").strip("/~"):
            continue                       # «/» da solo (es. percorso di un cookie)
        ext = bool(c["_nome"].match(PurePosixPath(s.replace("\\", "/")).name))
        nomecampo = rx["file"].search(kk) or rx["cartella"].search(kk)
        if ruolo != "fonte" and f != "nome" and not (
                (f == "assoluto" and c["_radici"].match(s) and (ext or nomecampo)) or
                (f == "windows" and (ext or nomecampo)) or (f == "relativo" and ext) or
                (f == "relativo" and nomecampo and not re.search(r"[=+\[\]]", s))):
            continue                       # testo con barre (tipi MIME, componenti, build, base64): non è un file
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        cand.append({"campo": kk, "valore": str(v)[:500], "percorso": s, "forma": f, "ruolo": ruolo})
    unisci_cartella_nome(cand)
    # il nome del file da solo vale come file citato se nessun campo ha il percorso
    if any(x["ruolo"] == "file" and x["forma"] != "nome" for x in cand):
        cand = [x for x in cand if not (x["forma"] == "nome" and x["ruolo"] == "file" and
                                        any(y["forma"] != "nome" and y["ruolo"] == "file" and
                                            y["percorso"].lower().endswith(x["percorso"].lower()) for y in cand))]
    return cand, hint


def unisci_cartella_nome(cand):
    """Cartella e nome del file in due campi della stessa riga («Directory: DCIM/100APPLE» + «Filename: IMG_0059.PNG»)
    → un solo candidato con il percorso completo (campo «Directory + Filename»), che si cerca per percorso e non per
    solo nome. Il campo della cartella resta, segnato «unito», e diventa il collegamento «cartella» del file. Con più
    cartelle e più nomi si abbinano nell'ordine (stesso numero) o tutti alla prima cartella."""
    dirs = [x for x in cand if x["ruolo"] == "cartella" and x["forma"] != "nome"]
    names = [x for x in cand if x["ruolo"] == "file" and x["forma"] == "nome"]
    if not dirs or not names:
        return
    for i, n in enumerate(names):
        d = dirs[i] if len(dirs) == len(names) else dirs[0]
        sep = "\\" if d["forma"] == "windows" else "/"
        dp = d["percorso"].rstrip("/\\")
        if not dp or dp.replace("\\", "/").lower().endswith("/" + n["percorso"].lower()):
            continue
        full = dp + sep + n["percorso"]
        f = forma(full)
        if not f or f == "nome":
            continue
        n.update({"campo": d["campo"] + " + " + n["campo"], "campi": [d["campo"], n["campo"]], "valore": full,
                  "percorso": full, "forma": f, "cartella": d["campo"], "solo_nome": dict(n)})
        d["unito"] = True


# ---------------------------------------------------------------------------------------------- indice

def _nav_path(case):
    return Path(case.root) / "navigazione.sqlite"


def _ensure_nav(case, wait=900):
    """Indice dell'albero pronto (lo costruisce l'interfaccia, se serve) con gli indici per nome e dimensione."""
    import forense_gui as G
    t0 = time.time()
    while True:
        st = G.ensure_nav(case)
        if st.get("state") == "ready":
            break
        if st.get("state") == "error" or time.time() - t0 > wait:
            raise ValueError(st.get("msg") or tr("Albero non disponibile."))
        time.sleep(0.3)
    f = _nav_path(case)
    key = (str(f), f.stat().st_mtime_ns)
    if key not in _idx_done:
        with _lock:
            if key not in _idx_done:
                try:
                    w = sqlite3.connect(str(f), timeout=60)
                    w.execute("CREATE INDEX IF NOT EXISTS nav_name ON nav(name COLLATE NOCASE)")
                    w.execute("CREATE INDEX IF NOT EXISTS nav_size ON nav(size)")
                    w.commit()
                    w.close()
                except sqlite3.Error:
                    pass
                _idx_done.add((str(f), f.stat().st_mtime_ns))
    return sqlite3.connect(f.as_uri() + "?mode=ro", uri=True, timeout=30)


def _lava_media(case):
    """{«media/…»: (percorso nell'estrazione, incorporato, tipo)} dal database del rapporto di iLEAPP/ALEAPP."""
    lp = (getattr(case, "meta", None) or {}).get("leapp") or {}
    if not lp.get("rapporto"):
        return {}, None
    rep = Path(case.root) / lp["rapporto"]
    db = rep / "_lava_artifacts.db"
    key = str(db)
    if key in _lava_cache:
        return _lava_cache[key], rep
    m = {}
    if db.is_file():
        try:
            c = sqlite3.connect(db.as_uri() + "?mode=ro&immutable=1", uri=True)
            try:
                for ep, sp, emb, typ in c.execute("SELECT extraction_path, source_path, is_embedded, type FROM _lava_media_items"):
                    if ep:
                        m[str(ep).strip("/")] = (sp, bool(emb), typ)
            finally:
                c.close()
        except sqlite3.Error:
            pass
    _lava_cache[key] = m
    return m, rep


class Indice:
    """Ricerca dei file di un caso per percorso, hash, nome e dimensione (una connessione per richiesta)."""

    def __init__(self, case):
        import forense_agent as fa
        self.case = case
        self.mobile = fa.is_mobile(case)
        self.plat = ((case.meta.get("mobile") or {}).get("piattaforma") or "") if self.mobile else ""
        self.nav = _ensure_nav(case)
        self.lava, self.rep = _lava_media(case) if self.mobile else ({}, None)
        try:
            self.rep_top = {x.name.lower() for x in self.rep.iterdir()} if self.rep and self.rep.is_dir() else set()
        except OSError:
            self.rep_top = set()
        self._memo = {}

    def close(self):
        try:
            self.nav.close()
        except sqlite3.Error:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # --- primitive
    def per_nome(self, name):
        return self.nav.execute("SELECT part, path, inode, size, isdir, deleted FROM nav WHERE name = ? COLLATE NOCASE",
                                (name,)).fetchall()

    def per_dimensione(self, size):
        return self.nav.execute("SELECT part, path, inode, size, isdir, deleted FROM nav WHERE size = ? AND isdir = 0 "
                                "LIMIT ?", (int(size), MAX_HASH_CAND + 1)).fetchall()

    def da_inode(self, part, inode):
        return self.nav.execute("SELECT part, path, inode, size, isdir, deleted FROM nav WHERE part=? AND inode=? "
                                "ORDER BY deleted LIMIT 1", (int(part), str(inode))).fetchone()

    def da_percorso(self, part, path):
        return self.nav.execute("SELECT part, path, inode, size, isdir, deleted FROM nav WHERE part=? AND path=? "
                                "ORDER BY deleted LIMIT 1", (int(part), str(path))).fetchone()

    def sha_noti(self, rows):
        """SHA-256 già calcolati (tabella degli hash del caso o verifiche di questa sessione): {(part, inode): sha256}.
        Non calcola nulla."""
        import forense_agent as fa
        out = {}
        for r in rows:
            h = _hash_cache.get((str(self.case.root), int(r[0]), str(r[2]), "sha256"))
            if h:
                out[(int(r[0]), str(r[2]))] = h
        todo = [(int(r[0]), str(r[2])) for r in rows if (int(r[0]), str(r[2])) not in out]
        if not todo:
            return out
        try:
            con = fa.db_ro(self.case)
            try:
                if con.execute("SELECT name FROM sqlite_master WHERE name='hashes'").fetchone():
                    for k in todo:
                        x = con.execute("SELECT sha256 FROM hashes WHERE part=? AND inode=? AND sha256 IS NOT NULL LIMIT 1",
                                        k).fetchone()
                        if x and x[0]:
                            out[k] = x[0]
            finally:
                con.close()
        except Exception:
            pass
        return out

    # --- varianti del percorso da cercare (componenti, in minuscolo; «*» = qualsiasi componente)
    def varianti(self, s, f, utente=None):
        c = conf()
        out = []
        if f == "windows":
            p = s
            for rx in c["_winpre"]:
                m = rx.match(p)
                if m:
                    p = p[m.end():]
                    break
            for var, rep in c["windows_variabili"].items():
                if p.upper().startswith(var):
                    p = rep.replace("{utente}", utente or "*") + p[len(var):]
                    break
            out.append(p.replace("\\", "/"))
        elif f == "assoluto":
            rules = c["android"] if self.plat == "android" else c["ios"] if self.plat == "ios" else c["macos"]
            low = s.lower()
            for a, b in rules:
                if low.startswith(a.lower()):
                    out.append(b + s[len(a):])
            if not self.mobile:
                m = re.match(r"^/Volumes/[^/]+/(.+)$", s)
                if m:
                    out.append(m.group(1))
            if s.startswith("~/"):
                out.append("Users/*/" + s[2:])
            out.append(s.lstrip("/~"))
        else:
            out.append(s.replace("\\", "/"))
        res = []
        for p in out:
            comps = [x for x in p.strip("/").split("/") if x not in ("", ".")]
            if comps and comps not in res:
                res.append(comps)
        return res

    def _match(self, rows, variants, want_dir=None, pref=None):
        """Righe dell'indice il cui percorso finisce con una delle varianti; la migliore prima (a parità, quella della
        partizione `pref`, cioè della riga che cita il file: conta con più installazioni o più volumi)."""
        best = []
        for part, path, inode, size, isdir, deleted in rows:
            if want_dir is not None and bool(isdir) != want_dir:
                continue
            pc = (path or "").split("/")
            pl = [x.lower() for x in pc]
            for vi, v in enumerate(variants):
                n = len(v)
                if n > len(pl):
                    continue
                tail = pl[-n:]
                if all(a == "*" or a.lower() == b for a, b in zip(v, tail)):
                    exact = pc[-n:] == v
                    score = (vi, 0 if pref is None or part == pref else 1, 0 if exact else 1, int(deleted or 0), len(pc), path)
                    best.append((score, (part, path, inode, size, isdir, deleted)))
                    break
        best.sort(key=lambda x: x[0])
        return [r for _, r in best]

    def per_percorso(self, s, f, utente=None, want_dir=None, pref=None):
        variants = self.varianti(s, f, utente)
        if not variants:
            return []
        names = {v[-1] for v in variants if v[-1] != "*"}
        rows = []
        for n in names:
            rows += self.per_nome(n)
        return self._match(rows, variants, want_dir, pref)

    # --- hash
    def hash_file(self, part, inode, alg="sha256", size=None):
        import forense_agent as fa
        key = (str(self.case.root), int(part), str(inode), alg)
        if key in _hash_cache:
            return _hash_cache[key]
        if size and size > MAX_VERIFY:
            return None
        h = hashlib.new(alg)
        try:
            for b in fa.icat_stream(self.case, int(part), str(inode)):
                h.update(b)
        except Exception:
            return None
        _hash_cache[key] = h.hexdigest()
        return _hash_cache[key]

    def per_hash(self, hint):
        """File con l'hash indicato: tabella degli hash del caso, poi i file della stessa dimensione."""
        import forense_agent as fa
        for alg in ("sha256", "sha1", "md5"):
            if not hint.get(alg):
                continue
            con = fa.db_ro(self.case)
            try:
                if con.execute("SELECT name FROM sqlite_master WHERE name='hashes'").fetchone():
                    r = con.execute(f"SELECT part, inode FROM hashes WHERE {alg} = ? LIMIT 1", (hint[alg],)).fetchone()
                    if r:
                        x = self.da_inode(r[0], r[1])
                        if x:
                            return x, alg
            finally:
                con.close()
            if hint.get("size"):
                rows = self.per_dimensione(hint["size"])
                if len(rows) > MAX_HASH_CAND:
                    return None, alg
                for r in sorted(rows, key=lambda r: (int(r[5] or 0), len(r[1] or ""))):
                    if r[2] and self.hash_file(r[0], r[2], alg, r[3]) == hint[alg]:
                        return r, alg
            return None, alg
        return None, None

    # --- risoluzione
    def risolvi(self, s, f, hint=None, utente=None, ruolo="file", veloce=False, pref=None):
        """Cerca il file (o la cartella) `s` di forma `f`. Restituisce un dizionario con stato trovato | rapporto | assente,
        metodo, part, inode, path, size, copie, verifica, nota."""
        hint = hint or {}
        key = (s, f, ruolo, utente, veloce, pref, tuple(sorted(hint.items())))
        if key in self._memo:
            return dict(self._memo[key])
        out = self._risolvi(s, f, hint, utente, ruolo, veloce, pref)
        if len(self._memo) < 200000:
            self._memo[key] = dict(out)
        return out

    def _risolvi(self, s, f, hint, utente, ruolo, veloce, pref=None):
        out = {"percorso": s, "forma": f, "stato": "assente", "metodo": None, "copie": 0}
        want_dir = True if ruolo == "cartella" else None
        # file del rapporto di iLEAPP/ALEAPP («media/…», «_HTML/…»): percorso originale dal loro database
        if self.rep and f == "relativo" and s.split("/")[0].lower() in self.rep_top:
            rel = s.strip("/")
            item = self.lava.get(rel)
            try:
                on_disk = (self.rep / rel).is_file()
            except OSError:
                on_disk = False
            if item or on_disk:
                out["rapporto"] = (self.rep / rel).relative_to(Path(self.case.root)).as_posix()
                sp, emb, typ = item or (None, False, None)
                if sp and not emb:
                    r = self.per_percorso(sp, forma(sp) or "relativo")
                    if r:
                        return self._found(out, r, "percorso_leapp", hint, veloce)
                    out["nota"] = tr("copia nel rapporto di iLEAPP/ALEAPP; l'originale {p} non è nell'estrazione").format(p=sp)
                elif sp and emb:
                    out["incorporato_in"] = sp
                    out["nota"] = tr("ricavato da iLEAPP/ALEAPP dal contenuto di {p} (non è un file a sé nell'estrazione)").format(p=sp)
                else:
                    out["nota"] = tr("file del rapporto di iLEAPP/ALEAPP")
                out["stato"] = "rapporto"
                return out
        rows = self.per_percorso(s, f, utente, want_dir, pref) if f != "nome" else []
        if rows and ruolo == "file":                 # un file con lo stesso percorso di una cartella (miniature di Foto)
            files = [r for r in rows if not r[4]]
            rows = files or rows
        if rows:
            return self._found(out, rows, "percorso", hint, veloce)
        if ruolo == "cartella":
            return out
        name = PurePosixPath(s.replace("\\", "/")).name if f != "nome" else s
        if not veloce and any(hint.get(a) for a in ("sha256", "sha1", "md5")):
            r, alg = self.per_hash(hint)
            if r:
                out["hash_alg"] = alg
                return self._found(out, [r], "hash", hint, True, verificato=True)
        if name and conf()["_nome"].match(name):
            rows = sorted((r for r in self.per_nome(name) if not r[4]),
                          key=lambda r: (int(r[5] or 0), len(r[1] or ""), r[1] or ""))
            if hint.get("size"):
                rows = [r for r in rows if r[3] == hint["size"]]
                if rows:
                    return self._found(out, rows, "nome+dimensione", hint, veloce, candidati=True)
            elif rows:
                return self._found(out, rows, "nome", hint, veloce, candidati=True)
        return out

    def _found(self, out, rows, metodo, hint, veloce, verificato=False, candidati=False):
        """Esito «trovato» dalla prima riga. Per percorso le altre righe sono copie con lo stesso percorso finale;
        per nome sono candidati alla pari (il file giusto non si può scegliere da qui)."""
        part, path, inode, size, isdir, deleted = rows[0]
        out.update({"stato": "trovato", "metodo": metodo, "part": part, "path": path, "inode": inode, "size": size,
                    "isdir": int(isdir or 0), "deleted": int(deleted or 0), "copie": 0 if candidati else len(rows) - 1})
        if verificato:
            out["verifica"] = "uguale"
        elif not isdir and inode and (not veloce or (len(rows) == 1 and (size or 0) <= MAX_VERIFY_VELOCE)):
            # anche nella ricerca veloce (tabella, report portatile) con un solo file: l'esito resta quello del pannello
            for alg in ("sha256", "sha1", "md5"):
                if hint.get(alg):
                    h = self.hash_file(part, inode, alg, size)
                    if h:
                        out["verifica"] = "uguale" if h == hint[alg] else "diverso"
                        out["hash_alg"] = alg
                    break
        altre = rows[:MAX_ELENCO] if candidati else rows[1:MAX_ELENCO + 1]
        if altre:
            sha = {} if veloce else self.sha_noti(altre + [rows[0]])
            el = [{"part": r[0], "path": r[1], "inode": r[2], "size": r[3], "isdir": int(r[4] or 0),
                   "deleted": int(r[5] or 0), "sha256": sha.get((int(r[0]), str(r[2])))} for r in altre]
            if candidati:
                out["candidati"], out["n_candidati"] = el, len(rows)
            else:
                out["copie_elenco"] = el
            if sha.get((int(part), str(inode))):
                out["sha256"] = sha[(int(part), str(inode))]
        return out


class IndiceEstrazione(Indice):
    """Come Indice, ma sull'elenco dei file dell'estrazione di uno smartphone (estrazione.sqlite): serve durante
    l'importazione delle chat, quando l'albero (navigazione.sqlite) può non esserci ancora. Dizionari in memoria
    costruiti alla prima ricerca."""

    def __init__(self, case, part):
        self.case = case
        self.mobile = True
        self.plat = (case.meta.get("mobile") or {}).get("piattaforma") or ""
        self.part = int(part)
        self.nav = None
        self.lava, self.rep = _lava_media(case)
        try:
            self.rep_top = {x.name.lower() for x in self.rep.iterdir()} if self.rep and self.rep.is_dir() else set()
        except OSError:
            self.rep_top = set()
        self._memo = {}
        self._by_name = self._by_size = self._by_id = None

    def close(self):
        pass

    def _load(self):
        if self._by_name is not None:
            return
        import forense_mobile as fm
        self._by_name, self._by_size, self._by_id, self._by_path = {}, {}, {}, {}
        con = fm.mx(self.case)
        try:
            for i, path, size, isdir in con.execute("SELECT id, path, size, isdir FROM mobile_files WHERE part=?", (self.part,)):
                r = (self.part, path, str(i), size, isdir, 0)
                self._by_name.setdefault(path.rpartition("/")[2].lower(), []).append(r)
                self._by_id[str(i)] = r
                self._by_path[path] = r
                if not isdir:
                    self._by_size.setdefault(size, []).append(r)
        finally:
            con.close()

    def per_nome(self, name):
        self._load()
        return list(self._by_name.get(str(name).lower(), []))

    def per_dimensione(self, size):
        self._load()
        return self._by_size.get(int(size), [])[:MAX_HASH_CAND + 1]

    def da_inode(self, part, inode):
        self._load()
        return self._by_id.get(str(inode))

    def da_percorso(self, part, path):
        self._load()
        return self._by_path.get(str(path))

    def per_hash(self, hint):
        for alg in ("sha256", "sha1", "md5"):
            if hint.get(alg):
                if not hint.get("size"):
                    return None, alg
                rows = self.per_dimensione(hint["size"])
                if len(rows) > MAX_HASH_CAND:
                    return None, alg
                for r in sorted(rows, key=lambda r: len(r[1] or "")):
                    if self.hash_file(r[0], r[2], alg, r[3]) == hint[alg]:
                        return r, alg
                return None, alg
        return None, None


# ------------------------------------------------------------------------------------------- per riga

def leapp_fonte(case, sub, campi):
    """Database da cui iLEAPP/ALEAPP ha letto una riga: il campo «Source…» della riga se è un percorso, altrimenti la riga
    del .lava (meta leapp.fonti) con lo stesso nome del file indicato nella riga o la prima; senza «>> …». None se manca."""
    fonti = [x.split(" >> ")[0].strip().strip("/") for x in
             str(((case.meta.get("leapp") or {}).get("fonti") or {}).get(sub) or "").splitlines() if x.strip()]
    vals = [str(v) for k, v in (campi or {}).items() if _ruolo(k) == "fonte" and v]
    for v in vals:
        p = (valore_percorso(v) or "").strip("/")
        if "/" in p:
            return p
    for v in vals:                          # solo il nome («gphotos-1.db»): la riga del .lava con quel nome
        n = PurePosixPath(str(v).strip()).name.lower()
        same = [f for f in fonti if PurePosixPath(f).name.lower() == n]
        if same:
            return sorted(same, key=lambda x: (".magisk/mirror" in x, len(x)))[0]
    return sorted(fonti[:1])[0] if fonti else None


def file_citati(case, riga, veloce=False, idx=None):
    """File citati da una riga {cat, src_path, part, inode, user, data}: {"fonte": ris|None, "file": [ris…]}.
    Ogni risultato ha campo, valore, ruolo e l'esito di Indice.risolvi."""
    data = riga.get("data")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            data = {}
    data = data if isinstance(data, dict) else {}
    own = idx is None
    idx = idx or Indice(case)
    try:
        campi = campi_piatti(data)
        cat = riga.get("cat")
        if cat not in NO_TITOLO and riga.get("title"):
            campi.insert(0, ("Elemento", str(riga["title"])))     # dischi: LNK, download, cestino… citano il file nel titolo
        if cat == "cestino" and "/$i" in str(riga.get("src_path") or "").lower():
            sp = str(riga["src_path"])
            k = sp.lower().rfind("/$i")
            campi.insert(0, ("contenuto nel cestino", sp[:k] + "/$R" + sp[k + 3:]))
        cand, hint = candidati(campi)
        utente = riga.get("user") or None
        fonte = None
        leapp = riga.get("cat") == "leapp"
        if riga.get("inode") not in (None, "") and riga.get("part") is not None:
            r = idx.da_inode(riga["part"], riga["inode"])
            fonte = {"campo": "Fonte", "valore": riga.get("src_path") or "", "ruolo": "fonte", "stato": "trovato" if r else "assente",
                     "metodo": "percorso", "percorso": riga.get("src_path") or "", "copie": 0}
            if r:
                fonte.update({"part": r[0], "path": r[1], "inode": r[2], "size": r[3], "isdir": r[4], "deleted": r[5]})
            else:
                fonte.update({"part": riga["part"], "inode": riga["inode"], "path": riga.get("src_path")})
        else:
            sp = leapp_fonte(case, data.get("artefatto") or riga.get("src_path"), data.get("campi")) if leapp else None
            sp = sp or next((x["percorso"] for x in cand if x["ruolo"] == "fonte"), None) or (
                None if leapp else riga.get("src_path"))
            if sp:
                fonte = {"campo": "Fonte", "valore": sp, "ruolo": "fonte"}
                fonte.update(idx.risolvi(sp, forma(sp) or "relativo", ruolo="fonte", veloce=True))
        files, dirs = [], []
        fpath = (fonte or {}).get("path") or ""
        pref = None if idx.mobile or riga.get("part") in (None, "") else int(riga["part"])
        for x in cand:
            if x["ruolo"] == "fonte":
                continue
            if x["ruolo"] == "file" and len(files) >= MAX_CITATI:
                continue
            r = dict(idx.risolvi(x["percorso"], x["forma"], hint, utente, x["ruolo"], veloce, pref))
            if x.get("solo_nome") and not (r.get("stato") == "trovato" and r.get("metodo") == "percorso"):
                x = x["solo_nome"]          # cartella + nome non porta a un file: il nome resta da solo (es. «Original Filename»)
                r = dict(idx.risolvi(x["percorso"], x["forma"], hint, utente, x["ruolo"], veloce, pref))
            if r.get("path") and r["path"] == fpath and x["ruolo"] != "file":
                continue
            r.update({"campo": x["campo"], "valore": x["valore"], "ruolo": x["ruolo"], "campi": [x["campo"]]})
            if x.get("cartella"):
                r["_cartella"] = x["cartella"]
            if x.get("unito"):
                r["unito"] = True
            (dirs if x["ruolo"] == "cartella" else files).append(r)
        if not files and hint.get("nome") and not any(x["forma"] == "nome" for x in cand):
            r = dict(idx.risolvi(hint["nome"], "nome", hint, utente, "file", veloce))
            r.update({"campo": "nome del file", "valore": hint["nome"], "ruolo": "file", "campi": ["nome del file"]})
            files.append(r)
        files = raggruppa(idx, files, dirs)
        for r in files + ([fonte] if fonte else []):
            r["tipo"] = tipo_file(r.get("path") or r.get("rapporto") or r.get("percorso"))
        return {"fonte": fonte, "file": files}
    finally:
        if own:
            idx.close()


def livello(r):
    """certo | probabile | assente. Certo: percorso completo, hash, collegamento registrato da iLEAPP/ALEAPP, o hash
    della riga uguale; probabile: solo nome, nome e dimensione, o hash della riga DIVERSO; assente: non nella
    copia/estrazione (anche se iLEAPP/ALEAPP ne ha una copia nel suo rapporto)."""
    if not r or r.get("stato") != "trovato":
        return "assente"
    if r.get("verifica") == "diverso":
        return "probabile"
    if r.get("verifica") == "uguale" or r.get("metodo") in METODI_CERTI:
        return "certo"
    return "probabile"


def _forza(r):
    """Ordine per scegliere l'esito di un file citato da più campi: più piccolo = più forte."""
    lv = livello(r)
    m = r.get("metodo")
    met = METODI_CERTI + METODI_PROBABILI
    return ({"certo": 0, "probabile": 1, "assente": 2}[lv], 0 if r.get("verifica") == "uguale" else 1,
            met.index(m) if m in met else 9, 0 if r.get("stato") == "rapporto" else 1)


def _chiave(r):
    if r.get("stato") == "trovato" and r.get("inode") not in (None, ""):
        return ("f", int(r["part"]), str(r["inode"]))
    if r.get("stato") == "rapporto" and r.get("rapporto"):
        return ("r", r["rapporto"])
    return ("p", str(r.get("percorso") or "").replace("\\", "/").lower())


def _unisci(g, m):
    """Unisce l'esito `m` (stesso file) nel file citato `g`; resta l'esito più forte."""
    campi = g["campi"] + [c for c in m["campi"] if c not in g["campi"]]
    metodi = g["metodi"] + [x for x in m["metodi"] if x not in g["metodi"]]
    cart = g["_cartelle_campi"] + [c for c in m["_cartelle_campi"] if c not in g["_cartelle_campi"]]
    if _forza(m) < _forza(g):
        keep = {k: g[k] for k in ("rapporto",) if g.get(k) and not m.get(k)}
        g.clear()
        g.update(m)
        g.update(keep)
    if m.get("rapporto") and not g.get("rapporto"):
        g["rapporto"] = m["rapporto"]
    g.update({"campi": campi, "metodi": metodi, "_cartelle_campi": cart, "campo": ", ".join(campi)})


def raggruppa(idx, files, dirs):
    """Un file citato per ogni file DIVERSO: i campi che portano allo stesso file (stesso part/inode, stessa copia nel
    rapporto di iLEAPP, stesso percorso non trovato) si uniscono; un esito per solo nome il cui candidato è già un file
    trovato con certezza si unisce a quello. Le cartelle diventano collegamenti «cartella» del file (quella della
    stessa riga unita al nome: la cartella che contiene il file trovato); le cartelle senza file restano da sole."""
    groups = {}
    for r in files:
        r = dict(r)
        r["metodi"] = [{"campo": r["campo"], "metodo": r.get("metodo"), "stato": r.get("stato"),
                        "verifica": r.get("verifica")}]
        r["_cartelle_campi"] = [r.pop("_cartella")] if r.get("_cartella") else []
        k = _chiave(r)
        if k in groups:
            _unisci(groups[k], r)
        else:
            r["campo"] = ", ".join(r["campi"])
            groups[k] = r
    out = list(groups.values())
    certi = {(int(g["part"]), str(g["inode"])): g for g in out if livello(g) == "certo" and g.get("inode") not in (None, "")}
    for g in list(out):
        if livello(g) == "probabile" and g.get("candidati") and g not in certi.values():
            hit = next((certi[(int(c["part"]), str(c["inode"]))] for c in g["candidati"]
                        if (int(c["part"]), str(c["inode"])) in certi), None)
            if hit is not None:
                _unisci(hit, g)
                out.remove(g)
    for g in out:
        g["livello"] = livello(g)
        g["cartelle"] = []
    soli = []
    for d in dirs:
        link = {"campo": d["campo"], "percorso": d.get("percorso"), "stato": d.get("stato"), "part": d.get("part"),
                "inode": d.get("inode"), "path": d.get("path"), "copie": d.get("copie") or 0}
        g = next((g for g in out if d["campo"] in g["_cartelle_campi"]), None)
        if g is not None and g.get("stato") == "trovato" and g.get("path") and "/" in g["path"]:
            par = idx.da_percorso(g["part"], g["path"].rsplit("/", 1)[0])     # la cartella del file trovato
            if par:
                link.update({"stato": "trovato", "part": par[0], "path": par[1], "inode": par[2], "copie": 0})
        if g is None and d.get("stato") == "trovato":
            g = next((g for g in out if g.get("stato") == "trovato" and g.get("part") == d.get("part") and
                      str(g.get("path") or "").lower().startswith(str(d.get("path") or "").lower() + "/")), None)
        if g is None:
            g = out[0] if out else None
        if g is not None:
            g["cartelle"].append(link)
        else:
            d = dict(d)
            d.update({"livello": "certo" if d.get("stato") == "trovato" else "assente", "cartelle": [],
                      "metodi": [{"campo": d["campo"], "metodo": d.get("metodo"), "stato": d.get("stato")}]})
            soli.append(d)
    for g in out:
        g.pop("_cartelle_campi", None)
    return out + soli


def tipo_file(p):
    ext = PurePosixPath(str(p or "")).suffix.lower()
    return ("immagine" if ext in IMG_EXT else "video" if ext in VID_EXT else "audio" if ext in AUD_EXT else
            "pdf" if ext == ".pdf" else "")


def percorso_mostrato(r):
    """Il file trovato; con più candidati alla pari (solo nome) il nome com'è citato, non il primo candidato."""
    if r.get("stato") == "trovato" and not ((r.get("n_candidati") or 0) > 1 and livello(r) == "probabile"):
        return r.get("path")
    return r.get("percorso")


def univoco(r):
    """Esito utilizzabile per collegare UN file (allegati delle chat): trovato, non cartella e, se per solo nome, con
    tutti gli omonimi della stessa dimensione (come prima della 2.20: altrimenti il file non si può scegliere)."""
    if r.get("stato") != "trovato" or r.get("isdir"):
        return False
    if r.get("metodo") == "nome":
        c = r.get("candidati") or []
        return len({x.get("size") for x in c}) <= 1 and (r.get("n_candidati") or 0) <= len(c)
    return True


def esito_metodo(metodo, verifica=None):
    """«probabile, da verificare (per solo nome)», «trovato con certezza (per hash)»: esito breve di un allegato."""
    lv = livello({"stato": "trovato", "metodo": metodo, "verifica": verifica})
    return tr("{e} ({m})").format(e=tr(LIVELLI[lv]), m=tr(METODI.get(metodo, metodo or "")))


def metodo_testo(r):
    """«per percorso (Media); per percorso (Directory + Filename)»: come è stato trovato il file, campo per campo."""
    out = []
    for m in r.get("metodi") or [{"campo": r.get("campo"), "metodo": r.get("metodo"), "stato": r.get("stato")}]:
        c = tr(CAMPI_INTERNI[m["campo"]]) if m.get("campo") in CAMPI_INTERNI else (m.get("campo") or "")
        if m.get("stato") == "trovato" and m.get("metodo") in METODI:
            t = tr(METODI[m["metodo"]])
        elif m.get("stato") == "rapporto":
            t = tr("solo copia nel rapporto di iLEAPP/ALEAPP")
        else:
            t = tr("non trovato")
        out.append(f"{t} ({c})" if c else t)
    return "; ".join(out)


def etichetta(r):
    """Testo dell'esito per pannelli, Reperto, Preferiti, report e agente: percorso — esito in parole semplici; metodo
    per campo; hash; candidati (solo nome) o copie con lo stesso percorso finale."""
    if not r:
        return ""
    lv = r.get("livello") or livello(r)
    if r.get("ruolo") == "cartella":
        return tr("{p} — cartella trovata").format(p=r.get("path")) if r.get("stato") == "trovato" else \
            tr("{p} — cartella non presente nell'estrazione").format(p=r.get("percorso"))
    s = tr("{p} — {e}; metodo: {m}").format(p=percorso_mostrato(r), e=tr(LIVELLI[lv]), m=metodo_testo(r))
    if r.get("verifica") == "uguale":
        s += tr("; hash verificato")
    elif r.get("verifica") == "diverso":
        s += tr("; ATTENZIONE: hash diverso da quello registrato nella riga")
    if r.get("stato") == "rapporto" and r.get("nota"):
        s += "; " + r["nota"]
    n = r.get("n_candidati") or 0
    if lv == "probabile" and n > 1:
        s += tr("; {n} candidati: {l}").format(n=n, l=", ".join(c["path"] for c in r.get("candidati") or []))
        if n > len(r.get("candidati") or []):
            s += " …"
    elif r.get("copie"):
        s += tr("; altre {n} copie con lo stesso percorso finale").format(n=r["copie"]) if r["copie"] > 1 else \
            tr("; un'altra copia con lo stesso percorso finale")
    return s


def etichetta_disco(r, mobile):
    """Come etichetta(), con «non presente nella copia» per i dischi."""
    s = etichetta(r)
    if not mobile:
        s = s.replace(tr("non presente nell'estrazione"), tr("non presente nella copia"))
    return s


def risolvi_testo(case, p, utente=None, idx=None):
    """Un percorso citato in un testo (risposta dell'agente, messaggio della timeline): esito di Indice.risolvi."""
    s = valore_percorso(p)
    f = forma(s)
    if not f:
        return {"percorso": p, "stato": "assente", "copie": 0}
    own = idx is None
    idx = idx or Indice(case)
    try:
        r = idx.risolvi(s, f, {}, utente, "file")
        if r.get("stato") == "assente" and f != "nome":
            d = idx.risolvi(s, f, {}, utente, "cartella")
            if d.get("stato") == "trovato":
                r = d
        r["tipo"] = tipo_file(r.get("path") or s)
        return r
    finally:
        if own:
            idx.close()
