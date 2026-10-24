# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - volumi APFS (Mac).

The Sleuth Kit non legge APFS: qui i contenitori APFS si leggono con libfsapfs (modulo Python
pyfsapfs), sempre in sola lettura, direttamente dalla copia forense (raw o E01), senza creare copie.

Come si inserisce nel resto del programma
- Ogni VOLUME APFS diventa una «partizione» del caso con un offset sintetico
  (offset del contenitore + (n. volume + 1) * APFS_STEP): così elenco file, albero, filtri,
  report e analisi estese lo trattano come qualunque altro file system.
  `part_key`, `real_offset`, `vol_index` convertono fra offset sintetico e posizione reale.
- L'«inode» di un file è l'identificatore APFS (numerico, unico dentro il volume).
- Date: APFS ha nanosecondi; nella timeline si usano i secondi (UTC).
- File cancellati: libfsapfs non li recupera, quindi deleted = 0 per tutte le voci.
- Volumi cifrati (FileVault): si aprono con password o chiave di ripristino. La chiave resta
  SOLO in memoria (variabile d'ambiente REPERTIA_APFS_SECRETS del processo); non viene mai
  scritta nel caso né nel registro.
"""
import datetime as dt
import json
import os
import re
import stat
import threading
from forense_lingua import tr, N_  # noqa: E402

APFS_STEP = 1 << 40
RECOVERY_RE = re.compile(r"^[A-Z0-9]{4}(-[A-Z0-9]{4}){5}$", re.I)
ENV = "REPERTIA_APFS_SECRETS"
KIND_IT = {"d": N_("directory"), "r": N_("file"), "l": N_("collegamento simbolico"), "c": N_("dispositivo a caratteri"),
           "b": N_("dispositivo a blocchi"), "p": N_("pipe (FIFO)"), "h": N_("socket")}
SYSTEM_VOLS = {"preboot", "recovery", "vm", "update", "xarts", "iscpreboot", "hardware", "baseband"}


class ApfsLocked(Exception):
    """Volume APFS cifrato e non sbloccato."""


# ------------------------------------------------------------------ chiavi e offset

def is_apfs_part(part):
    try:
        return int(part) >= APFS_STEP
    except (TypeError, ValueError):
        return False


def part_key(real_sectors, idx):
    return int(real_sectors) + (int(idx) + 1) * APFS_STEP


def real_offset(key):
    return int(key) % APFS_STEP


def vol_index(key):
    return int(key) // APFS_STEP - 1


_SECRETS = []
_LOCK = threading.RLock()


def secrets():
    out = list(_SECRETS)
    try:
        for s in json.loads(os.environ.get(ENV) or "[]"):
            if isinstance(s, dict) and s.get("valore") and s not in out:
                out.append(s)
    except (ValueError, TypeError):
        pass
    return out


def set_secrets(items):
    """Chiavi per sbloccare i volumi (solo in memoria e nell'ambiente di questo processo e dei
    suoi figli). Ogni voce: {"tipo": "password"|"recovery"|"auto", "valore": "...", "volume": nome o uuid (facoltativo)}."""
    clean = []
    for s in items or []:
        v = str(s.get("valore") or "")
        if v:
            clean.append({"tipo": s.get("tipo") or "auto", "valore": v, "volume": s.get("volume") or ""})
    with _LOCK:
        _SECRETS[:] = clean
        for c in _OPEN.values():
            c.reset_unlock()
    if clean:
        os.environ[ENV] = json.dumps(clean)
    else:
        os.environ.pop(ENV, None)


def add_secret(valore, tipo="auto", volume=""):
    cur = secrets()
    cur.append({"tipo": tipo, "valore": valore, "volume": volume or ""})
    set_secrets(cur)


# ------------------------------------------------------------------ apertura

def have_lib():
    try:
        import pyfsapfs  # noqa: F401
        return True
    except ImportError:
        return False


def guess_role(name, locked=False):
    n = (name or "").strip().lower()
    if n in SYSTEM_VOLS:
        return n.capitalize() if n != "vm" else "VM"
    if n == "data" or n.endswith(" - data") or n.endswith("- dati"):
        return "Data"
    return "System"


class Cont:
    """Un contenitore APFS aperto sulla copia forense."""

    def __init__(self, image, real_sectors, length_sectors):
        import pyfsapfs
        import forense_estesa as fe
        self.lock = threading.RLock()
        self.img = fe.ImageFile(image)
        start = int(real_sectors) * 512
        length = int(length_sectors) * 512 if length_sectors else max(0, (self.img.size or 0) - start)
        self.region = fe.Region(self.img, start, length)
        self.c = pyfsapfs.container()
        self.c.open_file_object(self.region)
        self.vols = {}
        self.tried = {}
        self.enc = {}       # volumi nati cifrati (idx -> True)
        self.ok = {}        # volumi cifrati verificati leggibili (idx -> True)

    def reset_unlock(self):
        self.tried.clear()
        self.ok.clear()

    def _get(self, idx):
        """Volume `idx` (oggetto nuovo se non ancora aperto), annotando se nasce cifrato."""
        v = self.vols.get(idx)
        if v is None:
            v = self.vols[idx] = self.c.get_volume(idx)
            self.enc.setdefault(idx, bool(v.is_locked()))
        return v

    @staticmethod
    def _probe(v):
        """True solo se la radice del volume si legge davvero."""
        try:
            root = v.get_root_directory()
            if root is None:
                return False
            root.get_number_of_sub_file_entries()
            return True
        except Exception:
            return False

    def is_locked(self, idx, v=None):
        """True se il volume non è davvero leggibile. libfsapfs può dare per «sbloccato» un volume cifrato
        aperto con una chiave SBAGLIATA (is_locked() False ma radice illeggibile, 0 file): per i volumi nati
        cifrati si controlla quindi che la radice sia leggibile."""
        with self.lock:
            if self.ok.get(idx):
                return False
            v = v or self._get(idx)
            try:
                if v.is_locked():
                    return True
            except Exception:
                return True
            if not self.enc.get(idx):
                return False
            if self._probe(v):
                self.ok[idx] = True
                return False
            return True

    def volume(self, idx):
        with self.lock:
            v = self._get(idx)
            if self.is_locked(idx, v):
                self.unlock(v, idx)
                v = self.vols[idx]
            return v

    def unlock(self, v, idx=None):
        """Prova le chiavi note sul volume. True se ora è davvero aperto (radice leggibile)."""
        with self.lock:
            if idx is None:
                idx = next((i for i, x in self.vols.items() if x is v), None)
            chk = (lambda x: self.is_locked(idx, x)) if idx is not None else (lambda x: x.is_locked())
            if not chk(v):
                return True
            name, uuid = v.name or "", str(v.identifier or "")
            tentato = False
            for s in secrets():
                if s.get("volume") and s["volume"] not in (name, uuid):
                    continue
                key = (uuid, s["valore"])
                if key in self.tried:
                    continue
                self.tried[key] = True
                kind = s.get("tipo") or "auto"
                if kind == "auto":
                    kind = "recovery" if RECOVERY_RE.match(s["valore"].strip()) else "password"
                vv = v
                try:
                    if tentato and idx is not None:     # dopo un tentativo errato l'oggetto può restare in uno stato incerto
                        vv = self.c.get_volume(idx)
                    tentato = True
                    if kind == "recovery":
                        vv.set_recovery_password(s["valore"].strip())
                    else:
                        vv.set_password(s["valore"])
                    vv.unlock()
                except Exception:
                    continue
                if not chk(vv):
                    if idx is not None:
                        self.vols[idx] = vv
                    return True
            return False

    def close(self):
        with self.lock:
            self.vols.clear()
            try:
                self.c.close()
            except Exception:
                pass
            self.img.close()


_OPEN = {}


def _part(case, part):
    p = next((x for x in case.meta.get("partitions", []) if int(x["offset"]) == int(part)), None)
    if not p or not p.get("apfs"):
        raise ValueError(tr("Il volume APFS {part} non esiste in questo caso.").format(part=part))
    return p


def container(case, part):
    p = _part(case, part)
    a = p["apfs"]
    key = (str(case.image), int(a["real_offset"]))
    with _LOCK:
        c = _OPEN.get(key)
        if c is None:
            c = _OPEN[key] = Cont(case.image, a["real_offset"], a.get("length_sectors"))
        return c


def volume(case, part):
    c = container(case, part)
    v = c.volume(vol_index(part))
    if c.is_locked(vol_index(part), v):
        a = _part(case, part)["apfs"]
        raise ApfsLocked(tr("Il volume APFS «{v1}» è cifrato (FileVault): inserisci la password o la chiave di "
                            "ripristino per leggerne i contenuti.").format(v1=a.get('name') or vol_index(part)))
    return c, v


def close_all():
    with _LOCK:
        for c in _OPEN.values():
            try:
                c.close()
            except Exception:
                pass
        _OPEN.clear()


def is_locked(case, part):
    """True se il volume è cifrato e le chiavi note non lo aprono."""
    try:
        c = container(case, part)
        return c.is_locked(vol_index(part), c.volume(vol_index(part)))
    except ApfsLocked:
        return True
    except Exception:
        return False


def locked_parts(case):
    """Volumi APFS cifrati dei quali non si ha (ancora) la chiave: [(offset, nome)]."""
    out = []
    for p in case.meta.get("partitions", []):
        a = p.get("apfs")
        if a and a.get("encrypted") and is_locked(case, p["offset"]):
            out.append((p["offset"], a.get("name")))
    return out


# ------------------------------------------------------------------ riconoscimento

def is_container_head(head):
    return len(head) >= 36 and head[32:36] == b"NXSB"


def detect(case, real_sectors, length_sectors):
    """Se all'offset (in settori da 512) c'è un contenitore APFS lo apre e restituisce l'elenco dei volumi,
    altrimenti None. I volumi cifrati senza chiave risultano locked=True."""
    if not have_lib():
        return None
    try:
        key = (str(case.image), int(real_sectors))
        with _LOCK:
            old = _OPEN.pop(key, None)
        if old:
            old.close()
        c = Cont(case.image, real_sectors, length_sectors)
    except Exception:
        return None
    with _LOCK:
        _OPEN[(str(case.image), int(real_sectors))] = c
    vols = []
    try:
        n = c.c.number_of_volumes
        for i in range(n):
            with c.lock:
                v = c.c.get_volume(i)
                c.vols[i] = v
                enc = bool(v.is_locked())
                c.enc[i] = enc
                if enc:
                    c.unlock(v, i)
                    v = c.vols[i]
                name = v.name or f"Volume {i}"
                vols.append({"vol": i, "name": name, "uuid": str(v.identifier or ""), "encrypted": enc,
                             "locked": c.is_locked(i, v), "role": guess_role(name)})
    except Exception:
        return None
    return vols


def partition_entries(base, vols, real_sectors, length_sectors):
    """Voci di partizione del caso (una per volume) al posto del contenitore."""
    out = []
    for v in vols:
        label = f"APFS · {v['name']}" + (tr(" (cifrato)") if v["encrypted"] else "")
        out.append({"offset": part_key(real_sectors, v["vol"]), "length_sectors": length_sectors,
                    "desc": label, "slot": base.get("slot"), "readable": not v["locked"], "fs": "APFS",
                    "apfs": {"real_offset": int(real_sectors), "length_sectors": length_sectors, "vol": v["vol"],
                             "name": v["name"], "uuid": v["uuid"], "role": v["role"],
                             "encrypted": v["encrypted"], "container_desc": base.get("desc")}})
    return out


# ------------------------------------------------------------------ elenco file e timeline

def _ftype(mode):
    m = stat.S_IFMT(mode)
    t = {stat.S_IFDIR: "d", stat.S_IFREG: "r", stat.S_IFLNK: "l", stat.S_IFCHR: "c", stat.S_IFBLK: "b",
         stat.S_IFIFO: "p", stat.S_IFSOCK: "h"}.get(m, "r")
    return f"{t}/{t}"


def _iso(ns):
    if not ns or ns <= 0:
        return None
    try:
        return dt.datetime.fromtimestamp(ns // 1_000_000_000, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return None


def _iso_ns(ns):
    if not ns or ns <= 0:
        return "-"
    try:
        s = dt.datetime.fromtimestamp(ns // 1_000_000_000, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        return f"{s}.{ns % 1_000_000_000:09d} UTC"
    except (OverflowError, OSError, ValueError):
        return "-"


def index(case, part, con, say=None):
    """Percorre il volume e scrive elenco file (tabella files) ed eventi di timeline (origin 'tsk',
    stesso formato dell'elenco TSK, così l'albero e i filtri funzionano uguali).
    Restituisce (voci, cancellate, eventi)."""
    import forense_agent as fa
    c, v = volume(case, part)
    root = None
    with c.lock:
        # Alcuni volumi (snapshot, volumi di sistema sigillati, strutture danneggiate) non restituiscono
        # la radice: si prova con l'identificatore standard (2) e con il percorso "/".
        for getter in (lambda: v.get_root_directory(), lambda: v.get_file_entry_by_identifier(2),
                       lambda: v.get_file_entry_by_path("/")):
            try:
                root = getter()
            except Exception:
                root = None
            if root is not None:
                break
    if root is None:
        if say:
            a = _part(case, part)["apfs"]
            say(tr("  Volume APFS «{v1}»: radice non leggibile (volume vuoto, snapshot o struttura "
                   "danneggiata): volume saltato.").format(v1=a.get('name') or vol_index(part)))
        return 0, 0, 0
    stack = [(root, "")]
    files, evs = [], []
    n = nev = 0
    seen = {root.identifier}
    nextsay = 100000
    while stack:
        d, base = stack.pop()
        with c.lock:
            try:
                cnt = d.get_number_of_sub_file_entries()
            except Exception:
                continue
            for i in range(cnt):
                try:
                    e = d.get_sub_file_entry(i)
                    name = e.name or f"[senza nome {e.identifier}]"
                    path = f"{base}/{name}" if base else name
                    mode = e.file_mode
                    typ = _ftype(mode)
                    ident = e.identifier
                    size = e.size or 0
                    times = (("A", e.get_access_time_as_integer()), ("M", e.get_modification_time_as_integer()),
                             ("C", e.get_inode_change_time_as_integer()), ("B", e.get_creation_time_as_integer()))
                except Exception:
                    continue
                files.append((int(part), str(ident), 0, typ, path))
                n += 1
                for k, ns in times:
                    ts = _iso(ns)
                    if ts:
                        evs.append((ts, k, "FILE", path, tr("{v1} | {path} | inode {ident} | {size} B").format(v1=tr(fa.KIND[k]), path=path, ident=ident, size=size),
                                    "tsk", int(part)))
                if typ == "d/d" and ident not in seen:
                    seen.add(ident)
                    stack.append((e, path))
        if len(files) >= 20000:
            con.executemany(fa.INSERT_FILE, files)
            files.clear()
        if len(evs) >= 50000:
            con.executemany(fa.INSERT_EV, evs)
            nev += len(evs)
            evs.clear()
        if say and n >= nextsay:
            nextsay += 100000
            say(tr("  {n} file elencati...").format(n=n))
    con.executemany(fa.INSERT_FILE, files)
    con.executemany(fa.INSERT_EV, evs)
    nev += len(evs)
    con.commit()
    return n, 0, nev


# ------------------------------------------------------------------ contenuto e metadati

def _ident(inode):
    try:
        return int(str(inode).split("-")[0])
    except ValueError:
        raise ValueError(tr("inode APFS non valido"))


def _entry(case, part, inode):
    c, v = volume(case, part)
    with c.lock:
        e = v.get_file_entry_by_identifier(_ident(inode))
    if e is None:
        raise ValueError(tr("inode {inode} non trovato nel volume APFS").format(inode=inode))
    return c, v, e


def stream(case, part, inode, chunk=1 << 20):
    """Contenuto del file a blocchi (come icat). I contenuti compressi (decmpfs) sono già espansi."""
    try:
        c, _v, e = _entry(case, part, inode)
    except ApfsLocked:
        raise
    except Exception:
        return
    with c.lock:
        size = e.size or 0
        if stat.S_IFMT(e.file_mode) not in (stat.S_IFREG, 0):
            return
    pos = 0
    while pos < size:
        with c.lock:
            data = e.read_buffer_at_offset(min(chunk, size - pos), pos)
        if not data:
            break
        yield data
        pos += len(data)


def head_tail(case, part, inode, n=4096, tail=0):
    """(dimensione, inizio, fine) del file."""
    c, _v, e = _entry(case, part, inode)
    with c.lock:
        size = e.size or 0
        head = e.read_buffer_at_offset(min(n, size), 0) if size else b""
        end = e.read_buffer_at_offset(min(tail, size), max(0, size - tail)) if tail and size else b""
    return size, head, end


def _path_of(c, v, e):
    parts, guard = [], 0
    cur = e
    while cur is not None and guard < 200:
        guard += 1
        pid = cur.get_parent_identifier()
        if cur.identifier == 2 or not pid or pid == cur.identifier:
            break
        parts.append(cur.name or str(cur.identifier))
        cur = v.get_file_entry_by_identifier(pid)
    return "/".join(reversed(parts))


def istat_text(case, part, inode):
    """Metadati del file in testo (come istat): date con nanosecondi, permessi, proprietario,
    posizione fisica nel contenitore e attributi estesi (es. quarantena di macOS)."""
    c, v, e = _entry(case, part, inode)
    a = _part(case, part)["apfs"]
    with c.lock:
        mode = e.file_mode
        typ = _ftype(mode)[0]
        L = [tr("APFS · volume «{v1}» ({v2}) · identificatore (inode) {identifier}").format(v1=a.get('name'), v2=a.get('role'), identifier=e.identifier),
             tr("Percorso: /{v1}").format(v1=_path_of(c, v, e)),
             tr("Tipo: {v1} · modo: {v2} ({v3})").format(v1=tr(KIND_IT.get(typ, typ)), v2=stat.filemode(mode), v3=oct(mode & 0o7777)),
             tr("Dimensione: {size} byte · collegamenti: {v1}").format(size=e.size, v1=e.get_number_of_links()),
             tr("Proprietario (uid): {v1} · gruppo (gid): {v2}").format(v1=e.get_owner_identifier(), v2=e.get_group_identifier()),
             tr("Cartella superiore: inode {v1}").format(v1=e.get_parent_identifier()),
             tr("Date (UTC):"),
             tr("  Creazione:                 {v1}").format(v1=_iso_ns(e.get_creation_time_as_integer())),
             tr("  Modifica contenuto:        {v1}").format(v1=_iso_ns(e.get_modification_time_as_integer())),
             tr("  Modifica metadati (change): {v1}").format(v1=_iso_ns(e.get_inode_change_time_as_integer())),
             tr("  Ultimo accesso:            {v1}").format(v1=_iso_ns(e.get_access_time_as_integer()))]
        try:
            L.append(tr("  Aggiunta alla cartella:    {v1}").format(v1=_iso_ns(e.get_added_time_as_integer())))
        except Exception:
            pass
        if typ == "l":
            try:
                L.append(tr("Destinazione del collegamento: {v1}").format(v1=e.get_symbolic_link_target()))
            except Exception:
                pass
        try:
            ne = e.get_number_of_extents()
            if ne and typ == "r":
                L.append(tr("Estensioni dati ({ne}): offset fisico nel contenitore, byte, flag").format(ne=ne))
                cbase = int(a["real_offset"]) * 512
                for i in range(min(ne, 50)):
                    off, ln, fl = e.get_extent(i)
                    L.append(tr("  {off} (nella copia: {v1}) · {ln} · {fl}").format(off=off, v1=cbase + off, ln=ln, fl=fl))
                if ne > 50:
                    L.append(tr("  … altre {v1}").format(v1=ne - 50))
        except Exception:
            pass
        try:
            nx = e.get_number_of_extended_attributes()
            if nx:
                L.append(tr("Attributi estesi ({nx}):").format(nx=nx))
            for i in range(nx):
                x = e.get_extended_attribute(i)
                val = ""
                if x.size and x.size <= 512:
                    raw = x.read_buffer(x.size)
                    if raw.startswith(b"bplist"):
                        val = tr(" = (property list)")
                    else:
                        txt = raw.decode("utf-8", "replace")
                        if all(ch.isprintable() or ch in "\n\t" for ch in txt):
                            val = " = " + txt.replace("\n", " ")
                        else:
                            val = " = 0x" + raw[:32].hex()
                L.append(tr("  {name} ({size} byte){val}").format(name=x.name, size=x.size, val=val))
        except Exception:
            pass
    return "\n".join(L)


def link_target(case, part, inode):
    """Destinazione di un collegamento simbolico APFS (o None)."""
    try:
        c, _v, e = _entry(case, part, inode)
        with c.lock:
            return e.get_symbolic_link_target()
    except Exception:
        return None


def xattr(case, part, inode, name):
    """Valore di un attributo esteso (o None)."""
    c, _v, e = _entry(case, part, inode)
    with c.lock:
        try:
            x = e.get_extended_attribute_by_name(name)
            return x.read_buffer(x.size) if x and x.size else b""
        except Exception:
            return None


# ------------------------------------------------------------------ sistema operativo

def detect_os(case, part, con):
    """Descrizione del sistema (macOS) del volume, oppure None."""
    import plistlib
    import forense_agent as fa
    a = _part(case, part)["apfs"]
    ino = fa.lookup(con, part, "system/library/coreservices/systemversion.plist")
    if ino:
        try:
            d = plistlib.loads(fa.icat_read(case, part, ino, 1 << 20))
            ver = f"macOS {d.get('ProductVersion', '')}".strip()
        except Exception:
            ver = "macOS"
        role = (a.get("role") or "").lower()
        return ver + (f" ({a.get('name')})" if role in SYSTEM_VOLS else "")
    if fa.lookup(con, part, "private/var/db/dslocal/nodes/default/users") is not None or \
            con.execute("SELECT 1 FROM files WHERE part=? AND lower(path) LIKE 'users/%' LIMIT 1", (part,)).fetchone():
        return tr("macOS (volume Dati)")
    return None


# ------------------------------------------------------------------ sblocco a caso aperto

def apply_key(case, part, secret, kind):
    """Imposta la chiave (solo in memoria) e verifica che apra il volume; altrimenti ValueError."""
    p = _part(case, part)
    a = p["apfs"]
    secret = (secret or "").strip() if kind == "recovery" else (secret or "")
    if not secret:
        raise ValueError(tr("Inserisci la password o la chiave di ripristino."))
    set_secrets([s for s in secrets() if s.get("volume") != a.get("uuid")] +
                [{"tipo": "recovery" if kind == "recovery" else "password", "valore": secret,
                  "volume": a.get("uuid") or ""}])
    c = container(case, part)
    with c.lock:
        idx = vol_index(part)
        v = c._get(idx)
        c.ok.pop(idx, None)
        c.unlock(v, idx)
        if c.is_locked(idx, c.vols[idx]):
            raise ValueError(tr("Chiave o password non corretta, oppure il volume è protetto da chiavi dell'hardware "
                             "(Mac con chip T2 o Apple Silicon): il volume resta bloccato."))


def unlock_and_index(case, part, secret, kind, progress):
    """Sblocca un volume cifrato con la chiave data e, se il volume non era ancora stato elencato,
    lo aggiunge al caso (elenco file e timeline). La chiave resta solo in memoria."""
    import sqlite3
    import forense_agent as fa
    p = _part(case, part)
    a = p["apfs"]
    apply_key(case, part, secret, kind)
    indexed = bool(p.get("readable")) and "files" in p
    if not indexed:
        progress(tr("Volume sbloccato: elenco i file di «{v1}»…").format(v1=a.get('name')))
        con = sqlite3.connect(case.db_path)
        con.executescript(fa.SCHEMA)
        con.execute("DELETE FROM files WHERE part=?", (int(part),))
        con.execute("DELETE FROM events WHERE part=? AND origin='tsk'", (int(part),))
        n, dele, nev = index(case, part, con, progress)
        p["readable"] = True
        p["files"], p["deleted"] = n, dele
        p["os"] = detect_os(case, part, con)
        tl = case.meta.setdefault("timeline", {"tsk_events": 0, "plaso_events": 0})
        tl["tsk_events"] = int(tl.get("tsk_events") or 0) + nev
        con.close()
        case.meta["volumi_cifrati"] = [x for x in case.meta.get("volumi_cifrati", [])
                                       if int(x["offset"]) != int(part)]
        for f in ("navigazione.sqlite", "navigazione.sqlite.tmp"):
            try:
                (case.root / f).unlink()
            except OSError:
                pass
    case.log("apfs_sbloccato", {"volume": a.get("name"), "uuid": a.get("uuid"),
                                "credenziale": tr("chiave di ripristino") if kind == "recovery" else "password",
                                "indicizzato_ora": not indexed})
    case.save()
    return {"sbloccato": True, "volume": a.get("name"), "indicizzato_ora": not indexed,
            "files": p.get("files")}
