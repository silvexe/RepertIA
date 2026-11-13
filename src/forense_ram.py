#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (3.0.4) - analisi di un dump della memoria RAM di un computer Windows.

Il motore è MemProcFS (Ulf Frisk, AGPL-3.0), caricato solo qui: legge il dump in sola lettura e ne ricava processi,
connessioni di rete, moduli, driver, attività pianificate, utenti e dati del sistema. I risultati vanno nella tabella
`artifacts` del caso, come gli artefatti dei dischi: Risultati, filtri, preferiti, report e strumenti dell'agente li
trovano senza altro codice.

Regole:
- nessuna richiesta di rete: MemProcFS parte sempre con `-disable-symbolserver` e l'esito dice se il server dei simboli
  risulta davvero disattivato. Senza simboli alcune funzioni (es. i servizi) non danno risultati: l'esito lo dichiara;
- MemProcFS legge solo memoria di Windows; se non riconosce il sistema il caso resta con hash e carving, e lo dice;
- sono dati letti dalla memoria: un processo o una connessione possono essere residui di strutture già liberate.
  L'esito e il report lo indicano come dati DA VERIFICARE.
"""
import datetime as dt
import json
import os
import re
import shutil
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import forense_agent as fa  # noqa: E402
from forense_lingua import tr, N_  # noqa: E402

ESTENSIONI = (".mem", ".vmem", ".dmp", ".lime", ".raw", ".bin", ".img", ".dd")
DATA_RE = r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC"
MAX_MODULI = 200000
INTEGRITA = {0: "?", 1: "untrusted", 2: "low", 3: "medium", 4: "medium+", 5: "high", 6: "system", 7: "protected"}


class RamNonDisponibile(RuntimeError):
    pass


def cartelle_motore():
    """Dove può stare la libreria di MemProcFS (vmm.dll, vmm.so o vmm.dylib, dentro una cartella `memprocfs`):
    variabile REPERTIA_MEMPROCFS, poi strumenti/memprocfs."""
    import forense_vmm
    out = []
    if os.environ.get("REPERTIA_MEMPROCFS"):
        out.append(Path(os.environ["REPERTIA_MEMPROCFS"]))
    base = Path(os.environ.get("REPERTIA_STRUMENTI", HERE.parent / "strumenti"))
    out.append(base / "memprocfs")
    return [d for d in out if (d / "memprocfs" / forense_vmm.nomi_libreria()[0]).is_file()]


def carica():
    """Il motore: l'adattatore di RepertIA (forense_vmm.py) sulla libreria di MemProcFS, lo stesso su Mac, Windows e
    Linux; oppure RamNonDisponibile con il motivo. Un modulo `memprocfs` già caricato (il motore finto del collaudo)
    ha la precedenza; il modulo Python ufficiale non si cerca, perché non esiste per tutti i sistemi."""
    if sys.modules.get("memprocfs") is not None:
        return sys.modules["memprocfs"]
    import forense_vmm
    err = ""
    for d in cartelle_motore():
        try:
            forense_vmm.libreria(d / "memprocfs")
            forense_vmm.CARTELLA = d / "memprocfs"
            return forense_vmm
        except (ImportError, OSError, AttributeError) as e:
            err = str(e)[:300]
    raise RamNonDisponibile(tr("MemProcFS non trovato: l'analisi della memoria RAM richiede il componente memprocfs "
                               "(cartella strumenti/memprocfs del pacchetto).") + (f" [{err}]" if err else ""))


def presente():
    """True se il componente c'è (senza caricarlo): per l'elenco degli strumenti."""
    return sys.modules.get("memprocfs") is not None or bool(cartelle_motore())


def disponibile():
    """(True, versione) oppure (False, motivo): per l'interfaccia, senza aprire nulla."""
    try:
        m = carica()
    except RamNonDisponibile as e:
        return False, str(e)
    if getattr(m, "CARTELLA", None):
        return True, m.versione(m.CARTELLA)
    return True, getattr(m, "__version__", "") or ""


def _iso(s):
    """'2025-03-07 19:41:08 UTC' -> '2025-03-07T19:41:08' (UTC, come le altre date del caso); altro -> None."""
    m = re.match(r"(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)", str(s or "").strip())
    return f"{m.group(1)}T{m.group(2)}" if m else None


def _leggi(vmm, percorso, limite=64 << 20):
    try:
        return vmm.vfs.read(percorso, limite).decode("utf-8", "replace")
    except Exception:
        return ""


def _leggi_tutto(vmm, percorso, blocco=1 << 20):
    """Un file grande di MemProcFS letto a blocchi, secondo la dimensione che dichiara (la lettura in un colpo fallisce)."""
    try:
        cartella, _, nome = percorso.rpartition("/")
        size = int(vmm.vfs.list(cartella or "/")[nome]["size"])
    except Exception:
        return ""
    pezzi, pos = [], 0
    while pos < size:
        try:
            b = vmm.vfs.read(percorso, min(blocco, size - pos), pos)
        except Exception:
            break
        if not b:
            break
        pezzi.append(b)
        pos += len(b)
    return b"".join(pezzi).decode("utf-8", "replace")


def _colonne(testa, nomi):
    """Posizione iniziale di ogni colonna in una riga d'intestazione a larghezza fissa."""
    return {n: testa.find(n) for n in nomi}


def leggi_processi(vmm):
    """Processi: quelli attivi dall'API, date e processi terminati dall'elenco testuale. Lista di dict."""
    testo = _leggi(vmm, "/sys/proc/proc.txt")
    righe = testo.splitlines()
    tempi = {}
    if len(righe) > 2:
        col = _colonne(righe[0], ("Pid", "Parent", "Flag", "User", "Create Time"))
        for r in righe[2:]:
            m = re.match(r"^(-+) (.{1,15}?)\s+(\d+)\s+(\d+)\s", r)
            d = re.findall(DATA_RE, r)
            if not m:
                continue
            flag = r[col["Parent"] + 6:col["User"]].strip() if col["User"] > 0 else ""
            utente = r[col["User"]:col["Create Time"]].strip() if col["Create Time"] > 0 else ""
            tempi[int(m.group(3))] = {"nome": m.group(2).strip(), "ppid": int(m.group(4)), "livello": len(m.group(1)),
                                      "flag": flag, "utente": utente, "avvio": _iso(d[0]) if d else None,
                                      "fine": _iso(d[1]) if len(d) > 1 else None}
    out, visti = [], set()
    try:
        attivi = vmm.process_list()
    except Exception:
        attivi = []
    for p in attivi:
        d = {"pid": p.pid, "attivo": True}
        for k, attr in (("ppid", "ppid"), ("nome", "name"), ("nome_lungo", "fullname"), ("percorso", "pathuser"),
                        ("percorso_kernel", "pathkernel"), ("comando", "cmdline"), ("sid", "sid"),
                        ("sessione", "session"), ("integrita", "integrity"), ("wow64", "is_wow64"), ("stato", "state")):
            try:
                d[k] = getattr(p, attr)
            except Exception:
                d[k] = None
        t = tempi.get(p.pid) or {}
        d.update(avvio=t.get("avvio"), fine=t.get("fine"), utente=t.get("utente") or "", flag=t.get("flag") or "")
        if not d["avvio"]:
            d["avvio"] = _iso(_leggi(vmm, f"/pid/{p.pid}/time-create.txt", 64))
        visti.add(p.pid)
        out.append(d)
    for pid, t in tempi.items():           # terminati: restano solo nell'elenco testuale
        if pid not in visti:
            out.append({"pid": pid, "attivo": False, "ppid": t["ppid"], "nome": t["nome"], "nome_lungo": t["nome"],
                        "percorso": None, "percorso_kernel": None, "comando": None, "sid": None, "sessione": None,
                        "integrita": None, "wow64": None, "stato": None, "avvio": t["avvio"], "fine": t["fine"],
                        "utente": t["utente"], "flag": t["flag"]})
    per_pid = {d["pid"]: d for d in out}
    for d in out:              # il PID del padre può essere stato riusato da un processo nato dopo: allora il padre non c'è più
        g = per_pid.get(d.get("ppid"))
        d["padre"] = g.get("nome") if g and not (g.get("avvio") and d.get("avvio") and g["avvio"] > d["avvio"]) else None
    return sorted(out, key=lambda d: (d.get("avvio") or "", d["pid"]))


RETE_RE = re.compile(r"^(\w{4})\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*?)\s*(" + DATA_RE + r"|\*\*\*)\s+([0-9a-f]{8,16})\s*(.*)$")


def leggi_rete(vmm):
    """Connessioni e porte in ascolto dall'elenco dettagliato (protocollo e stato per esteso)."""
    out = []
    for r in _leggi(vmm, "/sys/net/netstat-v.txt").splitlines()[2:]:
        m = RETE_RE.match(r)
        if not m:
            continue
        out.append({"pid": int(m.group(2)), "protocollo": m.group(3), "stato": m.group(4), "origine": m.group(5),
                    "destinazione": m.group(6), "processo": m.group(7).strip(), "ora": _iso(m.group(8)),
                    "percorso": m.group(10).strip()})
    return out


ATT_RE = re.compile(r"^(\w{4}) (\{[0-9A-Fa-f-]{36}\}) (.+?)\s{2,}(" + DATA_RE + r"|\*\*\*)\s+(\S+)\s+(.*)$")


def leggi_attivita(vmm):
    out = []
    for r in _leggi(vmm, "/sys/tasks/tasks.txt").splitlines()[2:]:
        m = ATT_RE.match(r)
        if m:
            out.append({"guid": m.group(2), "nome": m.group(3).strip(), "ora": _iso(m.group(4)), "utente": m.group(5),
                        "comando": m.group(6).strip()})
    return out


def leggi_sistema(vmm):
    """Dati del sistema da /sys: dict con nome del computer, versione, date, fuso, hardware, interfacce di rete."""
    s = {"computer": _leggi(vmm, "/sys/computername.txt", 256).strip(),
         "versione": _leggi(vmm, "/sys/version.txt", 64).strip(),
         "architettura": _leggi(vmm, "/sys/architecture.txt", 32).strip(),
         "avvio": _iso(_leggi(vmm, "/sys/time-boot.txt", 64)),
         "acquisizione": _iso(_leggi(vmm, "/sys/time-current.txt", 64)),
         "fuso_windows": _leggi(vmm, "/sys/timezone.txt", 128).strip(),
         "simboli_da_rete": _leggi(vmm, "/conf/config_symbolserver_enable.txt", 8).strip() == "1"}
    info = _leggi(vmm, "/sys/sysinfo/sysinfo.txt", 1 << 20)
    s["testo"] = info.strip()[:8000]
    for chiave, etichetta in (("memoria", "Physical Memory"), ("cpu", "CPU"), ("produttore", "System Vendor"),
                              ("bios", "BIOS Vendor")):
        m = re.search(r"^\s*%s:\s*(.+)$" % re.escape(etichetta), info, re.M)
        if m:
            s[chiave] = m.group(1).strip()
    s["rete"] = [{"campo": a, "valore": b.strip()} for a, b in re.findall(r"^\s{4}(Dhcp\w+|\w*IPAddress\w*|\w*NameServer\w*):\s*(\S.*)$", info, re.M)]
    return s


def _metti(con, conta, cat, ts, titolo, dettaglio="", utente="", fonte="", dati=None):
    con.execute("INSERT INTO artifacts(cat, ts, title, detail, user, src_path, part, inode, data) VALUES (?,?,?,?,?,?,?,?,?)",
                (cat, ts, str(titolo)[:500], str(dettaglio or "")[:4000], utente or "", fonte, None, None,
                 json.dumps(dati, ensure_ascii=False, default=str) if dati else None))
    conta[cat] += 1


_VMM = {}        # dump -> (vmm, scansione completa): una sola apertura per preparazione


def apri(dump, scansione=False):
    """Apre il dump con MemProcFS, senza server dei simboli; scansione=True avvia anche la lettura dell'intera memoria
    (file, MFT, timeline). RamNonDisponibile se il motore manca o non riconosce il dump."""
    m = carica()
    k = str(dump)
    v = _VMM.get(k)
    if v and (v[1] or not scansione):
        return v[0]
    if v:
        chiudi(dump)
    try:
        vmm = m.Vmm(["-device", k, "-disable-symbolserver"] + (["-forensic", "1"] if scansione else []))
    except Exception as e:
        raise RamNonDisponibile(tr("MemProcFS non riconosce questo dump come memoria di un computer Windows "
                                   "(formato non supportato, sistema troppo vecchio o non Windows). [{e}]").format(e=str(e)[:200]))
    _VMM[k] = (vmm, scansione)
    return vmm


def chiudi(dump=None):
    for k in [str(dump)] if dump else list(_VMM):
        v = _VMM.pop(k, None)
        if v:
            try:
                v[0].close()
            except Exception:
                pass


def attendi_scansione(vmm, limite_s=6 * 3600):
    """Aspetta che MemProcFS finisca di leggere tutta la memoria. True se finita."""
    t0 = time.time()
    while time.time() - t0 < limite_s:
        p = _leggi(vmm, "/forensic/progress_percent.txt", 8).strip()
        if p == "100":
            return True
        fa.avanz(None, int(p) if p.isdigit() else 0, 100)
        time.sleep(2)
    return False


# ------------------------------------------------------------------ file ancora presenti in memoria

NOME_OGGETTO = re.compile(r"^[0-9a-f]{16}-")
VIETATI = re.compile(r'[<>:"|?*\x00-\x1f]')
MAX_PERCORSO = 230           # oltre, il file va in _percorsi_lunghi (Windows senza percorsi lunghi non li aprirebbe)
MAX_FILE = 2 << 30           # un file più grande di così non si copia (resta nell'elenco, con la nota)
MAX_RESIDENTE = 1024         # oltre, il contenuto non sta nel record MFT (MemProcFS restituirebbe zeri)
# hive del registro che servono agli artefatti di sistema (programmi eseguiti, USB, utenti, reti...)
HIVE_UTILI = {"system", "software", "sam", "security", "default", "ntuser.dat", "usrclass.dat", "amcache.hve"}


def hive_con_controllo(dato):
    """L'hive ricostruito dalla memoria ha l'intestazione com'era caricata, con il controllo (XOR dei primi 508 byte, al
    byte 508) non aggiornato: le librerie che leggono il registro lo rifiutano. Restituisce (hive con il controllo
    ricalcolato, True se è cambiato). Il resto dell'hive non si tocca."""
    import struct
    if len(dato) < 512 or dato[:4] != b"regf":
        return dato, False
    x = 0
    for (v,) in struct.iter_unpack("<I", dato[:508]):
        x ^= v
    x = 0xFFFFFFFE if x == 0xFFFFFFFF else 1 if x == 0 else x
    if struct.unpack_from("<I", dato, 508)[0] == x:
        return dato, False
    return dato[:508] + struct.pack("<I", x) + dato[512:], True


def hive_in_memoria(vmm):
    """Hive del registro caricati in memoria che servono agli artefatti: [(file in /registry/hive_files, coda del percorso
    in minuscolo con le barre dritte, dimensione)]. Senza simboli MemProcFS conosce solo la coda del percorso (32
    caratteri): il primo pezzo può essere troncato."""
    out = []
    try:
        elenco = list(vmm.reg_hive_list())
    except Exception:
        return out
    try:                       # la dimensione vera è quella del file esposto: h.size non conta l'intestazione (4.096 byte)
        esposti = {n: int(e.get("size") or 0) for n, e in vmm.vfs.list("/registry/hive_files").items()}
    except Exception:
        esposti = {}
    for h in elenco:
        coda =str(getattr(h, "name_short", "") or "").replace("\\", "/").strip().lower()
        if coda.rsplit("/", 1)[-1] in HIVE_UTILI:
            nome = str(getattr(h, "name", "")) + ".reghive"
            out.append((nome, coda, esposti.get(nome) or int(getattr(h, "size", 0) or 0) + 4096))
    return out


def _percorso_hive(coda, noti):
    """Percorso d'origine (minuscolo, con / iniziale) a cui corrisponde la coda di un hive, oppure None se non è
    determinabile senza ambiguità. `noti`: percorsi d'origine già in elenco."""
    if "/" not in coda:                                    # SYSTEM: MemProcFS ne dà solo il nome
        return "/windows/system32/config/" + coda if coda in ("system", "software", "sam", "security", "default") else None
    if coda.startswith("/systemroot/"):
        return "/windows/" + coda[len("/systemroot/"):]
    for prova in (coda.lstrip("/"), coda.lstrip("/").split("/", 1)[-1]):     # coda intera, poi senza il primo pezzo (troncato)
        trovati = [k for k in noti if k.endswith("/" + prova)]
        if len(trovati) == 1:
            return trovati[0]
        if len(trovati) > 1:
            return None
    resto = coda.lstrip("/").split("/", 1)[-1]
    return "/windows/" + resto if resto.startswith("system32/config/") else None


def date_mft(vmm):
    """{percorso minuscolo: (creazione, modifica)} dai record MFT trovati in memoria (/forensic/ntfs/ntfs_files.txt)."""
    out = {}
    riga = re.compile(r"^\s*[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+(" + DATA_RE + r"|\*\*\*) : (" + DATA_RE +
                      r"|\*\*\*)\s+[0-9a-f]+\s+.{4}\s\\[0-9a-f]+(\\.*)$")
    for r in _leggi_tutto(vmm, "/forensic/ntfs/ntfs_files.txt").splitlines():
        m = riga.match(r)
        if m and (m.group(1) != "***" or m.group(2) != "***"):
            out.setdefault(m.group(3).replace("\\", "/").lower(), (_iso(m.group(1)), _iso(m.group(2))))
    return out


def _epoca(iso):
    if not iso:
        return None
    try:
        return dt.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc).timestamp()
    except ValueError:
        return None


def _coda_a_zero(f, da):
    """True se dal byte `da` alla fine il file contiene solo zeri."""
    try:
        with open(f, "rb") as fh:
            fh.seek(da)
            while b := fh.read(1 << 20):
                if b.strip(b"\0"):
                    return False
        return True
    except OSError:
        return False


def estrai(case, dump, say=print):
    """Copia derivata dei file ancora presenti in memoria (estratta/memoria/, sola lettura) + elenco con le date dei
    record MFT (.voci.json), nel formato delle sorgenti logiche. I file sono spesso INCOMPLETI: le pagine non più in
    memoria mancano (MemProcFS le riempie di zeri). Restituisce (cartella, riferimenti)."""
    ok, ver = disponibile()
    if not ok:
        raise OSError(ver)
    say(tr("Lettura dell'intera memoria con MemProcFS {v} (file, MFT, timeline; senza server dei simboli)…").format(v=ver))
    fa.avanz("ram")
    vmm = apri(dump, scansione=True)
    if not attendi_scansione(vmm):
        raise OSError(tr("MemProcFS non ha finito di leggere la memoria nel tempo previsto."))
    date = date_mft(vmm)
    trovati = []                       # (percorso in MemProcFS, parti del percorso, dimensione)

    def scendi(v, parti):
        try:
            voci = vmm.vfs.list(v)
        except Exception:
            return
        for nome in sorted(voci):
            e = voci[nome]
            if e.get("f_isdir"):
                scendi(v + "/" + nome, parti + [nome])
            else:
                trovati.append((v + "/" + nome, parti + [nome], int(e.get("size") or 0)))
    scendi("/forensic/files/ROOT", [])
    tot = sum(s for _v, _p, s in trovati if s <= MAX_FILE)
    dest = case.root / "estratta"
    dest.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(dest).free < tot * 1.05 + (2 << 30):
        raise OSError(tr("Spazio insufficiente per la copia dei file in memoria: servono circa {v:.1f} GB.").format(v=tot * 1.05 / 1e9))
    out = dest / "memoria"
    if out.exists():
        fa.rmtree_force(out)
    out.mkdir()
    say(tr("Copia dei file ancora presenti in memoria: {n} file, {g:.1f} GB (copia derivata; spesso incompleti)…").format(n=len(trovati), g=tot / 1e9))
    voci, usati, fatti, saltati = [], set(), 0, 0
    conta = {"lunghi": 0}

    def colloca(parti, cartella=False):
        """Percorso nella copia: nomi ripuliti, senza doppioni, accorciato se troppo lungo per Windows."""
        pulite = [VIETATI.sub("_", NOME_OGGETTO.sub("", x)).rstrip(". ") or "_" for x in parti]
        rel = "/".join(pulite)
        if rel.lower() in usati:                                   # stesso file aperto più volte: resta l'indirizzo dell'oggetto
            base, punto, est = pulite[-1].rpartition(".")
            agg = "~" + (parti[-1][10:16] if NOME_OGGETTO.match(parti[-1]) else str(len(usati)))
            pulite[-1] = (base + agg + punto + est) if punto and not cartella else pulite[-1] + agg
            rel = "/".join(pulite)
        if not cartella and len(str(out)) + 1 + len(rel) > MAX_PERCORSO:
            conta["lunghi"] += 1
            rel = "_percorsi_lunghi/%05d_%s" % (conta["lunghi"], pulite[-1][-80:])
        usati.add(rel.lower())
        return rel

    per_orig = {}                      # percorso d'origine minuscolo -> voce (per unire i record MFT)
    for vp, parti, size in trovati:
        rel = colloca(parti)
        orig = "/" + "/".join(NOME_OGGETTO.sub("", x) for x in parti)
        cre, mod = date.get(orig.lower(), (None, None))
        nota = None
        f = out / rel
        scritti = 0
        if size > MAX_FILE:
            saltati += 1
            nota = "troppo grande: non copiato"
        else:
            f.parent.mkdir(parents=True, exist_ok=True)
            with open(f, "wb") as fh:
                while scritti < size:
                    try:
                        b = vmm.vfs.read(vp, min(4 << 20, size - scritti), scritti)
                    except Exception:
                        b = b""
                    if not b:
                        break
                    fh.write(b)
                    scritti += len(b)
            try:
                if mod:
                    os.utime(f, (_epoca(mod), _epoca(mod)))
                os.chmod(f, 0o444)
            except (OSError, TypeError):
                pass
        voci.append({"path": rel, "isdir": False, "size": scritti, "csize": size, "method": 0, "loc": 0, "mode": 0,
                     "times": {k: v for k, v in (("B", _epoca(cre)), ("M", _epoca(mod))) if v}, "dos": None, "dsrc": "memoria",
                     "cifrato": False, "crc": None, "memoria": orig, "oggetto": parti[-1][:16], "nota": nota})
        per_orig.setdefault(orig.lower(), voci[-1])
        fatti += scritti
        fa.avanz(None, fatti, tot, "B")
    # record MFT trovati in memoria: nome, date e dimensione di file e cartelle; il contenuto c'è solo per i file
    # piccoli (residenti nel record). I file non residenti restano nell'elenco a 0 byte, con la dimensione registrata.
    say(tr("Record MFT in memoria: file e cartelle con nome, date e dimensione…"))
    n_mft = n_res = n_cart = n_tronc = 0
    pila = []
    try:
        for vol in sorted(vmm.vfs.list("/forensic/ntfs")):
            if vmm.vfs.list("/forensic/ntfs").get(vol, {}).get("f_isdir"):
                pila.append(("/forensic/ntfs/" + vol, []))
    except Exception:
        pila = []
    while pila:
        v, parti = pila.pop()
        try:
            elenco = vmm.vfs.list(v)
        except Exception:
            continue
        for nome in sorted(elenco):
            if nome == "$_INFO":
                continue
            e = elenco[nome]
            orig = "/" + "/".join(parti + [nome])
            cre, mod = date.get(orig.lower(), (None, None))
            tempi = {k: x for k, x in (("B", _epoca(cre)), ("M", _epoca(mod))) if x}
            if e.get("f_isdir"):
                pila.append((v + "/" + nome, parti + [nome]))
                if orig.lower() not in per_orig and parti + [nome] != ["$_ORPHAN"]:
                    n_cart += 1
                    voci.append({"path": colloca(parti + [nome], True), "isdir": True, "size": 0, "csize": 0, "method": 0, "loc": 0,
                                 "mode": 0, "times": tempi, "dos": None, "dsrc": "mft", "cifrato": False, "crc": None, "memoria": orig})
                    per_orig[orig.lower()] = voci[-1]
                continue
            size = int(e.get("size") or 0)
            dato = b""
            if 0 < size <= MAX_RESIDENTE:
                try:
                    dato = vmm.vfs.read(v + "/" + nome, size, 0)
                except Exception:
                    dato = b""
                if not dato.strip(b"\0"):
                    dato = b""
            gia = per_orig.get(orig.lower())
            if gia is not None:                     # c'è già l'oggetto file: il record aggiunge dimensione e, se vuoto, contenuto
                gia["csize"] = max(int(gia.get("csize") or 0), size)
                # la cache di Windows arrotonda il file a blocchi (es. 262.144 byte) e riempie di zeri: se il record MFT
                # dice la dimensione vera e dopo ci sono solo zeri, la copia si ferma alla dimensione vera
                if 0 < size < gia["size"] and gia["dsrc"] == "memoria" and _coda_a_zero(out / gia["path"], size):
                    f = out / gia["path"]
                    try:
                        os.chmod(f, 0o644)
                        with open(f, "r+b") as fh:
                            fh.truncate(size)
                        os.chmod(f, 0o444)
                        fatti -= gia["size"] - size
                        gia["size"] = size
                        n_tronc += 1
                    except OSError:
                        pass
                if dato and not gia["size"]:
                    f = out / gia["path"]
                    try:
                        if f.exists():
                            os.chmod(f, 0o644)
                        f.parent.mkdir(parents=True, exist_ok=True)
                        f.write_bytes(dato)
                        os.chmod(f, 0o444)
                        gia["size"], gia["dsrc"] = len(dato), "mft_res"
                        n_res += 1
                        fatti += len(dato)
                    except OSError:
                        pass
                continue
            rel = colloca(parti + [nome])
            scritti = 0
            if dato:
                f = out / rel
                try:
                    f.parent.mkdir(parents=True, exist_ok=True)
                    f.write_bytes(dato)
                    if mod:
                        os.utime(f, (_epoca(mod), _epoca(mod)))
                    os.chmod(f, 0o444)
                    scritti = len(dato)
                    n_res += 1
                    fatti += scritti
                except (OSError, TypeError):
                    scritti = 0
            n_mft += 1
            voci.append({"path": rel, "isdir": False, "size": scritti, "csize": size, "method": 0, "loc": 0, "mode": 0, "times": tempi,
                         "dos": None, "dsrc": "mft_res" if scritti else "mft", "cifrato": False, "crc": None, "memoria": orig})
            per_orig[orig.lower()] = voci[-1]
    # hive del registro: Windows li tiene caricati in memoria e MemProcFS li ricostruisce da lì, di solito più completi
    # della copia rimasta nella cache dei file. Sostituiscono (o aggiungono) il file corrispondente: così gli artefatti
    # di sistema si leggono dal registro com'era in memoria al momento dell'acquisizione.
    say(tr("Registro di Windows in memoria: hive caricati..."))
    hive_fatti, per_file = [], {}
    for nome, coda, size in hive_in_memoria(vmm):
        dove = _percorso_hive(coda, per_orig)
        if dove and size >= 4096 and size > per_file.get(dove, ("", 0))[1]:
            per_file[dove] = (nome, size)
    for dove, (nome, size) in sorted(per_file.items()):
        pezzi, letti = [], 0
        while letti < size:
            try:
                b = vmm.vfs.read("/registry/hive_files/" + nome, min(4 << 20, size - letti), letti)
            except Exception:
                b = b""
            if not b:
                break
            pezzi.append(b)
            letti += len(b)
        dato = b"".join(pezzi)
        if dato[:4] != b"regf":
            continue
        dato, corretto = hive_con_controllo(dato)
        gia = per_orig.get(dove)
        if gia is None:
            parti = [x for x in dove.strip("/").split("/")]
            parti = ["Windows", "System32", "config", parti[-1].upper()] if dove.startswith("/windows/system32/config/") else parti
            gia = {"path": colloca(parti), "isdir": False, "size": 0, "csize": 0, "method": 0, "loc": 0, "mode": 0, "times": {}, "dos": None,
                   "dsrc": "memoria", "cifrato": False, "crc": None, "memoria": "/" + "/".join(parti)}
            voci.append(gia)
            per_orig[dove] = gia
        f = out / gia["path"]
        try:
            if f.exists():
                os.chmod(f, 0o644)
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(dato)
            os.chmod(f, 0o444)
        except OSError:
            continue
        hive_fatti.append({"file": gia["path"], "byte": len(dato), "prima": gia["size"], "hive": nome, "controllo_intestazione_ricalcolato": corretto})
        fatti += len(dato) - gia["size"]
        gia["size"], gia["csize"], gia["dsrc"] = len(dato), max(int(gia.get("csize") or 0), len(dato)), "memoria"
    lunghi = conta["lunghi"]
    sha = case.meta.get("sha256")
    rif = {"origine": str(dump), "sha256_origine": sha.get(Path(dump).name) if isinstance(sha, dict) else sha,
           "operazione": "MemProcFS /forensic/files", "strumento": f"MemProcFS {ver}", "voci": len(voci), "byte": fatti,
           "non_copiati": saltati, "percorsi_accorciati": lunghi, "con_date_mft": sum(1 for v in voci if v["times"]),
           "oggetti_file": len(trovati), "solo_record_mft": n_mft, "cartelle_mft": n_cart, "contenuto_dal_record_mft": n_res,
           "riportati_alla_dimensione_del_record": n_tronc, "hive_del_registro": hive_fatti,
           "incompleti": True, "creata": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    Path(str(out) + ".json").write_text(json.dumps(rif, indent=1), encoding="utf-8")
    Path(str(out) + ".voci.json").write_text(json.dumps(voci, ensure_ascii=False), encoding="utf-8")
    return out, rif


# ------------------------------------------------------------------ registro letto dalla memoria, chiave per chiave
#
# Gli hive ricostruiti dalla memoria hanno spesso pagine mancanti e libregf li rifiuta interi (SOFTWARE) o non ne ricava
# nulla. MemProcFS invece legge le singole chiavi e salta ciò che manca. Queste due classi danno alle chiavi di MemProcFS
# gli stessi nomi che il codice degli artefatti usa con libregf (pyregf): così programmi, utenti, reti, USB, UserAssist,
# ShimCache, BAM… si leggono con lo stesso codice dei dischi, senza copiarlo.

class ValoreMem:
    def __init__(self, v):
        self._v = v
        self.name = "" if v.name == "(Default)" else v.name
        self.type = v.type

    @property
    def data(self):
        try:
            d = self._v.value
            return d() if callable(d) else d
        except Exception:
            return b""

    def get_data_as_string(self):
        return self.data.decode("utf-16-le", "replace").split("\0", 1)[0]

    def get_data_as_integer(self):
        d = self.data
        return int.from_bytes(d[:8] if self.type == 11 else d[:4], "big" if self.type == 5 else "little")

    def get_data_as_multi_string(self):
        return [x for x in self.data.decode("utf-16-le", "replace").split("\0") if x]


class ChiaveMem:
    def __init__(self, k):
        self._k = k
        self.name = k.name

    def _figli(self):
        try:
            return list(self._k.subkeys())
        except Exception:
            return []

    def _valori(self):
        try:
            return list(self._k.values())
        except Exception:
            return []

    @property
    def sub_keys(self):
        return [ChiaveMem(x) for x in self._figli()]

    @property
    def values(self):
        return [ValoreMem(x) for x in self._valori()]

    @property
    def number_of_sub_keys(self):
        return len(self._figli())

    @property
    def number_of_values(self):
        return len(self._valori())

    def get_sub_key(self, i):
        return ChiaveMem(self._figli()[i])

    def get_value(self, i):
        return ValoreMem(self._valori()[i])

    def get_sub_key_by_name(self, nome):
        n = str(nome).lower()
        for x in self._figli():
            if x.name.lower() == n:
                return ChiaveMem(x)
        return None

    def get_sub_key_by_path(self, percorso):
        k = self
        for pezzo in [p for p in str(percorso).replace("/", "\\").split("\\") if p]:
            k = k.get_sub_key_by_name(pezzo)
            if k is None:
                return None
        return k

    def get_value_by_name(self, nome):
        n = (nome or "").lower()
        for x in self._valori():
            if ("" if x.name == "(Default)" else x.name).lower() == n:
                return ValoreMem(x)
        return None

    def get_last_written_time_as_integer(self):
        return int(getattr(self._k, "time_int", 0) or 0)

    get_written_time_as_integer = get_last_written_time_as_integer

    @property
    def last_written_time(self):
        ft = self.get_last_written_time_as_integer()
        return dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=ft // 10) if ft else None


def radice_registro(vmm, hive_fatti):
    """Funzione percorso-del-file -> radice dell'hive letta dalla memoria (ChiaveMem) oppure None. SYSTEM, SOFTWARE,
    SECURITY e SAM da HKLM; gli hive degli utenti dalla loro radice, se l'hive è tra quelli messi nel caso."""
    try:
        per_nome = {str(h.name) + ".reghive": h for h in vmm.reg_hive_list()}
    except Exception:
        per_nome = {}
    per_file = {str(x.get("file", "")).lower(): per_nome.get(x.get("hive")) for x in hive_fatti or []}

    def radice(percorso):
        p = str(percorso).replace("\\", "/").lower().lstrip("/")
        base = p.rsplit("/", 1)[-1]
        try:
            if p.endswith("system32/config/" + base) and base in ("system", "software", "security", "sam"):
                k = vmm.reg_key("HKLM\\" + base.upper())
            else:
                h = per_file.get(p)
                if h is None:
                    return None
                k = h.rootkey
            if not k.subkeys():
                return None
            return ChiaveMem(k)
        except Exception:
            return None
    return radice


SERVIZI_AVVIO = {0: N_("all'avvio del sistema (boot)"), 1: N_("dal sistema"), 2: N_("automatico"), 3: N_("manuale"), 4: N_("disattivato")}


def leggi_servizi(vmm):
    """Servizi di Windows dal registro in memoria (HKLM\\SYSTEM\\<ControlSet>\\Services), senza i simboli di debug: solo
    i servizi veri e propri (tipo 0x10, 0x20 e loro varianti), non i driver. Lista di dict."""
    out = []
    try:
        radice = ChiaveMem(vmm.reg_key("HKLM\\SYSTEM"))
    except Exception:
        return out
    cs = None
    for s in radice.sub_keys:
        if re.fullmatch(r"(?i)ControlSet\d+", s.name):
            cs = cs or s
    servizi = cs.get_sub_key_by_name("Services") if cs else None
    for k in (servizi.sub_keys if servizi else []):
        def val(nome, intero=False):
            v = k.get_value_by_name(nome)
            if v is None:
                return None
            try:
                return v.get_data_as_integer() if intero else v.get_data_as_string()
            except Exception:
                return None
        tipo = val("Type", True)
        if not tipo or not tipo & 0x30:
            continue
        t = k.last_written_time
        dll = ""
        try:
            par = k.get_sub_key_by_name("Parameters")
            v = par.get_value_by_name("ServiceDll") if par else None
            dll = (v.get_data_as_string() or "") if v is not None else ""
        except Exception:
            dll = ""
        out.append({"nome": k.name, "nome_mostrato": val("DisplayName") or "", "percorso": val("ImagePath") or "", "dll": dll, "avvio": val("Start", True),
                    "utente": val("ObjectName") or "", "tipo": tipo, "chiave_scritta": t.strftime("%Y-%m-%dT%H:%M:%S") if t else None,
                    "insieme": cs.name})
    return sorted(out, key=lambda d: d["nome"].lower())


# ------------------------------------------------------------------ simboli di debug di Windows (solo su richiesta)
#
# Alcune funzioni di MemProcFS (lo stato dei servizi, tra le altre) hanno bisogno dei simboli di debug del Windows del
# dump, che Microsoft pubblica sul suo server dei simboli. Durante l'analisi di un caso RepertIA non va mai in rete: i
# simboli si scaricano solo dalla pagina iniziale, senza un caso aperto, dopo che l'analista ha accettato le condizioni
# di Microsoft. Restano in una cartella locale (Symbols, accanto al motore) e da lì MemProcFS li usa anche senza rete.
# Al server arrivano solo nome e identificativo dei file di simboli richiesti (dicono quale versione di Windows è),
# non il contenuto del dump. I file dei simboli non si ridistribuiscono (licenza Microsoft): non entrano nei pacchetti.

SIMBOLI_NOTA = "repertia_simboli.json"


def cartella_motore():
    """Cartella della libreria di MemProcFS (con vmm, il file che scarica i simboli e Symbols)."""
    m = carica()
    return Path(getattr(m, "CARTELLA", None) or Path(m.__file__).parent).resolve()


def _scarica_simboli_file(motore):
    """Il file della libreria che sa scaricare i simboli: symsrv.dll su Windows, libpdbcrust su Linux e Mac. None se manca."""
    for nome in ("symsrv.dll", "libpdbcrust.so", "libpdbcrust2.so", "libpdbcrust.dylib"):
        if (motore / nome).is_file():
            return motore / nome
    return None


def _motore_scrivibile(motore):
    """Vero se nella cartella del motore si può scrivere (lì stanno Symbols e il consenso alle condizioni)."""
    if sys.platform != "win32":
        return os.access(motore, os.W_OK)
    import tempfile
    try:                                # su Windows os.access non basta per le cartelle
        with tempfile.NamedTemporaryFile(dir=motore, prefix=".prova_scrittura_"):
            return True
    except OSError:
        return False


def simboli_non_salvabili(motore, scrivibile=None):
    """(3.0.4) Perché i simboli non si possono salvare accanto al motore; stringa vuota se si può. Il caso tipico è
    il Mac: un'app scaricata e aperta senza essere stata spostata gira da una copia temporanea di sola lettura
    («App Translocation»), e lo scarico finiva con «Read-only file system»."""
    if _motore_scrivibile(motore) if scrivibile is None else scrivibile:
        return ""
    if "/AppTranslocation/" in Path(motore).as_posix():
        return tr("macOS sta eseguendo RepertIA da una posizione temporanea di sola lettura, quindi i simboli non si possono "
                  "salvare. Chiudi RepertIA, sposta RepertIA.app con il Finder in Applicazioni o in un'altra cartella e riaprila.")
    return tr("RepertIA non può scrivere nella cartella in cui salva i simboli ({c}). Sposta RepertIA in una cartella in "
              "cui il tuo utente può scrivere e riaprila.").format(c=motore)


def simboli_stato():
    """Simboli già scaricati e se lo scarico è possibile, senza aprire nulla e senza rete."""
    try:
        motore = cartella_motore()
    except RamNonDisponibile as e:
        return {"disponibile": False, "motivo": str(e), "file": 0, "byte": 0, "scarichi": []}
    cache = motore / "Symbols"
    pdb = [p for p in cache.rglob("*.pdb") if p.is_file()] if cache.is_dir() else []       # c'è anche una cartella con quel nome
    try:
        nota = json.loads((cache / SIMBOLI_NOTA).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        nota = []
    motivo = ("" if _scarica_simboli_file(motore) else tr("In questa installazione manca il file che scarica i simboli "
                                                           "(symsrv.dll).")) or simboli_non_salvabili(motore)
    return {"disponibile": not motivo, "motivo": motivo, "scrivibile": not simboli_non_salvabili(motore),
            "cartella": str(cache), "condizioni": str(next((motore / n for n in ("license_dbghelp.txt", "license_libpdbcrust.txt") if (motore / n).is_file()), motore / "LICENSE.txt")), "file": len(pdb),
            "byte": sum(p.stat().st_size for p in pdb), "accettate": (motore / "symsrv.yes").exists(), "scarichi": nota[-20:]}


def _pdb_in_cache(cache):
    return {str(p.relative_to(cache)).replace("\\", "/"): p.stat().st_size for p in cache.rglob("*.pdb") if p.is_file()} if cache.is_dir() else {}


def scarica_simboli(dump, accetto, progress=None):
    """Apre il dump con il server dei simboli di Microsoft ATTIVO, una volta, per far scaricare a MemProcFS i simboli di
    quel Windows nella cartella locale. Solo dalla pagina iniziale, senza un caso aperto, con il consenso dell'analista
    alle condizioni di Microsoft. Restituisce che cosa è stato scaricato (nomi, dimensioni, SHA-256)."""
    import hashlib
    if accetto is not True:
        raise ValueError(tr("Lo scarico dei simboli richiede che l'analista accetti le condizioni di Microsoft."))
    dump = Path(dump)
    if not dump.is_file():
        raise ValueError(tr("File del dump non trovato."))
    m = carica()
    motore = cartella_motore()
    if not _scarica_simboli_file(motore):
        raise OSError(tr("In questa installazione manca il file che scarica i simboli (symsrv.dll)."))
    if simboli_non_salvabili(motore):
        raise OSError(simboli_non_salvabili(motore))
    chiudi()
    if getattr(m, "SCARICO_SIMBOLI", "") == "impedito":
        # Mac e Linux: in questo processo la libreria non può più usare la rete (forense_vmm.impedisci_scarico_simboli)
        return _scarica_simboli_a_parte(dump, progress)
    cache = motore / "Symbols"
    cache.mkdir(exist_ok=True)
    prima = _pdb_in_cache(cache)
    (motore / "symsrv.no").unlink(missing_ok=True)
    (motore / "symsrv.yes").write_bytes(b"")          # consenso alle condizioni: senza, symsrv aprirebbe una sua finestra
    dice = progress or (lambda *_: None)
    dice({"msg": tr("Apertura del dump e richiesta dei simboli a Microsoft…")})
    try:
        vmm = m.Vmm(["-device", str(dump), "-waitinitialize"])
    except Exception as e:
        raise RamNonDisponibile(tr("MemProcFS non riconosce questo dump come memoria di un computer Windows "
                                   "(formato non supportato, sistema troppo vecchio o non Windows). [{e}]").format(e=str(e)[:200]))
    try:
        s = leggi_sistema(vmm)
        fermo, ultimo, righe, t0 = 0, -1, 0, time.time()
        while fermo < 8 and time.time() - t0 < 600:            # finché arrivano file nuovi (fermo = 16 secondi senza novità)
            for f in ("/sys/services/services.txt", "/sys/proc/proc.txt", "/sys/net/netstat-v.txt", "/sys/drivers/drivers.txt"):
                _leggi(vmm, f, 1 << 16)
            righe = len([r for r in _leggi(vmm, "/sys/services/services.txt").splitlines()[2:] if r.strip()])
            n = sum(_pdb_in_cache(cache).values())
            fermo = fermo + 1 if n == ultimo else 0
            ultimo = n
            dice({"msg": tr("Simboli scaricati finora: {n} MB").format(n=round(n / 1e6, 1)), "fatti": n})
            time.sleep(2)
        if not righe:                       # Mac e Linux: l'elenco di MemProcFS resta vuoto, lo legge RepertIA
            righe = len(leggi_servizi_memoria(vmm, s))
    finally:
        try:
            vmm.close()
        except Exception:
            pass
    nuovi = []
    for rel, size in sorted(_pdb_in_cache(cache).items()):
        if prima.get(rel) != size:
            nuovi.append({"file": rel, "byte": size, "sha256": hashlib.sha256((cache / rel).read_bytes()).hexdigest()})
    esito = {"ts": fa.now(), "server": "https://msdl.microsoft.com/download/symbols", "windows": s.get("versione"), "computer": s.get("computer"),
             "dump": dump.name, "scaricati": nuovi, "byte": sum(x["byte"] for x in nuovi), "servizi_letti": righe}
    try:
        nota = json.loads((cache / SIMBOLI_NOTA).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        nota = []
    (cache / SIMBOLI_NOTA).write_text(json.dumps(nota + [esito], indent=1, ensure_ascii=False), encoding="utf-8")
    return esito


def _scarica_simboli_a_parte(dump, progress=None):
    """Lo scarico dei simboli in un altro processo Python, avviato con REPERTIA_RAM_RETE_SIMBOLI=1: è l'unico in cui
    libpdbcrust può raggiungere Microsoft. Avanzamento ed esito arrivano come righe JSON sull'uscita standard."""
    import subprocess
    import forense_vmm
    codice = ("import sys, json; sys.path.insert(0, sys.argv[1]); import forense_agent, forense_ram as fr\n"
              "def dice(d): print(json.dumps({'fatti': d.get('fatti')}), flush=True)\n"
              "try:\n"
              "    print(json.dumps({'esito': fr.scarica_simboli(sys.argv[2], True, dice)}), flush=True)\n"
              "except Exception as e:\n"
              "    print(json.dumps({'errore': str(e)[:400], 'tipo': type(e).__name__}), flush=True)\n")
    amb = dict(os.environ, PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1")
    amb[forense_vmm.RETE_SIMBOLI_ENV] = "1"
    amb["REPERTIA_MEMPROCFS"] = str(cartella_motore().parent)
    dice = progress or (lambda *_: None)
    dice({"msg": tr("Apertura del dump e richiesta dei simboli a Microsoft…")})
    esito = errore = None
    with subprocess.Popen([sys.executable, "-c", codice, str(HERE), str(dump)], env=amb, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True, encoding="utf-8") as pr:
        for riga in pr.stdout:
            try:
                d = json.loads(riga)
            except ValueError:
                continue
            if d.get("fatti") is not None:
                dice({"msg": tr("Simboli scaricati finora: {n} MB").format(n=round(d["fatti"] / 1e6, 1)), "fatti": d["fatti"]})
            esito, errore = d.get("esito") or esito, d if d.get("errore") else errore
    if esito is None:
        if errore and errore.get("tipo") == "RamNonDisponibile":
            raise RamNonDisponibile(errore["errore"])
        raise OSError(errore["errore"] if errore else tr("Lo scarico dei simboli si è interrotto."))
    return esito


def leggi_servizi_memoria(vmm, sistema):
    """Servizi con lo stato letti da RepertIA nella memoria di services.exe (forense_ram_servizi.py), quando MemProcFS
    non dà il suo elenco: succede su Mac e Linux, anche con i simboli nella cartella locale. Stessi campi di
    leggi_servizi_stato; lista vuota se i simboli non ci sono o un controllo non passa. Mai rete."""
    m = carica()
    if getattr(m, "__name__", "") != "forense_vmm" or sys.platform == "win32":
        return []
    try:
        import forense_ram_servizi
        build = int(str(sistema.get("versione") or "0").split(".")[-1])
        utenti = {p["pid"]: p.get("utente", "") for p in leggi_processi(vmm)}
        percorsi = {d["nome"].lower(): d.get("dll") or d["percorso"] for d in leggi_servizi(vmm)}
        righe, _motivo = forense_ram_servizi.leggi(vmm, cartella_motore(), build, sistema.get("architettura"), utenti, percorsi)
        return righe
    except Exception:
        return []


def leggi_servizi_stato(vmm):
    """Servizi con lo stato di esecuzione dall'elenco di MemProcFS (c'è solo con i simboli nella cartella locale).
    Lista di dict; vuota se l'elenco non c'è. Le colonne si prendono dalla riga d'intestazione, a larghezza fissa."""
    righe = _leggi(vmm, "/sys/services/services.txt", 16 << 20).splitlines()
    if len(righe) < 3:
        return []
    t = righe[0]
    c = {"avvio": t.find("Start Type"), "nome": t.find("Name / Display Name"), "utente": t.find("User", t.find("Name / Display Name")),
         "percorso": t.find("Image Path"), "comando": t.find("Object Name")}
    c["stato"] = t.find("State", c["avvio"] + 10)
    c["tipo"] = t.find("Type", c["stato"] + 5)
    c["oggetto"] = t.find("Obj Address")
    if min(c.values()) < 0:
        return []
    out = []
    for r in righe[2:]:
        m = re.match(r"^\s*[0-9a-fA-F]+\s+(\d+)\s", r)
        if not m:
            continue
        nome, _, mostrato = r[c["nome"]:c["utente"]].strip().partition(" / ")
        percorso, _, comando = r[c["percorso"]:].partition("::")            # «percorso :: oggetto o riga di comando»
        utente = r[c["utente"]:c["percorso"]].strip()
        out.append({"pid": int(m.group(1)), "avvio": r[c["avvio"]:c["stato"]].strip(), "stato": r[c["stato"]:c["tipo"]].strip(),
                    "tipo": " ".join(r[c["tipo"]:c["oggetto"]].split()), "nome": nome.strip(), "nome_mostrato": mostrato.strip(),
                    "utente": "" if utente == "---" else utente, "percorso": percorso.strip(), "comando": comando.strip()})
    return out


# ------------------------------------------------------------------ timeline della memoria

TL_RE = re.compile(r"^(" + DATA_RE + r")\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s(.*)$")
TL_FONTI = {"NTFS": N_("File NTFS (record MFT in memoria)"), "REG": N_("Registro (chiavi modificate)"),
            "EVTX": N_("Registri eventi di Windows"), "PROC": N_("Processi"), "NET": N_("Rete"),
            "SHTASK": N_("Attività pianificate"), "WEB": N_("Cronologia web"), "AMCACHE": N_("Amcache"), "AMCA": N_("Amcache"),
            "PREFETCH": N_("Prefetch"), "KOBJ": N_("Oggetti del kernel")}
TL_AZIONI = {"CRE": N_("creazione"), "MOD": N_("modifica"), "DEL": N_("eliminazione"), "RD": N_("lettura"), "---": N_("evento")}


def timeline(vmm, con, say=print):
    """Eventi della timeline di MemProcFS (già in UTC) nella tabella events, origine 'ram'. I thread non si importano."""
    con.execute("DELETE FROM events WHERE origin='ram'")
    conta, batch, resto, pos = Counter(), [], b"", 0
    try:
        size = int(vmm.vfs.list("/forensic/timeline")["timeline_all.txt"]["size"])
    except Exception:
        return {}

    def riga(r):
        m = TL_RE.match(r)
        if not m:
            return
        tipo = m.group(2).upper()
        if tipo in ("THREAD", "NTFS"):      # NTFS: le date dei record MFT sono già eventi dei file dell'elenco
            return
        testo = m.group(7).strip()
        pid = m.group(4)
        # percorso solo per i file (senza il numero del volume): è quello che la Timeline prova ad aprire nell'albero
        percorso = ""
        batch.append((_iso(m.group(1)), tr(TL_AZIONI.get(m.group(3), m.group(3))), tr(TL_FONTI.get(tipo, tipo)), percorso[:1000],
                      (testo + (f" | PID {pid}" if tipo in ("PROC", "NET", "WEB", "EVTX") and pid != "0" else ""))[:2000], "ram", None))
        conta[tipo] += 1
    while pos < size:
        try:
            b = vmm.vfs.read("/forensic/timeline/timeline_all.txt", min(8 << 20, size - pos), pos)
        except Exception:
            break
        if not b:
            break
        pos += len(b)
        righe = (resto + b).split(b"\n")
        resto = righe.pop()
        for r in righe:
            riga(r.decode("utf-8", "replace"))
        if len(batch) >= 50000:
            con.executemany(fa.INSERT_EV, batch)
            batch.clear()
        fa.avanz(None, pos, size, "B")
    if resto:
        riga(resto.decode("utf-8", "replace"))
    con.executemany(fa.INSERT_EV, batch)
    con.commit()
    return dict(conta)


def run(case, con, say=print):
    """Analizza il dump del caso e riempie `artifacts`. Restituisce l'esito (dict) oppure None."""
    import forense_estesa as fe
    dump = Path(case.meta.get("evidence") or case.meta.get("image") or "")
    if not dump.exists():
        say(tr("Dump della memoria non raggiungibile: {p}. Collega il disco che lo contiene.").format(p=dump))
        return None
    ok, ver = disponibile()
    if not ok:
        say(ver)
        return None
    say(tr("Analisi della memoria RAM con MemProcFS {v} (senza server dei simboli)...").format(v=ver))
    completa = bool(_VMM.get(str(dump), (None, False))[1])        # già aperto con la scansione (preparazione)
    try:
        vmm = apri(dump)
    except RamNonDisponibile as e:
        say(str(e))
        return None
    fe.ensure_schema(con)
    con.execute("DELETE FROM artifacts WHERE src_path LIKE 'RAM:%'")
    n, avvisi = Counter(), []
    try:
        s = leggi_sistema(vmm)
        if s["simboli_da_rete"]:
            avvisi.append(tr("ATTENZIONE: il server dei simboli risulta attivo."))
        fonte = "RAM: /sys"
        _metti(con, n, "sistema", s["acquisizione"], tr("Memoria RAM di {c}: Windows {v}").format(c=s["computer"] or "?", v=s["versione"] or "?"),
               tr("acquisizione {a} UTC · avvio del sistema {b} UTC · fuso {f} · {m}").format(
                   a=(s["acquisizione"] or "?").replace("T", " "), b=(s["avvio"] or "?").replace("T", " "),
                   f=s["fuso_windows"] or "?", m=s.get("memoria") or s["architettura"]), "", fonte, s)
        if s["avvio"]:
            _metti(con, n, "sistema", s["avvio"], tr("Avvio del sistema"), s["computer"], "", fonte)
        for r in s["rete"]:
            _metti(con, n, "reti", None, f"{r['campo']}: {r['valore']}", tr("interfaccia di rete (dal registro in memoria)"), "", fonte)
        try:
            utenti = vmm.maps.user()
        except Exception:
            utenti = []
        sid_nome = {u.get("sid"): u.get("name") for u in utenti}
        for u in utenti:
            _metti(con, n, "utenti", None, tr("Account {name}").format(name=u.get("name")), f"SID {u.get('sid')}", u.get("name"),
                   "RAM: /sys/users", {"sid": u.get("sid")})
        say(tr("  processi..."))
        processi = leggi_processi(vmm)
        for d in processi:
            utente = d.get("utente") or sid_nome.get(d.get("sid")) or ""
            stato = "" if d["attivo"] else tr(" [terminato]")
            dett = d.get("comando") or d.get("percorso") or d.get("percorso_kernel") or ""
            dett += tr(" · padre {p} (PID {i})").format(p=d.get("padre") or tr("non più presente"), i=d.get("ppid"))
            if d.get("fine"):
                dett += tr(" · terminato {t} UTC").format(t=d["fine"].replace("T", " "))
            if d.get("integrita") is not None:
                d["integrita_nome"] = INTEGRITA.get(d["integrita"], str(d["integrita"]))
            _metti(con, n, "processi", d.get("avvio"), f"{d.get('nome_lungo') or d.get('nome')} (PID {d['pid']}){stato}", dett, utente,
                   f"RAM: /pid/{d['pid']}", d)
        say(tr("  connessioni di rete..."))
        for r in leggi_rete(vmm):
            _metti(con, n, "connessioni", r["ora"], f"{r['protocollo']} {r['origine']} → {r['destinazione']}",
                   tr("{s} · processo {p} (PID {i})").format(s=r["stato"], p=r["processo"] or "?", i=r["pid"]), "",
                   "RAM: /sys/net/netstat-v.txt", r)
        say(tr("  attività pianificate e driver..."))
        for a in leggi_attivita(vmm):
            _metti(con, n, "attivita", a["ora"], a["nome"], a["comando"], a["utente"], "RAM: /sys/tasks/tasks.txt", a)
        try:
            driver = vmm.maps.kdriver()
        except Exception:
            driver = []
        for k in driver:
            _metti(con, n, "driver", None, k.get("name") or "?", k.get("path") or "", "", "RAM: /sys/drivers",
                   {"servizio": k.get("service_key_name"), "percorso": k.get("path")})
        say(tr("  moduli dei processi..."))
        attivi = {}
        try:
            attivi = {p.pid: p for p in vmm.process_list()}
        except Exception:
            pass
        fatti = 0
        for i, (pid, p) in enumerate(sorted(attivi.items())):
            fa.avanz(None, i, len(attivi))
            try:
                moduli = p.module_list()
            except Exception:
                continue
            nome = getattr(p, "name", "?")
            for mo in moduli:
                if fatti >= MAX_MODULI:
                    break
                try:
                    _metti(con, n, "moduli", None, mo.name, mo.fullname, "", f"RAM: /pid/{pid}/modules",
                           {"processo": nome, "pid": pid, "base": hex(mo.base), "dimensione": mo.image_size})
                    fatti += 1
                except Exception:
                    continue
        if fatti >= MAX_MODULI:
            avvisi.append(tr("Moduli: elenco fermato a {n} righe.").format(n=MAX_MODULI))
        servizi = [d for d in leggi_servizi_stato(vmm) if not d["tipo"].startswith("DRV")]      # i driver hanno la loro categoria
        fonte_servizi = "RAM: /sys/services/services.txt"
        if not servizi:
            # Mac e Linux: MemProcFS non trova il simbolo dell'elenco dei servizi; con i simboli in locale lo legge RepertIA
            servizi = [d for d in leggi_servizi_memoria(vmm, s) if not d["tipo"].startswith("DRV")]
            fonte_servizi = "RAM: memoria di services.exe (elenco dei servizi)"
        if servizi:
            # (3.0.4) con i simboli nella cartella locale MemProcFS dà anche lo stato di esecuzione di ogni servizio
            say(tr("  servizi (con lo stato di esecuzione)..."))
            for d in servizi:
                _metti(con, n, "servizi", None, d["nome"] + (f" ({d['nome_mostrato']})" if d["nome_mostrato"] else ""),
                       tr("{st}{pid} · avvio {a} · {p} · eseguito come {u}").format(
                           st=d["stato"] or "?", pid=tr(" (PID {i})").format(i=d["pid"]) if d["pid"] else "", a=d["avvio"] or "?",
                           p=" · ".join(x for x in (d["percorso"], d["comando"]) if x) or "?", u=d["utente"] or "?"), "", fonte_servizi, d)
            st = simboli_stato()
            avvisi.append(tr("Servizi: {n} con lo stato di esecuzione al momento dell'acquisizione, letti con i simboli di debug di "
                             "Windows già nella cartella locale ({f} file; scaricati a caso chiuso, nessuna richiesta di rete durante "
                             "questa analisi).").format(n=n["servizi"], f=st.get("file", 0)))
        if not servizi:
            # senza i simboli MemProcFS non elenca i servizi in esecuzione: si leggono quelli configurati nel registro
            say(tr("  servizi (dal registro in memoria)..."))
            for d in leggi_servizi(vmm):
                avvio = tr(SERVIZI_AVVIO.get(d["avvio"], "?")) if d["avvio"] is not None else "?"
                _metti(con, n, "servizi", d["chiave_scritta"], d["nome"] + (f" ({d['nome_mostrato']})" if d["nome_mostrato"] and not d["nome_mostrato"].startswith("@") else ""),
                       tr("{p} · avvio {a} · eseguito come {u}").format(p=d["percorso"] or "?", a=avvio, u=d["utente"] or "?"), "",
                       f"RAM: registro HKLM\\SYSTEM\\{d['insieme']}\\Services\\{d['nome']}", d)
            avvisi.append(tr("Servizi: {n} letti dalla configurazione nel registro in memoria (la data è l'ultima scrittura della chiave). "
                             "Lo stato di esecuzione al momento dell'acquisizione non è disponibile: servirebbero i simboli di debug "
                             "di Windows, che RepertIA non scarica.").format(n=n["servizi"]) if n["servizi"] else
                          tr("Servizi: nessun dato (servono i simboli di debug di Windows, che RepertIA non scarica durante l'analisi)."))
        eventi = {}
        if completa:
            say(tr("  timeline della memoria..."))
            eventi = timeline(vmm, con, say)
        con.commit()
    finally:
        chiudi(dump)
    esito = {"ts": fa.now(), "motore": f"MemProcFS {ver}", "simboli_da_rete": bool(s["simboli_da_rete"]),
             "sistema": {k: s.get(k) for k in ("computer", "versione", "architettura", "avvio", "acquisizione", "fuso_windows",
                                               "memoria", "cpu", "produttore")},
             "conteggi": dict(n), "eventi": eventi, "avvisi": avvisi}
    say(tr("Memoria RAM: Windows {v}, computer {c}; processi {p}, connessioni {r}, moduli {m}, driver {d}, attività {a}.").format(
        v=s["versione"] or "?", c=s["computer"] or "?", p=n["processi"], r=n["connessioni"], m=n["moduli"], d=n["driver"], a=n["attivita"]))
    for a in avvisi:
        say("  " + a)
    return esito


def prepara(args):
    """Caso nuovo da un dump della RAM (forense_agent.py prepara --ram). Il caso è una sorgente logica: i file ancora
    in memoria vengono copiati nel caso da MemProcFS e si leggono come quelli di un archivio estratto; artefatti e
    timeline della memoria si aggiungono dopo l'elenco dei file (dopo_elenco, chiamata da forense_mobile)."""
    import argparse
    import forense_mobile as fm
    return fm.cmd_prepara(argparse.Namespace(
        case=args.case, image=args.image, logica=True, ram=True, drone=False, lingua=getattr(args, "lingua", None),
        info=getattr(args, "info", None), fuso=getattr(args, "fuso", None), no_hash=getattr(args, "no_hash", False),
        decomprimi=False, keychain=None, sysdiagnose=None, wa_backup=False, chat=False, leapp=False,
        no_indice=getattr(args, "no_indice", False), hash_file=getattr(args, "hash_file", False), trascrizione=None))


def dopo_elenco(case, con, say=print):
    """Dopo l'elenco dei file (sorgente logica da un dump): artefatti, timeline e fuso letti dalla memoria."""
    # (3.0.4) artefatti di sistema dagli hive del registro e dagli altri file in memoria (programmi eseguiti, USB,
    # utenti, reti...): prima, perché l'analisi della memoria aggiunge poi i suoi senza toccarli
    if (case.meta.get("estratta") or {}).get("hive_del_registro"):
        import forense_estesa as fe                   # (carica anche forense_art_windows, nell'ordine giusto)
        import forense_art_windows as faw
        aperto = next(iter(_VMM.values()), None)
        try:
            # il registro si legge chiave per chiave dalla memoria (tollera le pagine mancanti); dove non c'è, dal file
            faw.HIVE_MEMORIA = radice_registro(aperto[0], case.meta["estratta"]["hive_del_registro"]) if aperto else None
            if fa.run_addon(case, con, "artefatti"):
                say(tr("Artefatti di sistema letti dal registro in memoria e dai file ancora presenti."))
        except Exception as e:
            say(tr("Artefatti di sistema dal registro in memoria non letti: {e}").format(e=e))
        finally:
            faw.HIVE_MEMORIA = None
    fatto = fa.run_addon(case, con, "ram")
    if not fatto:
        chiudi()
        say("!" * 70 + "\n" + tr("L'analisi della memoria non è riuscita: restano l'hash del dump e i file copiati dalla memoria.") + "\n" + "!" * 70)
        return False
    nome = ((case.meta.get("ram") or {}).get("sistema") or {}).get("fuso_windows") or ""
    z = fa.fuso_valido(fa.WIN_TZ.get(nome.split(" [")[0].strip()))
    fd = case.meta.get("fuso_dispositivo") or {}
    fd["rilevato"] = {"tz": z, "nome": nome, "fonte": tr("memoria RAM")} if nome else None
    if z and fd.get("auto"):
        fd["tz"], fd["origine"], fd["stato"] = z, tr("rilevato dalla memoria RAM"), "rilevato"
    elif z:
        fd["stato"] = "confermato" if fa.fuso_equivalenti(z, fd.get("tz")) else "discordante"
    else:
        fd["stato"] = "non_verificabile" if fd.get("auto") else "scelto_non_verificato"
    case.meta["fuso_dispositivo"] = fd
    ev = (case.meta.get("ram") or {}).get("eventi") or {}
    case.meta.setdefault("timeline", {})["ram_events"] = sum(ev.values())
    case.log("fuso_dispositivo", fd)
    case.save()
    return True
