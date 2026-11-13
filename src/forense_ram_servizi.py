#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (3.0.4) - servizi di Windows con lo stato di esecuzione, letti dalla memoria di services.exe.

Su Windows MemProcFS elenca i servizi (/sys/services/services.txt) quando i simboli di debug sono nella cartella
locale. Su Mac e Linux lo stesso MemProcFS 5.19.3 non ci riesce: cerca in services.pdb il simbolo `ServiceDatabase`,
che nei Windows recenti è scritto col nome completo del C++ (`?ServiceDatabase@@3VCServiceDatabase@@A`), e la libreria
che su Mac e Linux legge i simboli (libpdbcrust) confronta i nomi così come sono. Questo file fa la stessa lettura
che fa MemProcFS (vmm/vmmwinsvc.c, Ulf Frisk, AGPL-3.0: stesse strutture, stessi controlli), chiedendo il simbolo
anche col nome completo:

  1. processo services.exe figlio di wininit.exe;
  2. identificativo dei simboli (GUID ed età) dall'intestazione PE di services.exe in memoria;
  3. services.pdb con quell'identificativo nella cartella locale dei simboli (MAI dalla rete: se manca, nessun elenco);
  4. indirizzo dell'elenco dal simbolo; record `Sc19` dei servizi, record `Sc16` con PID, comando e utente; nomi.

Limiti dichiarati: solo Windows a 64 bit dalla build 15063 (Windows 10 1703), come la strada dei simboli di MemProcFS;
ogni controllo fallito dà un elenco vuoto con il motivo, e il chiamante usa allora la configurazione dal registro.
Sola lettura: la memoria del processo si legge dal file `/pid/<pid>/memory.vmem` di MemProcFS.
"""
import ctypes as C
import struct
import sys
from pathlib import Path

SIMBOLI_NOMI = ("ServiceDatabase", "?ServiceDatabase@@3VCServiceDatabase@@A")
AVVIO = ("BOOT_START", "SYSTEM_START", "AUTO_START", "DEMAND_START", "DISABLED", "---")
STATO = ("---", "STOPPED", "START_PEND", "STOP_PEND", "RUNNING", "CONT_PEND", "PAUSE_PEND", "PAUSED", "---")
MAX_SERVIZI = 20000


def scostamenti(build):
    """Posizione dei campi nei record Sc19 e Sc16 a 64 bit (vmmwinsvc.c, VmmWinSvc_OffsetLocator). None se non noti."""
    if build < 15063:
        return None
    o16 = {"dim": 0x60, "tag": 0x00, "indietro": 0x08, "avanti": 0x10, "comando": 0x18, "utente_tipo": 0x00, "pid": 0x20, "utente": 0x58}
    o19 = {"dim": 0x130, "tag": 0x08, "indietro": 0x10, "avanti": 0x18, "ordinale": 0x20, "avvio": 0x24, "nome": 0x38,
           "nome_mostrato": 0x40, "stato": 0x48, "esteso": 0xe8}
    if build >= 16299:
        o16.update(pid=0x28, utente_tipo=0x20)
    if build >= 18362:
        o19.update(esteso=0xf0)
    if build >= 19041:
        o19.update(esteso=0x128)
    if build >= 26100:
        o19.update(dim=0x158, stato=0x50, esteso=0x150)
    return o19, o16


def _utente64(va, allineato=False):
    """Indirizzo valido dello spazio utente a 64 bit (VMM_UADDR64 / VMM_UADDR64_8)."""
    return bool(va) and not va & (0xffff800000000007 if allineato else 0xffff800000000000)


def _tipo(t):
    if t & 0x01:
        return "DRV KERNEL"
    if t & 0x02:
        return "DRV FS"
    if t & 0x04:
        return "DRV ADAPTER"
    if t & 0x08:
        return "DRV RECOGN"
    if t & 0x10 and t & 0x20:
        return "PROC OWN|SHR"
    if t & 0x10:
        return "PROC OWN"
    if t & 0x20:
        return "PROC SHR"
    return "---"


class _Memoria:
    """Memoria virtuale di un processo, dal file memory.vmem di MemProcFS."""

    def __init__(self, vmm, pid):
        self._vmm, self._file = vmm, f"/pid/{pid}/memory.vmem"

    def leggi(self, va, quanti):
        try:
            d = self._vmm.vfs.read(self._file, quanti, va)
        except Exception:
            return None
        return d if d is not None and len(d) == quanti else None

    def puntatore(self, dati, dove):
        return struct.unpack_from("<Q", dati, dove)[0]

    def testo(self, va):
        """Stringa UTF-16 terminata da zero (come VmmWinSvc_ResolveStrAddSingle: massimo 2.047 caratteri, i primi tre
        devono essere caratteri a un byte). '' se non leggibile."""
        if va < 0x10000 or not _utente64(va):
            return ""
        d = b""
        for quanti in (512, 4094):
            d = self.leggi(va, quanti) or b""
            fine = next((i for i in range(0, len(d) - 1, 2) if d[i] == 0 and d[i + 1] == 0), -1)
            if fine >= 0:
                d = d[:fine]
                break
        if len(d) < 2:
            return ""
        primi = struct.unpack_from(f"<{min(3, len(d) // 2)}H", d)
        if any(c > 0xff for c in primi):
            return ""
        return d[:len(d) // 2 * 2].decode("utf-16-le", "replace")


def identificativo_simboli(mem, base):
    """(nome del pdb, GUID+età come li scrive il server dei simboli) dall'intestazione PE in memoria, o None."""
    t = mem.leggi(base, 0x1000)
    if not t or t[:2] != b"MZ":
        return None
    pe = struct.unpack_from("<I", t, 0x3c)[0]
    if pe > 0xf00 or t[pe:pe + 4] != b"PE\0\0":
        return None
    opz = pe + 24
    if struct.unpack_from("<H", t, opz)[0] != 0x20b:           # solo PE32+ (64 bit)
        return None
    rva, dim = struct.unpack_from("<II", t, opz + 112 + 6 * 8)   # cartella dei dati di debug
    if not rva or not dim or dim > 0x400:
        return None
    voci = mem.leggi(base + rva, dim - dim % 28)
    for i in range(0, len(voci or b""), 28):
        tipo, quanti, dove = struct.unpack_from("<I", voci, i + 12)[0], struct.unpack_from("<I", voci, i + 16)[0], struct.unpack_from("<I", voci, i + 20)[0]
        if tipo != 2 or not 24 < quanti <= 0x200:               # 2 = CodeView
            continue
        cv = mem.leggi(base + dove, quanti)
        if not cv or cv[:4] != b"RSDS":
            continue
        d1, d2, d3 = struct.unpack_from("<IHH", cv, 4)
        eta = struct.unpack_from("<I", cv, 20)[0]
        nome = cv[24:].split(b"\0")[0].decode("utf-8", "replace").replace("\\", "/").rsplit("/", 1)[-1]
        return nome, f"{d1:08X}{d2:04X}{d3:04X}" + cv[12:20].hex().upper() + str(eta)
    return None


def scostamento_simbolo(motore, pdb, nomi):
    """Posizione di un simbolo nel modulo, letta da un pdb locale con libpdbcrust (solo lettura del file)."""
    est = ".dylib" if sys.platform == "darwin" else ".so"
    file = next((Path(motore) / n for n in ("libpdbcrust" + est, "libpdbcrust2" + est) if (Path(motore) / n).is_file()), None)
    if file is None:
        return 0, ""
    lib = C.CDLL(str(file))
    lib.pdbcrust_open.restype, lib.pdbcrust_open.argtypes = C.c_size_t, [C.c_char_p]
    lib.pdbcrust_close.restype, lib.pdbcrust_close.argtypes = None, [C.c_size_t]
    lib.pdbcrust_symbol_offset.restype, lib.pdbcrust_symbol_offset.argtypes = C.c_uint, [C.c_size_t, C.c_char_p]
    h = lib.pdbcrust_open(str(pdb).encode("utf-8"))
    if not h:
        return 0, ""
    try:
        for n in nomi:
            o = lib.pdbcrust_symbol_offset(h, n.encode("ascii"))
            if o:
                return o, n
    finally:
        lib.pdbcrust_close(h)
    return 0, ""


def percorri(mem, capi, o19, o16):
    """Record dei servizi raggiungibili dai due capi dell'elenco (come VmmWinSvc_MainListWalk e
    VmmWinSvc_GetExtendedInfo). `mem` offre leggi(va, quanti), puntatore(dati, dove) e testo(va)."""
    da_fare, visti, righe = list(capi), set(), []
    while da_fare and len(visti) < MAX_SERVIZI:
        va = da_fare.pop()
        if not va or va in visti:
            continue
        visti.add(va)
        r = mem.leggi(va, o19["dim"])
        if not r or r[o19["tag"]:o19["tag"] + 4] != b"Sc19":
            continue
        ordinale, avvio = struct.unpack_from("<I", r, o19["ordinale"])[0], struct.unpack_from("<I", r, o19["avvio"])[0]
        if ordinale > 0xffff or avvio > 4:
            continue
        v1, v2 = mem.puntatore(r, o19["indietro"]), mem.puntatore(r, o19["avanti"])
        v1, v2 = v1 if _utente64(v1, True) else 0, v2 if _utente64(v2, True) else 0
        if not v1 and not v2:
            continue
        da_fare += [v1, v2]
        nome_va = mem.puntatore(r, o19["nome"])
        if nome_va < 0x10000 or not _utente64(nome_va):
            continue
        tipo, stato = struct.unpack_from("<II", r, o19["stato"])
        esteso = mem.puntatore(r, o19["esteso"])
        d = {"ordinale": ordinale, "oggetto": va, "avvio": AVVIO[min(5, avvio)], "stato": STATO[min(8, stato)], "tipo": _tipo(tipo),
             "nome": mem.testo(nome_va), "nome_mostrato": mem.testo(mem.puntatore(r, o19["nome_mostrato"])),
             "pid": 0, "utente": "", "comando": "", "percorso": ""}
        if tipo & 0x03:                                     # driver: il campo è il nome dell'oggetto
            d["comando"] = mem.testo(esteso)
        elif _utente64(esteso, True):                       # servizio: record Sc16 con PID, comando e utente
            x = mem.leggi(esteso, o16["dim"])
            if x and x[o16["tag"]:o16["tag"] + 4] == b"Sc16":
                d["pid"] = struct.unpack_from("<I", x, o16["pid"])[0]
                d["comando"] = mem.testo(mem.puntatore(x, o16["comando"]))
                d["utente"] = mem.testo(mem.puntatore(x, o16["utente"])) if o16["utente"] else ""
        righe.append(d)
    return righe


def leggi(vmm, motore, build, architettura, utenti_per_pid=None, percorsi=None):
    """(servizi, motivo). servizi: lista di dict come quelli dell'elenco di MemProcFS (pid, avvio, stato, tipo, nome,
    nome_mostrato, utente, percorso, comando) più ordinale, oggetto e simbolo; vuota, con il motivo, se un controllo
    non passa. `utenti_per_pid` e `percorsi` (nome del servizio → percorso dal registro) completano le righe."""
    if (architettura or "").upper() != "X64":
        return [], "solo Windows a 64 bit"
    sc = scostamenti(build or 0)
    if not sc:
        return [], "versione di Windows precedente alla build 15063"
    o19, o16 = sc
    try:
        processi = list(vmm.process_list())
    except Exception as e:
        return [], f"elenco dei processi non leggibile: {str(e)[:100]}"
    per_pid = {p.pid: p for p in processi}
    servizio = next((p for p in processi if (p.name or "").lower() == "services.exe"
                     and (getattr(per_pid.get(p.ppid), "name", "") or "").lower() == "wininit.exe"), None)
    if servizio is None:
        return [], "processo services.exe (figlio di wininit.exe) non trovato"
    try:
        modulo = next((m for m in servizio.module_list() if (m.name or "").lower() == "services.exe"), None)
    except Exception:
        modulo = None
    if modulo is None:
        return [], "modulo services.exe non trovato nel processo"
    mem = _Memoria(vmm, servizio.pid)
    ident = identificativo_simboli(mem, modulo.base)
    if not ident:
        return [], "identificativo dei simboli di services.exe non leggibile dalla memoria"
    pdb = Path(motore) / "Symbols" / ident[0] / ident[1] / ident[0]
    if not pdb.is_file():
        return [], f"simboli di {ident[0]} ({ident[1]}) non presenti nella cartella locale"
    dove, simbolo = scostamento_simbolo(motore, pdb, SIMBOLI_NOMI)
    if not dove:
        return [], f"simbolo dell'elenco dei servizi non trovato in {ident[0]}"
    testa = mem.leggi(modulo.base + dove, 0x18)
    if not testa:
        return [], "elenco dei servizi non leggibile dalla memoria di services.exe"
    capi = [mem.puntatore(testa, 8), mem.puntatore(testa, 16)]
    if not all(_utente64(v, True) for v in capi):
        return [], "l'elenco dei servizi in memoria non ha indirizzi validi"
    righe = percorri(mem, capi, o19, o16)
    righe.sort(key=lambda d: (d["ordinale"], d["oggetto"]))
    # controlli di coerenza: meglio nessun elenco che un elenco letto male
    if len(righe) < 10:
        return [], f"elenco dei servizi troppo corto ({len(righe)} record validi)"
    senza_nome = sum(1 for d in righe if not d["nome"])
    if senza_nome * 10 > len(righe):
        return [], f"{senza_nome} record su {len(righe)} senza nome leggibile"
    righe = [d for d in righe if d["nome"]]
    for d in righe:
        if d["nome_mostrato"] == d["nome"]:
            d["nome_mostrato"] = ""
        if not d["utente"] and d["pid"] and utenti_per_pid:
            d["utente"] = utenti_per_pid.get(d["pid"], "") or ""
        d["percorso"] = (percorsi or {}).get(d["nome"].lower(), "")
        d["simbolo"] = simbolo
        d["oggetto"] = f"{d['oggetto']:012x}"
    return righe, ""
