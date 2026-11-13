#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (3.0.4) - adattatore verso la libreria di MemProcFS (vmm.dll, vmm.so, vmm.dylib).

MemProcFS (Ulf Frisk, AGPL-3.0) pubblica il suo modulo Python solo per Windows e Linux. Perché l'analisi della RAM sia
la stessa su Mac, Windows e Linux, RepertIA chiama direttamente la libreria con ctypes, con le funzioni C dichiarate in
`vmmdll.h` (identico nei tre archivi della release). Questo file offre a `forense_ram.py` gli stessi nomi del modulo
Python ufficiale, limitati a quelli che RepertIA usa:

    Vmm(argomenti)            .close()
    vmm.vfs.list(percorso)    -> {nome: {"f_isdir": bool, "size": int}}
    vmm.vfs.read(percorso, quanti, da)  -> bytes
    vmm.process_list()        -> processi con pid, ppid, name, fullname, pathuser, pathkernel, cmdline, sid, session,
                                 integrity, is_wow64, state e module_list() (name, fullname, base, image_size)
    vmm.maps.user()           -> [{"sid", "name", "va-reghive"}]
    vmm.maps.kdriver()        -> [{"name", "path", "service_key_name", "va"}]
    vmm.reg_hive_list()       -> hive con name, name_short, size, rootkey
    vmm.reg_key(percorso)     -> chiave con name, time_int, subkeys(), values(); valori con name, type, size, value

Solo lettura: nessuna funzione di scrittura della libreria è dichiarata qui. Le strutture seguono vmmdll.h; se la
libreria restituisce una versione di struttura diversa da quella attesa la funzione si ferma con un errore, invece di
leggere campi spostati.
"""
import ctypes as C
import os
import sys
from pathlib import Path

LIBRERIE = {"win32": ("vmm.dll", "leechcore.dll"), "darwin": ("vmm.dylib", "leechcore.dylib")}
MAX_PATH = 260
PROC_MAGIC, PROC_VERSIONE = 0xc0ffee663df9301e, 7
HIVE_MAGIC, HIVE_VERSIONE = 0xc0ffee653df8d01e, 5
MAP_MODULE_VERSIONE, MAP_KDRIVER_VERSIONE, MAP_USER_VERSIONE = 6, 1, 2
STATUS_SUCCESS, STATUS_END_OF_FILE = 0x00000000, 0xC0000011
OPT_VER_MAJOR, OPT_VER_MINOR, OPT_VER_REVISION = 0x2000000900000000, 0x2000000A00000000, 0x2000000B00000000
NO_INDICE = 0xFFFFFFFF


def nomi_libreria():
    return LIBRERIE.get(sys.platform, ("vmm.so", "leechcore.so"))


# ------------------------------------------------------------------ nessuno scarico dei simboli (Mac e Linux)
# Su Windows `-disable-symbolserver` basta. Su Mac e Linux MemProcFS 5.19.3 chiede comunque a libpdbcrust di scaricare
# da Microsoft i simboli che non trova in locale (vmm/pdb.c: l'opzione non arriva a pdbcrust_pdb_download_ensure).
# libpdbcrust legge il proxy dall'ambiente una volta sola, alla prima richiesta, e poi usa sempre quello: prima di
# caricare vmm le si fa quindi fare una richiesta a vuoto con il proxy puntato su una porta locale chiusa, e subito
# dopo l'ambiente torna com'era (il resto del programma non ne risente). Da lì in poi, in questo processo, ogni
# scarico dei simboli fallisce senza uscire dal computer; i simboli già nella cartella locale si leggono lo stesso.
# Lo scarico esplicito (pagina iniziale, col consenso) gira in un processo a parte con RETE_SIMBOLI_ENV=1.
RETE_SIMBOLI_ENV = "REPERTIA_RAM_RETE_SIMBOLI"
PROXY_CHIUSO = "http://127.0.0.1:9"
_PROXY_NOMI = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")
SCARICO_SIMBOLI = "non verificato"      # "impedito", "permesso" (processo dello scarico), "non necessario" (Windows), o il motivo


def impedisci_scarico_simboli(cartella):
    """Vedi sopra. Restituisce lo stato (anche in SCARICO_SIMBOLI); non solleva errori."""
    global SCARICO_SIMBOLI
    if sys.platform == "win32":
        SCARICO_SIMBOLI = "non necessario"
        return SCARICO_SIMBOLI
    if os.environ.get(RETE_SIMBOLI_ENV) == "1":
        SCARICO_SIMBOLI = "permesso"
        return SCARICO_SIMBOLI
    import tempfile
    est = ".dylib" if sys.platform == "darwin" else ".so"
    file = next((Path(cartella) / n for n in ("libpdbcrust" + est, "libpdbcrust2" + est) if (Path(cartella) / n).is_file()), None)
    if file is None:
        SCARICO_SIMBOLI = "impedito"     # senza libpdbcrust MemProcFS non ha né simboli né scarico
        return SCARICO_SIMBOLI
    salvo = {k: os.environ.get(k) for k in _PROXY_NOMI}
    try:
        for k in _PROXY_NOMI:
            os.environ[k] = PROXY_CHIUSO
        f = C.CDLL(str(file)).pdbcrust_pdb_download_ensure
        f.restype, f.argtypes = C.c_bool, [C.c_char_p, C.c_char_p, C.c_char_p, C.c_bool, C.c_size_t, C.c_char_p]
        with tempfile.TemporaryDirectory() as d:
            arrivato = f(d.encode("utf-8"), b"0" * 32 + b"1", b"repertia_nessun_simbolo.pdb", True, 1024, C.create_string_buffer(1024))
        SCARICO_SIMBOLI = "impedito" if not arrivato else "la richiesta di prova non è stata fermata"
    except (OSError, AttributeError) as e:
        SCARICO_SIMBOLI = f"libpdbcrust non controllabile: {str(e)[:120]}"
    finally:
        for k, v in salvo.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return SCARICO_SIMBOLI


# ------------------------------------------------------------------ strutture di vmmdll.h

class _ExInfo(C.Structure):
    _fields_ = [("dwVersion", C.c_uint32), ("fCompressed", C.c_uint32), ("qwCreationTime", C.c_uint64),
                ("qwLastAccessTime", C.c_uint64), ("qwLastWriteTime", C.c_uint64)]


_AGGIUNGI_FILE = C.CFUNCTYPE(None, C.c_void_p, C.c_char_p, C.c_uint64, C.POINTER(_ExInfo))
_AGGIUNGI_CARTELLA = C.CFUNCTYPE(None, C.c_void_p, C.c_char_p, C.POINTER(_ExInfo))


class _FileList2(C.Structure):
    _fields_ = [("dwVersion", C.c_uint32), ("pfnAddFile", _AGGIUNGI_FILE), ("pfnAddDirectory", _AGGIUNGI_CARTELLA),
                ("h", C.c_void_p)]


class _ProcWin(C.Structure):
    _fields_ = [("vaEPROCESS", C.c_uint64), ("vaPEB", C.c_uint64), ("_Reserved1", C.c_uint64), ("fWow64", C.c_uint32),
                ("vaPEB32", C.c_uint32), ("dwSessionId", C.c_uint32), ("qwLUID", C.c_uint64),
                ("szSID", C.c_char * MAX_PATH), ("IntegrityLevel", C.c_uint32)]


class _ProcInfo(C.Structure):
    _fields_ = [("magic", C.c_uint64), ("wVersion", C.c_uint16), ("wSize", C.c_uint16), ("tpMemoryModel", C.c_uint32),
                ("tpSystem", C.c_uint32), ("fUserOnly", C.c_uint32), ("dwPID", C.c_uint32), ("dwPPID", C.c_uint32),
                ("dwState", C.c_uint32), ("szName", C.c_char * 16), ("szNameLong", C.c_char * 64),
                ("paDTB", C.c_uint64), ("paDTB_UserOpt", C.c_uint64), ("win", _ProcWin)]


class _HiveFile(C.Structure):
    _fields_ = [("fValid", C.c_uint32), ("dwHandle", C.c_uint32), ("vaFileObject", C.c_uint64)]


class _HiveInfo(C.Structure):
    _fields_ = [("magic", C.c_uint64), ("wVersion", C.c_uint16), ("wSize", C.c_uint16),
                ("_FutureReserved1", C.c_uint8 * 0x34), ("vaCMHIVE", C.c_uint64), ("vaHBASE_BLOCK", C.c_uint64),
                ("cbLength", C.c_uint32), ("uszName", C.c_char * 128), ("uszNameShort", C.c_char * 33),
                ("uszHiveRootPath", C.c_char * MAX_PATH), ("File", _HiveFile), ("_FutureReserved", C.c_uint64 * 0x0e)]


class _MappaTesta(C.Structure):          # inizio comune di VMMDLL_MAP_MODULE, _KDRIVER e _USER; le voci seguono subito dopo
    _fields_ = [("dwVersion", C.c_uint32), ("_Reserved1", C.c_uint32 * 5), ("pbMultiText", C.c_void_p),
                ("cbMultiText", C.c_uint32), ("cMap", C.c_uint32)]


class _ModuloVoce(C.Structure):
    _fields_ = [("vaBase", C.c_uint64), ("vaEntry", C.c_uint64), ("cbImageSize", C.c_uint32), ("fWoW64", C.c_uint32),
                ("uszText", C.c_char_p), ("_Reserved3", C.c_uint32), ("_Reserved4", C.c_uint32),
                ("uszFullName", C.c_char_p), ("tp", C.c_uint32), ("cbFileSizeRaw", C.c_uint32), ("cSection", C.c_uint32),
                ("cEAT", C.c_uint32), ("cIAT", C.c_uint32), ("_Reserved2", C.c_uint32), ("_Reserved1", C.c_uint64 * 3),
                ("pExDebugInfo", C.c_void_p), ("pExVersionInfo", C.c_void_p)]


class _DriverVoce(C.Structure):
    _fields_ = [("va", C.c_uint64), ("vaDriverStart", C.c_uint64), ("cbDriverSize", C.c_uint64),
                ("vaDeviceObject", C.c_uint64), ("uszName", C.c_char_p), ("uszPath", C.c_char_p),
                ("uszServiceKeyName", C.c_char_p), ("MajorFunction", C.c_uint64 * 28)]


class _UtenteVoce(C.Structure):
    _fields_ = [("_FutureUse1", C.c_uint32 * 2), ("uszText", C.c_char_p), ("vaRegHive", C.c_uint64),
                ("uszSID", C.c_char_p), ("_FutureUse2", C.c_uint32 * 2)]


def _testo(b):
    return (b or b"").decode("utf-8", "replace")


# ------------------------------------------------------------------ libreria

_LIB = {}


def libreria(cartella):
    """Carica vmm e leechcore dalla cartella indicata (una volta) e dichiara le funzioni usate."""
    cartella = Path(cartella).resolve()
    k = str(cartella)
    if k in _LIB:
        return _LIB[k]
    nome_vmm, nome_leech = nomi_libreria()
    if not (cartella / nome_vmm).is_file():
        raise ImportError(f"{nome_vmm} non trovato in {cartella}")
    if sys.platform == "win32":
        os.add_dll_directory(k)
        lib = C.CDLL(str(cartella / nome_vmm))
    else:
        stato = impedisci_scarico_simboli(cartella)        # PRIMA di caricare vmm
        if stato not in ("impedito", "permesso"):
            raise ImportError(f"MemProcFS non caricato: lo scarico dei simboli dalla rete non si può impedire ({stato})")
        # leechcore prima, con i simboli visibili a vmm, così non dipende dai percorsi di ricerca del sistema
        if (cartella / nome_leech).is_file():
            C.CDLL(str(cartella / nome_leech), mode=C.RTLD_GLOBAL)
        lib = C.CDLL(str(cartella / nome_vmm), mode=C.RTLD_GLOBAL)
    H, S, U32, U64 = C.c_void_p, C.c_char_p, C.c_uint32, C.c_uint64
    for nome, ret, arg in (
            ("VMMDLL_Initialize", H, [U32, C.POINTER(S)]),
            ("VMMDLL_InitializePlugins", U32, [H]),
            ("VMMDLL_Close", None, [H]),
            ("VMMDLL_MemFree", None, [C.c_void_p]),
            ("VMMDLL_ConfigGet", U32, [H, U64, C.POINTER(U64)]),
            ("VMMDLL_VfsListU", U32, [H, S, C.POINTER(_FileList2)]),
            ("VMMDLL_VfsReadU", U32, [H, S, C.c_void_p, U32, C.POINTER(U32), U64]),
            ("VMMDLL_PidList", U32, [H, C.POINTER(U32), C.POINTER(C.c_size_t)]),
            ("VMMDLL_ProcessGetInformation", U32, [H, U32, C.POINTER(_ProcInfo), C.POINTER(C.c_size_t)]),
            ("VMMDLL_ProcessGetInformationString", C.c_void_p, [H, U32, U32]),
            ("VMMDLL_Map_GetModuleU", U32, [H, U32, C.POINTER(C.c_void_p), U32]),
            ("VMMDLL_Map_GetKDriverU", U32, [H, C.POINTER(C.c_void_p)]),
            ("VMMDLL_Map_GetUsersU", U32, [H, C.POINTER(C.c_void_p)]),
            ("VMMDLL_WinReg_HiveList", U32, [H, C.POINTER(_HiveInfo), U32, C.POINTER(U32)]),
            ("VMMDLL_WinReg_EnumKeyExU", U32, [H, S, U32, C.c_void_p, C.POINTER(U32), C.POINTER(U64)]),
            ("VMMDLL_WinReg_EnumValueU", U32, [H, S, U32, C.c_void_p, C.POINTER(U32), C.POINTER(U32), C.c_void_p, C.POINTER(U32)]),
            ("VMMDLL_WinReg_QueryValueExU", U32, [H, S, C.POINTER(U32), C.c_void_p, C.POINTER(U32)])):
        f = getattr(lib, nome)
        f.restype, f.argtypes = ret, arg
    _LIB[k] = lib
    return lib


def versione(cartella):
    """Versione scritta accanto alla libreria da chi ha preparato il componente (versione.txt), senza aprire nulla."""
    try:
        return (Path(cartella) / "versione.txt").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


# ------------------------------------------------------------------ oggetti

class _Vfs:
    def __init__(self, vmm):
        self._v = vmm

    def list(self, percorso):
        out = {}

        def file(_h, nome, cb, _ex):
            out[_testo(nome)] = {"f_isdir": False, "size": int(cb), "name": _testo(nome)}

        def cartella(_h, nome, _ex):
            out[_testo(nome)] = {"f_isdir": True, "size": 0, "name": _testo(nome)}
        fl = _FileList2(2, _AGGIUNGI_FILE(file), _AGGIUNGI_CARTELLA(cartella), None)
        if not self._v._lib.VMMDLL_VfsListU(self._v._h, _percorso_vfs(percorso), C.byref(fl)):
            raise RuntimeError("Vmm.vfs.list(): " + str(percorso))
        return out

    def read(self, percorso, quanti=0x00100000, da=0):
        quanti = int(quanti)
        if quanti <= 0:
            return b""
        buf = C.create_string_buffer(quanti)
        letti = C.c_uint32(0)
        st = self._v._lib.VMMDLL_VfsReadU(self._v._h, _percorso_vfs(percorso), buf, quanti, C.byref(letti), int(da))
        if st not in (STATUS_SUCCESS, STATUS_END_OF_FILE):
            raise RuntimeError(f"Vmm.vfs.read(): {percorso} [0x{st:08x}]")
        return C.string_at(buf, letti.value)          # una copia sola dei byte letti


def _percorso_vfs(p):
    return str(p).replace("/", "\\").encode("utf-8")


class _Modulo:
    def __init__(self, e):
        self.name, self.fullname = _testo(e.uszText), _testo(e.uszFullName)
        self.base, self.entry, self.image_size, self.is_wow64 = e.vaBase, e.vaEntry, e.cbImageSize, bool(e.fWoW64)


class _Processo:
    def __init__(self, vmm, info):
        self._v = vmm
        self.pid, self.ppid, self.state = info.dwPID, info.dwPPID, info.dwState
        self.name, self.fullname = _testo(info.szName), _testo(info.szNameLong)
        self.sid, self.session = _testo(info.win.szSID), info.win.dwSessionId
        self.integrity, self.is_wow64 = info.win.IntegrityLevel, bool(info.win.fWow64)
        self.eprocess, self.peb, self.dtb = info.win.vaEPROCESS, info.win.vaPEB, info.paDTB

    def _stringa(self, quale):
        p = self._v._lib.VMMDLL_ProcessGetInformationString(self._v._h, self.pid, quale)
        if not p:
            raise RuntimeError("Vmm.process: stringa non disponibile")
        try:
            return _testo(C.string_at(p))
        finally:
            self._v._lib.VMMDLL_MemFree(p)

    pathkernel = property(lambda self: self._stringa(1))
    pathuser = property(lambda self: self._stringa(2))
    cmdline = property(lambda self: self._stringa(3))

    def module_list(self):
        return [_Modulo(e) for e in self._v._mappa("VMMDLL_Map_GetModuleU", _ModuloVoce, MAP_MODULE_VERSIONE, self.pid, 0)]


class _Valore:
    def __init__(self, vmm, chiave, nome, tipo, size):
        self._v, self._chiave = vmm, chiave
        self.name, self.type, self.size = nome, tipo, size

    @property
    def value(self):
        percorso = (self._chiave + "\\" + self.name).encode("utf-8")      # il valore predefinito si chiama «(Default)»
        tipo, cb = C.c_uint32(0), C.c_uint32(0)
        if not self._v._lib.VMMDLL_WinReg_QueryValueExU(self._v._h, percorso, C.byref(tipo), None, C.byref(cb)):
            raise RuntimeError("Vmm.reg_value: " + self.name)
        if not cb.value:
            return b""
        buf = C.create_string_buffer(cb.value)
        if not self._v._lib.VMMDLL_WinReg_QueryValueExU(self._v._h, percorso, C.byref(tipo), buf, C.byref(cb)):
            raise RuntimeError("Vmm.reg_value: " + self.name)
        return C.string_at(buf, cb.value)


class _Chiave:
    def __init__(self, vmm, percorso, nome=None, tempo=None):
        self._v, self.path = vmm, percorso
        if tempo is None:
            buf, cch, ft = C.create_string_buffer(1024), C.c_uint32(1024), C.c_uint64(0)
            if not vmm._lib.VMMDLL_WinReg_EnumKeyExU(vmm._h, percorso.encode("utf-8"), NO_INDICE, buf, C.byref(cch), C.byref(ft)):
                raise RuntimeError("Vmm.reg_key(): " + percorso)
            tempo = ft.value
        self.name = nome if nome is not None else percorso.rstrip("\\").rsplit("\\", 1)[-1]
        self.time_int = int(tempo)

    def subkeys(self):
        out, i, p = [], 0, self.path.encode("utf-8")
        while True:
            buf, cch, ft = C.create_string_buffer(1024), C.c_uint32(1024), C.c_uint64(0)
            if not self._v._lib.VMMDLL_WinReg_EnumKeyExU(self._v._h, p, i, buf, C.byref(cch), C.byref(ft)):
                break
            nome = _testo(buf.value)
            out.append(_Chiave(self._v, self.path + "\\" + nome, nome, ft.value))
            i += 1
        return out

    def values(self):
        out, i, p = [], 0, self.path.encode("utf-8")
        while True:
            buf, cch, tipo, cb = C.create_string_buffer(1024), C.c_uint32(1024), C.c_uint32(0), C.c_uint32(0)
            if not self._v._lib.VMMDLL_WinReg_EnumValueU(self._v._h, p, i, buf, C.byref(cch), C.byref(tipo), None, C.byref(cb)):
                break
            out.append(_Valore(self._v, self.path, _testo(buf.value), tipo.value, cb.value))
            i += 1
        return out


class _Hive:
    def __init__(self, vmm, h):
        self._v = vmm
        self.name, self.name_short, self.path = _testo(h.uszName), _testo(h.uszNameShort), _testo(h.uszHiveRootPath)
        self.size, self.addr, self.addr_baseblock = h.cbLength, h.vaCMHIVE, h.vaHBASE_BLOCK

    @property
    def rootkey(self):
        return _Chiave(self._v, f"0x{self.addr:016x}\\ROOT")


class _Mappe:
    def __init__(self, vmm):
        self._v = vmm

    def user(self):
        return [{"va-reghive": e.vaRegHive, "sid": _testo(e.uszSID), "name": _testo(e.uszText)}
                for e in self._v._mappa("VMMDLL_Map_GetUsersU", _UtenteVoce, MAP_USER_VERSIONE)]

    def kdriver(self):
        return [{"va": e.va, "va-driver-start": e.vaDriverStart, "size": e.cbDriverSize, "va-device": e.vaDeviceObject,
                 "name": _testo(e.uszName), "path": _testo(e.uszPath), "service_key_name": _testo(e.uszServiceKeyName)}
                for e in self._v._mappa("VMMDLL_Map_GetKDriverU", _DriverVoce, MAP_KDRIVER_VERSIONE)]


class Vmm:
    """Un dump aperto. `argomenti` come per MemProcFS (es. ["-device", file, "-disable-symbolserver"])."""

    def __init__(self, argomenti, cartella=None):
        self._lib = libreria(cartella or CARTELLA)
        arg = [b""] + [str(a).encode("utf-8") for a in argomenti]
        self._h = self._lib.VMMDLL_Initialize(len(arg), (C.c_char_p * len(arg))(*arg))
        if not self._h:
            raise RuntimeError("Vmm.init(): Initialization of vmm failed.")
        # il file system virtuale (/sys, /registry, /forensic…) esiste solo dopo l'avvio dei plugin interni (vmmdll.h)
        if not self._lib.VMMDLL_InitializePlugins(self._h):
            self.close()
            raise RuntimeError("Vmm.init(): Initialization of plugins failed.")
        self.vfs, self.maps = _Vfs(self), _Mappe(self)

    def close(self):
        if self._h:
            self._lib.VMMDLL_Close(self._h)
            self._h = None

    def versione(self):
        v = []
        for o in (OPT_VER_MAJOR, OPT_VER_MINOR, OPT_VER_REVISION):
            q = C.c_uint64(0)
            if not self._lib.VMMDLL_ConfigGet(self._h, o, C.byref(q)):
                return ""
            v.append(str(q.value))
        return ".".join(v)

    def _mappa(self, funzione, voce, versione_attesa, *arg):
        """Chiama una VMMDLL_Map_Get*: copia le voci in oggetti Python prima di liberare la memoria della libreria."""
        p = C.c_void_p(None)
        f = getattr(self._lib, funzione)
        ok = f(self._h, arg[0], C.byref(p), arg[1]) if arg else f(self._h, C.byref(p))
        if not ok or not p.value:
            raise RuntimeError(funzione)
        try:
            testa = _MappaTesta.from_address(p.value)
            if testa.dwVersion != versione_attesa:
                raise RuntimeError(f"{funzione}: versione {testa.dwVersion}, attesa {versione_attesa}")
            voci = (voce * testa.cMap).from_address(p.value + C.sizeof(_MappaTesta))
            return [_Copia(e, voce) for e in voci]
        finally:
            self._lib.VMMDLL_MemFree(p)

    def process_list(self):
        n = C.c_size_t(0)
        if not self._lib.VMMDLL_PidList(self._h, None, C.byref(n)):
            raise RuntimeError("Vmm.process_list()")
        pid = (C.c_uint32 * max(1, n.value))()
        if not self._lib.VMMDLL_PidList(self._h, pid, C.byref(n)):
            raise RuntimeError("Vmm.process_list()")
        out = []
        for i in range(n.value):
            try:
                out.append(self.process(pid[i]))
            except RuntimeError:
                continue
        return out

    def process(self, pid):
        info = _ProcInfo()
        info.magic, info.wVersion = PROC_MAGIC, PROC_VERSIONE
        cb = C.c_size_t(C.sizeof(_ProcInfo))
        if not self._lib.VMMDLL_ProcessGetInformation(self._h, int(pid), C.byref(info), C.byref(cb)):
            raise RuntimeError(f"Vmm.process({pid})")
        return _Processo(self, info)

    def reg_hive_list(self):
        n = C.c_uint32(0)
        if not self._lib.VMMDLL_WinReg_HiveList(self._h, None, 0, C.byref(n)) or not n.value:
            return []
        hive = (_HiveInfo * n.value)()
        for h in hive:
            h.magic, h.wVersion = HIVE_MAGIC, HIVE_VERSIONE
        if not self._lib.VMMDLL_WinReg_HiveList(self._h, hive, n.value, C.byref(n)):
            raise RuntimeError("Vmm.reg_hive_list()")
        return [_Hive(self, hive[i]) for i in range(n.value)]

    def reg_key(self, percorso):
        return _Chiave(self, str(percorso).rstrip("\\"))


class _Copia:
    """Copia dei campi di una voce di mappa: le stringhe della libreria vengono liberate con la mappa."""

    def __init__(self, e, voce):
        for nome, _tipo in voce._fields_:
            if not nome.startswith("_") and nome != "MajorFunction":
                setattr(self, nome, getattr(e, nome))


CARTELLA = None          # impostata da forense_ram.carica(): la cartella con la libreria
