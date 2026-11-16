# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""forense_artefatto.py - RepertIA by silvexe.
(3.0.5) Analisi completa di un singolo artefatto di Windows per la scheda «Decodifica» dell'anteprima: collegamenti
(.lnk), jump list (automaticDestinations e customDestinations), Prefetch (.pf), indici del cestino ($I) e, per i file
su NTFS, le date dei due attributi $STANDARD_INFORMATION e $FILE_NAME affiancate (dall'istat di Sleuth Kit).

Legge solo il file indicato (una copia locale estratta dal reperto), con le librerie già nei pacchetti: liblnk,
libfwsi, libolecf, libscca. Tutte le date sono in UTC, come sono scritte nell'artefatto. Il risultato è un elenco di
sezioni (titolo, righe chiave/valore) che la pagina mostra e che `come_testo` scrive in un file di testo."""
import datetime as dt
import io
import re
import struct
import uuid
from pathlib import Path
from forense_lingua import tr

MAX_VOCI = 500          # voci di una jump list mostrate
MAX_FILE_PF = 3000      # file caricati di un Prefetch mostrati

LINK_FLAGS = ("HasLinkTargetIDList", "HasLinkInfo", "HasName", "HasRelativePath", "HasWorkingDir", "HasArguments",
              "HasIconLocation", "IsUnicode", "ForceNoLinkInfo", "HasExpString", "RunInSeparateProcess", "Unused1",
              "HasDarwinID", "RunAsUser", "HasExpIcon", "NoPidlAlias", "Unused2", "RunWithShimLayer",
              "ForceNoLinkTrack", "EnableTargetMetadata", "DisableLinkPathTracking", "DisableKnownFolderTracking",
              "DisableKnownFolderAlias", "AllowLinkToLink", "UnaliasOnSave", "PreferEnvironmentPath",
              "KeepLocalIDListForUNCTarget")
FILE_ATTR = ((0x1, "READONLY"), (0x2, "HIDDEN"), (0x4, "SYSTEM"), (0x10, "DIRECTORY"), (0x20, "ARCHIVE"),
             (0x40, "DEVICE"), (0x80, "NORMAL"), (0x100, "TEMPORARY"), (0x200, "SPARSE_FILE"),
             (0x400, "REPARSE_POINT"), (0x800, "COMPRESSED"), (0x1000, "OFFLINE"), (0x2000, "NOT_CONTENT_INDEXED"),
             (0x4000, "ENCRYPTED"))
SHOW_WINDOW = {1: "SW_SHOWNORMAL", 3: "SW_SHOWMAXIMIZED", 7: "SW_SHOWMINNOACTIVE"}
LINK_INFO_FLAGS = ("VolumeIDAndLocalBasePath", "CommonNetworkRelativeLinkAndPathSuffix")
DRIVE_TYPE = {0: "DRIVE_UNKNOWN", 1: "DRIVE_NO_ROOT_DIR", 2: "DRIVE_REMOVABLE", 3: "DRIVE_FIXED", 4: "DRIVE_REMOTE",
              5: "DRIVE_CDROM", 6: "DRIVE_RAMDISK"}
DATA_BLOCK = {0xA0000001: "EnvironmentVariableDataBlock", 0xA0000002: "ConsoleDataBlock",
              0xA0000003: "TrackerDataBlock", 0xA0000004: "ConsoleFEDataBlock", 0xA0000005: "SpecialFolderDataBlock",
              0xA0000006: "DarwinDataBlock", 0xA0000007: "IconEnvironmentDataBlock", 0xA0000008: "ShimDataBlock",
              0xA0000009: "PropertyStoreDataBlock", 0xA000000B: "KnownFolderDataBlock",
              0xA000000C: "VistaAndAboveIDListDataBlock"}
CSIDL = {0: "Desktop", 2: "Programs", 5: "MyDocuments", 6: "Favorites", 7: "Startup", 8: "Recent", 9: "SendTo",
         11: "StartMenu", 13: "MyMusic", 14: "MyVideo", 16: "DesktopDirectory", 17: "MyComputer", 19: "NetHood",
         20: "Fonts", 21: "Templates", 22: "CommonStartMenu", 23: "CommonPrograms", 24: "CommonStartup",
         25: "CommonDesktopDirectory", 26: "AppData", 28: "LocalAppData", 32: "InternetCache", 33: "Cookies",
         34: "History", 35: "CommonAppData", 36: "Windows", 37: "System", 38: "ProgramFiles", 39: "MyPictures",
         40: "Profile", 43: "ProgramFilesCommon", 46: "CommonDocuments", 53: "CommonMusic", 54: "CommonPictures",
         55: "CommonVideo"}
CLSID = {"20d04fe0-3aea-1069-a2d8-08002b30309d": "My Computer", "450d8fba-ad25-11d0-98a8-0800361b1103": "My Documents",
         "208d2c60-3aea-1069-a2d7-08002b30309d": "Network", "645ff040-5081-101b-9f08-00aa002f954e": "Recycle Bin",
         "871c5380-42a0-1069-a2ea-08002b30309d": "Internet Explorer", "59031a47-3f72-44a7-89c5-5595fe6b30ee": "Users",
         "031e4825-7b94-4dc3-b131-e946b44c8dd5": "Libraries", "f02c1a0d-be21-4350-88b0-7367fc96ef3c": "Network",
         "26ee0668-a00a-44d7-9371-beb064c98683": "Control Panel", "018d5c66-4533-4307-9b53-224de2ed1fe6": "OneDrive",
         "679f85cb-0220-4080-b29b-5540cc05aab6": "Quick Access", "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
         "d3162b92-9365-467a-956b-92703aca08af": "Documents", "088e3905-0323-4b02-9826-5d99428e115f": "Downloads",
         "24ad3ad4-a569-4530-98e1-ab02f9417aa8": "Pictures", "3dfdf296-dbec-4fb4-81d1-6a3438bcf4de": "Music",
         "f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a": "Videos", "dfdf76a2-c82a-4d63-906a-5644ac457385": "Public",
         "c4aa340d-f20f-4863-afef-f87ef2e6ba25": "Public Desktop", "ed4824af-dce4-45a8-81e2-fc7965083634": "Public Documents",
         "b6ebfb86-6907-413c-9af7-4fc2abf07cc5": "Public Pictures", "3214fab5-9757-4298-bb61-92a9deaa44ff": "Public Music",
         "2400183a-6185-49fb-a2d8-4a392a602ba3": "Public Videos"}
LNK_FIRMA = b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F"


def tipo(nome):
    """Tipo di artefatto dal nome del file ('lnk', 'jump_auto', 'jump_custom', 'prefetch', 'cestino') o None."""
    n = re.split(r"[/\\]", str(nome or "").split(" › ")[-1])[-1].lower()
    if n.endswith(".lnk"):
        return "lnk"
    if n.endswith(".automaticdestinations-ms"):
        return "jump_auto"
    if n.endswith(".customdestinations-ms"):
        return "jump_custom"
    if n.endswith(".pf"):
        return "prefetch"
    if re.fullmatch(r"\$i[a-z0-9]{6}(\.[^.]*)?", n):
        return "cestino"
    return None


def nome_tipo(t):
    return {"lnk": tr("Collegamento di Windows (LNK)"), "jump_auto": tr("Jump list (automaticDestinations)"),
            "jump_custom": tr("Jump list (customDestinations)"), "prefetch": tr("Prefetch di Windows"),
            "cestino": tr("Indice del cestino di Windows ($I)")}.get(t, "")


# ---------------------------------------------------------------------------------------------------------- utilità
def _data(d):
    """datetime UTC (delle librerie libyal) -> 'AAAA-MM-GG HH:MM:SS[.frazione] UTC'; '' se assente."""
    if d is None:
        return ""
    try:
        if d.tzinfo is not None:
            d = d.astimezone(dt.timezone.utc).replace(tzinfo=None)
        if d.year <= 1601:
            return tr("non impostata")
        fr = f".{d.microsecond:06d}".rstrip("0") if d.microsecond else ""
        return d.strftime("%Y-%m-%d %H:%M:%S") + fr + " UTC"
    except (ValueError, OverflowError, AttributeError):
        return ""


def _filetime(n):
    try:
        n = int(n)
        if n <= 0:
            return tr("non impostata")
        return _data(dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=n // 10))
    except (ValueError, OverflowError, TypeError):
        return ""


def _prova(f, *a):
    """Valore di un metodo o attributo di una libreria, None se manca o dà errore (file rovinati)."""
    try:
        return f(*a) if callable(f) else f
    except Exception:
        return None


def _attr(o, nome):
    try:
        return getattr(o, nome)
    except Exception:
        return None


def _flags(v, nomi):
    if v is None:
        return ""
    att = [n for i, n in enumerate(nomi) if v & (1 << i)] if isinstance(nomi[0], str) else [n for b, n in nomi if v & b]
    return f"0x{v:08x}" + (f"  ({', '.join(att)})" if att else "")


def _seriale(v):
    return f"{(v >> 16) & 0xffff:04x}-{v & 0xffff:04x}" if isinstance(v, int) else ""


def _guid_info(g):
    """Indirizzo MAC, data e sequenza di un identificatore di tipo UUID versione 1; {} se non lo è."""
    try:
        u = uuid.UUID(str(g))
    except (ValueError, AttributeError, TypeError):
        return {}
    if u.version != 1:
        return {}
    mac = f"{u.node:012x}"
    quando = dt.datetime(1582, 10, 15) + dt.timedelta(microseconds=u.time // 10)
    return {"mac": ":".join(mac[i:i + 2] for i in range(0, 12, 2)), "data": _data(quando), "seq": u.clock_seq}


def _sez(titolo, righe):
    """Sezione senza le righe vuote; None se non ne resta nessuna."""
    r = [[k, str(v)] for k, v in righe if v not in (None, "")]
    return {"titolo": titolo, "righe": r} if r else None


def _hotkey(v):
    if not v:
        return "0x0000  (" + tr("nessuno") + ")"
    mod = [n for b, n in ((1, "SHIFT"), (2, "CTRL"), (4, "ALT")) if (v >> 8) & b]
    k = v & 0xff
    tasto = chr(k) if 0x30 <= k <= 0x5a else f"F{k - 0x6f}" if 0x70 <= k <= 0x87 else f"0x{k:02x}"
    return f"0x{v:04x}  ({'+'.join(mod + [tasto])})"


# ------------------------------------------------------------------------------------------------- collegamenti LNK
def _voci_idlist(dati):
    """Sezioni dell'elenco delle cartelle della destinazione (Link Target ID List), con libfwsi."""
    try:
        import pyfwsi
    except ImportError:
        return [_sez(tr("Elenco delle cartelle della destinazione (Link Target ID List)"),
                     [(tr("Nota"), tr("libfwsi non disponibile: elenco non decodificato"))])]
    out = []
    try:
        il = pyfwsi.item_list()
        il.copy_from_byte_stream(dati)
        n = il.number_of_items
    except Exception as e:
        return [_sez(tr("Elenco delle cartelle della destinazione (Link Target ID List)"),
                     [(tr("Nota"), tr("elenco non decodificato: {e}").format(e=e))])]
    for i in range(n):
        try:
            it = il.get_item(i)
        except Exception:
            continue
        classe = type(it).__name__
        righe = [(tr("Tipo di elemento"), f"{classe}  (0x{(_attr(it, 'class_type') or 0):02x})")]
        if classe == "root_folder":
            g = str(_attr(it, "shell_folder_identifier") or "")
            righe.append(("CLSID", g + (f" = {CLSID[g.lower()]}" if g.lower() in CLSID else "")))
        elif classe == "volume":
            righe += [(tr("Nome del volume"), _attr(it, "name")), (tr("Identificatore"), _attr(it, "identifier")),
                      ("CLSID", _attr(it, "shell_folder_identifier"))]
        elif classe == "file_entry":
            at = _attr(it, "file_attribute_flags")
            cartella = bool(at and at & 0x10)
            righe += [(tr("Nome corto (8.3)"), _attr(it, "name")),
                      (tr("Ultima modifica"), _data(_attr(it, "modification_time"))),
                      (tr("Attributi"), _flags(at, FILE_ATTR))]
            if not cartella:
                righe.append((tr("Dimensione"), tr("{n} byte").format(n=_attr(it, "file_size"))))
        elif classe == "network_location":
            righe += [(tr("Percorso di rete"), _attr(it, "location")), (tr("Descrizione"), _attr(it, "description")),
                      (tr("Commento"), _attr(it, "comments"))]
        g = _attr(it, "delegate_folder_identifier")
        if g:
            righe.append((tr("Cartella delegata"), g))
        for eb in (_attr(it, "extension_blocks") or []):
            if type(eb).__name__ == "file_entry_extension":
                rif = _attr(eb, "file_reference")
                righe += [(tr("Nome lungo"), _attr(eb, "long_name")),
                          (tr("Nome localizzato"), _attr(eb, "localized_name")),
                          (tr("Data di creazione"), _data(_attr(eb, "creation_time"))),
                          (tr("Ultimo accesso"), _data(_attr(eb, "access_time")))]
                if rif:
                    righe.append((tr("Riferimento NTFS (voce MFT-sequenza)"), f"{rif & 0xffffffffffff}-{rif >> 48}"))
            else:
                sg = _attr(eb, "signature")
                if sg is not None:
                    righe.append((tr("Blocco di estensione"), f"0x{sg:08x}"))
        s = _sez(tr("Elemento {n} dell'elenco").format(n=i + 1), righe)
        if s:
            out.append(s)
    return out


def _blocchi_grezzi(grezzo):
    """Dai byte del collegamento: cartella speciale e cartella nota (blocchi che liblnk non espone per nome)."""
    righe = []
    p = grezzo.find(b"\x10\x00\x00\x00\x05\x00\x00\xa0")
    if p >= 0 and p + 16 <= len(grezzo):
        ident, off = struct.unpack_from("<II", grezzo, p + 8)
        righe += [(tr("Identificatore della cartella speciale"), f"{ident}" + (f"  ({CSIDL[ident]})" if ident in CSIDL else "")),
                  (tr("Posizione del primo elemento figlio"), tr("{n} byte").format(n=off))]
    p = grezzo.find(b"\x1c\x00\x00\x00\x0b\x00\x00\xa0")
    if p >= 0 and p + 28 <= len(grezzo):
        g = str(uuid.UUID(bytes_le=grezzo[p + 8:p + 24]))
        righe += [(tr("Identificatore della cartella nota"), g + (f" = {CLSID[g]}" if g in CLSID else "")),
                  (tr("Posizione del primo elemento figlio"), tr("{n} byte").format(n=struct.unpack_from("<I", grezzo, p + 24)[0]))]
    return righe


def _link_info_flags(grezzo, fl):
    """Opzioni della struttura Link Info (liblnk non le espone): dai byte, dopo l'intestazione e l'elenco delle cartelle."""
    if not fl or not fl & 0x2 or len(grezzo) < 78:
        return None
    p = 76
    if fl & 0x1:
        p += 2 + struct.unpack_from("<H", grezzo, p)[0]
    if p + 12 > len(grezzo):
        return None
    dim, dint, opz = struct.unpack_from("<III", grezzo, p)
    return opz if 12 <= dint <= dim <= len(grezzo) - p else None


def analizza_lnk(grezzo):
    """Sezioni di un collegamento LNK dai suoi byte. Solleva ValueError se non è leggibile."""
    try:
        import pylnk
    except ImportError:
        raise ValueError(tr("liblnk non è disponibile in questa installazione."))
    lf = pylnk.file()
    try:
        lf.open_file_object(io.BytesIO(grezzo))
    except Exception as e:
        raise ValueError(tr("Collegamento non leggibile: {e}").format(e=e))
    sez = []
    try:
        fl = _attr(lf, "data_flags")
        sez.append(_sez(tr("Intestazione (destinazione del collegamento)"), [
            (tr("Data di creazione"), _data(_prova(lf.get_file_creation_time))),
            (tr("Ultimo accesso"), _data(_prova(lf.get_file_access_time))),
            (tr("Ultima modifica"), _data(_prova(lf.get_file_modification_time))),
            (tr("Dimensione del file"), tr("{n} byte").format(n=_attr(lf, "file_size"))),
            (tr("Attributi del file"), _flags(_attr(lf, "file_attribute_flags"), FILE_ATTR)),
            (tr("Indice dell'icona"), (lambda v: v - (1 << 32) if isinstance(v, int) and v > 0x7fffffff else v)(_attr(lf, "icon_index"))),
            (tr("Finestra all'apertura"), (lambda v: f"{v}  ({SHOW_WINDOW.get(v, '?')})" if v is not None else "")(_attr(lf, "show_window_value"))),
            (tr("Tasto di scelta rapida"), _hotkey(_attr(lf, "hot_key_value"))),
            (tr("Opzioni del collegamento (link flags)"), _flags(fl, LINK_FLAGS)),
            (tr("Collegamento rovinato"), tr("sì") if _prova(lf.is_corrupted) else "")]))
        idl = _attr(lf, "link_target_identifier_data")
        if idl:
            sez += _voci_idlist(idl)
        else:       # senza elenco nell'intestazione: può stare nel blocco aggiuntivo VistaAndAboveIDListDataBlock
            p = grezzo.rfind(bytes.fromhex("0c0000a0"))
            n = struct.unpack_from("<I", grezzo, p - 4)[0] if p >= 4 else 0
            if 10 <= n <= len(grezzo) - (p - 4):
                sez.append(_sez(tr("Elenco delle cartelle della destinazione (Link Target ID List)"),
                                [(tr("Origine"), "VistaAndAboveIDListDataBlock")]))
                sez += _voci_idlist(grezzo[p + 4:p - 4 + n])
        dtp = _attr(lf, "drive_type")
        sez.append(_sez(tr("Volume e percorso (Link Info)"), [
            (tr("Opzioni della posizione (location flags)"), _flags(_link_info_flags(grezzo, fl), LINK_INFO_FLAGS)),
            (tr("Tipo di unità"), f"{dtp}  ({DRIVE_TYPE.get(dtp, '?')})" if dtp is not None and (_attr(lf, "local_path") or _attr(lf, "drive_serial_number")) else ""),
            (tr("Numero di serie del volume"), _seriale(_attr(lf, "drive_serial_number")) if _attr(lf, "drive_serial_number") else ""),
            (tr("Etichetta del volume"), _attr(lf, "volume_label")),
            (tr("Percorso locale"), _attr(lf, "local_path")),
            (tr("Percorso di rete"), _attr(lf, "network_path"))]))
        sez.append(_sez(tr("Stringhe (String Data)"), [
            (tr("Descrizione"), _attr(lf, "description")),
            (tr("Percorso relativo"), _attr(lf, "relative_path")),
            (tr("Cartella di lavoro"), _attr(lf, "working_directory")),
            (tr("Argomenti della riga di comando"), _attr(lf, "command_line_arguments")),
            (tr("Posizione dell'icona"), _attr(lf, "icon_location")),
            (tr("Percorso con variabili d'ambiente"), _attr(lf, "environment_variables_location"))]))
        sez.append(_sez(tr("Cartella speciale (Special Folder / Known Folder)"), _blocchi_grezzi(grezzo)))
        df, dv = _attr(lf, "droid_file_identifier"), _attr(lf, "droid_volume_identifier")
        bf, bv = _attr(lf, "birth_droid_file_identifier"), _attr(lf, "birth_droid_volume_identifier")
        gi = _guid_info(df) or _guid_info(bf)
        sez.append(_sez(tr("Tracciamento (Distributed Link Tracker)"), [
            (tr("Nome del computer (NetBIOS)"), _attr(lf, "machine_identifier")),
            (tr("Identificatore del volume (droid)"), dv), (tr("Identificatore del file (droid)"), df),
            (tr("Identificatore del volume alla nascita"), bv), (tr("Identificatore del file alla nascita"), bf),
            (tr("Indirizzo MAC (dall'identificatore del file)"), gi.get("mac")),
            (tr("Data dell'identificatore"), gi.get("data")),
            (tr("Numero di sequenza dell'identificatore"), gi.get("seq"))]))
        blocchi = []
        for i in range(_attr(lf, "number_of_data_blocks") or 0):
            sg = _attr(_prova(lf.get_data_block, i), "signature")
            if sg is not None:
                blocchi.append((tr("Blocco {n}").format(n=i + 1), f"0x{sg:08x}  ({DATA_BLOCK.get(sg, '?')})"))
        sez.append(_sez(tr("Blocchi di dati aggiuntivi (Extra Data)"), blocchi))
    finally:
        _prova(lf.close)
    return [s for s in sez if s]


def _destinazione(sez):
    """Percorso della destinazione di un collegamento già analizzato (per il titolo di una voce)."""
    for s in sez:
        for k, v in s["righe"]:
            if k in (tr("Percorso locale"), tr("Percorso di rete")):
                return v
    for s in sez:
        for k, v in s["righe"]:
            if k == tr("Percorso relativo"):
                return v
    return ""


# ------------------------------------------------------------------------------------------------------- jump list
def _destlist(d):
    """DestList di una jump list automatica: (intestazione, {numero voce: righe})."""
    if len(d) < 32:
        return [], {}
    ver, n, fissate = struct.unpack_from("<III", d, 0)
    testa = [(tr("Versione del formato"), ver), (tr("Voci"), n), (tr("Voci fissate"), fissate)]
    out, pos = {}, 32
    for _ in range(min(n, 5000)):
        try:
            host = d[pos + 72:pos + 88].split(b"\x00")[0].decode("ascii", "ignore")
            num = struct.unpack_from("<I", d, pos + 88)[0]
            acc = struct.unpack_from("<Q", d, pos + 100)[0]
            fiss = struct.unpack_from("<i", d, pos + 108)[0]
            righe = [(tr("Numero della voce"), f"{num}  (0x{num:x})"), (tr("Ultimo accesso"), _filetime(acc)),
                     (tr("Fissata"), tr("no") if fiss == -1 else tr("sì, posizione {n}").format(n=fiss)),
                     (tr("Nome del computer (NetBIOS)"), host)]
            for nome, a in ((tr("Identificatore del volume (droid)"), 8), (tr("Identificatore del file (droid)"), 24),
                            (tr("Identificatore del volume alla nascita"), 40), (tr("Identificatore del file alla nascita"), 56)):
                righe.append((nome, str(uuid.UUID(bytes_le=d[pos + a:pos + a + 16]))))
            if ver >= 3:
                righe.insert(2, (tr("Volte aperto"), struct.unpack_from("<I", d, pos + 116)[0]))
                ln = struct.unpack_from("<H", d, pos + 128)[0]
                percorso = d[pos + 130:pos + 130 + ln * 2].decode("utf-16-le", "replace")
                pos += 130 + ln * 2 + 4
            else:
                ln = struct.unpack_from("<H", d, pos + 112)[0]
                percorso = d[pos + 114:pos + 114 + ln * 2].decode("utf-16-le", "replace")
                pos += 114 + ln * 2
            righe.insert(1, (tr("Percorso (DestList)"), percorso))
            out[num] = righe
        except (struct.error, ValueError):
            break
    return testa, out


def analizza_jump_auto(percorso):
    try:
        import pyolecf
    except ImportError:
        raise ValueError(tr("libolecf non è disponibile in questa installazione."))
    of = pyolecf.file()
    try:
        of.open(str(percorso))
    except Exception as e:
        raise ValueError(tr("Jump list non leggibile: {e}").format(e=e))
    voci, sez, dl = [], [], {}
    try:
        r = of.root_item
        figli = [r.get_sub_item(i) for i in range(r.number_of_sub_items)]
        for it in figli:
            if (it.name or "").lower() == "destlist" and it.size:
                testa, dl = _destlist(it.read(it.size))
                sez.append(_sez(tr("Elenco delle destinazioni (DestList)"), testa))
        flussi = [it for it in figli if (it.name or "").lower() != "destlist" and it.size]
        for it in flussi[:MAX_VOCI]:
            try:
                num = int(it.name, 16)
            except (TypeError, ValueError):
                num = None
            try:
                sl = analizza_lnk(it.read(it.size))
            except ValueError as e:
                sl = [_sez(tr("Nota"), [(tr("Nota"), str(e))])]
            testa = _sez(tr("Voce nel DestList"), dl.get(num, []))
            dal_destlist = next((v for k, v in dl.get(num, []) if k == tr("Percorso (DestList)")), "")
            voci.append({"titolo": tr("Voce {nome} — {dest}").format(nome=it.name, dest=_destinazione(sl) or dal_destlist or "?"),
                         "sezioni": ([testa] if testa else []) + sl})
        sez.insert(0, _sez(tr("Jump list"), [(tr("Collegamenti contenuti"), len(flussi)),
                                             (tr("Mostrati"), len(voci) if len(flussi) > MAX_VOCI else "")]))
    finally:
        _prova(of.close)
    return [s for s in sez if s], voci


def analizza_jump_custom(grezzo):
    pos, p = [], grezzo.find(LNK_FIRMA)
    while p >= 0:
        pos.append(p)
        p = grezzo.find(LNK_FIRMA, p + len(LNK_FIRMA))
    voci = []
    for i, a in enumerate(pos[:MAX_VOCI]):
        b = pos[i + 1] if i + 1 < len(pos) else len(grezzo)
        try:
            sl = analizza_lnk(grezzo[a:b])
        except ValueError as e:
            sl = [_sez(tr("Nota"), [(tr("Nota"), str(e))])]
        voci.append({"titolo": tr("Voce {nome} — {dest}").format(nome=i + 1, dest=_destinazione(sl) or "?"),
                     "sezioni": [_sez(tr("Posizione nel file"), [(tr("Byte"), f"{a} – {b - 1}")])] + sl})
    sez = [_sez(tr("Jump list"), [(tr("Collegamenti contenuti"), len(pos)),
                                  (tr("Mostrati"), len(voci) if len(pos) > MAX_VOCI else "")])]
    return [s for s in sez if s], voci


# -------------------------------------------------------------------------------------------------------- Prefetch
def analizza_prefetch(percorso):
    try:
        import pyscca
    except ImportError:
        raise ValueError(tr("libscca non è disponibile in questa installazione."))
    sf = pyscca.file()
    try:
        sf.open(str(percorso))
    except Exception as e:
        raise ValueError(tr("Prefetch non leggibile: {e}").format(e=e))
    sez = []
    try:
        h = _attr(sf, "prefetch_hash")
        sez.append(_sez(tr("Intestazione"), [
            (tr("Versione del formato"), _attr(sf, "format_version")),
            (tr("Programma"), _attr(sf, "executable_filename")),
            (tr("Impronta del percorso (prefetch hash)"), f"0x{h:08x}" if isinstance(h, int) else ""),
            (tr("Numero di esecuzioni"), _attr(sf, "run_count"))]))
        tempi = []
        for i in range(8):
            n = _prova(sf.get_last_run_time_as_integer, i)
            if n:
                tempi.append((tr("Esecuzione {n}").format(n=len(tempi) + 1), _filetime(n)))
        sez.append(_sez(tr("Ultime esecuzioni (dalla più recente)"), tempi))
        for i in range(_attr(sf, "number_of_volumes") or 0):
            v = _prova(sf.get_volume_information, i)
            if v is None:
                continue
            sn = _attr(v, "serial_number")
            sez.append(_sez(tr("Volume {n}").format(n=i + 1), [
                (tr("Percorso del dispositivo"), _attr(v, "device_path")),
                (tr("Data di creazione"), _data(_attr(v, "creation_time"))),
                (tr("Numero di serie del volume"), _seriale(sn) if isinstance(sn, int) else "")]))
        nf = _attr(sf, "number_of_filenames") or 0
        nomi = [(str(i + 1), _prova(sf.get_filename, i) or "") for i in range(min(nf, MAX_FILE_PF))]
        sez.append(_sez(tr("File caricati dal programma ({n})").format(n=nf) +
                        (tr(" — mostrati i primi {n}").format(n=MAX_FILE_PF) if nf > MAX_FILE_PF else ""), nomi))
    finally:
        _prova(sf.close)
    return [s for s in sez if s]


# ---------------------------------------------------------------------------------------------------------- cestino
def analizza_cestino(grezzo):
    if len(grezzo) < 28:
        raise ValueError(tr("Indice del cestino troppo corto."))
    ver, size, t = struct.unpack_from("<QQQ", grezzo, 0)
    if ver == 1:
        orig = grezzo[24:24 + 520].decode("utf-16-le", "ignore").split("\x00")[0]
    elif ver == 2:
        n = struct.unpack_from("<I", grezzo, 24)[0]
        orig = grezzo[28:28 + n * 2].decode("utf-16-le", "ignore").split("\x00")[0]
    else:
        raise ValueError(tr("Indice del cestino con una versione non riconosciuta ({v}).").format(v=ver))
    return [_sez(tr("Indice del cestino ($I)"), [
        (tr("Versione del formato"), f"{ver}  ({'Windows Vista – 8.1' if ver == 1 else 'Windows 10 / 11'})"),
        (tr("Percorso originale"), orig),
        (tr("Dimensione del file cancellato"), tr("{n} byte").format(n=size)),
        (tr("Data di cancellazione"), _filetime(t)),
        (tr("Contenuto"), tr("nel file con lo stesso nome che inizia per $R, nella stessa cartella"))])]


# ------------------------------------------------------------------------------------------------------- date NTFS
_ISTAT_BLOCCO = re.compile(r"\$(STANDARD_INFORMATION|FILE_NAME) Attribute Values:\s*\n(.*?)(?=\n\s*\n|\n\$|\nAttributes:|\Z)", re.S)
_ISTAT_RIGA = re.compile(r"^\s*(Created|File Modified|MFT Modified|Accessed):\s*(.+?)\s*$", re.M)


def date_ntfs(istat):
    """Dall'istat di Sleuth Kit su NTFS: le quattro date di $STANDARD_INFORMATION e di $FILE_NAME affiancate.
    Restituisce una sezione con tre colonne, o None se il file non è su NTFS."""
    blocchi = {m.group(1): dict(_ISTAT_RIGA.findall(m.group(2))) for m in _ISTAT_BLOCCO.finditer(istat or "")}
    si, fn = blocchi.get("STANDARD_INFORMATION"), blocchi.get("FILE_NAME")
    if not si or not fn:
        return None
    nomi = (("Created", tr("Creazione")), ("File Modified", tr("Modifica del contenuto")),
            ("MFT Modified", tr("Modifica della voce MFT")), ("Accessed", tr("Ultimo accesso")))
    righe = [[it, si.get(en, ""), fn.get(en, "")] for en, it in nomi]
    diverse = any(a != b for _, a, b in righe)
    return {"titolo": tr("Date NTFS: $STANDARD_INFORMATION e $FILE_NAME"),
            "colonne": ["", "$STANDARD_INFORMATION", "$FILE_NAME"], "righe": righe,
            "nota": (tr("Le date dei due attributi differiscono. $FILE_NAME si aggiorna di rado (creazione, "
                        "spostamento, cambio di nome), quindi una differenza è spesso normale; una data di "
                        "$STANDARD_INFORMATION precedente a quella di $FILE_NAME può dipendere da una copia o da "
                        "uno spostamento, oppure da una modifica delle date.") if diverse
                     else tr("Le date dei due attributi coincidono."))}


# ----------------------------------------------------------------------------------------------------------- insieme
def analizza(percorso, nome):
    """Analisi dell'artefatto nel file locale `percorso` (nome originale `nome`).
    Restituisce {"tipo", "titolo", "sezioni", "voci"}; ValueError se il tipo non è gestito o il file non si legge."""
    t = tipo(nome)
    if not t:
        raise ValueError(tr("Per questo tipo di file non c'è una decodifica."))
    p = Path(percorso)
    voci = []
    if t == "lnk":
        sez = analizza_lnk(p.read_bytes())
    elif t == "jump_auto":
        sez, voci = analizza_jump_auto(p)
    elif t == "jump_custom":
        sez, voci = analizza_jump_custom(p.read_bytes())
    elif t == "prefetch":
        sez = analizza_prefetch(p)
    else:
        sez = analizza_cestino(p.read_bytes())
    return {"tipo": t, "titolo": nome_tipo(t), "sezioni": sez, "voci": voci}


def _testo_sezioni(sezioni, rientro=""):
    out = []
    for s in sezioni:
        out.append(f"{rientro}[{s['titolo']}]")
        if s.get("colonne"):
            larg = [max(len(str(r[i])) for r in [s["colonne"]] + s["righe"]) for i in range(len(s["colonne"]))]
            for r in [s["colonne"]] + s["righe"]:
                out.append(rientro + "  ".join(str(c).ljust(larg[i]) for i, c in enumerate(r)).rstrip())
            if s.get("nota"):
                out.append(rientro + s["nota"])
        else:
            larg = min(max((len(k) for k, _ in s["righe"]), default=0) + 1, 48)
            for k, v in s["righe"]:
                out.append(f"{rientro}{(k + ':').ljust(larg + 1)} {v}")
        out.append("")
    return out


def come_testo(ris, intestazione):
    """Il risultato di `analizza` come testo. `intestazione`: righe (chiave, valore) sul file (nome, percorso, impronta)."""
    out = [f"RepertIA — {ris['titolo']}", ""]
    out += _testo_sezioni([{"titolo": tr("File analizzato"), "righe": [[k, str(v)] for k, v in intestazione if v not in (None, "")]}])
    out += _testo_sezioni(ris["sezioni"])
    for v in ris.get("voci") or []:
        out += ["=" * 78, v["titolo"], "=" * 78, ""]
        out += _testo_sezioni(v["sezioni"], "  ")
    out.append(tr("Le date dell'artefatto sono in UTC, come sono scritte nel file."))
    return "\r\n".join(out) + "\r\n"
