#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - MFT: chi usa un cluster (verifica dei file cancellati).

(3.0.4) Codice spostato da forense_estesa.py senza modifiche, per avere file più corti. Si carica tramite
forense_estesa, che ne riesporta i nomi: gli altri moduli continuano a usare «fe.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fe.<nome>»).
"""
import re
import sqlite3
import struct
import subprocess
from collections import Counter
from pathlib import Path
from forense_lingua import tr
import forense_agent as fa

import forense_estesa as fe
from forense_estesa import (
    Ctx, DOC_FAM, GENERIC_EXT, IMAGE_EXT, IMAGE_FAM, ImageFile, KNOWN_EXT, MEDIA_FAM, OOXML, Region, SUSPECT_EXT,
    add_anomaly, detect_sig, entropy, fs_rows, now, part_bounds)

# ------------------------------------------------------------------ MFT: chi usa un cluster (verifica dei cancellati)

def ntfs_runlist(rec, pos, end):
    """Decodifica una runlist NTFS: [(lcn o None se sparsa, lunghezza in cluster)]."""
    out, lcn = [], 0
    while pos < end:
        h = rec[pos]
        if h == 0:
            break
        nl, no = h & 0x0F, h >> 4
        if not nl or pos + 1 + nl + no > end:
            break
        length = int.from_bytes(rec[pos + 1:pos + 1 + nl], "little")
        if no:
            lcn += int.from_bytes(rec[pos + 1 + nl:pos + 1 + nl + no], "little", signed=True)
            out.append((lcn, length))
        else:
            out.append((None, length))
        pos += 1 + nl + no
    return out


def mft_fixup(rec, sector=512):
    """Record MFT con l'array di aggiornamento applicato; None se non è un record valido («FILE»)."""
    if rec[:4] != b"FILE":
        return None
    uo, uc = struct.unpack_from("<HH", rec, 4)
    if uc < 2 or uo + 2 * uc > len(rec):
        return None
    b = bytearray(rec)
    usn = b[uo:uo + 2]
    for i in range(1, uc):
        p = i * sector - 2
        if p + 2 > len(b) or b[p:p + 2] != usn:
            return None                 # settore scritto a metà: record non affidabile
        b[p:p + 2] = b[uo + 2 * i:uo + 2 * i + 2]
    return b


def mft_record_info(b):
    """(in_uso, record base o 0, sequenza, nome, [(lcn, lunghezza)] di tutti gli attributi non residenti)."""
    seq, = struct.unpack_from("<H", b, 0x10)
    first, flags = struct.unpack_from("<HH", b, 0x14)
    base = struct.unpack_from("<Q", b, 0x20)[0] & 0xFFFFFFFFFFFF
    pos, runs, name, name_ns = first, [], "", 9
    while pos + 16 <= len(b):
        typ, alen = struct.unpack_from("<II", b, pos)
        if typ == 0xFFFFFFFF or alen < 16 or pos + alen > len(b):
            break
        if b[pos + 8]:                                          # non residente
            ro = struct.unpack_from("<H", b, pos + 0x20)[0]
            runs.extend(r for r in ntfs_runlist(b, pos + ro, pos + alen) if r[0] is not None)
        elif typ == 0x30:                                       # $FILE_NAME residente
            vo = struct.unpack_from("<H", b, pos + 0x14)[0]
            v = pos + vo
            if v + 0x42 <= pos + alen:
                nl, ns = b[v + 0x40], b[v + 0x41]
                if not name or (name_ns == 2 and ns != 2):          # preferisce il nome lungo al nome DOS 8.3
                    name = bytes(b[v + 0x42:v + 0x42 + 2 * nl]).decode("utf-16-le", "replace")
                    name_ns = ns
        pos += alen
    return bool(flags & 1), base, seq, name, runs


def mft_cluster_owners(read, mft_size, rec_size, targets, progress=None, step=4 << 20):
    """Una passata sulla MFT: per ogni cluster di `targets` l'elenco dei record (anche liberi, cioè di file cancellati)
    che lo hanno nelle proprie runlist. `read(offset, n)` legge il file $MFT. Restituisce
    {cluster: [(record, in_uso, base, sequenza, nome)]}."""
    import bisect
    tg = sorted(set(targets))
    out = {}
    if not tg or rec_size <= 0:
        return out
    step -= step % rec_size
    off = 0
    while off < mft_size:
        buf = read(off, min(step, mft_size - off))
        if not buf:
            break
        for k in range(0, len(buf) - rec_size + 1, rec_size):
            raw = buf[k:k + rec_size]
            if raw[:4] != b"FILE":
                continue
            b = mft_fixup(raw)
            if b is None:
                continue
            try:
                in_use, base, seq, name, runs = mft_record_info(b)
            except (struct.error, IndexError):
                continue
            hit = None
            for lcn, n in runs:
                i = bisect.bisect_left(tg, lcn)
                while i < len(tg) and tg[i] < lcn + n:
                    hit = hit or []
                    hit.append(tg[i])
                    i += 1
            if hit:
                num = (off + k) // rec_size
                for c in hit:
                    out.setdefault(c, []).append((num, in_use, base, seq, name))
        off += len(buf)
        if progress:
            progress(off, mft_size)
    return out


def pe_raw_end(head):
    """Dove finisce un eseguibile PE secondo le sue intestazioni: (fine dell'ultima sezione, fine della firma
    Authenticode o 0), oppure None. Un PE vero è lungo esattamente così (salvo pochi byte di allineamento o dati
    aggiunti in coda, come negli installatori)."""
    try:
        lfa = struct.unpack_from("<I", head, 0x3C)[0]
        if head[lfa:lfa + 4] != b"PE\x00\x00":
            return None
        nsec, = struct.unpack_from("<H", head, lfa + 6)
        opt, = struct.unpack_from("<H", head, lfa + 20)
        st = lfa + 24 + opt
        if not 0 < nsec <= 96 or st + 40 * nsec > len(head):
            return None
        end = 0
        for i in range(nsec):
            rsz, rptr = struct.unpack_from("<II", head, st + 40 * i + 16)
            if rsz and rptr:
                end = max(end, rptr + rsz)
        magic, = struct.unpack_from("<H", head, lfa + 24)
        dd = lfa + 24 + (96 if magic == 0x10B else 112)
        cert = 0
        if opt >= (dd - lfa - 24) + 5 * 8:
            co, cs = struct.unpack_from("<II", head, dd + 4 * 8)        # directory 4: certificati (offset nel file)
            cert = co + cs if co and cs else 0
        return (end, cert) if end else None
    except struct.error:
        return None


def content_fits(fam, size, head, read_at):
    """Il formato riconosciuto all'inizio di un file è coerente con la sua dimensione e con la sua fine?
    Serve per i file CANCELLATI: se i primi cluster sono stati riusati, l'inizio è di un altro file e la fine (o le
    lunghezze scritte nelle intestazioni) non tornano. `read_at(offset, n)` legge il file. Restituisce
    True (coerente), False (non coerente: il contenuto non è di questo file) o None (formato senza controllo)."""
    if not size:
        return None

    def tail(n):
        try:
            return read_at(max(0, size - n), min(n, size)) or b""
        except Exception:
            return b""

    try:
        if fam == "exe":
            pe = pe_raw_end(head)
            if pe is None:
                return None
            end = max(pe)
            return end <= size <= end + 4096          # dati aggiunti oltre 4 KB (installatori): non dimostrabile
        if fam == "jpg":                              # il JPEG finisce con FF D9 (poi al più zeri o il blocco Samsung «SEFT»)
            t = tail(65536)
            return t.rstrip(b"\0").endswith(b"\xff\xd9") or (b"SEFT" in t[-64:] and b"\xff\xd9" in t)
        if fam == "png":
            return b"IEND\xaeB`\x82" in tail(4096)
        if fam == "gif":
            return tail(4096).rstrip(b"\0").endswith(b"\x3b")
        if fam == "pdf":
            return b"%%EOF" in tail(65536)
        if fam == "zip":
            return b"PK\x05\x06" in tail(65536 + 22)
        if fam in ("wav", "avi", "webp") and head[:4] == b"RIFF":
            n = struct.unpack_from("<I", head, 4)[0] + 8
            return n <= size + 1 and n >= size - 65536
        if fam == "reg" and head[:4] == b"regf" and len(head) >= 0x2C:
            end = 4096 + struct.unpack_from("<I", head, 0x28)[0]
            return end <= size <= end + (1 << 20)
        if fam == "7z" and head[:6] == b"7z\xbc\xaf\x27\x1c" and len(head) >= 32:
            off, ln = struct.unpack_from("<QQ", head, 12)
            return 32 + off + ln <= size
        if fam in ("mp4", "mov", "m4a", "3gp", "heic") and head[4:8] == b"ftyp":
            # scatole di primo livello: devono susseguirsi fino alla fine del file
            pos, k = 0, 0
            while pos < size and k < 64:
                h = head[pos:pos + 16] if pos + 16 <= len(head) else read_at(pos, 16)
                if len(h) < 8:
                    return False
                n = struct.unpack_from(">I", h, 0)[0]
                if n == 1:
                    if len(h) < 16:
                        return False
                    n = struct.unpack_from(">Q", h, 8)[0]
                elif n == 0:                                     # ultima scatola: fino alla fine del file
                    return True
                if n < 8 or not re.fullmatch(rb"[\x20-\x7e]{4}", h[4:8]):
                    return False
                pos += n
                k += 1
            return pos == size if k < 64 else None
    except (struct.error, OSError):
        return None
    return None


# moduli di programmi che usano un'estensione propria ma sono eseguibili PE (risorse di Office .odf, plug-in di Adobe
# .mpp/.api, filtri di Photoshop .8b?, dizionari .lex…): un PE con queste estensioni è normale, non un eseguibile mascherato
VENDOR_PE_EXT = {"odf", "mpp", "api", "lex", "ppi", "flt", "aex", "8bf", "8bi", "8be", "8bx", "8ba", "8by", "8bc", "8li",
                 "8bs", "aip", "apl", "dlu", "bpi", "plugin", "xpt", "x3d", "spi", "vst", "vst3", "ax", "ime", "nls", "tsp"}
# estensioni «da utente» (foto, video, audio, documenti): un eseguibile qui dentro è sempre da segnalare
USER_EXT = (set().union(*(fe.FAMILY_EXT[f] for f in MEDIA_FAM | {"pdf", "rtf"} if f in fe.FAMILY_EXT)) | OOXML |
            {"doc", "xls", "ppt", "txt", "csv", "jpg", "jpeg", "png", "gif", "bmp", "pdf", "mp3", "mp4", "mov", "avi",
             "mkv", "wav", "zip", "rar", "7z", "html", "htm", "eml", "msg", "odt", "ods", "odp", "rtf"}) - VENDOR_PE_EXT
# cartelle di programmi e del sistema (anche dentro Windows.old e le copie nel Cestino): qui un modulo PE con
# un'estensione insolita fa parte di un programma installato
SOFTWARE_PATH = re.compile(r"(?i)(?:^|/)(?:program files(?: \(x86\))?|programdata/(?:microsoft|package cache)|"
                           r"windows/(?:installer|system32|syswow64|winsxs|servicing|softwaredistribution|"
                           r"serviceprofiles/[^/]+/appdata/local/microsoft/windows/deliveryoptimization|microsoft\.net|"
                           r"assembly|immersivecontrolpanel|systemapps)|windowsapps|appdata/local/(?:microsoft|packages)|"
                           r"appdata/roaming/microsoft|root/office\d+|common files|microsoft office)/")
# icone degli installatori: Windows Installer conserva le icone dei programmi come file .exe/.dll rinominati .ico
INSTALLER_ICON = re.compile(r"(?i)(?:^|/)windows/installer/\{[0-9a-f-]{36}\}/[^/]+\.ico$")
# log delle transazioni del registro: iniziano con «regf» come l'alveare
REG_LOG_EXT = {"log", "log1", "log2", "sav", "tm", "blf"}
VIDEO_FAM = {"mov", "mp4", "m4a", "3gp", "mkv", "avi", "ogg"}


class HeadReader:
    """Primi byte (e ultimi, se serve) dei file: pytsk3 se disponibile, altrimenti icat."""
    def __init__(self, case):
        self.case = case
        self.fs = {}
        self.ok = False
        try:
            import pytsk3
            self.pytsk3 = pytsk3
            self.ok = True
        except ImportError:
            self.pytsk3 = None
        self.img = None

    def _img(self):
        """Immagine aperta con pytsk3 (E01 tramite pyewf), per leggere byte grezzi o aprire una partizione."""
        if self.img is None:
            pt = self.pytsk3
            if fa.is_e01(self.case.image):
                import pyewf
                h = pyewf.handle()
                h.open(pyewf.glob(self.case.image))

                class EwfImg(pt.Img_Info):
                    def __init__(s, hh):
                        s._h = hh
                        super().__init__(url="", type=pt.TSK_IMG_TYPE_EXTERNAL)

                    def read(s, off, size):
                        s._h.seek(off)
                        return s._h.read(size)

                    def get_size(s):
                        return s._h.get_media_size()
                self.img = EwfImg(h)
            else:
                self.img = pt.Img_Info(self.case.image)
        return self.img

    def _fs(self, part):
        if part not in self.fs:
            try:
                self.fs[part] = self.pytsk3.FS_Info(self._img(), offset=part * 512)
            except Exception:
                self.fs[part] = None
        return self.fs[part]

    @staticmethod
    def _ntfs_names(f, pt):
        """Nomi ($FILE_NAME) memorizzati nel record MFT, in minuscolo; None se non è un record NTFS."""
        names = None
        try:
            for a in f:
                if int(a.info.type) != int(pt.TSK_FS_ATTR_TYPE_NTFS_FNAME):
                    continue
                names = names or set()
                d = f.read_random(0, a.info.size, a.info.type, a.info.id)
                if len(d) >= 66:
                    names.add(d[66:66 + d[64] * 2].decode("utf-16-le", "replace").lower())
        except Exception:
            return names
        return names

    def _first_block(self, f, pt):
        """Primo blocco (in unità del file system) con dati veri del file; None se i dati sono residenti."""
        try:
            for a in f:
                if int(a.info.type) not in (int(pt.TSK_FS_ATTR_TYPE_NTFS_DATA), int(pt.TSK_FS_ATTR_TYPE_DEFAULT)):
                    continue
                if not int(a.info.flags) & int(pt.TSK_FS_ATTR_NONRES):
                    continue
                for r in a:
                    if int(r.flags) & (int(pt.TSK_FS_ATTR_RUN_FLAG_SPARSE) | int(pt.TSK_FS_ATTR_RUN_FLAG_FILLER)):
                        continue
                    return int(r.addr)
        except Exception:
            pass
        return None

    def _block_allocated(self, part, block):
        """True se il blocco è oggi assegnato a un file, False se libero, None se non lo si capisce."""
        try:
            r = subprocess.run(["blkstat", "-o", str(part), str(self.case.image), str(block)],
                               capture_output=True, timeout=120, stdin=subprocess.DEVNULL,
                               env=fa.tsk_env(self.case, ["blkstat"]))
        except (OSError, subprocess.TimeoutExpired):
            return None
        m = re.search(r"(?m)^(Not )?Allocated\b", r.stdout.decode("utf-8", "replace"))
        return None if not m else not m.group(1)

    def verify_deleted(self, part, inode, name):
        """Una voce CANCELLATA dell'elenco ha ancora il contenuto del proprio file?
        Il nome resta nella cartella anche dopo che il record (inode, MFT) è stato dato a un altro file e i suoi
        cluster a file nuovi: leggere «per inode» darebbe allora il contenuto di un altro file (un .png che
        «contiene» un eseguibile). Risposte:
          ok               record libero (o con lo stesso nome) e primo blocco non riutilizzato
          riassegnato      il record oggi appartiene a un altro file (nome diverso)
          sovrascritto     il primo blocco dei dati oggi è assegnato a un altro file
          non_verificabile mancano gli strumenti per controllare (il risultato va preso con cautela)"""
        if fa.ap.is_apfs_part(part) or not self.ok:
            return "non_verificabile"
        fs = self._fs(part)
        if fs is None:
            return "non_verificabile"
        pt = self.pytsk3
        try:
            f = fs.open_meta(inode=int(str(inode).split("-")[0]))
            meta = f.info.meta
        except Exception:
            return "non_verificabile"
        if meta is None:
            return "non_verificabile"
        alloc = bool(int(meta.flags) & int(pt.TSK_FS_META_FLAG_ALLOC))
        names = self._ntfs_names(f, pt)
        if names:
            if Path(name).name.lower() not in names:
                return "riassegnato"
        elif alloc:
            return "riassegnato"
        if self.is_ntfs(part):
            return "ok"                 # NTFS: i cluster si controllano tutti insieme con una passata sulla MFT (mft_owners)
        blk = self._first_block(f, pt)
        if blk is not None and self._block_allocated(part, blk):
            return "sovrascritto"
        return "ok"

    def is_ntfs(self, part):
        if fa.ap.is_apfs_part(part) or not self.ok:
            return False
        fs = self._fs(part)
        try:
            return fs is not None and bool(int(fs.info.ftype) & int(getattr(self.pytsk3, "TSK_FS_TYPE_NTFS_DETECT", 1)))
        except Exception:
            return False

    def first_cluster(self, part, inode):
        """Primo cluster dei dati del file (None se residenti o non leggibili)."""
        fs = self._fs(part) if self.ok and not fa.ap.is_apfs_part(part) else None
        if fs is None:
            return None
        try:
            return self._first_block(fs.open_meta(inode=int(str(inode).split("-")[0])), self.pytsk3)
        except Exception:
            return None

    def reader(self, part, inode):
        """read(offset, n) sul contenuto del file, anche cancellato (segue le runlist del record); None se non si può."""
        fs = self._fs(part) if self.ok and not fa.ap.is_apfs_part(part) else None
        if fs is None:
            return None
        try:
            f = fs.open_meta(inode=int(str(inode).split("-")[0]))
        except Exception:
            return None

        def rd(off, n):
            try:
                return f.read_random(off, n)
            except Exception:
                return b""
        return rd

    def mft_owners(self, part, clusters, progress=None):
        """Una passata sulla $MFT del volume NTFS: {cluster: [(record, in_uso, base, sequenza, nome)]} per i cluster
        chiesti, compresi i record LIBERI (file cancellati). None se la MFT non si legge."""
        fs = self._fs(part) if self.is_ntfs(part) else None
        if fs is None:
            return None
        try:
            boot = fs.open_meta(inode=7).read_random(0, 512)          # $Boot
            bps, spc = struct.unpack_from("<HB", boot, 11)
            cpr = struct.unpack_from("<b", boot, 0x40)[0]
            rs = 1 << -cpr if cpr < 0 else cpr * bps * spc
            mft = fs.open_meta(inode=0)
            size = int(mft.info.meta.size)
            if not 256 <= rs <= 65536 or not size:
                return None
            return mft_cluster_owners(lambda o, n: mft.read_random(o, n), size, rs, clusters, progress)
        except Exception:
            return None

    def read(self, part, inode, n=4096, tail=0):
        """(dimensione, inizio, fine) del file; dimensione None se sconosciuta."""
        if fa.ap.is_apfs_part(part):
            try:
                return fa.ap.head_tail(self.case, part, inode, n, tail)
            except Exception:
                return None, b"", b""
        if fa.is_mobile(self.case):          # estrazione di un telefono (2.20)
            import forense_mobile as fm
            try:
                return fm.head_tail(self.case, part, inode, n, tail)
            except Exception:
                return None, b"", b""
        if self.ok:
            fs = self._fs(part)
            if fs is not None:
                try:
                    num = int(str(inode).split("-")[0])
                    f = fs.open_meta(inode=num)
                    size = f.info.meta.size if f.info.meta else 0
                    head = f.read_random(0, min(n, size)) if size else b""
                    end = f.read_random(max(0, size - tail), min(tail, size)) if tail and size else b""
                    return size, head, end
                except Exception:
                    pass
        cmd = ["icat", "-o", str(part), self.case.image, str(inode)]
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 stdin=subprocess.DEVNULL)
            head = p.stdout.read(n)
            p.kill()
            p.wait()
        except OSError:
            return None, b"", b""
        return None, head, b""


def check_volumes(case, con):
    """Volumi cifrati: BitLocker (anche To Go), LUKS, FileVault/CoreStorage, APFS cifrato,
    possibili volumi VeraCrypt/TrueCrypt (partizione non leggibile ad alta entropia)."""
    out = []
    try:
        img = ImageFile(case.image)
    except OSError:
        print(tr("Copia forense non raggiungibile: controllo dei volumi saltato."), flush=True)
        return out
    parts = case.meta.get("partitions") or [{"offset": 0, "length_sectors": None, "readable": False}]
    for p in parts:
        if p.get("apfs"):       # volume APFS: cifrato e senza chiave -> si può sbloccare dal caso
            if p["apfs"].get("encrypted") and fa.ap.is_locked(case, p["offset"]):
                v = {"offset": p["offset"], "tipo": tr("APFS cifrato (FileVault)"), "decifrabile": True, "apfs": True,
                     "byte": (p.get("length_sectors") or 0) * 512, "desc": p.get("desc", ""),
                     "nome": p["apfs"].get("name")}
                out.append(v)
                add_anomaly(con, "volume", "volume", p["offset"], None,
                            tr("volume APFS «{v1}» (offset {offset})").format(v1=p['apfs'].get('name'), offset=p['offset']),
                            tr("volume APFS cifrato (FileVault): si sblocca con la password o la chiave di ripristino"),
                            real=tr("APFS cifrato"), size=v["byte"], sev=3)
                print(tr("Anomalie: volume APFS cifrato «{v1}»").format(v1=p['apfs'].get('name')), flush=True)
            continue
        start, length = part_bounds(case, p, img)
        if length <= 0:
            continue
        head = img.pread(start, 65536)
        kind = None
        region = Region(img, start, length)
        try:
            import pybde
            if pybde.check_volume_signature_file_object(region):
                kind = "BitLocker"
        except Exception:
            if head[3:11] == b"-FVE-FS-":
                kind = "BitLocker"
        if not kind and head[:6] == b"LUKS\xba\xbe":
            kind = "LUKS" if head[6:8] == b"\x00\x01" else "LUKS2"
        if not kind:
            try:
                import pyfvde
                region.seek(0)
                if pyfvde.check_volume_signature_file_object(region):
                    kind = "FileVault (CoreStorage)"
            except Exception:
                pass
        if not kind and p.get("apfs"):
            enc = [v for v in p["apfs"].get("volumes", []) if v.get("encrypted")]
            if enc:
                kind = tr("APFS cifrato (FileVault)")
        if not kind and not p.get("readable") and len(head) >= 65536 and entropy(head[512:]) > 7.95:
            kind = tr("possibile VeraCrypt/TrueCrypt")
        if kind:
            dec_ok = kind in ("BitLocker", "LUKS")      # LUKS2 non è supportato da libluksde
            v = {"offset": p["offset"], "tipo": kind, "byte": length, "desc": p.get("desc", ""),
                 "decifrabile": dec_ok}
            out.append(v)
            add_anomaly(con, "volume", "volume", p["offset"], None,
                        tr("partizione all'offset {offset} ({v1})").format(offset=p['offset'], v1=p.get('desc') or '').strip(),
                        f"volume {kind}" + (tr(": si può decifrare con la chiave di ripristino o la password")
                                            if dec_ok else ""), real=kind, size=length, sev=3)
            print(tr("Anomalie: volume cifrato {kind} all'offset {offset}").format(kind=kind, offset=p['offset']), flush=True)
    img.close()
    return out


def quick_encrypted(case):
    """Controllo rapido (solo le firme) dei volumi cifrati NON APFS, fatto già alla preparazione del caso:
    un BitLocker To Go, per esempio, viene letto da Sleuth Kit come un FAT senza contenuto utile e senza
    questo controllo l'operatore non se ne accorgerebbe."""
    out = []
    img = ImageFile(case.image)
    try:
        for p in case.meta.get("partitions") or [{"offset": 0, "length_sectors": None}]:
            if p.get("apfs"):
                continue
            start, length = part_bounds(case, p, img)
            if length <= 0:
                continue
            head = img.pread(start, 65536)
            region = Region(img, start, length)
            kind = None
            try:
                import pybde
                if pybde.check_volume_signature_file_object(region):
                    kind = "BitLocker"
            except Exception:
                if head[3:11] == b"-FVE-FS-":
                    kind = "BitLocker"
            if not kind and head[:6] == b"LUKS\xba\xbe":
                kind = "LUKS" if head[6:8] == b"\x00\x01" else "LUKS2"
            if not kind:
                try:
                    import pyfvde
                    region.seek(0)
                    if pyfvde.check_volume_signature_file_object(region):
                        kind = "FileVault (CoreStorage)"
                except Exception:
                    pass
            if kind:
                out.append({"offset": p["offset"], "tipo": kind, "byte": length, "desc": p.get("desc", ""),
                            "decifrabile": kind in ("BitLocker", "LUKS")})
    finally:
        img.close()
    return out


def run_anomalie(case, con):
    ctx = Ctx(case, con, "Anomalie")
    con.execute("DELETE FROM anomalies WHERE kind IN ('volume','estensione','contenitore') OR "
                "(kind='cifrato' AND detail NOT LIKE 'archivio%')")
    con.commit()
    vols = check_volumes(case, con)
    case.meta["volumi_cifrati"] = vols
    hr = HeadReader(case)
    sizes = {}
    nav = case.root / "navigazione.sqlite"
    if nav.exists():
        try:
            nc = sqlite3.connect(f"file:{nav.as_posix()}?mode=ro", uri=True)
            for part, inode, size in nc.execute("SELECT part, inode, size FROM nav WHERE isdir=0"):
                sizes[(part, str(inode))] = size
            nc.close()
        except sqlite3.Error:
            pass
    # prima i file con nome attuale, poi i cancellati: se un inode è già stato guardato come file «vero», la voce
    # cancellata con lo stesso inode è un nome vecchio (record riassegnato) e si salta
    rows = sorted(fs_rows(con, "1=1"), key=lambda r: r[2] or 0)
    if not hr.ok:
        print(tr("pytsk3 non disponibile: leggo l'inizio dei file con icat (più lento); "
              "per i file cancellati il contenuto non è verificabile."), flush=True)
    print(tr("Anomalie: controllo il contenuto di {v1} file...").format(v1=len(rows)), flush=True)
    seen = set()
    c = Counter()
    pending = []                # cancellati NTFS da confermare con la passata sulla MFT

    def flag(kind, part, inode, path, detail, ext, label, size, deleted, sev, fam=None, head=b""):
        """Registra l'anomalia. Per un file CANCELLATO prima verifica che il contenuto letto sia ancora il suo:
        record non riassegnato, contenuto coerente con dimensione e fine del file (content_fits) e, su NTFS, primo
        cluster non usato da nessun altro record della MFT, nemmeno di un altro file cancellato (mft_owners)."""
        if deleted:
            v = hr.verify_deleted(part, inode, Path(path).name)
            if v in ("riassegnato", "sovrascritto"):
                c["ignorati_" + v] += 1
                return False
            if v == "ok" and fam:
                rd = hr.reader(part, inode)
                fit = content_fits(fam, size, head, rd) if rd else None
                if fit is False:
                    c["ignorati_incoerente"] += 1
                    return False
                if hr.is_ntfs(part):
                    blk = hr.first_cluster(part, inode)
                    if blk is not None:
                        pending.append((blk, int(str(inode).split("-")[0]),
                                        (kind, "fs", part, inode, path, detail + tr(" · file cancellato"), ext, label, size,
                                         deleted, sev)))
                        return True
            if v == "ok":
                detail += tr(" · file cancellato")
            else:
                detail += tr(" · file cancellato: contenuto non verificabile")
                sev = min(sev, 1)
        add_anomaly(con, kind, "fs", part, inode, path, detail, ext, label, size, deleted, sev)
        c[kind] += 1
        return True

    for k, (part, inode, deleted, path) in enumerate(rows, 1):
        name = Path(path).name
        if ":" in name or (part, inode) in seen:
            continue
        seen.add((part, inode))
        ext = Path(name).suffix.lower().lstrip(".")
        want_tail = ext == "pdf" and hr.ok
        size, head, tail = hr.read(part, inode, 65536 if ext in SUSPECT_EXT or ext not in KNOWN_EXT else 4096,
                                   tail=65536 if want_tail else 0)
        if size is None:
            size = sizes.get((part, str(inode)))
        if not head:
            continue
        fam, label = detect_sig(head)
        if fam:
            fam_ok = ext in fe.FAMILY_EXT.get(fam, set())
            if fam == "ole" and ext in OOXML:
                flag("cifrato", part, inode, path, tr("documento Office protetto da "
                     "password (contenitore cifrato al posto del formato .%s)") % ext,
                     ext, label, size, deleted, 2, fam, head)
            elif fam == "zip" and len(head) > 8 and head[6] & 1 and ext not in OOXML and not con.execute(
                    "SELECT 1 FROM anomalies WHERE kind='cifrato' AND source='fs' AND part=? AND inode=?",
                    (part, str(inode))).fetchone():
                flag("cifrato", part, inode, path, tr("archivio ZIP protetto da password"),
                     ext, label, size, deleted, 2, fam, head)
            elif fam == "pdf" and (b"/Encrypt" in head or b"/Encrypt" in tail):
                flag("cifrato", part, inode, path, tr("PDF protetto da password o con "
                     "restrizioni"), ext, label, size, deleted, 1, fam, head)
            elif fam in ("dmgenc", "luks"):
                flag("cifrato", part, inode, path, label, ext, label, size, deleted, 3, fam, head)
            if not fam_ok and ext in KNOWN_EXT and not (fam == "ole" and ext in OOXML):
                exe_like = fam in ("exe", "elf", "macho")
                user_ext = ext in USER_EXT
                soft = bool(SOFTWARE_PATH.search(path))
                if ext in GENERIC_EXT and not exe_like:
                    continue        # estensione generica (dat, bin, db, tmp…): il contenuto può essere qualunque cosa
                if fam == "exe" and (ext in VENDOR_PE_EXT or INSTALLER_ICON.search(path)):
                    c["normali_moduli"] += 1        # modulo di un programma (Office .odf, Adobe .mpp, icone degli installatori)
                    continue
                if exe_like and soft and not user_ext:
                    c["normali_moduli"] += 1        # modulo PE nelle cartelle dei programmi o di Windows
                    continue
                if fam == "reg" and ext in REG_LOG_EXT:
                    c["normali_registro"] += 1      # log delle transazioni del registro (BCD.LOG, ….LOG1)
                    continue
                sev = (2 if ext in GENERIC_EXT else 3) if exe_like else \
                    2 if (fam in MEDIA_FAM | DOC_FAM | {"rar", "7z", "gz", "pst", "sqlite"}) else 1
                note = ""
                ext_fam = next((f for f, es in fe.FAMILY_EXT.items() if ext in es), None)
                if fam == "zip" and ext in fe.FAMILY_EXT["ole"] or fam == "ole" and ext in fe.FAMILY_EXT["zip"]:
                    sev = 1
                elif fam in IMAGE_FAM and ext in IMAGE_EXT:
                    sev, note = 1, tr(" (formato immagine diverso da quello indicato)")
                elif fam in MEDIA_FAM and ext_fam in MEDIA_FAM:
                    sev, note = 1, tr(" (foto/video/audio con l'estensione di un altro formato multimediale)")
                elif exe_like and ext in GENERIC_EXT:
                    sev, note = (1 if soft else 2), tr(" (eseguibile in un file con estensione generica)")
                elif exe_like:
                    note = tr(" (eseguibile mascherato)")
                elif ext_fam == "exe" and fam in MEDIA_FAM:
                    note = tr(" (foto/video/audio con l'estensione di un programma: possibile occultamento)")
                elif ext_fam == "exe":
                    sev, note = 1, tr(" (non è un eseguibile)")
                flag("estensione", part, inode, path, tr("estensione .{ext} ma il contenuto è {label}{note}").format(ext=ext, label=label, note=note),
                     ext, label, size, deleted, sev, fam, head)
        elif ext in SUSPECT_EXT and size and size >= (1 << 20) and size % 512 == 0 and \
                len(head) >= 65536 and entropy(head) > 7.995:
            flag("contenitore", part, inode, path,
                 tr("{v1} MB di dati casuali senza formato riconoscibile: possibile contenitore cifrato "
                    "(VeraCrypt/TrueCrypt)").format(v1=size >> 20), ext, tr("dati ad alta entropia"),
                 size, deleted, 2)
        fa.avanz(fatti=k, totale=len(rows))
        if k % 2000 == 0:
            con.commit()
            ctx.say(tr("{k} di {v1} file · {estensione} estensioni false, {cifrato} protetti, {contenitore} "
                       "possibili contenitori").format(k=k, v1=len(rows), estensione=c['estensione'], cifrato=c['cifrato'], contenitore=c['contenitore']))
    # cancellati su NTFS: il primo cluster non deve comparire nelle runlist di nessun altro record della MFT
    # (nemmeno libero: un file creato e poi cancellato a sua volta dopo il nostro lascia lì i propri dati)
    by_part = {}
    for blk, rec, args in pending:
        by_part.setdefault(args[2], []).append((blk, rec, args))
    for part, items in by_part.items():
        print(tr("Anomalie: controllo nella MFT (offset {part}) i cluster di {v1} file cancellati...").format(part=part, v1=len(items)), flush=True)
        owners = hr.mft_owners(part, [x[0] for x in items],
                               progress=lambda done, tot: ctx.say(tr("MFT {v1}%").format(v1=done * 100 // max(tot, 1))))
        for blk, rec, args in items:
            if owners is None:                  # MFT non leggibile: si ripiega sullo stato del cluster nel volume
                if hr._block_allocated(part, blk):
                    c["ignorati_sovrascritto"] += 1
                    continue
            elif any(o[0] != rec and o[2] != rec for o in owners.get(blk, [])):
                c["ignorati_riusato"] += 1
                continue
            add_anomaly(con, *args)
            c[args[0]] += 1
    con.commit()
    ctx.close()
    ign = sum(c[k] for k in ("ignorati_riassegnato", "ignorati_sovrascritto", "ignorati_riusato", "ignorati_incoerente"))
    res = {"file": len(seen), "estensione": c["estensione"], "cifrato": c["cifrato"],
           "contenitore": c["contenitore"], "volumi": len(vols), "ts": now(),
           "cancellati_ignorati": ign, "ignorati_riassegnato": c["ignorati_riassegnato"],
           "ignorati_sovrascritto": c["ignorati_sovrascritto"], "ignorati_riusato": c["ignorati_riusato"],
           "ignorati_incoerente": c["ignorati_incoerente"], "normali_moduli": c["normali_moduli"],
           "normali_registro": c["normali_registro"]}
    print(tr("Anomalie: {estensione} estensioni false, {cifrato} file protetti, {contenitore} possibili "
             "contenitori cifrati, {v1} volumi cifrati").format(estensione=c['estensione'], cifrato=c['cifrato'], contenitore=c['contenitore'], v1=len(vols)), flush=True)
    if ign:
        print(tr("Anomalie: {ign} voci di file cancellati non considerate perché il contenuto letto non è "
                 "più quello del file ({ignorati_riassegnato} con record riassegnato a un altro file, "
                 "{ignorati_sovrascritto} con dati riscritti da file presenti, {ignorati_riusato} con dati "
                 "riusati da un altro file cancellato, {ignorati_incoerente} con contenuto non coerente con "
                 "la dimensione o la fine del file).").format(ign=ign, ignorati_riassegnato=c['ignorati_riassegnato'], ignorati_sovrascritto=c['ignorati_sovrascritto'], ignorati_riusato=c['ignorati_riusato'], ignorati_incoerente=c['ignorati_incoerente']), flush=True)
    if c["normali_moduli"] or c["normali_registro"]:
        print(tr("Anomalie: non segnalati {normali_moduli} moduli di programmi con estensione propria (es. "
                 ".odf di Office, .mpp di Adobe, icone degli installatori) e {normali_registro} log del "
                 "registro.").format(normali_moduli=c['normali_moduli'], normali_registro=c['normali_registro']), flush=True)
    return res
