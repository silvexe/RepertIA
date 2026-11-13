#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - exFAT: catena dei cluster dei file cancellati e mappa dei cluster allocati.

(3.0.4) Codice spostato da forense_agent.py senza modifiche, per avere file più corti. Si carica tramite
forense_agent, che ne riesporta i nomi: gli altri moduli continuano a usare «fa.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fa.<nome>»).
"""
import struct

import forense_agent as fa

class CatenaExfat:
    """(3.0.2) exFAT, file cancellati frammentati. Alla cancellazione exFAT libera i cluster solo nella bitmap e lascia
    la catena nella FAT; Sleuth Kit invece legge ogni cancellato come contiguo dal primo cluster, e un file frammentato
    torna con i dati di altri file (provato con le immagini NIST CFTT DFR-05 e DFR-12). Qui si rilegge la voce di
    cartella dell'inode e si segue la catena nella FAT, ma solo se è certo che sia ancora quella del file: voce di un
    file (non cartella; cancellata, o attiva dentro una cartella cancellata) senza il flag NoFatChain, catena lunga esattamente quanto la dimensione e chiusa da fine
    catena, cluster tutti validi, distinti e liberi nella bitmap, e non contigui (altrimenti icat legge già giusto). In
    ogni altro caso resta la lettura di Sleuth Kit. Ogni ricostruzione si annota nel registro del caso (exfat_catena)."""
    PAG = 1 << 16

    def __init__(self, case, offset):
        import forense_estesa as fe
        self.ok, self.pag = False, {}
        self.img = fe.HeadReader(case)._img()
        self.base = offset * 512
        bs = self.img.read(self.base, 512)
        if bs[3:11] != b"EXFAT   ":
            return
        fat_off, _fat_len, heap, self.ncl, root = struct.unpack_from("<IIIII", bs, 80)
        self.bps = 1 << bs[108]
        self.cl = self.bps << bs[109]
        self.fat = self.base + fat_off * self.bps
        self.heap = self.base + heap * self.bps
        self.bitmap = None
        dati = b"".join(self._cluster(c) for c in self._segui(root, 1 << 12))   # radice: voce 0x81 = bitmap
        for i in range(0, len(dati) - 31, 32):
            if dati[i] == 0x81 and not dati[i + 1] & 1:                           # prima bitmap (prima FAT)
                primo, lun = struct.unpack_from("<IQ", dati, i + 20)
                self.bitmap = (self._segui(primo, (lun + self.cl - 1) // self.cl), lun)
                break
        self.ok = self.bitmap is not None

    def _leggi(self, pos, n):
        """Lettura con pagine in memoria (FAT e bitmap si leggono a pezzi, non tutte)."""
        out = b""
        while n > 0:
            p, d = divmod(pos, self.PAG)
            if p not in self.pag:
                self.pag[p] = self.img.read(p * self.PAG, self.PAG)
            b = self.pag[p][d:d + n]
            if not b:
                break
            out, pos, n = out + b, pos + len(b), n - len(b)
        return out

    def _cluster(self, c):
        return self.img.read(self.heap + (c - 2) * self.cl, self.cl)

    def _succ(self, c):
        return struct.unpack("<I", self._leggi(self.fat + c * 4, 4))[0]

    def _segui(self, c, lim):
        v = []
        while 2 <= c < self.ncl + 2 and len(v) < lim:
            v.append(c)
            c = self._succ(c)
        return v

    def _libero(self, c):
        clu, lun = self.bitmap
        i = c - 2
        if i // 8 >= lun:
            return False
        k, r = divmod(i // 8, self.cl)
        return k < len(clu) and not self._leggi(self.heap + (clu[k] - 2) * self.cl + r, 1)[0] >> (i % 8) & 1

    def catena(self, inode):
        """(cluster, dimensione) del cancellato frammentato, oppure None (si legge con icat)."""
        if not self.ok or not str(inode).isdigit() or int(inode) < 3:
            return None
        e = self.img.read(self.heap + (int(inode) - 3) * 32, 64)
        # voce di file + Stream Extension: cancellata (0x05/0x40) o rimasta attiva (0x85/0xC0) dentro una cartella
        # cancellata; in entrambi i casi i cluster devono risultare liberi nella bitmap (un file attivo li ha occupati)
        if len(e) < 64 or (e[0], e[32]) not in ((0x05, 0x40), (0x85, 0xC0)) or e[1] < 2:
            return None
        if struct.unpack_from("<H", e, 4)[0] & 0x10 or e[33] & 2:      # cartella, o NoFatChain: icat è già giusto
            return None
        primo, dim = struct.unpack_from("<IQ", e, 52)
        n = (dim + self.cl - 1) // self.cl
        if n < 2:
            return None
        v, c = [], primo
        while len(v) < n:
            if not 2 <= c < self.ncl + 2 or c in v or not self._libero(c):
                return None
            v.append(c)
            c = self._succ(c)
        if c < 0xFFFFFFF8 or all(b == a + 1 for a, b in zip(v, v[1:])):
            return None
        return v, dim

    def scostamenti(self, inode):
        """(3.0.2) Scostamento da UTC (in secondi) scritto nella voce exFAT per creazione (B), modifica (M) e accesso (A),
        None per ciascuno se il campo non è valido (bit 7 a zero: chi ha scritto il disco non l'ha registrato). L'ora del
        disco meno lo scostamento è l'istante UTC: in quel caso il fuso del dispositivo non serve (DFR-01 exFAT di NIST,
        scritto da un Mac: ora 22:12 con +4 h = 18:12 UTC). Sleuth Kit restituisce l'ora del disco senza applicarlo."""
        if not self.ok or not str(inode).isdigit() or int(inode) < 3:
            return None
        e = self.img.read(self.heap + (int(inode) - 3) * 32, 32)
        if len(e) < 32 or e[0] not in (0x85, 0x05):
            return None

        def sc(b):
            return None if not b & 0x80 else ((b & 0x7F) - (128 if b & 0x40 else 0)) * 900
        return {"B": sc(e[22]), "M": sc(e[23]), "A": sc(e[24])}

    def flusso(self, v, dim):
        i = 0
        while i < len(v) and dim > 0:
            j = i + 1
            while j < len(v) and v[j] == v[j - 1] + 1 and (j - i) * self.cl < 1 << 20:
                j += 1
            b = self.img.read(self.heap + (v[i] - 2) * self.cl, min((j - i) * self.cl, dim))
            if not b:
                return
            yield b
            dim -= len(b)
            i = j


CANC_BLOCCHI_RIUSATI = 3   # (3.0.2) cancellato con blocchi dei dati oggi assegnati a un altro file (vedi segna_riusati)


class MappaAllocati:
    """(3.0.2) Blocchi oggi assegnati a un file, nelle unità di Sleuth Kit (FAT ed exFAT: settori; NTFS: cluster; ext:
    blocchi), dalle mappe del file system lette una volta: NTFS $Bitmap, FAT tabella dei cluster, exFAT bitmap
    (CatenaExfat), ext bitmap dei blocchi dei gruppi. allocato(b) dà True/False, None se il file system non è gestito."""

    def __init__(self, case, offset, fs):
        import forense_estesa as fe
        self.fs = str(fs or "").lower()
        self.img = fe.HeadReader(case)._img()
        self.base = int(offset) * 512
        self.case, self.off = case, int(offset)
        self.tipo, self.pag = None, {}
        bs = self.img.read(self.base, 512)
        if self.fs.startswith("ntfs"):
            hr = fe.HeadReader(case)
            hr.img = self.img
            fsi = hr._fs(self.off)
            f = fsi.open_meta(inode=6)                               # $Bitmap
            self.bitmap = f.read_random(0, int(f.info.meta.size))
            self.tipo = "ntfs"
        elif self.fs.startswith("exfat"):
            self.cx = catena_exfat_lettore(case, offset)
            if self.cx:
                self.spc = self.cx.cl // self.cx.bps
                self.heap_sec = (self.cx.heap - self.base) // self.cx.bps
                self.tipo = "exfat"
        elif self.fs.startswith("fat"):
            bps, spc = struct.unpack_from("<H", bs, 11)[0], bs[13]
            ris, nfat, nroot = struct.unpack_from("<H", bs, 14)[0], bs[16], struct.unpack_from("<H", bs, 17)[0]
            tot = struct.unpack_from("<H", bs, 19)[0] or struct.unpack_from("<I", bs, 32)[0]
            fsz = struct.unpack_from("<H", bs, 22)[0] or struct.unpack_from("<I", bs, 36)[0]
            self.fat = self.base + ris * bps
            self.spc, self.bps = spc, bps
            self.dati = ris + nfat * fsz + (nroot * 32 + bps - 1) // bps   # primo settore dell'area dati
            ncl = (tot - self.dati) // spc
            self.bit = 12 if ncl < 4085 else 16 if ncl < 65525 else 32
            self.tipo = "fat"
        elif self.fs.startswith("ext"):
            sb = self.img.read(self.base + 1024, 1024)
            self.first, lbs = struct.unpack_from("<II", sb, 20)
            self.bsz = 1024 << lbs
            self.bpg = struct.unpack_from("<I", sb, 32)[0]
            inc = struct.unpack_from("<I", sb, 96)[0]
            self.dsz = (struct.unpack_from("<H", sb, 254)[0] or 32) if inc & 0x80 else 32
            self.gdt = self.base + (self.first + 1) * self.bsz
            self.gruppi = {}
            self.tipo = "ext"

    def _leggi(self, pos, n):
        out = b""
        while n > 0:
            k, d = divmod(pos, 1 << 16)
            if k not in self.pag:
                self.pag[k] = self.img.read(k << 16, 1 << 16)
            b = self.pag[k][d:d + n]
            if not b:
                break
            out, pos, n = out + b, pos + len(b), n - len(b)
        return out

    def allocato(self, b):
        if self.tipo == "ntfs":
            i = b >> 3
            return i < len(self.bitmap) and bool(self.bitmap[i] >> (b & 7) & 1)
        if self.tipo == "exfat":
            if b < self.heap_sec:
                return True
            return not self.cx._libero((b - self.heap_sec) // self.spc + 2)
        if self.tipo == "fat":
            if b < self.dati:
                return True                                          # tabella o cartella radice: non sono dati
            c = (b - self.dati) // self.spc + 2
            if self.bit == 32:
                v = struct.unpack("<I", self._leggi(self.fat + c * 4, 4))[0] & 0x0FFFFFFF
            elif self.bit == 16:
                v = struct.unpack("<H", self._leggi(self.fat + c * 2, 2))[0]
            else:
                w = struct.unpack("<H", self._leggi(self.fat + c * 3 // 2, 2))[0]
                v = w >> 4 if c & 1 else w & 0xFFF
            return v != 0
        if self.tipo == "ext":
            g, i = divmod(b - self.first, self.bpg)
            if g not in self.gruppi:
                d = self._leggi(self.gdt + g * self.dsz, self.dsz)
                bmp = struct.unpack_from("<I", d, 0)[0] | ((struct.unpack_from("<I", d, 0x20)[0] << 32) if self.dsz >= 64 else 0)
                flags = struct.unpack_from("<H", d, 0x12)[0]
                self.gruppi[g] = None if flags & 2 else bmp          # BLOCK_UNINIT: nessun blocco di dati usato
            bmp = self.gruppi[g]
            if bmp is None:
                return False
            return bool(self._leggi(self.base + bmp * self.bsz + (i >> 3), 1)[0] >> (i & 7) & 1)
        return None


def segna_riusati(case, offset, con, fs):
    """(3.0.2) Un file cancellato i cui blocchi oggi sono assegnati a un altro file restituisce (in parte) il contenuto di
    quel file. Per ogni cancellato (deleted = 1, file) si controllano tutti i blocchi che RepertIA leggerebbe (le runlist
    di Sleuth Kit, o la catena exFAT se si segue) e, se anche uno è assegnato, la voce diventa CANC_BLOCCHI_RIUSATI.
    Solo NTFS, FAT, exFAT ed ext; registro «cancellati_blocchi_riusati». Restituisce quanti ne ha segnati."""
    try:
        import forense_estesa as fe
        import pytsk3 as pt
        m = MappaAllocati(case, offset, fs)
        if m.tipo is None:
            return 0
        hr = fe.HeadReader(case)
        hr.img = m.img
        fsi = hr._fs(int(offset))
        if fsi is None:
            return 0
    except Exception:
        return 0
    segnati = []
    righe = con.execute("SELECT rowid, inode FROM files WHERE part=? AND deleted=1 AND type LIKE '%r'", (int(offset),)).fetchall()
    for rid, ino in righe:
        try:
            if m.tipo == "exfat":
                x = catena_exfat(case, offset, ino) if str(ino).isdigit() else None
                if x:
                    blocchi = [(m.heap_sec + (c - 2) * m.spc, m.spc) for c in x[1]]
                else:
                    blocchi = None
            else:
                blocchi = None
            if blocchi is None:
                f = fsi.open_meta(inode=int(str(ino).split("-")[0]))
                blocchi = []
                for a in f:
                    if int(a.info.type) not in (int(pt.TSK_FS_ATTR_TYPE_NTFS_DATA), int(pt.TSK_FS_ATTR_TYPE_DEFAULT)):
                        continue
                    if not int(a.info.flags) & int(pt.TSK_FS_ATTR_NONRES):
                        continue
                    for r in a:
                        if int(r.flags) & (int(pt.TSK_FS_ATTR_RUN_FLAG_SPARSE) | int(pt.TSK_FS_ATTR_RUN_FLAG_FILLER)) \
                                or int(r.addr) == 0:
                            continue
                        blocchi.append((int(r.addr), int(r.len)))
            if any(m.allocato(b) for a, n in blocchi for b in range(a, a + n)):
                segnati.append((rid, ino))
        except Exception:
            continue
    if segnati:
        con.executemany("UPDATE files SET deleted=? WHERE rowid=?", [(CANC_BLOCCHI_RIUSATI, r) for r, _i in segnati])
        con.commit()
        case.log("cancellati_blocchi_riusati", {"partizione": int(offset), "n": len(segnati),
                                                "inode": [i for _r, i in segnati][:200]})
    return len(segnati)


_CATENE_EXFAT = {}


def catena_exfat_lettore(case, offset):
    """Lettore exFAT della partizione (uno per immagine e partizione), oppure None se non è exFAT o non si apre."""
    k = (str(case.image), int(offset))
    if k not in _CATENE_EXFAT:
        try:
            r = CatenaExfat(case, int(offset))
            _CATENE_EXFAT[k] = r if r.ok else None
        except Exception:
            _CATENE_EXFAT[k] = None
    return _CATENE_EXFAT[k]


def catena_exfat(case, offset, inode):
    """(cluster letti, catena, dimensione) per un cancellato exFAT frammentato (vedi CatenaExfat), altrimenti None."""
    r = catena_exfat_lettore(case, offset)
    try:
        x = r.catena(inode) if r else None
    except Exception:
        x = None
    return (r, *x) if x else None
