#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - triage: partizioni, file system, sistema operativo, elenco dei file, timeline.

(3.0.4) Codice spostato da forense_agent.py senza modifiche, per avere file più corti. Si carica tramite
forense_agent, che ne riesporta i nomi: gli altri moduli continuano a usare «fa.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fa.<nome>»).
"""
import csv
import datetime as dt
import json
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from forense_lingua import tr
import forense_apfs as ap

import forense_agent as fa
from forense_agent import (
    CANC_RIASSEGNATO, FLS_RE, INSERT_EV, INSERT_FILE, IS_WIN, KIND, MMLS_RE, MappaAllocati, PLASO_CONTAINER,
    PLASO_IMAGE, catena_exfat_lettore, dec, now, sh, stream_lines)

# -------------------------------------------------------------------- triage

def apfs_volumes(case, offset):
    """Se all'offset c'è un contenitore APFS restituisce i volumi letti da pstat
    (nome, ruolo, cifrato), altrimenti None. pstat può fermarsi a metà sui Mac recenti:
    si usa comunque quello che ha stampato."""
    if not shutil.which("pstat"):
        return None
    try:
        cp = sh(case, ["pstat", "-o", str(offset), case.image], timeout=300)
    except subprocess.TimeoutExpired:
        return None
    out = dec(cp.stdout)
    if not re.search(r"^Type:\s*APFS", out, re.M):
        return None
    vols, cur = [], None
    for line in out.splitlines():
        line = line.lstrip("|+-> ").strip()
        if line.startswith("Volume "):
            cur = {"uuid": line.split()[1], "name": None, "role": None, "encrypted": None}
            vols.append(cur)
        elif cur and (m := re.match(r"Name \(Role\):\s*(.*?)\s*\(([^)]*)\)\s*$", line)):
            cur["name"], cur["role"] = m.group(1), m.group(2)
        elif cur and (m := re.match(r"Encrypted:\s*(\w+)", line)):
            cur["encrypted"] = m.group(1).lower().startswith("y")
    err = dec(cp.stderr).strip()
    return {"volumes": vols, "complete": cp.returncode == 0,
            "error": err.splitlines()[-1] if err else None}


_LAYOUT = {}


def layout_volumi(case):
    """Suddivisione del disco come la stampa mmls (come la vista «volumi» di Autopsy): tabella delle partizioni e
    TUTTE le righe, anche Meta e spazio non allocato. Settori riportati in unità da 512 byte, come gli offset del caso.
    Ogni voce: n (indice di mmls, «vol<n>»), slot, start, end, length, desc, kind (meta|unalloc|vol), parts (offset delle
    partizioni del caso che iniziano lì: una, o una per volume APFS) e part (la prima, o None). None se l'immagine non ha una tabella delle partizioni."""
    key = (str(case.root), str(case.image))
    if key in _LAYOUT:
        return _LAYOUT[key]
    res = None
    try:
        cp = subprocess.run(["mmls", case.image], capture_output=True, stdin=subprocess.DEVNULL, timeout=300)
    except (OSError, subprocess.SubprocessError):
        cp = None
    if cp is not None and cp.returncode == 0:
        out = dec(cp.stdout)
        lines = out.splitlines()
        u = re.search(r"Units are in (\d+)-byte sectors", out)
        unit = int(u.group(1)) if u else 512
        scale = max(1, unit // 512)
        tipo = next((l.strip() for l in lines if l.strip() and not l.startswith(" ")), "") or tr("Tabella delle partizioni")
        voci = []
        for line in lines:
            m = re.match(r"^\s*(\d+):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$", line)
            if not m:
                continue
            slot = m.group(2)
            kind = "meta" if slot == "Meta" else "unalloc" if slot.startswith("-") else "vol"
            voci.append({"n": int(m.group(1)), "slot": slot, "start": int(m.group(3)) * scale,
                         "end": (int(m.group(4)) + 1) * scale - 1, "length": int(m.group(5)) * scale,
                         "desc": m.group(6).strip(), "kind": kind, "part": None})
        if voci:
            res = {"tipo": tipo, "unita": unit, "voci": voci}
    if res:
        parts = case.meta.get("partitions", [])
        for v in res["voci"]:
            if v["kind"] != "vol":
                continue
            # le partizioni del caso che iniziano qui; un contenitore APFS ne ha una per volume (offset sintetici)
            v["parts"] = [p["offset"] for p in parts
                          if p["offset"] == v["start"] or (p.get("apfs") or {}).get("real_offset") == v["start"]]
            v["part"] = v["parts"][0] if v["parts"] else None
    _LAYOUT[key] = res
    return res


def detect_partitions(case):
    cands = []
    cp = sh(case, ["mmls", case.image])
    if cp.returncode == 0:
        out = dec(cp.stdout)
        # i dischi a 4K (es. Mac Apple Silicon) hanno unità da 4096 byte: gli altri strumenti
        # TSK con -o usano settori da 512, quindi gli offset vanno convertiti
        u = re.search(r"Units are in (\d+)-byte sectors", out)
        scale = max(1, int(u.group(1)) // 512) if u else 1
        if scale > 1:
            case.meta["settore_byte"] = int(u.group(1))
            print(tr("Disco con settori da {v1} byte: offset convertiti in settori da 512.").format(v1=u.group(1)))
        for line in out.splitlines():
            m = MMLS_RE.match(line)
            if m and m.group(1) != "Meta" and not m.group(1).startswith("-"):
                cands.append((int(m.group(2)) * scale, int(m.group(4)) * scale,
                              m.group(5).strip(), m.group(1)))
    if not cands:  # es. pendrive senza tabella partizioni
        cands = [(0, None, tr("intero volume (nessuna tabella partizioni)"), None)]
    found = []
    for start, length, desc, slot in cands:
        fs = sh(case, ["fsstat", "-o", str(start), case.image], timeout=600)
        t = re.search(r"File System Type:\s*(.+)", dec(fs.stdout))
        found.append({"offset": start, "length_sectors": length, "desc": desc,
                      "slot": slot, "readable": fs.returncode == 0,
                      "fs": t.group(1).strip() if (fs.returncode == 0 and t) else None})
    found = apfs_expand(case, found)
    for p in found:
        if not p["readable"] and not p.get("apfs") and not p.get("fs"):
            info = apfs_volumes(case, p["offset"])
            if info:
                p["fs"] = tr("APFS (contenitore)")
                p["apfs_pstat"] = info
    return found


def apfs_expand(case, found):
    """Sostituisce ogni contenitore APFS con i suoi volumi (letti con libfsapfs): un volume per voce,
    cifrati compresi (readable False finché non si fornisce la chiave)."""
    out, n_cont = [], 0
    for p in found:
        vols = None
        if p.get("slot") != "Meta" and (not p["readable"] or "APFS" in (p.get("fs") or "").upper()):
            vols = apfs_probe(case, p)
        if not vols:
            out.append(p)
            continue
        n_cont += 1
        ents = ap.partition_entries(p, vols, p["offset"], p.get("length_sectors"))
        out += ents
        print(tr("Contenitore APFS all'offset {offset}: {v1} volumi - ").format(offset=p['offset'], v1=len(vols))
              + ", ".join(f"{e['apfs']['name']}{' (cifrato' + (', sbloccato' if e['readable'] else ', serve la chiave') + ')' if e['apfs']['encrypted'] else ''}"
                          for e in ents), flush=True)
    return out


def apfs_probe(case, p):
    """Volumi APFS della partizione, se lo è (controllo rapido della firma NXSB, poi libfsapfs)."""
    if not ap.have_lib():
        return None
    try:
        import forense_estesa as fe
        img = fe.ImageFile(case.image)
        try:
            head = img.pread(p["offset"] * 512, 64)
        finally:
            img.close()
    except Exception:
        return None
    if not ap.is_container_head(head):
        return None
    return ap.detect(case, p["offset"], p.get("length_sectors"))


def apfs_message(parts):
    """Spiegazione per le copie di Mac con APFS non leggibile da TSK."""
    vols = [v for p in parts for v in (p.get("apfs") or {}).get("volumes", [])]
    names = ", ".join(f"{v['name']} ({v['role']}{', cifrato' if v.get('encrypted') else ''})"
                      for v in vols if v.get("name")) or tr("non elencati")
    return (tr("Copia di un Mac con contenitore APFS (volumi letti: ") + names + tr("). "
            "The Sleuth Kit non riesce a leggerne i volumi (volume di sistema sigillato dei macOS recenti).\n"
            "Sui Mac Apple Silicon o con chip T2 il volume Dati di una copia fisica è inoltre cifrato con "
            "chiavi legate all'hardware e non si può decifrare fuori dal Mac.\n"
            "Per questi Mac serve un'acquisizione logica del volume Dati, fatta sul Mac acceso e sbloccato."))


def _fls_windows(s):
    """Come fls.exe di Sleuth Kit su Windows scrive un nome UTF-8: i caratteri oltre 255 diventano «?», gli altri un byte
    Latin-1 (che letto come UTF-8 non è valido: «Gefäß» → «Gef��»). La perdita è definitiva, per questo serve pytsk3."""
    return dec("".join(c if ord(c) < 256 else "?" for c in s).encode("latin-1"))


class NomiVeri:
    """(3.0.2) Windows: fls.exe scrive i nomi nella codifica del sistema e quelli non ASCII (cinese, russo, arabo, ma
    anche «à» o «ß») arrivano alterati. Alla prima riga alterata si leggono con pytsk3 i nomi veri della partizione
    (stesso Sleuth Kit, ma in UTF-8) e ogni percorso si ricollega con (inode, forma alterata). Se più nomi danno la stessa
    forma (voci cancellate con inode 0: «北京.txt» e «東京.txt» diventano entrambe «??.txt») si usano nell'ordine della
    cartella, che fls e pytsk3 percorrono allo stesso modo. Su Mac e Linux fls scrive già UTF-8 e non serve."""
    def __init__(self, case, offset):
        self.case, self.offset, self.mappa = case, offset, None

    @staticmethod
    def alterato(s):
        return "?" in s or "�" in s

    def _carica(self):
        self.mappa = {}
        try:
            import forense_estesa as fe
            import pytsk3 as pt
            fs = fe.HeadReader(self.case)._fs(self.offset)
        except Exception:
            fs = None
        if fs is None:
            return
        visti, coda = set(), [(fs.open_dir(path="/"), "")]
        while coda:
            d, base = coda.pop()
            try:
                voci = list(d)
            except Exception:
                continue
            for e in voci:
                try:
                    nome = e.info.name.name.decode("utf-8", "replace")
                    addr = int(e.info.name.meta_addr)
                except Exception:
                    continue
                if nome in (".", ".."):
                    continue
                vero = f"{base}{nome}"
                if any(ord(c) > 127 for c in vero):
                    self.mappa.setdefault((addr, _fls_windows(vero)), []).append(vero)
                meta = e.info.meta
                if meta is not None and int(meta.type) == int(pt.TSK_FS_META_TYPE_DIR) and addr not in visti:
                    visti.add(addr)
                    try:
                        coda.append((e.as_directory(), vero + "/"))
                    except Exception:
                        pass

    def correggi(self, percorso, inode):
        """Percorso vero di una riga di fls (inode «64-128-2», «53100», «0»), o quello di fls se non si sa."""
        if os.name != "nt" or not self.alterato(percorso):
            return percorso
        if self.mappa is None:
            self._carica()
        try:
            addr = int(str(inode).split("-")[0])
        except ValueError:
            return percorso
        v = self.mappa.get((addr, percorso))
        if not v:
            return percorso
        return v.pop(0) if len(v) > 1 else v[0]


def orfani_ext(case, offset, visti):
    """(3.0.2) ext: inode di file cancellati che Sleuth Kit 4.15 non elenca tra gli orfani ($OrphanFiles), per esempio i
    file ext2 rimasti dentro una cartella cancellata il cui nome ha inode 0 (immagini NIST CFTT DFR-11 e DFR-12: il
    contenuto è intatto, Sleuth Kit 3.2.2 li elencava). Si prendono da `ils` (inode non allocati e rimossi) quelli con
    dimensione, non già elencati da fls con nessun nome, e si aggiungono come «$OrphanFiles/OrphanFile-N» (come fls)."""
    if not shutil.which("ils"):
        return []
    out = []
    for line in stream_lines(case, ["ils", "-o", str(offset), case.image]):
        x = line.split("|")
        if len(x) < 11 or not x[0].isdigit() or x[1] != "f":
            continue
        try:
            dim = int(x[10])
        except ValueError:
            continue
        if dim > 0 and x[0] not in visti:
            out.append(x[0])
    return out


CARTELLE_EXT_MAX = 32 << 30      # oltre questa dimensione del file system non si cercano i blocchi di cartella liberi
_PUNTO_PUNTO = re.compile(rb"(....)\x0c\x00\x01\x02\.\x00\x00\x00(....)(..)\x02\x02\.\.\x00\x00", re.S)


def _voci_cartella_ext(b, max_ino):
    """Voci (inode, nome, tipo) di un blocco di cartella ext: quelle collegate dai rec_len e quelle cancellate rimaste
    nella coda di una voce (il rec_len della precedente le ha inglobate). Tipo 1 file, 2 cartella, 7 collegamento."""
    out, i = [], 0
    while i + 8 <= len(b):
        ino, rl, nl, tp = struct.unpack_from("<IHBB", b, i)
        if rl < 8 or i + rl > len(b) or i + 8 + nl > len(b):
            break
        out.append((ino, b[i + 8:i + 8 + nl], tp))
        j = i + ((8 + nl + 3) & ~3)
        while j + 8 <= i + rl:
            ino2, rl2, nl2, tp2 = struct.unpack_from("<IHBB", b, j)
            nm = b[j + 8:j + 8 + nl2]
            if nl2 and rl2 >= 8 and j + 8 + nl2 <= i + rl and tp2 in (1, 2, 7) and len(nm) == nl2 \
                    and all(c >= 32 and c != 47 and c != 127 for c in nm):
                out.append((ino2, nm, tp2))
                j += (8 + nl2 + 3) & ~3
                continue
            # voce cancellata il cui numero di inode è stato coperto dal nome più lungo della voce che ne ha preso il
            # posto (rec_len, lunghezza e tipo stanno in j…j+3, il nome da j+4): resta solo il nome (inode 0)
            rl3, nl3, tp3 = struct.unpack_from("<HBB", b, j)
            nm = b[j + 4:j + 4 + nl3]
            if nl3 and tp3 in (1, 2, 7) and rl3 >= ((8 + nl3 + 3) & ~3) and j - 4 + rl3 <= i + rl \
                    and len(nm) == nl3 and all(c >= 32 and c != 47 and c != 127 for c in nm) \
                    and not any(b[j + 4 + nl3:j - 4 + ((8 + nl3 + 3) & ~3)]):
                out.append((0, nm, tp3))
                j += (4 + nl3 + 3) & ~3
                continue
            j += 4
        i += rl
    return [(ino, nm.decode("utf-8", "replace"), tp) for ino, nm, tp in out
            if 0 <= ino <= max_ino and nm not in (b".", b"..") and tp in (1, 2, 7)]


def _blocchi_journal_ext(case, offset):
    """Blocchi del journal ext3/ext4 (inode 8): contengono copie di blocchi di cartella, da non leggere come cartelle."""
    try:
        import forense_estesa as fe
        fsi = fe.HeadReader(case)._fs(int(offset))
        out = set()
        for a in fsi.open_meta(inode=8):
            for r in a:
                if int(r.addr):
                    out.update(range(int(r.addr), int(r.addr) + int(r.len)))
        return out
    except Exception:
        return set()


def cartelle_ext(case, offset, con, fs):
    """(3.0.2) ext3/ext4: alla cancellazione l'inode di una cartella perde i puntatori ai blocchi, ma il blocco con le voci
    (nome → inode) resta sul disco finché non è riusato. Sleuth Kit non lo trova più e i file che conteneva restano senza
    nome («$OrphanFiles/OrphanFile-N») o non sono elencati affatto (immagini NIST CFTT DFR-11 e DFR-12 ext3/ext4, file in
    una cartella cancellata). Si cercano nei blocchi LIBERI i blocchi di cartella (prima voce «.» che punta a sé, seconda
    «..»), se ne leggono le voci e: l'orfano senza nome prende il suo percorso; l'inode non elencato si aggiunge come
    cancellato; l'inode già elencato con un nome resta com'è. La cartella prende il nome della voce cancellata che la
    elenca, altrimenti «$OrphanFiles/OrphanDir-N». Nel primo blocco delle cartelle vive (non nelle copie del journal) si
    prendono solo i nomi cancellati il cui inode è stato coperto da una voce nuova (DFR-08 ext3 «Atlas.txt»), elencati
    con inode 0 come fa fls. Solo file system fino a CARTELLE_EXT_MAX. Restituisce le voci aggiunte; registro
    «cartelle_ext»."""
    try:
        m = MappaAllocati(case, offset, fs)
        if m.tipo != "ext":
            return 0
        sb = m.img.read(m.base + 1024, 1024)
        n_ino, n_blk = struct.unpack_from("<II", sb, 0)
        if n_blk * m.bsz > CARTELLE_EXT_MAX:
            case.log("cartelle_ext", {"partizione": int(offset), "saltato": "dimensione", "byte": n_blk * m.bsz})
            return 0
    except Exception:
        return 0
    trovate = {}                                     # inode della cartella → (genitore, voci)
    journal = None
    passo = 4 << 20
    pos = 0
    while pos < n_blk * m.bsz:
        try:
            d = m.img.read(m.base + pos, passo + 32)
        except Exception:
            break
        if not d:
            break
        for x in _PUNTO_PUNTO.finditer(d):
            if x.start() % m.bsz or x.start() >= passo:
                continue
            blk = (pos + x.start()) // m.bsz
            me, pa = struct.unpack("<I", x.group(1))[0], struct.unpack("<I", x.group(2))[0]
            if not (0 < me <= n_ino and 0 < pa <= n_ino):
                continue
            voci = _voci_cartella_ext(d[x.start():x.start() + m.bsz], n_ino)
            if m.allocato(blk) is not False:
                # cartella viva (Sleuth Kit la legge già): solo i nomi senza inode; mai le copie nel journal
                if journal is None:
                    journal = _blocchi_journal_ext(case, offset)
                if blk in journal:
                    continue
                voci = [v for v in voci if v[0] == 0]
            if voci:
                g = trovate.setdefault(me, [pa, []])
                g[1] += [v for v in voci if v not in g[1]]
        pos += passo
    if not trovate:
        return 0
    off = int(offset)
    righe, percorsi = {}, set()
    for rid, ino, tipo, pa in con.execute("SELECT rowid, inode, type, path FROM files WHERE part=?", (off,)):
        righe.setdefault(str(ino), []).append((rid, tipo, pa))
        percorsi.add(pa)
    nomi_dir = {}
    for me, (pa, voci) in trovate.items():
        for ino, nome, tp in voci:
            if tp == 2:
                nomi_dir.setdefault(ino, (me, nome))
    memo = {}

    def percorso(c, prof=0):
        if c == 2:
            return ""
        if c in memo:
            return memo[c]
        p = None
        for _rid, tipo, pa in reversed(righe.get(str(c), [])):
            if tipo.startswith("d") and not pa.startswith("$OrphanFiles/"):
                p = pa
                break
        if p is None and c in nomi_dir and prof < 64:
            su = percorso(nomi_dir[c][0], prof + 1)
            p = f"{su}/{nomi_dir[c][1]}" if su else nomi_dir[c][1]
        if p is None:
            p = f"$OrphanFiles/OrphanDir-{c}"
        memo[c] = p
        return p
    nuovi, rinominati = [], []
    for me, (_pa, voci) in sorted(trovate.items()):
        base = percorso(me)
        for ino, nome, tp in voci:
            dest = f"{base}/{nome}" if base else nome
            if ino == 0:                                 # nome rimasto senza inode: si elenca come fa fls («r/- * 0»)
                if dest not in percorsi:
                    t = "d/-" if tp == 2 else "l/-" if tp == 7 else "r/-"
                    nuovi.append((off, "0", 1, t, dest))
                    percorsi.add(dest)
                continue
            gia = righe.get(str(ino), [])
            orfano = [r for r in gia if r[2] == f"$OrphanFiles/OrphanFile-{ino}"]
            if orfano:
                rinominati.append((dest, orfano[0][0]))
            elif not gia:
                t = "d/d" if tp == 2 else "l/l" if tp == 7 else "r/r"
                nuovi.append((off, str(ino), 1, t, dest))
                righe[str(ino)] = [(None, t, dest)]
    if rinominati:
        con.executemany("UPDATE files SET path=? WHERE rowid=?", rinominati)
    if nuovi:
        con.executemany(INSERT_FILE, nuovi)
    con.commit()
    if nuovi or rinominati:
        case.log("cartelle_ext", {"partizione": off, "cartelle": len(trovate), "aggiunti": len(nuovi),
                                  "orfani_con_nome": len(rinominati), "esempi": [r[4] for r in nuovi[:20]]})
    return len(nuovi)


def nomi_residui_exfat(case, offset, con):
    """(3.0.2) exFAT: una voce di file è un gruppo (0x85 file, 0xC0 stream, 0xC1 nome; cancellata: 0x05, 0x40, 0x41).
    Quando un file nuovo riusa le prime voci di un gruppo cancellato, le voci di nome che avanzano restano nella cartella
    senza dimensione né cluster (DFR-08 exFAT «Deneb.txt»: Sleuth Kit non le elenca). Nei cluster di cartella (quelli
    che contengono voci già elencate) si cercano le voci di nome cancellate fuori da ogni gruppo e si elencano con
    inode 0, come fls fa per i nomi senza metadati. Restituisce le voci aggiunte; registro «exfat_nomi_residui»."""
    xf = catena_exfat_lettore(case, offset)
    if not xf:
        return 0
    off = int(offset)
    cartelle, percorsi = {}, set()
    for ino, pa in con.execute("SELECT inode, path FROM files WHERE part=?", (off,)):
        percorsi.add(pa)
        if str(ino).isdigit() and int(ino) >= 3:
            c = (int(ino) - 3) * 32 // xf.cl + 2
            if 2 <= c < xf.ncl + 2:
                cartelle.setdefault(c, pa.rsplit("/", 1)[0] if "/" in pa else "")
    nuovi, resto, prec = [], 0, None
    for c in sorted(cartelle):
        testa = c != prec    # cluster non adiacente al precedente: le voci in testa possono finire un gruppo di prima
        if testa:
            resto = 0
        prec = c + 1
        b = xf._cluster(c)
        nome = []

        def chiudi():
            s = "".join(nome).split("\0")[0]
            nome.clear()
            if s and all(ch.isprintable() and ch not in '/\\:*?"<>|' for ch in s):
                dest = f"{cartelle[c]}/{s}" if cartelle[c] else s
                if dest not in percorsi:
                    percorsi.add(dest)
                    nuovi.append((off, "0", 1, "r/-", dest))
        for i in range(0, len(b) - 31, 32):
            t = b[i]
            if resto:
                resto -= 1
                continue
            if testa and t in (0x40, 0x41, 0xC0, 0xC1):
                continue
            testa = False
            if t in (0x85, 0x05):
                if nome:
                    chiudi()
                resto = b[i + 1]
            elif t == 0x41 and b[i + 1] == 0:
                nome.append(b[i + 2:i + 32].decode("utf-16-le", "replace"))
            else:
                if nome:
                    chiudi()
                if t == 0:
                    break
        if nome:
            chiudi()
    if nuovi:
        con.executemany(INSERT_FILE, nuovi)
        con.commit()
        case.log("exfat_nomi_residui", {"partizione": off, "n": len(nuovi), "esempi": [r[4] for r in nuovi[:20]]})
    return len(nuovi)


def build_listing(case, offset, con, fs=""):
    n = deleted = 0
    batch = []
    veri = NomiVeri(case, offset)
    ext = str(fs or "").lower().startswith("ext")
    visti = set()
    for line in stream_lines(case, ["fls", "-r", "-p", "-o", str(offset), case.image]):
        m = FLS_RE.match(line)
        if not m:
            continue
        d = (CANC_RIASSEGNATO if m.group(4) else 1) if m.group(2) else 0
        batch.append((offset, m.group(3), d, m.group(1), veri.correggi(m.group(5), m.group(3))))
        if ext:
            visti.add(m.group(3))
        n += 1
        deleted += d
        if n % 2000 == 0:
            fa.avanz(fatti=n)
        if len(batch) >= 20000:
            con.executemany(INSERT_FILE, batch)
            batch.clear()
            if n % 100000 == 0:
                print(tr("  {n} file elencati...").format(n=n), flush=True)
    if ext:
        agg = orfani_ext(case, offset, visti)
        if agg:
            batch += [(offset, i, 1, "-/r", f"$OrphanFiles/OrphanFile-{i}") for i in agg]
            n += len(agg)
            deleted += len(agg)
            case.log("orfani_ext", {"partizione": offset, "inode": agg[:200], "n": len(agg)})
    con.executemany(INSERT_FILE, batch)
    con.commit()
    k = 0
    try:
        if ext:
            k = cartelle_ext(case, offset, con, fs)
        elif str(fs or "").lower().startswith("exfat"):
            k = nomi_residui_exfat(case, offset, con)
    except Exception:
        k = 0
    n += k
    deleted += k
    return n, deleted


def lookup(con, offset, path):
    r = con.execute("SELECT inode FROM files WHERE part=? AND deleted=0 "
                    "AND lower(path)=? LIMIT 1", (offset, path)).fetchone()
    return r[0] if r else None


def detect_os(case, offset, con):
    if ap.is_apfs_part(offset):
        return ap.detect_os(case, offset, con)
    if fa.lookup(con, offset, "windows/system32/config/system"):
        return "Windows"
    for p in ("usr/lib/os-release", "etc/os-release"):
        ino = fa.lookup(con, offset, p)
        if ino:
            txt = dec(fa.icat_read(case, offset, ino, 65536))
            m = re.search(r'^PRETTY_NAME="?([^"\n]+)', txt, re.M)
            return f"Linux ({m.group(1)})" if m else "Linux"
    ino = fa.lookup(con, offset, "system/library/coreservices/systemversion.plist")
    if ino:
        try:
            d = plistlib.loads(fa.icat_read(case, offset, ino, 1 << 20))
            return f"macOS {d.get('ProductVersion', '')}".strip()
        except Exception:
            return "macOS"
    return None


UA_RE = re.compile(r"^u(\d+)-(\d+)$")       # tratto di spazio non allocato: u<byte iniziale>-<lunghezza in byte>


def _ua_pos(inode):
    """Posizione di un tratto non allocato per il report: byte iniziale e finale nella copia."""
    m = UA_RE.fullmatch(str(inode or ""))
    if not m:
        return ""
    a, n = int(m.group(1)), int(m.group(2))
    return tr("byte {a:,}–{v1:,}").format(a=a, v1=a + n - 1).replace(",", ".")


def fs_block_size(case, part):
    """Dimensione in byte dell'unità con cui Sleuth Kit numera i blocchi della partizione (blkls, blkcat, ifind):
    il settore per FAT/exFAT, il cluster per NTFS, il blocco per ext/HFS."""
    t = dec(sh(case, ["fsstat", "-o", str(part), case.image], timeout=600).stdout)
    fs = (next((p.get("fs") for p in case.meta.get("partitions", []) if p.get("offset") == part), None) or "").upper()
    keys = (["Sector Size"] if "FAT" in fs else []) + ["Block Size", "Cluster Size", "Sector Size"]
    return next((int(m.group(1)) for k in keys for m in [re.search(k + r":\s*(\d+)", t)] if m), 512)


def unalloc_runs(case, part, progress=None):
    """Tratti contigui di spazio non allocato del file system della partizione (come il nodo $Unalloc di Autopsy):
    lista di (byte iniziale nell'immagine, lunghezza in byte), dai blocchi che Sleuth Kit segna come non allocati
    (`blkls -l -A`, blocchi consecutivi uniti). Il risultato è in cache (<cache>/non_allocato/p<offset>.json) perché
    su un disco grande il calcolo dura qualche minuto. Nessun dato della copia viene scritto: solo le posizioni."""
    if ap.is_apfs_part(part):
        raise ValueError(tr("Per i volumi APFS lo spazio non allocato non è disponibile (Sleuth Kit non legge APFS)."))
    cf = fa.cache_base(case) / "non_allocato" / f"p{part}.json"
    try:
        d = json.loads(cf.read_text())
        if d.get("image") == str(case.image):
            return d
    except (OSError, ValueError):
        pass
    bs = fs_block_size(case, part)
    base = part * 512
    runs, s, e, n = [], None, None, 0
    case.log("cmd", ["blkls", "-l", "-A", "-o", str(part), case.image])
    p = subprocess.Popen(["blkls", "-l", "-A", "-o", str(part), case.image], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, env=fa.tsk_env(case, ["blkls"]))
    try:
        for line in p.stdout:
            a = line.split(b"|", 1)[0]
            if not a.isdigit():
                continue
            b = int(a)
            n += 1
            if e is not None and b == e + 1:
                e = b
            else:
                if s is not None:
                    runs.append([base + s * bs, (e - s + 1) * bs])
                s = e = b
            if progress and n % 2_000_000 == 0:
                progress(tr("{n:,} blocchi non allocati letti").format(n=n).replace(",", "."))
    finally:
        p.wait()
    if s is not None:
        runs.append([base + s * bs, (e - s + 1) * bs])
    size = fa.media_size(case)
    if size is None:
        try:
            size = Path(case.image).stat().st_size if not fa.is_e01(case.image) else None
        except OSError:
            size = None
    if size:              # blocchi oltre la fine della copia (immagine troncata): non esistono, si tolgono
        runs = [[a, min(ln, size - a)] for a, ln in runs if a < size]
    if p.returncode not in (0, None) and not runs:
        raise ValueError(tr("Sleuth Kit non è riuscito a leggere lo spazio non allocato di questa partizione."))
    d = {"image": str(case.image), "part": part, "block_size": bs, "blocchi": n,
         "byte": sum(r[1] for r in runs), "runs": runs, "creato": now()}
    try:
        cf.parent.mkdir(parents=True, exist_ok=True)
        cf.write_text(json.dumps(d))
    except OSError:
        pass
    case.log("non_allocato", {"partizione": part, "tratti": len(runs), "blocchi": n, "byte": d["byte"],
                              "blocco": bs})
    return d


def tsk_timeline(case, offset, con):
    n, batch = 0, []
    fat = fa.part_is_fat(case, offset)
    if fa.tsk_neutro(case):
        case.meta["tsk_fuso"] = fa.TSK_FUSO_MARCA
    veri = NomiVeri(case, offset)
    xf = catena_exfat_lettore(case, offset) if fat and fa.tsk_neutro(case) else None   # (3.0.2) scostamenti UTC exFAT
    for line in stream_lines(case, ["fls", "-r", "-m", "/", *fa.tsk_tz(case), "-o", str(offset), case.image]):
        p = line.split("|")
        if len(p) < 11:
            continue
        name = "|".join(p[1:-9])
        inode, size = p[-9], p[-5]
        try:
            sc = xf.scostamenti(inode) if xf else None
        except Exception:
            sc = None
        if NomiVeri.alterato(name):             # «/percorso[ (deleted)]»: (3.0.2) nomi non ASCII su Windows
            m = re.fullmatch(r"/(.*?)( \(deleted(?:-realloc)?\))?", name)
            if m:
                name = "/" + veri.correggi(m.group(1), inode) + (m.group(2) or "")
        for kind, val in zip("AMCB", p[-4:]):   # atime|mtime|ctime|crtime
            try:
                t = int(val)
                if t <= 0:
                    continue
                t = t - sc[kind] if sc and sc.get(kind) is not None else fa.tsk_epoch(case, t, fat)
                ts = dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
            except (ValueError, OverflowError, OSError):
                continue
            batch.append((ts, kind, "FILE", name,
                          tr("{v1} | {name} | inode {inode} | {size} B").format(v1=tr(KIND[kind]), name=name, inode=inode, size=size), "tsk", offset))
        if len(batch) >= 50000:
            con.executemany(INSERT_EV, batch)
            n += len(batch)
            batch.clear()
    con.executemany(INSERT_EV, batch)
    con.commit()
    return n + len(batch)


def _bundled_pythons():
    """Python inclusi nei pacchetti di RepertIA (app per Mac, installazione Windows), per
    usare il loro plaso anche quando RepertIA è avviato con un altro Python (es. dai sorgenti
    con «Avvia RepertIA.command»)."""
    here = Path(__file__).resolve().parent
    home = Path.home()
    out = [os.environ.get("REPERTIA_PYTHON") or ""]
    if IS_WIN:
        la = os.environ.get("LOCALAPPDATA") or str(home / "AppData" / "Local")
        out += [here.parent / "python" / "python.exe",
                Path(la) / "Programs" / "RepertIA" / "python" / "python.exe"]
    else:
        apps = [here.parent.parent.parent, here.parent / "RepertIA.app", here.parent.parent / "RepertIA.app",
                Path("/Applications/RepertIA.app"), home / "Applications" / "RepertIA.app",
                home / "Desktop" / "RepertIA" / "RepertIA.app", home / "Downloads" / "RepertIA" / "RepertIA.app"]
        out += [here.parent / "python" / "bin" / "python3"]
        out += [a / "Contents" / "Resources" / "python" / "bin" / "python3" for a in apps]
    seen, res = set(), []
    for p in out:
        if p and str(p) not in seen and Path(p).is_file():
            seen.add(str(p))
            res.append(str(p))
    return res


_PLASO_PY = {}


def _python_has_plaso(py):
    """Il Python indicato ha plaso? (controllo eseguito una volta, senza caricare plaso qui)."""
    if py not in _PLASO_PY:
        try:
            r = subprocess.run([py, "-c", "import importlib.util as u, sys; sys.exit(0 if "
                                "u.find_spec('plaso') and u.find_spec('plaso.scripts.log2timeline') "
                                "else 1)"], capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
            _PLASO_PY[py] = r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            _PLASO_PY[py] = False
    return _PLASO_PY[py]


def plaso_native():
    """Comandi (liste) di log2timeline e psort senza Docker, oppure None.
    Prima plaso installato nel Python che esegue RepertIA (pacchetti Mac e Windows), poi il
    Python incluso nell'app/installazione di RepertIA, poi i comandi nel PATH."""
    import importlib.util
    try:
        if importlib.util.find_spec("plaso") and importlib.util.find_spec("plaso.scripts.log2timeline"):
            return ([sys.executable, "-m", "plaso.scripts.log2timeline"],
                    [sys.executable, "-m", "plaso.scripts.psort"])
    except Exception:
        pass
    for py in _bundled_pythons():
        if os.path.realpath(py) != os.path.realpath(sys.executable) and _python_has_plaso(py):
            return ([py, "-m", "plaso.scripts.log2timeline"], [py, "-m", "plaso.scripts.psort"])
    l2t = shutil.which("log2timeline.py") or shutil.which("log2timeline")
    ps = shutil.which("psort.py") or shutil.which("psort")
    return ([l2t], [ps]) if l2t and ps else None


def plaso_status():
    """(pronto, modo, messaggio). modo: native, docker, docker_off, no_image, missing."""
    if plaso_native():
        return True, "native", tr("plaso installato")
    if not shutil.which("docker"):
        return False, "missing", (tr("Plaso non trovato: avvia RepertIA da RepertIA.app (Mac) o dall'installazione (Windows), "
                                     "che lo includono; in alternativa installa Docker Desktop e, con internet, esegui: docker "
                                     "pull {PLASO_IMAGE}").format(PLASO_IMAGE=PLASO_IMAGE))
    try:
        if subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode:
            return False, "docker_off", (tr("Docker Desktop non è aperto: avvialo, attendi "
                                         "che sia pronto e riprova."))
        r = subprocess.run(["docker", "image", "inspect", PLASO_IMAGE],
                           capture_output=True, timeout=30)
    except subprocess.TimeoutExpired:
        return False, "docker_off", tr("Docker non risponde: riavvia Docker Desktop.")
    if r.returncode:
        return False, "no_image", (tr("Immagine di plaso non scaricata: con internet esegui docker pull {PLASO_IMAGE} (oppure "
                                      "'Aggiorna strumenti').").format(PLASO_IMAGE=PLASO_IMAGE))
    return True, "docker", "plaso tramite Docker"


RECOVERY_RE = re.compile(r"^\d{6}(-\d{6}){7}$|^[A-Z0-9]{4}(-[A-Z0-9]{4}){5}$")


def plaso_credentials(case):
    """Credenziali per plaso (`TIPO:VALORE`) dalle chiavi tenute in memoria per i volumi APFS."""
    if not any((p.get("apfs") or {}).get("encrypted") for p in case.meta.get("partitions", [])):
        return []
    out = []
    for s_ in ap.secrets():
        v, t = s_.get("valore") or "", s_.get("tipo") or "auto"
        if t == "auto":
            t = "recovery" if RECOVERY_RE.match(v.strip().upper()) else "password"
        x = ("recovery_password:" if t == "recovery" else "password:") + v
        if x not in out:
            out.append(x)
    return out


def mask_credentials(cmd):
    out, hide = [], False
    for c in cmd:
        if hide:
            out.append(str(c).split(":", 1)[0] + ":***")
            hide = False
            continue
        if c == "--credential":
            hide = True
        out.append(tr("<avvio di plaso.scripts.log2timeline con le chiavi dall'ambiente>") if str(c).startswith("import json,os,runpy") else c)
    return out


def run_plaso(case, con):
    """Crea la timeline plaso. Restituisce il numero di eventi, None se non riesce."""
    ok, mode, msg = plaso_status()
    if not ok:
        print(msg)
        return None
    img = Path(case.image)
    storage, csv_out = case.root / "plaso.plaso", case.root / "plaso.csv"
    for f in (storage, csv_out):
        if f.exists():
            f.unlink()
    if mode == "native":
        (l2t, ps), pre = plaso_native(), []
        src, sto, out = str(img), str(storage), str(csv_out)
    else:
        pre = ["docker", "run", "--rm", "--network", "none", "--name",
               f"{PLASO_CONTAINER}-{os.getpid()}",
               *fa.docker_mount(img.parent, "/evidence", ro=True), *fa.docker_mount(case.root, "/case"),
               PLASO_IMAGE]
        l2t, ps = ["log2timeline"], ["psort"]
        src, sto, out = f"/evidence/{img.name}", "/case/plaso.plaso", "/case/plaso.csv"
    v = subprocess.run(pre + l2t + ["--version"], capture_output=True)
    v = dec(v.stdout + v.stderr).strip().splitlines()
    case.meta.setdefault("tool_versions", {})["plaso"] = (
        (v[-1] if v else "?") + (" (Docker)" if mode == "docker" else ""))
    print(tr("Plaso: {plaso}. Può richiedere molto tempo.").format(plaso=case.meta['tool_versions']['plaso']))
    # niente hash di ogni file e niente parser "filestat": le date dei file sono già
    # nella timeline di Sleuth Kit; plaso si concentra sugli artefatti di sistema
    opts = ["--hashers", "none", "--parsers", "!filestat"]
    z = (case.meta.get("fuso_dispositivo") or {}).get("tz")
    if z:       # fonti con ora locale e senza fuso (syslog, setupapi…): plaso le legge come UTC se non gli si dice altro
        opts += ["--timezone", z]
    case.meta["plaso_options"] = " ".join(opts)
    # 2.14: chiavi dei volumi cifrati (FileVault/APFS) sbloccati in questa sessione: plaso le riceve
    # con --credential, altrimenti salta proprio quei volumi. Mai nel registro né su disco: nel
    # modo nativo passano dall'ambiente del processo (non dalla riga di comando).
    creds = plaso_credentials(case)
    env, l2t_run = None, l2t
    if creds:
        case.meta["plaso_credenziali"] = sorted({c.split(":", 1)[0] for c in creds})
        print(tr("Plaso: uso {v1} chiave/i dei volumi cifrati sbloccati (non registrate).").format(v1=len(creds)), flush=True)
        if mode == "native":
            env = dict(os.environ, REPERTIA_PLASO_CRED=json.dumps(creds))
            l2t_run = [l2t[0], "-c", "import json,os,runpy,sys; c=json.loads(os.environ.pop('REPERTIA_PLASO_CRED'));"
                       "sys.argv=['log2timeline']+[a for x in c for a in ('--credential',x)]+sys.argv[1:];"
                       "runpy.run_module('plaso.scripts.log2timeline',run_name='__main__')"] \
                if len(l2t) >= 3 and l2t[1] == "-m" else l2t + [a for x in creds for a in ("--credential", x)]
        else:
            l2t_run = l2t + [a for x in creds for a in ("--credential", x)]
    steps = [pre + l2t_run + ["--unattended", "--partitions", "all", "--volumes", "all", *opts,
                          "--status_view", "linear", "--status_view_interval", "15",
                          "--storage_file", sto, src],
             pre + ps + ["--status_view", "none", "-o", "dynamic", "--output_time_zone", "UTC",
                         "-w", out, sto]]
    for cmd in steps:
        shown = mask_credentials(cmd)
        case.log("cmd", shown)
        print("$ " + " ".join(str(c) for c in shown))
        if subprocess.run(cmd, cwd=case.root, env=env).returncode != 0:   # i log di plaso nel caso
            print(tr("plaso ha restituito un errore: controlla l'output sopra."))
            return None
    con.execute("DELETE FROM events WHERE origin='plaso'")
    csv.field_size_limit(2**31 - 1)
    n, batch = 0, []
    with open(csv_out, newline="", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            d = r.get("datetime") or ""
            if not d[:4].isdigit() or d.startswith("0000"):
                continue
            batch.append((d[:19], r.get("timestamp_desc", ""),
                          r.get("source_long") or r.get("source", ""),
                          r.get("display_name", ""), (r.get("message") or "")[:2000],
                          "plaso", None))
            if len(batch) >= 50000:
                con.executemany(INSERT_EV, batch)
                n += len(batch)
                batch.clear()
    con.executemany(INSERT_EV, batch)
    con.commit()
    return n + len(batch)
