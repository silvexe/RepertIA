#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - carving (PhotoRec, bulk_extractor) e flussi senza sprechi di spazio.

(3.0.4) Codice spostato da forense_agent.py senza modifiche, per avere file più corti. Si carica tramite
forense_agent, che ne riesporta i nomi: gli altri moduli continuano a usare «fa.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fa.<nome>»).
"""
import bisect
import csv
import hashlib
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from forense_lingua import tr
import forense_apfs as ap

import forense_agent as fa
from forense_agent import (
    DOC_EXT, FEATURE_KINDS, IS_WIN, MAX_EXTRACT, META_EXT, MappaAllocati, dec, ensure_extra_tables,
    ensure_index_schema, exif_run, extract_text, install_hint, noelev_env, note_skipped, now, rmtree_force, sh,
    sha256_file, store_text, tool_version)

# ------------------------------------------------------------- carving

def photorec_spec(case, p):
    """Numero di partizione per PhotoRec (stringa vuota se non c'è tabella partizioni)."""
    if p.get("length_sectors") is None:
        return ""
    slot = p.get("slot")
    if slot and re.fullmatch(r"\d+:\d+", slot):
        tbl, idx = map(int, slot.split(":"))
        if tbl == 0:
            return str(idx + 1)
        logical = [q for q in case.meta["partitions"]
                   if q.get("slot") and not q["slot"].startswith("000:")]
        return str(5 + logical.index(p))
    return str([q for q in case.meta["partitions"] if not ap.is_apfs_part(q["offset"])].index(p) + 1)


def parse_photorec_report(xml_path):
    files, vol = [], None
    try:
        root = ET.parse(xml_path).getroot()
    except Exception:
        return files, vol
    strip = lambda t: t.split("}")[-1]
    for el in root.iter():
        tag = strip(el.tag)
        if tag == "volume" and vol is None:
            br = next((e for e in el.iter() if strip(e.tag) == "byte_run"), None)
            if br is not None:
                vol = int(br.get("img_offset", 0))
        if tag == "fileobject":
            name = size = off = None
            for c in el.iter():
                t = strip(c.tag)
                if t == "filename":
                    name = c.text
                elif t == "filesize":
                    size = int(c.text or 0)
                elif t == "byte_run" and off is None:
                    off = int(c.get("img_offset", 0))
            if name:
                # PhotoRec a volte scrive il percorso completo: si conserva solo il nome
                files.append((name.replace("\\", "/").rsplit("/", 1)[-1], size, off))
    return files, vol


def normalize_carved_names(case):
    """Casi preparati con versioni precedenti: alcuni file recuperati sono registrati col
    percorso completo invece del solo nome, e non si trovano. Si riportano al nome
    (tabelle carved, doc_text e meta). Restituisce il numero di nomi corretti."""
    if not case.db_path.exists():
        return 0
    con = sqlite3.connect(case.db_path, timeout=30)
    fixed = 0
    try:
        if not fa.table_exists(con, "carved"):
            return 0
        rows = con.execute("SELECT rowid, name FROM carved WHERE name LIKE '%/%' "
                           "OR name LIKE '%\\%'").fetchall()
        if not rows:
            return 0
        base = lambda n: n.replace("\\", "/").rsplit("/", 1)[-1]
        con.executemany("UPDATE carved SET name=? WHERE rowid=?", [(base(n), r) for r, n in rows])
        for t in ("doc_text", "meta"):
            if fa.table_exists(con, t):
                rr = con.execute(f"SELECT rowid, inode FROM {t} WHERE source='carving' AND "
                                 "(inode LIKE '%/%' OR inode LIKE '%\\%')").fetchall()
                con.executemany(f"UPDATE {t} SET inode=? WHERE rowid=?", [(base(n), r) for r, n in rr])
        con.commit()
        fixed = len(rows)
    finally:
        con.close()
    case.log("nomi_recuperati_corretti", fixed)
    return fixed


def photorec_has_ntfs():
    """True se PhotoRec sa leggere la mappa dello spazio usato di NTFS (libreria ntfs presente).
    Senza, in modalità 'spazio libero' analizzerebbe l'intera partizione, file compresi.
    Se la versione non si riesce a leggere si assume di sì (comportamento di sempre)."""
    try:
        cp = subprocess.run(["photorec", "/version"], capture_output=True, timeout=30,
                            stdin=subprocess.DEVNULL, env=noelev_env())
    except (OSError, subprocess.SubprocessError):
        return True
    m = re.search(r"ntfs lib:\s*([^,\s]+)", dec(cp.stdout + cp.stderr), re.I)
    return not (m and m.group(1).lower() == "none")


class UnallocMap:
    """Riporta un offset nel flusso dello spazio non allocato (blkls) all'offset reale nell'immagine.
    NTFS: dalla mappa dei cluster ($Bitmap, una sola lettura). Altri file system: blkcalc per
    ogni file recuperato (lento, con un massimo); oltre il massimo l'offset resta ignoto (None)."""
    MAX_BLKCALC = 3000

    def __init__(self, case, part_off, bs, stream_size):
        self.case, self.off, self.bs = case, part_off, bs
        self.base = part_off * 512
        self.blocks = stream_size // bs
        self.starts = self.runs = None
        self.cache, self.calls = {}, 0
        self._bitmap()

    def _bitmap(self):
        c, img = self.case, str(self.case.image)
        fs = sh(c, ["fsstat", "-o", str(self.off), img])
        if fs.returncode != 0 or "NTFS" not in dec(fs.stdout).split("METADATA")[0]:
            return
        bm = sh(c, ["icat", "-o", str(self.off), img, "6"])     # $Bitmap
        if bm.returncode != 0 or not bm.stdout:
            return
        data, runs, u, total = bm.stdout, [], 0, 0
        for span in re.finditer(rb"[^\xff]+", data):
            for i in range(span.start(), span.end()):
                b = data[i]
                for bit in range(8):
                    if not (b >> bit) & 1:
                        cl = i * 8 + bit
                        if runs and runs[-1][1] + runs[-1][2] == cl:
                            runs[-1][2] += 1
                        else:
                            runs.append([total, cl, 1])
                        total += 1
        # i cluster oltre la fine del volume non fanno parte del flusso: si tagliano in coda
        while runs and total > self.blocks:
            extra = min(total - self.blocks, runs[-1][2])
            runs[-1][2] -= extra
            total -= extra
            if runs[-1][2] == 0:
                runs.pop()
        if total != self.blocks:      # mappa non coerente con blkls: si usa blkcalc
            return
        self.runs = runs
        self.starts = [r[0] for r in runs]

    def real(self, stream_off):
        u, w = divmod(stream_off, self.bs)
        if self.runs is not None:
            k = bisect.bisect_right(self.starts, u) - 1
            if k < 0:
                return None
            r = self.runs[k]
            return self.base + (r[1] + (u - r[0])) * self.bs + w
        if u not in self.cache:
            if self.calls >= self.MAX_BLKCALC:
                return None
            self.calls += 1
            cp = sh(self.case, ["blkcalc", "-u", str(u), "-o", str(self.off), str(self.case.image)])
            m = re.search(rb"\d+", cp.stdout or b"")
            self.cache[u] = int(m.group()) if (cp.returncode == 0 and m) else None
        blk = self.cache[u]
        return None if blk is None else self.base + blk * self.bs + w


# ------------------------------------------------------------ flussi senza sprechi di spazio
# Un disco da 1 TB acquisito in un E01 da 40 GB NON deve diventare un file da 1 TB nel caso.
# RepertIA non crea più la copia raw completa: Sleuth Kit legge l'E01 direttamente e, quando uno
# strumento ha bisogno di un file raw (PhotoRec), gli si passa solo ciò che serve, in forma
# "compatta": i blocchi da 1 MiB interamente a zero non vengono scritti e una mappa riporta ogni
# offset del file compatto all'offset reale nell'immagine. Il file temporaneo si cancella a fine lavoro.

ZERO_CHUNK = 1 << 20


class SpaceError(Exception):
    """Spazio su disco esaurito durante la scrittura di un file temporaneo."""


class ZeroMap:
    """Mappa fra il file compatto (senza i blocchi a zero) e il flusso originale.
    segs: [[offset nel flusso, offset nel file compatto, lunghezza]] in ordine crescente."""

    def __init__(self, segs, total):
        self.segs, self.total = segs, total
        self.starts = [s[1] for s in segs]

    def stream(self, off):
        """Offset nel file compatto -> offset nel flusso originale (None se fuori mappa)."""
        if off is None or not self.segs:
            return off
        k = bisect.bisect_right(self.starts, off) - 1
        if k < 0:
            return None
        s, f, _ = self.segs[k]
        return s + (off - f)


def mark_sparse(path):
    """Windows: un file è 'sparso' solo se lo si dichiara (NTFS). Sul Mac (APFS) è automatico."""
    if IS_WIN:
        try:
            subprocess.run(["fsutil", "sparse", "setflag", str(path)], capture_output=True,
                           stdin=subprocess.DEVNULL, timeout=30)
        except (OSError, subprocess.SubprocessError):
            pass


def free_bytes(path):
    p = Path(path)
    while not p.exists() and p != p.parent:
        p = p.parent
    try:
        return shutil.disk_usage(p).free
    except OSError:
        return None


def gb(n):
    return f"{n / 1e9:.1f} GB"


def stream_to_file(case, cmd, target, mode="compact", label="", total=None):
    """Esegue `cmd` e scrive il suo output in `target` risparmiando spazio.
    mode 'compact': i blocchi da 1 MiB tutti a zero non vengono scritti (restituisce la mappa);
    mode 'sparse':  i blocchi a zero diventano "buchi" del file (stesse posizioni dell'originale).
    Ritorna dict(rc, stream, written, zmap). Se il disco si riempie solleva SpaceError
    (il file parziale viene eliminato)."""
    case.log("cmd", list(cmd) + [">", str(target), f"[{mode}]"])
    zero = bytes(ZERO_CHUNK)
    segs, pos, written, t0 = [], 0, 0, time.time()
    last = t0
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         stdin=subprocess.DEVNULL)
    try:
        with open(target, "wb") as fh:
            if mode == "sparse":
                fh.flush()
                mark_sparse(target)
            while True:
                chunk = p.stdout.read(ZERO_CHUNK)
                if not chunk:
                    break
                n = len(chunk)
                is_zero = (chunk == zero) if n == ZERO_CHUNK else not any(chunk)
                if is_zero:
                    if mode == "sparse":
                        fh.seek(n, 1)
                else:
                    fh.write(chunk)
                    if mode == "compact":
                        if segs and segs[-1][0] + segs[-1][2] == pos:
                            segs[-1][2] += n
                        else:
                            segs.append([pos, written, n])
                    written += n
                pos += n
                now_t = time.time()
                if now_t - last >= 20:
                    last = now_t
                    pct = f" ({pos * 100 // total}%)" if total else ""
                    print(tr("  {v1}: letti {v2}{pct}, scritti su disco {v3}").format(v1=label or 'lettura', v2=gb(pos), pct=pct, v3=gb(written)), flush=True)
            if mode == "sparse":
                fh.truncate(pos)
        rc = p.wait()
    except OSError as e:
        p.kill()
        p.wait()
        try:
            Path(target).unlink()
        except OSError:
            pass
        if getattr(e, "errno", None) in (28, 112):           # ENOSPC / ERROR_DISK_FULL
            raise SpaceError(str(e))
        raise
    except BaseException:
        p.kill()
        p.wait()
        raise
    finally:
        try:
            p.stdout.close()
        except OSError:
            pass
    saved = pos - written
    case.log("flusso_compatto" if mode == "compact" else "flusso_sparso",
             {"etichetta": label, "byte_letti": pos, "byte_scritti": written,
              "byte_risparmiati": saved, "secondi": round(time.time() - t0, 1)})
    print(tr("  {v1}: {v2} letti, {v3} scritti su disco ({v4} di zeri non scritti).").format(v1=label or 'flusso', v2=gb(pos), v3=gb(written), v4=gb(saved)), flush=True)
    return {"rc": rc, "stream": pos, "written": written,
            "zmap": ZeroMap(segs, pos) if mode == "compact" else None}



def extract_unallocated(case, part_off, target):
    """Scrive in 'target' i blocchi non allocati della partizione (Sleuth Kit, blkls), senza i
    blocchi tutti a zero (file compatto). Restituisce (dimensione blocco, byte del flusso,
    ZeroMap) oppure None."""
    img = str(case.image)
    fs = sh(case, ["fsstat", "-o", str(part_off), img])
    m = re.search(r"(?:Cluster|Block) Size:\s*(\d+)", dec(fs.stdout))
    if fs.returncode != 0 or not m:
        return None
    bs = int(m.group(1))
    r = stream_to_file(case, ["blkls", "-A", "-o", str(part_off), img], target, "compact",
                       tr("spazio non allocato (partizione {part_off})").format(part_off=part_off))
    if r["rc"] != 0 or r["stream"] == 0:
        return None
    return bs, r["stream"], r["zmap"]


TESTO_CARVING = {"txt", "html", "htm", "xml", "csv", "log", "json", "js", "css", "ini", "tex", "eml", "mbox", "sh", "py",
                 "c", "h", "php", "asp", "jsp", "pl", "rb", "bat", "reg", "vcf", "ics", "srt", "md", "url", "sql"}


def _unita_tsk(m):
    """Byte di un'unità di Sleuth Kit per MappaAllocati: NTFS cluster, ext blocco, FAT/exFAT settore."""
    if m.tipo == "ntfs":
        bs = m.img.read(m.base, 512)
        return struct.unpack_from("<H", bs, 11)[0] * bs[13]
    if m.tipo == "ext":
        return m.bsz
    if m.tipo == "fat":
        return m.bps
    if m.tipo == "exfat":
        return m.cx.bps
    return None


def carving_non_allineati(case, con, p, out, target, mode, zmap, umap, coperti, mapping, by_type, warnings):
    """(3.0.2) Dopo PhotoRec, nello stesso spazio, i file grafici che non cominciano all'inizio di un settore (vedi
    forense_carving_byte). Spazio letto: il file dato a PhotoRec (spazio non allocato estratto o immagine compatta:
    tutto); con PhotoRec sulla partizione dell'immagine raw, la partizione saltando i blocchi oggi allocati (mappa del
    file system; se il file system non è gestito la ricerca si salta e lo si dice). Restituisce i file aggiunti."""
    import forense_carving_byte as cb
    off = p["offset"]
    target = Path(target)
    dim = target.stat().st_size
    scarta = None
    if mode == "freespace" and target == Path(case.image):
        a = off * 512
        b = min(dim, a + int(p.get("length_sectors") or 0) * 512) if p.get("length_sectors") else dim
        try:
            mp = MappaAllocati(case, off, p.get("fs"))
            u = _unita_tsk(mp) if mp.tipo else None
        except Exception:
            mp, u = None, None
        if not u:
            warnings.append(tr("Partizione a offset {off}: carving dei file non allineati ai settori saltato (file system "
                               "senza mappa dello spazio allocato).").format(off=off))
            return 0

        def scarta(pos):
            return mp.allocato((pos - a) // u) is not False
    else:
        a, b = 0, dim

    def allineato(pos):
        s = zmap.stream(pos) if zmap is not None else pos
        return s is None or s % 512 == 0
    with open(target, "rb") as fh:
        trovati = cb.cerca(fh, a, b, coperti, allineato, scarta)
        if not trovati:
            return 0
        dest = out / "non_allineati"
        dest.mkdir(exist_ok=True)
        n = 0
        for pos, ext, ln in trovati:
            fh.seek(pos)
            dati = fh.read(ln)
            img_off = pos
            if zmap is not None:
                img_off = zmap.stream(img_off)
            if umap is not None and img_off is not None:
                img_off = umap.real(img_off)
            pezzi = [(f"b{pos}.{ext}", dati)]
            if ext == "jpg":
                t = cb.miniatura_exif(dati)
                if t:
                    pezzi.append((f"tb{pos}.jpg", t))
            for nome, d in pezzi:
                f = dest / nome
                f.write_bytes(d)
                f.chmod(0o444)
                rel = str(f.relative_to(case.root))
                typ = nome.rsplit(".", 1)[-1]
                con.execute("INSERT INTO carved VALUES (?,?,?,?,?,?,?)",
                            (nome, rel, off, len(d), typ, img_off, hashlib.sha256(d).hexdigest()))
                by_type[typ] = by_type.get(typ, 0) + 1
                n += 1
                if f.suffix.lower() in META_EXT:
                    mapping[str(f.resolve())] = ("carving", off, nome, 1, f"[recuperato] {rel}")
    case.log("carving_non_allineati", {"partizione": off, "file": n,
                                       "per_tipo": {e: sum(1 for x in trovati if x[1] == e) for e in {x[1] for x in trovati}}})
    print(tr("Carving dei file non allineati ai settori: {n} file in più.").format(n=n), flush=True)
    return n


def run_photorec(case, con, cdir):
    if not shutil.which("photorec"):
        print(tr("PhotoRec non installato ({v1}): salto il recupero dei file.").format(v1=install_hint('testdisk')))
        return None
    con.execute("DELETE FROM carved")
    con.execute("DELETE FROM doc_text WHERE source='carving'")
    ensure_extra_tables(con)
    con.execute("DELETE FROM doc_text_extra WHERE source='carving'")
    con.execute("DELETE FROM doc_skipped WHERE source='carving'")
    con.execute("DELETE FROM meta WHERE source='carving'")
    readable = [p for p in case.meta["partitions"] if p["readable"] and not ap.is_apfs_part(p["offset"])]
    jobs = [(p, photorec_spec(case, p), "freespace") for p in readable]
    if not jobs:   # nessun file system leggibile: si analizza tutta l'immagine
        jobs = [({"offset": 0}, "", "wholespace")]
    # Se questo PhotoRec non conosce NTFS, "freespace" analizzerebbe anche i file presenti:
    # in quel caso lo spazio non allocato lo estrae Sleuth Kit (blkls) e PhotoRec lavora su quello.
    # Con un E01 PhotoRec non può leggere l'immagine direttamente e non si crea più la copia raw
    # completa: anche qui lo spazio non allocato lo estrae Sleuth Kit (blkls) in un file compatto.
    e01 = fa.is_e01(case.image)
    use_unalloc = any(m == "freespace" for _, _, m in jobs) and (e01 or not photorec_has_ntfs())
    if use_unalloc and not shutil.which("blkls"):
        print(tr("Manca blkls (Sleuth Kit) e senza di esso PhotoRec analizzerebbe anche i file "
              "presenti (o non legge l'E01): salto il recupero dei file."))
        return None
    if e01 and any(m == "wholespace" for _, _, m in jobs) and not shutil.which("img_cat"):
        print(tr("Manca img_cat (Sleuth Kit): salto il recupero dei file."))
        return None
    total, by_type, warnings = 0, {}, []
    for p, num, mode in jobs:
        off = p["offset"]
        out = cdir / f"photorec_p{off}"
        rmtree_force(out)
        out.mkdir(parents=True)
        target, umap, ufile, zmap = case.image, None, None, None
        if use_unalloc and mode == "freespace":
            ufile = cdir / f"spazio_non_allocato_p{off}.raw"
            try:
                ex = extract_unallocated(case, off, ufile)
            except SpaceError:
                ex = None
                warnings.append(tr("Partizione a offset {off}: spazio su disco esaurito durante l'estrazione dello spazio non "
                                   "allocato.").format(off=off))
            if ex is None:
                print(tr("Partizione offset {off}: spazio non allocato non estraibile, la salto.").format(off=off))
                warnings.append(tr("Partizione a offset {off}: spazio non allocato non estraibile.").format(off=off))
                if ufile.exists():
                    ufile.unlink()
                continue
            umap = UnallocMap(case, off, ex[0], ex[1])
            zmap = ex[2]
            target, num, mode = ufile, "", "wholespace"
            case.log("spazio_non_allocato", {"partizione": off, "blocco": ex[0], "byte": ex[1],
                                             "scritti": sum(x[2] for x in zmap.segs),
                                             "mappa": tr("bitmap NTFS") if umap.runs is not None
                                             else "blkcalc"})
        elif e01 and mode == "wholespace":
            # nessun file system leggibile: tutta l'immagine, in forma compatta (senza zeri)
            ufile = cdir / "immagine_compatta.raw"
            try:
                r = stream_to_file(case, ["img_cat", str(case.image)], ufile, "compact",
                                   tr("immagine intera"))
            except SpaceError:
                r = None
                warnings.append(tr("Spazio su disco esaurito durante la lettura dell'immagine."))
            if r is None or r["rc"] != 0 or r["stream"] == 0:
                print(tr("Immagine non leggibile con img_cat, la salto."))
                if ufile.exists():
                    ufile.unlink()
                continue
            zmap = r["zmap"]
            target = ufile
        excl = photorec_exclusions()
        # (3.0.2) tipi predefiniti di PhotoRec, come nelle prove NIST CFTT: «everything» accende anche le firme che
        # l'autore lascia spente perché rumorose (gsm, …) e sulle immagini NIST di carving grafico spezza BMP e TIFF
        # (basic 39/47 invece di 47/47). REPERTIA_PHOTOREC_TIPI=tutti per riaccenderle tutte.
        tutti = os.environ.get("REPERTIA_PHOTOREC_TIPI", "").strip().lower() == "tutti"
        fopt = ("fileopt,everything,enable" if tutti else "fileopt") if (tutti or excl) else ""
        spec = ",".join(x for x in (num, fopt, *[f"{t},disable" for t in excl], mode, "search") if x)
        if excl and not any("esclusi" in w for w in warnings):
            warnings.append(tr("Tipi di file esclusi dal carving perché danno falsi positivi che coprono i file veri "
                               "(PhotoRec 7.2): {v1} (variabile REPERTIA_PHOTOREC_ESCLUDI).").format(v1=', '.join(excl)))
        cmd = ["photorec", "/log", "/d", str(out / "recup"), "/cmd", target, spec]
        case.log("cmd", cmd)
        what = (tr("spazio libero") if (mode == "freespace" or umap is not None)
                else tr("intera immagine"))
        print(tr("PhotoRec ({what}) - partizione offset {off}: può richiedere molto tempo...").format(what=what, off=off),
              flush=True)
        try:
            proc = subprocess.Popen(cmd, cwd=out, stdin=subprocess.DEVNULL, env=noelev_env(),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as e:
            print(tr("PhotoRec non si avvia ({e}): salto il recupero dei file.").format(e=e))
            if ufile is not None and ufile.exists():
                ufile.unlink()
            return None
        last = -1
        while proc.poll() is None:
            time.sleep(10)
            n = sum(1 for d in out.glob("recup.*") for f in d.iterdir() if f.name != "report.xml")
            fa.avanz(fatti=n)
            if n != last:
                print(tr("  PhotoRec: {n} file recuperati finora...").format(n=n), flush=True)
                last = n
        mapping, docs = {}, 0
        # PhotoRec mette al massimo 500 file per cartella (recup.1, recup.2, …) ma scrive un solo report.xml
        # in recup.1 con i nomi senza cartella: prima della 2.15 i file oltre il 500° non entravano nel caso.
        where = {f.name: f for d in out.glob("recup.*") if d.is_dir() for f in d.iterdir()}
        coperti = []          # (3.0.2) intervalli dei file di PhotoRec nel file letto, per il carving non allineato
        for rep in sorted(out.glob("recup.*/report.xml")):
            files, vol = parse_photorec_report(rep)
            if vol is not None and mode == "freespace" and vol != off * 512:
                warnings.append(tr("PhotoRec ha analizzato il volume a byte {vol} invece della partizione a offset {off}: "
                                   "verificare.").format(vol=vol, off=off))
            for name, size, img_off in files:
                f = rep.parent / name
                if not f.exists():
                    f = where.get(Path(name).name)
                if f is None or not f.exists():
                    continue
                f.chmod(0o444)
                rel = str(f.relative_to(case.root))
                ext = f.suffix.lower()
                typ = ext.lstrip(".") or "?"
                # i file di testo non contano: PhotoRec ne stima la fine e possono sbordare sull'inizio di
                # un'immagine (NIST «Byte Shifted»: un .txt di riempimento copriva i primi 2 byte di un TIFF)
                if img_off is not None and typ not in TESTO_CARVING:
                    coperti.append((img_off, img_off + (size or f.stat().st_size)))
                if zmap is not None:      # offset nel file compatto -> offset nel flusso
                    img_off = zmap.stream(img_off)
                if umap is not None:      # offset nel flusso non allocato -> offset nell'immagine
                    img_off = umap.real(img_off)
                con.execute("INSERT INTO carved VALUES (?,?,?,?,?,?,?)",
                            (name, rel, off, size or f.stat().st_size, typ, img_off,
                             sha256_file(f)))
                by_type[typ] = by_type.get(typ, 0) + 1
                total += 1
                if ext in DOC_EXT:
                    notes = []
                    r = extract_text(f.read_bytes()[:MAX_EXTRACT], name, cdir, notes)
                    if r and r[1].strip():
                        store_text(con, f"[recuperato] {rel}", r[1], "carving", off, name, 1, r[0])
                        docs += 1
                    for reason, detail in notes:
                        note_skipped(con, "carving", off, name, 1, f"[recuperato] {rel}",
                                     reason, detail)
                if ext in META_EXT:
                    mapping[str(f.resolve())] = ("carving", off, name, 1, f"[recuperato] {rel}")
        # miniature EXIF estratte da PhotoRec dalle foto recuperate (t<settore>.jpg, non elencate in report.xml):
        # possono mostrare l'immagine originale anche se la foto è stata modificata; stesso offset della foto
        done = {r[0] for r in con.execute("SELECT name FROM carved WHERE part=?", (off,))}
        offs = {r[0]: r[1] for r in con.execute("SELECT name, img_offset FROM carved WHERE part=?", (off,))}
        for nm, f in sorted(where.items()):
            if nm in done or nm == "report.xml" or not nm.startswith("t"):
                continue
            parent = next((k for k in offs if k.startswith("f" + nm[1:].split(".")[0])), None)
            if parent is not None:
                t_off = offs[parent]
            else:
                # (3.0.2) foto non recuperata (frammentata, PhotoRec la scarta) ma miniatura intera: si tiene, con
                # l'offset dal nome (t<settore>.jpg, come f<settore>; immagini NIST CFTT di carving grafico)
                sett = re.match(r"t(\d+)", nm)
                if not sett:
                    continue
                s = int(sett.group(1))
                # il numero è in settori dall'inizio di ciò che PhotoRec ha letto: si usa lo scarto della foto
                # recuperata più vicina prima della miniatura (stessa zona), altrimenti la conversione diretta
                vic = max(((int(m.group(1)), o) for k, o in offs.items() if o is not None
                           for m in [re.match(r"f(\d+)", k)] if m and int(m.group(1)) <= s), default=None)
                if vic is not None:
                    t_off = vic[1] + (s - vic[0]) * 512
                else:
                    t_off = s * 512
                    if zmap is not None:
                        t_off = zmap.stream(t_off)
                    if umap is not None:
                        t_off = umap.real(t_off)
            f.chmod(0o444)
            rel = str(f.relative_to(case.root))
            typ = f.suffix.lower().lstrip(".") or "?"
            con.execute("INSERT INTO carved VALUES (?,?,?,?,?,?,?)",
                        (nm, rel, off, f.stat().st_size, typ, t_off, sha256_file(f)))
            by_type[typ] = by_type.get(typ, 0) + 1
            total += 1
            mapping[str(f.resolve())] = ("carving", off, nm, 1, f"[recuperato] {rel}")
        if os.environ.get("REPERTIA_CARVING_BYTE", "1").strip() != "0":
            try:
                k = carving_non_allineati(case, con, p, out, target, mode, zmap, umap, coperti, mapping, by_type, warnings)
            except Exception as e:  # noqa: BLE001 - il carving di PhotoRec resta valido comunque
                k = 0
                warnings.append(tr("Carving dei file non allineati ai settori non riuscito: {e}").format(e=e))
            total += k
        exif_run(con, out, mapping)
        con.commit()
        if ufile is not None and ufile.exists():
            ufile.unlink()      # copia temporanea dello spazio non allocato
    for w in warnings:
        print(tr("Attenzione: ") + w)
    with open(cdir / "file_recuperati.csv", "w", newline="", encoding="utf-8") as fh:
        wr = csv.writer(fh)
        wr.writerow([tr(h) for h in ["file", "percorso", "partizione_offset", "dimensione", "tipo",
                     "offset_byte_immagine", "sha256"]])
        wr.writerows(con.execute("SELECT name, relpath, part, size, type, img_offset, sha256 "
                                 "FROM carved ORDER BY img_offset"))
    print(tr("PhotoRec: {total} file recuperati.").format(total=total))
    case.meta.setdefault("tool_versions", {})["photorec"] = tool_version(["photorec", "/version"])
    return {"files": total, "by_type": dict(sorted(by_type.items(), key=lambda x: -x[1])),
            "warnings": warnings}


def photorec_exclusions():
    """Tipi da disattivare in PhotoRec: dalla 7.2 la firma «dovecot» dà falsi positivi a catena (centinaia di
    file da 80 KB) che coprono documenti e video veri (provato su DFTT 11: 8 file identici su 15 invece di 13).
    PhotoRec 7.1 non conosce il tipo e rifiuta il comando: si disattiva solo dalla 7.2."""
    v = tool_version(["photorec", "/version"]) or ""
    m = re.search(r"PhotoRec (\d+)\.(\d+)", v)
    if not m or (int(m.group(1)), int(m.group(2))) < (7, 2):
        return []
    val = os.environ.get("REPERTIA_PHOTOREC_ESCLUDI", "dovecot").strip().lower()
    if val in ("", "nessuno", "none", "0"):
        return []
    return [t for t in re.split(r"[,\s]+", val) if re.fullmatch(r"[a-z0-9_]+", t)]


def docker_mount(src, dst, ro=False):
    """Montaggio di una cartella in Docker, valido anche con i percorsi di Windows."""
    return ["--mount", f"type=bind,source={src},target={dst}" + (",readonly" if ro else "")]


def bulk_available():
    return bool(shutil.which("bulk_extractor"))


def media_size(case):
    """Dimensione (byte) del supporto originale secondo Sleuth Kit; None se non la dice."""
    try:
        cp = sh(case, ["img_stat", str(case.image)], timeout=300)
    except (OSError, subprocess.SubprocessError):
        return None
    t = dec(cp.stdout)
    m = re.search(r"Size of data in bytes:\s*(\d+)", t) or re.search(r"Size in bytes:\s*(\d+)", t)
    return int(m.group(1)) if m else None


def _bulk_run(case, img, out, extra=()):
    cmd = ["bulk_extractor", *extra, "-o", str(out), str(img)]
    case.log("cmd", cmd)
    return subprocess.run(cmd, stdin=subprocess.DEVNULL).returncode == 0


def _bulk_image_size(out):
    """Dimensione dell'immagine come l'ha vista bulk_extractor (report.xml), None se non c'è."""
    try:
        t = (Path(out) / "report.xml").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = re.search(r"<image_size>\s*(\d+)\s*</image_size>", t)
    return int(m.group(1)) if m else None


def run_bulk(case, con, cdir):
    if not shutil.which("bulk_extractor"):
        print(tr("bulk_extractor non disponibile (")
              + (tr("componente non trovato: reinstalla RepertIA") if IS_WIN else install_hint("bulk_extractor"))
              + tr("): salto le tracce."))
        return None
    out = cdir / "bulk_extractor"
    rmtree_force(out)
    img = str(case.image)
    zmap, tmp = None, None
    print(tr("bulk_extractor: ricerca di email, siti, telefoni, coordinate GPS e altre tracce "
          "in tutta l'immagine (anche spazio libero)..."), flush=True)
    try:
        ok = False
        if fa.is_e01(img):
            # Un E01 si legge direttamente (libewf), senza copie raw: lo si verifica con una
            # prova su 1 MiB (la dimensione vista da bulk_extractor deve essere quella del disco).
            media, direct = media_size(case), None
            probe = cdir / "bulk_prova"
            rmtree_force(probe)
            if media and _bulk_run(case, img, probe, ("-Y", "0-1048576")):
                seen = _bulk_image_size(probe)
                direct = None if seen is None else (seen == media)
            rmtree_force(probe)
            if direct is not False:
                ok = _bulk_run(case, img, out)
                if ok and direct is None and media and _bulk_image_size(out) not in (None, media):
                    ok, direct = False, False          # non legge l'E01: ha scandito il contenitore
            if direct is False or (not ok and direct is None):
                rmtree_force(out)
                print(tr("Questa versione di bulk_extractor non legge direttamente l'E01: uso un file "
                      "temporaneo compatto (senza i blocchi a zero), che sarà cancellato."),
                      flush=True)
                tmp = cdir / "immagine_compatta.raw"
                r = stream_to_file(case, ["img_cat", img], tmp, "compact", tr("immagine intera"),
                                   total=media)
                if r["rc"] != 0 or r["stream"] == 0:
                    print(tr("Immagine non leggibile con img_cat: salto le tracce."))
                    return None
                zmap = r["zmap"]
                ok = _bulk_run(case, tmp, out)
        else:
            ok = _bulk_run(case, img, out)
    except SpaceError:
        print(tr("Spazio su disco esaurito durante la preparazione per bulk_extractor: salto le tracce. "
              "Libera spazio o sposta la cartella dei casi (variabile FORENSE_CASI) su un disco più capiente."))
        return None
    finally:
        if tmp is not None and Path(tmp).exists():
            Path(tmp).unlink()
    if not ok:
        print(tr("bulk_extractor ha restituito un errore."))
        return None
    fix = (lambda t: re.sub(r"^\d+", lambda m: str(zmap.stream(int(m.group())) or 0), t, count=1)
           ) if zmap is not None else (lambda t: t)
    con.execute("DELETE FROM features")
    counts = {}
    for kind in FEATURE_KINDS:
        f = out / f"{kind}.txt"
        if not f.exists():
            continue
        batch = []
        with open(f, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 2:
                    continue
                parts[0] = fix(parts[0])
                m = re.match(r"\d+", parts[0])
                batch.append((kind, parts[0], int(m.group()) if m else None, parts[1],
                              (parts[2] if len(parts) > 2 else "")[:500]))
        con.executemany("INSERT INTO features VALUES (?,?,?,?,?)", batch)
        if batch:
            counts[kind] = len(batch)
    con.commit()
    case.meta.setdefault("tool_versions", {})["bulk_extractor"] = tool_version(["bulk_extractor", "-V"]) or "?"
    print(tr("bulk_extractor: ") + (", ".join(f"{k} {v}" for k, v in counts.items()) or tr("nessuna traccia")))
    return {"kinds": counts}


def run_carving(case, con):
    """Recupero dallo spazio non allocato: PhotoRec (file) e bulk_extractor (tracce)."""
    ensure_index_schema(con)
    if not (shutil.which("photorec") or bulk_available()):
        print(tr("Né PhotoRec né bulk_extractor sono disponibili: ")
              + install_hint("testdisk bulk_extractor"))
        return None
    cdir = case.root / "carving"
    cdir.mkdir(exist_ok=True)
    res = {"photorec": run_photorec(case, con, cdir), "bulk_extractor": run_bulk(case, con, cdir),
           "dir": str(cdir), "ts": now()}
    return res if (res["photorec"] or res["bulk_extractor"]) else None
