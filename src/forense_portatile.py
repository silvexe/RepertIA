#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""
forense_portatile.py - RepertIA by silvexe.
Report portatile: il caso esportato in una cartella con index.html che si apre in qualsiasi
browser, offline, senza RepertIA e senza la copia forense. Contiene il catalogo completo
(file anche cancellati, date, hash, metadati, testi indicizzati, timeline, tracce, reperti)
e il contenuto dei file scelti: solo reperti e selezioni, anche documenti e immagini fino a
una dimensione, oppure tutti i file del supporto. Niente modello AI.

I dati sono file JavaScript (dati/*.js) caricati con <script>, perché i browser non
permettono di leggere file locali in altro modo da una pagina aperta con doppio clic.
Il contenuto delle prove non viene mai interpretato come HTML: è mostrato come testo,
immagini o pagine PDF già convertite in immagini.
"""
import base64, csv, errno, sys, hashlib, html, json, os, re, shutil, subprocess, threading, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import forense_agent as fa
import forense_gui as g
import forense_lingua as lg  # noqa: E402
from forense_lingua import tr, N_  # noqa: E402

HERE = Path(__file__).resolve().parent
CHUNK_ROWS = 40_000            # righe del catalogo per file dati
ATT_CHUNK = 20_000             # file inclusi per file dati
TEXT_CHUNK = 4 << 20           # caratteri di testo per file dati
TEXT_PER_DOC = 60_000          # caratteri di testo conservati per documento
TEXT_TOTAL = 400 << 20         # limite complessivo dei testi
LEAPP_PARTE = 20_000         # (2.20) righe di iLEAPP/ALEAPP per file nel report portatile
EV_PARTE = 50_000            # (2.20) eventi per file della timeline nei giorni molto pieni
MSG_MAX = 400                  # caratteri del messaggio di ogni evento
FEATURES_MAX = 200_000         # tracce di bulk_extractor
# anteprime: complete per reperti e selezioni, leggere per i file inclusi in blocco
FULL = {"hex": 64 << 10, "text": 2 << 20, "pages": 40, "office": True, "tools": True}
BULK = {"hex": 4 << 10, "text": 200 << 10, "pages": 3, "office": False, "tools": False}
WORKERS = max(2, min(6, (os.cpu_count() or 4)))
STR_READ = 50 << 20            # byte letti per estrarre le stringhe di un file
STR_PER_FILE = 100_000         # caratteri di stringhe conservati per file
STR_TOTAL = 1500 << 20         # limite complessivo delle stringhe nel report
NO_STRINGS = {"image", "image_conv", "video", "audio"}   # solo rumore: si cercano nei metadati
ASCII_RE = re.compile(rb"[\x20-\x7e\t]{5,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
REF_RE = re.compile(r"offset\s+(\d+)\s*,\s*inode\s+(\d+(?:-\d+-\d+)?)", re.I)
CARVED_RE = re.compile(r"file recuperato\s+([^\s,;()]+)", re.I)
DOC_EXT = g.IMG_NATIVE | g.IMG_CONVERT | {".pdf"} | g.WORD_EXT | g.OFFICE_EXT | g.TEXT_LIKE
# (2.20) spazio su disco: ogni file occupa almeno un cluster (128 KB su un disco exFAT da 1 TB), quindi con centinaia
# di migliaia di file piccoli il report occupa molto più della somma delle dimensioni dei file
DET_GRP = 100                  # dettagli dei file inclusi in blocco: un file dati ogni 100 (prima uno per file)
RISERVA = 2 << 30              # spazio da lasciare libero sul disco del caso
DETAIL_B = 7 << 10             # dettaglio di un file nel file dati (intestazione, dati), testo escluso
PREV_IMG = 600 << 10           # anteprima JPEG di un'immagine da convertire (HEIC, TIFF, RAW…)
PREV_PAGE = 300 << 10          # pagina JPEG di un PDF o di un documento Office
CAT_ROW = 300                  # byte del catalogo e delle impronte per voce del file system
FILE_DATI = 2000               # file dati del report oltre ai dettagli (catalogo, giorni della timeline, iLEAPP…), al massimo


def js(name, obj):
    """Riga JavaScript che consegna i dati al visore (ensure_ascii: nessun carattere che
    possa rompere lo script)."""
    return f"FD.push({json.dumps(name)},{json.dumps(obj, ensure_ascii=True, separators=(',', ':'))});\n"


def write_js(path, name, obj):
    Path(g.lp(path.parent)).mkdir(parents=True, exist_ok=True)
    with open(g.lp(path), "w", encoding="ascii") as f:
        f.write(js(name, obj))


def sha_md5(path):
    h, m = hashlib.sha256(), hashlib.md5()
    with open(g.lp(path), "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
            m.update(chunk)
    return h.hexdigest(), m.hexdigest()


def kind_of(name, head):
    ext = Path(name).suffix.lower()
    if ext in g.IMG_NATIVE or g.sniff_mime(head):
        return "image"
    if ext in g.IMG_CONVERT:
        return "image_conv"
    if ext == ".pdf" or head[:4] == b"%PDF":
        return "pdf"
    if ext in g.WORD_EXT | g.OFFICE_EXT:
        return "office"
    if ext in g.VIDEO_MIME:
        return "video"
    if ext in g.AUDIO_MIME:
        return "audio"
    if ext in g.TEXT_LIKE or g.printable_ratio(head[:8192]) > 0.92:
        return "text"
    return "other"


def wait_nav(case, progress, timeout=1800):
    st = g.ensure_nav(case)
    t0 = time.time()
    while st["state"] == "building":
        progress(st.get("msg") or tr("Preparo l'albero del file system…"))
        time.sleep(1)
        st = g.ensure_nav(case)
        if time.time() - t0 > timeout:
            raise ValueError(tr("L'albero del file system non è pronto: riprova tra poco."))
    if st["state"] != "ready":
        raise ValueError(st.get("msg") or tr("Albero del file system non disponibile."))


def bulk_query(mode, mb, deleted):
    """Condizione SQL (sulla tabella nav) dei file inclusi in blocco."""
    q = ("SELECT part, inode, path, size, deleted FROM nav WHERE isdir=0 AND inode IS NOT NULL "
         "AND IFNULL(size, 0) > 0 AND type NOT LIKE 'v/%'")
    args = []
    if mode == "piccoli":
        q += " AND size <= ?"
        args.append(int(mb * (1 << 20)))
    if not deleted:
        q += " AND deleted = 0"
    return q, args


def cluster_size(path):
    """Unità di allocazione del disco (byte): il minimo che occupa un file non vuoto."""
    try:
        if os.name == "nt":
            import ctypes
            spc, bps, fc, tc = (ctypes.c_ulong() for _ in range(4))
            root = os.path.splitdrive(os.path.abspath(path))[0] + "\\"
            if ctypes.windll.kernel32.GetDiskFreeSpaceW(root, ctypes.byref(spc), ctypes.byref(bps),
                                                        ctypes.byref(fc), ctypes.byref(tc)):
                return spc.value * bps.value or 4096
            return 4096
        st = os.statvfs(path)
        return st.f_frsize or st.f_bsize or 4096
    except (OSError, AttributeError, ValueError):
        return 4096


class Spazio:
    """(2.20) Spazio che il report occupa sul disco: contenuto dei file arrotondato ai cluster, cartelle,
    anteprime, file dati, testi e stringhe, catalogo e impronte."""

    def __init__(self, cl, testi=TEXT_TOTAL, ad=False):
        self.cl, self.n, self.bytes, self.disk, self.conv, self.pages, self.text = cl, 0, 0, 0, 0, 0, 0
        self.ad = ad                               # «._nome» di macOS: tolti man mano, restano quelli delle cartelle
        self.dirs = set()                          # cartelle che il report crea in file/ (con le madri)
        self.testi = min(TEXT_TOTAL, testi)        # testi già indicizzati dei documenti (dati/testi)

    def r(self, x):
        return -(-int(x) // self.cl) * self.cl

    def add(self, path, size, part=None):
        size = int(size or 0)
        self.n += 1
        d = f"{part}/{path or ''}".rsplit("/", 1)[0]
        while d and d not in self.dirs:
            self.dirs.add(d)
            d = d.rpartition("/")[0]
        self.bytes += size
        self.disk += self.r(size)
        ext = Path(path or "").suffix.lower()
        if ext in g.IMG_CONVERT:
            self.conv += 1
        elif ext == ".pdf" or ext in g.WORD_EXT or ext in g.OFFICE_EXT:
            self.pages += 1
        elif ext in g.TEXT_LIKE:
            self.text += min(size, BULK["text"])

    def need(self, voci):
        """Byte stimati con voci = righe del catalogo (albero del file system)."""
        cartelle = len(self.dirs) + self.n // 1000 + 10
        extra = (self.n * DETAIL_B + int(self.text * 1.3)) + self.r(1) * (self.n // DET_GRP + 1)
        extra += self.conv * self.r(PREV_IMG) + self.pages * BULK["pages"] * self.r(PREV_PAGE)
        extra += (self.conv + self.pages) * self.cl             # una cartella in anteprime/ per file
        extra += min(STR_TOTAL, self.bytes // 4) + int(self.testi * 1.3) + voci * CAT_ROW
        extra += (cartelle + min(FILE_DATI, 50 + voci // 500)) * self.cl * (2 if self.ad else 1)
        return int((self.disk + extra) * 1.05)

    def out(self, voci):
        return {"files": self.n, "bytes": self.bytes, "need": self.need(voci)}


def testi_case(case):
    """Caratteri dei testi già indicizzati (doc_text) del caso, per la stima."""
    con = fa.db_ro(case)
    try:
        if not fa.table_exists(con, "doc_text"):
            return 0
        return con.execute("SELECT IFNULL(SUM(LENGTH(body)), 0) FROM doc_text").fetchone()[0]
    finally:
        con.close()


def estimate(case):
    """Quanti file e quanti byte per ciascuna scelta di contenuto (per la finestra), con lo spazio
    che il report occuperà davvero sul disco del caso."""
    st = g.ensure_nav(case)
    if st["state"] != "ready":
        return {"ready": False, "msg": st.get("msg") or tr("Albero in preparazione…")}
    try:
        case.export_dir.mkdir(exist_ok=True)
        du = shutil.disk_usage(case.export_dir)
        free, total = du.free, du.total
    except OSError:
        free = total = None
    cl = cluster_size(case.export_dir) if free is not None else 4096
    ad = free is not None and appledouble(case.export_dir)
    con = g.nav_db(case)
    out = {"ready": True}
    try:
        voci = con.execute("SELECT COUNT(*) FROM nav").fetchone()[0]
        tx = testi_case(case)
        tutti, alloc, picc = Spazio(cl, tx, ad), Spazio(cl, tx, ad), Spazio(cl, tx, ad)
        q, a = bulk_query("tutti", 0, True)
        for part, inode, path, size, d in con.execute(q, a):
            tutti.add(path, size, part)
            if not d:
                alloc.add(path, size, part)
            if (size or 0) <= 5 << 20 and Path(path).suffix.lower() in DOC_EXT:
                picc.add(path, size, part)
        out["tutti"] = tutti.out(voci)
        out["tutti_allocati"] = alloc.out(voci)
        out["piccoli_5"] = picc.out(voci)
    finally:
        con.close()
    out.update({"free": free, "total": total, "cluster": cl, "riserva": RISERVA, "appledouble": ad})
    out["image_ok"] = Path(case.image).exists()
    return out


def appledouble(path):
    """(2.20) True se macOS su questo disco (exFAT, FAT, rete) salva gli attributi estesi in un file «._nome»
    accanto a ogni file e cartella: contiene solo com.apple.provenance ma occupa un cluster intero (128 KB)."""
    if sys.platform != "darwin":
        return False
    probe = os.path.join(path, f".repertia_prova_{os.getpid()}")
    try:
        with open(probe, "w") as f:
            f.write("x")
        return os.path.exists(os.path.join(path, "._" + os.path.basename(probe)))
    except OSError:
        return False
    finally:
        for q in (probe, os.path.join(path, "._" + os.path.basename(probe))):
            try:
                os.unlink(q)
            except OSError:
                pass


def togli_ad(p):
    """Toglie il «._nome» di macOS accanto a un file del report (solo sui dischi con appledouble)."""
    p = str(p)
    try:
        os.unlink(os.path.join(os.path.dirname(p), "._" + os.path.basename(p)))
    except OSError:
        pass


def togli_ad_tutti(root):
    """Toglie tutti i «._nome» di macOS nel report: lì nessun file del supporto inizia con «._» (dest_rel)."""
    for base, dirs, files in os.walk(root):
        for fn in files:
            if fn.startswith("._"):
                try:
                    os.unlink(os.path.join(base, fn))
                except OSError:
                    pass


def disco_pieno(e):
    """True se l'errore è «disco pieno» (anche ERROR_DISK_FULL di Windows)."""
    return isinstance(e, OSError) and (e.errno in (errno.ENOSPC, getattr(errno, "EDQUOT", -1))
                                       or getattr(e, "winerror", None) in (39, 112))


def gb(b):
    return (f"{b / 1e9:.1f} GB" if b >= 1e9 else f"{b / 1e6:.0f} MB").replace(".", ",")


# ------------------------------------------------------------ file da includere

def wanted_files(case, opts, progress):
    """{chiave: info} dei file il cui contenuto va nel report."""
    want = {}

    def add(key, why, full, **info):
        cur = want.setdefault(key, {"why": set(), "full": False})
        cur["why"].add(why)
        cur["full"] = cur["full"] or full
        for k, v in info.items():
            cur.setdefault(k, v)

    for f in case.findings():
        text = f"{f.get('references', '')} {f.get('description', '')}"
        for part, inode in REF_RE.findall(text):
            add(("fs", int(part), inode), f"reperto {f['n']}", True)
        for name in CARVED_RE.findall(text):
            add(("c", None, Path(name).name), f"reperto {f['n']}", True)
    for cat in fa.bookmarks(case):            # segnalibri delle categorie «nel report»
        for itm in cat["items"]:
            if itm["source"] == "carving":
                add(("c", None, Path(str(itm["inode"])).name), tr("preferiti: {name}").format(name=cat['name']), True)
            elif itm["source"] == "fs" and itm["part"] is not None:
                add(("fs", int(itm["part"]), str(itm["inode"])), tr("preferiti: {name}").format(name=cat['name']), True)
    if case.export_dir.exists():
        for mf in sorted(case.export_dir.glob("selezione_*/manifest.csv")):
            with open(mf, encoding="utf-8-sig", newline="") as fh:
                for r in csv.DictReader(fh, delimiter=";"):
                    src = mf.parent / (r.get("file_esportato") or "")
                    po = r.get("percorso_originale") or ""
                    if po.startswith("[carving]"):
                        add(("c", None, Path(po.split("]", 1)[1].strip()).name), tr("selezione esportata"),
                            True, exported=src)
                    elif r.get("inode"):
                        add(("fs", int(r["partizione_offset"]), r["inode"]), tr("selezione esportata"),
                            True, exported=src)
    mode = opts.get("contenuto") or "scelti"
    if mode in ("piccoli", "tutti"):
        mb = float(opts.get("auto_mb") or 5)
        why = tr("tutti i file") if mode == "tutti" else tr("documenti e immagini fino a {mb:g} MB").format(mb=mb)
        q, a = bulk_query(mode, mb, opts.get("cancellati", True))
        con = g.nav_db(case)
        try:
            for part, inode, path, size, d in con.execute(q, a):
                if mode == "tutti" or Path(path).suffix.lower() in DOC_EXT:
                    add(("fs", part, inode), why, False, size=size or 0, path=path)
        finally:
            con.close()
        if mode == "tutti" and fa.table_exists(fa.db_ro(case), "carved"):
            c2 = fa.db_ro(case)
            try:
                for (name,) in c2.execute("SELECT name FROM carved"):
                    add(("c", None, Path(name.replace("\\", "/")).name), tr("tutti i file (recuperati)"), False)
            finally:
                c2.close()
    progress(tr("File da includere: {v1:,}").format(v1=len(want)).replace(",", "."), 3)
    return want


def dest_rel(it, used, lock, ad=False):
    """Percorso nel report che conserva l'albero originale (file/partizione_N/...). Con ad (macOS su exFAT/FAT)
    un nome che inizia con «._» diventa «_._…»: lì macOS scriverebbe gli attributi del file accanto sopra il
    file del supporto (il percorso originale resta nel catalogo)."""
    def sp(x):
        x = g.safe_part(x)
        return "_" + x if ad and x.startswith("._") else x
    if it["source"] == "carving":
        rel = Path("file", "recuperati_carving", sp(it["name"]))
    else:
        segs = [sp(s) for s in (it["path"] or f"inode_{it['inode']}").split("/") if s]
        rel = Path("file", f"partizione_{it['part']}", *segs) if segs else \
            Path("file", f"partizione_{it['part']}", f"inode_{it['inode']}")
    with lock:
        k = str(rel).lower()
        if k in used:
            tag = (it["inode"] or "c").replace("-", "_")
            rel = rel.with_name(f"{rel.stem}__inode_{tag}{rel.suffix}")
            k = str(rel).lower()
        used.add(k)
    return rel


def extract(case, it, info, dest):
    """Copia il contenuto del file nel report. False se non è leggibile."""
    Path(g.lp(dest.parent)).mkdir(parents=True, exist_ok=True)
    if it["source"] == "carving":
        shutil.copyfile(g.lp(it["file"]), g.lp(dest))
        return True
    exp = info.get("exported")
    if exp and Path(g.lp(exp)).exists():
        shutil.copyfile(g.lp(exp), g.lp(dest))
        return True
    cached = fa.cached_copy(case, it["part"], it["inode"])
    if cached:
        shutil.copyfile(g.lp(cached), g.lp(dest))
        return True
    n = 0
    with open(g.lp(dest), "wb") as f:
        for chunk in fa.icat_stream(case, it["part"], it["inode"]):
            f.write(chunk)
            n += len(chunk)
    return True


def office_fallback(dest, pdir):
    """Documento Office senza LibreOffice: HTML (Word/ODT/RTF con textutil di macOS) oppure
    immagine della prima pagina (Quick Look di macOS). Restituisce (html, anteprima)."""
    if Path(dest).suffix.lower() in g.WORD_EXT:
        h = g.word_html(Path(g.lp(dest)))
        if h:
            return h[:3 << 20], False
    if g.IS_MAC and shutil.which("qlmanage"):
        Path(g.lp(pdir)).mkdir(parents=True, exist_ok=True)
        tmp = Path(g.lp(pdir)) / "ql"
        tmp.mkdir(exist_ok=True)
        if g.run_quiet(["qlmanage", "-t", "-s", "1400", "-o", str(tmp), g.lp(dest)], 40):
            png = next(tmp.glob("*.png"), None)
            if png and g.to_jpeg(png, Path(g.lp(pdir / "anteprima.jpg")), 1400):
                shutil.rmtree(tmp, ignore_errors=True)
                return None, True
        shutil.rmtree(tmp, ignore_errors=True)
    return None, False


def make_previews(case, it, dest, pdir, kind, lvl):
    """Pagine PDF/Office come JPEG e immagini convertite, in anteprime/<id>/."""
    pages, preview = 0, False
    if kind == "image_conv":
        Path(g.lp(pdir)).mkdir(parents=True, exist_ok=True)
        if g.to_jpeg(Path(g.lp(dest)), Path(g.lp(pdir / "anteprima.jpg")), 2000):
            preview = True
    pdf = None
    if kind == "pdf":
        pdf = dest
    elif kind == "office" and g.tool("soffice"):
        try:
            pdf = g.office_pdf(case, it, Path(g.lp(dest)))
        except Exception:
            pdf = None
    if pdf and g.tool("pdftoppm"):
        Path(g.lp(pdir)).mkdir(parents=True, exist_ok=True)
        g.run_quiet([g.tool("pdftoppm"), "-f", "1", "-l", str(lvl["pages"]), "-r", "100", "-jpeg",
                     "-jpegopt", "quality=82", g.lp(pdf), g.lp(pdir / "p")], 600)
        found = []
        for img in Path(g.lp(pdir)).glob("p-*.jpg"):
            m = re.search(r"-(\d+)\.jpg$", img.name)
            if m:
                n = int(m.group(1))
                img.replace(img.with_name(f"pagina_{n:03d}.jpg"))
                found.append(n)
        pages = max(found) if found else 0
    html_doc = None
    if kind == "office" and not pages:
        html_doc, preview = office_fallback(dest, pdir)
    return pages, preview, html_doc


def strings_of(path, limit=STR_PER_FILE):
    """Testo leggibile di un file binario (ASCII e UTF-16LE), per la ricerca nel report."""
    with open(g.lp(path), "rb") as f:
        data = f.read(STR_READ)
    parts, n = [], 0
    for rx, enc in ((ASCII_RE, "latin-1"), (UTF16_RE, "utf-16-le")):
        for m in rx.finditer(data):
            t = m.group().decode(enc, "replace").strip()
            if t:
                parts.append(t)
                n += len(t) + 1
                if n >= limit:
                    return "\n".join(parts)[:limit]
    return "\n".join(parts)


def _unalloc(case):
    """Tratti di spazio non allocato già calcolati nel caso (cartella $Unalloc): solo posizione e dimensione, il
    contenuto resta nella copia forense. Non si calcolano qui (su un disco grande servono minuti)."""
    out = {}
    for p in case.meta.get("partitions", []):
        if not p.get("readable"):
            continue
        try:
            d = json.loads(g.ua_cache_file(case, p["offset"]).read_text())
        except (OSError, ValueError):
            continue
        if d.get("image") != str(case.image):
            continue
        out[str(p["offset"])] = {"byte": d["byte"], "tratti": len(d["runs"]), "blocco": d["block_size"],
                                 "runs": d["runs"][:5000]}
    return out


def _layout(case):
    """Suddivisione del disco (righe di mmls) per l'albero del report portatile; None senza tabella delle partizioni."""
    try:
        return fa.layout_volumi(case)
    except Exception:
        return None


def istat_text(case, it):
    if it["source"] != "fs" or not Path(case.image).exists():
        return ""
    if fa.ap.is_apfs_part(it["part"]):
        try:
            return g.apfs_istat_tokens(fa.ap.istat_text(case, it["part"], it["inode"])[:20000])
        except Exception:
            return ""
    if fa.is_mobile(case):                   # estrazione di un telefono (2.20): date UTC come APFS
        import forense_mobile as fm
        try:
            return g.apfs_istat_tokens(fm.istat_text(case, it["part"], it["inode"])[:20000])
        except Exception:
            return ""
    try:
        cmd = ["istat", *fa.tsk_tz(case), "-o", str(it["part"]), case.image, it["inode"]]
        cp = subprocess.run(cmd, capture_output=True, timeout=120, env=fa.tsk_env(case, cmd))
        return g.istat_tokens(case, fa.istat_zona(case, it["part"], fa.dec(cp.stdout))[:20000])
    except (OSError, subprocess.TimeoutExpired):
        return ""


def exif_json(dest):
    if not g.tool("exiftool"):
        return None
    try:
        cp = subprocess.run([g.tool("exiftool"), "-json", "-G1", "-a", "-s", "-x", "System:all",
                             g.lp(dest)], capture_output=True, timeout=120)
        d = json.loads(fa.dec(cp.stdout) or "[]")
        if d:
            d[0].pop("SourceFile", None)
            return d[0]
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass
    return None


# ------------------------------------------------------------ esportazione

CITED_THUMBS = 3000             # (2.20) miniature delle immagini citate dagli artefatti incluse nel report


def art_segreti(case, con, rows, includi):
    """(2.20) Valori segreti del portachiavi (password, chiavi, token) nelle righe di iLEAPP/ALEAPP: nel caso sono già
    sostituiti dal segnaposto; si rimettono solo se l'operatore l'ha scelto creando il report (scelta registrata).
    Restituisce quanti valori sono stati inclusi."""
    import forense_mobile_portachiavi as fmk
    if not includi:
        return 0
    val = fmk.valori_segreti(con)
    n = 0
    for r in rows:
        sv = val.get(r[-1])
        if not sv:
            continue
        try:
            d = json.loads(r[11]) if r[11] else {}
        except ValueError:
            continue
        campi = d.get("campi") or {}
        for k, v in sv.items():
            campi[k] = v
            n += 1
        try:
            det = json.loads(r[3]) if r[3] and str(r[3]).startswith("{") else None
        except ValueError:
            det = None
        if isinstance(det, dict):
            det.update({k: v for k, v in sv.items() if k in det})
            r[3] = json.dumps(det, ensure_ascii=False)
        for v in sv.values():                       # titolo: i segnaposto nell'ordine dei campi
            r[2] = str(r[2]).replace(fmk.MASK, str(v)[:80], 1)
        d["campi"] = campi
        r[11] = json.dumps(d, ensure_ascii=False)
    case.log("portatile_valori_segreti", {"inclusi": n})
    return n


def art_cited(case, out, rows):
    """(2.20) File citati da ogni artefatto, con la stessa ricerca dell'interfaccia (forense_percorsi): l'ultimo elemento
    della riga (i dati dell'artefatto) diventa [[campi, esito, stato, offset, inode, percorso, miniatura, tipo, livello,
    metodo per campo, candidati [[percorso, dimensione, offset, inode]…] e il loro numero, copie [[percorso, dimensione,
    SHA-256]…], cartelle [[percorso, stato]…], verifica, ruolo, nota]…], un elemento per file DIVERSO;
    la fonte risolta sostituisce quella salvata (iLEAPP/ALEAPP: il database con il percorso completo). Le immagini
    trovate hanno una miniatura in citati/ (al massimo CITED_THUMBS). Restituisce {"n": miniature, "troncato": bool}."""
    import forense_percorsi as fp
    try:
        idx = fp.Indice(case)
    except Exception:
        for r in rows:
            r[11] = None
        return {"n": 0, "troncato": False}
    mobile = fa.is_mobile(case)
    d = out / "citati"
    n, cut, done = 0, False, {}
    try:
        for r in rows:
            data = r[11]
            r[11] = None
            try:
                c = fp.file_citati(case, {"cat": r[0], "title": r[2], "user": r[4], "src_path": r[5], "part": r[6],
                                          "inode": r[7], "data": data}, veloce=True, idx=idx)
            except Exception:
                continue
            f = c.get("fonte")
            if f and f.get("stato") == "trovato" and r[7] in (None, ""):
                r[5], r[6], r[7] = f["path"], f["part"], f["inode"]
            cl = []
            for x in c["file"][:fp.MAX_CITATI]:
                th = ""
                if x.get("tipo") == "immagine" and x["stato"] in ("trovato", "rapporto"):
                    key = (x.get("part"), x.get("inode"), x.get("rapporto"))
                    if key in done:
                        th = done[key]
                    elif n < CITED_THUMBS:
                        th = _cited_thumb(case, x, d, n)
                        done[key] = th
                        n += bool(th)
                    else:
                        cut = True
                cl.append([", ".join(tr(fp.CAMPI_INTERNI[k]) if k in fp.CAMPI_INTERNI else k for k in x.get("campi") or [x.get("campo")]),
                           fp.etichetta_disco(x, mobile), x["stato"], x.get("part"), x.get("inode"),
                           x.get("path") or x.get("percorso"), th, x.get("tipo") or "", x.get("livello") or fp.livello(x),
                           fp.metodo_testo(x),
                           [[c["path"], c["size"], c["part"], c["inode"]] for c in x.get("candidati") or []],
                           x.get("n_candidati") or 0,
                           [[c["path"], c["size"], c.get("sha256")] for c in x.get("copie_elenco") or []],
                           [[d.get("path") or d.get("percorso"), d.get("stato")] for d in x.get("cartelle") or []],
                           x.get("verifica"), x.get("ruolo"), x.get("nota"), x.get("copie") or 0])
            r[11] = cl or None
    finally:
        idx.close()
    return {"n": n, "troncato": cut}


def _cited_thumb(case, x, d, n):
    """Miniatura (160 px) di un'immagine citata: dal file della copia/estrazione o dalla copia nel rapporto di iLEAPP."""
    try:
        if x["stato"] == "trovato":
            t = g.thumb_bytes(case, {"source": "fs", "part": x["part"], "inode": x["inode"], "size": 160})
            data = t[0] if t else None
        else:
            from PIL import Image
            import io
            im = Image.open(case.root / x["rapporto"])
            im.thumbnail((160, 160))
            buf = io.BytesIO()
            im.convert("RGB").save(buf, "JPEG", quality=80)
            data = buf.getvalue()
    except Exception:
        return ""
    if not data:
        return ""
    try:                                     # solo immagini vere (un file danneggiato o finto non diventa una miniatura rotta)
        from PIL import Image
        import io
        Image.open(io.BytesIO(data)).verify()
    except Exception:
        return ""
    d.mkdir(parents=True, exist_ok=True)
    f = d / f"c{n}.jpg"
    f.write_bytes(data)
    return f"citati/{f.name}"


def export_ext(case, out, dati, opts):
    """Artefatti di sistema, posta, archivi e allegati, anomalie (forense_estesa) in dati/estese.js;
    con «tutti i file» o «documenti e immagini» anche i file estratti, nella cartella estratti/."""
    con = fa.db_ro(case)
    has = lambda t: fa.table_exists(con, t)
    ext = {"art": [], "mail": [], "x": [], "anom": []}
    try:
        if has("artifacts"):
            # smartphone (2.20): anche gruppo/voce per le sottovoci e i dati delle conversazioni
            mob = fa.is_mobile(case) and "grp" in {r[1] for r in con.execute("PRAGMA table_info(artifacts)")}
            ext["art"] = [list(r) for r in con.execute(
                "SELECT cat, ts, title, detail, user, src_path, part, inode"
                + (", grp, sub, CASE WHEN cat='messaggi' THEN data END" if mob else ", NULL, NULL, NULL")
                + ", data, id FROM artifacts ORDER BY ts IS NULL, ts DESC")]
            ext["segreti"] = art_segreti(case, con, ext["art"], bool(opts.get("segreti"))) if mob else 0
            for r in ext["art"]:
                r.pop()                                                   # id: serviva solo per i valori segreti
            ext["cited_thumbs"] = art_cited(case, out, ext["art"])      # (2.20) elemento 11: file citati
            if mob:
                for r in ext["art"]:
                    if r[10]:
                        r[10] = json.loads(r[10])
                ext["art_sub"] = True
                ext["leapp_date"] = (case.meta.get("leapp") or {}).get("colonne_data") or {}
                # (2.20) righe di iLEAPP/ALEAPP in file per artefatto (al massimo LEAPP_PARTE righe ciascuno), caricati
                # quando servono: in un telefono possono essere centinaia di migliaia (iPhone di prova: 500.000 righe,
                # 618 MB in estese.js caricati all'avvio, troppi per il browser)
                rest, by = [], {}
                for r in ext["art"]:
                    if r[0] == "leapp":
                        by.setdefault((r[8] or "", r[9] or ""), []).append(r)
                    else:
                        rest.append(r)
                if by:
                    idx, n = [], 0
                    for (gk, sk), rows in sorted(by.items()):
                        files = []
                        for i in range(0, len(rows), LEAPP_PARTE):
                            n += 1
                            rel = f"leapp/{n // 1000:03d}/{n:06d}.js"
                            write_js(dati / rel, "leapp", {"f": rel, "rows": rows[i:i + LEAPP_PARTE]})
                            files.append(rel)
                        idx.append([gk, sk, len(rows), files])
                    ext["art"] = rest
                    ext["leapp_idx"] = idx
                    ext["leapp_n"] = sum(x[2] for x in idx)
        if has("mail"):
            budget = 40 << 20
            for r in con.execute("SELECT id, date, sender, recipients, cc, subject, n_att, fmt, folder, src_path, body "
                                 "FROM mail ORDER BY date IS NULL, date DESC"):
                r = list(r)
                body = (r[10] or "")[:20000]
                budget -= len(body)
                r[10] = body if budget > 0 else ""
                ext["mail"].append(r)
        mode = opts.get("contenuto") or "scelti"
        lim = (500 << 20) if mode == "tutti" else int(float(opts.get("auto_mb") or 5) * (1 << 20)) if mode == "piccoli" else -1
        if has("xitems"):
            for xid, kind, path, name, size, mtime, enc, sha, note, mail, rel in con.execute(
                    "SELECT id, kind, path, name, size, mtime, encrypted, sha256, note, mail, relpath FROM xitems ORDER BY path"):
                dest = ""
                src = case.root / rel if rel else None
                if src and src.exists() and 0 <= src.stat().st_size <= lim:
                    d = out / "estratti" / kind
                    d.mkdir(parents=True, exist_ok=True)
                    f = d / f"x{xid}_{g.safe_part(name or 'file')}"
                    shutil.copyfile(src, f)
                    dest = f.relative_to(out).as_posix()
                ext["x"].append([xid, kind, path, name, size, mtime, enc, sha, note, mail, dest])
        if has("anomalies"):
            ext["anom"] = [list(r) for r in con.execute(
                "SELECT kind, path, detail, size, sev, part, inode, source FROM anomalies ORDER BY sev DESC, kind, path")]
    finally:
        con.close()
    if not any(ext.values()):
        return False
    import forense_estesa as fe
    ext["art_cats"] = {k: tr(v) for k, v in fe.ART_CATS.items()}
    if ext.get("art_sub"):
        ext["art_cats"].update({"messaggi": tr("Messaggi delle chat"), "leapp": tr("Artefatti iLEAPP/ALEAPP (smartphone)")})
    ext["anom_kinds"] = {k: tr(v) for k, v in fe.ANOM_KINDS.items()}
    write_js(dati / "estese.js", "ext", ext)
    return True


def _strumenti_mobile(case):
    """(2.20) Casi smartphone: solo gli strumenti usati davvero (iLEAPP/ALEAPP con impronta, lettori di chat, …)."""
    import forense_mobile_chat as fmc
    return fmc.strumenti_dict(case)


STOP = threading.Event()             # Interrompi della finestra del report portatile (/api/portable_stop)


class Interrotto(Exception):
    pass


class SenzaSpazio(Exception):
    """(2.20) spazio insufficiente prima di cominciare o disco quasi pieno durante l'estrazione."""


def export_portable(case, opts, progress):
    """Crea il report portatile; con Interrompi, o se il disco si riempie, si ferma e toglie la
    cartella lasciata a metà (il disco non resta pieno)."""
    STOP.clear()
    pstate = {"pct": 0.0, "out": None, "pieno": None}

    def togli(evento, extra):
        out = pstate["out"]
        if out is not None and out.exists():
            shutil.rmtree(g.lp(out), ignore_errors=True)
        case.log(evento, {"cartella": str(out.relative_to(case.root)) if out else None,
                          "avanzamento_pct": round(pstate["pct"], 1), **extra})

    try:
        return _export_portable(case, opts, progress, pstate)
    except Interrotto:
        togli("report_portatile_interrotto", {})
        raise ValueError(tr("Report portatile interrotto: la cartella lasciata a metà è stata tolta."))
    except SenzaSpazio as e:
        togli("report_portatile_spazio", {"motivo": str(e)})
        raise ValueError(str(e))
    except OSError as e:
        if not disco_pieno(e):
            raise
        togli("report_portatile_spazio", {"motivo": str(e)})
        raise ValueError(tr("Disco pieno durante il report portatile: la cartella lasciata a metà è stata tolta "
                            "e lo spazio è di nuovo libero. Libera spazio o scegli un'altra opzione."))


def _export_portable(case, opts, progress, pstate):
    t0 = time.time()
    opts = dict(opts or {})
    raw_progress = progress

    def progress(msg, pct=None, eta=None):
        """Avanzamento per la finestra: messaggio, percentuale complessiva, minuti stimati."""
        if pstate["pieno"]:
            raise SenzaSpazio(pstate["pieno"])
        if STOP.is_set():
            raise Interrotto()
        if pct is not None:
            pstate["pct"] = max(pstate["pct"], min(100.0, pct))
        raw_progress({"msg": msg, "pct": round(pstate["pct"], 1), "eta": eta})

    progress(tr("Controllo l'albero del file system…"), 1)
    try:
        fa.normalize_carved_names(case)
    except Exception:
        pass
    wait_nav(case, progress)
    out = g.unique(case.export_dir / f"report_portatile_{g.stamp_now()}")
    pstate["out"] = out
    dati = out / "dati"
    for d in ("a", "eventi", "testi", "file", "allegati"):
        (dati / d).mkdir(parents=True, exist_ok=True)
    ad = appledouble(g.lp(out))           # (2.20) macOS su exFAT/FAT: «._nome» accanto a ogni file, tolti man mano
    # lingua del report: quella del caso (la pagina si traduce da sé con questo dizionario)
    with open(g.lp(dati / "lingua.js"), "w", encoding="ascii") as f:
        f.write("window.LG = " + json.dumps({"lingua": lg.lingua(), "diz": lg.dizionario(lg.lingua())}) + ";\n")
    counts = {}

    # --- metadati già indicizzati (servono anche alle anteprime leggere)
    con = fa.db_ro(case)
    meta_rows, meta_data = [], {}
    if fa.table_exists(con, "meta"):
        for source, part, inode, deleted, path, make, model, taken, lat, lon, author, data in con.execute(
                "SELECT source, part, inode, deleted, path, make, model, taken, lat, lon, author, data "
                "FROM meta"):
            meta_rows.append([source, part, inode, deleted, path, make, model, taken, lat, lon, author])
            meta_data[(part, inode) if source != "carving" else ("c", inode)] = data
        if fa.is_mobile(case):          # (2.20) telefoni: app delle chat in cui il file è allegato (11) e messaggio (12)
            import forense_mobile_gui as fmg
            dd = [{"part": m[1], "inode": m[2]} for m in meta_rows]
            fmg.meta_origini(con, dd)
            for m, d in zip(meta_rows, dd):
                if d.get("chat"):
                    m += [d["chat"], d["chat_mid"]]
    con.close()

    # --- contenuto dei file
    progress(tr("Raccolgo i file da includere…"), 2)
    want = wanted_files(case, opts, progress)
    # dimensioni per l'avanzamento e testi già indicizzati (per non duplicarli con le stringhe)
    nav0 = g.nav_db(case)
    try:
        for (src_kind, part, ident), info in want.items():
            if src_kind == "fs" and info.get("size") is None:
                r = nav0.execute("SELECT size FROM nav WHERE part=? AND inode=? AND isdir=0 LIMIT 1",
                                 (part, ident)).fetchone()
                info["size"] = (r[0] if r else 0) or 0
    finally:
        nav0.close()
    total_bytes = sum(v.get("size") or 0 for v in want.values()) or 1
    # (2.20) spazio: prima si controlla che il report ci stia (cluster, anteprime, dati), poi durante
    # l'estrazione si lascia sempre libera la RISERVA; se manca ci si ferma e si toglie la cartella
    cl = cluster_size(out)
    sp = Spazio(cl, testi_case(case) if opts.get("testi", True) else 0, ad)
    for (src_kind, part, ident), info in want.items():
        sp.add(info.get("path") or ident, info.get("size"), part)
    nav0 = g.nav_db(case)
    try:
        voci = nav0.execute("SELECT COUNT(*) FROM nav").fetchone()[0]
    finally:
        nav0.close()
    need = sp.need(voci)
    free0 = shutil.disk_usage(g.lp(out)).free
    if need + RISERVA > free0:
        raise SenzaSpazio(tr("Spazio insufficiente per il report portatile: servono circa {need} sul disco del "
                             "caso ({files} file per {content}, più anteprime, dati e indici; ogni file occupa "
                             "almeno {cl} KB su questo disco) e ne sono liberi {free}, da cui lasciare liberi "
                             "{ris}. Libera spazio o scegli un'altra opzione.").format(
            need=gb(need), files=f"{sp.n:,}".replace(",", "."), content=gb(sp.bytes), cl=cl // 1024,
            free=gb(free0), ris=gb(RISERVA)))
    spc = {"bytes": 0, "files": 0}

    def guarda_spazio(written):
        """(col lock) ogni 256 MB o 500 file controlla lo spazio libero."""
        spc["bytes"] += written
        spc["files"] += 1
        if spc["bytes"] < 256 << 20 and spc["files"] < 500:
            return
        spc["bytes"] = spc["files"] = 0
        free = shutil.disk_usage(g.lp(out)).free
        if free < RISERVA and not pstate["pieno"]:
            pstate["pieno"] = tr("Il disco del caso si stava riempiendo (liberi {free}): il report portatile si è "
                                 "fermato e la cartella lasciata a metà è stata tolta, così lo spazio è di nuovo "
                                 "libero. Libera spazio o scegli un'altra opzione.").format(free=gb(free))
    con = fa.db_ro(case)
    indexed = set()
    if fa.table_exists(con, "doc_text"):
        for source, part, inode in con.execute("SELECT source, part, inode FROM doc_text"):
            indexed.add(("c", inode) if source == "carving" else (part, inode))
    con.close()
    str_tmp = out / "stringhe.tmp"
    str_fh, str_state = open(g.lp(str_tmp), "w", encoding="utf-8"), {"chars": 0, "files": 0, "full": False}
    items = sorted(want.items(), key=lambda kv: (not kv[1]["full"], str(kv[0])))
    need_image = any(k[0] == "fs" and not v.get("exported") for k, v in items)
    if need_image and not Path(case.image).exists():
        raise ValueError(tr("La copia forense non è raggiungibile: collega il disco che la contiene "
                         "(serve per estrarre i file da includere)."))
    att_rows, skipped, used, lock = [None] * len(items), [], set(), threading.Lock()
    done = {"n": 0, "bytes": 0}

    def work(idx, key, info):
        if STOP.is_set() or pstate["pieno"]:
            return
        aid = idx + 1
        src_kind, part, ident = key
        try:
            it = g.file_ident(case, {"source": "carving", "name": ident} if src_kind == "c"
                              else {"source": "fs", "part": part, "inode": ident})
            rel = dest_rel(it, used, lock, ad)
            dest = out / rel
            extract(case, it, info, dest)
        except Exception as e:     # file non leggibile: si annota e si prosegue
            with lock:
                if disco_pieno(e):     # disco pieno: non è un file illeggibile, ci si ferma
                    pstate["pieno"] = pstate["pieno"] or tr(
                        "Disco pieno durante il report portatile: la cartella lasciata a metà è stata tolta "
                        "e lo spazio è di nuovo libero. Libera spazio o scegli un'altra opzione.")
                else:
                    skipped.append({"file": str(ident), "motivo": str(e)[:200]})
            return
        lvl = FULL if info["full"] else BULK
        with open(g.lp(dest), "rb") as fh:
            head = fh.read(lvl["hex"])
        kind = kind_of(dest.name, head)
        sha, md5 = sha_md5(dest)
        pdir = out / "anteprime" / f"{aid:06d}"
        pages, preview, html_doc = make_previews(case, it, dest, pdir, kind, lvl)
        text = ""
        if kind == "text":
            with open(g.lp(dest), "rb") as fh:
                text = g.decode_text(fh.read(lvl["text"]))
        mk = (it["part"], it["inode"]) if it["source"] == "fs" else ("c", it["name"])
        if mk not in indexed and kind not in NO_STRINGS and not str_state["full"]:
            try:
                body = text[:STR_PER_FILE] if kind == "text" else strings_of(dest)
            except OSError:
                body = ""
            if body.strip():
                row = [it["source"], it["part"], it["inode"] if it["source"] == "fs" else it["name"],
                       it["path"], it.get("deleted", 0), "testo" if kind == "text" else "stringhe", body]
                with lock:
                    if str_state["chars"] + len(body) > STR_TOTAL:
                        str_state["full"] = True
                    else:
                        str_fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                        str_state["chars"] += len(body)
                        str_state["files"] += 1
        exif = None
        if lvl["tools"]:
            exif = exif_json(dest)
        elif meta_data.get(mk):
            try:
                exif = json.loads(meta_data[mk])
            except ValueError:
                exif = None
        size = os.path.getsize(g.lp(dest))
        det = {"id": aid, "hex": base64.b64encode(head).decode(), "text": text, "html": html_doc,
               "istat": istat_text(case, it) if lvl["tools"] else "", "exif": exif, "full": info["full"]}
        if info["full"]:
            write_js(dati / "a" / f"{aid // 1000:04d}" / f"{aid:06d}.js", "detail", det)
        else:                      # (2.20) file in blocco: 100 dettagli per file dati (meno file sul disco)
            line = js("detail", det)
            gf = g.lp(dati / "a" / f"g{aid // DET_GRP:05d}.js")
            with lock:
                with open(gf, "a", encoding="ascii") as fh:
                    fh.write(line)
                if ad:
                    togli_ad(gf)
        if ad:
            togli_ad(g.lp(dest))
            if info["full"]:
                togli_ad(g.lp(dati / "a" / f"{aid // 1000:04d}" / f"{aid:06d}.js"))
            if Path(g.lp(pdir)).is_dir():
                togli_ad_tutti(g.lp(pdir))
        att_rows[idx] = [aid, it["source"], it["part"], it["inode"],
                         it["name"] if it["source"] == "carving" else None, rel.as_posix(), size,
                         it.get("deleted", 0), kind, pages, 1 if preview else 0, sha, md5,
                         sorted(info["why"]), 1 if info["full"] else 0]
        with lock:
            done["n"] += 1
            done["bytes"] += size
            guarda_spazio(size)
            if done["n"] % 10 == 0 or done["n"] == len(items):
                frac = min(1.0, 0.5 * done["n"] / len(items) + 0.5 * done["bytes"] / total_bytes)
                el = time.time() - tf
                eta = round(el * (1 - frac) / frac / 60, 1) if frac > 0.02 and el > 10 else None
                b = done["bytes"]
                bs = f"{b / 1e9:.2f} GB".replace(".", ",") if b >= 1e9 else f"{b / 1e6:.0f} MB"
                progress(tr("File inclusi: {n:,} di {v1:,}").format(n=done['n'], v1=len(items)).replace(",", ".") + f" · {bs}",
                         4 + 80 * frac, eta)

    tf = time.time()
    try:
        with ThreadPoolExecutor(WORKERS) as ex:
            list(ex.map(lambda a: work(*a), [(i, k, v) for i, (k, v) in enumerate(items)]))
    finally:
        str_fh.close()
    if pstate["pieno"]:
        raise SenzaSpazio(pstate["pieno"])
    if STOP.is_set():
        raise Interrotto()
    att_rows = [r for r in att_rows if r]
    att_of = {}
    for r in att_rows:
        att_of[(r[2], r[3]) if r[1] == "fs" else ("c", r[4])] = r[0]
    att_chunks = []
    for k in range(0, len(att_rows), ATT_CHUNK):
        fn = f"allegati/a{len(att_chunks):04d}.js"
        write_js(dati / fn, "atts", att_rows[k:k + ATT_CHUNK])
        att_chunks.append(fn)
    counts["allegati"] = len(att_rows)
    counts["allegati_byte"] = sum(r[6] for r in att_rows)

    con = fa.db_ro(case)
    nav = g.nav_db(case)
    try:
        # --- hash dei file (se calcolati)
        hashes = {}
        if fa.table_exists(con, "hashes"):
            for part, inode, md5, sha1, sha256 in con.execute(
                    "SELECT part, inode, md5, sha1, sha256 FROM hashes"):
                hashes[(part, inode)] = (md5, sha1, sha256)
        att_hash = {(r[2], r[3]): (r[12], None, r[11]) for r in att_rows if r[1] == "fs"}

        # --- catalogo dei file (albero completo)
        progress(tr("Catalogo dei file…"), 85)
        chunks, rows, total = [], [], 0
        cols = ["part", "parent", "name", "isdir", "deleted", "inode", "size", "mtime", "atime",
                "ctime", "crtime", "type", "md5", "sha1", "sha256", "att"]
        for (part, parent, name, isdir, deleted, inode, size, m, a, c, b,
             typ) in nav.execute("SELECT part, parent, name, isdir, deleted, inode, size, mtime, "
                                 "atime, ctime, crtime, type FROM nav ORDER BY id"):
            h = hashes.get((part, inode)) or att_hash.get((part, inode)) or (None, None, None)
            rows.append([part, parent, name, isdir, deleted, inode, size, m, a, c, b, typ, *h,
                         att_of.get((part, inode), 0) if not isdir else 0])
            total += 1
            if len(rows) >= CHUNK_ROWS:
                fn = f"file/f{len(chunks):04d}.js"
                write_js(dati / fn, "files", rows)
                chunks.append(fn)
                rows = []
                progress(tr("Catalogo dei file: {total:,} voci").format(total=total).replace(",", "."))
        if rows or not chunks:
            fn = f"file/f{len(chunks):04d}.js"
            write_js(dati / fn, "files", rows)
            chunks.append(fn)
        counts["file"] = total

        # --- testi: documenti indicizzati e stringhe degli altri file inclusi, a blocchi,
        # con l'indice file -> blocco per la scheda Testo
        text_chunks, text_index, tb = [], {}, {"buf": [], "size": 0}
        tot_chars, ndocs, truncated = 0, 0, False

        def tput(row):
            tb["buf"].append(row)
            key = f"c:{row[2]}" if row[0] == "carving" else f"{row[1]}:{row[2]}"
            text_index[key] = len(text_chunks)
            tb["size"] += len(row[6]) + len(row[3] or "")
            if tb["size"] >= TEXT_CHUNK:
                tflush()

        def tflush():
            if tb["buf"]:
                fn = f"testi/t{len(text_chunks):04d}.js"
                write_js(dati / fn, "texts", tb["buf"])
                text_chunks.append(fn)
                tb["buf"], tb["size"] = [], 0

        if opts.get("testi", True) and fa.table_exists(con, "doc_text"):
            progress(tr("Testi dei documenti…"), 90)
            for path, body, source, part, inode, deleted, kind in con.execute(
                    "SELECT path, body, source, part, inode, deleted, kind FROM doc_text"):
                body = (body or "")[:TEXT_PER_DOC]
                if tot_chars + len(body) > TEXT_TOTAL:
                    truncated = True
                    break
                tput([source, part, inode, path, deleted, kind, body])
                tot_chars += len(body)
                ndocs += 1
        counts["testi"] = ndocs
        nstr = 0
        if opts.get("testi", True) and str_state["files"]:
            progress(tr("Testo e stringhe degli altri file…"), 92)
            with open(g.lp(str_tmp), encoding="utf-8") as fh:
                for line in fh:
                    tput(json.loads(line))
                    nstr += 1
        tflush()
        counts["stringhe"] = nstr
        counts["stringhe_troncate"] = str_state["full"]

        write_js(dati / "meta.js", "meta", meta_rows)
        counts["metadati"] = len(meta_rows)

        # --- timeline (2.20): un file per GIORNO (i giorni con più di EV_PARTE eventi in più parti), caricato quando
        # serve: la tabella compare subito anche nei mesi con milioni di eventi (prima un file per mese da centinaia di MB)
        progress(tr("Timeline…"), 94)
        months, days, parts = {}, {}, {}
        origins = ["tsk"] + (["plaso"] if opts.get("plaso", True) else [])
        state = {"d": None, "buf": [], "n": 0}

        def flush():
            if state["d"] and state["buf"]:
                state["n"] += 1
                write_js(dati / "eventi" / state["d"][:7] / f"{state['d']}_{state['n']}.js", "events",
                         {"d": state["d"], "p": state["n"], "rows": state["buf"]})
                parts[state["d"]] = state["n"]
            state["buf"] = []

        q = ("SELECT ts, kind, origin, source, path, message, part FROM events WHERE ts > '1970' "
             f"AND origin IN ({','.join('?' * len(origins))}) ORDER BY ts")
        nev = 0
        for ts, kind, origin, source, path, msg, part in con.execute(q, origins):
            dy = ts[:10]
            if dy != state["d"]:
                flush()
                state["d"], state["n"] = dy, 0
            elif len(state["buf"]) >= EV_PARTE:
                flush()
            ino = None
            if origin == "tsk":
                mm = g.EV_RE.search(msg or "")
                ino = mm.group(1) if mm else None
                msg = None
            state["buf"].append([ts, kind, origin, source, path, (msg or "")[:MSG_MAX] or None,
                                 part, ino])
            mo = ts[:7]
            months[mo] = months.get(mo, 0) + 1
            dd = days.setdefault(dy, [0, 0])
            dd[0 if origin == "tsk" else 1] += 1
            nev += 1
            if nev % 200_000 == 0:
                progress(tr("Timeline: {nev:,} eventi").format(nev=nev).replace(",", "."))
        flush()
        counts["eventi"] = nev

        # --- tracce (bulk_extractor) e file recuperati
        feats = []
        if opts.get("tracce", True) and fa.table_exists(con, "features"):
            for kind, off, pos, feat, ctx in con.execute(
                    f"SELECT kind, offset, pos, feature, context FROM features LIMIT {FEATURES_MAX}"):
                feats.append([kind, off, feat, (ctx or "")[:200]])
        write_js(dati / "tracce.js", "traces", feats)
        carved = []
        if fa.table_exists(con, "carved"):
            for name, rel, part, size, typ, img_off, sha in con.execute(
                    "SELECT name, relpath, part, size, type, img_offset, sha256 FROM carved"):
                carved.append([name, size, typ, img_off, sha, att_of.get(("c", name), 0)])
        write_js(dati / "carving.js", "carved", carved)
        counts["tracce"], counts["recuperati"] = len(feats), len(carved)
    finally:
        con.close()
        nav.close()

    # --- informazioni del caso e report
    try:
        os.remove(g.lp(str_tmp))
    except OSError:
        pass
    progress(tr("Analisi estese (artefatti, posta, archivi, anomalie)…"), 96)
    has_ext = export_ext(case, out, dati, opts)
    progress(tr("Report e informazioni del caso…"), 97)
    m = case.meta
    report_md = fa.write_report(case).read_text(encoding="utf-8")
    mode = opts.get("contenuto") or "scelti"
    info = {
        "id": f"{case.root.name}-{g.stamp_now()}", "case": case.root.name,
        "generated": fa.now(), "app": f"{fa.APP_NAME} {fa.APP_VERSION} ({fa.APP_BY})",
        "info_caso": m.get("info_caso") or {},
        "fuso_dispositivo": fa.fuso_testo(m),
        "fuso_tz": (m.get("fuso_dispositivo") or {}).get("tz") or "",
        "fuso_stato": (m.get("fuso_dispositivo") or {}).get("stato") or "",
        "created": m.get("created"), "evidence": Path(m.get("evidence", m.get("image", ""))).name,
        "converted": bool(m.get("converted_from_e01")), "disk_type": m.get("disk_type"),
        "sha256": m.get("sha256") or {}, "sha256_ts": m.get("sha256_ts"),
        "sha256_differito": bool(m.get("sha256_differito")),
        "hash_acquisizione": m.get("hash_uguale_ad_acquisizione"),
        "hash_dati": m.get("hash_dati"), "hash_dati_testo": fa.hash_dati_testo(m.get("hash_dati")) if m.get("hash_dati") else "",
        "verifiche": m.get("verifiche", []), "partitions": m.get("partitions", []), "layout": _layout(case), "non_allocato": _unalloc(case),
        "tools": (_strumenti_mobile(case) if fa.is_mobile(case) else m.get("tool_versions") or {}), "timeline": m.get("timeline") or {},
        "hash_file": bool(m.get("hash_file")), "report_md": report_md, "findings": case.findings(),
        "cols": cols, "file_chunks": chunks, "att_chunks": att_chunks, "text_chunks": text_chunks,
        "text_index": text_index,
        "bookmarks": [{"name": c["name"], "note": c["note"],
                       "items": [[(f"c:{Path(str(i['inode'])).name}" if i["source"] == "carving"
                                   else f"chat:{i['inode']}" if i["source"] == "chat"
                                   else f"{i['part']}:{i['inode']}"), i["note"] or "", i["path"]]
                                 for i in c["items"]]} for c in fa.bookmarks(case)],
        "att_cols": ["id", "source", "part", "inode", "name", "file", "size", "deleted", "kind",
                     "pages", "preview", "sha256", "md5", "why", "full"],
        "text_truncated": truncated, "months": months, "days": days, "ev_parts": parts, "counts": counts,
        "skipped": skipped[:500], "skipped_n": len(skipped), "mode": mode,
        "options": {k: v for k, v in opts.items() if k != "zip"},
        "ext": has_ext, "volumi_cifrati": m.get("volumi_cifrati") or [],
    }
    write_js(dati / "caso.js", "case", info)

    tpl = (HERE / "forense_portatile.html").read_text(encoding="utf-8")
    if fa.is_mobile(case) and (HERE / "forense_mobile_portatile.html").exists():   # smartphone (2.20): chat
        import forense_mobile_chat as fmc
        if fmc.export_portable(case, dati):
            tpl = tpl.replace("<!--REPERTIA_MOBILE-->", (HERE / "forense_mobile_portatile.html").read_text(encoding="utf-8"))
    (out / "index.html").write_text(tpl.replace("__TITLE__", html.escape(case.root.name)),
                                    encoding="utf-8")
    what = {"scelti": tr("il contenuto dei soli file citati nei reperti e delle selezioni esportate"),
            "piccoli": tr("il contenuto di documenti e immagini fino alla dimensione scelta, dei reperti "
                       "e delle selezioni esportate"),
            "tutti": tr("il contenuto di tutti i file del supporto")}[mode]
    (out / "LEGGIMI.txt").write_text(
        tr("REPORT PORTATILE - RepertIA (By silvexe)\r\n\r\nCaso: {name}\r\nGenerato: "
           "{generated}\r\n\r\nApri index.html con un browser (Chrome, Edge, Firefox, Safari): funziona "
           "offline,\r\nsenza installare nulla e senza la copia forense. Copia l'intera cartella: "
           "index.html\r\nda solo non basta.\r\n\r\nContiene il catalogo completo del supporto (file anche "
           "cancellati, date, hash,\r\nmetadati, testi dei documenti, timeline, reperti) e {what}.\r\nI "
           "file sono nella cartella 'file', con l'albero delle cartelle originale; le "
           "anteprime\r\n(pagine dei documenti) in 'anteprime'. Le note che aggiungi restano nel tuo "
           "browser:\r\nesportale dal pannello Note per consegnarle.\r\n\r\nINTEGRITA'\r\nimpronte.csv "
           "contiene lo SHA-256 di ogni file del report; IMPRONTA_REPORT.txt contiene\r\nlo SHA-256 di "
           "impronte.csv, registrato da RepertIA al momento della generazione.\r\n").format(name=case.root.name, generated=info['generated'], what=what),
        encoding="utf-8")

    # --- impronte di integrità (riusa gli hash già calcolati dei file inclusi)
    progress(tr("Impronte di integrità…"), 98)
    if ad:
        togli_ad_tutti(g.lp(out))
    known = {r[5]: r[11] for r in att_rows}
    lines = []
    for root, dirs, files in os.walk(g.lp(out)):
        for fn in files:
            f = Path(root) / fn
            rel = Path(os.path.relpath(f, g.lp(out))).as_posix()
            sha = known.get(rel) or sha_md5(f)[0]
            lines.append(f"{rel};{f.stat().st_size};{sha}")
    lines.sort()
    imp = out / "impronte.csv"
    imp.write_text("file;byte;sha256\n" + "\n".join(lines) + "\n", encoding="utf-8")
    fingerprint = sha_md5(imp)[0]
    (out / "IMPRONTA_REPORT.txt").write_text(
        tr("SHA-256 di impronte.csv: {fingerprint}\r\nGenerato: {generated}\r\n").format(fingerprint=fingerprint, generated=info['generated']), encoding="utf-8")
    size = sum(int(l.rsplit(";", 2)[1]) for l in lines) + imp.stat().st_size
    if ad:
        togli_ad(g.lp(imp))
        togli_ad(g.lp(out / "IMPRONTA_REPORT.txt"))
        togli_ad(g.lp(out))
    zip_rel = zip_nota = None
    if opts.get("zip"):
        progress(tr("Creo lo zip…"), 99)
        free = shutil.disk_usage(g.lp(out)).free
        if size * 1.02 + RISERVA > free:       # (2.20) lo zip non deve riempire il disco: il report resta
            zip_nota = tr("Zip non creato: servono circa {need}, liberi {free}. Il report è completo nella "
                          "cartella.").format(need=gb(size), free=gb(free))
        else:
            try:
                z = shutil.make_archive(g.lp(out), "zip", root_dir=g.lp(out.parent), base_dir=out.name)
                zip_rel = os.path.relpath(z, g.lp(case.root))
                if ad:
                    togli_ad(z)
            except OSError as e:
                if not disco_pieno(e):
                    raise
                Path(g.lp(out) + ".zip").unlink(missing_ok=True)
                zip_nota = tr("Zip non creato: disco pieno. Il report è completo nella cartella.")
    res = {"path": str(out), "rel": str(out.relative_to(case.root)), "zip": zip_rel, "zip_nota": zip_nota,
           "size": size, "fingerprint": fingerprint, "counts": counts, "mode": mode,
           "skipped": skipped[:50], "skipped_n": len(skipped), "elapsed": round(time.time() - t0, 1)}
    case.log("report_portatile", {k: v for k, v in res.items() if k != "skipped"})
    progress(tr("Completato"), 100)
    return res
