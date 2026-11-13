#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - indice del testo dei documenti e dei metadati.

(3.0.4) Codice spostato da forense_agent.py senza modifiche, per avere file più corti. Si carica tramite
forense_agent, che ne riesporta i nomi: gli altri moduli continuano a usare «fa.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fa.<nome>»).
"""
import csv
import html
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import zipfile
from pathlib import Path
from forense_lingua import N_
from forense_lingua import tr

import forense_agent as fa
from forense_agent import (
    cached_copy, dec, icat_stream, install_hint, is_mobile, noelev_env, now)

# ------------------------------------------- testo dei documenti e metadati

TEXT_EXT = {".txt", ".csv", ".md", ".log", ".json", ".xml", ".html", ".htm", ".eml",
            ".ini", ".cfg", ".tsv", ".vcf", ".ics", ".rtf"}
OFFICE_EXT = {".pdf", ".doc", ".docx", ".docm", ".dot", ".dotx", ".xls", ".xlsx", ".xlsm",
              ".ppt", ".pptx", ".pps", ".ppsx", ".odt", ".ods", ".odp", ".msg", ".pages",
              ".numbers", ".key"}
DOC_EXT = TEXT_EXT | OFFICE_EXT
IMG_EXT = {".jpg", ".jpeg", ".heic", ".heif", ".png", ".tif", ".tiff", ".gif", ".bmp",
           ".webp", ".dng", ".cr2", ".cr3", ".nef", ".arw", ".orf", ".raf", ".rw2",
           ".mov", ".mp4", ".m4v", ".3gp", ".avi"}
META_EXT = IMG_EXT | (OFFICE_EXT - {".msg"})
# cartelle di sistema escluse dall'indice del testo (i metadati delle immagini restano)
SKIP_TEXT_PREFIX = ("windows/", "program files", "programdata/", "$", "system/", "usr/",
                    "library/", "private/", "bin/", "sbin/", "lib/", "lib64/", "opt/",
                    "proc/", "sys/", "var/lib/", "snap/", "applications/", "boot/")
SKIP_TEXT_PART = ("/.cache/", "/node_modules/", "/site-packages/", "/appdata/local/microsoft/",
                  "/appdata/local/packages/", "/library/caches/", "/winsxs/")
MAX_EXTRACT = 50 << 20      # byte letti per file da indicizzare
MAX_TEXT = 200_000          # caratteri per riga dell'indice (i testi più lunghi vanno in più blocchi)
MAX_TEXT_TOTAL = 20_000_000  # caratteri indicizzati al massimo per file (tutti i blocchi)
TEXT_OVERLAP = 500          # sovrapposizione tra blocchi: una frase a cavallo non va persa
MAX_PDF_PAGES = 20000       # pagine lette al massimo per PDF (a blocchi di PDF_BLOCK)
PDF_BLOCK = 500
MAX_BIG_FILE = int(os.environ.get("REPERTIA_MAX_FILE_MB", "1024") or 1024) << 20
MAX_INDEX_FILES = 100_000
FEATURE_KINDS = ("email", "url", "url_searches", "domain", "telephone", "ccn", "gps", "exif",
                 "ip", "rfc822", "pii", "winlnk", "winprefetch", "vcard")
INDEX_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(source TEXT, part INTEGER, inode TEXT, deleted INTEGER,
    path TEXT, make TEXT, model TEXT, taken TEXT, lat REAL, lon REAL, author TEXT, data TEXT);
CREATE INDEX IF NOT EXISTS idx_meta_pi ON meta(part, inode);
CREATE TABLE IF NOT EXISTS carved(name TEXT, relpath TEXT, part INTEGER, size INTEGER,
    type TEXT, img_offset INTEGER, sha256 TEXT);
CREATE TABLE IF NOT EXISTS features(kind TEXT, offset TEXT, pos INTEGER, feature TEXT,
    context TEXT);
CREATE INDEX IF NOT EXISTS idx_feat ON features(kind, feature);
CREATE TABLE IF NOT EXISTS doc_text_extra(source TEXT, part INTEGER, inode TEXT, seq INTEGER,
    path TEXT, body TEXT, deleted INTEGER, kind TEXT);
CREATE INDEX IF NOT EXISTS idx_dte ON doc_text_extra(source, part, inode);
CREATE TABLE IF NOT EXISTS doc_skipped(source TEXT, part INTEGER, inode TEXT, deleted INTEGER,
    path TEXT, size INTEGER, reason TEXT, detail TEXT);
"""
DOC_COLS = "path, body, source, part, inode, deleted, kind"


def has_fts5():
    try:
        sqlite3.connect(":memory:").execute("CREATE VIRTUAL TABLE t USING fts5(a)")
        return True
    except sqlite3.Error:
        return False


def ensure_index_schema(con):
    con.executescript(INDEX_SCHEMA)
    if has_fts5():
        con.execute(f"CREATE VIRTUAL TABLE IF NOT EXISTS doc_text USING fts5({DOC_COLS}, "
                    "tokenize='unicode61 remove_diacritics 2')")
    else:
        con.execute(f"CREATE TABLE IF NOT EXISTS doc_text({DOC_COLS})")


SKIP_LABEL = {
    "testo_parziale": N_("testo indicizzato solo in parte"),
    "file_grande": N_("file troppo grande: non indicizzato (o solo in parte)"),
    "metadati_parziali": N_("metadati letti solo dall'inizio del file"),
    "pdf_solo_stringhe": N_("PDF letto come semplici stringhe (manca pdftotext)"),
    "pdf_senza_testo": N_("PDF senza livello di testo (forse una scansione)"),
    "nessun_testo": N_("nessun testo estratto (formato non riconosciuto o file danneggiato)"),
    "errore_estrazione": N_("errore durante l'estrazione del testo"),
    "lettura_fallita": N_("file non leggibile dall'immagine (struttura non valida o non supportata): non indicizzato"),
    "senza_dati": N_("contenuto non presente nella sorgente: il file è registrato senza i dati"),
}


def ensure_extra_tables(con):
    con.execute("CREATE TABLE IF NOT EXISTS doc_text_extra(source TEXT, part INTEGER, inode TEXT, "
                "seq INTEGER, path TEXT, body TEXT, deleted INTEGER, kind TEXT)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_dte ON doc_text_extra(source, part, inode)")
    con.execute("CREATE TABLE IF NOT EXISTS doc_skipped(source TEXT, part INTEGER, inode TEXT, "
                "deleted INTEGER, path TEXT, size INTEGER, reason TEXT, detail TEXT)")


def note_skipped(con, source, part, inode, deleted, path, reason, detail="", size=None):
    """Registra un file non indicizzato o indicizzato solo in parte (con il motivo)."""
    ensure_extra_tables(con)
    con.execute("DELETE FROM doc_skipped WHERE source=? AND part IS ? AND inode=? AND reason=?",
                (source, part, str(inode), reason))
    con.execute("INSERT INTO doc_skipped VALUES (?,?,?,?,?,?,?,?)",
                (source, part, str(inode), deleted, path, size, reason, detail))


def store_text(con, path, body, source, part, inode, deleted, kind):
    """Salva il testo di un file nell'indice. Il primo blocco (MAX_TEXT caratteri) sta in doc_text;
    il resto, fino a MAX_TEXT_TOTAL caratteri, in doc_text_extra a blocchi che si sovrappongono
    di poco: la ricerca li guarda tutti. Se si supera anche MAX_TEXT_TOTAL il file è segnalato."""
    body = body or ""
    con.execute(f"INSERT INTO doc_text({DOC_COLS}) VALUES (?,?,?,?,?,?,?)",
                (path, body[:MAX_TEXT], source, part, inode, deleted, kind))
    if len(body) <= MAX_TEXT:
        return
    ensure_extra_tables(con)
    con.execute("DELETE FROM doc_text_extra WHERE source=? AND part IS ? AND inode=?",
                (source, part, str(inode)))
    top = min(len(body), MAX_TEXT_TOTAL)
    for seq, i in enumerate(range(MAX_TEXT, top, MAX_TEXT), 1):
        con.execute("INSERT INTO doc_text_extra VALUES (?,?,?,?,?,?,?,?)",
                    (source, part, str(inode), seq, path,
                     body[max(0, i - TEXT_OVERLAP):min(i + MAX_TEXT, top)], deleted, kind))
    if len(body) > MAX_TEXT_TOTAL:
        note_skipped(con, source, part, inode, deleted, path, "testo_parziale",
                     tr("indicizzati i primi {MAX_TEXT_TOTAL:,} di {v1:,} caratteri").format(MAX_TEXT_TOTAL=MAX_TEXT_TOTAL, v1=len(body)).replace(",", "."))


def write_skipped_csv(case, con):
    """Elenco dei file non indicizzati o parziali, con il motivo (non_indicizzati.csv nel caso)."""
    if not fa.table_exists(con, "doc_skipped"):
        return 0
    rows = con.execute("SELECT source, part, inode, deleted, path, size, reason, detail "
                       "FROM doc_skipped ORDER BY reason, path").fetchall()
    p = case.root / "non_indicizzati.csv"
    if not rows:
        p.unlink(missing_ok=True)
        return 0
    with open(p, "w", newline="", encoding="utf-8-sig") as fh:
        wr = csv.writer(fh, delimiter=";")
        wr.writerow([tr(h) for h in ["origine", "partizione_offset", "inode", "cancellato", "percorso",
                     "motivo", "dettaglio"]])
        for src, part, ino, d, path, size, reason, detail in rows:
            wr.writerow([src, part, ino, tr("sì") if d else tr("no"), path,
                         tr(SKIP_LABEL.get(reason, reason)), detail])
    return len(rows)


def tool_version(cmd):
    try:
        cp = subprocess.run(cmd, capture_output=True, timeout=60, env=noelev_env(),
                            stdin=subprocess.DEVNULL)
    except Exception:
        return None
    out = [l.strip() for l in dec(cp.stdout + cp.stderr).splitlines() if l.strip()]
    return out[0] if out else None


XML_BREAK = re.compile(r"</(?:w:p|a:p|text:p|text:h|row|si|c)>|<(?:w:br|w:tab|text:line-break|text:tab)\b[^>]*>")


def xml_text(x):
    x = XML_BREAK.sub("\n", x)
    x = re.sub(r"<[^<>]+>", "", x)
    x = html.unescape(x)
    return re.sub(r"\n\s*\n+", "\n", re.sub(r"[ \t]+", " ", x)).strip()


def office_text(data):
    """Testo da docx/xlsx/pptx/odt/ods/odp. None se non è un documento Office."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        names = z.namelist()
    except Exception:
        return None
    num = lambda n: [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", n)]
    if "word/document.xml" in names:
        kind = "DOCX"
        pick = [n for n in names if re.fullmatch(
            r"word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml", n)]
    elif any(n.startswith("xl/") for n in names):
        kind = "XLSX"
        pick = (["xl/sharedStrings.xml"] if "xl/sharedStrings.xml" in names else []) + \
            sorted((n for n in names if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", n)), key=num)
    elif any(n.startswith("ppt/slides/") for n in names):
        kind = "PPTX"
        pick = sorted((n for n in names if re.fullmatch(r"ppt/(slides|notesSlides)/\w+\d+\.xml", n)),
                      key=num)
    elif "content.xml" in names:
        kind = "OpenDocument"
        pick = ["content.xml"]
    else:
        return None
    out = []
    for n in pick:
        try:
            if z.getinfo(n).file_size > 200 << 20:      # protezione da archivi anomali
                continue
            out.append(xml_text(z.read(n).decode("utf-8", "replace")))
        except Exception:
            continue
    return kind, "\n".join(out)


def pdf_text_file(path, notes=None):
    """Testo di un PDF su disco, a blocchi di PDF_BLOCK pagine (fino a MAX_PDF_PAGES)."""
    pages = None
    if shutil.which("pdfinfo"):
        try:
            cp = subprocess.run(["pdfinfo", str(path)], capture_output=True, timeout=120)
            m = re.search(r"^Pages:\s+(\d+)", dec(cp.stdout), re.M)
            pages = int(m.group(1)) if m else None
        except (OSError, subprocess.SubprocessError):
            pages = None
    out, first = [], 1
    while first <= MAX_PDF_PAGES:
        if pages is not None and first > pages:
            break
        last = min(first + PDF_BLOCK - 1, MAX_PDF_PAGES)
        try:
            cp = subprocess.run(["pdftotext", "-q", "-enc", "UTF-8", "-f", str(first),
                                 "-l", str(last), str(path), "-"], capture_output=True, timeout=180)
        except subprocess.TimeoutExpired:
            if not out:
                return None
            if notes is not None:
                notes.append(("testo_parziale", tr("PDF: lettura interrotta (tempo scaduto) dalla pagina {first}").format(first=first)))
            break
        txt = dec(cp.stdout).replace("\r\n", "\n")     # Windows scrive CRLF, il Mac LF
        out.append(txt)
        if pages is None and not txt.strip():
            break
        first = last + 1
    if notes is not None and pages and pages > MAX_PDF_PAGES:
        notes.append(("testo_parziale", tr("PDF di {pages} pagine: lette le prime {MAX_PDF_PAGES}").format(pages=pages, MAX_PDF_PAGES=MAX_PDF_PAGES)))
    return "".join(out)


def pdf_text(data, tmpdir, notes=None):
    if not shutil.which("pdftotext"):
        return None
    # Il file va chiuso prima di lanciare pdftotext: su Windows un file temporaneo ancora aperto
    # non può essere riaperto da un altro programma (i PDF risultavano senza testo).
    f = tempfile.NamedTemporaryFile(suffix=".pdf", dir=tmpdir, delete=False)
    try:
        with f:
            f.write(data)
        return pdf_text_file(f.name, notes)
    finally:
        try:
            os.unlink(f.name)
        except OSError:
            pass


def file_stream(case, offset, inode):
    """Contenuto di un file a blocchi (dalla cache del caso se c'è, altrimenti con icat)."""
    c = cached_copy(case, offset, inode)
    if c:
        with open(c, "rb") as fh:
            while chunk := fh.read(1 << 20):
                yield chunk
    else:
        yield from icat_stream(case, offset, inode)


def big_file_text(case, part, inode, path, head, tmp, notes):
    """File più grande del limite di lettura (MAX_EXTRACT). I PDF si copiano su disco (fino a
    MAX_BIG_FILE) e si leggono a blocchi di pagine; i file di testo si leggono in flusso fino a
    MAX_TEXT_TOTAL caratteri. Gli altri formati (Office, archivi) restano esclusi e segnalati."""
    ext = Path(path).suffix.lower()
    lim_mb = MAX_BIG_FILE >> 20
    if head.startswith(b"%PDF"):
        if not shutil.which("pdftotext"):
            notes.append(("file_grande", tr("PDF oltre {v1} MB: manca pdftotext").format(v1=MAX_EXTRACT >> 20)))
            return None
        f = tempfile.NamedTemporaryFile(suffix=".pdf", dir=tmp, delete=False)
        gen, size, ok = file_stream(case, part, inode), 0, True
        try:
            with f:
                for chunk in gen:
                    size += len(chunk)
                    if size > MAX_BIG_FILE:
                        ok = False
                        break
                    f.write(chunk)
            gen.close()
            if not ok:
                notes.append(("file_grande", tr("PDF oltre {lim_mb} MB: non indicizzato (il limite si cambia con la variabile "
                                                "REPERTIA_MAX_FILE_MB)").format(lim_mb=lim_mb)))
                return None
            t = pdf_text_file(f.name, notes)
            if t is None:
                notes.append(("file_grande", tr("PDF molto grande: lettura interrotta (tempo scaduto)")))
                return None
            return ("PDF", t) if t.strip() else (tr("PDF senza testo (forse una scansione)"), "")
        finally:
            gen.close()
            try:
                os.unlink(f.name)
            except OSError:
                pass
    if head.startswith((b"PK\x03\x04", b"\xd0\xcf\x11\xe0")):
        notes.append(("file_grande", tr("documento oltre {v1} MB: non indicizzato").format(v1=MAX_EXTRACT >> 20)))
        return None
    sample = head[:65536]
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        enc, kind = "utf-16", tr("testo UTF-16")
    elif b"\x00" in sample and ext not in TEXT_EXT:
        notes.append(("file_grande", tr("file binario oltre {v1} MB: non indicizzato").format(v1=MAX_EXTRACT >> 20)))
        return None
    else:
        try:
            sample.decode("utf-8")
            enc, kind = "utf-8", tr("testo UTF-8")
        except UnicodeDecodeError as e:
            if e.start >= len(sample) - 3 and e.reason.startswith("unexpected end"):
                enc, kind = "utf-8", tr("testo UTF-8")
            else:
                enc, kind = "cp1252", tr("testo (Windows-1252)")
    import codecs
    dcd = codecs.getincrementaldecoder(enc)(errors="replace")
    parts, n, more = [], 0, False
    gen = file_stream(case, part, inode)
    try:
        for chunk in gen:
            t = dcd.decode(chunk)
            parts.append(t)
            n += len(t)
            if n >= MAX_TEXT_TOTAL:
                more = True
                break
    finally:
        gen.close()
    text = "".join(parts)
    if more:
        text = text[:MAX_TEXT_TOTAL]
        notes.append(("testo_parziale", tr("file oltre {v1} MB: indicizzati i primi {v2:,} caratteri").format(v1=MAX_EXTRACT >> 20, v2=len(text)).replace(",", ".")))
    return kind, text


def rtf_text(t):
    t = re.sub(r"\\'([0-9a-fA-F]{2})", lambda m: bytes.fromhex(m.group(1)).decode("cp1252", "replace"), t)
    t = re.sub(r"\\u(-?\d+)\??", lambda m: chr(int(m.group(1)) % 65536), t)
    t = re.sub(r"\\(par|line)\b ?", "\n", t)
    t = re.sub(r"\{\\\*[^{}]*\}", "", t)
    t = re.sub(r"\\[a-zA-Z]+-?\d* ?", "", t)
    return re.sub(r"[{}]", "", t)


def binary_strings(data):
    a = [s.decode("cp1252", "replace") for s in
         re.findall(rb"[\x20-\x7e\xa0-\xff]{5,}", data[:20 << 20])
         if re.search(rb"[A-Za-z]{3}", s)]
    u = [s.decode("utf-16le", "replace")
         for s in re.findall(rb"(?:[\x20-\x7e\xa0-\xff]\x00){5,}", data[:20 << 20])]
    return "\n".join(a + u)


def extract_text(data, name, tmpdir, notes=None):
    """(tipo, testo) per documenti e file di testo; None per file binari non riconosciuti.
    notes (facoltativo): lista a cui si aggiungono (motivo, dettaglio) se il testo è parziale."""
    ext = Path(name).suffix.lower()
    head = data[:8]
    if head.startswith(b"PK\x03\x04"):
        r = office_text(data)
        if r:
            return r
        return None
    if head.startswith(b"%PDF"):
        t = pdf_text(data, tmpdir, notes)
        if t is None:
            if notes is not None:
                notes.append(("pdf_solo_stringhe", tr("pdftotext non disponibile o tempo scaduto")))
            return tr("PDF (pdftotext non installato: stringhe)"), binary_strings(data)
        return ("PDF", t) if t.strip() else (tr("PDF senza testo (forse una scansione)"), "")
    if head.startswith(b"{\\rtf"):
        return "RTF", rtf_text(data.decode("latin-1"))
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return tr("documento Office vecchio formato o Outlook .msg (stringhe)"), binary_strings(data)
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return tr("testo UTF-16"), data.decode("utf-16", "replace")
    sample = data[:4096]
    if b"\x00" in sample and ext not in TEXT_EXT:
        return None
    try:
        txt, kind = data.decode("utf-8"), tr("testo UTF-8")
    except UnicodeDecodeError:
        if ext not in TEXT_EXT:
            return None
        txt, kind = data.decode("cp1252", "replace"), tr("testo (Windows-1252)")
    if ext in (".html", ".htm") or re.match(r"\s*<(!doctype html|html)", txt[:200], re.I):
        txt = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", txt)
        txt = html.unescape(re.sub(r"<[^<>]+>", " ", txt))
        kind = "HTML"
    return kind, txt


def skip_for_text(path):
    p = path.lower()
    return p.startswith(SKIP_TEXT_PREFIX) or any(s in "/" + p for s in SKIP_TEXT_PART)


DATE_PRIORITY = ("DateTimeOriginal", "CreateDate", "CreationDate", "Created", "ModifyDate")
_TZ_END = re.compile(r"(Z|[+-]\d\d:?\d\d)$")
_OFFSET_TAG = {"DateTimeOriginal": "OffsetTimeOriginal", "CreateDate": "OffsetTimeDigitized",
               "ModifyDate": "OffsetTime"}


def pick_meta_date(clean):
    """Data dei metadati di un file (exiftool): in ordine di priorità (scatto, creazione, modifica), non nell'ordine
    in cui exiftool stampa i campi. Restituisce (testo, tag scelto): il testo è 'AAAA:MM:GG HH:MM:SS' e ha il
    fuso (+01:00, Z) solo se il file lo indica (OffsetTime* dell'EXIF, contenitori QuickTime che per specifica
    sono UTC, date XMP/PDF che lo contengono già); altrimenti è ora locale scritta dal dispositivo, fuso ignoto."""
    for name in DATE_PRIORITY:
        for k, v in clean.items():
            if k.split(":")[-1] != name or v in ("", None):
                continue
            s = str(v).strip()
            if not s or s.startswith("0000") or not re.match(r"\d{4}[:\-]\d\d[:\-]\d\d", s):
                continue
            if not _TZ_END.search(s):
                grp = k.split(":")[0]
                off = clean.get(f"{grp}:{_OFFSET_TAG.get(name, '')}") if name in _OFFSET_TAG else None
                if isinstance(off, str) and re.fullmatch(r"[+-]\d\d:\d\d", off.strip()):
                    s += off.strip()
                elif grp in ("QuickTime", "Track1", "Track2", "Track3", "Track4", "Movie", "Media") \
                        and name in ("CreateDate", "ModifyDate"):
                    s += "Z"            # specifica QuickTime/MP4: secondi dal 1904 in UTC
            return s, k
    return None, None


def gps_da(meta):
    """(3.0) Latitudine e longitudine con il segno. Con -G1 exiftool dà «GPS:GPSLongitude» senza segno e la direzione a parte
    (N/S/E/O), «Composite:GPSLongitude» con il segno: prima si leggeva il primo trovato e Ovest e Sud risultavano positivi."""
    def val(nome):
        c = meta.get("Composite:" + nome)
        if c not in ("", None):
            return float(c)
        for k, v in meta.items():
            if k.split(":")[-1] == nome and v not in ("", None):
                v, r = float(v), next((str(x).strip().upper() for y, x in meta.items() if y.split(":")[-1] == nome + "Ref" and x), "")
                return -abs(v) if r[:1] in ("S", "W") else v
        return None
    try:
        lat, lon = val("GPSLatitude"), val("GPSLongitude")
    except (TypeError, ValueError):
        return None, None
    if lat is None or lon is None or (lat == 0 and lon == 0):
        return None, None
    return lat, lon


def gps_ripara(case):
    """(3.0) Casi preparati prima della 3.0: ricalcola il segno delle coordinate dai metadati salvati, una volta sola, e lo
    registra. La copia forense non c'entra: cambia solo la tabella dei risultati del caso."""
    if case.meta.get("gps_segno_3") or not case.db_path.exists():
        return 0
    con = sqlite3.connect(case.db_path)
    n = 0
    try:
        if fa.table_exists(con, "meta"):
            for rid, la, lo, data in con.execute("SELECT rowid, lat, lon, data FROM meta WHERE lat IS NOT NULL").fetchall():
                try:
                    a, o = gps_da(json.loads(data or "{}"))
                except ValueError:
                    continue
                if a is not None and (a, o) != (la, lo):
                    con.execute("UPDATE meta SET lat=?, lon=? WHERE rowid=?", (a, o, rid))
                    n += 1
            con.commit()
    finally:
        con.close()
    case.meta["gps_segno_3"] = True
    if n:
        case.meta["gps_corretto"] = n
        case.log("gps_corretto", {"righe": n, "motivo": tr("segno di latitudine e longitudine dei metadati, ricalcolato dai valori salvati")})
    case.save()
    return n


def exif_run(con, target, mapping):
    """Esegue exiftool su un file o una cartella; mapping: percorso -> (source, part, inode,
    deleted, percorso da mostrare). Inserisce i risultati nella tabella meta."""
    if not mapping or not shutil.which("exiftool"):
        return 0, 0
    cmd = ["exiftool", "-j", "-n", "-G1", "-q", "-q", "-charset", "filename=utf8"]
    if Path(target).is_dir():
        cmd.append("-r")
    try:
        cp = subprocess.run(cmd + [str(target)], capture_output=True, timeout=3600)
        items = json.loads(dec(cp.stdout) or "[]")
    except Exception:
        return 0, 0
    n = gps = 0
    for it in items:
        info = mapping.get(str(Path(it.get("SourceFile", "")).resolve()))
        if not info:
            continue
        clean = {k: v for k, v in it.items() if k != "SourceFile"
                 and k.split(":")[0] not in ("System", "File", "ExifTool")}
        if not clean:
            continue

        def g(*keys):
            for k, v in clean.items():
                if k.split(":")[-1] in keys and v not in ("", None):
                    return v
            return None
        taken, taken_tag = pick_meta_date(clean)
        if taken_tag:
            clean["RepertIA:DataScelta"] = taken_tag      # da quale campo viene la data mostrata
        lat, lon = gps_da(clean)
        con.execute("INSERT INTO meta VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (*info, g("Make"), g("Model"),
                     taken,
                     lat, lon, author_of(clean),
                     json.dumps(clean, ensure_ascii=False, default=str)[:20000]))
        n += 1
        gps += lat is not None
    return n, gps


def author_of(meta):
    """Autore di un documento o di una foto; per i PDF 'Creator' è il programma, non la persona."""
    pick = lambda *names: next((str(v) for k, v in meta.items() if k.split(":")[-1] in names
                                and not (k.startswith("PDF:") and k.endswith("Creator"))
                                and v not in ("", None)), None)
    who = pick("Author", "Creator", "Artist")
    last = pick("LastModifiedBy")
    if who and last and last != who:
        return tr("{who} (ultima modifica: {last})").format(who=who, last=last)
    return who or (tr("ultima modifica: {last}").format(last=last) if last else None)


def build_index(case, con):
    """Testo dei documenti (ricercabile) e metadati di foto, video e documenti."""
    ensure_index_schema(con)
    con.execute("DELETE FROM doc_text WHERE source='fs'")
    con.execute("DELETE FROM meta WHERE source='fs'")
    if not shutil.which("exiftool"):
        print(tr("exiftool non installato: indicizzo solo il testo ({v1}).").format(v1=install_hint('exiftool')))
    if not shutil.which("pdftotext"):
        print(tr("pdftotext non installato: dei PDF leggo solo le stringhe ({v1}).").format(v1=install_hint('poppler')))
    ensure_extra_tables(con)
    con.execute("DELETE FROM doc_text_extra WHERE source='fs'")
    con.execute("DELETE FROM doc_skipped WHERE source='fs'")
    rows = con.execute("SELECT part, inode, deleted, path FROM files "
                       "WHERE type LIKE '%/r' ORDER BY deleted, path").fetchall()
    todo = []
    skip = skip_for_text
    if is_mobile(case):                  # smartphone: i dati dell'utente stanno proprio in private/var e data/
        import forense_mobile as fm
        skip = fm.skip_for_text
    for part, inode, deleted, path in rows:
        ext = Path(path).suffix.lower()
        want_text = ext in DOC_EXT and not skip(path)
        want_meta = ext in META_EXT
        if want_text or want_meta:
            todo.append((part, inode, deleted, path, want_text, want_meta))
    avvisi = []
    if len(todo) > MAX_INDEX_FILES:
        print(tr("Trovati {v1} file: indicizzo i primi {MAX_INDEX_FILES}.").format(v1=len(todo), MAX_INDEX_FILES=MAX_INDEX_FILES))
        avvisi.append(tr("Trovati {v1} file da indicizzare: indicizzati solo i primi {MAX_INDEX_FILES}.").format(v1=len(todo), MAX_INDEX_FILES=MAX_INDEX_FILES))
        todo = todo[:MAX_INDEX_FILES]
    print(tr("Indicizzazione testo e metadati: {v1} file da esaminare...").format(v1=len(todo)), flush=True)
    tmp = case.root / "tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir()
    texts = metas = gps = 0
    mapping, seen = {}, set()
    stats = {}      # gruppo di file -> [con testo da cercare, con testo indicizzato]
    n_meta_cand = 0

    def group(ext):
        return ("PDF" if ext == ".pdf" else tr("documenti Office/OpenDocument") if ext in OFFICE_EXT
                else tr("file di testo"))

    def flush():
        nonlocal metas, gps
        a, b = exif_run(con, tmp, mapping)
        metas += a
        gps += b
        for f in mapping:
            Path(f).unlink(missing_ok=True)
        mapping.clear()

    for k, (part, inode, deleted, path, want_text, want_meta) in enumerate(todo, 1):
        if (part, inode) in seen:
            continue
        seen.add((part, inode))
        ext = Path(path).suffix.lower()
        try:
            data = fa.icat_read(case, part, inode, MAX_EXTRACT)
        except Exception as e:
            # (3.0.2) un file illeggibile (es. voce di un AD1 con la tabella dei blocchi non valida: «struct.error: total
            # struct size too long» da dissect.evidence) fermava tutta la preparazione: ora resta tra i non indicizzati,
            # con il motivo, e si va avanti
            note_skipped(con, "fs", part, inode, deleted, path, getattr(e, "motivo", "lettura_fallita"),
                         str(e)[:200] if hasattr(e, "motivo") else f"{type(e).__name__}: {str(e)[:200]}")
            continue
        if data and want_text:
            g = stats.setdefault(group(ext), [0, 0])
            g[0] += 1
            notes = []
            try:
                if len(data) >= MAX_EXTRACT:       # file più grande del limite di lettura
                    r = big_file_text(case, part, inode, path, data, tmp, notes)
                else:
                    r = extract_text(data, path, tmp, notes)
            except Exception as e:
                r = None
                notes.append(("errore_estrazione", str(e)[:200]))
            if r and r[1].strip():
                store_text(con, path, r[1], "fs", part, inode, deleted, r[0])
                texts += 1
                g[1] += 1
            elif r is None and not notes:
                notes.append(("nessun_testo", tr("formato non riconosciuto o file danneggiato")))
            elif r and r[0].startswith("PDF senza testo"):
                notes.append(("pdf_senza_testo", tr("forse una scansione: serve l'OCR")))
            for reason, detail in notes:
                note_skipped(con, "fs", part, inode, deleted, path, reason, detail)
        if want_meta:
            n_meta_cand += 1
            if len(data) >= MAX_EXTRACT:
                note_skipped(con, "fs", part, inode, deleted, path, "metadati_parziali",
                             tr("letti solo i primi {v1:g} MB del file: i metadati in fondo al file possono mancare").format(v1=MAX_EXTRACT / (1 << 20)))
        if data and want_meta:
            f = tmp / f"{part}_{inode}{Path(path).suffix.lower()}"
            f.write_bytes(data)
            mapping[str(f.resolve())] = ("fs", part, inode, deleted, path)
            if len(mapping) >= 200:
                flush()
        fa.avanz(fatti=k, totale=len(todo))
        if k % 500 == 0:
            con.commit()
            print(tr("  {k} di {v1} file esaminati...").format(k=k, v1=len(todo)), flush=True)
    flush()
    con.commit()
    shutil.rmtree(tmp, ignore_errors=True)
    print(tr("Documenti con testo: {texts}; file con metadati: {metas} (con GPS: {gps})").format(texts=texts, metas=metas, gps=gps))
    # controllo di coerenza: file candidati e file effettivamente indicizzati
    if not shutil.which("pdftotext") and stats.get("PDF"):
        avvisi.append(tr("pdftotext non disponibile: {v1} PDF letti solo come stringhe.").format(v1=stats['PDF'][0]))
    if shutil.which("pdftotext") and stats.get("PDF", [0, 0])[0] >= 3 and stats["PDF"][1] == 0:
        avvisi.append(tr("Nessuno dei {v1} PDF ha testo estratto: se non sono tutte scansioni, controllare "
                         "pdftotext.").format(v1=stats['PDF'][0]))
    for gname, (cand, ok) in stats.items():
        if gname != "PDF" and cand >= 10 and ok == 0:
            avvisi.append(tr("Nessuno dei {cand} {gname} ha testo estratto: controllare gli strumenti.").format(cand=cand, gname=gname))
    if shutil.which("exiftool") and n_meta_cand >= 3 and metas == 0:
        avvisi.append(tr("Nessun metadato estratto da {n_meta_cand} file: controllare exiftool.").format(n_meta_cand=n_meta_cand))
    for w in avvisi:
        print(tr("Attenzione: ") + w)
    n_skip = con.execute("SELECT COUNT(*) FROM doc_skipped WHERE source='fs'").fetchone()[0]
    if n_skip:
        print(tr("File non indicizzati o indicizzati solo in parte: {n_skip} (elenco in non_indicizzati.csv)").format(n_skip=n_skip))
    write_skipped_csv(case, con)
    tv = case.meta.setdefault("tool_versions", {})
    for name, cmd in (("exiftool", ["exiftool", "-ver"]), ("pdftotext", ["pdftotext", "-v"])):
        if shutil.which(cmd[0]):
            tv[name] = tool_version(cmd)
    media = None
    if True:                    # (3.0.1) foto, video e audio riconosciuti dal contenuto (anche nelle cache), per app o cartella
        import forense_mobile_media as fmm
        try:
            media = fmm.run(case, con, lambda x: print(x, flush=True))
        except Exception as e:
            avvisi.append(tr("Foto, video e audio per contenuto: non completato ({vname}: {e})").format(vname=type(e).__name__, e=e))
            print(tr("Attenzione: ") + avvisi[-1], flush=True)
    return {"documenti": texts, "metadati": metas, "gps": gps, "ts": now(),
            "non_indicizzati": n_skip, "avvisi": avvisi, "media": media,
            "copertura": {g: {"candidati": a, "con_testo": b} for g, (a, b) in stats.items()}}
