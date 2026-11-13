#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - strumenti che l'agente IA può chiamare.

(3.0.4) Codice spostato da forense_agent.py senza modifiche, per avere file più corti. Si carica tramite
forense_agent, che ne riesporta i nomi: gli altri moduli continuano a usare «fa.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fa.<nome>»).
"""
import hashlib
import inspect
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path
from forense_lingua import tr
import forense_apfs as ap

import forense_agent as fa
from forense_agent import (
    FINDING_IA, INODE_RE, MAX_TEXT, SKIP_LABEL, add_finding, clip, dec, icat_stream, is_mobile, istat_zona, like,
    pagina, sh, show_text, table_exists, tsk_tz)

# ----------------------------------------------------------------- strumenti

def make_tools(case):
    parts = {p["offset"]: p for p in case.meta["partitions"] if p["readable"]}

    def _off(offset):
        o = int(offset)
        if o not in parts:
            raise ValueError(tr("offset {o} non valido. Offset leggibili: {v1}").format(o=o, v1=sorted(parts)))
        return o

    def _ino(inode):
        i = str(inode).strip()
        if not INODE_RE.fullmatch(i):
            raise ValueError(tr("inode non valido (atteso es. 1234 oppure 1234-128-1)"))
        return i

    def _db():
        return sqlite3.connect(case.db_path.as_uri() + "?mode=ro", uri=True)

    try:
        fts = "fts5" in (_db().execute("SELECT sql FROM sqlite_master WHERE name='doc_text'")
                         .fetchone() or [""])[0].lower()
    except sqlite3.Error:
        fts = False

    def _name(o, i):
        con = _db()
        r = con.execute("SELECT path FROM files WHERE part=? AND inode=? LIMIT 1",
                        (o, i)).fetchone()
        con.close()
        return r[0] if r else f"inode_{i}"

    def _where(start, end, contains, origin):
        w, p = [], []
        if start:
            w.append("ts >= ?")
            p.append(start)
        if end:
            w.append("ts <= ?")
            p.append(end if "T" in end else end + "T23:59:59")
        if contains:
            w.append("(path LIKE ? ESCAPE '\\' OR message LIKE ? ESCAPE '\\' "
                     "OR source LIKE ? ESCAPE '\\')")
            p += [like(contains)] * 3
        if origin:
            w.append("origin = ?")
            p.append(origin)
        return (" WHERE " + " AND ".join(w)) if w else "", p

    def case_overview() -> str:
        """Riepilogo del caso: immagine, hash, partizioni, file system, sistema operativo, timeline."""
        keys = ("image", "sha256", "disk_type", "partitions", "timeline")
        return clip(json.dumps({k: case.meta.get(k) for k in keys}, indent=1, ensure_ascii=False))

    def fs_info(offset: int) -> str:
        """Dettagli del file system di una partizione (etichetta, seriale, date, dimensione cluster).

        Args:
            offset: offset della partizione in settori
        """
        if ap.is_apfs_part(_off(offset)):
            a = parts[_off(offset)]["apfs"]
            return clip(json.dumps({k: a.get(k) for k in ("name", "role", "uuid", "encrypted", "vol")},
                                   ensure_ascii=False, indent=1) + tr("\nFile system APFS (libfsapfs)"))
        if is_mobile(case):
            import forense_mobile as fm
            return clip(fm.fs_info_text(case, _off(offset)))
        cp = sh(case, ["fsstat", "-o", str(_off(offset)), case.image], timeout=600)
        return clip(dec(cp.stdout + cp.stderr))

    def list_directory(offset: int, inode: str = "") -> str:
        """Elenca il contenuto di una directory, inclusi i file cancellati (segnati con *).

        Args:
            offset: offset della partizione in settori
            inode: inode della directory; vuoto per la radice
        """
        if ap.is_apfs_part(_off(offset)):
            return list_directory_apfs(_off(offset), inode)
        if is_mobile(case):
            import forense_mobile as fm
            return clip(fm.list_dir_text(case, _off(offset), inode))
        cmd = ["fls", "-o", str(_off(offset)), case.image]
        if inode:
            cmd.append(_ino(inode))
        cp = sh(case, cmd, timeout=600)
        return clip(dec(cp.stdout + cp.stderr))

    def list_directory_apfs(o, inode):
        if inode:
            c, v, e = ap._entry(case, o, inode)
        else:
            c, v = ap.volume(case, o)
            with c.lock:
                e = v.get_root_directory()
        out = []
        with c.lock:
            for i in range(e.get_number_of_sub_file_entries()):
                s = e.get_sub_file_entry(i)
                out.append(f"{ap._ftype(s.file_mode)} {s.identifier}:\t{s.name}")
        return clip("\n".join(out))

    def find_files(offset: int, name_contains: str = "", deleted_only: bool = False,
                   limit: int = 100, salta: int = 0) -> str:
        """Cerca file per parte del percorso (senza distinzione maiuscole/minuscole).

        Args:
            offset: offset della partizione in settori
            name_contains: testo nel percorso, es. '.docx' o 'Users/mario'; vuoto per tutti
            deleted_only: se true restituisce solo i file cancellati
            limit: numero massimo di risultati (max 500)
            salta: righe da saltare, per proseguire dopo una risposta incompleta
        """
        o = _off(offset)
        only_del = str(deleted_only).lower() in ("true", "1", "yes", "si")
        limit = max(1, min(int(limit), 500))
        cond = "part=? AND path LIKE ? ESCAPE '\\'" + (" AND deleted>=1" if only_del else "")
        a = (o, like(name_contains))
        con = _db()
        total = con.execute(f"SELECT COUNT(*) FROM files WHERE {cond}", a).fetchone()[0]
        rows = con.execute(f"SELECT deleted, type, inode, path FROM files WHERE {cond} "
                           "ORDER BY rowid LIMIT ? OFFSET ?", a + (limit, max(0, int(salta)))).fetchall()
        con.close()
        lines = [f'{"*" if d else " "} {t} {i}\t{p}' for d, t, i, p in rows]
        return pagina(lines, total, salta, tr("* = cancellato. Per proseguire il parametro si chiama «salta» (qui offset è la partizione)."))

    def file_metadata(offset: int, inode: str) -> str:
        """Metadati di un file: timestamp, dimensione, attributi, cluster (istat).

        Args:
            offset: offset della partizione in settori
            inode: inode del file
        """
        if ap.is_apfs_part(_off(offset)):
            return clip(ap.istat_text(case, _off(offset), _ino(inode)))
        if is_mobile(case):
            import forense_mobile as fm
            return clip(fm.istat_text(case, _off(offset), _ino(inode)))
        cp = sh(case, ["istat", *tsk_tz(case), "-o", str(_off(offset)), case.image, _ino(inode)], timeout=600)
        return clip(istat_zona(case, _off(offset), dec(cp.stdout + cp.stderr), _ino(inode)))

    def _show(data, name, max_chars, start=0):
        return show_text(data, name, case.root, min(int(max_chars), fa.MAX_OUT), start)

    def read_file_text(offset: int, inode: str, max_chars: int = 8000, start: int = 0) -> str:
        """Legge un file a porzioni. Dai documenti (docx, xlsx, pptx, odt, pdf, rtf) estrae il
        testo vero; dai file binari le stringhe leggibili. Mostra anche i primi byte (magic
        number). Se il testo è più lungo della porzione, in fondo dice quanto manca e con quale
        valore di start proseguire.

        Args:
            offset: offset della partizione in settori
            inode: inode del file
            max_chars: caratteri massimi da restituire per volta
            start: carattere da cui iniziare (0 = dall'inizio; per continuare usa il valore
                   indicato in fondo alla risposta precedente)
        """
        o, i = _off(offset), _ino(inode)
        data = fa.icat_read(case, o, i, 50 << 20)
        if not data:
            return tr("File vuoto o non recuperabile.")
        return _show(data, _name(o, i), max_chars, start)

    def file_exif(offset: int, inode: str) -> str:
        """Tutti i metadati di un file con exiftool: fotocamera, data di scatto, GPS,
        autore e date dei documenti, software usato.

        Args:
            offset: offset della partizione in settori
            inode: inode del file
        """
        if not shutil.which("exiftool"):
            return tr("exiftool non installato.")
        o, i = _off(offset), _ino(inode)
        data = fa.icat_read(case, o, i, 200 << 20)
        if not data:
            return tr("File vuoto o non recuperabile.")
        f = tempfile.NamedTemporaryFile(suffix=Path(_name(o, i)).suffix, dir=case.root,
                                        delete=False)
        try:
            with f:         # chiuso prima di exiftool (su Windows un file aperto non si riapre)
                f.write(data)
            cp = subprocess.run(["exiftool", "-G1", "-s", "-c", "%.6f", f.name],
                                capture_output=True, timeout=120)
        finally:
            try:
                os.unlink(f.name)
            except OSError:
                pass
        lines = [l for l in dec(cp.stdout).splitlines()
                 if not re.match(r"\[(System|ExifTool)\]", l)]
        return clip(tr("Metadati di {v1}:\n").format(v1=_name(o, i)) + "\n".join(lines))

    def search_text(query: str, limit: int = 30, offset: int = 0) -> str:
        """Cerca parole dentro il testo dei documenti (Word, Excel, PowerPoint, PDF, OpenDocument,
        RTF, testo, email) e dei file recuperati col carving. Restituisce file e frammento.

        Args:
            query: parole da cercare (devono comparire tutte), es. 'bonifico Rossi';
                   una frase esatta va tra virgolette
            limit: numero massimo di risultati (max 100)
            offset: righe da saltare, per proseguire dopo una risposta incompleta
        """
        limit, offset = max(1, min(int(limit), 100)), max(0, int(offset))
        terms = re.findall(r'"[^"]+"|[^\s"]+', query)
        if not terms:
            return tr("Indica almeno una parola.")
        con = _db()
        try:
            if fts:
                q = " ".join('"' + t.strip('"').replace('"', "") + '"' for t in terms)
                total = con.execute("SELECT COUNT(*) FROM doc_text WHERE doc_text MATCH ?",
                                    (q,)).fetchone()[0]
                rows = con.execute(
                    "SELECT source, part, inode, deleted, path, kind, "
                    "snippet(doc_text, 1, '[', ']', ' … ', 16) FROM doc_text "
                    "WHERE doc_text MATCH ? ORDER BY rank, rowid LIMIT ? OFFSET ?", (q, limit, offset)).fetchall()
            else:
                w = " AND ".join(["(body LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\')"] * len(terms))
                a = [x for t in terms for x in (like(t.strip('"')),) * 2]
                total = con.execute(f"SELECT COUNT(*) FROM doc_text WHERE {w}", a).fetchone()[0]
                rows = con.execute(f"SELECT source, part, inode, deleted, path, kind, "
                                   f"substr(body, 1, 200) FROM doc_text WHERE {w} ORDER BY rowid LIMIT ? OFFSET ?",
                                   a + [limit, offset]).fetchall()
            # testi lunghi: i blocchi oltre i primi MAX_TEXT caratteri stanno in doc_text_extra
            if table_exists(con, "doc_text_extra"):
                w2 = " AND ".join(["body LIKE ? ESCAPE '\\'"] * len(terms))
                a2 = [like(t.strip('"')) for t in terms]
                known = {(r[0], r[1], str(r[2])) for r in rows}
                added = set()
                for src, part, ino, d, path, kind, body in con.execute(
                        f"SELECT source, part, inode, deleted, path, kind, body FROM doc_text_extra "
                        f"WHERE {w2} LIMIT 500", a2).fetchall():
                    key = (src, part, str(ino))
                    if key in known or key in added:
                        continue
                    added.add(key)
                    total += 1
                    if not offset and len(rows) < limit:
                        low = body.lower()
                        pos = min([low.find(t.strip('"').lower()) for t in terms
                                   if low.find(t.strip('"').lower()) >= 0] or [0])
                        rows.append((src, part, ino, d, path, kind + tr(" · oltre i primi {MAX_TEXT:,} caratteri").format(MAX_TEXT=MAX_TEXT).replace(",", "."),
                                     body[max(0, pos - 80):pos + 160]))
        finally:
            con.close()
        out = []
        for src, part, ino, d, path, kind, snip in rows:
            where = (tr("recuperato col carving: {ino} (usa read_carved)").format(ino=ino) if src == "carving"
                     else tr("offset {part}, inode {ino}{v1}").format(part=part, ino=ino, v1=tr(' CANCELLATO') if d else ''))
            out.append(f"- {path} [{kind}; {where}]\n  {' '.join(snip.split())}")
        return pagina(out, total, offset)

    def list_not_indexed(reason: str = "", limit: int = 50) -> str:
        """Elenca i file il cui testo NON è stato indicizzato o lo è solo in parte (file troppo
        grandi, testo oltre il limite, PDF senza testo, estrazione fallita), con il motivo.
        Per questi file search_text non basta: va letto il file (read_file_text).

        Args:
            reason: filtro sul motivo (es. 'grande', 'parziale', 'scansione'); vuoto = tutti
            limit: numero massimo di righe (max 200)
        """
        limit = max(1, min(int(limit), 200))
        con = _db()
        try:
            if not table_exists(con, "doc_skipped"):
                return tr("Nessun elenco: l'indicizzazione del testo non è stata eseguita con questa versione.")
            rows = con.execute("SELECT source, part, inode, deleted, path, reason, detail "
                               "FROM doc_skipped ORDER BY reason, path").fetchall()
        finally:
            con.close()
        if reason:
            r = reason.lower()
            rows = [x for x in rows if r in (x[5] + " " + tr(SKIP_LABEL.get(x[5], ""))).lower()
                    or r in (x[6] or "").lower()]
        if not rows:
            return tr("Nessun file non indicizzato (con questo filtro).")
        by = {}
        for x in rows:
            by[x[5]] = by.get(x[5], 0) + 1
        out = [tr("{v1} file non indicizzati o parziali: ").format(v1=len(rows))
               + "; ".join(f"{tr(SKIP_LABEL.get(k, k))} {n}" for k, n in by.items())]
        for src, part, ino, d, path, rs, detail in rows[:limit]:
            where = (tr("carving: {ino}").format(ino=ino) if src == "carving"
                     else tr("offset {part}, inode {ino}{v1}").format(part=part, ino=ino, v1=tr(' CANCELLATO') if d else ''))
            out.append(f"- {path} [{tr(SKIP_LABEL.get(rs, rs))}; {where}] {detail or ''}")
        if len(rows) > limit:
            out.append(tr("... altri {v1} (elenco completo in non_indicizzati.csv)").format(v1=len(rows) - limit))
        return clip("\n".join(out))

    def search_metadata(contains: str = "", gps_only: bool = False, limit: int = 50, offset: int = 0) -> str:
        """Cerca nei metadati di foto, video e documenti (marca e modello del dispositivo,
        data di scatto o creazione, coordinate GPS, autore). Senza filtri dà un riepilogo.

        Args:
            contains: testo da cercare nei metadati o nel percorso, es. 'iPhone', 'Rossi', '2024:03'
            gps_only: se true mostra solo i file con coordinate GPS
            limit: numero massimo di risultati (max 300)
            offset: righe da saltare, per proseguire dopo una risposta incompleta
        """
        only_gps = str(gps_only).lower() in ("true", "1", "yes", "si")
        con = _db()
        try:
            if not contains and not only_gps:
                tot, gps = con.execute("SELECT COUNT(*), COUNT(lat) FROM meta").fetchone()
                devs = con.execute("SELECT make || ' ' || model, COUNT(*) FROM meta WHERE model "
                                   "IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 15").fetchall()
                auth = con.execute("SELECT author, COUNT(*) FROM meta WHERE author IS NOT NULL "
                                   "GROUP BY 1 ORDER BY 2 DESC LIMIT 15").fetchall()
                rng = con.execute("SELECT MIN(taken), MAX(taken) FROM meta WHERE taken "
                                  "IS NOT NULL").fetchone()
                out = [tr("File con metadati: {tot}; con coordinate GPS: {gps}").format(tot=tot, gps=gps),
                       tr("Date (scatto/creazione): da {v1} a {v2}").format(v1=rng[0], v2=rng[1]), "", tr("Dispositivi:")]
                out += [f"  {d}: {n}" for d, n in devs] or ["  -"]
                out += ["", tr("Autori dei documenti:")] + ([f"  {a}: {n}" for a, n in auth] or ["  -"])
                return "\n".join(out)
            w, a = [], []
            if contains:
                w.append("(data LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\')")
                a += [like(contains)] * 2
            if only_gps:
                w.append("lat IS NOT NULL")
            cond = " AND ".join(w)
            limit = max(1, min(int(limit), 300))
            total = con.execute(f"SELECT COUNT(*) FROM meta WHERE {cond}", a).fetchone()[0]
            rows = con.execute(f"SELECT source, part, inode, deleted, path, make, model, taken, "
                               f"lat, lon, author FROM meta WHERE {cond} ORDER BY taken, rowid "
                               f"LIMIT ? OFFSET ?", a + [limit, max(0, int(offset))]).fetchall()
        finally:
            con.close()
        out = []
        for src, part, ino, d, path, mk, md, tk, lat, lon, au in rows:
            ref = (tr("carving: {ino}").format(ino=ino) if src == "carving"
                   else tr("offset {part}, inode {ino}{v1}").format(part=part, ino=ino, v1=tr(' CANCELLATO') if d else ''))
            info = [x for x in (" ".join(y for y in (mk, md) if y) or None,
                                f"data {tk}" if tk else None,
                                f"GPS {lat:.6f},{lon:.6f}" if lat is not None else None,
                                f"autore {au}" if au else None) if x]
            out.append(f"- {path} [{ref}] " + "; ".join(info))
        return pagina(out, total, offset)

    def carved_files(type: str = "", limit: int = 100, offset: int = 0) -> str:
        """File recuperati con PhotoRec dallo spazio libero (file cancellati il cui indice non
        esiste più). Senza filtri dà anche il riepilogo per tipo.

        Args:
            type: estensione da filtrare, es. 'jpg', 'pdf', 'docx'; vuoto per tutti
            limit: numero massimo di risultati (max 500)
            offset: righe da saltare, per proseguire dopo una risposta incompleta
        """
        limit = max(1, min(int(limit), 500))
        t = type.lower().lstrip(".")
        con = _db()
        try:
            summ = con.execute("SELECT type, COUNT(*) FROM carved GROUP BY 1 ORDER BY 2 DESC").fetchall()
            cond, a = ("WHERE type = ?", [t]) if t else ("", [])
            rows = con.execute(f"SELECT name, type, size, part, img_offset, sha256 FROM carved "
                               f"{cond} ORDER BY img_offset, rowid LIMIT ? OFFSET ?", a + [limit, max(0, int(offset))]).fetchall()
            totale = con.execute(f"SELECT COUNT(*) FROM carved {cond}", a).fetchone()[0]
        finally:
            con.close()
        testa = tr("Per tipo: ") + (", ".join(f"{k} {n}" for k, n in summ) or tr("nessun file recuperato"))
        out = [tr("- {n} | {ty} | {sz} byte | partizione {p} | byte {off} nell'immagine | SHA-256 {v1}…").format(n=n, ty=ty, sz=sz, p=p, off=off, v1=h[:16]) for n, ty, sz, p, off, h in rows]
        return pagina(out, totale, offset, testa)

    def read_carved(name: str, max_chars: int = 8000, start: int = 0) -> str:
        """Legge un file recuperato col carving (testo dei documenti, stringhe dei binari)
        e ne mostra i metadati se presenti. Se il testo è lungo si legge a porzioni.

        Args:
            name: nome del file recuperato, es. 'f0002074.jpg'
            max_chars: caratteri massimi da restituire per volta
            start: carattere da cui iniziare (per continuare usa il valore indicato in fondo
                   alla risposta precedente)
        """
        con = _db()
        try:
            r = con.execute("SELECT relpath, img_offset, sha256 FROM carved WHERE name = ?",
                            (name.strip(),)).fetchone()
            m = con.execute("SELECT data FROM meta WHERE source='carving' AND inode = ?",
                            (name.strip(),)).fetchone()
        finally:
            con.close()
        if not r:
            return tr("Nessun file recuperato con nome {name}.").format(name=name)
        f = case.root / r[0]
        head = tr("File {v1} (byte {v2} nell'immagine, SHA-256 {v3})\n").format(v1=r[0], v2=r[1], v3=r[2])
        if m:
            head += tr("Metadati: ") + m[0][:2000] + "\n"
        return head + _show(f.read_bytes()[:50 << 20], f.name, max_chars, start)

    def search_traces(kind: str = "", contains: str = "", limit: int = 100, offset: int = 0) -> str:
        """Tracce trovate da bulk_extractor in tutta l'immagine, anche nello spazio libero e nei
        file cancellati: email, url, ricerche web, telefoni, carte di credito, coordinate GPS, IP.
        Senza filtri dà il riepilogo con i valori più frequenti.

        Args:
            kind: tipo: email, url, url_searches, domain, telephone, ccn, gps, exif, ip,
                  rfc822, pii, winlnk, winprefetch, vcard; vuoto per tutti
            contains: testo da cercare nel valore o nel contesto
            limit: numero massimo di risultati (max 300)
            offset: righe da saltare, per proseguire dopo una risposta incompleta
        """
        con = _db()
        try:
            if not kind and not contains:
                out = [tr("Tracce per tipo:")]
                for k, n in con.execute("SELECT kind, COUNT(*) FROM features GROUP BY 1 "
                                        "ORDER BY 2 DESC").fetchall():
                    top = con.execute("SELECT feature, COUNT(*) FROM features WHERE kind=? "
                                      "GROUP BY 1 ORDER BY 2 DESC LIMIT 8", (k,)).fetchall()
                    out.append(tr("- {k}: {n} (più frequenti: ").format(k=k, n=n)
                               + ", ".join(f"{v[:60]} ×{c}" for v, c in top) + ")")
                return clip("\n".join(out))
            w, a = [], []
            if kind:
                w.append("kind = ?")
                a.append(kind.strip().lower())
            if contains:
                w.append("(feature LIKE ? ESCAPE '\\' OR context LIKE ? ESCAPE '\\')")
                a += [like(contains)] * 2
            cond = " AND ".join(w)
            limit = max(1, min(int(limit), 300))
            total = con.execute(f"SELECT COUNT(*) FROM features WHERE {cond}", a).fetchone()[0]
            rows = con.execute(f"SELECT kind, offset, feature, context FROM features WHERE {cond} "
                               f"ORDER BY pos, rowid LIMIT ? OFFSET ?", a + [limit, max(0, int(offset))]).fetchall()
        finally:
            con.close()
        out = [tr("- [{k}] byte {o} | {v1} | contesto: {v2}").format(k=k, o=o, v1=v, v2=c[:160]) for k, o, v, c in rows]
        return pagina(out, total, offset, tr("Offset in byte dall'inizio dell'immagine (usa locate_offset per sapere a quale file appartengono)."))

    bsize = {}

    def _block_size(o):
        if o not in bsize:
            t = dec(sh(case, ["fsstat", "-o", str(o), case.image], timeout=600).stdout)
            fs = (parts[o].get("fs") or "").upper()
            keys = (["Sector Size"] if "FAT" in fs else []) + ["Block Size", "Cluster Size",
                                                               "Sector Size"]
            bsize[o] = next((int(m.group(1)) for k in keys
                             for m in [re.search(k + r":\s*(\d+)", t)] if m), 512)
        return bsize[o]

    def locate_offset(byte_offset: str) -> str:
        """Indica a quale partizione e a quale file appartiene un byte dell'immagine
        (es. l'offset di una traccia o di un file recuperato), oppure se è spazio libero.

        Args:
            byte_offset: offset in byte dall'inizio dell'immagine, es. '2314763'
        """
        m = re.match(r"\d+", str(byte_offset).strip())
        if not m:
            return tr("Offset non valido.")
        b = int(m.group())
        for p in case.meta["partitions"]:
            start = (p["apfs"]["real_offset"] if p.get("apfs") else p["offset"]) * 512
            end = start + p["length_sectors"] * 512 if p.get("length_sectors") else None
            if b < start or (end is not None and b >= end):
                continue
            if not p["readable"]:
                return tr("Byte {b}: partizione offset {offset} non leggibile da TSK.").format(b=b, offset=p['offset'])
            if ap.is_apfs_part(p["offset"]):
                return (tr("Byte {b}: dentro il contenitore APFS (volumi: ").format(b=b) + ", ".join(
                    q["apfs"]["name"] for q in case.meta["partitions"] if q.get("apfs")
                    and q["apfs"]["real_offset"] == p["apfs"]["real_offset"]) +
                    tr("). La localizzazione del file da un byte non è supportata per APFS."))
            bs = _block_size(p["offset"])
            blk = (b - start) // bs
            cp = sh(case, ["ifind", "-o", str(p["offset"]), "-d", str(blk), case.image],
                    timeout=600)
            ino = dec(cp.stdout).strip()
            base = tr("Byte {b}: partizione offset {offset}, blocco {blk} (da {bs} byte)").format(b=b, offset=p['offset'], blk=blk, bs=bs)
            if cp.returncode != 0 or not INODE_RE.fullmatch(ino):
                return base + tr(": nessun file lo usa (spazio non allocato o metadati).")
            con = _db()
            r = con.execute("SELECT path, deleted FROM files WHERE part=? AND inode=? LIMIT 1",
                            (p["offset"], ino)).fetchone()
            con.close()
            path = r[0] if r else tr("(percorso sconosciuto)")
            return base + tr(": inode {ino} {path}").format(ino=ino, path=path) + (tr(" (CANCELLATO)") if r and r[1] else "")
        return tr("Byte {b}: fuori dalle partizioni (es. spazio tra partizioni).").format(b=b)

    def file_hash(offset: int, inode: str) -> str:
        """Calcola SHA-256 e dimensione del contenuto di un file.

        Args:
            offset: offset della partizione in settori
            inode: inode del file
        """
        o, i = _off(offset), _ino(inode)
        h, n = hashlib.sha256(), 0
        for c in icat_stream(case, o, i):
            h.update(c)
            n += len(c)
        return tr("SHA-256 {v1} ({n} byte) {v2}").format(v1=h.hexdigest(), n=n, v2=_name(o, i))

    def export_file(offset: int, inode: str) -> str:
        """Esporta un file nella cartella export del caso (sola lettura) con il suo SHA-256.

        Args:
            offset: offset della partizione in settori
            inode: inode del file
        """
        o, i = _off(offset), _ino(inode)
        name = re.sub(r"[^\w.\-]+", "_", Path(_name(o, i)).name)[:100] or "file"
        dest = case.export_dir / f"p{o}_i{i}_{name}"
        if dest.exists():
            return tr("Già esportato: {dest}").format(dest=dest)
        h, n = hashlib.sha256(), 0
        with open(dest, "wb") as f:
            for c in icat_stream(case, o, i):
                f.write(c)
                h.update(c)
                n += len(c)
        dest.chmod(0o444)
        case.log("export", {"offset": o, "inode": i, "dest": str(dest), "sha256": h.hexdigest()})
        return tr("Esportato in {dest} ({n} byte), SHA-256 {v1}").format(dest=dest, n=n, v1=h.hexdigest())

    def query_timeline(start: str = "", end: str = "", contains: str = "",
                       origin: str = "", limit: int = 100, offset: int = 0) -> str:
        """Interroga la timeline (orari UTC), ordinata per data.

        Args:
            start: data/ora iniziale, es. '2024-03-01' o '2024-03-01T14:00:00'
            end: data/ora finale inclusa
            contains: testo da cercare in percorso, sorgente o messaggio
            origin: 'tsk' (file system) o 'plaso' (artefatti di sistema); vuoto per entrambe
            limit: numero massimo di eventi (max 300)
            offset: righe da saltare, per proseguire dopo una risposta incompleta
        """
        w, p = _where(start, end, contains, origin)
        limit = max(1, min(int(limit), 300))
        con = _db()
        total = con.execute(f"SELECT COUNT(*) FROM events{w}", p).fetchone()[0]
        rows = con.execute(f"SELECT ts, kind, source, message FROM events{w} "
                           "ORDER BY ts, rowid LIMIT ? OFFSET ?", p + [limit, max(0, int(offset))]).fetchall()
        con.close()
        return pagina([" | ".join(str(x) for x in r) for r in rows], total, offset)

    def timeline_activity(start: str = "", end: str = "", contains: str = "") -> str:
        """Panoramica della timeline: primo/ultimo evento, giorni con più attività, sorgenti.

        Args:
            start: data/ora iniziale (opzionale)
            end: data/ora finale (opzionale)
            contains: filtro testuale (opzionale)
        """
        w, p = _where(start, end, contains, "")
        con = _db()
        first, last, tot = con.execute(
            f"SELECT MIN(ts), MAX(ts), COUNT(*) FROM events{w}", p).fetchone()
        days = con.execute(f"SELECT substr(ts,1,10) d, COUNT(*) c FROM events{w} "
                           "GROUP BY d ORDER BY c DESC LIMIT 25", p).fetchall()
        srcs = con.execute(f"SELECT origin || ' / ' || source, COUNT(*) c FROM events{w} "
                           "GROUP BY 1 ORDER BY c DESC LIMIT 20", p).fetchall()
        con.close()
        out = [tr("Eventi: {tot}; primo: {first}; ultimo: {last}").format(tot=tot, first=first, last=last), "", tr("Giorni più attivi:")]
        out += [f"  {d}: {c}" for d, c in days]
        out += ["", tr("Sorgenti:")] + [f"  {s}: {c}" for s, c in srcs]
        return clip("\n".join(out))

    def record_finding(title: str, description: str, references: str) -> str:
        """Registra un reperto di interesse investigativo per il report finale (non conteggi, statistiche o semplici risposte).

        Args:
            title: titolo breve del reperto
            description: descrizione, separando fatti osservati e ipotesi
            references: riferimenti verificabili (offset, inode, percorso, timestamp, hash)
        """
        x = add_finding(case, title, description, references, FINDING_IA)
        return tr("Reperto n.{v1} registrato.").format(v1=x["n"])

    def find_by_hash(hashes: str) -> str:
        """Cerca file della copia per hash MD5, SHA-1 o SHA-256 (anche più hash separati da
        spazi, virgole o a capo). Restituisce percorso, inode, stato e tutti gli hash.

        Args:
            hashes: uno o più hash esadecimali
        """
        hs = sorted({h.lower() for h in re.findall(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|"
                                                   r"\b[0-9a-fA-F]{64}\b", hashes)})
        if not hs:
            return tr("Nessun hash valido (attesi MD5 32, SHA-1 40 o SHA-256 64 caratteri esadecimali).")
        con = _db()
        rows = con.execute("SELECT part, inode, path, deleted, size, md5, sha1, sha256 FROM hashes "
                           "WHERE md5 IN (SELECT value FROM json_each(?)) OR sha1 IN (SELECT value "
                           "FROM json_each(?)) OR sha256 IN (SELECT value FROM json_each(?))",
                           [json.dumps(hs)] * 3).fetchall()
        con.close()
        found = {h for r in rows for h in r[5:8]}
        out = [tr("{v1} file corrispondenti; hash non trovati: {v2}").format(v1=len(rows), v2=', '.join(h for h in hs if h not in found) or 'nessuno')]
        for p, i, pa, d, sz, m5, s1, s2 in rows[:200]:
            out.append(tr("{v1} offset {p} inode {i}\t{pa}\t{sz} B\tMD5 {m5}\tSHA1 {s1}\tSHA256 {s2}").format(v1='*' if d else ' ', p=p, i=i, pa=pa, sz=sz, m5=m5, s1=s1, s2=s2))
        return clip("\n".join(out))

    def query_database(offset: int, inode: str, sql: str, salta: int = 0) -> str:
        """Esegue una query SQL in sola lettura su un database SQLite del caso (copia di lavoro con -wal e -journal;
        l'originale non è toccato). La query va nel registro. 200 righe per volta; date e numeri NON convertiti: dichiara
        unità e fuso quando li interpreti. Per sapere quante righe ci sono usa prima SELECT COUNT(*).

        Args:
            offset: offset della partizione o dell'estrazione
            inode: inode del file del database
            sql: una sola istruzione SELECT
            salta: righe da saltare, per proseguire dopo una risposta incompleta
        """
        import forense_database as fdb
        import forense_gui as G
        return clip(fdb.interroga(G, case, {"part": _off(offset), "inode": str(inode)}, sql, salta=salta), fa.MAX_OUT + 300)

    def flights() -> str:
        """Voli dei droni trovati nel caso: file, formato, stato, date come nella fonte, posizioni, lunghezza calcolata sui
        punti in metri, quota massima in metri, modello e numero di serie se il registro li riporta. Una traccia dice cosa
        riporta il file, non chi pilotava. «cifrato» = telemetria non letta.
        """
        import forense_droni as fdr
        out = [json.dumps({k: v.get(k) for k in ("nome", "file", "formato", "stato", "inizio", "fine", "punti_tot", "lunghezza_m", "quota_max", "riepilogo", "sha256", "nota")}, ensure_ascii=False) for v in fdr.voli(case)]
        return clip("\n".join(out)) if out else tr("Nessun volo letto in questo caso.")

    def location_points(categoria: str = "", da: str = "", a: str = "", offset: int = 0) -> str:
        """Punti con coordinate del caso (metadati, chat, artefatti iLEAPP/ALEAPP), gli stessi della Mappa. Senza categoria
        elenca le categorie con il numero di punti. Una posizione è un dato della fonte: non prova che il dispositivo
        fosse lì. Date come nella fonte, senza conversione di fuso: dichiaralo quando le citi. Nella colonna fonte
        «a|N» si apre con read_artifact(N), «f|fs|offset|inode|percorso» è un file, «c|N» è un messaggio.

        Args:
            categoria: nome esatto di una categoria, oppure vuoto per l'elenco
            da: data iniziale AAAA-MM-GG, facoltativa
            a: data finale AAAA-MM-GG, facoltativa
        """
        import forense_mappe as fmp
        r = fmp.punti(case)
        if not categoria:
            return "\n".join(f"{c['nome']}: {c['punti']}" for c in r["categorie"]) or tr("Nessun punto con coordinate in questo caso.")
        idx = next((i for i, c in enumerate(r["categorie"]) if c["nome"] == categoria), None)
        if idx is None:
            return tr("Categoria sconosciuta: {c}").format(c=categoria)
        sel = [p for p in r["punti"] if p[2] == idx and (not da or (p[4] and p[4][:10] >= da)) and (not a or (p[4] and p[4][:10] <= a))]
        off = max(0, int(offset))
        return pagina([f"{p[3]}\t{p[5]}\t{p[1]}\t{p[0]}" for p in sel[off:off + 200]], len(sel), off, tr("Fonte, data come nella fonte, latitudine, longitudine:"))

    def deleted_records(offset: int, inode: str, salta: int = 0) -> str:
        """Elenca i record cancellati recuperati dai byte di un database SQLite del caso. Sono DA VERIFICARE: un record
        può essere la vecchia copia di una riga aggiornata. Citali come tali, con tabella e offset.

        Args:
            offset: offset della partizione o dell'estrazione
            inode: inode del file del database
        """
        import forense_database as fdb
        import forense_gui as G
        return clip(fdb.recuperati_testo(G, case, {"part": _off(offset), "inode": str(inode)}, salta=salta), fa.MAX_OUT + 300)

    def read_artifact(artifact_id: int) -> str:
        """Tutti i campi di un artefatto del caso, compresi quelli di iLEAPP/ALEAPP. Il numero è quello che i riferimenti
        chiamano «riga N della tabella artifacts» e che location_points indica come «a|N».

        Args:
            artifact_id: numero della riga nella tabella artifacts
        """
        con = _db()
        try:
            # (3.0.2) grp e sub ci sono solo nei casi smartphone: nei casi disco la richiesta falliva
            gs = "grp, sub" if "grp" in {c[1] for c in con.execute("PRAGMA table_info(artifacts)")} else "NULL, NULL"
            r = con.execute(f"SELECT cat, {gs}, ts, title, detail, user, src_path, data FROM artifacts WHERE id=?",
                            (int(artifact_id),)).fetchone()
        finally:
            con.close()
        if not r:
            return tr("Artefatto {id} non trovato.").format(id=artifact_id)
        d = dict(zip(("cat", "grp", "sub", "ts", "title", "detail", "user", "src_path"), r[:8]))
        try:
            d["data"] = json.loads(r[8]) if r[8] else None
        except ValueError:
            d["data"] = r[8]
        return clip(json.dumps(d, ensure_ascii=False, indent=1))

    def list_bookmarks(category: str = "", contains: str = "", start: str = "", end: str = "", offset: int = 0) -> str:
        """Preferiti del caso in ordine di data dell'evento, con categorie, note e fonte. La prima riga dà i conteggi:
        quanti preferiti in tutto, quanti con i filtri, quanti per categoria e quanti senza data. La colonna evento dice
        a che cosa si riferisce la data: una data di modifica non prova da sola quando un fatto è avvenuto.

        Args:
            category: parte del nome di una categoria, oppure vuoto per tutte
            contains: testo da cercare in nome, percorso o nota (opzionale)
            start: data iniziale AAAA-MM-GG dell'evento (opzionale; esclude i preferiti senza data)
            end: data finale AAAA-MM-GG dell'evento (opzionale; esclude i preferiti senza data)
            offset: righe da saltare, per proseguire dopo una risposta incompleta
        """
        tutti = fa.bookmarks_timeline(case, False)
        if not tutti:
            return tr("Nessun preferito in questo caso.")
        righe, c, da, a = tutti, str(contains or "").lower(), str(start or "")[:10], str(end or "")[:10]
        if category:
            righe = [x for x in righe if any(category.lower() in k.lower() for k in x["categorie"])]
        if c:
            righe = [x for x in righe if any(c in str(x.get(k) or "").lower() for k in ("name", "path", "note"))]
        if da:
            righe = [x for x in righe if x["ts"] and x["ts"][:10] >= da]
        if a:
            righe = [x for x in righe if x["ts"] and x["ts"][:10] <= a]
        cat = {}
        for x in righe:
            for k in x["categorie"]:
                cat[k] = cat.get(k, 0) + 1
        testa = tr("Preferiti: {t} in tutto, {n} con questi filtri ({s} senza data). Per categoria: {c}.").format(
            t=len(tutti), n=len(righe), s=sum(1 for x in righe if not x["ts"]),
            c="; ".join(f"{k} {v}" for k, v in sorted(cat.items(), key=lambda kv: (-kv[1], kv[0]))) or tr("nessuna"))
        off = max(0, int(offset))
        return pagina([json.dumps({k: x.get(k) for k in ("ts", "fine", "evento", "name", "path", "source", "part", "inode", "categorie", "note")},
                                  ensure_ascii=False) for x in righe[off:off + 300]], len(righe), off, testa)

    def saved_searches(search_id: int = 0, contains: str = "", offset: int = 0) -> str:
        """Ricerche salvate dall'analista nel caso (parole, hash, ricerca veloce). Senza search_id elenca le ricerche con
        numero, titolo, data, termini e numero di risultati; con search_id elenca i risultati di quella ricerca (file,
        dove è stato trovato il termine, dettaglio). Dicono che cosa l'analista ha già cercato e trovato.

        Args:
            search_id: numero della ricerca, oppure 0 per l'elenco delle ricerche
            contains: testo da cercare nel percorso o nel dettaglio dei risultati (opzionale)
            offset: righe da saltare, per proseguire dopo una risposta incompleta
        """
        f = case.root / "ricerche.sqlite"
        if not f.exists():
            return tr("Nessuna ricerca salvata in questo caso.")
        con = sqlite3.connect(f.as_uri() + "?mode=ro", uri=True)
        try:
            if not fa.table_exists(con, "searches"):
                return tr("Nessuna ricerca salvata in questo caso.")
            off = max(0, int(offset))
            if not int(search_id or 0):
                rows = con.execute("SELECT sid, title, created, params, total, note FROM searches ORDER BY sid").fetchall()
                if not rows:
                    return tr("Nessuna ricerca salvata in questo caso.")
                out = []
                for sid, title, created, params, total, note in rows:
                    try:
                        par = json.loads(params or "{}")
                    except ValueError:
                        par = {}
                    out.append(json.dumps({"n": sid, "titolo": title, "creata": created, "tipo": par.get("mode"), "termini": par.get("terms"),
                                           "dove": par.get("where"), "risultati": total}, ensure_ascii=False))
                return pagina(out[off:off + 300], len(out), off, tr("Ricerche salvate: {n}.").format(n=len(out)))
            s = con.execute("SELECT title, total FROM searches WHERE sid=?", (int(search_id),)).fetchone()
            if not s:
                return tr("Ricerca {n} non trovata.").format(n=search_id)
            w, a = " WHERE sid=?", [int(search_id)]
            if contains:
                w += " AND (path LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\')"
                a += [fa.like(contains)] * 2
            tot = con.execute(f"SELECT COUNT(*) FROM hits{w}", a).fetchone()[0]
            rows = con.execute(f"SELECT source, part, inode, path, deleted, size, mtime, wheres, terms, detail FROM hits{w} "
                               "ORDER BY id LIMIT 300 OFFSET ?", a + [off]).fetchall()
            return pagina([json.dumps(dict(zip(("source", "part", "inode", "path", "deleted", "size", "mtime", "dove", "termini", "dettaglio"), r)),
                                      ensure_ascii=False) for r in rows], tot, off,
                          tr("Ricerca {n} «{t}»: {r} risultati.").format(n=search_id, t=s[0], r=tot))
        finally:
            con.close()

    def similar_images(offset: int, inode: str) -> str:
        """Immagini del caso simili a quella indicata (hash percettivo dHash a 64 bit, già calcolato dall'analisi «Hash
        percettivi»). «distanza» = bit diversi: 0 è la stessa immagine anche ridimensionata o ricompressa; valori più
        alti sono somiglianze DA VERIFICARE guardando le immagini, non una prova che siano la stessa foto.

        Args:
            offset: offset della partizione o dell'estrazione
            inode: inode del file dell'immagine
        """
        import forense_estesa as fe
        con = _db()
        try:
            if not fa.table_exists(con, "phash"):
                return tr("Esegui prima l'analisi «Hash percettivi» (Analisi aggiuntive).")
            part = _off(offset)
            r = con.execute("SELECT dhash FROM phash WHERE source='fs' AND inode=? AND part=?", (str(inode), part)).fetchone()
            if not r:
                return tr("Questa immagine non ha un hash percettivo (non si apre o non era tra le immagini analizzate).")
            righe = [json.dumps({"distanza": d, "source": s, "part": p, "inode": i, "path": pa}, ensure_ascii=False)
                     for d, s, p, i, pa in fe.phash_similar(con, r[0]) if not (s == "fs" and str(i) == str(inode) and p == part)]
        finally:
            con.close()
        return pagina(righe, len(righe), 0, tr("Immagini simili: {n} (soglia {s} bit su 64).").format(n=len(righe), s=fe.PHASH_NEAR))

    tools = [case_overview, fs_info, list_directory, find_files, file_metadata,
             read_file_text, file_hash, export_file, query_timeline, timeline_activity]
    tools.append(query_database)
    tools.append(location_points)
    tools.append(flights)               # (3.0) anche i dischi: i voli si cercano nelle copie forensi
    tools.append(deleted_records)
    tools.append(read_artifact)
    tools.append(list_bookmarks)
    tools.append(saved_searches)        # (3.0.4) ricerche salvate dall'analista e loro risultati
    if (case.meta.get("estese") or {}).get("phash"):
        tools.append(similar_images)    # (3.0.4) immagini simili, se gli hash percettivi sono stati calcolati
    if shutil.which("exiftool"):
        tools.append(file_exif)
    if case.meta.get("indice") or case.meta.get("carving"):
        tools += [search_text, search_metadata, list_not_indexed]
    carv = case.meta.get("carving") or {}
    if carv.get("photorec"):
        tools += [carved_files, read_carved]
    if carv.get("bulk_extractor"):
        tools += [search_traces, locate_offset]
    if case.meta.get("hash_file"):
        tools.append(find_by_hash)
    try:
        import forense_estesa as fe
        tools += fe.agent_tools(case)
    except ImportError:
        pass
    if is_mobile(case):                  # smartphone: strumenti per chat, contatti e artefatti di iLEAPP/ALEAPP
        import forense_mobile_chat as fmc
        tools += fmc.agent_tools(case)
    import forense_mobile_media as fmm   # (3.0.1) foto, video e audio riconosciuti dal contenuto, dischi e telefoni
    tools += fmm.agent_tools(case)
    tools.append(record_finding)
    return {t.__name__: t for t in tools}


PY2JSON = {int: "integer", str: "string", bool: "boolean", float: "number"}


def tool_schema(fn):
    doc = inspect.getdoc(fn) or ""
    desc = doc.split("\n\nArgs:")[0].strip()
    arg_desc = (dict(re.findall(r"^\s+(\w+):\s*(.+)$", doc.split("Args:")[1], re.M))
                if "Args:" in doc else {})
    props, req = {}, []
    for name, p in inspect.signature(fn).parameters.items():
        props[name] = {"type": PY2JSON.get(p.annotation, "string"),
                       "description": arg_desc.get(name, "")}
        if p.default is inspect.Parameter.empty:
            req.append(name)
    return {"type": "function",
            "function": {"name": fn.__name__, "description": desc,
                         "parameters": {"type": "object", "properties": props,
                                        "required": req}}}
