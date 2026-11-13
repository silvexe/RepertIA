#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - liste di hash (NSRL e altre): file noti e file da segnalare.

(3.0.4) Codice spostato da forense_estesa.py senza modifiche, per avere file più corti. Si carica tramite
forense_estesa, che ne riesporta i nomi: gli altri moduli continuano a usare «fe.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fe.<nome>»).
"""
import json
import re
import sqlite3
from pathlib import Path
from forense_lingua import tr
import forense_agent as fa

import forense_estesa as fe
from forense_estesa import (
    PHASH_NEAR, add_anomaly, dhash_dist, ensure_schema, now, phash_reference)

# ------------------------------------------------------------------ liste di hash (NSRL e altre)

HEX = re.compile(rb"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])")


def hash_lists():
    return fa.load_settings().get("liste_hash", [])


def save_hash_lists(lists):
    d = fa.load_settings()
    d["liste_hash"] = lists
    fa.save_settings(d)


def iter_list_hashes(path, wanted_lens=(32, 40, 64)):
    """Hash contenuti in una lista: testo/CSV (NSRLFile.txt, HashKeeper, elenchi) o NSRL RDS
    in formato SQLite."""
    p = Path(path)
    with open(p, "rb") as fh:
        head = fh.read(16)
    if head == b"SQLite format 3\x00":
        con = sqlite3.connect(f"file:{p.as_posix()}?mode=ro&immutable=1", uri=True)
        try:
            for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')").fetchall():
                cols = [c[1] for c in con.execute(f'PRAGMA table_info("{t}")')]
                hc = [c for c in cols if c.lower() in ("md5", "sha1", "sha256", "sha-1", "sha-256", "hash")]
                if not hc:
                    continue
                for row in con.execute(f'SELECT {", ".join(chr(34) + c + chr(34) for c in hc)} FROM "{t}"'):
                    for v in row:
                        if v:
                            yield str(v).strip().lower()
                break
        finally:
            con.close()
        return
    with open(p, "rb") as fh:
        for line in fh:
            for m in HEX.findall(line):
                yield m.decode().lower()


HEX_FULL = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}")


def iter_list_entries(path):
    """(hash, categoria o None) di una lista. I file JSON in formato Project VIC (VICS) o CAID si leggono per campi
    (MD5/SHA1/SHA256 e Category); gli altri formati come iter_list_hashes, senza categoria."""
    p = Path(path)
    if p.suffix.lower() == ".json" and p.stat().st_size < (3 << 30):
        try:
            with open(p, encoding="utf-8-sig") as fh:
                data = json.load(fh)
        except (ValueError, OSError, UnicodeDecodeError):
            data = None
        found = False
        stack = [data] if data is not None else []
        while stack:
            x = stack.pop()
            if isinstance(x, dict):
                keys = {str(k).lower(): k for k in x}
                cat = next((x[keys[k]] for k in ("category", "categoria", "classification") if k in keys), None)
                for k in ("md5", "sha1", "sha-1", "sha256", "sha-256"):
                    v = x.get(keys[k]) if k in keys else None
                    if isinstance(v, str) and HEX_FULL.fullmatch(v.strip().lower()):
                        found = True
                        yield v.strip().lower(), (str(cat) if cat not in (None, "") else None)
                stack.extend(v for v in x.values() if isinstance(v, (dict, list)))
            elif isinstance(x, list):
                stack.extend(x)
        if found:
            return
    for h in iter_list_hashes(path):
        yield h, None


def phash_index(refs):
    """Indice per la ricerca dei vicini entro PHASH_NEAR bit: 64 bit in PHASH_NEAR+1 pezzi; due hash a distanza
    <= PHASH_NEAR coincidono in almeno un pezzo (principio dei cassetti)."""
    k = PHASH_NEAR + 1
    bounds = [(64 * i // k, 64 * (i + 1) // k) for i in range(k)]
    idx = {}
    for j, (h, nm) in enumerate(refs):
        u = h & 0xFFFFFFFFFFFFFFFF
        for i, (a, b) in enumerate(bounds):
            idx.setdefault((i, (u >> a) & ((1 << (b - a)) - 1)), []).append(j)
    return bounds, idx


def phash_nearest(h, refs, index):
    bounds, idx = index
    u = h & 0xFFFFFFFFFFFFFFFF
    cand = set()
    for i, (a, b) in enumerate(bounds):
        cand.update(idx.get((i, (u >> a) & ((1 << (b - a)) - 1)), ()))
    best = None
    for j in cand:
        d = dhash_dist(h, refs[j][0])
        if d <= PHASH_NEAR and (best is None or d < best[0]):
            best = (d, refs[j][1])
    return best


def compare_phash_folder(con, L, progress):
    """Lista «cartella di immagini di riferimento»: immagini del caso simili (hash percettivo) a quelle della cartella."""
    if not fa.table_exists(con, "phash") or not con.execute("SELECT 1 FROM phash LIMIT 1").fetchone():
        return {"nome": L["nome"], "errore": tr("esegui prima «Hash percettivi» tra le analisi aggiuntive")}
    progress(tr("Lista «{nome}»: calcolo gli hash percettivi delle immagini di riferimento…").format(nome=L['nome']))
    refs = phash_reference(L["path"])
    if not refs:
        return {"nome": L["nome"], "errore": tr("nessuna immagine leggibile nella cartella")}
    index = phash_index(refs)
    hits = 0
    for src, part, inode, path, d in con.execute("SELECT source, part, inode, path, dhash FROM phash").fetchall():
        best = phash_nearest(d, refs, index)
        if not best:
            continue
        hits += 1
        source = src if src in ("x", "carving") else "fs"
        con.execute("INSERT INTO known VALUES (?,?,?,?,?,?,?)",
                    (source, part, inode, path, L["tipo"], L["nome"], f"dhash:{d & 0xFFFFFFFFFFFFFFFF:016x}"))
        if L["tipo"] == "segnalati":
            add_anomaly(con, "segnalato", source, part, inode, path,
                        tr("immagine simile a «{v1}» della cartella di riferimento «{nome}» (hash percettivo: {v2} "
                           "bit diversi su 64{v3}): da verificare a vista").format(v1=best[1], nome=L['nome'], v2=best[0], v3=tr(', quasi identica') if best[0] <= 4 else ''),
                        real=f"dhash:{d & 0xFFFFFFFFFFFFFFFF:016x}", sev=3 if best[0] <= 4 else 2)
    return {"nome": L["nome"], "tipo": L["tipo"], "immagini_riferimento": len(refs), "file": hits, "percettivo": True}


def compare_lists(case, progress):
    lists = hash_lists()
    if not lists:
        raise ValueError(tr("Nessuna lista di hash: aggiungine una (NSRL, elenco di hash noti o da segnalare)."))
    con = sqlite3.connect(case.db_path, timeout=60)
    ensure_schema(con)
    idx = {}
    warn = None
    if fa.table_exists(con, "hashes"):
        for part, inode, path, md5, sha1, sha256 in con.execute("SELECT part, inode, path, md5, sha1, sha256 FROM hashes"):
            for h in (md5, sha1, sha256):
                if h:
                    idx.setdefault(h.lower(), []).append(("fs", part, inode, path))
    else:
        warn = (tr("Hash dei file della copia non ancora calcolati: confrontati solo i file estratti. "
                "Per tutti i file esegui Analisi aggiuntive → Hash dei file."))
    for xid, path, md5, sha1, sha256 in con.execute("SELECT id, path, md5, sha1, sha256 FROM xitems WHERE sha256 IS NOT NULL"):
        for h in (md5, sha1, sha256):
            if h:
                idx.setdefault(h.lower(), []).append(("x", None, str(xid), path))
    if not idx and not all(Path(L["path"]).is_dir() for L in lists):
        con.close()
        raise ValueError(tr("Calcola prima gli hash dei file (Analisi aggiuntive → Hash dei file)."))
    con.execute("DELETE FROM known")
    con.execute("DELETE FROM anomalies WHERE kind='segnalato'")
    res = []
    for L in lists:
        if not Path(L["path"]).exists():
            res.append({"nome": L["nome"], "errore": tr("file della lista non trovato")})
            continue
        if Path(L["path"]).is_dir():
            res.append(compare_phash_folder(con, L, progress))
            con.commit()
            continue
        n = hits = 0
        seen = set()
        for h, cat in iter_list_entries(L["path"]):
            n += 1
            if n % 500000 == 0:
                progress(tr("Lista «{nome}»: {n:,} hash letti, {hits:,} file trovati").format(nome=L['nome'], n=n, hits=hits).replace(",", "."))
            for src, part, inode, path in idx.get(h, ()):
                key = (src, part, inode)
                if key in seen:
                    continue
                seen.add(key)
                hits += 1
                con.execute("INSERT INTO known VALUES (?,?,?,?,?,?,?)", (src, part, inode, path, L["tipo"], L["nome"], h))
                if L["tipo"] == "segnalati":
                    add_anomaly(con, "segnalato", src, part, inode, path,
                                tr("hash presente nella lista «{nome}»").format(nome=L['nome']) + (tr(", categoria {cat}").format(cat=cat) if cat else ""),
                                real=h, sev=3)
        res.append({"nome": L["nome"], "tipo": L["tipo"], "hash": n, "file": hits})
        con.commit()
    con.close()
    out = {"liste": res, "ts": now(), **({"avviso": warn} if warn else {})}
    case.meta["liste_hash"] = out
    case.save()
    case.log("confronto_liste_hash", out)
    return out
