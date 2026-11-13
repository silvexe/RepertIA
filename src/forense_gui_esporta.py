#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - interfaccia, selezioni ed esportazioni.

(3.0.4) Codice spostato da forense_gui.py senza modifiche, per avere file più corti. Si carica tramite
forense_gui, che ne riesporta i nomi: gli altri moduli continuano a usare «G.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («G.<nome>»).
"""
import os
import re
import sys
from pathlib import Path
from forense_lingua import tr
import forense_agent as fa
import forense_lingua as lg

import forense_gui as G
from forense_gui import (
    IMG_MIME, IS_WIN, SES, fmt_ts, is_dir_type, nav_db, results, testo_fuso, tz_zone)

# ------------------------------------------------- selezioni ed esportazioni

def selected_rows(case, b):
    """Righe selezionate: elenco di id oppure 'tutte' quelle dei filtri attuali (meno le escluse)."""
    q = dict(b.get("query") or {})
    q["kind"] = b.get("kind") or q.get("kind") or "file"
    q.pop("offset", None)
    ids = None if b.get("all") else [str(x) for x in (b.get("ids") or [])]
    if ids is not None and not ids:
        raise ValueError(tr("Nessun elemento selezionato."))
    r = results(case, q, ids=ids, limit=None, full=True)
    excl = {str(x) for x in (b.get("exclude") or [])}
    return q["kind"], [x for x in r["rows"] if str(x["id"]) not in excl]


def canc_txt(d):
    """Indicazione «cancellato» nelle etichette dei reperti; (3.0.2) 2 = nome cancellato con l'inode riassegnato."""
    if d == 2:
        return tr(", cancellato, inode riassegnato a un altro file (contenuto non suo)")
    if d == 3:
        return tr(", cancellato, blocchi riusati da altri file (contenuto in parte non suo)")
    return tr(", cancellato") if d else ""


def ref_label(kind, x):
    if kind in G.EXT_KINDS:
        return G.ext_ref_label(kind, x)
    if kind in ("hits", "doc") and x.get("source") == "x":
        return tr("file estratto {path} (id {inode})").format(path=x['path'], inode=x['inode'])
    if kind in ("hits", "doc") and x.get("source") == "posta":
        return tr("messaggio di posta {path}").format(path=x['path'])
    if kind == "hits" and x.get("source") == "image":
        return tr("byte {inode} della copia forense ({v1})").format(inode=x['inode'], v1=x.get('detail') or '')
    if kind == "carved":
        return tr("file recuperato {name} (offset {img_offset} nell'immagine, SHA-256 {sha256})").format(name=x['name'], img_offset=x['img_offset'], sha256=x['sha256'])
    if kind in ("doc", "meta") and x.get("source") == "carving":
        return tr("file recuperato {inode}").format(inode=x['inode'])
    if kind == "trace":
        return tr("traccia {tkind} \"{feature}\" all'offset {offset} dell'immagine").format(tkind=x['tkind'], feature=x['feature'], offset=x['offset'])
    if kind == "timeline":
        what = x["path"] if x["origin"] == "tsk" else x["message"]
        return tr("evento del {ts} UTC ({v1}, {kind}): {what}").format(ts=x['ts'], v1=tr('file system') if x['origin'] == 'tsk' else x['source'], kind=x['kind'], what=what)
    if kind == "hits":
        if x.get("source") == "carving":
            return tr("file recuperato {name} (trovato in {wheres}: {terms})").format(name=x['name'], wheres=x['wheres'], terms=x['terms'])
        return (f"{x['path']} (offset {x['part']}, inode {x['inode']}"
                + (canc_txt(x["deleted"]))
                + (f", SHA-256 {x['sha256']}" if x.get("sha256") else "")
                + tr("; trovato in {wheres}: {terms})").format(wheres=x['wheres'], terms=x['terms']))
    if kind == "explore":
        return (f"{x['path']}{'/' if x['isdir'] else ''} (offset {x['part']}"
                + (f", inode {x['inode']}" if x.get("inode") else "")
                + (canc_txt(x["deleted"])) + ")")
    return f"{x['path']} (offset {x['part']}, inode {x['inode']}{canc_txt(x.get('deleted'))})"


CSV_COLS = {
    "hits": [("path", "percorso"), ("deleted", "cancellato"), ("source", "origine"),
             ("part", "partizione_offset"), ("inode", "inode"), ("size", "byte"),
             ("mtime", "modifica_utc"), ("wheres", "trovato_in"), ("terms", "termini"),
             ("detail", "dettaglio"), ("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256")],
    "explore": [("path", "percorso"), ("isdir", "cartella"), ("deleted", "cancellato"),
                ("part", "partizione_offset"), ("inode", "inode"), ("type", "tipo"),
                ("size", "byte"), ("mtime", "modifica_utc"), ("atime", "accesso_utc"),
                ("ctime", "metadati_utc"), ("crtime", "creazione_utc")],
    "file": [("path", "percorso"), ("deleted", "cancellato"), ("part", "partizione_offset"),
             ("inode", "inode"), ("type", "tipo"), ("size", "byte"), ("mtime", "modifica_utc"),
             ("atime", "accesso_utc"), ("ctime", "metadati_utc"), ("crtime", "creazione_utc")],
    "timeline": [("ts", "data_utc"), ("kind", "evento"), ("origin", "fonte"), ("source", "sorgente"),
                 ("path", "percorso"), ("message", "dettaglio"), ("part", "partizione_offset"),
                 ("inode", "inode")],
    "doc": [("path", "documento"), ("kind", "tipo"), ("deleted", "cancellato"), ("source", "origine"),
            ("part", "partizione_offset"), ("inode", "inode"), ("size", "byte"), ("mtime", "modifica_utc"), ("crtime", "creazione_utc"),
            ("snippet", "testo")],
    "meta": [("path", "file"), ("make", "marca"), ("model", "modello"), ("taken", "data_metadati"), ("taken_tz", "fuso_della_data"),
             ("lat", "lat"), ("lon", "lon"), ("author", "autore"), ("deleted", "cancellato"),
             ("source", "origine"), ("part", "partizione_offset"), ("inode", "inode"), ("size", "byte"), ("mtime", "modifica_utc"),
             ("crtime", "creazione_utc")],
    "carved": [("name", "file"), ("type", "tipo"), ("size", "byte"), ("img_offset", "offset_immagine"),
               ("sha256", "sha256"), ("relpath", "percorso_nel_caso")],
    "trace": [("tkind", "tipo"), ("feature", "valore"), ("count", "occorrenze"),
              ("offset", "offset"), ("context", "contesto")],
}


def stamp_now():
    import datetime as _dt
    return _dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def unique(path):
    """Nuovo percorso non esistente (aggiunge _2, _3... se serve)."""
    p, n = path, 2
    while p.exists():
        p = path.with_name(f"{path.stem}_{n}{path.suffix}")
        n += 1
    return p


def export_csv(case, b):
    import csv
    kind, rows = selected_rows(case, b)
    cols = CSV_COLS.get(kind) or G.EXT_CSV[kind]
    if kind == "meta" and fa.is_mobile(case):   # (2.20) telefoni: app delle chat in cui il file è allegato
        cols = cols + [("chat", "origine_chat")]
    if kind == "trace" and rows and "count" not in rows[0]:
        cols = [c for c in cols if c[0] != "count"]
    d = case.export_dir / "elenchi"
    d.mkdir(parents=True, exist_ok=True)
    name = {"hits": "ricerca", "explore": "esplora", "file": "file", "timeline": "timeline", "doc": "documenti",
            "meta": "metadati", "carved": "recuperati", "trace": "evidenze_di_interesse", "art": "artefatti",
            "mail": "posta", "arch": "archivi_allegati", "vss": "copie_shadow", "anom": "anomalie"}[kind]
    path = unique(d / f"{name}_{G.stamp_now()}.csv")
    tz = b.get("tz") or (b.get("query") or {}).get("tz")
    zone = tz_zone(case, tz)
    suf = "utc" if zone == "UTC" else tr("ora_italiana") if tz == "rome" else tr("fuso_") + re.sub(r"\W+", "_", zone).lower()
    dcols = {k for k, h in cols if h.endswith("_utc")}
    head = [(tr(c[1][:-4]) + "_" + suf) if c[1].endswith("_utc") else tr(c[1]) for c in cols]
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        wr = csv.writer(f, delimiter=";")
        wr.writerow(head)
        for x in rows:
            wr.writerow(["" if x.get(k) is None else (tr("sì") if x[k] else tr("no"))
                         if k in ("isdir", "deleted") else (fmt_ts(case, tz, x.get(k)) if k in dcols and zone != "UTC" else
                                                     testo_fuso(case, tz, x.get(k)) if k in ("detail", "message") else x.get(k))
                         for k, _ in cols])
    path.chmod(0o444)
    case.log("export_elenco", {"kind": kind, "righe": len(rows), "dest": str(path), "fuso": zone})
    return {"path": str(path), "rel": str(path.relative_to(case.root)), "rows": len(rows)}


def export_targets(case, kind, rows):
    """Converte le righe selezionate in file da estrarre: (part, inode, percorso, cancellato)
    per il file system, oppure ('carving', percorso nel caso, nome) per i file recuperati.
    Le cartelle vengono espanse con tutto il loro contenuto."""
    fs, carved, dirs, skipped = {}, {}, [], 0

    def add_fs(part, inode, path, deleted):
        if inode:
            fs.setdefault((int(part), str(inode), path), deleted)

    for x in rows:
        if kind == "explore":
            if x["isdir"]:
                dirs.append((x["part"], x["path"]))
            else:
                add_fs(x["part"], x["inode"], x["path"], x["deleted"])
        elif kind == "file":
            if is_dir_type(x["type"]):
                dirs.append((x["part"], x["path"].strip("/")))
            else:
                add_fs(x["part"], x["inode"], x["path"], x["deleted"])
        elif kind in ("doc", "meta"):
            if x.get("source") == "carving":
                carved[x["inode"]] = None
            elif x.get("source") in ("x", "posta"):
                skipped += x.get("source") == "posta"
            else:
                add_fs(x["part"], x["inode"], x["path"], x["deleted"])
        elif kind == "timeline":
            if x.get("inode"):
                fs.setdefault((int(x["part"]), str(x["inode"]), None), 0)
            else:
                skipped += 1
        elif kind == "carved":
            carved[x["name"]] = x["relpath"]
        elif kind == "hits":
            if x.get("source") == "carving":
                carved[x["name"]] = None
            elif x.get("source") in ("x", "image", "mail", "art", "posta", "chat"):
                skipped += x.get("source") != "x"
            else:
                add_fs(x["part"], x["inode"], x["path"], x["deleted"])
        elif kind == "anom":
            if x.get("source") == "fs" and x.get("inode"):
                add_fs(x["part"], x["inode"], x["path"], x["deleted"])
            elif x.get("source") != "x":
                skipped += 1
        elif kind in ("arch", "vss"):
            pass                      # file estratti: x_targets
        else:
            skipped += 1
    con = None
    if dirs or any(k[2] is None for k in fs):
        con = nav_db(case)
        for part, d in dirs:
            for ino, p, dl in con.execute(
                    "SELECT inode, path, deleted FROM nav WHERE part=? AND isdir=0 AND inode IS NOT NULL "
                    "AND substr(path, 1, ?) = ?", (part, len(d) + 1, d + "/")):
                add_fs(part, ino, p, dl)
        for k in [k for k in fs if k[2] is None]:
            r = con.execute("SELECT path, deleted, isdir FROM nav WHERE part=? AND inode=? "
                            "ORDER BY deleted LIMIT 1", (k[0], k[1])).fetchone()
            del fs[k]
            if r and not r[2]:
                fs.setdefault((k[0], k[1], r[0]), r[1])
            elif not r:
                fs.setdefault((k[0], k[1], f"inode_{k[1]}"), 0)
        con.close()
    if any(v is None for v in carved.values()):
        c2 = fa.db_ro(case)
        for name in [n for n, v in carved.items() if v is None]:
            r = c2.execute("SELECT relpath FROM carved WHERE name=? OR name LIKE ? ESCAPE '\\' LIMIT 1", (name, "%/" + fa.like(name)[1:-1])).fetchone()
            carved[name] = r[0] if r else None
        c2.close()
    return fs, {n: v for n, v in carved.items() if v}, skipped


WIN_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10))}


def safe_part(s):
    s = re.sub(r'[\x00-\x1f:*?"<>|\\]', "_", s).strip()
    s = s.rstrip(". ") or s          # Windows non ammette punti o spazi finali
    if s.split(".")[0].upper() in WIN_RESERVED:
        s = "_" + s
    return (s if s not in ("", ".", "..") else "_")[:150]


def lp(p):
    """Percorso utilizzabile anche oltre i 260 caratteri su Windows (prefisso \\\\?\\)."""
    p = str(Path(p).resolve()) if IS_WIN else str(p)
    if IS_WIN and not p.startswith("\\\\?\\"):
        p = ("\\\\?\\UNC\\" + p[2:]) if p.startswith("\\\\") else "\\\\?\\" + p
    return p


def chat_targets(case, kind, rows):
    """(2.21) Chat nella selezione: conversazioni intere (schede «messaggi») e id dei messaggi singoli dei Preferiti."""
    if kind != "hits" or not fa.is_mobile(case):
        return [], []
    th = fa.bm_threads(case)
    chats = list(dict.fromkeys(th[str(x["inode"])] for x in rows if x.get("source") == "art" and str(x["inode"]) in th))
    return chats, [int(x["inode"]) for x in rows if x.get("source") == "chat"]


def export_selection(case, b, progress):
    """Estrae i file selezionati in export/selezione_<data>/ conservando l'albero delle
    cartelle, in sola lettura, con manifest.csv (percorso originale, inode, SHA-256)."""
    import csv, hashlib
    kind, rows = selected_rows(case, b)
    fs, carved, skipped = export_targets(case, kind, rows)
    xs = G.x_targets(case, kind, rows)
    for i in [i for i, v in xs.items() if not v[1]]:
        del xs[i]
        skipped += 1
    chats, msgs = chat_targets(case, kind, rows)
    skipped = max(0, skipped - len(chats) - len(msgs))
    if not fs and not carved and not xs and not chats and not msgs:
        raise ValueError(tr("Nella selezione non ci sono file esportabili "
                         "(le tracce e gli eventi senza inode si esportano come elenco CSV)."))
    if fs and not Path(case.image).exists():
        raise ValueError(tr("La copia forense non è raggiungibile: collega il disco che la contiene."))
    out = unique(case.export_dir / f"selezione_{G.stamp_now()}")
    out.mkdir(parents=True)
    used, man, total = set(), [], len(fs) + len(carved)
    for n, ((part, inode, path), deleted) in enumerate(sorted(fs.items(), key=lambda t: t[0][2]), 1):
        progress(f"{n} di {total}: {path}")
        segs = [safe_part(s) for s in path.split("/")]
        dest = out.joinpath(f"partizione_{part}" if part >= 0 else "disco", *segs)
        if str(dest).lower() in used or os.path.exists(lp(dest)):
            dest = dest.with_name(f"{dest.stem}__inode_{inode.replace('-', '_')}{dest.suffix}")
        used.add(str(dest).lower())
        os.makedirs(lp(dest.parent), exist_ok=True)
        h, size = hashlib.sha256(), 0
        with open(lp(dest), "wb") as f:
            for chunk in G.item_stream(case, part, inode):
                f.write(chunk)
                h.update(chunk)
                size += len(chunk)
        os.chmod(lp(dest), 0o444)
        man.append([path, part, inode, "si" if deleted else "no", size, h.hexdigest(),
                    str(dest.relative_to(out))])
    for n, (name, rel) in enumerate(carved.items(), len(fs) + 1):
        progress(f"{n} di {total}: {name}")
        src = case.root / rel
        dest = out / "recuperati_carving" / safe_part(name)
        os.makedirs(lp(dest.parent), exist_ok=True)
        h = hashlib.sha256()
        with open(src, "rb") as fi, open(lp(dest), "wb") as fo:
            while chunk := fi.read(1 << 20):
                fo.write(chunk)
                h.update(chunk)
        os.chmod(lp(dest), 0o444)
        man.append([f"[carving] {rel}", "", "", "", os.stat(lp(dest)).st_size, h.hexdigest(),
                    str(dest.relative_to(out))])
    for n, (xid, (xpath, rel)) in enumerate(xs.items(), len(fs) + len(carved) + 1):
        progress(f"{n} di {total + len(xs)}: {xpath}")
        src = case.root / rel
        dest = out / "estratti" / f"x{xid}_{safe_part(Path(rel).name.split('_', 1)[-1])}"
        os.makedirs(lp(dest.parent), exist_ok=True)
        h = hashlib.sha256()
        with open(src, "rb") as fi, open(lp(dest), "wb") as fo:
            while chunk := fi.read(1 << 20):
                fo.write(chunk)
                h.update(chunk)
        os.chmod(lp(dest), 0o444)
        man.append([f"[estratto] {xpath}", "", "", "", os.stat(lp(dest)).st_size, h.hexdigest(),
                    str(dest.relative_to(out))])
    if chats or msgs:                  # (2.21) chat dei Preferiti: HTML e CSV con allegati, messaggi singoli in un CSV
        import forense_mobile_gui as fmg
        cd = out / "chat"
        for n, tid in enumerate(chats, 1):
            progress(tr("Chat {n} di {t}").format(n=n, t=len(chats)))
            r = fmg.export_chat(G, case, {"thread": tid, "tz": b.get("tz"), "lingua": lg.lingua(), "da": b.get("chat_da"),
                                                              "a": b.get("chat_a"), "cartella": str(cd)})
            for fx in (r or {}).get("files", []):
                man.append([f"[chat] {tid}", "", "", "", (cd / fx["file"]).stat().st_size, fx["sha256"], f"chat/{fx['file']}"])
            for a in (r or {}).get("allegati_file", []):
                man.append([f"[allegato chat] {a['origine']}", "", "", "", (cd / a["file"]).stat().st_size, a["sha256"], f"chat/{a['file']}"])
        if msgs:
            cd.mkdir(exist_ok=True)
            fx = cd / "messaggi_preferiti.csv"
            fmg.preferiti_csv(case, fx, msgs)
            man.append([tr("[messaggi nei Preferiti]"), "", "", "", fx.stat().st_size, fa.sha256_file(fx), "chat/messaggi_preferiti.csv"])
    with open(out / "manifest.csv", "w", newline="", encoding="utf-8-sig") as f:
        wr = csv.writer(f, delimiter=";")
        wr.writerow([tr(h) for h in ["percorso_originale", "partizione_offset", "inode", "cancellato", "byte",
                     "sha256", "file_esportato"]])
        wr.writerows(man)
    (out / "manifest.csv").chmod(0o444)
    case.log("export_selezione", {"kind": kind, "file": len(man), "dest": str(out)})
    return {"path": str(out), "rel": str(out.relative_to(case.root)), "files": len(man),
            "skipped": skipped}


def selection_refs(case, b, cap=60):
    kind, rows = selected_rows(case, b)
    return {"total": len(rows), "kind": kind, "refs": [ref_label(kind, x) for x in rows[:cap]]}

def preview(b):
    """Anteprima di un file del file system o recuperato: testo, metadati, immagine."""
    import base64
    t = SES.case_tools
    if b.get("source") == "carving":
        if "read_carved" not in t:
            raise ValueError(tr("Carving non disponibile."))
        name = str(b["name"])
        text = t["read_carved"](name, 20000)
        con = fa.db_ro(SES.case)
        r = con.execute("SELECT relpath FROM carved WHERE name=? OR name LIKE ? ESCAPE '\\' LIMIT 1", (name, "%/" + fa.like(name)[1:-1])).fetchone()
        con.close()
        f = SES.case.root / r[0] if r else None
        data = f.read_bytes() if f and f.stat().st_size < 15 << 20 else b""
        title, meta = name, ""
    else:
        part, inode = int(b["part"]), str(b["inode"])
        con = fa.db_ro(SES.case)
        r = con.execute("SELECT path FROM files WHERE part=? AND inode=? LIMIT 1",
                        (part, inode)).fetchone()
        con.close()
        title = r[0] if r else f"inode {inode}"
        text = t["read_file_text"](part, inode, 20000)
        meta = t["file_exif"](part, inode) if "file_exif" in t else ""
        data = fa.icat_read(SES.case, part, inode, 15 << 20)
    mime = IMG_MIME.get(Path(title).suffix.lower())
    if not mime and data[:3] == b"\xff\xd8\xff":
        mime = "image/jpeg"
    if not mime and data[:8] == b"\x89PNG\r\n\x1a\n":
        mime = "image/png"
    image = (f"data:{mime};base64," + base64.b64encode(data).decode()) if mime and data else None
    return {"title": title, "text": text, "meta": meta, "image": image}
