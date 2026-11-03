# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (3.0): punti del caso sulla mappa. Solo dati locali: nessuna richiesta di rete da un caso aperto.

Fonti: coordinate dei metadati (foto e video), posizioni negli allegati delle chat, coppie di campi Latitude/Longitude
degli artefatti iLEAPP/ALEAPP. Ogni punto rimanda alla sua fonte. Le date restano quelle della fonte, senza conversione di fuso.
I livelli importati (KML) sono dell'analista: separati dalle evidenze, con nome e hash nel registro."""
import hashlib
import json
import re
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.sax.saxutils import escape

from forense_lingua import N_, tr

MAX_PUNTI = 300000
MAX_KML = 100 << 20
_DATA = re.compile(r"^(\d{4})[-:](\d\d)[-:](\d\d)(?:[ T](\d\d:\d\d:\d\d))?")
_CAMPO_LAT = re.compile(r"^(.*?)\s*\b(latitude|lat)$", re.I)


def data_norm(t):
    m = _DATA.match(str(t or ""))
    return f"{m[1]}-{m[2]}-{m[3]}" + (f" {m[4]}" if m[4] else "") if m else ""


def _num(v):
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if x == x else None


def _coppie(campi):
    """Coppie (latitudine, longitudine, nome) nei campi di un artefatto: stesso prefisso, es. «Origin Latitude»."""
    out = []
    for k in campi:
        m = _CAMPO_LAT.match(k)
        if not m:
            continue
        pre = m[1]
        for fine in ("Longitude", "longitude", "Long", "Lon", "lon", "LONGITUDE"):
            o = (pre + " " + fine).strip()
            if o in campi:
                out.append((k, o, pre))
                break
    return out


_RIEP = {}


def riepilogo(case):
    """Conteggi per l'albero dei risultati: si ricalcolano solo se il caso è cambiato. -> ([[categoria, punti]], voli con posizioni)"""
    def mt(f):
        try:
            return f.stat().st_mtime_ns
        except OSError:
            return 0
    root = Path(case.root)
    db = [x for x in root.glob("*.sqlite") if x.name != "ricerche.sqlite"]
    chiave = (str(root), mt(root / "voli.json"), tuple(mt(x) for x in sorted(db)))
    if _RIEP.get("k") != chiave:
        r = punti(case)
        _RIEP.update(k=chiave, v=([[c["nome"], c["punti"]] for c in r["categorie"] if c["punti"]], sum(1 for v in r["voli"] if v["punti"])))
    return _RIEP["v"]


def punti(case):
    """-> {categorie, punti: [[lon, lat, categoria, rif, data_normalizzata, data_fonte]], esclusi, troncato}"""
    import forense_agent as fa
    cat, idx, pt = [], {}, []
    esclusi = {"zero": 0, "fuori_scala": 0}
    troncato = False

    def k(nome, tipo):
        if nome not in idx:
            idx[nome] = len(cat)
            cat.append({"nome": nome, "tipo": tipo, "punti": 0})
        return idx[nome]

    def add(lat, lon, c, rif, ts):
        nonlocal troncato
        la, lo = _num(lat), _num(lon)
        if la is None or lo is None:
            return
        if not (-90 <= la <= 90 and -180 <= lo <= 180):
            esclusi["fuori_scala"] += 1
            return
        if la == 0 and lo == 0:           # 0,0 è quasi sempre «posizione assente»: si conta, non si disegna
            esclusi["zero"] += 1
            return
        if len(pt) >= MAX_PUNTI:
            troncato = True
            return
        cat[c]["punti"] += 1
        pt.append([round(lo, 7), round(la, 7), c, rif, data_norm(ts), str(ts or "")[:40]])

    con = fa.db_ro(case)
    try:
        if fa.table_exists(con, "meta"):
            for src, part, inode, path, taken, la, lo in con.execute(
                    "SELECT source, part, inode, path, taken, lat, lon FROM meta WHERE lat IS NOT NULL AND lon IS NOT NULL"):
                add(la, lo, k(tr("Foto e video (metadati)"), "foto"), f"f|{src or 'fs'}|{part}|{inode}|{path or ''}", taken)
        if fa.table_exists(con, "chat_attachments"):
            for mid, la, lo, ts in con.execute("SELECT a.msg, a.lat, a.lon, m.ts FROM chat_attachments a LEFT JOIN chat_messages m ON m.id=a.msg "
                                               "WHERE a.lat IS NOT NULL AND a.lon IS NOT NULL"):
                add(la, lo, k(tr("Chat (posizioni)"), "chat"), f"c|{mid}", ts)
        if fa.table_exists(con, "artifacts") and fa.is_mobile(case):
            for aid, ts, sub, data in con.execute("SELECT id, ts, sub, data FROM artifacts WHERE cat='leapp' AND lower(data) LIKE '%lat%' "
                                                  "AND lower(data) LIKE '%lon%'"):
                try:
                    campi = (json.loads(data or "{}").get("campi")) or {}
                except ValueError:
                    continue
                for a, o, pre in _coppie(campi):
                    add(campi.get(a), campi.get(o), k(sub + (f" ({pre})" if pre else ""), "artefatto"), f"a|{aid}", ts)
    finally:
        con.close()
    import forense_droni as fdr
    return {"categorie": cat, "punti": pt, "esclusi": esclusi, "troncato": troncato, "livelli": livelli(case), "voli": fdr.voli(case),
            "preferiti": _stato(case).get("preferiti", [])}


def chiave(p):
    """Un punto come stringa stabile: riferimento alla fonte, coordinate e data (uno stesso artefatto può avere più coppie)."""
    return f"{p[3]}|{p[0]}|{p[1]}|{p[4]}"


CAT_PREFERITI = N_("Posizioni GPS (mappa)")
SEGNO = "⌖ "        # inizio della nota di un preferito della mappa: bookmarks_timeline ne prende la data della posizione


def _elemento(rif):
    """Il riferimento di un punto come elemento dei Preferiti: file, artefatto o messaggio."""
    t = str(rif).split("|")
    if t[0] == "f" and len(t) >= 5:
        return {"source": "x", "id": t[3], "path": t[4]} if t[1] == "x" else {"source": "fs", "part": t[2], "inode": t[3], "path": "|".join(t[4:])}
    if t[0] == "a":
        return {"source": "art", "id": t[1]}
    if t[0] == "c":
        return {"source": "chat", "id": t[1]}
    return None


def _nota(p, cat):
    return f"{SEGNO}{p[4] or p[5] or '?'} · {p[1]}, {p[0]} · {cat}"


def preferito(case, b, G=None):
    """(3.0) Punti preferiti della mappa: si mostrano da soli e si animano per periodo; con G vanno anche nei Preferiti
    del caso (categoria «Posizioni GPS (mappa)»), con la data della posizione per la Timeline. Dato dell'analista, nel registro."""
    k = str(b.get("k") or "")[:600]
    r = punti(case)
    p = next((x for x in r["punti"] if chiave(x) == k), None)
    if not p:
        raise ValueError(tr("Punto non trovato."))
    st = _stato(case)
    pr = [x for x in st.get("preferiti", []) if x != k]
    if b.get("on"):
        pr.append(k)
    st["preferiti"] = pr
    _salva(case, st)
    case.log("mappa_preferito", {"punto": p[3], "lat": p[1], "lon": p[0], "data": p[5], "aggiunto": bool(b.get("on"))})
    it = _elemento(p[3]) if G else None
    if it:
        nome = tr(CAT_PREFERITI)
        # uno stesso elemento (un artefatto, una foto) può avere più posizioni preferite: una riga sola, con tutte nella nota
        stessi = sorted((x for x in r["punti"] if x[3] == p[3] and chiave(x) in set(pr)), key=lambda x: x[4] or "")
        con = G.search_db(case)
        try:
            c = con.execute("SELECT cid FROM bm_cat WHERE name = ? COLLATE NOCASE", (nome,)).fetchone()
            dove = "cid=? AND source=? AND inode=?" + (" AND part=?" if it["source"] == "fs" else "")
            arg = [it["source"], str(it.get("inode") or it.get("id"))] + ([int(it["part"])] if it["source"] == "fs" else [])
            if c and not stessi:
                con.execute(f"DELETE FROM bm WHERE {dove}", [c[0]] + arg)
                # la categoria la crea la mappa: vuota, sparisce anche dall'albero dei Preferiti
                if not con.execute("SELECT 1 FROM bm WHERE cid=? LIMIT 1", (c[0],)).fetchone():
                    con.execute("DELETE FROM bm_cat WHERE cid=?", (c[0],))
                con.commit()
        finally:
            con.close()
        if stessi:
            G.bm_add(case, {"cat": nome, "item": it, "note": ""})
            con = G.search_db(case)
            try:
                c = con.execute("SELECT cid FROM bm_cat WHERE name = ? COLLATE NOCASE", (nome,)).fetchone()
                con.execute(f"UPDATE bm SET note=? WHERE {dove}", ["\n".join(_nota(x, r["categorie"][x[2]]["nome"]) for x in stessi)[:2000], c[0]] + arg)
                con.commit()
            finally:
                con.close()
    return {"preferiti": pr}


def _cartella(case):
    d = Path(case.root) / "mappa"
    d.mkdir(exist_ok=True)
    return d


def _stato(case):
    f = Path(case.root) / "mappa" / "livelli.json"
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"kml": [], "estratti": []}


def _salva(case, st):
    (_cartella(case) / "livelli.json").write_text(json.dumps(st, ensure_ascii=False), encoding="utf-8")


def livelli(case):
    return {"kml": _stato(case).get("kml", []), "estratti": mappe()}


# Mappe di sfondo: comuni a tutti i casi, nella cartella accanto alle impostazioni; un file scelto dall'analista resta dov'è.
def _esterne():
    import forense_mappe_scarica as fms
    try:
        return json.loads((fms.cartella() / "esterne.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def mappe():
    import forense_mappe_scarica as fms
    out = []
    for f in sorted(fms.cartella().glob("*.pmtiles")):
        try:
            info = json.loads(Path(str(f) + ".json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            info = {}
        out.append({"id": f.name, "nome": info.get("zona") or f.stem, "maxzoom": info.get("maxzoom"), "data": info.get("data_dati"), "byte": f.stat().st_size,
                    "sha256": info.get("sha256"), "esterna": False, "ok": True})
    for e in _esterne():
        p = Path(e["path"])
        out.append({"id": "x:" + e["sha256"][:16], "nome": p.name, "maxzoom": None, "data": None, "byte": e.get("byte"), "sha256": e["sha256"], "esterna": True, "ok": p.is_file()})
    return out


def percorso_mappa(mid):
    import forense_mappe_scarica as fms
    mid = str(mid or "")
    if mid.startswith("x:"):
        for e in _esterne():
            if "x:" + e["sha256"][:16] == mid:
                return Path(e["path"])
        raise ValueError(tr("File non trovato."))
    f = fms.cartella() / Path(mid).name
    if f.suffix != ".pmtiles" or not f.is_file():
        raise ValueError(tr("File non trovato."))
    return f


def aggiungi_file(path):
    """«Ho già un file»: nessuna rete, va bene anche a caso aperto. Il file resta dov'è."""
    import forense_mappe_scarica as fms
    f = Path(str(path or ""))
    if not f.is_file():
        raise ValueError(tr("File non trovato."))
    with open(f, "rb") as fh:
        if fh.read(7) != b"PMTiles":
            raise ValueError(tr("Il file non è un estratto PMTiles."))
    h = hashlib.sha256()
    with open(f, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    es = [e for e in _esterne() if e["path"] != str(f)]
    es.append({"path": str(f), "sha256": h.hexdigest(), "byte": f.stat().st_size})
    (fms.cartella() / "esterne.json").write_text(json.dumps(es, ensure_ascii=False), encoding="utf-8")
    return mappe()


def rimuovi_mappa(mid):
    import forense_mappe_scarica as fms
    mid = str(mid or "")
    if mid.startswith("x:"):
        es = [e for e in _esterne() if "x:" + e["sha256"][:16] != mid]
        (fms.cartella() / "esterne.json").write_text(json.dumps(es, ensure_ascii=False), encoding="utf-8")
    else:
        f = percorso_mappa(mid)
        f.unlink(missing_ok=True)
        Path(str(f) + ".json").unlink(missing_ok=True)
    return mappe()


def usa_mappa(case, mid):
    """Lo sfondo scelto resta nel registro del caso: è uno sfondo, non un'evidenza."""
    m = next((x for x in mappe() if x["id"] == str(mid)), None)
    if m:
        case.log("mappa_sfondo", {"nome": m["nome"], "data_dati": m["data"], "byte": m["byte"], "sha256": m["sha256"]})
    return {"ok": True}


def _coord(t):
    out = []
    for g in (t or "").split():
        p = g.split(",")
        if len(p) >= 2:
            lo, la = _num(p[0]), _num(p[1])
            if lo is not None and la is not None and -180 <= lo <= 180 and -90 <= la <= 90:
                out.append([lo, la])
    return out


def _kml(dati):
    if b"<!DOCTYPE" in dati[:4096].upper() or b"<!ENTITY" in dati.upper():
        raise ValueError(tr("KML non accettato: contiene dichiarazioni DOCTYPE o ENTITY."))
    try:
        rad = ET.fromstring(dati)
    except ET.ParseError as e:
        raise ValueError(tr("KML non leggibile: {e}").format(e=e))
    ns = rad.tag.split("}")[0] + "}" if rad.tag.startswith("{") else ""
    fe = []
    for pm in rad.iter(ns + "Placemark"):
        nome = (pm.findtext(ns + "name") or "")[:200]
        for tag, tipo in (("Point", "Point"), ("LineString", "LineString"), ("Polygon", "Polygon")):
            for g in pm.iter(ns + tag):
                c = _coord(g.findtext(f".//{ns}coordinates"))
                if not c:
                    continue
                geo = {"Point": c[0], "LineString": c, "Polygon": [c]}[tipo]
                fe.append({"type": "Feature", "properties": {"nome": nome}, "geometry": {"type": tipo, "coordinates": geo}})
    if not fe:
        raise ValueError(tr("Nessun elemento geografico nel file."))
    return {"type": "FeatureCollection", "features": fe}


def importa_kml(case, path):
    f = Path(str(path or ""))
    if not f.is_file():
        raise ValueError(tr("File non trovato."))
    if f.stat().st_size > MAX_KML:
        raise ValueError(tr("File troppo grande."))
    dati = f.read_bytes()
    geo = _kml(dati)
    sha = hashlib.sha256(dati).hexdigest()
    st = _stato(case)
    nome = f"livello_{len(st.get('kml', [])) + 1}.geojson"
    (_cartella(case) / nome).write_text(json.dumps(geo, ensure_ascii=False), encoding="utf-8")
    st.setdefault("kml", []).append({"nome": f.name, "file": nome, "sha256": sha, "elementi": len(geo["features"])})
    _salva(case, st)
    case.log("mappa_kml", {"file": f.name, "percorso": str(f), "sha256": sha, "elementi": len(geo["features"])})
    return livelli(case)


def livello_kml(case, n):
    st = _stato(case)
    x = st.get("kml", [])[int(n)]
    return json.loads((Path(case.root) / "mappa" / Path(x["file"]).name).read_text(encoding="utf-8"))


def aggiungi_estratto(case, path):
    """Registra un file PMTiles locale scelto dall'analista: resta dov'è, non entra nel caso."""
    f = Path(str(path or ""))
    if not f.is_file():
        raise ValueError(tr("File non trovato."))
    with open(f, "rb") as fh:
        if fh.read(7) != b"PMTiles":
            raise ValueError(tr("Il file non è un estratto PMTiles."))
    st = _stato(case)
    st.setdefault("estratti", []).append({"path": str(f)})
    _salva(case, st)
    case.log("mappa_estratto", {"file": f.name, "percorso": str(f), "byte": f.stat().st_size})
    return livelli(case)


def percorso_estratto(case, n):
    return Path(_stato(case).get("estratti", [])[int(n)]["path"])


def esporta(G, case, b):
    """KML o GPX dei punti scelti, in export/mappa/, con SHA-256 e voce nel registro."""
    fmt = "gpx" if b.get("formato") == "gpx" else "kml"
    r = punti(case)
    scelte = set(b.get("categorie") or [])
    da, a = str(b.get("da") or ""), str(b.get("a") or "")
    sel = [p for p in r["punti"] if r["categorie"][p[2]]["nome"] in scelte and (not da or (p[4] and p[4][:10] >= da)) and (not a or (p[4] and p[4][:10] <= a))]
    if b.get("solo_preferiti"):        # i preferiti valgono in tutte le categorie, spuntate o no
        pr = set(r["preferiti"])
        sel = [p for p in r["punti"] if chiave(p) in pr and (not da or (p[4] and p[4][:10] >= da)) and (not a or (p[4] and p[4][:10] <= a))]
    id_voli = set(b.get("voli") or [])
    sc_voli = [v for v in r["voli"] if v["id"] in id_voli and v["punti"]]
    d = case.export_dir / "mappa"
    d.mkdir(parents=True, exist_ok=True)
    dest = G.unique(d / f"punti_{G.stamp_now()}.{fmt}")
    with open(dest, "w", encoding="utf-8") as fo:
        if fmt == "kml":
            fo.write('<?xml version="1.0" encoding="UTF-8"?>\n<kml xmlns="http://www.opengis.net/kml/2.2"><Document>\n')
            for v in sc_voli:
                coord = " ".join(f"{q[0]},{q[1]}" + (f",{q[2]}" if q[2] is not None else "") for q in v["punti"])
                fo.write(f"<Placemark><name>{escape(v['nome'])}</name><description>{escape(v['inizio'])} | {escape(v['file'])} | {v['sha256']}</description>"
                         f"<LineString><coordinates>{coord}</coordinates></LineString></Placemark>\n")
            for p in sel:
                fo.write(f"<Placemark><name>{escape(r['categorie'][p[2]]['nome'])}</name><description>{escape(p[5])} | {escape(p[3])}</description>"
                         f"<Point><coordinates>{p[0]},{p[1]}</coordinates></Point></Placemark>\n")
            fo.write("</Document></kml>\n")
        else:
            fo.write('<?xml version="1.0" encoding="UTF-8"?>\n<gpx version="1.1" creator="RepertIA" xmlns="http://www.topografix.com/GPX/1/1">\n')
            for v in sc_voli:
                fo.write(f"<trk><name>{escape(v['nome'])}</name><desc>{escape(v['file'])} | {v['sha256']}</desc><trkseg>")
                for q in v["punti"]:
                    fo.write(f'<trkpt lat="{q[1]}" lon="{q[0]}">' + (f"<ele>{q[2]}</ele>" if q[2] is not None else "") + "</trkpt>")
                fo.write("</trkseg></trk>\n")
            for p in sel:
                fo.write(f'<wpt lat="{p[1]}" lon="{p[0]}"><name>{escape(r["categorie"][p[2]]["nome"])}</name><desc>{escape(p[5])} | {escape(p[3])}</desc></wpt>\n')
            fo.write("</gpx>\n")
    sha = hashlib.sha256(dest.read_bytes()).hexdigest()
    dest.chmod(0o444)
    rel = str(dest.relative_to(case.root))
    case.log("mappa_esporta", {"formato": fmt, "punti": len(sel), "voli": [v["file"] for v in sc_voli], "categorie": sorted(scelte), "da": da, "a": a, "dest": rel, "sha256": sha})
    return {"message": tr("Esportate {n} righe in {rel} (SHA-256 {sha})").format(n=len(sel) + len(sc_voli), rel=rel, sha=sha)}
