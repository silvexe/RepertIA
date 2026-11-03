# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (3.0): scarica un estratto di mappa da Protomaps (formato PMTiles v3), solo su richiesta dell'analista e solo
senza un caso aperto: il controllo è nel server. Si chiedono solo zone dell'elenco, mai un riquadro libero, così il server
esterno non può ricavare il luogo di un'indagine. Dati OpenStreetMap (ODbL), separati dal programma.
Solo libreria standard."""
import gzip
import hashlib
import json
import math
import os
import struct
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from forense_lingua import tr

BUILDS = "https://build-metadata.protomaps.dev/builds.json"
BASE = "https://build.protomaps.com/"
UA = {"User-Agent": "RepertIA"}
MAX_TESSERE = 30_000_000
BLOCCO = 8 << 20
SALTO = 1 << 20
LIVELLI = {"z6": 6, "z10": 10, "z12": 12, "z15": 15}
ANNULLA = threading.Event()


def cartella():
    """Mappe comuni a tutti i casi, accanto alle impostazioni."""
    import forense_agent as fa
    d = Path(fa.SETTINGS_PATH).parent / "mappe"
    d.mkdir(parents=True, exist_ok=True)
    return d


def elenco_zone():
    f = Path(__file__).resolve().parent / "forense_mappe_elenco.json"
    return json.loads(f.read_text(encoding="utf-8"))


def _get(url, ini=None, fine=None, tentativi=4, esatto=True):
    h = dict(UA)
    if ini is not None:
        h["Range"] = f"bytes={ini}-{fine}"
    for k in range(tentativi):
        if ANNULLA.is_set():
            raise InterruptedError
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=60) as r:
                d = r.read()
            if esatto and ini is not None and len(d) != fine - ini + 1:
                raise OSError("lunghezza inattesa")
            return d
        except OSError:
            if k == tentativi - 1:
                raise
            time.sleep(1 + 2 * k)
    raise OSError


def ultima_data():
    d = json.loads(_get(BUILDS).decode("utf-8"))
    return d[-1]["key"]


def _rot(n, x, y, rx, ry):
    if ry == 0:
        if rx != 0:
            x, y = n - 1 - x, n - 1 - y
        x, y = y, x
    return x, y


def zxy_id(z, x, y):
    """Numero della tessera sulla curva di Hilbert (specifica PMTiles v3)."""
    acc = ((1 << (2 * z)) - 1) // 3
    a, tx, ty, s = z - 1, x, y, 0
    while a >= 0:
        rx = 1 if tx & (1 << a) else 0
        ry = 1 if ty & (1 << a) else 0
        s += ((3 * rx) ^ ry) << (2 * a)
        tx, ty = _rot(1 << (a + 1), tx & ((1 << (a + 1)) - 1), ty & ((1 << (a + 1)) - 1), rx, ry)
        a -= 1
    return acc + s


def _xy(lon, lat, z):
    lat = max(-85.0511, min(85.0511, lat))
    n = 1 << z
    x = int((lon + 180) / 360 * n)
    r = math.radians(lat)
    y = int((1 - math.log(math.tan(r) + 1 / math.cos(r)) / math.pi) / 2 * n)
    return max(0, min(n - 1, x)), max(0, min(n - 1, y))


def tessere(parti, zmax):
    """Numeri delle tessere che coprono i riquadri fino allo zoom zmax. Vuoto = tutto il mondo."""
    ids = set()
    for z in range(zmax + 1):
        for w, s, e, n in parti or [[-180, -85.0511, 180, 85.0511]]:
            x0, y0 = _xy(w, n, z)
            x1, y1 = _xy(e, s, z)
            for x in range(x0, x1 + 1):
                for y in range(y0, y1 + 1):
                    ids.add(zxy_id(z, x, y))
        if len(ids) > MAX_TESSERE:
            raise ValueError(tr("Zona troppo grande per questo livello di dettaglio."))
    return ids


def _varint(b, o):
    v = s = 0
    while True:
        c = b[o]
        o += 1
        v |= (c & 127) << s
        if c < 128:
            return v, o
        s += 7


def _dir_leggi(b):
    n, o = _varint(b, 0)
    ids, run, lun, off = [0] * n, [0] * n, [0] * n, [0] * n
    u = 0
    for i in range(n):
        d, o = _varint(b, o)
        u += d
        ids[i] = u
    for a in (run, lun):
        for i in range(n):
            a[i], o = _varint(b, o)
    for i in range(n):
        v, o = _varint(b, o)
        off[i] = off[i - 1] + lun[i - 1] if v == 0 and i > 0 else v - 1
    return list(zip(ids, run, off, lun))


def _vi(v):
    out = bytearray()
    while v >= 128:
        out.append((v & 127) | 128)
        v >>= 7
    out.append(v)
    return bytes(out)


def _dir_scrivi(voci):
    parti = [_vi(len(voci))]
    u = 0
    for e in voci:
        parti.append(_vi(e[0] - u))
        u = e[0]
    parti += [_vi(e[1]) for e in voci]
    parti += [_vi(e[3]) for e in voci]
    for i, e in enumerate(voci):
        parti.append(_vi(0) if i > 0 and e[2] == voci[i - 1][2] + voci[i - 1][3] else _vi(e[2] + 1))
    return gzip.compress(b"".join(parti), mtime=0)


def _intestazione(url):
    h = _get(url, 0, 16383, esatto=False)   # testata e radice stanno nei primi 16 KB
    if h[:7] != b"PMTiles" or h[7] != 3:
        raise ValueError(tr("Il file non è un estratto PMTiles."))
    k = struct.unpack("<QQQQQQQQ", h[8:72])
    q = dict(zip(("root_o", "root_l", "meta_o", "meta_l", "leaf_o", "leaf_l", "dati_o", "dati_l"), k))
    q["ic"], q["tc"], q["tt"], q["minz"], q["maxz"] = h[97], h[98], h[99], h[100], h[101]
    if q["ic"] != 2:
        raise ValueError(tr("Formato della mappa non supportato."))
    q["testa"] = h
    return q


def _voci(url, q, ids, progress):
    """Voci delle tessere chieste: si leggono solo le directory foglia che servono."""
    radice = _dir_leggi(gzip.decompress(q["testa"][q["root_o"]:q["root_o"] + q["root_l"]]))
    srt = sorted(ids)
    import bisect
    tess, foglie = [], []
    for i, e in enumerate(radice):
        fine = radice[i + 1][0] if i + 1 < len(radice) else 1 << 62
        a = bisect.bisect_left(srt, e[0])
        if a >= len(srt) or srt[a] >= fine:
            continue
        if e[1] == 0:
            foglie.append(e)
        else:
            tess.append(e)
    fatte = [0]

    def leggi(e):
        d = _dir_leggi(gzip.decompress(_get(url, q["leaf_o"] + e[2], q["leaf_o"] + e[2] + e[3] - 1)))
        fatte[0] += 1
        progress({"msg": tr("Lettura dell'indice della mappa: {a} di {b}").format(a=fatte[0], b=len(foglie))})
        return d

    with ThreadPoolExecutor(4) as ex:
        for d in ex.map(leggi, foglie):
            tess.extend(d)
    out = []
    for tid, run, off, lun in tess:
        a = bisect.bisect_left(srt, tid)
        while a < len(srt) and srt[a] < tid + run:
            out.append((srt[a], off, lun))
            a += 1
    out.sort()
    return out


def stima(data, parti, zmax, progress=lambda _x: None):
    """Peso previsto, in byte: legge solo l'indice."""
    url = BASE + data + ".pmtiles"
    q = _intestazione(url)
    v = _voci(url, q, tessere(parti, min(zmax, q["maxz"])), progress)
    return {"byte": sum(lun for _o, lun in {(x[1], x[2]) for x in v}), "tessere": len(v), "data": data}


def scarica(nome, parti, zmax, data, dest, progress):
    """Scrive l'estratto in dest, passando da un file .parziale: se qualcosa va storto non resta nulla a metà."""
    ANNULLA.clear()
    url = BASE + data + ".pmtiles"
    q = _intestazione(url)
    zmax = min(zmax, q["maxz"])
    v = _voci(url, q, tessere(parti, zmax), progress)
    if not v:
        raise ValueError(tr("Nessuna tessera per questa zona."))
    uniche = sorted({(o, l) for _t, o, l in v})
    tot = sum(l for _o, l in uniche)
    blocchi, cor = [], [uniche[0]]
    for e in uniche[1:]:
        ult = cor[-1]
        if e[0] - (ult[0] + ult[1]) > SALTO or e[0] + e[1] - cor[0][0] > BLOCCO:
            blocchi.append(cor)
            cor = [e]
        else:
            cor.append(e)
    blocchi.append(cor)
    posto = {}
    n = 0
    for o, l in uniche:
        posto[(o, l)] = n
        n += l
    parz = Path(str(dest) + ".parziale")
    fatti, t0, lock = [0], time.time(), threading.Lock()
    h_ric = q["dati_o"]

    def prendi(b):
        ini, fine = b[0][0], b[-1][0] + b[-1][1] - 1
        d = _get(url, h_ric + ini, h_ric + fine)
        return b, ini, d

    try:
        tmp = open(parz, "wb")
        testa_len = 127
        # directory e metadati si conoscono ora: si scrivono prima dei dati, come nella specifica
        voci = []
        for t, o, l in v:
            p = posto[(o, l)]
            if voci and voci[-1][2] == p and voci[-1][3] == l and voci[-1][0] + voci[-1][1] == t:
                voci[-1][1] += 1
            else:
                voci.append([t, 1, p, l])
        root, leaves = _dirs([tuple(x) for x in voci])
        meta = gzip.decompress(_get(url, q["meta_o"], q["meta_o"] + q["meta_l"] - 1))
        try:
            mj = json.loads(meta)
        except ValueError:
            mj = {}
        mj["repertia"] = {"zona": nome, "data_dati": data, "maxzoom": zmax}
        meta = gzip.compress(json.dumps(mj).encode("utf-8"), mtime=0)
        ro, mo, lo = testa_len, testa_len + len(root), testa_len + len(root) + len(meta)
        dato = lo + len(leaves)
        tmp.write(b"\0" * 127 + root + meta + leaves)
        tmp.truncate(dato + tot)
        with ThreadPoolExecutor(4) as ex:
            for b, ini, d in ex.map(prendi, blocchi):
                for o, l in b:
                    tmp.seek(dato + posto[(o, l)])
                    tmp.write(d[o - ini:o - ini + l])
                with lock:
                    fatti[0] += sum(l for _o, l in b)
                progress({"msg": tr("Scarico {f}: {a} di {b} MB").format(f=nome, a=fatti[0] >> 20, b=max(1, tot >> 20)),
                          "pct": round(100 * fatti[0] / max(1, tot), 1), "fatti": fatti[0], "totale": tot})
        lats = [x for p in (parti or [[-180, -85, 180, 85]]) for x in (p[1], p[3])]
        lons = [x for p in (parti or [[-180, -85, 180, 85]]) for x in (p[0], p[2])]
        w, s, e_, n_ = min(lons), min(lats), max(lons), max(lats)
        clust = 1 if all(voci[i][2] >= voci[i - 1][2] for i in range(1, len(voci))) else 0
        intest = b"PMTiles\x03" + struct.pack("<QQQQQQQQQQQ", ro, len(root), mo, len(meta), lo, len(leaves), dato, tot,
                                              len(v), len(voci), len(uniche))
        intest += bytes([clust, q["ic"], q["tc"], q["tt"], q["minz"], zmax])
        cz = max(q["minz"], min(zmax, 6))
        intest += struct.pack("<iiii", int(w * 1e7), int(s * 1e7), int(e_ * 1e7), int(n_ * 1e7))
        intest += bytes([cz]) + struct.pack("<ii", int((w + e_) / 2 * 1e7), int((s + n_) / 2 * 1e7))
        tmp.seek(0)
        tmp.write(intest)
        tmp.close()
        h = hashlib.sha256()
        with open(parz, "rb") as fh:
            for x in iter(lambda: fh.read(1 << 20), b""):
                h.update(x)
        sha = h.hexdigest()
        os.replace(parz, dest)
    except BaseException:
        try:
            tmp.close()
        except (OSError, NameError):
            pass
        parz.unlink(missing_ok=True)
        raise
    info = {"zona": nome, "data_dati": data, "maxzoom": zmax, "sha256": sha, "byte": os.path.getsize(dest), "fonte": url,
            "tempo_s": round(time.time() - t0)}
    Path(str(dest) + ".json").write_text(json.dumps(info, ensure_ascii=False), encoding="utf-8")
    return info


def _dirs(voci):
    """Directory radice e foglie: se la radice supera 16 KB le voci si spezzano in foglie (specifica v3)."""
    r = _dir_scrivi(voci)
    if len(r) <= 16257:
        return r, b""
    passo = 4096
    while True:
        foglie, rad, o = bytearray(), [], 0
        for i in range(0, len(voci), passo):
            pz = voci[i:i + passo]
            d = _dir_scrivi(pz)
            rad.append((pz[0][0], 0, o, len(d)))
            foglie += d
            o += len(d)
        r = _dir_scrivi(rad)
        if len(r) <= 16257:
            return r, bytes(foglie)
        passo *= 2
