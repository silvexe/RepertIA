# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (3.0): record cancellati nei database SQLite, letti dai byte di una copia di lavoro.

Sono risultati DA VERIFICARE: non sono mai mescolati alle righe del database. Si accetta una lettura solo se i conti
delle lunghezze tornano; se ne restano più d'una, il record è «ambiguo» e non vale come recupero. Livelli:
  integra   cella completa (pagina libera, WAL, spazio libero di una pagina): rowid presente
  testa     primo record di un freeblock: i primi 4 byte sono sovrascritti, il rowid è perso
  ambiguo   più letture possibili, o la tabella non si può stabilire
Una riga scritta prima di un ALTER TABLE ADD COLUMN ha meno colonne: le ultime vengono dal DEFAULT e sono segnate.
Solo libreria standard."""
import os
import shutil
import sqlite3
import struct
import tempfile
import time

MAX_RECORD = 20000
LIMITE_S = 120
MAX_TESTO = 4000
_SZ = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 7: 8, 8: 0, 9: 0}


class _Scaduto(Exception):
    pass


def _vi(b, o, lim=None):
    v = 0
    lim = len(b) if lim is None else lim
    for k in range(9):
        if o + k >= lim:
            return None, 0
        c = b[o + k]
        if k == 8:
            return (v << 8) | c, 9
        v = (v << 7) | (c & 127)
        if c < 128:
            return v, k + 1
    return None, 0


def _len_vi(n):
    k = 1
    while n >= 128:
        n >>= 7
        k += 1
    return k


def _size(s):
    if s < 10:
        return _SZ[s]
    if s in (10, 11):
        return None
    return (s - 12) // 2 if s % 2 == 0 else (s - 13) // 2


def _val(s, b):
    if s == 0:
        return "NULL"
    if s == 8:
        return "i0"
    if s == 9:
        return "i1"
    if s <= 6:
        return "i%d" % int.from_bytes(b, "big", signed=True)
    if s == 7:
        return "r%s" % struct.unpack(">d", b)[0]
    if s % 2 == 0:
        return "b%d" % len(b)
    return "t" + b.decode("utf-8")


def _compat(a, s):
    if s == 0:
        return True
    if a == "i":
        return s <= 6 or s in (8, 9)
    if a == "t":
        return s >= 13 and s % 2 == 1
    return _size(s) is not None


def _locale(p, u):
    x = u - 35
    if p <= x:
        return p
    m = ((u - 12) * 32 // 255) - 23
    k = m + (p - m) % (u - 4)
    return k if k <= x else m


def _leggi(path):
    data = open(path, "rb").read()
    ps = struct.unpack(">H", data[16:18])[0]
    ps = 65536 if ps == 1 else ps
    pag = {i + 1: data[i * ps:(i + 1) * ps] for i in range(len(data) // ps)}
    orig = dict(pag)
    ha, in_wal = False, {}
    w = path + "-wal"
    if os.path.exists(w) and os.path.getsize(w) > 32:
        d = open(w, "rb").read()
        salt = d[16:24]
        o = 32
        pend, pos = {}, {}
        while o + 24 + ps <= len(d):
            pn, comm = struct.unpack(">II", d[o:o + 8])
            if d[o + 8:o + 16] != salt:
                break
            pend[pn] = d[o + 24:o + 24 + ps]
            pos[pn] = o + 24
            if comm:
                pag.update(pend)
                in_wal.update(pos)
                pend, pos = {}, {}
                ha = True
            o += 24 + ps
    return data, ps, pag, orig, ha, in_wal


def _dflt(x):
    if x is None:
        return "NULL"
    x = x.strip().strip("()")
    if x.upper() == "NULL":
        return "NULL"
    if x[:1] in "'\"":
        return "t" + x[1:-1]
    try:
        return "i%d" % int(x)
    except ValueError:
        pass
    try:
        return "r%s" % float(x)
    except ValueError:
        return "?"


def _cvt(r):
    return ["NULL" if x is None else "i%d" % x if isinstance(x, int) else "r%s" % x if isinstance(x, float)
            else "b%d" % len(x) if isinstance(x, bytes) else "t" + x for x in r]


def _schema(path):
    """Schema e righe vive da una copia temporanea accanto al database (mai nella cartella temporanea di sistema)."""
    t = tempfile.mkdtemp(prefix="schema_", dir=os.path.dirname(path) or ".")
    q = os.path.join(t, "c.db")
    shutil.copy(path, q)
    if os.path.exists(path + "-wal"):
        shutil.copy(path + "-wal", q + "-wal")
    c = sqlite3.connect(q)
    s = {}
    try:
        for n, rp in c.execute("SELECT name, rootpage FROM sqlite_master WHERE type='table' AND rootpage>0").fetchall():
            q_n = '"' + n.replace('"', '""') + '"'
            cols = c.execute(f"PRAGMA table_info({q_n})").fetchall()
            pk = [x[0] for x in cols if x[5] == 1 and x[2].upper() == "INTEGER"]
            x = {"root": rp, "nomi": [y[1] for y in cols],
                 "cols": ["i" if "INT" in y[2].upper() else "t" if "TEXT" in y[2].upper() or "CHAR" in y[2].upper() else "x" for y in cols],
                 "pk": pk[0] if len(pk) == 1 and sum(1 for y in cols if y[5]) == 1 else -1, "df": [_dflt(y[4]) for y in cols]}
            try:
                vivi = [tuple(r) for r in c.execute(f"SELECT * FROM {q_n}")]
            except sqlite3.Error:
                vivi = []
            x["vs"] = {tuple(v for j, v in enumerate(_cvt(r)) if j != x["pk"]) for r in vivi}
            x["ids"] = {r[x["pk"]] for r in vivi} if x["pk"] >= 0 else set()
            s[n] = x
    finally:
        c.close()
        shutil.rmtree(t, ignore_errors=True)
    return s


def _foglie(pag, root):
    out, st, vis = [], [root], set()
    while st:
        n = st.pop()
        if n in vis or n not in pag:
            continue
        vis.add(n)
        p = pag[n]
        h = 100 if n == 1 else 0
        if p[h] == 13:
            out.append(n)
        elif p[h] == 5:
            st.append(struct.unpack(">I", p[h + 8:h + 12])[0])
            for i in range(struct.unpack(">H", p[h + 3:h + 5])[0]):
                o = struct.unpack(">H", p[h + 12 + 2 * i:h + 14 + 2 * i])[0]
                if o + 4 <= len(p):
                    st.append(struct.unpack(">I", p[o:o + 4])[0])
    return out


def _catena(pag, ps, pn, serve):
    b, vis = b"", set()
    while len(b) < serve:
        if not pn or pn in vis or pn not in pag:
            return None
        vis.add(pn)
        p = pag[pn]
        b += p[4:ps]
        pn = struct.unpack(">I", p[:4])[0]
    return b[:serve]


def _decodi(tipi, corpo):
    v, q = [], 0
    for t in tipi:
        n = _size(t)
        if n is None or q + n > len(corpo):
            return None
        try:
            v.append(_val(t, corpo[q:q + n]))
        except (UnicodeDecodeError, struct.error):
            return None
        q += n
    return v


def _cella(p, i, lim, ps, pag, ncols=None):
    """Cella intera in i: lunghezza dichiarata = intestazione + dati. -> (rowid, tipi, valori, fine)"""
    pl, a = _vi(p, i, lim)
    rid, b = _vi(p, i + a, lim) if a else (None, 0)
    if not a or not b or pl is None or rid is None or rid <= 0 or pl < 2 or pl > 1 << 30:
        return None
    s = i + a + b
    h, c = _vi(p, s, lim)
    if not c or h is None or h < c + 1 or h > pl or s + h > ps:
        return None
    tipi, q = [], s + c
    while q < s + h:
        t, k = _vi(p, q, s + h)
        if not k or t is None or _size(t) is None:
            return None
        tipi.append(t)
        q += k
    if q != s + h or not tipi or (ncols and len(tipi) > ncols) or h + sum(_size(t) for t in tipi) != pl:
        return None
    loc = _locale(pl, ps)
    if loc == pl:
        fine = s + pl
        if fine > lim:
            return None
        v = _decodi(tipi, p[s + h:fine])
        return (rid, tipi, v, fine) if v is not None else None
    fine = s + loc + 4
    if fine > lim:
        return None
    res = _catena(pag, ps, struct.unpack(">I", p[s + loc:s + loc + 4])[0], pl - loc)
    if res is None:
        return (rid, tipi, None, fine)         # overflow perso: la cella non si completa
    v = _decodi(tipi, p[s + h:s + loc] + res)
    return (rid, tipi, v, fine) if v is not None else None


def _completa(v, x):
    n = len(x["cols"])
    return v + x["df"][len(v):n], len(v) < n


def _adatta(tipi, x, stretto=True):
    c = x["cols"]
    if len(tipi) > len(c) or not tipi:
        return False
    m = sum(1 for a, t in zip(c, tipi) if not _compat(a, t))
    return m == 0 if stretto else m * 3 <= len(tipi)


def _senza(x, v):
    return tuple(y for j, y in enumerate(v) if j != x["pk"])


def _e_viva(x, v):
    w = _senza(x, v)
    if "?" not in w:
        return w in x["vs"]
    return any(len(y) == len(w) and all(a == "?" or a == b for a, b in zip(w, y)) for y in x["vs"])


def _testa(p, a, b, x, ps, pag):
    """Primo record di un freeblock. Nei 4 byte persi stanno lunghezza, rowid, lunghezza dell'intestazione e colonne
    iniziali: si accetta una lettura solo se i conti tornano e se finisce su un confine."""
    c = x["cols"]
    n, pk, cand = len(c), x["pk"], {}
    for s in range(a, min(a + 6, b)):
        for m in range(n, max(0, n - 4), -1):
            for persi in ((0, 1) if s == a else (0,)):
                if persi >= m:
                    continue
                q, tipi, ok = s, [], True
                for col in c[persi:m]:
                    t, k = _vi(p, q, b)
                    if not k or t is None or _size(t) is None or not _compat(col, t):
                        ok = False
                        break
                    tipi.append(t)
                    q += k
                if not ok or not tipi:
                    continue
                tot = sum(_size(t) for t in tipi)
                nsz = [j for j in range(persi) if j != pk]
                for slack in (range(0, 9) if nsz else (0,)):
                    fine = q + slack + tot
                    if fine > b:
                        break
                    pl = 1 + persi + (q - s) + slack + tot
                    lp = _len_vi(pl)
                    if s == a:
                        lr = 3 - persi - lp
                    else:
                        if p[s - 1] != (q - s) + 1:
                            continue
                        lr = (s - 1 - (a - 4)) - lp
                    if lr < 1 or fine - (a - 4) != lp + lr + pl:
                        continue
                    if not (b - fine <= 3 or _cella(p, fine, b, ps, pag, n)):
                        continue
                    v = _decodi(tipi, p[q + slack:fine])
                    if v is None or any(y.startswith("t") and any(ord(h) < 32 and h not in "\n\r\t" for h in y) for y in v):
                        continue
                    if not any(y not in ("NULL", "t", "i0", "i1") for y in v):
                        continue            # nessun valore significativo: non è un recupero
                    pers = []
                    for j in range(persi):
                        if j == pk:
                            pers.append("NULL")
                        elif len(nsz) == 1 and c[j] == "i" and slack in (1, 2, 3, 4, 6, 8):
                            pers.append("i%d" % int.from_bytes(p[q:q + slack], "big", signed=True))
                        else:
                            pers.append("?")
                    if persi <= pk < persi + len(v) and v[pk - persi] != "NULL":
                        continue
                    tutto = _completa(pers + v, x)[0]
                    cand.setdefault(tuple(tutto), (fine, persi + len(v)))
    if len(cand) > 1:           # a parità di conti, vale la lettura che finisce sul confine del freeblock
        al = {v: k for v, k in cand.items() if b - k[0] <= 3}
        if len(al) == 1:
            cand = al
    return cand


def limiti(path, ps, data, ha_wal):
    """Quello che si legge dal file e che riduce il recupero. secure_delete non è scritto nel file."""
    auto = struct.unpack(">I", data[52:56])[0] if len(data) >= 56 else 0
    incr = struct.unpack(">I", data[64:68])[0] if len(data) >= 68 else 0
    return {"page_size": ps, "auto_vacuum": "incremental" if auto and incr else "full" if auto else "off",
            "pagine_libere": struct.unpack(">I", data[36:40])[0] if len(data) >= 40 else 0, "wal": ha_wal}


def recupera(path):
    """-> {record: [...], limiti: {...}, troncato, scaduto, nomi: {tabella: colonne}}. Non scrive nel database."""
    data, ps, pag, orig, ha, in_wal = _leggi(path)
    s = _schema(path)
    t0 = time.monotonic()
    out, visti = [], set()

    def controlla():
        if time.monotonic() - t0 > LIMITE_S:
            raise _Scaduto
        if len(out) >= MAX_RECORD:
            raise OverflowError

    def aggiungi(livello, fonte, n, rid, pn, o, v, letti, in_w=None):
        x = s[n]
        k = (n, tuple(v))
        if k in visti or (livello != "ambiguo" and _e_viva(x, list(v))):
            return
        visti.add(k)
        v = list(v)
        if x["pk"] >= 0 and x["pk"] < len(v):       # il rowid è la chiave: mai un NULL o uno 0 che sembrino veri
            v[x["pk"]] = "i%d" % rid if rid is not None else "?"
        nomef = "wal" if in_w is not None else "db"
        off = in_w + o if in_w is not None else (pn - 1) * ps + o
        nc = len(x["nomi"])
        out.append({"livello": livello, "fonte": fonte, "tabella": n, "rowid": rid, "pagina": pn, "offset": off, "file": nomef,
                    "valori": v, "dal_default": list(range(letti, nc))})
        controlla()

    def scorri(p, pn, a, b, n, x, fonte, in_w):
        i = a
        while i < b - 2:
            r = _cella(p, i, b, ps, pag, len(x["cols"]))
            if r and _adatta(r[1], x, False) and any(t >= 13 or t in range(1, 7) for t in r[1]):
                if r[2] is not None:
                    aggiungi("integra", fonte, n, r[0], pn, i, _completa(r[2], x)[0], len(r[2]), in_w)
                i = r[3]
            else:
                i += 1

    troncato = scaduto = False
    try:
        st, liberi = struct.unpack(">I", pag[1][32:36])[0], set()
        while st and st in pag and st not in liberi:
            p = pag[st]
            liberi.add(st)
            k = struct.unpack(">I", p[4:8])[0]
            for i in range(min(k, (ps - 8) // 4)):
                liberi.add(struct.unpack(">I", p[8 + 4 * i:12 + 4 * i])[0])
            st = struct.unpack(">I", p[:4])[0]
        for pn in sorted(liberi):
            p = pag.get(pn)
            if not p or p[0] != 13:
                continue
            for i in range(min(struct.unpack(">H", p[3:5])[0], (ps - 8) // 2)):
                o = struct.unpack(">H", p[8 + 2 * i:10 + 2 * i])[0]
                r = _cella(p, o, ps, ps, pag) if o + 2 < ps else None
                if not r or not r[2]:
                    continue
                tt = [n for n, x in s.items() if _adatta(r[1], x)]
                if tt:
                    n = tt[0]
                    aggiungi("integra" if len(tt) == 1 else "ambiguo", "pagina_libera", n, r[0], pn, o, _completa(r[2], s[n])[0], len(r[2]), in_wal.get(pn))
        if ha:
            for n, x in s.items():
                for pn in _foglie(orig, x["root"]):
                    p = orig[pn]
                    h = 100 if pn == 1 else 0
                    for i in range(struct.unpack(">H", p[h + 3:h + 5])[0]):
                        o = struct.unpack(">H", p[h + 8 + 2 * i:h + 10 + 2 * i])[0]
                        r = _cella(p, o, ps, ps, orig, len(x["cols"]))
                        if r and r[2] and (x["pk"] < 0 or r[0] not in x["ids"]):
                            aggiungi("integra", "cancellata_nel_wal", n, r[0], pn, o, _completa(r[2], x)[0], len(r[2]))
        for n, x in s.items():
            for pn in _foglie(pag, x["root"]):
                p = pag[pn]
                h = 100 if pn == 1 else 0
                nc = struct.unpack(">H", p[h + 3:h + 5])[0]
                cc = struct.unpack(">H", p[h + 5:h + 7])[0] or 65536
                in_w = in_wal.get(pn)
                fb, vis = struct.unpack(">H", p[h + 1:h + 3])[0], set()
                while fb and fb + 4 <= ps and fb not in vis:
                    vis.add(fb)
                    nx, sz = struct.unpack(">HH", p[fb:fb + 4])
                    e = min(fb + sz, ps)
                    c = _testa(p, fb + 4, e, x, ps, pag)
                    dopo = fb + 4
                    if c:
                        lv = "testa" if len(c) == 1 else "ambiguo"
                        for v, (f, letti) in c.items():
                            if not _e_viva(x, list(v)):
                                aggiungi(lv, "spazio_libero", n, None, pn, fb, list(v), letti, in_w)
                        dopo = max(q[0] for q in c.values())
                    scorri(p, pn, dopo, e, n, x, "spazio_libero", in_w)
                    fb = nx
                scorri(p, pn, h + 8 + 2 * nc, cc, n, x, "spazio_libero", in_w)
    except _Scaduto:
        scaduto = True
    except OverflowError:
        troncato = True
    for r in out:
        r["valori"] = [_mostra(v) for v in r["valori"]]
    return {"record": out, "limiti": limiti(path, ps, data, ha), "troncato": troncato, "scaduto": scaduto,
            "nomi": {n: x["nomi"] for n, x in s.items()}}


def _mostra(v):
    if v == "NULL":
        return ["n", ""]
    if v == "?":
        return ["?", ""]
    if v[:1] == "b":
        return ["b", v[1:]]
    s = v[1:]
    return [v[0], s[:MAX_TESTO], True] if len(s) > MAX_TESTO else [v[0], s]
