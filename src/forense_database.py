# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (3.0): gestore dei database SQLite trovati nella copia o nell'estrazione.

Si lavora sempre su una copia di lavoro nella cartella del caso, con i file -wal, -shm e -journal accanto se ci sono;
l'originale non è mai toccato. Le query passano da un autorizzatore che ammette solo letture (nessuna scrittura, ATTACH,
estensione o PRAGMA che non sia di sola consultazione). Ogni query scritta dall'analista va nel registro del caso."""
import csv
import hashlib
import json
import re
import shutil
import sqlite3
import tempfile
import threading
import time
import uuid
from pathlib import Path

from forense_lingua import tr

SUFFISSI = ("-wal", "-shm", "-journal")
PREFISSO = "dbgest_"
MAX_SESSIONI = 4
MAX_PER_PAGINA = 1000
MAX_CSV = 1_000_000
MAX_TESTO = 4000
LIMITE_S = 30
PRAGMA_OK = {"table_info", "table_xinfo", "table_list", "index_list", "index_info", "index_xinfo", "foreign_key_list",
             "database_list", "user_version", "application_id", "page_size", "page_count", "freelist_count",
             "encoding", "journal_mode", "auto_vacuum", "secure_delete", "schema_version"}
FUNZIONI_NO = {"load_extension", "fts3_tokenizer", "readfile", "writefile", "edit"}
_SESS = {}
_LOCK = threading.Lock()


def _autorizza(azione, a1, a2, _nome_db, _trigger):
    """Solo letture. PRAGMA: elenco chiuso e senza valore da impostare (journal_mode=… cambierebbe il file)."""
    if azione in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_RECURSIVE):
        return sqlite3.SQLITE_OK
    if azione == sqlite3.SQLITE_FUNCTION:
        return sqlite3.SQLITE_DENY if str(a2 or "").lower() in FUNZIONI_NO else sqlite3.SQLITE_OK
    if azione == sqlite3.SQLITE_PRAGMA and str(a1 or "").lower() in PRAGMA_OK:
        if a2 is None or str(a1).lower().endswith(("_info", "_xinfo", "_list")):
            return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _sha(f):
    h = hashlib.sha256()
    with open(f, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _accanto_disco(G, case, it, tmp, nome):
    """File -wal/-shm/-journal accanto al database in una copia di disco (stessa cartella, stesso nome + suffisso)."""
    if it.get("source") != "fs":
        return
    try:
        con = G.nav_db(case)
    except (ValueError, sqlite3.Error):
        return
    try:
        for suf in SUFFISSI:
            r = con.execute("SELECT inode FROM nav WHERE part=? AND path=? AND isdir=0 AND deleted=0 LIMIT 1",
                            (it["part"], it["path"] + suf)).fetchone()
            if not r:
                continue
            _, f = G.file_size(case, G.file_ident(case, {"part": it["part"], "inode": r[0]}))
            if f:
                shutil.copyfile(f, tmp / (nome + suf))
    finally:
        con.close()


def _copia_lavoro(G, case, it):
    tmp = Path(tempfile.mkdtemp(prefix=PREFISSO, dir=str(case.root)))
    try:
        if it.get("source") == "fs" and G.fa.is_mobile(case):
            import forense_mobile_chat as fmc
            import forense_mobile_gui as fmg
            path = fmg._mx_path(case, it["part"], it["inode"]) or it.get("path") or ""
            w = fmc.WorkDB(case, int(it["part"]), it["inode"], path, None)
            try:
                w.db.close()
                nome = w.file.name
                for suf in ("",) + SUFFISSI:       # solo i file attesi: su exFAT macOS crea e toglie da solo i «._nome»
                    f = w.tmp / (nome + suf)
                    if f.exists():
                        shutil.move(str(f), str(tmp / f.name))
            finally:
                shutil.rmtree(w.tmp, ignore_errors=True)
        else:
            _, f = G.file_size(case, it)
            if not f:
                raise ValueError(tr("File molto grande: usa la vista esadecimale."))
            nome = Path(it.get("name") or "database").name or "database"
            shutil.copyfile(f, tmp / nome)
            _accanto_disco(G, case, it, tmp, nome)
    except FileNotFoundError:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError(tr("Copia forense non raggiungibile: ricollegala con «Collega copia forense» nel menu Caso."))
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return tmp, tmp / nome


def _apri_con(f):
    con = sqlite3.connect(str(f), isolation_level=None, check_same_thread=False)
    con.execute("PRAGMA query_only=ON")
    con.set_authorizer(_autorizza)
    return con


def _chiudi(s):
    try:
        s["con"].close()
    finally:
        shutil.rmtree(s["tmp"], ignore_errors=True)


def pulisci_vecchie(case):
    """Copie di lavoro rimaste da un'esecuzione interrotta."""
    attive = {str(s["tmp"]) for s in _SESS.values()}
    for d in Path(case.root).glob(PREFISSO + "*"):
        if d.is_dir() and str(d) not in attive:
            shutil.rmtree(d, ignore_errors=True)


def tabelle(con):
    out = []
    righe = con.execute("SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY type, name").fetchall()
    for nome, tipo in righe:
        q = '"' + nome.replace('"', '""') + '"'
        try:
            cols = [r[1] for r in con.execute(f"PRAGMA table_info({q})")]
            n = con.execute(f"SELECT COUNT(*) FROM {q}").fetchone()[0]
            err = None
        except sqlite3.Error as e:
            cols, n, err = [], None, str(e)
        out.append({"nome": nome, "tipo": tipo, "righe": n, "colonne": cols, "errore": err})
    return out


def _formato(b):
    """Cosa si riconosce dai primi byte di un file con estensione da database che non è SQLite: solo firme certe."""
    if not b:
        return tr("file vuoto")
    if not b.strip(b"\x00"):
        return tr("solo byte a zero")
    if b[:4] in (b"CMMM", b"IMMM"):
        return tr("cache delle miniature di Windows (thumbcache)")
    if b[4:8] == b"\xef\xcd\xab\x89":
        return tr("database ESE di Windows")
    if b[12:16] in (b"\x00\x06\x15\x61", b"\x61\x15\x06\x00", b"\x00\x05\x31\x62", b"\x62\x31\x05\x00"):
        return tr("Berkeley DB")
    return tr("non riconosciuto; primi byte: {h}").format(h=b[:8].hex(" "))


def apri(G, case, b):
    it = G.file_ident(case, b)
    with _LOCK:
        pulisci_vecchie(case)
        while len(_SESS) >= MAX_SESSIONI:
            _chiudi(_SESS.pop(next(iter(_SESS))))
    tmp, f = _copia_lavoro(G, case, it)
    try:
        with open(f, "rb") as fh:
            testa = fh.read(4096)
        if testa[:16] != b"SQLite format 3\x00":
            shutil.rmtree(tmp, ignore_errors=True)
            return {"non_sqlite": True, "nome": f.name, "percorso": it.get("path"), "formato": _formato(testa)}
        impronte = {f.name: _sha(f)}
        for suf in SUFFISSI:
            x = tmp / (f.name + suf)
            if x.exists():
                impronte[x.name] = _sha(x)
        con = _apri_con(f)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    sid = uuid.uuid4().hex
    fonte = {k: it.get(k) for k in ("source", "part", "inode", "path", "name", "id")}
    with _LOCK:
        _SESS[sid] = {"con": con, "tmp": tmp, "file": f, "root": str(case.root), "fonte": fonte, "impronte": impronte,
                      "lock": threading.Lock()}
    accanto = sorted(x for x in impronte if x != f.name)
    try:
        elenco_t = tabelle(con)
    except sqlite3.Error as e:          # database danneggiato o formato non supportato: nessuna copia resta nel caso
        with _LOCK:
            _chiudi(_SESS.pop(sid))
        case.log("db_apri", {"file": it.get("path"), "impronte": impronte, "esito": "errore", "errore": str(e)[:300]})
        raise ValueError(tr("Database non leggibile: {e}").format(e=e))
    case.log("db_apri", {"file": it.get("path"), "part": it.get("part"), "inode": it.get("inode"), "impronte": impronte})
    return {"id": sid, "nome": f.name, "percorso": it.get("path"), "impronte": impronte, "accanto": accanto,
            "tabelle": elenco_t}


def _sess(case, b):
    s = _SESS.get(str(b.get("id") or ""))
    if not s or s["root"] != str(case.root):
        raise ValueError(tr("Database non più aperto: riaprilo dall'anteprima."))
    return s


def _cella(v):
    if v is None:
        return ["n", ""]
    if isinstance(v, bool) or isinstance(v, int):
        return ["i", str(v)]
    if isinstance(v, float):
        return ["r", repr(v)]
    if isinstance(v, (bytes, memoryview)):
        v = bytes(v)
        return ["b", tr("[{n} byte] ").format(n=len(v)) + v[:32].hex(" ")]
    s = str(v)
    return ["t", s[:MAX_TESTO], True] if len(s) > MAX_TESTO else ["t", s]


def _esegui(s, sql):
    fine = time.monotonic() + LIMITE_S
    s["con"].set_progress_handler(lambda: 1 if time.monotonic() > fine else 0, 20000)
    return s["con"].execute(sql)


def query(case, b):
    """Una pagina di risultati. Sola lettura garantita dall'autorizzatore, non dal testo della query."""
    s = _sess(case, b)
    sql = str(b.get("sql") or "").strip()
    if not sql:
        raise ValueError(tr("Scrivi una query."))
    per = max(1, min(int(b.get("per") or 200), MAX_PER_PAGINA))
    pagina = max(0, int(b.get("pagina") or 0))
    scritta = bool(b.get("scritta"))
    voce = {"file": s["fonte"].get("path"), "part": s["fonte"].get("part"), "inode": s["fonte"].get("inode"), "sql": sql[:20000]}
    t0 = time.monotonic()
    with s["lock"]:
        try:
            cur = _esegui(s, sql)
            cols = [c[0] for c in cur.description or []]
            for _ in range(pagina * per):
                if cur.fetchone() is None:
                    break
            righe = cur.fetchmany(per + 1)
            altre = len(righe) > per
            righe = [[_cella(v) for v in r] for r in righe[:per]]
            cur.close()
        except (sqlite3.Error, sqlite3.Warning, ValueError) as e:
            if scritta and pagina == 0:
                case.log("db_query", {**voce, "esito": "errore", "errore": str(e)[:300]})
            raise ValueError(tr("Query non eseguita: {e}").format(e=e))
        finally:
            s["con"].set_progress_handler(None, 0)
    if scritta and pagina == 0:
        case.log("db_query", {**voce, "esito": "ok", "colonne": cols, "righe_prima_pagina": len(righe)})
    return {"colonne": cols, "righe": righe, "pagina": pagina, "per": per, "altre": altre,
            "ms": round((time.monotonic() - t0) * 1000)}


def _csv_v(v):
    if v is None:
        return ""
    if isinstance(v, (bytes, memoryview)):
        return bytes(v).hex()
    return v


def esporta_csv(G, case, b):
    s = _sess(case, b)
    sql = str(b.get("sql") or "").strip()
    if not sql:
        raise ValueError(tr("Scrivi una query."))
    d = case.export_dir / "database"
    d.mkdir(parents=True, exist_ok=True)
    dest = G.unique(d / f"{G.safe_part(Path(s['file'].name).stem)}_{G.stamp_now()}.csv")
    n = 0
    with s["lock"]:
        try:
            cur = _esegui(s, sql)
            with open(dest, "w", newline="", encoding="utf-8-sig") as fo:
                w = csv.writer(fo)
                w.writerow([c[0] for c in cur.description or []])
                for r in cur:
                    if n >= MAX_CSV:
                        break
                    w.writerow([_csv_v(v) for v in r])
                    n += 1
        except (sqlite3.Error, sqlite3.Warning, ValueError) as e:
            dest.unlink(missing_ok=True)
            raise ValueError(tr("Query non eseguita: {e}").format(e=e))
        finally:
            s["con"].set_progress_handler(None, 0)
    sha = _sha(dest)
    dest.chmod(0o444)
    rel = str(dest.relative_to(case.root))
    troncato = n >= MAX_CSV
    case.log("db_csv", {"file": s["fonte"].get("path"), "sql": sql[:20000], "righe": n, "troncato": troncato, "dest": rel, "sha256": sha})
    msg = tr("Esportate {n} righe in {rel} (SHA-256 {sha})").format(n=n, rel=rel, sha=sha)
    if troncato:
        msg += " " + tr("Esportazione fermata a {n} righe.").format(n=MAX_CSV)
    return {"message": msg, "path": rel, "righe": n, "sha256": sha}


def preferito(G, case, b):
    """Aggiunge il database ai Preferiti; nella nota la query e i valori della riga scelta."""
    s = _sess(case, b)
    f = s["fonte"]
    sql = " ".join(str(b.get("sql") or "").split())
    riga = b.get("riga") or {}
    valori = "; ".join(f"{k} = {v}" for k, v in riga.items())
    nota = (str(b.get("note") or "").strip() + "\n" + tr("Query: {sql}").format(sql=sql) + "\n"
            + tr("Riga: {valori}").format(valori=valori)).strip()[:2000]
    item = {"source": f.get("source") or "fs", "id": f.get("id"), "part": f.get("part"), "inode": f.get("inode"),
            "path": f.get("path"), "name": f.get("name")}
    r = G.bm_add(case, {"cat": b.get("cat"), "note": nota, "item": item})
    case.log("db_preferito", {"file": f.get("path"), "sql": sql[:20000], "riga": valori[:2000], "categoria": b.get("cat")})
    return r


NOMI_DB = ("history", "cookies", "login data", "web data", "favicons", "top sites", "places", "shortcuts")
EST_DB = (".db", ".sqlite", ".sqlite3", ".db3", ".sqlitedb", ".storedata", ".sql3")
MAX_ELENCO = 5000


def elenco(G, case):
    """Candidati database del caso, per estensione o nome noto: se un file è davvero SQLite lo controlla l'apertura."""
    con = G.nav_db(case)
    try:
        q = " OR ".join(["lower(path) LIKE ?"] * len(EST_DB) + ["lower(name)=?"] * len(NOMI_DB))
        righe = con.execute(f"SELECT part, inode, path, name, size, deleted FROM nav WHERE isdir=0 AND ({q}) ORDER BY deleted, path LIMIT ?",
                            ["%" + e for e in EST_DB] + list(NOMI_DB) + [MAX_ELENCO + 1]).fetchall()
    finally:
        con.close()
    return {"file": [{"part": r[0], "inode": r[1], "path": r[2], "name": r[3], "size": r[4], "deleted": r[5]} for r in righe[:MAX_ELENCO]],
            "troncato": len(righe) > MAX_ELENCO}


def _like(t):
    return "%" + t.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def cerca(case, b):
    """Cerca un valore in tutte le colonne di tutte le tabelle (senza distinguere maiuscole ASCII); i BLOB sono confrontati come
    testo. Con `recuperati` anche nei record cancellati. Dice in quali tabelle e colonne si trova, non cambia nulla."""
    s = _sess(case, b)
    t = str(b.get("testo") or "").strip()
    if not t:
        raise ValueError(tr("Scrivi il valore da cercare."))
    pat, tabs, parziale = _like(t), [], False
    fine = time.monotonic() + LIMITE_S
    with s["lock"]:
        s["con"].set_progress_handler(lambda: 1 if time.monotonic() > fine else 0, 20000)
        try:
            nomi = [r[0] for r in s["con"].execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()]
            for nome in nomi:
                q = '"' + nome.replace('"', '""') + '"'
                try:
                    cols = [r[1] for r in s["con"].execute(f"PRAGMA table_info({q})")]
                    trovate = []
                    for c in cols:
                        qc = '"' + c.replace('"', '""') + '"'
                        n = s["con"].execute(f"SELECT COUNT(*) FROM {q} WHERE {qc} LIKE ? ESCAPE '\\'", (pat,)).fetchone()[0]
                        if n:
                            trovate.append({"colonna": c, "righe": n})
                except sqlite3.OperationalError as e:
                    if "interrupt" in str(e).lower():
                        parziale = True
                        break
                    continue            # tabella virtuale o funzione non disponibile
                except sqlite3.Error:
                    continue
                if trovate:
                    lit = "'" + pat.replace("'", "''") + "'"
                    w = " OR ".join('"' + x["colonna"].replace('"', '""') + f'" LIKE {lit} ESCAPE \'\\\'' for x in trovate)
                    tabs.append({"tabella": nome, "colonne": trovate, "sql": f"SELECT * FROM {q} WHERE {w}"})
        finally:
            s["con"].set_progress_handler(None, 0)
    rec = None
    if b.get("recuperati"):
        r = recuperati(case, b)
        tl = t.lower()
        rec = {}
        for x in r["record"]:
            if any(v[0] in "tir" and tl in str(v[1]).lower() for v in x["valori"]):
                rec[x["tabella"]] = rec.get(x["tabella"], 0) + 1
    case.log("db_cerca", {"file": s["fonte"].get("path"), "testo": t[:500], "tabelle": [x["tabella"] for x in tabs],
                          "record_cancellati": rec, "parziale": parziale})
    return {"testo": t, "tabelle": tabs, "recuperati": rec, "parziale": parziale}


def recuperati(case, b):
    """(3.0) Record cancellati letti dai byte della copia di lavoro: una volta per sessione, sempre da verificare."""
    import forense_recupero as fr
    s = _sess(case, b)
    with s["lock"]:
        if "recupero" not in s:
            r = fr.recupera(str(s["file"]))
            for i, x in enumerate(r["record"]):
                x["n"] = i
                x["riscontri"] = []
            r["csv"] = []
            s["recupero"] = r
            liv = {}
            for x in r["record"]:
                liv[x["livello"]] = liv.get(x["livello"], 0) + 1
            case.log("db_recupero", {"file": s["fonte"].get("path"), "impronte": s["impronte"], "record": len(r["record"]),
                                     "livelli": liv, "limiti": r["limiti"], "troncato": r["troncato"], "scaduto": r["scaduto"]})
    return s["recupero"]


# Riscontro col CSV di FQLite. Nel suo CSV non ci sono virgolette: a capo, «;» e byte binari spezzano le righe. Sono affidabili
# solo le prime 5 colonne, a inizio riga. Si confronta la posizione (tabella, stato D/F, offset uguale o fino a 5 byte più
# avanti, come risulta dalla prova su sei database), mai i valori. «Non trovato» non è una prova contraria.
_RIGA_FQ = re.compile(rb"^([^;\r\n]*);\[\d+\|\d+\];-?\d*;([DF]);(-?\d+);", re.M)
_INTEST_FQ = b"_TBLNAME;_PLL;_ROWID;_STATUS;_OFFSET;"
MAX_CSV_BYTE = 500 << 20
TOLLERANZA = 5


def riscontro_csv(case, b):
    """Importa il CSV di una tabella esportato da FQLite. Il file è scelto dall'analista e resta dov'è."""
    s = _sess(case, b)
    if "recupero" not in s:
        recuperati(case, b)
    f = Path(str(b.get("path") or ""))
    if not f.is_file():
        raise ValueError(tr("File non trovato."))
    if f.stat().st_size > MAX_CSV_BYTE:
        raise ValueError(tr("File troppo grande."))
    dati = f.read_bytes()
    if not dati.lstrip(b"\xef\xbb\xbf").startswith(_INTEST_FQ):
        raise ValueError(tr("Formato non riconosciuto: il file non sembra un CSV esportato da FQLite."))
    strumento = " ".join(str(b.get("strumento") or "FQLite").split())[:80] or "FQLite"
    per = {}
    for t, _st, off in _RIGA_FQ.findall(dati):
        per.setdefault(t.decode("utf-8", "replace"), set()).add(int(off))
    r = s["recupero"]
    abbinati = 0
    for x in r["record"]:
        if x["file"] != "db" or x["fonte"] == "cancellata_nel_wal":
            continue
        pos = per.get(x["tabella"])
        if pos and any(x["offset"] + d in pos for d in range(TOLLERANZA + 1)) and strumento not in x["riscontri"]:
            x["riscontri"].append(strumento)
            abbinati += 1
    sha = hashlib.sha256(dati).hexdigest()
    voce = {"file": f.name, "strumento": strumento, "sha256": sha, "tabelle": sorted(per), "record_csv": sum(len(v) for v in per.values()), "abbinati": abbinati}
    r["csv"].append(voce)
    case.log("db_riscontro_csv", {**voce, "database": s["fonte"].get("path")})
    return {**voce, "record": r["record"], "csv": r["csv"]}


def esadecimale(case, b):
    """Byte della copia di lavoro attorno a un record: si controlla il record senza passare dalla sua lettura."""
    s = _sess(case, b)
    f = s["file"] if str(b.get("file") or "db") == "db" else s["tmp"] / (s["file"].name + "-wal")
    off = max(0, int(b.get("offset") or 0))
    ini = max(0, off - off % 16 - 32)
    with open(f, "rb") as fh:
        fh.seek(ini)
        d = fh.read(512)
    righe = []
    for i in range(0, len(d), 16):
        pz = d[i:i + 16]
        righe.append(f"{ini + i:010x}  {pz.hex(' '):<47}  " + "".join(chr(c) if 32 <= c < 127 else "." for c in pz))
    return {"testo": "\n".join(righe), "file": f.name, "offset": off}


def esporta_recuperati(G, case, b):
    s = _sess(case, b)
    r = recuperati(case, b)
    d = case.export_dir / "database"
    d.mkdir(parents=True, exist_ok=True)
    dest = G.unique(d / f"{G.safe_part(Path(s['file'].name).stem)}_recuperati_{G.stamp_now()}.csv")
    with open(dest, "w", newline="", encoding="utf-8-sig") as fo:
        w = csv.writer(fo)
        w.writerow(["stato", "livello", "fonte", "tabella", "rowid", "file", "pagina", "offset", "colonne_dal_default", "riscontri", "valori_json"])
        for x in r["record"]:
            nomi = r["nomi"].get(x["tabella"]) or []
            w.writerow(["da verificare", x["livello"], x["fonte"], x["tabella"], "" if x["rowid"] is None else x["rowid"], x["file"], x["pagina"],
                        x["offset"], ",".join(nomi[j] for j in x["dal_default"] if j < len(nomi)), ",".join(x["riscontri"]),
                        json.dumps({(nomi[j] if j < len(nomi) else str(j)): (None if v[0] == "n" else "?" if v[0] == "?" else v[1]) for j, v in enumerate(x["valori"])}, ensure_ascii=False)])
    sha = _sha(dest)
    dest.chmod(0o444)
    rel = str(dest.relative_to(case.root))
    case.log("db_recupero_csv", {"file": s["fonte"].get("path"), "record": len(r["record"]), "dest": rel, "sha256": sha})
    return {"message": tr("Esportate {n} righe in {rel} (SHA-256 {sha})").format(n=len(r["record"]), rel=rel, sha=sha)}


def reperto_recuperato(G, case, b):
    """L'analista ha controllato il record e lo registra come reperto: resta scritto che viene da un recupero."""
    s = _sess(case, b)
    r = recuperati(case, b)
    x = next((y for y in r["record"] if y["n"] == int(b.get("n"))), None)
    t = str(b.get("title") or "").strip()
    if x is None or not t:
        raise ValueError(tr("Serve almeno un titolo."))
    if not b.get("verificato"):
        raise ValueError(tr("Conferma di aver controllato il record."))
    nomi = r["nomi"].get(x["tabella"]) or []
    valori = "; ".join(f"{nomi[j] if j < len(nomi) else j} = {'?' if v[0] == '?' else v[1]}" for j, v in enumerate(x["valori"]))
    desc = (str(b.get("description") or "").strip() + "\n" + tr("Record recuperato dallo spazio libero del database, controllato dall'analista. Livello: {l}; riscontri: {c}.").format(
        l=x["livello"], c=", ".join(x["riscontri"]) or "-")).strip()
    rif = (tr("Database: {dove}").format(dove=s["fonte"].get("path")) + f"\n{x['tabella']}, {x['file']}, offset {x['offset']}\n"
           + "SHA-256: " + ", ".join(f"{k} {v}" for k, v in s["impronte"].items()) + "\n" + tr("Riga: {valori}").format(valori=valori))[:4000]
    y = G.fa.add_finding(case, t, desc, rif, G.fa.FINDING_ANALISTA)
    case.log("db_recupero_reperto", {"file": s["fonte"].get("path"), "tabella": x["tabella"], "offset": x["offset"], "livello": x["livello"], "reperto": y["n"]})
    return {"n": y["n"]}


def recuperati_testo(G, case, ident, max_record=100, salta=0):
    """Per l'agente IA: elenco dei record cancellati, sempre dichiarati da verificare."""
    a = apri(G, case, ident)
    try:
        r = recuperati(case, a)
        nomi = r["nomi"]
        out = [tr("Record recuperati: {n}. Sono DA VERIFICARE, non confermati: citali come tali, con tabella e offset. Un record può essere la vecchia copia di una riga aggiornata.").format(n=len(r["record"]))]
        inizio, spazio, n = max(0, int(salta or 0)), G.fa.MAX_OUT - 400 - len(out[0]), 0
        for x in r["record"][inizio:inizio + max_record]:
            ns = nomi.get(x["tabella"]) or []
            riga = f"{x['livello']} {x['tabella']} {x['file']} offset {x['offset']}: " + "; ".join(
                f"{ns[j] if j < len(ns) else j}={'?' if v[0] == '?' else v[1][:300]}" for j, v in enumerate(x["valori"]) if v[0] != "n")
            if n and spazio - len(riga) - 1 < 0:
                break
            spazio -= len(riga) + 1
            n += 1
            out.append(riga)
        if inizio + n < len(r["record"]):
            out.append(tr("Righe {a}–{b}. INCOMPLETO: per le successive richiama con salta={b}.").format(a=inizio + 1, b=inizio + n))
        return "\n".join(out)
    finally:
        chiudi(case, {"id": a["id"]})


def riferimenti(s, sql, riga):
    """Riferimenti verificabili di un reperto: file, impronte all'apertura, query, valori della riga."""
    f = s["fonte"]
    imp = ", ".join(f"{k} {v}" for k, v in s["impronte"].items())
    dove = f"{f.get('path')}" + (f" (offset {f.get('part')}, inode {f.get('inode')})" if f.get("inode") is not None else "")
    valori = "; ".join(f"{k} = {v}" for k, v in (riga or {}).items())
    return (tr("Database: {dove}").format(dove=dove) + "\nSHA-256: " + imp + "\n" + tr("Query: {sql}").format(sql=" ".join(sql.split()))
            + ("\n" + tr("Riga: {valori}").format(valori=valori) if valori else ""))[:4000]


def reperto(G, case, b):
    """Reperto scritto dall'analista dal gestore: origine «analista», con i riferimenti della riga."""
    s = _sess(case, b)
    t = str(b.get("title") or "").strip()
    if not t:
        raise ValueError(tr("Serve almeno un titolo."))
    x = G.fa.add_finding(case, t, str(b.get("description") or "").strip(),
                         riferimenti(s, str(b.get("sql") or ""), b.get("riga")), G.fa.FINDING_ANALISTA)
    return {"n": x["n"]}


def interroga(G, case, ident, sql, max_righe=200, salta=0):
    """Per l'agente IA: apre, esegue una query in sola lettura, chiude. Testo con i valori come sono nel database."""
    a = apri(G, case, ident)
    try:
        s = _SESS[a["id"]]
        voce = {"file": s["fonte"].get("path"), "sql": str(sql)[:20000], "origine": "agente"}
        with s["lock"]:
            try:
                cur = _esegui(s, str(sql))
                cols = [c[0] for c in cur.description or []]
                inizio = resto = max(0, int(salta or 0))
                while resto and cur.fetchmany(min(resto, 10000)):      # si salta senza tenere le righe in memoria
                    resto -= min(resto, 10000)
                righe = cur.fetchmany(max_righe + 1)
            except (sqlite3.Error, sqlite3.Warning, ValueError) as e:
                case.log("db_query", {**voce, "esito": "errore", "errore": str(e)[:300]})
                return tr("Query non eseguita: {e}").format(e=e)
            finally:
                s["con"].set_progress_handler(None, 0)
        altre = len(righe) > max_righe
        case.log("db_query", {**voce, "esito": "ok", "colonne": cols, "righe": min(len(righe), max_righe)})
        out = [tr("Database {p}, SHA-256 {h}. Valori come sono nel database: date e numeri NON convertiti.").format(
            p=s["fonte"].get("path"), h=s["impronte"][s["file"].name]), "\t".join(cols)]
        spazio, mostrate = G.fa.MAX_OUT - 400 - sum(len(x) for x in out), 0
        for r in righe[:max_righe]:
            riga = "\t".join(("NULL" if v is None else _cella(v)[1][:500]).replace("\n", " ") for v in r)
            if mostrate and spazio - len(riga) - 1 < 0:
                break
            spazio -= len(riga) + 1
            out.append(riga)
            mostrate += 1
        if altre or mostrate < len(righe):
            out.append(tr("Righe {a}–{b}. INCOMPLETO: per le successive richiama con salta={b}.").format(a=inizio + 1, b=inizio + mostrate))
        else:
            out.append(tr("Righe {a}–{b}: fine dei risultati.").format(a=inizio + 1, b=inizio + mostrate) if mostrate else tr("Nessuna riga."))
        return "\n".join(out)
    finally:
        chiudi(case, {"id": a["id"]})


def riferimenti(s, sql, riga):
    """Riferimenti verificabili di un reperto: file, impronte all'apertura, query, valori della riga."""
    f = s["fonte"]
    imp = ", ".join(f"{k} {v}" for k, v in s["impronte"].items())
    dove = f"{f.get('path')}" + (f" (offset {f.get('part')}, inode {f.get('inode')})" if f.get("inode") is not None else "")
    valori = "; ".join(f"{k} = {v}" for k, v in (riga or {}).items())
    return (tr("Database: {dove}").format(dove=dove) + "\nSHA-256: " + imp + "\n" + tr("Query: {sql}").format(sql=" ".join(sql.split()))
            + ("\n" + tr("Riga: {valori}").format(valori=valori) if valori else ""))[:4000]


def reperto(G, case, b):
    """Reperto scritto dall'analista dal gestore: origine «analista», con i riferimenti della riga."""
    s = _sess(case, b)
    t = str(b.get("title") or "").strip()
    if not t:
        raise ValueError(tr("Serve almeno un titolo."))
    x = G.fa.add_finding(case, t, str(b.get("description") or "").strip(),
                         riferimenti(s, str(b.get("sql") or ""), b.get("riga")), G.fa.FINDING_ANALISTA)
    return {"n": x["n"]}


def interroga(G, case, ident, sql, max_righe=200, salta=0):
    """Per l'agente IA: apre, esegue una query in sola lettura, chiude. Testo con i valori come sono nel database."""
    a = apri(G, case, ident)
    try:
        s = _SESS[a["id"]]
        voce = {"file": s["fonte"].get("path"), "sql": str(sql)[:20000], "origine": "agente"}
        with s["lock"]:
            try:
                cur = _esegui(s, str(sql))
                cols = [c[0] for c in cur.description or []]
                inizio = resto = max(0, int(salta or 0))
                while resto and cur.fetchmany(min(resto, 10000)):      # si salta senza tenere le righe in memoria
                    resto -= min(resto, 10000)
                righe = cur.fetchmany(max_righe + 1)
            except (sqlite3.Error, sqlite3.Warning, ValueError) as e:
                case.log("db_query", {**voce, "esito": "errore", "errore": str(e)[:300]})
                return tr("Query non eseguita: {e}").format(e=e)
            finally:
                s["con"].set_progress_handler(None, 0)
        altre = len(righe) > max_righe
        case.log("db_query", {**voce, "esito": "ok", "colonne": cols, "righe": min(len(righe), max_righe)})
        out = [tr("Database {p}, SHA-256 {h}. Valori come sono nel database: date e numeri NON convertiti.").format(
            p=s["fonte"].get("path"), h=s["impronte"][s["file"].name]), "\t".join(cols)]
        for r in righe[:max_righe]:
            out.append("\t".join(("NULL" if v is None else _cella(v)[1][:500]).replace("\n", " ") for v in r))
        if altre:
            out.append(tr("Mostrate le prime {n} righe: restringi la query.").format(n=max_righe))
        return "\n".join(out)
    finally:
        chiudi(case, {"id": a["id"]})


def chiudi(case, b):
    with _LOCK:
        s = _SESS.pop(str(b.get("id") or ""), None)
    if s and s["root"] == str(case.root):
        _chiudi(s)
    return {"ok": True}
