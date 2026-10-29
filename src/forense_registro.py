# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (2.20) – verifica a posteriori del registro a catena (audit_log.jsonl).

Ogni riga del registro (dalla 2.14) porta `n` (numero progressivo) e `prev`, lo SHA-256 della riga precedente così come
è scritta nel file (la prima: 64 zeri). Questo modulo ricalcola la catena su un registro qualsiasi (anche copiato da un
altro computer), senza RepertIA installato: serve solo Python 3. Dice:

- se la catena è integra;
- la prima riga alterata (il suo contenuto non è più quello di cui la riga successiva ha registrato lo SHA-256);
- le righe mancanti in mezzo (salto nei numeri progressivi) e quelle inserite o fuori ordine;
- con l'hash finale stampato nel report (e facoltativamente il numero di voci): se il registro di allora è ancora tutto
  lì (righe aggiunte dopo = operazioni successive, normale), se mancano righe in fondo o se è stato riscritto;
- per i file esportati citati nel registro (con il loro SHA-256) che si trovano nella cartella del caso: se sono ancora
  uguali.

Cosa NON dimostra: chi ha scritto il registro né che le operazioni descritte siano avvenute davvero; un registro riscritto
per intero con una catena ricalcolata risulta integro finché non lo si confronta con un hash finale conservato altrove
(report consegnato, verbale). Uso da terminale: `python3 forense_registro.py <audit_log.jsonl | cartella del caso>
[--hash-finale H] [--voci N] [--json] [--lingua it|en]`.
"""
import hashlib
import json
import os
import re
import sys
from pathlib import Path

try:
    from forense_lingua import tr
except ImportError:                       # usato da solo, senza gli altri file di RepertIA
    def tr(s):
        return s

GENESIS = "0" * 64
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
MAX_FILE_HASH = 4 << 30                   # file esportati più grandi di 4 GB: non ricalcolati (dichiarato)


def _sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def trova_registro(path):
    """File del registro: il percorso dato o `audit_log.jsonl` dentro la cartella del caso."""
    p = Path(str(path)).expanduser()
    if p.is_dir():
        p = p / "audit_log.jsonl"
    if not p.is_file():
        raise FileNotFoundError(tr("Registro non trovato: {p}").format(p=p))
    return p


def _corto(b, n=400):
    s = b.decode("utf-8", "replace")
    return s if len(s) <= n else s[:n] + "…"


def verifica(path, hash_finale=None, voci=None, file_esportati=True):
    """Ricalcola la catena del registro. Restituisce un dizionario con l'esito (vedi `testo`)."""
    reg = trova_registro(path)
    root = reg.parent
    R = {"file": str(reg), "righe": 0, "voci": 0, "senza_catena": 0, "catena_da": None, "ultimo_n": None,
         "hash_finale": None, "integro": True, "prima_alterata": None, "mancanti": [], "fuori_ordine": [],
         "altri_problemi": [], "esportati": None, "atteso": None}
    righe = []                             # (riga nel file, byte, rec)
    with open(reg, "rb") as f:
        for i, raw in enumerate(f, 1):
            line = raw.rstrip(b"\r\n")
            if not line.strip():
                continue
            try:
                rec = json.loads(line.decode("utf-8"))
            except Exception:
                rec = None
            righe.append((i, line, rec if isinstance(rec, dict) else None))
    R["righe"] = len(righe)
    prev_line, exp_n = None, None
    for k, (i, line, rec) in enumerate(righe):
        if rec is None or "prev" not in rec:
            if R["catena_da"] is None:
                R["senza_catena"] += 1
            else:
                R["altri_problemi"].append({"riga": i, "motivo": tr("riga senza catena (o non JSON) dopo l'inizio della catena"),
                                            "contenuto": _corto(line)})
            prev_line = line
            continue
        if R["catena_da"] is None:
            R["catena_da"] = i
        n = rec.get("n")
        want = hashlib.sha256(prev_line).hexdigest() if prev_line is not None else GENESIS
        gap = isinstance(n, int) and isinstance(exp_n, int) and n > exp_n
        if gap:                            # numeri saltati: righe tolte in mezzo
            R["mancanti"].append({"dopo_riga": righe[k - 1][0] if k else None, "da_n": exp_n, "a_n": n - 1, "quante": n - exp_n,
                                  "riga": i})
        elif isinstance(exp_n, int) and n != exp_n:
            R["fuori_ordine"].append({"riga": i, "n": n, "atteso": exp_n})
        if rec.get("prev") != want and not gap:
            if prev_line is None:
                R["altri_problemi"].append({"riga": i, "motivo": tr("la prima riga della catena non parte da 64 zeri"),
                                            "contenuto": _corto(line)})
            elif R["prima_alterata"] is None:
                ip, lp, rp = righe[k - 1]
                R["prima_alterata"] = {"riga": ip, "n": (rp or {}).get("n"), "contenuto": _corto(lp),
                                       "hash_attuale": hashlib.sha256(lp).hexdigest(), "hash_atteso": rec.get("prev"),
                                       "scoperta_alla_riga": i}
        exp_n = (n if isinstance(n, int) else (exp_n or 0)) + 1
        R["ultimo_n"] = n if isinstance(n, int) else R["ultimo_n"]
        prev_line = line
    R["voci"] = R["righe"]
    R["hash_finale"] = hashlib.sha256(prev_line).hexdigest() if prev_line is not None else None
    R["integro"] = not (R["prima_alterata"] or R["mancanti"] or R["fuori_ordine"] or R["altri_problemi"])
    # confronto con l'hash finale stampato nel report (e il numero di voci)
    if hash_finale:
        hf = str(hash_finale).strip().strip("`").lower()
        if not HEX64.match(hf):
            R["atteso"] = {"esito": "non_valido", "hash": hf}
        else:
            pos = next((k for k, (_i, line, _r) in enumerate(righe) if hashlib.sha256(line).hexdigest() == hf), None)
            if pos is not None:
                ok_voci = voci is None or int(voci) == pos + 1
                R["atteso"] = {"esito": "trovato" if ok_voci else "trovato_voci_diverse", "hash": hf, "riga": righe[pos][0],
                               "voci_allora": pos + 1, "voci_attese": voci, "aggiunte_dopo": len(righe) - pos - 1}
            elif voci is not None and int(voci) > len(righe):
                R["atteso"] = {"esito": "mancano_in_fondo", "hash": hf, "voci_attese": int(voci), "voci_ora": len(righe),
                               "quante": int(voci) - len(righe)}
            else:
                R["atteso"] = {"esito": "non_trovato", "hash": hf, "voci_attese": voci, "voci_ora": len(righe)}
    if file_esportati:
        R["esportati"] = controlla_esportati(righe, root)
    return R


def _rel_nel_caso(p, root):
    """Percorso registrato → file nella cartella del caso (anche se il caso è stato copiato o spostato altrove)."""
    s = str(p or "")
    if not s:
        return None
    q = Path(s)
    if q.is_absolute() and q.exists():
        try:
            q.resolve().relative_to(root.resolve())
            return q
        except ValueError:
            return None                    # fuori dalla cartella del caso: non si controlla
    parts = [x for x in re.split(r"[\\/]+", s) if x and not re.match(r"^[A-Za-z]:$", x)]
    for k in range(len(parts)):
        c = root.joinpath(*parts[k:])
        if c.exists() and (len(parts) - k >= 2 or k == len(parts) - 1):
            return c
    return None


def controlla_esportati(righe, root):
    """SHA-256 dei file esportati citati nel registro (voci con un percorso e il suo SHA-256), se sono nella cartella del
    caso. Per lo stesso file conta l'ultima voce (un report rigenerato sostituisce il precedente)."""
    cit = {}                               # percorso registrato → (riga, sha256, evento)
    for i, _line, rec in righe:
        if not rec:
            continue
        ev, d = rec.get("event"), rec.get("data")
        if not isinstance(d, dict) or not str(ev or "").startswith(("export", "report_")):
            continue                       # solo file prodotti dal caso: esportazioni e report Word/PDF
        base = d.get("dest") or d.get("file")
        if isinstance(base, str) and HEX64.match(str(d.get("sha256") or "")):
            cit[base] = (i, d["sha256"].lower(), ev)
        if ev == "export_chat" and isinstance(d.get("file"), list):        # file della chat esportata
            for x in d["file"]:
                if isinstance(x, dict) and HEX64.match(str(x.get("sha256") or "")):
                    cit[str(Path(d.get("cartella") or "") / x.get("file", ""))] = (i, x["sha256"].lower(), ev)
    out = {"controllati": 0, "uguali": 0, "diversi": [], "assenti": [], "fuori_caso": 0, "troppo_grandi": 0,
           "manifest": {"controllati": 0, "uguali": 0, "diversi": []}}
    for p, (i, sha, ev) in cit.items():
        f = _rel_nel_caso(p, root)
        if f is None:
            q = Path(p)
            if q.is_absolute() and q.exists():
                out["fuori_caso"] += 1
            else:
                out["assenti"].append({"riga": i, "file": p, "evento": ev})
            continue
        if not f.is_file():
            continue
        if f.stat().st_size > MAX_FILE_HASH:
            out["troppo_grandi"] += 1
            continue
        out["controllati"] += 1
        got = _sha_file(f)
        if got == sha:
            out["uguali"] += 1
        else:
            out["diversi"].append({"riga": i, "file": str(f.relative_to(root)), "evento": ev, "atteso": sha, "attuale": got})
    # selezioni esportate: ogni file è nel manifest.csv della cartella, con lo SHA-256 calcolato all'esportazione
    for i, _line, rec in righe:
        if not rec or rec.get("event") != "export_selezione" or not isinstance(rec.get("data"), dict):
            continue
        d = _rel_nel_caso(rec["data"].get("dest"), root)
        mf = d / "manifest.csv" if d and d.is_dir() else None
        if not mf or not mf.is_file():
            continue
        import csv
        with open(mf, encoding="utf-8-sig", newline="") as fh:
            rd = csv.reader(fh, delimiter=";")
            next(rd, None)
            for row in rd:
                if len(row) < 7 or not HEX64.match(row[5] or "") or not row[6]:
                    continue
                f = d / row[6]
                if not f.is_file() or f.stat().st_size > MAX_FILE_HASH:
                    continue
                out["manifest"]["controllati"] += 1
                got = _sha_file(f)
                if got == row[5].lower():
                    out["manifest"]["uguali"] += 1
                else:
                    out["manifest"]["diversi"].append({"riga": i, "file": str(f.relative_to(root)), "atteso": row[5].lower(), "attuale": got})
    return out


def testo(R):
    """Esito in parole semplici (righe di testo)."""
    L = [tr("Registro: {f}").format(f=R["file"]),
         tr("Voci: {n}; hash finale (SHA-256 dell'ultima riga): {h}").format(n=R["voci"], h=R["hash_finale"] or "-")]
    if R["senza_catena"]:
        L.append(tr("Le prime {n} righe sono di versioni precedenti alla 2.14, senza catena: non verificabili.").format(n=R["senza_catena"]))
    if R["integro"]:
        L.append(tr("ESITO: catena INTEGRA – nessuna riga alterata, tolta in mezzo o inserita."))
    else:
        L.append(tr("ESITO: catena INTERROTTA."))
        pa = R["prima_alterata"]
        if pa:
            L.append(tr("Prima riga alterata: riga {r} del file (voce n. {n}). Il suo contenuto non è più quello registrato dalla "
                        "riga successiva: SHA-256 atteso {a}, attuale {b}. Contenuto attuale: {c}").format(
                r=pa["riga"], n=pa["n"], a=pa["hash_atteso"], b=pa["hash_attuale"], c=pa["contenuto"]))
            L.append(tr("Il contenuto originale non si può ricostruire: la catena dice solo che quella riga è stata cambiata."))
        for m in R["mancanti"]:
            L.append(tr("Righe mancanti: {q} (voci n. {a}–{b}) tolte prima della riga {r} del file.").format(
                q=m["quante"], a=m["da_n"], b=m["a_n"], r=m["riga"]))
        for x in R["fuori_ordine"][:20]:
            L.append(tr("Riga {r}: voce n. {n} invece di {a} (riga inserita, duplicata o spostata).").format(r=x["riga"], n=x["n"], a=x["atteso"]))
        for x in R["altri_problemi"][:20]:
            L.append(tr("Riga {r}: {m}").format(r=x["riga"], m=x["motivo"]))
    a = R.get("atteso")
    if a:
        e = a["esito"]
        if e == "non_valido":
            L.append(tr("Hash finale atteso non valido (servono 64 caratteri esadecimali)."))
        elif e == "trovato":
            L.append(tr("Hash finale atteso: TROVATO alla riga {r} (voci allora: {v}). Il registro di allora è ancora tutto lì; "
                        "dopo ci sono {d} righe aggiunte in seguito (operazioni successive, normale: la prima è di solito la "
                        "voce «report»).").format(r=a["riga"], v=a["voci_allora"], d=a["aggiunte_dopo"]))
        elif e == "trovato_voci_diverse":
            L.append(tr("Hash finale atteso trovato alla riga {r}, ma le voci fino a lì sono {v} e non {w}: controllare il "
                        "numero indicato.").format(r=a["riga"], v=a["voci_allora"], w=a["voci_attese"]))
        elif e == "mancano_in_fondo":
            L.append(tr("Hash finale atteso NON trovato e il registro ha {o} voci invece di almeno {v}: mancano almeno {q} "
                        "righe in fondo.").format(o=a["voci_ora"], v=a["voci_attese"], q=a["quante"]))
        else:
            L.append(tr("Hash finale atteso NON trovato in nessuna riga: righe tolte in fondo, ultima riga di allora modificata "
                        "oppure registro riscritto (anche se la catena risulta integra, non è il registro di allora)."))
    x = R.get("esportati")
    if x:
        L.append(tr("File esportati citati nel registro e presenti nella cartella del caso: {c} controllati, {u} uguali, "
                    "{d} diversi; {a} non trovati.").format(c=x["controllati"], u=x["uguali"], d=len(x["diversi"]), a=len(x["assenti"])))
        for y in x["diversi"][:30]:
            L.append(tr("  DIVERSO: {f} (riga {r}, {e}): SHA-256 registrato {a}, attuale {b}").format(
                f=y["file"], r=y["riga"], e=y["evento"], a=y["atteso"], b=y["attuale"]))
        mf = x["manifest"]
        if mf["controllati"]:
            L.append(tr("File delle selezioni esportate (manifest.csv): {c} controllati, {u} uguali, {d} diversi.").format(
                c=mf["controllati"], u=mf["uguali"], d=len(mf["diversi"])))
            for y in mf["diversi"][:30]:
                L.append(tr("  DIVERSO: {f}: SHA-256 nel manifest {a}, attuale {b}").format(f=y["file"], a=y["atteso"], b=y["attuale"]))
        if x["troppo_grandi"]:
            L.append(tr("{n} file oltre 4 GB non ricalcolati.").format(n=x["troppo_grandi"]))
    return L


def esito_breve(R):
    """integro | alterato | mancanti | riscritto (con l'hash atteso) – per riepiloghi e collaudo."""
    a = (R.get("atteso") or {}).get("esito")
    if R["prima_alterata"] or R["fuori_ordine"] or R["altri_problemi"]:
        return "alterato"
    if R["mancanti"]:
        return "mancanti"
    if a == "mancano_in_fondo":
        return "mancanti_in_fondo"
    if a == "non_trovato":
        return "riscritto_o_troncato"
    return "integro"


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description=tr("Verifica la catena del registro audit_log.jsonl di un caso di RepertIA"))
    ap.add_argument("registro", help=tr("audit_log.jsonl oppure la cartella del caso"))
    ap.add_argument("--hash-finale", help=tr("hash finale del registro stampato nel report (SHA-256 dell'ultima riga)"))
    ap.add_argument("--voci", type=int, help=tr("numero di voci del registro stampato nel report"))
    ap.add_argument("--no-file", action="store_true", help=tr("non ricalcola gli SHA-256 dei file esportati"))
    ap.add_argument("--json", action="store_true", help=tr("risultato in JSON"))
    ap.add_argument("--lingua", choices=["it", "en"], help=tr("lingua dei messaggi"))
    args = ap.parse_args(argv)
    if args.lingua:
        try:
            import forense_lingua as lg
            lg.imposta(args.lingua)
        except ImportError:
            pass
    try:
        R = verifica(args.registro, args.hash_finale, args.voci, not args.no_file)
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(R, indent=1, ensure_ascii=False))
    else:
        print("\n".join(testo(R)))
    x = R.get("esportati") or {}
    bad = (not R["integro"] or esito_breve(R) != "integro" or (R.get("atteso") or {}).get("esito") in ("non_valido", "trovato_voci_diverse")
           or x.get("diversi") or (x.get("manifest") or {}).get("diversi"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    sys.exit(main())
