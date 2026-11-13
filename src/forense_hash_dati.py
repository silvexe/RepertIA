#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - hash dei dati acquisiti e confronto con quelli attesi.

(3.0.4) Codice spostato da forense_agent.py senza modifiche, per avere file più corti. Si carica tramite
forense_agent, che ne riesporta i nomi: gli altri moduli continuano a usare «fa.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fa.<nome>»).
"""
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from forense_lingua import N_
from forense_lingua import tr

import forense_agent as fa
from forense_agent import (
    dec, image_segments, noelev_env, now)

# -------------------------------------------------------------- hash dei dati acquisiti (2.14)

HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
HASH_LABEL = re.compile(r"(?i)\b(md5|sha[-_ ]?1|sha[-_ ]?256)\b")
HASH_HEX = re.compile(r"\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")
E01_HEADER_KEYS = (("case_number", N_("Numero del caso")), ("evidence_number", N_("Numero del reperto")),
                   ("description", N_("Descrizione")), ("examiner_name", N_("Operatore")), ("notes", N_("Note")),
                   ("acquiry_date", N_("Data di acquisizione")), ("system_date", N_("Data del sistema di acquisizione")),
                   ("acquiry_software", N_("Programma di acquisizione")),
                   ("acquiry_software_version", N_("Versione del programma")),
                   ("acquiry_operating_system", N_("Sistema operativo di acquisizione")),
                   ("model", N_("Modello del supporto")), ("serial_number", N_("Numero di serie del supporto")),
                   ("device_label", N_("Etichetta del supporto")))


def _algo(lbl):
    return re.sub(r"[-_ ]", "", lbl.lower())


def hash_attesi_da_file(img):
    """Hash di acquisizione scritti dai programmi di acquisizione accanto all'immagine (FTK Imager
    `.txt`, Guymager `.info`, ewfacquire/dc3dd `.log`, file `.md5/.sha1/.sha256`, RepertIA
    `.acquisizione.json`). Restituisce {algoritmo: set(valori)}, {algoritmo: [file]}."""
    img = Path(img)
    stems = {img.name, img.stem, Path(img.stem).stem}
    found, src = {}, {}
    try:
        cands = [p for p in img.parent.iterdir() if p.is_file() and p != img and p.stat().st_size < 4 << 20]
    except OSError:
        return found, src
    for p in cands:
        nm, low = p.name, p.name.lower()
        if re.fullmatch(r"\.[Ee]\d\d", p.suffix) and p.stem == img.stem:
            continue
        if not any(nm.startswith(s) for s in stems if s) or not low.endswith(
                (".txt", ".info", ".log", ".md5", ".sha1", ".sha256", ".hash", ".json", ".csv")):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if low.endswith(".acquisizione.json"):
            try:
                d = json.loads(text)
                for k in ("md5", "sha1", "sha256"):
                    if d.get(k):
                        found.setdefault(k, set()).add(d[k].lower())
                        src.setdefault(k, []).append(nm)
            except ValueError:
                pass
            continue
        for line in text.splitlines():
            hx = HASH_HEX.findall(line)
            if not hx:
                continue
            lab = HASH_LABEL.search(line)
            for h in hx:
                a = HASH_LEN[len(h)]
                if lab and _algo(lab.group(1)) != a:
                    continue
                if not lab and not low.endswith((".md5", ".sha1", ".sha256", ".hash")):
                    continue
                found.setdefault(a, set()).add(h.lower())
                if nm not in src.setdefault(a, []):
                    src[a].append(nm)
    return found, src


def _progress_printer(total, label):
    st = {"last": -1}
    fa.avanz("hash")          # (2.20) seconda lettura (dati acquisiti): la barra riparte da zero nello stesso passo

    def pr(done):
        fa.avanz(fatti=done, totale=total, unita="B")
        pct = int(done * 100 / (total or 1)) // 5 * 5
        if pct != st["last"]:
            st["last"] = pct
            print(f"  {label} {pct}% ({done / 1e9:.1f} di {total / 1e9:.1f} GB)", flush=True)
    return pr


def _e01_open(img):
    import pyewf
    h = pyewf.handle()
    h.open([str(p) for p in image_segments(img)])
    return h


def verifica_dati(img, show=False):
    """MD5, SHA-1 e SHA-256 del contenuto acquisito. Per l'E01 legge i dati con libewf (che controlla
    anche i codici di controllo di ogni blocco) e confronta con gli hash registrati nell'E01; per il
    raw legge il file. In entrambi i casi confronta anche con gli hash dei log di acquisizione."""
    img = Path(img)
    res = {"ts": now(), "attesi": {}, "fonti": {}, "calcolati": {}, "errori_lettura": []}
    hs = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    if fa.is_e01(img):
        res["tipo"] = "E01"
        try:
            h = _e01_open(img)
        except ImportError:
            return _verifica_ewfverify(img, res)
        try:
            for k, v in (h.get_hash_values() or {}).items():
                a = _algo(k)
                if a in hs and v and set(v.strip("0")):
                    res["attesi"].setdefault(a, [])
                    if v.lower() not in res["attesi"][a]:
                        res["attesi"][a].append(v.lower())
                    res["fonti"].setdefault(a, []).append(tr("registrato nell'E01"))
            hdr = {}
            for k, _ in E01_HEADER_KEYS:
                try:
                    val = h.get_header_value(k)
                except Exception:
                    val = None
                if val:
                    hdr[k] = str(val)
            res["intestazione"] = hdr
            size = h.get_media_size()
            res["dimensione"] = size
            chunk = max(int(h.get_chunk_size() or 32768), 32768) * 64
            pr = _progress_printer(size, tr("verifica dei dati dell'E01")) if show else None
            off = 0
            while off < size:
                n = min(chunk, size - off)
                try:
                    data = h.read_buffer_at_offset(n, off)
                except Exception as e:
                    # blocco illeggibile o con codice di controllo errato: si conta come zeri, come ewfverify
                    res["errori_lettura"].append({"offset": off, "byte": n, "errore": str(e)[:200]})
                    data = b"\0" * n
                if not data:
                    res["errori_lettura"].append({"offset": off, "byte": size - off, "errore": tr("fine dati inattesa")})
                    break
                for x in hs.values():
                    x.update(data)
                off += len(data)
                if pr:
                    pr(off)
        finally:
            h.close()
    else:
        res["tipo"] = "raw"
        size = img.stat().st_size
        res["dimensione"] = size
        pr = _progress_printer(size, tr("hash dei dati")) if show else None
        done = 0
        with open(img, "rb") as f:
            while chunk := f.read(8 << 20):
                for x in hs.values():
                    x.update(chunk)
                done += len(chunk)
                if pr:
                    pr(done)
    res["calcolati"] = {k: v.hexdigest() for k, v in hs.items()}
    return _verifica_esito(img, res)


def _verifica_ewfverify(img, res):
    """Senza pyewf: ewfverify da riga di comando (stesso controllo)."""
    exe = shutil.which("ewfverify")
    if not exe:
        res["esito"] = "non_verificabile"
        res["errore"] = tr("né pyewf né ewfverify disponibili")
        return res
    cp = subprocess.run([exe, "-q", "-d", "sha1", "-d", "sha256", str(img)], capture_output=True,
                        stdin=subprocess.DEVNULL, env=noelev_env())
    out = dec(cp.stdout + cp.stderr)
    for a, lab in (("md5", "MD5"), ("sha1", "SHA1"), ("sha256", "SHA256")):
        m = re.search(lab + r" hash stored in file:\s*([0-9a-fA-F]+)", out)
        if m and set(m.group(1).strip("0")):
            res["attesi"].setdefault(a, []).append(m.group(1).lower())
            res["fonti"].setdefault(a, []).append(tr("registrato nell'E01"))
        m = re.search(lab + r" hash calculated over data:\s*([0-9a-fA-F]+)", out)
        if m:
            res["calcolati"][a] = m.group(1).lower()
    for m in re.finditer(r"(?i)checksum error.*?sector[s]?:?\s*(\d+)", out):
        res["errori_lettura"].append({"offset": int(m.group(1)) * 512, "errore": tr("codice di controllo errato")})
    res["strumento"] = fa.tool_version([exe, "-V"]) or "ewfverify"
    return _verifica_esito(img, res)


def _verifica_esito(img, res):
    side, srcs = hash_attesi_da_file(img)
    for a, vals in side.items():
        for v in vals:
            if v not in res["attesi"].setdefault(a, []):
                res["attesi"][a].append(v)
        res["fonti"].setdefault(a, []).extend(f"file {s}" for s in srcs.get(a, []))
    conf = {}
    for a, vals in res["attesi"].items():
        if a in res["calcolati"]:
            conf[a] = res["calcolati"][a] in vals
            if len(vals) > 1:
                res.setdefault("avvisi", []).append(tr("{v1}: valori di acquisizione diversi tra loro ({v2})").format(v1=a.upper(), v2=len(vals)))
    res["confronti"] = conf
    if not conf:
        res["esito"] = "nessun_hash_di_acquisizione"
    elif all(conf.values()) and not res["errori_lettura"]:
        res["esito"] = "corrisponde"
    else:
        res["esito"] = "diverso"
    return res


def hash_dati_testo(v):
    if not v:
        return tr("non calcolato")
    e = v.get("esito")
    if e == "corrisponde":
        ok = [a for a, x in v["confronti"].items() if x]
        fonti = sorted({f for a in ok for f in v["fonti"].get(a, [])})
        return (tr("CORRISPONDE all'hash di acquisizione (") + ", ".join(a.upper() for a in ok)
                + ("; " + "; ".join(fonti) if fonti else "") + ")"
                + (tr(" — attenzione: ") + "; ".join(v["avvisi"]) if v.get("avvisi") else ""))
    if e == "diverso":
        bad = [a.upper() for a, ok in v.get("confronti", {}).items() if not ok]
        return (tr("ATTENZIONE: DIVERSO dall'hash di acquisizione") + (f" ({', '.join(bad)})" if bad else "")
                + (tr("; {v1} blocchi illeggibili o con codice di controllo errato").format(v1=len(v['errori_lettura'])) if v.get("errori_lettura") else ""))
    if e == "nessun_hash_di_acquisizione":
        return (tr("calcolato; nessun hash di acquisizione trovato (né nell'E01 né in un log accanto all'immagine) "
                "con cui confrontarlo"))
    if e == "errore":
        return tr("non calcolato: ") + v.get("errore", "")
    return tr("non verificabile: ") + v.get("errore", "")


def hash_dati_md(v):
    """Righe di report per la sezione «Hash dei dati acquisiti»."""
    if not v:
        return [tr("- Non calcolato (caso preparato prima della 2.14 o con l'analisi speditiva): usa *Verifica hash*.")]
    L = [tr("- Esito: **{v1}**").format(v1=hash_dati_testo(v)),
         tr("- Tipo: {v1}").format(v1=v.get('tipo', '-')) + (tr(", {dimensione} byte di dati").format(dimensione=v['dimensione']) if v.get("dimensione") else "")
         + tr("; calcolato il {v1}").format(v1=v.get('ts', '-'))]
    for a in ("md5", "sha1", "sha256"):
        if v.get("calcolati", {}).get(a):
            att = v.get("attesi", {}).get(a)
            L.append(tr("- {v1} calcolato: `{v2}`").format(v1=a.upper(), v2=v['calcolati'][a]) + (
                tr(" — atteso `{v1}` ({v2}): ").format(v1=', '.join(att), v2='; '.join(sorted(set(v['fonti'].get(a, [])))))
                + ("uguale" if v.get("confronti", {}).get(a) else tr("**DIVERSO**")) if att else tr(" — nessun valore di acquisizione")))
    for w in v.get("avvisi", []):
        L.append(tr("- Attenzione: {w}").format(w=w))
    for e in v.get("errori_lettura", [])[:20]:
        L.append(tr("- Blocco illeggibile all'offset {v1}: {v2}").format(v1=e.get('offset'), v2=e.get('errore', '')))
    hdr = v.get("intestazione") or {}
    if hdr:
        L += ["", tr("Dati di acquisizione registrati nell'E01:"), ""]
        for k, lab in E01_HEADER_KEYS:
            if hdr.get(k):
                L.append(f"- {tr(lab)}: {hdr[k]}")
    return L
