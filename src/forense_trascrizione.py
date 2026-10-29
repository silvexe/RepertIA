# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (2.20) - trascrizione automatica degli audio con Whisper (whisper.cpp), sul computer, senza rete e senza LLM.

- Motore: whisper-cli di whisper.cpp (MIT), nella cartella strumenti del pacchetto (strumenti/whisper/bin).
- Modelli: NON inclusi nei pacchetti. L'analista sceglie un modello dall'elenco MODELLI e accetta il download
  (finestra di consenso con avvertenze), oppure indica un file già scaricato: in entrambi i casi il file deve avere
  lo SHA-256 dell'elenco. Ogni modello installato ha una scheda (chi/quando/da dove/impronta) in `modelli.json`.
- Conversione: ffmpeg porta l'audio (opus, m4a, mp3, amr…) a WAV 16 kHz mono in una cartella temporanea del caso;
  l'audio originale non si tocca.
- Risultato: il testo va nella tabella dei testi del caso (doc_text, tipo «Trascrizione automatica»), quindi nella
  ricerca; i segmenti con gli orari nella tabella `trascrizioni` (scheda Trascrizione dell'anteprima). Nel registro
  del caso: modello, impronta, versione del motore, opzioni ed esito.
"""
import hashlib, json, os, shutil, sqlite3, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path

import forense_agent as fa
from forense_lingua import tr, N_  # noqa: E402

WHISPER_VERSIONE = "1.9.5"           # whisper.cpp compilato/scaricato per i pacchetti (build/*/COME_RICOSTRUIRE.txt)
HF_COMMIT = "5359861c739e955e79d9a303bcbc70fb988958b1"   # versione fissata del repository dei modelli
HF_URL = "https://huggingface.co/ggerganov/whisper.cpp/resolve/" + HF_COMMIT + "/"
KIND = N_("Trascrizione automatica")                       # tipo nella tabella dei testi

# id, file, byte, SHA-256 (dal repository ufficiale, commit HF_COMMIT), descrizioni per la finestra di consenso
MODELLI = [
    {"id": "base", "file": "ggml-base-q5_1.bin", "size": 59707625,
     "sha256": "422f1ae452ade6f30a004d7e5c6a43195e4433bc370bf23fac9cc591f01a8898",
     "nome": N_("Veloce (base)"), "nota": N_("il più rapido; in italiano sbaglia più parole")},
    {"id": "small", "file": "ggml-small-q5_1.bin", "size": 190085487,
     "sha256": "ae85e4a935d7a567bd102fe55afc16bb595bdb618e11b2fc7591bc08120411bb",
     "nome": N_("Bilanciato (small)"), "nota": N_("consigliato: veloce e buono in italiano"), "consigliato": True},
    {"id": "turbo", "file": "ggml-large-v3-turbo-q5_0.bin", "size": 574041195,
     "sha256": "394221709cd5ad1f40c46e6031ca61bce88931e6e088c188294c6d5a55ffa7e2",
     "nome": N_("Preciso (large-v3-turbo)"), "nota": N_("più lento, per gli audio importanti")},
]
BY_ID = {m["id"]: m for m in MODELLI}
BY_SHA = {m["sha256"]: m for m in MODELLI}

SCHEMA = """CREATE TABLE IF NOT EXISTS trascrizioni(source TEXT, part INTEGER, inode TEXT, path TEXT, deleted INTEGER,
    modello TEXT, modello_sha256 TEXT, motore TEXT, lingua TEXT, durata REAL, segmenti TEXT, testo TEXT, ts TEXT);
CREATE INDEX IF NOT EXISTS idx_trascrizioni ON trascrizioni(part, inode);"""


# ------------------------------------------------------------------ modelli

def models_dir():
    """Cartella dei modelli, accanto alle impostazioni (vale per tutti i casi)."""
    d = Path(fa.SETTINGS_PATH).parent / "modelli_trascrizione"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _schede():
    try:
        return json.loads((models_dir() / "modelli.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _salva_schede(d):
    p = models_dir() / "modelli.json"
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, p)


def sha256(path, progress=None):
    h, n = hashlib.sha256(), 0
    with open(path, "rb") as f:
        while b := f.read(4 << 20):
            h.update(b)
            n += len(b)
            if progress:
                progress(n)
    return h.hexdigest()


def installed():
    """{id: scheda} dei modelli presenti (file esistente con la dimensione attesa; l'impronta si è verificata
    all'installazione ed è nella scheda)."""
    out = {}
    for mid, s in _schede().items():
        m = BY_ID.get(mid)
        f = models_dir() / (m["file"] if m else "")
        if m and f.is_file() and f.stat().st_size == m["size"]:
            out[mid] = {**s, "path": str(f)}
    return out


def exe():
    return shutil.which("whisper-cli")


def ffmpeg():
    return shutil.which("ffmpeg")


def stato():
    """Per la finestra: motore, ffmpeg, modelli dell'elenco con lo stato di installazione."""
    inst = installed()
    return {"motore": bool(exe()), "ffmpeg": bool(ffmpeg()), "versione": WHISPER_VERSIONE, "cartella": str(models_dir()),
            "modelli": [{"id": m["id"], "nome": tr(m["nome"]), "nota": tr(m["nota"]), "file": m["file"], "size": m["size"],
                         "sha256": m["sha256"], "url": HF_URL + m["file"], "consigliato": bool(m.get("consigliato")),
                         "installato": m["id"] in inst, "scheda": inst.get(m["id"])} for m in MODELLI]}


def _registra(mid, origine, case=None):
    m = BY_ID[mid]
    d = _schede()
    d[mid] = {"file": m["file"], "sha256": m["sha256"], "origine": origine, "installato": fa.now(),
              "consenso": True, "utente": os.environ.get("USER") or os.environ.get("USERNAME") or ""}
    _salva_schede(d)
    if case is not None:
        case.log("modello_trascrizione_installato", {"modello": m["file"], "sha256": m["sha256"], "origine": origine})


def scarica(mid, accetto, progress, case=None):
    """Scarica il modello scelto SOLO con il consenso esplicito (accetto=True) e ne verifica lo SHA-256."""
    if not accetto:
        raise ValueError(tr("Il download del modello richiede il consenso dell'analista."))
    m = BY_ID.get(mid)
    if not m:
        raise ValueError(tr("Modello sconosciuto."))
    dest = models_dir() / m["file"]
    part = dest.with_name(dest.name + ".parziale")
    url = HF_URL + m["file"]
    req = urllib.request.Request(url, headers={"User-Agent": "RepertIA"})
    h, n, t0 = hashlib.sha256(), 0, time.time()
    try:
        with urllib.request.urlopen(req, timeout=60) as r, open(part, "wb") as f:
            while b := r.read(1 << 20):
                f.write(b)
                h.update(b)
                n += len(b)
                progress({"msg": tr("Scarico {f}: {a} di {b} MB").format(f=m["file"], a=n >> 20, b=m["size"] >> 20),
                          "pct": round(100 * n / m["size"], 1), "fatti": n, "totale": m["size"]})
    except Exception:
        part.unlink(missing_ok=True)
        raise
    if n != m["size"] or h.hexdigest() != m["sha256"]:
        part.unlink(missing_ok=True)
        raise ValueError(tr("Il file scaricato non corrisponde al modello atteso (SHA-256 diverso): eliminato."))
    os.replace(part, dest)
    _registra(mid, url, case)
    return {"modello": mid, "sha256": m["sha256"], "secondi": round(time.time() - t0, 1)}


def importa(path, progress, case=None):
    """Modello già scaricato (computer senza rete): accettato solo se lo SHA-256 è uno di quelli dell'elenco."""
    p = Path(path)
    if not p.is_file():
        raise ValueError(tr("File non trovato."))
    m = next((x for x in MODELLI if x["size"] == p.stat().st_size), None)
    if not m:
        raise ValueError(tr("Il file non è uno dei modelli dell'elenco (dimensione diversa)."))
    s = sha256(p, lambda n: progress({"msg": tr("Verifico l'impronta: {a} di {b} MB").format(a=n >> 20, b=m["size"] >> 20),
                                      "pct": round(100 * n / m["size"], 1), "fatti": n, "totale": m["size"]}))
    if s != m["sha256"]:
        raise ValueError(tr("Il file non è uno dei modelli dell'elenco (SHA-256 diverso)."))
    dest = models_dir() / m["file"]
    if p.resolve() != dest.resolve():
        shutil.copyfile(p, dest.with_name(dest.name + ".parziale"))
        os.replace(dest.with_name(dest.name + ".parziale"), dest)
    _registra(m["id"], tr("file indicato dall'analista: {p}").format(p=str(p)), case)
    return {"modello": m["id"], "sha256": s}


def rimuovi(mid, case=None):
    m = BY_ID.get(mid)
    if not m:
        raise ValueError(tr("Modello sconosciuto."))
    (models_dir() / m["file"]).unlink(missing_ok=True)
    d = _schede()
    d.pop(mid, None)
    _salva_schede(d)
    if case is not None:
        case.log("modello_trascrizione_rimosso", {"modello": m["file"]})
    return {"ok": True}


# ------------------------------------------------------------------ audio da trascrivere

def audio_rows(con, scope, scelti=None):
    """(part, inode, deleted, path) degli audio: «chat» = allegati di messaggi delle chat, «tutti», «selezione»."""
    import forense_gui as g
    q = "SELECT part, inode, deleted, path FROM files WHERE type LIKE '%/r' AND " + g.audio_where()
    if scope == "selezione":
        keys = {(int(p), str(i)) for p, i in (scelti or [])}
        return [r for r in con.execute(q) if (r[0], str(r[1])) in keys]
    if scope == "chat":
        has = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='chat_attachments'").fetchone()
        if not has:
            return []
        q += (" AND (part, inode) IN (SELECT part, inode FROM chat_attachments WHERE inode IS NOT NULL AND inode != '')")
    return con.execute(q + " ORDER BY path").fetchall()


def _wav(src, dest, timeout=600):
    """Audio → WAV 16 kHz mono (formato richiesto da Whisper). Durata in secondi, None se non convertibile."""
    r = subprocess.run([ffmpeg(), "-v", "error", "-nostdin", "-y", "-i", str(src), "-vn", "-ar", "16000", "-ac", "1",
                        "-c:a", "pcm_s16le", str(dest)], capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
    if r.returncode != 0 or not dest.exists() or dest.stat().st_size <= 44:
        return None
    return (dest.stat().st_size - 44) / 32000.0


def _whisper(model, wav, lang, out, timeout):
    """Esegue whisper-cli; restituisce (lingua, segmenti [[inizio_s, fine_s, testo], ...])."""
    cmd = [exe(), "-m", str(model), "-f", str(wav), "-l", lang or "auto", "-oj", "-of", str(out), "-np", "-sns",
           "-t", str(max(2, min(8, (os.cpu_count() or 4))))]
    r = subprocess.run(cmd, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
    js = Path(str(out) + ".json")
    if r.returncode != 0 or not js.exists():
        raise RuntimeError(fa.dec(r.stderr)[-300:] or tr("trascrizione non riuscita"))
    d = json.loads(js.read_text(encoding="utf-8", errors="replace"))
    segs = []
    for s in d.get("transcription") or []:
        o = s.get("offsets") or {}
        t = (s.get("text") or "").strip()
        if t:
            segs.append([round((o.get("from") or 0) / 1000, 2), round((o.get("to") or 0) / 1000, 2), t])
    return (d.get("result") or {}).get("language") or lang, segs


def opzioni(d):
    """Opzioni scelte dall'analista, ripulite (finestra della trascrizione o pagina del nuovo caso)."""
    d = d if isinstance(d, dict) else json.loads(d or "{}")
    scope = d.get("scope") if d.get("scope") in ("chat", "tutti", "selezione") else "chat"
    mid = str(d.get("modello") or "")
    if mid not in BY_ID:
        raise ValueError(tr("Modello sconosciuto."))
    try:
        max_min = max(0.0, float(d.get("max_min") if d.get("max_min") is not None else 30))
    except (TypeError, ValueError):
        max_min = 30.0
    return {"scope": scope, "modello": mid, "lingua": str(d.get("lingua") or "auto")[:8], "rifai": bool(d.get("rifai")),
            "max_min": max_min, "scelti": [[int(p), str(i)] for p, i in (d.get("scelti") or [])][:200000]}


def da_preparazione(case, con, opts_json):
    """(2.20) Trascrizione scelta alla creazione del caso: ultimo passo della preparazione (dopo indice e chat)."""
    try:
        case.meta["trascrizione_opzioni"] = opzioni(opts_json)
        case.save()
        fa.run_addon(case, con, "trascrizione")
    except Exception as e:
        print(tr("Trascrizione: non completata ({vname}: {e})").format(vname=type(e).__name__, e=e), flush=True)


def run(case, con):
    """Analisi aggiuntiva «trascrizione»: le opzioni le sceglie l'analista (case.meta["trascrizione_opzioni"])."""
    import forense_estesa as fe
    opts = dict(case.meta.get("trascrizione_opzioni") or {})
    scope = opts.get("scope") or "chat"
    mid = opts.get("modello") or "small"
    lang = opts.get("lingua") or "auto"
    rifai = bool(opts.get("rifai"))
    max_min = float(opts.get("max_min") or 0)
    if not exe():
        print(tr("Motore di trascrizione (whisper-cli) non trovato: reinstalla RepertIA."), flush=True)
        return None
    if not ffmpeg():
        print(tr("ffmpeg non trovato: serve per convertire gli audio. Reinstalla RepertIA."), flush=True)
        return None
    inst = installed()
    if mid not in inst:
        print(tr("Il modello scelto non è installato: installalo dalla finestra della trascrizione."), flush=True)
        return None
    m = BY_ID[mid]
    model = Path(inst[mid]["path"])
    exe_sha = sha256(exe())
    con.executescript(SCHEMA)
    rows = audio_rows(con, scope, opts.get("scelti"))
    fatti = {(p, str(i)) for p, i in con.execute("SELECT part, inode FROM trascrizioni WHERE modello = ?", (m["file"],))}
    todo = [r for r in rows if rifai or (r[0], str(r[1])) not in fatti]
    kind = tr(KIND)
    case.log("trascrizione_avviata", {"modello": m["file"], "modello_sha256": m["sha256"], "motore": "whisper.cpp " + WHISPER_VERSIONE,
                                      "motore_sha256": exe_sha, "ambito": scope, "lingua": lang, "rifai": rifai,
                                      "durata_massima_min": max_min or None, "audio": len(todo), "gia_trascritti": len(rows) - len(todo)})
    print(tr("Trascrizione: {n} audio da trascrivere con il modello {m} ({g} già trascritti con lo stesso modello).").format(
        n=len(todo), m=m["file"], g=len(rows) - len(todo)), flush=True)
    ctx = fe.Ctx(case, con, N_("Trascrizione"))
    ok = vuoti = errori = saltati = 0
    secondi = 0.0
    t0 = time.time()
    try:
        for k, (part, inode, deleted, path) in enumerate(todo, 1):
            src = ctx.tmp / f"a_{k}{Path(path).suffix.lower()[:8] or '.bin'}"
            wav = ctx.tmp / f"a_{k}.wav"
            try:
                if not fe.copy_fs_file(case, part, inode, src, 2 << 30):
                    errori += 1
                    continue
                dur = _wav(src, wav)
                if dur is None:
                    errori += 1
                    continue
                if max_min and dur > max_min * 60:
                    saltati += 1
                    continue
                lingua, segs = _whisper(model, wav, lang, ctx.tmp / f"a_{k}", max(120, dur * 4))
                testo = "\n".join(s[2] for s in segs)
                if rifai:
                    con.execute("DELETE FROM trascrizioni WHERE part = ? AND inode = ?", (part, str(inode)))
                    con.execute("DELETE FROM doc_text WHERE source = 'fs' AND part = ? AND inode = ? AND kind = ?",
                                (part, str(inode), kind))
                con.execute("INSERT INTO trascrizioni VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            ("fs", part, str(inode), path, deleted, m["file"], m["sha256"], "whisper.cpp " + WHISPER_VERSIONE,
                             lingua, round(dur, 2), json.dumps(segs, ensure_ascii=False), testo, fa.now()))
                if testo.strip():
                    fa.store_text(con, path, testo, "fs", part, str(inode), deleted, kind)
                    ok += 1
                else:
                    vuoti += 1
                secondi += dur
            except Exception as e:
                errori += 1
                print(tr("Trascrizione non riuscita per {p}: {e}").format(p=path, e=str(e)[:200]), flush=True)
            finally:
                for f in ctx.tmp.glob(f"a_{k}*"):
                    f.unlink(missing_ok=True)
            con.commit()
            el = time.time() - t0
            eta = el / k * (len(todo) - k)
            fa.avanz(fatti=k, totale=len(todo))
            ctx.say(tr("{k} di {n} · {ok} con testo · circa {m} min alla fine").format(k=k, n=len(todo), ok=ok,
                                                                                        m=max(1, round(eta / 60))))
    finally:
        con.commit()
        ctx.close()
    res = {"audio": len(todo), "con_testo": ok, "senza_parlato": vuoti, "non_riusciti": errori, "oltre_durata": saltati,
           "minuti_audio": round(secondi / 60, 1), "modello": m["file"], "modello_sha256": m["sha256"],
           "motore": "whisper.cpp " + WHISPER_VERSIONE, "motore_sha256": exe_sha, "ambito": scope, "lingua": lang,
           "ts": fa.now()}
    print(tr("Trascrizione: {ok} audio con testo, {v} senza parlato, {e} non riusciti, {s} oltre la durata massima "
             "({mi} minuti di audio).").format(ok=ok, v=vuoti, e=errori, s=saltati, mi=res["minuti_audio"]), flush=True)
    return res


def segmenti(case, part, inode):
    """Trascrizioni di un file (più recente per prima), per la scheda dell'anteprima."""
    con = fa.db_ro(case)
    try:
        if not fa.table_exists(con, "trascrizioni"):
            return []
        rows = con.execute("SELECT modello, modello_sha256, motore, lingua, durata, segmenti, ts FROM trascrizioni "
                           "WHERE part = ? AND inode = ? ORDER BY ts DESC", (int(part), str(inode))).fetchall()
    finally:
        con.close()
    return [{"modello": a, "modello_sha256": b, "motore": c, "lingua": d, "durata": e, "segmenti": json.loads(f or "[]"),
             "ts": g} for a, b, c, d, e, f, g in rows]
