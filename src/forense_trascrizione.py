# SPDX-License-Identifier: AGPL-3.0-or-later
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
import hashlib, json, os, shutil, sqlite3, subprocess, sys, tempfile, time, urllib.error, urllib.request
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
    """{id: scheda} dei modelli presenti (file esistente con la dimensione registrata; l'impronta si è verificata
    all'installazione ed è nella scheda). (3.0.1) La scheda può avere impronta e dimensione diverse dall'elenco, se
    verificate con quelle dichiarate da Hugging Face o indicate dall'analista."""
    out = {}
    for mid, s in _schede().items():
        m = BY_ID.get(mid)
        if not m:
            continue
        f = models_dir() / (s.get("file") or m["file"])
        if f.is_file() and f.stat().st_size == int(s.get("size") or m["size"]):
            out[mid] = {**s, "path": str(f)}
    return out


def in_uso(mid):
    """(3.0.1) File e SHA-256 del modello installato (dalla scheda), per registro e tabella delle trascrizioni."""
    m, s = BY_ID[mid], installed().get(mid) or {}
    return {"file": s.get("file") or m["file"], "sha256": s.get("sha256") or m["sha256"]}


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


def _registra(mid, origine, case=None, sha=None, size=None, verifica=None):
    m = BY_ID[mid]
    d = _schede()
    d[mid] = {"file": m["file"], "sha256": sha or m["sha256"], "size": size or m["size"], "origine": origine, "installato": fa.now(),
              "consenso": True, "utente": os.environ.get("USER") or os.environ.get("USERNAME") or ""}
    if verifica:
        d[mid]["verifica"] = verifica
    _salva_schede(d)
    if case is not None:
        case.log("modello_trascrizione_installato", {"modello": m["file"], "sha256": d[mid]["sha256"], "origine": origine,
                                                     "verifica": verifica})


# (3.0.1) impronta dichiarata da Hugging Face prima di scaricare: l'API del repository dà SHA-256 e dimensione di ogni file
HF_API = "https://huggingface.co/api/models/ggerganov/whisper.cpp/paths-info/"


def _ctx():
    import ssl
    c = ssl.create_default_context()
    try:
        import certifi
        c.load_verify_locations(certifi.where())
    except Exception:
        pass
    return c


def dichiarato(mid):
    """SHA-256 e dimensione che Hugging Face dichiara per il file del modello: prima alla versione fissata (HF_COMMIT),
    poi all'ultima («main») se quella non c'è più. {sha256, size, rev, url} o eccezione (rete assente, risposta guasta)."""
    m = BY_ID[mid]
    for rev in (HF_COMMIT, "main"):
        req = urllib.request.Request(HF_API + rev, data=json.dumps({"paths": [m["file"]]}).encode(), method="POST",
                                     headers={"User-Agent": "RepertIA", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20, context=_ctx()) as r:
                dati = json.loads(r.read(1 << 20))
        except urllib.error.HTTPError as e:
            if e.code == 404 and rev == HF_COMMIT:
                continue
            raise
        x = next((y for y in dati if isinstance(y, dict) and y.get("path") == m["file"]), None)
        sha = ((x or {}).get("lfs") or {}).get("oid")
        if x and sha and len(sha) == 64:
            return {"sha256": sha.lower(), "size": int(x.get("size") or (x.get("lfs") or {}).get("size") or 0), "rev": rev,
                    "url": "https://huggingface.co/ggerganov/whisper.cpp/resolve/" + rev + "/" + m["file"]}
    raise ValueError(tr("Hugging Face non indica l'impronta di {f}.").format(f=m["file"]))


def scarica(mid, accetto, progress, case=None):
    """Scarica il modello scelto SOLO con il consenso esplicito (accetto=True). (3.0.1) Prima legge da Hugging Face lo SHA-256
    dichiarato per quel file, poi confronta il file scaricato con quello; se è diverso dall'elenco di RepertIA lo dice
    nella scheda e nel registro. Senza la dichiarazione (API non raggiungibile) vale l'impronta dell'elenco."""
    if not accetto:
        raise ValueError(tr("Il download del modello richiede il consenso dell'analista."))
    m = BY_ID.get(mid)
    if not m:
        raise ValueError(tr("Modello sconosciuto."))
    progress({"msg": tr("Leggo da Hugging Face l'impronta dichiarata di {f}…").format(f=m["file"])})
    try:
        d = dichiarato(mid)
    except Exception as e:
        d = None
        avviso = tr("impronta dichiarata non letta ({e}): confronto con l'elenco di RepertIA").format(e=str(e)[:160])
    atteso, size, url = (d["sha256"], d["size"] or m["size"], d["url"]) if d else (m["sha256"], m["size"], HF_URL + m["file"])
    if d:
        avviso = (tr("SHA-256 dichiarato da Hugging Face uguale a quello dell'elenco di RepertIA") if atteso == m["sha256"] else
                  tr("SHA-256 dichiarato da Hugging Face ({h}) diverso da quello dell'elenco di RepertIA ({e}): il file è stato "
                     "verificato con quello dichiarato").format(h=atteso, e=m["sha256"]))
    dest = models_dir() / m["file"]
    part = dest.with_name(dest.name + ".parziale")
    h, n, t0, testa, tentativi = hashlib.sha256(), 0, time.time(), b"", 0
    try:
        with open(part, "wb") as f:
            # (3.0.1) uno scaricamento interrotto riprende da dove si era fermato (al massimo 5 volte), invece di
            # finire con un file corto e un'impronta «diversa»
            while n < size and tentativi < 6:
                tentativi += 1
                hd = {"User-Agent": "RepertIA", **({"Range": f"bytes={n}-"} if n else {})}
                try:
                    with urllib.request.urlopen(urllib.request.Request(url, headers=hd), timeout=60, context=_ctx()) as r:
                        if n and r.status != 206:           # il server non riprende: si ricomincia da capo
                            f.seek(0); f.truncate(); h, n = hashlib.sha256(), 0
                        while b := r.read(1 << 20):
                            if len(testa) < 512:
                                testa += b[:512 - len(testa)]
                            f.write(b)
                            h.update(b)
                            n += len(b)
                            progress({"msg": tr("Scarico {f}: {a} di {b} MB").format(f=m["file"], a=n >> 20, b=size >> 20),
                                      "pct": round(100 * n / size, 1), "fatti": n, "totale": size})
                except (urllib.error.URLError, OSError, TimeoutError) as e:
                    if tentativi >= 6 or n == 0:
                        raise
                    progress({"msg": tr("Collegamento interrotto ({e}): riprendo da {a} MB…").format(e=str(e)[:80], a=n >> 20)})
                    time.sleep(2)
                if n > size or testa.lstrip()[:1] == b"<":     # pagina web al posto del modello: inutile riprovare
                    break
    except Exception:
        part.unlink(missing_ok=True)
        raise
    calc = h.hexdigest()
    if n != size or calc != atteso:
        part.unlink(missing_ok=True)
        t = testa.lstrip().lower()
        if t.startswith(b"<") or b"<html" in t[:200]:
            motivo = tr("è arrivata una pagina web invece del modello: un proxy, un filtro della rete o un antivirus ha "
                        "sostituito lo scaricamento")
        elif n < size:
            motivo = tr("scaricamento incompleto: {n} byte su {s}").format(n=n, s=size)
        elif n > size:
            motivo = tr("ricevuti più byte del previsto: {n} su {s}").format(n=n, s=size)
        else:
            motivo = tr("stessa dimensione ma contenuto diverso (file alterato in transito, per esempio da un antivirus)")
        try:
            import forense_diagnostica as fdg
            fdg.evento("trascrizione_modello", modello=m["file"], byte=n, attesi=size, sha256=calc, atteso=atteso, motivo=motivo)
        except Exception:
            pass
        raise ValueError(tr("Il file ricevuto non è il modello ({m}): eliminato. Atteso SHA-256 {a}, calcolato {c}. Si può "
                            "scaricare da un altro computer e indicarlo con «Ho già il file del modello…».").format(m=motivo, a=atteso, c=calc))
    os.replace(part, dest)
    _registra(mid, url, case, calc, n, avviso)
    return {"modello": mid, "sha256": calc, "secondi": round(time.time() - t0, 1), "verifica": avviso}


def importa(path, progress, case=None, mid=None, sha_atteso=None, sha_dich=None):
    """Modello già scaricato (computer senza rete). Accettato se lo SHA-256 è uno di quelli dell'elenco oppure (3.0.1) se è
    uguale a quello scritto dall'analista (`sha_atteso`, per esempio letto sulla pagina del modello da un altro computer):
    allora vale per il modello scelto (`mid`), o a quello dichiarato da Hugging Face (`sha_dich`, letto nella finestra a
    caso chiuso: un modello aggiornato da Hugging Face si accetta senza scrivere niente). Il calcolo è sempre fatto qui; nella scheda e nel registro restano le due
    impronte e chi le ha confrontate."""
    p = Path(path)
    if not p.is_file():
        raise ValueError(tr("File non trovato."))
    sha_atteso = "".join(str(sha_atteso or "").split()).lower() or None
    if sha_atteso and not all(c in "0123456789abcdef" for c in sha_atteso) or sha_atteso and len(sha_atteso) != 64:
        raise ValueError(tr("L'impronta scritta non è uno SHA-256 (64 cifre esadecimali)."))
    sha_dich = str(sha_dich or "").lower() if len(str(sha_dich or "")) == 64 else None
    size = p.stat().st_size
    m = next((x for x in MODELLI if x["size"] == size), None)
    if not m and not sha_atteso and not sha_dich:
        raise ValueError(tr("Il file non è uno dei modelli dell'elenco (dimensione diversa). Se è una versione più recente, "
                            "scrivi lo SHA-256 indicato dalla fonte e riprova."))
    s = sha256(p, lambda n: progress({"msg": tr("Verifico l'impronta: {a} di {b} MB").format(a=n >> 20, b=size >> 20),
                                      "pct": round(100 * n / size, 1), "fatti": n, "totale": size}))
    verifica = None
    if s in BY_SHA:
        m = BY_SHA[s]
        if sha_atteso and sha_atteso != s:
            raise ValueError(tr("SHA-256 calcolato {c}: è quello dell'elenco, ma diverso da quello scritto ({a}).").format(c=s, a=sha_atteso))
    elif sha_atteso and s == sha_atteso:
        m = BY_ID.get(mid) or m
        if not m:
            raise ValueError(tr("Scegli a quale modello corrisponde il file."))
        verifica = tr("SHA-256 calcolato uguale a quello scritto dall'analista ({h}); diverso dall'elenco di RepertIA").format(h=s)
    elif not sha_atteso and sha_dich and s == sha_dich:
        m = BY_ID.get(mid) or m
        if not m:
            raise ValueError(tr("Scegli a quale modello corrisponde il file."))
        verifica = tr("SHA-256 calcolato uguale a quello dichiarato da Hugging Face ({h}); diverso dall'elenco di RepertIA").format(h=s)
    else:
        raise ValueError((tr("SHA-256 calcolato {c}: diverso da quello scritto ({a}).") if sha_atteso else
                          tr("SHA-256 calcolato {c}: non è nell'elenco. Se la fonte indica questa impronta, scrivila e riprova.")).format(
            c=s, a=sha_atteso))
    dest = models_dir() / m["file"]
    if p.resolve() != dest.resolve():
        shutil.copyfile(p, dest.with_name(dest.name + ".parziale"))
        os.replace(dest.with_name(dest.name + ".parziale"), dest)
    _registra(m["id"], tr("file indicato dall'analista: {p}").format(p=str(p)), case, s, size, verifica)
    return {"modello": m["id"], "sha256": s, "verifica": verifica}


def rimuovi(mid, case=None):
    m = BY_ID.get(mid)
    if not m:
        raise ValueError(tr("Modello sconosciuto."))
    d = _schede()
    (models_dir() / ((d.get(mid) or {}).get("file") or m["file"])).unlink(missing_ok=True)
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


DETTATURA_MAX = 30 << 20            # byte di una registrazione: oltre due minuti di parlato


def dettatura(dati, lingua):
    """(3.0) Dettatura di un prompt: l'audio resta in una cartella temporanea, cancellata subito, e non entra nel caso.
    Modello: il più adatto fra quelli già installati, senza scaricare nulla. Restituisce (testo, modello, durata in secondi)."""
    if not exe() or not ffmpeg():
        raise ValueError(tr("Motore di trascrizione o ffmpeg non trovati: reinstalla RepertIA."))
    inst = installed()
    mid = next((x for x in ("small", "base", "turbo") if x in inst), None)
    if not mid:
        raise ValueError(tr("Nessun modello di trascrizione installato."))
    if not dati or len(dati) > DETTATURA_MAX:
        raise ValueError(tr("Registrazione vuota o troppo lunga."))
    with tempfile.TemporaryDirectory(prefix="repertia_dettatura_") as d:
        d = Path(d)
        (d / "voce.bin").write_bytes(dati)
        durata = _wav(d / "voce.bin", d / "voce.wav", 120)
        if durata is None:
            raise ValueError(tr("Audio del microfono non leggibile."))
        _lang, segs = _whisper(inst[mid]["path"], d / "voce.wav", lingua, d / "testo", 300)
    return " ".join(s[2] for s in segs).strip(), mid, round(durata, 1)


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
    m = {**BY_ID[mid], **in_uso(mid)}
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


# ------------------------------------------------------------------ (3.0.1) trascrizione rivista dall'analista
#
# La trascrizione automatica non si tocca. L'analista scrive la sua versione sotto l'audio e la salva come bozza o la
# conferma; ogni salvataggio è una riga nuova (storico), con operatore, data e SHA-256 del testo, ed è nel registro del
# caso. Il testo dell'analista entra nella ricerca («Trascrizione verificata dall'analista»); le confermate sono anche
# nella categoria dei Preferiti «Trascrizioni confermate» (il messaggio della chat, o il file se non è allegato a una chat).

KIND_AN = N_("Trascrizione verificata dall'analista")
CAT_CONF = N_("Trascrizioni confermate")
SCHEMA_AN = """CREATE TABLE IF NOT EXISTS trascrizioni_analista(id INTEGER PRIMARY KEY, source TEXT, part INTEGER, inode TEXT,
    path TEXT, testo TEXT, testo_sha256 TEXT, automatica TEXT, stato TEXT, operatore TEXT, ts TEXT);
CREATE INDEX IF NOT EXISTS idx_tr_an ON trascrizioni_analista(part, inode, id);"""
TESTO_MAX = 200_000


def ultima_analista(con, part, inode):
    """Versione più recente dell'analista per un file, con il numero di versioni; None se non c'è."""
    if not fa.table_exists(con, "trascrizioni_analista"):
        return None
    r = con.execute("SELECT testo, testo_sha256, stato, operatore, ts, automatica, (SELECT COUNT(*) FROM trascrizioni_analista "
                    "WHERE part = ? AND inode = ?) FROM trascrizioni_analista WHERE part = ? AND inode = ? ORDER BY id DESC LIMIT 1",
                    (int(part), str(inode), int(part), str(inode))).fetchone()
    return dict(zip(("testo", "testo_sha256", "stato", "operatore", "ts", "automatica", "versioni"), r)) if r else None


def confermate_sql(col_part="part", col_inode="inode"):
    """Condizione SQL: file con la trascrizione dell'analista confermata nella versione più recente."""
    return (f"({col_part}, {col_inode}) IN (SELECT a.part, a.inode FROM trascrizioni_analista a WHERE a.stato = 'confermata' "
            "AND a.id = (SELECT MAX(b.id) FROM trascrizioni_analista b WHERE b.part = a.part AND b.inode = a.inode))")


def salva_analista(case, part, inode, testo, conferma, operatore):
    """Nuova versione della trascrizione dell'analista (bozza o confermata). Restituisce la versione salvata e i messaggi
    delle chat a cui l'audio è allegato (per la categoria dei Preferiti)."""
    part, inode = int(part), str(inode)
    testo = str(testo or "").replace("\r\n", "\n").strip()
    op = " ".join(str(operatore or "").split())[:120]
    if not testo:
        raise ValueError(tr("Scrivi il testo della trascrizione."))
    if len(testo) > TESTO_MAX:
        raise ValueError(tr("Testo troppo lungo."))
    if conferma and not op:
        raise ValueError(tr("Indica l'operatore che conferma la trascrizione."))
    con = sqlite3.connect(case.db_path, timeout=30)
    try:
        con.executescript(SCHEMA_AN)
        r = con.execute("SELECT path, deleted FROM files WHERE part = ? AND inode = ? LIMIT 1", (part, inode)).fetchone()
        if not r:
            raise ValueError(tr("File non trovato nel caso."))
        path, deleted = r
        au = con.execute("SELECT modello, testo FROM trascrizioni WHERE part = ? AND inode = ? ORDER BY ts DESC LIMIT 1",
                         (part, inode)).fetchone() if fa.table_exists(con, "trascrizioni") else None
        sha = hashlib.sha256(testo.encode("utf-8")).hexdigest()
        stato = "confermata" if conferma else "bozza"
        ts = fa.now()
        con.execute("INSERT INTO trascrizioni_analista(source, part, inode, path, testo, testo_sha256, automatica, stato, operatore, ts) "
                    "VALUES ('fs',?,?,?,?,?,?,?,?,?)", (part, inode, path, testo, sha, au[0] if au else None, stato, op or None, ts))
        kind = tr(KIND_AN)
        if fa.table_exists(con, "doc_text"):
            con.execute("DELETE FROM doc_text WHERE source = 'fs' AND part = ? AND inode = ? AND kind = ?", (part, inode, kind))
            fa.store_text(con, path, testo, "fs", part, inode, deleted, kind)
        mids = [x[0] for x in con.execute("SELECT DISTINCT a.msg FROM chat_attachments a WHERE a.part = ? AND a.inode = ? ORDER BY a.msg",
                                          (part, inode))] if fa.table_exists(con, "chat_attachments") else []
        con.commit()
    finally:
        con.close()
    case.log("trascrizione_analista", {"file": path, "part": part, "inode": inode, "stato": stato, "operatore": op or None,
                                       "testo_sha256": sha, "caratteri": len(testo), "automatica_modello": au[0] if au else None,
                                       "uguale_alla_automatica": bool(au and (au[1] or "").strip() == testo), "messaggi_chat": mids[:20]})
    return {"stato": stato, "operatore": op or None, "ts": ts, "testo_sha256": sha, "path": path, "messaggi": mids}


def analista_storico(case, part, inode):
    """Versioni dell'analista di un file, dalla più recente (per l'anteprima e la chat)."""
    con = fa.db_ro(case)
    try:
        if not fa.table_exists(con, "trascrizioni_analista"):
            return []
        return [dict(zip(("testo", "testo_sha256", "stato", "operatore", "ts", "automatica"), r)) for r in con.execute(
            "SELECT testo, testo_sha256, stato, operatore, ts, automatica FROM trascrizioni_analista WHERE part = ? AND inode = ? "
            "ORDER BY id DESC LIMIT 50", (int(part), str(inode)))]
    finally:
        con.close()
