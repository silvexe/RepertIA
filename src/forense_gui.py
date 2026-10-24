#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""
forense_gui.py - Interfaccia grafica locale per forense_agent.py.

RepertIA by silvexe.
Avvio:  python3 forense_gui.py   (oppure doppio clic su "Avvia RepertIA.command" su Mac,
        "RepertIA" dal menu Start su Windows)
Si apre il browser su http://127.0.0.1:<porta>. Il server ascolta solo sul Mac
stesso (nessun accesso dalla rete) e non usa internet.
"""
import json, os, platform, re, secrets, shutil, signal, socket, sqlite3, subprocess, sys, threading, time
import webbrowser
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import forense_agent as fa  # noqa: E402
import forense_lingua as lg  # noqa: E402
from forense_lingua import tr, N_  # noqa: E402

TOKEN = secrets.token_urlsafe(24)
IS_MAC = platform.system() == "Darwin"
IS_WIN = platform.system() == "Windows"
LOCK = threading.Lock()


# ----------------------------------------------------------------- stato

class Prep:
    """Preparazione di un caso in corso (sottoprocesso `prepara`)."""
    def __init__(self):
        self.proc = None
        self.lines = []
        self.root = None
        self.rc = None
        self.add = None
        self.next_image = None     # copia decifrata creata: da analizzare come nuovo caso
        self.ask = None            # domanda in attesa all'operatore (volumi cifrati rilevati)
        self._ask_n = 0

    def start(self, root, image=None, plaso=False, carving=False, add=None, hash_file=False,
              no_hash=False, estese=False, vss=False, ocr=False, info=None, fuso=None, lingua=None):
        """Nuovo caso (image) oppure analisi aggiuntiva su un caso esistente (add)."""
        cmd = [sys.executable, "-u", str(HERE / "forense_agent.py"), "prepara",
               "--case", str(root)]
        if add:
            cmd += ["--aggiungi", add] + (["--fuso", fuso] if fuso else [])
        else:
            cmd += ["--image", image] + (["--plaso"] if plaso else []) + \
                   (["--carving"] if carving else []) + (["--hash-file"] if hash_file else []) + \
                   (["--no-hash"] if no_hash else []) + (["--estese"] if estese else []) + \
                   (["--vss"] if vss else []) + (["--ocr"] if ocr else []) + \
                   (["--info", json.dumps(info, ensure_ascii=False)] if info else []) + \
                   (["--fuso", fuso] if fuso else []) + (["--lingua", lingua] if lingua else [])
        self.lines, self.root, self.rc, self.ask, self.next_image = [], root, None, None, None
        self.add = add or "all"
        env = dict(os.environ, FORENSE_DA_GUI="1", PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
        extra = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if IS_WIN
                 else {"start_new_session": True})
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL if add else subprocess.PIPE, env=env, **extra)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for raw in self.proc.stdout:
            for line in fa.dec(raw).replace("\r", "\n").split("\n"):
                if line.startswith(fa.ASK_MARK):       # domanda dell'agente: non va nel registro a video
                    self._on_ask(line[len(fa.ASK_MARK):])
                elif line.strip():
                    self.lines.append(line.rstrip())
            if len(self.lines) > 5000:
                del self.lines[:1000]
        self.rc = self.proc.wait()

    def _on_ask(self, payload):
        try:
            d = json.loads(payload)
        except ValueError:
            return
        if d.get("fine"):
            self.ask = None
            return
        if d.get("decifrata"):
            self.ask = None
            self.next_image = d["decifrata"]
            return
        if d.get("errore") and d.get("errore_uuid"):     # chiave sbagliata: toglie quella provata anche qui
            fa.ap.set_secrets([x for x in fa.ap.secrets() if x.get("volume") != d["errore_uuid"]])
        self._ask_n += 1
        d["n"] = self._ask_n
        self.ask = d

    def answer(self, d):
        """Risposta dell'operatore alla domanda sui volumi cifrati (azione: procedi | sblocca | annulla).
        Le chiavi viaggiano solo nella pipe verso l'agente e restano in memoria."""
        if not self.running or self.proc.stdin is None or not self.ask:
            raise ValueError(tr("Nessuna domanda in attesa."))
        az = d.get("azione")
        if az not in ("procedi", "sblocca", "decifra", "annulla"):
            raise ValueError(tr("Azione non valida."))
        msg = {"azione": az}
        if az == "sblocca":
            vol = next((v for v in self.ask.get("volumi", []) if int(v["offset"]) == int(-1 if d.get("offset") is None else d["offset"])), None)
            if not vol or not vol.get("apfs"):
                raise ValueError(tr("Volume non valido."))
            secret = d.get("secret") or ""
            if not secret.strip():
                raise ValueError(tr("Scrivi la password o la chiave di ripristino."))
            kind = "recovery" if d.get("kind") == "recovery" else "password"
            # anche in questo processo (serve poi a leggere i contenuti del caso)
            fa.ap.set_secrets([x for x in fa.ap.secrets() if x.get("volume") != vol.get("uuid")] +
                              [{"tipo": kind, "valore": secret.strip() if kind == "recovery" else secret,
                                "volume": vol.get("uuid") or ""}])
            msg.update(offset=vol["offset"], secret=secret, kind=kind)
        if az == "decifra":
            vol = next((v for v in self.ask.get("volumi", []) if int(v["offset"]) == int(-1 if d.get("offset") is None else d["offset"])), None)
            if not vol or vol.get("apfs") or not vol.get("decifrabile"):
                raise ValueError(tr("Volume non valido."))
            if not (d.get("secret") or "").strip():
                raise ValueError(tr("Scrivi la password o la chiave di ripristino."))
            msg.update(offset=vol["offset"], secret=d["secret"], kind="recovery" if d.get("kind") == "recovery" else "password")
        self.ask = None
        try:
            self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
            self.proc.stdin.flush()
        except OSError:
            raise ValueError(tr("La preparazione non risponde più."))

    @property
    def running(self):
        return self.proc is not None and self.rc is None

    def stop(self):
        """Ferma la preparazione, i programmi avviati (PhotoRec, bulk_extractor...) e
        l'eventuale container di plaso, che altrimenti continuerebbe a girare in Docker."""
        if self.running:
            if IS_WIN:   # chiude anche i processi figli (TSK, PhotoRec, exiftool...)
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(self.proc.pid)],
                               capture_output=True)
            else:
                try:
                    os.killpg(self.proc.pid, signal.SIGTERM)
                except OSError:
                    self.proc.terminate()
        stop_plaso_containers()


class Session:
    """Caso aperto e conversazione con l'agente."""
    def __init__(self):
        self.case = None
        self.llm = None
        self.llm_error = None
        self.tools = None
        self.messages = None
        self.events = []
        self.busy = False
        self.stop = threading.Event()
        self.tasks = {}
        self.conv = None            # conversazione corrente {id, created, title}
        self.saved_messages = None  # messaggi ripresi da una conversazione salvata

    def emit(self, kind, data):
        self.events.append({"n": len(self.events), "kind": kind, "data": data})

    # --- conversazioni salvate (cartella conversazioni/ del caso)
    def conv_dir(self):
        return self.case.root / "conversazioni"

    def new_conv(self):
        import datetime as _dt
        now = _dt.datetime.now()
        cid = now.strftime("%Y%m%d_%H%M%S")
        while (self.conv_dir() / f"{cid}.json").exists():
            cid += "x"
        self.conv = {"id": cid, "created": fa.now(), "title": None}
        self.events, self.saved_messages = [], None

    def save_conv(self):
        """Salva eventi (per l'interfaccia) e messaggi (per l'agente). Le conversazioni senza
        domande non vengono salvate."""
        if not self.case or not self.conv:
            return
        questions = [e["data"] for e in self.events if e["kind"] == "user"]
        if not questions:
            return
        msgs = self.messages if self.messages else self.saved_messages
        d = {**self.conv, "title": self.conv.get("title") or questions[0][:120],
             "updated": fa.now(), "questions": len(questions),
             "events": self.events, "messages": msgs or []}
        self.conv["title"] = d["title"]
        self.conv_dir().mkdir(exist_ok=True)
        p = self.conv_dir() / f"{self.conv['id']}.json"
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(d, ensure_ascii=False, default=str), encoding="utf-8")
        tmp.replace(p)

    def list_convs(self):
        out = []
        if self.case and self.conv_dir().exists():
            for p in self.conv_dir().glob("*.json"):
                try:
                    d = json.loads(p.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                out.append({"id": d.get("id", p.stem), "title": d.get("title"),
                            "created": d.get("created"), "updated": d.get("updated"),
                            "questions": d.get("questions", 0)})
        out.sort(key=lambda c: c.get("updated") or "", reverse=True)
        return out

    def load_conv(self, cid):
        p = self.conv_dir() / f"{Path(str(cid)).name}.json"
        if not p.exists():
            raise ValueError(tr("Conversazione non trovata."))
        d = json.loads(p.read_text(encoding="utf-8"))
        self.conv = {"id": d.get("id", p.stem), "created": d.get("created"),
                     "title": d.get("title"), "resumed": True, "updated": d.get("updated")}
        self.events = d.get("events") or []
        for i, e in enumerate(self.events):
            e["n"] = i
        self.saved_messages = d.get("messages") or None
        if self.llm:
            self.tools, self.messages = fa.start_session(self.case, self.llm)
            if self.saved_messages:
                self.messages = [self.messages[0]] + self.saved_messages[1:]

    def connect(self):
        self.llm, self.llm_error = None, None
        if self.messages:          # non perdere la conversazione in corso
            self.saved_messages = self.messages
        self.tools, self.messages = None, None
        try:
            conf = fa.load_settings()
            url = conf["url"] if conf["modo"] == "remoto" else ""
            if conf["modo"] == "remoto" and not url:
                raise fa.LLMError(tr("Server in rete scelto ma senza indirizzo: inseriscilo e premi Collega."))
            self.llm = fa.connect_llm(fa.BACKEND, url, fa.MODEL, fa.NUM_CTX,
                                      api_key=conf["api_key"] or fa.API_KEY)
            if self.case:
                self.tools, self.messages = fa.start_session(self.case, self.llm)
                if self.saved_messages:
                    # conversazione ripresa: prompt di sistema aggiornato, storia invariata
                    self.messages = [self.messages[0]] + self.saved_messages[1:]
        except fa.LLMError as e:
            self.llm_error = str(e)
        except Exception as e:
            self.llm_error = tr("Errore di connessione al server LLM: {e}").format(e=e)

    def open(self, root, resume=True):
        if self.case and self.conv:
            self.save_conv()
        self.case = fa.Case(root)
        if not self.case.meta:
            raise ValueError(tr("Nessun caso in {root}").format(root=root))
        self.busy = False
        self.llm, self.messages = None, None
        self.new_conv()
        convs = self.list_convs() if resume else []
        if convs:
            try:
                self.load_conv(convs[0]["id"])
            except (OSError, ValueError):
                self.new_conv()
        try:
            fa.normalize_carved_names(self.case)   # casi preparati con versioni precedenti
        except Exception:
            pass
        try:
            fa.reclaim_e01_raw(self.case)          # toglie la vecchia copia raw (anche 1 TB) di un E01
        except Exception:
            pass
        try:
            fa.ripara_date_fat(self.case)          # date FAT dei casi preparati con il fuso passato con -z
        except Exception:
            pass
        try:
            prune_cache(self.case)                 # cache delle anteprime entro un tetto di spazio
        except Exception:
            pass
        self.case_tools = fa.make_tools(self.case)
        ensure_nav(self.case)       # l'albero si prepara in background
        self.connect()

    def refresh(self):
        """Ricarica il caso dopo un'analisi aggiuntiva senza perdere la conversazione:
        l'agente riceve i nuovi strumenti e il prompt aggiornato."""
        self.case = fa.Case(self.case.root)
        self.case_tools = fa.make_tools(self.case)
        if self.llm and self.messages:
            self.tools = fa.make_tools(self.case)
            self.messages[0] = {"role": "system", "content": fa.system_prompt(self.case)}

    def summary(self, what):
        text, questions = fa.summary_md(self.case, what)
        titles = {"all": tr("Riepilogo del caso"), "base": tr("Riepilogo del file system"),
                  "indice": tr("Riepilogo: testo dei documenti e metadati"),
                  "plaso": tr("Riepilogo: timeline plaso"), "carving": tr("Riepilogo: carving"),
                  "hash": tr("Riepilogo: hash dei file"),
                  "immagine": tr("SHA-256 della copia forense")}
        self.emit("summary", {"title": titles.get(what, tr("Riepilogo")), "md": text,
                              "questions": questions, "what": what})

    def ask(self, q):
        self.busy = True
        self.stop.clear()
        self.emit("user", q)
        mark = len(self.messages)
        self.messages.append({"role": "user", "content": q})
        self.case.log("user", q)
        self.save_conv()

        def run():
            try:
                fa.agent_turn(self.case, self.tools, self.messages, self.emit, self.stop)
                if self.stop.is_set():
                    del self.messages[mark:]
            except Exception as e:
                self.emit("error", tr("Errore: {e}").format(e=e))
            finally:
                self.emit("done", None)
                try:
                    self.save_conv()
                except OSError as e:
                    self.emit("error", tr("Conversazione non salvata: {e}").format(e=e))
                self.busy = False
        threading.Thread(target=run, daemon=True).start()


PREP = Prep()
SES = Session()


# ----------------------------------------------------------- utilità

def stop_plaso_containers():
    if not shutil.which("docker"):
        return
    try:
        ids = subprocess.run(["docker", "ps", "-q", "--filter", f"name={fa.PLASO_CONTAINER}"],
                             capture_output=True, text=True, timeout=20).stdout.split()
        if ids:
            subprocess.run(["docker", "rm", "-f", *ids], capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        pass


def clean_path(p):
    p = (p or "").strip().strip("'\"")
    if p.startswith("file://"):
        from urllib.parse import unquote
        p = unquote(urlparse(p).path)
    return p.replace("\\ ", " ")


FILE_FILTERS = {
    "image": N_("Copie forensi|*.e01;*.dd;*.raw;*.img;*.001;*.bin;*.dmg;*.vhd;*.vmdk|Tutti i file|*.*"),
    "list": N_("Elenchi (*.csv;*.txt;*.tsv;*.body)|*.csv;*.txt;*.tsv;*.body|Tutti i file (*.*)|*.*"),
    "any": N_("Tutti i file|*.*"),
}


def _ps_str(t):
    """Stringa per PowerShell tra apici singoli (l'apostrofo si raddoppia: «Scegli l'elenco»)."""
    return "'" + str(t).replace("'", "''") + "'"


def _as_str(t):
    """Stringa per AppleScript tra virgolette doppie."""
    return '"' + str(t).replace("\\", "\\\\").replace('"', '\\"') + '"'


def choose_file(prompt=None, kind="image", any_file=False):
    """Finestra nativa di scelta di un file: la copia forense (kind «image»), un elenco CSV/TXT di un altro
    strumento («list») o un file qualsiasi («any», anche any_file=True). Restituisce il percorso o None."""
    if any_file:
        kind = "any"
    prompt = prompt or {"image": tr("Scegli la copia forense (raw, dd, img, E01)"), "list": tr("Scegli l'elenco"),
                        "any": tr("Scegli il file della lista di hash")}[kind]
    if IS_MAC:
        script = ("tell application (path to frontmost application as text) to POSIX path of (choose file "
                  f"with prompt {_as_str(prompt)})")
        cmd = ["osascript", "-e", script]
    elif IS_WIN:
        ps = ("Add-Type -AssemblyName System.Windows.Forms;"
              "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
              "$f=New-Object System.Windows.Forms.Form -Property @{TopMost=$true};"
              "$d=New-Object System.Windows.Forms.OpenFileDialog;"
              f"$d.Title={_ps_str(prompt)};$d.Filter={_ps_str(tr(FILE_FILTERS[kind]))};"
              "if($d.ShowDialog($f) -eq 'OK'){$d.FileName}")
        r = subprocess.run(["powershell", "-NoProfile", "-STA", "-Command", ps],
                           capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        path = r.stdout.decode("utf-8", "replace").strip()
        return path if r.returncode == 0 and path else None
    elif shutil.which("zenity"):
        cmd = ["zenity", "--file-selection", f"--title={prompt}"]
    else:
        raise RuntimeError(tr("Finestra di scelta non disponibile: incolla il percorso."))
    r = subprocess.run(cmd, capture_output=True, text=True)
    path = r.stdout.strip() if r.returncode == 0 else ""
    return path or None


def choose_folder(prompt=None):
    """Finestra nativa di scelta cartella. Restituisce il percorso o None."""
    prompt = prompt or tr("Scegli la cartella")
    if IS_MAC:
        script = ('tell application (path to frontmost application as text) to '
                  f'POSIX path of (choose folder with prompt {_as_str(prompt)})')
        cmd = ["osascript", "-e", script]
    elif IS_WIN:
        ps = ("Add-Type -AssemblyName System.Windows.Forms;"
              "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
              "$f=New-Object System.Windows.Forms.Form -Property @{TopMost=$true};"
              "$d=New-Object System.Windows.Forms.FolderBrowserDialog;"
              f"$d.Description={_ps_str(prompt)};$d.ShowNewFolderButton=$true;"
              "if($d.ShowDialog($f) -eq 'OK'){$d.SelectedPath}")
        r = subprocess.run(["powershell", "-NoProfile", "-STA", "-Command", ps],
                           capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        path = r.stdout.decode("utf-8", "replace").strip()
        return path if r.returncode == 0 and path else None
    elif shutil.which("zenity"):
        cmd = ["zenity", "--file-selection", "--directory", f"--title={prompt}"]
    else:
        raise RuntimeError(tr("Finestra di scelta non disponibile: incolla il percorso."))
    r = subprocess.run(cmd, capture_output=True, text=True)
    path = r.stdout.strip().rstrip("/") if r.returncode == 0 else ""
    return path or None


def check_dest(dest, create=True):
    """Verifica una cartella di destinazione per salvare casi o la cache: deve esistere (o almeno la
    cartella che la contiene) ed essere scrivibile. Restituisce (Path, spazio libero)."""
    p = Path(clean_path(dest)).expanduser()
    if not str(p).strip():
        raise ValueError(tr("Indica una cartella."))
    if p.exists() and not p.is_dir():
        raise ValueError(tr("Il percorso indicato è un file, non una cartella."))
    if not p.exists() and not p.parent.is_dir():
        raise ValueError(tr("La cartella non esiste e non può essere creata: disco non collegato o percorso errato."))
    if create or p.exists():
        try:
            if create:
                p.mkdir(exist_ok=True)
            t = p / (".repertia_prova_%d" % os.getpid())
            t.write_bytes(b"x")
            t.unlink()
        except OSError as e:
            raise ValueError(tr("Non posso scrivere in questa cartella ({v1}).").format(v1=e.strerror or e))
    return p.resolve(), fa.free_bytes(p)


def reveal(path):
    """Mostra un file o una cartella nel Finder (o nel file manager su Linux)."""
    p = Path(path)
    if IS_MAC:
        subprocess.Popen(["open", "-R", str(p)] if p.is_file() else ["open", str(p)])
    elif IS_WIN:
        if p.is_file():
            subprocess.Popen(f'explorer /select,"{p}"')
        else:
            os.startfile(str(p))
    elif shutil.which("xdg-open"):
        subprocess.Popen(["xdg-open", str(p if p.is_dir() else p.parent)])


def requirements():
    plaso, _, plaso_msg = fa.plaso_status()
    w = lambda b: bool(shutil.which(b))
    return {
        "plaso_msg": plaso_msg,
        "sleuthkit": all(shutil.which(b) for b in fa.TSK_BINS),
        "ewf": w("ewfexport") or (IS_WIN and w("img_cat")), "exiftool": w("exiftool"),
        "pdftotext": w("pdftotext"),
        "photorec": w("photorec"), "bulk_extractor": fa.bulk_available(),
        "platform": "windows" if IS_WIN else "mac" if IS_MAC else "linux",
        "openai": fa.OpenAI is not None,
        "plaso": plaso,
        "cases_home": str(fa.CASES_HOME),
    }


def apfs_bloccati(c):
    """Volumi APFS cifrati già elencati nel caso ma non sbloccati in questa sessione (la chiave non si salva)."""
    ps = c.meta.get("partitions", [])
    if not any(p.get("apfs") and p.get("readable") and p["apfs"].get("encrypted") for p in ps):
        return []
    try:
        lk = dict(fa.ap.locked_parts(c))
    except Exception:
        return []
    return [{"offset": p["offset"], "nome": p["apfs"].get("name"), "byte": (p.get("length_sectors") or 0) * 512}
            for p in ps if p.get("readable") and p["offset"] in lk]


def case_summary(c):
    m = c.meta
    ev = m.get("evidence", m.get("image", ""))
    return {
        "root": str(c.root), "name": c.root.name, "created": m.get("created"),
        "info": m.get("info_caso") or {}, "lingua": lg.lingua_caso(c),
        "fuso_dispositivo": m.get("fuso_dispositivo") or None,
        "fuso_stato": fa.fuso_stato_testo(m) if m.get("fuso_dispositivo") else "",
        "evidence": ev, "evidence_ok": Path(ev).exists() and Path(m.get("image", ev)).exists(),
        "converted": bool(m.get("converted_from_e01")),
        "disk_type": m.get("disk_type"), "partitions": m.get("partitions", []),
        "sha256": m.get("sha256"), "sha256_ts": m.get("sha256_ts"),
        "sha256_differito": bool(m.get("sha256_differito")), "timeline": m.get("timeline"),
        "verifiche": m.get("verifiche", []), "findings": len(c.findings()),
        "riscontri": m.get("riscontri") or [],
        "hash_dati": m.get("hash_dati"), "hash_dati_testo": fa.hash_dati_testo(m.get("hash_dati")) if m.get("hash_dati") else "",
        "indice": m.get("indice"), "carving": m.get("carving"), "hash_file": m.get("hash_file"),
        "complete": "timeline" in m, "estese": m.get("estese") or {}, "volumi_cifrati": m.get("volumi_cifrati") or [],
        "decifrate": m.get("decifrate") or [], "derivata": m.get("derivata"), "liste_hash": m.get("liste_hash"),
        "apfs_bloccati": apfs_bloccati(c),
    }


def image_info(path, dest=None):
    p = Path(path).expanduser()
    if not p.exists():
        return {"ok": False, "error": tr("File non trovato. Controlla che il disco sia collegato.")}
    if p.is_dir():
        return {"ok": False, "error": tr("È una cartella: scegli il file dell'immagine "
                "(per gli E01 il primo segmento, .E01).")}
    segs = fa.image_segments(p.resolve())
    root, exists = fa.case_for_image(p, dest or None)
    return {"ok": True, "path": str(p.resolve()),
            "size": sum(s.stat().st_size for s in segs), "segments": len(segs),
            "e01": fa.is_e01(p), "case_root": str(root), "case_exists": exists,
            "free": fa.free_bytes(dest or fa.CASES_HOME)}


def addon_check(what):
    """Solleva un errore leggibile se mancano gli strumenti per un'analisi aggiuntiva."""
    if what == "plaso":
        ok, _, msg = fa.plaso_status()
        if not ok:
            raise ValueError(msg)
    elif what == "carving":
        if not (shutil.which("photorec") or fa.bulk_available()):
            raise ValueError(tr("Per il carving servono PhotoRec e bulk_extractor: {v1} (o 'Aggiorna strumenti').").format(v1=fa.install_hint('testdisk bulk_extractor')))
    elif what == "ocr":
        if not fe_mod().tesseract():
            raise ValueError(tr("Per l'OCR serve Tesseract: ") + (tr("reinstalla RepertIA o esegui 'Aggiorna strumenti'")
                                                             if IS_WIN else tr("in Terminale esegui brew install tesseract")))
    elif what == "phash":
        fe = fe_mod()
        if fe.missing_modules("phash") and not fe.bundled_python_with(["PIL"]):
            raise ValueError(tr("Per gli hash percettivi serve Pillow: avvia RepertIA dall'app (Mac) o dall'installazione (Windows)."))
    elif what == "vss":
        fe = fe_mod()
        miss = fe.missing_modules("vss")
        if miss and not fe.bundled_python_with(miss):
            raise ValueError(tr("Per le copie shadow servono libvshadow e pytsk3: avvia RepertIA dall'app (Mac) "
                             "o dall'installazione (Windows), che li includono."))
    elif what == "indice" and not shutil.which("exiftool"):
        raise ValueError(tr("Manca exiftool: {v1} (o 'Aggiorna strumenti').").format(v1=fa.install_hint('exiftool poppler')))


# ------------------------------------------------- scheda Risultati

PAGE = 200
TL_KIND = {"M": N_("modifica"), "A": N_("accesso"), "C": N_("metadati"), "B": N_("creazione")}
IMG_MIME = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".gif": "image/gif",
            ".webp": "image/webp", ".bmp": "image/bmp", ".heic": "image/heic",
            ".tif": "image/tiff", ".tiff": "image/tiff"}


def yes(v):
    return str(v).lower() in ("1", "true", "yes", "si", "on")


def counts(case):
    con = fa.db_ro(case)
    try:
        one = lambda sql: con.execute(sql).fetchone()[0]
        has = lambda t: fa.table_exists(con, t)
        n_files = one("SELECT COUNT(*) FROM files")
        return {
            "explore": n_files,
            "search": len(search_list(case)),
            "bm": sum(c["n"] for c in bm_categories(case)) if (case.root / "ricerche.sqlite").exists() else 0,
            "file": n_files,
            "timeline": one("SELECT COUNT(*) FROM events"),
            "doc": one("SELECT COUNT(*) FROM doc_text") if has("doc_text") else None,
            "meta": one("SELECT COUNT(*) FROM meta") if has("meta") else None,
            "carved": one("SELECT COUNT(*) FROM carved") if has("carved") and
            (case.meta.get("carving") or {}).get("photorec") else None,
            "trace": one("SELECT COUNT(*) FROM features") if has("features") and
            (case.meta.get("carving") or {}).get("bulk_extractor") else None,
            **ext_counts(case, con),
        }
    finally:
        con.close()


def is_dir_type(t):
    return bool(t) and t[-1] in "dV"


# ------------------------------------------------- filtri per colonna
#
# Ogni colonna degli elenchi può essere filtrata: q["cf"] è un JSON {colonna: {...}} con
#   testo   {"v": "rossi -bianchi \"via roma\""}  tutte le parole devono comparire (contiene,
#           senza distinguere maiuscole); con "-" davanti una parola deve NON comparire
#   numero  {"min": byte, "max": byte}               dimensioni
#   data    {"from": "2024-03-01", "to": "2024-03-31"}  (già in UTC per le colonne con orario)
# Ogni elenco dichiara le sue colonne come {chiave: (espressione SQL, tipo)}, tipo t|n|d|D
# (d: data e ora UTC 'AAAA-MM-GGTHH:MM:SS'; D: solo data 'AAAA-MM-GG').

def cf_parse(q):
    raw = q.get("cf")
    if not raw:
        return {}
    try:
        d = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return d if isinstance(d, dict) else {}


def cf_terms(text):
    out = []
    for m in re.finditer(r'(-?)"([^"]+)"|(-?)(\S+)', text or ""):
        neg, term = (m.group(1), m.group(2)) if m.group(2) is not None else (m.group(3), m.group(4))
        if term:
            out.append((bool(neg), term))
    return out[:8]


class CfValues(Exception):
    """Segnale interno: la richiesta chiedeva l'elenco dei valori presenti in una colonna."""
    def __init__(self, rows):
        Exception.__init__(self)
        self.rows = rows


def cf_apply(q, spec, w, a):
    """Aggiunge a w/a le condizioni dei filtri di colonna attivi. Ricorda le colonne dell'elenco
    (per l'ordinamento e per l'elenco dei valori). Con q["cfv"] il filtro di quella colonna è
    escluso, come nel menu a tendina di Excel."""
    q["_spec"] = spec
    skip = q.get("cfv")
    for key, v in list(cf_parse(q).items())[:16]:
        if key not in spec or not isinstance(v, dict) or key == skip:
            continue
        expr, typ = spec[key]
        if typ == "t":
            sel = v.get("sel")
            if isinstance(sel, list) and sel:
                w.append(f"IFNULL({expr}, '') IN (SELECT value FROM json_each(?))")
                a.append(json.dumps([str(x) for x in sel[:500]]))
            for neg, term in cf_terms(str(v.get("v") or "")[:300]):
                w.append(f"IFNULL({expr}, '') {'NOT ' if neg else ''}LIKE ? ESCAPE '\\'")
                a.append(fa.like(term))
        elif typ == "n":
            for op, k in ((">=", "min"), ("<=", "max")):
                x = v.get(k)
                if x in (None, ""):
                    continue
                try:
                    x = int(float(x))
                except (TypeError, ValueError):
                    continue
                w.append(f"{expr} {op} ?"); a.append(x)
        elif typ in ("d", "D"):
            lo, hi = str(v.get("from") or "")[:19], str(v.get("to") or "")[:19]
            if lo:
                w.append(f"{expr} >= ?"); a.append(lo)
            if hi:
                if typ == "d" and len(hi) == 10:
                    hi += "T23:59:59"
                w.append(f"{expr} <= ?"); a.append(hi)


def cf_order(q, default, pre=""):
    """ORDER BY: la colonna scelta con un clic sull'intestazione (q["sk"], q["sd"] = asc|desc),
    poi l'ordine normale dell'elenco per rendere stabile la paginazione."""
    spec = q.get("_spec") or {}
    k = q.get("sk")
    if k not in spec:
        return default
    expr, typ = spec[k]
    d = "DESC" if q.get("sd") == "desc" else "ASC"
    o = f"{expr} COLLATE NOCASE {d}" if typ == "t" else f"({expr}) IS NULL, {expr} {d}"
    return f"{pre}{o}, {default}"


def cf_values(con, q, sql_from, w, a):
    """Valori distinti (con quante righe) della colonna q["cfv"], con gli altri filtri attivi."""
    spec = q.get("_spec") or {}
    k = q.get("cfv")
    if k not in spec or spec[k][1] != "t":
        raise CfValues([])
    expr = spec[k][0]
    cond = " WHERE " + " AND ".join(list(w) + [f"length(IFNULL({expr}, '')) <= 200"])
    raise CfValues(con.execute(
        f"SELECT IFNULL({expr}, '') v, COUNT(*) c FROM {sql_from}{cond} GROUP BY v "
        "ORDER BY c DESC, v COLLATE NOCASE LIMIT 301", a).fetchall())


def _sql_lit(s):
    return "'" + s.replace("'", "''") + "'"


def cf_timeline():
    """Colonne filtrabili della timeline: le etichette dei tipi di evento sono nella lingua dell'interfaccia."""
    lab = "CASE kind " + " ".join(f"WHEN '{k}' THEN {_sql_lit(tr(v))}" for k, v in TL_KIND.items()) + " ELSE kind END"
    return {"ts": ("ts", "d"), "kind": (lab, "t"),
            "source": (f"CASE WHEN origin='tsk' THEN {_sql_lit(tr('file system'))} ELSE source END", "t"),
            "detail": ("CASE WHEN origin='tsk' THEN path ELSE message END", "t")}
CF_META = {"path": ("path", "t"), "device": ("(IFNULL(make,'') || ' ' || IFNULL(model,''))", "t"),
           "taken": ("replace(substr(taken, 1, 10), ':', '-')", "D"), "author": ("author", "t")}
CF_CARVED = {"name": ("name", "t"), "type": ("type", "t"), "size": ("size", "n"),
             "img_offset": ("img_offset", "n"), "sha256": ("sha256", "t")}
CF_DOC = {"path": ("path", "t")}


def cf_hits(bm=False):
    p = "bm." if bm else ""
    spec = {"path": (p + "path", "t"), "size": (p + "size", "n"), "mtime": (p + "mtime", "d")}
    if bm:
        spec.update({"note": ("bm.note", "t"), "sha256": ("bm.sha256", "t")})
    else:
        spec.update({"wheres": ("wheres", "t"), "terms": ("terms", "t"), "detail": ("detail", "t")})
    return spec


def tl_where(q, w, a):
    """Filtri della timeline, comuni a tabella e grafico."""
    L = fa.like
    cf_apply(q, cf_timeline(), w, a)
    text = (q.get("q") or "").strip()
    if text:
        w.append("(path LIKE ? ESCAPE '\\' OR message LIKE ? ESCAPE '\\' OR "
                 "source LIKE ? ESCAPE '\\')"); a += [L(text)] * 3
    if q.get("start"):
        w.append("ts >= ?"); a.append(q["start"])
    if q.get("end"):
        e = q["end"]
        if "T" not in e:
            e += {4: "-12-31T23:59:59", 7: "-31T23:59:59"}.get(len(e), "T23:59:59")
        w.append("ts <= ?"); a.append(e)
    if q.get("origin"):
        w.append("origin = ?"); a.append(q["origin"])
    if q.get("ekind"):
        w.append("kind = ?"); a.append(q["ekind"])


def results(case, q, ids=None, limit=PAGE, full=False):
    """Una pagina di risultati (limit=None: tutte le righe, per esportazioni e selezioni).
    ids: solo le righe con questi identificativi (colonna `id`). Con q["cfv"]: l'elenco dei valori
    presenti nella colonna indicata ({"values": [[valore, righe], ...], "more": bool})."""
    try:
        return _results(case, q, ids, limit, full)
    except CfValues as e:
        return {"kind": q.get("kind", "file"), "values": [list(r) for r in e.rows[:300]],
                "more": len(e.rows) > 300}


def _results(case, q, ids=None, limit=PAGE, full=False):
    kind, text, off = q.get("kind", "file"), (q.get("q") or "").strip(), int(q.get("offset", 0))
    if kind == "explore":
        return nav_list(case, q, ids, limit)
    if kind == "hits":
        return bm_list(case, q, ids, limit) if q.get("cid") else hits_list(case, q, ids, limit)
    if kind in EXT_KINDS:
        return ext_results(case, q, ids, limit)
    con = fa.db_ro(case)
    w, a = [], []
    L = fa.like
    lim = f" LIMIT {int(limit)} OFFSET {int(off)}" if limit else ""
    idcol = "rowid"

    def restrict():
        if ids is not None:
            w.append(f"{idcol} IN (SELECT value FROM json_each(?))")
            a.append(json.dumps([int(x) for x in ids if str(x).lstrip("-").isdigit()]))

    def page(sql_from, cols, order):
        restrict()
        if q.get("cfv"):
            cf_values(con, q, sql_from, w, a)
        order = cf_order(q, order)
        cond = (" WHERE " + " AND ".join(w)) if w else ""
        total = con.execute(f"SELECT COUNT(*) FROM {sql_from}{cond}", a).fetchone()[0]
        rows = con.execute(f"SELECT rowid, {cols} FROM {sql_from}{cond} ORDER BY {order}{lim}",
                           a).fetchall()
        return total, rows

    try:
        if kind == "file":
            if text:
                w.append("path LIKE ? ESCAPE '\\'"); a.append(L(text))
            if yes(q.get("deleted")):
                w.append("deleted = 1")
            if q.get("ext"):
                w.append("lower(path) LIKE ?"); a.append("%." + q["ext"].lower().lstrip("."))
            # dimensione e date vengono dall'indice di navigazione (se pronto)
            nv = nav_attach(con, case)

            def nvc(c):
                return (f"(SELECT n.{c} FROM nv.nav n WHERE n.part = files.part "
                        "AND n.inode = files.inode LIMIT 1)") if nv else "NULL"
            cf_apply(q, {"path": ("path", "t"), "type": ("type", "t"), "inode": ("inode", "t"),
                         "size": (nvc("size"), "n"), "mtime": (nvc("mtime"), "d"),
                         "crtime": (nvc("crtime"), "d"), "atime": (nvc("atime"), "d")}, w, a)
            total, rows = page("files", "part, inode, deleted, type, path, " + ", ".join(
                nvc(c) for c in ("size", "mtime", "crtime", "atime")), "path")
            data = [{"id": r, "part": p, "inode": i, "deleted": d, "type": t, "path": pa,
                     "size": sz, "mtime": mt, "crtime": ct, "atime": at}
                    for r, p, i, d, t, pa, sz, mt, ct, at in rows]
        elif kind == "timeline":
            tl_where(q, w, a)
            total, rows = page("events", "ts, kind, source, path, message, origin, part", "ts")
            data = []
            for rid, ts, k, src, pa, msg, orig, part in rows:
                m = re.search(r"inode (\S+)", msg or "") if orig == "tsk" else None
                data.append({"id": rid, "ts": ts, "kind": tr(TL_KIND.get(k, k)), "source": src,
                             "path": pa, "message": (msg or "") if full else (msg or "")[:400],
                             "origin": orig, "part": part, "inode": m.group(1) if m else None})
        elif kind == "doc":
            fts = "fts5" in (con.execute("SELECT sql FROM sqlite_master WHERE name='doc_text'")
                             .fetchone() or [""])[0].lower()
            cf_apply(q, CF_DOC, w, a)
            dx = (q.get("dext") or "").strip().lower().lstrip(".")
            if dx == "~posta":
                w.append("source = 'posta'")
            elif dx == "~senza":          # nome senza punto: si guarda solo dopo l'ultimo «/» e l'ultimo «›» del percorso
                b1 = "replace(path, rtrim(path, replace(path, '/', '')), '')"
                b2 = f"replace({b1}, rtrim({b1}, replace({b1}, '›', '')), '')"
                w.append(f"source <> 'posta' AND {b2} NOT LIKE '%.%'")
            elif dx:
                w.append("source <> 'posta' AND lower(path) LIKE ? ESCAPE '\\'"); a.append("%." + fa.like(dx).strip("%"))
            if text and fts:
                terms = re.findall(r'"[^"]+"|[^\s"]+', text)
                mq = " ".join('"' + t.strip('"').replace('"', "") + '"' for t in terms)
                w.append("doc_text MATCH ?"); a.append(mq)
                restrict()
                if q.get("cfv"):
                    cf_values(con, q, "doc_text", w, a)
                cond = " WHERE " + " AND ".join(w)
                total = con.execute(f"SELECT COUNT(*) FROM doc_text{cond}", a).fetchone()[0]
                rows = con.execute("SELECT rowid, path, kind, source, part, inode, deleted, "
                                   "snippet(doc_text, 1, '«', '»', ' … ', 18) FROM doc_text"
                                   f"{cond} ORDER BY {cf_order(q, 'rank')}{lim}", a).fetchall()
            else:
                if text:
                    w.append("(body LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\')"); a += [L(text)] * 2
                total, rows = page("doc_text", "path, kind, source, part, inode, deleted, "
                                   "substr(body, 1, 240)", "path")
            data = [{"id": r, "path": p, "kind": k, "source": s, "part": pt, "inode": i,
                     "deleted": d, "snippet": " ".join((sn or "").split())}
                    for r, p, k, s, pt, i, d, sn in rows]
        elif kind == "meta":
            if text:
                w.append("(data LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\')"); a += [L(text)] * 2
            if yes(q.get("gps")):
                w.append("lat IS NOT NULL")
            cf_apply(q, CF_META, w, a)
            total, rows = page("meta", "path, make, model, taken, lat, lon, author, source, part, "
                               "inode, deleted", "taken IS NULL, taken")
            data = [dict(zip(("id", "path", "make", "model", "taken", "lat", "lon", "author",
                              "source", "part", "inode", "deleted"), r)) for r in rows]
            for d in data:
                d["taken_tz"] = taken_tz_text(d.get("taken"))
        elif kind == "carved":
            if text:
                w.append("name LIKE ? ESCAPE '\\'"); a.append(L(text))
            if q.get("type"):
                w.append("type = ?"); a.append(q["type"].lower().lstrip("."))
            cf_apply(q, CF_CARVED, w, a)
            total, rows = page("carved", "name, type, size, part, img_offset, sha256, relpath",
                               "img_offset")
            data = [dict(zip(("id", "name", "type", "size", "part", "img_offset", "sha256",
                              "relpath"), r)) for r in rows]
        elif kind == "trace":
            if q.get("tkind"):
                w.append("kind = ?"); a.append(q["tkind"])
            if text:
                w.append("(feature LIKE ? ESCAPE '\\' OR context LIKE ? ESCAPE '\\')"); a += [L(text)] * 2
            if yes(q.get("grouped", "1")):
                if ids is not None:
                    w.append("(kind || char(9) || feature) IN (SELECT value FROM json_each(?))")
                    a.append(json.dumps([str(x) for x in ids]))
                cond = (" WHERE " + " AND ".join(w)) if w else ""
                total = con.execute(f"SELECT COUNT(*) FROM (SELECT 1 FROM features{cond} "
                                    "GROUP BY kind, feature)", a).fetchone()[0]
                rows = con.execute(f"SELECT kind, feature, COUNT(*) n, MIN(pos), MIN(offset) "
                                   f"FROM features{cond} GROUP BY kind, feature "
                                   f"ORDER BY n DESC, feature{lim}", a).fetchall()
                data = [{"id": f"{k}\t{f}", "tkind": k, "feature": f, "count": n, "offset": o}
                        for k, f, n, _, o in rows]
            else:
                total, rows = page("features", "kind, offset, feature, context", "pos")
                data = [{"id": r, "tkind": k, "offset": o, "feature": f,
                         "context": c if full else c[:240]} for r, k, o, f, c in rows]
        else:
            raise ValueError(tr("Sezione sconosciuta."))
    finally:
        con.close()
    return {"kind": kind, "total": total, "offset": off, "page": PAGE, "rows": data}


# ------------------------------------------------- fuso orario (UTC -> ora italiana / fuso rilevato)
#
# I dati del caso restano in UTC; la conversione serve solo a mostrarli. Si usa il database dei
# fusi di Python se c'è, altrimenti (solo per l'Italia) la regola europea dell'ora legale (dal 1996).
# Modalità di visualizzazione ("tz"): "utc", "rome" (ora italiana), "dev" (fuso del dispositivo rilevato
# o scelto per il caso) oppure direttamente un nome IANA (es. "America/New_York").

try:
    from zoneinfo import ZoneInfo
    _ROME = ZoneInfo("Europe/Rome")
except Exception:
    ZoneInfo = None
    _ROME = None
TS_RE = re.compile(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.\d+)?(?:Z|[+-]00:?00)?")
_ZCACHE = {}


def _zone_obj(name):
    if not name or name == "UTC" or ZoneInfo is None:
        return None
    if name not in _ZCACHE:
        try:
            _ZCACHE[name] = ZoneInfo(name)
        except Exception:
            _ZCACHE[name] = None
    return _ZCACHE[name]


def tz_zone(case, tz):
    """Nome IANA della modalità di visualizzazione richiesta: "UTC", "Europe/Rome", il fuso del dispositivo del
    caso ("dev") oppure un nome IANA valido. Per un valore non riconosciuto restituisce "UTC"."""
    if not tz or str(tz).lower() == "utc":
        return "UTC"
    if tz == "rome":
        return "Europe/Rome"
    if tz == "dev":
        z = ((case.meta.get("fuso_dispositivo") or {}).get("tz") if case is not None else None)
        return z if z and (z == "UTC" or _zone_obj(z) is not None) else "UTC"
    return tz if tz == "Europe/Rome" or _zone_obj(tz) is not None else "UTC"


def tz_label(case, tz):
    """Etichetta da scrivere accanto alle date ('UTC', 'ora italiana' o il fuso rilevato)."""
    z = tz_zone(case, tz)
    if z == "UTC":
        return "UTC"
    if tz == "rome":
        return tr("ora italiana")
    f = (case.meta.get("fuso_dispositivo") or {}) if case is not None else {}
    st = f.get("stato")
    return (tr("fuso rilevato {z}").format(z=z) if st in ("rilevato", "confermato") else tr("fuso impostato {z}").format(z=z)) if tz == "dev" else z


def _off_tag(zone, off):
    """Sigla dello scostamento: CET/CEST per l'Italia, altrimenti 'UTC+HH:MM' (le sigle dei fusi sono ambigue)."""
    if zone == "Europe/Rome":
        return "CEST" if off == 7200 else "CET" if off == 3600 else "UTC%+03d:%02d" % (int(off // 3600), abs(off) % 3600 // 60)
    if zone == "UTC":
        return "UTC"
    sign = "+" if off >= 0 else "-"
    return "UTC%s%02d:%02d" % (sign, abs(int(off)) // 3600, abs(int(off)) % 3600 // 60)


def _rome_dt(dt):
    import datetime as _dt
    if _ROME is not None:
        return dt.replace(tzinfo=_dt.timezone.utc).astimezone(_ROME).replace(tzinfo=None)

    def last_sunday(m):
        x = _dt.datetime(dt.year, m, 31, 1)
        return x - _dt.timedelta(days=(x.weekday() + 1) % 7)
    return dt + _dt.timedelta(hours=2 if last_sunday(3) <= dt < last_sunday(10) else 1)


def _zone_dt(dt, zone):
    """Data e ora UTC (naive) -> data e ora del fuso (naive)."""
    import datetime as _dt
    if zone == "UTC":
        return dt
    if zone == "Europe/Rome":
        return _rome_dt(dt)
    zo = _zone_obj(zone)
    if zo is None:
        raise ValueError(tr("fuso non disponibile"))
    return dt.replace(tzinfo=_dt.timezone.utc).astimezone(zo).replace(tzinfo=None)


def to_zone(ts, zone, sep=None, tag=False):
    """Data e ora UTC ('2024-03-01T10:00:00', anche con Z o +00:00) nel fuso indicato, stessa forma. Con tag=True
    aggiunge la sigla (CET/CEST per l'Italia, altrimenti UTC+HH:MM): nell'ora doppia del passaggio all'ora solare è
    l'unico modo per distinguere i due istanti. Se il fuso non è disponibile restituisce il testo com'è."""
    import datetime as _dt
    m = TS_RE.fullmatch((ts or "").strip()) if isinstance(ts, str) else None
    if not m:
        return ts
    try:
        utc = _dt.datetime(*map(int, m.groups()))
        loc = _zone_dt(utc, zone)
    except (ValueError, OverflowError):
        return ts
    out = loc.strftime(f"%Y-%m-%d{sep or ts[10]}%H:%M:%S")
    if tag:
        out += " " + _off_tag(zone, (loc - utc).total_seconds())
    return out


def to_rome(ts, sep=None, tag=False):
    return to_zone(ts, "Europe/Rome", sep, tag)


def local_to_utc_str(loc, zone):
    """Data e ora locali del fuso (naive) -> UTC; fold=0 (prima occorrenza) nell'ora doppia. None se non valida."""
    import datetime as _dt
    zo = _ROME if zone == "Europe/Rome" else _zone_obj(zone)
    if zone == "UTC":
        return loc
    if zo is None:
        return None
    return loc.replace(tzinfo=zo).astimezone(_dt.timezone.utc).replace(tzinfo=None)


_FILE_AFTER = re.compile(r"^(?:\.[A-Za-z0-9]{1,6}\b|[ \t]?[\w\-]+\.[A-Za-z0-9]{1,6}\b)")


def _ts_is_text(md, m):
    """True se l'orario trovato fa parte di un nome di file, di un percorso, di un testo tra apici inversi o di una
    cella di tabella con altro testo: in quel caso non è un orario del report e non va toccato."""
    s, e = m.span()
    ls = md.rfind("\n", 0, s) + 1
    le = md.find("\n", e)
    le = len(md) if le < 0 else le
    before, after = md[ls:s], md[e:le]
    if before.count("`") % 2 == 1:
        return True
    if before and (before[-1] in "/\\_-" or before[-1].isalnum()):
        return True
    if _FILE_AFTER.match(after):
        return True
    if before.lstrip().startswith("|"):
        a = before.rfind("|") + 1
        b = after.find("|")
        cell = (before[a:] + m.group(0) + (after[:b] if b >= 0 else after)).strip()
        if cell != m.group(0):
            return True
    return False


def md_to_zone_ex(md, zone):
    """Report in markdown con gli orari UTC convertiti nel fuso indicato (con la sigla). Non tocca nomi di
    file, percorsi, testo tra apici inversi né celle con altro testo. Restituisce (testo, convertiti, lasciati)."""
    out, last, conv, skip = [], 0, 0, 0
    for m in TS_RE.finditer(md):
        if _ts_is_text(md, m):
            skip += 1
            continue
        out.append(md[last:m.start()])
        out.append(to_zone(m.group(0), zone, m.group(0)[10], tag=True))
        last = m.end()
        conv += 1
    out.append(md[last:])
    return "".join(out), conv, skip


def md_to_rome_ex(md):
    return md_to_zone_ex(md, "Europe/Rome")


def md_to_rome(md):
    return md_to_rome_ex(md)[0]


def fmt_ts(case, tz, s):
    """Data e ora UTC del caso scritte nel fuso scelto, SEMPRE con la sigla (UTC, CET/CEST o UTC+HH:MM).
    Le date che non sono in UTC (ora locale senza fuso) restano come sono e lo dicono."""
    s = ("" if s is None else str(s)).strip()
    if not s:
        return ""
    if s.lower().endswith("locale"):
        return s.replace("T", " ") + tr(" (ora locale, fuso non indicato)")
    if TS_RE.fullmatch(s):
        z = tz_zone(case, tz)
        r = to_zone(s, z, " ", tag=True)
        return r if r != s else s.replace("T", " ") + " UTC"
    return s


ISTAT_TS = re.compile(r"(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)(\.\d+)? \(([^)\s]{1,12})\)")


def _istat_walk(case, text, fn):
    """Applica fn(utc_naive, frazione, originale) a ogni orario dell'istat di Sleuth Kit. Sleuth Kit li stampa nel fuso
    del dispositivo (-z): ogni orario si riporta all'istante assoluto (la sigla che stampa distingue le due ore
    dell'ora doppia). Restituisce (testo, n. convertiti, fuso del dispositivo) oppure (testo, 0, None) se il fuso non è
    registrato (casi preparati prima della 2.13.7)."""
    import datetime as _dt
    dev = (case.meta.get("fuso_dispositivo") or {}).get("tz")
    if not dev or (dev not in ("UTC", "Europe/Rome") and _zone_obj(dev) is None):
        return text, 0, None
    devo = _ROME if dev == "Europe/Rome" else (None if dev == "UTC" else _zone_obj(dev))
    n = [0]

    def conv(m):
        try:
            naive = _dt.datetime.fromisoformat(m.group(1) + " " + m.group(2))
            if devo is None:
                aware = naive.replace(tzinfo=_dt.timezone.utc)
            else:
                aware = None
                for fold in (0, 1):
                    c = naive.replace(tzinfo=devo, fold=fold)
                    if c.tzname() == m.group(4):
                        aware = c
                        break
                if aware is None:
                    aware = naive.replace(tzinfo=devo)
            utc = aware.astimezone(_dt.timezone.utc).replace(tzinfo=None)
            r = fn(utc, m.group(3) or "", m.group(0))
        except (ValueError, OverflowError):
            return m.group(0)
        n[0] += 1
        return r
    return ISTAT_TS.sub(conv, text), n[0], dev


NO_DEV_NOTE = N_("Caso preparato prima della 2.13.7: Sleuth Kit ha scritto gli orari nel fuso del computer usato per "
               "l'analisi, che non è registrato. Gli orari qui sotto NON sono stati convertiti.")


def istat_to_zone(case, text, tz):
    """Orari dell'istat nel fuso scelto, con la sigla. Restituisce (testo, nota)."""
    zone = tz_zone(case, tz)

    def f(utc, frac, orig):
        loc = _zone_dt(utc, zone)
        return f"{loc:%Y-%m-%d %H:%M:%S}{frac} ({_off_tag(zone, (loc - utc).total_seconds())})"
    out, n, dev = _istat_walk(case, text, f)
    if dev is None:
        return text, tr(NO_DEV_NOTE)
    return out, (tr("Orari del file system (Sleuth Kit) scritti in: {v1}. Sleuth Kit li ha letti nel fuso del "
                    "dispositivo ({dev}); NTFS/ext/HFS memorizzano UTC, FAT/exFAT memorizzano l'ora locale del "
                    "dispositivo. Orari convertiti: {n}.").format(v1=tz_label(case, tz), dev=dev, n=n))


TOK_A, TOK_B = "\u27e6", "\u27e7"


def istat_tokens(case, text):
    """Per il report portatile: ogni orario diventa ⟦AAAA-MM-GGTHH:MM:SS[.frazione]⟧ in UTC, che il browser riscrive
    nel fuso scelto. Con APFS (già UTC) vale lo stesso. Restituisce il testo (con una riga di avviso se il fuso del
    dispositivo non è registrato)."""
    out, n, dev = _istat_walk(case, text, lambda u, fr, o: f"{TOK_A}{u:%Y-%m-%dT%H:%M:%S}{fr}{TOK_B}")
    if dev is None:
        return tr(NO_DEV_NOTE) + "\n\n" + text
    return out


def apfs_istat_tokens(text):
    return re.sub(r"(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)(\.\d+)? UTC",
                  lambda m: f"{TOK_A}{m.group(1)}T{m.group(2)}{m.group(3) or ''}{TOK_B}", text)


def apfs_istat_to_zone(case, text, tz):
    """Date dell'istat APFS (sempre UTC, con nanosecondi) nel fuso scelto."""
    zone = tz_zone(case, tz)
    n = [0]

    def conv(m):
        r = to_zone(f"{m.group(1)}T{m.group(2)}", zone, " ", tag=True)
        n[0] += 1
        return r.replace(" ", " ", 1).rsplit(" ", 1)[0] + (m.group(3) or "") + " " + r.rsplit(" ", 1)[1]
    out = re.sub(r"(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)(\.\d+)? UTC", conv, text)
    out = out.replace(tr("Date (UTC):"), tr("Date ({v1}):").format(v1=tz_label(case, tz)))
    return out, (tr("Orari APFS scritti in: {v1} (APFS memorizza UTC). Orari convertiti: {v2}.").format(v1=tz_label(case, tz), v2=n[0]))


_EXIF_DT = re.compile(r"^(\d{4}):(\d\d):(\d\d) (\d\d:\d\d:\d\d)(\.\d+)?\s*(Z|[+-]\d\d:?\d\d)?$")


def exif_to_zone(case, text, tz):
    """Date di exiftool: restano come scritte nel file; accanto a quelle che hanno il fuso (o sono UTC per
    specifica, QuickTime) si aggiunge l'orario nel fuso scelto, per le altre si dice che il fuso non c'è."""
    import datetime as _dt
    zone = tz_zone(case, tz)
    out = []
    offs = {}       # scostamenti dichiarati a parte (OffsetTime*) per lo stesso gruppo
    for l in text.splitlines():
        m = re.match(r"^\[(\w+)\]\s+(OffsetTime\w*)\s*:\s*([+-]\d\d:?\d\d|Z)\s*$", l)
        if m:
            offs[(m.group(1), m.group(2))] = m.group(3)
    pair = {"DateTimeOriginal": "OffsetTimeOriginal", "CreateDate": "OffsetTimeDigitized", "ModifyDate": "OffsetTime"}
    for l in text.splitlines():
        m = re.match(r"^(\[(\w+)\]\s+)(\w*(?:Date|Time)\w*)(\s*:\s*)(.*?)\s*$", l)
        d = _EXIF_DT.match(m.group(5)) if m else None
        if not d or m.group(3).startswith("GPS") and "Stamp" in m.group(3):
            out.append(l)
            continue
        off = d.group(6)
        sep_off = None
        if not off and (m.group(2), pair.get(m.group(3), "")) in offs:
            off = sep_off = offs[(m.group(2), pair[m.group(3)])]
        if not off and m.group(2) == "QuickTime":
            off = "Z"
        try:
            if off:
                dt = _dt.datetime(int(d.group(1)), int(d.group(2)), int(d.group(3)), *map(int, d.group(4).split(":")))
                if off != "Z":
                    o = re.match(r"([+-])(\d\d):?(\d\d)", off)
                    dt -= (1 if o.group(1) == "+" else -1) * _dt.timedelta(hours=int(o.group(2)), minutes=int(o.group(3)))
                loc = _zone_dt(dt, zone)
                out.append(l + f"   → {loc:%Y-%m-%d %H:%M:%S} {_off_tag(zone, (loc - dt).total_seconds())}"
                           + (f"  [fuso da {pair[m.group(3)]}]" if sep_off else tr("  [UTC per specifica QuickTime]") if not d.group(6) else ""))
            else:
                out.append(l + tr("   [fuso non indicato nel file: ora locale del dispositivo]"))
        except (ValueError, OverflowError):
            out.append(l)
    return "\n".join(out) + ("\n" if out else "")


_WORKCOPY_TAGS = ("FileModifyDate", "FileAccessDate", "FileInodeChangeDate", "FileCreateDate", "FileName",
                  "Directory", "FilePermissions")


def exif_no_workcopy(text):
    """Toglie da exiftool i campi del file system della COPIA DI LAVORO (data di estrazione, cartella temporanea,
    permessi): non sono dati della prova e porterebbero la data di oggi nel fuso del computer."""
    keep = []
    for l in text.splitlines():
        m = re.match(r"\[(?:File|System)\]\s+(\w+)\s*:", l)
        if m and m.group(1) in _WORKCOPY_TAGS:
            continue
        keep.append(l)
    return "\n".join(keep) + ("\n" if keep else "")


def taken_tz_text(s):
    """Fuso della data dei metadati: quello scritto nel file oppure 'non indicato (ora locale del dispositivo)'."""
    s = str(s or "").strip()
    if not s:
        return ""
    m = re.search(r"(Z|[+-]\d\d:?\d\d)$", s)
    if not m:
        return tr("non indicato (ora locale del dispositivo)")
    return "UTC" if m.group(1) == "Z" else m.group(1)


def tl_hist(case, q):
    """Eventi per giorno (o mese/anno) con gli stessi filtri della tabella."""
    gran = q.get("gran") or "auto"
    w, a = [], []
    tl_where(q, w, a)
    cond = (" WHERE " + " AND ".join(w)) if w else ""
    con = fa.db_ro(case)
    tsx = "ts"
    zone = tz_zone(case, q.get("tz"))
    if zone != "UTC":       # giorni e mesi nel fuso scelto (i filtri restano in UTC)
        con.create_function("rome", 1, lambda t: to_zone(t, zone), deterministic=True)
        tsx = "rome(ts)"
    try:
        if gran == "auto":
            # giorni se il periodo è breve, poi mesi, poi anni (date anomale molto lontane)
            lo, hi, nm = con.execute(f"SELECT MIN(substr({tsx},1,10)), MAX(substr({tsx},1,10)), "
                                     f"COUNT(DISTINCT substr({tsx},1,7)) FROM events{cond}",
                                     a).fetchone()
            span = 0
            if lo and hi:
                import datetime as _dt
                try:
                    span = (_dt.date.fromisoformat(hi) - _dt.date.fromisoformat(lo)).days
                except ValueError:
                    span = 10 ** 6
            gran = "day" if span <= 400 else "month" if nm <= 400 else "year"
        n = {"day": 10, "month": 7, "year": 4}[gran]
        rows = con.execute(
            f"SELECT substr({tsx},1,{n}) k, COUNT(*), SUM(kind='M'), SUM(kind='A'), SUM(kind='C'), "
            f"SUM(kind='B'), SUM(origin='plaso') FROM events{cond} GROUP BY k ORDER BY k",
            a).fetchall()
    finally:
        con.close()
    return {"gran": gran, "bins": [{"k": k, "n": t, "M": m, "A": ac, "C": c, "B": b, "plaso": p}
                                   for k, t, m, ac, c, b, p in rows if k]}


# ------------------------------------------------- albero del file system

NAV_LOCK = threading.Lock()
NAV_STATE = {}
EV_RE = re.compile(r"\| inode (\S+) \| (-?\d+) B$")
NAV_COLS = ("id", "part", "parent", "name", "path", "isdir", "deleted", "type", "inode", "fid",
            "size", "mtime", "atime", "ctime", "crtime", "ndirs", "nitems")


def nav_file(case):
    return case.root / "navigazione.sqlite"


def nav_stamp(case):
    con = fa.db_ro(case)
    try:
        return "v2:%d:%d:%d:%d" % (con.execute("SELECT COUNT(*), IFNULL(MAX(rowid),0) FROM files").fetchone()
                                   + con.execute("SELECT COUNT(*), IFNULL(MAX(rowid),0) FROM events WHERE origin='tsk'").fetchone())
    finally:
        con.close()


def ensure_nav(case):
    """Avvia (una volta) la costruzione dell'indice di navigazione; restituisce lo stato."""
    key = str(case.root)
    with NAV_LOCK:
        st = NAV_STATE.get(key)
        if st and st["state"] in ("building", "ready"):
            return st
        ok = False
        if nav_file(case).exists():
            try:
                c = sqlite3.connect(nav_file(case).as_uri() + "?mode=ro", uri=True)
                ok = c.execute("SELECT v FROM info WHERE k='stamp'").fetchone()[0] == nav_stamp(case)
                c.close()
            except Exception:
                ok = False
        if ok:
            NAV_STATE[key] = {"state": "ready"}
        else:
            NAV_STATE[key] = {"state": "building", "msg": tr("Preparo l'albero del file system…")}
            threading.Thread(target=build_nav, args=(case,), daemon=True).start()
        return NAV_STATE[key]


def build_nav(case):
    """Ricava dall'elenco dei file (fls) l'albero delle cartelle con dimensioni e date.
    È un indice di comodo, ricostruibile: sta in navigazione.sqlite, accanto a caso.sqlite,
    che resta invariato."""
    key = str(case.root)
    st = NAV_STATE[key]
    tmp = case.root / "navigazione.sqlite.tmp"
    try:
        if tmp.exists():
            tmp.unlink()
        stamp = nav_stamp(case)
        src = fa.db_ro(case)
        out = sqlite3.connect(tmp)
        out.executescript("""
            PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
            CREATE TABLE info(k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE ev(part INTEGER, inode TEXT, size INTEGER, kind TEXT, ts TEXT);
            CREATE TABLE f(part INTEGER, parent TEXT, name TEXT, path TEXT, isdir INTEGER,
                           deleted INTEGER, type TEXT, inode TEXT, fid INTEGER);
        """)
        st["msg"] = tr("Albero: leggo date e dimensioni…")
        batch = []
        for ts, kind, msg, part in src.execute(
                "SELECT ts, kind, message, part FROM events WHERE origin='tsk'"):
            m = EV_RE.search(msg or "")
            if m:
                batch.append((part, m.group(1), int(m.group(2)), kind, ts))
            if len(batch) >= 50000:
                out.executemany("INSERT INTO ev VALUES (?,?,?,?,?)", batch)
                batch.clear()
        out.executemany("INSERT INTO ev VALUES (?,?,?,?,?)", batch)
        out.executescript("""
            CREATE TABLE info2 AS SELECT part, inode, MAX(size) size,
                MAX(CASE WHEN kind='M' THEN ts END) m, MAX(CASE WHEN kind='A' THEN ts END) a,
                MAX(CASE WHEN kind='C' THEN ts END) c, MAX(CASE WHEN kind='B' THEN ts END) b
                FROM ev GROUP BY part, inode;
            CREATE INDEX i2 ON info2(part, inode);
            DROP TABLE ev;
        """)
        st["msg"] = tr("Albero: ricostruisco le cartelle…")
        dirs, parents, batch, n = set(), set(), [], 0
        for fid, part, inode, deleted, typ, path in src.execute(
                "SELECT rowid, part, inode, deleted, type, path FROM files"):
            path = (path or "").strip("/")
            if not path:
                continue
            isdir = 1 if is_dir_type(typ) else 0
            parent, _, name = path.rpartition("/")
            batch.append((part, parent, name, path, isdir, deleted, typ, inode, fid))
            if isdir:
                dirs.add((part, path))
            parents.add((part, parent))
            n += 1
            if len(batch) >= 50000:
                out.executemany("INSERT INTO f VALUES (?,?,?,?,?,?,?,?,?)", batch)
                batch.clear()
                st["msg"] = tr("Albero: {n:,} voci…").format(n=n).replace(",", ".")
        src.close()
        # cartelle presenti solo come percorso (es. genitori di file orfani)
        for part, p in list(parents):
            while p and (part, p) not in dirs:
                dirs.add((part, p))
                par, _, name = p.rpartition("/")
                batch.append((part, par, name, p, 1, 0, "d/d", None, None))
                p = par
        out.executemany("INSERT INTO f VALUES (?,?,?,?,?,?,?,?,?)", batch)
        out.executescript("""
            CREATE TABLE nav(id INTEGER PRIMARY KEY, part INTEGER, parent TEXT, name TEXT,
                path TEXT, isdir INTEGER, deleted INTEGER, type TEXT, inode TEXT, fid INTEGER,
                size INTEGER, mtime TEXT, atime TEXT, ctime TEXT, crtime TEXT,
                ndirs INTEGER DEFAULT 0, nitems INTEGER DEFAULT 0);
            INSERT INTO nav(part, parent, name, path, isdir, deleted, type, inode, fid,
                            size, mtime, atime, ctime, crtime)
                SELECT f.part, f.parent, f.name, f.path, f.isdir, f.deleted, f.type, f.inode, f.fid,
                       CASE WHEN f.isdir THEN NULL ELSE i.size END, i.m, i.a, i.c, i.b
                FROM f LEFT JOIN info2 i ON i.part = f.part AND i.inode = f.inode
                ORDER BY f.part, f.parent, f.isdir DESC, f.name COLLATE NOCASE;
            DROP TABLE f; DROP TABLE info2;
            CREATE INDEX nav_parent ON nav(part, parent, isdir);
            CREATE INDEX nav_path ON nav(part, path);
            CREATE INDEX nav_inode ON nav(part, inode);
            CREATE TABLE cnt AS SELECT part, parent, COUNT(*) n,
                COUNT(DISTINCT CASE WHEN isdir THEN path END) nd FROM nav GROUP BY part, parent;
            CREATE INDEX cnt_i ON cnt(part, parent);
            UPDATE nav SET nitems = IFNULL((SELECT n FROM cnt WHERE cnt.part = nav.part
                                                AND cnt.parent = nav.path), 0),
                           ndirs = IFNULL((SELECT nd FROM cnt WHERE cnt.part = nav.part
                                                AND cnt.parent = nav.path), 0)
                WHERE isdir = 1;
        """)
        out.execute("INSERT INTO info VALUES ('stamp', ?)", (stamp,))
        out.commit()
        out.close()
        tmp.replace(nav_file(case))
        st.clear()
        st["state"] = "ready"
    except Exception as e:
        st.clear()
        st.update({"state": "error", "msg": tr("Albero non disponibile: {e}").format(e=e)})
        try:
            tmp.unlink()
        except OSError:
            pass


def nav_attach(con, case):
    """Collega all'archivio del caso l'indice di navigazione (dimensioni e date), se è pronto."""
    try:
        if ensure_nav(case).get("state") != "ready":
            return False
        con.execute("ATTACH DATABASE ? AS nv", (nav_file(case).as_uri() + "?mode=ro",))
        return True
    except sqlite3.Error:
        return False


def nav_db(case):
    st = ensure_nav(case)
    if st["state"] != "ready":
        raise ValueError(st.get("msg") or tr("Albero in preparazione…"))
    return sqlite3.connect(nav_file(case).as_uri() + "?mode=ro", uri=True)


def nav_tree(case, q):
    """Sottocartelle di una cartella (o le partizioni, se part è vuoto)."""
    st = ensure_nav(case)
    if st["state"] != "ready":
        return {"state": st["state"], "msg": st.get("msg")}
    con = nav_db(case)
    try:
        if q.get("part") in (None, ""):
            out = []
            enc = {int(v["offset"]): v.get("tipo") or "cifrato"
                   for v in case.meta.get("volumi_cifrati") or []}
            for p in case.meta.get("partitions", []):
                if not p.get("readable") and p["offset"] not in enc:
                    continue
                r = (con.execute("SELECT n, nd FROM cnt WHERE part=? AND parent=''",
                                 (p["offset"],)).fetchone() if p.get("readable") else None) or (0, 0)
                out.append({"part": p["offset"], "path": "",
                            "name": (tr("Volume APFS «{v1}»").format(v1=p['apfs'].get('name')) if p.get("apfs")
                                     else tr("Partizione {offset}").format(offset=p['offset'])),
                            "fs": p.get("fs"), "os": p.get("os"), "nitems": r[0], "ndirs": r[1],
                            "enc": enc.get(p["offset"])})
            lay = None
            try:
                lay = fa.layout_volumi(case)
            except Exception:
                lay = None
            if lay:
                lay = {"tipo": lay["tipo"], "unita": lay["unita"], "voci": [
                    dict(v, label=f"vol{v['n']} ({v['desc']}: {v['start']}-{v['end']})") for v in lay["voci"]]}
            return {"state": "ready", "parts": out, "layout": lay}
        rows = con.execute(
            "SELECT path, name, MIN(deleted), MAX(ndirs), MAX(nitems) FROM nav "
            "WHERE part=? AND parent=? AND isdir=1 GROUP BY path ORDER BY name COLLATE NOCASE "
            "LIMIT 5000", (int(q["part"]), q.get("path") or "")).fetchall()
    finally:
        con.close()
    dirs = [{"path": p, "name": n, "deleted": d, "ndirs": nd, "nitems": ni} for p, n, d, nd, ni in rows]
    part = int(q["part"])
    if not (q.get("path") or "") and not fa.ap.is_apfs_part(part):
        # cartella virtuale con lo spazio non allocato del file system (come $Unalloc di Autopsy)
        dirs.append({"path": "$Unalloc", "name": "$Unalloc", "deleted": 0, "ndirs": 0, "nitems": None, "virtual": "ua"})
    return {"state": "ready", "dirs": dirs}


def nav_list(case, q, ids=None, limit=PAGE):
    """Contenuto di una cartella (o dell'intero sottoalbero) per la sezione Esplora."""
    if (q.get("dir") or "").strip("/") == "$Unalloc" and not yes(q.get("sub")):
        return ua_list(case, q, ids, limit)
    con = nav_db(case)
    off = int(q.get("offset", 0))
    w, a = [], []
    try:
        if ids is not None:
            w.append("id IN (SELECT value FROM json_each(?))")
            a.append(json.dumps([int(x) for x in ids if str(x).isdigit()]))
        else:
            part, d = int(q.get("part") or 0), (q.get("dir") or "").strip("/")
            w.append("part = ?"); a.append(part)
            if yes(q.get("sub")):
                if d:
                    w.append("substr(path, 1, ?) = ?"); a += [len(d) + 1, d + "/"]
            else:
                w.append("parent = ?"); a.append(d)
            text = (q.get("q") or "").strip()
            if text:
                w.append("name LIKE ? ESCAPE '\\'"); a.append(fa.like(text))
            if yes(q.get("deleted")):
                w.append("deleted = 1")
            cf_apply(q, {"name": ("path" if yes(q.get("sub")) else "name", "t"), "size": ("size", "n"),
                         "mtime": ("mtime", "d"), "crtime": ("crtime", "d"), "atime": ("atime", "d")},
                     w, a)
        kn = known_attach(case, con)
        if kn and yes(q.get("noti")):
            w.append("NOT EXISTS (SELECT 1 FROM k.known WHERE k.known.part = nav.part AND k.known.inode = nav.inode "
                     "AND k.known.kind = 'noti')")
        if q.get("cfv"):
            cf_values(con, q, "nav", w, a)
        cond = " WHERE " + " AND ".join(w)
        order = ("path COLLATE NOCASE, deleted" if yes(q.get("sub")) and ids is None
                 else "isdir DESC, name COLLATE NOCASE, deleted")
        if ids is None:
            order = cf_order(q, order, "" if yes(q.get("sub")) else "isdir DESC, ")
        total = con.execute(f"SELECT COUNT(*) FROM nav{cond}", a).fetchone()[0]
        lim = f" LIMIT {int(limit)} OFFSET {off}" if limit else ""
        kcol = (", (SELECT k.known.kind || ':' || k.known.list FROM k.known WHERE k.known.part = nav.part "
                "AND k.known.inode = nav.inode LIMIT 1)") if kn else ", NULL"
        rows = con.execute(f"SELECT {', '.join(NAV_COLS)}{kcol} FROM nav{cond} "
                           f"ORDER BY {order}{lim}", a).fetchall()
    finally:
        con.close()
    return {"kind": "explore", "total": total, "offset": off, "page": PAGE,
            "rows": [dict(zip(NAV_COLS + ("known",), r)) for r in rows]}


def known_attach(case, con):
    """Collega i risultati del confronto con le liste di hash (tabella known del caso)."""
    if not case.meta.get("liste_hash"):
        return False
    try:
        con.execute("ATTACH DATABASE ? AS k", (case.db_path.as_uri() + "?mode=ro",))
        return bool(con.execute("SELECT name FROM k.sqlite_master WHERE name='known'").fetchone())
    except sqlite3.Error:
        return False


def clean_fs_path(p):
    p = (p or "").strip().strip("`'\"")
    p = re.sub(r" \((deleted|deleted-realloc|\$FILE_NAME)\)$", "", p)
    return p.replace("\\", "/").strip("/")


def nav_locate(case, b):
    """Dove si trova un file nell'albero: per offset+inode, per percorso, o per id di Esplora."""
    con = nav_db(case)
    try:
        r = None
        if b.get("inode") not in (None, ""):
            r = con.execute("SELECT part, path, isdir, deleted FROM nav WHERE part=? AND inode=? "
                            "ORDER BY deleted, length(path) LIMIT 1",
                            (int(b.get("part") or 0), str(b["inode"]))).fetchone()
        if not r and b.get("path"):
            p = clean_fs_path(b["path"])
            parts = [int(b["part"])] if b.get("part") not in (None, "") else None
            sql = "SELECT part, path, isdir, deleted FROM nav WHERE path = ?"
            r = con.execute(sql + (" AND part = ?" if parts else "") + " LIMIT 1",
                            [p] + (parts or [])).fetchone()
            if not r and p:
                r = con.execute("SELECT part, path, isdir, deleted FROM nav WHERE path LIKE ? "
                                "ESCAPE '\\' ORDER BY length(path) LIMIT 1",
                                ("%" + p.replace("\\", "\\\\").replace("%", "\\%")
                                 .replace("_", "\\_"),)).fetchone()
    finally:
        con.close()
    if not r:
        raise ValueError(tr("File non trovato nell'albero del file system."))
    part, path, isdir, deleted = r
    parent = path.rpartition("/")[0]
    index = 0
    if not isdir:   # posizione nella cartella, per aprire la pagina giusta
        con = nav_db(case)
        try:
            for i, (p, dl) in enumerate(con.execute(
                    "SELECT path, deleted FROM nav WHERE part=? AND parent=? "
                    "ORDER BY isdir DESC, name COLLATE NOCASE, deleted", (part, parent))):
                if p == path and dl == deleted:
                    index = i
                    break
        finally:
            con.close()
    return {"part": part, "path": path, "isdir": isdir, "deleted": deleted, "index": index,
            "dir": path if isdir else parent, "select": None if isdir else path}


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


def ref_label(kind, x):
    if kind in EXT_KINDS:
        return ext_ref_label(kind, x)
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
                + (tr(", cancellato") if x["deleted"] else "")
                + (f", SHA-256 {x['sha256']}" if x.get("sha256") else "")
                + tr("; trovato in {wheres}: {terms})").format(wheres=x['wheres'], terms=x['terms']))
    if kind == "explore":
        return (f"{x['path']}{'/' if x['isdir'] else ''} (offset {x['part']}"
                + (f", inode {x['inode']}" if x.get("inode") else "")
                + (tr(", cancellato") if x["deleted"] else "") + ")")
    return f"{x['path']} (offset {x['part']}, inode {x['inode']}{tr(', cancellato') if x.get('deleted') else ''})"


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
             ("atime", "accesso_utc"), ("crtime", "creazione_utc")],
    "timeline": [("ts", "data_utc"), ("kind", "evento"), ("origin", "fonte"), ("source", "sorgente"),
                 ("path", "percorso"), ("message", "dettaglio"), ("part", "partizione_offset"),
                 ("inode", "inode")],
    "doc": [("path", "documento"), ("kind", "tipo"), ("deleted", "cancellato"), ("source", "origine"),
            ("part", "partizione_offset"), ("inode", "inode"), ("snippet", "testo")],
    "meta": [("path", "file"), ("make", "marca"), ("model", "modello"), ("taken", "data_metadati"), ("taken_tz", "fuso_della_data"),
             ("lat", "lat"), ("lon", "lon"), ("author", "autore"), ("deleted", "cancellato"),
             ("source", "origine"), ("part", "partizione_offset"), ("inode", "inode")],
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
    cols = CSV_COLS.get(kind) or EXT_CSV[kind]
    if kind == "trace" and rows and "count" not in rows[0]:
        cols = [c for c in cols if c[0] != "count"]
    d = case.export_dir / "elenchi"
    d.mkdir(parents=True, exist_ok=True)
    name = {"hits": "ricerca", "explore": "esplora", "file": "file", "timeline": "timeline", "doc": "documenti",
            "meta": "metadati", "carved": "recuperati", "trace": "evidenze_di_interesse", "art": "artefatti",
            "mail": "posta", "arch": "archivi_allegati", "vss": "copie_shadow", "anom": "anomalie"}[kind]
    path = unique(d / f"{name}_{stamp_now()}.csv")
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
                         if k in ("isdir", "deleted") else (fmt_ts(case, tz, x.get(k)) if k in dcols and zone != "UTC" else x.get(k))
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
            elif x.get("source") in ("x", "image", "mail", "art", "posta"):
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


def export_selection(case, b, progress):
    """Estrae i file selezionati in export/selezione_<data>/ conservando l'albero delle
    cartelle, in sola lettura, con manifest.csv (percorso originale, inode, SHA-256)."""
    import csv, hashlib
    kind, rows = selected_rows(case, b)
    fs, carved, skipped = export_targets(case, kind, rows)
    xs = x_targets(case, kind, rows)
    for i in [i for i, v in xs.items() if not v[1]]:
        del xs[i]
        skipped += 1
    if not fs and not carved and not xs:
        raise ValueError(tr("Nella selezione non ci sono file esportabili "
                         "(le tracce e gli eventi senza inode si esportano come elenco CSV)."))
    if fs and not Path(case.image).exists():
        raise ValueError(tr("La copia forense non è raggiungibile: collega il disco che la contiene."))
    out = unique(case.export_dir / f"selezione_{stamp_now()}")
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
            for chunk in item_stream(case, part, inode):
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


# ------------------------------------------------- anteprime, miniature, esadecimale
#
# I file della copia vengono estratti una volta (icat, sola lettura) in <caso>/cache/file/
# e da lì si generano miniature, pagine dei PDF, conversioni e la vista esadecimale.
# La cache è ricostruibile e si può cancellare in qualsiasi momento.

import base64, hashlib, tempfile
CACHE_MAX = 2 << 30            # oltre questa dimensione il file non viene copiato in cache
THUMB_SEM = threading.Semaphore(3)
PAGE_SEM = threading.Semaphore(2)     # pagine PDF disegnate in parallelo al massimo
PAGE_BLOCK = 4                        # pagine disegnate con un solo pdftoppm
LO_LOCK = threading.Lock()            # LibreOffice: un profilo, una conversione alla volta
KEY_LOCKS, KEY_LOCK = {}, threading.Lock()
IMG_NATIVE = {".jpg", ".jpeg", ".jpe", ".jfif", ".png", ".gif", ".webp", ".bmp", ".ico", ".avif"}
IMG_CONVERT = {".heic", ".heif", ".tif", ".tiff", ".dng", ".cr2", ".cr3", ".nef", ".arw", ".orf",
               ".raf", ".psd", ".tga"}
IMG_ALL = IMG_NATIVE | IMG_CONVERT
WORD_EXT = {".doc", ".docx", ".docm", ".dot", ".dotx", ".rtf", ".odt", ".wpd", ".wps", ".pages"}
OFFICE_EXT = {".xls", ".xlsx", ".xlsm", ".xlsb", ".ods", ".ppt", ".pptx", ".pptm", ".pps", ".ppsx",
              ".odp", ".key", ".numbers", ".vsd", ".vsdx", ".pub"}
VIDEO_MIME = {".mp4": "video/mp4", ".m4v": "video/mp4", ".mov": "video/quicktime",
              ".webm": "video/webm", ".3gp": "video/3gpp"}
VIDEO_OTHER = {".avi", ".mkv", ".wmv", ".mpg", ".mpeg", ".flv", ".mts", ".m2ts"}
AUDIO_MIME = {".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".aac": "audio/aac", ".wav": "audio/wav",
              ".ogg": "audio/ogg", ".oga": "audio/ogg", ".opus": "audio/ogg", ".flac": "audio/flac",
              ".amr": "audio/amr"}
TEXT_LIKE = set(fa.TEXT_EXT) | {".ini", ".cfg", ".conf", ".yaml", ".yml", ".js", ".py", ".sh",
                                ".bat", ".ps1", ".vbs", ".sql", ".tsv", ".srt", ".vcf", ".ics",
                                ".plist", ".reg", ".inf", ".css", ".php", ".c", ".h", ".java",
                                ".mbox", ".svg"}
RAW_MIME = {**{e: "image/jpeg" for e in (".jpg", ".jpeg", ".jpe", ".jfif")}, ".png": "image/png",
            ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
            ".ico": "image/x-icon", ".avif": "image/avif", **VIDEO_MIME, **AUDIO_MIME}
IS_LINUX = platform.system() == "Linux"


def tool(name):
    """Percorso di un programma esterno, anche fuori dal PATH (LibreOffice su Mac)."""
    p = shutil.which(name)
    if not p and name == "soffice" and IS_MAC:
        app = Path("/Applications/LibreOffice.app/Contents/MacOS/soffice")
        p = str(app) if app.exists() else None
    if not p and name == "convert":
        p = shutil.which("magick")
    return p


def run_quiet(cmd, timeout=60):
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout,
                              stdin=subprocess.DEVNULL).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def safe_key(s):
    return re.sub(r"[^\w.\-]+", "_", str(s))[:120]


def safe_ext(e):
    e = (e or "").lower()
    return e if re.fullmatch(r"\.[a-z0-9]{1,8}", e) else ".bin"


def cache_dir(case, sub):
    d = fa.cache_base(case) / sub
    d.mkdir(parents=True, exist_ok=True)
    return d


CACHE_LIMIT = int(float(os.environ.get("REPERTIA_CACHE_MAX_GB", "5")) * (1 << 30))


def prune_cache(case, limit=None):
    """Tiene la cache delle anteprime entro un tetto (predefinito 5 GB, variabile
    REPERTIA_CACHE_MAX_GB): se lo supera, elimina i file meno recenti fino al 70%.
    Sono solo copie ricostruibili: il caso (database, reperti, esportazioni) non si tocca.
    Si esegue all'apertura del caso, quando nessuna anteprima è in corso."""
    if limit is None:
        g = (case.meta or {}).get("cache_gb")
        try:
            limit = int(float(g) * (1 << 30)) if g not in (None, "") else CACHE_LIMIT
        except (TypeError, ValueError):
            limit = CACHE_LIMIT
    if limit <= 0:                 # 0 = nessun limite
        return 0
    base = fa.cache_base(case)
    files, total = [], 0
    for sub in ("file", "pdf", "pagine", "conv", "miniature", "tmp"):
        d = base / sub
        if not d.is_dir():
            continue
        for f in d.rglob("*"):
            try:
                if f.is_file():
                    st = f.stat()
                    files.append((max(st.st_atime, st.st_mtime), st.st_size, f))
                    total += st.st_size
            except OSError:
                pass
    if total <= limit:
        return 0
    freed = 0
    for _, size, f in sorted(files, key=lambda x: x[0]):
        if total - freed <= limit * 0.7:
            break
        try:
            f.chmod(0o644)
            f.unlink()
            freed += size
        except OSError:
            pass
    if freed:
        case.log("cache_ridotta", {"liberati": freed, "limite": limit})
    return freed


CACHE_SUBS = ("file", "pdf", "pagine", "conv", "miniature", "testo2", "evidenze", "libreoffice", "tmp")


def _tree_size(d):
    total, n = 0, 0
    for f in d.rglob("*"):
        try:
            if f.is_file():
                total += f.stat().st_size
                n += 1
        except OSError:
            pass
    return total, n


def cache_info(case):
    """Stato della cache del caso: dove sta, quanto occupa, qual è il limite."""
    base = fa.cache_base(case)
    total, files = (_tree_size(base) if base.is_dir() else (0, 0))
    g = case.meta.get("cache_gb")
    custom = bool(case.meta.get("cache_dir"))
    return {"path": str(base), "size": total, "files": files, "custom": custom,
            "custom_ok": (not custom) or base != case.root / "cache",
            "limit_gb": float(g) if g not in (None, "") else CACHE_LIMIT / (1 << 30),
            "limit_default": g in (None, ""), "free": fa.free_bytes(base)}


def _rm_force(path):
    import stat as _st

    def onerr(func, p, exc):
        try:
            os.chmod(p, _st.S_IRWXU)
            func(p)
        except OSError:
            pass
    shutil.rmtree(path, onerror=onerr)


def cache_clear(case):
    """Svuota la cache (copie ricostruibili delle anteprime). Non tocca il caso."""
    base = fa.cache_base(case)
    freed = 0
    if base.is_dir():
        for d in list(base.iterdir()):
            try:
                if d.is_dir():
                    freed += _tree_size(d)[0]
                    _rm_force(d)
                elif d.is_file():
                    freed += d.stat().st_size
                    d.unlink()
            except OSError:
                pass
    case.log("cache_svuotata", {"liberati": freed})
    return freed


def cache_set(case, b):
    """Imposta il limite di spazio (GB, 0 = nessun limite) e/o la cartella della cache del caso."""
    if "gb" in b and b["gb"] not in (None, ""):
        try:
            g = float(str(b["gb"]).replace(",", "."))
        except ValueError:
            raise ValueError(tr("Il limite deve essere un numero di GB (0 = nessun limite)."))
        if g < 0 or g > 100000:
            raise ValueError(tr("Limite non valido."))
        case.meta["cache_gb"] = g
    elif b.get("gb_default"):
        case.meta.pop("cache_gb", None)
    moved = None
    if b.get("reset_dir") and case.meta.get("cache_dir"):
        old = fa.cache_base(case)
        case.meta.pop("cache_dir", None)
        if old.is_dir() and old != case.root / "cache":
            _rm_force(old)
        moved = str(case.root / "cache")
    elif b.get("dir"):
        p, _free = check_dest(b["dir"])
        new = p if p.name.lower().startswith("repertia_cache") else p / ("RepertIA_cache_" + case.root.name)
        if str(new) != str(fa.cache_base(case)):
            old = fa.cache_base(case)
            new.mkdir(parents=True, exist_ok=True)
            case.meta["cache_dir"] = str(new)
            if old.is_dir() and old != new:     # la vecchia cache si elimina: è ricostruibile
                _rm_force(old)
            moved = str(new)
    case.save()
    case.log("cache_impostata", {"gb": case.meta.get("cache_gb"), "dir": case.meta.get("cache_dir")})
    prune_cache(case)
    return moved


def copy_case(case, dest, progress):
    """Copia il caso (senza la cache, ricostruibile) in un'altra posizione e la registra tra le
    cartelle dei casi. L'originale resta dov'è."""
    destp, free = check_dest(dest)
    src = case.root
    if destp == src or src in destp.parents:
        raise ValueError(tr("La destinazione non può stare dentro il caso stesso."))
    target = destp / src.name
    n = 2
    while target.exists():
        target = destp / f"{src.name}_{n}"
        n += 1
    cache_p = src / "cache"
    files = []
    for f in src.rglob("*"):
        try:
            if f.is_file() and cache_p not in f.parents and not f.name.endswith((".tmp", ".parziale")):
                files.append((f, f.stat().st_size))
        except OSError:
            pass
    total = sum(s for _, s in files)
    if free is not None and free < total * 1.05 + (50 << 20):
        raise ValueError(tr("Spazio insufficiente nella destinazione: servono {v1}, disponibili {v2}.").format(v1=fa.gb(total), v2=fa.gb(free)))
    case.log("copia_caso", {"destinazione": str(target), "file": len(files), "byte": total})
    done = 0
    last = 0.0
    import time as _t
    try:
        for f, size in files:
            rel = f.relative_to(src)
            out = target / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, out)
            done += size
            if _t.time() - last > 1:
                last = _t.time()
                progress(tr("Copia in corso… {v1} di {v2}").format(v1=fa.gb(done), v2=fa.gb(total)))
        # verifica: stesso numero di file e stessa dimensione
        got = sum(1 for _ in target.rglob("*") if _.is_file())
        if got < len(files):
            raise ValueError(tr("La copia risulta incompleta: controlla lo spazio e riprova."))
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise
    meta = target / "case.json"
    try:                      # la copia non eredita una cartella di cache scelta per l'originale
        m = json.loads(meta.read_text())
        if m.pop("cache_dir", None) is not None:
            meta.write_text(json.dumps(m, indent=2, ensure_ascii=False))
    except (OSError, ValueError):
        pass
    fa.register_case_home(destp)
    return {"path": str(target), "root": str(target), "files": len(files), "bytes": total}


UA_ID_BASE = 10 ** 12           # id delle righe dei tratti non allocati nell'elenco (non si sovrappongono a quelli di nav)
UA_CACHE_MAX = 64 << 20         # i tratti fino a questa dimensione si copiano in cache (anteprima, testo, SHA-256)
UA_JOBS, UA_LOCK = {}, threading.Lock()


def ua_cache_file(case, part):
    return fa.cache_base(case) / "non_allocato" / f"p{part}.json"


def ua_runs(case, part, wait=True):
    """Tratti non allocati della partizione. wait=False: se non sono ancora calcolati avvia il calcolo in background e
    restituisce None (lo stato si legge con ua_job)."""
    try:
        d = json.loads(ua_cache_file(case, part).read_text())
        if d.get("image") == str(case.image):
            return d
    except (OSError, ValueError):
        pass
    if wait:
        return fa.unalloc_runs(case, part)
    key = (str(case.root), part)
    with UA_LOCK:
        job = UA_JOBS.get(key)
        if job and job["state"] == "building":
            return None
        job = UA_JOBS[key] = {"state": "building", "msg": tr("Calcolo lo spazio non allocato con Sleuth Kit…")}

    def run():
        try:
            fa.unalloc_runs(case, part, progress=lambda m: job.update(msg=m))
            job["state"] = "ready"
        except Exception as e:
            job.update(state="error", msg=str(e))
    threading.Thread(target=run, daemon=True).start()
    return None


def ua_job(case, part):
    return UA_JOBS.get((str(case.root), part)) or {"state": "building", "msg": tr("Calcolo lo spazio non allocato…")}


def ua_name(part, start, ln):
    s, e = start // 512, (start + ln) // 512 - 1
    return f"Unalloc_{part}_{s}_{e}" if part >= 0 else f"Disco_{s}_{e}"


def ua_ident(case, part, inode):
    """Tratto di spazio non allocato (inode «u<byte iniziale>-<lunghezza>»): di una partizione (part = offset) o
    del disco fuori dalle partizioni (part = -1, righe «Unallocated» o volumi non leggibili della tabella)."""
    m = fa.UA_RE.fullmatch(inode)
    start, ln = int(m.group(1)), int(m.group(2))
    if part < 0:
        lay = fa.layout_volumi(case) or {}
        ok = next((v for v in lay.get("voci", []) if v["start"] * 512 == start and v["length"] * 512 >= ln
                   and (v["kind"] == "unalloc" or (v["kind"] == "vol" and not v.get("parts")))), None)
        if not ok:
            raise ValueError(tr("Area del disco non valida."))
        what = (tr("spazio non allocato del disco") if ok["kind"] == "unalloc"
                else tr("volume che Sleuth Kit non legge (contenuto grezzo)"))
        path = f"vol{ok['n']} ({ok['desc']}: {ok['start']}-{ok['end']})"
    else:
        if part not in {p["offset"] for p in case.meta.get("partitions", []) if p.get("readable")}:
            raise ValueError(tr("Partizione non valida."))
        d = ua_runs(case, part)
        if not any(r[0] == start and r[1] == ln for r in d["runs"]):
            raise ValueError(tr("Tratto di spazio non allocato non valido."))
        what = tr("spazio non allocato del file system")
        path = "$Unalloc/" + ua_name(part, start, ln)
    name = ua_name(part, start, ln)
    return {"source": "ua", "part": part, "inode": inode, "start": start, "path": path, "name": name,
            "key": f"ua_{start}_{ln}", "ext": "", "size": ln, "deleted": 0, "what": what}


def ua_stream(case, it, start=0, size=4 << 20):
    """Byte del tratto (dalla posizione `start` nel tratto), letti dalla copia forense."""
    pos, end = start, it["size"]
    while pos < end:
        c = image_read(case, it["start"] + pos, min(size, end - pos))
        if not c:
            break
        yield pos, c
        pos += len(c)


def item_stream(case, part, inode):
    """Contenuto di un elemento della copia: file (icat) o tratto non allocato (letto dall'immagine)."""
    if fa.UA_RE.fullmatch(str(inode)):
        for _, c in ua_stream(case, ua_ident(case, int(part), str(inode))):
            yield c
        return
    yield from fa.icat_stream(case, part, inode)


def export_ua(case, part, inode):
    it = ua_ident(case, part, inode)
    if not Path(case.image).exists():
        raise ValueError(tr("La copia forense non è raggiungibile: collega il disco che la contiene."))
    dest = unique(case.export_dir / "non_allocato" / (it["name"] + ".bin"))
    dest.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    with open(lp(dest), "wb") as f:
        for _, c in ua_stream(case, it):
            f.write(c)
            h.update(c)
    os.chmod(lp(dest), 0o444)
    case.log("export_non_allocato", {"partizione": part, "byte_iniziale": it["start"], "byte": it["size"],
                                     "sha256": h.hexdigest(), "dest": str(dest)})
    n = lambda v: f"{v:,}".replace(",", ".")
    return (tr("Esportato {v1} ({v2} byte, dal byte {v3} al {v4} della copia), SHA-256 {v5}").format(v1=dest.relative_to(case.root), v2=n(it['size']), v3=n(it['start']), v4=n(it['start'] + it['size'] - 1), v5=h.hexdigest()))


def ua_list(case, q, ids=None, limit=PAGE):
    """Contenuto della cartella virtuale $Unalloc: un elemento per tratto contiguo di spazio non allocato."""
    part = int(q.get("part") or 0)
    off = int(q.get("offset", 0))
    d = ua_runs(case, part, wait=ids is not None or limit is None)
    if d is None:
        job = ua_job(case, part)
        if job["state"] == "error":
            raise ValueError(job["msg"])
        return {"kind": "explore", "total": 0, "offset": 0, "page": PAGE, "rows": [], "building": job["msg"]}
    rows = []
    for i, (st, ln) in enumerate(d["runs"]):
        nm = ua_name(part, st, ln)
        rows.append({"id": UA_ID_BASE + i, "part": part, "parent": "$Unalloc", "name": nm, "path": "$Unalloc/" + nm,
                     "isdir": 0, "deleted": 0, "type": "r/r", "inode": f"u{st}-{ln}", "fid": None, "size": ln,
                     "mtime": None, "atime": None, "ctime": None, "crtime": None, "ndirs": 0, "nitems": 0,
                     "known": None, "ua": 1, "start": st, "s0": st // 512, "s1": (st + ln) // 512 - 1})
    if ids is not None:
        want = {int(x) for x in ids if str(x).isdigit()}
        rows = [r for r in rows if r["id"] in want]
    text = (q.get("q") or "").strip().lower()
    if text:
        rows = [r for r in rows if text in r["name"].lower()]
    if q.get("sk") == "size":
        rows.sort(key=lambda r: r["size"], reverse=q.get("sd") == "desc")
    elif q.get("sk") == "name" and q.get("sd") == "desc":
        rows.reverse()
    total = len(rows)
    page = rows[off:off + limit] if limit else rows
    return {"kind": "explore", "total": total, "offset": off, "page": PAGE, "rows": page,
            "ua": {"blocco": d["block_size"], "byte": d["byte"], "tratti": len(d["runs"])}}


def file_ident(case, b):
    """Identifica un file della copia (offset+inode) o recuperato col carving (nome)."""
    if fa.UA_RE.fullmatch(str(b.get("inode") or "")):     # tratto di spazio non allocato
        return ua_ident(case, int(b.get("part")), str(b.get("inode")))
    if b.get("source") == "x":            # estratto da archivio, allegato, copia shadow
        return x_ident(case, b)
    if b.get("source") == "image":          # la copia forense stessa (esadecimale delle tracce)
        return image_ident(case)
    if (b.get("source") or "fs") == "carving":
        name = Path(str(b.get("name") or "")).name
        con = fa.db_ro(case)
        try:
            r = con.execute("SELECT relpath FROM carved WHERE name=? OR name LIKE ? ESCAPE '\\' LIMIT 1", (name, "%/" + fa.like(name)[1:-1])).fetchone()
        finally:
            con.close()
        if not r or not (case.root / r[0]).exists():
            raise ValueError(tr("File recuperato non trovato."))
        p = case.root / r[0]
        return {"source": "carving", "name": name, "path": name, "key": "c_" + safe_key(name),
                "ext": Path(name).suffix.lower(), "size": p.stat().st_size, "file": p,
                "deleted": 0, "part": None, "inode": None}
    part, inode = int(b.get("part")), str(b.get("inode") or "").strip()
    if not fa.INODE_RE.fullmatch(inode):
        raise ValueError(tr("inode non valido."))
    if part not in {p["offset"] for p in case.meta.get("partitions", []) if p.get("readable")}:
        raise ValueError(tr("Partizione non valida."))
    path, size, deleted = None, None, 0
    try:
        con = nav_db(case)
        r = con.execute("SELECT path, size, deleted FROM nav WHERE part=? AND inode=? AND isdir=0 "
                        "ORDER BY deleted LIMIT 1", (part, inode)).fetchone()
        con.close()
        if r:
            path, size, deleted = r
    except (ValueError, sqlite3.Error):
        pass
    if not path:
        con = fa.db_ro(case)
        r = con.execute("SELECT path, deleted FROM files WHERE part=? AND inode=? LIMIT 1",
                        (part, inode)).fetchone()
        con.close()
        path, deleted = (r[0], r[1]) if r else (f"inode_{inode}", 0)
    ext = Path(path.split(":")[0]).suffix.lower()      # NTFS: file.txt:Zone.Identifier
    return {"source": "fs", "part": part, "inode": inode, "path": path, "name": Path(path).name,
            "key": f"p{part}_i{safe_key(inode)}", "ext": ext, "size": size, "deleted": deleted}


def key_lock(key):
    with KEY_LOCK:
        return KEY_LOCKS.setdefault(key, threading.Lock())


def cached_file(case, it, limit=CACHE_MAX):
    """Copia del file nella cache del caso (con la sua estensione, utile agli strumenti
    di anteprima). None se il file è più grande di `limit`."""
    if it["source"] in ("carving", "x"):
        return it["file"]
    if it["source"] == "ua":
        limit = min(limit, UA_CACHE_MAX)
    dest = cache_dir(case, "file") / (it["key"] + safe_ext(it["ext"]))
    if dest.exists():
        return dest
    if it.get("size") and it["size"] > limit:
        return None
    if not Path(case.image).exists():
        raise ValueError(tr("La copia forense non è raggiungibile: collega il disco che la contiene."))
    with key_lock(it["key"]):
        if dest.exists():
            return dest
        tmp = dest.with_name(dest.name + ".parziale")
        n = 0
        with open(tmp, "wb") as f:
            for chunk in item_stream(case, it["part"], it["inode"]):
                f.write(chunk)
                n += len(chunk)
                if n > limit:
                    break
        if n > limit:
            tmp.unlink()
            return None
        tmp.replace(dest)
        dest.chmod(0o444)
    return dest


def file_size(case, it):
    f = cached_file(case, it)
    return (f.stat().st_size if f else it.get("size") or 0), f


def read_range(case, it, off, n):
    if it["source"] == "image":
        return image_read(case, off, n), it["size"]
    if it["source"] == "x" and not it.get("file"):
        raise ValueError(tr("File non estratto: ") + (it["rec"].get("note") or tr("contenuto non disponibile")))
    size, f = file_size(case, it)
    if f:
        with open(f, "rb") as fh:
            fh.seek(off)
            return fh.read(n), size
    if it["source"] == "ua":                 # tratto non allocato grande: lettura diretta dalla copia
        n = max(0, min(n, it["size"] - off))
        return (image_read(case, it["start"] + off, n) if n else b""), it["size"]
    # file enorme: si legge in streaming fino al punto richiesto (più lento)
    out, pos = bytearray(), 0
    gen = fa.icat_stream(case, it["part"], it["inode"])
    try:
        for chunk in gen:
            if pos + len(chunk) > off:
                out += chunk[max(0, off - pos):]
                if len(out) >= n:
                    break
            pos += len(chunk)
    finally:
        gen.close()
    return bytes(out[:n]), size


def iter_chunks(case, it, start=0, size=4 << 20):
    if it["source"] == "image":
        yield from image_chunks(case, start, size)
        return
    if it["source"] == "x" and not it.get("file"):
        raise ValueError(tr("File non estratto."))
    _, f = file_size(case, it)
    if f:
        with open(f, "rb") as fh:
            fh.seek(start)
            pos = start
            while chunk := fh.read(size):
                yield pos, chunk
                pos += len(chunk)
        return
    if it["source"] == "ua":
        yield from ua_stream(case, it, start, size)
        return
    pos = 0
    gen = fa.icat_stream(case, it["part"], it["inode"])
    try:
        for chunk in gen:
            if pos + len(chunk) > start:
                s = max(0, start - pos)
                yield pos + s, chunk[s:]
            pos += len(chunk)
    finally:
        gen.close()


def hex_page(case, b):
    it = file_ident(case, b)
    off = max(0, int(b.get("offset") or 0))
    n = max(16, min(int(b.get("length") or 4096), 1 << 16))
    data, size = read_range(case, it, off, n)
    return {"offset": off, "size": size, "data": base64.b64encode(data).decode(),
            "title": it["path"]}


def hex_search(case, b, max_hits=500):
    """Cerca testo (ASCII/UTF-8 o UTF-16LE) o una sequenza esadecimale dentro il file."""
    it = file_ident(case, b)
    mode, pat = b.get("mode") or "text", b.get("pattern") or ""
    nocase = mode in ("text", "utf16") and not yes(b.get("case"))
    if mode == "hex":
        h = re.sub(r"[^0-9a-fA-F]", "", pat)
        if len(h) < 2 or len(h) % 2:
            raise ValueError(tr("Sequenza esadecimale non valida (es. FF D8 FF oppure 504B0304)."))
        needle = bytes.fromhex(h)
    elif mode == "utf16":
        needle = (pat.lower() if nocase else pat).encode("utf-16-le")
    else:
        needle = (pat.lower() if nocase else pat).encode("utf-8")
    if not needle:
        raise ValueError(tr("Scrivi cosa cercare."))
    start = max(0, int(b.get("from") or 0))
    hits, tail, tail_pos = [], b"", start
    for pos, chunk in iter_chunks(case, it, start):
        buf = tail + chunk
        base_pos = pos - len(tail)
        hay = buf.lower() if nocase else buf      # minuscole ASCII (vale anche per UTF-16LE)
        i = hay.find(needle)
        while i != -1:
            if base_pos + i >= start and (not hits or hits[-1] != base_pos + i):
                hits.append(base_pos + i)
                if len(hits) >= max_hits:
                    return {"hits": hits, "more": True}
            i = hay.find(needle, i + 1)
        tail = buf[-(len(needle) - 1):] if len(needle) > 1 else b""
    return {"hits": hits, "more": False}


def sniff_mime(data):
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[:2] == b"BM":
        return "image/bmp"
    return None


def to_jpeg(src, out, size):
    """Converte/riduce un'immagine in JPEG con gli strumenti disponibili."""
    if IS_MAC and shutil.which("sips"):
        if run_quiet(["sips", "-s", "format", "jpeg", "-s", "formatOptions", "80", "-Z", str(size),
                      str(src), "--out", str(out)]) and out.exists():
            return True
    conv = tool("convert")
    if conv and not IS_WIN:          # su Windows "convert" è un comando di sistema diverso
        if run_quiet([conv, str(src) + "[0]", "-auto-orient", "-thumbnail", f"{size}x{size}>",
                      "-quality", "80", "jpeg:" + str(out)]) and out.exists():
            return True
    try:
        from PIL import Image, ImageOps
        with Image.open(src) as im:
            im = ImageOps.exif_transpose(im)
            im.thumbnail((size, size))
            if im.mode not in ("RGB", "L"):
                im = im.convert("RGB")
            im.save(out, "JPEG", quality=80)
        return out.exists()
    except Exception:
        return False


def make_thumb(case, it, f, size, out):
    ext = it["ext"]
    head = open(f, "rb").read(16)
    with tempfile.TemporaryDirectory(dir=cache_dir(case, "tmp")) as td:
        td = Path(td)
        if ext in IMG_ALL or sniff_mime(head):
            if to_jpeg(f, out, size):
                return True
            if (ext in IMG_NATIVE or sniff_mime(head)) and f.stat().st_size < (8 << 20):
                shutil.copyfile(f, out)          # il browser la ridimensiona da sé
                return True
        if (ext == ".pdf" or head[:4] == b"%PDF") and tool("pdftoppm"):
            if run_quiet([tool("pdftoppm"), "-f", "1", "-l", "1", "-scale-to", str(size), "-jpeg",
                          "-singlefile", str(f), str(out.with_suffix(""))], 60) and out.exists():
                return True
        if IS_MAC and shutil.which("qlmanage"):  # Quick Look: Office, Pages, video, testo...
            if run_quiet(["qlmanage", "-t", "-s", str(size), "-o", str(td), str(f)], 30):
                png = next(td.glob("*.png"), None)
                if png:
                    shutil.move(str(png), out)
                    return True
        if (ext in VIDEO_MIME or ext in VIDEO_OTHER) and tool("ffmpeg"):
            if run_quiet([tool("ffmpeg"), "-v", "quiet", "-ss", "1", "-i", str(f), "-frames:v", "1",
                          "-vf", f"scale={size}:-2", "-y", str(td / "v.jpg")], 60) \
                    and (td / "v.jpg").exists():
                shutil.move(str(td / "v.jpg"), out)
                return True
        if ext in WORD_EXT | OFFICE_EXT:
            pdf = office_pdf(case, it, f)
            if pdf and tool("pdftoppm") and run_quiet(
                    [tool("pdftoppm"), "-f", "1", "-l", "1", "-scale-to", str(size), "-jpeg",
                     "-singlefile", str(pdf), str(out.with_suffix(""))], 60) and out.exists():
                return True
    return False


def thumb_bytes(case, b):
    """Miniatura (JPEG/PNG) di un file; None se non si può generare."""
    it = file_ident(case, b)
    size = max(64, min(int(b.get("size") or 256), 1600))
    out = cache_dir(case, "miniature") / f"{it['key']}_{size}.jpg"
    none = out.with_suffix(".nessuna")
    if out.exists():
        data = out.read_bytes()
        return data, sniff_mime(data) or "image/jpeg"
    if none.exists():
        return None
    if it.get("size") and it["size"] > (512 << 20) and it["ext"] not in IMG_ALL:
        return None
    with THUMB_SEM:
        if not out.exists():
            f = cached_file(case, it)
            ok = bool(f) and make_thumb(case, it, f, size, out)
            if not ok:
                none.touch()
                return None
    data = out.read_bytes()
    return data, sniff_mime(data) or "image/jpeg"


def office_pdf(case, it, f):
    """Converte un documento Office/OpenDocument in PDF con LibreOffice, se installato."""
    soffice = tool("soffice")
    if not soffice:
        return None
    out = cache_dir(case, "pdf") / (it["key"] + ".pdf")
    if out.exists():
        return out
    with key_lock(it["key"] + "_pdf"), LO_LOCK:
        if out.exists():
            return out
        # profilo di LibreOffice conservato nel caso: crearlo ogni volta costa diversi secondi
        prof = cache_dir(case, "libreoffice")
        with tempfile.TemporaryDirectory(dir=cache_dir(case, "tmp")) as td:
            ok = run_quiet([soffice, f"-env:UserInstallation={prof.as_uri()}", "--headless",
                            "--norestore", "--convert-to", "pdf", "--outdir", td, str(f)], 180)
            pdf = next(Path(td).glob("*.pdf"), None)
            if ok and pdf:
                shutil.move(str(pdf), out)
                return out
    return None


def pdf_pages(pdf):
    try:
        r = subprocess.run([tool("pdfinfo"), str(pdf)], capture_output=True, timeout=30)
        m = re.search(r"^Pages:\s+(\d+)", fa.dec(r.stdout), re.M)
        return int(m.group(1)) if m else 1
    except (OSError, subprocess.TimeoutExpired, TypeError):
        return 1


def page_png(case, b):
    """Una pagina di un PDF (o di un documento convertito in PDF) come immagine JPEG:
    nessun contenuto attivo del documento arriva al browser. Le pagine si disegnano a
    blocchi (un solo pdftoppm per più pagine) e al massimo due blocchi alla volta."""
    it = file_ident(case, b)
    n = max(1, int(b.get("n") or 1))
    stem = f"{it['key']}{'_c' if yes(b.get('conv')) else ''}"
    d = cache_dir(case, "pagine")
    out = d / f"{stem}_{n}.jpg"
    if out.exists():
        return out.read_bytes()
    f = cached_file(case, it)
    if yes(b.get("conv")):
        f = office_pdf(case, it, f)
    if not f or not tool("pdftoppm"):
        raise ValueError(tr("Pagina non disponibile."))
    first = (n - 1) // PAGE_BLOCK * PAGE_BLOCK + 1
    with key_lock(f"{stem}_pg{first}"):
        if not out.exists():
            with PAGE_SEM, tempfile.TemporaryDirectory(dir=cache_dir(case, "tmp")) as td:
                run_quiet([tool("pdftoppm"), "-f", str(first), "-l", str(first + PAGE_BLOCK - 1),
                           "-r", "110", "-jpeg", "-jpegopt", "quality=88", str(f),
                           str(Path(td) / "p")], 120)
                for img in Path(td).glob("p-*.jpg"):
                    m = re.search(r"-(\d+)\.jpg$", img.name)
                    if m:
                        dest = d / f"{stem}_{int(m.group(1))}.jpg"
                        if not dest.exists():
                            shutil.move(str(img), dest)
    if not out.exists():
        raise ValueError(tr("Impossibile disegnare la pagina."))
    return out.read_bytes()


def converted_image(case, b):
    """Immagini che il browser non mostra (HEIC, TIFF, RAW...) convertite in JPEG."""
    it = file_ident(case, b)
    out = cache_dir(case, "conv") / f"{it['key']}.jpg"
    if not out.exists():
        f = cached_file(case, it)
        if not f or not to_jpeg(f, out, 2400):
            raise ValueError(tr("Conversione dell'immagine non disponibile su questo computer."))
    return out.read_bytes()


CSP_DOC = ("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
           "img-src data:; style-src 'unsafe-inline'; font-src data:\">")


def word_html(f):
    """Documento Word/RTF/ODT in HTML con textutil (macOS), ripulito da script e risorse esterne."""
    if not (IS_MAC and shutil.which("textutil")):
        return None
    try:
        r = subprocess.run(["textutil", "-convert", "html", "-stdout", str(f)],
                           capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0 or not r.stdout:
        return None
    h = fa.dec(r.stdout)
    h = re.sub(r"(?is)<(script|style\b[^>]*>\s*@import|iframe|object|embed)\b.*?</\1\s*>", "", h)
    h = re.sub(r"(?is)<(script|iframe|object|embed|link|base|meta)\b[^>]*>", "", h)
    h = re.sub(r"(?i)\son\w+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", "", h)
    m = re.search(r"(?i)<head[^>]*>", h)       # la regola che blocca risorse esterne va nell'intestazione
    return h[:m.end()] + CSP_DOC + h[m.end():] if m else CSP_DOC + h


def printable_ratio(data):
    if not data:
        return 0
    try:
        t = data.decode("utf-8")
        return sum(c.isprintable() or c in "\r\n\t" for c in t) / len(t)
    except UnicodeDecodeError:
        return sum(32 <= c < 127 or c in (9, 10, 13) for c in data) / len(data)


def decode_text(data):
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    if len(data) > 8 and data[1::2].count(0) > len(data) / 4:
        return data.decode("utf-16-le", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", "replace")


def media_url(kind, it, **extra):
    q = {"source": it["source"], "t": TOKEN, **extra}
    if it["source"] == "carving":
        q["name"] = it["name"]
    elif it["source"] == "x":
        q["id"] = it["id"]
    else:
        q.update(part=it["part"], inode=it["inode"])
    from urllib.parse import urlencode
    return f"/api/{kind}?" + urlencode(q)


def view_info(case, b):
    """Come mostrare un file nel riquadro di anteprima."""
    if b.get("source") == "mail":
        return mail_view(case, b)
    if b.get("source") == "art":
        return art_view(case, b)
    it = file_ident(case, b)
    size, f = file_size(case, it)
    ext = it["ext"]
    head = b""
    if f:
        with open(f, "rb") as fh:
            head = fh.read(8192)
    base = {"title": it["path"], "name": it["name"], "size": size, "deleted": it["deleted"],
            "ext": ext, "source": it["source"], "part": it["part"], "inode": it["inode"],
            "carved_name": it["name"] if it["source"] == "carving" else None,
            "id": it.get("id"), "magic": head[:16].hex(" ")}
    if it["source"] == "x" and not f:
        return {**base, "type": "none", "note": tr("File non estratto: ") + (it["rec"].get("note") or tr("contenuto non disponibile"))}
    if it["source"] == "ua":
        base["title"] = it["path"]
        if not f:
            return {**base, "type": "none", "note": tr("Spazio non allocato ({what}): non è un file. Usa Testo (stringhe leggibili dei primi 50 "
                                                       "MB) o Esadecimale (tutto il tratto).").format(what=it['what'])}
    if not f:
        return {**base, "type": "none", "note": tr("File molto grande: usa la vista esadecimale.")}
    if not size:
        return {**base, "type": "none", "note": tr("File vuoto (0 byte): per i file cancellati il "
                "contenuto può non essere più recuperabile.")}
    if head.startswith(b"SQLite format 3\x00"):
        try:
            return {**base, "type": "html", "html": sqlite_view(f), "note": tr("Database SQLite: tabelle e prime righe (sola lettura).")}
        except sqlite3.Error:
            pass
    mime = sniff_mime(head)
    if ext in IMG_NATIVE or mime:
        return {**base, "type": "image", "src": media_url("raw", it)}
    if ext in IMG_CONVERT:
        return {**base, "type": "image", "src": media_url("conv", it)}
    if ext == ".pdf" or head[:4] == b"%PDF":
        if tool("pdftoppm"):
            return {**base, "type": "pdf", "pages": pdf_pages(f), "src": media_url("page", it)}
    if ext in WORD_EXT | OFFICE_EXT:
        pdf = office_pdf(case, it, f)
        if pdf and tool("pdftoppm"):
            return {**base, "type": "pdf", "pages": pdf_pages(pdf), "src": media_url("page", it, conv=1),
                    "note": tr("Impaginazione ricostruita con LibreOffice.")}
        if ext in WORD_EXT:
            h = word_html(f)
            if h:
                return {**base, "type": "html", "html": h,
                        "note": tr("Impaginazione semplificata (textutil di macOS).")}
        t = thumb_bytes(case, {**b, "size": 1400})
        if t:
            return {**base, "type": "image", "src": media_url("thumb", it, size=1400),
                    "note": tr("Prima pagina (anteprima di sistema). Il testo completo è nella scheda Testo.")}
        return {**base, "type": "text", "text": "", "note": tr("Anteprima visuale non disponibile: "
                "apri la scheda Testo (installando LibreOffice si vedono le pagine).")}
    if ext in VIDEO_MIME:
        return {**base, "type": "video", "src": media_url("raw", it), "mime": VIDEO_MIME[ext]}
    if ext in AUDIO_MIME:
        return {**base, "type": "audio", "src": media_url("raw", it), "mime": AUDIO_MIME[ext]}
    if ext in TEXT_LIKE or printable_ratio(head) > 0.92:
        with open(f, "rb") as fh:
            data = fh.read(300_000)
        return {**base, "type": "text", "text": decode_text(data), "truncated": size > len(data)}
    if ext in VIDEO_OTHER:
        t = thumb_bytes(case, {**b, "size": 900})
        if t:
            return {**base, "type": "image", "src": media_url("thumb", it, size=900),
                    "note": tr("Fotogramma del video (il formato non si riproduce nel browser).")}
    t = thumb_bytes(case, {**b, "size": 1200}) if IS_MAC else None
    if t:
        return {**base, "type": "image", "src": media_url("thumb", it, size=1200)}
    return {**base, "type": "none", "note": tr("Nessuna anteprima visuale per questo tipo di file: "
            "guarda Testo, Esadecimale o Metadati.")}


def file_details(case, b):
    """Scheda Metadati: istat (date, attributi, cluster) ed exiftool."""
    if b.get("source") in ("mail", "art"):
        v = mail_view(case, b) if b.get("source") == "mail" else art_view(case, b)
        return {"istat": v.get("headers") or "", "exif": "", "sha256": ""}
    tz = b.get("tz")
    it = file_ident(case, b)
    t = SES.case_tools
    if it["source"] == "x":
        istat = x_details(case, it, tz)
        exif = ""
        if it["file"] and shutil.which("exiftool"):
            r = subprocess.run(["exiftool", "-G", "-s", str(it["file"])], capture_output=True, timeout=60)
            exif = exif_no_workcopy(fa.dec(r.stdout))
    elif it["source"] == "ua":
        S, L = it["start"], it["size"]
        istat = (tr("Spazio non allocato — {what}\n\nElemento:            {path}\n").format(what=it['what'], path=it['path'])
                 + (tr("Partizione (offset): {part} settori\n").format(part=it['part']) if it["part"] >= 0 else "")
                 + tr("Byte nella copia:    {S:,} – {v1:,}\nSettori (512 byte):  {v2:,} – {v3:,}\nDimensione:      "
                      "    {L:,} byte\n\nNon è un file: sono i blocchi che il file system segna come liberi "
                      "(Sleuth Kit, blkls), letti direttamente dalla copia forense. Possono contenere resti di "
                      "file cancellati.").format(S=S, v1=S + L - 1, v2=S // 512, v3=(S + L) // 512 - 1, L=L)).replace(",", ".")
        exif = ""
        if L > UA_CACHE_MAX:
            istat += tr("\n\nLo SHA-256 di un tratto così grande si calcola all'esportazione (Esporta).")
    elif it["source"] == "carving":
        istat = tr("File recuperato col carving: {name} ({size} byte).").format(name=it['name'], size=it['size'])
        exif = ""
        if shutil.which("exiftool"):
            r = subprocess.run(["exiftool", "-G", "-s", str(it["file"])], capture_output=True,
                               timeout=60)
            exif = exif_no_workcopy(fa.dec(r.stdout))
    else:
        istat = t["file_metadata"](it["part"], it["inode"])
        if fa.ap.is_apfs_part(int(it["part"])):
            istat, note = apfs_istat_to_zone(case, istat, tz)
        else:
            istat, note = istat_to_zone(case, istat, tz)
        if re.search(r"^Directory Entry:", istat, re.M) and re.search(r"^Accessed:", istat, re.M):
            note += (tr(" FAT/exFAT: l'ultimo accesso è solo una data (nel disco l'ora non c'è, TSK scrive 00:00:00 ora locale): "
                     "l'ora che compare dopo la conversione NON è significativa, vale la data nel fuso del dispositivo."))
        istat = note + "\n\n" + istat
        exif = t["file_exif"](it["part"], it["inode"]) if "file_exif" in t else ""
    if exif:
        exif = exif_to_zone(case, exif, tz)
        exif = (tr("Date scritte nel file così come sono; dove il file indica il fuso, a destra c'è l'orario "
                   "in: {v1}.\n\n").format(v1=tz_label(case, tz))) + exif
    sha = ""
    _, f = file_size(case, it)
    if f:
        h = hashlib.sha256()
        with open(f, "rb") as fh:
            while c := fh.read(1 << 20):
                h.update(c)
        sha = h.hexdigest()
    return {"istat": istat, "exif": exif, "sha256": sha}


FULL_TEXT_MAX = 2_000_000       # caratteri mostrati al massimo nella scheda Testo


def carved_full_text(case, name):
    con = fa.db_ro(case)
    try:
        r = con.execute("SELECT relpath, img_offset, sha256 FROM carved WHERE name = ?",
                        (name.strip(),)).fetchone()
        m = con.execute("SELECT data FROM meta WHERE source='carving' AND inode = ?",
                        (name.strip(),)).fetchone()
    finally:
        con.close()
    if not r:
        return tr("Nessun file recuperato con nome {name}.").format(name=name)
    f = case.root / r[0]
    head = tr("File {v1} (byte {v2} nell'immagine, SHA-256 {v3})\n").format(v1=r[0], v2=r[1], v3=r[2])
    if m:
        head += tr("Metadati: ") + m[0][:2000] + "\n"
    return head + fa.show_text(f.read_bytes()[:50 << 20], f.name, cache_dir(case, "tmp"),
                               FULL_TEXT_MAX, more_hint=False)


def file_text(case, b):
    """Testo del file per la scheda Testo, conservato in cache dopo la prima estrazione.
    Si mostra il testo intero (fino a FULL_TEXT_MAX caratteri), non la porzione dell'agente."""
    if b.get("source") == "mail":
        v = mail_view(case, b)
        h = v["head"]
        con = fa.db_ro(case)
        body = con.execute("SELECT body FROM mail WHERE id=?", (v["id"],)).fetchone()[0]
        con.close()
        return {"text": "\n".join(f"{k}: {x}" for k, x in h.items() if x) + "\n\n" + (body or "")}
    if b.get("source") == "art":
        v = art_view(case, b)
        return {"text": re.sub(r"<[^>]+>", " ", v["html"].split("</style>")[-1])}
    it = file_ident(case, b)
    if it["source"] == "x":
        return {"text": x_text(case, it)}
    out = cache_dir(case, "testo2") / f"{it['key']}.txt"
    if out.exists():
        return {"text": out.read_text(encoding="utf-8", errors="replace")}
    if it["source"] == "carving":
        text = carved_full_text(case, it["name"])
    else:
        local = None
        if (it.get("size") or 0) <= (50 << 20):
            try:
                local = cached_file(case, it)      # copia locale: il testo si estrae da lì
            except ValueError:
                local = None
        data = (Path(local).read_bytes()[:50 << 20] if local
                else image_read(case, it["start"], min(it["size"], 50 << 20)) if it["source"] == "ua"
                else fa.icat_read(case, it["part"], it["inode"], 50 << 20))
        if it["source"] == "ua" and data:
            text = (tr("Spazio non allocato: {path} — byte {start:,}–{v1:,} della copia ({size:,} byte). Stringhe "
                       "leggibili (ASCII e UTF-16)").format(path=it['path'], start=it['start'], v1=it['start'] + it['size'] - 1, size=it['size'])
                    + (tr(" dei primi 50 MB") if it["size"] > 50 << 20 else "") + ":\n\n").replace(",", ".") + \
                fa.show_text(data, "non_allocato.bin", cache_dir(case, "tmp"), FULL_TEXT_MAX, more_hint=False)
            try:
                out.write_text(text, encoding="utf-8")
            except OSError:
                pass
            return {"text": text}
        text = (fa.show_text(data, it["name"], cache_dir(case, "tmp"), FULL_TEXT_MAX,
                             more_hint=False) if data else tr("File vuoto o non recuperabile."))
    try:
        out.write_text(text, encoding="utf-8")
    except OSError:
        pass
    return {"text": text}


# ------------------------------------------------- ricerca globale (parole chiave e hash)
#
# Gli esiti di ogni ricerca vengono salvati in <caso>/ricerche.sqlite: si riaprono come
# schede e si lavora solo su quei file (anteprima, selezione, esportazione...).

SEARCH_STOP = threading.Event()
HASH_TOKEN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])")
WHERE_LABEL = {"name": N_("nome"), "path": N_("percorso"), "doc": N_("testo documento"), "meta": N_("metadati"),
               "raw": N_("contenuto"), "hash": "hash", "img": N_("byte grezzi della copia")}
HIT_COLS = ("id", "source", "part", "inode", "path", "name", "deleted", "size", "mtime", "wheres",
            "terms", "detail", "md5", "sha1", "sha256")


def search_db(case):
    con = sqlite3.connect(case.root / "ricerche.sqlite", timeout=30)
    con.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS searches(sid INTEGER PRIMARY KEY, title TEXT, created TEXT,
            params TEXT, total INTEGER, elapsed REAL, note TEXT);
        CREATE TABLE IF NOT EXISTS hits(id INTEGER PRIMARY KEY, sid INTEGER, source TEXT,
            part INTEGER, inode TEXT, path TEXT, name TEXT, deleted INTEGER, size INTEGER,
            mtime TEXT, wheres TEXT, terms TEXT, detail TEXT, md5 TEXT, sha1 TEXT, sha256 TEXT);
        CREATE INDEX IF NOT EXISTS idx_hits_sid ON hits(sid);
        CREATE TABLE IF NOT EXISTS bm_cat(cid INTEGER PRIMARY KEY, name TEXT UNIQUE, created TEXT,
            note TEXT, in_report INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS bm(id INTEGER PRIMARY KEY, cid INTEGER, source TEXT,
            part INTEGER, inode TEXT, path TEXT, name TEXT, deleted INTEGER, size INTEGER,
            mtime TEXT, md5 TEXT, sha1 TEXT, sha256 TEXT, note TEXT, ts TEXT);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_bm_u ON bm(cid, source, part, inode);
        CREATE INDEX IF NOT EXISTS idx_bm_cid ON bm(cid);
    """)
    return con


# ------------------------------------------------- segnalibri (categorie di file)
#
# Stanno in ricerche.sqlite accanto alle ricerche salvate; ogni categoria si apre come
# scheda (kind "hits" con cid) e riusa elenco, miniature, anteprima ed esportazioni.

BM_MAX = 200_000


def bm_categories(case):
    con = search_db(case)
    try:
        return [{"cid": c, "name": n, "created": cr, "note": nt or "", "in_report": bool(r), "n": k}
                for c, n, cr, nt, r, k in con.execute(
                    "SELECT c.cid, c.name, c.created, c.note, c.in_report, "
                    "(SELECT COUNT(*) FROM bm WHERE bm.cid = c.cid) FROM bm_cat c ORDER BY c.name COLLATE NOCASE")]
    finally:
        con.close()


def bm_add(case, b):
    """Aggiunge i file selezionati (cartelle comprese, con il loro contenuto) a una categoria,
    creata se non esiste."""
    name = " ".join(str(b.get("cat") or "").split())[:80]
    if not name:
        raise ValueError(tr("Indica il nome della categoria."))
    it = b.get("item")
    xs, others = {}, []
    if it and (it.get("source") in ("x", "mail", "art")):
        fs, carved, skipped = {}, [], 0
        if it["source"] == "x":
            xs = {int(it.get("id") or it.get("inode")): (it.get("path"), None)}
        else:
            others = [(it["source"], int(it.get("id") or it.get("inode")))]
    elif it:                                   # un solo file (riga o anteprima)
        if (it.get("source") or "fs") == "carving":
            fs, carved, skipped = {}, [Path(str(it.get("name") or "")).name], 0
        else:
            if not (fa.INODE_RE.fullmatch(str(it.get("inode") or "")) or fa.UA_RE.fullmatch(str(it.get("inode") or ""))):
                raise ValueError(tr("File non valido."))
            fs, carved, skipped = {(int(it["part"]), str(it["inode"]), str(it.get("path") or "")): 0}, [], 0
    else:
        kind, rows = selected_rows(case, b.get("sel") or {})
        fs, carved, skipped = export_targets(case, kind, rows)
        xs = x_targets(case, kind, rows)
        if kind in ("mail", "art"):
            others = [(kind, int(x["id"])) for x in rows]
        elif kind == "hits":
            others = [(x["source"], int(x["inode"])) for x in rows if x.get("source") == "mail"]
    if len(fs) + len(carved) + len(xs) + len(others) > BM_MAX:
        raise ValueError(tr("Troppi file ({v1:,}): restringi la selezione.").format(v1=len(fs) + len(carved)).replace(",", "."))
    note = str(b.get("note") or "").strip()[:2000]
    hashes = {}
    cs = fa.db_ro(case)
    try:
        if fa.table_exists(cs, "hashes") and fs:
            for part, inode, md5, sha1, sha256 in cs.execute("SELECT part, inode, md5, sha1, sha256 FROM hashes"):
                hashes[(part, inode)] = (md5, sha1, sha256)
        cinfo = {}
        if carved and fa.table_exists(cs, "carved"):
            for nm, size, sha in cs.execute("SELECT name, size, sha256 FROM carved"):
                cinfo[Path(nm.replace("\\", "/")).name] = (size, sha)
    finally:
        cs.close()
    nav = None
    try:
        nav = nav_db(case)
    except (ValueError, sqlite3.Error):
        pass
    con = search_db(case)
    now = fa.now()
    try:
        r = con.execute("SELECT cid FROM bm_cat WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
        if r:
            cid = r[0]
        else:
            cid = con.execute("INSERT INTO bm_cat(name, created, note, in_report) VALUES (?,?,?,1)",
                              (name, now, "")).lastrowid
        batch = []
        for (part, inode, path), deleted in fs.items():
            size = mtime = None
            if nav is not None:
                x = nav.execute("SELECT path, size, mtime, deleted FROM nav WHERE part=? AND inode=? "
                                "AND isdir=0 ORDER BY deleted LIMIT 1", (part, inode)).fetchone()
                if x:
                    path, size, mtime, deleted = x[0] if not path else path, x[1], x[2], x[3]
            path = (path or f"inode_{inode}").strip("/")
            sha_ua = None
            if fa.UA_RE.fullmatch(inode):           # tratto non allocato: dimensione e SHA-256 (fino a 256 MB)
                size = int(fa.UA_RE.fullmatch(inode).group(2))
                if size <= 256 << 20:
                    h = hashlib.sha256()
                    for c in item_stream(case, part, inode):
                        h.update(c)
                    sha_ua = h.hexdigest()
            batch.append((cid, "ua" if fa.UA_RE.fullmatch(inode) else "fs", part, inode, path, path.rsplit("/", 1)[-1],
                          deleted, size, mtime,
                          *(hashes.get((part, inode)) or (None, None, sha_ua)), note, now))
        for nm in carved:
            nm = Path(str(nm).replace("\\", "/")).name
            size, sha = cinfo.get(nm, (None, None))
            batch.append((cid, "carving", None, nm, f"[recuperato] {nm}", nm, 0, size, None,
                          None, None, sha, note, now))
        if xs or others:
            cx = fa.db_ro(case)
            try:
                for xid in xs:
                    r = cx.execute("SELECT path, name, deleted, size, mtime, md5, sha1, sha256 FROM xitems WHERE id=?",
                                   (xid,)).fetchone()
                    if r:
                        batch.append((cid, "x", None, str(xid), r[0], r[1], r[2] or 0, r[3], r[4], r[5], r[6], r[7], note, now))
                for src, oid in others:
                    if src == "mail":
                        r = cx.execute("SELECT subject, sender, date FROM mail WHERE id=?", (oid,)).fetchone()
                        if r:
                            batch.append((cid, "mail", None, str(oid), f"✉ {r[0]} — {r[1]}", r[0], 0, None, r[2],
                                          None, None, None, note, now))
                    else:
                        r = cx.execute("SELECT title, cat, ts FROM artifacts WHERE id=?", (oid,)).fetchone()
                        if r:
                            batch.append((cid, "art", None, str(oid), f"[{r[1]}] {r[0]}", r[0], 0, None, r[2],
                                          None, None, None, note, now))
            finally:
                cx.close()
        before = con.execute("SELECT COUNT(*) FROM bm WHERE cid=?", (cid,)).fetchone()[0]
        con.executemany("INSERT OR IGNORE INTO bm(cid, source, part, inode, path, name, deleted, size, "
                        "mtime, md5, sha1, sha256, note, ts) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
        con.commit()
        total = con.execute("SELECT COUNT(*) FROM bm WHERE cid=?", (cid,)).fetchone()[0]
    finally:
        con.close()
        if nav is not None:
            nav.close()
    case.log("preferiti", {"categoria": name, "aggiunti": total - before, "saltati": skipped})
    return {"cid": cid, "name": name, "added": total - before, "total": total, "skipped": skipped}


def bm_list(case, q, ids=None, limit=PAGE):
    con = search_db(case)
    off = int(q.get("offset", 0))
    w, a = ["bm.cid = ?"], [int(q.get("cid") or 0)]
    if ids is not None:
        w.append("bm.id IN (SELECT value FROM json_each(?))")
        a.append(json.dumps([int(x) for x in ids if str(x).isdigit()]))
    text = (q.get("q") or "").strip()
    if text:
        w.append("(bm.path LIKE ? ESCAPE '\\' OR bm.note LIKE ? ESCAPE '\\')"); a += [fa.like(text)] * 2
    if yes(q.get("deleted")):
        w.append("bm.deleted = 1")
    cf_apply(q, cf_hits(True), w, a)
    cond = " WHERE " + " AND ".join(w)
    try:
        if q.get("cfv"):
            cf_values(con, q, "bm", w, a)
        total = con.execute(f"SELECT COUNT(*) FROM bm{cond}", a).fetchone()[0]
        lim = f" LIMIT {int(limit)} OFFSET {off}" if limit else ""
        rows = con.execute("SELECT bm.id, bm.source, bm.part, bm.inode, bm.path, bm.name, bm.deleted, "
                           "bm.size, bm.mtime, c.name, '', bm.note, bm.md5, bm.sha1, bm.sha256 "
                           f"FROM bm JOIN bm_cat c ON c.cid = bm.cid{cond} "
                           f"ORDER BY {cf_order(q, 'bm.path COLLATE NOCASE')}{lim}", a).fetchall()
    finally:
        con.close()
    return {"kind": "hits", "total": total, "offset": off, "page": PAGE,
            "rows": [dict(zip(HIT_COLS, r)) for r in rows]}


def bm_remove(case, b):
    kind, rows = selected_rows(case, b)
    ids = [int(x["id"]) for x in rows]
    con = search_db(case)
    try:
        con.executemany("DELETE FROM bm WHERE id=?", [(i,) for i in ids])
        con.commit()
    finally:
        con.close()
    case.log("preferiti_rimossi", {"n": len(ids)})
    return {"removed": len(ids)}


def bm_cat_update(case, b):
    cid = int(b.get("cid") or 0)
    con = search_db(case)
    try:
        if b.get("name") is not None:
            name = " ".join(str(b["name"]).split())[:80]
            if not name:
                raise ValueError(tr("Il nome non può essere vuoto."))
            if con.execute("SELECT 1 FROM bm_cat WHERE name = ? COLLATE NOCASE AND cid <> ?",
                           (name, cid)).fetchone():
                raise ValueError(tr("Esiste già una categoria con questo nome."))
            con.execute("UPDATE bm_cat SET name=? WHERE cid=?", (name, cid))
        if b.get("note") is not None:
            con.execute("UPDATE bm_cat SET note=? WHERE cid=?", (str(b["note"])[:4000], cid))
        if b.get("in_report") is not None:
            con.execute("UPDATE bm_cat SET in_report=? WHERE cid=?", (1 if b["in_report"] else 0, cid))
        con.commit()
    finally:
        con.close()
    case.log("preferiti_categoria", {k: v for k, v in b.items()})
    return {"ok": True}


def bm_cat_delete(case, cid):
    con = search_db(case)
    try:
        name = (con.execute("SELECT name FROM bm_cat WHERE cid=?", (int(cid),)).fetchone() or [""])[0]
        con.execute("DELETE FROM bm WHERE cid=?", (int(cid),))
        con.execute("DELETE FROM bm_cat WHERE cid=?", (int(cid),))
        con.commit()
    finally:
        con.close()
    case.log("preferiti_categoria_eliminata", {"cid": int(cid), "nome": name})
    return {"ok": True}


# ------------------------------------------------- immagine, tracce e file di plaso
#
# Le tracce di bulk_extractor hanno un offset nell'immagine; gli eventi di plaso un
# percorso (display_name). Qui si risale al file del file system per anteprima,
# esadecimale, albero ed Esplora file; l'immagine stessa si legge in esadecimale.

IMG_SIZE = {}
BSIZE = {}
IMG_SEARCH_WINDOW = 64 << 20


def image_ident(case):
    img = case.image
    if img not in IMG_SIZE:
        size = None
        cp = subprocess.run(["img_stat", img], capture_output=True, stdin=subprocess.DEVNULL)
        t = fa.dec(cp.stdout)
        m = re.search(r"Size in bytes:\s*(\d+)", t) or re.search(r"Size[^\n:]*:\s*(\d+)", t)
        if m:
            size = int(m.group(1))
        if not size and Path(img).exists():
            size = sum(p.stat().st_size for p in fa.image_segments(img))
        IMG_SIZE[img] = size or 0
    name = Path(img).name
    return {"source": "image", "part": None, "inode": None, "path": tr("Copia forense {name}").format(name=name),
            "name": name, "key": "image", "ext": "", "size": IMG_SIZE[img], "deleted": 0}


def image_read(case, off, n):
    """Byte della copia forense dall'offset `off` (raw: lettura diretta; E01: img_cat)."""
    img = case.image
    if not Path(img).exists():
        raise ValueError(tr("La copia forense non è raggiungibile: collega il disco che la contiene."))
    if not fa.is_e01(img):
        with open(img, "rb") as fh:
            fh.seek(off)
            return fh.read(n)
    s, e = off // 512, (off + n - 1) // 512
    cp = subprocess.run(["img_cat", "-s", str(s), "-e", str(e), img], capture_output=True,
                        stdin=subprocess.DEVNULL, timeout=120)
    return cp.stdout[off - s * 512:][:n]


def image_chunks(case, start, size=4 << 20):
    """Per la ricerca nell'esadecimale dell'immagine: solo una finestra dall'offset di partenza."""
    pos, end = start, start + IMG_SEARCH_WINDOW
    while pos < end:
        c = image_read(case, pos, min(size, end - pos))
        if not c:
            break
        yield pos, c
        pos += len(c)


def _fs_block_size(case, part):
    key = (case.image, part)
    if key not in BSIZE:
        t = fa.dec(fa.sh(case, ["fsstat", "-o", str(part), case.image], timeout=600).stdout)
        fs = next((p.get("fs") or "" for p in case.meta.get("partitions", []) if p["offset"] == part), "")
        keys = (["Sector Size"] if "FAT" in fs.upper() else []) + ["Block Size", "Cluster Size", "Sector Size"]
        BSIZE[key] = next((int(m.group(1)) for k in keys for m in [re.search(k + r":\s*(\d+)", t)] if m), 512)
    return BSIZE[key]


def _istat_blocks(text):
    """Blocchi del contenuto dall'output di istat (ext, FAT, NTFS $DATA non residente, HFS)."""
    out, on = [], False
    for line in text.splitlines():
        s = line.strip()
        if re.match(r"(Direct Blocks|Sectors|Blocks|Data Fork Blocks):", s) or \
                re.match(r"Type: \$DATA \(128-\d+\)\s+Name: N/A\s+Non-Resident", s):
            if out:
                break
            on = True
            continue
        if on:
            if s and re.fullmatch(r"[\d\s]+", s):
                out += [int(x) for x in s.split()]
            elif out:
                break
    return out


def trace_locate(case, b):
    """Il file che contiene un byte dell'immagine (offset di una traccia), con la posizione
    del byte dentro il file; altrimenti dove si trova (spazio libero, fuori partizione)."""
    m = re.match(r"\d+", str(b.get("offset") or "").strip())
    if not m:
        raise ValueError(tr("Offset non valido."))
    off = int(m.group())
    for p in case.meta.get("partitions", []):
        start = (p["apfs"]["real_offset"] if p.get("apfs") else p["offset"]) * 512
        end = start + p["length_sectors"] * 512 if p.get("length_sectors") else None
        if off < start or (end is not None and off >= end):
            continue
        if p.get("apfs"):
            return {"found": False, "offset": off,
                    "message": tr("Byte {off}: dentro il contenitore APFS (volume «{v1}»): la localizzazione del file da un "
                                  "byte non è supportata per APFS.").format(off=off, v1=p['apfs'].get('name'))}
        if not p.get("readable"):
            return {"found": False, "offset": off,
                    "message": tr("Byte {off}: partizione offset {offset} non leggibile da TSK.").format(off=off, offset=p['offset'])}
        bs = _fs_block_size(case, p["offset"])
        blk = (off - start) // bs
        cp = fa.sh(case, ["ifind", "-o", str(p["offset"]), "-d", str(blk), case.image], timeout=600)
        ino = fa.dec(cp.stdout).strip()
        where = tr("Byte {off}: partizione offset {offset}, blocco {blk} (da {bs} byte)").format(off=off, offset=p['offset'], blk=blk, bs=bs)
        if cp.returncode != 0 or not fa.INODE_RE.fullmatch(ino):
            return {"found": False, "offset": off,
                    "message": where + tr(": nessun file lo usa (spazio non allocato o metadati).")}
        it = file_ident(case, {"part": p["offset"], "inode": ino})
        fo = None
        if b.get("no_istat"):
            return {"found": True, "offset": off, "part": p["offset"], "inode": ino, "path": it["path"],
                    "deleted": it["deleted"], "file_offset": None, "message": where + tr(": inode {ino} {path}").format(ino=ino, path=it['path'])}
        try:
            blocks = _istat_blocks(fa.dec(fa.sh(case, ["istat", *fa.tsk_tz(case), "-o", str(p["offset"]), case.image, ino],
                                                timeout=600).stdout))
            if blk in blocks:
                fo = blocks.index(blk) * bs + (off - start) % bs
        except (subprocess.SubprocessError, OSError):
            pass
        return {"found": True, "offset": off, "part": p["offset"], "inode": ino, "path": it["path"],
                "deleted": it["deleted"], "file_offset": fo,
                "message": where + tr(": inode {ino} {path}").format(ino=ino, path=it['path']) + (tr(" (CANCELLATO)") if it["deleted"] else "")
                + (tr(", byte {fo} del file").format(fo=fo) if fo is not None else "")}
    return {"found": False, "offset": off, "message": tr("Byte {off}: fuori dalle partizioni.").format(off=off)}


def trace_paths(case, b):
    """Percorso del file che contiene ciascun offset (righe visibili delle evidenze di interesse).
    I risultati restano in cache nel caso, così ifind si esegue una volta sola per offset."""
    from concurrent.futures import ThreadPoolExecutor
    offs = []
    for o in (b.get("offsets") or [])[:400]:
        m = re.match(r"\d+", str(o))
        if m and m.group() not in offs:
            offs.append(m.group())
    db = sqlite3.connect(cache_dir(case, "evidenze") / "percorsi.sqlite", timeout=30)
    try:
        db.execute("CREATE TABLE IF NOT EXISTS pos(offset TEXT PRIMARY KEY, data TEXT)")
        out = {}
        for o in offs:
            r = db.execute("SELECT data FROM pos WHERE offset=?", (o,)).fetchone()
            if r:
                out[o] = json.loads(r[0])
        todo = [o for o in offs if o not in out]

        def one(o):
            try:
                x = trace_locate(case, {"offset": o, "no_istat": True})
            except Exception as e:      # noqa: BLE001 - una riga non deve fermare le altre
                return o, {"found": False, "message": str(e), "temp": True}
            return o, {k: x.get(k) for k in ("found", "part", "inode", "path", "deleted", "message")}
        if todo:
            with ThreadPoolExecutor(max_workers=4) as ex:
                for o, d in ex.map(one, todo):
                    out[o] = d
                    if not d.get("temp"):
                        db.execute("INSERT OR REPLACE INTO pos VALUES (?,?)", (o, json.dumps(d)))
            db.commit()
    finally:
        db.close()
    return {"paths": out}


def plaso_fs_path(p):
    """display_name di plaso (TSK:/..., NTFS:\\..., OS:C:\\...) -> percorso nel file system."""
    p = (p or "").strip()
    p = re.sub(r"^(?:[A-Za-z][\w\-]*:)+(?=[/\\])", "", p)
    p = re.sub(r"^(?:[A-Za-z][\w\-]*:)+[A-Za-z]:(?=[/\\])", "", p)
    p = re.sub(r"^[A-Za-z]:(?=[/\\])", "", p)
    return clean_fs_path(p)


def tl_resolve(case, b):
    """Il file del file system a cui si riferisce un evento di plaso (dal suo percorso)."""
    p = plaso_fs_path(b.get("path"))
    if not p:
        raise ValueError(tr("L'evento non indica un file."))
    con = nav_db(case)
    try:
        sql = ("SELECT part, inode, path, deleted FROM nav WHERE isdir=0 AND inode IS NOT NULL "
               "AND inode <> '' AND ")
        r = con.execute(sql + "path = ? ORDER BY deleted LIMIT 1", (p,)).fetchone() or \
            con.execute(sql + "lower(path) = lower(?) ORDER BY deleted LIMIT 1", (p,)).fetchone() or \
            con.execute(sql + "path LIKE ? ESCAPE '\\' ORDER BY deleted, length(path) LIMIT 1",
                        ("%/" + p.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_"),)).fetchone()
    finally:
        con.close()
    if not r:
        raise ValueError(tr("Il file «{p}» non è nell'albero del file system della copia.").format(p=p))
    return {"part": r[0], "inode": str(r[1]), "path": r[2], "deleted": r[3]}


def export_reveal(case, b):
    """Esporta il file (se non già esportato) e lo mostra in Esplora file / Finder."""
    o, i = int(b["part"]), str(b["inode"])
    if not fa.INODE_RE.fullmatch(i):
        raise ValueError(tr("inode non valido."))
    msg = SES.case_tools["export_file"](o, i)
    found = sorted(case.export_dir.glob(f"p{o}_i{i}_*"))
    if found:
        reveal(found[0])
    return {"message": msg}


def reveal_trace(case, kind):
    """Mostra il file di bulk_extractor con le tracce di quel tipo."""
    c = case.meta.get("carving") or {}
    d = Path(c.get("dir") or "carving")
    d = d if d.is_absolute() else case.root / d
    f = d / "bulk_extractor" / f"{re.sub(r'[^\w]', '', kind or '')}.txt"
    target = f if f.exists() else d / "bulk_extractor"
    if not target.exists():
        raise ValueError(tr("File di bulk_extractor non trovato nella cartella del caso."))
    reveal(target)
    return {"ok": True}


DOC_EXT_RE = re.compile(r"\.([A-Za-z0-9_+\-]{1,10})$")


def doc_ext_counts(con, limit=60):
    """Documenti indicizzati divisi per estensione: [(estensione, quanti)], dal più numeroso.
    «~posta» = messaggi di posta (non hanno un file), «~senza» = nome senza estensione."""
    cnt = Counter()
    try:
        for path, source in con.execute("SELECT path, source FROM doc_text"):
            if source == "posta":
                cnt["~posta"] += 1
                continue
            m = DOC_EXT_RE.search(re.split(r"[/\\]| › ", path or "")[-1])
            cnt[m.group(1).lower() if m else "~senza"] += 1
    except sqlite3.Error:
        return []
    return cnt.most_common(limit)


def res_tree(case):
    """Voci e sottovoci per la vista ad albero dei Risultati."""
    con = fa.db_ro(case)
    try:
        has = lambda t: fa.table_exists(con, t)
        q = lambda sql: con.execute(sql).fetchall()
        out = {"tl": dict(q("SELECT origin, COUNT(*) FROM events GROUP BY 1")),
               "plaso": q("SELECT source, COUNT(*) FROM events WHERE origin='plaso' GROUP BY 1 "
                          "ORDER BY 2 DESC LIMIT 40"),
               "deleted": con.execute("SELECT COUNT(*) FROM files WHERE deleted=1").fetchone()[0],
               "trace": q("SELECT kind, COUNT(*) FROM features GROUP BY 1 ORDER BY 2 DESC") if has("features") else [],
               "carved": q("SELECT type, COUNT(*) FROM carved GROUP BY 1 ORDER BY 2 DESC LIMIT 40") if has("carved") else [],
               "doc": q("SELECT kind, COUNT(*) FROM doc_text GROUP BY 1 ORDER BY 2 DESC LIMIT 20") if has("doc_text") else [],
               "docext": doc_ext_counts(con) if has("doc_text") else [],
               "gps": con.execute("SELECT COUNT(*) FROM meta WHERE lat IS NOT NULL").fetchone()[0] if has("meta") else 0}
    finally:
        con.close()
    out["searches"] = [{"sid": s["sid"], "title": s["title"], "total": s["total"]} for s in search_list(case)]
    out.update(ext_tree(case))
    out["bm"] = bm_categories(case) if (case.root / "ricerche.sqlite").exists() else []
    return out


# ------------------------------------------------- report in PDF e Word
#
# Si parte dal report.md generato da forense_agent (stesso contenuto) e lo si scrive
# come PDF (A4, font standard) e come documento Word .docx, senza programmi esterni.

def md_blocks(text):
    """Il markdown del report in blocchi: ("h", livello, testo), ("p", testo),
    ("li", livello, testo), ("table", righe)."""
    out, para, tbl = [], [], None

    def flush():
        nonlocal para, tbl
        if para:
            out.append(("p", " ".join(para)))
            para = []
        if tbl:
            out.append(("table", tbl))
            tbl = None
    for raw in text.splitlines():
        line = raw.rstrip()
        s = line.strip()
        if s.startswith("|"):
            if para:
                out.append(("p", " ".join(para)))
                para = []
            if re.fullmatch(r"\|[\s|:\-]+\|?", s):
                continue
            cells = re.split(r"(?<!\\)\|", s.strip("|"))
            (tbl := tbl if tbl is not None else []).append([c.strip().replace("\\|", "|") for c in cells])
            continue
        if tbl:
            out.append(("table", tbl))
            tbl = None
        if not s:
            flush()
            continue
        m = re.match(r"(#{1,6})\s+(.*)", s)
        if m:
            flush()
            out.append(("h", len(m.group(1)), m.group(2)))
            continue
        m = re.match(r"(\s*)[-*]\s+(.*)", line)
        if m:
            flush()
            out.append(("li", len(m.group(1)) // 2, m.group(2)))
            continue
        para.append(s)
    flush()
    return out


def md_runs(text):
    """Testo con **grassetto** e `codice` -> [(testo, stile)] con stile "", "b" o "c"."""
    runs = []
    for part in re.split(r"(\*\*[^*]+\*\*|`[^`]+`)", text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**") and len(part) > 4:
            runs.append((part[2:-2], "b"))
        elif part.startswith("`") and part.endswith("`") and len(part) > 2:
            runs.append((part[1:-1], "c"))
        else:
            runs.append((part, ""))
    return runs


# larghezze (millesimi di em) di Helvetica e Helvetica-Bold, caratteri 32-126
_HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278] + [556] * 10 + \
    [278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833,
     722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556,
     556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556,
     500, 722, 500, 500, 500, 334, 260, 334, 584]
_HELVB = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278] + [556] * 10 + \
    [333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833,
     722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556,
     611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611,
     556, 778, 556, 556, 500, 389, 280, 389, 584]


def _pdf_char(ch):
    """Carattere rappresentabile in WinAnsi (cp1252), altrimenti un sostituto leggibile."""
    try:
        ch.encode("cp1252")
        return ch
    except UnicodeEncodeError:
        import unicodedata
        base = unicodedata.normalize("NFKD", ch).encode("ascii", "ignore").decode()
        return base or {"⭐": "*", "✓": "v", "→": "->", "←": "<-"}.get(ch, "?")


def _pdf_w(text, style, size):
    if style == "c":
        return len(text) * 600 * size / 1000
    tab = _HELVB if style == "b" else _HELV
    w = 0
    for ch in text:
        o = ord(ch)
        if 32 <= o <= 126:
            w += tab[o - 32]
        else:
            import unicodedata
            b = unicodedata.normalize("NFKD", ch)[:1]
            w += tab[ord(b) - 32] if b and 32 <= ord(b) <= 126 else 556
    return w * size / 1000


class PdfDoc:
    W, H, M = 595.28, 841.89, 50

    def __init__(self, title):
        self.title = title
        self.pages, self.ops, self.y = [], None, 0
        self.new_page()

    def new_page(self):
        self.ops = []
        self.pages.append(self.ops)
        self.y = self.H - self.M

    def need(self, h):
        if self.y - h < self.M + 20:
            self.new_page()

    @staticmethod
    def _esc(s):
        s = "".join(_pdf_char(c) for c in s)
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def text(self, x, y, s, style, size, gray=0):
        f = {"b": "F2", "c": "F3"}.get(style, "F1")
        self.ops.append(f"BT {gray:.2f} g /{f} {size:.1f} Tf {x:.2f} {y:.2f} Td ({self._esc(s)}) Tj ET")

    def wrap(self, runs, width, size):
        """Righe di [(x, testo, stile)] che stanno in `width`, spezzando anche le parole lunghe."""
        lines, cur, x = [], [], 0.0
        toks = []
        for t, st in runs:
            for w in re.findall(r"\S+\s*|\s+", t.replace("\n", " ")):
                toks.append((w, st))
        for w, st in toks:
            ww = _pdf_w(w, st, size)
            if x + _pdf_w(w.rstrip(), st, size) > width and cur:
                lines.append(cur)
                cur, x = [], 0.0
                if not w.strip():
                    continue
            while _pdf_w(w.rstrip(), st, size) > width:      # parola più lunga della riga
                k = len(w)
                while k > 1 and _pdf_w(w[:k], st, size) > width - x:
                    k -= 1
                cur.append((x, w[:k], st))
                lines.append(cur)
                cur, x, w = [], 0.0, w[k:]
            ww = _pdf_w(w, st, size)
            cur.append((x, w, st))
            x += ww
        if cur:
            lines.append(cur)
        return lines or [[]]

    def para(self, runs, size=10, indent=0, bullet=None, before=0, after=4):
        width = self.W - 2 * self.M - indent
        lines = self.wrap(runs, width, size)
        lead = size * 1.32
        self.y -= before
        for n, ln in enumerate(lines):
            self.need(lead)
            self.y -= lead
            if bullet and n == 0:
                self.text(self.M + indent - 10, self.y, bullet, "", size)
            for x, t, st in ln:
                self.text(self.M + indent + x, self.y, t, st, size)
        self.y -= after

    def table(self, rows):
        if not rows:
            return
        nc = max(len(r) for r in rows)
        rows = [r + [""] * (nc - len(r)) for r in rows]
        W = self.W - 2 * self.M
        size = 7 if nc > 5 else 8.5
        pad = 3
        nat = [min(max(_pdf_w(re.sub(r"[*`]", "", r[c]), "b" if i == 0 else "", size) for i, r in enumerate(rows)) + 2 * pad, 260)
               for c in range(nc)]
        nat = [max(n, 28, min(_pdf_w(re.sub(r"[*`]", "", rows[0][c]), "b", size) + 2 * pad + 1, 80))
               for c, n in enumerate(nat)]
        tot = sum(nat)
        cw = [n * W / tot for n in nat]
        lead = size * 1.25

        def cells(r, head):
            return [self.wrap([(t, "b" if head else st) for t, st in md_runs(c)], cw[i] - 2 * pad, size)
                    for i, c in enumerate(r)]

        def draw(r, head):
            ls = cells(r, head)
            h = max(len(x) for x in ls) * lead + 2 * pad
            if self.y - h < self.M + 20:
                self.new_page()
                if not head:
                    draw(rows[0], True)
            top, x = self.y, self.M
            if head:
                self.ops.append(f"0.92 g {self.M:.2f} {top - h:.2f} {W:.2f} {h:.2f} re f 0 g")
            for i, ln in enumerate(ls):
                yy = top - pad
                for line in ln:
                    yy -= lead
                    for dx, t, st in line:
                        self.text(x + pad + dx, yy + 2, t, st, size)
                self.ops.append(f"0.6 G 0.4 w {x:.2f} {top - h:.2f} {cw[i]:.2f} {h:.2f} re S")
                x += cw[i]
            self.y = top - h
        draw(rows[0], True)
        for r in rows[1:]:
            draw(r, False)
        self.y -= 8

    def render(self):
        import zlib
        objs = []

        def add(b):
            objs.append(b if isinstance(b, bytes) else b.encode("cp1252", "replace"))
            return len(objs)
        cat = add("")      # segnaposto
        pages_id = add("")
        fonts = [add(f"<< /Type /Font /Subtype /Type1 /BaseFont /{n} /Encoding /WinAnsiEncoding >>")
                 for n in ("Helvetica", "Helvetica-Bold", "Courier")]
        res = f"<< /Font << /F1 {fonts[0]} 0 R /F2 {fonts[1]} 0 R /F3 {fonts[2]} 0 R >> >>"
        kids, n = [], len(self.pages)
        for i, ops in enumerate(self.pages, 1):
            foot = (f"BT 0.45 g /F1 7.5 Tf {self.M:.2f} 28 Td ({self._esc(self.title)}) Tj ET "
                    f"BT 0.45 g /F1 7.5 Tf {self.W - self.M - 60:.2f} 28 Td (Pagina {i} di {n}) Tj ET")
            data = zlib.compress(("\n".join(ops) + "\n" + foot).encode("cp1252", "replace"))
            cs = add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(data) + data + b"\nendstream")
            kids.append(add(f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {self.W} {self.H}] "
                            f"/Resources {res} /Contents {cs} 0 R >>"))
        objs[cat - 1] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode()
        objs[pages_id - 1] = (f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] "
                              f"/Count {len(kids)} >>").encode()
        info = add(f"<< /Title ({self._esc(self.title)}) /Producer ({fa.APP_NAME} {fa.APP_VERSION}) >>")
        buf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offs = []
        for i, o in enumerate(objs, 1):
            offs.append(len(buf))
            buf += b"%d 0 obj\n" % i + o + b"\nendobj\n"
        x = len(buf)
        buf += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
        buf += b"".join(b"%010d 00000 n \n" % o for o in offs)
        buf += b"trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
            len(objs) + 1, cat, info, x)
        return bytes(buf)


def report_pdf(md_text, title):
    d = PdfDoc(title)
    sizes = {1: 18, 2: 14, 3: 12}
    for b in md_blocks(md_text):
        if b[0] == "h":
            sz = sizes.get(b[1], 11)
            d.need(sz * 3)
            d.para([(b[2], "b")], size=sz, before=sz * 0.6, after=sz * 0.35)
            if b[1] <= 2:
                d.ops.append(f"0.7 G 0.5 w {d.M:.2f} {d.y + 2:.2f} m {d.W - d.M:.2f} {d.y + 2:.2f} l S")
                d.y -= 4
        elif b[0] == "p":
            d.para(md_runs(b[1]))
        elif b[0] == "li":
            d.para(md_runs(b[2]), indent=14 + 14 * b[1], bullet="•" if not b[1] else "-", after=2)
        elif b[0] == "table":
            d.table(b[1])
    return d.render()


def _x(s):
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(s))
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _docx_runs(runs, size=None, bold=False):
    out = []
    for t, st in runs:
        rpr = ("<w:b/>" if bold or st == "b" else "") + \
              ('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>' if st == "c" else "") + \
              (f'<w:sz w:val="{size}"/><w:szCs w:val="{size}"/>' if size else "")
        out.append(f'<w:r>{f"<w:rPr>{rpr}</w:rPr>" if rpr else ""}<w:t xml:space="preserve">{_x(t)}</w:t></w:r>')
    return "".join(out)


def report_docx(md_text, title):
    import zipfile, io
    body = []
    for b in md_blocks(md_text):
        if b[0] == "h":
            st = "Title" if b[1] == 1 else f"Heading{min(b[1] - 1, 3)}"
            body.append(f'<w:p><w:pPr><w:pStyle w:val="{st}"/></w:pPr>{_docx_runs([(b[2], "")])}</w:p>')
        elif b[0] == "p":
            body.append(f"<w:p>{_docx_runs(md_runs(b[1]))}</w:p>")
        elif b[0] == "li":
            ind = 360 + 360 * b[1]
            body.append(f'<w:p><w:pPr><w:spacing w:after="40"/><w:ind w:left="{ind}" w:hanging="240"/></w:pPr>'
                        f'{_docx_runs([("•" if not b[1] else "–", "")])}<w:r><w:tab/></w:r>{_docx_runs(md_runs(b[2]))}</w:p>')
        elif b[0] == "table":
            rows = b[1]
            nc = max(len(r) for r in rows)
            sz = 14 if nc > 5 else 17
            trs = []
            for i, r in enumerate(rows):
                r = r + [""] * (nc - len(r))
                shd = '<w:shd w:val="clear" w:color="auto" w:fill="E7E9EE"/>' if i == 0 else ""
                tcs = "".join(
                    f'<w:tc><w:tcPr>{shd}</w:tcPr>'
                    f'<w:p><w:pPr><w:spacing w:after="0"/></w:pPr>{_docx_runs(md_runs(c), sz, bold=(i == 0))}</w:p></w:tc>'
                    for c in r)
                trs.append(f'<w:tr>{"<w:trPr><w:tblHeader/></w:trPr>" if i == 0 else ""}{tcs}</w:tr>')
            body.append('<w:tbl><w:tblPr><w:tblStyle w:val="Griglia"/><w:tblW w:w="5000" w:type="pct"/>'
                        '<w:tblLayout w:type="autofit"/></w:tblPr>'
                        f'<w:tblGrid>{"".join("<w:gridCol/>" for _ in range(nc))}</w:tblGrid>{"".join(trs)}</w:tbl>'
                        '<w:p><w:pPr><w:spacing w:after="60"/></w:pPr></w:p>')
    ns = ('xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"')
    footer = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr {ns}><w:p><w:pPr><w:jc w:val="center"/></w:pPr>'
              f'<w:r><w:rPr><w:sz w:val="15"/><w:color w:val="777777"/></w:rPr><w:t xml:space="preserve">{_x(title)} · pagina </w:t></w:r>'
              '<w:r><w:rPr><w:sz w:val="15"/><w:color w:val="777777"/></w:rPr><w:fldChar w:fldCharType="begin"/></w:r>'
              '<w:r><w:rPr><w:sz w:val="15"/><w:color w:val="777777"/></w:rPr><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r>'
              '<w:r><w:rPr><w:sz w:val="15"/><w:color w:val="777777"/></w:rPr><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>')
    doc = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {ns}><w:body>{"".join(body)}'
           '<w:sectPr><w:footerReference w:type="default" r:id="rIdF"/><w:pgSz w:w="11906" w:h="16838"/>'
           '<w:pgMar w:top="1134" w:right="1021" w:bottom="1134" w:left="1021" w:header="567" w:footer="567" w:gutter="0"/>'
           '</w:sectPr></w:body></w:document>')
    hd = lambda i, sz, sp: (f'<w:style w:type="paragraph" w:styleId="Heading{i}"><w:name w:val="heading {i}"/>'
                            '<w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>'
                            f'<w:pPr><w:keepNext/><w:spacing w:before="{sp}" w:after="80"/><w:outlineLvl w:val="{i - 1}"/></w:pPr>'
                            f'<w:rPr><w:b/><w:color w:val="1F3A5F"/><w:sz w:val="{sz}"/><w:szCs w:val="{sz}"/></w:rPr></w:style>')
    styles = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles {ns}>'
              '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri" w:eastAsia="Calibri"/>'
              '<w:sz w:val="20"/><w:szCs w:val="20"/><w:lang w:val="it-IT"/></w:rPr></w:rPrDefault>'
              '<w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>'
              '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>'
              '<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:qFormat/>'
              '<w:pPr><w:spacing w:after="160"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:color w:val="1F3A5F"/><w:sz w:val="36"/><w:szCs w:val="36"/></w:rPr></w:style>'
              + hd(1, 28, 280) + hd(2, 24, 200) + hd(3, 21, 160) +
              '<w:style w:type="table" w:styleId="Griglia"><w:name w:val="Griglia"/><w:tblPr><w:tblBorders>'
              + "".join(f'<w:{s} w:val="single" w:sz="4" w:space="0" w:color="A0A4AA"/>' for s in ("top", "left", "bottom", "right", "insideH", "insideV"))
              + '</w:tblBorders><w:tblCellMar><w:left w:w="60" w:type="dxa"/><w:right w:w="60" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>'
              '</w:styles>')
    ctypes = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
              '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
              '<Default Extension="xml" ContentType="application/xml"/>'
              '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
              '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
              '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
              '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
              '</Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '</Relationships>')
    drels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
             '<Relationship Id="rIdS" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
             '<Relationship Id="rIdF" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>'
             '</Relationships>')
    core = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f'<dc:title>{_x(title)}</dc:title><dc:creator>{_x(fa.APP_NAME)}</dc:creator></cp:coreProperties>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in (("[Content_Types].xml", ctypes), ("_rels/.rels", rels),
                           ("word/document.xml", doc), ("word/styles.xml", styles),
                           ("word/footer1.xml", footer), ("word/_rels/document.xml.rels", drels),
                           ("docProps/core.xml", core)):
            z.writestr(name, data)
    return buf.getvalue()


def report_export(case, fmt, tz=None):
    """report.md aggiornato e la sua versione in PDF o Word nella cartella del caso
    (tz="rome": orari in ora italiana; report.md resta in UTC)."""
    import hashlib
    if fmt not in ("pdf", "docx"):
        raise ValueError(tr("Formato non previsto."))
    md = fa.write_report(case).read_text(encoding="utf-8")
    zone = tz_zone(case, tz)
    if zone != "UTC":
        md, n_conv, n_skip = md_to_zone_ex(md, zone)
        first, _, rest = md.partition("\n")
        sigle = (tr("ciascuno con la sigla CET (UTC+1) o CEST (UTC+2, ora legale)") if zone == "Europe/Rome"
                 else tr("ciascuno con lo scostamento da UTC (UTC+HH:MM)"))
        lab = tz_label(case, tz)
        md = (first + tr("\n\n- Orari: **{lab}**").format(lab=lab) + ("" if zone in lab else f" ({zone})") + tr(", {sigle}; nel database del caso e nel registro restano in UTC. Orari convertiti: "
                                                                                             "{n_conv}.").format(sigle=sigle, n_conv=n_conv)
              + (tr(" {n_skip} orari compaiono in nomi di file, percorsi o testo non riconoscibile e sono "
                    "rimasti invariati (UTC).").format(n_skip=n_skip) if n_skip else "")
              + tr(" Le date di FAT/exFAT sono ora locale del dispositivo, già riportata a UTC col fuso indicato "
                "nei dati del caso.") + rest)
    title = tr("Report di analisi forense – {name}").format(name=case.root.name)
    data = report_pdf(md, title) if fmt == "pdf" else report_docx(md, title)
    p = case.root / f"report.{fmt}"
    if p.exists():
        p.chmod(0o644)
    p.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    case.log("report_" + fmt, {"file": str(p), "sha256": sha, "fuso": zone})
    return {"rel": p.name, "path": str(p), "sha256": sha, "size": len(data)}


import html as html_mod

# ------------------------------------------------- analisi estese: risultati, anteprime, azioni
#
# Archivi e posta, artefatti di sistema, copie shadow e anomalie stanno in caso.sqlite
# (tabelle di forense_estesa). I file estratti hanno "source" = "x" e id numerico.

EXT_KINDS = ("art", "mail", "arch", "vss", "anom")
X_COLS = ("id", "kind", "part", "inode", "src_path", "parent", "mail", "inner", "path", "name", "size",
          "mtime", "encrypted", "deleted", "relpath", "md5", "sha1", "sha256", "note", "store")


def ext_counts(case, con):
    est = case.meta.get("estese") or {}
    has = lambda t: fa.table_exists(con, t)
    one = lambda sql: con.execute(sql).fetchone()[0]
    return {
        "art": one("SELECT COUNT(*) FROM artifacts") if has("artifacts") and "artefatti" in est else None,
        "mail": one("SELECT COUNT(*) FROM mail") if has("mail") and "archivi" in est else None,
        "arch": one("SELECT COUNT(*) FROM xitems WHERE kind IN ('archivio','allegato','miniatura')") if has("xitems") and (
            "archivi" in est or "artefatti" in est) else None,
        "vss": one("SELECT COUNT(*) FROM xitems WHERE kind='vss'") if has("xitems") and "vss" in est else None,
        "anom": one("SELECT COUNT(*) FROM anomalies") if has("anomalies") and (
            "anomalie" in est or case.meta.get("liste_hash") or case.meta.get("volumi_cifrati")) else None,
    }


def ext_results(case, q, ids=None, limit=PAGE):
    kind, text, off = q.get("kind"), (q.get("q") or "").strip(), int(q.get("offset", 0))
    con = fa.db_ro(case)
    w, a = [], []
    L = fa.like
    lim = f" LIMIT {int(limit)} OFFSET {int(off)}" if limit else ""
    if ids is not None:
        w.append("id IN (SELECT value FROM json_each(?))")
        a.append(json.dumps([int(x) for x in ids if str(x).lstrip("-").isdigit()]))
    try:
        if kind == "art":
            if not fa.table_exists(con, "artifacts"):
                raise ValueError(tr("Artefatti non ancora estratti."))
            if q.get("cat"):
                w.append("cat = ?"); a.append(q["cat"])
            if text:
                w.append("(title LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\' OR user LIKE ? ESCAPE '\\' "
                         "OR src_path LIKE ? ESCAPE '\\')"); a += [L(text)] * 4
            if q.get("start"):
                w.append("ts >= ?"); a.append(q["start"])
            if q.get("end"):
                w.append("ts <= ?"); a.append(q["end"] + ("T23:59:59" if "T" not in q["end"] else ""))
            cf_apply(q, {"ts": ("ts", "d"), "cat": ("cat", "t"), "title": ("(title || ' ' || IFNULL(user,''))", "t"),
                         "detail": ("detail", "t"), "src_path": ("src_path", "t")}, w, a)
            cols = ("id", "cat", "ts", "title", "detail", "user", "src_path", "part", "inode", "data")
            table, order = "artifacts", "ts IS NULL, ts DESC, id"
        elif kind == "mail":
            if not fa.table_exists(con, "mail"):
                raise ValueError(tr("Posta non ancora analizzata."))
            if text:
                w.append("(subject LIKE ? ESCAPE '\\' OR sender LIKE ? ESCAPE '\\' OR recipients LIKE ? ESCAPE '\\' "
                         "OR body LIKE ? ESCAPE '\\')"); a += [L(text)] * 4
            if yes(q.get("att")):
                w.append("n_att > 0")
            if q.get("fmt"):
                w.append("fmt = ?"); a.append(q["fmt"])
            if q.get("start"):
                w.append("date >= ?"); a.append(q["start"])
            if q.get("end"):
                w.append("date <= ?"); a.append(q["end"] + ("T23:59:59" if "T" not in q["end"] else ""))
            cf_apply(q, {"date": ("date", "d"), "sender": ("sender", "t"), "recipients": ("recipients", "t"),
                         "subject": ("subject", "t"),
                         "folder": ("(IFNULL(fmt,'') || ' ' || IFNULL(folder,'') || ' ' || IFNULL(src_path,''))", "t")}, w, a)
            cols = ("id", "date", "sender", "recipients", "cc", "subject", "n_att", "fmt", "folder", "src_path",
                    "part", "inode", "xid")
            table, order = "mail", "date IS NULL, date DESC, id"
        elif kind in ("arch", "vss"):
            if not fa.table_exists(con, "xitems"):
                raise ValueError(tr("Analisi non ancora eseguita."))
            if kind == "vss":
                w.append("kind = 'vss'")
                if q.get("store"):
                    w.append("store = ?"); a.append(q["store"])
            else:
                w.append("kind IN ('archivio','allegato','miniatura')")
                if q.get("xk"):
                    w.append("kind = ?"); a.append(q["xk"])
            if text:
                w.append("path LIKE ? ESCAPE '\\'"); a.append(L(text))
            if yes(q.get("enc")):
                w.append("encrypted = 1")
            if q.get("ext"):
                w.append("lower(name) LIKE ?"); a.append("%." + q["ext"].lower().lstrip("."))
            cf_apply(q, {"path": ("path", "t"), "inner": ("path", "t"), "store": ("store", "t"),
                         "size": ("size", "n"), "mtime": ("mtime", "d"),
                         "note": ("(IFNULL(sha256,'') || ' ' || IFNULL(note,''))", "t")}, w, a)
            cols = X_COLS
            table, order = "xitems", "path COLLATE NOCASE"
        elif kind == "anom":
            if not fa.table_exists(con, "anomalies"):
                raise ValueError(tr("Anomalie non ancora cercate."))
            if q.get("akind"):
                w.append("kind = ?"); a.append(q["akind"])
            if text:
                w.append("(path LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\')"); a += [L(text)] * 2
            cf_apply(q, {"kind": ("kind", "t"), "path": ("path", "t"), "detail": ("detail", "t"),
                         "size": ("size", "n")}, w, a)
            cols = ("id", "kind", "source", "part", "inode", "path", "detail", "ext", "real", "size", "deleted", "sev")
            table, order = "anomalies", "sev DESC, kind, path COLLATE NOCASE"
        else:
            raise ValueError(tr("Sezione sconosciuta."))
        if q.get("cfv"):
            cf_values(con, q, table, w, a)
        order = cf_order(q, order)
        cond = (" WHERE " + " AND ".join(w)) if w else ""
        total = con.execute(f"SELECT COUNT(*) FROM {table}{cond}", a).fetchone()[0]
        rows = [dict(zip(cols, r)) for r in con.execute(
            f"SELECT {', '.join(cols)} FROM {table}{cond} ORDER BY {order}{lim}", a)]
    finally:
        con.close()
    for r in rows:
        if "data" in r and r["data"]:
            try:
                r["data"] = json.loads(r["data"])
            except ValueError:
                pass
    return {"kind": kind, "total": total, "offset": off, "page": PAGE, "rows": rows}


def ext_tree(case):
    """Sottovoci per la vista ad albero: categorie, tipi, formati."""
    con = fa.db_ro(case)
    out = {}
    try:
        if fa.table_exists(con, "artifacts"):
            out["art"] = con.execute("SELECT cat, COUNT(*) FROM artifacts GROUP BY cat ORDER BY 2 DESC").fetchall()
        if fa.table_exists(con, "anomalies"):
            out["anom"] = con.execute("SELECT kind, COUNT(*) FROM anomalies GROUP BY kind ORDER BY MAX(sev) DESC").fetchall()
        if fa.table_exists(con, "xitems"):
            out["arch"] = con.execute("SELECT kind, COUNT(*) FROM xitems WHERE kind IN ('archivio','allegato','miniatura') "
                                      "GROUP BY kind").fetchall()
            out["vss"] = con.execute("SELECT store, COUNT(*) FROM xitems WHERE kind='vss' GROUP BY store ORDER BY store").fetchall()
        if fa.table_exists(con, "mail"):
            out["mail"] = con.execute("SELECT fmt, COUNT(*) FROM mail GROUP BY fmt").fetchall()
    finally:
        con.close()
    return out


def x_ident(case, b):
    """Un file estratto (archivio, allegato, copia shadow)."""
    con = fa.db_ro(case)
    try:
        r = con.execute(f"SELECT {', '.join(X_COLS)} FROM xitems WHERE id=?", (int(b.get("id") or b.get("inode") or 0),)).fetchone()
    finally:
        con.close()
    if not r:
        raise ValueError(tr("File estratto non trovato."))
    x = dict(zip(X_COLS, r))
    f = case.root / x["relpath"] if x["relpath"] else None
    if f is not None and not f.exists():
        f = None
    return {"source": "x", "id": x["id"], "name": x["name"], "path": x["path"], "key": f"x_{x['id']}",
            "ext": Path(x["name"] or "").suffix.lower(), "size": f.stat().st_size if f else x["size"],
            "file": f, "deleted": x["deleted"] or 0, "part": None, "inode": None, "rec": x}


def phash_simili(case, b):
    """Immagini del caso simili (hash percettivo) a quella indicata."""
    fe = fe_mod()
    con = fa.db_ro(case)
    try:
        if not fa.table_exists(con, "phash"):
            raise ValueError(tr("Esegui prima l'analisi «Hash percettivi» (Analisi aggiuntive)."))
        src = b.get("source") or "fs"
        key = str(b.get("id")) if src == "x" else str(b.get("name")) if src == "carving" else str(b.get("inode"))
        sql, args = "SELECT dhash FROM phash WHERE source=? AND inode=?", [src, key]
        if src == "fs":
            sql += " AND part=?"
            args.append(int(b.get("part")))
        r = con.execute(sql, args).fetchone()
        if not r:
            raise ValueError(tr("Questa immagine non ha un hash percettivo (non si apre o non era tra le immagini analizzate)."))
        out = []
        for d, s, p, i, pa in fe.phash_similar(con, r[0]):
            if s == src and str(i) == key and (src != "fs" or p == int(b.get("part"))):
                continue
            out.append({"dist": d, "source": s, "part": p, "inode": i, "path": pa})
        return {"simili": out, "soglia": fe.PHASH_NEAR}
    finally:
        con.close()


X_KIND_LBL = {"archivio": N_("contenuto di un archivio"), "allegato": N_("allegato di posta"), "vss": N_("copia shadow"),
              "miniatura": N_("miniatura della cache di Esplora file (thumbcache)")}


def x_details(case, it, tz=None):
    x = it["rec"]
    lines = [tr("File estratto: {path}").format(path=x['path']),
             tr("Tipo: ") + tr(X_KIND_LBL.get(x["kind"], x["kind"])),
             tr("File di origine nella copia: {src_path} (offset {part}, inode {inode})").format(src_path=x['src_path'], part=x['part'], inode=x['inode']) if x["kind"] != "vss"
             else (tr("Snapshot APFS: {store} (volume all'offset {part}, identificatore nello snapshot {inode})").format(store=x['store'], part=x['part'], inode=x['inode'])
                   if str(x["store"] or "").startswith("snapshot APFS") else
                   tr("Copia shadow: {store} (partizione all'offset {part}, inode nella copia shadow {inode})").format(store=x['store'], part=x['part'], inode=x['inode'])),
             tr("Dimensione: {size} byte").format(size=x['size']), tr("Data indicata ({v1}): {v2}").format(v1=tz_label(case, tz), v2=fmt_ts(case, tz, x['mtime']) or '-'),
             tr("Protetto da password: {v1}").format(v1=tr('sì') if x['encrypted'] else tr('no')),
             f"MD5: {x['md5'] or '-'}", f"SHA-1: {x['sha1'] or '-'}", f"SHA-256: {x['sha256'] or '-'}",
             tr("Copia nel caso: {v1}").format(v1=x['relpath'] or tr('non estratto')) + (f" ({x['note']})" if x["note"] else "")]
    return "\n".join(lines)


def x_text(case, it):
    f = it.get("file")
    if not f:
        return tr("File non estratto: ") + (it["rec"].get("note") or tr("contenuto non disponibile"))
    data = f.read_bytes()[:50 << 20]
    tmp = cache_dir(case, "tmp")
    try:
        r = fa.extract_text(data, it["name"], tmp)
    except Exception:
        r = None
    if not r and data.startswith(b"SQLite format 3\x00"):
        return fe_mod().sqlite_dump(f, 60000)
    return r[1] if r else fa.binary_strings(data)


def fe_mod():
    import forense_estesa as fe
    return fe


def mail_view(case, b):
    """Messaggio di posta per il riquadro di anteprima: intestazioni, testo o HTML (senza
    contenuti esterni), allegati apribili."""
    con = fa.db_ro(case)
    try:
        r = con.execute("SELECT id, date, sender, recipients, cc, subject, body, html, headers, src_path, folder, fmt, "
                        "part, inode FROM mail WHERE id=?", (int(b.get("id") or b.get("inode") or 0),)).fetchone()
        atts = con.execute("SELECT id, name, size, encrypted, relpath, note FROM xitems WHERE mail=? ORDER BY id",
                           (int(b.get("id") or b.get("inode") or 0),)).fetchall()
    finally:
        con.close()
    if not r:
        raise ValueError(tr("Messaggio non trovato."))
    mid, date, snd, to, cc, subj, body, htm, hdr, src, folder, fmt, part, inode = r
    page = htm if htm else f"<pre style='white-space:pre-wrap;font:13px/1.5 -apple-system,Segoe UI,sans-serif'>{html_mod.escape(body or '')}</pre>"
    page = re.sub(r"(?is)<(script|iframe|object|embed|link|meta)\b.*?(</\1>|>)", "", page)
    return {"type": "mail", "title": subj, "name": subj, "source": "mail", "id": mid, "size": len(body or ""),
            "deleted": 0, "part": part, "inode": inode, "magic": "",
            "head": {"Da": snd, "A": to, "Cc": cc, f"Data ({tz_label(case, b.get('tz'))})": fmt_ts(case, b.get("tz"), date), "Oggetto": subj,
                     "Fonte": f"{src} › {folder}" if folder else src, "Formato": fmt},
            "html": CSP_DOC + "<base target='_blank'>" + page, "headers": hdr or "",
            "atts": [{"id": i, "name": n, "size": z, "enc": e, "ok": bool(rel), "note": nt} for i, n, z, e, rel, nt in atts]}


def art_view(case, b):
    con = fa.db_ro(case)
    try:
        r = con.execute("SELECT id, cat, ts, title, detail, user, src_path, part, inode, data FROM artifacts WHERE id=?",
                        (int(b.get("id") or b.get("inode") or 0),)).fetchone()
    finally:
        con.close()
    if not r:
        raise ValueError(tr("Artefatto non trovato."))
    aid, cat, ts, title, detail, user, src, part, inode, data = r
    fe = fe_mod()
    rows = [(tr("Categoria"), tr(fe.ART_CATS.get(cat, cat))), (tr("Data ({v1})").format(v1=tz_label(case, b.get('tz'))), fmt_ts(case, b.get("tz"), ts)), (tr("Elemento"), title),
            (tr("Dettagli"), detail), (tr("Utente"), user), (tr("Fonte"), f"{src} (offset {part}, inode {inode})" if src else "")]
    try:
        for k, v in (json.loads(data) if data else {}).items():
            if v not in (None, "", []):
                rows.append((k.replace("_", " "), ", ".join(map(str, v)) if isinstance(v, list) else str(v)))
    except ValueError:
        pass
    h = "<table style='border-collapse:collapse;font:13px/1.5 -apple-system,Segoe UI,sans-serif;width:100%'>" + "".join(
        f"<tr><th style='text-align:left;vertical-align:top;padding:5px 10px;border-bottom:1px solid #ddd;white-space:nowrap'>"
        f"{html_mod.escape(k)}</th><td style='padding:5px 10px;border-bottom:1px solid #ddd;word-break:break-word'>"
        f"{html_mod.escape(str(v or ''))}</td></tr>" for k, v in rows) + "</table>"
    return {"type": "html", "title": title, "name": title, "source": "art", "id": aid, "size": 0, "deleted": 0,
            "part": part, "inode": inode, "magic": "", "html": CSP_DOC + h, "src_path": src}


def sqlite_view(f):
    con = sqlite3.connect(f"file:{Path(f).as_posix()}?mode=ro&immutable=1", uri=True)
    parts = []
    try:
        tabs = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")][:60]
        for t in tabs:
            try:
                n = con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                cur = con.execute(f'SELECT * FROM "{t}" LIMIT 300')
            except sqlite3.Error:
                continue
            cols = [c[0] for c in cur.description or []]
            body = []
            for row in cur:
                cells = []
                for v in row:
                    if isinstance(v, bytes):
                        s = f"[{len(v)} byte] " + v[:24].hex(" ")
                    else:
                        s = "" if v is None else str(v)
                    cells.append(f"<td>{html_mod.escape(s[:400])}</td>")
                body.append("<tr>" + "".join(cells) + "</tr>")
            parts.append(f"<h3>{html_mod.escape(t)} <small>({n} righe{', mostrate le prime 300' if n > 300 else ''})</small></h3>"
                         f"<div class='w'><table><tr>{''.join(f'<th>{html_mod.escape(c)}</th>' for c in cols)}</tr>{''.join(body)}</table></div>")
    finally:
        con.close()
    css = ("<style>body{font:12.5px/1.4 -apple-system,Segoe UI,sans-serif;margin:10px}h3{font-size:14px;margin:16px 0 6px}"
           "small{color:#777;font-weight:400}.w{overflow:auto;max-height:420px;border:1px solid #ddd}"
           "table{border-collapse:collapse;font-size:12px}td,th{border:1px solid #e3e3e3;padding:3px 6px;vertical-align:top;"
           "text-align:left;white-space:nowrap;max-width:420px;overflow:hidden;text-overflow:ellipsis}th{background:#f2f3f5;position:sticky;top:0}</style>")
    return CSP_DOC + css + ("".join(parts) or tr("<p>Nessuna tabella.</p>"))


def export_x(case, b):
    """Copia un file estratto (archivio, allegato, copia shadow) in export/ e lo mostra."""
    it = x_ident(case, b)
    if not it["file"]:
        raise ValueError(tr("Il file non è stato estratto: ") + (it["rec"].get("note") or ""))
    d = case.export_dir / "estratti"
    d.mkdir(parents=True, exist_ok=True)
    dest = d / f"x{it['id']}_{safe_part(it['name'] or 'file')}"
    if not dest.exists():
        shutil.copyfile(it["file"], dest)
        dest.chmod(0o444)
    case.log("export_estratto", {"id": it["id"], "origine": it["path"], "dest": str(dest), "sha256": it["rec"]["sha256"]})
    if b.get("reveal"):
        reveal(dest)
    return {"message": tr("Esportato in {dest} (SHA-256 {sha256})").format(dest=dest, sha256=it['rec']['sha256']), "path": str(dest)}


def x_targets(case, kind, rows):
    """File estratti (source x) presenti nelle righe selezionate: {id: (percorso, relpath)}."""
    ids = []
    for x in rows:
        if kind in ("arch", "vss"):
            ids.append(x["id"])
        elif kind in ("hits", "doc") and x.get("source") == "x":
            ids.append(int(x["inode"]))
        elif kind == "anom" and x.get("source") == "x":
            ids.append(int(x["inode"]))
        elif kind == "mail":
            pass
    if not ids:
        return {}
    con = fa.db_ro(case)
    try:
        return {i: (p, rel) for i, p, rel in con.execute(
            "SELECT id, path, relpath FROM xitems WHERE id IN (SELECT value FROM json_each(?))", (json.dumps(ids),))}
    finally:
        con.close()


def ext_ref_label(kind, x):
    if kind == "art":
        return (tr("artefatto «{title}» ({cat}, {v1}): {detail}").format(title=x['title'], cat=x['cat'], v1=(x['ts'] + ' UTC') if x['ts'] else tr('senza data'), detail=x['detail'])
                + (tr(" — fonte {src_path} (offset {part}, inode {inode})").format(src_path=x['src_path'], part=x['part'], inode=x['inode']) if x.get("src_path") else ""))
    if kind == "mail":
        return (tr("messaggio «{subject}» del {v1} da {sender} a {recipients} ({src_path} › {folder}, offset "
                   "{part}, inode {inode})").format(subject=x['subject'], v1=(x['date'] + ' UTC') if x['date'] else '?', sender=x['sender'], recipients=x['recipients'], src_path=x['src_path'], folder=x['folder'], part=x['part'], inode=x['inode']))
    if kind in ("arch", "vss"):
        return (tr("{path} ({size} byte").format(path=x['path'], size=x['size']) + (f", SHA-256 {x['sha256']}" if x.get("sha256") else "")
                + (tr(", protetto da password") if x.get("encrypted") else "") + (f"; {x['note']}" if x.get("note") else "")
                + (tr("; file di origine offset {part}, inode {inode}").format(part=x['part'], inode=x['inode']) if kind == "arch" else "") + ")")
    if kind == "anom":
        return tr("anomalia: {path} — {detail}").format(path=x['path'], detail=x['detail']) + (f" (offset {x['part']}, inode {x['inode']})" if x.get("part") is not None else "")
    return str(x)


EXT_CSV = {
    "art": [("cat", "categoria"), ("ts", "data_utc"), ("title", "elemento"), ("detail", "dettagli"), ("user", "utente"),
            ("src_path", "fonte"), ("part", "partizione_offset"), ("inode", "inode")],
    "mail": [("date", "data_utc"), ("sender", "mittente"), ("recipients", "destinatari"), ("cc", "cc"),
             ("subject", "oggetto"), ("n_att", "allegati"), ("fmt", "formato"), ("folder", "cartella"),
             ("src_path", "file_di_posta"), ("part", "partizione_offset"), ("inode", "inode")],
    "arch": [("path", "percorso"), ("kind", "tipo"), ("size", "byte"), ("mtime", "data_utc"), ("encrypted", "cifrato"),
             ("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256"), ("src_path", "file_di_origine"),
             ("part", "partizione_offset"), ("inode", "inode"), ("relpath", "copia_nel_caso"), ("note", "note")],
    "vss": [("path", "percorso"), ("store", "copia_shadow"), ("size", "byte"), ("mtime", "modifica_utc"), ("note", "stato"),
            ("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256"), ("relpath", "copia_nel_caso")],
    "anom": [("kind", "tipo"), ("path", "file"), ("detail", "dettaglio"), ("ext", "estensione"), ("real", "contenuto"),
             ("size", "byte"), ("deleted", "cancellato"), ("part", "partizione_offset"), ("inode", "inode")],
}


def x_search_items(case):
    con = fa.db_ro(case)
    try:
        if not fa.table_exists(con, "xitems"):
            return []
        return con.execute("SELECT id, path, name, relpath, size, mtime, md5, sha1, sha256 FROM xitems").fetchall()
    finally:
        con.close()


def raw_image_search(case, terms, match, cs, encs, progress, stop, cap=3000):
    """Cerca le parole nei byte grezzi di tutta la copia (spazio non allocato, slack, file
    cancellati sovrascritti, metadati): [(offset, termine, codifica, estratto)]."""
    brx = [(t, enc, rx) for t in terms for enc, rx in byte_regexes(t, match, cs, encs)]
    # caso più comune (contiene, senza distinguere maiuscole): ricerca diretta dei byte, molto più veloce
    fast = None
    if match == "contains" and all(t.isascii() for t in terms):
        fast = [(t, enc, (t if cs else t.lower()).encode("utf-16-le" if enc == "utf16" else "utf-8"))
                for t in terms for enc in encs]
    maxlen = max(len(t.encode("utf-16-le")) for t in terms) + 64
    it = image_ident(case)
    total = it["size"] or 0
    out, pos, tail, tlast = [], 0, b"", 0
    step = 16 << 20
    while not stop.is_set():
        chunk = image_read(case, pos, step)
        if not chunk:
            break
        buf = tail + chunk
        base = pos - len(tail)
        if fast:
            hay = buf if cs else buf.lower()
            for t, enc, needle in fast:
                i = hay.find(needle)
                while i != -1:
                    if i + len(needle) > len(tail):     # non già trovata nel blocco precedente
                        out.append((base + i, t, enc, byte_snippet(buf, i, i + len(needle), enc)))
                        if len(out) >= cap:
                            return out, True
                    i = hay.find(needle, i + 1)
        else:
            for t, enc, rx in brx:
                for m in rx.finditer(buf):
                    if m.end() <= len(tail):        # già trovata nel blocco precedente
                        continue
                    o = base + m.start()
                    out.append((o, t, enc, byte_snippet(buf, m.start(), m.end(), enc)))
                    if len(out) >= cap:
                        return out, True
        pos += len(chunk)
        tail = buf[-maxlen:]
        if time.time() - tlast > 0.5:
            tlast = time.time()
            progress(tr("Byte grezzi della copia: {v1:.2f} di {v2:.2f} GB · {v3} occorrenze").format(v1=pos / 1e9, v2=total / 1e9, v3=len(out)))
        if len(chunk) < step:
            break
    return out, False


def decrypt_task(root, b, progress):
    case = fa.Case(root)
    return fe_mod().decrypt_volume(case, int(b["offset"]), b.get("secret") or "", b.get("kind") or "password", progress)


def hashlist_add(b):
    fe = fe_mod()
    lists = fe.hash_lists()
    name = " ".join(str(b.get("nome") or "").split())[:80]
    tipo = "segnalati" if b.get("tipo") == "segnalati" else "noti"
    if b.get("testo"):
        found = sorted({m.decode().lower() for m in fe.HEX.findall(str(b["testo"]).encode())})
        if not found:
            raise ValueError(tr("Nessun hash valido nel testo incollato."))
        d = fa.CASES_HOME / "liste_hash"
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{safe_part(name or 'lista')}_{stamp_now()}.txt"
        path.write_text("\n".join(found) + "\n", encoding="utf-8")
    else:
        path = Path(clean_path(b.get("path") or ""))
        if not (path.is_file() or path.is_dir()):
            raise ValueError(tr("File o cartella della lista non trovato."))
    if not name:
        name = path.stem
    if any(x["nome"].lower() == name.lower() for x in lists):
        raise ValueError(tr("Esiste già una lista con questo nome."))
    if path.is_dir():               # cartella di immagini di riferimento: confronto per somiglianza (hash percettivi)
        n_img = sum(1 for x in path.rglob("*") if x.is_file() and x.suffix.lower() in fe.PHASH_IMG)
        if not n_img:
            raise ValueError(tr("La cartella non contiene immagini."))
        lists.append({"nome": name, "path": str(path), "tipo": tipo, "aggiunta": fa.now(), "cartella": True,
                      "immagini": n_img, "byte": 0})
    else:
        lists.append({"nome": name, "path": str(path), "tipo": tipo, "aggiunta": fa.now(),
                      "byte": path.stat().st_size})
    fe.save_hash_lists(lists)
    return {"liste": lists}


def term_regex(term, match, case_sens, target):
    """Espressione per confrontare un termine con nome, percorso o testo."""
    t = term if match == "regex" else re.escape(term)
    if match == "word" or (match in ("starts", "exact") and target == "text"):
        t = rf"(?<!\w){t}" + ("" if match == "starts" else r"(?!\w)")
    elif match == "starts":
        t = "^" + t
    elif match == "exact":
        t = f"^{t}$"
    try:
        return re.compile(t, 0 if case_sens else re.I)
    except re.error as e:
        raise ValueError(tr("Espressione regolare non valida «{term}»: {e}").format(term=term, e=e))


def byte_regexes(term, match, case_sens, encs):
    """Espressioni sui byte grezzi: UTF-8 e/o UTF-16LE (le stringhe di Windows)."""
    out, fl = [], 0 if case_sens else re.I
    for enc in encs:
        if match == "regex":
            if enc != "utf8":
                continue
            out.append((enc, re.compile(term.encode("utf-8"), fl)))
            continue
        raw = term.encode("utf-8" if enc == "utf8" else "utf-16-le")
        pat = re.escape(raw)
        if match in ("word", "exact") and enc == "utf8":
            pat = rb"(?<![A-Za-z0-9_])" + pat + rb"(?![A-Za-z0-9_])"
        elif match == "starts" and enc == "utf8":
            pat = rb"(?<![A-Za-z0-9_])" + pat
        out.append((enc, re.compile(pat, fl)))
    return out


def snippet(text, s, e, width=70):
    a, b = max(0, s - width), min(len(text), e + width)
    return ("…" if a else "") + " ".join(text[a:b].split()) + ("…" if b < len(text) else "")


def byte_snippet(buf, s, e, enc, width=48):
    a, b = max(0, s - width), min(len(buf), e + width)
    if enc == "utf16":
        a -= (a - s) % 2
        txt = buf[a:b].decode("utf-16-le", "replace")
    else:
        txt = buf[a:b].decode("utf-8", "replace")
    return " ".join("".join(c if c.isprintable() else "·" for c in txt).split())


def search_universe(case, f):
    """File della copia che rientrano nei filtri: (part, inode, path, name, deleted, size, mtime)."""
    con = nav_db(case)
    w, a = ["isdir = 0", "inode IS NOT NULL", "type NOT LIKE 'v/%'"], []
    if f.get("deleted") == "only":
        w.append("deleted = 1")
    elif f.get("deleted") == "no":
        w.append("deleted = 0")
    exts = [e.strip().lower().lstrip(".*") for e in re.split(r"[,;\s]+", f.get("ext") or "") if e.strip()]
    if exts:
        w.append("(" + " OR ".join("lower(name) LIKE ?" for _ in exts) + ")")
        a += ["%." + e for e in exts]
    d = (f.get("dir") or "").strip().strip("/")
    if d:
        w.append("(lower(path) LIKE ? ESCAPE '\\' OR lower(path) LIKE ? ESCAPE '\\')")
        a += [fa.like(d.lower()).strip("%") + "/%", "%/" + fa.like(d.lower()).strip("%") + "/%"]
    if f.get("part") not in (None, ""):
        w.append("part = ?"); a.append(int(f["part"]))
    if f.get("size_min") not in (None, ""):
        w.append("size >= ?"); a.append(int(float(f["size_min"])))
    if f.get("size_max") not in (None, ""):
        w.append("size <= ?"); a.append(int(float(f["size_max"])))
    if f.get("date_from"):
        w.append("mtime >= ?"); a.append(f["date_from"])
    if f.get("date_to"):
        w.append("mtime <= ?"); a.append(f["date_to"] + "T23:59:59")
    try:
        return [r for r in con.execute(
            f"SELECT part, inode, path, name, deleted, size, mtime FROM nav WHERE {' AND '.join(w)} "
            "ORDER BY part, path", a)]
    finally:
        con.close()


def carved_universe(case, f):
    con = fa.db_ro(case)
    try:
        if not fa.table_exists(con, "carved"):
            return []
        rows = con.execute("SELECT name, relpath, size, sha256 FROM carved").fetchall()
    finally:
        con.close()
    exts = [e.strip().lower().lstrip(".*") for e in re.split(r"[,;\s]+", f.get("ext") or "") if e.strip()]
    out = []
    for name, rel, size, sha in rows:
        if exts and not any(name.lower().endswith("." + e) for e in exts):
            continue
        if f.get("size_min") not in (None, "") and size < int(float(f["size_min"])):
            continue
        if f.get("size_max") not in (None, "") and size > int(float(f["size_max"])):
            continue
        out.append((name, rel, size, sha))
    return out


def file_chunks(case, part, inode, ext):
    """Contenuto di un file: dalla cache se già estratto, altrimenti in streaming con icat."""
    p = fa.cache_base(case) / "file" / (f"p{part}_i{safe_key(inode)}" + safe_ext(ext))
    if p.exists():
        with open(p, "rb") as fh:
            while c := fh.read(1 << 20):
                yield c
    else:
        yield from fa.icat_stream(case, part, inode)


def local_chunks(p):
    with open(p, "rb") as fh:
        while c := fh.read(1 << 20):
            yield c


def run_search(case, b, progress):
    """Esegue una ricerca e ne salva gli esiti. Restituisce {sid, title, total}."""
    t0 = time.time()
    SEARCH_STOP.clear()
    mode = b.get("mode") or "kw"
    f = b.get("filters") or {}
    inc_carved = yes(f.get("carved")) and bool((case.meta.get("carving") or {}).get("photorec"))
    if not Path(case.image).exists() and (mode == "hash" or "raw" in (b.get("where") or [])):
        pass   # i file già in cache o con hash calcolato restano utilizzabili
    progress(tr("Preparo l'elenco dei file…"))
    ensure_nav(case)
    for _ in range(600):
        if NAV_STATE.get(str(case.root), {}).get("state") != "building":
            break
        time.sleep(0.5)
    uni = search_universe(case, f)
    carved = carved_universe(case, f) if inc_carved else []
    # file estratti da archivi, allegati e copie shadow (con gli stessi filtri di estensione e dimensione)
    xit = []
    if f.get("estratti", True) not in (False, "0", 0, "false"):
        exts_x = [e.strip().lower().lstrip(".*") for e in re.split(r"[,;\s]+", f.get("ext") or "") if e.strip()]
        for r in x_search_items(case):
            if exts_x and not any((r[2] or "").lower().endswith("." + e) for e in exts_x):
                continue
            if f.get("size_min") not in (None, "") and (r[4] or 0) < int(float(f["size_min"])):
                continue
            if f.get("size_max") not in (None, "") and (r[4] or 0) > int(float(f["size_max"])):
                continue
            xit.append(r)
    xinfo = lambda r: (None, str(r[0]), r[1], r[2], 0, r[4], r[5])
    H = {}
    known = {}
    try:
        cr = fa.db_ro(case)
        if fa.table_exists(cr, "hashes"):
            for p, i, md5, sha1, sha256 in cr.execute("SELECT part, inode, md5, sha1, sha256 FROM hashes"):
                known[(p, i)] = (md5, sha1, sha256)
        cr.close()
    except sqlite3.Error:
        pass

    def hit(key, info, where, term, detail):
        h = H.get(key)
        if not h:
            h = H[key] = {"info": info, "wheres": [], "terms": [], "details": []}
        if where not in h["wheres"]:
            h["wheres"].append(where)
        if term not in h["terms"]:
            h["terms"].append(term)
        if detail and len(h["details"]) < 6:
            h["details"].append(detail)

    stopped = False
    note = {}
    if mode == "hash":
        wanted = {t.lower() for t in HASH_TOKEN.findall(b.get("hashes") or "")}
        if not wanted:
            raise ValueError(tr("Nessun hash valido: servono MD5 (32), SHA-1 (40) o SHA-256 (64) "
                             "caratteri esadecimali."))
        compute = (b.get("hash_compute") or "missing") == "missing"
        missing = [r for r in uni if (r[0], r[1]) not in known]
        if missing and compute and not Path(case.image).exists():
            raise ValueError(tr("Per calcolare gli hash mancanti serve la copia forense: collega il disco."))
        wcon = None
        if missing and compute:
            wcon = sqlite3.connect(case.db_path, timeout=60)
            wcon.executescript(fa.HASH_SCHEMA)
        batch, nbytes, tlast = [], 0, 0
        todo = missing if compute else []
        for k, (part, inode, path, name, deleted, size, mtime) in enumerate(todo, 1):
            if SEARCH_STOP.is_set():
                stopped = True
                break
            try:
                n, md5, sha1, sha256 = fa.hash_stream(file_chunks(case, part, inode, Path(name).suffix))
            except Exception:
                continue
            nbytes += n
            known[(part, inode)] = (md5, sha1, sha256)
            batch.append((part, inode, path, deleted, n, md5, sha1, sha256, fa.now()))
            if time.time() - tlast > 0.5:
                tlast = time.time()
                progress(tr("Calcolo gli hash mancanti: {k} di {v1} file · {v2:.0f} MB").format(k=k, v1=len(todo), v2=nbytes / 1e6))
            if len(batch) >= 200:
                wcon.executemany("INSERT OR REPLACE INTO hashes VALUES (?,?,?,?,?,?,?,?,?)", batch)
                wcon.commit()
                batch.clear()
        if wcon:
            wcon.executemany("INSERT OR REPLACE INTO hashes VALUES (?,?,?,?,?,?,?,?,?)", batch)
            wcon.commit()
            wcon.close()
            case.log("hash_file_al_volo", {"file": len(todo)})
        progress(tr("Confronto gli hash…"))
        found = set()
        for part, inode, path, name, deleted, size, mtime in uni:
            hs = known.get((part, inode))
            if not hs:
                continue
            for label, v in zip(("MD5", "SHA-1", "SHA-256"), hs):
                if v and v in wanted:
                    found.add(v)
                    hit(("fs", part, inode, path), (part, inode, path, name, deleted, size, mtime, hs),
                        "hash", v, f"{label} {v}")
        for name, rel, size, sha in carved:
            hs = (None, None, sha)
            if wanted - {sha}:
                if any(len(x) in (32, 40) for x in wanted):
                    try:
                        _, md5, sha1, _s = fa.hash_stream(open(case.root / rel, "rb"))
                        hs = (md5, sha1, sha)
                    except OSError:
                        pass
            for label, v in zip(("MD5", "SHA-1", "SHA-256"), hs):
                if v and v in wanted:
                    found.add(v)
                    hit(("carving", None, name, name), (None, name, name, name, 0, size, None, hs),
                        "hash", v, tr("{label} {v1} (file recuperato)").format(label=label, v1=v))
        for r in xit:
            for label, v in zip(("MD5", "SHA-1", "SHA-256"), r[6:9]):
                if v and v in wanted:
                    found.add(v)
                    hit(("x", None, str(r[0]), r[1]), (*xinfo(r), r[6:9]), "hash", v, tr("{label} {v1} (file estratto)").format(label=label, v1=v))
        note = {"cercati": len(wanted), "trovati": len(found),
                "non_trovati": sorted(wanted - found)[:2000],
                "senza_hash": 0 if compute else len(missing)}
        terms_all = sorted(wanted)
    else:
        terms = [t.strip() for t in (b.get("terms") or "").splitlines() if t.strip()]
        if not terms:
            raise ValueError(tr("Scrivi almeno una parola da cercare."))
        where = [w for w in (b.get("where") or []) if w in WHERE_LABEL and w != "hash"]
        if not where:
            raise ValueError(tr("Scegli dove cercare."))
        match, cs = b.get("match") or "contains", yes(b.get("case"))
        terms_all = terms
        allowed = {(r[0], r[1]) for r in uni}
        # nome e percorso
        if "name" in where or "path" in where:
            progress(tr("Cerco nei nomi dei file…"))
            rx_n = [(t, term_regex(t, match, cs, "name")) for t in terms]
            rx_p = [(t, term_regex(t, match, cs, "path")) for t in terms]
            for r in uni:
                part, inode, path, name = r[:4]
                for t, rx in rx_n:
                    if "name" in where and rx.search(name):
                        hit(("fs", part, inode, path), r, "name", t, None)
                for t, rx in rx_p:
                    if "path" in where and rx.search(path):
                        hit(("fs", part, inode, path), r, "path", t, None)
            for name, rel, size, sha in carved:
                for t, rx in rx_n:
                    if rx.search(name):
                        hit(("carving", None, name, name), (None, name, name, name, 0, size, None),
                            "name", t, None)
            for r in xit:
                for t, rx in rx_n:
                    if "name" in where and rx.search(r[2] or ""):
                        hit(("x", None, str(r[0]), r[1]), xinfo(r), "name", t, None)
                for t, rx in rx_p:
                    if "path" in where and rx.search(r[1] or ""):
                        hit(("x", None, str(r[0]), r[1]), xinfo(r), "path", t, None)
        rinfo = {(r[0], r[1]): r for r in uni}
        # testo dei documenti e metadati indicizzati
        for wkey, table, col in (("doc", "doc_text", "body"), ("doc", "doc_text_extra", "body"),
                                 ("meta", "meta", "data")):
            if wkey not in where or SEARCH_STOP.is_set():
                continue
            con = fa.db_ro(case)
            try:
                if not fa.table_exists(con, table):
                    continue
                progress(tr("Cerco nel testo dei documenti…") if wkey == "doc" else tr("Cerco nei metadati…"))
                rxs = [(t, term_regex(t, match, cs, "text")) for t in terms]
                cond, args = "", []
                if match in ("contains", "word", "starts", "exact"):
                    cond = " WHERE " + " OR ".join(f"{col} LIKE ? ESCAPE '\\'" for _ in terms)
                    args = [fa.like(t) for t in terms]
                for src, part, inode, deleted, path, body in con.execute(
                        f"SELECT source, part, inode, deleted, path, {col} FROM {table}{cond}", args):
                    if SEARCH_STOP.is_set():
                        stopped = True
                        break
                    body = body or ""
                    if src == "x":
                        key, info = ("x", None, str(inode), path), (None, str(inode), path, Path(str(path)).name.split(" › ")[-1], 0, None, None)
                    elif src == "posta":
                        key, info = ("mail", None, str(inode), path), (None, str(inode), path, path.split(" › ")[-1], 0, None, None)
                    elif src == "carving":
                        if not inc_carved:
                            continue
                        name = Path(str(inode)).name
                        key, info = ("carving", None, name, name), (None, name, name, name, 0, None, None)
                    else:
                        r = rinfo.get((part, str(inode)))
                        if r is None:
                            continue
                        key, info = ("fs", part, r[1], r[2]), r
                    for t, rx in rxs:
                        m = rx.search(body)
                        if m:
                            hit(key, info, wkey, t, f"{tr(WHERE_LABEL[wkey])}: {snippet(body, m.start(), m.end())}")
            finally:
                con.close()
        # contenuto grezzo, byte per byte
        if "raw" in where and not SEARCH_STOP.is_set():
            encs = [e for e in (b.get("enc") or ["utf8", "utf16"]) if e in ("utf8", "utf16")] or ["utf8"]
            brx = [(t, enc, rx) for t in terms for enc, rx in byte_regexes(t, match, cs, encs)]
            maxlen = max(len(t.encode("utf-16-le")) for t in terms) + 64
            items = [("fs", r) for r in uni] + [("carving", c) for c in carved] + \
                [("x", r) for r in xit if r[3]]
            if any(s == "fs" for s, _ in items) and not Path(case.image).exists():
                note["avviso"] = tr("Copia forense non collegata: contenuto cercato solo nei file in cache.")
            total_b, done_b, tlast = sum((x[5] if s == "fs" else x[4] if s == "x" else x[2]) or 0 for s, x in items), 0, 0
            for k, (src, x) in enumerate(items, 1):
                if SEARCH_STOP.is_set():
                    stopped = True
                    break
                if src == "fs":
                    part, inode, path, name = x[:4]
                    key, info = ("fs", part, inode, path), x
                    if not Path(case.image).exists() and not (fa.cache_base(case) / "file" / (
                            f"p{part}_i{safe_key(inode)}" + safe_ext(Path(name).suffix))).exists():
                        continue
                    gen = file_chunks(case, part, inode, Path(name).suffix)
                elif src == "x":
                    key, info = ("x", None, str(x[0]), x[1]), xinfo(x)
                    gen = local_chunks(case.root / x[3])
                else:
                    name, rel, size, sha = x
                    key, info = ("carving", None, name, name), (None, name, name, name, 0, size, None)
                    gen = local_chunks(case.root / rel)
                seen, tail, pos = set(), b"", 0
                try:
                    for chunk in gen:
                        buf = tail + chunk
                        base = pos - len(tail)
                        for t, enc, rx in brx:
                            if (t, enc) in seen:
                                continue
                            m = rx.search(buf)
                            if m:
                                seen.add((t, enc))
                                hit(key, info, "raw", t, tr("contenuto{v1} all'offset {v2}: {v3}").format(v1=' UTF-16' if enc == 'utf16' else '', v2=base + m.start(), v3=byte_snippet(buf, m.start(), m.end(), enc)))
                        pos += len(chunk)
                        done_b += len(chunk)
                        tail = buf[-maxlen:]
                        if len(seen) == len(brx) or SEARCH_STOP.is_set():
                            break
                        if time.time() - tlast > 0.5:
                            tlast = time.time()
                            progress(tr("Contenuto dei file: {k} di {v1} · {v2:.0f} di {v3:.0f} MB").format(k=k, v1=len(items), v2=done_b / 1e6, v3=total_b / 1e6))
                finally:
                    if hasattr(gen, "close"):
                        gen.close()
        # byte grezzi di tutta la copia: spazio non allocato, slack, file sovrascritti
        if "img" in where and not SEARCH_STOP.is_set():
            if not Path(case.image).exists():
                note["avviso"] = tr("Copia forense non collegata: ricerca nei byte grezzi non eseguita.")
            else:
                encs = [e for e in (b.get("enc") or ["utf8", "utf16"]) if e in ("utf8", "utf16")] or ["utf8"]
                occ, more = raw_image_search(case, terms, match, cs, encs, progress, SEARCH_STOP)
                stopped = stopped or SEARCH_STOP.is_set()
                for off, t, enc, snip in occ:
                    lab = tr("Copia forense · byte {off:,}").format(off=off).replace(",", ".")
                    hit(("image", None, str(off), lab), (None, str(off), lab, f"byte {off}", 0, None, None),
                        "img", t, f"{'UTF-16 ' if enc == 'utf16' else ''}{snip}")
                if more:
                    note["avviso"] = tr("Molte occorrenze nei byte grezzi: mostrate le prime 3.000.")
        if b.get("combine") == "all" and len(terms) > 1:
            H = {k: v for k, v in H.items() if len(v["terms"]) == len(terms)}
    # file il cui testo non è nell'indice (o solo in parte): la ricerca nel testo non li copre per intero
    try:
        con_n = fa.db_ro(case)
        try:
            if fa.table_exists(con_n, "doc_skipped") and "doc" in (b.get("where") or []):
                nn = con_n.execute("SELECT COUNT(*) FROM doc_skipped").fetchone()[0]
                if nn:
                    note["non_indicizzati"] = nn
        finally:
            con_n.close()
    except Exception:
        pass
    # salvataggio
    progress(tr("Salvo i risultati…"))
    title = (b.get("title") or "").strip() or (
        (tr("Hash: 1 valore") if len(terms_all) == 1 else tr("Hash: {v1} valori").format(v1=len(terms_all))) if mode == "hash"
        else tr("Parole: ") + ", ".join(terms_all[:4]) + ("…" if len(terms_all) > 4 else ""))
    if stopped:
        title += tr(" (interrotta)")
    con = search_db(case)
    try:
        cur = con.execute("INSERT INTO searches(title, created, params, total, elapsed, note) "
                          "VALUES (?,?,?,?,?,?)", (title, fa.now(), json.dumps(b, ensure_ascii=False),
                                                    len(H), round(time.time() - t0, 1),
                                                    json.dumps(note, ensure_ascii=False)))
        sid = cur.lastrowid
        rows = []
        for (src, part, inode, path), h in sorted(H.items(), key=lambda kv: str(kv[0][3]).lower()):
            info = h["info"]
            hs = info[7] if len(info) > 7 else (known.get((part, inode)) if src == "fs" else None)
            hs = hs or (None, None, None)
            rows.append((sid, src, part, str(inode), path, info[3], info[4], info[5], info[6],
                         ", ".join(tr(WHERE_LABEL[w]) for w in h["wheres"]), "; ".join(h["terms"]),
                         " · ".join(h["details"])[:900], *hs))
        con.executemany("INSERT INTO hits(sid, source, part, inode, path, name, deleted, size, mtime, "
                        "wheres, terms, detail, md5, sha1, sha256) VALUES "
                        "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        con.commit()
    finally:
        con.close()
    case.log("ricerca", {"sid": sid, "titolo": title, "parametri": b, "risultati": len(H),
                         "interrotta": stopped})
    return {"sid": sid, "title": title, "total": len(H), "stopped": stopped, "note": note}


def hits_list(case, q, ids=None, limit=PAGE):
    con = search_db(case)
    off = int(q.get("offset", 0))
    w, a = ["sid = ?"], [int(q.get("sid") or 0)]
    if ids is not None:
        w.append("id IN (SELECT value FROM json_each(?))")
        a.append(json.dumps([int(x) for x in ids if str(x).isdigit()]))
    text = (q.get("q") or "").strip()
    if text:
        w.append("(path LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\')"); a += [fa.like(text)] * 2
    if q.get("hwhere"):
        w.append("wheres LIKE ?"); a.append("%" + q["hwhere"] + "%")
    if (q.get("term") or "").strip():
        w.append("terms LIKE ? ESCAPE '\\'"); a.append(fa.like(q["term"].strip()))
    if yes(q.get("deleted")):
        w.append("deleted = 1")
    cf_apply(q, cf_hits(), w, a)
    cond = " WHERE " + " AND ".join(w)
    try:
        if q.get("cfv"):
            cf_values(con, q, "hits", w, a)
        total = con.execute(f"SELECT COUNT(*) FROM hits{cond}", a).fetchone()[0]
        lim = f" LIMIT {int(limit)} OFFSET {off}" if limit else ""
        rows = con.execute(f"SELECT {', '.join(HIT_COLS)} FROM hits{cond} ORDER BY {cf_order(q, 'path COLLATE NOCASE')}{lim}",
                           a).fetchall()
    finally:
        con.close()
    return {"kind": "hits", "total": total, "offset": off, "page": PAGE,
            "rows": [dict(zip(HIT_COLS, r)) for r in rows]}


def search_list(case):
    if not (case.root / "ricerche.sqlite").exists():
        return []
    con = search_db(case)
    try:
        return [{"sid": s, "title": t, "created": c, "total": n, "elapsed": e,
                 "note": json.loads(nt or "{}"), "params": json.loads(p or "{}")}
                for s, t, c, p, n, e, nt in con.execute(
                    "SELECT sid, title, created, params, total, elapsed, note FROM searches "
                    "ORDER BY sid DESC")]
    finally:
        con.close()


def search_delete(case, sid):
    con = search_db(case)
    try:
        con.execute("DELETE FROM hits WHERE sid=?", (int(sid),))
        con.execute("DELETE FROM searches WHERE sid=?", (int(sid),))
        con.commit()
    finally:
        con.close()
    case.log("ricerca_eliminata", {"sid": int(sid)})


def run_task(name, fn, with_progress=False):
    """Operazione lunga in background; lo stato si legge con /api/task?name=..."""
    if SES.tasks.get(name, {}).get("done") is False:
        raise ValueError(tr("Operazione già in corso: attendi che finisca."))
    SES.tasks[name] = {"done": False, "progress": ""}
    lingua = lg.lingua()        # quella della richiesta: del caso per report ed esportazioni, dell'interfaccia per il resto

    def progress(msg):
        SES.tasks[name]["progress"] = msg

    def wrap():
        try:
            with lg.usa(lingua):
                res = fn(progress) if with_progress else fn()
            SES.tasks[name] = {"done": True, "result": res}
        except Exception as e:
            SES.tasks[name] = {"done": True, "error": str(e)}
    threading.Thread(target=wrap, daemon=True).start()


# ----------------------------------------------------------- HTTP

BIN_PATHS = {"/api/thumb", "/api/page", "/api/conv", "/api/raw"}


# Richieste che producono testi del caso (report, esportazioni, riscontri, verifiche): nella lingua del caso,
# scelta alla sua creazione; tutte le altre nella lingua dell'interfaccia.
CASE_LANG_PATHS = {"/api/report", "/api/report_export", "/api/export", "/api/export_x", "/api/portable",
                   "/api/riscontro", "/api/verify", "/api/finding", "/api/case_info_set", "/api/hashlist_compare"}


def lingua_js():
    """Lingua dell'interfaccia e dizionario per la pagina (sicuro dentro <script>)."""
    d = {"lingua": lg.lingua(), "lingue": lg.LINGUE, "diz": lg.dizionario(lg.lingua())}
    return json.dumps(d, ensure_ascii=False).replace("</", "<\\/")


def lingua_set(codice):
    """Cambia la lingua dell'interfaccia e la ricorda nelle impostazioni (i casi mantengono la loro)."""
    c = lg.imposta(codice)
    st = fa._raw_settings()
    st["lingua"] = c
    fa.save_settings(st)
    return {"lingua": c}


class Handler(BaseHTTPRequestHandler):
    server_version = "RepertIA"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str))

    def _allowed(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")

    def do_GET(self):
        if not self._allowed():
            return self._send(403, "vietato", "text/plain")
        u = urlparse(self.path)
        if u.path == "/":
            html = (HERE / "forense_gui.html").read_text(encoding="utf-8")
            return self._send(200, html.replace("__TOKEN__", TOKEN).replace("__LINGUA__", lingua_js()), "text/html")
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path in BIN_PATHS:
            # immagini e media: <img>/<video> non possono mandare intestazioni, il codice
            # arriva nell'indirizzo (resta comunque solo su 127.0.0.1)
            if q.get("t") != TOKEN and self.headers.get("X-Token") != TOKEN:
                return self._send(403, "vietato", "text/plain")
            try:
                return self.binary(u.path, q)
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception as e:
                return self._send(404, str(e), "text/plain")
        if self.headers.get("X-Token") != TOKEN:
            return self._send(403, tr("token mancante"), "text/plain")
        try:
            self._json(self.get(u.path, q))
        except Exception as e:
            self._json({"error": str(e)}, 400)

    def _bin(self, data, ctype, code=200, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "sandbox; default-src 'none'")
        self.send_header("Cache-Control", "private, max-age=3600")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def binary(self, path, q):
        if not SES.case:
            raise ValueError(tr("Nessun caso aperto."))
        if path == "/api/thumb":
            r = thumb_bytes(SES.case, q)
            if not r:
                return self._send(404, tr("nessuna miniatura"), "text/plain")
            return self._bin(r[0], r[1])
        if path == "/api/page":
            return self._bin(page_png(SES.case, q), "image/jpeg")
        if path == "/api/conv":
            return self._bin(converted_image(SES.case, q), "image/jpeg")
        if path == "/api/raw":
            it = file_ident(SES.case, q)
            size, f = file_size(SES.case, it)
            if not f:
                raise ValueError(tr("File troppo grande per l'anteprima."))
            data_head = open(f, "rb").read(16)
            # mai HTML/SVG/script: solo immagini e media dichiarati per tipo
            ctype = RAW_MIME.get(it["ext"]) or sniff_mime(data_head) or "application/octet-stream"
            start, end = 0, size - 1
            m = re.match(r"bytes=(\d*)-(\d*)", self.headers.get("Range") or "")
            code = 200
            if m and size:
                if m.group(1):
                    start = int(m.group(1))
                    end = int(m.group(2)) if m.group(2) else size - 1
                else:
                    start = max(0, size - int(m.group(2) or 0))
                end = min(end, size - 1)
                code = 206
            length = max(0, end - start + 1)
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(length))
            self.send_header("Accept-Ranges", "bytes")
            if code == 206:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "sandbox; default-src 'none'")
            self.send_header("Content-Disposition", "inline")
            self.end_headers()
            with open(f, "rb") as fh:
                fh.seek(start)
                left = length
                while left > 0:
                    c = fh.read(min(1 << 20, left))
                    if not c:
                        break
                    self.wfile.write(c)
                    left -= len(c)
            return
        raise ValueError(tr("percorso sconosciuto"))

    def do_POST(self):
        if not self._allowed() or self.headers.get("X-Token") != TOKEN:
            return self._send(403, "vietato", "text/plain")
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
            path = urlparse(self.path).path
            with lg.usa(lg.lingua_caso(SES.case) if SES.case and path in CASE_LANG_PATHS else lg.lingua()):
                self._json(self.post(path, body))
        except Exception as e:
            self._json({"error": str(e)}, 400)

    # --- GET
    def get(self, path, q):
        if path == "/api/home":
            st = fa._raw_settings()
            return {"req": requirements(),
                    "cases": [case_summary(c) for c in fa.all_cases()],
                    "prep_running": PREP.running,
                    "homes": [{"path": str(h), "ok": h.is_dir(), "default": i == 0}
                              for i, h in enumerate(fa.case_homes())],
                    "last_dest": st.get("ultima_cartella_casi") or ""}
        if path == "/api/prep":
            since = int(q.get("since", 0))
            return {"lines": PREP.lines[since:], "total": len(PREP.lines),
                    "running": PREP.running, "rc": PREP.rc, "add": PREP.add, "ask": PREP.ask, "next_image": PREP.next_image,
                    "root": str(PREP.root) if PREP.root else None}
        if path == "/api/events":
            since = int(q.get("since", 0))
            return {"events": SES.events[since:], "busy": SES.busy,
                    "findings": SES.case.findings() if SES.case else []}
        if path == "/api/results":
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            return results(SES.case, q)
        if path == "/api/counts":
            return counts(SES.case)
        if path == "/api/tl_hist":
            return tl_hist(SES.case, q)
        if path == "/api/tree":
            return nav_tree(SES.case, q)
        if path == "/api/searches":
            return {"searches": search_list(SES.case)}
        if path == "/api/bm_cats":
            return {"cats": bm_categories(SES.case)}
        if path == "/api/res_tree":
            return res_tree(SES.case)
        if path == "/api/hashlists":
            return {"liste": fe_mod().hash_lists(), "esito": (SES.case.meta.get("liste_hash") if SES.case else None)}
        if path == "/api/convs":
            return {"convs": SES.list_convs(), "current": SES.conv and SES.conv["id"]}
        if path == "/api/case":
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            return self.state()
        if path == "/api/task":
            return SES.tasks.get(q.get("name"), {"done": True, "error": "sconosciuto"})
        raise ValueError(tr("percorso sconosciuto"))

    # --- POST
    def post(self, path, b):
        if path == "/api/choose":
            p = choose_file()
            return {"path": p} if p else {"cancelled": True}
        if path == "/api/check":
            dest = clean_path(b.get("dest")) if b.get("dest") else None
            if dest:
                check_dest(dest, create=False)      # solo verifica: la cartella si crea all'avvio
            return image_info(clean_path(b.get("path")), dest)
        if path == "/api/choose_file":
            p = choose_file(b.get("prompt") or None, kind="list")
            return {"path": p} if p else {"cancelled": True}
        if path == "/api/riscontro":
            import forense_riscontro as fr
            src = Path(clean_path(b.get("path") or "")).expanduser()
            if not src.is_file():
                raise ValueError(tr("File non trovato: indica il CSV esportato dall'altro strumento."))
            case, tool = SES.case, (b.get("strumento") or "").strip()[:120]
            run_task("riscontro", lambda progress: fr.riscontro(case, src, tool, progress), with_progress=True)
            return {"ok": True}
        if path == "/api/choose_folder":
            p = choose_folder(b.get("prompt") or tr("Scegli la cartella"))
            return {"path": p} if p else {"cancelled": True}
        if path == "/api/dest_check":
            p, free = check_dest(b.get("dest"))
            return {"path": str(p), "free": free}
        if path == "/api/add_home":
            p, _ = check_dest(b.get("path"))
            if (p / "case.json").exists():           # scelta la cartella di un caso: si aggiunge quella che lo contiene
                p = p.parent
            fa.register_case_home(p)
            n = sum(1 for d in p.iterdir() if (d / "case.json").exists())
            return {"path": str(p), "cases": n}
        if path == "/api/remove_home":
            fa.unregister_case_home(b.get("path") or "")
            return {"ok": True}
        if path == "/api/lingua_set":
            return lingua_set(b.get("lingua"))
        if path == "/api/prepare":
            if PREP.running:
                raise ValueError(tr("Una preparazione è già in corso."))
            dest = None
            if b.get("dest"):
                dest, _free = check_dest(b.get("dest"))
            info = image_info(clean_path(b.get("path")), str(dest) if dest else None)
            if not info["ok"]:
                raise ValueError(info["error"])
            if info["case_exists"]:
                return {"root": info["case_root"], "existing": True}
            if dest:
                fa.register_case_home(dest)
                st = fa._raw_settings(); st["ultima_cartella_casi"] = str(dest); fa.save_settings(st)
            fuso = None
            if str(b.get("fuso") or "").strip():
                fuso = fa.fuso_valido(b.get("fuso"))
                if not fuso:
                    raise ValueError(tr("Fuso orario del dispositivo non riconosciuto: usa un nome come "
                                     "Europe/Rome o UTC."))
            missing = [k for k in ("sleuthkit",) if not requirements()[k]]
            if missing:
                raise ValueError(tr("Manca The Sleuth Kit: ")
                                 + (tr("reinstalla RepertIA") if IS_WIN
                                    else tr("in Terminale esegui brew install sleuthkit libewf")))
            if not dest:
                fa.CASES_HOME.mkdir(parents=True, exist_ok=True)
            if b.get("plaso"):
                addon_check("plaso")
            if b.get("carving"):
                addon_check("carving")
            if b.get("ocr"):
                addon_check("ocr")
            PREP.start(Path(info["case_root"]), image=info["path"], plaso=bool(b.get("plaso")),
                       carving=bool(b.get("carving")), hash_file=bool(b.get("hash_file")),
                       no_hash=bool(b.get("no_hash")), estese=bool(b.get("estese")),
                       vss=bool(b.get("vss")), ocr=bool(b.get("ocr")),
                       info=fa.info_caso_clean(b.get("info")), fuso=fuso, lingua=lg.valida(b.get("lingua") or lg.lingua()))
            return {"root": info["case_root"], "existing": False}
        if path in ("/api/cache_info", "/api/cache_set", "/api/cache_clear", "/api/copy_case"):
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            if path == "/api/cache_info":
                return cache_info(SES.case)
            if path == "/api/cache_clear":
                return {"freed": cache_clear(SES.case), **cache_info(SES.case)}
            if path == "/api/cache_set":
                moved = cache_set(SES.case, b)
                return {"moved": moved, **cache_info(SES.case)}
            if PREP.running:
                raise ValueError(tr("Una preparazione è in corso: attendi che finisca."))
            if SES.busy:
                raise ValueError(tr("Attendi che l'agente finisca o interrompilo."))
            case = SES.case
            run_task("copycase", lambda progress: copy_case(case, b.get("dest"), progress), True)
            return {"ok": True}
        if path == "/api/case_info_set":
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            info = fa.info_caso_clean(b.get("info"))
            if info:
                SES.case.meta["info_caso"] = info
            else:
                SES.case.meta.pop("info_caso", None)
            SES.case.save()
            SES.case.log("info_caso", info or "rimossi")
            return {"info": info}
        if path == "/api/addon":
            what = b.get("what")
            if what not in fa.ADDONS:
                raise ValueError(tr("Analisi sconosciuta."))
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            if PREP.running:
                raise ValueError(tr("Una preparazione è già in corso."))
            if SES.busy:
                raise ValueError(tr("Attendi che l'agente finisca o interrompilo."))
            addon_check(what)
            if what == "immagine":
                ev = SES.case.meta.get("evidence", SES.case.meta.get("image", ""))
                if not Path(ev).exists():
                    raise ValueError(tr("La copia forense non è raggiungibile: collega il disco che la contiene."))
            PREP.start(SES.case.root, add=what)
            return {"root": str(SES.case.root)}
        if path == "/api/fuso_set":
            z = fa.fuso_valido(b.get("tz"))
            if not z:
                raise ValueError(tr("Fuso orario non riconosciuto (esempi: Europe/Rome, UTC, America/New_York)."))
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            if PREP.running:
                raise ValueError(tr("Una preparazione è già in corso."))
            if SES.busy:
                raise ValueError(tr("Attendi che l'agente finisca o interrompilo."))
            with NAV_LOCK:
                NAV_STATE.pop(str(SES.case.root), None)
            PREP.start(SES.case.root, add="fuso", fuso=z)
            return {"root": str(SES.case.root)}
        if path == "/api/prep_answer":
            PREP.answer(b)
            return {"ok": True}
        if path == "/api/prep_stop":
            PREP.stop()
            return {"ok": True}
        if path == "/api/open":
            with LOCK:
                SES.open(b["root"], resume=b.get("resume", True))
                if b.get("summary") and not (SES.conv or {}).get("resumed"):
                    SES.summary(b["summary"])
            return self.state()
        if path == "/api/conv_open":
            if SES.busy:
                raise ValueError(tr("Attendi la fine della risposta o interrompi."))
            with LOCK:
                SES.save_conv()
                SES.load_conv(b["id"])
            return self.state()
        if path == "/api/conv_delete":
            p = SES.conv_dir() / f"{Path(str(b['id'])).name}.json"
            if SES.conv and SES.conv["id"] == b["id"]:
                raise ValueError(tr("Non puoi eliminare la conversazione aperta."))
            if p.exists():
                trash = SES.conv_dir() / "eliminate"
                trash.mkdir(exist_ok=True)
                p.replace(trash / p.name)
                SES.case.log("conversazione_eliminata", p.name)
            return {"convs": SES.list_convs()}
        if path == "/api/locate_file":
            return nav_locate(SES.case, b)
        if path == "/api/search_start":
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            case = SES.case
            run_task("search", lambda progress: run_search(case, b, progress), True)
            return {"ok": True}
        if path == "/api/search_stop":
            SEARCH_STOP.set()
            return {"ok": True}
        if path == "/api/search_delete":
            search_delete(SES.case, b["sid"])
            return {"searches": search_list(SES.case)}
        if path == "/api/sel_csv":
            return export_csv(SES.case, b)
        if path == "/api/sel_refs":
            return selection_refs(SES.case, b)
        if path == "/api/case_info":
            c = fa.Case(clean_path(b.get("root") or ""))
            if not c.meta:
                raise ValueError(tr("Caso non trovato."))
            return case_summary(c)
        if path == "/api/export_x":
            return export_x(SES.case, b)
        if path == "/api/decrypt":
            root = b.get("root") or (str(SES.case.root) if SES.case else None)
            if not root:
                raise ValueError(tr("Nessun caso."))
            if not (b.get("secret") or "").strip():
                raise ValueError(tr("Scrivi la password o la chiave di ripristino."))
            case0 = fa.Case(root)
            pa = next((x for x in case0.meta.get("partitions", []) if int(x["offset"]) == int(b.get("offset") or -1)), None)
            if pa and pa.get("apfs") and "timeline" not in case0.meta:
                # volume APFS cifrato in un caso mai preparato: verifica la chiave e rilancia la preparazione
                if PREP.running:
                    raise ValueError(tr("Una preparazione è già in corso."))
                fa.ap.apply_key(case0, pa["offset"], b.get("secret"), b.get("kind"))
                PREP.start(Path(root), image=case0.meta.get("evidence", case0.meta.get("image")), estese=True)
                return {"ok": True, "prepare": True, "image": case0.meta.get("evidence", case0.meta.get("image"))}
            run_task("decrypt", lambda progress: decrypt_task(root, b, progress), True)
            return {"ok": True}
        if path == "/api/hashlist_add":
            return hashlist_add(b)
        if path == "/api/hashlist_remove":
            fe = fe_mod()
            fe.save_hash_lists([x for x in fe.hash_lists() if x["nome"] != b.get("nome")])
            return {"liste": fe.hash_lists()}
        if path == "/api/hashlist_compare":
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            case = SES.case
            run_task("hashlist", lambda progress: fe_mod().compare_lists(case, progress), True)
            return {"ok": True}
        if path == "/api/choose_any":
            return {"path": choose_file(any_file=True)}
        if path == "/api/trace_paths":
            return trace_paths(SES.case, b)
        if path == "/api/trace_locate":
            return trace_locate(SES.case, b)
        if path == "/api/tl_resolve":
            return tl_resolve(SES.case, b)
        if path == "/api/export_reveal":
            return export_reveal(SES.case, b)
        if path == "/api/reveal_trace":
            return reveal_trace(SES.case, b.get("kind"))
        if path == "/api/report_export":
            return report_export(SES.case, b.get("fmt"), b.get("tz"))
        if path == "/api/bm_add":
            return bm_add(SES.case, b)
        if path == "/api/bm_remove":
            return bm_remove(SES.case, b)
        if path == "/api/bm_cat_update":
            return bm_cat_update(SES.case, b)
        if path == "/api/bm_cat_delete":
            return bm_cat_delete(SES.case, b.get("cid"))
        if path == "/api/sel_export":
            run_task("export", lambda progress: export_selection(SES.case, b, progress), True)
            return {"ok": True}
        if path == "/api/refresh":
            with LOCK:
                SES.refresh()
                if b.get("summary"):
                    SES.summary(b["summary"])
            return self.state()
        if path == "/api/summary":
            SES.summary(b.get("what") or "all")
            return {"ok": True}
        if path == "/api/preview":
            return preview(b)
        if path == "/api/view":
            return view_info(SES.case, b)
        if path == "/api/hex":
            return hex_page(SES.case, b)
        if path == "/api/hexsearch":
            return hex_search(SES.case, b)
        if path == "/api/fileinfo":
            return file_details(SES.case, b)
        if path == "/api/simili":
            return phash_simili(SES.case, b)
        if path == "/api/filetext":
            return file_text(SES.case, b)
        if path == "/api/export":
            if fa.UA_RE.fullmatch(str(b.get("inode") or "")):
                return {"message": export_ua(SES.case, int(b["part"]), str(b["inode"]))}
            out = SES.case_tools["export_file"](int(b["part"]), str(b["inode"]))
            return {"message": out}
        if path == "/api/locate":
            fn = SES.case_tools.get("locate_offset")
            if not fn:
                raise ValueError(tr("Disponibile dopo il carving con bulk_extractor."))
            return {"message": fn(str(b["offset"]))}
        if path == "/api/finding":
            t = (b.get("title") or "").strip()
            if not t:
                raise ValueError(tr("Serve almeno un titolo."))
            SES.case_tools["record_finding"](t, (b.get("description") or "").strip(),
                                             (b.get("references") or "").strip())
            return {"findings": SES.case.findings()}
        if path == "/api/portable":
            import forense_portatile as fp
            opts = {k: b.get(k) for k in ("contenuto", "cancellati", "testi", "plaso", "tracce", "zip",
                                           "auto_mb")}
            run_task("portable", lambda progress: fp.export_portable(SES.case, opts, progress), True)
            return {"ok": True}
        if path == "/api/portable_estimate":
            import forense_portatile as fp
            return fp.estimate(SES.case)
        if path == "/api/open_portable":
            rel = Path(b.get("rel") or "")
            target = (SES.case.root / rel / "index.html").resolve()
            if SES.case.root.resolve() not in target.parents or not target.exists():
                raise ValueError(tr("Report non trovato."))
            import webbrowser
            webbrowser.open(target.as_uri())
            return {"ok": True}
        if path == "/api/reveal_path":
            rel = Path(b.get("rel") or "")
            target = (SES.case.root / rel).resolve()
            if SES.case.root.resolve() not in target.parents or not target.exists():
                raise ValueError(tr("Percorso non valido."))
            reveal(target)
            return {"ok": True}
        if path == "/api/llm_config":
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            if SES.busy:
                raise ValueError(tr("Attendi che l'agente finisca o interrompilo."))
            conf = fa.load_settings()
            modo = b.get("modo")
            if modo not in ("locale", "remoto"):
                raise ValueError(tr("Scelta del server non valida."))
            conf["modo"] = modo
            if modo == "remoto":
                url = (b.get("url") or "").strip()
                if not re.fullmatch(r"(https?://)?[\w.\-\[\]:]+(:\d+)?/?(v1/?)?", url):
                    raise ValueError(tr("Indirizzo non valido: es. 192.168.1.20 oppure http://192.168.1.20:8080"))
                conf["url"] = url
                if b.get("api_key") is not None:
                    conf["api_key"] = b["api_key"].strip()
            fa.save_settings(conf)
            with LOCK:
                SES.connect()
            return self.state()
        if path == "/api/reconnect":
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            with LOCK:
                SES.connect()
            return self.state()
        if path == "/api/ask":
            q = (b.get("q") or "").strip()
            if not q:
                raise ValueError(tr("Domanda vuota."))
            if not SES.messages:
                raise ValueError(tr("Il server LLM non è collegato."))
            if SES.busy:
                raise ValueError(tr("L'agente sta ancora lavorando."))
            SES.ask(q)
            return {"ok": True}
        if path == "/api/stop":
            SES.stop.set()
            return {"ok": True}
        if path == "/api/new_chat":
            if SES.busy:
                raise ValueError(tr("Attendi la fine della risposta o interrompi."))
            SES.save_conv()
            SES.new_conv()
            if SES.llm:
                SES.tools, SES.messages = fa.start_session(SES.case, SES.llm)
            return self.state()
        if path == "/api/report":
            p = fa.write_report(SES.case)
            return {"path": str(p), "text": p.read_text(encoding="utf-8")}
        if path == "/api/verify":
            if not SES.case.meta.get("sha256"):
                raise ValueError(tr("Lo SHA-256 della copia non è ancora stato calcolato "
                                 "(analisi speditiva): usa “Calcola hash copia”."))
            run_task("verify", lambda: fa.verify_hash(SES.case))
            return {"ok": True}
        if path == "/api/reveal":
            what = b.get("what")
            target = {"case": SES.case.root, "export": SES.case.export_dir,
                      "report": SES.case.root / "report.md"}.get(what)
            if target is None or not Path(target).exists():
                raise ValueError(tr("Elemento non ancora presente."))
            reveal(target)
            return {"ok": True}
        raise ValueError(tr("percorso sconosciuto"))

    def state(self):
        c = SES.case
        conf = fa.load_settings()
        return {"case": case_summary(c), "conv": SES.conv, "llm": SES.llm and
                {k: SES.llm.get(k) for k in ("backend", "url", "model", "ctx", "notes", "remoto")},
                "llm_error": SES.llm_error, "findings": c.findings(),
                "llm_conf": {"modo": conf["modo"], "url": conf["url"], "has_key": bool(conf["api_key"])}}


def free_port(start=8765):
    for port in range(start, start + 50):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(tr("Nessuna porta libera"))


def main():
    lg.segna_gui()
    port = free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"
    print(tr("{APP_NAME} {APP_BY} - pronto su {url}").format(APP_NAME=fa.APP_NAME, APP_BY=fa.APP_BY, url=url))
    print(tr("Lascia aperta questa finestra; per chiudere premi Ctrl+C."))
    if not os.environ.get("FORENSE_NO_BROWSER"):
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print(tr("\nChiuso."))
        try:
            SES.save_conv()
        except OSError:
            pass
        PREP.stop()


if __name__ == "__main__":
    main()
