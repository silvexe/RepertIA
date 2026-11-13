#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
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
from urllib.parse import urlparse, parse_qs, unquote

if __name__ == "__main__":     # (3.0.4) avviato come programma: «import forense_gui» negli altri moduli deve dare
    sys.modules.setdefault("forense_gui", sys.modules[__name__])   # questo stesso modulo, non una seconda copia

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import forense_agent as fa  # noqa: E402
import forense_diagnostica as fd  # noqa: E402
import forense_lingua as lg  # noqa: E402
from forense_lingua import tr, N_  # noqa: E402

TOKEN = secrets.token_urlsafe(24)


def tok_ok(t):
    """(3.0.1) Confronto del token a tempo costante."""
    return isinstance(t, str) and secrets.compare_digest(t.encode(), TOKEN.encode())
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
        self.av = {}               # (2.20) avanzamento per la barra: fase, fatti, totale, orari

    def start(self, root, image=None, plaso=False, carving=False, add=None, hash_file=False,
              no_hash=False, estese=False, vss=False, ocr=False, info=None, fuso=None, lingua=None, trascrizione=None,
              ram=False):
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
                   (["--fuso", fuso] if fuso else []) + (["--lingua", lingua] if lingua else []) + \
                   (["--trascrizione", json.dumps(trascrizione)] if trascrizione else []) + \
                   (["--ram"] if ram else [])          # (3.0.4) dump della memoria RAM
        self.lines, self.root, self.rc, self.ask, self.next_image = [], root, None, None, None
        self.add = add or "all"
        t = time.time()
        self.av = {"t0": t, "t_out": t}
        env = dict(os.environ, FORENSE_DA_GUI="1", PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
        extra = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if IS_WIN
                 else {"start_new_session": True})
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL if add else subprocess.PIPE, env=env, **extra)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for raw in self.proc.stdout:
            for line in fa.dec(raw).replace("\r", "\n").split("\n"):
                if line.strip():
                    self.av["t_out"] = time.time()
                if line.startswith(fa.ASK_MARK):       # domanda dell'agente: non va nel registro a video
                    self._on_ask(line[len(fa.ASK_MARK):])
                elif line.startswith(fa.AVANZ_MARK):   # (2.20) avanzamento per la barra: nemmeno questo va a video
                    self._on_avanz(line[len(fa.AVANZ_MARK):])
                elif line.strip():
                    self.lines.append(line.rstrip())
            if len(self.lines) > 5000:
                del self.lines[:1000]
        self.rc = self.proc.wait()
        if self.rc:
            fd.errore_processo(self.add, self.rc, self.lines)

    def _on_avanz(self, payload):
        try:
            d = json.loads(payload)
        except ValueError:
            return
        t = time.time()
        if d.get("fase"):
            self.av.update(fase=d["fase"], t_fase=t, fatti=None, totale=None, t_num=None, unita=None)
        if "fatti" in d:
            if self.av.get("fatti") is None:            # primo numero della fase: da qui si stima il tempo
                self.av["t_num"], self.av["n0"] = t, d["fatti"]
            self.av.update(fatti=d["fatti"], totale=d.get("totale"), unita=d.get("unita"))

    def avanz(self):
        """Avanzamento per /api/prep: secondi trascorsi (totale, fase, dall'ultima riga) e stima della fine."""
        a, t = self.av, time.time()
        if not a:
            return None
        r = {"fase": a.get("fase"), "fatti": a.get("fatti"), "totale": a.get("totale"), "unita": a.get("unita"),
             "tot_s": int(t - a["t0"]), "fase_s": int(t - a["t_fase"]) if a.get("t_fase") else None,
             "silenzio_s": int(t - a["t_out"]), "fine_s": None}
        f, tot, t1 = a.get("fatti"), a.get("totale"), a.get("t_num")
        if tot and f is not None and t1 and t - t1 > 20 and f > a.get("n0", 0):
            r["fine_s"] = int((t - t1) / (f - a["n0"]) * max(tot - f, 0))
        return r

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
        ev = {"n": len(self.events), "kind": kind, "data": data}
        if kind == "answer":                # (2.20.1) modello che ha scritto la risposta, per l'etichetta sotto
            ev["model"] = fa.MODEL
        self.events.append(ev)

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
            if url and fa.url_esterno(url) and conf.get("esterno_confermato") != url:
                raise fa.LLMError(tr("Il server {url} è fuori dalla rete locale: premi Collega e conferma l'avviso per "
                                     "usarlo.").format(url=url))
            # (3.0.4) modello scelto dall'analista nel menu; senza scelta vale FORENSE_MODEL o quello caricato nel server
            self.llm = fa.connect_llm(fa.BACKEND, url, conf.get("modello") or os.environ.get("FORENSE_MODEL", ""),
                                      int(os.environ.get("FORENSE_CTX") or 0),     # non fa.NUM_CTX: resterebbe quello del primo collegamento
                                      api_key=conf["api_key"] or fa.API_KEY)
            self.llm["notes"] = list(getattr(self, "note_modello", None) or []) + self.llm["notes"]
            self.note_modello = None
            if self.case:
                self.tools, self.messages = fa.start_session(self.case, self.llm)
                if self.saved_messages:
                    # conversazione ripresa: prompt di sistema aggiornato, storia invariata
                    self.messages = [self.messages[0]] + self.saved_messages[1:]
        except fa.LLMError as e:
            self.llm_error = str(e)
        except Exception as e:
            self.llm_error = tr("Errore di connessione al server LLM: {e}").format(e=e)

    def chiudi_caso(self):
        """(3.0) Torna alla Home senza caso aperto: solo così si può andare in rete per mappe e modelli."""
        if self.busy:
            raise ValueError(tr("L'agente sta lavorando: fermalo prima."))
        if self.case:
            import forense_database as fdb
            for sid in [k for k, v in fdb._SESS.items() if v["root"] == str(self.case.root)]:
                fdb.chiudi(self.case, {"id": sid})
        self.case = self.llm = self.tools = self.messages = self.conv = self.saved_messages = None
        self.case_tools = None
        self.events = []

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
            fa.gps_ripara(self.case)               # (3.0) segno delle coordinate delle foto
        except Exception:
            pass
        try:
            import forense_mobile_chat as fmc
            fmc.lid_ripara(self.case)              # (3.0) LID di WhatsApp associati al numero
        except Exception:
            pass
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
        text, questions = summary_cached(self.case, what)
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
    """Stringa per PowerShell tra apici singoli: si raddoppia ogni carattere che PowerShell prende per apice singolo,
    anche quelli tipografici ‘ ’ ‚ ‛ («Scegli l'elenco», «l’elenco»)."""
    return "'" + re.sub("([\'\u2018\u2019\u201a\u201b])", r"\1\1", str(t)) + "'"


def richiesta(d):
    """Parametri di una richiesta del browser senza le chiavi interne (iniziano con «_», es. _spec, _cfsel): quelle le
    aggiunge solo il server."""
    return {k: v for k, v in d.items() if not str(k).startswith("_")}


def _as_str(t):
    """Stringa per AppleScript tra virgolette doppie: le virgolette tipografiche “ ” „ ‟, che AppleScript può prendere
    per virgolette, diventano dritte con la barra davanti."""
    t = re.sub("[“”„‟]", '"', str(t))
    return '"' + t.replace("\\", "\\\\").replace('"', '\\"') + '"'


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


MODULI_OK = {}


def modulo_ok(mod):
    """(3.0) True se il modulo si carica davvero (non basta che il file ci sia: può mancare una libreria nativa)."""
    if mod not in MODULI_OK:
        try:
            __import__(mod)
            MODULI_OK[mod] = True
        except Exception:
            MODULI_OK[mod] = False
    return MODULI_OK[mod]


def ram_presente():
    try:
        import forense_ram as fr
        return fr.presente()
    except Exception:
        return False


def strumenti_stato(plaso, plaso_msg):
    """(3.0) Tutti gli strumenti che RepertIA usa, per gruppo: programmi trovati e moduli caricati. id = voce della spiegazione."""
    import forense_estesa as fe
    import forense_mobile_leapp as fml
    import forense_trascrizione as ftr
    w = lambda b: bool(shutil.which(b))
    mappa = Path(__file__).resolve().parent / "mappa" / "maplibre-gl.mjs"
    v = [("copie", "sleuthkit", "Sleuth Kit", all(shutil.which(b) for b in fa.TSK_BINS)),
         ("copie", "ewf", "libewf (E01)", w("ewfexport") or (IS_WIN and w("img_cat"))),
         *[("copie", m, n, modulo_ok(m)) for m, n in (("pytsk3", "pytsk3"), ("pyewf", "pyewf"), ("pyfsapfs", "libfsapfs (APFS)"),
                                                     ("pybde", "libbde (BitLocker)"), ("pyfvde", "libfvde (FileVault)"),
                                                     ("pyluksde", "libluksde (LUKS)"), ("pyvshadow", "libvshadow"))],
         ("contenuti", "exiftool", "exiftool", w("exiftool")), ("contenuti", "pdftotext", "Poppler (pdftotext)", w("pdftotext")),
         ("contenuti", "tesseract", "Tesseract (OCR)", bool(fe.tesseract())), ("contenuti", "7zip", "7-Zip", bool(fe.seven_zip())),
         ("contenuti", "ffmpeg", "FFmpeg", bool(ftr.ffmpeg())), ("contenuti", "whisper", "whisper.cpp", bool(ftr.exe())),
         ("contenuti", "PIL", "Pillow", modulo_ok("PIL")),
         ("analisi", "photorec", "PhotoRec", w("photorec")), ("analisi", "bulk_extractor", "bulk_extractor", fa.bulk_available()),
         ("analisi", "plaso", "plaso", plaso),
         ("analisi", "memprocfs", "MemProcFS (RAM)", ram_presente()),          # (3.0.4) dump della memoria RAM
         *[("artefatti", m, n, modulo_ok(m)) for m, n in (("pypff", "libpff"), ("pyregf", "libregf"), ("pyscca", "libscca"), ("pylnk", "liblnk"),
                                                         ("pyolecf", "libolecf"), ("pyevtx", "libevtx"), ("pyesedb", "libesedb"))],
         ("smartphone", "ileapp", "iLEAPP", bool(fml.tool_dir("ios"))), ("smartphone", "aleapp", "ALEAPP", bool(fml.tool_dir("android"))),
         ("altri", "maplibre", "MapLibre", mappa.is_file()), ("altri", "openai", "client openai", fa.OpenAI is not None)]
    out = [{"gruppo": g_, "id": i, "nome": n, "ok": bool(ok)} for g_, i, n, ok in v]
    out[[x["id"] for x in out].index("plaso")]["msg"] = plaso_msg
    out.append({"gruppo": "altri", "id": "soffice", "nome": "LibreOffice", "ok": bool(tool("soffice")), "facoltativo": True})
    return out


def requirements():
    plaso, _, plaso_msg = fa.plaso_status()
    w = lambda b: bool(shutil.which(b))
    return {
        "strumenti": strumenti_stato(plaso, plaso_msg),
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
        "fuso_dispositivo": {**m["fuso_dispositivo"], "origine": lg.valore(m["fuso_dispositivo"].get("origine"))} if m.get("fuso_dispositivo") else None,
        "fuso_stato": fa.fuso_stato_testo(m) if m.get("fuso_dispositivo") else "",
        "evidence": ev, "evidence_ok": Path(ev).exists() and Path(m.get("image", ev)).exists(),
        "converted": bool(m.get("converted_from_e01")),
        "disk_type": m.get("disk_type"), "disk_type_vis": lg.valore(m.get("disk_type")),
        "partitions": [{**p, "fs": lg.valore(p.get("fs"))} for p in m.get("partitions", [])],
        "sha256": m.get("sha256"), "sha256_ts": m.get("sha256_ts"),
        "sha256_differito": bool(m.get("sha256_differito")), "timeline": m.get("timeline"),
        "verifiche": m.get("verifiche", []), "findings": len(c.findings()),
        "riscontri": m.get("riscontri") or [],
        "hash_dati": m.get("hash_dati"), "hash_dati_testo": fa.hash_dati_testo(m.get("hash_dati")) if m.get("hash_dati") else "",
        "indice": m.get("indice"), "carving": m.get("carving"), "hash_file": m.get("hash_file"), "gps_corretto": m.get("gps_corretto"),
        "complete": "timeline" in m, "estese": m.get("estese") or {}, "volumi_cifrati": m.get("volumi_cifrati") or [],
        "decifrate": m.get("decifrate") or [], "derivata": m.get("derivata"), "liste_hash": m.get("liste_hash"),
        "apfs_bloccati": apfs_bloccati(c),
        "tipo_caso": m.get("tipo_caso") or "disco", "drone": bool(m.get("drone")), "logica": bool(m.get("logica")), "ram": bool(m.get("ram_dump")),
        **(_mobile_summary(c) if fa.is_mobile(c) else {}),
    }


def _mobile_summary(c):
    import forense_mobile_gui as fmg
    return fmg.summary(c)


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
    elif what == "ram":                 # (3.0.4) dump della memoria RAM: serve MemProcFS
        import forense_ram as fr
        ok, motivo = fr.disponibile()
        if not ok:
            raise ValueError(motivo)
    elif what == "ocr":
        if not fe_mod().tesseract():
            raise ValueError(tr("Per l'OCR serve Tesseract: ") + (tr("reinstalla RepertIA o esegui 'Aggiorna strumenti'")
                                                             if IS_WIN else tr("in Terminale esegui brew install tesseract")
                                                             if fa.IS_MAC else tr("in Terminale esegui {v1}").format(v1=fa.install_hint("tesseract"))))
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
    elif what == "trascrizione":        # (2.20) motore, ffmpeg e modello scelto (installato con il consenso)
        import forense_trascrizione as ftr
        if not ftr.exe() or not ftr.ffmpeg():
            raise ValueError(tr("Motore di trascrizione o ffmpeg non trovati: reinstalla RepertIA."))
        mid = ((SES.case.meta if SES.case else {}).get("trascrizione_opzioni") or {}).get("modello")
        if mid not in ftr.installed():
            raise ValueError(tr("Il modello scelto non è installato: installalo dalla finestra della trascrizione."))
    elif what == "indice" and not shutil.which("exiftool"):
        raise ValueError(tr("Manca exiftool: {v1} (o 'Aggiorna strumenti').").format(v1=fa.install_hint('exiftool poppler')))


def trascr_check(o):
    """(2.20) Trascrizione scelta alla creazione del caso: opzioni ripulite (None se non scelta); motore, ffmpeg e
    modello devono esserci già (il modello si installa prima, con il consenso, dalla pagina del nuovo caso)."""
    if not o:
        return None
    import forense_trascrizione as ftr
    o = ftr.opzioni(o)
    o["scope"] = "tutti" if o["scope"] == "selezione" else o["scope"]
    o.pop("scelti", None)
    if not ftr.exe() or not ftr.ffmpeg():
        raise ValueError(tr("Motore di trascrizione o ffmpeg non trovati: reinstalla RepertIA."))
    if o["modello"] not in ftr.installed():
        raise ValueError(tr("Il modello scelto non è installato: installalo dalla finestra della trascrizione."))
    return o


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
            "meta": media_tutti_conta(con, bool(media_contenuto(case, con))) if has("meta") else None,
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


# ------------------------------------------------- filtri per colonna  → forense_gui_filtri.py (3.0.4)
from forense_gui_filtri import (  # noqa: E402,F401
    cf_parse, cf_terms, CfValues, CALL_VERSI, cf_apply, cf_order, cf_values, _sql_lit, cf_timeline, CF_META,
    CF_CARVED, CF_DOC, file_dati, cf_file_dati, cf_hits, tl_where, results, _results)


# ------------------------------------------------- fuso orario (UTC -> ora italiana / fuso rilevato)  → forense_gui_fuso.py (3.0.4)
from forense_gui_fuso import (  # noqa: E402,F401
    ZoneInfo, _ROME, TS_RE, _ZCACHE, _zone_obj, tz_zone, tz_label, _off_tag, _rome_dt, _zone_dt, to_zone, to_rome,
    local_to_utc_str, _FILE_AFTER, _ts_is_text, md_to_zone_ex, md_to_rome_ex, md_to_rome, fmt_ts, ISTAT_TS, UTC_NEL_TESTO, testo_fuso, DATA_CON_SIGLA, MESI_BREVI, data_fmt, date_vista,
    _istat_walk, NO_DEV_NOTE, istat_to_zone, TOK_A, TOK_B, istat_tokens, apfs_istat_tokens, apfs_istat_to_zone,
    _EXIF_DT, exif_to_zone, _WORKCOPY_TAGS, exif_no_workcopy, taken_tz_text, tl_e_preferiti, tl_evidenze_sql,
    tl_evidenze_pagina, tl_hist_da, tl_hist_evidenze, tl_preferito_campi, tl_preferiti_cf, tl_preferiti_valori,
    tl_preferiti, tl_hist_preferiti, tl_hist)


# ------------------------------------------------- albero del file system  → forense_gui_albero.py (3.0.4)
from forense_gui_albero import (  # noqa: E402,F401
    NAV_LOCK, NAV_STATE, EV_RE, NAV_COLS, nav_file, nav_stamp, ensure_nav, build_nav, nav_attach, nav_db, nav_tree,
    nav_list, known_attach, clean_fs_path, _sysdiag_di, nav_locate)


# ------------------------------------------------- selezioni ed esportazioni  → forense_gui_esporta.py (3.0.4)
from forense_gui_esporta import (  # noqa: E402,F401
    selected_rows, canc_txt, ref_label, CSV_COLS, stamp_now, unique, export_csv, export_targets, WIN_RESERVED,
    safe_part, lp, chat_targets, export_selection, selection_refs, preview)


# ------------------------------------------------- anteprime, miniature, esadecimale  → forense_gui_anteprime.py (3.0.4)
from forense_gui_anteprime import (  # noqa: E402,F401
    base64, hashlib, tempfile, CACHE_MAX, THUMB_SEM, THUMB_GEN, PAGE_SEM, PAGE_BLOCK, LO_LOCK, KEY_LOCKS, KEY_LOCK,
    IMG_NATIVE, IMG_CONVERT, IMG_ALL, WORD_EXT, OFFICE_EXT, VIDEO_MIME, HEIF_BRANDS, video_brand, VIDEO_OTHER,
    VIDEO_EXT, video_where, video_args, PHOTO_EXT, photo_where, photo_args, AUDIO_MIME, AUDIO_EXT, audio_where,
    audio_from, altri_where, altri_args, media_tutti_from, audio_senza_meta, media_tutti_conta, trascr_where,
    media_contenuto, TEXT_LIKE, RAW_MIME, IS_LINUX, tool, run_quiet, safe_key, safe_ext, cache_dir, CACHE_LIMIT,
    prune_cache, CACHE_SUBS, _tree_size, cache_info, _rm_force, cache_clear, cache_set, copy_case, UA_ID_BASE,
    UA_CACHE_MAX, UA_JOBS, UA_LOCK, ua_cache_file, ua_runs, ua_job, ua_name, ua_ident, ua_stream, item_stream,
    export_ua, ua_list, file_ident, key_lock, cached_file, file_size, read_range, iter_chunks, hex_page, hex_search,
    sniff_mime, to_jpeg, make_thumb, thumb_bytes, thumb_put, office_pdf, pdf_pages, page_png, converted_image,
    CSP_DOC, word_html, printable_ratio, decode_text, media_url, ext_contenuto, view_info, file_details,
    FULL_TEXT_MAX, carved_full_text, file_text)


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


# ------------------------------------------------- segnalibri (categorie di file)  → forense_gui_segnalibri.py (3.0.4)
from forense_gui_segnalibri import (  # noqa: E402,F401
    BM_MAX, bm_categories, _oid, item_ref, _item_ref, bm_add, trascr_categoria, bm_list, bm_timeline_csv, bm_remove,
    bm_cat_update, bm_cat_delete)


# ------------------------------------------------- immagine, tracce e file di plaso  → forense_gui_immagine.py (3.0.4)
from forense_gui_immagine import (  # noqa: E402,F401
    IMG_SIZE, BSIZE, IMG_SEARCH_WINDOW, image_ident, image_read, image_chunks, _fs_block_size, _istat_blocks,
    trace_locate, trace_paths, plaso_fs_path, resolve_path, tl_resolve, export_reveal, reveal_trace, DOC_EXT_RE,
    doc_ext_counts, _MEMO, _MEMO_LOCK, case_stamp, _MEMO_KEYLOCK, MEMO_DISCO_MAX, _META_FIRMA, META_VOLATILI,
    meta_firma, memo_disco_stamp, memo_disco_file, memo_disco_leggi, memo_disco_scrivi, memo, res_tree)


# ------------------------------------------------- report in PDF e Word  → forense_gui_report.py (3.0.4)
from forense_gui_report import (  # noqa: E402,F401
    md_blocks, md_runs, _HELV, _HELVB, _pdf_char, _pdf_w, PdfDoc, ia_meta_testo, report_pdf, _x, _docx_runs,
    report_docx, report_export, html_mod)


# ------------------------------------------------- analisi estese: risultati, anteprime, azioni  → forense_gui_estese.py (3.0.4)
from forense_gui_estese import (  # noqa: E402,F401
    EXT_KINDS, X_COLS, ext_counts, ext_results, cited_ref, cited_rows, cited_info, ext_tree, x_ident, phash_simili,
    X_KIND_LBL, x_details, x_text, fe_mod, mail_view, art_view, art_campi, _art_campi, sqlite_view, export_x,
    x_targets, ext_ref_label, EXT_CSV, x_search_items, raw_image_search, decrypt_task, hashlist_add, term_regex,
    byte_regexes, snippet, byte_snippet, search_universe, carved_universe, file_chunks, local_chunks, run_search,
    hits_list, _occupato, fast_search, _fast_search, fast_search_gruppo, fast_search_save, search_list,
    search_delete, summary_cached, diag_testo, senza_caso, aggiornamenti_stato, aggiornamenti_post, run_task)


# ----------------------------------------------------------- HTTP

BIN_PATHS = {"/api/thumb", "/api/page", "/api/conv", "/api/raw", "/api/mobile/leapp_media", "/api/mobile/att_thumb", "/api/mappa_pm"}
MAPPA_FILE = {"maplibre-gl.mjs": "text/javascript", "maplibre-gl-worker.mjs": "text/javascript", "maplibre-gl-shared.mjs": "text/javascript",
              "maplibre-gl.css": "text/css", "pmtiles.js": "text/javascript", "ne_50m.geojson": "application/json"}


# Richieste che producono testi del caso (report, esportazioni, riscontri, verifiche): nella lingua del caso,
# scelta alla sua creazione; tutte le altre nella lingua dell'interfaccia.
CASE_LANG_PATHS = {"/api/report", "/api/report_export", "/api/relazione", "/api/relazione_opzioni", "/api/export", "/api/export_x", "/api/portable", "/api/mobile/export_chat",
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
        # (3.0.1) le pagine del programma non si incorniciano in siti esterni (clickjacking); la guida resta nel riquadro interno
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Content-Security-Policy", "frame-ancestors 'self'")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str))

    def _caso_cambiato(self, path):
        """(3.0) Il server tiene un solo caso: una scheda rimasta su un altro caso non deve ricevere né scrivere i dati di questo.
        La scheda dichiara il suo caso in X-Caso; si risponde 409 e la pagina si blocca con un avviso."""
        dichiarato = unquote(self.headers.get("X-Caso") or "")
        if not dichiarato or not SES.case or path == "/api/open" or dichiarato == str(SES.case.root):
            return False
        self._json({"caso_cambiato": True, "aperto": SES.case.root.name, "error": tr("Questa scheda è rimasta su un altro caso.")}, 409)
        return True

    def _allowed(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")

    def do_GET(self):
        if not self._allowed():
            return self._send(403, "vietato", "text/plain")
        u = urlparse(self.path)
        if u.path == "/":
            html = (HERE / "forense_gui.html").read_text(encoding="utf-8")
            if (HERE / "forense_mobile.html").exists():      # parte smartphone (2.20), se inclusa nel pacchetto
                import forense_mobile_gui as fmg
                html = html.replace("<!--REPERTIA_MOBILE-->", fmg.fragment())
            return self._send(200, html.replace("__TOKEN__", TOKEN).replace("__VERSIONE__", fa.APP_VERSION).replace("__LINGUA__", lingua_js()), "text/html")
        q = richiesta({k: v[0] for k, v in parse_qs(u.query).items()})
        if u.path == "/guida/guida.html":       # (3.0) guida in italiano e inglese, nessun dato del caso
            f = HERE / "guida" / "guida.html"
            if not f.is_file():
                return self._send(404, tr("Guida non inclusa in questo pacchetto."), "text/plain")
            return self._send(200, f.read_bytes(), "text/html")
        if u.path.startswith("/mappa/"):        # (3.0) componenti della mappa, solo l'elenco chiuso: nessun dato del caso
            nome = unquote(u.path[7:])
            font = re.fullmatch(r"fonts/Noto Sans (Regular|Medium|Italic)/\d+-\d+\.pbf", nome)     # scritte della mappa
            if (not font and nome not in MAPPA_FILE) or not (HERE / "mappa" / nome).is_file():
                return self._send(404, "", "text/plain")
            dati = (HERE / "mappa" / nome).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/x-protobuf" if font else MAPPA_FILE[nome])
            self.send_header("Content-Length", str(len(dati)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(dati)
            return
        if u.path in BIN_PATHS:
            # immagini e media: <img>/<video> non possono mandare intestazioni, il codice
            # arriva nell'indirizzo (resta comunque solo su 127.0.0.1)
            if not (tok_ok(q.get("t")) or tok_ok(self.headers.get("X-Token"))):
                return self._send(403, "vietato", "text/plain")
            try:
                return self.binary(u.path, q)
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception as e:
                return self._send(404, str(e), "text/plain")
        if not tok_ok(self.headers.get("X-Token")):
            return self._send(403, tr("token mancante"), "text/plain")
        if self._caso_cambiato(u.path):
            return
        try:
            self._json(self.get(u.path, q))
        except Exception as e:
            fd.errore("GET " + u.path, e)
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
        if path == "/api/mappa_pm":          # (3.0) estratto PMTiles locale, a richieste Range
            import forense_mappe as fmp
            f = fmp.percorso_mappa(q.get("n"))
            size = f.stat().st_size
            m = re.match(r"bytes=(\d+)-(\d*)", self.headers.get("Range") or "")
            start = int(m.group(1)) if m else 0
            end = min(int(m.group(2)) if m and m.group(2) else size - 1, size - 1)
            self.send_response(206 if m else 200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", str(max(0, end - start + 1)))
            if m:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            with open(f, "rb") as fh:
                fh.seek(start)
                self.wfile.write(fh.read(max(0, end - start + 1)))
            return
        if path == "/api/thumb":
            r = thumb_bytes(SES.case, q)
            if not r:
                return self._send(404, tr("nessuna miniatura"), "text/plain")
            return self._bin(r[0], r[1])
        if path == "/api/page":
            return self._bin(page_png(SES.case, q), "image/jpeg")
        if path == "/api/mobile/leapp_media":            # allegati copiati da iLEAPP/ALEAPP nel loro rapporto (2.20)
            import forense_mobile_gui as fmg
            data, ctype = fmg.leapp_media(SES.case, q)
            return self._bin(data, ctype)
        if path == "/api/mobile/att_thumb":              # miniatura di un allegato salvata nel database dell'app (2.20)
            import forense_mobile_gui as fmg
            data, ctype = fmg.att_thumb(SES.case, q)
            return self._bin(data, ctype)
        if path == "/api/conv":
            return self._bin(converted_image(SES.case, q), "image/jpeg")
        if path == "/api/raw":
            it = file_ident(SES.case, q)
            size, f = file_size(SES.case, it)
            if not f:
                raise ValueError(tr("File troppo grande per l'anteprima."))
            data_head = open(f, "rb").read(16)
            # mai HTML/SVG/script: solo immagini e media dichiarati per tipo
            ctype = RAW_MIME.get(ext_contenuto(it["ext"], data_head)) or sniff_mime(data_head) or \
                VIDEO_MIME.get(video_brand(it["ext"], data_head) or "") or "application/octet-stream"
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
        if not self._allowed() or not tok_ok(self.headers.get("X-Token")):
            return self._send(403, "vietato", "text/plain")
        n = int(self.headers.get("Content-Length") or 0)
        u = urlparse(self.path)
        if self._caso_cambiato(u.path):
            self.rfile.read(n)
            return
        if u.path == "/api/dettatura":          # (3.0) corpo audio, non JSON: non viene salvato né entra nel caso
            try:
                import forense_trascrizione as ftr
                if n <= 0 or n > ftr.DETTATURA_MAX:
                    raise ValueError(tr("Registrazione vuota o troppo lunga."))
                testo, mid, durata = ftr.dettatura(self.rfile.read(n), lg.lingua())
                if SES.case:
                    SES.case.log("dettatura", {"modello": mid, "durata_s": durata})
                return self._json({"testo": testo})
            except Exception as e:
                fd.errore("POST /api/dettatura", e)
                return self._json({"error": str(e)}, 400)
        if u.path == "/api/thumb_put":          # (2.20) corpo JPEG, non JSON
            try:
                if not SES.case:
                    raise ValueError(tr("Nessun caso aperto."))
                if n <= 0 or n > (2 << 20):
                    raise ValueError(tr("Miniatura non valida."))
                data = self.rfile.read(n)
                q = richiesta({k: v[0] for k, v in parse_qs(u.query).items()})
                return self._json({"ok": True, "salvata": thumb_put(SES.case, q, data)})
            except Exception as e:
                return self._json({"error": str(e)}, 400)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
            if isinstance(body, dict):
                body = richiesta(body)
            path = urlparse(self.path).path
            with lg.usa(lg.lingua_caso(SES.case) if SES.case and path in CASE_LANG_PATHS else lg.lingua()):
                self._json(self.post(path, body))
        except Exception as e:
            fd.errore("POST " + urlparse(self.path).path, e)
            self._json({"error": str(e)}, 400)

    # --- GET
    def get(self, path, q):
        if path.startswith("/api/mobile/"):           # casi smartphone (2.20)
            import forense_mobile_gui as fmg
            return fmg.get(sys.modules[__name__], path, q)
        if path == "/api/aggiornamenti":
            return aggiornamenti_stato()
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
                    "av": PREP.avanz(),
                    "root": str(PREP.root) if PREP.root else None}
        if path == "/api/events":
            since = int(q.get("since", 0))
            return {"events": SES.events[since:], "busy": SES.busy,
                    "findings": SES.case.findings() if SES.case else []}
        if path == "/api/ram/simboli_stato":    # (3.0.4) simboli di debug di Windows già scaricati (nessuna rete)
            import forense_ram as fr
            return fr.simboli_stato()
        if path == "/api/trascr/stato":         # (2.20) motore, ffmpeg e modelli della trascrizione
            import forense_trascrizione as ftr
            return ftr.stato()
        if path == "/api/trascr/segmenti":
            import forense_trascrizione as ftr
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            return {"trascrizioni": ftr.segmenti(SES.case, q.get("part"), q.get("inode")),
                    "analista": ftr.analista_storico(SES.case, q.get("part"), q.get("inode"))}
        if path == "/api/results":
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            return results(SES.case, q)
        if path == "/api/counts":
            return memo(SES.case, ("counts",), lambda: counts(SES.case))
        if path == "/api/tl_hist":
            if q.get("origin") == "preferiti":      # (3.0) cambiano senza cambiare i risultati del caso: niente memoria
                return tl_hist(SES.case, q)
            return memo(SES.case, ("tl_hist",) + tuple(sorted((k, str(v)) for k, v in q.items())), lambda: tl_hist(SES.case, q))
        if path == "/api/tree":
            return nav_tree(SES.case, q)
        if path == "/api/searches":
            return {"searches": search_list(SES.case)}
        if path == "/api/ricerca_veloce":           # (2.20) ricerca veloce nei risultati del caso
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            return fast_search(SES.case, q)
        if path == "/api/foto_gps":                 # (3.0) coordinate di un file, per «Vedi sulla mappa»
            con = fa.db_ro(SES.case)
            try:
                r = con.execute("SELECT lat, lon FROM meta WHERE part=? AND inode=? AND lat IS NOT NULL LIMIT 1", (q.get("part"), q.get("inode"))).fetchone() \
                    if fa.table_exists(con, "meta") else None
            finally:
                con.close()
            return {"lat": r[0], "lon": r[1]} if r else {}
        if path == "/api/bm_timeline":
            return {"rows": fa.bookmarks_timeline(SES.case, False, q.get("cid"))}
        if path == "/api/diag_preview":
            return {"testo": diag_testo()}
        if path == "/api/bm_cats":
            return {"cats": bm_categories(SES.case)}
        if path == "/api/res_tree":
            return memo(SES.case, ("res_tree",), lambda: res_tree(SES.case))
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
        if path.startswith("/api/mobile/"):           # casi smartphone (2.20)
            import forense_mobile_gui as fmg
            return fmg.post(sys.modules[__name__], path, b)
        if path == "/api/aggiornamenti":          # (3.0.1) avviso di nuove versioni: solo lettura dell'ultima release
            return aggiornamenti_post(b)
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
        if path == "/api/ram/simboli":         # (3.0.4) simboli di debug per un dump: solo senza caso e con il consenso
            import forense_ram as fr
            if b.get("accetto") is not True:
                raise ValueError(tr("Lo scarico dei simboli richiede che l'analista accetti le condizioni di Microsoft."))
            senza_caso()
            dump = clean_path(b.get("dump") or "")
            if not dump or not Path(dump).expanduser().is_file():
                raise ValueError(tr("File del dump non trovato."))
            run_task("ram_simboli", lambda progress: fr.scarica_simboli(Path(dump).expanduser(), True, progress), True)
            return {"ok": True}
        if path == "/api/ram/scegli_dump":
            p = choose_file(tr("Scegli il dump della memoria RAM"), kind="any")
            return {"path": p} if p else {"cancelled": True}
        if path == "/api/ram/simboli_cartella":
            import forense_ram as fr
            st = fr.simboli_stato()
            d = Path(st["condizioni"] if b.get("condizioni") else st.get("cartella") or "")
            if not st.get("cartella") or not d.exists():
                raise ValueError(tr("Percorso non valido."))
            reveal(d)
            return {"ok": True}
        if path == "/api/trascr/scarica":      # (2.20) modello di trascrizione: solo con il consenso dell'analista
            import forense_trascrizione as ftr
            if b.get("accetto") is not True:
                raise ValueError(tr("Il download del modello richiede il consenso dell'analista."))
            senza_caso()
            mid, case = b.get("modello"), SES.case
            run_task("trascr_modello", lambda progress: ftr.scarica(mid, True, progress, case), True)
            return {"ok": True}
        if path == "/api/trascr/importa":
            import forense_trascrizione as ftr
            p = choose_file(tr("Scegli il file del modello (ggml-….bin)"), kind="any")
            if not p:
                return {"cancelled": True}
            case, mid, sha, dich = SES.case, b.get("modello"), b.get("sha256"), b.get("dichiarato")
            run_task("trascr_modello", lambda progress: ftr.importa(p, progress, case, mid, sha, dich), True)
            return {"ok": True, "path": p}
        if path == "/api/trascr/analista":     # (3.0.1) trascrizione rivista dall'analista: bozza o confermata
            import forense_trascrizione as ftr
            case = SES.case
            if not case:
                raise ValueError(tr("Nessun caso aperto."))
            r = ftr.salva_analista(case, b.get("part"), b.get("inode"), b.get("testo"), b.get("conferma") is True, b.get("operatore"))
            trascr_categoria(case, r, b.get("part"), b.get("inode"))
            return r
        if path == "/api/trascr/dichiarato":   # (3.0.1) SHA-256 che Hugging Face dichiara ora per il modello (solo senza caso)
            import forense_trascrizione as ftr
            senza_caso()
            try:
                d = ftr.dichiarato(b.get("modello"))
            except Exception as e:
                return {"errore": str(e)[:200]}
            return {**d, "uguale": d["sha256"] == ftr.BY_ID[b.get("modello")]["sha256"]}
        if path == "/api/trascr/cartella":     # (2.20) apre la cartella dei modelli nel Finder / Esplora risorse
            import forense_trascrizione as ftr
            reveal(ftr.models_dir())
            return {"ok": True}
        if path == "/api/trascr/rimuovi":
            import forense_trascrizione as ftr
            return ftr.rimuovi(b.get("modello"), SES.case)
        if path == "/api/registro_scegli":         # (2.20) verifica del registro: file audit_log.jsonl o cartella del caso
            p = (choose_folder(tr("Scegli la cartella del caso")) if b.get("folder")
                 else choose_file(tr("Scegli il registro audit_log.jsonl"), kind="any"))
            return {"path": p} if p else {"cancelled": True}
        if path == "/api/registro_verifica":       # (2.20) ricalcolo della catena del registro (anche di un altro caso)
            import forense_registro as frg
            own = bool(b.get("caso"))
            if own and not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            src = SES.case.root if own else Path(clean_path(b.get("path") or "")).expanduser()
            hf = (b.get("hash") or "").strip() or None
            vo = str(b.get("voci") or "").strip()
            if vo and not vo.isdigit():
                raise ValueError(tr("Il numero di voci deve essere un numero intero."))
            try:
                R = frg.verifica(src, hf, int(vo) if vo else None)
            except FileNotFoundError as e:
                raise ValueError(str(e))
            out = {"esito": frg.esito_breve(R), "integro": R["integro"], "testo": frg.testo(R), "voci": R["voci"],
                   "hash_finale": R["hash_finale"], "atteso": R.get("atteso"),
                   "file_diversi": len((R.get("esportati") or {}).get("diversi") or []) + len(((R.get("esportati") or {}).get("manifest") or {}).get("diversi") or [])}
            if own:                                 # la verifica del caso aperto resta nel suo registro (dopo le righe verificate)
                SES.case.log("verifica_registro", {"esito": out["esito"], "voci": R["voci"], "hash_finale": R["hash_finale"],
                                                   "hash_atteso": hf, "voci_attese": int(vo) if vo else None,
                                                   "file_diversi": out["file_diversi"]})
            return out
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
                                    else tr("in Terminale esegui brew install sleuthkit libewf") if fa.IS_MAC
                                    else tr("in Terminale esegui {v1}").format(v1=fa.install_hint("sleuthkit libewf"))))
            if not dest:
                fa.CASES_HOME.mkdir(parents=True, exist_ok=True)
            if b.get("plaso"):
                addon_check("plaso")
            if b.get("carving"):
                addon_check("carving")
            if b.get("ram"):
                addon_check("ram")
            if b.get("ocr"):
                addon_check("ocr")
            tro = trascr_check(b.get("trascrizione"))
            PREP.start(Path(info["case_root"]), image=info["path"], plaso=bool(b.get("plaso")),
                       carving=bool(b.get("carving")), hash_file=bool(b.get("hash_file")),
                       no_hash=bool(b.get("no_hash")), estese=bool(b.get("estese")),
                       vss=bool(b.get("vss")), ocr=bool(b.get("ocr")),
                       info=fa.info_caso_clean(b.get("info")), fuso=fuso, lingua=lg.valida(b.get("lingua") or lg.lingua()),
                       trascrizione=tro, ram=bool(b.get("ram")))
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
            if what == "trascrizione":       # (2.20) opzioni scelte dall'analista: le legge il sottoprocesso
                o = b.get("opzioni") or {}
                o = {"scope": o.get("scope") if o.get("scope") in ("chat", "tutti", "selezione") else "chat",
                     "modello": str(o.get("modello") or ""), "lingua": str(o.get("lingua") or "auto")[:8],
                     "rifai": bool(o.get("rifai")), "max_min": float(o.get("max_min") or 0),
                     "scelti": []}
                if o["scope"] == "selezione" and (b.get("opzioni") or {}).get("scelti"):   # un audio dall'anteprima
                    o["scelti"] = [[int(pt), str(ino)] for pt, ino in b["opzioni"]["scelti"]][:200]
                if o["scope"] == "selezione" and b.get("sel"):     # selezione corrente (come per i Preferiti)
                    kind, rows = selected_rows(SES.case, b["sel"])
                    fs, _c, _s = export_targets(SES.case, kind, rows)
                    o["scelti"] = [[int(pt), str(ino)] for pt, ino, _p in fs][:200000]
                if o["scope"] == "selezione" and not o["scelti"]:
                    raise ValueError(tr("Nessun audio selezionato."))
                SES.case.meta["trascrizione_opzioni"] = o
                SES.case.save()
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
        if path == "/api/cited":
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            return cited_info(SES.case, b)
        if path == "/api/resolve_path":
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            return resolve_path(SES.case, b)
        if path == "/api/item_ref":
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            return {"text": item_ref(SES.case, b)}
        if path == "/api/search_start":
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            case = SES.case
            run_task("search", lambda progress: run_search(case, b, progress), True)
            return {"ok": True}
        if path == "/api/ricerca_veloce_salva":     # (2.20) ricerca veloce salvata come ricerca del caso
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            return fast_search_save(SES.case, b)
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
        if path == "/api/bm_timeline_csv":
            return bm_timeline_csv(SES.case, b)
        if path == "/api/copy_link":
            cp = clean_path(b.get("path") or "")
            if not cp:
                raise ValueError(tr("Indica il percorso della copia forense."))
            run_task("copylink", lambda progress: fa.collega_copia(SES.case, cp, bool(b.get("conferma")), progress), True)
            return {"root": str(SES.case.root)}
        if path == "/api/diag_save":
            d = choose_folder(tr("Scegli dove salvare il log diagnostico"))
            if not d:
                return {"cancelled": True}
            f = unique(Path(d) / f"RepertIA_diagnostica_{stamp_now()}.txt")
            f.write_text(diag_testo(), encoding="utf-8")
            return {"path": str(f)}
        if path == "/api/diag_js":
            fd.evento("errore_pagina", messaggio=b.get("messaggio"), riga=int(b.get("riga") or 0), colonna=int(b.get("colonna") or 0))
            return {"ok": True}
        if path == "/api/caso_chiudi":          # (3.0)
            SES.chiudi_caso()
            return {"ok": True}
        if path.startswith("/api/mappa_"):      # (3.0)
            import forense_mappe as fmp
            import forense_mappe_scarica as fms
            if path == "/api/mappa_punti":
                return fmp.punti(SES.case)
            if path == "/api/mappa_esporta":
                return fmp.esporta(sys.modules[__name__], SES.case, b)
            if path == "/api/mappa_preferito":
                return fmp.preferito(SES.case, b, sys.modules[__name__])
            if path == "/api/mappa_voli_cerca":     # sui file del caso: nessuna rete
                import forense_droni as fdr
                case = SES.case
                run_task("voli", lambda progress: fdr.run(case, lambda m: progress({"msg": m})), True)
                return {"ok": True}
            if path == "/api/mappa_kml_dati":
                return fmp.livello_kml(SES.case, b.get("n") or 0)
            if path == "/api/mappa_usa":
                return fmp.usa_mappa(SES.case, b.get("id"))
            if path == "/api/mappa_kml":
                scelto = b.get("path") or choose_file(tr("Scegli il file KML"), kind="any")
                return fmp.importa_kml(SES.case, scelto) if scelto else {"annullato": True}
            if path == "/api/mappa_file":        # «Ho già un file»: nessuna rete
                scelto = b.get("path") or choose_file(tr("Scegli l'estratto PMTiles"), kind="any")
                return {"mappe": fmp.aggiungi_file(scelto)} if scelto else {"annullato": True}
            if path == "/api/mappa_cartella":
                reveal(fms.cartella())
                return {"ok": True}
            if path == "/api/mappa_elenco":
                return {"mappe": fmp.mappe(), "cartella": str(fms.cartella()), "zone": [{k: z[k] for k in ("id", "it", "en", "continente")} for z in fms.elenco_zone()]}
            if path == "/api/mappa_rimuovi":
                return {"mappe": fmp.rimuovi_mappa(b.get("id"))}
            senza_caso()
            zona = next((z for z in fms.elenco_zone() if z["id"] == b.get("zona")), None) if b.get("zona") != "mondo" else {"id": "mondo", "it": tr("Mondo"), "en": "World", "parti": []}
            zm = fms.LIVELLI.get(b.get("livello"))
            if not zona or zm is None:
                raise ValueError(tr("Zona o livello non validi."))
            if zona["id"] == "mondo":
                zm = 6
            if path == "/api/mappa_stima":
                run_task("mappa_stima", lambda progress: {**fms.stima(fms.ultima_data().replace(".pmtiles", ""), zona["parti"], zm, progress), "url": fms.BASE}, True)
                return {"ok": True}
            if path == "/api/mappa_annulla":
                fms.ANNULLA.set()
                return {"ok": True}
            if path == "/api/mappa_scarica":
                if b.get("accetto") is not True:
                    raise ValueError(tr("Lo scaricamento richiede il consenso dell'analista."))
                nome = zona["it"] if lg.lingua() == "it" else zona["en"]

                def lavoro(progress):
                    data = fms.ultima_data().replace(".pmtiles", "")
                    return fms.scarica(nome, zona["parti"], zm, data, fms.cartella() / f"{zona['id']}_z{zm}_{data}.pmtiles", progress)
                run_task("mappa_scarica", lavoro, True)
                return {"ok": True}
            raise ValueError(tr("percorso sconosciuto"))
        if path in ("/api/db_apri", "/api/db_query", "/api/db_csv", "/api/db_preferito", "/api/db_reperto", "/api/db_chiudi",
                    "/api/db_recuperati", "/api/db_riscontro", "/api/db_hex", "/api/db_rec_csv", "/api/db_rec_reperto", "/api/db_scegli_csv", "/api/db_cerca", "/api/db_elenco"):   # (3.0)
            import forense_database as fdb
            g = sys.modules[__name__]
            if path == "/api/db_apri":
                return fdb.apri(g, SES.case, b)
            if path == "/api/db_query":
                return fdb.query(SES.case, b)
            if path == "/api/db_csv":
                return fdb.esporta_csv(g, SES.case, b)
            if path == "/api/db_preferito":
                return fdb.preferito(g, SES.case, b)
            if path == "/api/db_cerca":
                return fdb.cerca(SES.case, b)
            if path == "/api/db_elenco":
                return fdb.elenco(g, SES.case)
            if path == "/api/db_recuperati":
                return fdb.recuperati(SES.case, b)
            if path == "/api/db_riscontro":
                return fdb.riscontro_csv(SES.case, b)
            if path == "/api/db_hex":
                return fdb.esadecimale(SES.case, b)
            if path == "/api/db_rec_csv":
                return fdb.esporta_recuperati(g, SES.case, b)
            if path == "/api/db_rec_reperto":
                return fdb.reperto_recuperato(g, SES.case, b)
            if path == "/api/db_scegli_csv":
                return {"path": choose_file(tr("Scegli il CSV esportato da FQLite"), kind="list")}
            if path == "/api/db_reperto":
                return fdb.reperto(g, SES.case, b)
            return fdb.chiudi(SES.case, b)
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
            return date_vista(view_info(SES.case, b), b)
        if path == "/api/hex":
            return hex_page(SES.case, b)
        if path == "/api/hexsearch":
            return hex_search(SES.case, b)
        if path == "/api/fileinfo":
            return date_vista(file_details(SES.case, b), b)
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
            # (2.20.1) scritto dall'analista nel modulo «Registra reperto»: origine «analista», non modello IA
            fa.add_finding(SES.case, t, (b.get("description") or "").strip(), (b.get("references") or "").strip(),
                           fa.FINDING_ANALISTA)
            return {"findings": SES.case.findings()}
        if path == "/api/finding_confirm":       # (2.20.1) «Confermo, verificato»: operatore e data nel registro
            fa.confirm_finding(SES.case, b.get("n"), b.get("operatore"))
            return {"findings": SES.case.findings()}
        if path == "/api/relazione_opzioni":        # (3.0.1) report illustrato: cosa si può scegliere
            import forense_relazione as frl
            return frl.opzioni(SES.case)
        if path == "/api/relazione_elementi":
            import forense_relazione as frl
            return {"elementi": frl.elementi_categoria(SES.case, b.get("cid"))}
        if path == "/api/relazione":
            import forense_relazione as frl
            o = {k: b.get(k) for k in ("titolo", "autore", "tz", "formati", "sezioni", "preferiti", "tutto", "originali",
                                       "originali_tutti", "chat_da", "chat_a", "dfmt")}
            run_task("relazione", lambda progress: frl.crea(SES.case, o, progress), True)
            return {"ok": True}
        if path == "/api/portable":
            import forense_portatile as fp
            opts = {k: b.get(k) for k in ("contenuto", "cancellati", "testi", "plaso", "tracce", "zip",
                                           "auto_mb", "segreti")}
            run_task("portable", lambda progress: fp.export_portable(SES.case, opts, progress), True)
            return {"ok": True}
        if path == "/api/portable_stop":
            import forense_portatile as fp
            fp.STOP.set()
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
        if path == "/api/open_relazione":           # (3.0.1) report illustrato: si apre con il programma predefinito
            rel = Path(b.get("rel") or "")
            nome = b.get("file") if b.get("file") in ("report.html", "report.pdf", "report.docx") else "report.html"
            target = (SES.case.root / rel / nome).resolve()
            if (SES.case.export_dir.resolve() not in target.parents or not target.parent.name.startswith("report_")
                    or not target.exists()):
                raise ValueError(tr("Report non trovato."))
            if nome == "report.html":
                import webbrowser
                webbrowser.open(target.as_uri())
            elif IS_MAC:
                subprocess.Popen(["open", str(target)])
            elif IS_WIN:
                os.startfile(str(target))
            elif shutil.which("xdg-open"):
                subprocess.Popen(["xdg-open", str(target)])
            return {"ok": True}
        if path == "/api/reveal_path":
            rel = Path(b.get("rel") or "")
            target = (SES.case.root / rel).resolve()
            if SES.case.root.resolve() not in target.parents or not target.exists():
                raise ValueError(tr("Percorso non valido."))
            reveal(target)
            return {"ok": True}
        if path == "/api/agente_passi":          # (3.0.4) turni del modello per ogni domanda: vale dalla domanda successiva
            try:
                n = int(b.get("passi"))
            except (TypeError, ValueError):
                n = 0
            if not fa.PASSI_MIN <= n <= fa.PASSI_MAX:
                raise ValueError(tr("Turni per domanda: un numero tra {a} e {b}.").format(a=fa.PASSI_MIN, b=fa.PASSI_MAX))
            conf = fa.load_settings()
            conf["passi"] = n
            fa.save_settings(conf)
            if SES.case:
                SES.case.log("agente_turni_per_domanda", n)
            return {"passi": fa.passi_max()}
        if path == "/api/llm_avvia":             # (3.0.4) avvia il server di Ollama o LM Studio su questo computer
            if not SES.case:
                raise ValueError(tr("Nessun caso aperto."))
            if SES.busy:
                raise ValueError(tr("Attendi che l'agente finisca o interrompilo."))
            nome = b.get("programma")
            if nome not in ("ollama", "lmstudio"):
                raise ValueError(tr("Programma non valido."))
            try:
                base = fa.avvia_programma(nome)
            except fa.LLMError as e:
                raise ValueError(str(e))
            SES.case.log("server_llm_avviato", {"programma": nome, "url": base})
            conf = fa.load_settings()
            conf["modo"] = "locale"
            fa.save_settings(conf)
            with LOCK:
                SES.connect()
            return self.state()
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
                if fa.url_esterno(url) and not b.get("esterno_ok") and conf.get("esterno_confermato") != url:
                    # (2.20.1) server fuori dalla rete locale: prima l'avviso esplicito all'analista, poi si usa
                    return {"conferma_esterno": url}
                if fa.url_esterno(url):
                    conf["esterno_confermato"] = url
                    SES.case.log("server_llm_esterno_confermato", {"url": url})
                conf["url"] = url
                if b.get("api_key") is not None:
                    conf["api_key"] = b["api_key"].strip()
            if b.get("contesto") is not None:         # (3.0.4) contesto dei modelli che RepertIA fa caricare
                try:
                    n = int(b["contesto"])
                except (TypeError, ValueError):
                    n = 0
                if not fa.CTX_MIN <= n <= fa.CTX_MAX:
                    raise ValueError(tr("Contesto: un numero di token tra {a} e {b}.").format(a=fa.CTX_MIN, b=fa.CTX_MAX))
                conf["contesto"] = n
            if b.get("modello") is not None:          # (3.0.4) "" = quello caricato nel server
                conf["modello"] = str(b["modello"]).strip()[:300]
                da_caricare = conf["modello"] or (b.get("contesto") is not None and (SES.llm or {}).get("model")) or ""
                if da_caricare:
                    # il caricamento può durare minuti: fuori dal blocco, così l'interfaccia continua a rispondere
                    fa.API_KEY = conf["api_key"] or fa.API_KEY
                    kind, base = fa.detect_backend(fa.BACKEND, conf["url"] if modo == "remoto" else "")
                    SES.note_modello = fa.carica_modello(kind, base, da_caricare, conf.get("contesto")) if kind else None
                    SES.case.log("modello_llm_scelto", {"modello": da_caricare, "contesto": conf.get("contesto") or fa.CTX_MODELLO, "server": base})
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
            def verifica(progress):
                # (3.0) avanzamento leggibile: prima lettura = file della copia, seconda = dati acquisiti (avanz("hash"))
                st = {"passo": 1}

                def hook(fase, fatti, totale):
                    if fase == "hash" and fatti is None:
                        st["passo"] = 2
                    if fatti is not None and totale:
                        cosa = tr("SHA-256 della copia") if st["passo"] == 1 else tr("dati acquisiti")
                        progress({"passo": st["passo"], "msg": tr("{p}/2 {cosa}: {pct}% ({a:.1f} di {b:.1f} GB)").format(
                            p=st["passo"], cosa=cosa, pct=int(fatti * 100 / totale), a=fatti / 1e9, b=totale / 1e9)})
                fa.AVANZ_HOOK[0] = hook
                try:
                    return fa.verify_hash(SES.case)
                finally:
                    fa.AVANZ_HOOK[0] = None
            run_task("verify", verifica, True)
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
                {k: SES.llm.get(k) for k in ("backend", "url", "model", "ctx", "notes", "remoto", "esterno", "tipo", "elenco")},
                "llm_error": SES.llm_error, "findings": c.findings(),
                "llm_conf": {"modo": conf["modo"], "url": conf["url"], "has_key": bool(conf["api_key"]), "passi": fa.passi_max(),
                             "modello": conf.get("modello") or "", "contesto": fa.contesto_modello(), "programmi": sorted(fa.programmi_llm())}}


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
    fd.installa(fa.SETTINGS_PATH.parent / "diagnostica.log")
    fd.evento("avvio", versione=fa.APP_VERSION, sistema=platform.platform(terse=True), python=platform.python_version())
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
