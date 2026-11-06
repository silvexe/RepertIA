#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (3.0): controlla i pacchetti costruiti prima di pubblicarli, sui file finali e non sulla cartella di lavoro.

Uso: python3 tools/controlla_pacchetti.py <cartella dei pacchetti> [--versione 3.0.0] [--no-avvio]

Per ogni pacchetto: permessi di esecuzione, link simbolici, versione, file necessari, sorgenti uguali a src/, niente file
di sistema o percorsi personali. Inoltre: Setup uguale allo zip Windows, guida, archivio di collaudo, SHA256SUMS. Sul Mac
estrae lo zip e avvia il programma da `avvia.command`, come fa l'app: il collaudo da riga di comando non passa da lì.
Non sostituisce il collaudo né la prova a mano (doppio clic sull'app, Setup su Windows). Esce con 1 se qualcosa non va."""
import argparse
import hashlib
import os
import platform
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
SRC = RADICE / "src"
ESEGUIBILI_MAC = ["RepertIA/Aggiorna strumenti.command", "RepertIA/Collaudo RepertIA.command",
                  "RepertIA/RepertIA.app/Contents/MacOS/RepertIA", "RepertIA/RepertIA.app/Contents/Resources/avvia.command",
                  "RepertIA/RepertIA.app/Contents/Resources/python/bin/python3.12",
                  "RepertIA/RepertIA.app/Contents/Resources/strumenti/7zip/7zz",
                  "RepertIA/RepertIA.app/Contents/Resources/strumenti/ffmpeg/bin/ffmpeg",
                  "RepertIA/RepertIA.app/Contents/Resources/strumenti/whisper/bin/whisper-cli"]
ESEGUIBILI_LINUX = ["RepertIA/RepertIA.sh", "RepertIA/installa.sh", "RepertIA/collaudo.sh", "RepertIA/aggiorna-strumenti.sh",
                    "RepertIA/strumenti/7zip/7zz", "RepertIA/strumenti/ffmpeg/bin/ffmpeg"]
NECESSARI_WIN = ["RepertIA/RepertIA.bat", "RepertIA/Collaudo.bat", "RepertIA/python/python.exe", "RepertIA/strumenti/7zip/7z.exe",
                 "RepertIA/strumenti/exiftool/exiftool.exe", "RepertIA/strumenti/sleuthkit/bin/fls.exe"]
DOCUMENTI = ["LICENSE", "THIRD_PARTY_LICENSES.md", "VALIDAZIONE.md", "AI_ACT.md", "LEGGIMI.txt", "README_EN.txt"]
PERSONALE = re.compile(rb"/Users/(?!<|\$|nome|utente|USER|mario)[A-Za-z0-9._-]+/")
ERRORI = []


def esito(nome, ok, dettaglio=""):
    print(("  ok   " if ok else "  NO   ") + nome + (f" - {dettaglio}" if dettaglio and not ok else ""))
    if not ok:
        ERRORI.append(nome)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def attesi_src():
    """File di src/ che devono stare nei pacchetti: percorso relativo → impronta."""
    out = {}
    for f in SRC.rglob("*"):
        if not f.is_file() or "__pycache__" in f.parts or f.name.startswith("._") or f.name == ".DS_Store":
            continue
        if f.suffix == ".command" and f.parent == SRC:
            continue
        out[f.relative_to(SRC).as_posix()] = sha(f.read_bytes())
    return out


def comuni(nomi, leggi, base, versione, prefisso):
    """Controlli uguali per tutti i pacchetti. `nomi` = percorsi nell'archivio, `leggi` = contenuto di un percorso."""
    sporchi = [n for n in nomi if "/._" in n or n.endswith("/.DS_Store") or (f"/{base}/" in n and "__pycache__" in n)]
    esito("niente file di sistema né cache nei sorgenti", not sporchi, ", ".join(sporchi[:3]))
    att = attesi_src()
    diversi = [k for k, v in att.items() if f"{base}/{k}" not in nomi or sha(leggi(f"{base}/{k}")) != v]
    esito(f"file del programma uguali a src/ ({len(att)})", not diversi, ", ".join(diversi[:5]))
    for parte in ("mappa/maplibre-gl.mjs", "mappa/fonts/Noto Sans Regular/0-255.pbf", "guida/guida.html", "lingua_en.json"):
        esito(f"presente {parte}", f"{base}/{parte}" in nomi)
    m = re.search(rb'^APP_VERSION = "([^"]+)"', leggi(f"{base}/forense_agent.py"), re.M)
    esito(f"versione {versione} nel programma", bool(m) and m.group(1).decode() == versione)
    for d in DOCUMENTI:
        esito(f"presente {d}", f"{prefisso}{d}" in nomi)
    testi = [f"{prefisso}{d}" for d in DOCUMENTI if f"{prefisso}{d}" in nomi] + [f"{base}/README.md", f"{base}/guida/guida.html"]
    pers = [n for n in testi if PERSONALE.search(leggi(n))]
    esito("nessun percorso personale in documenti e guida", not pers, ", ".join(pers))
    prima = leggi(f"{prefisso}LEGGIMI.txt").lstrip(b"\xef\xbb\xbf").split(b"\n", 1)[0].decode("utf-8", "replace")
    esito(f"versione {versione} nel LEGGIMI", versione in prima, prima)


def mac(p, versione, avvio):
    print(f"\n{p.name}")
    if not p.exists():
        return esito("presente", False)
    z = zipfile.ZipFile(p)
    info = {i.filename: i for i in z.infolist()}
    res = "RepertIA/RepertIA.app/Contents/Resources"
    for n in ESEGUIBILI_MAC:
        esito(f"eseguibile {n.rsplit('/', 1)[-1]}", n in info and bool((info[n].external_attr >> 16) & 0o111), n)
    link = [i for i in info.values() if stat.S_ISLNK(i.external_attr >> 16)]
    esito("link simbolici conservati", len(link) >= 5, str(len(link)))
    comuni(set(info), z.read, f"{res}/RepertIA", versione, "RepertIA/")
    esito(f"versione {versione} in Info.plist", f"<string>{versione}</string>".encode() in z.read("RepertIA/RepertIA.app/Contents/Info.plist"))
    if not avvio:
        return None
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        return print("  --   avvio non provato: serve un Mac Apple Silicon")
    with tempfile.TemporaryDirectory() as t:
        subprocess.run(["unzip", "-q", str(p), "-d", t], check=True)      # unzip conserva permessi e link
        cmd = Path(t) / res / "avvia.command"
        log = Path(t) / "avvio.log"
        env = dict(os.environ, FORENSE_NO_BROWSER="1", FORENSE_CASI=str(Path(t) / "casi"), PYTHONUNBUFFERED="1",
                   FORENSE_IMPOSTAZIONI=str(Path(t) / "imp.json"), PYTHONDONTWRITEBYTECODE="1")
        with open(log, "wb") as o:
            pr = subprocess.Popen([str(cmd)], env=env, stdout=o, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        try:
            url = None
            for _ in range(60):
                m = re.search(r"http://127\.0\.0\.1:\d+", log.read_text(errors="replace"))
                if m:
                    url = m.group(0)
                    break
                time.sleep(1)
            esito("avvio dallo zip estratto, con avvia.command", bool(url), log.read_text(errors="replace")[-300:])
            if url:
                for rotta in ("/", "/guida/guida.html", "/mappa/maplibre-gl.mjs"):
                    try:
                        cod = urllib.request.urlopen(url + rotta, timeout=10).status
                    except OSError as e:
                        cod = e
                    esito(f"risponde {rotta}", cod == 200, str(cod))
        finally:
            pr.terminate()
            pr.wait(timeout=20)
    return None


def windows(zp, setup, versione):
    print(f"\n{zp.name}")
    if not zp.exists():
        return esito("presente", False)
    z = zipfile.ZipFile(zp)
    nomi = set(z.namelist())
    for n in NECESSARI_WIN:
        esito(f"presente {n.rsplit('/', 1)[-1]}", n in nomi, n)
    comuni(nomi, z.read, "RepertIA/RepertIA", versione, "RepertIA/")
    print(f"\n{setup.name}")
    if not setup.exists():
        return esito("presente", False)
    with tempfile.TemporaryDirectory() as t:
        r = subprocess.run([sys.executable, str(RADICE / "build/windows/nsis_x.py"), str(setup), t], capture_output=True, text=True)
        esito("si estrae", r.returncode == 0, r.stderr[-200:])
        base = Path(t)
        dentro = {f.relative_to(base).as_posix() for f in base.rglob("*") if f.is_file()}
        zipf = {n[len("RepertIA/"):] for n in nomi if not n.endswith("/")}
        esito(f"stessi file dello zip ({len(zipf)})", dentro == zipf, f"{len(dentro ^ zipf)} diversi")
        div = [n for n in dentro & zipf if sha((base / n).read_bytes()) != sha(z.read("RepertIA/" + n))]
        esito("stesso contenuto dello zip", not div, ", ".join(div[:3]))
    return None


def linux(p, versione):
    print(f"\n{p.name}")
    if not p.exists():
        return esito("presente", False)
    with tarfile.open(p) as t:
        membri = {m.name: m for m in t.getmembers()}
        for n in ESEGUIBILI_LINUX:
            esito(f"eseguibile {n.rsplit('/', 1)[-1]}", n in membri and bool(membri[n].mode & 0o111), n)
        comuni({n for n, m in membri.items() if m.isfile()}, lambda n: t.extractfile(n).read(), "RepertIA/RepertIA", versione, "RepertIA/")
    return None


def varie(cart, versione):
    print("\nAltri allegati")
    g = cart / f"RepertIA-guida-{versione}.html"
    esito("guida uguale a src/guida", g.exists() and g.read_bytes() == (SRC / "guida/guida.html").read_bytes())
    c = cart / "RepertIA-collaudo.zip"
    if c.exists():
        z = zipfile.ZipFile(c)
        for f in sorted((RADICE / "collaudo").glob("atteso*.json")):
            esito(f"collaudo: {f.name} uguale al repository", z.read(f"RepertIA-collaudo/{f.name}") == f.read_bytes())
        esito("collaudo: licenza AGPL", "RepertIA-collaudo/LICENZE/AGPL-3.0.txt" in z.namelist())
        esito("collaudo: niente registri diagnostici", not [n for n in z.namelist() if "diagnostica" in n])
    else:
        esito("presente RepertIA-collaudo.zip", False)
    s = cart / "SHA256SUMS.txt"
    if not s.exists():
        return esito("presente SHA256SUMS.txt", False)
    righe = [x.split(None, 1) for x in s.read_text().splitlines() if x.strip()]
    elenco = {n.strip() for _h, n in righe}
    div = [n.strip() for h, n in righe if not (cart / n.strip()).exists() or sha((cart / n.strip()).read_bytes()) != h]
    esito(f"SHA256SUMS corrisponde ai file ({len(righe)})", not div, ", ".join(div))
    fuori = [f.name for f in cart.iterdir() if f.is_file() and f.suffix in (".zip", ".exe", ".gz", ".tar", ".xz", ".html") and f.name not in elenco]
    esito("ogni allegato è in SHA256SUMS", not fuori, ", ".join(fuori))
    esito("rapporti con percorsi personali fuori da SHA256SUMS", not [n for n in elenco if n.startswith("collaudo_")])
    firma(s)
    return None


def firma(s):
    """(3.0.1) Firma minisign di SHA256SUMS con la chiave pubblicata in SECURITY.md. Si firma dopo la costruzione:
    se manca la firma lo si segnala soltanto; se c'è deve essere valida."""
    m = s.with_name(s.name + ".minisig")
    if not m.exists():
        print("  --   SHA256SUMS non ancora firmato (firma.sh, poi caricare SHA256SUMS.txt.minisig)")
        return
    chiave = re.search(r"^(RW[A-Za-z0-9+/]{54})$", (RADICE / "SECURITY.md").read_text(encoding="utf-8"), re.M)
    if not chiave:
        return esito("firma: chiave pubblica in SECURITY.md", False)
    try:
        r = subprocess.run(["minisign", "-V", "-q", "-P", chiave.group(1), "-m", str(s)], capture_output=True, text=True)
    except FileNotFoundError:
        return esito("firma: minisign installato", False, "brew install minisign")
    esito("firma di SHA256SUMS valida (chiave di SECURITY.md)", r.returncode == 0, (r.stderr or r.stdout).strip())


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("cartella", type=Path)
    ap.add_argument("--versione")
    ap.add_argument("--no-avvio", action="store_true", help="non avviare il programma dallo zip Mac")
    a = ap.parse_args()
    versione = a.versione or re.search(r'^APP_VERSION = "([^"]+)"', (SRC / "forense_agent.py").read_text(encoding="utf-8"), re.M).group(1)
    c = a.cartella
    mac(c / f"RepertIA-{versione}-Mac.zip", versione, not a.no_avvio)
    windows(c / f"RepertIA-{versione}-Windows.zip", c / f"RepertIA-{versione}-Setup.exe", versione)
    linux(c / f"RepertIA-{versione}-Linux.tar.gz", versione)
    varie(c, versione)
    print(f"\n{'Tutto a posto.' if not ERRORI else str(len(ERRORI)) + ' controlli NON superati:'}")
    for e in ERRORI:
        print("  - " + e)
    print("Restano a mano: doppio clic sull'app dallo zip scaricato, Setup e collaudo su Windows, collaudo su Linux.")
    return 1 if ERRORI else 0


if __name__ == "__main__":
    sys.exit(main())
