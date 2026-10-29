#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Prova automatica della navigazione dell'interfaccia di RepertIA (2.20): Ricerca, Indietro/Avanti, briciole.

Uso:  python3 tools/prova_navigazione.py --casi <cartella con i casi> [--python <python di RepertIA>]
                                         [--caso NOME ...] [--termine PAROLA] [--browser chromium|webkit]
                                         [--larghezza 1280 --altezza 800] [--rapporto file.md] [--lingua it|en]

Avvia l'interfaccia (forense_gui.py) sui casi della cartella, in un browser comandato da Playwright, e per ogni caso
(dischi e smartphone) prova tre percorsi:
  A. pulsante «🔎 Ricerca» in alto → ricerca → risultati → clic su una voce dell'albero → contenuto giusto →
     Indietro → di nuovo i risultati → Indietro → pannello Ricerca → Indietro → sezione di partenza → Indietro → pagina
     iniziale (File System);
  B. lo stesso riaprendo i risultati con l'etichetta della ricerca in alto;
  C. lo stesso riaprendo i risultati con la voce della ricerca nell'albero (sotto «🔎 Ricerca»);
  D. due sottovoci cliccate di seguito senza attendere: alla fine tabella e briciole devono indicare l'ultima.
Dopo ogni passo controlla che le briciole corrispondano alla sezione aperta e che la tabella mostri proprio quella
sezione (`resTable.dataset.shown`). Esce con 0 se tutto torna, 1 se no.

Serve Playwright nel Python che esegue questo file (`pip install playwright` e `python -m playwright install chromium`);
non è nei pacchetti di RepertIA. Le ricerche fatte restano salvate nei casi (ricerche.sqlite e registro): usare copie
dei casi del collaudo, mai casi reali.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"

STATO = """() => ({tab: resTab, sec: resSec, shown: document.getElementById('resTable').dataset.shown || '',
  depth: NAV.depth, restoring: NAV.restoring, back: NAV.back.length, fwd: NAV.fwd.length,
  cr: [...document.querySelectorAll('#navRow .navcr > a, #navRow .navcr > span:not(.sep)')].map(e => e.textContent.trim())})"""
STABILE = "NAV.depth === 0 && !NAV.restoring && resTab === 'res' && document.getElementById('resTable').dataset.shown === resSec"


class Prova:
    def __init__(self, page, caso, rapporto):
        self.p, self.caso, self.r = page, caso, rapporto
        self.ok = self.ko = 0

    def stato(self):
        return self.p.evaluate(STATO)

    def attendi(self, sec=None, timeout=90000):
        cond = f"() => ({STABILE})" + ("" if sec is None else f" && ({sec})")
        try:
            self.p.wait_for_function(cond, timeout=timeout)
        except Exception:
            return False
        self.p.wait_for_timeout(250)
        return True

    def controlla(self, passo, sec, briciole, stabile=True):
        """sec: regex della sezione attesa; briciole: elenco di regex, una per voce delle briciole."""
        s = self.stato()
        err = []
        if not stabile:
            err.append("la pagina non si stabilizza (caricamento senza fine)")
        if not re.fullmatch(sec, s["sec"]):
            err.append(f"sezione {s['sec']!r}, attesa {sec!r}")
        if s["shown"] != s["sec"]:
            err.append(f"la tabella mostra {s['shown']!r}, le briciole {s['sec']!r}")
        if len(s["cr"]) != len(briciole) or not all(re.search(b, c) for b, c in zip(briciole, s["cr"])):
            err.append(f"briciole {' › '.join(s['cr'])!r}, attese {' › '.join(briciole)!r}")
        esito = "superato" if not err else "NON SUPERATO: " + "; ".join(err)
        if err:
            self.ko += 1
        else:
            self.ok += 1
        riga = f"| {self.caso} | {passo} | {' › '.join(s['cr'])} | {s['sec']} | {esito} |"
        print(riga, flush=True)
        self.r.append(riga)
        return not err

    # ---- azioni ----
    def clic(self, sel):
        # la stessa voce può comparire due volte nell'albero (sotto «Ricerca» e sotto «Schede aperte»): la prima visibile
        self.p.locator(sel).locator("visible=true").first.click(timeout=15000)

    def albero(self, nodo):
        n = self.p.locator(f"#rTree .rtn[data-n='{nodo}']")
        if not n.count() or not n.first.is_visible():
            # la voce è dentro una voce chiusa: apre i genitori
            par = nodo.rsplit(":", 1)[0] if ":" in nodo else None
            if par:
                self.albero_apri(par)
        self.clic(f"#rTree .rtn[data-n='{nodo}'] .nm")

    def albero_apri(self, nodo):
        if ":" in nodo:
            self.albero_apri(nodo.rsplit(":", 1)[0])
        el = self.p.locator(f"#rTree .rtn[data-n='{nodo}']")
        if el.count() and not self.p.locator(f"#rTree .rtn[data-n='{nodo}'] + .rtsub").count():
            self.clic(f"#rTree .rtn[data-n='{nodo}'] .car")
            self.p.wait_for_timeout(300)

    def indietro(self):
        self.clic("#navRow [data-nav='-1']")

    def sezione_libera(self, escluse):
        """prima voce principale dell'albero con dati, diversa da quelle indicate"""
        ids = self.p.evaluate("""() => [...document.querySelectorAll('#rTree > .rtn:not(.dis), #rtList > .rtn:not(.dis)')].map(e => [e.dataset.n,
            (e.querySelector('.ct') || {}).textContent || ''])""")
        for k in ["art", "doc", "file", "meta", "timeline", "trace", "mail"]:
            for n, ct in ids:
                if n == k and k not in escluse and ct.strip() not in ("", "0"):
                    return k
        return None


ETICHETTE = {"timeline": r"^Timeline$", "art": r"^Artefatti di sistema$", "doc": r"^Documenti$", "file": r"^File$",
             "meta": r"^Foto/Video/Audio$", "trace": r"^Evidenze di interesse$", "mail": r"^Posta$", "explore": r"^File System$",
             "search": r"Ricerca$"}
ETICHETTE_EN = {"timeline": r"^Timeline$", "art": r"^System artifacts$", "doc": r"^Documents$", "file": r"^Files$",
                "meta": r"^Photos/Videos/Audio$", "trace": r"^Items of interest$", "mail": r"^Mail$", "explore": r"^File System$",
                "search": r"Search$"}


def prova_caso(P, url, termine, lab):
    page, caso = P.p, P.caso
    page.goto(url)
    page.wait_for_selector(f".case[data-root$='{caso}']", timeout=30000)
    page.click(f".case[data-root$='{caso}']")
    page.wait_for_selector("#vCase:not(.hidden)", timeout=60000)
    page.wait_for_timeout(800)
    page.evaluate("() => { if (typeof setNavMode === 'function' && NAVMODE !== 'tree') setNavMode('tree'); }")
    if page.evaluate("() => resTab") != "res":
        page.click(".tabs button[data-tab=res]")
    st = P.attendi()
    P.controlla("pagina iniziale", "explore", [lab["explore"]], st)
    page.wait_for_selector("#rTree .rtn[data-n=timeline]", timeout=30000)

    # ---- A: pulsante in alto ----
    P.albero("timeline"); st = P.attendi("resSec === 'timeline'")
    P.controlla("A Timeline", "timeline", [lab["timeline"]], st)
    P.clic("#btnSrch"); st = P.attendi("resSec === 'search'")
    P.controlla("A pulsante 🔎 Ricerca", "search", [lab["search"]], st)
    if page.locator("#sMode [data-m=kw]").count():      # casi smartphone: si apre su «⚡ Risultati del caso»
        page.click("#sMode [data-m=kw]")
    page.fill("#sTerms", termine)
    P.clic("#sGo")
    try:
        page.wait_for_function("() => /^s\\d+$/.test(resSec)", timeout=600000)
    except Exception:
        pass
    st = P.attendi()
    sid = page.evaluate("() => resSec")
    titolo = page.evaluate("() => (XTABS.find(t => t.id === resSec) || {}).title || ''")
    br_ris = [lab["search"], "^" + re.escape(titolo) + "$"]
    P.controlla("A risultati della ricerca", r"s\d+", br_ris, st)
    altra = P.sezione_libera({"timeline"}) or "timeline"
    P.albero(altra); st = P.attendi(f"resSec === '{altra}'")
    P.controlla(f"A clic su «{altra}» nell'albero", altra, [lab[altra]], st)
    P.indietro(); st = P.attendi(f"resSec === '{sid}'")
    P.controlla("A Indietro → risultati", re.escape(sid), br_ris, st)
    P.indietro(); st = P.attendi("resSec === 'search'")
    P.controlla("A Indietro → pannello Ricerca", "search", [lab["search"]], st)
    P.indietro(); st = P.attendi("resSec === 'timeline'")
    P.controlla("A Indietro → Timeline", "timeline", [lab["timeline"]], st)
    P.indietro(); st = P.attendi("resSec === 'explore'")
    P.controlla("A Indietro → pagina iniziale", "explore", [lab["explore"]], st)
    page.wait_for_timeout(500)
    P.clic("#navRow [data-nav='1']"); st = P.attendi("resSec === 'timeline'")
    P.controlla("A Avanti → Timeline", "timeline", [lab["timeline"]], st)

    # ---- B: etichetta della ricerca in alto ----
    P.clic(f"#srchTags .stag[data-sid='{sid[1:]}'] .sl"); st = P.attendi(f"resSec === '{sid}'")
    P.controlla("B etichetta in alto → risultati", re.escape(sid), br_ris, st)
    P.albero(altra); st = P.attendi(f"resSec === '{altra}'")
    P.controlla(f"B clic su «{altra}»", altra, [lab[altra]], st)
    P.indietro(); st = P.attendi(f"resSec === '{sid}'")
    P.controlla("B Indietro → risultati", re.escape(sid), br_ris, st)
    P.indietro(); st = P.attendi("resSec === 'timeline'")
    P.controlla("B Indietro → Timeline", "timeline", [lab["timeline"]], st)

    # ---- C: voce della ricerca nell'albero ----
    P.albero_apri("search")
    P.clic(f"#rTree .rtn[data-n='search'] + .rtsub .rtn[data-n='{sid}'] .nm"); st = P.attendi(f"resSec === '{sid}'")
    P.controlla("C voce dell'albero → risultati", re.escape(sid), br_ris, st)
    P.albero(altra); st = P.attendi(f"resSec === '{altra}'")
    P.controlla(f"C clic su «{altra}»", altra, [lab[altra]], st)
    P.indietro(); st = P.attendi(f"resSec === '{sid}'")
    P.controlla("C Indietro → risultati", re.escape(sid), br_ris, st)
    P.indietro(); st = P.attendi("resSec === 'timeline'")
    P.controlla("C Indietro → Timeline", "timeline", [lab["timeline"]], st)

    # ---- E: voci madri chiuse (▸) nell'albero: «Ricerca», «Preferiti», «Schede aperte» ----
    for madre in ("search", "bm", "tabs"):
        if page.locator(f"#rTree .rtn[data-n='{madre}'] + .rtsub").count():
            P.clic(f"#rTree .rtn[data-n='{madre}'] .car")
            page.wait_for_timeout(300)
    P.albero(altra); st = P.attendi(f"resSec === '{altra}'")
    P.controlla(f"E voci chiuse, clic su «{altra}»", altra, [lab[altra]], st)
    P.albero("timeline"); st = P.attendi("resSec === 'timeline'")
    P.controlla("E voci chiuse, clic su Timeline", "timeline", [lab["timeline"]], st)
    P.indietro(); st = P.attendi(f"resSec === '{altra}'")
    P.controlla("E Indietro", altra, [lab[altra]], st)
    P.albero_apri("search")

    # ---- D: due sottovoci di seguito senza attendere ----
    P.albero_apri(altra)
    figli = page.evaluate(f"""() => [...document.querySelectorAll("#rTree .rtn[data-n^='{altra}:']")].filter(e => e.offsetParent)
        .map(e => [e.dataset.n, e.querySelector('.nm').textContent.trim()])""")
    if figli:
        P.clic(f"#rTree .rtn[data-n='{altra}'] .nm")
        P.clic(f"#rTree .rtn[data-n='{figli[-1][0]}'] .nm")
        st = P.attendi()
        page.wait_for_timeout(3000)       # una risposta lenta della prima voce non deve sostituire la seconda
        P.controlla(f"D «{altra}» e subito «{figli[-1][1]}»", altra, [lab[altra], "^" + re.escape(figli[-1][1]) + "$"], st)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--casi", required=True, help="cartella con i casi (copie del collaudo)")
    ap.add_argument("--python", default=sys.executable, help="Python con cui avviare RepertIA (predefinito: questo)")
    ap.add_argument("--caso", action="append", help="nome della cartella del caso (più volte); predefinito: tutti")
    ap.add_argument("--termine", default="e", help="parola da cercare (nome e documenti)")
    ap.add_argument("--browser", default="chromium", choices=["chromium", "webkit", "firefox"])
    ap.add_argument("--larghezza", type=int, default=1280)
    ap.add_argument("--altezza", type=int, default=800)
    ap.add_argument("--lingua", default="it", choices=["it", "en"])
    ap.add_argument("--rapporto", help="scrive anche un rapporto in Markdown")
    a = ap.parse_args()
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Serve Playwright: pip install playwright && python -m playwright install chromium", file=sys.stderr)
        return 2
    casi_dir = Path(a.casi).resolve()
    casi = a.caso or sorted(d.name for d in casi_dir.iterdir() if (d / "case.json").exists())
    tmp = Path(tempfile.mkdtemp(prefix="repertia_nav_"))
    (tmp / "imp.json").write_text(json.dumps({"lingua": a.lingua}), encoding="utf-8")
    env = dict(os.environ, FORENSE_NO_BROWSER="1", FORENSE_CASI=str(casi_dir), FORENSE_IMPOSTAZIONI=str(tmp / "imp.json"),
               PYTHONUNBUFFERED="1")
    srv = subprocess.Popen([a.python, "forense_gui.py"], cwd=SRC, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    url = None
    t0 = time.time()
    while time.time() - t0 < 60:
        riga = srv.stdout.readline()
        m = re.search(r"(http://127\.0\.0\.1:\d+/)", riga or "")
        if m:
            url = m.group(1)
            break
    if not url:
        srv.kill()
        print("L'interfaccia non si è avviata", file=sys.stderr)
        return 2
    lab = ETICHETTE if a.lingua == "it" else ETICHETTE_EN
    rapporto = ["| caso | passo | briciole | sezione | esito |", "|---|---|---|---|---|"]
    ok = ko = 0
    errori_js = []
    try:
        with sync_playwright() as pw:
            b = getattr(pw, a.browser).launch()
            page = b.new_page(viewport={"width": a.larghezza, "height": a.altezza})
            page.on("pageerror", lambda e: errori_js.append(str(e)))
            for c in casi:
                P = Prova(page, c, rapporto)
                try:
                    prova_caso(P, url, a.termine, lab)
                except Exception as e:  # passo non eseguibile: conta come non superato
                    P.ko += 1
                    riga = f"| {c} | (interrotta) | | | NON SUPERATO: {str(e).splitlines()[0][:160]} |"
                    print(riga)
                    rapporto.append(riga)
                ok += P.ok
                ko += P.ko
            b.close()
    finally:
        srv.terminate()
    if errori_js:
        ko += len(errori_js)
        for e in errori_js:
            print("ERRORE JS:", e)
            rapporto.append(f"| | errore JavaScript | | | NON SUPERATO: {e[:160]} |")
    sintesi = f"Navigazione ({a.browser}, {a.larghezza}×{a.altezza}, {a.lingua}): {ok}/{ok + ko} controlli superati"
    print(sintesi)
    if a.rapporto:
        Path(a.rapporto).write_text(f"# Prova della navigazione di RepertIA\n\n{sintesi}\n\n" + "\n".join(rapporto) + "\n", encoding="utf-8")
    return 0 if ko == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
