#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Controllo delle traduzioni di RepertIA.

Raccoglie i testi da tradurre dai sorgenti (`tr("…")` e `N_("…")` nel Python, `T("…")` e `TF("…")` negli script
delle pagine HTML) e li confronta con il dizionario `src/lingua_<codice>.json`:
  - testi senza traduzione;
  - traduzioni con segnaposto ({nome}, {0}) o marcatori HTML diversi da quelli del testo italiano;
  - voci del dizionario non più usate (solo segnalate: il testo statico delle pagine e le chiavi calcolate,
    come le etichette delle colonne dei CSV, non si ricavano dai sorgenti).

Uso:  python3 tools/lingua_controlla.py [src] [--lingua en] [--elenco]   (--elenco: stampa i testi mancanti in JSON)
Esce con 1 se mancano traduzioni o ci sono segnaposto diversi."""
import ast
import json
import re
import sys
from pathlib import Path

FIELD = re.compile(r"(?<!\{)\{([A-Za-z_]\w*|\d+)(?:[!:][^{}]*)?\}(?!\})")
TAG = re.compile(r"</?(a|b|i|u|br|hr|p|pre|code|kbd|div|span|small|strong|em|sub|sup|h[1-6]|ul|ol|li|table|thead|tbody|tr|td|th|"
                 r"label|input|select|option|textarea|button|fieldset|legend|datalist|img|svg|details|summary|mark)(?=[\s>/])")
JS_CALL = re.compile(r"""\b(TF?)\(\s*("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`[^`$\\]*`)\s*[,)]""")


def py_keys(path):
    out = []
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("tr", "N_") and n.args \
                and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
            out.append(n.args[0].value)
    return out


def js_keys(path):
    out = []
    html = path.read_text(encoding="utf-8")
    for m in JS_CALL.finditer(html):
        lit = m.group(2)
        if lit[0] == "`":
            out.append(lit[1:-1])
        else:
            try:
                out.append(json.loads('"' + lit[1:-1].replace('\\\'', "'").replace('"', '\\"').replace('\\\\"', '\\"') + '"')
                           if lit[0] == "'" else json.loads(lit))
            except ValueError:
                out.append(ast.literal_eval(lit))
    return out


def fields(s):
    return sorted(FIELD.findall(s))


def tags(s):
    return sorted(TAG.findall(s))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    src = Path(args[0] if args else Path(__file__).resolve().parent.parent / "src")
    code = sys.argv[sys.argv.index("--lingua") + 1] if "--lingua" in sys.argv else "en"
    diz_path = src / f"lingua_{code}.json"
    diz = json.loads(diz_path.read_text(encoding="utf-8")) if diz_path.exists() else {}
    keys = {}
    for p in sorted(src.glob("forense_*.py")):
        for k in py_keys(p):
            keys.setdefault(k, p.name)
    for p in sorted(src.glob("forense_*.html")):
        for k in js_keys(p):
            keys.setdefault(k, p.name)
    missing = [k for k in keys if k not in diz]
    bad = [(k, diz[k]) for k in keys if k in diz and isinstance(diz[k], str)
           and (fields(k) != fields(diz[k]) or tags(k) != tags(diz[k]))]
    unused = [k for k in diz if k not in keys and k != "#"]
    if "--elenco" in sys.argv:
        print(json.dumps(missing, ensure_ascii=False, indent=0))
        return 0
    print(f"{diz_path.name}: {len(keys)} testi nei sorgenti, {len(diz)} voci nel dizionario")
    print(f"  senza traduzione: {len(missing)}")
    for k in missing[:40]:
        print(f"    [{keys[k]}] {k[:110]!r}")
    print(f"  segnaposto o marcatori HTML diversi: {len(bad)}")
    for k, v in bad[:40]:
        print(f"    {k[:80]!r} -> {v[:80]!r}")
    print(f"  voci non trovate nei sorgenti (testo statico delle pagine o chiavi calcolate): {len(unused)}")
    return 1 if missing or bad else 0


if __name__ == "__main__":
    sys.exit(main())
