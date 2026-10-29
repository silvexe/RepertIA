#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""File citati per sezione (RepertIA 2.20): quante righe citano un file e quanti di questi file si trovano nella copia
o nell'estrazione, con la stessa ricerca dell'interfaccia (src/forense_percorsi.py).

Uso:  python3 file_citati_conta.py <caso> [<caso> …] [--md uscita.md]

Sezioni: artefatti di iLEAPP/ALEAPP, artefatti di sistema (per categoria), chiamate, timeline di plaso (percorso
dell'evento) e allegati delle chat. Un file citato = un file DIVERSO della riga (i campi che portano allo stesso file sono
uniti, come nel pannello), con l'esito in tre livelli: certi, probabili, non presenti (allegati delle chat: solo per
metodo). Ricerca, Preferiti, Reperto, risposte dell'agente e report portatile usano le
stesse funzioni sulle stesse righe: non si contano a parte. La ricerca qui è quella veloce delle tabelle (percorso
e nome, senza ricalcolare gli hash); gli allegati delle chat riportano l'esito salvato all'importazione.
"""
import collections
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
import forense_agent as fa  # noqa: E402
import forense_percorsi as fp  # noqa: E402


def conta_caso(root):
    case = fa.Case(Path(root))
    if not case.meta:
        raise SystemExit(f"Caso non trovato: {root}")
    out = collections.OrderedDict()
    idx = fp.Indice(case)
    con = fa.db_ro(case)
    try:
        cats = {}
        if fa.table_exists(con, "artifacts"):
            for cat, title, user, src, part, inode, data in con.execute(
                    "SELECT cat, title, user, src_path, part, inode, data FROM artifacts"):
                if cat == "messaggi":
                    continue
                sez = ("Artefatti iLEAPP/ALEAPP" if cat == "leapp" else "Chiamate" if cat == "chiamate"
                       else f"Artefatti di sistema · {cat}")
                c = out.setdefault(sez, collections.Counter())
                c["righe"] += 1
                r = fp.file_citati(case, {"cat": cat, "title": title, "user": user, "src_path": src, "part": part,
                                          "inode": inode, "data": data}, veloce=True, idx=idx)
                fs = [x for x in r["file"] if x["ruolo"] == "file"]
                if not fs:
                    continue
                c["con_file"] += 1
                for x in fs:                       # un elemento per file DIVERSO (campi della stessa riga già uniti)
                    c["file"] += 1
                    c[x["stato"] if x["stato"] != "trovato" else "trovato:" + x["metodo"]] += 1
                    c["livello:" + x["livello"]] += 1
                    c["uniti"] += len(x.get("campi") or []) > 1
                cats[sez] = True
        # timeline di plaso: il percorso dell'evento
        import forense_gui as G
        memo = {}
        c = collections.Counter()
        for (path,) in con.execute("SELECT path FROM events WHERE origin = 'plaso' AND path IS NOT NULL AND path <> ''"):
            c["righe"] += 1
            p = G.plaso_fs_path(path)
            if not p or "/" not in p:
                continue
            if p not in memo:
                r = fp.risolvi_testo(case, p, idx=idx)
                memo[p] = r["stato"] if r["stato"] != "trovato" else "trovato:" + r["metodo"]
            c["con_file"] += 1
            c["file"] += 1
            c[memo[p]] += 1
        if c["righe"]:
            out["Timeline (plaso)"] = c
        # allegati delle chat (esito salvato all'importazione)
        if fa.table_exists(con, "chat_attachments"):
            have = {r[1] for r in con.execute("PRAGMA table_info(chat_attachments)")}
            met = "a.metodo" if "metodo" in have else "NULL"
            th = "a.thumb IS NOT NULL" if "thumb" in have else "0"
            for app, inode, path, metodo, thumb in con.execute(
                    f"SELECT m.app, a.inode, a.path, {met}, {th} FROM chat_attachments a JOIN chat_messages m "
                    "ON m.id = a.msg WHERE a.lat IS NULL"):
                c = out.setdefault(f"Allegati delle chat · {app}", collections.Counter())
                c["righe"] += 1
                c["con_file"] += 1
                c["file"] += 1
                if inode not in (None, ""):
                    c["trovato:" + (metodo or "percorso")] += 1
                elif str(path or "").startswith("leapp:"):
                    c["rapporto"] += 1
                elif thumb:
                    c["miniatura"] += 1
                else:
                    c["assente"] += 1
    finally:
        con.close()
        idx.close()
    return case, out


COLS = [("percorso", "per percorso"), ("percorso_leapp", "via iLEAPP/ALEAPP"), ("hash", "per hash"),
        ("nome+dimensione", "nome+dim. (da verificare)"), ("nome", "solo nome (da verificare)")]
LIV = [("certo", "✅ certi"), ("probabile", "⚠️ probabili"), ("assente", "❌ non presenti")]


def tabella(nome, out):
    righe = [f"### {nome}", "",
             "| Sezione | Righe | Righe con file citato | File citati | Trovati | " + " | ".join(l for _, l in COLS)
             + " | Solo nel rapporto iLEAPP/ALEAPP | Solo miniatura | Non trovati | " + " | ".join(l for _, l in LIV)
             + " | Più campi uniti |",
             "|---" * (12 + len(COLS)) + "|"]
    tot = collections.Counter()
    liv = lambda c: " | ".join(f"{c['livello:' + k]:,}" for k, _ in LIV) + f" | {c['uniti']:,} |"
    for sez, c in out.items():
        if not c["con_file"] and not sez.startswith("Allegati"):
            continue
        tot.update(c)
        trov = sum(c["trovato:" + k] for k, _ in COLS)
        righe.append(f"| {sez} | {c['righe']:,} | {c['con_file']:,} | {c['file']:,} | {trov:,} | "
                     + " | ".join(f"{c['trovato:' + k]:,}" for k, _ in COLS)
                     + f" | {c['rapporto']:,} | {c['miniatura']:,} | {c['assente']:,} | " + liv(c))
    trov = sum(tot["trovato:" + k] for k, _ in COLS)
    righe.append(f"| **Totale** | {tot['righe']:,} | {tot['con_file']:,} | {tot['file']:,} | {trov:,} | "
                 + " | ".join(f"{tot['trovato:' + k]:,}" for k, _ in COLS)
                 + f" | {tot['rapporto']:,} | {tot['miniatura']:,} | {tot['assente']:,} | " + liv(tot))
    return "\n".join(righe).replace(",", ".") + "\n"


def main():
    args = sys.argv[1:]
    md = None
    if "--md" in args:
        i = args.index("--md")
        md = Path(args[i + 1])
        del args[i:i + 2]
    if not args:
        raise SystemExit(__doc__)
    txt = []
    for root in args:
        case, out = conta_caso(root)
        nome = (case.meta.get("info") or {}).get("nome") or Path(root).name
        txt.append(tabella(nome, out))
        print(txt[-1], flush=True)
    if md:
        md.write_text("\n".join(txt), encoding="utf-8")


if __name__ == "__main__":
    main()
