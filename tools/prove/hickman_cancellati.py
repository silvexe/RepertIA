# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Validazione Android 14: i messaggi che Hickman ha cancellato si ritrovano con il recupero dei record cancellati di
RepertIA (forense_recupero.recupera, lo stesso del pulsante «Record cancellati»)? Legge copie dei database originali.
Uso: hickman_cancellati.py <cartella grezzi> <uscita.json>"""
import json, sys
sys.stdout.reconfigure(encoding="utf-8")
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import forense_recupero as fr
import hickman_riferimenti_android14 as R

G, OUT = Path(sys.argv[1]), Path(sys.argv[2])
CASI = [("Messaggi (bugle_db)", G / "bugle" / "bugle_db", R.SMS_CANCELLATI),
        ("Messaggi (mmssms.db)", G / "mmssms" / "mmssms.db", R.SMS_CANCELLATI),
        ("WhatsApp (msgstore.db)", G / "whatsapp" / "msgstore.db", R.WHATSAPP_CANCELLATI),
        ("Telegram (cache4.db)", G / "telegram" / "cache4.db", R.TELEGRAM_CANCELLATI)]
norm = lambda s: (s or "").replace("’", "'").lower()
ris = []
for nome, db, rif in CASI:
    r = fr.recupera(str(db))
    for data, ora, dire, testo in rif:
        hit = [x for x in r["record"] if any(norm(testo) in norm(str(v)) for v in x["valori"])]
        ris.append({"database": nome, "data": data, "ora_locale": ora, "testo": testo, "record_recuperati": len(r["record"]),
                    "troncato": r["troncato"], "scaduto": r["scaduto"], "trovato": bool(hit),
                    "dove": [{k: x.get(k) for k in ("tabella", "fonte", "livello", "pagina")} for x in hit][:3]})
        print(f"{nome:26} {testo[:40]:42} recuperati {len(r['record']):5}  trovato: {bool(hit)}  {ris[-1]['dove'][:1]}")
OUT.write_text(json.dumps(ris, ensure_ascii=False, indent=1), encoding="utf-8")
