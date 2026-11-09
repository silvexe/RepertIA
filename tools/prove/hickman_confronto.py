# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Confronta un caso RepertIA delle immagini Android 14 / iOS 17 di Hickman con i riferimenti dei documenti allegati
all'immagine (hickman_riferimenti_android14.py, hickman_riferimenti_ios17.py). Solo lettura del caso.
Uso: hickman_confronto.py <cartella del caso> <modulo dei riferimenti> <InstalledAppsList.txt o -> <uscita.json>"""
import importlib, json, re, sqlite3, sys
sys.stdout.reconfigure(encoding="utf-8")
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
R = importlib.import_module(sys.argv[2])
CASO, APPLIST, OUT = Path(sys.argv[1]), (None if sys.argv[3] == "-" else Path(sys.argv[3])), Path(sys.argv[4])
APP = getattr(R, "APP", {})            # filtro dell'app nel caso, se diverso dal nome
con = sqlite3.connect(f"file:{CASO / 'caso.sqlite'}?mode=ro", uri=True)
q = lambda s, a=(): con.execute(s, a).fetchall()
TOLL = timedelta(minutes=2)          # l'ora del documento è al minuto e scritta a mano


def norm(s):
    return re.sub(r"\s+", " ", (s or "").replace("’", "'").replace("‘", "'").lower()).strip()


def finestra(data, ora):
    t = datetime.strptime(R.utc(data, ora), "%Y-%m-%d %H:%M")
    return (t - TOLL).strftime("%Y-%m-%dT%H:%M:%S"), (t + TOLL + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S")


def chat(app_like, rif):
    out = []
    for data, ora, dire, testo in rif:
        a, b = finestra(data, ora)
        righe = q("select ts,direction,text,kind,n_att,app from chat_messages where lower(app) like ? and ts between ? and ? "
                  "and direction=?", (app_like, a, b, dire))
        if testo:
            ok = [r for r in righe if norm(testo) in norm(r[2])]
        else:
            ok = [r for r in righe if r[3] == "allegato" or (r[4] or 0) > 0]
        out.append({"data": data, "ora_locale": ora, "utc": R.utc(data, ora), "verso": dire, "testo": testo or "(allegato)",
                    "esito": "trovato" if ok else "non trovato", "repertia": ok[0][0] if ok else None})
    return out


def cancellati(app_like, rif):
    out = []
    for data, ora, dire, testo in rif:
        a, b = finestra(data, ora)
        nella_chat = [r for r in q("select ts,app,status,kind,extra from chat_messages where lower(app) like ? and ts between ? and ?",
                                   (app_like, a, b)) if True]
        nome = app_like.strip("%")
        testo_chat = q("select ts,app,kind,status from chat_messages where lower(app) like ? and lower(text) like ?",
                       (app_like, f"%{norm(testo)}%"))
        testo_art = q("select ts,sub,substr(title,1,80) from artifacts where (lower(grp) like ? or lower(sub) like ?) and "
                      "(lower(detail) like ? or lower(data) like ?) limit 5",
                      (f"%{nome}%", f"%{nome}%", f"%{norm(testo)}%", f"%{norm(testo)}%"))
        out.append({"data": data, "ora_locale": ora, "utc": R.utc(data, ora), "testo": testo,
                    "nel_caso": bool(testo_chat or testo_art), "chat": testo_chat[:3], "artefatti": testo_art[:3],
                    "voci_in_quel_minuto": [list(r[:4]) for r in nella_chat][:5]})
    return out


def chiamate():
    out = []
    righe = [(r[0], json.loads(r[1] or "{}")) for r in q("select ts,data from artifacts where cat='chiamate' and ts is not null")]
    for data, ora, dire, num in R.CHIAMATE:
        a, b = finestra(data, ora)
        ok = [(ts, d) for ts, d in righe if a <= ts <= b and d.get("app") == "telefono"
              and re.sub(r"\D", "", d.get("numero") or "").endswith(num)]
        out.append({"data": data, "ora_locale": ora, "utc": R.utc(data, ora), "verso_doc": dire, "numero": num,
                    "esito": "trovato" if ok else "non trovato",
                    "repertia": [(ts, d.get("verso"), d.get("durata_s")) for ts, d in ok][:2]})
    return out


def chiamate_app(app, rif):
    out = []
    righe = [(r[0], json.loads(r[1] or "{}")) for r in q("select ts,data from artifacts where cat='chiamate' and ts is not null")]
    msg = q("select ts,direction,text,extra from chat_messages where lower(app) like ? and kind='chiamata'", (app,))
    for data, ora, dire, tipo in rif:
        a, b = finestra(data, ora)
        ok = [(ts, d.get("verso"), d.get("video")) for ts, d in righe if a <= ts <= b and app.strip("%") in (d.get("app") or "").lower()]
        ok += [(r[0], r[1], r[2]) for r in msg if a <= r[0] <= b]
        out.append({"data": data, "ora_locale": ora, "utc": R.utc(data, ora), "verso": dire, "tipo": tipo,
                    "esito": "trovato" if ok else "non trovato", "repertia": ok[:2]})
    return out


def web():
    out = []
    subs = getattr(R, "WEB_SUB", ("Web History", "Web Visits"))
    righe = q(f"select ts,lower(title||' '||coalesce(detail,'')),src_path from artifacts where sub in ({','.join('?' * len(subs))})", subs)
    for data, ora, frammento in R.CHROME:
        a, b = finestra(data, ora)
        f = norm(frammento)
        ok = [r for r in righe if a <= r[0] <= b and (getattr(R, "WEB_SOLO_ORA", False)
              or f in r[1] or f.replace(" ", "+") in r[1] or f.replace(" ", "%20") in r[1])]
        out.append({"data": data, "ora_locale": ora, "utc": R.utc(data, ora), "cerca": frammento,
                    "esito": "trovato" if ok else "non trovato", "repertia": ok[0][0] if ok else None})
    (d1, o1), (d2, o2) = getattr(R, "PRIVATA", (("2024-07-13", "21:24"), ("2024-07-13", "21:36")))
    a, _ = finestra(d1, o1); _, b = finestra(d2, o2)
    inco = [{"cerca": f, "presente": bool([r for r in righe if a <= r[0] <= b and f.lower() in r[1]])}
            for f in R.CHROME_INCOGNITO]
    return out, inco


def wifi_bt():
    gw = getattr(R, "WIFI_GRP", ("WiFi Profiles",))
    w = " ".join(r[0] for r in q("select lower(title||' '||coalesce(detail,'')||' '||coalesce(data,'')) from artifacts "
                                 f"where grp in ({','.join('?' * len(gw))})", gw))
    bt = " ".join(r[0] for r in q("select lower(title||' '||coalesce(detail,'')||' '||coalesce(data,'')) from artifacts where grp like 'Bluetooth%'"))
    return ([{"ssid": s, "esito": "trovato" if s.lower() in w else "non trovato"} for s in R.WIFI],
            [{"nome": n, "mac": m, "esito": "trovato" if m in bt or (getattr(R, "BT_NOME", False) and n.lower() in bt) else "non trovato",
              "mac_trovato": m in bt, "nome_trovato": n.lower() in bt} for n, m in R.BLUETOOTH])


def identita():
    meta = json.loads((CASO / "case.json").read_text(encoding="utf-8"))
    sis = (meta.get("mobile") or {}).get("sistema") or {}
    testo_case = json.dumps(meta, ensure_ascii=False).lower()
    reg = (CASO / "audit_log.jsonl").read_text(encoding="utf-8", errors="replace").lower() if (CASO / "audit_log.jsonl").exists() else ""
    imei = {i: bool(q("select 1 from artifacts where detail like ? or data like ? limit 1", (f"%{i}%", f"%{i}%")))
            for i in R.IDENTITA.get("imei", [])}
    out = {"sha256": R.IDENTITA["sha256_zip"] in testo_case or R.IDENTITA["sha256_zip"] in reg,
           "versione": sis.get("versione"), "patch": sis.get("patch"), "build": sis.get("build"), "imei": imei,
           "sistema": sis}
    if APPLIST:
        pk_caso = {json.loads(r[0])["campi"].get("Name") or json.loads(r[0])["campi"].get("Package Name")
                   for r in q("select data from artifacts where sub='package_info'")}   # campo completo, non il titolo
        pk_allegato = {l.strip() for l in APPLIST.read_text(encoding="utf-8").splitlines() if l.strip()}
        out.update({"app_caso": len(pk_caso), "app_allegato": len(pk_allegato), "solo_allegato": sorted(pk_allegato - pk_caso),
                    "solo_caso": sorted(pk_caso - pk_allegato)})
    return out


ris = {"identita": identita(),
       "sms": chat(APP.get("sms", "sms"), R.SMS), "sms_cancellati": cancellati(APP.get("sms", "sms"), R.SMS_CANCELLATI),
       "whatsapp": chat("whatsapp", R.WHATSAPP), "whatsapp_cancellati": cancellati("whatsapp", R.WHATSAPP_CANCELLATI),
       "whatsapp_chiamate": chiamate_app("%whatsapp%", R.WHATSAPP_CHIAMATE),
       "signal": chat("signal", R.SIGNAL), "signal_cancellati": cancellati("signal", R.SIGNAL_CANCELLATI),
       "telegram": chat("telegram", R.TELEGRAM), "telegram_cancellati": cancellati("telegram", R.TELEGRAM_CANCELLATI),
       "chiamate": chiamate()}
if hasattr(R, "SMS_MODIFICATI"):
    ris["sms_modificati"] = chat(APP.get("sms", "sms"), R.SMS_MODIFICATI)
ris["chrome"], ris["chrome_incognito"] = web()
ris["wifi"], ris["bluetooth"] = wifi_bt()
OUT.write_text(json.dumps(ris, ensure_ascii=False, indent=1), encoding="utf-8")
for k, v in ris.items():
    if isinstance(v, list) and v and "esito" in v[0]:
        print(f"{k:20} {sum(x['esito'] == 'trovato' for x in v)}/{len(v)}",
              "  mancano:", [(x.get('ora_locale'), x.get('testo') or x.get('cerca') or x.get('ssid') or x.get('nome') or x.get('numero')) for x in v if x["esito"] != "trovato"][:6])
    elif k.endswith("cancellati"):
        print(f"{k:20} nel caso: {[x['nel_caso'] for x in v]}  {[(x['chat'], x['artefatti']) for x in v]}")
print("incognito presenti:", [x for x in ris["chrome_incognito"] if x["presente"]])
i = ris["identita"]; print("identita:", {k: i.get(k) for k in ("sha256", "versione", "patch", "build", "imei", "app_caso", "app_allegato")},
                         "solo allegato", i.get("solo_allegato", [])[:10], "solo caso", i.get("solo_caso", [])[:10])
