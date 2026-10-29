# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - chat e chiamate ricavate dagli artefatti di iLEAPP/ALEAPP (dalla 2.20).

Le app di chat che RepertIA non legge con i propri lettori (Telegram, Discord, Instagram, Burner, Wickr, ...) e i
registri delle chiamate (telefono, FaceTime, Duo, app VoIP) si vedono anche in «Messaggi delle chat» (una riga per
conversazione, vista chat) e in «Chiamate» (una riga per chiamata). Le righe originali di iLEAPP/ALEAPP restano negli
Artefatti: qui si riordinano soltanto, con il riferimento alla riga di partenza (artefatto e numero di riga del caso).

- La corrispondenza tra colonne e campi è in `forense_mobile_leapp_mappa.json` (si estende senza toccare il codice).
  Per gli artefatti non elencati che iLEAPP/ALEAPP dichiarano come conversazione (vista «conversation» del loro
  file .lava) si usa la loro dichiarazione.
- Messaggi uguali (stesso identificativo, o stessa conversazione, data, verso e testo) letti da più artefatti o da
  copie dello stesso database (es. mirror di Magisk) sono un messaggio solo, con tutte le fonti.
- Chiamate: righe di fonti diverse con lo stesso numero (o la stessa app senza numero) entro 5 secondi (o la
  tolleranza della fonte, es. interactionC che segna l'inizio dell'interazione qualche secondo prima) sono la stessa
  chiamata; si tengono tutte le fonti e si segnalano i valori discordanti.
"""
import datetime as dt
import json
import re
from pathlib import Path

from forense_lingua import tr, N_  # noqa: E402

HERE = Path(__file__).resolve().parent
MAPPA = HERE / "forense_mobile_leapp_mappa.json"
STESSA_CHIAMATA_S = 5           # secondi entro cui due righe di fonti diverse sono la stessa chiamata («tolleranza_s» per fonte)
MAX_TOLL = 120
CALL_APP = {"telefono": N_("Telefono"), "facetime": "FaceTime"}
VERSI = {"out": N_("in uscita"), "in": N_("in arrivo"), "persa": N_("persa"), "rifiutata": N_("rifiutata"),
         "segreteria": N_("segreteria")}
TIPI = (N_("voce"), N_("video"), N_("audio"))      # valori di «tipo_valori» nella mappa, tradotti dove si mostrano
CHAT_RX = re.compile(r"messag|chat|direct|conversation|call|voip|dm\b", re.I)
VUOTI = {"", "none", "null", "nan", "(null)", "n/a", "no call duration"}


def carica():
    return json.loads(MAPPA.read_text(encoding="utf-8"))


def _val(c, f):
    if ">" in f or "+" in f:
        sep, parts = (" → ", f.split(">")) if ">" in f else (" ", f.split("+"))
        vals = [x for x in (_val(c, p) for p in parts) if x]
        return sep.join(vals) or None
    v = c.get(f)
    if v is None:
        return None
    v = str(v).strip().strip(",").strip()
    return None if v.lower() in VUOTI else v


def _get(c, fields):
    for f in fields or []:
        v = _val(c, f)
        if v:
            return v
    return None


def _match(v, valori):
    v = (v or "").strip().lower()
    if not v:
        return None
    for k, r in (valori or {}).items():
        if v.startswith(k.lower()):
            return r
    return None


BARRE = re.compile(r"^(\d{4})/(\d{2})/(\d{2}) (\d{2}:\d{2}:\d{2})$")


def _ts(v, spec=None):
    """Data ISO UTC. `ts_barre_utc` nella voce (2.20): «AAAA/MM/GG hh:mm:ss» è UTC (verificato con la documentazione per
    Google Voice di ALEAPP); senza, quel formato non si legge (fuso non noto)."""
    import forense_mobile_leapp as fml
    t = fml._iso(v) if v else None
    if not t and v and spec and spec.get("ts_barre_utc"):
        m = BARRE.match(str(v).strip())
        t = f"{m.group(1)}-{m.group(2)}-{m.group(3)}T{m.group(4)}" if m else None
    return t if t and t >= "1990" else None


def _durata(v):
    """Secondi da «hh:mm:ss», «mm:ss» o da un numero; None se manca."""
    if not v:
        return None
    s = str(v).strip()
    m = re.fullmatch(r"(?:(\d+)\s*min\.?)?\s*(?:(\d+)\s*sec\.?)?", s)     # (2.20) «1 min. 36 sec.» (TeleGuard di ALEAPP)
    if m and (m.group(1) or m.group(2)):
        return float(int(m.group(1) or 0) * 60 + int(m.group(2) or 0))
    if ":" in s:
        try:
            p = [float(x) for x in s.split(":")]
        except ValueError:
            return None
        tot = 0.0
        for x in p:
            tot = tot * 60 + x
        return round(tot, 3)
    try:
        return round(float(s), 3)
    except ValueError:
        return None


def hms(s):
    if s is None:
        return ""
    s = int(round(s))
    return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"


def _split_key(k):
    return tuple(k.split("|", 1)) if "|" in k else (None, k)


# ------------------------------------------------------------------------------ righe iLEAPP

class Righe:
    """Righe degli artefatti iLEAPP/ALEAPP del caso, lette una volta per artefatto."""

    def __init__(self, con):
        self.con = con
        self.cache = {}

    def get(self, key):
        tool, name = _split_key(key)
        k = (tool, name)
        if k not in self.cache:
            out = []
            for i, d, src, part in self.con.execute("SELECT id, data, src_path, part FROM artifacts WHERE cat='leapp' AND sub=?",
                                                    (name,)):
                try:
                    d = json.loads(d)
                except (TypeError, ValueError):
                    continue
                if tool and d.get("leapp") != tool:
                    continue
                out.append((i, d.get("campi") or {}, src, part, d.get("leapp")))
            self.cache[k] = out
        return self.cache[k]


def _nomi(R, spec):
    out = {}
    for _i, c, *_ in R.get(spec["artefatto"]):
        k = _val(c, spec["chiave"])
        n = _get(c, spec["nome"])
        if k and n:
            out.setdefault(k, n)
    return out


def _proprietario(R, spec):
    vals = set()
    for _i, c, *_ in R.get(spec["artefatto"]):
        ok = True
        for f, want in (spec.get("filtro") or {}).items():
            have = _val(c, f)
            ok = ok and (bool(have) if want == "*" else have == want)
        v = _val(c, spec["campo"]) if ok else None
        if v:
            vals.add(v)
    return vals


def _filtro(spec, c):
    for f, want in (spec.get("filtro") or {}).items():
        if (_val(c, f) or "") != want:
            return False
    return True


def _verso(spec, c, owners):
    if spec.get("proprietario"):
        mine = owners.get(spec["proprietario"]) or set()
        v = _get(c, spec.get("confronta"))
        if mine and v:
            return "out" if v in mine else "in"
        return "unk"
    vs = spec.get("verso")
    if not vs:
        return "unk"
    r = _match(_val(c, vs["campo"]), vs.get("valori"))
    pz = vs.get("presenza")         # (2.20) verso dalla presenza di un campo: {campo, si, no} (es. «From ID» di Line)
    if not r and pz:
        r = pz["si"] if _val(c, pz["campo"]) else pz["no"]
    return r or vs.get("predefinito") or "unk"


class Fonti:
    """Database di origine di ogni artefatto (source_path del file .lava; per riga, la colonna «Source File»),
    trovato nell'indice dell'estrazione: percorso, offset dell'estrazione e numero della voce (inode)."""

    def __init__(self, case, part):
        import forense_mobile as fm
        self.case, self.part, self.fm = case, part, fm
        self.lp = (case.meta.get("leapp") or {}).get("fonti") or {}
        self.memo = {}

    def per(self, artefatto, c=None):
        raw = (c and (_val(c, "Source File") or _val(c, "Source file name") or _val(c, "Source File Located"))) \
            or self.lp.get(artefatto) or ""
        raw = str(raw).split(",")[0].strip()
        if not raw:
            return None, None, None
        if raw not in self.memo:
            m = self.fm.mx(self.case)
            try:
                r = m.execute("SELECT id, path FROM mobile_files WHERE part=? AND isdir=0 AND path=?", (self.part, raw)).fetchone()
                if not r:
                    tail = "/".join(raw.replace("\\", "/").split("/")[-4:])
                    r = m.execute("SELECT id, path FROM mobile_files WHERE part=? AND isdir=0 AND path LIKE ? ESCAPE '\\' "
                                  "ORDER BY length(path) LIMIT 1",
                                  (self.part, "%" + tail.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_"))).fetchone()
            finally:
                m.close()
            self.memo[raw] = (self.part, str(r[0]), r[1]) if r else (None, None, raw)
        return self.memo[raw]


class Allegati:
    """File allegati citati da iLEAPP/ALEAPP, con la ricerca comune dei file citati (forense_percorsi): «media/…» del loro
    rapporto → file originale dell'estrazione (dal loro database), percorsi del telefono con la tabella dei percorsi,
    nome e dimensione; se l'originale manca resta la copia nel rapporto (mostrata come copia di lavoro)."""

    def __init__(self, case, part):
        import forense_percorsi as fp
        self.case, self.part, self.fp = case, part, fp
        self.idx = fp.IndiceEstrazione(case, part)
        self.memo = {}

    def trova(self, v):
        v = (v or "").strip()
        if not v:
            return None
        if v not in self.memo:
            fp = self.fp
            res = {"name": re.split(r"[\\/]", v.rstrip("/"))[-1][:200] or v[:200], "device_path": v}
            s = fp.valore_percorso(v)
            f = fp.forma(s) if s else None
            if f:
                r = self.idx.risolvi(s, f, {})
                if fp.univoco(r):
                    res.update({"part": r["part"], "inode": str(r["inode"]), "path": r["path"], "size": r["size"],
                                "metodo": r["metodo"]})
                elif r["stato"] == "rapporto" and r.get("rapporto"):
                    res["path"] = "leapp:" + r["rapporto"]
                    try:
                        res["size"] = (self.case.root / r["rapporto"]).stat().st_size
                    except OSError:
                        pass
            self.memo[v] = res
        return self.memo[v]


def _specs(case, mappa, sezione):
    """Voci della mappa per una sezione; per le chat anche le conversazioni dichiarate nel .lava e non elencate."""
    out = dict(mappa.get(sezione) or {})
    if sezione != "chat":
        return out, []
    lp = case.meta.get("leapp") or {}
    tool = lp.get("strumento")      # (2.20) una voce «ALEAPP|nome» non copre la stessa tabella di iLEAPP (e viceversa)
    names = {_split_key(k)[1] for k in out if _split_key(k)[0] in (None, tool)} | \
        set((mappa.get("escluse") or {}).get("artefatti") or [])
    auto = []
    for name, v in (lp.get("viste") or {}).items():
        if name in names or not v.get("textColumn"):
            continue
        sent = v.get("directionSentValue")
        spec = {"app": name.split(" - ")[0].strip(), "ts": [v.get("timeColumn")], "testo": [v.get("textColumn")],
                "mittente": [v.get("senderColumn")] if v.get("senderColumn") else [],
                "chat": [v["conversationDiscriminatorColumn"]] if v.get("conversationDiscriminatorColumn") else None,
                "titolo": [v["conversationLabelColumn"]] if v.get("conversationLabelColumn") else [],
                "allegato": [v["mediaColumn"]] if v.get("mediaColumn") else []}
        if v.get("directionColumn") and sent is not None:
            spec["verso"] = {"campo": v["directionColumn"], "valori": {str(sent).lower(): "out"}, "predefinito": "in"}
        out[name] = spec
        auto.append(name)
    return out, auto


# ---------------------------------------------------------------------------------- chat

def chat_from_leapp(case, con, names=None):
    """Conversazioni e messaggi dagli artefatti di iLEAPP/ALEAPP nelle tabelle chat_* (origine «leapp»). Da chiamare con
    le conversazioni «leapp» precedenti già cancellate. Restituisce {app: {...}}, {artefatto: righe usate}, [automatici]."""
    import forense_mobile as fm
    import forense_mobile_chat as fmc
    lp = case.meta.get("leapp") or {}
    if lp.get("esito") != "ok":
        return {}, {}, []
    fmc.ensure_schema(con)
    mappa = carica()
    specs, auto = _specs(case, mappa, "chat")
    R = Righe(con)
    nomi = {k: _nomi(R, s) for k, s in (mappa.get("nomi") or {}).items()}
    owners = {k: _proprietario(R, s) for k, s in (mappa.get("proprietari") or {}).items()}
    part = int(fm.sorgenti(case)[0]["offset"])
    F, A = Fonti(case, part), Allegati(case, part)
    names = names if names is not None else fmc.name_map(con)
    writers, usate, seen, dup = {}, {}, {}, {}
    tsend, tgroup, ttitle, tother = {}, {}, {}, {}
    # (2.20) artefatti che iLEAPP legge decifrando il database con la chiave del portachiavi (Signal, Session, SimpleX)
    import forense_mobile_portachiavi as fmk
    pk_uso = (((case.meta.get("leapp") or {}).get("portachiavi")) or {}).get("uso")
    decifrate = fmk.regole()["decifrate"] if pk_uso in ("fornito", "estrazione") else set()
    for key, spec in specs.items():
        _tool, name = _split_key(key)
        rows = R.get(key)
        if not rows:
            continue
        app = spec["app"]
        nm = nomi.get(spec.get("nomi")) or {}
        n_used = 0
        for rid, c, src, rpart, tool in rows:
            if not _filtro(spec, c):
                continue
            ts = _ts(_get(c, spec.get("ts")), spec)
            d = _verso(spec, c, owners)
            text = _get(c, spec.get("testo"))
            ev = _get(c, spec.get("evento")) if not text else None
            ch = spec.get("chat")
            if isinstance(ch, dict):
                tkey = _get(c, ch.get("out" if d == "out" else "in")) or _get(c, ch.get("in")) or ""
            else:
                tkey = _get(c, ch) if ch else ""
            tkey = tkey or ""
            mid = _get(c, spec.get("id"))
            dk = (app, "id", mid) if mid else (app, tkey, ts, d, text or ev or "")
            ref = {"strumento": tool, "artefatto": name, "riga": rid}
            n_used += 1                     # righe lette (anche quelle doppie, unite al primo messaggio)
            if dk in seen:
                dup.setdefault(seen[dk], []).append(ref)
                continue
            fp, fi, fpath = F.per(name, c)
            W = writers.get(app)
            if not W:
                W = writers[app] = fmc.Writer(con, app, fp if fp is not None else part, fi, fpath or name)
                W.inode = fi
            W.part, W.inode = (fp if fp is not None else part), fi
            snd = _get(c, spec.get("mittente"))
            snd_name = nm.get(snd) if snd else None
            title = _get(c, spec.get("titolo"))
            title = nm.get(title, title) if title else (nm.get(tkey) if tkey else None)
            if not ch:
                title = tr("{app} (conversazioni non distinte da {s})").format(app=app, s=tool)
            other = _get(c, spec.get("interlocutore")) if d != "out" or not spec.get("interlocutore_se_in") else None
            th = W.thread(tkey, title or tkey or app, [other or tkey] if (other or tkey) else [])
            if other and th not in tother:
                tother[th] = other
            if title and (th not in ttitle or (d != "out" and not ttitle[th][1])):
                ttitle[th] = (title, d != "out")
            if d != "out" and snd:
                tsend.setdefault(th, {}).setdefault(snd_name or snd, 0)
                tsend[th][snd_name or snd] += 1
            g = spec.get("gruppo")
            if g and (_val(c, g["campo"]) or "").lower() in g.get("valori", []):
                tgroup[th] = True
            acc = _get(c, spec.get("account")) or (sorted(owners.get(spec.get("proprietario")) or [None])[0])
            if acc:
                W.see_local(th, acc)
            kind, extra = "testo", {"fonte": "leapp", "strumento": tool, "artefatto": name, "riga_leapp": rid}
            if name in decifrate:
                extra["decifrato"] = pk_uso
            if not text:
                if ev:
                    kind = "sistema"
                    text = ev
                elif spec.get("nota_senza_testo"):
                    extra["tipo"] = tr(spec["nota_senza_testo"])
            atts = []
            av = _get(c, spec.get("allegato"))
            if av:
                atts.append(A.trova(av))
                if kind == "testo" and not text:
                    kind = "allegato"
            pos = spec.get("posizione")
            lat = lon = None
            if pos:
                try:
                    lat, lon = float(_val(c, pos[0])), float(_val(c, pos[1]))
                except (TypeError, ValueError):
                    lat = lon = None
            msg = W.message(th, ts, "sys" if kind == "sistema" and d == "unk" else d, snd, text, kind,
                            f"{tool} «{name}»", rid, sender_name=snd_name if snd_name != snd else None, extra=extra)
            seen[dk] = msg
            for a in atts:
                W.attachment(msg, a.get("name"), None, a.get("size"), a.get("device_path"),
                             (a.get("part"), a.get("inode"), a.get("path")) if a.get("path") else None, metodo=a.get("metodo"))
            if lat is not None and lon is not None and (lat or lon):
                W.attachment(msg, tr("posizione"), None, None, None, None, lat, lon)
        if n_used:
            usate[key] = n_used
    # fonti in più dei messaggi doppi, titoli, gruppi, numero/account di questo telefono
    for mid, refs in dup.items():
        r = con.execute("SELECT extra FROM chat_messages WHERE id=?", (mid,)).fetchone()
        ex = json.loads(r[0]) if r and r[0] else {}
        ex["altre_fonti"] = refs
        con.execute("UPDATE chat_messages SET extra=? WHERE id=?", (json.dumps(ex, ensure_ascii=False), mid))
    out = {}
    for app, W in writers.items():
        ids = list(W.threads.values())
        for th in ids:
            snd = tsend.get(th) or {}
            if tgroup.get(th):
                con.execute("UPDATE chat_threads SET is_group=1, participants=? WHERE id=?",
                            (json.dumps(sorted(snd), ensure_ascii=False), th))
            if th in ttitle:
                con.execute("UPDATE chat_threads SET title=? WHERE id=?", (ttitle[th][0], th))
            elif snd:                       # senza titolo: il mittente più frequente dei messaggi ricevuti
                con.execute("UPDATE chat_threads SET title=? WHERE id=?", (max(snd, key=snd.get), th))
            if th in tother:
                con.execute("UPDATE chat_threads SET participants=? WHERE id=? AND is_group=0",
                            (json.dumps([tother[th]], ensure_ascii=False), th))
        for th, cnt in W.local.items():
            con.execute("UPDATE chat_threads SET local=? WHERE id=?", (max(cnt, key=cnt.get), th))
        con.execute(f"UPDATE chat_threads SET origin='leapp' WHERE id IN ({','.join('?' * len(ids))})", ids)
        out[app] = {"conversazioni": len(ids), "messaggi": W.n_msg, "allegati": W.n_att, "fonti": [W.src],
                    "fonte": lp.get("strumento")}
    return out, usate, auto


def _leapp_thread_ids(con):
    import forense_mobile_chat as fmc
    fmc.ensure_schema(con)
    return [r[0] for r in con.execute("SELECT id FROM chat_threads WHERE origin='leapp'")]


def remove_leapp_chats(con):
    """Toglie conversazioni, messaggi, allegati, eventi e righe «Messaggi» ricavati da iLEAPP/ALEAPP."""
    ids = _leapp_thread_ids(con)
    if not ids:
        return set()
    j = json.dumps(ids)
    apps = {r[0] for r in con.execute("SELECT DISTINCT app FROM chat_threads WHERE origin='leapp'")}
    con.execute("DELETE FROM chat_attachments WHERE msg IN (SELECT id FROM chat_messages WHERE thread IN "
                "(SELECT value FROM json_each(?)))", (j,))
    con.execute("DELETE FROM chat_messages WHERE thread IN (SELECT value FROM json_each(?))", (j,))
    con.execute("DELETE FROM chat_threads WHERE origin='leapp'")
    con.execute("DELETE FROM artifacts WHERE cat='messaggi' AND data LIKE '%\"chat_thread\"%' AND "
                "json_extract(data, '$.chat_thread') IN (SELECT value FROM json_each(?))", (j,))
    if apps:
        con.execute(f"DELETE FROM events WHERE origin='chat' AND source IN ({','.join('?' * len(apps))})", list(apps))
    return apps


# ------------------------------------------------------------------------------- chiamate

def fonti_txt(fonti):
    """«iLEAPP «Call History», iLEAPP «interactionC …» ×2»: artefatti di provenienza, con quante righe ciascuno."""
    cnt = {}
    for f in fonti:
        k = f"{f.get('strumento')} «{f.get('artefatto')}»"
        cnt[k] = cnt.get(k, 0) + 1
    return ", ".join(k + (f" ×{n}" if n > 1 else "") for k, n in cnt.items())


def call_label(app):
    return tr(CALL_APP[app]) if app in CALL_APP else app


def calls_from_leapp(case, con, names=None):
    """Una riga di «Chiamate» per chiamata (categoria «chiamate», gruppo = app), con le fonti unite; anche nella
    timeline (origine «chiamate»). Restituisce il riepilogo per meta["chiamate"]."""
    import forense_agent as fa
    import forense_mobile as fm
    import forense_mobile_chat as fmc
    fmc.ensure_art_cols(con)
    con.execute("DELETE FROM artifacts WHERE cat='chiamate'")
    con.execute("DELETE FROM events WHERE origin='chiamate'")
    lp = case.meta.get("leapp") or {}
    import forense_mobile_chiamate as fmca
    proprie, usate_proprie = fmca.raccogli(case, con)      # lette dai database delle app (fonti verificate)
    if lp.get("esito") != "ok" and not proprie:
        return None
    mappa = carica()
    specs = _specs(case, mappa, "chiamate")[0] if lp.get("esito") == "ok" else {}
    R = Righe(con)
    nomi = {k: _nomi(R, s) for k, s in (mappa.get("nomi") or {}).items()}
    owners = {k: _proprietario(R, s) for k, s in (mappa.get("proprietari") or {}).items()}
    part = int(fm.sorgenti(case)[0]["offset"])
    F = Fonti(case, part)
    names = names if names is not None else fmc.name_map(con)
    raw, usate, by_id = [], {}, {}
    for key, spec in specs.items():
        _tool, name = _split_key(key)
        nm = nomi.get(spec.get("nomi")) or {}
        n = 0
        for rid, c, src, rpart, tool in R.get(key):
            if not _filtro(spec, c):
                continue
            ad = spec.get("app_da")
            if ad:
                pv = _val(c, ad["campo"]) or ""
                app = _match(pv, ad.get("valori")) or (pv if ad.get("predefinito") == "*" and pv else ad.get("predefinito")) or "telefono"
            else:
                app = spec.get("app") or "telefono"
            v = _verso(spec, c, owners)
            ts, fine = _ts(_get(c, spec.get("ts")), spec), _ts(_get(c, spec.get("fine")), spec)
            dur = _durata(_get(c, spec.get("durata")))
            nsp = spec.get("numero")        # (2.20) {"in": [...], "out": [...]}: il numero dell'altra persona dipende dal verso
            numero = _get(c, nsp.get("out" if v == "out" else "in")) if isinstance(nsp, dict) else _get(c, nsp)
            nome_app = None if spec.get("nome_se_in") and v == "out" else _get(c, spec.get("nome"))
            if numero and numero in nm:
                nome_app = nome_app or nm[numero]
            tipo = _get(c, spec.get("tipo"))
            if tipo and spec.get("tipo_valori"):
                tipo = tr(spec["tipo_valori"].get(tipo, tipo))
            rec = {"app": app, "fine_inizio": bool(spec.get("fine_come_inizio")), "debole": bool(spec.get("app_debole")), "toll": float(spec.get("tolleranza_s") or STESSA_CHIAMATA_S), "ts": ts, "fine": fine, "verso": v, "numero": numero,
                   "nome_app": nome_app, "durata_s": dur, "tipo": tipo, "esito": _get(c, spec.get("esito")),
                   "account": _get(c, spec.get("account")), "nota": tr(spec["nota"]) if spec.get("nota") else None,
                   "fonti": [{"strumento": tool, "artefatto": name, "riga": rid}], "src": F.per(name, c)}
            rs = spec.get("risposta")
            if rs:
                a = (_val(c, rs["campo"]) or "").lower()
                rec["risposta"] = True if a in rs.get("si", []) else False if a in rs.get("no", []) else None
            cid = _get(c, spec.get("id"))
            fs = spec.get("fine_se")
            if cid and (app, cid) in by_id:        # stessa chiamata in più righe (inizio e fine, copie del database)
                prev = by_id[(app, cid)]
                is_end = fs and (_val(c, fs["campo"]) or "").lower() in [x.lower() for x in fs.get("valori", [])]
                if is_end and ts:
                    prev["fine"] = prev.get("fine") or ts
                prev["fonti"].append(rec["fonti"][0])
                n += 1
                continue
            if fs and (_val(c, fs["campo"]) or "").lower() in [x.lower() for x in fs.get("valori", [])]:
                rec["fine"], rec["ts"] = ts, None
            if cid:
                by_id[(app, cid)] = rec
            raw.append(rec)
            n += 1
        if n:
            usate[key] = n
    raw += proprie
    usate.update(usate_proprie)
    for r in raw:
        if r["ts"] is None and r.get("fine") and r.get("durata_s") is not None:
            try:
                t = dt.datetime.fromisoformat(r["fine"]) - dt.timedelta(seconds=r["durata_s"])
                r["ts"] = t.strftime("%Y-%m-%dT%H:%M:%S")
            except ValueError:
                pass
        if r["ts"] is None and r.get("fine") and r.get("durata_s") is None and r.get("fine_inizio"):
            r["ts"] = r["fine"]         # (2.20) senza durata (chiamata annullata) l'orario della riga è l'inizio
        if r["durata_s"] is None and r.get("fine") and r.get("ts"):
            try:
                d = (dt.datetime.fromisoformat(r["fine"]) - dt.datetime.fromisoformat(r["ts"])).total_seconds()
                r["durata_s"] = d if d >= 0 else None
            except ValueError:
                pass
    # doppioni tra fonti diverse: stesso numero (o stessa app senza numero) entro pochi secondi
    # a parità di orario prima le righe di iLEAPP/ALEAPP: le chiamate lette da RepertIA si aggiungono come fonte
    raw.sort(key=lambda r: (r["ts"] or "9999", r["fonti"][0].get("strumento") == "RepertIA", r["fonti"][0]["artefatto"]))
    calls = []

    def secs(t):
        try:
            return dt.datetime.fromisoformat(t).timestamp()
        except (TypeError, ValueError):
            return None
    for r in raw:
        k = fmc.norm_number(r["numero"]) if r["numero"] else None
        t = secs(r["ts"])
        hit = None
        if t is not None:
            for c in reversed(calls):
                tc = c["_t"]
                if tc is None or t - tc > MAX_TOLL:
                    break
                if t - tc > max(c["toll"], r["toll"]):
                    continue
                same = (k and c["_k"] == k) or (not k and not c["_k"] and (c["app"] == r["app"] or c["debole"] or r["debole"]))
                if same and not {f["artefatto"] for f in c["fonti"]} & {f["artefatto"] for f in r["fonti"]}:
                    hit = c
                    break
        if not hit:
            r["_k"], r["_t"] = k, t
            calls.append(r)
            continue
        hit["fonti"] += r["fonti"]
        # orari diversi tra il messaggio WhatsApp di tipo 59 e il registro delle chiamate (chiamate in uscita)
        if t is not None and hit["_t"] is not None and abs(t - hit["_t"]) > 10 and \
                "ZWAMESSAGE" in {f.get("tabella") for f in hit["fonti"]}:
            hit.setdefault("discordanze", []).append({"campo": "ts", "valore": r["ts"], "fonte": r["fonti"][0]["artefatto"]})
        if hit["debole"] and not r["debole"]:
            # (2.20) anche l'orario dalla fonte non debole (es. Call History invece di interactionC, che segna l'inizio
            # dell'interazione qualche secondo prima)
            hit["app"], hit["debole"], hit["ts"] = r["app"], False, r["ts"] or hit["ts"]
        for f in ("verso", "numero", "nome_app", "durata_s", "tipo", "esito", "risposta", "fine", "account", "nota"):
            a, b = hit.get(f), r.get(f)
            # la nota del tipo 59 parla dell'orario d'inizio: vale solo se l'orario della chiamata viene da quel messaggio
            if f == "nota" and r["fonti"][0].get("tabella") == "ZWAMESSAGE":
                continue
            if a in (None, "", "unk"):
                hit[f] = b
            elif b not in (None, "", "unk") and a != b and f in ("verso", "durata_s", "risposta"):
                hit.setdefault("discordanze", []).append({"campo": f, "valore": b, "fonte": r["fonti"][0]["artefatto"]})
    rows, evs, per_app = [], [], {}
    for r in calls:
        if r.get("risposta") is None:
            if r["verso"] in ("persa", "rifiutata", "segreteria"):
                r["risposta"] = False
            elif r.get("durata_s"):
                r["risposta"] = True
        nome_rub = names.get(fmc.norm_number(r["numero"])) if r["numero"] else None
        lbl = call_label(r["app"])
        who = " ".join(x for x in (nome_rub or r.get("nome_app"), r["numero"]) if x) or tr("(non indicato)")
        vv = tr(VERSI[r["verso"]]) if r["verso"] in VERSI else tr("verso non indicato")
        title = tr("{app}: chiamata {v} · {who}").format(app=lbl, v=vv, who=who)
        det = " · ".join(x for x in (
            tr("durata {d}").format(d=hms(r["durata_s"])) if r.get("durata_s") is not None else None,
            (tr("risposta: sì") if r["risposta"] else tr("risposta: no")) if r.get("risposta") is not None else None,
            r.get("tipo"), r.get("esito"), r.get("nota"),
            tr("fonti: {f}").format(f=fonti_txt(r["fonti"]))) if x)
        sp, si, spath = r["src"] if r["src"] else (None, None, None)
        data = {"chiamata": True, "app": r["app"], "app_lbl": lbl, "verso": r["verso"], "numero": r["numero"],
                "nome_rubrica": nome_rub, "nome_app": r.get("nome_app"), "ts": r["ts"], "fine": r.get("fine"),
                "durata_s": r.get("durata_s"), "risposta": r.get("risposta"), "tipo": r.get("tipo"), "esito": r.get("esito"),
                "account": r.get("account"), "nota": r.get("nota"), "fonti": r["fonti"], "discordanze": r.get("discordanze")}
        rows.append(("chiamate", r["ts"], title[:300], det, "", spath or "", sp, si, json.dumps(data, ensure_ascii=False),
                     r["app"], None))
        per_app[r["app"]] = per_app.get(r["app"], 0) + 1
        if r["ts"]:
            evs.append((r["ts"], "CALL", lbl, spath or "", f"{lbl} | {vv} | {who}" + (f" | {hms(r['durata_s'])}" if r.get("durata_s") is not None else ""),
                        "chiamate", None))
    con.executemany("INSERT INTO artifacts(cat, ts, title, detail, user, src_path, part, inode, data, grp, sub) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
    con.executemany(fa.INSERT_EV, evs)
    return {"n": len(calls), "righe": sum(usate.values()), "unite": sum(len(c["fonti"]) - 1 for c in calls), "app": per_app,
            "artefatti": usate, "ts": fa.now()}


# ------------------------------------------------------------------------------- insieme

def non_mappati(case, con):
    """Artefatti di iLEAPP/ALEAPP del caso che sembrano chat o chiamate ma non sono nella mappa (per il registro)."""
    mappa = carica()
    known = {_split_key(k)[1] for s in ("chat", "chiamate") for k in (mappa.get(s) or {})}
    known |= set((mappa.get("escluse") or {}).get("artefatti") or [])
    known |= {s["artefatto"].split("|", 1)[-1] for s in list((mappa.get("nomi") or {}).values()) + list((mappa.get("proprietari") or {}).values())}
    known |= set(((case.meta.get("leapp") or {}).get("viste") or {}).keys())
    return sorted({r[0] for r in con.execute("SELECT DISTINCT sub FROM artifacts WHERE cat='leapp'")
                   if r[0] and r[0] not in known and CHAT_RX.search(r[0])})


def run(case, con, say=print):
    """Dopo l'importazione di iLEAPP/ALEAPP: rifà le conversazioni «leapp» (lasciando quelle dei lettori di RepertIA)
    e le chiamate, aggiorna riepilogo, timeline e artefatti."""
    import forense_mobile_chat as fmc
    remove_leapp_chats(con)
    names = fmc.name_map(con) if con.execute("SELECT name FROM sqlite_master WHERE name='chat_contacts'").fetchone() else {}
    apps, usate, auto = chat_from_leapp(case, con, names)
    ids = _leapp_thread_ids(con)
    if ids:
        fmc.thread_stats(con, ids)
        ids = _leapp_thread_ids(con)
        fmc.chat_events(con, ids)
        fmc.thread_artifacts(con, names, ids)
    ch = case.meta.setdefault("chat", {})
    ch["app"] = {k: v for k, v in (ch.get("app") or {}).items() if not v.get("fonte")}
    ch["app"].update(apps)
    cs = calls_from_leapp(case, con, names)
    case.meta["chiamate"] = cs
    nm = non_mappati(case, con)
    case.meta["leapp_chat"] = {"chat": usate, "automatici": auto, "chiamate": (cs or {}).get("artefatti", {}), "non_mappati": nm}
    con.commit()
    fmc.aggiorna_estese(case, con)
    case.log("leapp_chat", {"app": {k: v["messaggi"] for k, v in apps.items()}, "chiamate": (cs or {}).get("n"),
                            "artefatti": usate, "non_mappati": nm})
    case.save()
    if apps:
        say(tr("Chat da {s}: {a}").format(s=(case.meta.get("leapp") or {}).get("strumento", "iLEAPP/ALEAPP"),
                                           a=", ".join(f"{k} {v['messaggi']}" for k, v in sorted(apps.items()))))
    if cs:
        say(tr("Chiamate: {n} (righe lette {r}, fonti unite {u})").format(n=cs["n"], r=cs["righe"], u=cs["unite"]))
    return apps, cs
