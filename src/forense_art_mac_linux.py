#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - cronologia dei browser (tutti i sistemi) e artefatti di macOS e Linux.

(3.0.4) Codice spostato da forense_estesa.py senza modifiche, per avere file più corti. Si carica tramite
forense_estesa, che ne riesporta i nomi: gli altri moduli continuano a usare «fe.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fe.<nome>»).
"""
import plistlib
import re
import shutil
import sqlite3
from pathlib import Path
from forense_lingua import tr
import forense_agent as fa

import forense_estesa as fe
from forense_estesa import (
    decode_bytes, filetime, iso, safe_name, unixtime, user_of)

# ---- browser (tutti i sistemi)

def chrome_time(us):
    try:
        us = int(us)
        return filetime(us * 10) if us > 0 else None
    except (TypeError, ValueError):
        return None


def browser_history(A, ctx, part):
    con = ctx.con
    cands = []
    for p, inode, d, path in con.execute(
            "SELECT part, inode, deleted, path FROM files WHERE part=? AND type LIKE '%r' AND deleted=0 AND "
            "(lower(path) LIKE '%/history' OR lower(path) LIKE '%/places.sqlite' OR lower(path) LIKE '%/history.db')",
            (part,)):
        low = path.lower()
        if low.endswith("/history") and re.search(r"chrome|chromium|edge|brave|opera|vivaldi|yandex|coccoc", low):
            cands.append(("chrome", p, inode, path))
        elif low.endswith("/places.sqlite"):
            cands.append(("firefox", p, inode, path))
        elif low.endswith("/history.db") and "safari" in low:
            cands.append(("safari", p, inode, path))
    for kind, p, inode, path in cands:
        f = fe.fetch(ctx, p, inode, path, 2 << 30)
        if not f or open(f, "rb").read(16) != b"SQLite format 3\x00":
            continue
        user = user_of(path)
        m = re.search(r"(?i)(google/chrome|microsoft/edge|bravesoftware|opera software|vivaldi|chromium|firefox|safari)", path)
        br = {"google/chrome": "Chrome", "microsoft/edge": "Edge", "bravesoftware": "Brave", "opera software": "Opera",
              "vivaldi": "Vivaldi", "chromium": "Chromium", "firefox": "Firefox", "safari": "Safari"}.get(
            (m.group(1).lower() if m else ""), kind.capitalize())
        src = (p, inode, path)
        try:
            db = sqlite3.connect(f"file:{f.as_posix()}?mode=ro&immutable=1", uri=True)
            if kind == "chrome":
                for url, title, n, t in db.execute("SELECT url, title, visit_count, last_visit_time FROM urls "
                                                   "ORDER BY last_visit_time DESC LIMIT 50000"):
                    A.add("web", chrome_time(t), title or url, tr("{br}: {url} · {n} visite").format(br=br, url=url, n=n), user, src,
                          {"browser": br, "url": url, "visite": n})
                try:
                    for target, st, total, url in db.execute(
                            "SELECT d.target_path, d.start_time, d.total_bytes, "
                            "(SELECT url FROM downloads_url_chains c WHERE c.id=d.id ORDER BY chain_index DESC LIMIT 1) "
                            "FROM downloads d"):
                        A.add("download", chrome_time(st), target or url, tr("{br}: scaricato da {url} · {total} byte").format(br=br, url=url, total=total),
                              user, src, {"browser": br, "url": url})
                except sqlite3.Error:
                    pass
                try:
                    for term, url, t in db.execute("SELECT k.term, u.url, u.last_visit_time FROM keyword_search_terms k "
                                                   "JOIN urls u ON u.id=k.url_id"):
                        A.add("ricerche", chrome_time(t), term, tr("{br}: ricerca web ({v1})").format(br=br, v1=url[:200]), user, src,
                              {"browser": br})
                except sqlite3.Error:
                    pass
            elif kind == "firefox":
                for url, title, n, t in db.execute("SELECT url, title, visit_count, last_visit_date FROM moz_places "
                                                   "WHERE visit_count > 0 ORDER BY last_visit_date DESC LIMIT 50000"):
                    A.add("web", unixtime((t or 0) / 1e6), title or url, tr("Firefox: {url} · {n} visite").format(url=url, n=n), user, src,
                          {"browser": "Firefox", "url": url, "visite": n})
                try:
                    for content, added, url in db.execute(
                            "SELECT a.content, a.dateAdded, p.url FROM moz_annos a JOIN moz_anno_attributes n "
                            "ON n.id=a.anno_attribute_id JOIN moz_places p ON p.id=a.place_id "
                            "WHERE n.name='downloads/destinationFileURI'"):
                        A.add("download", unixtime((added or 0) / 1e6), content, tr("Firefox: scaricato da {url}").format(url=url), user,
                              src, {"browser": "Firefox", "url": url})
                except sqlite3.Error:
                    pass
            else:
                for url, n, t, title in db.execute(
                        "SELECT i.url, i.visit_count, MAX(v.visit_time), v.title FROM history_items i "
                        "JOIN history_visits v ON v.history_item=i.id GROUP BY i.id ORDER BY 3 DESC LIMIT 50000"):
                    A.add("web", unixtime((t or 0) + 978307200), title or url, tr("Safari: {url} · {n} visite").format(url=url, n=n), user,
                          src, {"browser": "Safari", "url": url, "visite": n})
            db.close()
        except sqlite3.Error:
            pass
        finally:
            fe.togli(f)


# ---- macOS e Linux

def read_small(ctx, p, inode, path, n=8 << 20):
    try:
        return fa.icat_read(ctx.case, p, inode, n)
    except Exception:
        return b""


def _part_meta(ctx, part):
    return next((p for p in ctx.case.meta.get("partitions", []) if p.get("offset") == part), {}) or {}


def is_mac_volume(ctx, part):
    """Volume macOS: di sistema (SystemVersion.plist), Dati (dslocal, Users, ruolo APFS Data) o HFS+ completo."""
    con = ctx.con
    if fe.find_files(con, part, "system/library/coreservices/systemversion.plist"):
        return "sistema"
    if fe.find_files(con, part, "private/var/db/dslocal/nodes/default/users/%.plist"):
        return "dati"
    a = _part_meta(ctx, part).get("apfs") or {}
    if (a.get("role") or "").lower() == "data":
        return "dati"
    if a and con.execute("SELECT 1 FROM files WHERE part=? AND lower(path) LIKE 'users/%/library/%' LIMIT 1",
                         (part,)).fetchone():
        return "dati"
    return None


def cocoa(t):
    """Secondi (o nanosecondi) dal 2001-01-01 UTC (date di Apple) -> ISO."""
    try:
        t = float(t)
    except (TypeError, ValueError):
        return None
    if not t:
        return None
    if abs(t) > 1e14:          # nanosecondi (chat.db di macOS recenti)
        t /= 1e9
    return unixtime(t + 978307200)


def plist_of(ctx, p, inode, path, n=16 << 20):
    try:
        return plistlib.loads(read_small(ctx, p, inode, path, n))
    except Exception:
        return None


def fetch_sqlite(ctx, part, inode, path):
    """Copia un database SQLite con i file -wal/-journal accanto (i messaggi più recenti stanno
    spesso solo nel -wal) e lo apre: la copia temporanea può essere modificata da SQLite,
    l'originale no."""
    f = fe.fetch(ctx, part, inode, path, 2 << 30)
    if not f or open(f, "rb").read(16) != b"SQLite format 3\x00":
        return None, None
    d = ctx.tmp / f"db_{part}_{safe_name(str(inode), 40)}"
    d.mkdir(exist_ok=True)
    main = d / "db.sqlite"
    shutil.copyfile(f, main)
    wal = False
    for suf in ("-wal", "-journal"):
        ino = fa.lookup(ctx.con, part, path.lower() + suf)
        if ino:
            g = fe.fetch(ctx, part, ino, path + suf, 2 << 30)
            if g:
                shutil.copyfile(g, d / ("db.sqlite" + suf))
                wal = wal or suf == "-wal"
    try:
        db = sqlite3.connect(str(main))
        db.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except sqlite3.Error:
        return None, None
    return db, wal


def bookmark_paths(data):
    """Percorso di un bookmark Apple ('book…', usato da .sfl2/.sfl3, login items, Dock):
    componenti del percorso (chiave 0x1004) e volume (0x2002). Restituisce (percorso, volume)."""
    import struct
    try:
        if data[:4] not in (b"book", b"alis") or len(data) < 0x40:
            return None, None
        hdr = struct.unpack_from("<I", data, 12)[0]
        base = hdr
        toc = struct.unpack_from("<I", data, base)[0] + base
        vals = {}
        guard = 0
        while toc and toc + 20 <= len(data) and guard < 16:
            guard += 1
            _sz, _magic, _ident, nxt, cnt = struct.unpack_from("<IIIII", data, toc)
            for i in range(min(cnt, 512)):
                k, off, _r = struct.unpack_from("<III", data, toc + 20 + i * 12)
                vals[k] = off + base
            toc = nxt + base if nxt else 0

        def item(off):
            ln, typ = struct.unpack_from("<II", data, off)
            raw = data[off + 8: off + 8 + ln]
            if typ == 0x0101:
                return raw.decode("utf-8", "replace")
            if typ == 0x0601:
                return [item(struct.unpack_from("<I", raw, j)[0] + base) for j in range(0, ln, 4)]
            return None
        comps = item(vals[0x1004]) if 0x1004 in vals else None
        vol = item(vals[0x2002]) if 0x2002 in vals else None
        path = "/" + "/".join(c for c in comps if isinstance(c, str)) if isinstance(comps, list) else None
        return path, vol if isinstance(vol, str) else None
    except Exception:
        return None, None


def _keyed_objects(d):
    """Oggetti di un NSKeyedArchiver con riferimenti risolti in modo semplice."""
    objs = d.get("$objects") or []

    def res(x, depth=0):
        if depth > 8:
            return x
        if isinstance(x, plistlib.UID):
            return res(objs[x.data], depth + 1) if x.data < len(objs) else None
        if isinstance(x, dict):
            if "NS.objects" in x and "NS.keys" in x:
                return {str(res(k, depth + 1)): res(v, depth + 1) for k, v in zip(x["NS.keys"], x["NS.objects"])}
            if "NS.objects" in x:
                return [res(v, depth + 1) for v in x["NS.objects"]]
            if "NS.string" in x:
                return x["NS.string"]
            if "NS.data" in x:
                return x["NS.data"]
            if "NS.time" in x:
                return cocoa(x["NS.time"])
            return {k: res(v, depth + 1) for k, v in x.items() if k != "$class"}
        return x
    top = d.get("$top") or {}
    return res(top.get("root")) if "root" in top else None, objs


def _attributed_text(blob):
    """Testo di un messaggio salvato solo come NSAttributedString (attributedBody, macOS 13+)."""
    if not blob:
        return ""
    try:
        i = blob.find(b"NSString")
        if i < 0:
            return ""
        j = blob.find(b"+", i)
        if j < 0:
            return ""
        n = blob[j + 1]
        k = j + 2
        if n == 0x81:
            n = int.from_bytes(blob[k:k + 2], "little")
            k += 2
        elif n == 0x82:
            n = int.from_bytes(blob[k:k + 4], "little")
            k += 4
        return blob[k:k + n].decode("utf-8", "replace")
    except Exception:
        return ""


def mac_artifacts(A, ctx, part):
    """macOS. Dalla 2.14 riconosce anche il volume Dati dei Mac recenti (Catalina e successivi): lì ci
    sono utenti, reti, programmi installati dall'utente e tutti gli artefatti dell'utente, mentre il
    volume di sistema (sigillato) ha solo la versione di macOS."""
    con = ctx.con
    kind = is_mac_volume(ctx, part)
    if not kind:
        return False
    rows = fe.find_files(con, part, "system/library/coreservices/systemversion.plist")
    if rows:
        p, inode, _, path = rows[0]
        try:
            d = plistlib.loads(read_small(ctx, p, inode, path))
            A.add("sistema", None, tr("Sistema operativo: {v1} {v2}").format(v1=d.get('ProductName', 'macOS'), v2=d.get('ProductVersion', '')),
                  f"build {d.get('ProductBuildVersion', '')}", "", (p, inode, path))
        except Exception:
            pass
    for p, inode, _, path in fe.find_files(con, part, "private/var/db/dslocal/nodes/default/users/%.plist"):
        try:
            d = plistlib.loads(read_small(ctx, p, inode, path))
            name = (d.get("name") or [Path(path).stem])[0]
            uid = int((d.get("uid") or ["0"])[0])
            if uid < 500 and name != "root":
                continue
            real = (d.get("realname") or [""])[0]
            A.add("utenti", None, tr("Account {name}").format(name=name), tr("{real} · UID {uid} · home {v1}").format(real=real, uid=uid, v1=(d.get('home') or [''])[0]),
                  name, (p, inode, path))
        except Exception:
            continue
    for p, inode, _, path in fe.find_files(con, part, "applications/%.app/contents/info.plist"):
        if path.lower().count(".app/") > 1:
            continue
        try:
            d = plistlib.loads(read_small(ctx, p, inode, path, 2 << 20))
            A.add("programmi", None, d.get("CFBundleName") or Path(path).parts[1],
                  tr("versione {v1} · {v2}").format(v1=d.get('CFBundleShortVersionString', ''), v2=d.get('CFBundleIdentifier', '')), "",
                  (p, inode, path))
        except Exception:
            continue
    for p, inode, _, path in fe.find_files(con, part, "library/receipts/installhistory.plist"):
        try:
            for it in plistlib.loads(read_small(ctx, p, inode, path)):
                A.add("programmi", iso(it.get("date")), it.get("displayName", ""),
                      tr("installazione {v1} con {v2}").format(v1=it.get('displayVersion', ''), v2=it.get('processName', '')), "", (p, inode, path))
        except Exception:
            pass
    for p, inode, _, path in fe.find_files(con, part, "library/preferences/com.apple.wifi.known-networks.plist"):
        try:
            d = plistlib.loads(read_small(ctx, p, inode, path))
            for k, v in d.items():
                ssid = k.replace("wifi.network.ssid.", "")
                t = v.get("JoinedByUserAt") or v.get("JoinedBySystemAt") or v.get("AddedAt")
                A.add("reti", iso(t), tr("Rete Wi-Fi: {ssid}").format(ssid=ssid), f"aggiunta {iso(v.get('AddedAt')) or ''}", "", (p, inode, path))
        except Exception:
            pass
    for p, inode, _, path in fe.find_files(con, part, "library/preferences/systemconfiguration/com.apple.airport.preferences.plist"):
        try:
            d = plistlib.loads(read_small(ctx, p, inode, path))
            for k, v in (d.get("KnownNetworks") or {}).items():
                A.add("reti", iso(v.get("LastConnected")), tr("Rete Wi-Fi: {v1}").format(v1=v.get('SSIDString', k)), "", "", (p, inode, path))
        except Exception:
            pass
    for fn in (mac_sistema, mac_quarantena, mac_avvio, mac_tcc, mac_messaggi, mac_recenti, mac_safari_download,
               mac_knowledgec, mac_dispositivi, mac_timemachine):
        try:
            fn(A, ctx, part)
        except Exception as e:
            print(f"  {fn.__name__}: {type(e).__name__}: {e}", flush=True)
        con.commit()
    return True


def mac_sistema(A, ctx, part):
    con = ctx.con
    for p, inode, _, path in fe.find_files(con, part, "library/preferences/systemconfiguration/preferences.plist"):
        d = plist_of(ctx, p, inode, path) or {}
        s = ((d.get("System") or {}).get("System") or {})
        for k, lab in (("ComputerName", tr("Nome del computer")), ("HostName", tr("Nome host"))):
            if s.get(k):
                A.add("sistema", None, f"{lab}: {s[k]}", "", "", (p, inode, path))
        lh = ((d.get("System") or {}).get("Network") or {}).get("HostNames", {}).get("LocalHostName")
        if lh:
            A.add("sistema", None, tr("Nome nella rete locale: {lh}.local").format(lh=lh), "", "", (p, inode, path))
    for p, inode, _, path in fe.find_files(con, part, "library/preferences/com.apple.loginwindow.plist"):
        d = plist_of(ctx, p, inode, path) or {}
        if d.get("lastUserName"):
            A.add("sistema", None, tr("Ultimo utente che ha effettuato l'accesso: {lastUserName}").format(lastUserName=d['lastUserName']), "", d["lastUserName"],
                  (p, inode, path))
        if d.get("autoLoginUser"):
            A.add("sistema", None, tr("Accesso automatico attivo per: {autoLoginUser}").format(autoLoginUser=d['autoLoginUser']), "", d["autoLoginUser"],
                  (p, inode, path))
        if d.get("GuestEnabled") is not None:
            A.add("sistema", None, tr("Utente ospite: ") + (tr("attivo") if d.get("GuestEnabled") else tr("disattivato")), "", "",
                  (p, inode, path))
    for p, inode, _, path in fe.find_files(con, part, "library/preferences/.globalpreferences.plist"):
        d = plist_of(ctx, p, inode, path) or {}
        city = d.get("com.apple.TimeZonePref.Last_Selected_City")
        if isinstance(city, list) and len(city) > 3:
            A.add("sistema", None, tr("Fuso orario scelto: {v1}").format(v1=city[3]), tr("città {v1} ({v2})").format(v1=city[5] if len(city) > 5 else '', v2=city[4] if len(city) > 4 else ''), "", (p, inode, path))
    for p, inode, _, path in fe.find_files(con, part, "library/preferences/com.apple.timezone.auto.plist"):
        d = plist_of(ctx, p, inode, path) or {}
        if "Active" in d:
            A.add("sistema", None, tr("Fuso orario automatico (dalla posizione): ") + (tr("sì") if d["Active"] else tr("no")), "", "",
                  (p, inode, path))


def mac_quarantena(A, ctx, part):
    """Eventi di quarantena: ogni file scaricato o ricevuto, con URL di origine e programma."""
    for p, inode, _, path in fe.find_files(ctx.con, part, "users/%/library/preferences/com.apple.launchservices.quarantineeventsv%"):
        if path.lower().endswith(("-wal", "-shm", "-journal")):
            continue
        db, _ = fe.fetch_sqlite(ctx, p, inode, path)
        if not db:
            continue
        user = user_of(path)
        try:
            for t, agent, bid, url, origin, sender, addr in db.execute(
                    "SELECT LSQuarantineTimeStamp, LSQuarantineAgentName, LSQuarantineAgentBundleIdentifier, "
                    "LSQuarantineDataURLString, LSQuarantineOriginURLString, LSQuarantineSenderName, "
                    "LSQuarantineSenderAddress FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp"):
                det = tr("con {v1}").format(v1=agent or bid or '?') + (tr(" · pagina {origin}").format(origin=origin) if origin else "") + \
                      (tr(" · mittente {v1} {v2}").format(v1=sender or '', v2=addr or '').rstrip() if sender or addr else "")
                A.add("download", cocoa(t), url or origin or tr("(senza URL)"), tr("Quarantena macOS: ") + det, user,
                      (p, inode, path), {"programma": agent, "bundle": bid, "url": url, "origine": origin})
        except sqlite3.Error:
            pass
        db.close()


def mac_avvio(A, ctx, part):
    """Avvio automatico: LaunchAgents e LaunchDaemons (sistema e utenti)."""
    pats = ("library/launchagents/%.plist", "library/launchdaemons/%.plist", "users/%/library/launchagents/%.plist",
            "system/library/launchagents/%.plist", "system/library/launchdaemons/%.plist")
    for pat in pats:
        apple = pat.startswith("system/")
        for p, inode, _, path in fe.find_files(ctx.con, part, pat):
            if path.lower().count("/") > pat.count("/"):
                continue
            d = plist_of(ctx, p, inode, path, 1 << 20)
            if not isinstance(d, dict):
                continue
            label = d.get("Label") or Path(path).stem
            if apple and str(label).startswith("com.apple."):
                continue
            prog = d.get("Program") or " ".join(str(x) for x in (d.get("ProgramArguments") or []))
            flags = [k for k in ("RunAtLoad", "KeepAlive") if d.get(k)]
            when = tr("all'accesso dell'utente") if "launchagents" in pat else tr("all'avvio del sistema")
            A.add("avvio", None, label, f"{prog or '(programma non indicato)'} · {when}"
                  + (f" · {', '.join(flags)}" if flags else "") + (tr(" · disattivato") if d.get("Disabled") else ""),
                  user_of(path), (p, inode, path), {"programma": prog})
    # elementi di login gestiti da macOS 13+ (Background Task Management): si elencano i percorsi
    for p, inode, _, path in fe.find_files(ctx.con, part, "private/var/db/com.apple.backgroundtaskmanagement/backgrounditems-v%.btm"):
        d = plist_of(ctx, p, inode, path) or {}
        try:
            _root, objs = _keyed_objects(d)
        except Exception:
            objs = []
        seen = set()
        for o in objs:
            if isinstance(o, bytes) and o[:4] == b"book":
                pth, _v = bookmark_paths(o)
                if pth and pth not in seen:
                    seen.add(pth)
                    A.add("avvio", None, Path(pth).name, tr("elemento di login / in background: {pth}").format(pth=pth), "",
                          (p, inode, path))
            elif isinstance(o, str) and o.startswith("file:///") and o not in seen:
                seen.add(o)
                A.add("avvio", None, Path(o).name, tr("elemento di login / in background: {o}").format(o=o), "", (p, inode, path))


TCC_AUTH = {0: "negato", 1: "sconosciuto", 2: "consentito", 3: "limitato"}


def mac_tcc(A, ctx, part):
    """Permessi concessi alle app (TCC): disco completo, fotocamera, microfono, schermo, accessibilità…"""
    for pat in ("library/application support/com.apple.tcc/tcc.db", "users/%/library/application support/com.apple.tcc/tcc.db"):
        for p, inode, _, path in fe.find_files(ctx.con, part, pat):
            db, _ = fe.fetch_sqlite(ctx, p, inode, path)
            if not db:
                continue
            cols = {r[1] for r in db.execute("PRAGMA table_info(access)")}
            auth = "auth_value" if "auth_value" in cols else "allowed"
            when = "last_modified" if "last_modified" in cols else "NULL"
            try:
                for svc, client, val, t in db.execute(f"SELECT service, client, {auth}, {when} FROM access"):
                    s = str(svc).replace("kTCCService", "")
                    stato = TCC_AUTH.get(val, str(val)) if auth == "auth_value" else (tr("consentito") if val else tr("negato"))
                    A.add("permessi", unixtime(t), f"{s}: {client}", f"{stato} · "
                          + (tr("per tutti gli utenti") if not path.lower().startswith("users/") else tr("per l'utente")),
                          user_of(path), (p, inode, path), {"servizio": s, "app": client, "stato": stato})
            except sqlite3.Error:
                pass
            db.close()


def mac_messaggi(A, ctx, part):
    """iMessage/SMS (chat.db), compresi i messaggi ancora solo nel -wal e quelli in attributedBody."""
    for p, inode, _, path in fe.find_files(ctx.con, part, "users/%/library/messages/chat.db"):
        db, wal = fe.fetch_sqlite(ctx, p, inode, path)
        if not db:
            continue
        user = user_of(path)
        cols = {r[1] for r in db.execute("PRAGMA table_info(message)")}
        ab = "m.attributedBody" if "attributedBody" in cols else "NULL"
        try:
            q = ("SELECT m.ROWID, m.date, m.text, " + ab + ", m.is_from_me, h.id, m.service, "
                 "(SELECT c.chat_identifier || COALESCE(' «' || NULLIF(c.display_name, '') || '»', '') FROM chat_message_join j "
                 " JOIN chat c ON c.ROWID=j.chat_id WHERE j.message_id=m.ROWID LIMIT 1), "
                 "(SELECT group_concat(COALESCE(a.transfer_name, a.filename), ' | ') FROM message_attachment_join x "
                 " JOIN attachment a ON a.ROWID=x.attachment_id WHERE x.message_id=m.ROWID) "
                 "FROM message m LEFT JOIN handle h ON h.ROWID=m.handle_id ORDER BY m.date")
            n = 0
            for rid, t, text, body, me, who, svc, chat, att in db.execute(q):
                txt = text or _attributed_text(body)
                verso = tr("inviato a") if me else tr("ricevuto da")
                A.add("messaggi", cocoa(t), (txt or (tr("(allegato) ") + att if att else tr("(senza testo)")))[:500],
                      f"{svc or 'iMessage'} · {verso} {who or '?'}" + (tr(" · conversazione {chat}").format(chat=chat) if chat else "")
                      + (tr(" · allegati: {att}").format(att=att) if att else ""), user, (p, inode, path),
                      {"id": rid, "da_me": bool(me), "contatto": who, "servizio": svc, "allegati": att, "testo": txt})
                n += 1
            if wal:
                A.add("messaggi", None, tr("chat.db di {user}: letti anche i messaggi nel file -wal").format(user=user), tr("{n} messaggi in tutto").format(n=n),
                      user, (p, inode, path))
        except sqlite3.Error as e:
            print(tr("  chat.db {path}: {e}").format(path=path, e=e), flush=True)
        db.close()


def mac_recenti(A, ctx, part):
    """Documenti, cartelle, app e server recenti (.sfl2/.sfl3 di com.apple.sharedfilelist)."""
    for p, inode, _, path in fe.find_files(ctx.con, part, "users/%/library/application support/com.apple.sharedfilelist/%.sfl%"):
        d = plist_of(ctx, p, inode, path)
        if not isinstance(d, dict):
            continue
        user = user_of(path)
        lista = Path(path).stem.replace("com.apple.LSSharedFileList.", "")
        try:
            root, objs = _keyed_objects(d)
        except Exception:
            continue
        items = root.get("items") if isinstance(root, dict) else None
        done = set()
        for it in items or []:
            if not isinstance(it, dict):
                continue
            bm = it.get("Bookmark")
            pth, vol = bookmark_paths(bm) if isinstance(bm, bytes) else (None, None)
            name = it.get("Name") or (Path(pth).name if pth else "")
            if not (pth or name):
                continue
            done.add(pth or name)
            A.add("recenti", None, name or pth, f"{lista}: {pth or ''}" + (tr(" · volume {vol}").format(vol=vol) if vol else ""), user,
                  (p, inode, path), {"elenco": lista, "percorso": pth, "volume": vol})
        for o in objs:
            if isinstance(o, bytes) and o[:4] == b"book":
                pth, vol = bookmark_paths(o)
                if pth and pth not in done:
                    done.add(pth)
                    A.add("recenti", None, Path(pth).name, f"{lista}: {pth}" + (tr(" · volume {vol}").format(vol=vol) if vol else ""), user,
                          (p, inode, path), {"elenco": lista, "percorso": pth, "volume": vol})


def mac_safari_download(A, ctx, part):
    for p, inode, _, path in fe.find_files(ctx.con, part, "users/%/library/%safari/downloads.plist"):
        d = plist_of(ctx, p, inode, path) or {}
        for it in d.get("DownloadHistory") or []:
            t = it.get("DownloadEntryDateFinishedKey") or it.get("DownloadEntryDateAddedKey")
            A.add("download", iso(t), it.get("DownloadEntryPath") or it.get("DownloadEntryURL"),
                  tr("Safari: scaricato da {v1} · {v2} byte").format(v1=it.get('DownloadEntryURL', ''), v2=it.get('DownloadEntryProgressTotalToLoad', '')),
                  user_of(path), (p, inode, path), {"browser": "Safari", "url": it.get("DownloadEntryURL")})


def mac_knowledgec(A, ctx, part):
    """Uso delle app e dello schermo (knowledgeC.db, fino a macOS 13; poi Biome, non letto)."""
    for pat in ("private/var/db/coreduet/knowledge/knowledgec.db", "users/%/library/application support/knowledge/knowledgec.db"):
        for p, inode, _, path in fe.find_files(ctx.con, part, pat):
            db, _ = fe.fetch_sqlite(ctx, p, inode, path)
            if not db:
                continue
            try:
                for stream, val, s, e in db.execute(
                        "SELECT ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE, ZENDDATE FROM ZOBJECT WHERE ZSTREAMNAME IN "
                        "('/app/inFocus','/app/usage','/app/webUsage','/display/isBacklit','/device/isLocked',"
                        "'/media/nowPlaying','/safari/history') ORDER BY ZSTARTDATE LIMIT 200000"):
                    dur = (e - s) if (e and s) else None
                    A.add("uso", cocoa(s), f"{stream}: {val or ''}".strip(),
                          tr("fino a {v1}").format(v1=(cocoa(e) or '').replace('T', ' ')) + (f" · {int(dur)} s" if dur is not None else ""),
                          user_of(path), (p, inode, path), {"flusso": stream, "valore": val, "fine": cocoa(e)})
            except sqlite3.Error:
                pass
            db.close()


def mac_dispositivi(A, ctx, part):
    """Dispositivi Bluetooth associati e volumi esterni visti dal Finder (chiavette, dischi, immagini)."""
    for p, inode, _, path in fe.find_files(ctx.con, part, "library/preferences/com.apple.bluetooth.plist"):
        d = plist_of(ctx, p, inode, path) or {}
        for mac, v in (d.get("DeviceCache") or {}).items():
            if isinstance(v, dict):
                A.add("dispositivi", iso(v.get("LastInquiryUpdate") or v.get("LastNameUpdate")),
                      tr("Bluetooth: {v1}").format(v1=v.get('Name') or v.get('displayName') or mac), f"indirizzo {mac}", "", (p, inode, path))
        for mac in d.get("PairedDevices") or []:
            A.add("dispositivi", None, tr("Bluetooth associato: {mac}").format(mac=mac), "", "", (p, inode, path))
    for p, inode, _, path in fe.find_files(ctx.con, part, "users/%/library/preferences/com.apple.finder.plist"):
        d = plist_of(ctx, p, inode, path) or {}
        for k in (d.get("FXDesktopVolumePositions") or {}):
            nm = re.sub(r"_0x[0-9a-f]+$|_-?[0-9.e+]+$", "", str(k))
            A.add("dispositivi", None, tr("Volume mostrato sulla Scrivania: {nm}").format(nm=nm), f"chiave {k}", user_of(path), (p, inode, path))
        for it in d.get("FXRecentFolders") or []:
            if isinstance(it, dict):
                bm = it.get("file-bookmark")
                pth, vol = bookmark_paths(bm) if isinstance(bm, bytes) else (None, None)
                A.add("recenti", None, it.get("name") or pth, tr("Finder, cartelle recenti: {v1}").format(v1=pth or '')
                      + (tr(" · volume {vol}").format(vol=vol) if vol else ""), user_of(path), (p, inode, path))


def mac_timemachine(A, ctx, part):
    for p, inode, _, path in fe.find_files(ctx.con, part, "library/preferences/com.apple.timemachine.plist"):
        d = plist_of(ctx, p, inode, path) or {}
        A.add("backup", None, tr("Time Machine: backup automatico ") + ("attivo" if d.get("AutoBackup") else tr("non attivo")),
              "", "", (p, inode, path))
        for dst in d.get("Destinations") or []:
            dates = [iso(x) for x in (dst.get("SnapshotDates") or [])]
            nm = dst.get("LastKnownVolumeName") or dst.get("NetworkURL") or dst.get("DestinationID")
            A.add("backup", dates[-1] if dates else None, tr("Disco di backup: {nm}").format(nm=nm),
                  f"{len(dates)} backup" + (tr(", dal {v1} al {v2}").format(v1=dates[0], v2=dates[-1]) if dates else "")
                  + (f" · {dst.get('NetworkURL')}" if dst.get("NetworkURL") else ""), "", (p, inode, path),
                  {"backup": dates})


def linux_artifacts(A, ctx, part):
    con = ctx.con
    rows = fe.find_files(con, part, "etc/passwd")
    if not rows:
        return False
    p, inode, _, path = rows[0]
    for line in decode_bytes(read_small(ctx, p, inode, path)).splitlines():
        f = line.split(":")
        if len(f) >= 7 and (f[2] == "0" or (f[2].isdigit() and 1000 <= int(f[2]) < 65000)):
            A.add("utenti", None, tr("Account {v1}").format(v1=f[0]), tr("UID {v1} · {v2} · home {v3} · shell {v4}").format(v1=f[2], v2=f[4], v3=f[5], v4=f[6]), f[0], (p, inode, path))
    for nm in ("etc/hostname", "etc/timezone"):
        for p, inode, _, path in fe.find_files(con, part, nm):
            v = decode_bytes(read_small(ctx, p, inode, path, 4096)).strip()
            if v:
                A.add("sistema", None, (tr("Nome del computer: ") if "hostname" in nm else tr("Fuso orario: ")) + v, "", "", (p, inode, path))
    for p, inode, _, path in fe.find_files(con, part, "etc/networkmanager/system-connections/%"):
        t = decode_bytes(read_small(ctx, p, inode, path, 65536))
        m = re.search(r"(?m)^ssid=(.+)$", t) or re.search(r"(?m)^id=(.+)$", t)
        if m:
            A.add("reti", None, tr("Rete: {v1}").format(v1=m.group(1).strip()), "NetworkManager", "", (p, inode, path))
    return True


def shell_history(A, ctx, part):
    for pat in ("home/%/.bash_history", "root/.bash_history", "home/%/.zsh_history", "users/%/.zsh_history",
                "users/%/.bash_history", "root/.zsh_history"):
        for p, inode, _, path in fe.find_files(ctx.con, part, pat):
            lines = decode_bytes(read_small(ctx, p, inode, path, 4 << 20)).splitlines()
            user = user_of(path)
            for ln in lines[-5000:]:
                ts = None
                m = re.match(r"^: (\d+):\d+;(.*)$", ln)
                if m:
                    ts, ln = unixtime(m.group(1)), m.group(2)
                if ln.strip():
                    A.add("comandi", ts, ln.strip()[:400], Path(path).name, user, (p, inode, path))
