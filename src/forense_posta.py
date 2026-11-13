#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - posta elettronica (PST/OST, mbox, EML, EMLX, MSG).

(3.0.4) Codice spostato da forense_estesa.py senza modifiche, per avere file più corti. Si carica tramite
forense_estesa, che ne riesporta i nomi: gli altri moduli continuano a usare «fe.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fe.<nome>»).
"""
import email
import mailbox
import re
import shutil
from pathlib import Path
from forense_lingua import tr
import forense_agent as fa

import forense_estesa as fe
from forense_estesa import (
    Ctx, DEPTH_MAX, ENTRY_MAX, TOTAL_MAX, X_ROOT, archive_by_content, copy_fs_file, decode_bytes, fs_rows, hashes_of,
    html_to_text, index_text, is_archive_name, is_mail_name, iso, new_xitem, now, origin_deleted, process_container,
    safe_name, seven_zip, store_extracted)

# ------------------------------------------------------------------ posta

def addr_list(v):
    if not v:
        return ""
    try:
        return ", ".join(f"{n} <{a}>" if n and a else (a or n)
                         for n, a in email.utils.getaddresses([str(v)]))
    except Exception:
        return str(v)


def add_message(ctx, origin, parent, fmt, folder, disp, sender, to, cc, subject, date, body,
                html_body, headers, attachments, depth, consegna=None):
    """Registra un messaggio con i suoi allegati: [(nome, bytes)]. `consegna`: ora di consegna, se diversa da `date`."""
    con, case = ctx.con, ctx.case
    subject = (subject or "").strip() or tr("(senza oggetto)")
    mid = con.execute("INSERT INTO mail(part, inode, src_path, xid, fmt, folder, sender, recipients, "
                      "cc, subject, date, body, html, n_att, headers) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (origin[0], origin[1], origin[2], parent, fmt, folder, sender, to, cc, subject,
                       date, (body or "")[:fa.MAX_TEXT], (html_body or "")[:2_000_000] or None,
                       len(attachments), (headers or "")[:20000])).lastrowid
    mpath = f"{disp} › {folder + ' › ' if folder else ''}{subject[:100]}"
    txt = (f"Da: {sender}\nA: {to}\n" + (f"Cc: {cc}\n" if cc else "") +
           tr("Oggetto: {subject}\nData: {v1}\n\n{v2}").format(
               subject=subject, v1=(date or '') + (tr(" (consegnato {v1})").format(v1=consegna) if consegna else ''),
               v2=body or ''))
    fa.store_text(con, mpath, txt, "posta", None, str(mid), 0, "email")
    ctx.c["messaggi"] += 1
    for name, data in attachments:
        name = (name or "allegato").strip() or "allegato"
        apath = f"{mpath} › 📎 {name}"
        xid = new_xitem(con, kind="allegato", part=origin[0], inode=origin[1], src_path=origin[2],
                        parent=parent, mail=mid, inner=name, path=apath, name=Path(name).name,
                        size=len(data), mtime=date, deleted=origin_deleted(ctx, origin))
        ctx.c["allegati"] += 1
        if len(data) > ENTRY_MAX or ctx.extracted + len(data) > TOTAL_MAX:
            con.execute("UPDATE xitems SET note=? WHERE id=?", (tr("non estratto (troppo grande)"), xid))
            continue
        tmpf = ctx.tmp / f"a{xid}"
        tmpf.write_bytes(data)
        if index_text(con, case, apath, data[:fa.MAX_EXTRACT], name, "x", None, xid, 0, ctx.tmp):
            ctx.c["testi"] += 1
        n, md5, sha1, sha256 = hashes_of(tmpf)
        rel = store_extracted(case, tmpf, "posta", xid, name)
        ctx.extracted += n
        enc = 0
        if data[:4] == b"PK\x03\x04" and len(data) > 8 and data[6] & 1:
            enc = 1
        con.execute("UPDATE xitems SET relpath=?, md5=?, sha1=?, sha256=?, encrypted=? WHERE id=?",
                    (rel, md5, sha1, sha256, enc, xid))
        by_content = archive_by_content(name, data[:4096])
        if by_content:
            ctx.c["archivi riconosciuti dal contenuto"] += 1
        if depth < DEPTH_MAX and (is_archive_name(name) or is_mail_name(name) or bool(by_content)):
            process_container(ctx, case.root / rel, apath, origin, depth + 1, parent=xid)
    if ctx.c["messaggi"] % 200 == 0:
        con.commit()
        ctx.say(tr("{messaggi} messaggi, {allegati} allegati").format(messaggi=ctx.c['messaggi'], allegati=ctx.c['allegati']))
    return mid


def parse_email_bytes(raw):
    """Messaggio RFC 822 -> campi principali, testo, html, allegati."""
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    body = htm = ""
    atts = []
    try:
        b = msg.get_body(preferencelist=("plain",))
        if b is not None:
            body = b.get_content()
        h = msg.get_body(preferencelist=("html",))
        if h is not None:
            htm = h.get_content()
    except Exception:
        pass
    if not body and htm:
        body = html_to_text(htm)
    if not body and not msg.is_multipart():
        try:
            body = msg.get_content() if isinstance(msg.get_content(), str) else ""
        except Exception:
            body = decode_bytes(msg.get_payload(decode=True))
    try:
        for part in msg.iter_attachments():
            data = part.get_payload(decode=True)
            if data is None and part.get_content_type() == "message/rfc822":
                inner = part.get_payload()
                inner = inner[0] if isinstance(inner, list) and inner else inner
                data = inner.as_bytes() if hasattr(inner, "as_bytes") else b""
                atts.append(((part.get_filename() or tr("messaggio inoltrato")) + ".eml", data))
                continue
            atts.append((part.get_filename() or f"allegato.{part.get_content_subtype()}", data or b""))
    except Exception:
        pass
    date = None
    try:
        d = msg["date"].datetime if msg["date"] is not None else None
        date = iso(d)
    except Exception:
        pass
    hdr = "\n".join(f"{k}: {v}" for k, v in list(msg.items())[:60])
    return {"sender": addr_list(msg["from"]), "to": addr_list(msg["to"]), "cc": addr_list(msg["cc"]),
            "subject": str(msg["subject"] or ""), "date": date, "body": body, "html": htm,
            "headers": hdr, "atts": atts}


def process_eml_file(ctx, f, disp, origin, depth, parent):
    raw = Path(f).read_bytes()
    fmt = "EML"
    if disp.lower().endswith(".emlx"):      # Apple Mail: lunghezza, messaggio, plist
        m = re.match(rb"\s*(\d+)\s*\n", raw)
        if m:
            raw = raw[m.end():m.end() + int(m.group(1))]
        fmt = "EMLX"
    p = parse_email_bytes(raw)
    add_message(ctx, origin, parent, fmt, "", disp, p["sender"], p["to"], p["cc"], p["subject"],
                p["date"], p["body"], p["html"], p["headers"], p["atts"], depth)
    return 1


def process_mbox(ctx, f, disp, origin, depth, parent):
    box = mailbox.mbox(str(f), create=False)
    n = 0
    try:
        for key in box.iterkeys():
            try:
                raw = box.get_bytes(key)
            except Exception:
                continue
            p = parse_email_bytes(raw)
            add_message(ctx, origin, parent, "mbox", "", disp, p["sender"], p["to"], p["cc"],
                        p["subject"], p["date"], p["body"], p["html"], p["headers"], p["atts"], depth)
            n += 1
    finally:
        box.close()
    return n


def pff_text(m):
    body = ""
    for getter, conv in ((lambda: m.plain_text_body, decode_bytes),
                         (lambda: m.html_body, lambda b: html_to_text(decode_bytes(b))),
                         (lambda: m.rtf_body, lambda b: fa.rtf_text(decode_bytes(b)))):
        try:
            v = getter()
        except Exception:
            v = None
        if v:
            body = conv(v)
            if body.strip():
                break
    try:
        h = m.html_body
    except Exception:
        h = None
    return body, decode_bytes(h) if h else ""


def pff_recipients(m):
    to = []
    try:
        rc = m.recipients
        n = rc.number_of_sub_items if rc is not None else 0
        for i in range(n):
            it = rc.get_sub_item(i)
            name = addr = None
            for rsi in range(it.number_of_record_sets):
                r = it.get_record_set(rsi)
                for e in range(r.number_of_entries):
                    en = r.get_entry(e)
                    try:
                        if en.entry_type == 0x3001:
                            name = en.get_data_as_string()
                        elif en.entry_type in (0x39FE, 0x3003) and not addr:
                            addr = en.get_data_as_string()
                    except Exception:
                        pass
            if name or addr:
                to.append(f"{name} <{addr}>" if name and addr and name != addr else (addr or name))
    except Exception:
        pass
    return ", ".join(to)


def process_pst(ctx, f, disp, origin, depth, parent):
    try:
        import pypff
    except ImportError:
        ctx.c["PST non letti (manca libpff)"] += 1
        return 0
    pf = pypff.file()
    pf.open(str(f))
    n = 0
    try:
        stack = [(pf.get_root_folder(), "")]
        while stack:
            fo, path = stack.pop()
            try:
                for i in range(fo.number_of_sub_folders):
                    sf = fo.get_sub_folder(i)
                    stack.append((sf, (path + "/" + (sf.name or "")).strip("/")))
            except Exception:
                pass
            try:
                nm = fo.number_of_sub_messages
            except Exception:
                nm = 0
            for i in range(nm):
                try:
                    m = fo.get_sub_message(i)
                    headers = m.transport_headers or ""
                    hp = email.message_from_string(headers, policy=email.policy.default) if headers else None
                    sender = (addr_list(hp["from"]) if hp is not None and hp["from"] else "") or (m.sender_name or "")
                    to = (addr_list(hp["to"]) if hp is not None and hp["to"] else "") or pff_recipients(m)
                    cc = addr_list(hp["cc"]) if hp is not None and hp["cc"] else ""
                    # (3.0.2) data = ora di invio (come l'intestazione Date e le risposte NIST); l'ora di consegna va nel
                    # testo: per i messaggi inviati Outlook la registra al minuto (es. 18:44:00 per un invio alle 18:44:31)
                    date = iso(m.client_submit_time) or iso(m.delivery_time) or iso(m.creation_time)
                    consegna = iso(m.delivery_time)
                    body, htm = pff_text(m)
                    atts = []
                    for k in range(m.number_of_attachments):
                        try:
                            a = m.get_attachment(k)
                            size = a.size or 0
                            data = a.read_buffer(size) if size else b""
                            atts.append((a.long_filename or f"allegato_{k + 1}", data))
                        except Exception:
                            continue
                    folder = re.sub(r"^Top of (Outlook data file|Personal Folders)/?", "", path) or path
                    add_message(ctx, origin, parent, "PST/OST", folder, disp, sender, to, cc,
                                m.subject, date, body, htm, headers, atts, depth,
                                consegna=consegna if consegna and consegna != date else None)
                    n += 1
                except Exception:
                    ctx.c["messaggi non leggibili"] += 1
    finally:
        pf.close()
    return n


def process_msg_file(ctx, f, disp, origin, depth, parent):
    """Messaggio Outlook .msg (OLE): proprietà MAPI principali e allegati."""
    try:
        import pyolecf
    except ImportError:
        return 0
    of = pyolecf.file()
    of.open(str(f))
    try:
        root = of.root_item
        props = {}

        def read_item(it):
            try:
                return it.read(it.size)
            except Exception:
                return b""

        def strval(name, data):
            if name.endswith("001F"):
                return data.decode("utf-16-le", "replace").rstrip("\x00")
            if name.endswith("001E"):
                return decode_bytes(data).rstrip("\x00")
            return data
        atts = []
        for i in range(root.number_of_sub_items):
            it = root.get_sub_item(i)
            nm = it.name or ""
            if nm.startswith("__substg1.0_"):
                props[nm[12:16].upper()] = strval(nm.upper(), read_item(it))
            elif nm.startswith("__attach_version1.0_"):
                ap = {}
                for j in range(it.number_of_sub_items):
                    s = it.get_sub_item(j)
                    sn = s.name or ""
                    if sn.startswith("__substg1.0_"):
                        ap[sn[12:16].upper()] = strval(sn.upper(), read_item(s))
                aname = ap.get("3707") or ap.get("3704") or "allegato"
                data = ap.get("3701") if isinstance(ap.get("3701"), bytes) else b""
                atts.append((aname if isinstance(aname, str) else "allegato", data))
        g = lambda k: props.get(k) if isinstance(props.get(k), str) else ""
        headers = g("007D")
        hp = email.message_from_string(headers, policy=email.policy.default) if headers else None
        sender = (addr_list(hp["from"]) if hp is not None and hp["from"] else "") or \
            " ".join(x for x in (g("0C1A"), f"<{g('0C1F') or g('5D01')}>" if (g('0C1F') or g('5D01')) else "") if x)
        to = (addr_list(hp["to"]) if hp is not None and hp["to"] else "") or g("0E04")
        cc = (addr_list(hp["cc"]) if hp is not None and hp["cc"] else "") or g("0E03")
        date = None
        if hp is not None and hp["date"] is not None:
            try:
                date = iso(hp["date"].datetime)
            except Exception:
                pass
        body = g("1000")
        htm = props.get("1013")
        htm = decode_bytes(htm) if isinstance(htm, bytes) else (htm or "")
        if not body and htm:
            body = html_to_text(htm)
        add_message(ctx, origin, parent, "MSG", "", disp, sender, to, cc, g("0037"), date, body, htm,
                    headers, atts, depth)
        return 1
    finally:
        of.close()


def run_archivi(case, con):
    ctx = Ctx(case, con, "Archivi e posta")
    con.execute("DELETE FROM xitems WHERE kind IN ('archivio','allegato')")
    con.execute("DELETE FROM mail")
    con.execute("DELETE FROM doc_text WHERE source IN ('posta') OR (source='x' AND inode IN "
                "(SELECT CAST(id AS TEXT) FROM xitems WHERE kind IN ('archivio','allegato')))")
    con.execute("DELETE FROM anomalies WHERE kind='cifrato' AND detail LIKE 'archivio%'")
    for sub in ("archivi", "posta"):
        fa.rmtree_force(case.root / X_ROOT / sub)
    con.commit()
    rows = []
    for part, inode, deleted, path in fs_rows(con, "1=1"):
        n = Path(path).name
        low = n.lower()
        if is_archive_name(n) or is_mail_name(n) or \
                (not Path(low).suffix and re.search(r"(?i)(^|/)(mail|imapmail|local folders)/", path)):
            if ":" in n:          # flussi NTFS alternativi
                continue
            rows.append((part, inode, deleted, path))
    # archivi con un'altra estensione: si riconoscono dai primi byte (stessa lettura delle anomalie)
    chosen = {(r[0], str(r[1])) for r in rows}
    hr = fe.HeadReader(case)
    n_scan = 0
    for part, inode, deleted, path in fs_rows(con, "1=1"):
        n = Path(path).name
        if ":" in n or (part, str(inode)) in chosen:
            continue
        n_scan += 1
        try:
            _size, head, _t = hr.read(part, inode, 512)
        except Exception:
            continue
        if archive_by_content(n, head):
            rows.append((part, inode, deleted, path))
            chosen.add((part, str(inode)))
            ctx.c["archivi riconosciuti dal contenuto"] += 1
        if n_scan % 20000 == 0:
            ctx.say(tr("controllo del contenuto: {n_scan} file").format(n_scan=n_scan))
    exe = seven_zip()
    if not exe:
        print(tr("7-Zip non trovato: apro solo ZIP e tar (reinstalla RepertIA o 'Aggiorna strumenti')."),
              flush=True)
    else:
        case.meta.setdefault("tool_versions", {})["7-zip"] = fa.tool_version([exe]) or exe
    print(tr("Archivi e posta: {v1} file da esaminare...").format(v1=len(rows)), flush=True)
    for k, (part, inode, deleted, path) in enumerate(rows, 1):
        d = ctx.tmp / f"src_{k}"
        d.mkdir(exist_ok=True)
        f = d / safe_name(Path(path).name, 120)      # 7-Zip ricava dal nome quello del contenuto (.tar.gz)
        try:
            size = copy_fs_file(case, part, inode, f)
        except Exception:
            size = None
        if not size:
            f.unlink(missing_ok=True)
            continue
        head = open(f, "rb").read(512)
        name = Path(path).name.lower()
        if not Path(name).suffix and not head.startswith(b"From ") and not archive_by_content(name, head):
            f.unlink(missing_ok=True)
            continue
        process_container(ctx, f, path, (part, inode, path), 1)
        shutil.rmtree(d, ignore_errors=True)
        fa.avanz(fatti=k, totale=len(rows))
        ctx.say(tr("{k} di {v1} file · {archivi} archivi, {v2} file contenuti, {messaggi} messaggi, "
                   "{allegati} allegati").format(k=k, v1=len(rows), archivi=ctx.c['archivi'], v2=ctx.c['file in archivi'], messaggi=ctx.c['messaggi'], allegati=ctx.c['allegati']))
    con.commit()
    ctx.close()
    res = {k: v for k, v in ctx.c.items()}
    res.update({"ts": now(), "estratti_byte": ctx.extracted})
    print(tr("Archivi e posta: ") + (", ".join(f"{v} {tr(k)}" for k, v in ctx.c.items()) or tr("nessun archivio o file di posta")),
          flush=True)
    try:
        import pypff
        case.meta.setdefault("tool_versions", {})["libpff"] = str(pypff.get_version())
    except Exception:
        pass
    return res
