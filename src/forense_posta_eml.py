#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - una mail esportata come file .eml (3.0.6).

- EML, EMLX e mbox: i byte originali del messaggio (per EMLX senza la lunghezza iniziale e il plist di Apple Mail; per
  mbox il messaggio ritrovato nella casella dalle sue intestazioni, senza la riga «From » di separazione).
- PST/OST e MSG: il file non esiste come tale, quindi si RICOSTRUISCE dai dati letti da RepertIA: intestazioni di
  trasporto originali se ci sono (riga per riga, senza le Content-* e MIME-Version), altrimenti Da/A/Cc/Oggetto/Data
  letti; testo semplice e HTML; allegati estratti con i loro byte (le mail allegate restano file .eml identici). La
  ricostruzione lo dichiara nell'intestazione «X-RepertIA-Ricostruzione» e nelle avvertenze; per MSG si esporta anche
  il file .msg originale.
- (3.0.6) Il nome dei file dice che cosa sono: <data>_<ora>_<oggetto>_m<n>_ORIGINALE.eml o _RICOSTRUITA.eml; accanto,
  per le mail ricostruite, _intestazioni_ORIGINALI.txt con le intestazioni di trasporto come registrate nel file
  (rilette dal PST se nel caso sono troncate), citato con il suo SHA-256 nel .eml; per MSG _ORIGINALE.msg.
"""
import email
import email.policy
import email.utils
import hashlib
import mimetypes
import re
import shutil
import tempfile
from pathlib import Path
from forense_lingua import tr
import forense_agent as fa

TESTO_MAX = 200_000          # forense_posta.add_message: testo, HTML e intestazioni salvati fino a questi limiti
HTML_MAX = 2_000_000
INTEST_MAX = 20_000
ORIGINALI = ("EML", "EMLX", "mbox")


def _riga(case, con, mid):
    import forense_estesa as fe
    r = con.execute("SELECT id, part, inode, src_path, xid, fmt, folder, sender, recipients, cc, subject, date, body, "
                    f"html, n_att, headers, {fe.mail_bcc(con)} FROM mail WHERE id=?", (int(mid),)).fetchone()
    if not r:
        raise ValueError(tr("Messaggio non trovato."))
    return dict(zip(("id", "part", "inode", "src_path", "xid", "fmt", "folder", "sender", "recipients", "cc", "subject",
                     "date", "body", "html", "n_att", "headers", "bcc"), r))


def _contenitore(case, con, m, tmpd):
    """File da cui è stato letto il messaggio (EML, mbox, PST, MSG): il file estratto del caso se sta in un archivio o
    è un allegato, altrimenti una copia temporanea dal reperto. None se non raggiungibile."""
    if m["xid"]:
        r = con.execute("SELECT relpath FROM xitems WHERE id=?", (m["xid"],)).fetchone()
        p = case.root / r[0] if r and r[0] else None
        return p if p and p.is_file() else None
    if m["part"] is None or m["inode"] is None:
        return None
    dest = Path(tmpd) / "contenitore"
    try:
        with open(dest, "wb") as fh:
            for b in fa.icat_stream(case, m["part"], m["inode"]):
                fh.write(b)
    except Exception:
        return None
    return dest


def _intest(raw):
    """Intestazioni come le scrive forense_posta.parse_email_bytes (per ritrovare un messaggio nella casella mbox)."""
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    return "\n".join(f"{k}: {v}" for k, v in list(msg.items())[:60])[:INTEST_MAX]


def _da_mbox(con, m, f):
    """Byte del messaggio nella casella mbox: quello con le stesse intestazioni, contando gli uguali precedenti."""
    import mailbox
    prima = con.execute("SELECT COUNT(*) FROM mail WHERE fmt='mbox' AND part IS ? AND inode IS ? AND xid IS ? AND "
                        "headers IS ? AND id < ?", (m["part"], m["inode"], m["xid"], m["headers"], m["id"])).fetchone()[0]
    box = mailbox.mbox(str(f), create=False)
    try:
        for key in box.iterkeys():
            try:
                raw = box.get_bytes(key)
            except Exception:
                continue
            try:
                if _intest(raw) != (m["headers"] or ""):
                    continue
            except Exception:
                continue
            if prima == 0:
                return raw
            prima -= 1
    finally:
        box.close()
    return None


def _originale(case, con, m):
    """Byte originali del messaggio (EML, EMLX, mbox) o None, con il motivo."""
    tmpd = tempfile.mkdtemp(prefix="repertia_eml_")
    try:
        f = _contenitore(case, con, m, tmpd)
        if not f:
            return None, tr("file di posta non raggiungibile (collega il disco della copia forense)")
        if m["fmt"] == "mbox":
            raw = _da_mbox(con, m, f)
            return raw, None if raw else tr("messaggio non ritrovato nella casella mbox")
        raw = f.read_bytes()
        if m["fmt"] == "EMLX":
            x = re.match(rb"\s*(\d+)\s*\n", raw)
            if x:
                raw = raw[x.end():x.end() + int(x.group(1))]
        return raw, None
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


def _campi(righe):
    """Testo delle intestazioni → campi [(nome, testo con le righe di continuazione)]."""
    out = []
    for r in righe.replace("\r\n", "\n").split("\n"):
        if r[:1] in (" ", "\t") and out:
            out[-1][1] += "\r\n" + r
        elif ":" in r:
            out.append([r.split(":", 1)[0].strip(), r])
    return out


def _intestazioni(pairs):
    """Intestazioni scritte con la codifica giusta (nomi e oggetti con accenti), senza corpo."""
    from email.message import EmailMessage
    h = EmailMessage(policy=email.policy.SMTP)
    for k, v in pairs:
        if not v:
            continue
        try:
            h[k] = v
        except Exception:
            h[k] = re.sub(r"[\r\n]+", " ", str(v))
    raw = h.as_bytes(policy=email.policy.SMTP)
    return raw.split(b"\r\n\r\n", 1)[0] + b"\r\n" if raw.strip() else b""


def _cartella_pst(path):
    """Nome della cartella del PST come lo registra forense_posta.process_pst."""
    return re.sub(r"^Top of (Outlook data file|Personal Folders)/?", "", path) or path


def _pst_intestazioni(f, m):
    """(3.0.6) Intestazioni di trasporto complete rilette dal PST/OST (nel caso si salvano fino a INTEST_MAX caratteri):
    il messaggio della stessa cartella le cui intestazioni cominciano con quelle salvate. None se non ritrovato o se più
    messaggi diversi corrispondono."""
    try:
        import pypff
    except ImportError:
        return None
    salvate, trovate = m["headers"] or "", set()
    pf = pypff.file()
    try:
        pf.open(str(f))
        stack = [(pf.get_root_folder(), "")]
        while stack:
            fo, path = stack.pop()
            try:
                for i in range(fo.number_of_sub_folders):
                    sf = fo.get_sub_folder(i)
                    stack.append((sf, (path + "/" + (sf.name or "")).strip("/")))
            except Exception:
                pass
            if _cartella_pst(path) != (m["folder"] or ""):
                continue
            try:
                nm = fo.number_of_sub_messages
            except Exception:
                nm = 0
            for i in range(nm):
                try:
                    h = fo.get_sub_message(i).transport_headers or ""
                except Exception:
                    continue
                if h.startswith(salvate):
                    trovate.add(h)
    except Exception:
        return None
    finally:
        try:
            pf.close()
        except Exception:
            pass
    return trovate.pop() if len(trovate) == 1 else None


def intestazioni_originali(case, con, m):
    """(3.0.6) Intestazioni di trasporto originali di una mail PST/OST o MSG, così come registrate nel file: (testo,
    avvertenze). Nel caso sono salvate fino a INTEST_MAX caratteri; se sono state troncate, per i PST/OST si rileggono
    dal reperto."""
    h = m["headers"] or ""
    if len(h) < INTEST_MAX:
        return h, []
    if m["fmt"] == "PST/OST":
        tmpd = tempfile.mkdtemp(prefix="repertia_eml_")
        try:
            f = _contenitore(case, con, m, tmpd)
            intere = _pst_intestazioni(f, m) if f else None
        finally:
            shutil.rmtree(tmpd, ignore_errors=True)
        if intere:
            return intere, []
    n = f"{INTEST_MAX:,}".replace(",", ".")
    if m["fmt"] == "MSG":
        return h, [tr("intestazioni originali troncate a {n} caratteri: complete nel file .msg originale").format(n=n)]
    return h, [tr("intestazioni originali troncate a {n} caratteri").format(n=n)]


def _ricostruisci(case, con, m, hdr, rif=None):
    """.eml ricostruito dai dati letti (PST/OST, MSG): (byte, avvertenze). `hdr`: intestazioni di trasporto originali
    (intestazioni_originali); `rif`: file delle intestazioni esportato accanto, citato nella dichiarazione."""
    from email.message import EmailMessage
    note = [tr("ricostruito dai dati letti nel file {fmt}: non è un file originale").format(fmt=m["fmt"])]
    trasporto = [c for c in _campi(hdr) if not (c[0].lower().startswith("content-") or c[0].lower() == "mime-version")]
    nomi = {c[0].lower() for c in trasporto}
    if not trasporto:
        note.append(tr("intestazioni di trasporto assenti: Da, A, Cc, Ccn, Oggetto e Data scritti dai dati letti (Data = ora di invio)"))
    if len(m["body"] or "") >= TESTO_MAX:
        note.append(tr("testo troncato a {n} caratteri").format(n=f"{TESTO_MAX:,}".replace(",", ".")))
    if len(m["html"] or "") >= HTML_MAX:
        note.append(tr("HTML troncato a {n} caratteri").format(n=f"{HTML_MAX:,}".replace(",", ".")))
    data = None
    if m["date"]:
        try:
            import datetime as _dt
            data = email.utils.format_datetime(_dt.datetime.fromisoformat(m["date"][:19]).replace(tzinfo=_dt.timezone.utc))
        except ValueError:
            pass
    letti = [("From", m["sender"]), ("To", m["recipients"]), ("Cc", m["cc"]), ("Bcc", m["bcc"]), ("Subject", m["subject"]),
             ("Date", data)]
    aggiunti = [(k, v) for k, v in letti if k.lower() not in nomi] if trasporto else letti
    corpo = EmailMessage(policy=email.policy.SMTP)
    testo, htm = m["body"] or "", m["html"] or ""
    corpo.set_content(testo or ("" if htm else tr("(messaggio senza testo)")))
    if htm:
        corpo.add_alternative(htm, subtype="html")
    allegati = con.execute("SELECT id, name, relpath, note, sha256 FROM xitems WHERE mail=? ORDER BY id", (m["id"],)).fetchall()
    for xid, nome, rel, nota, sha in allegati:
        f = case.root / rel if rel else None
        if not f or not f.is_file():
            note.append(tr("allegato «{n}» non incluso: {m}").format(n=nome, m=nota or tr("non estratto")))
            continue
        tipo = (mimetypes.guess_type(nome or "")[0] or "application/octet-stream").split("/", 1)
        if tipo[0] in ("message", "multipart", "text"):     # byte identici: niente riconversione del testo o della mail
            tipo = ["application", "octet-stream"]
        corpo.add_attachment(f.read_bytes(), maintype=tipo[0], subtype=tipo[1], filename=nome or f"allegato_{xid}")
    if m["n_att"] and m["n_att"] > len(allegati):
        note.append(tr("{n} allegati registrati nel messaggio non sono tra quelli letti").format(n=m["n_att"] - len(allegati)))
    fonte = f"{m['src_path']} › {m['folder']}" if m["folder"] else m["src_path"]
    dich = tr("ricostruito da RepertIA {v} dai dati letti nel file {fmt} (non è il file originale); fonte: {f}").format(
        v=fa.APP_VERSION, fmt=m["fmt"], f=fonte)
    if rif:
        dich += "; " + tr("intestazioni originali nel file {f}").format(f=rif)
    testa = "\r\n".join(c[1] for c in trasporto).encode("utf-8") + (b"\r\n" if trasporto else b"")
    return testa + _intestazioni(aggiunti + [("X-RepertIA-Ricostruzione", dich)]) + corpo.as_bytes(policy=email.policy.SMTP), note


def suffissi():
    """(3.0.6) Suffissi dei file esportati di una mail: dicono nel nome che cosa è originale e che cosa è ricostruito."""
    return {"originale": tr("ORIGINALE"), "ricostruita": tr("RICOSTRUITA"), "intestazioni": tr("intestazioni_ORIGINALI")}


def _nome_base(m):
    """Data e ora di invio, oggetto e numero della mail: i file della stessa mail stanno vicini e in ordine di data."""
    quando = re.sub(r"\D", "", (m["date"] or "")[:19])
    base = "_".join(x for x in (f"{quando[:8]}_{quando[8:14]}" if quando else "", m["subject"] or "", f"m{m['id']}") if x)
    return re.sub(r'[\x00-\x1f:*?"<>|\\/]+', "_", base).strip(" ._")[:120] or f"m{m['id']}"


def mail_eml(case, con, mid, rif=None):
    """{"dati": byte del .eml, "originale": bool, "fmt", "note": [avvertenze], "nome": nome base dei file,
    "intestazioni": intestazioni di trasporto originali (solo per le mail ricostruite, "" se assenti),
    "altri": [(estensione, byte, descrizione)] (per MSG il file originale)}. `rif(testo)`: come citare nel .eml
    ricostruito il file delle intestazioni esportato accanto."""
    m = _riga(case, con, mid)
    note, altri = [], []
    dati, intest = None, ""
    if m["fmt"] in ORIGINALI:
        dati, perche = _originale(case, con, m)
        if dati is None:
            note.append(tr("byte originali non disponibili ({p}): mail ricostruita").format(p=perche))
    originale = dati is not None
    if not originale:
        intest, n1 = intestazioni_originali(case, con, m)
        dati, n2 = _ricostruisci(case, con, m, intest, rif(intest) if rif and intest else None)
        note += n2 + n1
        if m["fmt"] == "MSG":
            tmpd = tempfile.mkdtemp(prefix="repertia_eml_")
            try:
                f = _contenitore(case, con, m, tmpd)
                if f:
                    altri.append(("msg", f.read_bytes(), tr("file .msg originale")))
                else:
                    note.append(tr("file .msg originale non raggiungibile"))
            finally:
                shutil.rmtree(tmpd, ignore_errors=True)
    return {"dati": dati, "originale": originale, "fmt": m["fmt"], "note": note, "nome": _nome_base(m), "altri": altri,
            "intestazioni": intest, "mail": m}


def esporta(case, con, mid, cartella):
    """Scrive in `cartella`, in sola lettura, i file di una mail con lo stesso nome base e un suffisso che dice che cosa
    sono: <base>_ORIGINALE.eml (byte del file di posta) oppure <base>_RICOSTRUITA.eml (PST/OST, MSG), accanto
    <base>_intestazioni_ORIGINALI.txt (intestazioni di trasporto come registrate nel file, se ci sono) e per MSG
    <base>_ORIGINALE.msg. Restituisce le voci per il manifest."""
    m = _riga(case, con, mid)
    cartella.mkdir(parents=True, exist_ok=True)
    s = suffissi()
    tutti = (f"{s['originale']}.eml", f"{s['ricostruita']}.eml", f"{s['intestazioni']}.txt", f"{s['originale']}.msg")
    base0 = _nome_base(m)
    base, k = base0, 2
    while any((cartella / f"{base}_{t}").exists() for t in tutti):      # esportata di nuovo: i file restano insieme
        base, k = f"{base0}_{k}", k + 1
    nome_txt = f"{base}_{s['intestazioni']}.txt"
    r = mail_eml(case, con, mid, lambda t: f"{nome_txt} (SHA-256 {hashlib.sha256(t.encode('utf-8')).hexdigest()})")
    voci = [(f"{base}_{s['originale'] if r['originale'] else s['ricostruita']}.eml", r["dati"],
             tr("mail originale (byte del file)") if r["originale"] else tr("mail ricostruita"), r["originale"])]
    if r["intestazioni"]:
        voci.append((nome_txt, r["intestazioni"].encode("utf-8"),
                     tr("intestazioni di trasporto originali, come registrate nel file {fmt}").format(fmt=m["fmt"]), True))
    voci += [(f"{base}_{s['originale']}.{est}", dati, descr, True) for est, dati, descr in r["altri"]]
    out = []
    for nome, dati, descr, orig in voci:
        p = cartella / nome
        p.write_bytes(dati)
        p.chmod(0o444)
        out.append({"file": p, "byte": len(dati), "sha256": fa.sha256_file(p), "descrizione": descr, "originale": orig})
    case.log("mail_esportata", {"mail": m["id"], "formato": m["fmt"], "fonte": m["src_path"], "cartella": m["folder"],
                                "originale": r["originale"], "avvertenze": r["note"],
                                "file": [{"file": str(x["file"]), "sha256": x["sha256"]} for x in out]})
    return {"file": out, "note": r["note"], "originale": r["originale"], "mail": m}
