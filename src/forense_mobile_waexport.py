# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - chat esportate da WhatsApp con «Esporta chat» (dalla 3.0.6).

Che cosa si legge
- iOS: `_chat.txt` con righe `[GG/MM/AA, hh:mm:ss] Nome: testo` e allegati `<allegato: NNNNNNNN-PHOTO-….jpg>`.
- Android: `Chat WhatsApp con X.txt` / `WhatsApp Chat with X.txt` con righe `GG/MM/AA, hh:mm - Nome: testo` e
  allegati `IMG-…-WA0001.jpg (file allegato)`.
- Diciture in italiano e in inglese (verificate su esportazioni di prova di iOS e Android, novembre 2026); nelle altre
  lingue i messaggi si leggono come testo e le diciture restano come sono.
- Gli allegati si collegano per nome ai file della stessa cartella dell'esportazione (zip aperto come sorgente logica).

Limiti dichiarati (anche nel caso, `meta["chat"]["esportazioni"]`)
- È una copia fatta da chi usa il telefono, non un'acquisizione: mancano identificativi, stati di lettura, risposte
  (citazioni), reazioni, messaggi cancellati e numeri di telefono (solo i nomi della rubrica di chi esporta).
- Orari nell'ora locale del telefono, senza fuso: convertiti in UTC con il fuso indicato per il caso. Android scrive
  i minuti, iOS i secondi (due esportazioni iOS della stessa chat possono differire di un secondo).
- Il verso (inviato/ricevuto) non è scritto: si ricava da «Hai eliminato questo messaggio» o, nelle chat a due, dal
  nome del file (è l'altro interlocutore); altrimenti resta «verso non indicato».
- Su Android chiamate e messaggi a visualizzazione singola escono come righe senza testo: non si distinguono.
"""
import datetime as dt
import re
from pathlib import Path, PurePosixPath

from forense_lingua import tr, N_  # noqa: E402

APP = "whatsapp_export"
LRM = "‎"
_SP = r"[   ]"
_ORA = r"(\d{1,2})[:.](\d{2})(?:[:.](\d{2}))?(?:" + _SP + r"?([AaPp])\.?" + _SP + r"?[Mm]\.?)?"
_DATA = r"(\d{1,4})[/.\-](\d{1,2})[/.\-](\d{1,4}),?" + _SP
RIGA_IOS = re.compile(r"^" + LRM + r"?\[" + _DATA + _ORA + r"\]" + _SP + r"(.*)$", re.S)
RIGA_AND = re.compile(r"^" + LRM + r"?" + _DATA + _ORA + _SP + r"-" + _SP + r"(.*)$", re.S)

# nomi dei file di testo e dei titoli
TXT_IOS = "_chat.txt"
TITOLO_RE = re.compile(r"^(?:WhatsApp Chat - |WhatsApp Chat with |Chat WhatsApp con |Chat de WhatsApp con |"
                       r"WhatsApp-Chat mit |Discussion WhatsApp avec |Conversa do WhatsApp com )(.+)$", re.I)
TXT_AND_RE = re.compile(r"^(?:WhatsApp Chat with |Chat WhatsApp con |Chat de WhatsApp con |WhatsApp-Chat mit |"
                        r"Discussion WhatsApp avec |Conversa do WhatsApp com ).+\.txt$", re.I)

# diciture (minuscole, senza U+200E)
ALL_IOS = re.compile(r"<(?:allegato|attached|adjunto|anexo|angehängt|pièce jointe)\s*:\s*([^>]+)>\s*$", re.I)
ALL_AND = re.compile(r"^(.+?) \((?:file allegato|file attached|archivo adjunto|arquivo anexado|Datei angehängt|"
                     r"fichier joint)\)$", re.I)
OMESSI = {      # dicitura → tipo dell'allegato non esportato
    "immagine omessa": N_("immagine"), "image omitted": N_("immagine"),
    "video omesso": N_("video"), "video omitted": N_("video"),
    "audio omesso": N_("audio"), "audio omitted": N_("audio"),
    "documento omesso": N_("documento"), "document omitted": N_("documento"),
    "scheda contatto omessa": N_("contatto"), "contact card omitted": N_("contatto"),
    "gif omessa": N_("GIF"), "gif omesso": N_("GIF"), "gif omitted": N_("GIF"),
    "sticker omesso": N_("sticker"), "sticker omitted": N_("sticker"),
    "<media omessi>": N_("media"), "<media omitted>": N_("media"),
    "<il messaggio vocale visualizzabile una volta è stato omesso>": N_("vocale a visualizzazione singola"),
    "<view once voice message omitted>": N_("vocale a visualizzazione singola"),
}
MODIFICATO = re.compile(r"\s*<(?:questo messaggio è stato modificato|this message was edited)>\s*$", re.I)
ELIMINATO_MIO = re.compile(r"^(?:hai eliminato questo messaggio|you deleted this message)\.?$", re.I)
ELIMINATO = re.compile(r"^(?:questo messaggio è stato eliminato|this message was deleted)\.?$", re.I)
POSIZIONE = re.compile(r"^(?:posizione|location)\s*:\s*(https?://\S*?[?&]q=(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)\S*)$", re.I)
POS_LIVE = re.compile(r"^(?:posizione in tempo reale condivisa|live location shared)\.?$", re.I)
SONDAGGIO = re.compile(r"^(?:sondaggio|poll)\s*:\s*$", re.I)
CHIAMATA = re.compile(r"^(chiamata persa|videochiamata persa|chiamata|videochiamata|missed voice call|missed video call|"
                      r"voice call|video call)\.\s*(.*)$", re.I)
DURATA = re.compile(r"(\d+)\s*(h|ore|ora|hr|min|minuti|minuto|sec|secondi|secondo|s)\b", re.I)
URL = re.compile(r"^https?://\S+$")
TIPO_FILE = (("-PHOTO-", N_("immagine")), ("-VIDEO-", N_("video")), ("-AUDIO-", N_("audio")), ("-GIF-", N_("GIF")),
             ("-STICKER-", N_("sticker")), ("IMG-", N_("immagine")), ("VID-", N_("video")), ("PTT-", N_("vocale")),
             ("AUD-", N_("audio")), ("STK-", N_("sticker")), ("DOC-", N_("documento")))
VUOTO = N_("contenuto non esportato da WhatsApp (su Android: chiamata o messaggio a visualizzazione singola)")
AVVISO = N_("avviso generato da WhatsApp (non scritto da una persona)")


def titolo_da_nome(nome):
    """Interlocutore o gruppo dal nome dello zip, della cartella o del .txt («WhatsApp Chat - X 2.zip» → «X»)."""
    n = PurePosixPath((nome or "").replace("\\", "/")).name      # anche percorsi di Windows (immagine del caso)
    for ext in (".zip", ".txt"):
        if n.lower().endswith(ext):
            n = n[:-len(ext)]
    m = TITOLO_RE.match(n.strip())
    return m.group(1).strip() if m else None


def e_testo_esportato(path):
    """True se il percorso è il file di testo di un'esportazione («_chat.txt» o «WhatsApp Chat with X.txt»)."""
    n = PurePosixPath(path or "").name
    return n == TXT_IOS or bool(TXT_AND_RE.match(n))


def e_esportazione(img):
    """(per la scheda Smartphone) True se lo zip o la cartella `img` è un'esportazione di chat di WhatsApp."""
    from pathlib import Path
    p = Path(img)
    try:
        if p.is_dir():
            return any(e_testo_esportato(x.name) for x in p.iterdir() if x.is_file())
        import zipfile
        if zipfile.is_zipfile(p):
            with zipfile.ZipFile(p) as z:
                nomi = [n for n in z.namelist() if "/" not in n.strip("/")]
                return any(e_testo_esportato(n) for n in nomi) and len(z.namelist()) < 100000
    except OSError:
        return False
    return False


def _pulisci(s):
    return (s or "").replace(LRM, "").strip()


def voci(testo):
    """Righe del file → voci [(formato, numero di riga, campi della data, resto)], con le righe di continuazione unite."""
    out, formato = [], None
    for i, riga in enumerate(testo.splitlines(), 1):
        m = None
        if formato in (None, "ios"):
            m = RIGA_IOS.match(riga)
            if m and formato is None:
                formato = "ios"
        if not m and formato in (None, "android"):
            m = RIGA_AND.match(riga)
            if m and formato is None:
                formato = "android"
        if m:
            out.append([formato, i, m.groups()[:7], m.group(8)])
        elif out:
            out[-1][3] += "\n" + riga
    return formato, out


def ordine_data(vv):
    """'gma' (giorno/mese/anno), 'mga' o 'agm' dedotto dai valori; seconda voce: True se dedotto, False se ipotizzato."""
    a = [int(v[2][0]) for v in vv]
    b = [int(v[2][1]) for v in vv]
    if any(x > 31 for x in a):
        return "agm", True
    if any(x > 12 for x in a):
        return "gma", True
    if any(x > 12 for x in b):
        return "mga", True
    return "gma", False


def orario(campi, ordine, tz):
    """Campi della riga → (orario, ISO locale, dubbio). `tz`: nome IANA del fuso in cui era impostato il telefono,
    indicato dall'operatore; None = non indicato: l'orario resta l'ora del telefono «AAAA-MM-GGThh:mm:ss locale»
    (ora locale senza fuso, come le date DOS: nessuna conversione). Con un fuso: ISO UTC.
    dubbio: None; "doppia" (ora ripetuta al ritorno all'ora solare: si usa la prima, ora legale); "inesistente" (ora
    saltata al passaggio all'ora legale: convertita con lo scostamento di prima del salto); "fuso non disponibile"
    (database dei fusi assente: convertita come UTC). In questi casi l'orario va verificato."""
    x, y, z, hh, mm, ss, ap = campi
    x, y, z, hh, mm = int(x), int(y), int(z), int(hh), int(mm)
    g, me, a = (x, y, z) if ordine == "gma" else (y, x, z) if ordine == "mga" else (z, y, x)
    if a < 100:
        a += 2000
    if ap:
        hh = hh % 12 + (12 if ap.lower() == "p" else 0)
    loc = dt.datetime(a, me, g, hh, mm, int(ss or 0))
    if not tz:
        s = loc.strftime("%Y-%m-%dT%H:%M:%S")
        return s + " locale", s, None
    dubbio = None
    try:
        from zoneinfo import ZoneInfo
        z = ZoneInfo(tz)
        a0, a1 = loc.replace(tzinfo=z, fold=0), loc.replace(tzinfo=z, fold=1)
        utc = a0.astimezone(dt.timezone.utc)
        if a0.utcoffset() != a1.utcoffset():
            ritorno = utc.astimezone(z).replace(tzinfo=None)
            dubbio = "doppia" if ritorno == loc else "inesistente"
    except Exception:
        if str(tz).upper() != "UTC":
            dubbio = "fuso non disponibile"
        utc = loc.replace(tzinfo=dt.timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S"), loc.strftime("%Y-%m-%dT%H:%M:%S"), dubbio


def _tipo_file(nome):
    for k, t in TIPO_FILE:
        if k in nome:
            return t
    return N_("documento")


def _durata(s):
    tot = None
    for n, u in DURATA.findall(s or ""):
        u = u.lower()
        tot = (tot or 0) + int(n) * (3600 if u in ("h", "ore", "ora", "hr") else 60 if u.startswith("min") else 1)
    return tot


def classifica(formato, nome, testo):
    """Un messaggio → dict(kind, text, allegato, tipo, lat, lon, modificato, eliminato_mio, sistema, verso)."""
    r = {"kind": "testo", "text": None, "allegato": None, "tipo": None, "lat": None, "lon": None, "modificato": False,
         "eliminato_mio": False, "sistema": False, "url": None, "durata_s": None}
    grezzo = testo or ""
    t = grezzo.lstrip(LRM).rstrip()
    if MODIFICATO.search(t.replace(LRM, "")):
        r["modificato"] = True
        t = MODIFICATO.sub("", t.replace(LRM, ""))
    righe = t.split("\n")
    p = _pulisci(righe[0])
    resto = "\n".join(_pulisci(x) for x in righe[1:]).strip() or None
    if nome is None:                                     # Android: riga senza «Nome:» = avviso di WhatsApp
        r.update(kind="sistema", text=_pulisci(t), sistema=True, tipo=tr(AVVISO))
        return r
    m = ALL_IOS.search(_pulisci(t)) if formato == "ios" else ALL_AND.match(p)
    if m:
        f = m.group(1).strip()
        dida = _pulisci(ALL_IOS.sub("", _pulisci(t))) if formato == "ios" else resto
        r.update(kind="allegato", allegato=f, tipo=tr(_tipo_file(f)), text=dida or None)
        if f.lower().endswith(".vcf"):
            r["kind"] = "contatto"
        return r
    low = p.lower()
    for k, tipo in OMESSI.items():
        if low == k or (formato == "ios" and low.endswith(" " + k)):
            dida = _pulisci(p[:-len(k)]) if low != k else None
            r.update(kind="contatto" if tipo == "contatto" else "allegato", tipo=tr(tipo), text=dida or None,
                     allegato="")
            return r
    if ELIMINATO_MIO.match(p):
        r.update(kind="eliminato", eliminato_mio=True)
        return r
    if ELIMINATO.match(p):
        r.update(kind="eliminato")
        return r
    m = POSIZIONE.match(p)
    if m:
        r.update(kind="posizione", url=m.group(1), lat=float(m.group(2)), lon=float(m.group(3)), text=resto)
        return r
    if POS_LIVE.match(p):
        r.update(kind="posizione", tipo=tr("posizione in tempo reale (coordinate non esportate)"))
        return r
    if SONDAGGIO.match(p):
        r.update(kind="sondaggio", text=resto)
        return r
    m = CHIAMATA.match(p) if formato == "ios" else None
    if m:
        r.update(kind="chiamata", tipo=_pulisci(t).replace("\n", " "), durata_s=_durata(m.group(2)))
        return r
    if not _pulisci(t):
        r.update(kind="non gestito", tipo=tr(VUOTO))
        return r
    if formato == "ios" and grezzo.startswith(LRM):      # iOS: diciture di WhatsApp iniziano con U+200E
        r.update(kind="sistema", text=_pulisci(t), sistema=True, tipo=tr(AVVISO))
        return r
    r["text"] = "\n".join(_pulisci(x) if i == 0 else x.replace(LRM, "") for i, x in enumerate(t.split("\n")))
    if URL.match(r["text"]):
        r["kind"] = "link"
    return r


def analizza(testo, tz, titolo=None):
    """Testo dell'esportazione → dict con formato, ordine della data, messaggi (lista di dict), mittenti, chi ha
    esportato e titolo. Non scrive nulla: lo fa `leggi` (o il collaudo per le prove)."""
    formato, vv = voci(testo)
    if not vv:
        return None
    ordine, dedotto = ordine_data(vv)
    msgs, mittenti = [], {}
    for fmt, riga, campi, resto in vv:
        try:
            ts, loc, dubbio = orario(campi, ordine, tz)
        except ValueError:
            ts = loc = dubbio = None
        nome, corpo = None, resto
        k = resto.find(": ")
        if k > 0 and "\n" not in resto[:k]:
            nome, corpo = _pulisci(resto[:k]), resto[k + 2:]
        elif fmt == "ios" and resto.rstrip().endswith(":") and "\n" not in resto.rstrip()[:-1]:
            nome, corpo = _pulisci(resto.rstrip()[:-1]), ""
        elif fmt == "android" and resto.endswith(":") and "\n" not in resto:
            nome, corpo = _pulisci(resto[:-1]), ""
        c = classifica(fmt, nome, corpo)
        c.update(riga=riga, ts=ts, locale=loc, nome=nome, ora_dubbia=dubbio)
        if nome and not c["sistema"]:
            mittenti[nome] = mittenti.get(nome, 0) + 1
        msgs.append(c)
    # chi ha esportato: «Hai eliminato questo messaggio», poi (chat a due) il nome del file = l'altro interlocutore
    io, come = None, None
    mie = {m["nome"] for m in msgs if m["eliminato_mio"] and m["nome"]}
    if len(mie) == 1:
        io, come = mie.pop(), N_("dalla riga «Hai eliminato questo messaggio»")
    elif titolo and len(mittenti) == 2:
        altri = [n for n in mittenti if _stesso_nome(n, titolo)]
        if len(altri) == 1:
            io = [n for n in mittenti if n != altri[0]][0]
            come = N_("chat a due: il nome del file è l'altro interlocutore")
    gruppo = len(mittenti) > 2 or any(m["sistema"] and _gruppo(m["text"]) for m in msgs)
    return {"formato": formato, "ordine": ordine, "ordine_dedotto": dedotto, "messaggi": msgs,
            "mittenti": mittenti, "io": io, "io_come": come, "gruppo": gruppo, "titolo": titolo}


def _stesso_nome(a, b):
    a, b = (a or "").casefold().strip(), (b or "").casefold().strip()
    if a == b:
        return True
    b2 = re.sub(r" \d+$", "", b)                 # iOS aggiunge « 2», « 3» alle esportazioni successive
    return a == b2


def _gruppo(t):
    t = (t or "").lower()
    return any(k in t for k in ("il gruppo", "created group", "group name", "nome del gruppo", "added you",
                                "ti ha aggiunto", "hai aggiunto", "hai rimosso", " added ", " removed "))


def conta_mobile(m, part):
    """Numero di file di testo di esportazioni nell'elenco dei file di un'estrazione (estrazione.sqlite)."""
    return sum(1 for (path,) in m.execute("SELECT path FROM mobile_files WHERE part=? AND isdir=0 AND "
                                         "lower(path) LIKE '%.txt'", (part,)) if e_testo_esportato(path))


def cerca(con):
    """(3.0.6) Esportazioni nell'elenco dei file del caso (tabella files di caso.sqlite: dischi, telefoni, sorgenti
    logiche): file di testo [{"tipo": "testo", part, inode, path, cancellato}] e zip di esportazioni
    [{"tipo": "zip", …}] (gli zip si aprono come sorgente logica: non vengono letti da qui)."""
    out = []
    for part, inode, deleted, typ, path in con.execute(
            "SELECT part, inode, deleted, type, path FROM files WHERE (lower(path) LIKE '%.txt' OR lower(path) LIKE '%.zip')"
            " AND type NOT LIKE 'd%' ORDER BY path"):
        n = PurePosixPath(path or "").name
        if n.lower().endswith(".txt") and e_testo_esportato(n):
            out.append({"tipo": "testo", "part": part, "inode": str(inode), "path": path, "cancellato": bool(deleted)})
        elif n.lower().endswith(".zip") and titolo_da_nome(n) and not re.match(r"^\d{8}-", n):
            out.append({"tipo": "zip", "part": part, "inode": str(inode), "path": path, "cancellato": bool(deleted)})
    return out


def _testo(case, part, inode):
    import forense_agent as fa
    buf = bytearray()
    for b in fa.icat_stream(case, part, inode):
        buf += b
        if len(buf) > 512 << 20:
            raise ValueError(tr("file di testo troppo grande"))
    return bytes(buf).decode("utf-8-sig", errors="replace")


def _titolo(case, path):
    cartella = str(PurePosixPath(path).parent)
    cartella = "" if cartella == "." else cartella
    return (titolo_da_nome(PurePosixPath(path).name) or (titolo_da_nome(PurePosixPath(cartella).name) if cartella else None)
            or (titolo_da_nome(case.meta.get("image") or "") if not cartella and case.meta.get("logica") else None))


def _testo_zip(case, c):
    """Testo dell'esportazione dentro uno zip del caso, letto in una copia temporanea (per l'anteprima)."""
    import shutil
    import tempfile
    import zipfile
    import forense_agent as fa
    tmpd = Path(tempfile.mkdtemp(prefix="waexp_"))
    try:
        zp = tmpd / "x.zip"
        with open(zp, "wb") as fh:
            for b in fa.icat_stream(case, c["part"], c["inode"]):
                fh.write(b)
        if not zipfile.is_zipfile(zp):
            return None
        with zipfile.ZipFile(zp) as z:
            txt = [n for n in z.namelist() if "/" not in n.strip("/") and e_testo_esportato(n)]
            return z.read(txt[0]).decode("utf-8-sig", errors="replace") if txt else None
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


def anteprima(case, c, tz):
    """Riepilogo di un'esportazione per la finestra di scelta: formato, messaggi, periodo, mittenti, chi ha esportato."""
    if c["tipo"] == "zip":
        testo = _testo_zip(case, c)
        a = analizza(testo, tz, titolo_da_nome(PurePosixPath(c["path"]).name)) if testo else None
    else:
        a = analizza(_testo(case, c["part"], c["inode"]), tz, _titolo(case, c["path"]))
    if not a:
        return dict(c, valida=False)
    ts = [m["locale"] for m in a["messaggi"] if m["locale"]]
    return dict(c, valida=True, formato=a["formato"], messaggi=len(a["messaggi"]), mittenti=sorted(a["mittenti"]),
                io=a["io"], io_come=tr(a["io_come"]) if a["io_come"] else None, gruppo=a["gruppo"],
                titolo=a["titolo"], dal=min(ts) if ts else None, al=max(ts) if ts else None,
                allegati=sum(1 for m in a["messaggi"] if m["allegato"]))


def leggi(case, con, part, inode, path, W, tz, io=None):
    """Legge un'esportazione (file di testo nell'elenco dei file del caso) e la scrive con il Writer di
    forense_mobile_chat; restituisce il riepilogo o None. `io`: chi ha esportato scelto dall'operatore
    ("" = non indicato; None = ricavato dal file)."""
    cartella = str(PurePosixPath(path).parent)
    cartella = "" if cartella == "." else cartella
    # file della stessa cartella, per nome (i file presenti prima dei cancellati con lo stesso nome)
    pref = (cartella + "/") if cartella else ""
    files = {}
    for i, p in con.execute("SELECT inode, path FROM files WHERE part=? AND type NOT LIKE 'd%' AND path LIKE ? "
                            "ORDER BY deleted DESC", (part, pref + "%")):
        if p.startswith(pref) and "/" not in p[len(pref):]:
            files[p[len(pref):]] = ((part, str(i), p), "percorso")
    return _scrivi(_testo(case, part, inode), _titolo(case, path), files, path, cartella, W, tz, io)


def leggi_zip(case, con, c, W, tz, io=None, say=print):
    """(3.0.6) Esportazione ancora in zip dentro un disco o un telefono: copia derivata dei file dello zip in
    estratti/chat_esportate (file estratti «x» del caso, con le impronte), poi la lettura come per le altre."""
    x = estrai_zip(case, con, c, say)
    if not x:
        return None
    files = {k: ((None, str(xid), f"{c['path']} › {k}"), "estratto") for k, xid in x["file"].items()}
    testo = (case.root / x["txt_rel"]).read_bytes().decode("utf-8-sig", errors="replace")
    r = _scrivi(testo, titolo_da_nome(PurePosixPath(c["path"]).name), files, f"{c['path']} › {x['txt']}",
                PurePosixPath(c["path"]).name, W, tz, io)
    if r:
        r.update(zip=c["path"], zip_sha256=x["zip_sha256"], estratti=len(x["file"]), riusati=x["riusati"])
    return r


def _precedenti(case, con, where, args):
    """File estratti in una lettura precedente della stessa esportazione: {txt, txt_rel, file, sha256, riusati} se ci
    sono tutti, altrimenti li toglie (estrazione incompleta) e restituisce None."""
    prima = con.execute("SELECT id, inner, relpath, note FROM xitems WHERE kind='chat_esportata' AND " + where, args).fetchall()
    if prima and all((case.root / r[2]).exists() for r in prima if r[2]):
        file = {r[1]: r[0] for r in prima if r[2]}
        txt = [k for k in file if "/" not in k and e_testo_esportato(k)]
        sha = next((r[3][7:] for r in prima if (r[3] or "").startswith("sha256:")), None)
        if txt:
            rel = next(r[2] for r in prima if r[1] == txt[0])
            return {"txt": txt[0], "txt_rel": rel, "file": file, "zip_sha256": sha, "riusati": True}
    for r in prima:
        if r[2]:
            f = case.root / r[2]
            if f.exists():
                f.chmod(0o644)
                f.unlink()
        con.execute("DELETE FROM xitems WHERE id=?", (r[0],))
    return None


def _registra_file(case, con, origine, inner, sorgente, size, mtime, part, inode, src, cancellato, nota):
    """Un file dell'esportazione nella copia derivata (estratti/chat_esportate) come file estratto «x», con le impronte."""
    import forense_estesa as fe
    xid = fe.new_xitem(con, kind="chat_esportata", part=part, inode=None if inode is None else str(inode),
                       src_path=src, inner=inner, path=f"{origine} › {inner}", name=PurePosixPath(inner).name,
                       size=size, mtime=mtime, deleted=1 if cancellato else 0, note=nota)
    n, md5, sha1, sha256 = fe.hashes_of(sorgente)
    rel = fe.store_extracted(case, sorgente, "chat_esportate", xid, PurePosixPath(inner).name)
    con.execute("UPDATE xitems SET relpath=?, md5=?, sha1=?, sha256=?, size=? WHERE id=?",
                (rel, md5, sha1, sha256, n, xid))
    return xid, rel


def _estrai_zip_locale(case, con, zp, zsha, origine, part, inode, src, cancellato, tmpd, say):
    """Estrae uno zip già copiato in `tmpd` nella copia derivata del caso; None se non è un'esportazione."""
    import datetime as _dt
    import shutil
    import zipfile
    import forense_estesa as fe
    if not zipfile.is_zipfile(zp):
        return None
    with zipfile.ZipFile(zp) as z:
        voci = [i for i in z.infolist() if not i.is_dir()]
        txt = [i.filename for i in voci if "/" not in i.filename.strip("/") and e_testo_esportato(i.filename)]
        if not txt:
            return None
        if sum(i.file_size for i in voci) > fe.ARCHIVE_MAX:
            raise ValueError(tr("zip troppo grande per l'estrazione"))
        say(tr("Copia derivata dello zip {path} (SHA-256 {h}…)").format(path=origine, h=zsha[:16]))
        file, rel_txt = {}, None
        for k, i in enumerate(voci):
            inner = i.filename
            if inner.startswith("/") or ".." in PurePosixPath(inner).parts or i.file_size > fe.ENTRY_MAX:
                continue
            try:
                mt = _dt.datetime(*i.date_time).strftime("%Y-%m-%dT%H:%M:%S") + fe.LOCALE
            except ValueError:
                mt = None
            tf = tmpd / f"f{k}"
            with z.open(i) as s, open(tf, "wb") as d:
                shutil.copyfileobj(s, d)
            xid, rel = _registra_file(case, con, origine, inner, tf, i.file_size, mt, part, inode, src, cancellato,
                                      "sha256:" + zsha if k == 0 else None)
            file[inner] = xid
            if inner == txt[0]:
                rel_txt = rel
    con.commit()
    return {"txt": txt[0], "txt_rel": rel_txt, "file": file, "zip_sha256": zsha, "riusati": False}


def estrai_zip(case, con, c, say=print):
    """Copia derivata di uno zip di esportazione trovato nel caso: {txt, txt_rel, file: {nome nello zip: id del file
    estratto}, zip_sha256, riusati}. Se lo stesso zip è già stato estratto (stesso part/inode, file presenti) si riusa."""
    import hashlib
    import shutil
    import tempfile
    import forense_agent as fa
    import forense_estesa as fe
    fe.ensure_schema(con)
    x = _precedenti(case, con, "part=? AND inode=?", (c["part"], str(c["inode"])))
    if x:
        return x
    tmpd = Path(tempfile.mkdtemp(prefix="waexp_"))
    try:
        zp = tmpd / "esportazione.zip"
        h = hashlib.sha256()
        with open(zp, "wb") as fh:
            for b in fa.icat_stream(case, c["part"], c["inode"]):
                h.update(b)
                fh.write(b)
        x = _estrai_zip_locale(case, con, zp, h.hexdigest(), c["path"], c["part"], c["inode"], c["path"],
                               c.get("cancellato"), tmpd, say)
        if x:
            case.log("chat_esportata_zip_estratto", {"zip": c["path"], "part": c["part"], "inode": str(c["inode"]),
                                                      "sha256": x["zip_sha256"], "file": len(x["file"])})
        return x
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


# ------------------------------------------------- esportazioni aggiunte dall'operatore (es. da una pendrive)

def _origine_esterna(p):
    """('zip' | 'cartella' | 'testo', file di testo, file della cartella) di un percorso scelto dall'operatore."""
    import zipfile
    if p.is_dir():
        txt = [x for x in sorted(p.iterdir()) if x.is_file() and e_testo_esportato(x.name)]
        if not txt:
            raise ValueError(tr("Nella cartella non c'è il file di testo di un'esportazione di WhatsApp."))
        return "cartella", txt[0], [x for x in sorted(p.iterdir()) if x.is_file()]
    if p.is_file() and zipfile.is_zipfile(p):
        return "zip", None, None
    if p.is_file() and p.suffix.lower() == ".txt":
        return "testo", p, [x for x in sorted(p.parent.iterdir()) if x.is_file()]
    raise ValueError(tr("Scegli lo zip, la cartella o il file di testo di una chat esportata da WhatsApp."))


def _testo_esterno(p):
    import zipfile
    tipo, txt, _f = _origine_esterna(p)
    if tipo == "zip":
        with zipfile.ZipFile(p) as z:
            nn = [n for n in z.namelist() if "/" not in n.strip("/") and e_testo_esportato(n)]
            if not nn:
                raise ValueError(tr("Nello zip non c'è il file di testo di un'esportazione di WhatsApp."))
            return z.read(nn[0]).decode("utf-8-sig", errors="replace"), tipo
    return txt.read_bytes().decode("utf-8-sig", errors="replace"), tipo


def _impronta_esterna(p):
    """SHA-256 dello zip o del file di testo d'origine (per una cartella: del file di testo)."""
    import forense_agent as fa
    tipo, txt, _f = _origine_esterna(p)
    return fa.sha256_file(p if tipo == "zip" else txt)


def registra_esterna(case, path, tz):
    """Registra un'esportazione indicata dall'operatore (anche fuori dalla copia, es. da una pendrive): percorso,
    dimensione, SHA-256 nel registro a catena. La copia nel caso si fa alla lettura (analisi aggiuntiva)."""
    import forense_agent as fa
    p = Path(str(path)).expanduser().resolve()
    testo, tipo = _testo_esterno(p)
    a = analizza(testo, tz, titolo_da_nome(p.name))
    if not a:
        raise ValueError(tr("Il file non è nel formato di «Esporta chat» di WhatsApp."))
    voce = {"tipo": "esterna", "path": str(p), "nome": p.name, "origine": tipo,
            "byte": p.stat().st_size if p.is_file() else sum(x.stat().st_size for x in _origine_esterna(p)[2]),
            "sha256": _impronta_esterna(p), "ts": fa.now()}
    lst = [x for x in case.meta.get("chat_esportate_esterne") or [] if x.get("path") != voce["path"]]
    lst.append(voce)
    case.meta["chat_esportate_esterne"] = lst
    case.log("chat_esportata_esterna_registrata", voce)
    case.save()
    return voce


def anteprima_esterna(voce, tz):
    p = Path(voce["path"])
    try:
        testo, _t = _testo_esterno(p)
    except (OSError, ValueError) as e:
        return dict(voce, valida=False, errore=str(e) if isinstance(e, ValueError) else
                    tr("File non raggiungibile: collega il supporto che lo contiene."))
    a = analizza(testo, tz, titolo_da_nome(p.name))
    if not a:
        return dict(voce, valida=False)
    ts = [m["locale"] for m in a["messaggi"] if m["locale"]]
    return dict(voce, valida=True, formato=a["formato"], messaggi=len(a["messaggi"]), mittenti=sorted(a["mittenti"]),
                io=a["io"], io_come=tr(a["io_come"]) if a["io_come"] else None, gruppo=a["gruppo"],
                titolo=a["titolo"], dal=min(ts) if ts else None, al=max(ts) if ts else None,
                allegati=sum(1 for m in a["messaggi"] if m["allegato"]), part=None, inode=voce["sha256"])


def leggi_esterna(case, con, voce, W, tz, io=None, say=print):
    """Copia nel caso un'esportazione registrata dall'operatore e la legge (allegati dalla copia derivata)."""
    import shutil
    import tempfile
    import forense_estesa as fe
    p = Path(voce["path"])
    if not p.exists():
        raise ValueError(tr("File non raggiungibile: collega il supporto che lo contiene ({p}).").format(p=p))
    sha = _impronta_esterna(p)
    if sha != voce["sha256"]:
        raise ValueError(tr("Il file è cambiato dopo la registrazione (SHA-256 diverso): registralo di nuovo."))
    fe.ensure_schema(con)
    x = _precedenti(case, con, "part IS NULL AND src_path=?", (str(p),))
    if x and x["zip_sha256"] != sha:
        x = None
    if not x:
        tipo, txt, files = _origine_esterna(p)
        tmpd = Path(tempfile.mkdtemp(prefix="waexp_"))
        try:
            if tipo == "zip":
                zp = tmpd / "esportazione.zip"
                shutil.copyfile(p, zp)
                x = _estrai_zip_locale(case, con, zp, sha, str(p), None, None, str(p), False, tmpd, say)
            else:
                say(tr("Copia derivata dei file di {path} (SHA-256 del testo {h}…)").format(path=p, h=sha[:16]))
                file, rel_txt = {}, None
                for k, f in enumerate(files):
                    tf = tmpd / f"f{k}"
                    shutil.copyfile(f, tf)
                    import datetime as _dt
                    mt = _dt.datetime.fromtimestamp(f.stat().st_mtime, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
                    xid, rel = _registra_file(case, con, str(f.parent), f.name, tf, f.stat().st_size, mt, None, None,
                                              str(p), False, "sha256:" + sha if f == txt else None)
                    file[f.name] = xid
                    if f == txt:
                        rel_txt = rel
                con.commit()
                x = {"txt": txt.name, "txt_rel": rel_txt, "file": file, "zip_sha256": sha, "riusati": False}
        finally:
            shutil.rmtree(tmpd, ignore_errors=True)
        if not x:
            return None
        case.log("chat_esportata_esterna_copiata", {"origine": str(p), "sha256": sha, "file": len(x["file"])})
    files = {k: ((None, str(xid), f"{p} › {k}"), "estratto") for k, xid in x["file"].items()}
    testo = (case.root / x["txt_rel"]).read_bytes().decode("utf-8-sig", errors="replace")
    r = _scrivi(testo, titolo_da_nome(p.name) or titolo_da_nome(x["txt"]), files, f"{p} › {x['txt']}", p.name, W, tz, io)
    if r:
        r.update(esterna=str(p), sha256_origine=sha, estratti=len(x["file"]), riusati=x["riusati"])
    return r


def _scrivi(testo, titolo, files, path, cartella, W, tz, io):
    """Scrive conversazione, messaggi e allegati. `files`: {nome: ((part, inode, percorso), metodo)}."""
    nome_file = PurePosixPath(path.split(" › ")[-1]).name
    a = analizza(testo, tz, titolo)
    if not a:
        return None
    if io is not None:
        a["io"] = io if io in a["mittenti"] else None
        a["io_come"] = N_("indicato dall'operatore") if a["io"] else None
    tit = a["titolo"] or (cartella and PurePosixPath(cartella).name) or nome_file
    uguali = [n for n in a["mittenti"] if _stesso_nome(n, tit)]
    if not a["gruppo"] and len(uguali) == 1:
        tit = uguali[0]                          # «X 3» (terza esportazione su iOS) → «X», come nei messaggi
    # chi ha esportato è «questo dispositivo» (colonna local), non un interlocutore
    partecipanti = sorted(n for n in a["mittenti"] if n != a["io"])
    th = W.thread("esportazione:" + path, tit, partecipanti, a["gruppo"])
    if a["io"]:
        W.see_local(th, a["io"])
    n_file = n_senza = 0
    for x in a["messaggi"]:
        if x["sistema"]:
            verso, sender, sname = "sys", "", None
        elif a["io"] and x["nome"]:
            verso = "out" if x["nome"] == a["io"] else "in"
            sender, sname = ("", None) if verso == "out" else (x["nome"], x["nome"])
        else:
            verso, sender, sname = "unk", x["nome"] or "", x["nome"]
        extra = {"tipo": x["tipo"], "riga": x["riga"], "ora_locale": x["locale"], "fuso": tz,
                 "esportazione": nome_file, "ora_dubbia": x.get("ora_dubbia")}
        if x["modificato"]:
            extra["modificato"] = True
        if x["sistema"] and x["nome"]:
            extra["attribuito_a"] = x["nome"]          # iOS attribuisce gli avvisi al gruppo o alla persona interessata
        if x["durata_s"] is not None:
            extra["durata_s"] = x["durata_s"]
        mid = W.message(th, x["ts"], verso, sender, x["text"], x["kind"], nome_file, x["riga"],
                        service=tr("WhatsApp (chat esportata)"), sender_name=sname,
                        extra={k: v for k, v in extra.items() if v not in (None, "", False)})
        if x["allegato"] is not None:
            f = x["allegato"]
            trovato = files.get(f) if f else None
            if trovato:
                n_file += 1
            else:
                n_senza += 1
            W.attachment(mid, f or x["tipo"], None, None, f or None, trovato[0] if trovato else None,
                         metodo=trovato[1] if trovato else None)
        elif x["lat"] is not None:
            W.attachment(mid, tr("posizione"), None, None, x["url"], None, x["lat"], x["lon"])
    return {"file": path, "formato": a["formato"], "ordine_data": a["ordine"], "ordine_dedotto": a["ordine_dedotto"],
            "messaggi": len(a["messaggi"]), "mittenti": len(a["mittenti"]), "gruppo": a["gruppo"],
            "esportato_da": a["io"], "esportato_da_come": tr(a["io_come"]) if a["io_come"] else None,
            "allegati_trovati": n_file, "allegati_assenti": n_senza, "fuso": tz,
            "ore_dubbie": sum(1 for m in a["messaggi"] if m.get("ora_dubbia")),
            "precisione": tr("secondi") if a["formato"] == "ios" else tr("minuti")}
