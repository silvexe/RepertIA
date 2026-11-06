#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""
forense_relazione.py - RepertIA by silvexe.
(3.0.1) Report illustrato: chi lo riceve vede gli elementi come nel caso. L'analista sceglie le sezioni, le categorie
dei Preferiti (anche togliendo singoli elementi) e, se vuole, tipi interi (tutte le chat, tutte le foto, gli artefatti
di una categoria...). Ogni elemento è mostrato com'è nel caso:
  - foto: miniatura, e con un clic l'originale copiato nella cartella del report con il suo SHA-256;
  - video: un fotogramma (l'originale si copia solo se richiesto);
  - documenti: la prima pagina;
  - chat: i fumetti con mittente, ora, fonte del dato grezzo e gli allegati (foto visibili, video col fotogramma,
    gli altri file indicati come nella conversazione);
  - artefatti e posta: la scheda con i campi.
Escono un report HTML (cartella con report.html, pagine, file e anteprime), un PDF e un Word con lo stesso contenuto.
I file grandi sono divisi in pagine: il report regge anche «tutte le foto» di un telefono.
Il contenuto delle prove non viene mai interpretato come HTML: testo sempre con escape, immagini come JPEG.
"""
import csv, hashlib, html, io, json, re, shutil, sqlite3, time
from pathlib import Path

import forense_agent as fa
import forense_gui as g
import forense_relazione_pdf as rp
import forense_lingua as lg  # noqa: E402
from forense_lingua import tr, N_  # noqa: E402

PAGINA_FILE = 300              # elementi per pagina HTML nelle sezioni con molti file
PAGINA_RIGHE = 2000            # righe per pagina HTML nelle tabelle (artefatti, posizioni)
PAGINA_MSG = 3000              # messaggi per pagina HTML di una chat
THUMB = 360                    # lato delle anteprime (pixel)
ORIG_MAX = 2 << 30             # file più grandi non si copiano (restano indicati con hash)
RISERVA = 2 << 30              # spazio da lasciare libero sul disco del caso: oltre, gli originali non si copiano più
PDF_IMG_MAX = 5000             # anteprime nel PDF e nel Word; oltre, solo nel report HTML
PDF_RIGHE_MAX = 20000          # righe di tabella nel PDF e nel Word
FOTO, VIDEO, AUDIO, DOC, ALTRO = "foto", "video", "audio", "doc", "altro"
ICONA = {FOTO: "🖼", VIDEO: "🎞", AUDIO: "🎵", DOC: "📄", ALTRO: "📦"}

# sezioni testuali (dal report dell'analisi): chiave -> titoli «## …» del report che vi confluiscono
SEZIONI = [("caso", N_("Dati del caso e della copia forense"), (N_("## Hash dell'estrazione (SHA-256)"), N_("## Hash dei file della copia forense (SHA-256)"),
                                                                  N_("## Hash confrontato con quello dell'acquisizione"),
                                                                  N_("## Hash dei dati acquisiti (contenuto del supporto originale)"), N_("## Partizioni"))),
           ("analisi", N_("Analisi eseguite"), (N_("## Analisi eseguite"), N_("## File esportati"))),
           ("reperti", N_("Reperti"), (N_("## Reperti"),)),
           ("cronologia", N_("Cronologia dei preferiti"), ()),
           ("metodo", N_("Note metodologiche"), (N_("## Note metodologiche"),)),
           ("registro", N_("Ambiente e registro delle operazioni"), (N_("## Ambiente di analisi"), N_("## Registro delle operazioni (audit_log.jsonl)"))),
           ("testo", N_("Testo completo del report dell'analisi"), ())]
SEZ_DEFAULT = {"caso", "analisi", "reperti", "cronologia", "metodo", "registro"}

CSS = """:root{--bg:#f4f5f7;--card:#fff;--ink:#1d2330;--mut:#5b6475;--line:#d8dbe2;--acc:#2456c7;--out:#dbe8ff}
*{box-sizing:border-box}body{font:14px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;margin:0;background:var(--bg);color:var(--ink)}
a{color:var(--acc)}header.top{background:#1f3a5f;color:#fff;padding:18px 24px}header.top h1{margin:0 0 4px;font-size:22px}
header.top .meta{color:#c9d6ea;font-size:12.5px}header.top a{color:#fff}
nav.bc{font-size:12.5px;padding:8px 24px;background:#e9edf4;border-bottom:1px solid var(--line)}
main{max-width:1180px;margin:0 auto;padding:18px 16px 40px}
section.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin:0 0 16px}
h2{font-size:18px;margin:0 0 10px;color:#1f3a5f}h3{font-size:15px;margin:14px 0 6px}h4{font-size:13.5px;margin:10px 0 4px}
.hint,.meta{color:var(--mut);font-size:12.5px}.mono{font-family:Menlo,Consolas,monospace;font-size:11.5px;word-break:break-all}
table{border-collapse:collapse;width:100%;font-size:12.5px;margin:6px 0 10px}td,th{border:1px solid var(--line);padding:4px 7px;vertical-align:top;text-align:left;overflow-wrap:break-word;word-break:normal}
th{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}td{white-space:pre-line}table[style] td{overflow-wrap:anywhere}
th{background:#eef0f3}table.kv th{width:190px;white-space:nowrap}
.toc{columns:2;column-gap:28px}.toc li{margin:2px 0;break-inside:avoid}
.grid{display:flex;flex-direction:column;gap:8px}
.el{display:flex;gap:14px;align-items:flex-start;background:var(--card);border:1px solid var(--line);border-radius:9px;padding:10px 12px;font-size:12.5px}
.el .num{flex:0 0 auto;min-width:44px;text-align:center;font-weight:700;font-size:15px;color:#1f3a5f;background:#e9edf4;border-radius:6px;padding:5px 4px;line-height:1.2}
.el .num small{display:block;font-size:10.5px;font-weight:600;color:#5b6475}
.el .dati{flex:1;min-width:0}.el .dati table{margin:4px 0 0;font-size:12px}.el .dati th{width:150px;background:#f4f5f8}
.el .dati td{overflow-wrap:anywhere}.el .th{flex:0 0 220px;display:flex;align-items:center;justify-content:center;height:170px;background:#eef0f3;border-radius:6px;overflow:hidden;font-size:42px}
.el .th img{max-width:100%;max-height:170px;display:block}.el b{font-size:13.5px}
@media (max-width:640px){.el{flex-direction:column}.el .th{flex-basis:auto;width:100%}.el .num{align-self:flex-start}}
.el.del{border:1px dashed #d97706;background:#fdf8ee}.tag{display:inline-block;font-size:11px;border-radius:99px;padding:0 7px;background:#e6e8ee;color:var(--mut);margin-right:4px}
.tag.del{background:#fde7c7;color:#8a4b00}.nota{background:#fff8d6;border-left:3px solid #e0b400;padding:4px 8px;margin-top:4px}
.chat{display:flex;flex-direction:column;gap:6px;max-width:900px;margin:0 auto}
.day{align-self:center;font-size:11.5px;color:var(--mut);background:#e6e8ee;border-radius:99px;padding:2px 10px;margin:6px 0}
.b{max-width:76%;padding:7px 10px;border-radius:12px;background:#fff;border:1px solid var(--line);white-space:pre-wrap;word-wrap:break-word}
.b.out{align-self:flex-end;background:var(--out);border-color:transparent}.b.in{align-self:flex-start}
.b.sys{align-self:center;background:none;border:none;color:var(--mut);font-style:italic;font-size:12.5px;text-align:center}
.b.del{border:1px dashed #d97706;background:#fdf3e1}.w{font-size:12px;font-weight:600;color:var(--acc);margin-bottom:2px}
.m{font-size:11px;color:var(--mut);margin-top:3px;text-align:right}.k{font-style:italic;color:var(--mut)}
.a{margin-top:6px;padding:6px;border:1px solid var(--line);border-radius:8px;background:#f7f8fa;font-size:12px;white-space:normal}
.a img{display:block;max-width:260px;max-height:260px;border-radius:6px;margin-bottom:4px}
.pg{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0}.pg a,.pg b{padding:2px 9px;border:1px solid var(--line);border-radius:6px;background:#fff;text-decoration:none}
.mailbody{white-space:pre-wrap;background:#fafbfc;border:1px solid var(--line);border-radius:6px;padding:8px;font-size:12.5px;max-height:none}
footer{max-width:1180px;margin:0 auto 30px;padding:0 16px;font-size:11.5px;color:var(--mut)}
@media print{body{background:#fff}nav.bc,.pg{display:none}section.card,.el,.b{break-inside:avoid}header.top{background:#fff;color:#000}header.top .meta{color:#333}}"""


def E(x):
    return html.escape(str(x if x is not None else ""))


def tipo_di(nome, mime=None, head=b""):
    ext = Path(str(nome or "")).suffix.lower()
    m = str(mime or "")
    if ext in g.IMG_ALL or m.startswith("image/") or (head and g.sniff_mime(head)):
        return FOTO
    if ext in g.VIDEO_MIME or ext in g.VIDEO_OTHER or m.startswith("video/"):
        return VIDEO
    if ext in g.AUDIO_MIME or m.startswith("audio/") or ext in (".opus", ".amr", ".3ga"):
        return AUDIO
    if ext == ".pdf" or ext in g.WORD_EXT or ext in g.OFFICE_EXT or ext in (".txt", ".csv", ".rtf"):
        return DOC
    return ALTRO


def fsize(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return ""
    for u in ("byte", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{int(n)} {u}" if u == "byte" else f"{n:.1f} {u}".replace(".", "," if lg.lingua() != "en" else ".")
        n /= 1024


# ------------------------------------------------------------------ cosa si può scegliere

def opzioni(case):
    """Per la finestra «Crea report»: sezioni, categorie dei Preferiti e tipi interi con il numero di elementi."""
    tutto = []
    con = fa.db_ro(case)
    try:
        def conta(q, a=()):
            try:
                return con.execute(q, a).fetchone()[0] or 0
            except sqlite3.Error:
                return 0
        if fa.table_exists(con, "chat_threads"):
            n = conta("SELECT COUNT(*) FROM chat_threads")
            if n:
                tutto.append({"k": "chat", "lab": tr("Tutte le chat"), "n": n, "msg": conta("SELECT COUNT(*) FROM chat_messages")})
        carv = _carving(con)
        for k, lab in ((FOTO, tr("Tutte le foto")), (VIDEO, tr("Tutti i video")), (AUDIO, tr("Tutti gli audio"))):
            n = (conta("SELECT COUNT(*) FROM media_file WHERE tipo=?", (k,)) if fa.table_exists(con, "media_file") else 0) \
                + sum(1 for x in carv if x[3] == k)
            if n:
                tutto.append({"k": k, "lab": lab, "n": n})
        if fa.table_exists(con, "mail"):
            n = conta("SELECT COUNT(*) FROM mail")
            if n:
                tutto.append({"k": "posta", "lab": tr("Tutta la posta"), "n": n})
        if fa.table_exists(con, "artifacts"):
            fe = g.fe_mod()
            for cat, n in con.execute("SELECT cat, COUNT(*) FROM artifacts WHERE cat != 'leapp' GROUP BY cat ORDER BY cat"):
                tutto.append({"k": "art:" + cat, "lab": tr("Artefatti: {c}").format(c=tr(fe.ART_CATS.get(cat, cat))), "n": n,
                              "g": tr("Artefatti"), "nome": tr(fe.ART_CATS.get(cat, cat))})
            # (3.0.1) «g», «sg» e «nome»: gruppi da aprire e chiudere nella finestra (sottogruppo = categoria di iLEAPP/ALEAPP)
            for a, sg, n in con.execute("SELECT json_extract(data, '$.artefatto') a, MIN(grp), COUNT(*) FROM artifacts WHERE cat='leapp' "
                                        "AND json_valid(data) GROUP BY a ORDER BY MIN(grp) COLLATE NOCASE, a COLLATE NOCASE"):
                if a:
                    tutto.append({"k": "leapp:" + a, "lab": tr("iLEAPP/ALEAPP: {c}").format(c=a), "n": n,
                                  "g": "iLEAPP/ALEAPP", "sg": sg or tr("Altro"), "nome": a})
    finally:
        con.close()
    try:
        import forense_mappe as fmp
        n = len(fmp.punti(case)["punti"])
        if n:
            tutto.append({"k": "posizioni", "lab": tr("Tutte le posizioni (mappa)"), "n": n})
    except Exception:
        pass
    sez = [{"k": k, "lab": tr(lab), "on": k in SEZ_DEFAULT} for k, lab, _t in SEZIONI]
    cats = g.bm_categories(case) if (case.root / "ricerche.sqlite").exists() else []
    return {"sezioni": sez, "preferiti": cats, "tutto": tutto, "ia": fa.report_ia(case),
            "autore": (case.meta.get("info_caso") or {}).get("operatore") or ""}


def elementi_categoria(case, cid):
    """Elementi di una categoria dei Preferiti, per toglierne alcuni dal report."""
    con = g.search_db(case)
    try:
        return [{"id": i, "source": s, "path": p, "name": n, "deleted": d, "size": z, "note": nt or ""}
                for i, s, p, n, d, z, nt in con.execute("SELECT id, source, path, name, deleted, size, note FROM bm WHERE cid=? "
                                                        "ORDER BY path COLLATE NOCASE LIMIT 100000", (int(cid),))]
    finally:
        con.close()


# ------------------------------------------------------------------ costruzione

class Lavoro:
    """Cartella del report, copie dei file, anteprime e impronte. Un file del caso si copia una volta sola."""

    def __init__(self, case, o, out, progress):
        self.case, self.o, self.out, self.progress = case, o, out, progress
        self.tz = o.get("tz") or "utc"
        self.copie, self.anteprime, self.sha = {}, {}, {}
        self.n_file = self.n_th = 0
        self.senza_spazio = 0             # originali non copiati per non riempire il disco
        self.media = None
        self.cache_web = None
        for d in ("file", "anteprime", "pagine"):
            (out / d).mkdir(parents=True, exist_ok=True)

    def tipo_media(self, part, inode):
        """Tipo riconosciuto dal contenuto all'indicizzazione (media_file): vale anche per i file senza estensione."""
        if self.media is None:
            self.media = {}
            con = fa.db_ro(self.case)
            try:
                if fa.table_exists(con, "media_file"):
                    self.media = {(p, str(i)): t for p, i, t in con.execute("SELECT part, inode, tipo FROM media_file")}
            finally:
                con.close()
        try:
            return self.media.get((int(part), str(inode)))
        except (TypeError, ValueError):
            return None

    def ts(self, v):
        return data_fmt(g.fmt_ts(self.case, self.tz, v)) if v else ""

    def _nome(self, cart, nome, n):
        base = re.sub(r"[^\w.\-]+", "_", Path(str(nome or "file")).name)[-80:].strip("._") or "file"
        return f"{cart}/{n:06d}_{base}"

    def anteprima(self, chiave, b=None, dati=None, lato=THUMB):
        """Percorso relativo dell'anteprima JPEG di un file del caso (b = come per /api/thumb) o di byte già pronti."""
        if chiave in self.anteprime:
            return self.anteprime[chiave]
        rel = None
        try:
            if dati is None and b is not None:
                r = g.thumb_bytes(self.case, {**b, "size": lato})
                dati = r[0] if r else None
            if dati:
                dati = jpeg(dati, lato)
            if dati:
                self.n_th += 1
                rel = f"anteprime/{self.n_th:06d}.jpg"
                (self.out / rel).write_bytes(dati)
        except Exception:
            rel = None
        self.anteprime[chiave] = rel
        return rel

    def copia(self, chiave, b=None, sorgente=None, nome=None):
        """Copia l'originale nella cartella file/ (una volta): -> (percorso relativo, sha256) o (None, None)."""
        if chiave in self.copie:
            return self.copie[chiave]
        res = (None, None)
        try:
            dim = Path(sorgente).stat().st_size if sorgente is not None else (g.file_ident(self.case, b).get("size") or 0)
            if shutil.disk_usage(self.out).free - dim < RISERVA:
                self.senza_spazio += 1
                self.copie[chiave] = res
                return res
            self.n_file += 1
            if sorgente is not None:
                src = Path(sorgente)
                if src.stat().st_size <= ORIG_MAX:
                    rel = self._nome("file", nome or src.name, self.n_file)
                    h = hashlib.sha256()
                    with open(src, "rb") as fi, open(self.out / rel, "wb") as fo:
                        while ch := fi.read(1 << 20):
                            h.update(ch)
                            fo.write(ch)
                    res = (rel, h.hexdigest())
            else:
                it = g.file_ident(self.case, b)
                if (it.get("size") or 0) <= ORIG_MAX:
                    rel = self._nome("file", nome or it.get("name") or it.get("path"), self.n_file)
                    h = hashlib.sha256()
                    with open(self.out / rel, "wb") as fo:
                        for _pos, ch in g.iter_chunks(self.case, it):
                            h.update(ch)
                            fo.write(ch)
                    res = (rel, h.hexdigest())
        except Exception:
            res = (None, None)
        if res[0]:
            self.sha[res[0]] = res[1]
        self.copie[chiave] = res
        return res

    def vuoi_originale(self, tipo):
        if not self.o.get("originali", True):
            return False
        return tipo in (FOTO, DOC, AUDIO) or bool(self.o.get("originali_tutti"))


DFMT = ["iso"]                 # formato delle date scelto nell'interfaccia (menu 📅) per il report in corso
MESI = {"it": "gen feb mar apr mag giu lug ago set ott nov dic".split(), "en": "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()}


def data_fmt(t):
    """Data iniziale AAAA-MM-GG nel formato scelto: «gma» 31/01/2024, «mga» 01/31/2024, «esteso» 31 gen 2024, «iso» invariata.
    Cambia solo la presentazione: registro, impronte e CSV restano in ISO."""
    t = str(t or "")
    m = re.match(r"(\d{4})-(\d\d)-(\d\d)", t)
    f = DFMT[0]
    if not m or f not in ("gma", "mga", "esteso"):
        return t
    a, me, gi = m.groups()
    d = f"{gi}/{me}/{a}" if f == "gma" else f"{me}/{gi}/{a}" if f == "mga" else \
        f"{int(gi)} {MESI['en' if lg.lingua() == 'en' else 'it'][int(me) - 1]} {a}"
    resto = t[10:]
    return d + (" " + resto[1:] if resto[:1] == "T" else resto)      # solo la «T» tra data e ora (non quella di «UTC»)


def jpeg(dati, lato=THUMB):
    """JPEG (il PDF incorpora solo JPEG): le miniature PNG/WebP si convertono con PIL."""
    if dati[:3] == b"\xff\xd8\xff" and len(dati) < (lato * lato) // 2:
        return dati
    try:
        from PIL import Image, ImageOps
        im = ImageOps.exif_transpose(Image.open(io.BytesIO(dati)))
        im.thumbnail((lato, lato))
        if im.mode not in ("RGB", "L"):
            bg = Image.new("RGB", im.size, (255, 255, 255))
            im = im.convert("RGBA")
            bg.paste(im, mask=im.split()[-1])
            im = bg
        b = io.BytesIO()
        im.save(b, "JPEG", quality=82)
        return b.getvalue()
    except Exception:
        return None


# ---- elementi (indipendenti dal formato): dict con "t" = file | chat | scheda | tabella | mail | testo

def _cache_web(L, xid):
    """Nota (indirizzo web e offset) di un file estratto dalla cache di un browser; None per gli altri estratti."""
    if L.cache_web is None:
        con = fa.db_ro(L.case)
        try:
            L.cache_web = dict(con.execute("SELECT CAST(id AS TEXT), note FROM xitems WHERE kind = 'cache_web'")) \
                if fa.table_exists(con, "xitems") else {}
        finally:
            con.close()
    return L.cache_web.get(str(xid))


def el_file(L, src, part, inode, path, name=None, size=None, deleted=0, mtime=None, sha=None, nota="", extra=None, tipo=None):
    nome = name or Path(str(path or "")).name
    tipo = tipo or (L.tipo_media(part, inode) if src == "fs" else None) or tipo_di(nome)
    b = {"source": src, "part": part, "inode": inode, "id": inode, "name": nome, "path": path}
    k = (src, str(part), str(inode))
    th = L.anteprima(k, b) if src != "ua" and tipo in (FOTO, VIDEO, DOC) else None
    rel = grande = None
    if L.vuoi_originale(tipo) and src != "ua":
        rel, s2 = L.copia(k, b, nome=nome)
        sha = sha or s2
    if th and tipo == FOTO and Path(nome).suffix.lower() in g.IMG_CONVERT:
        grande = L.anteprima(k + ("grande",), b, lato=1600)     # HEIC, TIFF, RAW: da vedere anche dove il sistema non li apre
    righe = [(tr("Percorso"), path)]
    if src == "fs" and part is not None and (part or 0) >= 0:
        righe.append((tr("Posizione"), f"offset {part}, inode {inode}"))
    elif src == "carving":
        righe.append((tr("Posizione"), tr("file recuperato col carving")))
    elif src == "x" and _cache_web(L, inode):
        righe.append((tr("Posizione"), tr("estratto dalla voce di cache del browser (file d'origine nel percorso)")))
        extra = list(extra or []) + [(tr("Origine"), _cache_web(L, inode))]
    elif src == "x":
        righe.append((tr("Posizione"), tr("estratto da archivio, allegato o copia shadow")))
    stato = (tr("recuperato dallo spazio non allocato") if src in ("carving", "ua") else tr("cancellato") if deleted else tr("allocato"))
    righe += [(tr("Stato"), stato), (tr("Dimensione"), fsize(size) if size is not None else ""),
              (tr("Modificato ({tz})").format(tz=g.tz_label(L.case, L.tz)), L.ts(mtime)), ("SHA-256", sha or "")]
    righe += list(extra or [])
    return {"t": "file", "tipo": tipo, "titolo": nome, "thumb": th, "file": rel, "grande": grande, "del": bool(deleted),
            "righe": [(a, v) for a, v in righe if v not in (None, "")], "nota": nota or ""}


def el_scheda(L, art_id, nota=""):
    """Artefatto con tutti i campi, come nel pannello di dettaglio."""
    titolo, righe, _chat = g.art_campi(L.case, {"id": art_id, "tz": L.tz})
    righe = [(k, data_fmt(v) if re.match(r"\d{4}-\d\d-\d\d", str(v)) else v) for k, v in righe]
    return {"t": "scheda", "titolo": titolo or tr("Artefatto"), "righe": righe, "nota": nota}


def el_mail(L, mid, nota=""):
    con = fa.db_ro(L.case)
    try:
        r = con.execute("SELECT id, date, sender, recipients, cc, subject, body, html, src_path, folder, fmt FROM mail WHERE id=?",
                        (int(mid),)).fetchone()
        atts = con.execute("SELECT id, name, size, relpath, sha256 FROM xitems WHERE mail=? ORDER BY id", (int(mid),)).fetchall()
    finally:
        con.close()
    if not r:
        return None
    _id, date, snd, to, cc, subj, body, htm, src, folder, fmt = r
    testo = body or ""
    if not testo and htm:            # solo HTML: si mostra il testo, mai l'HTML della prova
        testo = html.unescape(re.sub(r"(?is)<(script|style)\b.*?</\1>|<[^>]+>", " ", htm))
        testo = re.sub(r"[ \t]+", " ", re.sub(r"\n\s*\n+", "\n\n", testo)).strip()
    allegati = []
    for aid, nome, size, relp, sha in atts:
        tipo = tipo_di(nome)
        f = (L.case.root / relp) if relp else None
        th = rel = None
        if f is not None and f.exists():
            k = ("x", "", str(aid))
            if tipo in (FOTO, VIDEO, DOC):
                th = L.anteprima(k, {"source": "x", "id": aid, "inode": aid, "name": nome})
            if L.vuoi_originale(tipo):
                rel, s2 = L.copia(k, sorgente=f, nome=nome)
                sha = sha or s2
        allegati.append({"tipo": tipo, "nome": nome, "size": size, "thumb": th, "file": rel, "sha": sha, "righe": []})
    righe = [(tr("Da"), snd), (tr("A"), to), (tr("Cc"), cc), (tr("Data ({tz})").format(tz=g.tz_label(L.case, L.tz)), L.ts(date)),
             (tr("Fonte"), f"{src} › {folder}" if folder else src), (tr("Formato"), fmt)]
    return {"t": "mail", "titolo": subj or tr("(senza oggetto)"), "righe": [(a, v) for a, v in righe if v], "testo": testo[:200000],
            "allegati": allegati, "nota": nota}


def el_chat(L, tid, nota="", solo_msg=None):
    """Conversazione (o un solo messaggio con `solo_msg`) con fumetti e allegati."""
    import forense_mobile_chat as fmc
    import forense_mobile_gui as fmg
    import forense_mobile_wa as fmw
    con = fa.db_ro(L.case)
    try:
        t = con.execute("SELECT id, app, title, participants, is_group, n_msg, first_ts, last_ts, src_path, local FROM chat_threads WHERE id=?",
                        (int(tid),)).fetchone()
        if not t:
            return None
        _id, app, title, parts, grp, n, first, last, src, local = t
        da, a = str(L.o.get("chat_da") or "")[:10], str(L.o.get("chat_a") or "")[:10]
        q = ("SELECT id, ts, direction, sender, sender_name, text, kind, status, service, src_table, src_row, extra FROM chat_messages "
             "WHERE thread=?")
        args = [int(tid)]
        if solo_msg is not None:
            q += " AND id=?"
            args.append(int(solo_msg))
        else:
            if da:
                q += " AND ts >= ?"
                args.append(da)
            if a:
                q += " AND ts < ?"
                args.append(a + "T99")
        msgs = con.execute(q + " ORDER BY ts, id", args).fetchall()
        att = fmg._attachments(con, [m[0] for m in msgs])
    finally:
        con.close()
    lbl = fmc.APP_LBL.get(app, app)
    plist = [x for x in json.loads(parts or "[]") if x]
    loc = tr("questo dispositivo") + (f" ({fmc.show_id(local)})" if local else "")
    other = (tr("gruppo «{g}»: ").format(g=title) + ", ".join(fmc.show_id(x) for x in plist)) if grp else \
        " ".join(x for x in (title, f"({fmc.show_id(plist[0])})" if plist and fmc.show_id(plist[0]) not in (title or "") else None) if x)
    righe = [(tr("App"), lbl), (tr("Interlocutori"), f"{loc} ↔ {other}"),
             (tr("Periodo"), f"{L.ts(first)} → {L.ts(last)}"), (tr("Messaggi"), (f"{len(msgs)} / {n}" if len(msgs) != (n or 0) else str(n))),
             (tr("Database di origine"), src or "")]
    out, lastday = [], ""
    for mid, ts, dr, snd, sname, text, kind, st, svc, tb, row, extra in msgs:
        ex = json.loads(extra) if extra else {}
        day = data_fmt(g.fmt_ts(L.case, L.tz, ts)[:10]) if ts else ""
        if day and day != lastday:
            out.append({"day": day})
            lastday = day
        cls = "out" if dr == "out" else "sys" if dr == "sys" or kind == "sistema" else "in"
        who = (sname or fmc.show_id(snd)) if cls == "in" and (grp or sname or snd) else ""
        txt = text if text else "[" + (fmw.etichetta(kind, ex) if kind and kind != "testo" else ex.get("tipo") or tr("senza testo")) + "]"
        aa = []
        for x in att.get(mid, []):
            aa.append(_allegato_chat(L, x))
        meta = " · ".join(v for v in (L.ts(ts), st, svc, f"{tb} #{row}") if v)
        out.append({"dir": cls, "del": kind == "eliminato", "who": who, "txt": txt, "corsivo": not text, "meta": meta, "att": aa})
    return {"t": "chat", "titolo": f"{lbl} · {title}", "righe": [(k, v) for k, v in righe if v], "msgs": out, "nota": nota,
            "parziale": solo_msg is not None}


def _allegato_chat(L, a):
    import forense_mobile_gui as fmg
    import forense_percorsi as fpc
    nome = a.get("name") or Path(str(a.get("path") or a.get("device_path") or "")).name or tr("allegato")
    tipo = (L.tipo_media(a.get("part"), a.get("inode")) if a.get("inode") not in (None, "", "None") else None) or tipo_di(nome, a.get("mime"))
    th = rel = grande = None
    sha = a.get("sha256")
    if a.get("path") and str(a["path"]).startswith("leapp:"):
        f = (L.case.root / a["path"][6:]).resolve()
        if (L.case.root / "leapp").resolve() in f.parents and f.is_file():
            k = ("leapp", "", str(f))
            if tipo in (FOTO, VIDEO):
                try:
                    if tipo == FOTO and f.stat().st_size < (40 << 20):
                        th = L.anteprima(k, dati=f.read_bytes())
                except OSError:
                    pass
            if L.vuoi_originale(tipo):
                rel, s2 = L.copia(k, sorgente=f, nome=nome)
                sha = sha or s2
    elif a.get("inode") not in (None, "", "None") and a.get("part") is not None:
        b = {"source": "fs", "part": int(a["part"]), "inode": str(a["inode"]), "name": nome}
        k = ("fs", str(a["part"]), str(a["inode"]))
        if tipo in (FOTO, VIDEO, DOC):
            th = L.anteprima(k, b)
        if L.vuoi_originale(tipo):
            rel, s2 = L.copia(k, b, nome=nome)
            sha = sha or s2
        if th and tipo == FOTO and Path(nome).suffix.lower() in g.IMG_CONVERT:
            grande = L.anteprima(k + ("grande",), b, lato=1600)
    if not th and a.get("thumb"):
        try:
            th = L.anteprima(("dbthumb", "", str(a["id"])), dati=fmg.att_thumb(L.case, {"id": a["id"]})[0])
        except (ValueError, sqlite3.Error):
            pass
    righe = []
    if a.get("size"):
        righe.append(fsize(a["size"]))
    if sha:
        righe.append("SHA-256 " + sha)
    if a.get("metodo") not in (None, "percorso"):
        righe.append(fpc.esito_metodo(a["metodo"], a.get("verifica")))
    if a.get("lat") is not None:
        righe.append(f"📍 {a.get('lat')}, {a.get('lon')}")
    if a.get("path") or a.get("device_path"):
        righe.append(str(a.get("path") or a.get("device_path")))
    t = a.get("trascrizione") or {}
    if (t.get("analista") or {}).get("stato") == "confermata":
        righe.append(tr("Trascrizione confermata dall'analista: «{t}»").format(t=t["analista"]["testo"]))
    elif t.get("testo"):
        righe.append(tr("Trascrizione automatica (da verificare ascoltando l'audio): «{t}»").format(t=t["testo"]))
    if not rel and not th and not a.get("path") and a.get("inode") in (None, "", "None"):
        righe.append(tr("file non presente nell'estrazione"))
    return {"tipo": tipo, "nome": nome, "thumb": th, "file": rel, "grande": grande, "righe": righe}


def el_tabella(intest, righe):
    righe = [[data_cella(c) if j == 0 and c else c for j, c in enumerate(r)] for r in righe]
    t = tabella_pulita([intest] + righe, taglia=2000)
    return {"t": "tabella", "intest": t[0], "righe": t[1:]}


# ---- sezioni

class Sezione:
    def __init__(self, k, titolo, nota="", n=0, gen=None, testo=None):
        self.k, self.titolo, self.nota, self.n, self.gen, self.testo = k, titolo, nota, n, gen, testo


def sezioni_testo(case, o):
    """Sezioni di testo dal report dell'analisi (report.md), divise per titolo «## …»."""
    md = fa.write_report(case).read_text(encoding="utf-8")
    parti, cur, testa = {}, None, []
    for riga in md.split("\n"):
        if riga.startswith("## "):
            cur = riga.strip()
            parti[cur] = []
        elif cur is None:
            testa.append(riga)
        else:
            parti[cur].append(riga)
    scelte = set(o.get("sezioni") or SEZ_DEFAULT)
    out = []
    for k, lab, titoli in SEZIONI:
        if k not in scelte:
            continue
        if k == "testo":
            out.append(Sezione(k, tr(lab), testo=md))
        elif k == "caso":
            corpo = [x for x in testa if not x.startswith("# ")]
            for t in titoli:
                if tr(t) in parti:
                    corpo += ["", "### " + tr(t)[3:], *parti[tr(t)]]
            out.append(Sezione(k, tr(lab), testo="\n".join(corpo)))
        elif k == "cronologia":
            L = fa.bookmarks_timeline_md(case)
            if L:
                out.append(Sezione(k, tr(lab), testo="\n".join(L[1:])))
        else:
            corpo = []
            for t in titoli:
                if tr(t) in parti:
                    corpo += (["", "### " + tr(t)[3:]] if len(titoli) > 1 else []) + parti[tr(t)]
            if any(x.strip() for x in corpo):
                out.append(Sezione(k, tr(lab), testo="\n".join(corpo)))
    return out, md


def sezioni_preferiti(case, o, L):
    sel = {str(k): v for k, v in (o.get("preferiti") or {}).items()}
    if not sel:
        return []
    th = fa.bm_threads(case)
    con = g.search_db(case)
    try:
        cats = con.execute("SELECT cid, name, note FROM bm_cat ORDER BY name COLLATE NOCASE").fetchall()
        out = []
        for cid, name, note in cats:
            s = sel.get(str(cid))
            if not s or not (s.get("on", True) if isinstance(s, dict) else s):
                continue
            esclusi = set(int(x) for x in (s.get("esclusi") or [])) if isinstance(s, dict) else set()
            rows = [r for r in con.execute("SELECT id, source, part, inode, path, name, deleted, size, mtime, sha256, note FROM bm WHERE cid=? "
                                           "ORDER BY path COLLATE NOCASE", (cid,)) if r[0] not in esclusi]

            def gen(rows=rows):
                for bid, src, part, inode, path, name, deleted, size, mt, sha, nt in rows:
                    try:
                        if src == "art" and str(inode) in th:
                            e = el_chat(L, th[str(inode)], nt)
                        elif src == "art":
                            e = el_scheda(L, inode, nt)
                        elif src == "chat":
                            e = _msg_singolo(L, inode, nt)
                        elif src == "mail":
                            e = el_mail(L, inode, nt)
                        else:
                            e = el_file(L, src, part, inode, path, name, size, deleted, mt, sha, nt)
                    except Exception as ex:
                        e = {"t": "scheda", "titolo": path or name or str(inode), "righe": [(tr("Errore"), str(ex))], "nota": nt or ""}
                    if e:
                        yield e
            out.append(Sezione(f"bm{cid}", "⭐ " + name, note or "", len(rows), gen))
        return out
    finally:
        con.close()


def _msg_singolo(L, mid, nota):
    con = fa.db_ro(L.case)
    try:
        r = con.execute("SELECT thread FROM chat_messages WHERE id=?", (int(mid),)).fetchone()
    finally:
        con.close()
    return el_chat(L, r[0], nota, solo_msg=mid) if r else None


def sezioni_tutto(case, o, L):
    out = []
    scelti = list(o.get("tutto") or [])
    for k in scelti:
        if k == "chat":
            con = fa.db_ro(case)
            try:
                ids = [r[0] for r in con.execute("SELECT id FROM chat_threads ORDER BY last_ts DESC")]
            finally:
                con.close()
            out.append(Sezione("chat", tr("Tutte le chat"), "", len(ids), lambda ids=ids: (e for e in (el_chat(L, t) for t in ids) if e)))
        elif k in (FOTO, VIDEO, AUDIO):
            con = fa.db_ro(case)
            try:
                rows = con.execute("SELECT part, inode, path, size, app FROM media_file WHERE tipo=? ORDER BY app, path", (k,)).fetchall() \
                    if fa.table_exists(con, "media_file") else []
                carv = [x for x in _carving(con) if x[3] == k]
                cache_web = {str(r[0]): dict(zip(("id", "name", "size", "deleted", "sha256", "mtime"), r)) for r in con.execute(
                    "SELECT id, name, size, deleted, sha256, mtime FROM xitems WHERE kind = 'cache_web'")} \
                    if fa.table_exists(con, "xitems") else {}
            finally:
                con.close()
            dett = _dettagli_nav(case, rows)
            lab = {FOTO: tr("Tutte le foto"), VIDEO: tr("Tutti i video"), AUDIO: tr("Tutti gli audio")}[k]

            def gen(rows=rows, dett=dett, carv=carv, k=k, cache_web=cache_web):
                for part, inode, path, size, app in rows:
                    extra = [(tr("App o cartella"), app)] if app and not str(app).startswith("~") else []
                    if part == -1:              # estratto da una voce della cache di un browser (inode = id dell'estratto)
                        x = cache_web.get(str(inode)) or {}
                        yield el_file(L, "x", None, inode, path, x.get("name"), x.get("size") or size, x.get("deleted") or 0, x.get("mtime"),
                                      x.get("sha256"), "", extra, tipo=k)
                        continue
                    d = dett.get((part, str(inode))) or {}
                    yield el_file(L, "fs", part, inode, path, None, size, d.get("deleted", 0), d.get("mtime"), None, "", extra, tipo=k)
                for name, size, off, _t, sha in carv:          # recuperati col carving (tipo dall'estensione data da PhotoRec)
                    yield el_file(L, "carving", None, Path(name).name, "[carving] " + name, Path(name).name, size, 0, None, sha, "",
                                  [(tr("Offset nella copia"), off)] if off is not None else [])
            out.append(Sezione(k, lab, tr("Classificati dal contenuto del file (non dalla sola estensione); i file recuperati col carving "
                                          "sono in fondo, con il tipo dato da PhotoRec."), len(rows) + len(carv), gen))
        elif k == "posta":
            con = fa.db_ro(case)
            try:
                ids = [r[0] for r in con.execute("SELECT id FROM mail ORDER BY date")]
            finally:
                con.close()
            out.append(Sezione("posta", tr("Tutta la posta"), "", len(ids), lambda ids=ids: (e for e in (el_mail(L, i) for i in ids) if e)))
        elif k.startswith("art:") or k.startswith("leapp:"):
            out.append(_sez_artefatti(case, L, k))
        elif k == "posizioni":
            import forense_mappe as fmp
            p = fmp.punti(case)
            cat = {i: c["nome"] for i, c in enumerate(p["categorie"])}
            righe = [[L.ts(x[4]) or x[5], f"{x[1]}, {x[0]}", cat.get(x[2], ""), str(x[3])] for x in p["punti"]]
            out.append(Sezione("posizioni", tr("Tutte le posizioni (mappa)"), tr("Coordinate come registrate nella fonte (latitudine, longitudine)."),
                               len(righe), lambda righe=righe: iter([el_tabella([tr("Data ({tz})").format(tz=g.tz_label(case, L.tz)), tr("Coordinate"),
                                                                                tr("Categoria"), tr("Riferimento")], righe)])))
    return [s for s in out if s]


def _carving(con):
    """[(nome, dimensione, offset, tipo, sha256)] dei file recuperati col carving."""
    if not fa.table_exists(con, "carved"):
        return []
    try:
        return [(n, z, o, tipo_di(n), h) for n, z, o, h in con.execute("SELECT name, size, img_offset, sha256 FROM carved ORDER BY name")]
    except sqlite3.Error:
        return []


def _dettagli_nav(case, rows):
    """Stato e data dei file dall'albero del file system, se è pronto (altrimenti senza)."""
    d = {}
    try:
        st = g.ensure_nav(case)
        if st.get("state") != "ready":
            return d
        con = g.nav_db(case)
        try:
            for i in range(0, len(rows), 500):
                pezzo = [[r[0], str(r[1])] for r in rows[i:i + 500]]
                for part, inode, dl, mt in con.execute("SELECT part, inode, deleted, mtime FROM nav WHERE (part, inode) IN "
                                                       "(SELECT json_extract(value,'$[0]'), json_extract(value,'$[1]') FROM json_each(?))",
                                                       (json.dumps(pezzo),)):
                    d[(part, str(inode))] = {"deleted": dl, "mtime": mt}
        finally:
            con.close()
    except Exception:
        pass
    return d


def _sez_artefatti(case, L, k):
    fe = g.fe_mod()
    con = fa.db_ro(case)
    try:
        if k.startswith("art:"):
            cat = k[4:]
            titolo = tr("Artefatti: {c}").format(c=tr(fe.ART_CATS.get(cat, cat)))
            rows = con.execute("SELECT ts, title, detail, user, src_path FROM artifacts WHERE cat=? ORDER BY ts", (cat,)).fetchall()
            intest = [tr("Data ({tz})").format(tz=g.tz_label(case, L.tz)), tr("Elemento"), tr("Dettagli"), tr("Utente"), tr("Fonte")]
            righe = [[L.ts(a), b or "", c or "", d or "", e or ""] for a, b, c, d, e in rows]
        else:
            nome = k[6:]
            titolo = tr("iLEAPP/ALEAPP: {c}").format(c=nome)
            rows = con.execute("SELECT ts, title, data FROM artifacts WHERE cat='leapp' AND json_valid(data) AND json_extract(data, '$.artefatto')=? "
                               "ORDER BY ts", (nome,)).fetchall()
            campi = []
            dati = []
            for ts, t, d in rows:
                try:
                    c = (json.loads(d) or {}).get("campi") or {}
                except ValueError:
                    c = {}
                if isinstance(c, list):
                    c = dict(c) if all(isinstance(x, (list, tuple)) and len(x) == 2 for x in c) else {}
                for kk in c:
                    if kk not in campi and len(campi) < 12:
                        campi.append(kk)
                dati.append((ts, t, c))
            intest = [tr("Data ({tz})").format(tz=g.tz_label(case, L.tz))] + (campi or [tr("Elemento")])
            righe = [[L.ts(ts)] + ([str(c.get(x, "")) for x in campi] if campi else [t or ""]) for ts, t, c in dati]
    finally:
        con.close()
    return Sezione(k, titolo, "", len(righe), lambda: iter([el_tabella(intest, righe)]))


# ------------------------------------------------------------------ HTML

def tabella_pulita(rows, taglia=400):
    """Righe di una tabella senza le colonne vuote in tutte le righe dei dati; celle oltre `taglia` caratteri accorciate
    (il testo completo è nella scheda dell'elemento)."""
    if not rows:
        return rows
    nc = max(len(r) for r in rows)
    rows = [list(r) + [""] * (nc - len(r)) for r in rows]
    tieni = [c for c in range(nc) if len(rows) < 2 or any(str(r[c]).strip() for r in rows[1:])]
    cut = lambda v: v if len(str(v)) <= taglia else str(v)[:taglia].rstrip() + " …"
    return [[cut(data_cella(r[c]) if i and re.match(r"\d{4}-\d\d-\d\d", str(r[c])) else r[c]) for c in tieni] for i, r in enumerate(rows)]


def data_cella(v):
    """Data in una cella di tabella: la data su una riga e l'ora sotto (la data non si spezza a metà)."""
    return re.sub(r"[ T]+(\d\d:\d\d(?::\d\d)?)", r"\n\1", data_fmt(v), count=1)


def _md_html(md):
    out = []
    for b in g.md_blocks(md):
        if b[0] == "h":
            lv = min(6, b[1] + 1)
            out.append(f"<h{lv}>{_runs_html(b[2])}</h{lv}>")
        elif b[0] == "p":
            out.append(f"<p>{_runs_html(b[1])}</p>")
        elif b[0] == "li":
            out.append(f'<ul style="margin:0 0 0 {b[1] * 18}px"><li>{_runs_html(b[2])}</li></ul>')
        elif b[0] == "table":
            rows = tabella_pulita(b[1], taglia=240)
            out.append(_colgroup(rows) + "".join("<tr>" + "".join((f"<th>{_runs_html(c)}</th>" if i == 0 else f"<td>{_runs_html(c)}</td>") for c in r) + "</tr>"
                                           for i, r in enumerate(rows)) + "</table>")
    return "\n".join(out)


def _colgroup(rows):
    """<table> a larghezze fisse, proporzionali al testo delle colonne (le colonne brevi non si schiacciano lettera per lettera)."""
    if not rows or len(rows[0]) < 3:
        return "<table>"
    nc = len(rows[0])
    lung = []
    for c in range(nc):
        vals = [len(re.sub(r"[*`]", "", str(r[c]))) for r in rows[1:]] or [0]
        media = sum(vals) / len(vals)
        lung.append(max(len(str(rows[0][c])) + 2, min(10 + media, 70), min(max(vals), 14)))
    tot = sum(lung)
    return ('<table style="table-layout:fixed">' + "<colgroup>" + "".join(f'<col style="width:{x * 100 / tot:.1f}%">' for x in lung)
            + "</colgroup>")


def _runs_html(t):
    return "".join(f"<b>{E(x)}</b>" if s == "b" else f'<code class="mono">{E(x)}</code>' if s == "c" else E(x) for x, s in g.md_runs(t))


def _kv_html(righe):
    return '<table class="kv">' + "".join(f"<tr><th>{E(k)}</th><td{' class=mono' if 'SHA' in str(k) else ''}>{E(v)}</td></tr>"
                                          for k, v in righe) + "</table>"


def _thumb_html(th, rel, tipo, pre=""):
    img = f'<img src="{pre}{E(th)}" alt="" loading="lazy">' if th else ICONA.get(tipo, "📦")
    return f'<a href="{pre}{E(rel)}" target="_blank">{img}</a>' if rel else img


def el_html(e, pre=""):
    t = e["t"]
    nota = f'<div class="nota">📝 {E(e["nota"])}</div>' if e.get("nota") else ""
    if t == "file":
        tags = (f'<span class="tag del">{E(tr("cancellato"))}</span>' if e["del"] else "")
        link = (f'<div style="margin-top:4px"><a href="{pre}{E(e["file"])}" target="_blank">{E(tr("Apri il file originale"))}</a></div>' if e.get("file") else "")
        return (f'<div class="el{" del" if e["del"] else ""}">' + (f'<div class="num">{e["num"][0]}<small>{E(tr("di {b}").format(b=e["num"][1]))}</small></div>' if e.get("num") else "") + f'<div class="dati"><b>{ICONA.get(e["tipo"], "")} {E(e["titolo"])}</b> {tags}'
                f'{_kv_html(e["righe"])}{link}{nota}</div>'
                f'<div class="th">{_thumb_html(e["thumb"], e.get("grande") or e.get("file"), e["tipo"], pre)}</div></div>')
    if t == "scheda":
        return f'<section class="card"><h3>{E(e["titolo"])}</h3>{_kv_html(e["righe"])}{nota}</section>'
    if t == "tabella":
        return ("<table><tr>" + "".join(f"<th>{E(c)}</th>" for c in e["intest"]) + "</tr>" +
                "".join("<tr>" + "".join(f"<td>{E(c)}</td>" for c in r) + "</tr>" for r in e["righe"]) + "</table>")
    if t == "mail":
        aa = "".join(_att_html(a, pre) for a in e["allegati"])
        return (f'<section class="card"><h3>✉️ {E(e["titolo"])}</h3>{_kv_html(e["righe"])}<div class="mailbody">{E(e["testo"])}</div>'
                f'{aa}{nota}</section>')
    if t == "chat":
        corpo = []
        for m in e["msgs"]:
            if "day" in m:
                corpo.append(f'<div class="day">{E(m["day"])}</div>')
                continue
            who = f'<div class="w">{E(m["who"])}</div>' if m["who"] else ""
            txt = f'<span class="k">{E(m["txt"])}</span>' if m["corsivo"] else E(m["txt"])
            corpo.append(f'<div class="b {m["dir"]}{" del" if m["del"] else ""}">{who}{txt}{"".join(_att_html(a, pre) for a in m["att"])}'
                         f'<div class="m">{E(m["meta"])}</div></div>')
        return (f'<section class="card"><h3>💬 {E(e["titolo"])}</h3>{_kv_html(e["righe"])}{nota}</section>'
                f'<div class="chat">{"".join(corpo)}</div>')
    return ""


def _att_html(a, pre):
    nome = f'<a href="{pre}{E(a["file"])}" target="_blank">{E(a["nome"])}</a>' if a.get("file") else E(a["nome"])
    img = (f'<a href="{pre}{E(a.get("grande") or a["file"])}" target="_blank"><img src="{pre}{E(a["thumb"])}" alt=""></a>' if a.get("thumb") and a.get("file")
           else f'<img src="{pre}{E(a["thumb"])}" alt="">' if a.get("thumb") else "")
    righe = "".join(f'<div class="{"mono" if r.startswith("SHA-256") else ""}">{E(r)}</div>' for r in a["righe"])
    return f'<div class="a">{img}{ICONA.get(a["tipo"], "📎")} {nome}{righe}</div>'


def pagina(titolo, corpo, testa, pre="", bc=""):
    return (f'<!doctype html><html lang="{E(testa["lingua"])}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src \'self\' data: file:; style-src \'unsafe-inline\'; media-src \'self\' file:">'
            f'<title>{E(titolo)}</title><style>{CSS}</style></head><body>'
            f'<header class="top"><h1>{E(testa["titolo"])}</h1><div class="meta">{E(testa["sotto"])}</div></header>'
            + (f'<nav class="bc"><a href="{pre}report.html">{E(tr("Indice del report"))}</a> › {E(bc)}</nav>' if bc else "")
            + f'<main>{corpo}</main><footer>{E(testa["piede"])}</footer></body></html>')


# ------------------------------------------------------------------ PDF

class PdfReport:
    def __init__(self, titolo, ia_testo, produttore):
        self.d = rp.Pdf(titolo, ia_testo, produttore)
        self.n_img = 0
        self.n_righe = 0
        self.tagliato = False

    def h(self, testo, lv):
        d = self.d
        sz = {1: 18, 2: 14.5, 3: 12, 4: 10.5}.get(lv, 10)
        d.need(150 if lv <= 3 else sz * 3)      # il titolo non resta da solo in fondo alla pagina
        d.para([(testo, "b")], size=sz, before=sz * 0.5, after=sz * 0.3, rgb=(0.12, 0.23, 0.37))
        if lv <= 2:
            d.rule()

    def p(self, runs, size=9.5, **k):
        self.d.para(runs, size=size, **k)

    def md(self, md):
        for b in g.md_blocks(md):
            if b[0] == "h":
                self.h(b[2], min(4, b[1] + 1))
            elif b[0] == "p":
                self.p(g.md_runs(b[1]))
            elif b[0] == "li":
                self.p(g.md_runs(b[2]), x0=self.d.M + 12 + 12 * b[1], bullet="•" if not b[1] else "–", after=2)
            elif b[0] == "table":
                t = tabella_pulita(b[1], taglia=240)
                self.tabella(t[0], t[1:], md=True)

    def kv(self, righe, size=8.5):
        if righe:
            self.tabella(None, [[k, str(v)] for k, v in righe], size=size, prima_col=135)

    def tabella(self, intest, righe, size=None, md=False, prima_col=None):
        d = self.d
        rows = ([intest] if intest else []) + righe
        if not rows:
            return
        nc = max(len(r) for r in rows)
        rows = [[str(c) for c in r] + [""] * (nc - len(r)) for r in rows]
        Wt = d.W - 2 * d.M
        size = size or (7 if nc > 5 else 8)
        pad = 3
        pulisci = (lambda s: re.sub(r"[*`]", "", s)) if md else (lambda s: s)
        if prima_col and nc == 2:
            cw = [prima_col, Wt - prima_col]
        else:
            riga_max = lambda v: max((d.larg(x, "", size) for x in pulisci(v)[:200].split("\n")), default=0)
            nat = [min(max(riga_max(r[c]) for r in rows[:200]) + 2 * pad, 240) for c in range(nc)]
            nat = [max(x, 30) for x in nat]
            # le colonne con date tengono la loro larghezza (la data intera su una riga); le altre si stringono
            fisse = [c for c in range(nc) if nat[c] <= 64 or any(re.match(r"\d", str(r[c])) and "\n" in str(r[c]) for r in rows[1:20])]
            libero = Wt - sum(nat[c] for c in fisse)
            altre = sum(nat[c] for c in range(nc) if c not in fisse) or 1
            if fisse and libero > 60 * (nc - len(fisse)):
                cw = [nat[c] if c in fisse else nat[c] * libero / altre for c in range(nc)]
            else:
                cw = None
            cw = cw or [x * Wt / sum(nat) for x in nat]
            # nessuna colonna più stretta della sua parola più lunga (fino a 90 pt): lo spazio si toglie alla più larga
            parola = [min(90, max((d.larg(w, "b" if i == 0 else "", size) for i, r in enumerate(rows[:200])
                                   for w in re.split(r"\s+", pulisci(str(r[c]))) if w), default=0) + 2 * pad + 1) for c in range(nc)]
            for c in range(nc):
                manca = parola[c] - cw[c]
                if manca > 0:
                    big = max(range(nc), key=lambda k: cw[k] - parola[k])
                    if big != c and cw[big] - manca >= parola[big]:
                        cw[c] += manca
                        cw[big] -= manca
        lead = size * 1.25

        def celle(r, head):
            return [d.wrap([(t, "b" if head else st) for t, st in (g.md_runs(c) if md else [(c, "")])], cw[i] - 2 * pad, size)
                    for i, c in enumerate(r)]

        def disegna(r, head):
            ls = celle(r, head)
            ls = [x[:60] for x in ls]                 # una cella lunghissima non deve occupare pagine intere
            hh = max(len(x) for x in ls) * lead + 2 * pad
            if d.y - hh < d.M + 18:
                d.new_page()
                if not head and intest:
                    disegna(rows[0], True)
            top, x = d.y, d.M
            if head or (prima_col and nc == 2):
                d.rect(d.M, top - hh, cw[0] if not head else Wt, hh, fill=(0.93, 0.94, 0.96))
            for i, ln in enumerate(ls):
                yy = top - pad
                for line in ln:
                    yy -= lead
                    for dx, t, st in line:
                        d.text(x + pad + dx, yy + 2, t, "b" if head else st, size)
                d.rect(x, top - hh, cw[i], hh, stroke=(0.7, 0.72, 0.76))
                x += cw[i]
            d.y = top - hh
        start = 0
        if intest:
            disegna(rows[0], True)
            start = 1
        for r in rows[start:]:
            if self.n_righe >= PDF_RIGHE_MAX:
                self.tagliato = True
                self.p([(tr("… righe successive solo nel report HTML."), "")], size=8)
                break
            self.n_righe += 1
            disegna(r, False)
        d.y -= 6

    def img(self, out, rel, x, y, w, h, link=None):
        """Anteprima nel riquadro (adattata, centrata); collegamento al file copiato."""
        if not rel or self.n_img >= PDF_IMG_MAX:
            if rel:
                self.tagliato = True
            return False
        try:
            data = (out / rel).read_bytes()
        except OSError:
            return False
        dim = rp.jpeg_dim(data)
        if not dim:
            return False
        iw, ih = dim[0], dim[1]
        s = min(w / iw, h / ih, 1.5)
        ww, hh = iw * s, ih * s
        xx, yy = x + (w - ww) / 2, y + (h - hh) / 2
        if self.d.immagine(data, xx, yy, ww, hh):
            self.n_img += 1
            if link:
                self.d.link(xx, yy, ww, hh, link)
            return True
        return False

    def griglia(self, out, els):
        """Una riga per file: a sinistra nome e dati tecnici, a destra l'anteprima (un clic apre il file)."""
        d = self.d
        Wt = d.W - 2 * d.M
        tw, th = 150, 112                 # riquadro dell'anteprima
        lw = 112                          # colonna delle etichette
        nw = 34                           # colonna del numero dell'evidenza
        for e in els:
            vw = Wt - tw - lw - 26 - (nw if e.get("num") else 0)
            titolo = d.wrap([(e["titolo"], "b")], Wt - tw - 30 - (nw if e.get("num") else 0), 9.5)
            righe = []
            for k, v in e["righe"]:
                lab = d.wrap([(k, "b")], lw - 4, 7.5)
                val = d.wrap([(str(v), "c" if k == "SHA-256" else "")], vw, 7 if k == "SHA-256" else 7.5)
                righe.append((lab, val))
            nota = []
            if e.get("nota"):
                nota = d.wrap([(tr("Nota: ") + e["nota"], "")], Wt - tw - 30 - (nw if e.get("num") else 0), 7.5)
                nota = nota[:6] + ([[(0, tr("… (nota completa nel report HTML)"), "")]] if len(nota) > 6 else [])
            alt_testo = 8 + len(titolo) * 12.5 + sum(max(len(l), len(v)) * 9.6 for l, v in righe) + len(nota) * 9.6 + 4
            hh = max(th + 12, alt_testo)
            if d.y - hh - 6 < d.M + 18:
                d.new_page()
            top = d.y
            d.rect(d.M, top - hh, Wt, hh, fill=(0.99, 0.97, 0.93) if e["del"] else (1, 1, 1),
                   stroke=(0.85, 0.47, 0.02) if e["del"] else (0.82, 0.84, 0.88), r=5)
            xt = d.W - d.M - tw - 6
            d.rect(xt, top - th - 6, tw, th, fill=(0.93, 0.94, 0.96), r=4)
            if not self.img(out, e.get("thumb"), xt, top - th - 6, tw, th, e.get("grande") or e.get("file")):
                lab = (tr("anteprima nel report HTML") if e.get("thumb") else
                       {FOTO: tr("foto"), VIDEO: tr("video"), AUDIO: tr("audio"), DOC: tr("documento")}.get(e["tipo"], tr("file")))
                d.text(xt + tw / 2 - d.larg(lab, "", 8.5) / 2, top - th / 2 - 8, lab, "", 8.5, (0.5, 0.5, 0.5))
                if e.get("file"):
                    d.link(xt, top - th - 6, tw, th, e["file"])
            x0, yy = d.M + 8 + (nw if e.get("num") else 0), top - 4
            if e.get("num"):
                d.rect(d.M + 5, top - 30, nw - 4, 25, fill=(0.91, 0.93, 0.96), r=3)
                a, b = str(e["num"][0]), tr("di {b}").format(b=e["num"][1])
                d.text(d.M + 5 + (nw - 4) / 2 - d.larg(a, "b", 9.5) / 2, top - 16, a, "b", 9.5, (0.12, 0.23, 0.37))
                d.text(d.M + 5 + (nw - 4) / 2 - d.larg(b, "", 6.5) / 2, top - 25, b, "", 6.5, (0.36, 0.39, 0.46))
            for line in titolo:
                yy -= 12.5
                for dx, t, st in line:
                    d.text(x0 + dx, yy, t, st, 9.5, (0.1, 0.12, 0.18))
            yy -= 2
            for lab, val in righe:
                for i in range(max(len(lab), len(val))):
                    yy -= 9.6
                    for dx, t, st in (lab[i] if i < len(lab) else []):
                        d.text(x0 + dx, yy, t, st, 7.5, (0.36, 0.39, 0.46))
                    for dx, t, st in (val[i] if i < len(val) else []):
                        d.text(x0 + lw + dx, yy, t, st, 7 if st == "c" else 7.5, (0.1, 0.12, 0.18))
            for line in nota:
                yy -= 9.6
                for dx, t, st in line:
                    d.text(x0 + dx, yy, t, st, 7.5, (0.45, 0.35, 0.0))
            d.y = top - hh - 6

    def chat(self, out, e):
        d = self.d
        self.h("💬 " + e["titolo"], 3)
        self.kv(e["righe"])
        if e.get("nota"):
            self.p([(tr("Nota: "), "b"), (e["nota"], "")], size=8.5)
        Wt = d.W - 2 * d.M
        bw = Wt * 0.72
        for m in e["msgs"]:
            if "day" in m:
                d.need(22)
                lab = m["day"]
                w = d.larg(lab, "", 8) + 16
                d.rect(d.W / 2 - w / 2, d.y - 15, w, 13, fill=(0.9, 0.91, 0.93), r=6)
                d.text(d.W / 2 - w / 2 + 8, d.y - 11.5, lab, "", 8, (0.36, 0.39, 0.46))
                d.y -= 20
                continue
            sys_ = m["dir"] == "sys"
            inner = (Wt * 0.8 if sys_ else bw) - 14
            blocchi = []
            if m["who"]:
                blocchi.append(("w", d.wrap([(m["who"], "b")], inner, 8)))
            blocchi.append(("t", d.wrap([(m["txt"], "")], inner, 9)))
            atts = []
            for a in m["att"]:
                ah = 0
                timg = None
                if a.get("thumb") and self.n_img < PDF_IMG_MAX:
                    try:
                        dim = rp.jpeg_dim((out / a["thumb"]).read_bytes())
                        if dim:
                            s = min(170 / dim[0], 150 / dim[1], 1.2)
                            timg = (dim[0] * s, dim[1] * s)
                            ah += timg[1] + 4
                    except OSError:
                        pass
                rr = d.wrap([("📎 " if a["tipo"] in (ALTRO, DOC) else "", ""), (a["nome"], "b")], inner - 8, 8)
                rr += [ln for r in a["righe"] for ln in d.wrap([(r, "c" if r.startswith("SHA-256") else "")], inner - 8, 6.8 if r.startswith("SHA-256") else 7.5)]
                ah += len(rr) * 9 + 8
                atts.append((a, timg, rr, ah))
            meta = d.wrap([(m["meta"], "")], inner, 7)
            hh = 8 + sum(len(x[1]) * (8 * 1.3 if x[0] == "w" else 9 * 1.3) for x in blocchi) + sum(x[3] + 4 for x in atts) + len(meta) * 9 + 4
            if hh > d.H - 2 * d.M - 40:          # fumetto più alto di una pagina: testo come paragrafo
                d.need(30)
                self.p([(m["who"] + ": " if m["who"] else "", "b"), (m["txt"], "")], size=9)
                self.p([(m["meta"], "")], size=7, rgb=(0.36, 0.39, 0.46))
                continue
            d.need(hh + 6)
            top = d.y
            w = (Wt * 0.8 if sys_ else bw)
            x = d.M + (Wt - w if m["dir"] == "out" else (Wt - w) / 2 if sys_ else 0)
            fill = None if sys_ else (0.86, 0.91, 1) if m["dir"] == "out" else (1, 1, 1)
            if m["del"]:
                fill = (0.99, 0.95, 0.88)
            if not sys_:
                d.rect(x, top - hh, w, hh, fill=fill, stroke=None if m["dir"] == "out" and not m["del"] else (0.82, 0.84, 0.88), r=8)
            yy = top - 4
            for kind, ls in blocchi:
                sz = 8 if kind == "w" else 9
                for line in ls:
                    yy -= sz * 1.3
                    for dx, t, st in line:
                        d.text(x + 7 + dx, yy, t, st, sz, (0.14, 0.34, 0.78) if kind == "w" else (0.36, 0.39, 0.46) if m["corsivo"] or sys_ else (0.1, 0.12, 0.18))
            for a, timg, rr, ah in atts:
                yy -= 4
                d.rect(x + 6, yy - ah, w - 12, ah, fill=(0.97, 0.97, 0.98), stroke=(0.82, 0.84, 0.88), r=5)
                y2 = yy - 4
                if timg:
                    y2 -= timg[1]
                    self.img(out, a["thumb"], x + 10, y2, timg[0], timg[1], a.get("grande") or a.get("file"))
                    y2 -= 4
                for line in rr:
                    y2 -= 9
                    for dx, t, st in line:
                        d.text(x + 10 + dx, y2, t, st, 6.8 if st == "c" else 8 if st == "b" else 7.5, (0.1, 0.12, 0.18))
                if a.get("file"):
                    d.link(x + 6, yy - ah, w - 12, ah, a["file"])
                yy -= ah
            for line in meta:
                yy -= 9
                for dx, t, st in line:
                    d.text(x + w - 7 - d.larg(m["meta"], "", 7) + dx if len(meta) == 1 else x + 7 + dx, yy, t, st, 7, (0.36, 0.39, 0.46))
            d.y = top - hh - 5

    def mail(self, out, e):
        self.h("✉ " + e["titolo"], 3)
        self.kv(e["righe"])
        if e["testo"]:
            self.p([(e["testo"][:30000], "")], size=8.5, before=4)
        if e["allegati"]:
            self.griglia(out, [{"t": "file", "tipo": a["tipo"], "titolo": a["nome"], "thumb": a["thumb"], "file": a["file"], "del": False,
                                "righe": [(tr("Dimensione"), fsize(a["size"]))] + ([("SHA-256", a["sha"])] if a.get("sha") else []), "nota": ""}
                               for a in e["allegati"]])
        if e.get("nota"):
            self.p([(tr("Nota: "), "b"), (e["nota"], "")], size=8.5)


# ------------------------------------------------------------------ Word

class DocxReport:
    """Word: titoli, paragrafi, tabelle, immagini (anteprime) e collegamenti relativi ai file copiati."""

    def __init__(self, titolo, ia_testo):
        self.titolo, self.ia_testo = titolo, ia_testo
        self.body, self.media, self.rels = [], [], []
        self.n_img = 0
        self.n_righe = 0

    @staticmethod
    def x(s):
        s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(s))
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def runs(self, runs, size=None, color=None):
        out = []
        for t, st in runs:
            rpr = ("<w:b/>" if st == "b" else "") + ('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>' if st == "c" else "") + \
                  (f'<w:color w:val="{color}"/>' if color else "") + (f'<w:sz w:val="{size}"/><w:szCs w:val="{size}"/>' if size else "")
            parti = str(t).split("\n")
            for i, p in enumerate(parti):
                if i:
                    out.append("<w:r><w:br/></w:r>")
                out.append(f'<w:r>{f"<w:rPr>{rpr}</w:rPr>" if rpr else ""}<w:t xml:space="preserve">{self.x(p)}</w:t></w:r>')
        return "".join(out)

    def h(self, testo, lv):
        st = "Title" if lv == 1 else f"Heading{min(lv - 1, 3)}"
        self.body.append(f'<w:p><w:pPr><w:pStyle w:val="{st}"/></w:pPr>{self.runs([(testo, "")])}</w:p>')

    def p(self, runs, size=None, ind=0, jc=None, shade=None, color=None):
        ppr = (f'<w:ind w:left="{ind}"/>' if ind else "") + (f'<w:jc w:val="{jc}"/>' if jc else "") + \
              (f'<w:shd w:val="clear" w:color="auto" w:fill="{shade}"/>' if shade else "")
        self.body.append(f'<w:p>{f"<w:pPr>{ppr}</w:pPr>" if ppr else ""}{self.runs(runs, size, color)}</w:p>')

    def md(self, md):
        for b in g.md_blocks(md):
            if b[0] == "h":
                self.h(b[2], min(4, b[1] + 1))
            elif b[0] == "p":
                self.p(g.md_runs(b[1]))
            elif b[0] == "li":
                self.p([("• " if not b[1] else "– ", "")] + g.md_runs(b[2]), ind=360 + 360 * b[1])
            elif b[0] == "table":
                t = tabella_pulita(b[1], taglia=240)
                self.tabella(t[0], t[1:], md=True)

    def tabella(self, intest, righe, md=False):
        rows = ([intest] if intest else []) + righe
        if not rows:
            return
        nc = max(len(r) for r in rows)
        sz = 14 if nc > 5 else 17
        trs = []
        for i, r in enumerate(rows):
            if i and self.n_righe >= PDF_RIGHE_MAX:
                break
            self.n_righe += 1 if i else 0
            r = [str(c) for c in r] + [""] * (nc - len(r))
            head = i == 0 and intest is not None
            shd = '<w:shd w:val="clear" w:color="auto" w:fill="E7E9EE"/>' if head else ""
            tcs = "".join(f'<w:tc><w:tcPr>{shd}</w:tcPr><w:p><w:pPr><w:spacing w:after="0"/></w:pPr>'
                          f'{self.runs([(t, "b" if head else st) for t, st in (g.md_runs(c) if md else [(c, "")])], sz)}</w:p></w:tc>' for c in r)
            trs.append(f'<w:tr>{"<w:trPr><w:tblHeader/></w:trPr>" if head else ""}{tcs}</w:tr>')
        self.body.append('<w:tbl><w:tblPr><w:tblStyle w:val="Griglia"/><w:tblW w:w="5000" w:type="pct"/></w:tblPr>'
                         f'<w:tblGrid>{"".join("<w:gridCol/>" for _ in range(nc))}</w:tblGrid>{"".join(trs)}</w:tbl>'
                         '<w:p><w:pPr><w:spacing w:after="60"/></w:pPr></w:p>')

    def kv(self, righe):
        if righe:
            self.tabella(None, [[k, str(v)] for k, v in righe])

    def _link(self, rel):
        self.rels.append(f'<Relationship Id="rL{len(self.rels)}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
                         f'Target="{self.x(rel)}" TargetMode="External"/>')
        return f"rL{len(self.rels) - 1}"

    def img(self, out, rel, maxw=200, maxh=170, link=None):
        """Immagine in linea (punti), cliccabile se c'è il file copiato. Restituisce l'XML del run."""
        if not rel or self.n_img >= PDF_IMG_MAX:
            return ""
        try:
            data = (out / rel).read_bytes()
        except OSError:
            return ""
        dim = rp.jpeg_dim(data)
        if not dim:
            return ""
        s = min(maxw / dim[0], maxh / dim[1], 1.2)
        cx, cy = int(dim[0] * s * 12700), int(dim[1] * s * 12700)
        self.media.append(data)
        n = len(self.media)
        self.n_img += 1
        rid = f"rI{n}"
        self.rels.append(f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/i{n}.jpg"/>')
        hl = f'<a:hlinkClick xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" r:id="{self._link(link)}"/>' if link else ""
        return ('<w:r><w:drawing><wp:inline xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">'
                f'<wp:extent cx="{cx}" cy="{cy}"/><wp:docPr id="{n}" name="i{n}">{hl}</wp:docPr>'
                '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
                f'<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="{n}" name="i{n}.jpg"/><pic:cNvPicPr/></pic:nvPicPr>'
                f'<pic:blipFill><a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
                f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
                '</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r>')

    def hyper(self, testo, rel):
        return f'<w:hyperlink r:id="{self._link(rel)}">{self.runs([(testo, "")], color="2456C7")}</w:hyperlink>'

    def file_el(self, out, e):
        """Una riga per file: a sinistra nome e dati tecnici, a destra l'anteprima cliccabile."""
        im = self.img(out, e.get("thumb"), 150, 115, link=e.get("grande") or e.get("file"))
        cella_img = f'<w:p><w:pPr><w:jc w:val="center"/></w:pPr>{im or self.runs([(ICONA.get(e["tipo"], ""), "")], 40)}</w:p>'
        testo = [f'<w:p><w:pPr><w:spacing w:after="40"/></w:pPr>{self.runs([(e["titolo"], "b")], 19)}</w:p>'] + [
            f'<w:p><w:pPr><w:spacing w:after="0"/><w:ind w:left="1700" w:hanging="1700"/><w:tabs><w:tab w:val="left" w:pos="1700"/></w:tabs></w:pPr>'
            f'{self.runs([(k, "b")], 15, "5B6475")}<w:r><w:tab/></w:r>{self.runs([(str(v), "c" if k == "SHA-256" else "")], 14 if k == "SHA-256" else 15)}</w:p>'
            for k, v in e["righe"]]
        if e.get("file"):
            testo.append(f'<w:p><w:pPr><w:spacing w:before="40" w:after="0"/></w:pPr>{self.hyper(tr("Apri il file originale"), e["file"])}</w:p>')
        if e.get("nota"):
            testo.append(f'<w:p>{self.runs([(tr("Nota: "), "b"), (e["nota"][:1500], "")], 15)}</w:p>')
        fill = '<w:shd w:val="clear" w:color="auto" w:fill="FDF8EE"/>' if e.get("del") else ""
        n = e.get("num")
        cn = (f'<w:tc><w:tcPr><w:tcW w:w="600" w:type="dxa"/><w:shd w:val="clear" w:color="auto" w:fill="E9EDF4"/></w:tcPr>'
              f'<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:after="0"/></w:pPr>{self.runs([(str(n[0]), "b")], 20, "1F3A5F")}</w:p>'
              f'<w:p><w:pPr><w:jc w:val="center"/></w:pPr>{self.runs([(tr("di {b}").format(b=n[1]), "")], 14, "5B6475")}</w:p></w:tc>' if n else "")
        gc = '<w:gridCol w:w="600"/>' if n else ""
        self.body.append('<w:tbl><w:tblPr><w:tblStyle w:val="Griglia"/><w:tblW w:w="5000" w:type="pct"/><w:tblLayout w:type="fixed"/></w:tblPr>'
                         f'<w:tblGrid>{gc}<w:gridCol w:w="{6400 if n else 7000}"/><w:gridCol w:w="3100"/></w:tblGrid><w:tr><w:trPr><w:cantSplit/></w:trPr>'
                         f'{cn}<w:tc><w:tcPr><w:tcW w:w="{6400 if n else 7000}" w:type="dxa"/>{fill}</w:tcPr>{"".join(testo)}</w:tc>'
                         f'<w:tc><w:tcPr><w:tcW w:w="3100" w:type="dxa"/><w:vAlign w:val="center"/>{fill}</w:tcPr>{cella_img}</w:tc></w:tr></w:tbl>'
                         '<w:p><w:pPr><w:spacing w:after="40"/></w:pPr></w:p>')

    def chat(self, out, e):
        self.h("💬 " + e["titolo"], 3)
        self.kv(e["righe"])
        for m in e["msgs"]:
            if "day" in m:
                self.p([(m["day"], "b")], 16, jc="center", color="5B6475")
                continue
            parti = []
            if m["who"]:
                parti.append(self.runs([(m["who"], "b")], 16, "2456C7") + "<w:r><w:br/></w:r>")
            parti.append(self.runs([(m["txt"], "")], 19, "5B6475" if m["corsivo"] else None))
            for a in m["att"]:
                im = self.img(out, a.get("thumb"), 170, 150, a.get("grande") or a.get("file"))
                parti.append("<w:r><w:br/></w:r>" + (im + "<w:r><w:br/></w:r>" if im else "")
                             + (self.hyper("📎 " + a["nome"], a["file"]) if a.get("file") else self.runs([("📎 " + a["nome"], "b")], 16))
                             + "".join("<w:r><w:br/></w:r>" + self.runs([(r, "c" if r.startswith("SHA-256") else "")], 14) for r in a["righe"]))
            parti.append("<w:r><w:br/></w:r>" + self.runs([(m["meta"], "")], 14, "5B6475"))
            fill = "FDF3E1" if m["del"] else "DBE8FF" if m["dir"] == "out" else "FFFFFF" if m["dir"] == "in" else None
            ind = '<w:ind w:left="2600"/>' if m["dir"] == "out" else '<w:ind w:right="2600"/>' if m["dir"] == "in" else '<w:jc w:val="center"/>'
            bord = ('<w:pBdr>' + "".join(f'<w:{s} w:val="single" w:sz="4" w:space="4" w:color="D8DBE2"/>' for s in ("top", "left", "bottom", "right"))
                    + '</w:pBdr>') if m["dir"] != "sys" else ""
            shd = f'<w:shd w:val="clear" w:color="auto" w:fill="{fill}"/>' if fill else ""
            self.body.append(f'<w:p><w:pPr>{bord}{shd}<w:spacing w:after="120"/>{ind}</w:pPr>{"".join(parti)}</w:p>')

    def mail(self, out, e):
        self.h("✉ " + e["titolo"], 3)
        self.kv(e["righe"])
        if e["testo"]:
            self.p([(e["testo"][:30000], "")], 17, shade="FAFBFC")
        for a in e["allegati"]:
            self.file_el(out, {"tipo": a["tipo"], "titolo": a["nome"], "thumb": a["thumb"], "file": a["file"],
                               "righe": [(tr("Dimensione"), fsize(a["size"]))] + ([("SHA-256", a["sha"])] if a.get("sha") else [])})

    def render(self):
        import zipfile
        ns = ('xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
              'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"')
        x = self.x
        footer = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr {ns}><w:p><w:pPr><w:jc w:val="center"/></w:pPr>'
                  f'<w:r><w:rPr><w:sz w:val="15"/><w:color w:val="777777"/></w:rPr><w:t xml:space="preserve">{x(self.titolo)} · </w:t></w:r>'
                  '<w:r><w:rPr><w:sz w:val="15"/><w:color w:val="777777"/></w:rPr><w:fldChar w:fldCharType="begin"/></w:r>'
                  '<w:r><w:rPr><w:sz w:val="15"/><w:color w:val="777777"/></w:rPr><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r>'
                  '<w:r><w:rPr><w:sz w:val="15"/><w:color w:val="777777"/></w:rPr><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>')
        doc = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {ns}><w:body>{"".join(self.body)}'
               '<w:sectPr><w:footerReference w:type="default" r:id="rIdF"/><w:pgSz w:w="11906" w:h="16838"/>'
               '<w:pgMar w:top="1000" w:right="900" w:bottom="1000" w:left="900" w:header="500" w:footer="500" w:gutter="0"/></w:sectPr></w:body></w:document>')
        hd = lambda i, sz, sp: (f'<w:style w:type="paragraph" w:styleId="Heading{i}"><w:name w:val="heading {i}"/><w:basedOn w:val="Normal"/>'
                                f'<w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:spacing w:before="{sp}" w:after="80"/>'
                                f'<w:outlineLvl w:val="{i - 1}"/></w:pPr><w:rPr><w:b/><w:color w:val="1F3A5F"/><w:sz w:val="{sz}"/><w:szCs w:val="{sz}"/></w:rPr></w:style>')
        styles = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles {ns}>'
                  '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri" w:eastAsia="Calibri"/>'
                  '<w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr></w:rPrDefault>'
                  '<w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>'
                  '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>'
                  '<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:qFormat/>'
                  '<w:pPr><w:spacing w:after="160"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:color w:val="1F3A5F"/><w:sz w:val="36"/></w:rPr></w:style>'
                  + hd(1, 28, 280) + hd(2, 24, 200) + hd(3, 21, 160) +
                  '<w:style w:type="table" w:styleId="Griglia"><w:name w:val="Griglia"/><w:tblPr><w:tblBorders>'
                  + "".join(f'<w:{s} w:val="single" w:sz="4" w:space="0" w:color="A0A4AA"/>' for s in ("top", "left", "bottom", "right", "insideH", "insideV"))
                  + '</w:tblBorders><w:tblCellMar><w:left w:w="60" w:type="dxa"/><w:right w:w="60" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style></w:styles>')
        ctypes = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                  '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                  '<Default Extension="xml" ContentType="application/xml"/><Default Extension="jpg" ContentType="image/jpeg"/>'
                  '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                  '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
                  '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
                  '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>')
        rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
                '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
                '</Relationships>')
        drels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                 '<Relationship Id="rIdS" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
                 '<Relationship Id="rIdF" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>'
                 + "".join(self.rels) + '</Relationships>')
        core = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
                f'<dc:title>{x(self.titolo)}</dc:title><dc:creator>{x(fa.APP_NAME)}</dc:creator>'
                + (f'<dc:description>{x(self.ia_testo)}</dc:description><cp:keywords>AI-generated content; {x(fa.APP_NAME)}</cp:keywords>' if self.ia_testo else "")
                + '</cp:coreProperties>')
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in (("[Content_Types].xml", ctypes), ("_rels/.rels", rels), ("word/document.xml", doc), ("word/styles.xml", styles),
                               ("word/footer1.xml", footer), ("word/_rels/document.xml.rels", drels), ("docProps/core.xml", core)):
                z.writestr(name, data)
            for i, m in enumerate(self.media, 1):
                z.writestr(f"word/media/i{i}.jpg", m, compress_type=zipfile.ZIP_STORED)
        return buf.getvalue()


# ------------------------------------------------------------------ insieme

def crea(case, o, progress=lambda m: None):
    """Crea il report illustrato in export/report_<data>/: report.html (+ pagine/), report.pdf, report.docx a scelta,
    file/ (originali copiati), anteprime/, impronte.csv. -> riepilogo."""
    t0 = time.time()
    formati = [f for f in (o.get("formati") or ["html", "pdf"]) if f in ("html", "pdf", "docx")] or ["html"]
    DFMT[0] = o.get("dfmt") if o.get("dfmt") in ("gma", "iso", "mga", "esteso") else "iso"
    out = g.unique(case.export_dir / f"report_{g.stamp_now()}")
    out.mkdir(parents=True)
    L = Lavoro(case, o, out, progress)
    titolo = (o.get("titolo") or "").strip() or tr("Report di analisi forense – {name}").format(name=case.root.name)
    autore = (o.get("autore") or "").strip()
    ia = fa.report_ia(case)
    ia_testo = g.ia_meta_testo() if ia else None
    progress({"msg": tr("Report dell'analisi…"), "pct": 2})
    sez_t, md = sezioni_testo(case, o)
    sez_p = sezioni_preferiti(case, o, L)
    sez_x = sezioni_tutto(case, o, L)
    sotto = " · ".join(x for x in (tr("Caso {c}").format(c=(case.meta.get("info_caso") or {}).get("nome") or case.root.name),
                                   tr("redatto da {a}").format(a=autore) if autore else "",
                                   tr("generato il {d} con {app} {v}").format(d=L.ts(fa.now()), app=fa.APP_NAME, v=fa.APP_VERSION),
                                   tr("orari: {tz}").format(tz=g.tz_label(case, L.tz))) if x)
    testa = {"lingua": case.meta.get("lingua") or "it", "titolo": titolo, "sotto": sotto,
             "piede": tr("Report creato da {app} {v}. Le miniature si aprono con un clic sul file originale, copiato nella cartella «file» "
                         "con il suo SHA-256 (elenco completo in impronte.csv). Il contenuto delle prove è mostrato come testo e immagini: "
                         "nessun contenuto attivo dei file viene eseguito.").format(app=fa.APP_NAME, v=fa.APP_VERSION)}
    pdf = PdfReport(titolo, ia_testo, f"{fa.APP_NAME} {fa.APP_VERSION}") if "pdf" in formati else None
    doc = DocxReport(titolo, ia_testo) if "docx" in formati else None
    for w in (pdf, doc):
        if w:
            w.h(titolo, 1)
            w.p([(sotto, "")], **({"size": 8.5} if w is pdf else {}))
            if ia:
                w.p([("⚠ " + g.ia_meta_testo(), "b")], **({"size": 8.5} if w is pdf else {}))
    indice = []
    tutte = sez_t + sez_p + sez_x
    tot = sum(max(1, s.n) for s in tutte) or 1
    fatti = 0
    conteggi = {"elementi": 0, "file_copiati": 0, "anteprime": 0, "pagine": 0}
    pag_n = 0
    num = 0
    for s in tutte:
        if s.testo is not None:          # testo: nell'indice, nel PDF e nel Word
            indice.append(("t", s, _md_html(s.testo)))
            for w in (pdf, doc):
                if w:
                    w.h(s.titolo, 2)
                    w.md(s.testo)
            continue
        progress({"msg": tr("{s}: preparo {n} elementi…").format(s=s.titolo, n=s.n), "pct": 3 + 92 * fatti / tot})
        for w in (pdf, doc):
            if w:
                w.h(f"{s.titolo} ({s.n})", 2)
                if s.nota:
                    w.p([(s.nota, "")])
        pagine, buf, grid, n_el = [], [], [], 0
        n_sez = 0
        pag_n += 1
        stem = f"pagine/{pag_n:03d}_{re.sub(r'[^A-Za-z0-9]+', '_', s.k)[:30]}"

        def chiudi_griglia():
            if grid:
                buf.append('<div class="grid">' + "".join(el_html(x, "../") for x in grid) + "</div>")
                if pdf:
                    pdf.griglia(out, grid)
                if doc:
                    for x in grid:
                        doc.file_el(out, x)
                grid.clear()

        def scrivi_pagina(ultima=False):
            chiudi_griglia()
            if buf:
                pagine.append("".join(buf))
                buf.clear()
        peso = 0
        for e in (s.gen() if s.gen else []):
            # (3.0.1) numero dell'evidenza nella sezione: «1 di 5», «2 di 5»… (il totale è accanto al titolo della sezione)
            if e["t"] == "tabella":
                e = {**e, "intest": [tr("N.")] + list(e["intest"]),
                     "righe": [[tr("{a} di {b}").format(a=n_sez + i + 1, b=s.n)] + list(r) for i, r in enumerate(e["righe"])]}
                n_sez += len(e["righe"])
            else:
                n_sez += 1
                e["num"] = (n_sez, s.n)
                if e["t"] != "file":
                    e["titolo"] = tr("{a} di {b}").format(a=n_sez, b=s.n) + " – " + e["titolo"]
            n_el += len(e["righe"]) if e["t"] == "tabella" else 1
            fatti += 1
            conteggi["elementi"] += 1
            if n_el % 20 == 0:
                progress({"msg": tr("{s}: {a} di {n}").format(s=s.titolo, a=n_el, n=s.n), "pct": 3 + 92 * fatti / tot})
            if e["t"] == "file":
                grid.append(e)
                peso += 1
                if len(grid) >= 30:
                    chiudi_griglia()
            else:
                chiudi_griglia()
                if e["t"] != "tabella":          # le tabelle si scrivono sotto, divise in pagine
                    buf.append(el_html(e, "../"))
                if e["t"] == "chat":
                    peso += max(1, len(e["msgs"]) // 10)
                    if pdf:
                        pdf.chat(out, e)
                    if doc:
                        doc.chat(out, e)
                elif e["t"] == "mail":
                    peso += 3
                    if pdf:
                        pdf.mail(out, e)
                    if doc:
                        doc.mail(out, e)
                elif e["t"] == "scheda":
                    peso += 1
                    if pdf:
                        pdf.h(e["titolo"], 3)
                        pdf.kv(e["righe"])
                        if e.get("nota"):
                            pdf.p([(tr("Nota: "), "b"), (e["nota"], "")], size=8.5)
                    if doc:
                        doc.h(e["titolo"], 4)
                        doc.kv(e["righe"])
                        if e.get("nota"):
                            doc.p([(tr("Nota: "), "b"), (e["nota"], "")])
                elif e["t"] == "tabella":
                    for i in range(0, max(1, len(e["righe"])), PAGINA_RIGHE):
                        if i:
                            scrivi_pagina()
                        buf.append(el_html({**e, "righe": e["righe"][i:i + PAGINA_RIGHE]}))
                    if pdf:
                        pdf.tabella(e["intest"], e["righe"])
                    if doc:
                        doc.tabella(e["intest"], e["righe"])
            if peso >= PAGINA_FILE:
                scrivi_pagina()
                peso = 0
        scrivi_pagina(True)
        if not pagine:
            pagine = [f'<p class="hint">{E(tr("Nessun elemento."))}</p>']
        nomi = [f"{stem}{'' if i == 0 else '_' + str(i + 1)}.html" for i in range(len(pagine))]
        for i, corpo in enumerate(pagine):
            pg = ""
            if len(pagine) > 1:
                pg = '<div class="pg">' + "".join(f"<b>{j + 1}</b>" if j == i else f'<a href="{Path(nomi[j]).name}">{j + 1}</a>'
                                                  for j in range(len(pagine))) + "</div>"
            testo = (f'<section class="card"><h2>{E(s.titolo)} ({n_el})</h2>' + (f'<p class="hint">{E(s.nota)}</p>' if s.nota else "")
                     + f'{pg}</section>{corpo}{pg}')
            (out / nomi[i]).write_text(pagina(f"{s.titolo} – {titolo}", testo, testa, "../", s.titolo), encoding="utf-8")
        conteggi["pagine"] += len(pagine)
        indice.append(("s", s, nomi[0], n_el, len(pagine)))
    # indice HTML
    progress({"msg": tr("Scrivo il report…"), "pct": 96})
    toc = "".join(f'<li><a href="#{E(x[1].k)}">{E(x[1].titolo)}</a></li>' if x[0] == "t" else
                  f'<li><a href="{E(x[2])}">{E(x[1].titolo)} ({x[3]})</a>'
                  f'{(" <span class=hint>" + E(tr("{p} pagine").format(p=x[4])) + "</span>") if x[4] > 1 else ""}</li>' for x in indice)
    avviso_spazio = (tr("{n} file originali non sono stati copiati per lasciare libero spazio sul disco del caso: compaiono con miniatura "
                        "e SHA-256 registrato, senza il collegamento al file.").format(n=L.senza_spazio) if L.senza_spazio else "")
    corpo = [f'<section class="card"><h2>{E(tr("Indice"))}</h2><ul class="toc">{toc}</ul>'
             + (f'<p class="nota">⚠ {E(g.ia_meta_testo())}</p>' if ia else "")
             + (f'<p class="nota">⚠ {E(avviso_spazio)}</p>' if avviso_spazio else "") + "</section>"]
    for x in indice:
        if x[0] == "t":
            corpo.append(f'<section class="card" id="{E(x[1].k)}"><h2>{E(x[1].titolo)}</h2>{x[2]}</section>')
        else:
            corpo.append(f'<section class="card"><h2>{E(x[1].titolo)} ({x[3]})</h2>' + (f'<p class="hint">{E(x[1].nota)}</p>' if x[1].nota else "")
                         + f'<p><a href="{E(x[2])}">{E(tr("Apri la sezione ({n} elementi)").format(n=x[3]))}</a></p></section>')
    (out / "report.html").write_text(pagina(titolo, "".join(corpo), testa), encoding="utf-8")
    nota_pdf = tr("I file citati (foto, documenti, audio) sono copiati nella cartella «file» accanto a questo documento: un clic sulla "
                  "miniatura li apre se il documento resta in quella cartella. Elenco con SHA-256 in impronte.csv.")
    risultati = []
    if pdf:
        progress({"msg": tr("Scrivo il PDF…"), "pct": 97})
        pdf.h(tr("File del report"), 2)
        pdf.p([(nota_pdf, "")])
        if pdf.tagliato:
            pdf.p([(tr("Il PDF contiene le prime {n} anteprime e {r} righe di tabella: il resto è nel report HTML.").format(n=PDF_IMG_MAX, r=PDF_RIGHE_MAX), "b")])
        if avviso_spazio:
            pdf.p([(avviso_spazio, "b")])
        if not pdf.d.car.ok:
            pdf.p([(tr("Carattere Unicode del sistema non trovato: i caratteri non latini compaiono come «?». Usa il report HTML."), "b")])
        (out / "report.pdf").write_bytes(pdf.d.render())
    if doc:
        progress({"msg": tr("Scrivo il Word…"), "pct": 98})
        doc.h(tr("File del report"), 2)
        doc.p([(nota_pdf, "")])
        if avviso_spazio:
            doc.p([(avviso_spazio, "b")])
        (out / "report.docx").write_bytes(doc.render())
    # impronte
    righe = []
    for f in sorted(p for p in out.rglob("*") if p.is_file()):
        rel = f.relative_to(out).as_posix()
        sha = L.sha.get(rel) or fa.sha256_file(f)
        righe.append((rel, f.stat().st_size, sha))
    with open(out / "impronte.csv", "w", encoding="utf-8", newline="") as fo:
        w = csv.writer(fo, delimiter=";")
        w.writerow(["file", "byte", "sha256"])
        w.writerows(righe)
    imp = fa.sha256_file(out / "impronte.csv")
    conteggi["file_copiati"] = sum(1 for v in L.copie.values() if v[0])
    conteggi["non_copiati_spazio"] = L.senza_spazio
    conteggi["anteprime"] = L.n_th
    principali = {n: dict((r[0], r[2]) for r in righe).get(n) for n in ("report.html", "report.pdf", "report.docx") if (out / n).exists()}
    res = {"rel": str(out.relative_to(case.root)), "path": str(out), "file": principali, "impronte_sha256": imp,
           "conteggi": conteggi, "byte": sum(r[1] for r in righe), "secondi": round(time.time() - t0, 1),
           "sezioni": [s.titolo for s in tutte], "pdf_ridotto": bool(pdf and pdf.tagliato)}
    case.log("report_illustrato", {k: v for k, v in res.items() if k != "path"} | {"opzioni": {k: v for k, v in o.items() if k != "preferiti"},
                                                                                    "preferiti": list((o.get("preferiti") or {}).keys())})
    progress({"msg": tr("Completato"), "pct": 100})
    return res
