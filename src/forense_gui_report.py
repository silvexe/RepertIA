#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - interfaccia, report in PDF e Word.

(3.0.4) Codice spostato da forense_gui.py senza modifiche, per avere file più corti. Si carica tramite
forense_gui, che ne riesporta i nomi: gli altri moduli continuano a usare «G.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («G.<nome>»).
"""
import re
from forense_lingua import tr
import forense_agent as fa

import forense_gui as G
from forense_gui import (
    md_to_zone_ex, tz_label, tz_zone)

# ------------------------------------------------- report in PDF e Word
#
# Si parte dal report.md generato da forense_agent (stesso contenuto) e lo si scrive
# come PDF (A4, font standard) e come documento Word .docx, senza programmi esterni.

def md_blocks(text):
    """Il markdown del report in blocchi: ("h", livello, testo), ("p", testo),
    ("li", livello, testo), ("table", righe)."""
    out, para, tbl = [], [], None

    def flush():
        nonlocal para, tbl
        if para:
            out.append(("p", " ".join(para)))
            para = []
        if tbl:
            out.append(("table", tbl))
            tbl = None
    for raw in text.splitlines():
        line = raw.rstrip()
        s = line.strip()
        if s.startswith("|"):
            if para:
                out.append(("p", " ".join(para)))
                para = []
            if re.fullmatch(r"\|[\s|:\-]+\|?", s):
                continue
            cells = re.split(r"(?<!\\)\|", s.strip("|"))
            (tbl := tbl if tbl is not None else []).append([c.strip().replace("\\|", "|") for c in cells])
            continue
        if tbl:
            out.append(("table", tbl))
            tbl = None
        if not s:
            flush()
            continue
        m = re.match(r"(#{1,6})\s+(.*)", s)
        if m:
            flush()
            out.append(("h", len(m.group(1)), m.group(2)))
            continue
        m = re.match(r"(\s*)[-*]\s+(.*)", line)
        if m:
            flush()
            out.append(("li", len(m.group(1)) // 2, m.group(2)))
            continue
        para.append(s)
    flush()
    return out


def md_runs(text):
    """Testo con **grassetto** e `codice` -> [(testo, stile)] con stile "", "b" o "c"."""
    runs = []
    for part in re.split(r"(\*\*[^*]+\*\*|`[^`]+`)", text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**") and len(part) > 4:
            runs.append((part[2:-2], "b"))
        elif part.startswith("`") and part.endswith("`") and len(part) > 2:
            runs.append((part[1:-1], "c"))
        else:
            runs.append((part, ""))
    return runs


# larghezze (millesimi di em) di Helvetica e Helvetica-Bold, caratteri 32-126
_HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278] + [556] * 10 + \
    [278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833,
     722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556,
     556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556,
     500, 722, 500, 500, 500, 334, 260, 334, 584]
_HELVB = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278] + [556] * 10 + \
    [333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833,
     722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556,
     611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611,
     556, 778, 556, 556, 500, 389, 280, 389, 584]


def _pdf_char(ch):
    """Carattere rappresentabile in WinAnsi (cp1252), altrimenti un sostituto leggibile."""
    try:
        ch.encode("cp1252")
        return ch
    except UnicodeEncodeError:
        import unicodedata
        base = unicodedata.normalize("NFKD", ch).encode("ascii", "ignore").decode()
        return base or {"⭐": "*", "✓": "v", "→": "->", "←": "<-"}.get(ch, "?")


def _pdf_w(text, style, size):
    if style == "c":
        return len(text) * 600 * size / 1000
    tab = _HELVB if style == "b" else _HELV
    w = 0
    for ch in text:
        o = ord(ch)
        if 32 <= o <= 126:
            w += tab[o - 32]
        else:
            import unicodedata
            b = unicodedata.normalize("NFKD", ch)[:1]
            w += tab[ord(b) - 32] if b and 32 <= ord(b) <= 126 else 556
    return w * size / 1000


class PdfDoc:
    W, H, M = 595.28, 841.89, 50

    def __init__(self, title, ia=False):
        self.title, self.ia = title, ia
        self.pages, self.ops, self.y = [], None, 0
        self.new_page()

    def new_page(self):
        self.ops = []
        self.pages.append(self.ops)
        self.y = self.H - self.M

    def need(self, h):
        if self.y - h < self.M + 20:
            self.new_page()

    @staticmethod
    def _esc(s):
        s = "".join(_pdf_char(c) for c in s)
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def text(self, x, y, s, style, size, gray=0):
        f = {"b": "F2", "c": "F3"}.get(style, "F1")
        self.ops.append(f"BT {gray:.2f} g /{f} {size:.1f} Tf {x:.2f} {y:.2f} Td ({self._esc(s)}) Tj ET")

    def wrap(self, runs, width, size):
        """Righe di [(x, testo, stile)] che stanno in `width`, spezzando anche le parole lunghe."""
        lines, cur, x = [], [], 0.0
        toks = []
        for t, st in runs:
            for w in re.findall(r"\S+\s*|\s+", t.replace("\n", " ")):
                toks.append((w, st))
        for w, st in toks:
            ww = _pdf_w(w, st, size)
            if x + _pdf_w(w.rstrip(), st, size) > width and cur:
                lines.append(cur)
                cur, x = [], 0.0
                if not w.strip():
                    continue
            while _pdf_w(w.rstrip(), st, size) > width:      # parola più lunga della riga
                k = len(w)
                while k > 1 and _pdf_w(w[:k], st, size) > width - x:
                    k -= 1
                cur.append((x, w[:k], st))
                lines.append(cur)
                cur, x, w = [], 0.0, w[k:]
            ww = _pdf_w(w, st, size)
            cur.append((x, w, st))
            x += ww
        if cur:
            lines.append(cur)
        return lines or [[]]

    def para(self, runs, size=10, indent=0, bullet=None, before=0, after=4):
        width = self.W - 2 * self.M - indent
        lines = self.wrap(runs, width, size)
        lead = size * 1.32
        self.y -= before
        for n, ln in enumerate(lines):
            self.need(lead)
            self.y -= lead
            if bullet and n == 0:
                self.text(self.M + indent - 10, self.y, bullet, "", size)
            for x, t, st in ln:
                self.text(self.M + indent + x, self.y, t, st, size)
        self.y -= after

    def table(self, rows):
        if not rows:
            return
        nc = max(len(r) for r in rows)
        rows = [r + [""] * (nc - len(r)) for r in rows]
        W = self.W - 2 * self.M
        size = 7 if nc > 5 else 8.5
        pad = 3
        nat = [min(max(_pdf_w(re.sub(r"[*`]", "", r[c]), "b" if i == 0 else "", size) for i, r in enumerate(rows)) + 2 * pad, 260)
               for c in range(nc)]
        nat = [max(n, 28, min(_pdf_w(re.sub(r"[*`]", "", rows[0][c]), "b", size) + 2 * pad + 1, 80))
               for c, n in enumerate(nat)]
        tot = sum(nat)
        cw = [n * W / tot for n in nat]
        lead = size * 1.25

        def cells(r, head):
            return [self.wrap([(t, "b" if head else st) for t, st in md_runs(c)], cw[i] - 2 * pad, size)
                    for i, c in enumerate(r)]

        def draw(r, head):
            ls = cells(r, head)
            h = max(len(x) for x in ls) * lead + 2 * pad
            if self.y - h < self.M + 20:
                self.new_page()
                if not head:
                    draw(rows[0], True)
            top, x = self.y, self.M
            if head:
                self.ops.append(f"0.92 g {self.M:.2f} {top - h:.2f} {W:.2f} {h:.2f} re f 0 g")
            for i, ln in enumerate(ls):
                yy = top - pad
                for line in ln:
                    yy -= lead
                    for dx, t, st in line:
                        self.text(x + pad + dx, yy + 2, t, st, size)
                self.ops.append(f"0.6 G 0.4 w {x:.2f} {top - h:.2f} {cw[i]:.2f} {h:.2f} re S")
                x += cw[i]
            self.y = top - h
        draw(rows[0], True)
        for r in rows[1:]:
            draw(r, False)
        self.y -= 8

    def render(self):
        import zlib
        objs = []

        def add(b):
            objs.append(b if isinstance(b, bytes) else b.encode("cp1252", "replace"))
            return len(objs)
        cat = add("")      # segnaposto
        pages_id = add("")
        fonts = [add(f"<< /Type /Font /Subtype /Type1 /BaseFont /{n} /Encoding /WinAnsiEncoding >>")
                 for n in ("Helvetica", "Helvetica-Bold", "Courier")]
        res = f"<< /Font << /F1 {fonts[0]} 0 R /F2 {fonts[1]} 0 R /F3 {fonts[2]} 0 R >> >>"
        kids, n = [], len(self.pages)
        for i, ops in enumerate(self.pages, 1):
            foot = (f"BT 0.45 g /F1 7.5 Tf {self.M:.2f} 28 Td ({self._esc(self.title)}) Tj ET "
                    f"BT 0.45 g /F1 7.5 Tf {self.W - self.M - 60:.2f} 28 Td (Pagina {i} di {n}) Tj ET")
            data = zlib.compress(("\n".join(ops) + "\n" + foot).encode("cp1252", "replace"))
            cs = add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(data) + data + b"\nendstream")
            kids.append(add(f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {self.W} {self.H}] "
                            f"/Resources {res} /Contents {cs} 0 R >>"))
        objs[cat - 1] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode()
        objs[pages_id - 1] = (f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] "
                              f"/Count {len(kids)} >>").encode()
        # (2.20.1, AI Act art. 50) nei metadati: il documento contiene testo generato da IA
        ia = (f" /Subject ({self._esc(ia_meta_testo())}) /Keywords (AI-generated content; {fa.APP_NAME})"
              if self.ia else "")
        info = add(f"<< /Title ({self._esc(self.title)}) /Producer ({fa.APP_NAME} {fa.APP_VERSION}){ia} >>")
        buf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offs = []
        for i, o in enumerate(objs, 1):
            offs.append(len(buf))
            buf += b"%d 0 obj\n" % i + o + b"\nendobj\n"
        x = len(buf)
        buf += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
        buf += b"".join(b"%010d 00000 n \n" % o for o in offs)
        buf += b"trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
            len(objs) + 1, cat, info, x)
        return bytes(buf)


def ia_meta_testo():
    return tr("Contiene testo generato da un modello di IA (reperti dell'agente): da verificare")


def report_pdf(md_text, title, ia=False):
    d = PdfDoc(title, ia)
    sizes = {1: 18, 2: 14, 3: 12}
    for b in md_blocks(md_text):
        if b[0] == "h":
            sz = sizes.get(b[1], 11)
            d.need(sz * 3)
            d.para([(b[2], "b")], size=sz, before=sz * 0.6, after=sz * 0.35)
            if b[1] <= 2:
                d.ops.append(f"0.7 G 0.5 w {d.M:.2f} {d.y + 2:.2f} m {d.W - d.M:.2f} {d.y + 2:.2f} l S")
                d.y -= 4
        elif b[0] == "p":
            d.para(md_runs(b[1]))
        elif b[0] == "li":
            d.para(md_runs(b[2]), indent=14 + 14 * b[1], bullet="•" if not b[1] else "-", after=2)
        elif b[0] == "table":
            d.table(b[1])
    return d.render()


def _x(s):
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(s))
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _docx_runs(runs, size=None, bold=False):
    out = []
    for t, st in runs:
        rpr = ("<w:b/>" if bold or st == "b" else "") + \
              ('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>' if st == "c" else "") + \
              (f'<w:sz w:val="{size}"/><w:szCs w:val="{size}"/>' if size else "")
        out.append(f'<w:r>{f"<w:rPr>{rpr}</w:rPr>" if rpr else ""}<w:t xml:space="preserve">{_x(t)}</w:t></w:r>')
    return "".join(out)


def report_docx(md_text, title, ia=False):
    import zipfile, io
    body = []
    for b in md_blocks(md_text):
        if b[0] == "h":
            st = "Title" if b[1] == 1 else f"Heading{min(b[1] - 1, 3)}"
            body.append(f'<w:p><w:pPr><w:pStyle w:val="{st}"/></w:pPr>{_docx_runs([(b[2], "")])}</w:p>')
        elif b[0] == "p":
            body.append(f"<w:p>{_docx_runs(md_runs(b[1]))}</w:p>")
        elif b[0] == "li":
            ind = 360 + 360 * b[1]
            body.append(f'<w:p><w:pPr><w:spacing w:after="40"/><w:ind w:left="{ind}" w:hanging="240"/></w:pPr>'
                        f'{_docx_runs([("•" if not b[1] else "–", "")])}<w:r><w:tab/></w:r>{_docx_runs(md_runs(b[2]))}</w:p>')
        elif b[0] == "table":
            rows = b[1]
            nc = max(len(r) for r in rows)
            sz = 14 if nc > 5 else 17
            trs = []
            for i, r in enumerate(rows):
                r = r + [""] * (nc - len(r))
                shd = '<w:shd w:val="clear" w:color="auto" w:fill="E7E9EE"/>' if i == 0 else ""
                tcs = "".join(
                    f'<w:tc><w:tcPr>{shd}</w:tcPr>'
                    f'<w:p><w:pPr><w:spacing w:after="0"/></w:pPr>{_docx_runs(md_runs(c), sz, bold=(i == 0))}</w:p></w:tc>'
                    for c in r)
                trs.append(f'<w:tr>{"<w:trPr><w:tblHeader/></w:trPr>" if i == 0 else ""}{tcs}</w:tr>')
            body.append('<w:tbl><w:tblPr><w:tblStyle w:val="Griglia"/><w:tblW w:w="5000" w:type="pct"/>'
                        '<w:tblLayout w:type="autofit"/></w:tblPr>'
                        f'<w:tblGrid>{"".join("<w:gridCol/>" for _ in range(nc))}</w:tblGrid>{"".join(trs)}</w:tbl>'
                        '<w:p><w:pPr><w:spacing w:after="60"/></w:pPr></w:p>')
    ns = ('xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"')
    footer = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr {ns}><w:p><w:pPr><w:jc w:val="center"/></w:pPr>'
              f'<w:r><w:rPr><w:sz w:val="15"/><w:color w:val="777777"/></w:rPr><w:t xml:space="preserve">{_x(title)} · pagina </w:t></w:r>'
              '<w:r><w:rPr><w:sz w:val="15"/><w:color w:val="777777"/></w:rPr><w:fldChar w:fldCharType="begin"/></w:r>'
              '<w:r><w:rPr><w:sz w:val="15"/><w:color w:val="777777"/></w:rPr><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r>'
              '<w:r><w:rPr><w:sz w:val="15"/><w:color w:val="777777"/></w:rPr><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>')
    doc = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {ns}><w:body>{"".join(body)}'
           '<w:sectPr><w:footerReference w:type="default" r:id="rIdF"/><w:pgSz w:w="11906" w:h="16838"/>'
           '<w:pgMar w:top="1134" w:right="1021" w:bottom="1134" w:left="1021" w:header="567" w:footer="567" w:gutter="0"/>'
           '</w:sectPr></w:body></w:document>')
    hd = lambda i, sz, sp: (f'<w:style w:type="paragraph" w:styleId="Heading{i}"><w:name w:val="heading {i}"/>'
                            '<w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>'
                            f'<w:pPr><w:keepNext/><w:spacing w:before="{sp}" w:after="80"/><w:outlineLvl w:val="{i - 1}"/></w:pPr>'
                            f'<w:rPr><w:b/><w:color w:val="1F3A5F"/><w:sz w:val="{sz}"/><w:szCs w:val="{sz}"/></w:rPr></w:style>')
    styles = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles {ns}>'
              '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri" w:eastAsia="Calibri"/>'
              '<w:sz w:val="20"/><w:szCs w:val="20"/><w:lang w:val="it-IT"/></w:rPr></w:rPrDefault>'
              '<w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>'
              '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>'
              '<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:qFormat/>'
              '<w:pPr><w:spacing w:after="160"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:color w:val="1F3A5F"/><w:sz w:val="36"/><w:szCs w:val="36"/></w:rPr></w:style>'
              + hd(1, 28, 280) + hd(2, 24, 200) + hd(3, 21, 160) +
              '<w:style w:type="table" w:styleId="Griglia"><w:name w:val="Griglia"/><w:tblPr><w:tblBorders>'
              + "".join(f'<w:{s} w:val="single" w:sz="4" w:space="0" w:color="A0A4AA"/>' for s in ("top", "left", "bottom", "right", "insideH", "insideV"))
              + '</w:tblBorders><w:tblCellMar><w:left w:w="60" w:type="dxa"/><w:right w:w="60" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>'
              '</w:styles>')
    ctypes = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
              '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
              '<Default Extension="xml" ContentType="application/xml"/>'
              '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
              '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
              '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
              '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
              '</Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '</Relationships>')
    drels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
             '<Relationship Id="rIdS" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
             '<Relationship Id="rIdF" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>'
             '</Relationships>')
    core = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f'<dc:title>{_x(title)}</dc:title><dc:creator>{_x(fa.APP_NAME)}</dc:creator>'
            + (f'<dc:description>{_x(ia_meta_testo())}</dc:description>'
               f'<cp:keywords>AI-generated content; {_x(fa.APP_NAME)}</cp:keywords>' if ia else "")
            + '</cp:coreProperties>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in (("[Content_Types].xml", ctypes), ("_rels/.rels", rels),
                           ("word/document.xml", doc), ("word/styles.xml", styles),
                           ("word/footer1.xml", footer), ("word/_rels/document.xml.rels", drels),
                           ("docProps/core.xml", core)):
            z.writestr(name, data)
    return buf.getvalue()


def report_export(case, fmt, tz=None):
    """report.md aggiornato e la sua versione in PDF o Word nella cartella del caso
    (tz="rome": orari in ora italiana; report.md resta in UTC)."""
    import hashlib
    if fmt not in ("pdf", "docx"):
        raise ValueError(tr("Formato non previsto."))
    md = fa.write_report(case).read_text(encoding="utf-8")
    zone = tz_zone(case, tz)
    if zone != "UTC":
        md, n_conv, n_skip = md_to_zone_ex(md, zone)
        first, _, rest = md.partition("\n")
        sigle = (tr("ciascuno con la sigla CET (UTC+1) o CEST (UTC+2, ora legale)") if zone == "Europe/Rome"
                 else tr("ciascuno con lo scostamento da UTC (UTC+HH:MM)"))
        lab = tz_label(case, tz)
        md = (first + tr("\n\n- Orari: **{lab}**").format(lab=lab) + ("" if zone in lab else f" ({zone})") + tr(", {sigle}; nel database del caso e nel registro restano in UTC. Orari convertiti: "
                                                                                             "{n_conv}.").format(sigle=sigle, n_conv=n_conv)
              + (tr(" {n_skip} orari compaiono in nomi di file, percorsi o testo non riconoscibile e sono "
                    "rimasti invariati (UTC).").format(n_skip=n_skip) if n_skip else "")
              + tr(" Le date di FAT/exFAT sono ora locale del dispositivo, già riportata a UTC col fuso indicato "
                "nei dati del caso.") + rest)
    title = tr("Report di analisi forense – {name}").format(name=case.root.name)
    ia = fa.report_ia(case)
    data = report_pdf(md, title, ia) if fmt == "pdf" else report_docx(md, title, ia)
    p = case.root / f"report.{fmt}"
    if p.exists():
        p.chmod(0o644)
    p.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    case.log("report_" + fmt, {"file": str(p), "sha256": sha, "fuso": zone})
    return {"rel": p.name, "path": str(p), "sha256": sha, "size": len(data)}


import html as html_mod
