#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""
forense_relazione_pdf.py - RepertIA by silvexe.
(3.0.1) PDF del report illustrato: testo Unicode (carattere TrueType del sistema incorporato, solo con i glifi usati),
immagini JPEG, collegamenti ai file copiati accanto al PDF. Niente librerie esterne.
Il carattere si cerca tra quelli del sistema (Arial su Mac e Windows, DejaVu/Liberation/Noto su Linux); se manca
si usa Helvetica, che copre solo l'alfabeto latino.
"""
import os, re, struct, sys, unicodedata, zlib
from pathlib import Path

if sys.platform == "darwin":
    _DIRS = ["/System/Library/Fonts/Supplemental", "/Library/Fonts", "/System/Library/Fonts"]
elif os.name == "nt":
    _DIRS = [os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts")]
else:
    _DIRS = ["/usr/share/fonts", "/usr/local/share/fonts", os.path.expanduser("~/.fonts")]
# (normale, grassetto, a spaziatura fissa, riserva per le scritture che il primo non ha)
CANDIDATI = {
    "r": ["Arial.ttf", "arial.ttf", "DejaVuSans.ttf", "LiberationSans-Regular.ttf", "NotoSans-Regular.ttf"],
    "b": ["Arial Bold.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf", "LiberationSans-Bold.ttf", "NotoSans-Bold.ttf"],
    "c": ["Courier New.ttf", "cour.ttf", "DejaVuSansMono.ttf", "LiberationMono-Regular.ttf"],
    "u": ["Arial Unicode.ttf", "ARIALUNI.TTF", "arialuni.ttf", "segoeui.ttf", "msyh.ttf", "NotoSansCJK-Regular.ttc",
          "DroidSansFallbackFull.ttf", "DejaVuSans.ttf"],
}


def trova(nomi):
    for d in _DIRS:
        if not os.path.isdir(d):
            continue
        for n in nomi:
            p = os.path.join(d, n)
            if os.path.isfile(p):
                return p
        for root, _dirs, files in os.walk(d):        # Linux: i caratteri stanno in sottocartelle
            low = {f.lower(): f for f in files}
            for n in nomi:
                if n.lower() in low and n.lower().endswith(".ttf"):
                    return os.path.join(root, low[n.lower()])
    return None


class Ttf:
    """Lettura minima di un TrueType (glifi quadratici): mappa caratteri → glifi, larghezze, sottoinsieme."""

    def __init__(self, path):
        self.path = path
        self.data = Path(path).read_bytes()
        n = struct.unpack(">H", self.data[4:6])[0]
        self.tab = {}
        for i in range(n):
            tag, _cs, off, ln = struct.unpack(">4sIII", self.data[12 + 16 * i: 28 + 16 * i])
            self.tab[tag.decode("latin-1")] = (off, ln)
        if "glyf" not in self.tab or "loca" not in self.tab:
            raise ValueError("non TrueType")
        h = self.t("head")
        self.upm = struct.unpack(">H", h[18:20])[0]
        self.bbox = struct.unpack(">hhhh", h[36:44])
        self.loca_long = struct.unpack(">h", h[50:52])[0] == 1
        hh = self.t("hhea")
        self.asc, self.desc = struct.unpack(">hh", hh[4:8])
        self.nhm = struct.unpack(">H", hh[34:36])[0]
        self.ng = struct.unpack(">H", self.t("maxp")[4:6])[0]
        hm = self.t("hmtx")
        self.adv = [struct.unpack(">H", hm[4 * i: 4 * i + 2])[0] for i in range(self.nhm)]
        self.cmap = self._cmap()
        lo = self.t("loca")
        if self.loca_long:
            self.loca = list(struct.unpack(f">{self.ng + 1}I", lo[:4 * (self.ng + 1)]))
        else:
            self.loca = [x * 2 for x in struct.unpack(f">{self.ng + 1}H", lo[:2 * (self.ng + 1)])]
        self.usati = {0}

    def t(self, tag):
        off, ln = self.tab[tag]
        return self.data[off: off + ln]

    def _cmap(self):
        c = self.t("cmap")
        n = struct.unpack(">H", c[2:4])[0]
        best = None
        for i in range(n):
            pid, eid, off = struct.unpack(">HHI", c[4 + 8 * i: 12 + 8 * i])
            fmt = struct.unpack(">H", c[off: off + 2])[0]
            if pid == 3 and eid == 10 and fmt == 12 or pid == 0 and fmt == 12:
                best = (12, off)
                break
            if (pid == 3 and eid == 1 or pid == 0) and fmt == 4 and not best:
                best = (4, off)
        m = {}
        if not best:
            return m
        fmt, off = best
        if fmt == 4:
            segx2 = struct.unpack(">H", c[off + 6: off + 8])[0]
            seg = segx2 // 2
            ends = struct.unpack(f">{seg}H", c[off + 14: off + 14 + segx2])
            starts = struct.unpack(f">{seg}H", c[off + 16 + segx2: off + 16 + 2 * segx2])
            deltas = struct.unpack(f">{seg}h", c[off + 16 + 2 * segx2: off + 16 + 3 * segx2])
            ro_off = off + 16 + 3 * segx2
            ros = struct.unpack(f">{seg}H", c[ro_off: ro_off + segx2])
            for s in range(seg):
                for ch in range(starts[s], ends[s] + 1):
                    if ch == 0xFFFF:
                        continue
                    if ros[s] == 0:
                        g = (ch + deltas[s]) & 0xFFFF
                    else:
                        p = ro_off + 2 * s + ros[s] + 2 * (ch - starts[s])
                        g = struct.unpack(">H", c[p: p + 2])[0]
                        if g:
                            g = (g + deltas[s]) & 0xFFFF
                    if g:
                        m[ch] = g
        else:
            ng = struct.unpack(">I", c[off + 12: off + 16])[0]
            for i in range(ng):
                a, b, g = struct.unpack(">III", c[off + 16 + 12 * i: off + 28 + 12 * i])
                for ch in range(a, b + 1):
                    m[ch] = g + ch - a
        return m

    def gid(self, ch):
        return self.cmap.get(ord(ch), 0)

    def w(self, g):
        return self.adv[g] if g < self.nhm else self.adv[-1]

    def sottoinsieme(self):
        """Il carattere con i soli glifi usati (gli altri vuoti): stessi numeri di glifo, file molto più piccolo."""
        gl = self.t("glyf")
        keep, todo = set(), list(self.usati)
        while todo:                                   # i glifi composti si portano dietro i loro pezzi
            g = todo.pop()
            if g in keep or g >= self.ng:
                continue
            keep.add(g)
            a, b = self.loca[g], self.loca[g + 1]
            if b - a >= 10 and struct.unpack(">h", gl[a: a + 2])[0] < 0:
                p = a + 10
                while True:
                    flags, comp = struct.unpack(">HH", gl[p: p + 4])
                    todo.append(comp)
                    p += 4 + (4 if flags & 1 else 2)
                    p += 8 if flags & 0x80 else 4 if flags & 0x40 else 2 if flags & 8 else 0
                    if not flags & 0x20:
                        break
        nuovo, loca = bytearray(), [0]
        for g in range(self.ng):
            if g in keep:
                nuovo += gl[self.loca[g]: self.loca[g + 1]]
                if len(nuovo) % 4:
                    nuovo += b"\0" * (4 - len(nuovo) % 4)
            loca.append(len(nuovo))
        tabs = {k: self.t(k) for k in ("head", "hhea", "hmtx", "maxp", "cvt ", "fpgm", "prep") if k in self.tab}
        head = bytearray(tabs["head"])
        head[50:52] = struct.pack(">h", 1)
        head[8:12] = b"\0\0\0\0"
        tabs["head"] = bytes(head)
        tabs["loca"] = struct.pack(f">{len(loca)}I", *loca)
        tabs["glyf"] = bytes(nuovo)
        tags = sorted(tabs)
        out = bytearray(struct.pack(">IHHHH", 0x00010000, len(tags), 0, 0, 0))
        off = 12 + 16 * len(tags)
        corpo = bytearray()
        for tg in tags:
            d = tabs[tg]
            cs = sum(struct.unpack(f">{(len(d) + 3) // 4}I", d + b"\0" * (-len(d) % 4))) & 0xFFFFFFFF
            out += struct.pack(">4sIII", tg.encode("latin-1"), cs, off + len(corpo), len(d))
            corpo += d + b"\0" * (-len(d) % 4)
        return bytes(out + corpo)


class Caratteri:
    """I caratteri del documento: per ogni carattere il primo che lo contiene (normale/grassetto/fisso, poi riserva)."""

    def __init__(self):
        self.f = {}
        for k, nomi in CANDIDATI.items():
            p = trova(nomi)
            if p and p.lower().endswith(".ttf"):
                try:
                    self.f[k] = Ttf(p)
                except (ValueError, struct.error, OSError, KeyError):
                    pass
        if "r" in self.f:
            self.f.setdefault("b", self.f["r"])
            self.f.setdefault("c", self.f["r"])
        self.ok = "r" in self.f

    def pezzi(self, testo, stile):
        """[(chiave carattere, testo)] con la riserva per i caratteri che il carattere dello stile non ha."""
        base = {"b": "b", "c": "c"}.get(stile, "r")
        out = []
        for ch in testo:
            k = base
            if ord(ch) > 0x2000 and not self.f[base].gid(ch) and not ("u" in self.f and self.f["u"].gid(ch)) \
                    and unicodedata.category(ch) in ("So", "Sk", "Mn", "Cf"):
                continue                      # emoji e simboli che nessun carattere ha: niente quadratini
            if ch not in "\n\t" and not self.f[base].gid(ch) and "u" in self.f and self.f["u"].gid(ch):
                k = "u"
            if out and out[-1][0] == k:
                out[-1][1] += ch
            else:
                out.append([k, ch])
        return out

    def larg(self, testo, stile, size):
        w = 0
        for k, s in self.pezzi(testo, stile):
            f = self.f[k]
            w += sum(f.w(f.gid(ch)) for ch in s) * 1000 / f.upm
        return w * size / 1000


class Pdf:
    """Pagine A4 con testo a capo, riquadri, immagini JPEG e collegamenti. Coordinate in punti, origine in basso."""
    W, H, M = 595.28, 841.89, 42

    def __init__(self, titolo, ia_testo=None, produttore=""):
        self.titolo, self.ia_testo, self.produttore = titolo, ia_testo, produttore
        self.car = Caratteri()
        self.pages, self.ops, self.links, self.y = [], None, None, 0
        self.imgs, self.img_key = [], {}
        self.usati_k = {"r"}
        self.new_page()

    # ------------------------------------------------------------ testo
    def new_page(self):
        self.ops, self.links = [], []
        self.pages.append((self.ops, self.links))
        self.y = self.H - self.M

    def need(self, h):
        if self.y - h < self.M + 18:
            self.new_page()
            return True
        return False

    def larg(self, t, stile="", size=10):
        if self.car.ok:
            return self.car.larg(t, stile, size)
        return len(t) * size * (0.6 if stile == "c" else 0.5)

    def _hex(self, k, s):
        f = self.car.f[k]
        gids = [f.gid(ch) for ch in s]
        f.usati.update(gids)
        return "<" + "".join(f"{g:04X}" for g in gids) + ">"

    def text(self, x, y, s, stile="", size=10, rgb=(0, 0, 0)):
        if not s:
            return
        col = "%.3f %.3f %.3f rg" % rgb
        if not self.car.ok:
            esc = s.encode("cp1252", "replace").decode("cp1252").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            f = {"b": "H2", "c": "H3"}.get(stile, "H1")
            self.ops.append(f"BT {col} /{f} {size:.1f} Tf {x:.2f} {y:.2f} Td ({esc}) Tj ET")
            return
        dx = 0
        for k, p in self.car.pezzi(s, stile):
            self.usati_k.add(k)
            self.ops.append(f"BT {col} /F{k} {size:.1f} Tf {x + dx:.2f} {y:.2f} Td {self._hex(k, p)} Tj ET")
            dx += self.car.larg(p, stile if k != "u" else "", size)

    def wrap(self, runs, width, size):
        """Righe di [(x, testo, stile)] dentro `width`; rispetta gli a capo e spezza le parole troppo lunghe."""
        lines, cur, x = [], [], 0.0
        for t, st in runs:
            for pezzo in re.findall(r"\n|[^\S\n]+|[^\s]+", str(t)):
                if pezzo == "\n":
                    lines.append(cur)
                    cur, x = [], 0.0
                    continue
                w = self.larg(pezzo, st, size)
                if x + w > width and cur and pezzo.strip():
                    lines.append(cur)
                    cur, x = [], 0.0
                if not pezzo.strip() and not cur:
                    continue
                while self.larg(pezzo, st, size) > width - x and len(pezzo) > 1:
                    k = len(pezzo)
                    while k > 1 and self.larg(pezzo[:k], st, size) > width - x:
                        k -= 1
                    cur.append((x, pezzo[:k], st))
                    lines.append(cur)
                    cur, x, pezzo = [], 0.0, pezzo[k:]
                cur.append((x, pezzo, st))
                x += self.larg(pezzo, st, size)
        if cur or not lines:
            lines.append(cur)
        return lines

    def para(self, runs, size=9.5, x0=None, width=None, before=0, after=4, rgb=(0, 0, 0), bullet=None):
        x0 = self.M if x0 is None else x0
        width = (self.W - self.M - x0) if width is None else width
        lead = size * 1.3
        self.y -= before
        for n, ln in enumerate(self.wrap(runs, width, size)):
            self.need(lead)
            self.y -= lead
            if bullet and n == 0:
                self.text(x0 - 9, self.y, bullet, "", size, rgb)
            for x, t, st in ln:
                self.text(x0 + x, self.y, t, st, size, rgb)
        self.y -= after

    def rule(self, gray=0.7):
        self.ops.append(f"{gray:.2f} G 0.5 w {self.M:.2f} {self.y:.2f} m {self.W - self.M:.2f} {self.y:.2f} l S")
        self.y -= 4

    def rect(self, x, y, w, h, fill=None, stroke=None, r=0):
        """Riquadro (y = lato in basso), angoli arrotondati con `r`."""
        if r:
            k = 0.5523 * r
            p = (f"{x + r:.2f} {y:.2f} m {x + w - r:.2f} {y:.2f} l {x + w - r + k:.2f} {y:.2f} {x + w:.2f} {y + r - k:.2f} {x + w:.2f} {y + r:.2f} c "
                 f"{x + w:.2f} {y + h - r:.2f} l {x + w:.2f} {y + h - r + k:.2f} {x + w - r + k:.2f} {y + h:.2f} {x + w - r:.2f} {y + h:.2f} c "
                 f"{x + r:.2f} {y + h:.2f} l {x + r - k:.2f} {y + h:.2f} {x:.2f} {y + h - r + k:.2f} {x:.2f} {y + h - r:.2f} c "
                 f"{x:.2f} {y + r:.2f} l {x:.2f} {y + r - k:.2f} {x + r - k:.2f} {y:.2f} {x + r:.2f} {y:.2f} c h")
        else:
            p = f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re"
        cmd = ("%.3f %.3f %.3f rg " % fill if fill else "") + ("%.3f %.3f %.3f RG 0.5 w " % stroke if stroke else "")
        self.ops.append(f"{cmd}{p} {'B' if fill and stroke else 'f' if fill else 'S'} 0 g 0 G")

    # ------------------------------------------------------------ immagini e collegamenti
    def immagine(self, jpeg, x, y, w, h):
        """JPEG disegnato nel riquadro (x, y in basso a sinistra); la stessa immagine si incorpora una volta."""
        k = (len(jpeg), zlib.crc32(jpeg))
        if k not in self.img_key:
            dim = jpeg_dim(jpeg)
            if not dim:
                return False
            self.imgs.append((jpeg, dim))
            self.img_key[k] = len(self.imgs)
        self.ops.append(f"q {w:.2f} 0 0 {h:.2f} {x:.2f} {y:.2f} cm /Im{self.img_key[k]} Do Q")
        return True

    def link(self, x, y, w, h, uri):
        """Zona cliccabile che apre `uri` (anche un percorso relativo a un file accanto al PDF)."""
        self.links.append((x, y, w, h, uri))

    # ------------------------------------------------------------ scrittura
    def render(self):
        objs = []

        def add(b):
            objs.append(b if isinstance(b, bytes) else b.encode("latin-1", "replace"))
            return len(objs)

        def ps(s):        # stringa PDF (UTF-16BE per i caratteri non latini)
            try:
                s.encode("latin-1")
                return "(" + s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ")"
            except UnicodeEncodeError:
                return "<FEFF" + s.encode("utf-16-be").hex().upper() + ">"
        cat = add("")
        pages_id = add("")
        n = len(self.pages)
        piedi = []
        for i in range(1, n + 1):            # piè di pagina prima dei caratteri: anche i suoi glifi vanno incorporati
            self.ops = []
            self.text(self.M, 22, self.titolo[:120], "", 7.5, (0.45, 0.45, 0.45))
            lab = f"{i} / {n}"
            self.text(self.W - self.M - self.larg(lab, "", 7.5), 22, lab, "", 7.5, (0.45, 0.45, 0.45))
            piedi.append(self.ops)
        fonts = {}
        if self.car.ok:
            for k, f in self.car.f.items():
                if k not in self.usati_k:
                    continue
                if f in [x[1] for x in fonts.values()]:
                    fonts[k] = next(v for v in fonts.values() if v[1] is f)
                    continue
                fonts[k] = (self._font(add, f, k), f)
            fres = " ".join(f"/F{k} {v[0]} 0 R" for k, v in fonts.items())
        else:
            ids = [add(f"<< /Type /Font /Subtype /Type1 /BaseFont /{n} /Encoding /WinAnsiEncoding >>")
                   for n in ("Helvetica", "Helvetica-Bold", "Courier")]
            fres = " ".join(f"/H{i + 1} {x} 0 R" for i, x in enumerate(ids))
        ims = []
        for data, (w, h, comp) in self.imgs:
            cs = {1: "/DeviceGray", 4: "/DeviceCMYK"}.get(comp, "/DeviceRGB")
            dec = " /Decode [1 0 1 0 1 0 1 0]" if comp == 4 else ""
            ims.append(add(b"<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace %s /BitsPerComponent 8%s "
                           b"/Filter /DCTDecode /Length %d >>\nstream\n" % (w, h, cs.encode(), dec.encode(), len(data)) + data + b"\nendstream"))
        xres = " ".join(f"/Im{i + 1} {x} 0 R" for i, x in enumerate(ims))
        res = f"{add(f'<< /Font << {fres} >> /XObject << {xres} >> >>')} 0 R"     # una volta sola, condiviso da tutte le pagine
        kids = []
        for i, (ops, links) in enumerate(self.pages, 1):
            foot = piedi[i - 1]
            data = zlib.compress(("\n".join(ops + foot)).encode("latin-1", "replace"))
            cs = add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(data) + data + b"\nendstream")
            annots = [add(f"<< /Type /Annot /Subtype /Link /Rect [{x:.2f} {y:.2f} {x + w:.2f} {y + h:.2f}] /Border [0 0 0] "
                          f"/A << /S /URI /URI {ps(u)} >> >>") for x, y, w, h, u in links]
            kids.append(add(f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {self.W} {self.H}] /Resources {res} "
                            f"/Contents {cs} 0 R" + (f" /Annots [{' '.join(f'{a} 0 R' for a in annots)}]" if annots else "") + " >>"))
        if self.car.ok:                      # i caratteri per ultimi: ora si sa quali glifi servono
            for k, (fid, f) in fonts.items():
                if objs[fid - 1] == b"":
                    self._font_fill(objs, add, fid, f)
        objs[cat - 1] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode()
        objs[pages_id - 1] = f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] /Count {len(kids)} >>".encode()
        ia = f" /Subject {ps(self.ia_testo)} /Keywords (AI-generated content)" if self.ia_testo else ""
        info = add(f"<< /Title {ps(self.titolo)} /Producer {ps(self.produttore)}{ia} >>")
        buf = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
        offs = []
        for i, o in enumerate(objs, 1):
            offs.append(len(buf))
            buf += b"%d 0 obj\n" % i + o + b"\nendobj\n"
        x = len(buf)
        buf += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
        buf += b"".join(b"%010d 00000 n \n" % o for o in offs)
        buf += b"trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, cat, info, x)
        return bytes(buf)

    def _font(self, add, f, k):
        return add(b"")             # segnaposto: si riempie a fine documento, quando si sa quali glifi servono

    def _font_fill(self, objs, add, fid, f):
        sub = f.sottoinsieme()
        data = zlib.compress(sub)
        ff = add(b"<< /Length %d /Length1 %d /Filter /FlateDecode >>\nstream\n" % (len(data), len(sub)) + data + b"\nendstream")
        sc = 1000 / f.upm
        nome = "AAAAAA+" + re.sub(r"[^A-Za-z0-9-]", "", Path(f.path).stem)[:40]
        desc = add(f"<< /Type /FontDescriptor /FontName /{nome} /Flags 32 /FontBBox [{' '.join(str(int(v * sc)) for v in f.bbox)}] "
                   f"/ItalicAngle 0 /Ascent {int(f.asc * sc)} /Descent {int(f.desc * sc)} /CapHeight {int(f.asc * sc)} /StemV 80 "
                   f"/FontFile2 {ff} 0 R >>")
        gs = sorted(f.usati)
        wl = " ".join(f"{g} [{int(f.w(g) * sc)}]" for g in gs)
        cid = add(f"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /{nome} /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) "
                  f"/Supplement 0 >> /FontDescriptor {desc} 0 R /W [{wl}] /CIDToGIDMap /Identity >>")
        inv = {}
        for ch, g in f.cmap.items():
            if g in f.usati and g not in inv:
                inv[g] = ch
        righe = []
        for g in gs:
            if g in inv:
                u = chr(inv[g]).encode("utf-16-be").hex().upper()
                righe.append(f"<{g:04X}> <{u}>")
        cm = ("/CIDInit /ProcSet findresource begin 12 dict begin begincmap /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) "
              "/Supplement 0 >> def /CMapName /Adobe-Identity-UCS def /CMapType 2 def 1 begincodespacerange <0000> <FFFF> "
              "endcodespacerange\n")
        for i in range(0, len(righe), 100):
            blocco = righe[i:i + 100]
            cm += f"{len(blocco)} beginbfchar\n" + "\n".join(blocco) + "\nendbfchar\n"
        cm += "endcmap CMapName currentdict /CMap defineresource pop end end"
        cmd = zlib.compress(cm.encode("ascii"))
        tu = add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(cmd) + cmd + b"\nendstream")
        objs[fid - 1] = (f"<< /Type /Font /Subtype /Type0 /BaseFont /{nome} /Encoding /Identity-H "
                         f"/DescendantFonts [{cid} 0 R] /ToUnicode {tu} 0 R >>").encode()


def jpeg_dim(b):
    """(larghezza, altezza, componenti) di un JPEG, None se non lo è."""
    if b[:2] != b"\xff\xd8":
        return None
    i = 2
    while i + 9 < len(b):
        if b[i] != 0xFF:
            i += 1
            continue
        m = b[i + 1]
        if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        ln = struct.unpack(">H", b[i + 2: i + 4])[0]
        if m in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            h, w = struct.unpack(">HH", b[i + 5: i + 9])
            return w, h, b[i + 9]
        i += 2 + ln
    return None
