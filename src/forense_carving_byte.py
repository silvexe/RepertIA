"""(3.0.2) Carving dei file grafici NON allineati ai settori.

PhotoRec cerca l'inizio dei file solo all'inizio di ogni settore: un'immagine che comincia a metà settore (file dentro
altri file, flussi copiati byte per byte, spazio non allocato di supporti con settori «spostati») non viene trovata.
Sulle immagini NIST CFTT di carving grafico (set 2014 «Byte Shifted» e set 2023 «Non-Aligned») RepertIA ne recuperava 0;
X-Ways, FTK, DC3 Advanced Carver e Forensic Explorer quasi tutte.

Qui si cercano a livello di byte, nello stesso spazio letto da PhotoRec, le firme di JPEG, PNG, GIF, BMP, TIFF e
HEIC/HEIF che NON stanno all'inizio di un settore, e per ognuna si ricava la fine dalla struttura del formato (nessuna
dimensione «a occhio»): JPEG segmenti fino a EOI, PNG blocchi con CRC fino a IEND, GIF blocchi fino al terminatore, BMP
dimensione nell'intestazione con i campi controllati, TIFF fine dell'ultimo dato puntato dalle IFD, HEIC scatole ISO BMFF
con «meta» e «mdat». Un candidato che non si chiude secondo il formato si scarta: niente file a metà. Si scartano anche i
candidati dentro un file già recuperato da PhotoRec o da questa ricerca (immagini incorporate, miniature EXIF).
"""
import re
import struct
import zlib

SETTORE = 512
MAX_DIM = {"jpg": 64 << 20, "png": 128 << 20, "gif": 64 << 20, "bmp": 256 << 20, "tif": 256 << 20, "heic": 128 << 20}
MIN_DIM = 256                       # sotto questa dimensione non è un'immagine utile (e i falsi positivi aumentano)
FIRME = re.compile(rb"\xff\xd8\xff[\xc0-\xfe]|\x89PNG\r\n\x1a\n|GIF8[79]a|BM.{4}\x00\x00\x00\x00|II\x2a\x00|MM\x00\x2a"
                   rb"|ftyp(?:heic|heix|heim|heis|hevc|hevx|mif1|msf1)", re.S)


class Lettore:
    """Letture casuali da un file aperto, con una piccola cache a pagine (i riconoscitori leggono a pezzi)."""
    PAG = 1 << 20

    def __init__(self, fh, fine):
        self.fh, self.fine, self.pag = fh, fine, {}

    def __call__(self, pos, n):
        if pos < 0 or pos >= self.fine:
            return b""
        n = min(n, self.fine - pos)
        out = []
        while n > 0:
            k, d = divmod(pos, self.PAG)
            if k not in self.pag:
                if len(self.pag) > 64:
                    self.pag.clear()
                self.fh.seek(k * self.PAG)
                self.pag[k] = self.fh.read(self.PAG)
            b = self.pag[k][d:d + n]
            if not b:
                break
            out.append(b)
            pos, n = pos + len(b), n - len(b)
        return b"".join(out)


def _jpeg(rd, s):
    """Lunghezza di un JPEG: segmenti con lunghezza fino a SOS, poi dati compressi fino a un marcatore; dopo l'ultimo
    SOS il primo EOI chiude il file. Servono un SOF e un SOS."""
    p, sof, sos = s + 2, False, False
    lim = s + MAX_DIM["jpg"]
    while p < lim:
        h = rd(p, 4)
        if len(h) < 2 or h[0] != 0xFF:
            return None
        m = h[1]
        if m == 0xFF:                                   # riempimento
            p += 1
            continue
        if m == 0xD9:
            return p + 2 - s if sof and sos else None
        if 0xD0 <= m <= 0xD7 or m == 0x01:
            p += 2
            continue
        if len(h) < 4:
            return None
        ln = struct.unpack(">H", h[2:4])[0]
        if ln < 2:
            return None
        if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            sof = True
        if m != 0xDA:
            p += 2 + ln
            continue
        sos = True
        p += 2 + ln                                     # dati compressi: fino a FF seguito da un marcatore vero
        while p < lim:
            b = rd(p, 1 << 16)
            if not b:
                return None
            i = b.find(b"\xff")
            while i >= 0 and i + 1 < len(b) and (b[i + 1] == 0 or 0xD0 <= b[i + 1] <= 0xD7 or b[i + 1] == 0xFF):
                i = b.find(b"\xff", i + 1)
            if i < 0 or i + 1 >= len(b):
                p += max(len(b) - 1, 1)
                continue
            p += i
            break
    return None


def _png(rd, s):
    if rd(s, 8) != b"\x89PNG\r\n\x1a\n":
        return None
    p, primo = s + 8, True
    while p - s < MAX_DIM["png"]:
        h = rd(p, 8)
        if len(h) < 8:
            return None
        ln, tipo = struct.unpack(">I", h[:4])[0], h[4:8]
        if ln > MAX_DIM["png"] or not tipo.isalpha() or (primo and tipo != b"IHDR"):
            return None
        dati = rd(p + 8, ln + 4)
        if len(dati) < ln + 4 or zlib.crc32(tipo + dati[:ln]) & 0xFFFFFFFF != struct.unpack(">I", dati[ln:])[0]:
            return None
        p += 12 + ln
        primo = False
        if tipo == b"IEND":
            return p - s
    return None


def _gif(rd, s):
    h = rd(s, 13)
    if len(h) < 13 or h[:3] != b"GIF":
        return None
    p = s + 13
    if h[10] & 0x80:
        p += 3 << ((h[10] & 7) + 1)
    immagini = 0

    def sottoblocchi(p):
        while True:
            b = rd(p, 1)
            if not b:
                return None
            p += 1
            if b[0] == 0:
                return p
            p += b[0]
            if p - s > MAX_DIM["gif"]:
                return None
    while p - s < MAX_DIM["gif"]:
        b = rd(p, 1)
        if not b:
            return None
        if b[0] == 0x3B:
            return p + 1 - s if immagini else None
        if b[0] == 0x21:
            p = sottoblocchi(p + 2)
        elif b[0] == 0x2C:
            d = rd(p, 10)
            if len(d) < 10:
                return None
            p += 10
            if d[9] & 0x80:
                p += 3 << ((d[9] & 7) + 1)
            p = sottoblocchi(p + 1)                      # dopo il byte della dimensione minima del codice LZW
            immagini += 1
        else:
            return None
        if p is None:
            return None
    return None


def _bmp(rd, s):
    h = rd(s, 30)
    if len(h) < 30:
        return None
    dim, _r, dati, dib = struct.unpack("<IIII", h[2:18])
    larg, alt = struct.unpack("<ii", h[18:26])
    piani, bpp = struct.unpack("<HH", h[26:30])
    if dib not in (12, 40, 52, 56, 64, 108, 124) or piani != 1 or bpp not in (1, 4, 8, 16, 24, 32):
        return None
    if not (0 < larg <= 65535 and 0 < abs(alt) <= 65535) or not (14 + dib <= dati < dim <= MAX_DIM["bmp"]):
        return None
    riga = ((larg * bpp + 31) // 32) * 4
    if dim < dati + riga * abs(alt) // 2:             # dati troppo pochi per l'immagine dichiarata
        return None
    return dim if len(rd(s + dim - 1, 1)) == 1 else None


TIFF_TIPI = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4}


def _tiff(rd, s):
    """Fine di un TIFF: il massimo tra la fine delle IFD, dei loro valori fuori riga e dei dati (strisce o tessere)."""
    h = rd(s, 8)
    if len(h) < 8:
        return None
    e = "<" if h[:2] == b"II" else ">" if h[:2] == b"MM" else None
    if e is None:
        return None
    fine, coda, viste, dati = 8, [struct.unpack(e + "I", h[4:8])[0]], set(), False
    while coda and len(viste) < 64:
        ifd = coda.pop()
        if ifd < 8 or ifd in viste or ifd > MAX_DIM["tif"]:
            return None if not viste else fine
        viste.add(ifd)
        n = rd(s + ifd, 2)
        if len(n) < 2:
            return None
        n = struct.unpack(e + "H", n)[0]
        if not 1 <= n <= 500:
            return None
        voci = rd(s + ifd + 2, n * 12 + 4)
        if len(voci) < n * 12 + 4:
            return None
        fine = max(fine, ifd + 2 + n * 12 + 4)
        campi = {}
        for i in range(n):
            tag, tipo, cnt = struct.unpack(e + "HHI", voci[i * 12:i * 12 + 8])
            if tipo not in TIFF_TIPI or cnt > 1 << 24:
                return None
            lung = TIFF_TIPI[tipo] * cnt
            val = voci[i * 12 + 8:i * 12 + 12]
            if lung > 4:
                o = struct.unpack(e + "I", val)[0]
                fine = max(fine, o + lung)
                campi[tag] = (tipo, cnt, o, None)
            else:
                campi[tag] = (tipo, cnt, None, val)

        def valori(tag):
            tipo, cnt, o, val = campi[tag]
            sz = TIFF_TIPI[tipo]
            b = val if o is None else rd(s + o, sz * cnt)
            if len(b) < sz * cnt or tipo not in (3, 4, 13):
                return []
            return list(struct.unpack(e + ("H" if sz == 2 else "I") * cnt, b[:sz * cnt]))
        for off_t, cnt_t in ((273, 279), (324, 325), (513, 514)):
            if off_t in campi and cnt_t in campi:
                oo, cc = valori(off_t), valori(cnt_t)
                if not oo or len(oo) != len(cc):
                    return None
                fine = max(fine, max(o + c for o, c in zip(oo, cc)))
                # 513/514 (miniatura JPEG dell'EXIF) allungano il file ma non bastano: un blocco EXIF dentro un JPEG
                # comincia anch'esso con un'intestazione TIFF. Un'immagine TIFF ha strisce o tessere e le dimensioni.
                if off_t != 513 and 256 in campi and 257 in campi:
                    dati = True
        for sub in (330, 34665):                        # SubIFD, IFD EXIF
            if sub in campi:
                coda += valori(sub)[:16]
        prox = struct.unpack(e + "I", voci[n * 12:n * 12 + 4])[0]
        if prox:
            coda.append(prox)
    if not dati or fine > MAX_DIM["tif"] or len(rd(s + fine - 1, 1)) < 1:
        return None
    return fine


BMFF_SU = {b"ftyp", b"meta", b"moov", b"mdat", b"free", b"skip", b"uuid", b"idat", b"wide", b"pdin", b"moof", b"mfra"}


def _heic(rd, s):
    p, visti = s, set()
    while p - s < MAX_DIM["heic"]:
        h = rd(p, 16)
        if len(h) < 8:
            break
        ln, tipo = struct.unpack(">I", h[:4])[0], h[4:8]
        if tipo not in BMFF_SU:
            break
        if ln == 1:
            if len(h) < 16:
                return None
            ln = struct.unpack(">Q", h[8:16])[0]
        if ln < 8 or (ln == 0):
            return None
        if p == s and tipo != b"ftyp":
            return None
        visti.add(tipo)
        p += ln
    if {b"ftyp", b"meta", b"mdat"} <= visti and len(rd(p - 1, 1)) == 1:
        return p - s
    return None


def riconosci(rd, s, firma):
    """(estensione, lunghezza) del file che comincia a s, o None."""
    if firma.startswith(b"\xff\xd8"):
        ext, ln = "jpg", _jpeg(rd, s)
    elif firma.startswith(b"\x89PNG"):
        ext, ln = "png", _png(rd, s)
    elif firma.startswith(b"GIF"):
        ext, ln = "gif", _gif(rd, s)
    elif firma.startswith(b"BM"):
        ext, ln = "bmp", _bmp(rd, s)
    elif firma[:2] in (b"II", b"MM"):
        ext, ln = "tif", _tiff(rd, s)
    elif firma.startswith(b"ftyp"):
        s -= 4
        ext, ln = "heic", _heic(rd, s)
    else:
        return None
    if ln is None or ln < MIN_DIM or ln > MAX_DIM[ext]:
        return None
    return s, ext, ln


def cerca(fh, inizio, fine, coperti, allineato, scarta=None, passo=16 << 20):
    """Scorre [inizio, fine) del file aperto e restituisce [(pos, ext, lunghezza)] dei file grafici non allineati.
    coperti: intervalli [a, b) già recuperati (PhotoRec), da non ripetere; allineato(pos) → True se pos è all'inizio di
    un settore dell'immagine (quei file li trova già PhotoRec); scarta(pos) → True per saltare (blocco allocato)."""
    rd = Lettore(fh, fine)
    cop = sorted(coperti)
    trovati = []

    def dentro(pos):
        for a, b in cop:
            if a <= pos < b:
                return True
            if a > pos:
                break
        return any(a <= pos < a + ln for a, _e, ln in trovati[-8:])
    pos = inizio
    while pos < fine:
        fh.seek(pos)
        d = fh.read(min(passo + 32, fine - pos))
        if not d:
            break
        for m in FIRME.finditer(d):
            if m.start() >= passo:
                break
            s = pos + m.start() - (4 if m.group().startswith(b"ftyp") else 0)
            if s < inizio or allineato(s) or dentro(s) or (scarta and scarta(s)):
                continue
            try:
                r = riconosci(rd, pos + m.start(), m.group())
            except (struct.error, OverflowError, ValueError):
                r = None
            if r and r[0] + r[2] <= fine:
                trovati.append(r)
        pos += passo
    return trovati


def miniatura_exif(d):
    """Miniatura EXIF incorporata in un JPEG (secondo SOI dentro APP1, fino al suo EOI), o None."""
    if d[:4] != b"\xff\xd8\xff\xe1" or len(d) < 8:
        return None
    fine = 4 + struct.unpack(">H", d[4:6])[0]
    i = d.find(b"\xff\xd8\xff", 6, fine)
    j = d.find(b"\xff\xd9", i + 3, fine) if i > 0 else -1
    return d[i:j + 2] if i > 0 and j > 0 else None
