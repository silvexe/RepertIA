# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA (3.0.2): lettore UDF (ECMA-167, OSTA UDF 1.02-2.60) per immagini di CD/DVD a settori da 2048 byte.

Serve dove Sleuth Kit (UDF non supportato) e 7-Zip (partizione virtuale non supportata) non arrivano: soprattutto i
CD-R e DVD-R masterizzati da Windows «come una chiavetta» (Live File System, UDF 2.01 con VAT: NIST CFReDS Data Leakage,
CD-R RM#3). Partizioni fisiche, virtuali (VAT 1.50 e 2.00) e di metadati (UDF 2.50/2.60); la tabella di sostituzione
dei dischi riscrivibili (Sparable) non è applicata e lo si dichiara.

Una VAT nuova si scrive a ogni sessione di scrittura senza cancellare le vecchie: le VAT precedenti ancora presenti
sul disco descrivono lo stato del disco in quel momento. I file che c'erano allora e non ci sono più (cancellati,
rinominati o sostituiti) si elencano a parte, come le voci di cartella segnate «cancellate». Solo lettura, solo libreria
standard; ogni struttura si accetta solo se l'etichetta (tag) è valida: somma di controllo e posizione registrata."""
import datetime as dt
import struct

S = 2048
FE, EFE, FID, AED, FSD = 261, 266, 257, 258, 256
T_VAT20, T_META = 248, 250
MAX_VOCI = 200000
MAX_PROF = 64


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def tag(b, pos=None):
    """Identificativo del descrittore se l'etichetta è valida (somma di controllo e, se indicata, posizione), altrimenti 0."""
    if len(b) < 16 or (sum(b[0:4]) + sum(b[5:16])) & 0xFF != b[4]:
        return 0
    if pos is not None and _u32(b, 12) != pos:
        return 0
    return _u16(b, 0)


def dstring(b):
    """Testo OSTA compresso: primo byte 8 (un byte per carattere) o 16 (UTF-16 big endian)."""
    if not b:
        return ""
    if b[0] == 16:
        return b[1:].decode("utf-16-be", "replace")
    return b[1:].decode("latin-1")


def data_udf(b):
    """Timestamp ECMA-167 (12 byte) -> (datetime UTC o locale senza fuso, True se UTC), oppure (None, None)."""
    tt, anno = _u16(b, 0), struct.unpack_from("<h", b, 2)[0]
    mese, giorno, ora, minuto, sec, cs, hu, mu = b[4:12]
    if not anno or not mese or not giorno:
        return None, None
    try:
        d = dt.datetime(anno, mese, giorno, ora, minuto, sec, cs * 10000 + hu * 100 + mu)
    except ValueError:
        return None, None
    tz = tt & 0x0FFF
    if tz & 0x800:
        tz -= 0x1000
    if tt >> 12 == 1 and tz != -2047:
        return d - dt.timedelta(minutes=tz), True
    return d, False


class UDF:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.f.seek(0, 2)
        self.n = self.f.tell() // S
        self.avvisi = []
        self._leggi_volume()

    def close(self):
        self.f.close()

    def sett(self, n, k=1):
        self.f.seek(n * S)
        return self.f.read(S * k)

    # ------------------------------------------------------------------ volume
    def _leggi_volume(self):
        avdp = None
        for n in (256, self.n - 1, self.n - 257, 512):
            if 0 <= n < self.n and tag(self.sett(n), n) == 2:
                avdp = self.sett(n)
                break
        if avdp is None:
            raise ValueError("UDF: ancora del volume (AVDP) non trovata")
        lun, pos = _u32(avdp, 16), _u32(avdp, 20)
        self.part, lvd = {}, None                # numero di partizione -> (inizio, lunghezza) in settori
        for n in range(pos, pos + max(1, lun // S)):
            b = self.sett(n)
            t = tag(b, n)
            if t == 5:
                self.part[_u16(b, 22)] = (_u32(b, 188), _u32(b, 192))
            elif t == 6 and lvd is None:
                lvd = b
            elif t == 8:
                break
        if lvd is None or not self.part:
            raise ValueError("UDF: descrittori di partizione o del volume logico mancanti")
        if _u32(lvd, 212) != S:
            raise ValueError("UDF: blocchi logici diversi da 2048 byte non supportati")
        self.nome = dstring(lvd[84:84 + lvd[84 + 127]]) if lvd[84 + 127] else ""
        self.fsd = (_u32(lvd, 248 + 4), _u16(lvd, 248 + 8))
        self.mappe, o = [], 440
        for _ in range(_u32(lvd, 268)):
            tipo, ln = lvd[o], lvd[o + 1]
            if not ln:
                break
            m = lvd[o:o + ln]
            if tipo == 1:
                self.mappe.append({"tipo": "fisica", "num": _u16(m, 4)})
            else:
                ident = m[5:5 + 23].split(b"\0")[0].decode("latin-1", "replace")
                num = _u16(m, 38)
                if "Virtual" in ident:
                    self.mappe.append({"tipo": "virtuale", "num": num})
                elif "Metadata" in ident:
                    self.mappe.append({"tipo": "metadati", "num": num, "file": _u32(m, 40)})
                elif "Sparable" in ident:
                    self.mappe.append({"tipo": "fisica", "num": num})
                    self.avvisi.append("partizione Sparable: tabella di sostituzione dei settori difettosi non applicata")
                else:
                    self.mappe.append({"tipo": "sconosciuta", "num": num, "id": ident})
            o += ln
        self.vat = None
        self.vat_gen = []
        if any(m["tipo"] == "virtuale" for m in self.mappe):
            self.vat_gen = self._trova_vat()
            if not self.vat_gen:
                raise ValueError("UDF: partizione virtuale senza tabella VAT leggibile")
            self.vat = self.vat_gen[-1]["tabella"]
        for m in self.mappe:
            if m["tipo"] == "metadati":
                fisica = next(i for i, x in enumerate(self.mappe) if x["tipo"] == "fisica")
                fe = self.fe(fisica, m["file"])
                m["estensioni"] = [x for x in (fe or {}).get("ad", []) if x[3] == 0]
                if not m["estensioni"]:
                    raise ValueError("UDF: file dei metadati non leggibile")

    def _fisica_di(self, num):
        return next((i for i, m in enumerate(self.mappe) if m["tipo"] == "fisica" and m["num"] == num), None)

    def assoluto(self, rif, lbn):
        """Settore assoluto del blocco logico lbn della partizione rif (indice della mappa)."""
        m = self.mappe[rif]
        inizio = self.part.get(m["num"], (0, 0))[0]
        if m["tipo"] == "fisica":
            return inizio + lbn
        if m["tipo"] == "virtuale":
            if self.vat is None or lbn >= len(self.vat) or self.vat[lbn] == 0xFFFFFFFF:
                return None
            return inizio + self.vat[lbn]
        if m["tipo"] == "metadati":
            off = lbn * S
            fis = self._fisica_di(m["num"])
            for p_rif, p_lbn, ln, _t in m["estensioni"]:
                if off < ln:
                    return self.assoluto(fis if fis is not None else p_rif, p_lbn) + off // S
                off -= ln
            return None
        return None

    def blocco(self, rif, lbn):
        n = self.assoluto(rif, lbn)
        return self.sett(n) if n is not None and 0 <= n < self.n else None

    # ------------------------------------------------------------------ VAT
    def _trova_vat(self):
        """Tutte le VAT presenti nella partizione fisica (dalla più vecchia alla più recente)."""
        rif = next(i for i, m in enumerate(self.mappe) if m["tipo"] == "fisica")
        inizio, lun = self.part[self.mappe[rif]["num"]]
        out = []
        fine = min(self.n, inizio + lun) if lun else self.n
        for n in range(inizio, fine):
            b = self.sett(n)
            if b[:2] not in (b"\x05\x01", b"\x0a\x01"):      # FE (261) o EFE (266)
                continue
            lbn = n - inizio
            if tag(b, lbn) not in (FE, EFE):
                continue
            ft = b[16 + 11]
            if ft not in (T_VAT20, 0):
                continue
            fe = self._fe_da(b, rif)
            if not fe or fe["size"] > 64 << 20:
                continue
            dati = self.dati(fe)
            tab = None
            if ft == T_VAT20 and len(dati) >= 152:
                lhd = _u16(dati, 0)
                if 152 <= lhd <= len(dati):
                    tab = list(struct.unpack_from(f"<{(len(dati) - lhd) // 4}I", dati, lhd))
                    prec, nf, nd = _u32(dati, 132), _u32(dati, 136), _u32(dati, 140)
            elif ft == 0 and len(dati) >= 36 and dati[-36:-36 + 23].startswith(b"*UDF Virtual Alloc Tbl"):
                tab = list(struct.unpack_from(f"<{(len(dati) - 36) // 4}I", dati, 0))
                prec, nf, nd = _u32(dati, len(dati) - 4), None, None
            if tab:
                out.append({"settore": n, "lbn": lbn, "tabella": tab, "precedente": prec, "file": nf, "cartelle": nd,
                            "modifica": fe["times"].get("M")})
        return out

    # ------------------------------------------------------------------ file entry
    def fe(self, rif, lbn):
        b = self.blocco(rif, lbn)
        if b is None or tag(b, lbn) not in (FE, EFE):
            return None
        return self._fe_da(b, rif)

    def _fe_da(self, b, rif):
        t = _u16(b, 0)
        flags = _u16(b, 16 + 18)
        ft = b[16 + 11]
        if t == FE:
            size, l_ea, l_ad, base = _u64(b, 56), _u32(b, 168), _u32(b, 172), 176
            tempi = {"A": b[72:84], "M": b[84:96], "C": b[96:108]}
            uid = _u64(b, 160)
        else:
            size, l_ea, l_ad, base = _u64(b, 56), _u32(b, 208), _u32(b, 212), 216
            tempi = {"A": b[80:92], "M": b[92:104], "B": b[104:116], "C": b[116:128]}
            uid = _u64(b, 200)
        times, locale = {}, False
        for k, v in tempi.items():
            d, utc = data_udf(v)
            if d:
                times[k] = d
                locale = locale or not utc
        ads = b[base + l_ea:base + l_ea + l_ad]
        fe = {"tipo": ft, "size": size, "times": times, "locale": locale, "uid": uid, "ad": [], "embedded": None}
        tad = flags & 7
        if tad == 3:
            fe["embedded"] = bytes(ads[:size])
        else:
            fe["ad"] = self._ad(ads, tad, rif)
        return fe

    def _ad(self, ads, tad, rif, prof=0):
        out, o = [], 0
        passo = 8 if tad == 0 else 16 if tad == 1 else 20
        while o + passo <= len(ads):
            ln = _u32(ads, o)
            tipo, ln = ln >> 30, ln & 0x3FFFFFFF
            if ln == 0:
                break
            if tad == 0:
                p_rif, lbn = rif, _u32(ads, o + 4)
            elif tad == 1:
                lbn, p_rif = _u32(ads, o + 4), _u16(ads, o + 8)
            else:
                lbn, p_rif = _u32(ads, o + 12), _u16(ads, o + 16)
            if tipo == 3:                      # continua in un Allocation Extent Descriptor
                b = self.blocco(p_rif, lbn) if p_rif < len(self.mappe) else None
                if b is not None and tag(b, lbn) == AED and prof < 32:
                    out += self._ad(b[24:24 + _u32(b, 20)], tad, p_rif, prof + 1)
                break
            out.append((p_rif if p_rif < len(self.mappe) else rif, lbn, ln, tipo))
            o += passo
        return out

    def dati(self, fe, limite=None):
        """Contenuto del file (estensioni «non registrate» = zeri), tagliato alla lunghezza del file."""
        tot = fe["size"] if limite is None else min(fe["size"], limite)
        if fe["embedded"] is not None:
            return fe["embedded"][:tot]
        return b"".join(self.pezzi(fe, tot))

    def pezzi(self, fe, tot=None):
        tot = fe["size"] if tot is None else tot
        if fe["embedded"] is not None:
            yield fe["embedded"][:tot]
            return
        resto = tot
        for rif, lbn, ln, tipo in fe["ad"]:
            if resto <= 0:
                break
            k = min(ln, resto)
            if tipo != 0:
                yield b"\0" * k
            else:
                fatti = 0
                while fatti < k:
                    n = self.assoluto(rif, lbn + fatti // S)
                    q = min(k - fatti, 64 * S)
                    if n is None:
                        yield b"\0" * q
                    else:
                        self.f.seek(n * S)
                        x = self.f.read(q)
                        yield x + b"\0" * (q - len(x))
                    fatti += q
            resto -= k

    # ------------------------------------------------------------------ cartelle
    def fid(self, dati):
        o = 0
        while o + 38 <= len(dati):
            if tag(dati[o:o + 16]) != FID:
                break
            car, l_fi = dati[o + 18], dati[o + 19]
            lbn, rif = _u32(dati, o + 20 + 4), _u16(dati, o + 20 + 8)
            l_iu = _u16(dati, o + 36)
            nome = dstring(dati[o + 38 + l_iu:o + 38 + l_iu + l_fi])
            yield {"nome": nome, "dir": bool(car & 2), "cancellato": bool(car & 4), "padre": bool(car & 8),
                   "rif": rif, "lbn": lbn}
            o += (38 + l_iu + l_fi + 3) & ~3

    def radice(self):
        lbn, rif = self.fsd
        b = self.blocco(rif, lbn)
        if b is None or tag(b, lbn) != FSD:
            raise ValueError("UDF: descrittore del file system (FSD) non trovato")
        return _u16(b, 400 + 8), _u32(b, 400 + 4)

    def elenco(self):
        """Voci della generazione attiva: dict con percorso, cartella, cancellato, fe."""
        out, visti = [], set()
        rif, lbn = self.radice()

        def giro(rif, lbn, base, prof):
            if prof > MAX_PROF or (rif, lbn) in visti or len(out) >= MAX_VOCI:
                return
            visti.add((rif, lbn))
            fe = self.fe(rif, lbn)
            if not fe:
                return
            for x in self.fid(self.dati(fe, 64 << 20)):
                if x["padre"] or not x["nome"]:
                    continue
                p = f"{base}/{x['nome']}" if base else x["nome"]
                r = x["rif"] if x["rif"] < len(self.mappe) else rif
                fx = self.fe(r, x["lbn"]) if (x["lbn"] or r) else None
                out.append({"percorso": p, "cartella": x["dir"], "cancellato": x["cancellato"], "fe": fx, "pos": (r, x["lbn"])})
                if x["dir"] and not x["cancellato"]:
                    giro(r, x["lbn"], p, prof + 1)
        giro(rif, lbn, "", 0)
        return out

    def generazioni(self):
        """Elenco per ogni VAT (dalla più vecchia alla attiva): [(vat, voci)]. Senza VAT: solo l'elenco attivo."""
        if not self.vat_gen:
            return [(None, self.elenco())]
        out = []
        attiva = self.vat
        for g in self.vat_gen:
            self.vat = g["tabella"]
            try:
                voci = self.elenco()
            except ValueError:
                voci = []
            out.append((g, voci))
        self.vat = attiva
        return out
