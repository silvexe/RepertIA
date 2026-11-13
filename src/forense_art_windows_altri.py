#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""RepertIA - artefatti di Windows: parser dei formati binari, ShellBags, Google Drive, Ricerca, Internet Explorer, Sticky Notes, SRUM, eventi, journal USN, thumbcache.

(3.0.4) Codice spostato da forense_estesa.py senza modifiche, per avere file più corti. Si carica tramite
forense_estesa, che ne riesporta i nomi: gli altri moduli continuano a usare «fe.<nome>». I nomi che possono
cambiare durante l'esecuzione si leggono ogni volta dal modulo di origine («fe.<nome>»).
"""
import base64
import datetime as dt
import html
import json
import re
import shutil
import sqlite3
import struct
from collections import Counter
from collections import deque
from pathlib import Path
from forense_lingua import N_
from forense_lingua import tr

import forense_estesa as fe
from forense_estesa import (
    Art, EVTX_DATA_RE, HeadReader, evtx_stato, fetch_hive, filetime, hashes_of, iso, lw, new_xitem, open_hive, rk,
    rv, safe_name, store_extracted, subkeys, unixtime, user_of)

# ------------------------------------------------------------------ Windows: parser di formati binari (2.18)
# Funzioni pure (byte -> dati): ShellBags (shell item), ShimCache, BAM, journal USN, thumbcache, hash percettivi.

KNOWN_SHELL_GUIDS = {
    "20d04fe0-3aea-1069-a2d8-08002b30309d": N_("Questo PC"), "59031a47-3f72-44a7-89c5-5595fe6b30ee": N_("Cartella utente"),
    "031e4825-7b94-4dc3-b131-e946b44c8dd5": N_("Raccolte"), "645ff040-5081-101b-9f08-00aa002f954e": N_("Cestino"),
    "f02c1a0d-be21-4350-88b0-7367fc96ef3c": N_("Rete"), "208d2c60-3aea-1069-a2d7-08002b30309d": N_("Risorse di rete"),
    "679f85cb-0220-4080-b29b-5540cc05aab6": N_("Accesso rapido"), "26ee0668-a00a-44d7-9371-beb064c98683": N_("Pannello di controllo"),
    "21ec2020-3aea-1069-a2dd-08002b30309d": N_("Pannello di controllo"), "018d5c66-4533-4307-9b53-224de2ed1fe6": "OneDrive",
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop", "374de290-123f-4565-9164-39c4925e467b": "Download",
    "088e3905-0323-4b02-9826-5d99428e115f": "Download", "d3162b92-9365-467a-956b-92703aca08af": N_("Documenti"),
    "a8cdff1c-4878-43be-b5fd-f8091c1c60d0": N_("Documenti"), "24ad3ad4-a569-4530-98e1-ab02f9417aa8": N_("Immagini"),
    "3add1653-eb32-4cb0-bbd7-dfa0abb5acca": N_("Immagini"), "3dfdf296-dbec-4fb4-81d1-6a3438bcf4de": N_("Musica"),
    "1cf1260c-4dd0-4ebb-811f-33c572699fde": N_("Musica"), "f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a": "Video",
    "a0953c92-50dc-43bf-be83-3742fed03c9c": "Video", "0db7e03f-fc29-4dc6-9020-ff41b59e513a": N_("Oggetti 3D"),
    "5e6c858f-0e22-4760-9afe-ea3317b67173": N_("Cartella utente"), "9e3995ab-1f9c-4f13-b827-48b24b6c7174": N_("Cartella utente"),
    "e88865ea-0e1c-4e20-9aa6-edcd0212c87c": N_("Galleria"), "f874310e-b6b7-47dc-bc84-b9e6b38f5903": "Home",
    "a52bba46-e9e1-435f-b3d9-28daa648c0f6": "OneDrive", "f42ee2d3-909f-4907-8871-4c22fc0bf756": N_("Documenti"),
    "7d83ee9b-2244-4e70-b1f5-5393042af1e4": "Download", "33e28130-4e1e-4676-835a-98395c3bc3bb": N_("Immagini"),
    "18989b1d-99b5-455b-841c-ab7c74e4ddfc": "Video", "4bd8d571-6d19-48d3-be97-422220080e43": N_("Musica"),
    "b7bede81-df94-4682-a7d8-57a52620b86f": "Screenshot", "ab5fb87b-7ce2-4f83-915d-550846c9537b": N_("Rullino"),
}


def _guid(b):
    import uuid
    try:
        return str(uuid.UUID(bytes_le=bytes(b[:16])))
    except ValueError:
        return ""


def dos_datetime(b, off=0):
    """Data/ora FAT (data a 16 bit, ora a 16 bit) -> ISO; None se nulla o non valida."""
    if len(b) < off + 4:
        return None
    d, t = struct.unpack_from("<HH", b, off)
    if not d:
        return None
    try:
        return dt.datetime(1980 + (d >> 9), (d >> 5) & 15, d & 31, t >> 11, (t >> 5) & 63, (t & 31) * 2).strftime("%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def _beef0004(d):
    """Blocco di estensione 0xBEEF0004 di uno shell item: (nome lungo, creazione, accesso, record MFT) o None."""
    i = d.find(b"\x04\x00\xef\xbe")
    if i < 4:
        return None
    e = i - 4
    try:
        size, ver = struct.unpack_from("<HH", d, e)
        blk = d[e:e + size] if size >= 20 else d[e:]
        ctime, atime = dos_datetime(blk, 8), dos_datetime(blk, 12)
        mft = None
        off = 18
        if ver >= 7:
            ref = struct.unpack_from("<Q", blk, 20)[0]
            mft = (ref & 0xFFFFFFFFFFFF, ref >> 48)
            off = 36
        if ver >= 3:
            off += 2
        if ver >= 9:
            off += 4
        if ver >= 8:
            off += 4
        end = off
        while end + 1 < len(blk) and blk[end:end + 2] != b"\0\0":
            end += 2
        name = blk[off:end].decode("utf-16-le", "replace") if end > off else None
        return name, ctime, atime, mft
    except struct.error:
        return None


def shell_item(d):
    """Uno shell item (ShellBags, LNK): (nome, {modifica, creazione, accesso, mft, tipo}). d comprende i 2 byte di
    dimensione iniziali."""
    info = {}
    if len(d) < 3:
        return None, info
    t = d[2]
    info["tipo"] = t
    if t in (0x1F, 0x2E) and len(d) >= 20:                      # cartella radice (GUID)
        g = _guid(d[4:20])
        return tr(KNOWN_SHELL_GUIDS.get(g, "{" + g + "}")), info
    if 0x20 <= t <= 0x2F:                                       # volume (lettera di unità)
        s = d[3:3 + 20].split(b"\0")[0].decode("ascii", "ignore")
        return (s.rstrip("\\") or "volume"), dict(info, volume=True)
    if (t & 0x70) == 0x40:                                      # percorso di rete (0x41-0x4F, 0xC1-0xCF)
        s = d[5:].split(b"\0")[0].decode("latin-1", "ignore")
        return (s or "rete"), dict(info, rete=True)
    if t == 0x01 and len(d) >= 12:                              # categoria del Pannello di controllo
        return tr("Pannello di controllo (categoria {v1})").format(v1=struct.unpack_from('<I', d, 8)[0]), info
    if t == 0x00 and len(d) >= 30 and d[6:10] == b"\xee\xbb\xfe\x23":     # cartella nota (GUID)
        g = _guid(d[14:30])
        return tr(KNOWN_SHELL_GUIDS.get(g, "{" + g + "}")), info
    if t == 0x00 and len(d) > 8:                                # elementi con property store: computer di rete, ricerche
        strs = [x.decode("utf-16-le") for x in re.findall(rb"(?:[\x20-\x7e]\x00){3,}", d)]
        prov = next((i for i, x in enumerate(strs) if x.startswith("Provider\\")), None)
        if prov is not None and prov + 1 < len(strs):           # computer trovato in rete (WSD/NetBIOS)
            extra = [x for x in strs[prov + 2:prov + 4]]
            info["rete_dettagli"] = ", ".join(extra)
            return "\\\\" + strs[prov + 1], dict(info, rete=True)
        full = next((x for x in strs if re.match(r"^[A-Za-z]:\\|^\\\\", x)), None)
        if full:
            return full, dict(info, volume=True)
        if strs and not _beef0004(d):
            return strs[0], info
    if 0x30 <= t <= 0x3F:                                       # file o cartella
        info["modifica"] = dos_datetime(d, 8)
        short = d[14:].split(b"\0")[0].decode("latin-1", "ignore")
        ext = _beef0004(d)
        if ext:
            name, info["creazione"], info["accesso"], info["mft"] = ext
            return (name or short), info
        return short or None, info
    if t == 0x71 and len(d) >= 30:                              # elemento del Pannello di controllo
        g = _guid(d[14:30])
        return tr(KNOWN_SHELL_GUIDS.get(g, "")) or tr("Pannello di controllo {") + g + "}", info
    ext = _beef0004(d)                                          # elementi «delegati» (0x74, 0x00 con proprietà)
    if ext and ext[0]:
        info["creazione"], info["accesso"], info["mft"] = ext[1], ext[2], ext[3]
        return ext[0], info
    return tr("[elemento di tipo 0x{t:02X}]").format(t=t), info


def shimcache_entries(d):
    """Voci di AppCompatCache (ShimCache): [(percorso, ultima modifica del file, eseguito o None)] in ordine
    (la prima è la più recente). Formati: Windows 10/11 («10ts» con intestazione 0x30/0x34), 8/8.1 (0x80),
    7 / Server 2008 R2 (0xBADC0FEE, 32 e 64 bit)."""
    out = []
    if len(d) < 8:
        return out, None
    sig = struct.unpack_from("<I", d, 0)[0]
    if sig in (0x30, 0x34) or (sig == 0x80 and d[0x80:0x84] in (b"10ts", b"00ts")):
        fmt = "Windows 10/11" if sig != 0x80 else "Windows 8/8.1"
        pos = sig
        while pos + 12 <= len(d) and d[pos:pos + 4] in (b"10ts", b"00ts"):
            dlen = struct.unpack_from("<I", d, pos + 8)[0]
            body = pos + 12
            plen = struct.unpack_from("<H", d, body)[0]
            path = d[body + 2:body + 2 + plen].decode("utf-16-le", "replace")
            q = body + 2 + plen
            if sig == 0x80:                     # 8.1: nome del pacchetto, flag
                if fmt and d[pos:pos + 4] == b"10ts" and q + 2 <= len(d):
                    pk = struct.unpack_from("<H", d, q)[0]
                    q += 2 + pk + 8
                else:
                    q += 8
            ft = struct.unpack_from("<Q", d, q)[0] if q + 8 <= body + dlen else 0
            out.append((path, filetime(ft), None))
            pos = body + dlen
        return out, fmt
    if sig == 0xBADC0FEE:
        n = struct.unpack_from("<I", d, 4)[0]
        # 64 bit: voci da 48 byte con offset a 64 bit; 32 bit: voci da 32 byte
        def try_x64():
            r = []
            for i in range(n):
                e = 128 + 48 * i
                plen, _, poff, ft, flags = struct.unpack_from("<HHxxxxQQI", d, e)
                if not 0 < poff < len(d) or poff + plen > len(d):
                    return None
                r.append((d[poff:poff + plen].decode("utf-16-le", "replace"), filetime(ft), bool(flags & 2)))
            return r
        def try_x86():
            r = []
            for i in range(n):
                e = 128 + 32 * i
                plen, _, poff, ft, flags = struct.unpack_from("<HHIQI", d, e)
                if not 0 < poff < len(d) or poff + plen > len(d):
                    return None
                r.append((d[poff:poff + plen].decode("utf-16-le", "replace"), filetime(ft), bool(flags & 2)))
            return r
        try:
            r = try_x64()
        except struct.error:
            r = None
        if r is None:
            try:
                r = try_x86()
            except struct.error:
                r = None
        return (r or []), "Windows 7"
    return out, None


USN_REASONS = [(0x1, N_("dati sovrascritti")), (0x2, N_("dati aggiunti")), (0x4, N_("dati troncati")), (0x10, N_("flusso con nome sovrascritto")),
               (0x20, N_("flusso con nome esteso")), (0x40, N_("flusso con nome troncato")), (0x100, N_("creato")), (0x200, N_("cancellato")),
               (0x400, N_("attributi estesi cambiati")), (0x800, N_("permessi cambiati")), (0x1000, N_("rinominato (nome vecchio)")),
               (0x2000, N_("rinominato (nome nuovo)")), (0x4000, N_("indicizzazione cambiata")), (0x8000, N_("attributi cambiati")),
               (0x10000, N_("collegamento fisico")), (0x20000, N_("compressione cambiata")), (0x40000, N_("cifratura cambiata")),
               (0x80000, N_("ID oggetto cambiato")), (0x100000, N_("reparse point cambiato")), (0x200000, N_("flusso cambiato")),
               (0x400000, N_("transazione")), (0x800000, N_("integrità cambiata")), (0x80000000, N_("chiuso"))]


def usn_reason_text(r):
    return ", ".join(tr(t) for b, t in USN_REASONS if r & b and b != 0x80000000)


def usn_records(buf):
    """Record del journal NTFS ($UsnJrnl:$J) in un blocco di dati: dict con usn, file (record MFT, sequenza),
    padre (record, sequenza), ts, reason, attr, nome. Accetta le versioni 2 e 3; salta zeri e dati non validi."""
    pos, n = 0, len(buf)
    while pos + 60 <= n:
        rl = struct.unpack_from("<I", buf, pos)[0]
        if rl == 0:
            pos += 8
            continue
        if rl < 60 or rl > 65536 or pos + rl > n:
            pos += 8
            continue
        major = struct.unpack_from("<H", buf, pos + 4)[0]
        try:
            if major == 2:
                fref, pref, usn, ts, reason = struct.unpack_from("<QQQQI", buf, pos + 8)
                attr = struct.unpack_from("<I", buf, pos + 52)[0]
                fnlen, fnoff = struct.unpack_from("<HH", buf, pos + 56)
                f = (fref & 0xFFFFFFFFFFFF, fref >> 48)
                p = (pref & 0xFFFFFFFFFFFF, pref >> 48)
            elif major == 3:
                f_lo, f_hi, p_lo, p_hi, usn, ts, reason = struct.unpack_from("<QQQQQQI", buf, pos + 8)
                attr = struct.unpack_from("<I", buf, pos + 68)[0]
                fnlen, fnoff = struct.unpack_from("<HH", buf, pos + 72)
                f = (f_lo & 0xFFFFFFFFFFFF, f_lo >> 48)
                p = (p_lo & 0xFFFFFFFFFFFF, p_lo >> 48)
            else:
                pos += 8
                continue
        except struct.error:
            break
        if fnoff + fnlen > rl or not fnlen or fnlen % 2:
            pos += 8
            continue
        name = buf[pos + fnoff:pos + fnoff + fnlen].decode("utf-16-le", "replace")
        yield {"usn": usn, "file": f, "padre": p, "ts": filetime(ts), "reason": reason, "attr": attr, "nome": name}
        pos += (rl + 7) & ~7


def thumbcache_entries(data):
    """Miniature di un file thumbcache_*.db (Windows 7-11): [(hash, estensione, dati, larghezza, altezza)]."""
    out = []
    if data[:4] != b"CMMM":
        return out
    ver = struct.unpack_from("<I", data, 4)[0]
    pos = 24 if ver >= 21 else 24
    n = len(data)
    while True:
        i = data.find(b"CMMM", pos)
        if i < 0 or i + 48 > n:
            break
        size = struct.unpack_from("<I", data, i + 4)[0]
        h = struct.unpack_from("<Q", data, i + 8)[0]
        ok = False
        fnlen, padlen, dlen = struct.unpack_from("<III", data, i + 16)
        # varianti dell'intestazione: 56 byte (Windows 8-11; nella versione 32 la dimensione comprende 4 byte dopo i dati),
        # 48 (Windows 7), 60; si sceglie quella in cui i dati cominciano con la firma di un'immagine
        cands = []
        for hdr, extra, wh in ((56, 0, True), (56, 4, True), (48, 0, False), (60, 0, True)):
            if i + hdr <= n and hdr + fnlen + padlen + dlen + extra == size:
                d0 = i + hdr + fnlen + padlen
                blob = data[d0:d0 + dlen]
                sig = blob[:3] == b"\xff\xd8\xff" or blob[:4] == b"\x89PNG" or blob[:2] == b"BM"
                cands.append((not sig, hdr, wh, blob))
        if cands:
            cands.sort(key=lambda x: x[0])
            _, hdr, wh, blob = cands[0]
            w, ht = struct.unpack_from("<II", data, i + 28) if wh else (0, 0)
            if dlen and blob:
                ext = ("jpg" if blob[:3] == b"\xff\xd8\xff" else "png" if blob[:4] == b"\x89PNG" else
                       "bmp" if blob[:2] == b"BM" else "bin")
                out.append((f"{h:016x}", ext, blob, w, ht))
            ok = True
        pos = i + (size if ok and size >= 48 else 4)
    return out


def dhash_image(fp):
    """Hash percettivo (differenza, 64 bit) di un'immagine: resiste a ridimensionamento, ricompressione e piccoli
    ritocchi, non a ritagli o rotazioni diverse da quella indicata nell'EXIF. None se l'immagine non si apre."""
    from PIL import Image, ImageOps
    try:
        with Image.open(fp) as im:
            im.draft("L", (64, 64))
            try:
                im = ImageOps.exif_transpose(im)
            except Exception:
                pass
            g = im.convert("L").resize((9, 8), Image.LANCZOS)
            px = list(g.getdata())
            w, h = im.size
    except Exception:
        return None
    if max(px) - min(px) < 8:
        return None             # immagine quasi uniforme (tutta di un colore): l'hash non distingue nulla
    v = 0
    for r in range(8):
        for c in range(8):
            v = (v << 1) | (px[r * 9 + c] > px[r * 9 + c + 1])
    return v - (1 << 64) if v >= (1 << 63) else v, w, h      # con segno: SQLite memorizza interi a 64 bit


def dhash_dist(a, b):
    return bin((a ^ b) & 0xFFFFFFFFFFFFFFFF).count("1")


# ------------------------------------------------------------------ Windows: installazioni, nuovi artefatti (2.18)

def win_roots(con, part):
    """Radici delle installazioni di Windows nel volume ('' = quella principale, 'Windows.old/'…): ogni cartella che
    contiene Windows/System32/config/SYSTEM (anche cancellato) o profili utente con NTUSER.DAT. La principale per prima."""
    out = set()
    for (path,) in con.execute("SELECT path FROM files WHERE part=? AND type LIKE '%r' "
                               "AND lower(path) LIKE '%windows/system32/config/system'", (part,)):
        if path.lower().endswith("windows/system32/config/system"):
            out.add(path[:len(path) - len("windows/system32/config/system")])
    for (path,) in con.execute("SELECT path FROM files WHERE part=? AND type LIKE '%r' AND deleted=0 "
                               "AND (lower(path) LIKE '%users/%/ntuser.dat' OR lower(path) LIKE '%documents and settings/%/ntuser.dat')",
                               (part,)):
        m = re.match(r"(?i)^((?:[^/]+/){0,2}?)(?:users|documents and settings)/[^/]+/ntuser\.dat$", path)
        if m:
            out.add(m.group(1))
    return sorted(out, key=lambda r: (r != "", r.count("/"), r.lower()))


def hive_rows(ctx, part, like):
    """Come fw, ma se l'alveare (o il registro eventi) non c'è fra i file presenti prova la voce cancellata: il contenuto
    si verifica all'apertura (firma) e l'esito è dichiarato tra gli artefatti di sistema."""
    return fe.fw(ctx, part, like) or fe.fw(ctx, part, like, deleted_ok=True)


def like_lit(s):
    """Testo letterale dentro un modello LIKE con ESCAPE '\\'."""
    return s.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def fw(ctx, part, like, deleted_ok=False):
    """find_files dentro l'installazione di Windows in esame (ctx.win_root)."""
    return fe.find_files(ctx.con, part, like_lit(getattr(ctx, "win_root", "") or "") + like, deleted_ok)


def shellbags(A, root_key, base, user, src, fonte):
    """Cartelle aperte in Esplora file (ShellBags): BagMRU di NTUSER.DAT o UsrClass.dat. Restano anche dopo che la
    cartella o il disco (chiavetta, disco esterno, rete) non esistono più."""
    top = rk(root_key, base)
    if top is None:
        return 0
    n = [0]

    def walk(key, prefix, depth):
        if key is None or depth > 40 or n[0] > 200000:
            return
        mru = rv(key, "MRUListEx")
        order = [i for i in struct.unpack(f"<{len(mru) // 4}I", mru) if i != 0xFFFFFFFF] \
            if isinstance(mru, bytes) and len(mru) >= 4 else []
        names = sorted({int(v.name) for v in (key.values if key is not None else []) if (v.name or "").isdigit()})
        for i in order + [x for x in names if x not in order]:
            d = rv(key, str(i))
            if not isinstance(d, bytes) or len(d) < 3:
                continue
            name, info = shell_item(d)
            if not name:
                continue
            path = name if info.get("volume") or info.get("rete") or not prefix else prefix + "\\" + name
            sub = rk(key, str(i))
            first = bool(order) and i == order[0]
            det = [tr("{fonte}: cartella aperta in Esplora file").format(fonte=fonte)]
            if first:
                det.append(tr("ultima aperta in questo livello (chiave scritta {v1})").format(v1=lw(key).replace('T', ' ')) if lw(key) else
                           tr("ultima aperta in questo livello"))
            for k, lbl in (("modifica", "modifica"), ("creazione", "creazione"), ("accesso", "accesso")):
                if info.get(k):
                    det.append(tr("{lbl} della cartella {v1}").format(lbl=lbl, v1=info[k].replace('T', ' ')))
            if info.get("mft"):
                det.append(tr("record MFT {v1} (sequenza {v2})").format(v1=info['mft'][0], v2=info['mft'][1]))
            if info.get("volume") or info.get("rete"):
                det.append(tr("unità o percorso completo") if info.get("volume") else tr("percorso di rete"))
            if info.get("rete_dettagli"):
                det.append(tr("computer in rete ({rete_dettagli})").format(rete_dettagli=info['rete_dettagli']))
            A.add("cartelle", lw(key) if first else None, path, "; ".join(det), user, src,
                  {"fonte": fonte, "tipo_elemento": info.get("tipo"), "modifica": info.get("modifica"),
                   "creazione": info.get("creazione"), "accesso": info.get("accesso"),
                   "mft": info.get("mft"), "chiave": f"{base}\\{prefix}"[:300]})
            n[0] += 1
            if sub is not None:
                walk(sub, path, depth + 1)

    walk(top, "", 0)
    return n[0]


def win_usrclass(A, ctx, part, row):
    """UsrClass.dat (Windows 7 e successivi): ShellBags della shell."""
    p, inode, _, path = row
    user = user_of(path)
    f = fetch_hive(A, ctx, p, inode, path)
    if not f:
        return
    try:
        hv, root = open_hive(f)
    except Exception:
        return
    try:
        shellbags(A, root, "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", user, (p, inode, path),
                  "ShellBags (UsrClass.dat)")
    finally:
        hv.close()


def win_shim_bam(A, root, cs, src):
    """Dal SYSTEM: ShimCache (AppCompatCache) e BAM/DAM (ultima esecuzione per utente)."""
    v = rv(rk(root, f"{cs}\\Control\\Session Manager\\AppCompatCache"), "AppCompatCache")
    if isinstance(v, bytes):
        ents, fmt = shimcache_entries(v)
        for pos, (path, mt, ex) in enumerate(ents[:5000], 1):
            A.add("esecuzioni", None, path, "; ".join(x for x in (
                tr("ShimCache ({fmt}): posizione {pos} (1 = la più recente)").format(fmt=fmt, pos=pos),
                tr("ultima modifica del file {v1}").format(v1=mt.replace('T', ' ')) if mt else "",
                (tr("eseguito (flag di inserimento)") if ex else tr("non risulta eseguito")) if ex is not None else
                tr("da Windows 8 la presenza in ShimCache NON prova l'esecuzione: il file è stato visto dal sistema")) if x),
                  "", src, {"fonte": "ShimCache", "posizione": pos, "modifica_file": mt, "eseguito": ex, "formato": fmt})
        if v and not ents:
            A.add("sistema", None, tr("ShimCache in formato non riconosciuto"), tr("intestazione 0x{v1:08X}").format(v1=struct.unpack_from('<I', v, 0)[0]),
                  "", src)
    for svc in ("bam", "dam"):
        for base in (f"{cs}\\Services\\{svc}\\State\\UserSettings", f"{cs}\\Services\\{svc}\\UserSettings"):
            for sk in subkeys(rk(root, base)):
                try:
                    vals = list(sk.values)
                except Exception:
                    vals = []
                for val in vals:
                    d = val.data if hasattr(val, "data") else None
                    if not isinstance(d, bytes) or len(d) < 8 or (val.name or "") in ("Version", "SequenceNumber"):
                        continue
                    t = filetime(struct.unpack_from("<Q", d, 0)[0])
                    A.add("esecuzioni", t, val.name, tr("{v1} (Background/Desktop Activity Moderator): ultima esecuzione per l'utente {name}").format(v1=svc.upper(), name=sk.name), sk.name, src, {"fonte": svc.upper(), "sid": sk.name})


def win_activities(A, ctx, part):
    """Cronologia attività di Windows 10/11 (ActivitiesCache.db): app usate, file aperti, appunti."""
    rows = fe.find_files(ctx.con, part, "%/appdata/local/connecteddevicesplatform/%/activitiescache.db")
    for p, inode, _, path in rows:
        db, _wal = fe.fetch_sqlite(ctx, p, inode, path)
        if db is None:
            continue
        user = user_of(path)
        try:
            cols = {c[1].lower() for c in db.execute("PRAGMA table_info(Activity)")}
            if "payload" not in cols:
                continue
            sel = [c for c in ("AppId", "Payload", "ActivityType", "StartTime", "EndTime", "LastModifiedTime",
                               "ClipboardPayload") if c.lower() in cols]
            for r in db.execute(f"SELECT {', '.join(sel)} FROM Activity"):
                x = dict(zip(sel, r))
                try:
                    pl = json.loads(x.get("Payload") or "{}") if isinstance(x.get("Payload"), (str, bytes)) else {}
                except ValueError:
                    pl = {}
                try:
                    app = json.loads(x.get("AppId") or "[]")
                    app = next((a.get("application") for a in app if a.get("platform") in ("windows_win32", "x_exe_path", "packageId")), None) \
                        or (app[0].get("application") if app else "")
                except (ValueError, AttributeError, TypeError):
                    app = str(x.get("AppId") or "")[:200]
                typ = x.get("ActivityType")
                start, end = unixtime(x.get("StartTime")), unixtime(x.get("EndTime"))
                what = {5: tr("app o file aperto"), 6: tr("app in uso"), 10: "appunti", 16: "copia/incolla"}.get(typ, tr("attività tipo {typ}").format(typ=typ))
                title = (tr("Appunti (testo copiato)") if typ == 10 else pl.get("displayText") or pl.get("appDisplayName") or app
                         or tr("attività"))
                extra = []
                if pl.get("description"):
                    extra.append(str(pl["description"])[:300])
                if pl.get("contentUri"):
                    extra.append(str(pl["contentUri"])[:300])
                if pl.get("activeDurationSeconds"):
                    extra.append(tr("attiva per {activeDurationSeconds} s").format(activeDurationSeconds=pl['activeDurationSeconds']))
                if typ == 10 and x.get("ClipboardPayload"):
                    try:
                        cp = json.loads(x["ClipboardPayload"])
                        txt = next((base64.b64decode(c.get("content", "")).decode("utf-8", "replace") for c in cp
                                    if c.get("formatName") == "Text"), "")
                        if txt:
                            extra.append(tr("testo copiato: ") + txt[:500])
                    except Exception:
                        pass
                A.add("uso", start, title, "; ".join(x for x in [tr("Cronologia attività: {what}").format(what=what), f"app {app}" if app else ""] +
                                                     ([f"fine {end.replace('T', ' ')}"] if end else []) + extra if x),
                      user, (p, inode, path), {"fonte": "ActivitiesCache", "tipo": typ, "app": app, "inizio": start, "fine": end})
        except sqlite3.Error:
            pass
        finally:
            db.close()


# (3.0.2) Google Drive per Windows (Backup and Sync / Drive legacy): NIST Data Leakage, domande 29-31 e 48-49
GDRIVE_LOG_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ ([+-]\d{4}) ")
GDRIVE_EV_RE = re.compile(r"RawEvent\((CREATE|DELETE|MOVE|MODIFY), path=u?['\"](.*?)['\"],(.*)")
GDRIVE_DIR_RE = re.compile(r"\bis_dir=(True|False)")
GDRIVE_SIZE_RE = re.compile(r"\bsize=(\d+)")
GDRIVE_MTIME_RE = re.compile(r"\bmtime=([\d.]+)")
GDRIVE_MAIL_RE = re.compile(r"Initializing User instance with new credentials\.?\s*([\w.+-]+@[\w-]+(?:\.[\w-]+)+)")
GDRIVE_MAX = 5000
GDRIVE_CONFIG = ("user_email", "local_sync_root_path", "highest_app_version", "upgrade_number", "selective_sync")


def _gdrive_ora(data, off):
    """Ora del registro di Google Drive (locale con scostamento, es. -0400) in UTC."""
    try:
        t = dt.datetime.strptime(data, "%Y-%m-%d %H:%M:%S")
        m = (1 if off[0] == "+" else -1) * (int(off[1:3]) * 60 + int(off[3:5]))
        return iso(t - dt.timedelta(minutes=m))
    except (ValueError, IndexError):
        return None


def _gdrive_val(q):
    try:
        return int(q[1]) if q[0] == "i" else float(q[1]) if q[0] == "r" else q[1] if q[0] == "t" else None
    except (ValueError, TypeError, IndexError):
        return None


def win_gdrive(A, ctx, part):
    """Google Drive per Windows (versione «Backup and Sync»): account e cartella da sync_config.db, file del cloud da
    snapshot.db (anche i record cancellati, letti dai byte e segnati da verificare), file creati e cancellati nella
    cartella sincronizzata da sync_log.log (ora locale con scostamento, convertita in UTC). I file cancellati del disco
    si provano lo stesso: se il contenuto è sovrascritto non si aprono e lo si dichiara. Le versioni nelle copie shadow
    si leggono con gdrive_vss dopo l'analisi delle copie shadow."""
    trovati, visti = 0, set()
    for nome in ("sync_config.db", "snapshot.db", "sync_log.log"):
        for p, inode, cancellato, path in fe.find_files(ctx.con, part, "%/google/drive/user_default/" + nome, True)[:20]:
            trovati += 1
            user, src = user_of(path), (p, inode, path)
            canc = tr(" (file cancellato)") if cancellato else ""
            if nome == "sync_log.log":
                f = fe.fetch(ctx, p, inode, path, 200 << 20)
                if not f:
                    A.add("cloud", None, tr("Google Drive: {name} non leggibile{c}").format(name=nome, c=canc), "", user, src)
                    continue
                _gdrive_log(A, f, user, src, canc, visti, {})
                continue
            db, _wal = fe.fetch_sqlite(ctx, p, inode, path)
            if db is None:
                A.add("cloud", None, tr("Google Drive: {name} non leggibile{c}").format(name=nome, c=canc),
                      tr("il contenuto non è un database SQLite (file cancellato e sovrascritto?)") if cancellato else "", user, src)
                continue
            _gdrive_db(A, nome, db, ctx.tmp / f"db_{p}_{safe_name(str(inode), 40)}" / "db.sqlite", user, src, canc, {})
    return trovati


def gdrive_vss(case, con, ctx):
    """(3.0.2) Google Drive nelle copie shadow: le versioni di sync_config.db, snapshot.db e sync_log.log estratte da
    run_vss (NIST Data Leakage, domande 48-49: nel disco attuale i due database sono cancellati e sovrascritti)."""
    con.execute("DELETE FROM artifacts WHERE cat='cloud' AND data LIKE '%\"copia_shadow\"%'")
    righe = con.execute("SELECT id, part, inode, src_path, store, relpath FROM xitems WHERE kind='vss' AND relpath IS NOT NULL "
                        "AND lower(src_path) LIKE '%/google/drive/user_default/%'").fetchall()
    per = {(st, sp.lower()): (xid, rp) for xid, _p, _i, sp, st, rp in righe}
    A, visti, n = Art(ctx), set(), 0
    for xid, part, inode, sp, store, rel in righe:
        nome = Path(sp).name.lower()
        if nome not in ("sync_config.db", "snapshot.db", "sync_log.log"):
            continue
        n += 1
        f = case.root / rel                 # relpath comprende già «estratti/»
        user, src = user_of(sp), (part, inode, sp)
        canc = tr(" (copia shadow: {store})").format(store=store)
        extra = {"copia_shadow": store}
        if nome == "sync_log.log":
            _gdrive_log(A, f, user, src, canc, visti, extra)
            continue
        d = ctx.tmp / f"gdvss_{xid}"
        d.mkdir(exist_ok=True)
        main = d / "db.sqlite"
        shutil.copyfile(f, main)
        for suf in ("-wal", "-journal"):
            w = per.get((store, sp.lower() + suf))
            if w:
                wf = case.root / w[1]
                if wf.exists():
                    shutil.copyfile(wf, d / ("db.sqlite" + suf))
        try:
            db = sqlite3.connect(str(main))
            db.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except sqlite3.Error:
            A.add("cloud", None, tr("Google Drive: {name} non leggibile{c}").format(name=nome, c=canc), "", user, src, extra)
            continue
        _gdrive_db(A, nome, db, main, user, src, canc, extra)
    con.commit()
    return n


def _gdrive_log(A, f, user, src, canc, visti, extra):
    n, prec = 0, ""
    for riga in open(f, "r", encoding="utf-8", errors="replace"):
        m = GDRIVE_LOG_RE.match(riga)
        if not m:
            if prec and GDRIVE_MAIL_RE.search(prec + " " + riga.strip()):     # indirizzo sulla riga dopo
                riga, m = prec + " " + riga.strip(), GDRIVE_LOG_RE.match(prec)
            else:
                continue
        prec = riga.rstrip() if "new credentials" in riga and not GDRIVE_MAIL_RE.search(riga) else ""
        ts = _gdrive_ora(m.group(1), m.group(2))
        e = GDRIVE_MAIL_RE.search(riga)
        if e:
            if ("mail", ts, e.group(1)) in visti:
                continue
            visti.add(("mail", ts, e.group(1)))
            A.add("cloud", ts, tr("Google Drive: accesso con l'account {v1}").format(v1=e.group(1)),
                  tr("sync_log.log{c}: «Initializing User instance with new credentials»").format(c=canc), user, src,
                  {"fonte": "Google Drive sync_log.log", "account": e.group(1), **extra})
            continue
        e = GDRIVE_EV_RE.search(riga)
        if not e or n >= GDRIVE_MAX:
            continue
        az, perc, resto = e.groups()
        chiave = (ts, az, perc)          # lo stesso evento è scritto più volte (aggregator, change_buffer) e nelle copie
        if chiave in visti:
            continue
        visti.add(chiave)
        n += 1
        q = GDRIVE_DIR_RE.search(resto)
        cart = q.group(1) if q else None
        q = GDRIVE_SIZE_RE.search(resto)
        size = q.group(1) if q else None
        q = GDRIVE_MTIME_RE.search(resto)
        mt = q.group(1) if q else None
        perc = perc.replace("\\\\", "\\")
        perc = perc[4:] if perc.startswith("\\\\?\\") else perc
        cosa = {"CREATE": tr("creato"), "DELETE": tr("cancellato"), "MOVE": tr("spostato"), "MODIFY": tr("modificato")}[az]
        A.add("cloud", ts, tr("Google Drive: {v1} {v2}").format(v1=(tr("cartella") if cart == "True" else tr("file")) + " " + cosa,
                                                                  v2=perc.replace("\\", "/").rsplit("/", 1)[-1]),
              "; ".join(x for x in (perc, tr("{v1} byte").format(v1=size) if size else "",
                                    tr("modificato il {v1}").format(v1=unixtime(mt).replace("T", " ")) if mt and unixtime(mt) else "",
                                    tr("sync_log.log{c}, ora locale {v1} {v2} convertita in UTC").format(c=canc, v1=m.group(1), v2=m.group(2))) if x),
              user, src, {"fonte": "Google Drive sync_log.log", "azione": az, "percorso": perc, "size": size,
                          "mtime": unixtime(mt) if mt else None, **extra})


def _gdrive_db(A, nome, db, main, user, src, canc, extra):
    try:
        tabs = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if nome == "sync_config.db" and "data" in tabs:
            # chiave in entry_key, valore con data_key «value»; solo le voci utili: altre (tango_storage) contengono gettoni
            kv = {str(k): v for k, dk, v in db.execute("SELECT entry_key, data_key, data_value FROM data")
                  if dk == "value" and k in GDRIVE_CONFIG}
            if kv:
                A.add("cloud", None, tr("Google Drive: account {v1}").format(v1=kv.get("user_email") or "?"),
                      "; ".join(x for x in (tr("cartella sincronizzata {v1}").format(v1=kv["local_sync_root_path"])
                                            if kv.get("local_sync_root_path") else "",
                                            tr("versione {v1}").format(v1=kv["highest_app_version"]) if kv.get("highest_app_version") else "",
                                            f"sync_config.db{canc}") if x), user, src,
                      {"fonte": "Google Drive sync_config.db", **{k: str(v)[:300] for k, v in kv.items()}, **extra})
        if nome == "snapshot.db" and "cloud_entry" in tabs:
            cols = [c[1] for c in db.execute("PRAGMA table_info(cloud_entry)")]
            righe = [(dict(zip(cols, r)), None) for r in db.execute("SELECT * FROM cloud_entry LIMIT ?", (GDRIVE_MAX,))]
            try:
                import forense_recupero as fr
                rec = fr.recupera(str(main))
                for x in rec["record"]:
                    if x["tabella"] == "cloud_entry" and x["livello"] in ("integra", "testa"):
                        v = [_gdrive_val(q) for q in x["valori"]]
                        righe.append((dict(zip(rec["nomi"]["cloud_entry"], v)), x))
            except Exception as e:
                A.add("cloud", None, tr("Google Drive: record cancellati di snapshot.db non letti"), f"{type(e).__name__}: {e}", user, src, extra)
            for r, x in righe:
                if r.get("doc_type") == 0 and not r.get("filename"):
                    continue
                rec_txt = (tr(" (record cancellato, da verificare)") if x else "")
                A.add("cloud", unixtime(r.get("modified")),
                      tr("Google Drive (cloud): {v1}").format(v1=r.get("filename") or "?") + rec_txt,
                      "; ".join(y for y in (tr("creato {v1}").format(v1=unixtime(r["created"]).replace("T", " ")) if unixtime(r.get("created")) else "",
                                            tr("{v1} byte").format(v1=r["size"]) if r.get("size") else "",
                                            tr("RIMOSSO dal cloud") if r.get("removed") else "",
                                            tr("condiviso") if r.get("shared") else "",
                                            f"doc_id {r['doc_id']}" if r.get("doc_id") else "",
                                            f"MD5 {r['checksum']}" if r.get("checksum") else "",
                                            (tr("snapshot.db{c}, record cancellato a offset {o} ({l})").format(c=canc, o=x["offset"], l=x["livello"])
                                             if x else f"snapshot.db{canc}")) if y), user, src,
                      {"fonte": "Google Drive snapshot.db", "recuperato": bool(x), **{k: (str(v)[:300] if v is not None else None)
                                                                                     for k, v in r.items()}, **extra})
    except sqlite3.Error as e:
        A.add("cloud", None, tr("Google Drive: {name} non leggibile{c}").format(name=nome, c=canc), f"{type(e).__name__}: {e}", user, src, extra)
    finally:
        db.close()


# (3.0.2) Indice di Ricerca di Windows, cronologia di Internet Explorer 10/11 (WebCache) e Sticky Notes: NIST Data Leakage,
# domande 13-15 e 40-46. I database ESE si leggono con forense_ese (pyesedb), senza applicare i loro log.
WS_EDB = "programdata/microsoft/search/data/applications/windows/windows.edb"
WS_SID_RE = re.compile(r"\{(S-1-[\d-]+)\}")
WS_UTENTE_RE = re.compile(r"(?i)^[a-z]:\\(?:users|documents and settings)\\([^\\]+)\\")


def _ws_utente(r, users):
    m = WS_UTENTE_RE.match(r.get("System_ItemPathDisplay") or "")
    if m:
        return m.group(1)
    m = WS_SID_RE.search(r.get("System_ItemUrl") or "")
    return users.get(m.group(1), m.group(1)) if m else ""


def _ws_persona(nome, indirizzo):
    if nome and indirizzo and nome != indirizzo:
        return f"{nome} <{indirizzo}>"
    return nome or indirizzo or ""


def win_ricerca(A, ctx, part, users):
    """Indice di Ricerca di Windows (Windows.edb): file e cartelle indicizzati (restano anche dopo la cancellazione),
    cronologia di Internet Explorer, posta di Outlook con un riassunto del testo, Sticky Notes. Una riga di riepilogo in
    «Sistema» dice che l'indicizzazione era attiva e che cosa conteneva l'indice."""
    rows = fe.fw(ctx, part, WS_EDB) or fe.fw(ctx, part, WS_EDB, deleted_ok=True)
    if not rows:
        return 0
    try:
        import forense_ese as fz
        import pyesedb  # noqa: F401
    except ImportError:
        A.add("sistema", None, tr("Indice di Ricerca di Windows non letto"), tr("manca il modulo pyesedb (libesedb)"), "", None)
        return 0
    n = 0
    for p, inode, cancellato, path in rows[:3]:
        src = (p, inode, path)
        f = fe.fetch(ctx, p, inode, path, 8 << 30)
        if not f:
            A.add("sistema", None, tr("Indice di Ricerca di Windows non leggibile"), path, "", src)
            continue
        try:
            righe, avvisi = fz.windows_search(f)
        except Exception as e:
            A.add("sistema", None, tr("Indice di Ricerca di Windows non leggibile"), f"{type(e).__name__}: {e}", "", src)
            continue
        conta = Counter()
        for r in righe:
            store = r.get("System_Search_Store") or ""
            conta[store or "?"] += 1
            user = _ws_utente(r, users)
            percorso = r.get("System_ItemPathDisplay") or r.get("System_ItemName") or ""
            dati = {"fonte": "Windows Search", "store": store, "percorso": percorso,
                    "creato": r.get("System_DateCreated"), "modificato": r.get("System_DateModified"),
                    "accesso": r.get("System_DateAccessed"), "indicizzato": r.get("System_Search_GatherTime"),
                    "dimensione": r.get("System_Size"), "tipo": r.get("System_ItemTypeText") or r.get("System_KindText")}
            date = "; ".join(x for x in (
                tr("creato {v1}").format(v1=dati["creato"].replace("T", " ")) if dati["creato"] else "",
                tr("modificato {v1}").format(v1=dati["modificato"].replace("T", " ")) if dati["modificato"] else "",
                tr("indicizzato {v1}").format(v1=dati["indicizzato"].replace("T", " ")) if dati["indicizzato"] else "") if x)
            if store == "iehistory" or r.get("Microsoft_IE_TargetUrl"):
                url = r.get("Microsoft_IE_TargetUrl") or percorso
                dati.update(url=url, visite=r.get("Microsoft_IE_VisitCount"), titolo=r.get("Microsoft_IE_Title"))
                A.add("indice", r.get("System_DateModified"), url,
                      "; ".join(x for x in (tr("Internet Explorer (indice di Ricerca di Windows)"),
                                            tr("{n} visite").format(n=dati["visite"]) if dati["visite"] else "",
                                            r.get("Microsoft_IE_Title") or "", date) if x), user, src, dati)
            elif store.startswith("mapi"):
                ts = r.get("System_Message_DateReceived") or r.get("System_Message_DateSent") or r.get("System_DateModified")
                testo = r.get("System_Search_AutoSummary") or ""
                da = _ws_persona(r.get("System_Message_FromName"), r.get("System_Message_FromAddress"))
                a = _ws_persona(r.get("System_Message_ToName"), r.get("System_Message_ToAddress"))
                dati.update(oggetto=r.get("System_Subject"), cartella=r.get("System_ItemFolderPathDisplay"), da=da, a=a,
                            inviato=r.get("System_Message_DateSent"), ricevuto=r.get("System_Message_DateReceived"),
                            allegati=r.get("System_Message_AttachmentNames"), testo=testo[:4000])
                A.add("indice", ts, r.get("System_Subject") or percorso,
                      "; ".join(x for x in (tr("Posta (indice di Ricerca di Windows)"), r.get("System_ItemFolderPathDisplay") or "",
                                            tr("da {v1}").format(v1=da) if da else "", tr("a {v1}").format(v1=a) if a else "",
                                            tr("allegati: {v1}").format(v1=dati["allegati"]) if dati["allegati"] else "",
                                            tr("testo: {v1}").format(v1=testo[:1500]) if testo else "") if x), user, src, dati)
            elif store.lower() == "stickynotes":
                testo = r.get("System_ItemName") or r.get("System_Search_AutoSummary") or ""
                if r.get("System_Kind") == "folder":
                    continue
                dati.update(testo=testo[:4000])
                A.add("indice", r.get("System_DateModified"), (testo or percorso)[:200],
                      "; ".join(x for x in (tr("Sticky Notes (indice di Ricerca di Windows)"), percorso, date) if x), user, src, dati)
            else:
                A.add("indice", r.get("System_DateModified"), percorso,
                      "; ".join(x for x in (tr("{v1} (indice di Ricerca di Windows)").format(v1=dati["tipo"] or store or tr("elemento")),
                                            tr("dimensione {v1}").format(v1=_nb(dati["dimensione"])) if dati["dimensione"] else "",
                                            date) if x), user, src, dati)
            n += 1
        A.add("sistema", None, tr("Ricerca di Windows: indice presente ({n} elementi)").format(n=len(righe)),
              "; ".join(x for x in (path + (tr(" (file cancellato)") if cancellato else ""),
                                    ", ".join(f"{k} {v}" for k, v in conta.most_common()),
                                    tr("log del database non applicati: le ultime modifiche possono mancare"), *avvisi) if x),
              "", src, {"fonte": "Windows Search", "elementi": len(righe), "contenuti": dict(conta), "avvisi": avvisi})
    return n


MOTORI_RICERCA = (("bing.", "q"), ("google.", "q"), ("yahoo.", "p"), ("duckduckgo.", "q"), ("yandex.", "text"),
                  ("baidu.", "wd"), ("ask.com", "q"), ("ecosia.", "q"))


def termine_ricerca(url):
    """(3.0.2) Parole cercate in un indirizzo di un motore di ricerca (anche nel frammento «#q=» di Google), o None."""
    import urllib.parse as up
    try:
        u = up.urlsplit(url)
    except ValueError:
        return None
    host = (u.hostname or "").lower()
    par = next((p for m, p in MOTORI_RICERCA if m in host), None)
    if not par or not any(s in u.path.lower() for s in ("search", "/s", "webhp", "/web")) and u.path not in ("", "/"):
        return None
    for parte in (u.fragment, u.query):           # il frammento vince: è la ricerca fatta nella pagina già aperta
        v = up.parse_qs(parte).get(par)
        if v and v[-1].strip():
            return v[-1].strip()[:300]
    return None


def win_webcache(A, ctx, part):
    """Cronologia di Internet Explorer 10/11 ed Edge legacy (WebCacheV01.dat): contenitori «History» (ultima visita,
    prima visita e numero di visite) e «MSHist01…» (una riga per giorno o settimana). Ore in UTC (AccessedTime)."""
    rows = fe.find_files(ctx.con, part, "%/appdata/local/microsoft/windows/webcache/webcachev01.dat")
    if not rows:
        return 0
    try:
        import forense_ese as fz
        import pyesedb  # noqa: F401
    except ImportError:
        A.add("web", None, tr("Cronologia di Internet Explorer non letta"), tr("manca il modulo pyesedb (libesedb)"), "", None)
        return 0
    n = 0
    for p, inode, _, path in rows[:50]:
        src, user = (p, inode, path), user_of(path)
        f = fe.fetch(ctx, p, inode, path, 4 << 30)
        if not f:
            continue
        try:
            visite, avvisi = fz.webcache(f)
        except Exception as e:
            A.add("web", None, tr("Cronologia di Internet Explorer non leggibile"), f"{type(e).__name__}: {e}", user, src)
            continue
        cercati = set()
        for v in visite:
            term = termine_ricerca(v["url"])
            if term and (term, v["ultima"]) not in cercati:      # (3.0.2) parole cercate, come per Chrome
                cercati.add((term, v["ultima"]))
                A.add("ricerche", v["ultima"], term, tr("{br}: ricerca web ({v1})").format(
                    br="Internet Explorer/Edge", v1=v["url"][:200]), user, src,
                      {"browser": "Internet Explorer/Edge", "url": v["url"], "fonte": "WebCacheV01.dat"})
            A.add("web", v["ultima"], v["url"],
                  "; ".join(x for x in (tr("Internet Explorer/Edge: {url}").format(url=v["url"]),
                                        tr("{n} visite").format(n=v["visite"]) if v["visite"] else "",
                                        tr("prima visita {v1}").format(v1=v["prima"].replace("T", " ")) if v["prima"] else "",
                                        tr("contenitore {v1}").format(v1=v["contenitore"])) if x), user, src,
                  {"browser": "Internet Explorer/Edge", "url": v["url"], "visite": v["visite"], "prima": v["prima"],
                   "contenitore": v["contenitore"], "fonte": "WebCacheV01.dat"})
            n += 1
        for a in avvisi:
            A.add("web", None, tr("Cronologia di Internet Explorer: {v1}").format(v1=a), "", user, src)
    return n


def _plum_ora(v):
    """Ora di plum.sqlite (Sticky Notes di Windows 10/11): tick .NET da 100 ns dall'anno 1."""
    try:
        v = int(v)
        return iso(dt.datetime(1, 1, 1) + dt.timedelta(microseconds=v // 10)) if v > 0 else None
    except (ValueError, TypeError, OverflowError):
        return None


def _plum_testo(t):
    # ogni riga comincia con «\id=<guid> »: si toglie
    return "\n".join(re.sub(r"^\\id=[0-9a-fA-F-]+\s?", "", r) for r in str(t or "").splitlines()).strip()


def win_sticky(A, ctx, part):
    """Sticky Notes: StickyNotes.snt (Windows 7-10 fino alla 1511, file OLE con una sotto-cartella per nota: testo nel
    flusso «3», RTF nel flusso «0», date della sotto-cartella) e plum.sqlite (Windows 10 dalla 1607 e 11, tabella Note)."""
    n = 0
    for p, inode, cancellato, path in fe.find_files(ctx.con, part, "%/appdata/roaming/microsoft/sticky notes/stickynotes.snt", True)[:20]:
        src, user = (p, inode, path), user_of(path)
        canc = tr(" (file cancellato)") if cancellato else ""
        f = fe.fetch(ctx, p, inode, path, 64 << 20)
        try:
            import pyolecf
            of = pyolecf.file()
            of.open(str(f))
        except Exception as e:
            A.add("note", None, tr("Sticky Notes: StickyNotes.snt non leggibile{c}").format(c=canc),
                  f"{type(e).__name__}: {e}" if f else "", user, src)
            continue
        try:
            for i in range(of.root_item.number_of_sub_items):
                it = of.root_item.get_sub_item(i)
                flussi = {it.get_sub_item(j).name: it.get_sub_item(j) for j in range(it.number_of_sub_items)}
                if "3" not in flussi and "0" not in flussi:
                    continue
                testo = ""
                if "3" in flussi:
                    testo = flussi["3"].read().decode("utf-16-le", "replace").replace("\x00", "").strip()
                if not testo and "0" in flussi:
                    rtf = flussi["0"].read().decode("latin-1", "replace")
                    testo = re.sub(r"\\[a-z]+-?\d* ?|[{}]", "", rtf).strip()
                mod = cre = None
                try:
                    mod = iso(it.get_modification_time())
                    cre = iso(it.get_creation_time())
                except Exception:
                    pass
                A.add("note", mod, testo[:200] or it.name,
                      "; ".join(x for x in (tr("Sticky Notes: nota {v1}{c}").format(v1=it.name, c=canc),
                                            tr("creata {v1}").format(v1=cre.replace("T", " ")) if cre else "",
                                            tr("modificata {v1}").format(v1=mod.replace("T", " ")) if mod else "",
                                            testo[:1500]) if x), user, src,
                      {"fonte": "StickyNotes.snt", "nota": it.name, "testo": testo[:4000], "creata": cre, "modificata": mod})
                n += 1
        finally:
            of.close()
    for p, inode, cancellato, path in fe.find_files(ctx.con, part, "%/appdata/local/packages/microsoft.microsoftstickynotes_%/localstate/plum.sqlite", True)[:20]:
        src, user = (p, inode, path), user_of(path)
        db, _wal = fe.fetch_sqlite(ctx, p, inode, path)
        if db is None:
            A.add("note", None, tr("Sticky Notes: plum.sqlite non leggibile"), "", user, src)
            continue
        try:
            cols = {c[1] for c in db.execute("PRAGMA table_info(Note)")}
            if "Text" not in cols:
                continue
            sel = [c for c in ("Id", "Text", "CreatedAt", "UpdatedAt", "DeletedAt", "IsOpen") if c in cols]
            for r in db.execute(f"SELECT {', '.join(sel)} FROM Note"):
                x = dict(zip(sel, r))
                testo, cre, mod = _plum_testo(x.get("Text")), _plum_ora(x.get("CreatedAt")), _plum_ora(x.get("UpdatedAt"))
                canc = _plum_ora(x.get("DeletedAt"))
                A.add("note", mod or cre, testo[:200] or str(x.get("Id") or ""),
                      "; ".join(y for y in (tr("Sticky Notes (plum.sqlite)"),
                                            tr("creata {v1}").format(v1=cre.replace("T", " ")) if cre else "",
                                            tr("modificata {v1}").format(v1=mod.replace("T", " ")) if mod else "",
                                            tr("cancellata {v1}").format(v1=canc.replace("T", " ")) if canc else "",
                                            testo[:1500]) if y), user, src,
                      {"fonte": "plum.sqlite", "nota": x.get("Id"), "testo": testo[:4000], "creata": cre, "modificata": mod,
                       "cancellata": canc})
                n += 1
        except sqlite3.Error as e:
            A.add("note", None, tr("Sticky Notes: plum.sqlite non leggibile"), f"{type(e).__name__}: {e}", user, src)
        finally:
            db.close()
    return n


def _ole_date(b):
    try:
        v = struct.unpack("<d", b[:8])[0]
        return iso(dt.datetime(1899, 12, 30) + dt.timedelta(days=v)) if 0 < v < 2958465 else None
    except (struct.error, OverflowError, ValueError, TypeError):
        return None


def _sid_from_bytes(b):
    try:
        rev, n = b[0], b[1]
        auth = int.from_bytes(b[2:8], "big")
        subs = struct.unpack_from(f"<{n}I", b, 8)
        return f"S-{rev}-{auth}" + "".join(f"-{s}" for s in subs)
    except (IndexError, struct.error):
        return None


def _nb(n):
    return f"{int(n):,} byte".replace(",", ".")


SRUM_APP = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
SRUM_NET = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"


def win_srum(A, ctx, part, users):
    """SRUM (SRUDB.dat, Windows 8+): uso delle app e traffico di rete per app e utente negli ultimi ~30-60 giorni.
    Richiede pyesedb (libesedb, incluso con plaso). Si riporta un riepilogo per app e utente."""
    rows = fe.fw(ctx, part, "windows/system32/sru/srudb.dat")
    if not rows:
        return
    try:
        import pyesedb
    except ImportError:
        A.add("sistema", None, tr("SRUM non letto"), tr("manca il modulo pyesedb (libesedb)"), "", None)
        return
    p, inode, _, path = rows[0]
    f = fe.fetch(ctx, p, inode, path, 4 << 30)
    if not f:
        return
    src = (p, inode, path)
    db = pyesedb.file()
    try:
        db.open(str(f))
    except Exception as e:
        A.add("sistema", None, tr("SRUM non leggibile"), f"{type(e).__name__}: {e}", "", src)
        return
    try:
        tables = {}
        for i in range(db.number_of_tables):
            t = db.get_table(i)
            tables[t.name] = t

        def records(t):
            cols = [(t.get_column(j).name, t.get_column(j).type) for j in range(t.number_of_columns)]
            for i in range(t.number_of_records):
                try:
                    r = t.get_record(i)
                except Exception:
                    continue
                out = {}
                for j, (cn, ct) in enumerate(cols):
                    try:
                        if ct in (7, 8):                       # double / data OLE
                            out[cn] = r.get_value_data(j)
                        elif ct in (1, 2, 3, 4, 5, 14, 15, 17):
                            out[cn] = r.get_value_data_as_integer(j)
                        else:
                            out[cn] = r.get_value_data(j)
                    except Exception:
                        out[cn] = None
                yield out
        ids = {}
        if "SruDbIdMapTable" in tables:
            for r in records(tables["SruDbIdMapTable"]):
                blob = r.get("IdBlob")
                if r.get("IdIndex") is None or not isinstance(blob, (bytes, bytearray)):
                    continue
                ids[r["IdIndex"]] = _sid_from_bytes(blob) if r.get("IdType") == 3 else \
                    blob.decode("utf-16-le", "replace").rstrip("\x00")
        agg = {}
        for tname, kind in ((SRUM_APP, "app"), (SRUM_NET, "rete")):
            t = tables.get(tname)
            if t is None:
                continue
            for r in records(t):
                ts = _ole_date(r.get("TimeStamp") or b"") if isinstance(r.get("TimeStamp"), (bytes, bytearray)) else None
                app, sid = ids.get(r.get("AppId"), f"id {r.get('AppId')}"), ids.get(r.get("UserId"), f"id {r.get('UserId')}")
                a = agg.setdefault((app, sid), {"campioni": 0, "primo": None, "ultimo": None, "letti": 0, "scritti": 0,
                                                "inviati": 0, "ricevuti": 0})
                a["campioni"] += 1
                if ts:
                    a["primo"] = min(a["primo"] or ts, ts)
                    a["ultimo"] = max(a["ultimo"] or ts, ts)
                if kind == "app":
                    a["letti"] += (r.get("ForegroundBytesRead") or 0) + (r.get("BackgroundBytesRead") or 0)
                    a["scritti"] += (r.get("ForegroundBytesWritten") or 0) + (r.get("BackgroundBytesWritten") or 0)
                else:
                    a["inviati"] += r.get("BytesSent") or 0
                    a["ricevuti"] += r.get("BytesRecvd") or 0
        for (app, sid), a in agg.items():
            user = users.get(sid, sid) if sid else ""
            A.add("uso", a["ultimo"], app, "; ".join(x for x in (
                tr("SRUM: {campioni} rilevazioni orarie dal {v1} al {v2}").format(campioni=a['campioni'], v1=(a['primo'] or '?').replace('T', ' '), v2=(a['ultimo'] or '?').replace('T', ' ')),
                tr("disco: letti {v1}, scritti {v2}").format(v1=_nb(a['letti']), v2=_nb(a['scritti'])) if a["letti"] or a["scritti"] else "",
                tr("rete: inviati {v1}, ricevuti {v2}").format(v1=_nb(a['inviati']), v2=_nb(a['ricevuti'])) if a["inviati"] or a["ricevuti"] else "",
                tr("utente {user}").format(user=user) if user else "") if x), user, src, {"fonte": "SRUM", **a, "sid": sid})
    finally:
        db.close()


EVTX_USERDATA_RE = re.compile(r"<UserData>(.*?)</UserData>", re.S)
EVTX_DATA_NONAME_RE = re.compile(r"<Data>([^<]*)</Data>")
EVTX_LEAF_RE = re.compile(r"<(\w+)>([^<]*)</\1>")
EVT_LOGS = "windows/system32/winevt/logs/"
# (file, {id: (categoria, descrizione)}, provider richiesto o None)
EVT_RULES = [
    ("security.evtx", {1102: ("eventi", N_("registro di sicurezza CANCELLATO")),
                       # (3.0.2) avvio e chiusura dal registro di sicurezza, uscite degli utenti (NIST Data Leakage, domanda 12)
                       4608: ("eventi", N_("avvio di Windows")),
                       1100: ("eventi", N_("chiusura del servizio registro eventi (spegnimento)")),
                       4634: ("eventi", N_("uscita dalla sessione")),
                       4647: ("eventi", N_("uscita richiesta dall'utente"))}, None),
    ("system.evtx", {104: ("eventi", N_("registro eventi cancellato")), 7045: ("eventi", N_("servizio installato")),
                     6005: ("eventi", N_("avvio del servizio registro eventi (accensione)")),
                     6006: ("eventi", N_("arresto del servizio registro eventi (spegnimento)")),
                     1074: ("eventi", N_("spegnimento o riavvio richiesto")),
                     6008: ("eventi", N_("spegnimento imprevisto")),
                     # (3.0.2) driver di dispositivi installati (UserPnp: chiavette, dischi, lettori) e unità CD/DVD
                     # usata per masterizzare con Windows (cdrom 133: le risposte NIST scrivono 113, ma sul PC del caso
                     # gli eventi sono 133, uno per masterizzazione, agli orari indicati da NIST): domande 22 e 32-33
                     20001: ("usb", N_("driver di un dispositivo installato")),
                     20003: ("usb", N_("servizio di un dispositivo aggiunto")),
                     133: ("dispositivi", N_("unità CD/DVD: evento registrato durante la masterizzazione"))}, None),
    ("microsoft-windows-terminalservices-localsessionmanager\\%4operational.evtx",
     {21: ("eventi", N_("sessione aperta (anche Desktop remoto)")), 24: ("eventi", N_("sessione disconnessa")),
      25: ("eventi", N_("sessione riconnessa"))}, None),
    ("microsoft-windows-terminalservices-remoteconnectionmanager\\%4operational.evtx",
     {1149: ("eventi", N_("Desktop remoto: autenticazione di rete riuscita"))}, None),
    ("microsoft-windows-windows defender\\%4operational.evtx",
     {1116: ("eventi", N_("Defender: minaccia rilevata")), 1117: ("eventi", N_("Defender: azione sulla minaccia")),
      5001: ("eventi", N_("Defender: protezione in tempo reale DISATTIVATA"))}, None),
    ("microsoft-windows-partition\\%4diagnostic.evtx", {1006: ("usb", N_("disco collegato o scollegato"))}, None),
]


def evtx_fields(xml):
    d = {k: html.unescape(v) for k, v in EVTX_DATA_RE.findall(xml)}
    for i, v in enumerate(EVTX_DATA_NONAME_RE.findall(xml), 1):      # (3.0.2) campi senza nome (es. cdrom 133)
        d.setdefault(f"Data{i}", html.unescape(v))
    m = EVTX_USERDATA_RE.search(xml)
    if m:
        for k, v in EVTX_LEAF_RE.findall(m.group(1)):
            d.setdefault(k, html.unescape(v))
    return d


def win_eventi(A, ctx, part):
    """Eventi di interesse dai registri di Windows: cancellazione dei registri, servizi installati, accensioni e
    spegnimenti, sessioni e Desktop remoto (con indirizzo), rilevamenti di Defender, dischi collegati."""
    try:
        import pyevtx  # noqa: F401
    except ImportError:
        A.add("sistema", None, tr("Eventi di sistema non letti"),
              tr("manca il modulo pyevtx (libevtx): servizi, accensioni, sessioni, Defender e dischi USB dai registri "
              "eventi non sono negli artefatti"), "", None)
        return
    for fname, rules, _prov in EVT_RULES:
        rows = fe.hive_rows(ctx, part, EVT_LOGS + fname)
        if not rows:
            continue
        p, inode, _, path = rows[0]
        f = fe.fetch(ctx, p, inode, path)
        if not f:
            A.add("sistema", None, tr("Registro eventi {name} non estratto").format(name=Path(path).name),
                  tr("il file non si legge dalla copia: i suoi eventi non sono negli artefatti"), "", (p, inode, path))
            continue
        st = {}
        try:
            evs = fe.evtx_records(f, set(rules), raw=True, stats=st)
        except Exception as e:
            A.add("sistema", None, tr("Registro eventi {name} non leggibile").format(name=Path(path).name), f"{type(e).__name__}: {e}", "",
                  (p, inode, path))
            continue
        n_rec = sum(1 for ev in evs if ev[4])
        A.add("sistema", None, tr("Registro eventi {name}: eventi di sistema letti").format(name=Path(path).name),
              tr("{v1} eventi utili ({v2})").format(v1=len(evs), v2=', '.join(str(i) for i in sorted(rules)))
              + (tr(", di cui {n_rec} da record recuperati").format(n_rec=n_rec) if n_rec else "") + f"; {evtx_stato(st)}"
              + (tr("; LIMITE RAGGIUNTO: negli artefatti i primi 20000 eventi in ordine di record, {v1} esclusi").format(v1=len(evs) - 20000) if len(evs) > 20000 else ""), "", (p, inode, path),
              {"eventi": len(evs), "da_record_recuperati": n_rec, "esclusi_per_limite": max(0, len(evs) - 20000), **st})
        for eid, t, prov, xml, recuperato in evs[:20000]:
            d = evtx_fields(xml)
            cat, desc = rules[eid]
            desc = tr(desc)
            if eid in (6005, 6006, 104, 1100) and "eventlog" not in prov.lower():
                continue
            if eid == 1074 and "user32" not in prov.lower():
                continue
            if eid in (4608, 4634, 4647) and "security-auditing" not in prov.lower():
                continue
            if eid in (20001, 20003) and "userpnp" not in prov.lower():
                continue
            if eid == 133 and "cdrom" not in prov.lower():
                continue
            if eid == 4634 and d.get("LogonType") not in ("2", "7", "10", "11"):
                continue        # uscite delle sessioni di rete e di servizio: migliaia, non sono uscite di una persona
            ts = filetime(t)
            if eid == 7045:
                title = tr("Servizio installato: {v1}").format(v1=d.get('ServiceName', '?'))
                det = tr("{v1} · avvio {v2} · account {v3}").format(v1=d.get('ImagePath', ''), v2=d.get('StartType', ''), v3=d.get('AccountName', ''))
            elif eid == 1074:
                title = tr("Spegnimento/riavvio richiesto")
                det = "; ".join(x for x in (d.get("param1"), d.get("param3"), d.get("param5"), d.get("param7"),
                                            d.get("param6")) if x)
            elif eid in (4634, 4647):
                title = tr("Uscita: {v1}").format(v1=d.get("TargetUserName", "?"))
                det = "; ".join(x for x in (tr("tipo di accesso {v1}").format(v1=d["LogonType"]) if d.get("LogonType") else "",
                                            tr("dominio {v1}").format(v1=d["TargetDomainName"]) if d.get("TargetDomainName") else "",
                                            tr("sessione {v1}").format(v1=d["TargetLogonId"]) if d.get("TargetLogonId") else "") if x)
            elif eid in (20001, 20003):
                dev = d.get("DeviceInstanceID") or d.get("DeviceInstanceId") or "?"
                title = (tr("Driver installato: {v1}") if eid == 20001 else tr("Servizio del dispositivo aggiunto: {v1}")).format(v1=dev)
                det = "; ".join(f"{k} {d[k]}" for k in ("DriverName", "DriverVersion", "DriverProvider", "SetupClass", "ServiceName",
                                                         "DriverFileName", "InstallStatus", "AddServiceStatus") if d.get(k))
            elif eid == 133:
                title = tr("Unità CD/DVD usata per masterizzare")
                det = "; ".join(v for k, v in d.items() if v)[:300]
            elif eid in (21, 24, 25):
                title = tr("Sessione {v1}: {v2}").format(v1=d.get('User', '?'), v2=desc.split(' (')[0].replace(tr('sessione '), ''))
                det = tr("indirizzo {v1} · sessione {v2}").format(v1=d.get('Address', ''), v2=d.get('SessionID', ''))
            elif eid == 1149:
                title = tr("Desktop remoto: {v1}").format(v1=d.get('Param1', '?'))
                det = tr("dominio {v1} · indirizzo di origine {v2}").format(v1=d.get('Param2', ''), v2=d.get('Param3', ''))
            elif eid in (1116, 1117):
                title = f"{desc}: {d.get('Threat Name', '?')}"
                det = "; ".join(x for x in (d.get("Path"), d.get("Detection User"), d.get("Action Name"),
                                            d.get("Process Name")) if x)
            elif eid == 1006:
                title = tr("Disco {v1} {v2}").format(v1=(d.get('Manufacturer') or '').strip(), v2=(d.get('Model') or '').strip()).strip()
                det = "; ".join(x for x in (f"seriale {d.get('SerialNumber')}" if d.get("SerialNumber") else "",
                                            tr("capacità {v1} byte").format(v1=d.get('Capacity')) if d.get("Capacity") not in (None, "0") else
                                            tr("capacità 0 (scollegato)"), d.get("ParentId") or "") if x)
            else:
                title = desc[0].upper() + desc[1:]
                det = "; ".join(f"{k} {v}" for k, v in list(d.items())[:6] if v)
            A.add(cat, ts, title + (tr(" (record recuperato)") if recuperato else ""),
                  tr("{name} evento {eid}: {desc}").format(name=Path(path).name, eid=eid, desc=desc) + (f"; {det}" if det else "")
                  + (tr("; record recuperato dallo spazio libero del registro (non più tra gli eventi attivi)")
                     if recuperato else ""), "",
                  (p, inode, path), {"fonte": Path(path).name, "evento": eid, "recuperato": bool(recuperato),
                                     **{k: v for k, v in list(d.items())[:20]}})


def win_usn(A, ctx, part, progress=None):
    """Journal NTFS ($Extend/$UsnJrnl:$J): file creati, cancellati e rinominati con data, anche se il record MFT è
    stato riutilizzato. I percorsi delle cartelle si ricostruiscono dalla MFT e dal journal stesso. Un journal assente
    o non leggibile è dichiarato tra gli artefatti di sistema: «nessuna operazione» non vale come «journal vuoto»."""
    hr = getattr(ctx, "hr", None) or HeadReader(ctx.case)
    ctx.hr = hr
    if not hr.is_ntfs(part):
        return 0
    src = (part, None, "/$Extend/$UsnJrnl:$J")
    fs = hr._fs(part)
    if fs is None:
        A.add("sistema", None, tr("Journal NTFS non letto"),
              tr("il volume non si apre con Sleuth Kit (pytsk3): le operazioni del journal $UsnJrnl non sono state lette"),
              "", src, {"journal": "non_letto"})
        return 0
    try:
        f = fs.open("/$Extend/$UsnJrnl")
    except Exception as e:
        if "not found" in str(e).lower() or "unable to find" in str(e).lower():
            A.add("sistema", None, tr("Journal NTFS assente"),
                  tr("nel volume non c'è $Extend/$UsnJrnl (journal disattivato o cancellato): nessuna operazione su file "
                  "ricavabile dal journal"), "", src, {"journal": "assente"})
        else:
            A.add("sistema", None, tr("Journal NTFS non letto"), tr("$Extend/$UsnJrnl non si apre: {vname}: {e}").format(vname=type(e).__name__, e=e),
                  "", src, {"journal": "non_letto", "errore": str(e)[:300]})
        return 0
    pt = hr.pytsk3
    attr = None
    for a in f:
        nm = a.info.name
        nm = nm.decode("utf-8", "ignore") if isinstance(nm, bytes) else (nm or "")
        if nm == "$J" and int(a.info.type) == int(pt.TSK_FS_ATTR_TYPE_NTFS_DATA):
            attr = a
            break
    if attr is None:
        A.add("sistema", None, tr("Journal NTFS assente"),
              tr("$Extend/$UsnJrnl esiste ma non ha il flusso $J (journal disattivato): nessuna operazione su file "
              "ricavabile dal journal"), "", src, {"journal": "assente"})
        return 0
    bs = fs.info.block_size
    size = int(attr.info.size)
    runs = []
    for r in attr:
        if int(r.flags) & (int(pt.TSK_FS_ATTR_RUN_FLAG_SPARSE) | int(pt.TSK_FS_ATTR_RUN_FLAG_FILLER)) or not r.len:
            continue
        runs.append((int(r.offset) * bs, int(r.len) * bs))

    def read(off, n):
        return f.read_random(off, n, attr.info.type, attr.info.id)

    def seq_of(rec):
        try:
            m = fs.open_meta(inode=rec).info.meta
            return int(m.seq), bool(int(m.flags) & int(pt.TSK_FS_META_FLAG_ALLOC))
        except Exception:
            return None
    return usn_to_artifacts(A, ctx, part, runs, size, read, progress, seq_of=seq_of)


def usn_dirs(con, part):
    """{record MFT: percorso} delle cartelle del volume (dall'elenco dei file); a parità di record vince la voce
    presente, non quella cancellata (il nome cancellato può puntare a un record poi riutilizzato)."""
    out = {}
    for inode, path in con.execute("SELECT inode, path FROM files WHERE part=? AND type LIKE 'd%' "
                                   "ORDER BY deleted", (part,)):
        try:
            out.setdefault(int(str(inode).split("-")[0]), path)
        except ValueError:
            pass
    out.setdefault(5, "")
    return out


USN_KEEP = 0x100 | 0x200 | 0x2000


def usn_to_artifacts(A, ctx, part, runs, size, read, progress=None, limit=500000, seq_of=None):
    """Operazioni del journal come artefatti. Le cartelle si cercano per riferimento completo (record MFT e numero di
    sequenza): il percorso attuale della MFT vale solo se il record è ancora quella cartella (`seq_of(record)` →
    (sequenza, allocato) o None; un record libero ha la sequenza aumentata di 1 alla cancellazione), altrimenti il
    nome registrato nel journal per quel riferimento, altrimenti «cartella MFT n» dichiarando il riutilizzo.
    Oltre `limit` operazioni si tengono le più recenti e il taglio è dichiarato tra gli artefatti di sistema."""
    dirs = usn_dirs(ctx.con, part)
    jdirs = {}                  # cartelle viste nel journal: (record, sequenza) -> (nome, (record, sequenza) del padre)
    old = {}                    # (record, sequenza) -> ultimo nome vecchio (rinomina)
    rows = deque(maxlen=limit)
    seqs = {}
    st = {"totale": 0, "riutilizzati": set(), "non_verificati": set(), "letti": 0}

    def same(rec, seq):
        """True se il record `rec` è oggi la stessa cartella del riferimento con sequenza `seq`; None se non si sa."""
        if rec == 5:
            return True
        if seq_of is None or not seq:
            return None
        if rec not in seqs:
            seqs[rec] = seq_of(rec)
        c = seqs[rec]
        if c is None:
            return None
        cur, alloc = c
        return cur == seq or (not alloc and cur == (seq + 1) & 0xFFFF)

    def resolve(ref, depth=0):
        rec, seq = ref
        ok = same(rec, seq) if rec in dirs else False
        if ok:
            return dirs[rec]
        if ref in jdirs and depth < 64:
            nm, par = jdirs[ref]
            base = resolve(par, depth + 1)
            return (base + "/" if base else "") + nm
        if rec in dirs and ok is None:          # sequenza non verificabile: percorso della MFT, dichiarato
            st["non_verificati"].add(ref)
            return dirs[rec]
        if rec in dirs:
            st["riutilizzati"].add(ref)
            return tr("<cartella MFT {rec} sequenza {seq}: record poi riutilizzato da {v1}>").format(rec=rec, seq=seq, v1=dirs[rec] or '/')
        return tr("<cartella MFT {rec}>").format(rec=rec)
    done = 0
    for off, ln in runs:
        pos = off
        end = min(off + ln, size)
        while pos < end:
            n = min(16 << 20, end - pos)
            buf = read(pos, n)
            if not buf:
                break
            for r in usn_records(buf):
                st["letti"] += 1
                if r["attr"] & 0x10:
                    jdirs[r["file"]] = (r["nome"], r["padre"])
                if r["reason"] & 0x1000:
                    old[r["file"]] = (r["nome"], r["padre"])
                if r["reason"] & 0x80000000 and r["reason"] & USN_KEEP:
                    st["totale"] += 1
                    # (3.0.2) il nome vecchio di QUESTA rinomina (l'ultimo visto prima del record di chiusura): un file
                    # rinominato più volte prendeva per tutte le rinomine il nome vecchio dell'ultima
                    if r["reason"] & 0x2000:
                        r["vecchio"] = old.get(r["file"])
                    rows.append(r)
            pos += n
            done += n
            if progress:
                progress(done)
    for r in rows:
        parent = resolve(r["padre"])
        path = (parent + "/" if parent else "") + r["nome"]
        what = []
        if r["reason"] & 0x100:
            what.append("creato")
        if r["reason"] & 0x200:
            what.append("cancellato")
        if r["reason"] & 0x2000:
            o = r.get("vecchio")
            if o:
                b = resolve(o[1])
            what.append("rinominato" + (tr(" (prima: {v1})").format(v1=(b + '/' if b else '') + o[0]) if o else ""))
        A.add("journal", r["ts"], path, "; ".join(what) + tr(" · {v1} · motivi registrati: {v2} · record MFT {v3} (sequenza {v4}) · USN {usn}").format(v1='cartella' if r['attr'] & 0x10 else 'file', v2=usn_reason_text(r['reason']), v3=r['file'][0], v4=r['file'][1], usn=r['usn']),
              user_of(path), None, {"fonte": "$UsnJrnl", "usn": r["usn"], "mft": r["file"], "padre": r["padre"],
                                     "reason": r["reason"], "attr": r["attr"]})
    tss = [r["ts"] for r in rows if r["ts"]]
    dal, al = (min(tss), max(tss)) if tss else (None, None)
    esclusi = st["totale"] - len(rows)
    det = [tr("{v1} operazioni su file (create, cancellate, rinominate) dal {v2} al {v3} (UTC), su "
              "{letti} record del journal").format(v1=len(rows), v2=(dal or '?').replace('T', ' '), v3=(al or '?').replace('T', ' '), letti=st['letti'])]
    if esclusi:
        det.append(tr("LIMITE RAGGIUNTO: le operazioni erano {totale}, tenute le {v1} più recenti; le {esclusi} "
                      "più vecchie (prima del {v2}) non sono negli artefatti").format(totale=st['totale'], v1=len(rows), esclusi=esclusi, v2=(dal or '?').replace('T', ' ')))
    if st["riutilizzati"]:
        det.append(tr("{v1} cartelle con il record MFT poi riutilizzato da un'altra cartella: indicate come "
                      "«cartella MFT n sequenza s», non con il percorso attuale").format(v1=len(st['riutilizzati'])))
    if st["non_verificati"]:
        det.append(tr("{v1} cartelle con il numero di sequenza non verificabile: percorso preso dalla MFT, da "
                      "confermare").format(v1=len(st['non_verificati'])))
    A.add("sistema", al, tr("Journal NTFS $UsnJrnl letto"), "; ".join(det), "", (part, None, "/$Extend/$UsnJrnl:$J"),
          {"journal": "letto", "operazioni": len(rows), "operazioni_totali": st["totale"], "escluse_per_limite": esclusi,
           "limite": limit, "dal": dal, "al": al, "cartelle_record_riutilizzato": len(st["riutilizzati"]),
           "cartelle_sequenza_non_verificata": len(st["non_verificati"])})
    return len(rows)


def win_thumbcache(A, ctx, part):
    """Miniature della cache di Esplora file (thumbcache_*.db): restano anche dopo la cancellazione delle immagini.
    Si estraggono in estratti/miniature, in sola lettura e con gli hash, tra i file estratti (tipo «miniatura»)."""
    rows = fe.find_files(ctx.con, part, "%/appdata/local/microsoft/windows/explorer/thumbcache\\_%.db")
    case, con = ctx.case, ctx.con
    n_tot = 0
    for p, inode, deleted, path in rows:
        if Path(path).name.lower() in ("thumbcache_idx.db",):
            continue
        f = fe.fetch(ctx, p, inode, path, 2 << 30)
        if not f:
            continue
        try:
            ents = thumbcache_entries(f.read_bytes())
        except Exception:
            ents = []
        user = user_of(path)
        for h, ext, blob, w, ht in ents:
            name = f"{h}.{ext}"
            vpath = f"{path}/{name}"
            xid = new_xitem(con, kind="miniatura", part=p, inode=inode, src_path=path, path=vpath, name=name,
                            size=len(blob), note=tr("miniatura {w}x{ht}").format(w=w, ht=ht) if w else "miniatura", store=user, deleted=deleted)
            tmp = ctx.tmp / f"t_{xid}"
            tmp.write_bytes(blob)
            n, md5, sha1, sha256 = hashes_of(tmp)
            rel = store_extracted(case, tmp, "miniature", xid, name)
            con.execute("UPDATE xitems SET relpath=?, md5=?, sha1=?, sha256=?, size=? WHERE id=?",
                        (rel, md5, sha1, sha256, n, xid))
            n_tot += 1
        if ents:
            A.add("recenti", None, tr("Cache delle miniature: {name}").format(name=Path(path).name),
                  tr("{v1} miniature estratte (in File estratti, tipo «miniatura»): immagini e video visti in "
                     "Esplora file, anche se poi cancellati").format(v1=len(ents)), user, (p, inode, path), {"fonte": "thumbcache", "miniature": len(ents)})
        fe.togli(f)
    return n_tot
