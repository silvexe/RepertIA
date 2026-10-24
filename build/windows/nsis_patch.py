# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Ricostruisce un installer NSIS 3 (Unicode, LZMA solido) sostituendo alcuni file, senza makensis.
Uso: python3 nsis_patch.py vecchio.exe nuovo.exe VER_VECCHIA VER_NUOVA percorso_rel=file_nuovo ...
  percorso_rel come nell'installazione, es. RepertIA/forense_agent.py
Il programma d'installazione (stub, script compilato, pagine) resta identico: cambiano i dati dei file indicati,
gli offset dei dati che seguono, le stringhe con la versione e la risorsa di versione dell'eseguibile."""
import lzma, struct, sys, zlib
sys.path.insert(0, ".")
import nsis_x as N

EW_WRITEUNINSTALLER = None      # trovato dall'analisi (istruzione con offset di dati)


def parse(exe_bytes):
    import io
    f = io.BytesIO(exe_bytes)
    off, flags, hlen, total = N.find_first_header(f)
    f.seek(off + 28)
    props = exe_bytes[off + 28:off + 33]
    st = N.Stream(f)
    n = struct.unpack("<I", st.read(4))[0]
    head = bytearray(st.read(hlen))
    blocks = []                         # (offset relativo ai dati, contenuto)
    pos = 0
    while True:
        h = st.read(4)
        if len(h) < 4:
            break
        size = struct.unpack("<I", h)[0]
        data = st.read(size & 0x7FFFFFFF)
        blocks.append((pos, size, data))
        pos += 4 + len(data)
    return off, flags, hlen, total, props, head, blocks


def main(old, new, vold, vnew, repl):
    exe = open(old, "rb").read()
    off, flags, hlen, total, props, head, blocks = parse(exe)
    end = off + total
    print(f"firstheader {off}, flags {flags:#x}, header {hlen}, totale {total}, file {len(exe)}, blocchi {len(blocks)}")
    # CRC: NSIS calcola il CRC32 dall'inizio del file fino a prima degli ultimi 4 byte dei dati
    fcrc = struct.unpack("<I", exe[end - 4:end])[0]
    c_all = zlib.crc32(exe[512:end - 4])           # NSIS 3: dal byte 512
    print("CRC nel file", hex(fcrc), "calcolato", hex(c_all), "OK" if c_all == fcrc else "DIVERSO")
    if c_all != fcrc:
        raise SystemExit("schema del CRC non riconosciuto: mi fermo")
    starts = {b[0]: i for i, b in enumerate(blocks)}
    # istruzioni e stringhe
    bl = [struct.unpack_from("<II", head, 4 + 8 * k) for k in range(8)]
    e_off, e_num = bl[2]
    s_off = bl[3][0]
    s_end = bl[4][0]
    strings = bytes(head[s_off:s_end])
    vmap = {21: "$INSTDIR", 31: "$INSTDIR"}
    outdir = None
    target = {}                         # offset blocco -> percorso relativo
    refs = []                           # (posizione nell'intestazione del parametro con un offset di dati)
    for k in range(e_num):
        base = e_off + 28 * k
        which, *p = struct.unpack_from("<7i", head, base)
        if which == N.EW_CREATEDIR and p[1]:
            outdir = N.nsis_string(strings, p[0], vmap)
        elif which == N.EW_EXTRACTFILE:
            name = N.nsis_string(strings, p[1], vmap)
            if p[2] not in starts:
                raise SystemExit(f"offset {p[2]} di {name} non è l'inizio di un blocco")
            refs.append(base + 4 + 4 * 2)
            if outdir and outdir.startswith("$INSTDIR"):
                rel = (outdir[len("$INSTDIR"):].strip("\\") + "\\" + name).strip("\\").replace("\\", "/")
                target.setdefault(p[2], []).append(rel)
    # altre istruzioni che puntano ai dati: WriteUninstaller (parametri che coincidono con inizi di blocco non usati da File)
    used = {struct.unpack_from("<i", head, r)[0] for r in refs}
    others = [b[0] for b in blocks if b[0] not in used]
    print("blocchi non usati da File:", len(others), others[:10])
    for k in range(e_num):
        base = e_off + 28 * k
        which, *p = struct.unpack_from("<7i", head, base)
        if which == N.EW_EXTRACTFILE:
            continue
        for j, v in enumerate(p):
            if v in others and v > 0:
                print(f"  istruzione {which} parametro {j} = {v} (blocco di dati)")
                refs.append(base + 4 + 4 * j)
    # sostituzioni
    want = dict(repl)
    hit = {}
    for o, rels in target.items():
        for r in rels:
            if r in want:
                if len(rels) > 1:
                    raise SystemExit(f"il blocco di {r} è condiviso con {rels}: non lo tocco")
                hit[o] = r
    missing = set(want) - set(hit.values())
    if missing:
        raise SystemExit(f"file non trovati nell'installer: {missing}")
    remap, pos, sizes = {}, 0, {}
    for o, size, data in blocks:
        if o in hit:
            sizes[o] = len(open(want[hit[o]], "rb").read())
            print(f"  sostituito {hit[o]}: {len(data)} -> {sizes[o]} byte")
        remap[o] = pos
        pos += 4 + sizes.get(o, len(data))
    for r in refs:
        v = struct.unpack_from("<i", head, r)[0]
        struct.pack_into("<i", head, r, remap[v])
    import os
    if os.environ.get("PROVA"):
        raise SystemExit("prova: mi fermo prima di comprimere")
    # versione nelle stringhe (UTF-16, stessa lunghezza)
    sv_old, sv_new = vold.encode("utf-16-le"), vnew.encode("utf-16-le")
    assert len(sv_old) == len(sv_new)
    s = bytes(head[s_off:s_end])
    nver = s.count(sv_old)
    head[s_off:s_end] = s.replace(sv_old, sv_new)
    print(f"stringhe con la versione: {nver}")
    # stub: risorsa di versione (testi e VS_FIXEDFILEINFO)
    # lo stub NON si modifica: il disinstallatore viene ricostruito da Windows copiandolo, con un CRC calcolato
    # da makensis sullo stub originale; cambiare anche solo la risorsa di versione renderebbe Disinstalla.exe «corrotto»
    stub = exe[:off]
    # ricompressione
    lc_lp_pb = props[0]
    lc, rem = lc_lp_pb % 9, lc_lp_pb // 9
    lp, pb = rem % 5, rem // 5
    dict_size = struct.unpack("<I", props[1:5])[0]
    comp = lzma.LZMACompressor(lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb,
                                                         "dict_size": dict_size, "preset": 6}])
    parts = [props, comp.compress(struct.pack("<I", hlen) + bytes(head))]
    for k, (o, size, data) in enumerate(blocks):
        if o in hit:
            data = open(want[hit[o]], "rb").read()
            size = len(data)
        parts.append(comp.compress(struct.pack("<I", size) + data))
        blocks[k] = None
        if k % 1000 == 0:
            print(f"  compressi {k}/{len(blocks)}", flush=True)
    parts.append(comp.flush())
    body = b"".join(parts)
    new_total = 28 + len(body) + 4
    fh = bytearray(exe[off:off + 28])
    struct.pack_into("<I", fh, 24, new_total)
    out = bytes(stub) + bytes(fh) + body
    out += struct.pack("<I", zlib.crc32(out[512:]))
    out += exe[end:]                    # eventuali dati dopo (di solito nessuno)
    open(new, "wb").write(out)
    print(f"scritto {new}: {len(out)} byte (prima {len(exe)})")


if __name__ == "__main__":
    a = sys.argv
    main(a[1], a[2], a[3], a[4], [x.split("=", 1) for x in a[5:]])
