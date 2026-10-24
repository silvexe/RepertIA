# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Estrae un installer NSIS 3 Unicode con compressione LZMA solida (SetCompressor /SOLID lzma), senza 7-Zip.
Uso: python3 nsis_x.py Setup.exe cartella_uscita
Ricostruisce i percorsi dalle istruzioni SetOutPath/File dello script compilato ($INSTDIR -> cartella_uscita)."""
import lzma, os, struct, sys

EW_CREATEDIR, EW_EXTRACTFILE = 11, 20
NB_ENTRIES, NB_STRINGS = 2, 3


def find_first_header(f):
    f.seek(0, 2)
    size = f.tell()
    off = 0
    while off < size:
        f.seek(off)
        b = f.read(28)
        if len(b) == 28 and b[4:20] == b"\xef\xbe\xad\xdeNullsoftInst":
            flags, _, hlen, total = struct.unpack("<I16sII", b)
            return off, flags, hlen, total
        off += 512
    raise SystemExit("intestazione NSIS non trovata")


class Stream:
    """Flusso decompresso letto in sequenza (LZMA grezzo con proprietà NSIS di 5 byte)."""
    def __init__(self, f):
        props = f.read(5)
        d = props[0]
        lc, rem = d % 9, d // 9
        lp, pb = rem % 5, rem // 5
        dict_size = struct.unpack("<I", props[1:5])[0]
        self.f = f
        self.dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[
            {"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": dict_size}])
        self.buf = bytearray()
        self.pos = 0                    # posizione assoluta (byte già consegnati)

    def _fill(self, n):
        while len(self.buf) < n:
            if self.dec.eof:
                break
            chunk = self.f.read(1 << 20) if self.dec.needs_input else b""
            if self.dec.needs_input and not chunk:
                break
            self.buf += self.dec.decompress(chunk, max_length=8 << 20)

    def read(self, n):
        self._fill(n)
        out = bytes(self.buf[:n])
        del self.buf[:n]
        self.pos += len(out)
        return out

    def skip(self, n):
        while n > 0:
            k = min(n, 8 << 20)
            got = self.read(k)
            if not got:
                raise EOFError
            n -= len(got)


def nsis_string(strings, idx, vars_map):
    """Stringa Unicode dalla tabella (idx in caratteri), con i codici speciali di NSIS 3."""
    out, i = [], idx
    while True:
        c = struct.unpack_from("<H", strings, 2 * i)[0]
        i += 1
        if c == 0:
            break
        if c in (1, 2, 3):              # LANG, SHELL, VAR: segue un parametro di un carattere
            p = struct.unpack_from("<H", strings, 2 * i)[0]
            i += 1
            if c == 3:
                n = (p & 0x7F) | (((p >> 8) & 0x7F) << 7)
                out.append(vars_map.get(n, "${VAR%d}" % n))
            elif c == 2:
                out.append("${SHELL%d}" % p)
            else:
                out.append("${LANG%d}" % p)
        elif c == 4:                    # SKIP: il carattere seguente è letterale
            out.append(chr(struct.unpack_from("<H", strings, 2 * i)[0]))
            i += 1
        else:
            out.append(chr(c))
    return "".join(out)


def main(exe, dest):
    f = open(exe, "rb")
    off, flags, hlen, total = find_first_header(f)
    f.seek(off + 28)
    st = Stream(f)
    n = struct.unpack("<I", st.read(4))[0]
    assert n == hlen, (n, hlen)
    head = st.read(hlen)
    data0 = st.pos                      # gli offset dei file contano da qui
    blocks = [struct.unpack_from("<II", head, 4 + 8 * k) for k in range(8)]
    e_off, e_num = blocks[NB_ENTRIES]
    s_off = blocks[NB_STRINGS][0]
    strings = head[s_off:blocks[NB_STRINGS + 1][0]] if blocks[NB_STRINGS + 1][0] > s_off else head[s_off:]
    entries = [struct.unpack_from("<7i", head, e_off + 28 * k) for k in range(e_num)]
    INSTDIR = 21
    vmap = {INSTDIR: "$INSTDIR", 31: "$INSTDIR"}   # 31 = $_OUTDIR usata da File /r
    plan, outdir = [], None
    for which, *p in entries:
        if which == EW_CREATEDIR and p[1]:          # SetOutPath
            outdir = nsis_string(strings, p[0], vmap)
        elif which == EW_EXTRACTFILE:
            name = nsis_string(strings, p[1], vmap)
            plan.append((p[2], outdir, name))
    print(f"{len(plan)} file nello script", flush=True)
    by_off = {}
    for o, d, nm in plan:
        by_off.setdefault(o, []).append((d, nm))
    done = 0
    for o in sorted(by_off):
        rel = data0 + o
        if rel < st.pos:
            raise SystemExit(f"offset all'indietro {o}")
        st.skip(rel - st.pos)
        size = struct.unpack("<I", st.read(4))[0] & 0x7FFFFFFF
        data = st.read(size)
        for d, nm in by_off[o]:
            if d is None or not d.startswith("$INSTDIR"):
                continue                # file del programma di installazione (plugin, disinstallatore)
            rp = (d[len("$INSTDIR"):].strip("\\") + "\\" + nm).strip("\\").replace("\\", "/")
            path = os.path.join(dest, rp)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as w:
                w.write(data)
            done += 1
    print(f"{done} file estratti in {dest}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
