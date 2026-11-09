#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Scarica le immagini pubbliche del caso NIST CFReDS «Data Leakage» (PC, chiavette RM#1 e RM#2, CD-R RM#3) e le
controlla con gli SHA-1 pubblicati da NIST. Riprende i download interrotti. Circa 8 GB.

Uso: scarica_nist_leakage.py <cartella di destinazione>"""
import hashlib
import sys
import time
import urllib.request
from pathlib import Path

BASE = "https://cfreds-archive.nist.gov/data_leakage_case/images"
SHA1 = {  # nome del file → (sottocartella del sito, SHA-1 pubblicato da NIST)
    "cfreds_2015_data_leakage_pc.E01": ("pc", "72432916933F5A309A8C456B40C9601D1F8D2A4F"),
    "cfreds_2015_data_leakage_pc.E02": ("pc", "0CAF4261ED8432A8B3BAA019B1B28FDF96F79130"),
    "cfreds_2015_data_leakage_pc.E03": ("pc", "BE836C891736C4C0C2253C6803399BF0F2A599BA"),
    "cfreds_2015_data_leakage_pc.E04": ("pc", "9159BFFD56097495F73FBBF967B75EB288B1E3DE"),
    "cfreds_2015_data_leakage_rm#1.E01": ("rm%231", "FFD0F3CBA3DFE3291F786B845A06A8AA56C1CD8C"),
    "cfreds_2015_data_leakage_rm#2.E01": ("rm%232", "2228554CD6FDD3C85BB80E0A0CD7F21A2364DC99"),
    "cfreds_2015_data_leakage_rm#3_type1.7z": ("rm%233", "13EEDDC40AD493022B22D7E0A6674DEF603F6247"),
}


def scarica(url, dest, tentativi=5):
    for n in range(tentativi):
        fatto = dest.stat().st_size if dest.exists() else 0
        req = urllib.request.Request(url, headers={"User-Agent": "RepertIA-prove", **({"Range": f"bytes={fatto}-"} if fatto else {})})
        try:
            with urllib.request.urlopen(req, timeout=120) as r, open(dest, "ab" if fatto and r.status == 206 else "wb") as f:
                while blocco := r.read(1 << 20):
                    f.write(blocco)
            return True
        except urllib.error.HTTPError as e:
            if e.code == 416:   # già completo
                return True
            print(f"  errore {e.code}, nuovo tentativo")
        except OSError as e:
            print(f"  errore {e}, nuovo tentativo")
        time.sleep(10 * (n + 1))
    return False


def sha1(p):
    h = hashlib.sha1()
    with open(p, "rb") as f:
        while blocco := f.read(1 << 22):
            h.update(blocco)
    return h.hexdigest().upper()


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out = Path(sys.argv[1]).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    errori = 0
    for nome, (cartella, atteso) in SHA1.items():
        print(nome)
        dest = out / nome
        if not scarica(f"{BASE}/{cartella}/{nome.replace('#', '%23')}", dest):
            print("  download non riuscito")
            errori += 1
            continue
        ok = sha1(dest) == atteso
        print("  SHA-1 uguale a quello NIST" if ok else "  SHA-1 DIVERSO da quello NIST")
        errori += not ok
    print(f"Fine: {errori} errori.")
    sys.exit(1 if errori else 0)


if __name__ == "__main__":
    main()
