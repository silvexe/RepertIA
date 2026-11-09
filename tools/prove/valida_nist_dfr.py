#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 silvexe
"""Validazione esterna di RepertIA sulle immagini NIST CFTT «Deleted File Recovery» (DFR-01…17, CFReDS).

Riferimento: NIST, «Test Images layout» (setup-july-10-2012.pdf, nella cartella delle immagini come setup.txt estratto
con pdftotext -layout): per ogni immagine i file cancellati, quelli con i metadati ancora presenti («Metadata found») e
quelli senza («Deleted files without metadata»). Ogni settore dei file di prova ha un'etichetta: il primo
«DFR\\nFile <nome> path <cartella>», gli altri «Block NNNNN Segment SSS file <nome> path <cartella>».

Per ogni caso preparato da RepertIA (forense_agent.py prepara --image dfr-NN-fs.dd --case <casi>/dfr-NN-fs --no-indice):
  A. elenco: i file cancellati CON metadati secondo NIST sono elencati da RepertIA come cancellati (asserzione CFTT
     DFR-CA-01: nome di ogni file cancellato recuperabile dai metadati);
  B. contenuto: per ogni file cancellato elencato, il contenuto letto da RepertIA (icat_read, la stessa funzione
     dell'interfaccia) settore per settore: quanti settori hanno l'etichetta del file stesso, quanti di un altro file
     (sovrascritto), quanti senza etichetta. Un file senza sovrascritture deve essere integro e in ordine.
Uso: valida_nist_dfr.py <cartella delle immagini con setup.txt> <cartella dei casi> [nome del caso …]
Esito: tabella nel formato dei rapporti CFTT (caso, atteso, ottenuto) su stdout; esce con 1 se una asserzione non torna."""
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
IMG = Path(sys.argv[1]).expanduser()
CASI = Path(sys.argv[2]).expanduser()
SOLO = set(sys.argv[3:])
sys.path.insert(0, str(Path(os.environ.get("REPERTIA_SRC", Path(__file__).resolve().parents[2] / "src"))))
import forense_agent as fa  # noqa: E402

TAG = re.compile(rb"\nDFR\n(?:File (?P<f1>\S+) path|Block (?P<b>\d+) Segment (?P<s>\d+) file (?P<f2>\S+) path)")


def riferimento(testo):
    """{caso: {"trovati": set, "non_trovati": set, "cancellati": {nome: (dim, settori)}, "sovrascritti": set}}.
    Gli elenchi vanno fino all'intestazione successiva (un cambio di pagina del PDF lascia righe vuote e il piè di pagina
    «Last save …», che si tolgono). DFR-04: NIST elenca alias ASCII («/tmp/dfr-04/BeiJing.txt»); il nome vero è nelle
    righe «/tmp/BeiJing.txt => 北京.txt)» della stessa sezione (senza i segni invisibili di direzione del testo)."""
    out = {}
    testo = re.sub(r"(?m)^Last save .*$", "", testo)
    parti = re.split(r"[\n\x0c]\d+\s+Test Image (\S+)[ \t]*\n", testo)
    for nome, corpo in zip(parti[1::2], parti[2::2]):
        r = {"trovati": None, "non_trovati": set(), "cancellati": {}, "sovrascritti": set()}
        alias = {Path(x).name: re.sub("[‎‏‪-‮]", "", y).strip()
                 for x, y in re.findall(r"(/tmp/\S+) => (.+?)\)\s*$", corpo, re.M)}
        vero = lambda n: alias.get(Path(n).name, n)
        m = re.search(r"Deleted files \(\d+\)\s*\nName.*?\n(.*?)\n\s*(?:MAC times|File delete times|Steps to Create)",
                      corpo, re.S)
        if m:
            for riga in m.group(1).splitlines():
                x = re.match(r"\s*(\S+)\s+(\d+)\s*\((\d+)\+(\d+)\)", riga)
                if x:
                    r["cancellati"][vero(x.group(1))] = (int(x.group(2)), int(x.group(3)) + int(x.group(4)))
        m = re.search(r"Metadata found (\d+) files, not found (\d+)", corpo)
        m2 = re.search(r"Deleted files without metadata \(cannot be found\)\s*\n(.*?)\n\s*Layout History", corpo, re.S)
        # nomi separati sull'estensione: nel testo del PDF manca a volte lo spazio («Sheliak.txtSulafat.txt»)
        r["non_trovati"] = ({vero(x) for x in re.findall(r"\S+?\.(?:txt|TXT|lnk|LNK)\d*", m2.group(1))}
                            if m2 else set())
        if m:
            r["trovati"] = set(r["cancellati"]) - r["non_trovati"]
        for a, b in re.findall(r"^(\S+) x (\S+): overlap", corpo, re.M):
            r["sovrascritti"].add(vero(a))
        r["link"] = {}                                  # DFR-14: hard link «link A->B» (stessa scheda, stessi dati)
        for a, b in re.findall(r"\blink\s+(\S+?)->(\S+)", corpo):
            r["link"].setdefault(b, set()).add(a)
            r["link"].setdefault(a, set()).add(b)
        r["etichetta"] = {v: Path(k).name for k, v in alias.items()}   # DFR-04: le etichette dei settori usano l'alias
        out[nome] = r
    return out


def forme(nome):
    """Come può comparire il nome nell'immagine: UTF-16 (NTFS, exFAT: i primi 15 caratteri, una voce di nome exFAT ne
    contiene 15), ASCII (ext), nome breve FAT 8.3 senza il primo carattere (alla cancellazione diventa 0xE5)."""
    v = [nome[:15].encode("utf-16-le"), nome.encode("utf-8")]
    base, _, ext = nome.upper().rpartition(".")
    if base and len(base) <= 8 and len(ext) <= 3:
        v.append((base.ljust(8) + ext.ljust(3))[1:].encode("ascii", "replace"))
    return v


def grezzo(dd, nomi, ntfs):
    """Rilettura dell'immagine senza Sleuth Kit: {nome: "FILE" | "altro" | None}. Su NTFS «FILE» se il nome (UTF-16) sta
    in un record MFT (blocco di 1024 byte che inizia con FILE), altrimenti «altro» se c'è altrove ($LogFile, spazio
    libero); None se il nome non c'è più in nessuna forma."""
    import mmap
    out = {}
    with open(dd, "rb") as fh:
        m = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        for n in nomi:
            dove = None
            for i, ago in enumerate(forme(Path(n).name)):
                p = m.find(ago)
                while p >= 0:
                    if m[p - p % 512:p - p % 512 + 5] == b"\nDFR\n":   # settore di dati etichettato: non è metadato
                        p = m.find(ago, p + 1)
                        continue
                    dove = dove or "altro"
                    if ntfs and i == 0 and m[p - p % 1024:p - p % 1024 + 4] == b"FILE":
                        dove = "FILE"
                        break
                    p = m.find(ago, p + 1)
                if dove == "FILE":
                    break
            out[n] = dove
    return out


def settori_grezzi(dd, nomi):
    """Rilettura dell'immagine senza Sleuth Kit: {nome: [settore assoluto di ogni blocco etichettato, in ordine di
    blocco]} per i settori che portano ancora l'etichetta del file; lista vuota se non ne resta nessuno."""
    import mmap
    out = {n: {} for n in nomi}
    with open(dd, "rb") as fh:
        m = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        for x in TAG.finditer(m):
            if x.start() % 512:
                continue
            f = (x.group("f1") or x.group("f2")).decode("latin-1")
            if f in out:
                out[f].setdefault(0 if x.group("f1") else int(x.group("b")), x.start() // 512)
    return {n: [v[k] for k in sorted(v)] for n, v in out.items()}


def settori(data):
    """Etichette dei settori del contenuto: lista di (file, blocco) o None per i settori senza etichetta."""
    v = []
    for i in range(0, len(data), 512):
        m = TAG.match(data[i:i + 512])
        v.append(None if not m else ((m.group("f1") or m.group("f2")).decode("latin-1"),
                                     0 if m.group("f1") else int(m.group("b"))))
    return v


def main():
    ref = riferimento((IMG / "setup.txt").read_text(encoding="utf-8", errors="replace"))
    esiti, righe = [], []
    for caso_dir in sorted(p for p in CASI.iterdir() if (p / "caso.sqlite").exists()):
        nome = caso_dir.name                                    # dfr-07-ntfs
        if SOLO and nome not in SOLO:
            continue
        m = re.fullmatch(r"dfr-(\d\d)(?:-(\w+))?-(\w+)", nome)
        chiave = f"{m.group(3)}-{m.group(1)}" + (f"-{m.group(2)}" if m.group(2) else "")   # ntfs-07[-one]
        r = ref.get(chiave)
        frammentato = m.group(1) in ("02", "03", "05", "06", "12", "13")  # casi DFR con file frammentati (06: attorno a un file)
        if not r:
            print(f"{nome}: nessun riferimento NIST «{chiave}»")
            continue
        case = fa.Case(caso_dir)
        con = sqlite3.connect(f"file:{caso_dir / 'caso.sqlite'}?mode=ro", uri=True)
        fs_di = {int(p["offset"]): (p.get("fs") or "").lower() for p in case.meta.get("partitions", [])}
        voci = list(con.execute("SELECT part, inode, type, path FROM files WHERE deleted>=1"))
        orfani = [(p, i) for p, i, t, pa in voci if "/OrphanFile-" in pa and t.endswith("r")]
        trov = {}                              # nome NIST -> voci di RepertIA con quel nome
        for f in r["cancellati"]:
            for p, i, t, pa in voci:
                n = Path(pa).name
                # FAT: alla cancellazione il primo carattere del nome breve diventa 0xE5 (Sleuth Kit lo mostra «_»)
                # (solo se il nome inizia con «_»: senza, A190-… e C190-… di partizioni diverse coincidevano)
                if n == f or pa == f or (fs_di.get(int(p), "").startswith("fat") and n[:1] == "_" and n[1:].upper() == f[1:].upper()):
                    trov.setdefault(f, []).append((p, i, t))
        if r["trovati"] is not None:
            manca = sorted(r["trovati"] - set(trov))
            # NIST elenca tra i cancellati anche file mai cancellati (DFR-07-two: Eltanin creato al passo 5 sui settori di
            # Castor): se nel caso il nome è un file attivo, il riferimento è smentito dai dati
            attivi = sorted(f for f in manca if con.execute(
                "SELECT 1 FROM files WHERE deleted=0 AND (path=? OR path LIKE ?)", (f, "%/" + f)).fetchone())
            # Cestino di Windows svuotato (DFR-01-recycle): il file è «$R…» e il gemello «$I…» ha il nome originale
            for p, i, t, pa in voci:
                if manca and Path(pa).name.startswith("$I") and t.endswith("r"):
                    dati_i = fa.icat_read(case, p, i, 4096)
                    erre = str(Path(pa).parent / ("$R" + Path(pa).name[2:])).replace("\\", "/")
                    for f in [f for f in manca if Path(f).name.encode("utf-16-le") in dati_i]:
                        trov[f] = [(pp, ii, tt) for pp, ii, tt, ppa in voci if ppa == erre]
                    manca = sorted(r["trovati"] - set(trov))
            # cartella cancellata (DFR-11, ext): il nome si perde ma la scheda resta come file orfano; vale come trovato
            # se il primo settore porta l'etichetta del file (letto con icat_read, come nell'interfaccia)
            orfani_di = {}
            if manca and orfani:
                for p, i in orfani:
                    s = settori(fa.icat_read(case, p, i, 512))
                    if s and s[0]:
                        orfani_di.setdefault(s[0][0], (p, i))
                for f in [f for f in manca if Path(f).name in orfani_di]:
                    trov[f] = [(*orfani_di[Path(f).name], "-/r")]
                manca = sorted(r["trovati"] - set(trov))
            lim = [f for f in manca if all(x.startswith("hfs") for x in fs_di.values())]
            # nomi che NIST dà con metadati ma che l'immagine grezza smentisce (se il .dd c'è ancora)
            dd = CASI.parent / f"{nome}.dd"
            ntfs = any(x.startswith("ntfs") for x in fs_di.values())
            g = grezzo(dd, [f for f in manca if f not in lim and f not in attivi], ntfs) if dd.exists() else {}
            rif = [f for f, d in g.items() if d is None or (ntfs and d != "FILE")] + attivi
            ok_a = not (set(manca) - set(lim) - set(rif))
            esiti.append(ok_a)
            righe.append(("OK" if not manca else ("NO" if not ok_a else "LIM" if lim else "RIF"), nome, "A",
                          f"{len(r['trovati'])} cancellati con metadati", f"{len(r['trovati'] & set(trov))} elencati"
                          + (f"; mancano {manca}" if manca else "")
                          + (" (Sleuth Kit non recupera i cancellati HFS+)" if lim else "")
                          + (f"; smentiti dall'immagine grezza {rif} (" + ("nessun record MFT li contiene: schede riusate"
                             if ntfs else "il nome non c'è più") + ")" if set(rif) - set(attivi) else "")
                          + (f"; {attivi}: file attivi, mai cancellati (NIST li elenca tra i cancellati)" if attivi else "")
                          + (f"; nell'immagine grezza ancora presenti {sorted(set(manca) - set(lim) - set(rif))}"
                             if g and not ok_a else "")))
        if m.group(1) == "04":
            # C (DFR-04, nomi non ASCII): ogni nome vero cancellato è elencato intatto (stessi caratteri Unicode).
            # Solo i nomi che Sleuth Kit trova sul disco (NIST: «metadata not found» per tutti, i nomi però restano).
            nomi_del = {Path(pa).name for _p, _i, _t, pa in voci}
            dd = CASI.parent / f"{nome}.dd"
            g = grezzo(dd, sorted(r["cancellati"]), False) if dd.exists() else {}
            attesi = sorted(f for f in r["cancellati"] if g.get(f, "altro"))
            manca = [f for f in attesi if f not in nomi_del]
            esiti.append(not manca)
            righe.append(("OK" if not manca else "NO", nome, "C", f"{len(attesi)} nomi non ASCII cancellati sul disco",
                          f"{len(attesi) - len(manca)} elencati intatti"
                          + (f"; alterati o mancanti {manca}; elencati invece {sorted(nomi_del - set(attesi))[:12]}"
                             if manca else "")))
        for f, (dim, n_set) in sorted(r["cancellati"].items()):
            if f not in trov:
                continue
            pieni = dim // 512                 # i settori pieni hanno l'etichetta; l'ultimo parziale no
            cand = [(p, i) for p, i, t in trov[f] if t.endswith("r") and str(i) != "0"]
            dove = ""
            data = b""
            for p, i in cand:
                data = fa.icat_read(case, p, i, dim + (1 << 20))
                if data:
                    break
            if not data:                       # nome senza inode (ext2): il contenuto può essere in un orfano
                for p, i in orfani:
                    d = fa.icat_read(case, p, i, dim + (1 << 20))
                    s = settori(d[:512])
                    if s and s[0] and s[0][0] in (f, r["etichetta"].get(f)):
                        data, dove = d, f" (dall'inode orfano {i}: nome e inode non collegati)"
                        break
            st = settori(data)
            mio = {f, r["etichetta"].get(f, f)}
            propri = [x[1] for x in st if x and x[0] in mio]
            altri = sorted({x[0] for x in st if x and x[0] not in mio})
            vuoti = sum(1 for x in st if x is None)
            integro = len(data) == dim and propri == list(range(pieni)) and vuoti == len(st) - pieni
            atteso_integro = f not in r["sovrascritti"]
            fs = next((fs_di.get(int(p), "") for p, _i, _t in trov[f]), "")
            if not atteso_integro:
                esito = "OK"                   # sovrascritto: si registra cosa si legge
            elif "hard-link-" in f and not propri and altri == [f.replace("hard-link-", "hard-file-")] and len(data) == dim:
                esito = "OK"                   # DFR-14: un hard link ha i dati del file collegato (stessa scheda)
            elif not data and any(con.execute("SELECT 1 FROM files WHERE deleted=0 AND path=?", (x,)).fetchone()
                                  for x in r["link"].get(f, ())):
                esito = "OK"                   # DFR-14 ext: nome cancellato di un hard link, i dati restano sotto l'altro nome
            elif "symbolic-link-" in f and not data:
                esito = "OK"                   # DFR-14: un collegamento simbolico NTFS non ha dati propri (punto di analisi)
            elif integro:
                esito = "OK"
            elif not data and fs in ("ext3", "ext4"):
                esito = "LIM"                  # ext3/ext4 azzerano i puntatori ai blocchi alla cancellazione
            elif frammentato and fs in ("fat12", "fat16", "fat32") and len(data) in (0, dim):
                esito = "LIM"                  # FAT azzera la catena dei cluster: un frammentato si legge come contiguo
            elif frammentato and fs == "exfat" and len(data) == dim:
                esito = "LIM"                  # exFAT: catena nella FAT non più valida (RepertIA legge allora come icat)
            else:
                esito = "NO"
            nota = ""
            dd = CASI.parent / f"{nome}.dd"
            if esito == "NO" and dd.exists():
                pos = settori_grezzi(dd, sorted(mio)).values()
                pos = max(pos, key=len)
                if not pos:
                    # nessun settore dell'immagine porta più l'etichetta del file: è stato sovrascritto (DFR-07-one
                    # exFAT Capella: la Layout History di NIST mostra i suoi settori diventati «metadata» al passo 5)
                    esito, nota = "RIF", " (nessun settore dell'immagine porta più l'etichetta: sovrascritto, NIST lo dà intatto)"
                elif fs.startswith("fat") and len(data) == dim and any(b != a + 1 for a, b in zip(pos, pos[1:])):
                    # sul disco il file è frammentato (DFR-08 FAT Megrez, attorno ad Alphard) e FAT azzera la catena
                    esito, nota = "LIM", f" (sul disco i suoi settori {pos[0]}…{pos[-1]} non sono contigui)"
            esiti.append(esito != "NO")
            righe.append((esito, nome, "B", f"{f}: {dim} byte" + ("" if atteso_integro else " (sovrascritto)"),
                          f"{len(data)} byte, settori propri {len(propri)}/{pieni}"
                          + (f", di altri file {altri}" if altri else "") + dove + nota
                          + (" (ext3/ext4: puntatori ai blocchi azzerati, contenuto non recuperabile dai metadati)"
                             if esito == "LIM" and not data and fs.startswith("ext") else "")
                          + (" (FAT: catena dei cluster azzerata, file frammentato: la lettura contigua supererebbe la fine"
                             " della partizione e Sleuth Kit non restituisce nulla)" if esito == "LIM" and not data
                             and fs.startswith("fat") else "")
                          + (" (exFAT: catena nella FAT non utilizzabile, cluster riusati o catena diversa dalla"
                             " dimensione, e il file si legge contiguo come fa Sleuth Kit)"
                             if esito == "LIM" and data and fs == "exfat" else "")
                          + (" (FAT: catena dei cluster azzerata alla cancellazione, file frammentato letto come contiguo:"
                             " il contenuto restituito NON è quello del file)" if esito == "LIM" and data and fs.startswith("fat") else "")))
    for esito, nome, tipo, att, ott in righe:
        print(f"{esito:3} {nome:22} {tipo}  atteso: {att:45}  ottenuto: {ott}")
    print(f"\n{sum(1 for x in righe if x[0] == 'OK')} OK, {sum(1 for x in righe if x[0] == 'LIM')} limiti noti, "
          f"{sum(1 for x in righe if x[0] == 'RIF')} smentite dall'immagine, "
          f"{sum(1 for x in righe if x[0] == 'NO')} NO su {len(righe)} asserzioni")
    return 0 if all(esiti) else 1


if __name__ == "__main__":
    sys.exit(main())
