# RepertIA

**Forensic analysis of disk and USB drive images, with a local, offline AI assistant.**
🇮🇹 **Versione italiana: [README.it.md](README.it.md)**

RepertIA analyses forensic images (E01, raw/dd, dmg) from a single local web interface, on Apple Silicon Macs, Windows
or Linux (experimental). It uses established forensic tools (The Sleuth Kit, libewf, plaso, PhotoRec, bulk_extractor,
ExifTool, libyal) and gathers their results into a case you can browse with filters, timelines and previews. An optional
language model running on the analyst's own computer answers questions in English or Italian, citing files, offsets and
inodes.
**No data leaves the computer**: no cloud, no accounts, no telemetry; the interface listens only on 127.0.0.1.

> **Disclaimer.** RepertIA is a personal project. It is not certified or validated by any third party and is not
> affiliated with any office or public administration. Results must be confirmed with a second tool or on the original
> data before being used in official reports or proceedings. The software is provided "as is", without any warranty
> (see [LICENSE](LICENSE)). The language model's answers are investigative leads, not conclusions.

## What it does

| Area | Features |
|---|---|
| File systems | NTFS, FAT/exFAT, ext, HFS+, APFS (FileVault too, with the key); deleted and orphan files, ADS; unallocated space; Volume Shadow Copies and APFS snapshots |
| Encrypted volumes | Detection of BitLocker, LUKS, FileVault, VeraCrypt (high entropy); decryption of BitLocker, LUKS1 and APFS with the key (never stored) |
| Windows artifacts | For every installation on the disk (including Windows.old): accounts and logons (SAM and event logs), Prefetch, Amcache, UserAssist, ShimCache, BAM, SRUM, LNK files and jump lists, ShellBags, Activity History, NTFS journal `$UsnJrnl`, events (services, power on/off, Remote Desktop, Defender, USB), networks, Recycle Bin, browsers |
| macOS artifacts | Data volume, quarantine, launch items, TCC, iMessage, recent documents, Safari, KnowledgeC, Bluetooth, Time Machine |
| Timeline | File system + plaso; dates in UTC, Italian time or the device's time zone (detected); FAT/exFAT converted correctly |
| Content | Document text with full-text search, OCR (Tesseract), EXIF/GPS metadata, archives, PST/OST/MBOX/EML mail |
| Recovery | Carving with PhotoRec, bulk_extractor features, File Explorer thumbnail cache |
| Anomalies | Fake extensions and disguised executables (deleted files are verified to avoid false positives), encrypted files and containers |
| Images and hash sets | Perceptual hashes (similar images), NSRL hash sets, Project VIC / CAID, folders of reference images |
| Safeguards | The image is never modified; data hashes compared with the acquisition hashes; hash-chained audit log; tool versions and program fingerprint in the report |
| Reports | Case report (Markdown, Word, PDF) and a portable HTML report for readers who do not have the forensic image |

User interface, reports and case texts are **in English or Italian** (each case's language is chosen when it is
created).

Full documentation: [docs/MANUAL.md](docs/MANUAL.md) (Italian original: [src/README.md](src/README.md)). Method, tests
and known limitations: [VALIDATION.md](VALIDATION.md) (Italian original: [VALIDAZIONE.md](VALIDAZIONE.md)).

## Download and installation

Ready-made packages are in the **Releases** section:

| | Mac (Apple Silicon) | Windows 10/11 64-bit | Linux x86_64 (experimental) |
|---|---|---|---|
| Package | `RepertIA-<version>-Mac.zip` (app with Python, plaso and libraries) | `RepertIA-<version>-Setup.exe` (no administrator rights needed) or the portable `RepertIA-<version>-Windows.zip` | `RepertIA-<version>-Linux.tar.gz` + `./installa.sh` (Ubuntu 24.04+, Debian 13) |
| External tools | installed with Homebrew on first start | included | installed with apt by `installa.sh`, which also sets up Python, plaso and the libraries |
| Acceptance test | `RepertIA-collaudo.zip` + *Collaudo RepertIA.command* | same zip, Start menu › RepertIA › Collaudo | same zip, `./collaudo.sh` |
| AI model (optional) | LM Studio, llama-server or Ollama, on the same computer or on the internal network | as Mac | as Mac |

**Tip:** right after installing, run the acceptance test (*collaudo*) and keep the `collaudo_<date>.md` report: it shows
that on that computer, with those versions, the program gives the expected results.

### Requirements

**Computer (without AI)**
- **System**: Mac with Apple Silicon (M1 or later), Windows 10/11 64-bit, or Linux x86_64 with Ubuntu 24.04 or later
  (experimental version).
- **Memory (RAM)**: 8 GB is enough for USB drives and small disks; 16 GB is comfortable.
- **Disk**: an SSD is better. The case is not a copy of the disk but a database with the indexes; add space for exported
  files, carving and the preview cache (at most about 5 GB per case). The forensic image can also be on an external disk,
  preferably USB 3 or Thunderbolt, because computing the hashes reads it entirely.
- **Processor**: more cores mainly shorten the plaso timeline, which can take hours on large disks.

**Local AI model (optional)**: the model must support *tool calling*, with a context of at least 16k tokens (32k is
better). As a guide:

| Memory for the model | Models | Result |
|---|---|---|
| 16 GB of RAM (or 8 GB GPU) | Qwen3.5-9B | simple questions only |
| 32 GB (or 16 GB GPU) | gpt-oss-20b | already acceptable |
| 48–64 GB (or 24–32 GB GPU) | Qwen3.8-27B, Qwen3.6-35B-A3B, Gemma 4 31B | recommended |
| 128 GB | gpt-oss-120b | the best you can run locally |

Load the model (LM Studio, llama-server or Ollama) with a context of about 32768, start the server and RepertIA finds it
automatically. On a Mac memory is shared: leave about ten GB free for the system. Without a graphics card the model runs
on the processor, but slowly; with *Network server* a single powerful computer on the internal network can serve several
workstations. Without a model RepertIA still works: all data can be browsed. The model suggestions come from public
rankings (October 2026): check them on your own cases.

### From source

```
git clone https://github.com/silvexe/RepertIA.git
cd RepertIA/src
python3 forense_gui.py          # Python 3.12+; requires The Sleuth Kit, libewf and the libyal modules (see docs/MANUAL.md)
```

Building the packages: [docs/BUILDING.md](docs/BUILDING.md).

## Acceptance test

`src/forense_collaudo.py` prepares a case for each test image and compares the results with the expected values in
[`collaudo/`](collaudo/): public images with results published by third parties (DFTT) and images built for the test.
The images are in the `RepertIA-collaudo.zip` archive in the Releases. Details in
[collaudo/README.en.md](collaudo/README.en.md) and [VALIDATION.md](VALIDATION.md).

## License

Copyright (C) 2026 silvexe.

RepertIA is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public
License** as published by the Free Software Foundation, **either version 3 of the License, or (at your option) any
later version** (SPDX: `GPL-3.0-or-later`). It is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY. Full text in [LICENSE](LICENSE).

The packages in the Releases include third-party components under their own licenses: list, versions and sources in
[THIRD_PARTY_LICENSES.en.md](THIRD_PARTY_LICENSES.en.md).

## How it was developed

The code was written with the help of Claude, an artificial intelligence model by Anthropic. Design choices,
verifications and tests are the author's. Every version is described in [CHANGELOG.en.md](CHANGELOG.en.md) with what
changes, how it was tested and what was not tested.

## Translations

The Italian documents are the originals; the English ones are translations. If they differ, the Italian text prevails
(in particular [VALIDAZIONE.md](VALIDAZIONE.md) and the manual [src/README.md](src/README.md)).

## Contributing and reporting issues

- Bugs and proposals: **Issues** section. **Never attach data from real cases** (images, extracts, screenshots with
  names or paths): use public or purpose-built test images.
- Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).
- Vulnerabilities: [SECURITY.md](SECURITY.md) (private reporting).
