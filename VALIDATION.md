# RepertIA – Validation document

*Translation of [VALIDAZIONE.md](VALIDAZIONE.md); the Italian text prevails.*

Program version: 2.19.0 · Document updated on 24/10/2026

This document describes **how RepertIA was verified, with which data, with which results and with which known
limitations**. It is meant for those who use the program in an expert examination and need to state the reliability of
the method (ISO/IEC 27041 "assurance of the suitability and adequacy of the incident investigative method", ISO/IEC
27042, ENFSI guidelines for digital forensics; the checks follow the approach of the NIST CFTT project: test data with a
known result, automatic comparison, repeatable report).

> RepertIA is a personal project, neither certified nor accredited. This document does not replace the validation by
> the laboratory that uses it: it provides the basis and explains how to repeat it. For the decisive results of each
> case a **cross-check with a second tool** remains recommended (section 4).

## 1. What the method guarantees

| Requirement | How it is met | Where it is checked |
|---|---|---|
| The forensic image is not modified | The case is a separate database; the image (E01, raw, dmg) is opened read-only by Sleuth Kit, libewf, libfsapfs. Extracted files go to `<case>/estratti` and `export`, read-only | Hash of the image before/after (Verify hashes) |
| Integrity of the acquired data | MD5/SHA-1/SHA-256 of the media data compared with the acquisition hashes of the E01 or of the logs (FTK Imager, Guymager…) | "Acquisition" row of the case; report section |
| Traceability of operations | `audit_log.jsonl` log of every command and analysis, chained with SHA-256 (each line contains the hash of the previous one) | "Verify hashes" also checks the chain; report: hash of the last line |
| Repeatability | Versions of tools and modules and SHA-256 fingerprint of the program's sources saved at preparation time and in the report | "Environment" section of the report |
| Correct dates | Data in UTC; FAT/exFAT converted from the device's time zone (detected from the registry or the system, and stated); daylight saving time and repeated hour handled; three display modes, always labelled | Acceptance test DFTT 5 (FAT, daylight saving time) |
| Distinction between data and interpretation | Results come from the program; the local language model proposes interpretations that must be checked on the data (every answer cites file, offset and inode) | — |

## 2. Automatic acceptance test (`forense_collaudo.py`)

The acceptance test (*collaudo*) prepares a case for each test image and compares the results with the expected ones
written in `atteso.json` / `atteso_dftt.json`. It is started with "Collaudo RepertIA" (Mac), from the Start menu >
RepertIA > Collaudo (Windows) or with `./collaudo.sh` (Linux), and produces `collaudo_<date>.md` with the result of each
check, the versions and the program fingerprint.

**Images with a known result published by third parties** (Digital Forensics Tool Testing, dftt.sourceforge.net;
results transcribed from the project's pages and confirmed by the archives' `results.txt`):
DFTT 5 (FAT12, dates with daylight saving time), 6 (FAT16, truncated image), 7 (NTFS), 8 (archives with a different
extension), 9/10 (keyword search), 11 (carving: offsets of the published files). The images are recognised by their
published MD5. Checks: MD5 of the files, deleted files, files extracted from archives, dates in the device's time zone,
carving (MD5 and start sector).

**Images built for the test** (known result because they were built): ext4 in E01 with deleted files; E01 with 4
altered bytes (must turn out DIFFERENT from the acquisition hash); FAT USB drive with an FTK Imager hash list; Mac Data
volume (plist, sqlite with WAL, bookmarks); APFS (dfvfs) unencrypted and encrypted with a password; BitLocker To Go
(dfvfs).

**Documented results** (from the project's change log):

| Version | Where | Result |
|---|---|---|
| 2.15.1 | User's Mac (PhotoRec 7.2, Sleuth Kit 4.15) | 111/111; 45/45 independent checks (DFTT); carving 13/15 identical to the published offsets |
| 2.15.2 | User's Mac | 112/112 |
| 2.15.2 | User's Windows 11 | 110/112: 2 errors on FAT dates with daylight saving time (DFTT 5) → fixed in 2.15.3 |
| 2.15.3 | User's Windows | all passed |
| 2.16.0 | User's Windows | all passed |
| 2.16.0 | User's Mac | 110/112: double FAT time-zone conversion (DFTT 5) caused by a Sleuth Kit bug on macOS → fixed in 2.16.1, verified in the container (50/50 also with Mac and Windows simulation) |
| 2.17.x – 2.19.0 | User's Windows | all passed |
| 2.19.0 | Linux: development environment (Ubuntu 24.04, Python 3.13; Sleuth Kit 4.15.0, PhotoRec 7.2 and libewf 20140814 built from source; without bulk_extractor) | 112/112 in Italian and 112/112 in English (46/46 on public images); carving DFTT 11: 13/15 as on the Mac |

Carving DFTT 11: 2 files out of 15 (enterprise.wav, haxor2.jpg) are not recovered by PhotoRec: this is a limitation of
PhotoRec, declared as a "measurement" and not as a requirement.

**To do for every new version:** run the acceptance test on Mac, Windows and Linux before use in a case and keep the
`collaudo_<date>.md` report with the expert report. Full test on the Mac: 2.18.1 112/112; 2.19.0 112/112 in Italian and
112/112 in English. Full test also run by the author on Windows for versions 2.17.x to 2.19.0.
**Linux (experimental, 2.19.0)**: test passed in the Linux development environment; to be repeated on a Linux computer
installed with `installa.sh` before use in a case.

## 3. Checks on real images

Besides the acceptance test, new features are tried on real case images (the data stay on the user's computer).
Documented examples:

- 2.17.3, "Anomalies" on a real image of a Windows disk (a few hundred GB, NTFS, over a million files): reports reduced
  from 566 to 231 by removing false positives on deleted files (clusters reused by other files, verified with a pass
  over the MFT and with content consistency); 1,500 randomly chosen files give no new reports.
- 2.17.3, account logons: compared with the 4624 / 7001 events extracted by plaso from the same disk.
- 2.18.0, artifacts on the same disk (program functions run on the real data; registry read with an independent
  pure-Python reader): the main installation and the previous ones in Windows.old recognised (for one of them the
  system hives turn out deleted and overwritten, which is stated); 1,489 ShellBags entries all recognised (drives,
  network paths, network computers, known folders); ShimCache 479 entries, BAM 51; NTFS journal 170,642 operations over
  a period of a few months, path rebuilt for all but one, only the 33 MB of real data read out of 52 GB logical; 1,313
  thumbnails extracted, all openable; perceptual hashes on 1,293 (20 uniform images excluded).

## 4. Cross-check with a second tool (for every case)

"Cross-check with another tool" compares RepertIA's file list and hashes with those exported by FTK Imager, Autopsy
or a Sleuth Kit body file and writes `riscontri/riscontro_<date>.{csv,md}`: files present in only one of the two,
different hashes. It is the recommended check for every case in which the results have evidential weight.
For decisive artifacts (logons, executions, USB devices, opened folders) it is advisable to confirm with a second tool
(Registry Explorer, Autopsy, X-Ways, AXIOM…) or directly on the raw data, which RepertIA always indicates (source file,
offset, inode, registry key).

## 5. Known limitations

- **File systems**: NTFS, FAT/exFAT, ext2/3/4, HFS+ (Sleuth Kit), APFS (libfsapfs, FileVault too, with the key) are
  read. Not read: ReFS, Storage Spaces, software RAID, LVM, btrfs, XFS. VeraCrypt/TrueCrypt only detected (high
  entropy), not opened. BitLocker and LUKS1 are opened with the key (derived copy).
- **APFS**: no recovery of deleted files (except snapshots); not tested on E01 images of recent real Macs (T2/Apple
  Silicon).
- **Windows registry**: transaction logs (.LOG1/.LOG2) are applied to a working copy only if the sequence is
  continuous; otherwise the hive is read as it is (stated among the artifacts).
- **Logons**: the SAM counter does not count logons with Microsoft accounts, PIN and Windows Hello; event logs keep only
  the most recent period (stated in the account card).
- **ShimCache**: since Windows 8 the presence of a program does not prove that it was executed; the date is the file's
  modification date. **ShellBags**: the folder dates are those recorded at the time (UTC, 2 s precision); the key's date
  indicates the last opening only for the first entry of the MRU list.
- **NTFS journal**: covers only the period still present in `$UsnJrnl:$J` (usually days or weeks); paths of deleted
  folders are rebuilt when the journal contains them, otherwise "MFT folder n". Since 2.18.1 folders are identified by
  record and sequence number (a reused record no longer gives the path of the current folder); above 500,000
  operations the most recent ones are kept, and the cut, a missing journal or one not read are stated among the system
  artifacts.
- **Event logs**: records recovered from the file's free space are marked as such and not counted twice if identical to
  an active record; unreadable records are counted and stated, not rebuilt.
- **Anomalies on deleted files**: reported only if the content demonstrably belongs to the file; a deleted executable
  with appended data (installers) may therefore not be reported.
- **Perceptual hashes** (64-bit dHash): they find resized or recompressed images, not cropped or rotated ones; matches
  are leads to be always checked visually; they do not replace PhotoDNA. Project VIC/CAID hash sets are used for the
  cryptographic hashes (MD5/SHA-1) and the category.
- **SRUM** (libesedb) and event logs (libevtx): read with the libraries included in plaso; the SRUM database can be
  "dirty" (not closed) and some rows unreadable.
- **Language model**: the answers are not literally reproducible and are not a result: every statement must be
  checked on the data indicated.

## 6. What was verified in 2.18.0 and how

| Feature | Test |
|---|---|
| Multiple installations (Windows.old) | Real disk: 3 installations, deleted hives recognised and stated |
| ShellBags (NTUSER.DAT, UsrClass.dat) | Built shell items (0xBEEF0004 v9, volume, GUID) and 1,489 real entries, none unrecognised |
| ShimCache / BAM | Built Windows 10/11 format and real SYSTEM hive (479 + 51 entries) |
| NTFS journal | Built USN v2 records (creation, deletion, rename, rebuilt folder) and real `$UsnJrnl:$J` (170,642 operations) |
| Thumbnails (thumbcache) | Built file (version 31) and real files (Windows 11 version 32: a header variant was found and handled) |
| Activity History | Built database and real database (252 activities) |
| Event logs, SRUM | Libraries simulated on the documented structure: to be confirmed on the real case with the included libraries (libevtx, libesedb) |
| Reading the journal and clusters with Sleuth Kit (pytsk3) | Logic tested with an independent reader; the link to pytsk3 must be confirmed by re-running "Artifacts" in the program |
| Perceptual hashes and reference folders | Resized and recompressed image = distance 0; different images far apart; uniform images excluded |
| Project VIC / CAID hash sets | VICS JSON with MD5, SHA-1 and category |

In **2.18.1**: journal paths with the sequence number (built journal: current folder, reused folder known and unknown
to the journal, deleted folder not reused, limit, unverifiable sequence, missing journal, volume that cannot be
opened); event logs with recovered, duplicate recovered and unreadable records (simulated libevtx). To be confirmed on a
real image with the included pytsk3 and libevtx (comparison with MFTECmd / EvtxECmd).

In **2.19.0** (language): the texts produced by the program are translated with a dictionary (`lingua_en.json`),
without touching data, hashes, paths and values read from the disk; a case's language is chosen when it is created and
stays the same. Full acceptance test run in both languages on the Mac and also on Windows. On the Mac: 112/112 in
Italian, 112/112 in English (in English the test recognises the translated expected titles). The dictionary is included
in the program fingerprint.

**Linux package (2.19.0)**: same program files as the Mac and Windows packages (identical fingerprint, `6d5b05c9…`).
Tests in the Linux development environment: acceptance test 112/112 in Italian and in English; a case with plaso
(log2timeline 20260720, multi-process mode with pyzmq), extended analyses and OCR on DFTT 7 (NTFS); interface opened in
the browser without errors. **Not tested**: `installa.sh` with apt and PyPI on a real computer (the development
environment cannot reach PyPI: the modules were built from source at the same versions), bulk_extractor, file selection
dialogs with zenity, the openai client (language model).

## 7. Change control

Every version is described in the change log ([CHANGELOG.en.md](CHANGELOG.en.md); manual, "Updates" section) with
what changes, how it was tested and what was NOT tested. The source fingerprint in the report makes it possible to
prove which version produced a result.
