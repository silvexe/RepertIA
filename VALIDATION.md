# RepertIA – Validation document

*Translation of [VALIDAZIONE.md](VALIDAZIONE.md); the Italian text prevails.*

Program version: 2.20.2 · Document updated on 30/10/2026

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
| 2.20.0 | Author's Mac (app's Python; iLEAPP 2026.4.5, ALEAPP 2026.4.4) | 422/422 in Italian and 422/422 in English, from the assembled Mac package: 173 for disks + 249 for smartphones, 18 of which on WhatsApp and photos/videos/audio (fake WhatsApp backup with an invented key, system notices, reading on iPhone, Photos only/Videos only, audio of the extraction and of the chats, origin from the chats) and 17 on the fast search in the results (index built, message found from part of its text, contact number found written in another format, contact entry preview, no secret keychain value in the index), 17 on the portable report (timeline per day with every event once, iLEAPP/ALEAPP rows in the files per artifact, fast search present), 33 of which on the interface buttons, 5 on cited files, attachments and chat summary, 44 in the two fake-keychain tests, 20 on cited files in three levels (19 in the fake-extraction test, 8 of them on the test rows, and 1 on the real iLEAPP SMS rows), 45 on the later verification of the log, 36 on log and tools in the report, 11 on sysdiagnoses (test 25 with public excerpts of the iLEAPP tests) and 7 on audio transcription (model list, mandatory consent, invalid files rejected, text path with a fake engine; the real transcription with an installed model is a measurement) (77/77 on public images or on values published by third parties) |
| 2.20.1 | Author's Mac (as for 2.20.0) | 427/427 in Italian and 427/427 in English, from the assembled Mac package: 178 for disks + 249 for smartphones; the 5 new ones concern the AI Act (agent finding "AI model – to be checked" in findings.json and in the report, without the sentence "every finding was verified"; AI metadata in Word and PDF; after "I confirm, verified" the finding is verified with operator and date in the report and in the log; local and private LLM servers told apart from external ones) (77/77 on public images or on values published by third parties) |
| 2.20.1 | Author's Windows 11 | 417/426 (77/77 on public images): empty rows imported from iLEAPP on Windows (5 errors) and path comparison in the test (4 errors) → fixed in 2.20.2 |
| 2.20.2 | Author's Mac (as for 2.20.0) | 433/433 in Italian and 433/433 in English, from the assembled Mac package: 178 for disks + 255 for smartphones; the 6 new ones check that no empty row enters the case, also with a TSV written the way iLEAPP does on Windows |
| 2.20.2 (fixes, before assembly) | Author's Windows 11 | test passed, confirmed by the author |

Carving DFTT 11: 2 files out of 15 (enterprise.wav, haxor2.jpg) are not recovered by PhotoRec: this is a limitation of
PhotoRec, declared as a "measurement" and not as a requirement.

**To do for every new version:** run the acceptance test on Mac, Windows and Linux before use in a case and keep the
`collaudo_<date>.md` report with the expert report. Full test on the Mac: 2.18.1 112/112; 2.19.0 112/112 in Italian and
112/112 in English. Full test also run by the author on Windows for versions 2.17.x to 2.19.0.
**Linux (experimental, 2.19.0)**: test passed in the Linux development environment; to be repeated on a Linux computer
installed with `installa.sh` before use in a case. **2.20.2**: acceptance test on the Mac 433/433 in both languages; passed on Windows with the fixes, before
assembly; to be repeated with the final Windows package and on Linux (packages built on the Mac).

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
- **Smartphones (2.20)**: only what is in the extraction can be seen; encrypted databases (Signal, WhatsApp `.crypt*`
  backups) are not read without the key; deleted messages in the free pages of databases are not recovered; extractions have
  no deleted files of the file system; the DOS dates of zip files (without time zone) are converted with the device time zone
  and declared; own readers only for WhatsApp, iMessage/SMS and SMS/MMS (the other apps with iLEAPP/ALEAPP, third-party
  programs whose version and fingerprint are recorded). Chats of the other apps and **Calls** are derived from the
  iLEAPP/ALEAPP rows according to `forense_mobile_leapp_mappa.json`: they are worth what the source rows are worth (given
  for every message and call); «direction not stated» and merged duplicates are declared; attachments copied by
  iLEAPP/ALEAPP into their report are working copies made by those tools, not the original in the extraction. The
  direction rules per app are verified only on the app versions of Hickman's images (2024): with other versions the
  database may change. **WhatsApp**: the meaning of the types and of the notice codes is not published by WhatsApp; on
  Android the notice codes are explained with public sources and their level (none verified on a phone with documented
  actions); on iPhone no source explains the notice codes (values and facts from the database are shown) and the read
  status of sent messages cannot be read. WhatsApp backups: only `.crypt14` with the key in the extraction (not
  crypt12/crypt15, not incremental backups). Beyond 500,000 iLEAPP/ALEAPP rows some tables are not imported (listed in the
  case; chats, messages and calls take precedence). The fast search looks only in the case results (not in the content
  of files or in the timeline). Calls: an interactionC row without a number is not
  merged with the matching system-log row (one in Hickman's iOS 17) and appears as a call of its own.
- **Cited files (2.20)**: the file named by a row (phone, Windows or macOS path, iLEAPP/ALEAPP «media/…», chat attachment)
  is looked up by path with the `forense_percorsi.json` table, then by hash if the row gives one, then by name and size or
  by name only; the latter are marked «to be verified» because they may be another file with the same name. A file not
  found may be outside the extraction (the phone's system partition, another disk) or deleted; Android `content://`
  references are not resolved; the translation of Windows paths (drives, volumes, environment variables) is tested with a
  test index, not yet on a real image. A thumbnail of an attachment taken from the app's database is a reduced
  representation saved by the app, not the file.
- **iOS keychain (2.20)**: RepertIA neither decrypts nor reads the keychain: it records it (SHA-256) and passes it to iLEAPP
  with `--keychain`; decryption and reading are iLEAPP's and are as reliable as iLEAPP. The supplied keychain serves only
  the artifacts that look up an app's key; the keychain artifacts (Wi-Fi, web passwords…) are derived by iLEAPP from the
  one inside the extraction. Tested only with **fake** keychains; **not tested on real GrayKey or Cellebrite keychains** nor
  on the real decryption of Signal, Session or SimpleX. Secret values are hidden in RepertIA, but the iLEAPP report in the
  case folder contains them in clear text.
- **iOS sysdiagnose (2.20)**: RepertIA does not interpret the sysdiagnose: it records it (SHA-256) and has iLEAPP read it
  (`-t gz`); the rows are as reliable as the iLEAPP modules. Creation date and device come from the **name** of the archive
  folder (and from `remotectl_dumpstate.txt` if present): a renamed archive would give wrong values. Tested with archives in
  the form of a sysdiagnose built with the public excerpts of the iLEAPP tests (`ps.txt`, BatteryUI, ManagedSettings):
  **not tested on complete sysdiagnoses** of a case; the unified logs (`system_logs.logarchive`) are read by iLEAPP only with
  its external program `unifiedlog_iterator`, not included.
- **Log verification (2.20)**: it proves that the log, up to the given final hash, has no lines changed, removed or inserted
  afterwards and that the exported files still present are the recorded ones; it does **not** prove who used the program
  nor that the operations described are correct or complete. Without a final hash kept elsewhere (delivered report,
  minutes) a log rewritten in full with a recomputed chain appears intact and lines removed at the end are not visible; the
  original content of an altered line cannot be reconstructed; exported files outside the case folder or deleted cannot be
  re-checked.
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

In **2.20.0** (smartphones): separate modules, loaded only for smartphone cases; the disk cases of the acceptance test
produce databases identical, row by row, to those of 2.19.0. Tests: (1) acceptance test with two extractions built from
excerpts of public images (iOS 15 by Josh Hickman, Android 15 «anne_a15») used in the iLEAPP and ALEAPP tests: number and
times of all iMessage/SMS (48), iOS WhatsApp (32) and Android SMS/MMS (91) messages equal to the results published by those
projects; Android WhatsApp built with known content (message only in the -wal file, names from the address books, linked
photo with SHA-256, location); zip with UTC and DOS dates, tar.gz with verified derived copy. (2) Full public images by Josh
Hickman: iOS 13.4.1 (Magnet ACQUIRE tar, 17 GB, 351,466 files) and Android 10 (zip, 5.2 GB, 76,403 files): WhatsApp, iMessage
and SMS messages have the times given in the author's documents (converted from EDT/EST to UTC). With iLEAPP 2026.4.5: the
48 iMessage/SMS messages of the chat view match those of the iLEAPP «SMS» artifact conversation by conversation (17 of 17,
same messages and same times) and the sum of the tree sub-entries (102 categories, 323 artifacts) equals the total number of
rows (300,277); with ALEAPP 2026.4.4: 70 categories, 207 artifacts, 78,370 rows. These tests found five bugs that were fixed
before publication (database lock with large extractions, 2020 WhatsApp schema, database copies left by Magisk, long fields
in the iLEAPP results, «._» files created by macOS on exFAT disks counted as iLEAPP/ALEAPP tables). Note: the published iOS 13.4.1 tar has an MD5 different from the acquisition log
because the author regenerated it after the acquisition. (3) Interface buttons (in the acceptance test since 2.20.0, with the
same requests as the page): Favorites, Finding, Source and «Show in the tree» on a file and an artifact of a disk case and, in
smartphone cases, on a file, an iLEAPP/ALEAPP artifact, a chat and a call (references without missing values, opened path
equal to the expected one); opening of every tree folder down to the second level with the stated number of items; tree index
deleted while the case is open and rebuilt. These are internal checks and are not counted among the values published by
third parties.
(4) Cited files and attachments (in the acceptance test from 2.20.0): Android test extraction with a built Google Photos
(`gphotos-1.db`: one file at the stated path, one moved to another folder, one missing → found by path, by name and size,
missing) and built WhatsApp attachments (one in place with `file_hash`, one moved and renamed, one with only the thumbnail
in the database, one missing → by path, by hash, thumbnail, missing; SHA-256 of the files found equal to `file_hash`); chat
summary saved in the case. On Hickman's full images: Pixel 3 Google Photos – Local Media found by path 108 of 108
(`/storage/emulated/0/…` → `data/media/0/…`); WhatsApp attachments of messages 14 and 16 found with SHA-256 equal to
`file_hash`; overall, in the iLEAPP/ALEAPP artifacts, 7,925 cited files found out of 9,956 (Pixel 3) and 11,803 out of
14,346 (iOS 13.4.1), with the count per method and section produced by `tools/file_citati_conta.py`. These tests found and
had two existing errors fixed (chat summary not saved because of a missing import; WhatsApp iOS photo dimensions read as a
location). Cited files in three levels (also in 2.20.0): **fake** iOS extraction `ios_file_citati.zip` (IMG_0059.PNG in the
same locations as in Hickman's public iOS 13.4.1 case: `DCIM/100APPLE`, copy in `PhotoData/OutgoingTemp`, thumbnail folder
with the same name; two different IMG_0100.JPG in different folders; two `verbale.pdf` with the same final path) and 8 rows
in the iLEAPP style with the expected result: «Directory» + «Filename» → a single file found with certainty by path with the
link to the folder; the same with the full path too → one file, two fields; an «Original Filename» from another folder →
second file, probable; name only with two namesakes → probable with two candidates; name and size → probable, one candidate;
name, size and SHA-256 → certain, hash verified; same final path in two apps → certain with one copy in the details; missing
name → not present. For every row the same result in the table's quick search (a single thumbnail) and in the portable
report. On the real iLEAPP SMS rows (test 20): 11 attachments, each a single file found with certainty, 8 given by two
fields («Attachment File» and the attachment name). On Hickman's full images, after merging the fields: iOS 13.4.1 12,941
distinct cited files (1,405 given by several fields of the same row): 10,060 certain, 382 probable, 2,499 not present (161
with a copy in the iLEAPP report); Pixel 3 9,920 (25 merged): 7,612 certain, 277 probable, 2,031 not present (1,124 with a
copy in the ALEAPP report). The test on the iOS case had one error fixed before publication: with one folder and two names
the folder was also joined to the original name («Original Filename»), which is elsewhere.
(5) iOS keychain (in the acceptance test from 2.20.0): minimal iOS extraction built with **fake** keychains (no real data) —
a decrypted one (`genp` with an invented Wi-Fi network and a Signal-style entry) passed to iLEAPP with `--keychain`, and one
in the Cellebrite encrypted format (invented keys) in `extra/KeychainDump` — in two tests, with and without a supplied
keychain: SHA-256 in the case and in the hash-chained log, `--keychain` in the iLEAPP command and entries read by iLEAPP,
keychain stated (supplied / found in the extraction), *Keychain Wifi Credentials* and *Keychain Web Passwords* artifacts
derived by iLEAPP, secret values never in clear text in the case tables (only in `leapp_segreti`), hidden in the interface
details, «Show» revealing the value and logging it without writing it, absent from the portable report without the explicit
choice and present with it, absent from the agent's artifact tool. These are internal checks.
(6) Sysdiagnose, smartphone reports and log verification (in the acceptance test from 2.20.0). Test 25: the iOS test
extraction with two archives in the form of a sysdiagnose built by `tools/collaudo_mobile.py --sysdiagnose` with the excerpts
published in the iLEAPP v2026.4.5 tests (MIT licence; downloaded from GitHub and checked with SHA-256): real `ps.txt` of an
iPhone with iOS 16 (build 20A362) and BatteryUI and ManagedSettings of iOS 26.6 (build 23G71) with the identifiers replaced
by the iLEAPP authors. Checked: SHA-256 in the case and in the hash-chained log; no copy in the case; creation date
(2025-04-07 15:06:18 UTC and 2027-07-19 14:18:09 UTC) and device from the name; rows in the «Sysdiagnose» group marked with
the file name; *Sysdiagnose Process* = 333 rows, equal to the number of processes in `ps.txt` counted **without iLEAPP**
(lines with at least 18 fields and numeric PIDs); «Remove» removing only the rows of that file; *Source* on a sysdiagnose row
with a clear message. Report: in every test, number of entries and final hash of the log equal to those of the log before the
«report» line; in disk cases the method with The Sleuth Kit as before (report of a disk case compared line by line with the
previous version: only the new log lines change); in smartphone cases no mention of Sleuth Kit or plaso outside the iLEAPP
section, method of the file system extraction, iLEAPP with version and fingerprint, SHA-256 of keychain and sysdiagnoses. Log
verification (`forense_registro.py`, the same as *Verify log* and `tools/verifica_registro.py`): in every test chain intact,
same final hash as the program and final hash of the report found; on test 01 (intact E01), on copies of the log: a modified
line reported with its number, a line removed in the middle reported with the number of the missing entry, three lines removed
at the end not detectable without final hash and detected with final hash and number of entries, lines added after the report
recognised as later ones; on the tests with exported chats: exported files identical and a modified exported file (on a copy)
detected. These are internal checks except those on published values (times, processes of `ps.txt`).
(7) Interface navigation (from 2.20.0, outside the acceptance test: it needs a browser driven by Playwright, which is not
in the packages): `tools/prova_navigazione.py --casi <copies of the acceptance test cases>` starts the interface and, on
every case, tries search from the 🔎 button at the top → results → click on a tree item → Back up to the start page →
Forward, the same from the search label and from the tree entry, two sub-items clicked one after the other without
waiting and the parent items of the tree closed; after every step it checks that the breadcrumbs show the open section and that the table shows exactly that
section. On cases 01, 20 and 25 of the acceptance test, 1280×800 window: 66/66 in Chromium (Italian and English) and in
WebKit.
(8) WhatsApp, calls and chats from iLEAPP/ALEAPP (from 2.20.0, outside the acceptance test: Josh Hickman's complete public
images are needed, tens of GB). Images: iOS 13.4.1, iOS 17.3 (Cellebrite FFS), Android 10 (Pixel 3), Android 14 (Pixel 7a,
Cellebrite FFS; SHA-256 of the archive and of the extraction equal to those in the .ufd file). **Non-regression**: the
four cases redone with the final sources and compared by content with those prepared with the sources of the previous
2.20.0: no message, attachment, conversation or call missing; only intended differences (ALEAPP's WhatsApp duplicate
removed; time of calls also found in interactionC taken from the system log *Call History*; on iOS 17 iLEAPP rows imported
with the new precedence beyond the 500,000 limit). **Comparison with the activities
documented** by Hickman (documents of the iOS 17 and Android 14 images: action, local date and time with the declared
time zone, text): a documented message is «found» if in the same app there is a message with the same text (normalised,
first 16 letters) within ±3 minutes, and its direction is compared; a call if in the same app there is a call within ±3
minutes. Chats derived from iLEAPP/ALEAPP: iOS 17.3 1,167 documented messages, 766 found, 759 with the same direction
matching the documentation; Android 14 656, 272, 271. The 8 different ones are not RepertIA errors: 7 are errors in the
documentation (the same message is marked «Sent» in the documents of both phones; where the app is also read on the other
phone, Gettr, Google Chat, Viber and Messenger, its database says that phone sent it, as RepertIA shows, and the context
confirms it: e.g. «Video call time.» followed by an incoming video call) and 1 is a wrong match of the script («Deleted.»
matched to «This message was deleted»). Right direction therefore 766 of 766 and 272 of 272. Calls: WhatsApp (iOS 17 8, Android 14
4), Skype (8 and 4), imo (Android 14 4), Signal (Android 14 4), Google Voice (2), Facebook Messenger (8, start computed),
TeleGuard (4, start computed) equal to the documentation; Android 14 phone 2,655 = rows of `calls` in calllog.db. Read
status: Android 14 22 deliveries and 10 reads as in the database; iPhone, the read time of received messages
(`ZSENTDATE`) matches within 1 s the receipt recorded by the Android 14 in the same conversation in 8 cases out of 10.
Backups: the Android 14 `msgstore.db.crypt14` decrypted with a verified tag (197 messages, all present in the current
database), 4 backups recognised as encrypted with another key, 2 incremental ones listed. These checks apply to the
**method** on the app versions used by Hickman, not to the messages of a case; the detail per artifact is in the
`verifiche` section of `forense_mobile_leapp_mappa.json`. The comparison scripts are outside the repository (they contain
personal paths): repeatable with the same public images.
Timeline chart (per-minute computation, 2.20.0): compared with the previous event-by-event computation, identical on iOS
17.3, Android 14 and DFTT 05, in the phone's and Italian time, per day, month, year and automatic choice, with and without
filters (text, period); on iOS 17.3 from about 40 s to 2-7 s.
**Not tested**: Windows and Linux, real GrayKey and Cellebrite extractions with their metadata, complete sysdiagnoses,
crypt12/crypt15 WhatsApp backups, WhatsApp notice codes on a phone with documented group actions.

## 7. Change control

Every version is described in the change log ([CHANGELOG.en.md](CHANGELOG.en.md); manual, "Updates" section) with
what changes, how it was tested and what was NOT tested. The source fingerprint in the report makes it possible to
prove which version produced a result.
