# Change log

*Translation of [CHANGELOG.md](CHANGELOG.md); the Italian text prevails. Versions 2.14.0 and later are translated in
full; earlier versions are summarised (details in the Italian change log).*

For every version: what changes, how it was tested, what was not tested.

## 2.19.0 – Linux package (experimental)

New **`RepertIA-2.19.0-Linux.tar.gz`** package for Linux x86_64 with Python 3.12 or later (Ubuntu 24.04+, Debian 13). The program does not change: same files and same fingerprint as the 2.19.0 Mac and Windows packages. `installa.sh` installs Sleuth Kit, libewf, PhotoRec, Poppler, ExifTool, Tesseract and zenity with apt, creates in `python/` the environment with plaso, libyal, pytsk3, Pillow and openai at the same versions as the other packages (`requirements-linux.txt`) and adds RepertIA to the applications menu; `RepertIA.sh` starts it, `collaudo.sh` runs the acceptance test, `aggiorna-strumenti.sh` updates the system tools. 7-Zip 26.01 for Linux and the OCR data are included. **Tested:** in the Linux development environment, acceptance test 112/112 in Italian and 112/112 in English, a case with plaso, extended analyses and OCR, interface in the browser. **Not tested:** `installa.sh` on a real computer (apt and PyPI), bulk_extractor, zenity, the openai client.

## 2.19.0

User interface and case texts **in Italian or English**. Language selector at the top right (the page reloads); in the new-case form you choose the **language of the case texts** (artifacts, summaries, Markdown/Word/PDF reports, portable report, exported CSV files), saved in `case.json` and shown in the case list and in the report (*Analysis environment*); earlier cases stay in Italian. Only the text changes: data, hashes, paths and values read from the disk do not change. Technique: the texts stay in Italian in the sources and act as keys (`tr()` in Python, `T()`/`TF()` in the pages) of the `lingua_en.json` dictionary (2,400 texts), which is included in the program fingerprint; new `tools/lingua_controlla.py` for the checks; dates and numbers in the pages formatted for the language. **Acceptance test** with `--lingua it|en` (in English it accepts the translated expected titles). **Windows**: bilingual installer (language chosen at start, which becomes RepertIA's default language), `README_EN.txt` next to `LEGGIMI.txt`; on the Mac `README_EN.txt` in the zip. The language model receives its instructions and answers in the interface language. **Tested:** acceptance test 112/112 in Italian and 112/112 in English on the Mac; English interface and portable report checked section by section on a test case. Acceptance test also run on Windows. The manual and VALIDAZIONE.md stay in Italian (English translations later added to the repository: docs/MANUAL.md, VALIDATION.md).

## 2.18.1

Reliability fixes for the NTFS journal and event logs. **NTFS journal: paths with the sequence number.** An operation's folder was looked up by MFT record number only: if that record had been reused by another folder, the file ended up in the wrong folder (a plausible but false path). Now the reference is complete (record and sequence): the current MFT path is used only if the record is still that folder (same sequence, or increased by 1 if the record is free); otherwise the name recorded in the journal for that reference is used, otherwise "MFT folder n sequence s: record later reused by …". For the same record, an existing entry wins over a deleted one. **Journal: limit and status stated.** Above 500,000 operations the most recent are kept and the new system entry "NTFS journal $UsnJrnl read" says how many, the period, how many were excluded and how many folders have a reused record or an unverifiable sequence; a missing (disabled) or unreadable journal is stated ("NTFS journal missing" / "not read") instead of silently giving zero operations. **Event logs: recovered and unreadable records.** Records recovered from the free space of the .evtx file are marked "recovered" (title, detail and `recuperato` field); those identical to an active record are not counted twice (previously a logon could be counted twice); unreadable records are counted. The account card says how many logons and sessions come from recovered records; each log read has a system entry with active, recovered and unreadable records, and for system events also the 20,000 limit if reached; logs not extracted or unreadable and a missing pyevtx module are stated. **Tested:** built journal (v2 records with current folder, reused folder known and unknown to the journal, deleted folder not reused, limit, unverifiable sequence; missing journal and volume that cannot be opened) and simulated libevtx (active, recovered, duplicate recovered, unreadable records) with logons and system events. **Not tested:** real pytsk3 (`open_meta(...).info.meta.seq`) and real libevtx on a disk: re-run "Artifacts" on a real image and compare with MFTECmd / EvtxECmd.

## 2.18.0

More forensic coverage of Windows disks. **All Windows installations**: registry, users, logons, prefetch, Amcache, SRUM and event logs are read for every folder containing `Windows/System32/config/SYSTEM` (including `Windows.old`, `Windows.old.000`), with the name in square brackets in the artifacts: on an upgraded or reinstalled disk the earlier activity was previously invisible. **New artifacts**: opened folders (ShellBags), ShimCache and BAM/DAM, SRUM, Activity History, NTFS journal `$UsnJrnl` (files created, deleted and renamed, with the rebuilt path), event logs (installed services, power on and off, sessions and Remote Desktop, Defender, USB drives, cleared logs), `thumbcache` thumbnails extracted with their hashes. New categories: *Opened folders*, *NTFS journal*, *System events*. **Perceptual hashes**: new optional analysis, *Similar images* search and comparison with folders of reference images in *Hash sets*; **Project VIC / CAID** (JSON) hash sets are read with their category. **Validation**: new `VALIDAZIONE.md` document (*Validation* section of the manual) with method, test data, acceptance test results and known limitations. Artifacts must be re-run (*System artifacts* → Redo) to see the new features in cases already prepared.

## 2.17.3

Two fixes after a second test on the same real image. **Anomalies: false positives remained among deleted files.** The 2.17.2 check only looked at whether the first cluster was currently assigned to an existing file; but if after the deletion those clusters were used by another file, itself deleted, they are free and the content read belongs to that other file (an `msedge.dll` that "contains" a JPEG, an `image.pdf` that "contains" an executable). Now a single pass over the MFT finds every other record (free ones too) using those clusters, and the content must be consistent with the file's size and ending; if it is not, the entry is excluded and the summary says how many and why. On the real image: of the 293 reports on deleted files 12 remain, almost all of low severity. Also, program modules with their own extension (`office.odf`, Acrobat's `Flash.mpp`…), executables in program folders, installer icons and registry logs are no longer anomalies; a photo/video swap is low severity. **User accounts: logons at 0.** For an account linked to a **Microsoft account** (or signing in with PIN/Windows Hello) Windows does not update the SAM logon counter and date. Logons are now counted from the event logs: `Security.evtx` (4624 successful, by type: interactive, cached credentials, remote; 7 = unlocks, counted separately; the two events an administrator generates for the same logon count once; 4625 failed) and `System.evtx` (Winlogon 7001, sessions). The account card shows the number of logons in its title, the period covered by the logs (earlier logons are no longer recorded), the last logon, the Microsoft account address and the SID; the SAM counter is still shown separately.

## 2.17.2

Three fixes after use on a real image. **Anomalies: false positives.** A `.png` could turn out to be a "Windows executable": for a *deleted* entry the program read the content from the inode number, but on NTFS (and FAT, ext) that record may already have been assigned to another file, or its clusters overwritten. Now, before reporting a deleted file, it checks that the name matches the one stored in the record and that the first data block has not been reused; entries no longer reliable are excluded (the number is in the summary). Files with a current name are examined first, so an inode already read is not read again under an old name. More known executable extensions (`.msstyles`, `.xll`, `.vxd`…), no anomaly for a different format in `.dat/.bin/.db/.tmp…` and low severity for a swap between image formats. **User accounts: logons always 0.** Windows writes registry changes first to the log files (`SAM.LOG1`, `SAM.LOG2`, `NTUSER.DAT.LOG1`…) and only occasionally to the hive: reading `SAM` alone shows an old state. Now the logs next to the hive (SAM, SYSTEM, SOFTWARE, NTUSER.DAT, Amcache) are applied to a **working copy** (records verified with Marvin32 hashes, only if the sequence is continuous; the original does not change) and the operation is stated among the artifacts ("Registry: logs applied to…"). Moreover the SAM counter does not count all logons (Microsoft account, PIN, Windows Hello): if it is 0 but the account has been used, "never logged on" is no longer written, and the last profile load and unload (SOFTWARE, ProfileList), the bad passwords and, for each user, the last write of `NTUSER.DAT` are added. **Documents by extension**: in the tree view the Documents entry is split by extension, with an *Extension* filter in the section.

## 2.17.1

On Windows the **Choose…** button of *Cross-check with another tool* did not open the file dialog (the apostrophe in the Italian title «Scegli l'elenco…» broke the Windows command). Also fixed the filter of the *Choose the forensic image* dialog (it showed CSV lists instead of forensic images) and the choice of the **hash set** file, which did not open.

## 2.17.0

**Unallocated space you can browse**, as in Autopsy: an `$Unalloc` folder in every volume with the free-space runs of the file system, which can be opened as text and hex, exported with SHA-256 and added to favourites; the same for unallocated areas between partitions and for volumes Sleuth Kit cannot read. Verified: the bytes of the runs match Sleuth Kit's unallocated stream (`blkls -A`) on FAT12, FAT16, NTFS and ext4 (from E01 too).

## 2.16.2

**Faster start on Windows**: before querying an LLM server the program checks within half a second that the port is open. On Windows every attempt on a closed port cost about 2 seconds and, without an LLM server running, opening could take tens of seconds; now it is immediate. An unreachable network server is discarded in a few seconds.

## 2.16.1

**Correct FAT/exFAT dates on the Mac too** when the device is in a different time zone from the computer: Sleuth Kit on macOS lost the time-zone setting and used the computer's (DFTT 5 test: times shifted). Now the neutral time zone reaches Sleuth Kit through the process environment, identically on Mac, Windows and Linux, and RepertIA converts to the device's time zone. Cases with FAT/exFAT partitions prepared with earlier versions are recomputed automatically when first opened (`date_fat_ricalcolate` entry in the log).

## 2.16.0

New packages: Mac app `RepertIA.app`, Windows installation in `Programs\RepertIA` with a "RepertIA" entry in the Start menu, test folder `RepertIA-collaudo`. Environment variables with the `REPERTIA_` prefix.

## 2.15.5

**Disk split into volumes** in the file-system tree (as in Autopsy): under "Disk · <table type>" all the rows of the partition table read with `mmls` appear — table area, unallocated areas and volumes — with index (`vol<n>`), description and sectors in 512-byte units (e.g. "vol2 (Win95 FAT32 (0x0b): 32-15257599)"). Readable volumes open as before; those Sleuth Kit cannot read are marked "file system not read"; APFS volumes are under their partition. A click on a row that cannot be opened shows its position and size in bytes. The same view is in the portable report. Images without a partition table (e.g. USB drives) stay as before.

## 2.15.4

In the new-case form the example for the *Operator* field is a fictitious name ("John Doe"). Added the note about the personal project and the development with the help of Claude (Anthropic).

## 2.15.3

**Correct FAT/exFAT dates on Windows too**: on Windows Sleuth Kit did not understand the name of the device's time zone (e.g. `Europe/Rome`) and applied "zone 0 with US daylight saving time": FAT/exFAT dates were shifted by one hour (DFTT 5 test on the Windows PC: 2 checks failed). Now Sleuth Kit always reads the time written on the disk as it is (neutral zone `UTC0`, understood the same way by Windows, macOS and Linux) and RepertIA converts to the device's time zone with the time-zone database (exact European daylight saving time, in past years too). This applies to the timeline, tree, Metadata tab and portable report; NTFS/ext/HFS/APFS dates (already UTC) do not change. Cases with FAT/exFAT partitions prepared on Windows with versions 2.13.7-2.15.2 are recomputed automatically when first opened (`date_fat_ricalcolate` entry in the log).

## 2.15.2

**Archives recognised by content**: an archive (ZIP, RAR, 7z, tar, gzip, xz, bzip2, CAB) with another extension, for example a ZIP renamed `.jpg` or `.boo` to hide it, now opens like the others, also inside other archives and mail attachments; documents that are ZIP files by construction (Word, Excel, OpenDocument, epub, jar, apk…) stay documents. The count of "archives recognised by content" is in the *Archives and mail* summary. DFTT 8 test: `file9.jpg` inside `file9.boo` is now extracted (from measurement to passed check): 112/112, 46/46 on the public images.

## 2.15.1

**Two carving errors found by the acceptance test on the Mac** (DFTT 11):
- **Recovered files beyond the 500th lost**: PhotoRec puts at most 500 files per folder (`recup.1`, `recup.2`…) but lists everything in a single `report.xml` without the folder; RepertIA recorded only those of the first. With more than 500 recovered files the others stayed on the disk but did not appear in the case, the report or the searches. Now they are all included (tested: 651 of 651).
- **"dovecot" false positives of PhotoRec 7.2** (Homebrew's on the Mac and the one in the Windows installer): hundreds of 80 KB files covering real documents and videos (DFTT 11: 8 identical files out of 15 instead of 13). From 7.2 that type is disabled (variable `REPERTIA_PHOTOREC_ESCLUDI`, `nessuno` to re-enable it); the report states it among the carving warnings.
- The **EXIF thumbnails** PhotoRec extracts from recovered photos (`t….jpg`) enter the case with the photo's offset.
- Acceptance test: new check "all files found by PhotoRec are in the case". Tested with PhotoRec 7.1 and 7.2 (built from source): 111/111, 45/45 on the public images, carving 13/15 identical at the published offset with both.

## 2.15.0

**Cross-check with other tools and acceptance test on public images**:
- **Cross-check with another tool** (Autopsy, FTK Imager, X-Ways, EnCase, AXIOM, Sleuth Kit): files with the same/different hash, found by only one, discordant "deleted" status; in the report and in the log.
- **Acceptance test with the DFTT images** and the values published by the project (included in the test zip): 44 checks passed out of 44; measurements: 3 fragmented files on FAT that cannot be rebuilt, 13 files out of 15 recovered identical and at the published offset by the DFTT 11 carving, ZIP with a different extension not opened.
- **Media without a readable file system** (damaged or unknown): previously preparation stopped; now the case is created and carving of the whole image, bulk_extractor, byte search and plaso remain available (found with DFTT 11).

## 2.14.0

**Verifiable integrity and complete Mac support**:
- **Hash of the acquired data** compared with the acquisition hash recorded in the E01 or in the acquisition program's log (FTK Imager, Guymager, ewfacquire…); an altered E01 or one with unreadable blocks = **DIFFERENT**; E01 acquisition data in the report.
- **Hash-chained log** (`audit_log.jsonl`): tampering is detected by *Verify hashes* and stated in the report.
- **Environment in the report**: program fingerprint and versions of all tools, at preparation and at report time.
- **Mac, bug fixed**: on Macs from Catalina onwards the artifacts of the **Data volume** (users, networks, programs) were not read because `SystemVersion.plist` is on the system volume. Now they are.
- **Mac, new artifacts**: download quarantine, launch items, TCC permissions, iMessage (also from the `-wal`), recent documents, Safari downloads, app usage (knowledgeC), Bluetooth and volumes, Time Machine, computer name and last user.
- **APFS snapshots** in the *Shadow copies* section: deleted files or earlier versions recovered from snapshots.
- **plaso on unlocked FileVault volumes** (it receives the key in memory) and the **Mac's time zone** detected automatically.
- **Acceptance test with reference images** (`forense_collaudo.py`, zip `RepertIA-collaudo.zip`).
- Tested: intact/altered E01, raw with FTK log, synthetic Data volume, normal/encrypted APFS (also with plaso), BitLocker To Go; GUI and portable report with Playwright. Not tested on a real E01 of a recent Mac, nor on real APFS snapshots (reading snapshots is tested with simulated data), nor on Windows.

## Earlier versions (summary)

- **2.13.9** – Dates and times: third display mode "device time zone" and labels always correct.
- **2.13.8** – The device's time zone is detected automatically (from the registry or the system).
- **2.13.7** – Court-proof dates and times: device time zone, displayed zone shown everywhere, daylight saving time.
- **2.13.6** – Wrong APFS password reliably recognised.
- **2.13.5** – BitLocker and LUKS can be decrypted from the encrypted-volumes pop-up.
- **2.13.4** – Warning about encrypted volumes before the analysis.
- **2.13.2** – Encrypted volumes excluded from the analysis.
- **2.13.1** – Warning about encrypted volumes.
- **2.13.0** – Macs with APFS (libfsapfs), FileVault unlocking.
- **2.12.0** – Configurable cache and case folders wherever you want.
- **2.11.0** – Case data, encrypted volumes in the tree, tree-view button.
- **2.10.1** – Sorting and value menus in the columns (program and portable report).
- **2.10.0** – Disk space: a 40 GB E01 no longer produces a 1 TB case; column filters in all lists.
- **2.9.1** – *Text* preview tab shows the whole text.
- **2.9** – Text index without silent truncation.
- **2.8** – Windows: PDF text extraction fixed.
