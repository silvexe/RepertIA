# RepertIA tested on NIST's public test images

*RepertIA 3.0.2 — November 2026 · Italiano: [nist-dfr-carving.it.md](nist-dfr-carving.it.md) · Other tests: [index](README.md)*

## In short

RepertIA is a **free and open source** forensic analysis tool. We tested it on the same disk images that **NIST** (the
US National Institute of Standards and Technology) uses to test forensic tools, and we put its results next to the
**best published result** in the official reports of the **CFTT** programme (Computer Forensics Tool Testing),
published by the US Department of Homeland Security (DHS). The reports cover widely used commercial and open source
tools: the names and details of each tool are in the reports themselves, which anyone can read (sources at the end).

The result, in three lines:

- **Deleted file recovery:** on FAT, exFAT, NTFS and ext RepertIA recovers **as many whole and correct files as the
  best published result, or more**. On exFAT it recovers **all** the files, more than the best published result.
- **Rebuilding images from free space (carving):** on whole files RepertIA **matches the best published result**, also
  when the files do not start at the beginning of a sector.
- **Honest results:** when a deleted file now contains data of another file, RepertIA **says so, in every case**.

Everything needed to repeat the tests is public: NIST's images, the DHS reports, the measuring scripts
([tools/prove](../../tools/prove/)).

## Why this test matters

A forensic tool must return **exactly** what is on the disk: a wrong file in an investigation can lead to wrong
conclusions. NIST built disk images in which every sector of every test file carries the name of the file it belongs
to. This makes it possible to check, sector by sector, whether a tool returns the right file, an incomplete file or a
mix of different files.

**How to read the tables.** For each test: RepertIA's number; the **best result published by NIST** among the tools
tested, with the type of tool that achieved it (commercial or open source); and who is **the best in this test**. The
details for each tool are in the reports listed at the end.

## 1. Deleted file recovery

**What is tested.** 90 NIST "Deleted File Recovery" images (DFR-01…17): deleted files on FAT12/16/32, exFAT, NTFS,
ext2/3/4 and HFS+, in simple and difficult cases (fragmented files, files partly overwritten by others, deleted folders,
names in Chinese, Arabic, Russian…). Six tools tested by NIST (2014-2015 reports).

**The number that matters: files returned whole and correct** (the "Full" column of the NIST reports).

| Test | File system | **RepertIA 3.0.2** | Best result published by NIST | Best in this test |
|---|---|---|---|---|
| Without overwriting | FAT | **807** | 807 (commercial and open source) | tie: RepertIA, commercial and open source |
| | exFAT | **273 of 273** | 270 (commercial) | **RepertIA** |
| | NTFS | **273 of 273** | 273 (commercial and open source) | tie: RepertIA, commercial and open source |
| | ext | **273** | 273 (commercial and open source) | tie: RepertIA, commercial and open source |
| With overwriting | FAT | **885** | 885 (commercial and open source) | tie: RepertIA, commercial and open source |
| | exFAT | **376 of 376** | 370 (commercial) | **RepertIA** |
| | NTFS | **374** | 374 (commercial and open source) | tie: RepertIA, commercial and open source |
| | ext | **373** | 372 (commercial and open source) | **RepertIA** |

*On FAT a fragmented file cannot come back intact with any tool (on deletion FAT clears the cluster chain); on
ext3/ext4 the system clears the pointers to the data, so no tool recovers the content from the metadata. This is why on
FAT and ext the numbers stay below the total for everyone.*

**What the table says.** RepertIA **matches or beats the best published result on all four file systems**. On exFAT it
recovers all the files: when a deleted file is fragmented, RepertIA follows the cluster chain left in the FAT instead of
reading the clusters in sequence.

**Transparency.** When a deleted file now contains data of an active file (because that space was reused), RepertIA
flags it in the interface and in the reports: "DELETED · INODE REASSIGNED" or "DELETED · BLOCKS REUSED". On the NIST
images **all** these cases are flagged (FAT 40 of 40, exFAT 11 of 11, NTFS 24 of 24, ext 330 of 330). In the reports,
only one of the tools tested flags some of them.

**The other items of the reports.**

| Item | **RepertIA 3.0.2** | Best result published by NIST | Best in this test |
|---|---|---|---|
| Active files and folders (DFR-16, DFR-17) | **all listed** on every file system | all listed (commercial) | tie: RepertIA and commercial |
| Creation, modification, access dates | **same as the NIST table** on NTFS, FAT, exFAT and ext2 | same (commercial) | tie: RepertIA and commercial |
| Non-Latin names (Chinese, Japanese, Arabic, Russian…) | **intact** on FAT, exFAT, NTFS and ext | intact (commercial) | tie: RepertIA and commercial |
| Emptied Recycle Bin, compressed NTFS, files inside the MFT | **recovered** | recovered (commercial and open source) | tie: RepertIA, commercial and open source |
| Deleted files with other files' data flagged | **all** (405 of 405) | some (commercial) | **RepertIA** |

**Overall check.** Besides the comparison with the reports, we checked every file of every image against the NIST
document that describes how they were built: **835 checks, none open**. 643 give the expected result; 179 are known
file system limits, explained (like the two above); in 13 cases the NIST document is contradicted by the image itself
(for example a file that NIST lists as intact but that its own history shows as overwritten).

## 2. Rebuilding images from free space (carving)

**What is tested.** When the file system index is gone, a file can still be rebuilt by recognising its content (this
is called "carving"). NIST prepared two sets of images with photos and graphics (JPG, PNG, GIF, BMP, TIFF, HEIC) laid
out in increasingly difficult ways: one from 2014 (nine tools tested, 2014-2015 reports) and one from 2023 (thirteen
tools tested, 2024-2025 reports).

**How we measured.** For RepertIA we used a **stricter** yardstick than the reports: a file counts as recovered only if
it is **byte-for-byte identical** to the original. The NIST reports instead judge by eye whether the image looks
complete.

2014 set: files recovered complete.

| Test | Files | **RepertIA 3.0.2** | Best result published by NIST | Best in this test |
|---|---|---|---|---|
| Contiguous | 47 | **47** | 47 (commercial and open source) | tie: RepertIA, commercial and open source |
| Contiguous with other data in between | 47 | **47** | 47 (commercial and open source) | tie: RepertIA, commercial and open source |
| Not sector-aligned | 47 | **47** | 47 (commercial) | tie: RepertIA and commercial |
| Fragmented in order | 47 | **17** | 25 (commercial) | commercial tool |
| Incomplete | 45 | **13** | 16 (commercial and open source) | commercial and open source tools |
| Fragmented out of order | 41 | **6** | 16 (commercial) | commercial tool |
| Interleaved in pairs | 23 | **13** | 13 (commercial and open source) | tie: RepertIA, commercial and open source |

2023 set: complete files, including the EXIF thumbnails of the JPGs (39 possible per layout).

| Layout | **RepertIA 3.0.2** | Best result published by NIST | Best in this test |
|---|---|---|---|
| Contiguous | **39 of 39** | 41* (commercial); 39 counting the same way (open source) | tie: RepertIA and open source* |
| Not sector-aligned | **39 of 39** | 39* (commercial); 36 counting the same way (commercial) | **RepertIA*** |
| Fragmented | **3** | 7* (commercial); 3 counting the same way (commercial and open source) | tie: RepertIA, commercial and open source* |

*\* The tool with the best published result also counts the 4 thumbnails inside the HEIC files, which RepertIA's count
does not include. Counting the same way, the best published result is 39 for contiguous (open source), 36 for
non-aligned (commercial) and 3 for fragmented (commercial and open source, tie): RepertIA matches or beats all three.*

**False positives** ("recovered" files that are none of the originals): **zero** on all 26 images.

**What the tables say.**

- On whole files, also when they do not start at the beginning of a sector, RepertIA recovers **everything**: it
  matches the best published result.
- On the **fragmented** files of the 2014 set RepertIA is below the best published result (17 against 25, 6 against
  16); on the 2023 set it matches it. This is the hardest case for every tool, and it is the next thing we will work on.

**Two defects found thanks to this test, and fixed.** RepertIA enabled in PhotoRec (the carving engine it uses) also
some "noisy" signatures that broke BMP and TIFF files; it now uses the recommended configuration. And files not aligned
to sectors were not found: now, after PhotoRec, RepertIA searches for them byte by byte and finds their end from the
structure of the format, discarding anything that does not close correctly.

## 3. What this test does not say

To be fair:

- The NIST reports on deleted file recovery (2014-2015) and on the 2014 carving set cover the versions of the tools of
  those years; today's versions may do better. For carving we also used the 2024-2025 reports, on recent versions.
- This is not a certification: NIST did not test RepertIA. We used its public images and its method, and we publish
  everything so that anyone can repeat the measurements.
- RepertIA's yardstick (byte-for-byte identity) is stricter than the reports' judgement by eye: where they differ, it
  is to RepertIA's disadvantage.

## 4. Sources and how to repeat the tests

- Reports on deleted file recovery: DHS, "Deleted File Recovery and Active File Listing",
  <https://www.dhs.gov/publication/deleted-file-recovery-and-active-file-listing>.
- Reports on graphic file carving: DHS, "Graphic File Carving",
  <https://www.dhs.gov/publication/graphic-file-carving>.
- NIST CFTT programme: <https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt>.
- NIST images: "Deleted File Recovery" (<https://cfreds-archive.nist.gov/dfr-images/>), "File Carving" 2014
  (<https://cfreds-archive.nist.gov/filecarvingtestreports.html>) and "File Carving Graphic Files" 2023
  (<https://cfreds.nist.gov/all/NIST/FileCarvingGraphicFiles>).
- Measuring scripts: [tools/prove](../../tools/prove/) (`valida_nist_dfr.py`, `cftt_metriche_dfr.py`,
  `confronto_cftt_dfr.py`, `valuta_carving_nist.py`, `valuta_carving_2023.py`, `confronto_cftt_carving.py`).

*Reports and questions: [repository issues](https://github.com/silvexe/RepertIA/issues).*
