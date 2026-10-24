# RepertIA — By silvexe — User manual

*Translation of the Italian manual [src/README.md](../src/README.md); the Italian text prevails. The version history
("Aggiornamenti") is in [CHANGELOG.en.md](../CHANGELOG.en.md) and the validation section in
[VALIDATION.md](../VALIDATION.md). Names of buttons and menus are given as they appear in the English interface; file
and folder names created by the program (`estratti`, `export`, `CasiForensi`…) are in Italian whatever the language.*

**Forensic analysis of disk and USB drive images with local artificial intelligence.**
Version 2.19.0 · macOS, Windows and Linux (experimental) · interface in English or Italian

RepertIA takes a forensic image (raw, dd, img or E01), indexes it with established forensic tools and lets you examine
it in two complementary ways:

- **without a model**, by browsing the indexed data directly: file-system tree, list of files including deleted ones,
  timeline with a chart per day, document text, photo metadata, recovered files and items of interest;
- **with an AI agent running on your computer** (LM Studio, llama-server or Ollama), to which you ask questions in
  English or Italian: it uses read-only tools only, cites offsets, inodes and paths and records findings for the
  report.

---

## Privacy: everything stays on your computer

RepertIA is designed to work **only locally**. Case data are **never sent to third parties**.

- **No external services.** There are no accounts, cloud, telemetry, usage statistics or automatic updates. The program
  contacts no website during the analysis.
- **The AI model is local.** The agent talks only to the LLM server started on your computer (`localhost`: LM Studio
  port 1234, llama-server 8080, Ollama 11434). Questions, answers and content read from the evidence stay on the
  machine.
- **The interface cannot be reached from the network.** The web server listens only on `127.0.0.1`, accepts only
  requests with a local address and with a random code generated at every start. Other computers on the network cannot
  connect.
- **The page loads nothing from the internet**: no external fonts, libraries or scripts.
- **plaso is included** in the Mac app and in the Windows installation and works locally; if you use the Docker
  alternative, it runs without network (`docker run --network none`).
- **Previews do not run content from the evidence.** Pages of PDFs and documents reach the browser as images; text as
  plain text; HTML/SVG are never opened as pages; converted Word documents are in an isolated frame that blocks scripts
  and any loading from the network.
- **The forensic image is never modified**: it is read with The Sleuth Kit read-only, its SHA-256 is recorded when it is
  opened (or later, in the quick analysis) and can be re-verified at any time.

The internet is needed only, and only when you ask, to **install or update the tools** (Homebrew, the Python `openai`
client, the plaso Docker image; on Linux apt and PyPI). At those times no case data is transmitted. Note: Homebrew may
send anonymous installation statistics on its own; they are disabled with `brew analytics off`.

> The only intended exception: if you choose **Network server** in the *LLM server* panel (or the `FORENSE_URL`
> variable / the `--url` option), the questions and the content read by the agent go to that server on the internal
> network; the report states it, with its address. The connection to the LLM server is always direct, never through a
> proxy. By default RepertIA uses only servers on this computer (`localhost`).

---

## Quick start

1. **LLM server.** Open LM Studio, load a model with a large context (e.g. 32768) and start the server in the
   *Developer* tab. llama-server or Ollama are fine too.
   *RepertIA works without an LLM server as well*: you can browse all the indexed data.
2. **Start RepertIA.** Mac: double-click the app (or `Avvia RepertIA.command`); the first time macOS may block it:
   right-click → *Open* → *Open*. On first start it installs by itself (Homebrew and internet required) Sleuth Kit,
   libewf, exiftool, poppler, testdisk (PhotoRec), bulk_extractor and Tesseract. Windows: Start menu → RepertIA. Linux:
   `./RepertIA.sh` (after `./installa.sh`).
3. The browser opens: **Choose the forensic image…**, select the image (for E01 files the first segment) and press
   **Start the analysis**. Hashes, partitions, file list, timeline, document text and metadata are done automatically.

Keep the Terminal (or command) window open while you work: closing it stops the interface.

---

## How to use it

### Cases
Every forensic image becomes a case in `~/CasiForensi/<image name>`. Choosing the same image again, or clicking the
case on the start page, **reopens the case without redoing anything**: indexing, additional analyses, findings and
conversations are already there.

### Reopening a case
- All indexed data can be browsed immediately in the **Results** tab, even without an LLM server and without running
  the tools again.
- **Conversations with the agent are saved** in the case folder. When reopened, the last one resumes, with questions,
  steps and answers: the agent remembers the context and you can continue where you left off.
- **New conversation** opens a clean one; earlier ones stay in **Conversations**, from where you can reopen or delete
  them (they remain in the `audit_log.jsonl` log anyway).
- If the LLM server is not running, RepertIA opens the Results directly; when you start it, **Retry** in the *LLM
  server* panel reconnects the agent without losing the conversation.

### LLM server on another computer
In the *LLM server* panel choose **This computer** (default: the server is looked for automatically on ports 8080, 1234
and 11434) or **Network server**: enter the server's address (e.g. `192.168.1.20`, or with the port
`http://192.168.1.20:8080`), the API key if needed, and press **Connect**. Without a port, 8080, 1234 and 11434 are
tried. The choice is saved (`~/Library/Application Support/RepertIA/impostazioni.json` on the Mac) and applies to all
cases; you go back to the local server with a click on *This computer*. The server must accept connections from the
network: llama-server with `--host 0.0.0.0`, LM Studio with *Serve on Local Network*, Ollama with
`OLLAMA_HOST=0.0.0.0`, and the port open in the firewall. To test: from your computer open
`http://ADDRESS:PORT/v1/models` in the browser; the list of models must appear.

### Results tab

| Section | What it shows |
|---|---|
| **File System** | Tree of the image on the left, folder content on the right, with size and dates (modified, created, accessed). At the top the **disk layout** as in the partition table (volumes, unallocated areas, table area). Deleted files and folders are marked in red; files without a folder are in `$OrphanFiles`; the file system's **unallocated space** is in `$Unalloc` (see below). Filter by name, search in all subfolders, deleted only. |
| **🔎 Search** | Search by **keywords** or by **hash** (single or a list) in all files of the image, with options and filters; each result opens in its own tab and stays saved (see below). |
| **Files** | Complete list of files, deleted ones too, with search in path and extension. |
| **Timeline** | **Activity bar chart** and table of events (modified, accessed, metadata changed, created; file system and plaso). |
| **Documents** | Search for words and phrases *inside* documents (Word, Excel, PowerPoint, PDF, OpenDocument, RTF, text, email). In the tree view the entry is split **by extension** (`.docx · Word`, `.xlsx · Excel`, `.pdf · PDF`…, plus *E-mail* and *No extension*, with the number of documents): a click shows only that family; the same filter is the section's *Extension* field. |
| **Photos and metadata** | Device, date taken, GPS and authors read with exiftool. |
| **Recovered files** | Files recovered from free space with PhotoRec (if run). |
| **Items of interest** | Emails, websites, searches, phone numbers, GPS found by bulk_extractor (if run). |
| **⭐ Favourites** | File categories created by the analyst (see *Favourites*). |

**Unallocated space (`$Unalloc`).** In every readable volume (not APFS) there is the virtual folder `$Unalloc`: one item
for every contiguous run of blocks the file system marks as free (Sleuth Kit, `blkls`), named
`Unalloc_<partition>_<start sector>_<end sector>`, with sectors and bytes in the image. They are not files: they may
contain remains of deleted files. They open like the other items in **Text** (readable ASCII and UTF-16 strings, first
50 MB) and **Hex** (the whole run, with search), they can be **exported** with SHA-256 to `export/non_allocato/` (also
as a selection, with `manifest.csv`) and added to **Favourites**: in the report they appear with their byte position and
SHA-256. The bytes are read from the forensic image only when needed; nothing is copied into the case. The first opening
of `$Unalloc` computes the runs (on a 1 TB disk a couple of minutes), then they stay in the case. The **Unallocated**
rows of the disk layout and volumes Sleuth Kit cannot read open the same way (Hex, Text, Export, Favourites). In the
portable report `$Unalloc` shows the list of runs already computed (position and size).

**Tree view (default).** The sections are a side tree, with indented sub-entries: deleted files, file-system and plaso
timeline (with plaso's individual sources), photos with GPS, types of recovered files, types of items of interest,
saved searches, favourite categories and open tabs. A sub-entry opens the section with the filter already set.
**☰ Tab view** switches to horizontal tabs, **🌲 Tree view** goes back to the tree; the choice is remembered.

**Time zone.** At the top, next to *Summary*, the **🕒 UTC / Italian time / Detected zone** selector shows dates and
times in UTC or in Italian time (Europe/Rome, with daylight saving time): lists, timeline
(also the *From/To* filters and the chart per day), previews and date interpretations in the hex view. Case data, the
log and `report.md` stay in UTC; the PDF and Word report can be saved with times in Italian time (stated at the
top). The same selector is in the portable report (there the months of the timeline bar stay in UTC).

**Plaso and bulk_extractor.** Plaso events have the **Preview**, **⭐ Favourites**, **Hex**, **Tree** and **Show in file
manager** (Finder on the Mac) buttons: the file is derived from the event's path (registry, evtx, prefetch, browser
history...), *Show in file manager* exports it to the case's export folder and shows it. In **items of interest**, under
each value there is the **Path** of the file containing it (click it to open it in the tree; otherwise it says whether
it is unallocated space or outside the partitions); the buttons are **Preview** (the file, already positioned on the
item's byte in hex), **⭐ Favourites**, **Hex** (the forensic image exactly at that offset, also in free space),
**Tree** and **Export** (exports the file to the case's export folder and shows it).

**Search by keywords or hash.** In the **🔎 Search** section:
- **Keywords**: one or more words or phrases (one per line). Choose **where to search**:
  - *file name* and/or *full path* (folder names too);
  - *text of indexed documents* (Word, Excel, PDF, email, text: fast);
  - *metadata* (author, device, software, GPS);
  - *raw content of every file, byte by byte*, as plain text and/or **UTF-16** (Windows strings): it finds the word
    also in non-indexed files, databases and binaries, but reads all files matching the filters, so it is slow on
    large disks.

  **How to compare**: *contains*, *whole word*, *starts with*, *equals* (exact name or path) or *regular expression*
  (e.g. an IBAN `IT\d{2}[A-Z]\d{10}`); case sensitivity optional; *any of the words* or *all in the same file*.
- **Hash**: MD5, SHA-1 or SHA-256, even mixed, pasted or loaded from a file (`.txt`, `.csv`, `.md5`, known-hash
  lists...): hashes are recognised automatically in any line format. The result also says **which hashes of the list
  were not found**.
- **Filters** (for both): existing only or deleted only, extensions, folder, size, modification date, partition, files
  recovered by carving.

**What each type of search covers (read before concluding that a word "is not there").**
The three choices do not search in the same way:

| Where you search | What it reads | What may be missed |
|---|---|---|
| *text of documents* | the text index, prepared with *Document text and metadata*: fast, reads inside PDF, Word, Excel, PowerPoint, OpenDocument, RTF, email, archives | files **not indexed or only partly indexed** (list below) |
| *raw content of every file* | the bytes of every file, non-indexed ones too, in UTF-8 and UTF-16 | text inside compressed formats: PDF, Word, Excel, PowerPoint and archives are **not** read this way; it is slow |
| *whole image* | all bytes of the image, including unallocated space and overwritten files | compressed text, fragmented files |

Limitations of the text index, all **stated** and not silent:
- **Long texts**: a file is indexed **in full, in blocks** (of 200,000 characters, with a short overlap so that a phrase
  spanning two blocks is not lost), up to **20 million characters** per file. Beyond this limit the file is reported as
  *partly indexed*.
- **PDF**: read in blocks of 500 pages, up to 20,000 pages. **Image-only** PDFs (scans) have no text to read: they are
  reported and handled with the *OCR* analysis.
- **Large files** (over 50 MB): text files and logs are read **as a stream**, without loading them into memory; PDFs are
  copied to disk and read in blocks of pages, up to **1 GB** (changed with the environment variable
  `REPERTIA_MAX_FILE_MB`, for example `2048`). Office documents and other formats over 50 MB, and PDFs over the limit,
  **are not indexed** and are reported.
- **System folders** (Windows, Program Files, ProgramData, `/usr`, `/Library`...) are deliberately excluded from the
  text index; they remain in names, metadata and content search.

**Non-indexed files.** At the end of indexing RepertIA writes `non_indicizzati.csv` in the case folder: one file per
line, with the reason (file too large, partial text, PDF without text, extraction failed, metadata read only from the
beginning). The number appears in the analysis summary, in the report and **above the results of every text search**
(⚠ N non-indexed files); the agent knows it (`list_not_indexed`) and, if a search finds nothing, says so. The program
also runs a **consistency check** and warns, for example, if none of the case's PDFs has extracted text (a sign that a
tool is not working), or if no metadata were extracted.

**To be sure not to miss anything** in a case with non-indexed files: search the *text of documents*, then repeat the
search also with *raw content* (filtering by extension or folder to limit the time); for excluded PDFs and Office
documents open the file and read it, or raise the limit with `REPERTIA_MAX_FILE_MB` and prepare *Document text and
metadata* again.

The search runs in the background with progress and can be **stopped**, keeping the results found so far. **The result
opens in a new 🔎 tab** with one file per line, where it was found (name, content, hash…), the terms, an excerpt of the
text around the word (or the offset in the file) and the hashes: there you work only on those files with all the
functions (list or thumbnails, preview and hex, selection, *Export files* with manifest, CSV, finding, *Show in tree*),
with internal filters (found in, term, deleted only). Searches stay in **Saved searches**, also when the case is
reopened: *Open*, *Reuse* (reloads the parameters), *Delete*. Every search is recorded in the case log.

**File hashes: when to compute them.** Computing MD5, SHA-1 and SHA-256 of all files means reading every file of the
image: a few minutes on a USB drive, even hours on a disk of hundreds of GB (it depends mainly on the speed of the disk
holding the image). That is why it is a choice:
- **before the analysis**: tick *Compute the hashes of all files* on the start page;
- **later**: *File hashes → Run* in the *Additional analyses* panel (or from the hash search form). If interrupted,
  *Update* resumes from the missing files;
- **only when needed**: a hash search without computed hashes computes them on the fly only for the files matching the
  filters (e.g. only `jpg` in one folder) and keeps them for later searches.

With computed hashes the summary also reports **files with identical content** and the agent can search by hash.

**Column filters.** In File System, Files, Timeline, Documents, Photos and metadata, Recovered files, Archives and
attachments, Shadow copies, Anomalies, Mail, Artifacts, Favourites and in search results, under the header there is a
row of filters, one per column:
- **text** (names, paths, types, devices, hashes, subjects…): contains, case-insensitive; several words = all must be
  present; `-word` = must not be present; phrases go in quotes (e.g. `smith -jones "main street"`);
- **size**: *min* and *max* with unit (`500KB`, `2MB`, `1.5GB`; a plain number = bytes);
- **date**: *from* and *to* (inclusive), in the zone chosen at the top (UTC or Italian time); for the timeline it also
  applies to the chart.

Filters apply together with each other and with those of the bar above; **Select all**, *Export files* and *Export CSV
list* respect them. Each section remembers its own; **✕ Clear** removes them. In File System the filters act on the open
folder: to search the whole subtree tick *Include subfolders*. The **Files** section also shows size and dates (from the
navigation index). In thumbnail view the filters stay active but are edited from the *List* view.

**View: list or thumbnails.** In File System, Files, Documents, Photos and Recovered files the **View** menu switches
between **☰ List**, **▦ Thumbnails** and **▣ Large thumbnails** (the choice is remembered for each section). Thumbnails
show photos, the first page of PDFs and Office documents and a frame of videos; other files have an icon by type.
Selection with the check boxes, Shift+click and "select the page" work here too.

**Preview pane.** A click on a file (row or thumbnail) opens the preview pane on the right; drag its edge to widen or
narrow it, close it with ✕ or Esc, and use the keyboard arrows to move to the next or previous file. It has four tabs:
- **Preview**: the file as it looks.
  - photos (HEIC, TIFF, RAW too, converted): click to switch between fitted and actual size;
  - PDF: all pages, one below the other;
  - Word, Excel, PowerPoint, OpenDocument: the laid-out pages if LibreOffice is installed (optional, recommended);
    otherwise on the Mac the Word document converted with textutil or the first page with the system preview (Quick
    Look);
  - text, logs, CSV, email, code: the text;
  - video and audio the browser can play (mp4, mov, mp3, m4a, wav…);
- **Text**: the extracted text (from documents and binary files too), **in full** up to two million characters; beyond
  that, the end says how many characters are missing. For binary files these are the readable strings;
- **Hex**: the content byte by byte (see below);
- **Metadata**: the file's SHA-256, file-system dates and attributes (istat), exiftool metadata.

The pane also offers *Show in tree*, *Export*, *Finding* and *Ask the agent*.

**Hex view.** Offset, bytes in hex and ASCII column, in 4 KB pages (◀ ▶ or *Go to offset*: decimal, `0x…` or relative
`+16`). You can search for **text**, **UTF-16 text** (Windows strings) or a **byte sequence** (e.g. `FF D8 FF`,
`50 4B 03 04`), moving between occurrences. Clicking a byte (Shift+click for a range, arrows to move) the inspector
shows: offset, value and **bits**, 8/16/32/64-bit little- and big-endian integers, floats, and the reading as a Unix,
Windows FILETIME, DOS/FAT, HFS+ or Apple **date**; plus ASCII, UTF-8 and UTF-16 text. *Copy hex* and *Copy offset* put
the values on the clipboard.

**Show in tree, in a separate tab.** In Files, Timeline, Documents and Photos the **path is clickable** (in thumbnails
the 📁 icon): a **new tab** opens with the tree already open on the folder and the file highlighted. The section you came
from stays as it was (filters, page, scroll position, selection): go back with the **↩** tab at the top left. Tabs are
closed with ×; at most eight stay open. The same applies to paths cited by the agent in its answers and to *Show in
tree* in the preview.

**Timeline chart.** Each bar is a day (or a month / year if the period is long; you can choose with *Day · Month ·
Year*). Hovering over a bar shows how many events and of what type; **clicking it, the table below shows only the events
of that period**. Clicking a month the chart goes down to its days; *← Whole period* returns to the full view. *Most
active periods* are shortcuts to the peaks. Text, event-type and source filters apply both to the chart and the table.

**Selection and export.** Every table has a column of check boxes:
- click a box for one item; **Shift+click** for a range;
- the box in the header selects the whole page, then *Select all N results* extends the selection to all results of the
  current filters (you can remove single items);
- in File System you can select files from different folders and whole folders too.

With the selection bar:
- **Export files** extracts the files (folders with all their content) to `export/selezione_<date>/`, **keeping the
  original folder tree**, read-only, with `manifest.csv`: original path, offset, inode, deleted yes/no, bytes and
  SHA-256 of each file. Exports appear in the report.
- **Export CSV list** saves the selected rows in `export/elenchi/` (separator `;`, opens with Excel or Numbers).
- **Finding** records a finding with the references of the chosen items.
- **Ask the agent** prepares a question about the selected items.

From every row *Preview*, *Export*, *Finding*, *Ask* and, for traces, *Where is it* also remain available (in File
System: *Preview* and *Export*; findings and questions are made from the selection bar or from the preview pane).

### Interface
- **Light / dark theme**: ☾ / ☀ button at the top right (the choice is remembered).
- **◧** next to the case name hides or shows the side panel, for more space.
- The width of the tree is adjusted by dragging its bottom-right corner.
- When you open the preview, the case panel hides itself to make room and reappears when you close it.

### Language (Italian / English)
- **Interface**: selector at the top right (*Italiano* / *English*); the choice is remembered in the settings and the
  page reloads. On Windows the language chosen during installation applies the first time.
- **Case texts**: artifacts, summaries, reports (Markdown, Word, PDF) and the portable report are in the **case
  language**, chosen in the new-case form (*Language of the case texts*) and saved in `case.json`. Changing the
  interface language does not change texts already produced; cases from earlier versions are in Italian. The case
  language is shown in the case list and in the *Analysis environment* section of the report.
- Only the **text** changes: data, hashes, paths, file names, dates and values read from the disk stay identical.
- The acceptance test runs in both languages: `forense_collaudo.py <folder> --lingua en`.
- From the terminal: `prepara ... --lingua en`; the `REPERTIA_LINGUA` variable sets the process language.
- Translations: `src/lingua_en.json` (Italian text → translation), included in the program fingerprint;
  `python3 tools/lingua_controlla.py` reports texts without a translation or with mismatched placeholders.

### Case panel
Media, hash and last verification, partitions, LLM server status, buttons **Report** (also as **PDF** and **Word**
.docx: `report.pdf` and `report.docx` in the case folder, with the SHA-256 in the log), **Portable report**, **Verify
hashes** (or **Compute image hash** if the hash has not been computed yet), **Case folder**, **Exported files**, the
**Additional analyses** to run or redo and the recorded **Findings**.

---

## Favourites (file categories)

In the Results select files with the check boxes on the left (whole folders too, with all their content) and press
**⭐ Favourites**, or **⭐ Favourites** on a file's row (after *Preview*) or in the preview pane: choose an existing
category or type a new name, with an optional note. The **⭐ Favourites** section lists the categories (rename,
description, delete) and each opens in a separate tab, with preview, export, finding and *Remove from category*.
Categories with **"in the report"** ticked go into the report (table per category with offset, inode, status, dates,
SHA-256 and note) and into the portable report, with the content and full previews of their files. Favourites are
stored in the case (`ricerche.sqlite`) and every operation is recorded in `audit_log.jsonl`.

## Portable report (for those who do not have the forensic image)

From the case panel, **Actions → Portable report** creates in `export/report_portatile_<date>/` a folder with
`index.html` to hand over (zipped too): it opens with a double-click in any browser, **offline**, without RepertIA,
without the forensic image and without AI.

- **It contains the whole catalogue**: file-system tree with deleted files, dates, sizes, hashes (if computed),
  metadata (device, date, GPS, author), extracted document text, timeline (file system and plaso), recovered files and
  traces, findings and report.
- **File content**, as you choose: only the files of findings and of selections exported with *Export*; also all
  documents and images up to a size; or **all files of the media** (deleted ones too, optionally), so the recipient can
  browse everything as if they had the forensic image. The dialog first shows number of files, size and free space.
  Files are in the `file/` folder with the original tree. For findings and selections: pages of PDFs and Office
  documents (with LibreOffice) as images, hex, exiftool and istat; for other files lighter previews (first pages of
  PDFs, first 4 KB in hex, metadata already indexed) and the *Open the original PDF* button.
- **Extended analyses**, if run: *System artifacts*, *Mail* (messages with attachments), *Archives and attachments* and
  *Anomalies* sections, with CSV export. Files extracted from archives and mail are included according to the same file
  content choice.
- Creation shows a **progress bar** with percentage, phase and estimated time.
- **Content search** covers the text of indexed documents and, for all other included files, the readable strings
  (ASCII and UTF-16) extracted at creation; photos, video and audio are searched in their metadata. In the browser the
  search scans the index in blocks, with progress and a *Stop* button.
- **Favourites in the portable report too**: the recipient sees the categories created in RepertIA and can create their
  own, selecting files in any list (check boxes, Shift for ranges) or with ⭐ in the preview; they stay in their
  browser. **Export favourites** saves them to a JSON file that another analyst loads with **Import** in the same
  report.
- **Export CSV** in every list (folder, search, timeline, metadata, included files, recovered, items of interest,
  favourites, selection) and **📄 New report** as **PDF** (browser print dialog), **Word** (.docx) or **HTML**: case data,
  findings, chosen favourite categories (with thumbnails, dates, SHA-256 and notes), notes and, optionally, the full
  report.
- Every list (File system, search, timeline, metadata, recovered files, traces, mail, anomalies, favourites) has the
  same **row of column filters** as the program (text, min/max size, from/to dates); "✕ filters" clears them.
- The recipient can **browse, search** (name, content, metadata, hash also from a list), scroll the **timeline** by
  month and day and add **notes** to files (they stay in their browser; they can be exported as JSON or CSV and
  re-imported).
- **Security**: evidence content is never executed or interpreted as a web page; HTML, scripts and active documents are
  shown as text or images.
- **Integrity**: `impronte.csv` has the SHA-256 of every file in the report; the fingerprint of `impronte.csv` (in
  `IMPRONTA_REPORT.txt` and in the final dialog) must be communicated to the recipient and is recorded in
  `audit_log.jsonl`.

## Additional analyses

- **File hashes** (optional): MD5, SHA-1 and SHA-256 of every file, deleted ones too, for comparison with known-hash
  lists and to find duplicates. It resumes where it stopped.
- **Text and metadata** (always, automatically): text of documents, deleted ones too if still readable; metadata of
  photos, videos and documents with exiftool. System folders are excluded.
- **plaso timeline** (optional): registry, prefetch, logs, browsers; on Macs also FSEvents and other macOS artifacts.
  Useful for system disks. It is included in the app (Mac) and the installation (Windows); on Linux `installa.sh`
  installs it: Docker is needed only if RepertIA is started from source without plaso. It can take hours. Since 2.14, if
  the case has an unlocked encrypted APFS volume, plaso receives the same key (in memory only, never in the log: there
  it appears as `password:***`) and analyses that volume too.
- **Carving** (optional): PhotoRec recovers files from free space into `<case>/carving`; bulk_extractor looks for
  traces on the whole disk and can tell which file they belong to. If the installed PhotoRec does not read NTFS (it
  happens with Homebrew's), the unallocated space is first extracted with Sleuth Kit (`blkls`) and PhotoRec works only on
  that: so files still present are not recovered as well. The offsets reported are always those of the image.

### Extended analyses (new in 2.5)

- **Archives and mail** (on by default): opens ZIP, RAR, 7z, tar/gz and nested archives with 7-Zip; reads PST/OST
  (Outlook), MSG, EML/EMLX and mbox mailboxes (Thunderbird without extension too). Messages and attachments appear in
  the *Mail* and *Archives and attachments* sections, and enter the search and the chat. Extracted files go to
  `<case>/estratti/` read-only, with MD5, SHA-1 and SHA-256, and with their origin path (archive → inner file).
  Password-protected archives are reported.
- **Anomalies** (on by default): extension that does not match the content (e.g. a JPEG named `.txt`), encrypted Office
  documents, PDFs and ZIPs, high-entropy containers (possible VeraCrypt/TrueCrypt volumes), BitLocker, LUKS, FileVault
  and encrypted APFS volumes. Since 2.17.2 **deleted files** are reported only if the content read is still theirs: if
  the record (inode, MFT) has been given to another file or the clusters overwritten, the entry is not an anomaly (this
  was the case of the "PNGs that are executables") and the analysis summary says how many entries were excluded and
  why. Since 2.17.3 the check is stricter: on NTFS a pass over the MFT checks that the deleted file's clusters do not
  appear in the runlists of any other record, not even of another file deleted later; and the content must be
  consistent with the file's size and ending (a JPEG ends with FF D9, a PDF with `%%EOF`, a ZIP with the central
  directory, the boxes of an MP4 reach exactly the end, an executable ends where its sections or its digital signature
  say). Not anomalies: program modules with their own extension (Office `.odf`, Adobe `.mpp`/`.api`, `.8bf` filters…),
  executables in program and Windows folders with non-"user" extensions, installer icons
  (`Windows\Installer\{…}\*.ico`) and registry logs (`BCD.LOG`). An executable inside a photo, video, PDF or document
  stays high severity. A different format in a file with a generic extension (`.dat`, `.bin`, `.db`, `.tmp`…) is not an
  anomaly; a swap between image formats (JPEG/PNG/WebP…) or between photo and video is a low-severity note.
- **System artifacts** (on by default), in summary cards:
  Windows — computer name, time zone, last shutdown, users (SAM, with the registry log files applied: see 2.17.2 in the
  change log; logons also counted from the `Security.evtx` and `System.evtx` event logs, 2.17.3), installed programs and
  autostart, connected USB devices (with times), known Wi-Fi networks, UserAssist, recent documents, typed paths, File
  Explorer searches, Prefetch, Amcache, `.lnk` shortcuts and jump lists, Recycle Bin; since 2.18 also **opened folders
  (ShellBags** from NTUSER.DAT and UsrClass.dat, including USB sticks and disks no longer connected), **ShimCache** and
  **BAM/DAM** (programs seen and run), **SRUM** (app usage and network traffic per app and user), **Activity History**
  (ActivitiesCache.db, including text copied to the clipboard if synchronised), **NTFS journal** `$UsnJrnl` (files
  created, deleted and renamed with date, even if the MFT record has been reused), **event logs** (installed services,
  power on and off, sessions and Remote Desktop with address, Defender detections and deactivations, connected USB
  drives, cleared logs) and **thumbnails** from the File Explorer cache (`thumbcache_*.db`, extracted among the
  extracted files: they remain even after the images are deleted). All **Windows installations** on the disk (including
  `Windows.old`) are analysed separately: their artifacts have the folder name in square brackets; Chrome, Edge,
  Firefox and Safari browsers (history, downloads, searches); Linux (users, network, shell history); macOS (see *Macs
  with APFS*: since 2.14 also the Data volume and the main artifacts).
- **Shadow copies (VSS) and APFS snapshots** (optional): lists Windows shadow copies and, since 2.14, **APFS volume
  snapshots** (for example local Time Machine snapshots and Time Machine backups on APFS disks) and recovers files
  present in a copy but deleted or different on the current disk. Snapshots are read with Sleuth Kit
  (`fsstat`/`fls`/`icat -S`); the sealed system volume is skipped (its snapshot is macOS itself); an encrypted volume
  needs the user's password.
- **OCR** (optional): with Tesseract (Italian and English) reads the text of photos, scans and PDFs without text, which
  becomes searchable.
- **Perceptual hashes** (optional, since 2.18): computes a "perceptual" hash (64-bit dHash) of every image (files of the
  image, deleted ones too, extracted files, thumbnails, carving). In an image's preview, *Similar images* finds the other
  images in the case that look the same even if resized or recompressed (not cropped or rotated): they are leads to be
  checked visually.
- **Hash sets / NSRL**: from the case panel, *Hash sets* loads lists of known hashes (text files, CSV, NSRL RDS SQLite
  databases, **Project VIC (VICS) / CAID JSON** with the category, since 2.18). *Known good* files can be hidden in the
  File System; those in a *to flag* list appear among the anomalies. It needs the file hashes. Since 2.18 a list can
  also be a **folder of reference images**: similar images in the case (perceptual hash) are reported with the
  distance, high severity if almost identical (*Perceptual hashes* must be run first).
- **Encrypted volumes**: if the disk is BitLocker, LUKS1 or FileVault and the password or recovery key is known,
  *Decrypt the volume* creates a decrypted copy in the `<case>/decifrata/` folder (with SHA-256 and the reference to the
  original image) and a new case on it. The original is not touched. LUKS2 is recognised but not decrypted. **Encrypted
  APFS** volumes (FileVault on recent Macs) are unlocked differently, without copies: see *Macs with APFS* below.
- **Raw byte search**: in the search, the *Whole image* option searches the text on the whole disk, unallocated space
  and slack included, and says which file each result belongs to when possible.

They are enabled when the case is created or later, from the *Additional analyses* panel, without losing the
conversation. **An E01 is no longer converted to raw** (since 2.10): Sleuth Kit, bulk_extractor and plaso read it
directly, and for carving PhotoRec receives only the unallocated space in a *compact* temporary file.

**plaso** is already included in the Mac app and in the Windows installer. Only if RepertIA is used from source without
plaso installed is Docker Desktop with the `log2timeline/plaso` image needed (`docker pull log2timeline/plaso`); with the
image on an external disk: *Docker Desktop → Settings → Resources → File sharing* must contain `/Volumes`.

---

### Macs with APFS (new in 2.13)

The Sleuth Kit does not read APFS, the file system of recent Macs. Since this version RepertIA reads **APFS
containers** with **libfsapfs** (`forense_apfs.py`), always read-only and directly from the image (raw or E01), without
creating copies.

- **One APFS volume = one "partition" of the case** (Macintosh HD, Data, Preboot, Recovery, VM…). In the tree it appears
  as *APFS volume "name"*; file list, filters, timeline, hashes, text index, previews, portable report and extended
  analyses work as for other file systems. The internal partition number (offset) is synthetic: container offset +
  (volume no. + 1) × 2⁴⁰ sectors.
- **inode** = APFS identifier of the file (unique within the volume). The *Metadata* tab shows the dates with
  **nanoseconds** (creation, modification, metadata change, access, added to folder), permissions, uid/gid, links,
  symbolic link targets, **physical position of the data** in the container and in the image and the **extended
  attributes** (e.g. `com.apple.quarantine`, `com.apple.metadata:kMDItemWhereFroms`).
- **Encrypted volumes (FileVault)**: they are unlocked with the **user's password** or the **recovery key**
  (XXXX-XXXX-XXXX-XXXX-XXXX-XXXX). If the case starts with an encrypted volume, preparation stops with "ENCRYPTED
  VOLUME": press *Decrypt / unlock the volume…*, type the key and preparation restarts. If only some volumes are
  encrypted, the case is prepared with the others and the encrypted volume is added later from *Decrypt…* (it is listed
  at that point). Opening a case with an encrypted volume already listed, a warning asks to unlock it to read its
  **contents** (the file list is already in the case).
  **The key is never written** to the case, the logs or the disk: it stays in memory only while RepertIA is open (from
  the terminal: `REPERTIA_APFS_SECRETS` variable, or it is asked without being shown). The log only shows the type of
  credential used.
- **Limitations to be aware of**:
  - **Macs with a T2 chip or Apple Silicon**: the Data volume of a *physical* image is protected by hardware-bound keys;
    the password alone is not enough and it cannot be decrypted outside the Mac. A logical acquisition of the Data volume
    made on the running, unlocked Mac is needed.
  - **Deleted files**: libfsapfs does not recover them: all entries appear as not deleted. Carving (PhotoRec /
    bulk_extractor) works on the whole image, not on the APFS unallocated space. Since 2.14 files deleted but still
    present in a **snapshot** are recovered with *Shadow copies and snapshots*.
  - *Fusion* volumes are not explored.
  - **Locating a file from a byte offset** (traces, carving) is not available for APFS.
  - **macOS artifacts (2.14)**, in *Artifacts*, read from the Data volume (or from the single volume of older Macs):
    accounts, computer name, last user, guest user, chosen time zone; Wi-Fi networks; installed programs and
    installation history; **quarantined downloads** (every downloaded or received file with URL, page and program);
    **launch items** (non-Apple LaunchAgents/LaunchDaemons, login items of macOS 13+); **TCC permissions** (full disk
    access, camera, microphone, screen…); **iMessage/SMS** from `chat.db`, including messages still only in the `-wal`
    file and text stored as `attributedBody` (macOS 13+), with contact, direction and attachments; **recent documents,
    folders and apps** (`.sfl2/.sfl3` and the Finder's recent folders); Safari downloads; **app usage** (knowledgeC.db, up
    to macOS 13); Bluetooth devices and external volumes seen by the Finder; **Time Machine** (backup disks and dates);
    shell history; browser history.
    Not read directly: **FSEvents** and the **unified log** (plaso reads them, if run), Biome (macOS 14+), keychain; USB
    connections of Macs are only in the unified log.
  - **Mac time zone (2.14)**: read from `/private/etc/localtime` or `.GlobalPreferences.plist`, for the "Detected zone"
    mode.
  - **Tests**: tested on APFS test images (unencrypted and encrypted with a password, raw and E01) and on a synthetic
    Data volume structure; not yet on a real E01 of a recent Mac (sealed system volume, Data volume, FileVault). The
    merged "firmlink" path of macOS is not rebuilt: Data and System stay separate volumes (in the Data volume the paths
    are the real ones: `Users/…`, `private/var/…`).

---

## What it uses

| Component | What it is for |
|---|---|
| **The Sleuth Kit** (`mmls`, `fsstat`, `fls`, `icat`, `istat`, `img_stat`) | partitions, file systems, list of files including deleted ones, read-only file reading, file-system timeline |
| **libewf** (`ewfexport`) | reading and converting E01 images |
| **exiftool** | metadata of photos, videos and documents (device, date taken, GPS, authors) |
| **poppler** (`pdftotext`, `pdftoppm`, `pdfinfo`) | PDF text; PDF pages and thumbnails as images |
| **sips**, **Quick Look** (`qlmanage`), **textutil** — part of macOS | thumbnails and conversion of photos (HEIC, TIFF, RAW), previews of Office/Pages/video, Word to HTML |
| **LibreOffice** (optional) | page previews of Word, Excel, PowerPoint and OpenDocument |
| **ImageMagick**, **ffmpeg** (optional) | alternatives for images and video frames (used if present, useful on Linux) |
| **PhotoRec** (testdisk) | recovery of files from unallocated space |
| **bulk_extractor** | traces (emails, URLs, searches, phone numbers, GPS, cards) across the whole image |
| **plaso** (`log2timeline`, `psort`), included (Docker only as an alternative) | timeline of system artifacts |
| **7-Zip** (`7zz` / `7z.exe`) | opening archives (ZIP, RAR, 7z, tar, gz, …) |
| **libyal** (libpff, libolecf, libregf, libscca, liblnk, libvshadow, libbde, libluksde, libfvde, **libfsapfs**) | Outlook mail, Windows registry, Prefetch, shortcuts, shadow copies, encrypted volumes, **Mac APFS volumes (encrypted too)** |
| **Tesseract OCR** | text of photos and scans |
| **Python 3** (standard library) + **SQLite** with FTS5 full-text search | the program's engine, indexes and searches |
| **`openai`** client for Python | only as a client towards the *local* LLM server (same protocol) |
| **LM Studio / llama-server / Ollama** | the language model, run on your computer |

The interface is an HTML/JavaScript page without external libraries, served by the program itself. The main files are:

- `forense_agent.py` — case preparation, agent tools, report (from the terminal too);
- `forense_gui.py` — local server of the interface, tree, timeline, selections, exports, saved conversations;
- `forense_gui.html` — the interface;
- `forense_estesa.py` — extended analyses: archives, mail, anomalies, artifacts, VSS, OCR, hash sets, encrypted volumes;
- `forense_apfs.py` — Mac APFS volumes (libfsapfs), encrypted ones too;
- `forense_collaudo.py` — acceptance test with the reference images (2.14);
- `forense_riscontro.py` — cross-check with the file/hash list of another tool (2.15);
- `forense_lingua.py`, `lingua_en.json` — language of the texts and English dictionary (2.19);
- `Avvia RepertIA.command`, `Aggiorna strumenti.command` — launchers for macOS.

---

## Case folder

| File / folder | Content |
|---|---|
| `case.json` | image, hashes, partitions, tool versions, analyses run |
| `caso.sqlite` | file list, timeline, document text, metadata, traces, file hashes |
| `non_indicizzati.csv` | files whose text is not in the index or only partly, with the reason (updated at every indexing) |
| `ricerche.sqlite` | saved searches and their results |
| `navigazione.sqlite` | tree index for the File System section (recreated automatically if missing) |
| `cache/` | copies of files opened in preview or hex, thumbnails, pages and conversions; recreated automatically: you can delete it whenever you want to free space |
| `conversazioni/` | conversations with the agent, one per file |
| `findings.json` | recorded findings |
| `audit_log.jsonl` | complete log of commands run, questions, answers and tool results, hash-chained (2.14) |
| `export/` | exported files (single ones and `selezione_*/` with `manifest.csv`) and CSV `elenchi/` |
| `carving/` | files recovered with PhotoRec and bulk_extractor results |
| `report.md` | report generated with the *Report* button |

---

## Safeguards for forensic work

- The forensic image is always opened **read-only**; the SHA-256 hash of the original (of all E01 segments too) is
  computed when the case is created and re-verified with *Verify hashes*.
- **Hash of the acquired data (2.14).** Besides the SHA-256 of the image *files*, RepertIA computes MD5, SHA-1 and
  SHA-256 of the original media's *data* (for an E01 the decompressed content, read with libewf) and compares them with
  the hash recorded by the acquisition program: the one written **in the E01** (FTK Imager, EnCase, Guymager,
  ewfacquire…) or in the **acquisition log** next to the image (FTK Imager `.txt`, Guymager `.info`, `.log`,
  `.md5/.sha1/.sha256`). The result (*matches*, *DIFFERENT*, *no acquisition hash*) is in the case panel (*Acquisition*
  row), in the report, in the portable report and in the log; the report also shows the acquisition data recorded in
  the E01 (examiner, case and evidence number, program, dates, model and serial number of the media). *Verify hashes*
  re-checks files and data. Computing the data reads the whole image again (it can be skipped with
  `REPERTIA_VERIFICA_DATI=0`).
- **Tamper-evident log (2.14).** Every line of `audit_log.jsonl` contains a sequence number (`n`) and the SHA-256 of the
  previous line (`prev`): a modified, removed or inserted line breaks the chain. *Verify hashes* also checks the chain;
  the report gives the status and the hash of the last line, which binds the log to that report. Logs of cases
  earlier than 2.14 remain valid: the chain starts from the first line written with 2.14.
- **Analysis environment (2.14).** At preparation the case records, and the report shows, the RepertIA version, the
  **program fingerprint** (SHA-256 of its files) and the versions of all tools and libraries (Sleuth Kit, libewf,
  libfsapfs, exiftool, plaso, 7-Zip, Tesseract, Python…); if they changed between preparation and report, the report
  says so.
- **Acceptance test (2.14, public images since 2.15).** `Collaudo RepertIA.command` (Mac), *Collaudo* in the Start menu
  (Windows) or `./collaudo.sh` (Linux), with the `RepertIA-collaudo` folder (separate zip), prepares a case for each
  reference image and compares the results with the expected values. Two groups, kept separate in the report:
  - **public DFTT images** (Digital Forensics Tool Testing, dftt.sourceforge.net, GPL license, included in the zip): the
    expected values are **those published by the project**, not chosen by RepertIA, and each image is recognised by its
    published MD5. They test: FAT dates with daylight saving time (5), deleted files on FAT (6) and NTFS including
    resident, ADS and fragmented ones (7), JPEGs with a wrong extension, deleted, in ZIP and tar.gz archives and in an
    ADS (8), carving of a FAT32 with a damaged boot sector, checking the published MD5 **and offsets** (11). These are
    the tests to cite;
  - **images prepared for RepertIA** (intact and altered E01, raw with FTK log, structure of a Mac, dfvfs APFS and
    BitLocker): they check the features the public images do not cover; they count as internal checks.
  **"Measurement"** entries are known limits that no file-system-based tool overcomes completely (fragmented deleted
  files on FAT, carving of damaged files): they are reported with their result but do not count. The
  `collaudo_<date>.md` report (in `CasiForensi/_collaudo/`) with version, fingerprint and tools is attached as
  documentation. To add more images (e.g. NIST CFReDS): an `atteso_<name>.json` file in the folder with the published
  values and the image's MD5. From the terminal: `python3 forense_collaudo.py <test folder>`.
- **Cross-check with another tool (2.15).** *Cross-check with another tool* in the case panel compares the case's files
  with the list exported by a second tool on the **same image**: Autopsy (*Save table as CSV*), FTK Imager (*Export File
  Hash List* or *Export Directory Listing*), X-Ways, EnCase, AXIOM (CSV with path and hash), Sleuth Kit
  (`fls -r -m / -h`). The format is recognised automatically. Result: files with the same hash (independent
  confirmation: each tool read the image on its own), with a **different** hash, present in only one of the two,
  discordant "deleted" status or size. The result goes into the report (*Cross-check with other tools* section, with the
  SHA-256 of the external file) and the log; the line-by-line detail in `riscontri/` in the case. From the terminal:
  `forense_agent.py riscontro --case CASE --file list.csv --strumento "Autopsy 4.21"`. It is the recommended way to
  confirm findings before using them.
- **Quick analysis**: unticking *Compute the SHA-256 of the forensic image now* on the start page, the analysis starts
  without waiting for the hash, which is computed later from the case panel with **Compute image hash** (from the
  terminal `--no-hash`, then `--aggiungi immagine`). The report gives the date and time of the computation and that it
  happened after the analysis started; until it is computed, the report flags it as missing.
- Every command, question and answer is recorded in `audit_log.jsonl`.
- Passwords and recovery keys of encrypted volumes **are never saved** (neither in the case nor in the logs): they stay
  in memory during the session.
- Exported files are read-only, with SHA-256 computed during extraction.
- Previews and hex work on a copy of the file extracted with `icat` into `cache/` (read-only), never on the forensic
  image; the Metadata tab shows its SHA-256.
- Times are in **UTC**; on FAT/exFAT they are often the device's local time.
- The agent distinguishes facts and hypotheses, but **every finding must be verified by the analyst** with the forensic
  tools before being used.

---

## Updates

Nothing updates itself, on purpose: every case records the versions of the tools used. To update, between one case and
the next and with internet: Mac `Aggiorna strumenti.command`, Windows *Aggiorna strumenti* in the Start menu, Linux
`./aggiorna-strumenti.sh`; they show the versions before and after.

The history of the versions is in [CHANGELOG.en.md](../CHANGELOG.en.md).

## Mac package (Apple Silicon)

`RepertIA-2.19.0-Mac.zip` contains **RepertIA.app** with Python 3.12, openai, Pillow and **plaso already included** (no
Docker). Drag the app into Applications; the first time: right-click → *Open* (or *System Settings → Privacy & Security
→ Open Anyway*), because it is not signed with an Apple certificate. The app opens the Terminal, installs the missing
tools with Homebrew (Sleuth Kit, libewf, exiftool, poppler, PhotoRec, bulk_extractor, Tesseract) and then the browser.
7-Zip, libpff and the Italian/English OCR data are already in the app. To update the tools there is
*Aggiorna strumenti.command* in the zip. Only for Macs with M1 or later.

## Windows version

`RepertIA-2.19.0-Setup.exe` installs RepertIA for the current user (no administrator rights) in
`%LOCALAPPDATA%\Programs\RepertIA`, with Python and the tools already included: plaso, The Sleuth Kit (reads E01 files
directly), ExifTool, Poppler, PhotoRec, bulk_extractor, 7-Zip, Tesseract OCR (Italian and English) and the libraries for
Outlook mail, shadow copies and encrypted volumes. It is started from the Start menu → **RepertIA**: a black window opens,
to be kept open, and the browser. Cases are in `%USERPROFILE%\CasiForensi`, settings in `%APPDATA%\RepertIA`.

- **plaso** is included in the installer (native Python version, without Docker).
- **bulk_extractor** (v2.2.0) is included in the installer as a native Windows program (no Docker, no internet).
  *Aggiorna strumenti* in the Start menu shows its version; to update it, install a new version of RepertIA.
- **Office previews**: install LibreOffice, it is found automatically.
- **Differences from the Mac**: no disk acquisition (use a dedicated acquisition tool); image previews with Pillow
  instead of the macOS tools; for carving an E01 the conversion to raw is done with Sleuth Kit's `img_cat`.
- Windows SmartScreen may flag the installer as an "unrecognised app" because it is not digitally signed: *More info* →
  *Run anyway*.
- To rebuild the installer see `build/windows/COME_RICOSTRUIRE.txt` in the repository and `docs/BUILDING.md`.

## Linux version (experimental)

`RepertIA-2.19.0-Linux.tar.gz` is for **Linux x86_64** with Python 3.12 or later (Ubuntu 24.04 or later, Debian 13).
The program is the same as the Mac and Windows versions (same source fingerprint).

```
tar -xzf RepertIA-2.19.0-Linux.tar.gz
cd RepertIA
./installa.sh          # once, with internet: asks for the administrator password
./RepertIA.sh          # or from the applications menu
```

- `installa.sh` installs with **apt** Sleuth Kit, libewf, PhotoRec, Poppler, ExifTool, Tesseract (with Italian), zenity
  (file selection dialogs) and, if the distribution has it, bulk_extractor; then it creates in `python/` an environment
  with **plaso, the libyal libraries, pytsk3, Pillow and openai at the same versions as the Mac and Windows packages**
  (`requirements-linux.txt`; the libyal libraries are compiled, 10-20 minutes) and adds RepertIA to the menu. The log is
  in `installa.log`; the script can be run again.
- Included in the archive: 7-Zip 26.01 (`strumenti/7zip`) and the Italian/English OCR data (`strumenti/tessdata`).
- **Differences from Mac and Windows**: the forensic tools are those of the distribution, with its versions (reported as
  always in the report, *Analysis environment* section); bulk_extractor may be missing in some distributions (carving
  then uses PhotoRec); no disk acquisition.
- `./collaudo.sh` runs the acceptance test with the `RepertIA-collaudo` folder (also `--lingua en`);
  `./aggiorna-strumenti.sh` shows and updates the tool versions with apt.
- **Experimental**: tested by the author in a Linux development environment; before using it in a case, run the
  acceptance test on your computer and keep the report.
- To rebuild the package see `build/linux/COME_RICOSTRUIRE.txt` in the repository.

## From the terminal

```
python3 forense_agent.py                 opens the graphical interface
python3 forense_agent.py avvia IMG       prepares if needed and opens the chat in the terminal
python3 forense_agent.py avvia IMG --no-hash   quick analysis: image hash postponed
python3 forense_agent.py prepara --case CASE --aggiungi immagine   computes the image SHA-256 later
python3 forense_agent.py prepara --case CASE --aggiungi indice hash plaso carving
python3 forense_agent.py prepara --case CASE --aggiungi archivi anomalie artefatti vss ocr
python3 forense_agent.py report  --case CASE
python3 forense_agent.py verifica --case CASE      SHA-256 of files, data hashes, log chain
python3 forense_collaudo.py TEST_FOLDER          acceptance test with the reference images
python3 forense_agent.py riscontro --case CASE --file LIST.csv --strumento "Autopsy 4.21"
```

The command names and options are in Italian (`avvia` = start, `prepara` = prepare, `aggiungi` = add, `verifica` =
verify, `riscontro` = cross-check); `--lingua en` sets the language of the case texts.
Useful variables: `FORENSE_CASI` (cases folder), `FORENSE_BACKEND`, `FORENSE_URL`, `FORENSE_MODEL`, `FORENSE_CTX`.

## Troubleshooting

- **"LLM server not connected"**: start the server in LM Studio (Developer tab) and press *Retry*. Meanwhile the Results
  work. With a network server the message shows the addresses tried: check address, port, listening on the network and
  firewall.
- **"The forensic image cannot be reached"**: connect the disk containing the image; lists, timeline and searches work
  without it, previews and exports do not.
- **No preview for Word/Excel/PowerPoint or a simplified preview**: install LibreOffice (free) and reopen the preview;
  meanwhile use the Text tab.
- **The video does not play**: the browser plays mp4/mov/webm; for other formats a frame is shown, or export the file.
- **Disk space**: the case's `cache/` folder grows with the files opened in preview; it can be deleted without losing
  anything. Files over 2 GB are not copied: the hex view reads them directly from the image (more slowly).
- **The text of a long file does not end in the preview, or the agent stops**: since 2.9.1 the preview shows up to two
  million characters and the agent continues in portions (`start`). With earlier versions the text was cut at about
  12,000 characters: update.
- **A word I know is in a file does not come up in the text search**: look at `non_indicizzati.csv` (and the ⚠ above
  the results): the file may be too large, an image-only PDF or in a system folder; try the search in the *raw content*
  (it does not read inside PDF and Office) or open the file. If the case was prepared with 2.7 or 2.8, redo *Document
  text and metadata*.
- **The raw content search is slow**: narrow it with extensions, folder or maximum size, or use *Text of indexed
  documents*, which is immediate. You can stop it and keep the results already found.
- **Hash search with few results**: if the hashes were not computed and you chose not to compute them on the fly, files
  without hashes are not compared (the result says so).
- **"ENCRYPTED VOLUME" on a Mac / the APFS volume does not open**: use *Decrypt / unlock the volume…* with the user's
  password or the recovery key. On a Mac with a T2 chip or Apple Silicon the password may not be enough (hardware-bound
  keys): a logical acquisition made on the running Mac is needed.
- **Tree being prepared**: when a case is first opened RepertIA builds the tree index (a few seconds; about 15 seconds
  per 500,000 files), then it stays ready.

---

RepertIA — conceived and developed by **silvexe**.

Personal project of silvexe, carried out privately and not connected with any office or administration.
Developed with the help of **Claude**, an artificial intelligence model by Anthropic; design choices, verifications and
tests are the author's.

---

## License

Copyright (C) 2026 silvexe. RepertIA is free software, released under the **GNU General Public License
version 3 or later** (GPL-3.0-or-later): it can be used, studied, modified and redistributed, modified too, provided it
is under the same license and with the source code. It is provided without any warranty. The third-party components
included in the packages have their own licenses (THIRD_PARTY_LICENSES.en.md in the project repository).

## Validation

See [VALIDATION.md](../VALIDATION.md) (translation of the Italian section *Validazione*, identical to
[VALIDAZIONE.md](../VALIDAZIONE.md)).
