# RepertIA — By silvexe — User manual

*Translation of the Italian manual [src/README.md](../src/README.md); the Italian text prevails. The version history
("Aggiornamenti") is in [CHANGELOG.en.md](../CHANGELOG.en.md) and the validation section in
[VALIDATION.md](../VALIDATION.md). Names of buttons and menus are given as they appear in the English interface; file
and folder names created by the program (`estratti`, `export`, `CasiForensi`…) are in Italian whatever the language.*

**Forensic analysis of disk and USB drive images with local artificial intelligence.**
Version 2.20.2 · macOS, Windows and Linux (experimental) · interface in English or Italian

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

## Requirements

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

**Preparation: progress (2.20).** During the preparation the page lists the chosen steps (the spinning dot is the one in
progress, the green ones are finished) and, below the *Technical details* and before **Stop**, a box with two bars:
**Overall progress** (step N of M, percentage, how long it has been running) and the bar of the **current step**, with
the numbers when the step knows them (e.g. "412,000 of 1,640,000 files", the image hash in GB) and an estimate of the time
left; for the steps that cannot know in advance how much work is left (plaso, file listing, PhotoRec) the bar keeps moving
while the program works. The line **Last signal from the program** says how many seconds have passed since the last
message; if the program writes nothing for more than 20 minutes a warning appears: some steps (plaso, PhotoRec, shadow
copies on large disks) work for a long time without messages; if it stays like that for hours you can stop and redo the
case without that step, running it later from the *Additional analyses*. Before 2.20 the list could show all the steps in
green and "FAT/exFAT dates with the device time zone" in progress right after the file listing, while the real work was
still halfway (for example in the shadow copies): now the steps come from the program itself, the same in Italian and in
English.

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

**External server (2.20.1).** If the address is neither on this computer nor on the local network (not a private IP
10.x, 172.16–31.x, 192.168.x nor a local name without dots or with `.local`, `.lan`, `.internal`…), RepertIA shows an
**explicit warning** before using it: questions and case content read by the agent would leave the local network. If the
analyst confirms, the use is recorded in the case log (`server_llm_esterno_confermato`, `server_llm_esterno`), the box
shows *(external server)* and the report says "external server indicated by the analyst: *address*" instead of
"internal network, without external services". When a case opens, an unconfirmed external server is not used. See
[AI_ACT.en.md](../AI_ACT.en.md).

### Results tab

| Section | What it shows |
|---|---|
| **File System** | Tree of the image on the left, folder content on the right, with size and dates (modified, created, accessed). At the top the **disk layout** as in the partition table (volumes, unallocated areas, table area). Deleted files and folders are marked in red; files without a folder are in `$OrphanFiles`; the file system's **unallocated space** is in `$Unalloc` (see below). Filter by name, search in all subfolders, deleted only. |
| **🔎 Search** | Search by **keywords** or by **hash** (single or a list) in all files of the image, with options and filters; each result opens in its own tab and stays saved (see below). |
| **Files** | Complete list of files, deleted ones too, with search in path and extension. |
| **Timeline** | **Activity bar chart** and table of events (modified, accessed, metadata changed, created; file system and plaso). |
| **Documents** | Search for words and phrases *inside* documents (Word, Excel, PowerPoint, PDF, OpenDocument, RTF, text, email). In the tree view the entry is split **by extension** (`.docx · Word`, `.xlsx · Excel`, `.pdf · PDF`…, plus *E-mail* and *No extension*, with the number of documents): a click shows only that family; the same filter is the section's *Extension* field. |
| **Photos/Videos/Audio** | Device, date taken, GPS and authors read with exiftool (photos, videos and documents); sub-items **Photos**, **Videos** and **Audio** (audio files from the case file list, also in cases already prepared). |
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
At the top of the tree the **Filter the entries** box (2.20) keeps only the entries that contain the typed words,
ignoring case and accents (e.g. «whatsapp», «biome», «whatsapp group»), with the parent entries open; **Esc** clears it.

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
- **later**: *File hashes → Run* in the *Additional analyses* menu (or from the hash search form). If interrupted,
  *Update* resumes from the missing files;
- **only when needed**: a hash search without computed hashes computes them on the fly only for the files matching the
  filters (e.g. only `jpg` in one folder) and keeps them for later searches.

With computed hashes the summary also reports **files with identical content** and the agent can search by hash.

**Column filters.** In File System, Files, Timeline, Documents, Photos/Videos/Audio, Recovered files, Archives and
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
- **Resizable panes** (2.20): a thin divider separates case panel, Results tree, folder tree of the File System, list,
  preview/details on the right and, in the chat view, the list of conversations. Drag it with the mouse; a
  **double-click** on the divider restores the default width. The sizes are kept in the browser memory (if available);
  **↔ Reset columns** also puts the panes back as they were. The same in the portable report (folder tree, Bookmark
  categories, preview, chat list).
- **Horizontal dividers** (2.20): where one part is above another, the boundary can also be moved up and down with the
  mouse — «Activity» chart of the Timeline and table, header and filters above the tables (search summary, File System
  path and filters, filter panel; a separate size for each section), filters and list of conversations and header and
  messages of the chat view; in the portable report the months/days chart of the Timeline and the list. A
  **double-click** restores the default height; **▾ / ▸** on the left of the divider (and ▾ next to the chart title)
  collapses the pane above into a thin line and reopens it. Sizes and collapsed panes are kept in the browser memory;
  **↔ Reset columns** also restores these.
- **Compact top bar** (2.20): if it does not fit on one line, the tools found become a single label **«✓ 8 tools»**
  (or «! 6 of 8 tools» if some are missing) that opens the full list with the usual hints when clicked; then the two
  most recent searches remain with **«all (N)»**, which opens the Search panel (all searches are also under *🔎 Search*
  in the tree), and the subtitle moves to the hint of the name.
- **🔎 Search** (2.20), top right below the theme selector, opens the search panel (disk and smartphone cases). After a
  search a **label** with the words and the number of files found appears next to it (e.g. «🔎 “bitcoin” · 37»): a
  click reopens its results, like the entry in the tree; ✕ removes only the label (the search stays saved). The last four
  searches of the case are shown; opening the panel or a label is a *Back / Forward* step. The *🔎 Search* entry also
  stays in the Results tree.
- **⚡ Case results: fast search** (2.20), first tab of the search panel (the default in smartphone cases): it searches
  **as you type** in what the case shows as results — system artifacts, iLEAPP/ALEAPP artifacts, calls, chat messages and
  conversations, contacts, mail — and answers in a few milliseconds even on a phone with 500,000 iLEAPP rows. The results
  are grouped as in the tree (*Contacts*, *Conversations*, *Chat › WhatsApp*, *Calls*, *iLEAPP/ALEAPP artifacts › category
  › artifact*…) and **collapsed**: the total is at the top, each group shows how many results it holds and opens with a
  click, so you pick the one you need. Every row has date, highlighted text and source; a click opens the item in the
  preview (for messages *💬 Open chat*), a conversation opens in the chat view, a **contact entry** opens in the preview
  with name, number, source database (*Source* button to see it in the tree), the other entries with the same number and
  the conversations with that number; *🔎 Search this number* starts a new search only when you ask for it. **Phone numbers in any format**: a
  search made of digits (at least 6, with or without +, spaces, brackets, dashes) compares the last 9 digits, so
  «+1 (919) 928-2177», «9199282177» and «19199282177@s.whatsapp.net» find each other. Words need at least 3 characters;
  upper and lower case are the same. **Save as search** keeps all the results as a case search (tab, *🔎 Search* entry,
  Bookmarks, CSV, log). The index is the file `ricerca_veloce.sqlite` in the case folder: it is built at the first search
  (only once, with progress: about 1 minute and 1 GB for an iPhone with 500,000 iLEAPP rows), rebuilt by itself when the
  results change, can be deleted without losing anything, and its building goes into the log. Secret keychain values do
  not enter the index. It does not search the content of files or the timeline: for those use the *Keywords* search.
- **Column filters** (2.20): the value box (▾) never goes outside the window, not even on 13" laptops: it opens below or
  above the button depending on the space, its height depends on the window height, the list of values scrolls inside it
  and sorting, search field and the *OK / Clear column / Cancel* buttons are always visible.
  The box can be **widened** by dragging the handle on its left edge, to read long file names (double click: default
  width; the size is kept in the browser's memory); the full name also appears when hovering over it.
  **Searching the values**: typing in *Search the values…* leaves visible only the values that contain the text; with
  **OK** (or Enter in the field) the filter keeps **only the values found and ticked**, as in Excel. Before 2.20 the values
  hidden by the search stayed ticked, and "Select all found" + OK meant "all": the filter was not applied. The same in the
  portable report.
- **Opening the case and heavy sections** (2.20): when a case opens, the window with the progress bar appears **at once,
  from the click**, and follows the opening of the case and the connection to the LLM server, then prepares the Results
  tree, the counts and the Timeline chart; the case is used when everything is ready. The **case summary** shown on
  opening stays in the case cache until the case and its databases change (test iPhone with 830,000 files: reopening
  from about 14 s to under a second). After opening, in the background, the first page of every section with data is
  prepared and the program remembers the last page seen in each section: the first click on *System artifacts*, *Timeline*,
  *Files*… no longer waits for the database query (same case: from 0.7–4.9 s to under 0.2 s) and going back to a section
  shows the table at once (it refreshes by itself if something changed meanwhile). After *Start the analysis* too the
  preparation page appears at once. The program keeps these answers in memory until the case databases change: moving
  between sections is immediate. The **Timeline chart** in the phone's time or in Italian time is computed much faster (test
  iPhone with 2.5 million events: from about 40 s to 2-7 s, same numbers as before) and, while it is being prepared, a
  waiting message is shown in its place.
- **Search the text** (2.20): in the *Text* tab of the preview, next to *Preview*, a search box like the Hex one: it
  highlights every occurrence (up to 5,000), **◀ ▶** or **Enter / Shift+Enter** move to the previous or next one, *match
  case* distinguishes upper and lower case.
- When you open the preview, the case panel hides itself to make room and reappears when you close it.
- **Resizable columns** (2.20) in every Results table, as in Excel: drag the right edge of the header; a **double click** on
  the edge fits the column to its text. Widths are remembered per section (browser storage) as long as the columns are the
  same; **↔ Reset columns** in the last header goes back to the automatic layout. The frozen header always stays on top,
  also above the «field: value» Details.
- **← Back / → Forward** (2.20), below the case bar: every opening (section or sub-item, file in the panel, *Show in tree*,
  search or bookmark tab, path quoted by the agent, *Open in Results* of the Summary, chat, conversation, attachment) is a
  step. Back returns to the previous state: tab, section, filters and search, sort order, page, scroll, row, open panel
  and, for chats, conversation, message and attachment. The browser Back button, **Alt+←** / **Alt+→** and **Cmd+[** /
  **Cmd+]** work too. Next to them, **breadcrumbs** (e.g. *System artifacts › Chat messages › Telegram › Josh Hickman ›
  📎 photo.jpg*, *🔎 Search › Words: …*, *Timeline › File system*): every item is clickable. The breadcrumbs always match
  what is shown: when the section or sub-item changes the table immediately shows «Loading…» and, if the data of an item
  clicked earlier arrive late, they are discarded. Every click is a step even if the previous loading has not finished
  (on large cases it takes a few seconds). Panels and previews close with **Esc** without reloading the table.

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

### Case panel and menu bar
The **case panel** (on the left) shows the case details, media, hash and last verification, partitions, LLM server
status and the recorded **Findings**.

**Menu bar (2.20).** Below the RepertIA name, in the case view, four drop-down menus (they used to be the *Actions* and
*Additional analyses* boxes of the panel):
- **Case**: *Edit case details*, **Case folder**, **Exported files**, **Cache and location**;
- **Report**: **Report** (also as **PDF** and **Word** .docx: `report.pdf` and `report.docx` in the case folder, with
  the SHA-256 in the log) and **Portable report**;
- **Checks**: **Verify hashes** (or **Compute image hash** if the hash has not been computed yet), **🔗 Verify log**,
  **Cross-check with another tool**, **Hash sets**;
- **Additional analyses**: each analysis with its status (✓ and the numbers, or "not performed") and **Run** / **Redo**
  (for smartphones also chats, iLEAPP/ALEAPP and WhatsApp backups).

On the right **← All cases**. A click opens the menu; with a menu open, hovering opens the others; a click on an item,
outside the menu or Esc closes it.

**Findings and verification (2.20.1, AI Act).** Every finding carries a label with its origin: **"Generated by AI model
(*name*) – to be checked"** for those recorded by the agent (in `findings.json`: `"origine": "modello IA"`, model,
server, `"stato": "da verificare"`), **"Entered by the analyst"** for those written with *Record finding*, "Origin not
recorded – to be checked" for those of cases prepared with earlier versions. After checking it on the forensic tools,
**✓ I confirm, verified** asks for the operator (the one in the case details is proposed) and records operator and date
in the case and in the log (`finding_verificato`): the label becomes "Verified by *operator* on *date*". The box title
shows how many findings are still to be checked. In the reports (Markdown, Word, PDF, portable) every finding carries
its label; the sentence "Every finding was verified by the analyst on the forensic tools" appears **only** if all of
them are, otherwise the report states how many are verified and how many are not; the Word and PDF metadata state that
the document contains AI-generated text. Under every answer of the agent there is the fixed label "Answer generated by
an AI model (*name*): hint to be checked". Automatic texts are marked as such: "Automatic transcription" for audio,
"automatic OCR text" in the document list and in the report. See [AI_ACT.en.md](../AI_ACT.en.md).

---

## Favourites (file categories)

In the Results select files with the check boxes on the left (whole folders too, with all their content) and press
**⭐ Favourites**, or **⭐ Favourites** on a file's row (after *Preview*) or in the preview pane: choose an existing
category or type a new name, with an optional note. The **⭐ Favourites** section lists the categories (rename,
description, delete) and each opens in a separate tab, with preview, export, finding and *Remove from category*.
Categories with **"in the report"** ticked go into the report (table per category with offset, inode, status, dates,
SHA-256 and note) and into the portable report, with the content and full previews of their files. Favourites are
stored in the case (`ricerche.sqlite`) and every operation is recorded in `audit_log.jsonl`.

## Audio transcription (2.20)

RepertIA transcribes the speech in audio files (chat voice notes, recordings, voicemail…) with **Whisper** (whisper.cpp
1.9.5 engine), **on this computer**: the audio is not sent to anyone and the LLM is not used. The text becomes
searchable and is always marked as **«automatic transcription, to be checked by listening to the audio»**: it does not
replace a certified transcription.

- **When**: when the case is created, with the **Transcribe the audio** box (forensic image page and smartphone page),
  as the last step of the preparation; or later, from the case: **Additional analyses → Audio transcription → Run**. It
  never starts by itself; for a single file, from its preview: **📝 Transcribe this audio** (or **🔁 Transcribe this audio
  again**, e.g. with another model). At the end you go back to the Results (or to the audio preview) with a notice of the
  outcome, without messages in the Conversation.
- **Which audio**: only audio attached to chats, all audio in the case, or only the selected files (e.g. from
  *Photos/Videos/Audio → Audio*). **Options**: language (detected automatically or fixed), maximum length per file
  (default 30 minutes), redo files already transcribed with the same model.
- **Model**: three models, *Fast (base, 60 MB)*, *Balanced (small, 190 MB, recommended)* and *Accurate
  (large-v3-turbo, 574 MB)*. They are **not in the packages** and are **not downloaded automatically**: the first time
  a window shows source (official whisper.cpp repository, pinned version), license (MIT), size and expected SHA-256; the
  download happens only with **I accept, download**, then the fingerprint is checked again (a different file is
  deleted). On an offline computer **I already have the model file…** accepts a file only if its SHA-256 is the listed
  one. Models stay next to the settings (`modelli_trascrizione/`, with `modelli.json`: who, when, from where) and serve
  all cases: the window shows the folder (**Open the folder**) and, next to each installed model, **Remove** (logged). When creating a case the window appears before starting; cancelling prepares the case without
  transcription.
- **Where the text appears**: text search (type «Automatic transcription»); preview of each audio file (tab with the
  sentences and their times: a click plays the audio from there); chat view, under the voice note; *Export chat* (HTML
  and CSV); portable report (chats and search); case report (section with numbers, model and SHA-256, engine and
  SHA-256, language).
- **Log**: the installation of each model and each transcription (model and fingerprint, engine version and
  fingerprint, options, outcome). The original audio is not touched: ffmpeg converts a working copy to 16 kHz WAV,
  removed afterwards.
- **Speed** (Apple Silicon Mac, small model): an 8-second audio in about 1.5 seconds. On Windows and Linux the engine
  runs on the processor, more slowly.

## Portable report (for those who do not have the forensic image)

From the **Report → Portable report** menu, RepertIA creates in `export/report_portatile_<date>/` a folder with
`index.html` to hand over (zipped too): it opens with a double-click in any browser, **offline**, without RepertIA,
without the forensic image and without AI.

- **It contains the whole catalogue**: file-system tree with deleted files, dates, sizes, hashes (if computed),
  metadata (device, date, GPS, author), extracted document text, timeline (file system and plaso), recovered files and
  traces, findings and report.
- **File content**, as you choose: only the files of findings and of selections exported with *Export*; also all
  documents and images up to a size; or **all files of the media** (deleted ones too, optionally), so the recipient can
  browse everything as if they had the forensic image. The dialog first shows number of files, size, free space and
  the **space the report will really take on the disk** (2.20): every file takes at least one cluster (128 KB on a 1 TB
  exFAT disk, so with many small files the report takes much more than the sum of the files), plus folders, previews,
  data and indexes. If it is not enough, keeping at least 2 GB free, *Create the report* stays disabled; during the
  creation the space is checked again and, if the disk is filling up, the report stops and removes the half-written
  folder (recorded in the case log). On a Mac, on exFAT/FAT disks, the hidden «._name» files that macOS creates next to
  every file are removed as it goes; a file of the media already named «._…» is saved as «_._…» (the original name
  stays in the catalogue).
  Files are in the `file/` folder with the original tree. For findings and selections: pages of PDFs and Office
  documents (with LibreOffice) as images, hex, exiftool and istat; for other files lighter previews (first pages of
  PDFs, first 4 KB in hex, metadata already indexed) and the *Open the original PDF* button.
- **Extended analyses**, if run: *System artifacts*, *Mail* (messages with attachments), *Archives and attachments* and
  *Anomalies* sections, with CSV export. Files extracted from archives and mail are included according to the same file
  content choice.
- Creation shows a **progress bar** with percentage, phase and estimated time. While the report is being created the
  dialog **stays open** (a click outside it or *Close* no longer hide it while the work goes on): it closes by itself at
  the end or with **Stop**, which stops the creation and removes the half-written folder (the stop is recorded in the
  case log). The report opens faster: the catalogue files are downloaded together and the tree indexes are lighter
  (test iPhone with 830,000 entries: from about 19 s to 5 s).
- **Content search** covers the text of indexed documents and, for all other included files, the readable strings
  (ASCII and UTF-16) extracted at creation; photos, video and audio are searched in their metadata. In the browser the
  search scans the index in blocks, with progress and a *Stop* button.
- **⚡ Case results** (2.20), first entry of the Search: as in the program, it searches as you type in the artifacts
  (also from iLEAPP/ALEAPP), calls, chats and conversations included in the report; results grouped and collapsed, a
  click opens the artifact or the message in the chat; phone numbers are found in any format (last 9 digits). Contacts
  tables are not in the portable report: contacts are found in the iLEAPP/ALEAPP artifacts. As you type it searches
  everything at once except the iLEAPP/ALEAPP rows; with **Enter** or *Search* it scans those too, one file at a time,
  with progress and *Stop* (iPhone with 500,000 rows: 1-4 s).
- **iLEAPP/ALEAPP artifacts on demand** (2.20): their rows are in files per artifact (at most 20,000 rows each) and are
  loaded by choosing the entry in the second menu of the *iLEAPP/ALEAPP artifacts* category; the total stays in the menu.
  Before, they were all in a single file loaded at start (test iPhone: 618 MB, too much for the browser); now that file
  is a few KB.
- **Timeline per day** (2.20): events are in files per day (in parts of 50,000 on very busy days) and the table appears as
  soon as the first one arrives; in months with more than 150,000 events the busiest day opens, the other days with a
  click and the whole month with *Load the whole month*. Test: iPhone with 2.5 million events (1.07 million in one day),
  table in 0.4 s instead of loading a file of hundreds of MB.
- **Browser Back and breadcrumbs** (2.20): every view, artifact category and open conversation is a step of the browser
  history; breadcrumbs at the top show where you are (every item is clickable), with ← →. In the chat view of smartphone
  cases: ⭐ for the whole conversation and **⬇ Export chat** (HTML and CSV downloaded by the browser; the SHA-256 of the two
  files is shown on screen and must be written down, because the portable report does not write to the case log).
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
- **Hash sets / NSRL**: from the *Checks* menu, *Hash sets* loads lists of known hashes (text files, CSV, NSRL RDS SQLite
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

They are enabled when the case is created or later, from the *Additional analyses* menu, without losing the
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

### Smartphones (new in 2.20)

From the start page, **📱 Smartphone** opens the analysis of a **full file system extraction** of an iPhone or an Android
phone, with the same interface, reports and log as for disks. **💽 Mass storage** is the usual path for E01, dd/raw and
dmg. In the list of cases the icon shows the type.

- **Formats**: the zip produced by acquisition tools (Cellebrite «Full File System», GrayKey, others), a tar (Magnet
  ACQUIRE, Android extractions), a **tar.gz** or an already extracted **folder**. **XRY** extractions can be opened if
  exported as a file system (folder, zip or tar); the proprietary `.xry` format is not read. A **UFDR** report is not a file
  system extraction: it will come in a later version.
- **No copies**: files are read from the extraction when needed (the zip's internal directory is read and each file is
  decompressed on its own). The extraction's SHA-256 is computed as for disk images and compared with the acquisition hash
  if there is a log next to it. A **tar.gz** does not allow reading a file without decompressing everything before it:
  RepertIA creates a **decompressed derived copy** in the case folder (`decompressa/`), with the SHA-256 of the original and
  of the copy and the reference to the original, which is not modified.
- **Tree, file list, timeline, search, document text, photo metadata, file hashes, previews, report and portable report**
  work as for disks; the extraction appears in the tree as «Extraction «name»». System and version (SystemVersion.plist,
  build.prop) and the **phone time zone** are read from the extraction.
- **Dates**: zip files with extended fields and tar files record dates in UTC. Zip entries with only the DOS date (local
  time without time zone, often the time of the extraction rather than of the phone) are converted with the device time
  zone and the case declares it. An already extracted folder has the dates of the computer it was copied to: declared.
- **Chats**: RepertIA's own readers for **WhatsApp** (iPhone and Android), **iMessage/SMS** (iPhone) and **SMS/MMS**
  (Android), with names from the phone's and WhatsApp's address books. Each database is read from a working copy with its
  `-wal`/`-shm` files, so messages not yet written back to the database also appear. The **💬 Open the chats** button in the
  case panel opens the **chat view**: conversations with filters by app, name or number, text and period; messages as
  bubbles with sender, time, status (delivered, read), attachments with thumbnail (*Preview*, *Show in tree*) and locations;
  each message shows the source database, table and row (click to copy the reference). Messages also go into the timeline
  and, one per conversation, into the Artifacts: the **Chat messages** entry is split by app in the tree; each row shows
  both parties (📱 *this device*, with the number or account if it is written in the extraction: sms.db, CommCenter,
  telephony.db, WhatsApp preferences; 👤 the other party with the address book name and the number or ID, *short
  code/service number* for 3-6 digit numbers such as 32665; 👥 for groups the name and participants) and, in the Details,
  the period in the chosen time zone, sent and received messages, attachments and a preview of the last message. The
  **💬 Open chat** button of the row opens the chat view on that conversation. In the chat view each message can be added
  to **⭐ Bookmarks** or recorded as a **📌 Finding** (reference with database, table and row); the «deleted message»
  placeholders left by the apps are highlighted. The **portable report** has the same chat view (*💬 Chats* entry), with
  the attachments that can be opened if their content is included in the report, ⭐ on single messages and *💬 Open chat*
  from the Artifacts.
- **iLEAPP and ALEAPP** (Alexis Brignoni and contributors, MIT licence): with the option *Artifacts with iLEAPP/ALEAPP*
  RepertIA runs the included version on the extraction; their tables become artifacts (category «iLEAPP/ALEAPP artifacts»),
  split in the tree by **iLEAPP/ALEAPP category** and then by **artifact**, each with its number of rows (a click filters the
  section; also in the portable report, with the second menu next to the category). The Details column shows the fields as
  a «field: value» table, with the dates in the time zone chosen at the top. Their HTML report stays in the case folder
  (`leapp/`): open it from the Finder or File Explorer, not inside RepertIA, because it contains evidence data. Version and
  fingerprint are in the case and in the report.
- **Chats and calls from iLEAPP/ALEAPP** (2.20): the chat apps RepertIA does not read with its own readers (Telegram,
  Discord, Instagram, Facebook Messenger, Google Messages, Snapchat on Android, LINE, Viber, Kik, TikTok, X, Zoom, Wire,
  TextNow, Burner, IMO, MeWe, Skout, Houseparty, CoverMe; Wickr metadata only) also appear in **Chat messages**, one
  sub-item per app, and in the chat view («direction not stated» when the source does not say whether a message was sent
  or received). The new **Calls** section has one row per call: date, direction (incoming, outgoing, missed, rejected,
  voicemail), number, address-book name, duration, answered, app (phone, FaceTime, WhatsApp, Duo, Instagram, LINE,
  Viber…), and all its sources. Equal rows from different sources are merged: same call if same number within 5 seconds
  (30 for *interactionC*, which records the start of the interaction a few seconds earlier); same message if same
  identifier, or same conversation, time, direction and text (e.g. database copies in the Magisk mirror). Values that
  differ between sources are flagged. The original rows stay in the *iLEAPP/ALEAPP artifacts*. The mapping between columns
  and fields is in `forense_mobile_leapp_mappa.json` (it can be extended without touching the code); artifacts that
  iLEAPP/ALEAPP declare as a conversation and that are not in the map are read with their declaration. WhatsApp,
  iMessage/SMS and SMS/MMS conversations remain those of RepertIA's readers (the corresponding iLEAPP/ALEAPP artifacts are
  not duplicated).
- **Chat buttons** (2.20): **💬 Open chat** in the table (icon) and in the details panel of a conversation, next to Source,
  Finding, Ask the agent and Bookmarks. In the chat view: ⭐ **Bookmarks** and 📌 **Finding** for a single message and for
  the **whole conversation**; **⬇ Export chat** writes to `export/chat/` a readable HTML (bubbles, image thumbnails,
  attachments copied alongside with their SHA-256) and a CSV, with a header giving case, app, parties, period, time zone
  used, extraction with SHA-256, source database with offset, inode and SHA-256 (also of the `-wal`/`-shm` files); the
  SHA-256 of the exported files go into the hash-chained log.
- **Attachment preview** (2.20): thumbnails in the bubbles already show the image; **videos** have a thumbnail too (a
  frame: Quick Look on Mac, ffmpeg on Windows and Linux), even when the file in the extraction has no extension (e.g.
  Telegram): the type is recognised from the attachment name or from the file header (MP4/MOV). In the Results thumbnails, if
  the program cannot make the thumbnail of a video, the browser takes the frame (it reads only the start of the file,
  when the tile is visible) and saves it as the thumbnail; thumbnails that failed with an earlier version are tried
  again. Thumbnails load in a queue, three at a time and only for visible tiles, so the page does not freeze even with
  hundreds of videos. A click opens the preview **over the
  chat**, which stays behind in the same position. Images (click to enlarge), video, audio, PDF and text as in the usual
  panel, with the Text, Hex and Metadata tabs and the buttons Show in tree, Export, Finding, Bookmarks and Ask the agent;
  the **← →** arrows (also on the keyboard) move to the previous or next attachment of the same chat, with date, sender and
  text of the message; **Esc** or ✕ close it and the message stays highlighted. Attachments of chats derived from
  iLEAPP/ALEAPP that their report copied (`media/…`) are shown as a declared working copy of that tool.
- **Attachments: file found, verified or thumbnail only** (2.20): attachments are looked up with the same search as the
  *Cited files* (below). WhatsApp records `file_hash` (base64 of the SHA-256): it finds the file even if it was moved or
  renamed and **verifies** it («SHA-256 equal to the one recorded by the app»; a different hash is flagged). If the file
  is not in the extraction, the **thumbnail stored in the database** is shown (WhatsApp Android: `message_thumbnail`,
  `message_thumbnails`, `raw_data`; WhatsApp iOS: the `.thumb` file named by the database) labelled «thumbnail from the
  database – file not present in the extraction», also in *Export chat* and in the portable report. Attachments of chats
  derived from iLEAPP/ALEAPP are linked to the original file of the extraction when it exists.
- **iOS keychain** (2.20): an iPhone's keychain is acquired separately (e.g. GrayKey). In the new smartphone case form (or in
  the case panel, *Choose the keychain…*) you give the file: RepertIA computes its SHA-256 (in the hash-chained log),
  **does not copy it into the case** (it is used from its path; if it changes after being recorded it is not used) and
  passes it to **iLEAPP with `--keychain`**; after choosing it in an existing case, run iLEAPP again. **Decryption and
  reading are done by iLEAPP.** The supplied keychain serves the artifacts that look up an app's key (Signal, Session,
  SimpleX, Snapchat, Wickr); the keychain artifacts (*Keychain Wifi Credentials*, *Keychain Web Passwords*, Bluetooth, mail
  accounts) are derived by iLEAPP from the keychain it finds inside the extraction (e.g. Cellebrite
  `extra/KeychainDump/backup_keychain_v2.plist`). The case panel and report state which keychain was used: *supplied by the
  examiner*, *found in the extraction* or *none*, with the entries read by iLEAPP. **Secret values** (passwords, keys,
  tokens): hidden («••••••») in tables, details, search, reports and agent; in the details panel **🔒 Secret values** →
  **Show** reveals one value at a time and the reading goes into the log (without the value); in the portable report only
  if *Include the keychain secret values* is ticked (choice logged). The iLEAPP report in the case folder contains them in
  clear text. Chats that iLEAPP decrypts with the keychain (Signal, Session, SimpleX) appear in the chat view with «🔑
  decrypted by iLEAPP with the keychain». Tested only with **fake** keychains; not tested on real GrayKey or Cellebrite
  keychains.
- **iOS sysdiagnose** (2.20): the archive `sysdiagnose_<date>_<time><offset>_<system>_<device>_<build>.tar.gz` that the
  iPhone produces on request (running processes, shutdowns, Wi-Fi, Bluetooth, battery, managed settings, logs…) is usually
  acquired separately. In the new smartphone case form the optional field **Sysdiagnose (.tar.gz)** accepts one or more
  (*Add* / *Choose…*: every file is checked at once and shows date and device); in an existing case *Add a sysdiagnose…*
  in the case panel. RepertIA computes its SHA-256 (in the hash-chained log), **does not copy it into the case** (if it
  changes after registration it is not read) and runs **iLEAPP a second time on the archive** (iLEAPP extracts into its
  report only the files it reads: modules *Sysdiagnose Process*, *Shutdown Log*, *sdl_…* (Wi-Fi, Bluetooth, disks,
  preferences, accounts…), *Battery UI*, *ManagedSettings*, *Container Manager* and the others that find their files). The
  rows go to the Artifacts, iLEAPP **Sysdiagnose** sub-entry, with the field *Origin* «from sysdiagnose <file name>» (also
  in the title). **Creation date** (UTC and phone time) and **device** (type, system, build; the model if
  `remotectl_dumpstate.txt` is there) come from the name of the archive folder, written by the iPhone: they are stated in
  the panel, in the report (*Sysdiagnose* section) and in the log. In the panel ↻ reads a sysdiagnose again and ✕ removes
  it from the case with its rows (the iLEAPP report stays in the case folder). *Source* on one of these rows explains that
  the file is inside the sysdiagnose, outside the extraction. Validation: archives in the form of a sysdiagnose built with
  the **public** excerpts of the iLEAPP tests (not complete sysdiagnoses); not tested on complete sysdiagnoses of a case.
- **Report of smartphone cases** (2.20): it lists only the tools actually used in that case, with their version —
  RepertIA (reading of the extraction), chat readers, iLEAPP/ALEAPP with the fingerprint, exiftool and pdftotext if
  indexed, 7-Zip and Tesseract if used, keychain and sysdiagnoses with their SHA-256 — at the top of the report, in
  *Analysis environment* and in the portable report; the method is described as reading of the file system extraction
  (no Sleuth Kit, partitions, unallocated space). The disk report does not change.
- **AI agent**: for smartphone cases it also has the tools `list_chats`, `read_chat`, `search_messages` and `find_contact`,
  and always cites the database, table and row of the messages.
- From the terminal: `python3 forense_mobile.py prepara --image EXTRACTION --case CASE [--leapp] [--decomprimi]
  [--keychain FILE] [--sysdiagnose FILE …]` and `python3 forense_mobile.py aggiungi --case CASE chat leapp`
  (`leapp-import` reads again the tables of the last iLEAPP/ALEAPP report without running it again; `sysdiagnose --file
  FILE` adds and reads a sysdiagnose, `sysdiagnose` alone reads them all again).
- **WhatsApp message types** (2.20): every message has its type (text, image, video, audio, document, GIF, sticker,
  location, contact, link, poll, call, notice, deleted message), taken from the database value (`ZWAMESSAGE.ZMESSAGETYPE`
  on iPhone, `message.message_type` or `messages.media_wa_type` on Android). WhatsApp does not publish the meaning of these
  values: those checked on Josh Hickman's public images are marked as verified, the others show «⚠ type not verified». An
  unknown value appears as **«[type N not handled]»** with the database number, never as a generic «attachment».
- **Delivery and read status** (2.20), only for **sent** messages: ✓ sent, ✓✓ delivered, blue ✓✓ read, ▶ played, with
  date and time when the database has them. Clicking the ticks opens the table with the status, the recipient (one per
  person in groups), the date, the **source** (table and column) and whether the meaning is verified. Verified: Android,
  older schema (Android 10) and schema from 2022 (Android 14: `receipt_user`, status 13 = read, 5 = delivered). **The
  absence of «read» does not prove that the message was not read**: read receipts can be turned off, and in the test data
  the first message sent on Android 14 is delivered but without a read time, although the other person replied.
  **iPhone**: the read status of sent messages cannot be read in this version (`ZMESSAGESTATUS` is 8 on all messages, sent
  and received); the grey tick does NOT mean that the message was not read. In the test data read receipts were on for
  both phones of the same conversation (the Android 14 received the receipts from the iPhone). For messages **received** on
  iPhone, instead, RepertIA shows **«read …»: the time this phone read the message** (`ZWAMESSAGE.ZSENTDATE`, which for
  received messages is not the sending time): on Hickman's two phones writing to each other it matches within 1 second the
  read receipt recorded by the other phone in 8 cases out of 10 (in the other two: 1 min 46 s during a call, and the first
  message from a number not in the contacts).
- **WhatsApp notices** (2.20): the notices WhatsApp inserts by itself into the conversation (group created, people added
  or left, end-to-end encryption…) are **«notice generated by WhatsApp (not written by a person)»**, never sent or
  received and without ticks (on Android the database marks them `from_me = 1`: in 2.20.0 before this fix they appeared
  as «sent»). Below the notice: the code as stored, the people named by the database (with the contact name) and the
  details (previous value, old and new number). The **?** explains what these values are. **Android**
  (`message_system.action_type`): where public sources explain the code, RepertIA also shows the sentence with its level:
  «**agreed by 2 public sources**» (WAInsight, `backend/app/models/enums.py`, derived from the decompiled app, and
  WhatsApp-Chat-Exporter, `utility.py`, both MIT licensed) or «**probable, 1 source**»; «and consistent with the test
  data» when Hickman's Android 14 image confirms it (11 group created, 12 people added, 67 encryption notice). No code is
  «verified»: that would need a test phone with documented actions. Agreed: 1, 5, 6, 10, 11, 12, 13, 14, 18, 20, 27, 28,
  56, 58; probable: 15, 21, 59, 67, 83, 84, 92; the others are shown only as a number. **iPhone** (`ZMESSAGETYPE` 6 and
  10, `ZGROUPEVENTTYPE`): **no public source** explains these numbers (iLEAPP says so too, module *WhatsApp - Group
  Events*; commercial programs use unpublished internal research). RepertIA reports the values as stored and only
  **facts derived from the database**: «recorded in the same second as the group creation» (`ZWAGROUPINFO.ZCREATIONDATE`),
  «first message of the conversation in WhatsApp's order» (`ZSORT`) and the position in WhatsApp's order when it differs
  from the one by time; «group name changed to …» (text of the notice; probable, 1 source: WhatsApp-Chat-Exporter,
  `ios_handler.py`). Note: `ZGROUPEVENTTYPE = 2` appears on **all** received messages, including ordinary ones, and on its
  own does not indicate an event. An interpretation needs public images with documented group actions or a controlled
  test on a test iPhone.
- **Calls** (2.20): besides those of iLEAPP/ALEAPP, RepertIA reads by itself the calls of **WhatsApp** (iPhone: the app's
  `CallHistory.sqlite` and type-59 chat messages; Android: `call_log` in `msgstore.db` and type-90 messages), **Skype**
  (`s4l-*.db`, table `calllogs`) and **imo** Android (`imofriends.db`, list in `imdata`, without duration). The same call
  found in several sources becomes **one row** with all the sources (table and row) and the discrepancies flagged (the
  time of a call also found in *interactionC*, which records the start of the interaction a few seconds earlier, is the
  one of the system log *Call History*). **Limit**: an interactionC row **without a number** is not merged with any call,
  because a number the source does not contain is not attributed: it appears as a call of its own with «(not stated)».
  It may therefore be the same call as a row of the system log (Hickman's iOS 17, 22/02/2024: interactionC incoming from
  14:59:45 to 15:00:03 without a number, Call History incoming rejected at 15:00:03 from +19787752806): check the sources
  before counting calls; in the
  chat the call appears only once. From iLEAPP/ALEAPP also Signal (when ALEAPP decrypts the database), Google Voice, Teams,
  Facebook Messenger and TeleGuard are read: for **Messenger** (msys) and **TeleGuard** the time written by
  ALEAPP/iLEAPP is the **end** of the call, so RepertIA computes the start by subtracting the duration (verified 4 of 4
  and 4 of 4 against the documentation). In the test images no VoIP app appears in the system call log: matching app ↔
  system log cannot be verified and is not done. **Coverage** (Hickman's public images; ✅ = compared with the documented
  calls):

  | App | iPhone | Android |
  |---|---|---|
  | Phone, FaceTime | ✅ CallHistory.storedata | ✅ calllog.db (Android 14: 2,655 = rows of `calls`) |
  | WhatsApp | ✅ own reader (iOS 17: 8 = documentation) | ✅ own reader (Android 14: 4 = documentation) |
  | Skype | ✅ own reader (iOS 17: 8) | ✅ own reader (Android 14: 4) |
  | imo | — | ✅ own reader (Android 14: 4) |
  | Signal | iLEAPP, if decrypted with the keychain | ✅ ALEAPP (Android 14: 4 of 4) |
  | Google Voice | iLEAPP | ✅ ALEAPP (2 of 2) |
  | Facebook Messenger | iLEAPP (without direction) | ✅ ALEAPP msys, start computed (8 of 8) |
  | TeleGuard | iLEAPP, start computed | ✅ ALEAPP, start computed (4 of 4) |
  | Teams | iLEAPP | — |
  | Instagram, Viber, LINE, Telegram, Zoom | iLEAPP | ALEAPP |

- **Chats of other apps from iLEAPP/ALEAPP: direction and reliability** (2.20): for each app the rule saying whether a
  message is sent or received is written in `forense_mobile_leapp_mappa.json`. Where the iLEAPP/ALEAPP column was wrong,
  the rule was derived by comparing the messages with those documented by Hickman (same text, time within 3 minutes):
  **LINE** (Android) from the presence of «From ID» (the «Direction» column is always 3), **imo** «0» = sent, **Life360**
  and **Slack** from the owner's account (Life360's «Message Sent» is not the direction). ALEAPP's WhatsApp messages
  (*Group Messages*, *One To One Messages*) are not added: they are the same ones read by RepertIA. Result on the public
  images: **iOS 17.3**, 1,167 documented messages, 766 found, **all with the right direction**; **Android 14**, 656
  documented, 272 found, **all with the right direction**. Seven messages (6 on iOS 17, 1 on Android 14) have a direction
  different from the one written in the documentation, but the error is in the documentation: the same message is marked
  «Sent» there for **both** phones, and where the app is also read on the other phone its database says that phone sent
  it (as RepertIA shows); an eighth was a wrong match of the comparison script. The ones not found are apps that neither iLEAPP nor
  ALEAPP read (Zoom, Wickr metadata only, Life360 on iPhone, Telegram and Teams on Android, Threema, Session, Truth
  Social, Mastodon, MEGA on Android, X) or messages deleted on purpose. Other limits found: Signal Android, the
  documented July 2024 conversations are not in ALEAPP's output; Snapchat iPhone, only 27/07/2024 is left in the database;
  Messenger Android, the «secret chat» messages are not in ALEAPP's output. These checks concern **the method** (the rules
  per app, on the app versions used by Hickman in 2024), not the messages of a case: in a real case there is nothing to
  compare with, and the interface shows no verification marks. The detail per artifact is in the `verifiche` section of
  the map.
- **Limit of 500,000 iLEAPP/ALEAPP rows** (2.20): if the iLEAPP/ALEAPP tables exceed the limit, RepertIA imports **first**
  the chat, message and call tables (those in the map, those iLEAPP/ALEAPP declare as conversations and those with
  *call*, *messag*, *chat*, *conversation*, *voicemail* in the name), then the others. The tables left out are listed in
  the case (`leapp.omesse`, with the rows imported and those in the report) and remain in the iLEAPP/ALEAPP report in the
  case folder. Below the limit the order does not change. In 2.20.0 before this fix, on iOS 17 the limit was filled by
  FSEvents (325,922 rows) and the chats of 23 apps were not imported.
- **Decrypted WhatsApp backups** (2.20, Android): every night WhatsApp saves an encrypted copy of the messages
  (`WhatsApp/Databases/msgstore*.db.crypt14`); a full extraction often contains the key too (`com.whatsapp/files/key`).
  With the box *Decrypt the WhatsApp backups (Android), if the key is in the extraction* (new case) or the additional
  analysis *Decrypted WhatsApp backups*, RepertIA decrypts the `.crypt14` files and reads them with its own reader. The
  chat view shows the app **🗄 WhatsApp (decrypted backup)**, with the backup name on each conversation; messages that
  are in the backup but not in the current database (same identifier missing) show **«⚠ only in the backup»**: they may
  have been deleted after the backup. Only a result with the correct AES-GCM authentication tag that is an SQLite
  database is accepted; the decrypted copies stay in the case (`backup_whatsapp/`, read only) and the SHA-256 of backup,
  key and decrypted copy go into the log. Outcomes declared: *encrypted with another key* (the backup signature is not the
  key's: typical of backups made before a new login), *incremental backup* (archive in an undocumented format: listed,
  not read), *format not handled* (crypt12, crypt15: for crypt15 the key is not on the phone). Format verified on
  Hickman's Android 14 image (offsets from WhatsApp-Chat-Exporter, `android_crypt.py`, MIT). From the terminal: `prepara
  … --wa-backup` or `aggiungi --case CASE wa-backup`.
- **Photos and videos ↔ chats** (2.20): in Results, under **Photos/Videos/Audio**, the sub-items **🖼 Photos**, **🎞 Videos** and **🎵 Audio** and the
  filters **Photos only**, **Videos only** and **Audio only**; in smartphone cases the item **💬 From chats** (one sub-item
  per app), also under each of Photos, Videos and Audio, lists the files attached to a message and the *Origin* filter chooses the app. Opening an attached photo or video, the **Origin**
  box says in which chat it was sent or received, by whom, when, with database, table and row, whether the file is
  certain or probable and whether the SHA-256 matches the one recorded by the app; **💬 Open in the chat** goes to the
  message. The CSV has the column `origine_chat`. Also in the portable report.
- **Preview of phone databases** (2.20): an SQLite database of the phone is previewed with its `-wal`, `-shm` and
  `-journal` files (on a working copy), as the chat readers do, and the note says so. Before, only the main file was
  read: on Android 14, 383 of the 508 databases with a `-wal` showed incomplete data.
- **Import notices** (2.20): the notices of the chat import (encrypted databases, keys found, backups) are in the button
  **⚠ Import notices (N)** of the panel, which opens a resizable window.
- **Limits**: only what is in the extraction can be seen (a logical extraction or a backup does not contain the app
  databases); encrypted databases (Signal if ALEAPP/iLEAPP does not decrypt it, WhatsApp backups `.crypt15` or made with
  another key) cannot be read; deleted messages still present in the free pages of databases are not recovered in this
  version; extractions have no deleted files of the file system.
- **Validation**: two test extractions in `RepertIA-collaudo/smartphone/` built with excerpts of the public images of Josh
  Hickman (iOS 15) and «anne_a15» (Android 15) used in the iLEAPP and ALEAPP tests: the times of all messages must match the
  results published by those projects; plus an Android WhatsApp built with known content. From 2.20 also fake keychains,
  cited files and two **sysdiagnoses** in the form of a real archive built with the public excerpts of the iLEAPP tests
  (the number of processes in `ps.txt` is counted without iLEAPP and must match).

### Cited files (new in 2.20)

Many rows name a file without being one: Google Photos «File Path /storage/emulated/0/Pictures/…», the document a LNK
shortcut or a jump list points to, the file downloaded by the browser, the content in the Recycle Bin, the Prefetch and
Amcache program, iLEAPP/ALEAPP «media/…», a chat attachment, a path written by the agent. RepertIA recognises these
fields and looks for the file in the forensic image or in the extraction, with the same function across the program
(`forense_percorsi.py`):

1. **by path**, with the mapping table `forense_percorsi.json`: Android `/storage/emulated/0`, `/sdcard`, `/mnt/sdcard` →
   `data/media/0`, `/data/user/0` → `data/data`; iOS `/var/mobile` ↔ `/private/var/mobile` (and `filesystem2/mobile` of
   Cellebrite-style extractions), `~/`, `file://` and paths relative to app containers; Windows drive letters, `\\?\Volume{…}`, `\Device\HarddiskVolumeN`, `%USERPROFILE%`,
   `%APPDATA%`, `%SystemRoot%`…; macOS `/Users`, `/Volumes/<name>`, `/private/var`. The final part of the path is
   compared regardless of case and, on a tie, the partition the row comes from wins (useful with several Windows
   installations). For iLEAPP/ALEAPP «media/…» the original path comes from their database (`_lava_media_items`). The
   table is extended by adding rows to the JSON file.
2. **by hash**, if the row gives one (SHA-256, SHA-1, MD5, also base64): in the case's hash table or among the files of
   the same size;
3. **by name and size**, or **by name only**: when several files have the same name, all of them are listed as candidates.

**Folder and name in the same row.** Many artifacts write the folder and the name in two fields (e.g. iLEAPP *Photos.sqlite
EXIF Analysis*: «Directory: DCIM/100APPLE», «Filename: IMG_0059.PNG»): RepertIA joins them into a full path
(`DCIM/100APPLE/IMG_0059.PNG`) and looks it up **by path**, not by name only. If the joined path does not lead to a file
(e.g. «Original Filename», the name the photo had before, in another folder) the name stays on its own. A field that only
gives a folder is not a cited file: it becomes the **📁 folder** link in the file's box (the folder that contains the file
found).

**One box for each different file.** If several fields of the same row lead to the same file (e.g. iLEAPP «Media», the copy
in its report linked to the original, and «Directory + Filename») there is a single **📎 Cited file**, with «given in the
fields: Media, Directory + Filename» below it.

**The result, in three levels** (the **?** button next to the result explains them):

| Result | When | What to do |
|---|---|---|
| ✅ **found with certainty** | full path, hash, or link recorded by iLEAPP/ALEAPP; if the row gives a hash and it matches: «**hash verified**» | nothing: the file is the one the row points to |
| ⚠️ **probable, to be verified** | name only, or name and size; also a file found by path whose hash is **different** from the row's | check the list of **candidates** (all the files with that name, with size, preview and tree): the row does not say which one |
| ❌ **not present in the extraction** (on disks «in the forensic image») | no matching file; if iLEAPP/ALEAPP only has a copy in its report or derived it from inside a database, this is stated and that copy is shown | the file was deleted, not acquired or never saved on the device |

If several fields point to the same file, the strongest method applies (a name-only result whose candidate is already the
file found with certainty by another field is merged into it). The method, field by field, is always written.

- **Details panel** of an artifact (also opened from Search, Favourites or Calls): above the table of fields, one
  **📎 Cited file** box for each different file with the path found (click = tree), the colour-coded result (green,
  orange, red) and the method, the fields that give it, the 📁 folder link, the **preview** (image, video, audio, first
  page of the PDF, text) and the buttons *Preview*, *Show in tree*, *Export*, *⭐ Favourites*; for a «probable» result
  with several files, the list of candidates. **▸ Technical details** (closed) holds the method for each field, the value
  written in the row, the SHA-256 if already computed and, if the same final part of the path exists in several places of
  the image/extraction, the **other copies with the same final path** (path, size, SHA-256 if computed) with the
  explanation: the row gives the final part of the path, the file shown is the one with the closest path, the SHA-256
  values tell whether the content is the same. Below, separate, the **Source**: the database or file the row comes from
  (e.g. `gphotos-1.db`) with its full path in the extraction and its button.
- **Artifacts table**: one thumbnail per row (the first image found), outlined in orange or red if the result is not
  certain; 📎 for other files (grey if none was found); hovering shows the result of each cited file.
- **Timeline**: *Preview*, *Tree* and *Export* on plaso rows use the same search. **AI agent**: the artifact tool reports
  the cited file found; paths written in the answers (also Windows or phone paths) open with one click (preview and tree).
  **Favourites, Finding and log**: the reference of an artifact lists the cited files with result and method per field.
  **Case report (Markdown, Word, PDF)**: after the Favourites tables, «Files cited by the artifacts in Bookmarks» writes
  for each cited file the result (found with certainty / probable, to be verified / not present), the path and the
  method per field; for probable results also the candidates.
- **Portable report**: for every artifact one box per different file with the colour-coded result, the «?», the fields,
  the folder, the candidates, the *Technical details* with the copies, the resolved source, a thumbnail of the images
  found (at most 3,000 per report) and *Open the cited file* if the content of the file is included in the report; the CSV
  has the result in words in the `file_citati` column.
- The search uses the tree index (`navigazione.sqlite`), to which it adds a name and size index the first time; tables
  and the portable report use the fast search (path and name; the row's hash is checked only when there is a single file
  of up to 16 MB, so that the result is the same as in the panel), the panel the full one. `tools/file_citati_conta.py <case>`
  counts per section the rows with a cited file and the files found and not found.
- **Limits**: a path on the phone's system partition (`/system/…`) or on another disk is not in the extraction or the
  image; Android `content://` references are not resolved; a file found by name only may be another file with the same
  name: it must be verified.

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
| **iLEAPP / ALEAPP** (2.20, MIT licence) | iPhone and Android app artifacts, in smartphone cases |
| **whisper.cpp** 1.9.5 (2.20, MIT licence; in the packages) + Whisper models (downloaded only with consent) | automatic transcription of audio, on the computer |
| **ffmpeg** (in the packages; on the Mac a minimal LGPL build from 2.20) | audio conversion for transcription and video frames |

The interface is an HTML/JavaScript page without external libraries, served by the program itself. The main files are:

- `forense_agent.py` — case preparation, agent tools, report (from the terminal too);
- `forense_gui.py` — local server of the interface, tree, timeline, selections, exports, saved conversations;
- `forense_gui.html` — the interface;
- `forense_estesa.py` — extended analyses: archives, mail, anomalies, artifacts, VSS, OCR, hash sets, encrypted volumes;
- `forense_apfs.py` — Mac APFS volumes (libfsapfs), encrypted ones too;
- `forense_collaudo.py` — acceptance test with the reference images (2.14);
- `forense_riscontro.py` — cross-check with the file/hash list of another tool (2.15);
- `forense_mobile.py`, `forense_mobile_chat.py`, `forense_mobile_leapp.py`, `forense_mobile_gui.py`, `forense_mobile.html` —
  smartphone cases (2.20): extractions, chats, iLEAPP/ALEAPP, interface; loaded only for smartphone cases;
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
| `ricerca_veloce.sqlite` | (2.20) index of the fast search in the case results; can be deleted, rebuilt at the first search |
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
- **Later verification of the log (2.20).** The report (Markdown, Word, PDF, portable report) prints the **number of
  entries** and the **final hash** of the log (SHA-256 of the last line) at the time of the report. **🔗 Verify log** — on
  the home page for any `audit_log.jsonl` or case folder (also copied from another computer), in the *Checks* menu for the
  open case — recomputes the chain and tells: *intact*; or the **first altered line** (line and entry number, expected
  and current SHA-256, current content); **missing lines** in the middle (gap in the sequence numbers); inserted or
  out-of-order lines. With the optional field **expected final hash** (and the number of entries) copied from the report
  it also detects **lines removed at the end** and a **log rewritten in full**: if the hash is found, the log of that
  time is still all there and the following lines are operations done later (the first is usually the «report» entry).
  It also re-checks the **SHA-256 of the exported files** cited in the log (exports, exported chats, Word/PDF reports;
  for selections the `manifest.csv`) if they are in the case folder. The verification of the open case stays in its log.
  Same check from the terminal, also without RepertIA installed (only Python is needed): `python3
  tools/verifica_registro.py <audit_log.jsonl | case folder> [--hash-finale H] [--voci N] [--json] [--lingua en]` (or
  `python3 forense_registro.py …` from the package sources); exit code 0 if everything matches, 1 if not.
  **What it proves**: that the log (up to the given final hash) is the one written by RepertIA line after line, with no
  line changed, removed or inserted afterwards, and that the exported files are still the recorded ones. **What it does
  not prove**: who used the program, nor that the operations described are correct or complete (the log says what
  RepertIA did, not whether the result is right); without a final hash kept elsewhere (delivered report, minutes) a log
  rewritten in full with a recomputed chain appears intact; lines removed at the end are visible only with the final hash;
  the original content of an altered line cannot be reconstructed; exported files outside the case folder or deleted
  cannot be re-checked.
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
- **Cross-check with another tool (2.15).** *Cross-check with another tool* (*Checks* menu) compares the case's files
  with the list exported by a second tool on the **same image**: Autopsy (*Save table as CSV*), FTK Imager (*Export File
  Hash List* or *Export Directory Listing*), X-Ways, EnCase, AXIOM (CSV with path and hash), Sleuth Kit
  (`fls -r -m / -h`). The format is recognised automatically. Result: files with the same hash (independent
  confirmation: each tool read the image on its own), with a **different** hash, present in only one of the two,
  discordant "deleted" status or size. The result goes into the report (*Cross-check with other tools* section, with the
  SHA-256 of the external file) and the log; the line-by-line detail in `riscontri/` in the case. From the terminal:
  `forense_agent.py riscontro --case CASE --file list.csv --strumento "Autopsy 4.21"`. It is the recommended way to
  confirm findings before using them.
- **Quick analysis**: unticking *Compute the SHA-256 of the forensic image now* on the start page, the analysis starts
  without waiting for the hash, which is computed later from the *Checks* menu with **Compute image hash** (from the
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

`RepertIA-2.20.2-Mac.zip` contains **RepertIA.app** with Python 3.12, openai, Pillow and **plaso already included** (no
Docker). Drag the app into Applications; the first time: right-click → *Open* (or *System Settings → Privacy & Security
→ Open Anyway*), because it is not signed with an Apple certificate. The app opens the Terminal, installs the missing
tools with Homebrew (Sleuth Kit, libewf, exiftool, poppler, PhotoRec, bulk_extractor, Tesseract) and then the browser.
7-Zip, libpff and the Italian/English OCR data are already in the app. To update the tools there is
*Aggiorna strumenti.command* in the zip. Only for Macs with M1 or later.

## Windows version

`RepertIA-2.20.2-Setup.exe` installs RepertIA for the current user (no administrator rights) in
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

`RepertIA-2.20.2-Linux.tar.gz` is for **Linux x86_64** with Python 3.12 or later (Ubuntu 24.04 or later, Debian 13).
The program is the same as the Mac and Windows versions (same source fingerprint).

```
tar -xzf RepertIA-2.20.2-Linux.tar.gz
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
- **"Model context full"** (2.20; before, it appeared as a server error 500, e.g. with Qwen on Ollama "no user query
  found in messages"): after some searches by the agent the tool results exceed the model context (the *Context* value in
  the LLM server box) and the server cuts the beginning of the conversation, question included. Raise the context (Ollama:
  Settings → *Context length* or `OLLAMA_CONTEXT_LENGTH=32768`; LM Studio: load the model with a context of 32768 or
  more), press *Reconnect* and check the new value; or ask more targeted questions (one term, one source). RepertIA does
  not shorten the results further by itself, so as not to remove useful elements.
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
