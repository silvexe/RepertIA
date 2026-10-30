RepertIA 2.20.2 - By silvexe (Mac Apple Silicon)
Forensic analysis of disk images and smartphone extractions with a local language model (LLM).

LANGUAGE
The interface is available in Italian and English: use the selector at the top right.
Each case keeps the language chosen when it is created (artifacts and reports);
cases created with earlier versions are in Italian.

SMARTPHONES (2.20)
On the start page "Smartphone" opens a full file system extraction of an iPhone or an Android phone
(zip from Cellebrite, GrayKey and others, tar, tar.gz or folder): chats (WhatsApp, iMessage/SMS,
SMS/MMS) with the bubble view, address books, timeline, searches and reports as for disks.
iLEAPP and ALEAPP (MIT licence) are included in strumenti/ileapp and strumenti/aleapp.

INSTALLATION
1. Drag RepertIA.app into the Applications folder (or wherever you prefer).
2. First start: right-click on RepertIA.app > Open > Open. If macOS still blocks it,
   go to System Settings > Privacy & Security and press "Open Anyway".
   (The app is not signed with an Apple certificate.)
3. Terminal opens: on the first start it installs with Homebrew (internet required)
   Sleuth Kit, libewf, exiftool, poppler, PhotoRec, bulk_extractor and Tesseract (OCR).
   Then the browser opens.

Python, openai, Pillow, plaso (system timeline), 7-Zip (archives), the libraries for Outlook
mail, shadow copies, encrypted volumes and Mac APFS volumes and the Italian/English OCR data are
already included in the app: Docker is not needed. To update the Homebrew tools use
"Aggiorna strumenti.command".

PRIVACY
RepertIA works only on this computer: the forensic image is opened read-only and the case
data are not sent to third parties. The only intended exception: if in the "LLM server"
panel you choose "Network server", the questions and the content read by the agent go to
that internal network server (the report states it).

The cases are in ~/CasiForensi (including those created with earlier versions).

INTEGRITY AND ACCEPTANCE TEST
- The case compares the hash of the data with the acquisition hash recorded in the E01 or in
  the log of the acquisition tool (FTK Imager, Guymager...); the case log is hash-chained.
- "Collaudo RepertIA.command": with the RepertIA-collaudo folder (from the
  RepertIA-collaudo.zip archive, next to the app, on the Desktop or in Downloads) it checks that
  RepertIA gives the expected results on reference images (including the public DFTT ones,
  with the published values) and writes the report in ~/CasiForensi/_collaudo.
- CROSS-CHECK: "Cross-check with another tool" button in the case: compares files and hashes
  with the list exported by Autopsy, FTK Imager, X-Ways... from the same image.

Personal project of silvexe, carried out privately and not connected with any office or administration. Developed with the help of Claude, an artificial intelligence model by Anthropic; design choices, verifications and tests are the author's.
