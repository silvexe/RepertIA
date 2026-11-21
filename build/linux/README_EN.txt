RepertIA 3.0.6 - By silvexe (Linux x86_64)
Forensic analysis of disk images, smartphone extractions and drone flight logs with a local language model (LLM).

LINUX VERSION (EXPERIMENTAL)
Same program as the Mac and Windows versions (same source fingerprint). The acceptance test was
run by the author in a Linux development environment; before using it in a case, run the
acceptance test on your computer (see below) and keep the report.
Systems: Ubuntu 24.04 or later, Debian 13 or other distributions with Python 3.12 or later,
64-bit Intel/AMD processor. On 64-bit ARM (aarch64) the program works with the tools of the
distribution (7-Zip and ffmpeg too); the package also contains, for ARM, the MemProcFS library for RAM
analysis and the audio transcription engine (whisper.cpp): installa.sh puts them in place, and must be
run again after every update of the program.

LANGUAGE
The interface is available in Italian and English: use the selector at the top right.
Each case keeps the language chosen when it is created (artifacts and reports).

SMARTPHONES (2.20)
On the start page "Smartphone" opens a full file system extraction of an iPhone or an Android phone
(zip from Cellebrite, GrayKey and others, tar, tar.gz or folder): chats (WhatsApp, iMessage/SMS,
SMS/MMS) with the bubble view, address books, timeline, searches and reports as for disks.
iLEAPP and ALEAPP (MIT licence) are included in strumenti/ileapp and strumenti/aleapp.
On Linux their libraries are installed by installa.sh.

INSTALLATION
1. Extract the archive wherever you prefer (for example in your home folder):
     tar -xzf RepertIA-3.0.6-Linux.tar.gz
2. Open a terminal in the RepertIA folder and run:
     ./installa.sh
   Internet access and the administrator password are required. The script:
   - installs with apt Sleuth Kit, libewf (ewf-tools), PhotoRec, Poppler, ExifTool, Tesseract (OCR) and
     zenity (file selection dialogs) and, if the distribution has it, bulk_extractor; packages the
     distribution does not have are listed at the end and do not block the others;
   - creates in python/ the Python environment with plaso, the libyal libraries, pytsk3, Pillow and
     the openai client, at the same versions as the Mac and Windows packages (requirements-linux.txt);
     the libyal libraries are compiled: it takes 10-20 minutes;
   - adds RepertIA to the applications menu.
   The installation log is in installa.log. The script can be run again.
3. Start RepertIA from the applications menu or with ./RepertIA.sh: the browser opens.

UPDATING TO A NEW VERSION
1. Close RepertIA.
2. Extract the new archive over the existing folder, giving the folder that contains RepertIA
   (for example your home folder, ~):
     tar -xzf RepertIA-<version>-Linux.tar.gz -C ~
   Cases (~/CasiForensi) and settings are not touched.
3. Run ./installa.sh again. It updates the Python libraries only if the new version uses different
   ones (it recognises this from requirements-linux.txt and from the iLEAPP and ALEAPP lists) and, on
   64-bit ARM, puts the ARM tools back in place. Internet access is required.
Limit: files that a new version no longer has stay in the folder (they do no harm). For a clean
folder: rename the old one, extract the new one, run ./installa.sh (the libyal libraries are compiled
again: 10-20 minutes), then delete the old one.

REMOVAL
- the program folder (RepertIA);
- the applications menu entry: ~/.local/share/applications/repertia.desktop;
- settings, diagnostic log and downloaded transcription models: ~/.config/RepertIA
  (up to 3.0.5: ~/Library/Application Support/RepertIA).
The cases in ~/CasiForensi stay (delete them yourself when no longer needed) and so do the packages
installed with apt, which other programs may also use (remove them with "sudo apt remove" if you wish).

BULK_EXTRACTOR (optional)
Debian and Ubuntu do not package it: build it from https://github.com/simsong/bulk_extractor
(instructions in its README). RepertIA uses it if the bulk_extractor command is in the PATH (for
example in /usr/local/bin, where "sudo make install" puts it) or if the program is in the
strumenti/bulk_extractor/ folder of RepertIA. Tools are checked at startup: restart RepertIA after
installing it. To check: "which bulk_extractor" in the terminal, or ./aggiorna-strumenti.sh.

Included in the archive: 7-Zip 26.05 (strumenti/7zip) and the Italian/English OCR data
(strumenti/tessdata). The system tools are updated with ./aggiorna-strumenti.sh; the versions
actually used are always listed in the case report (Analysis environment section).

PRIVACY
RepertIA works only on this computer: the forensic image is opened read-only and the case
data are not sent to third parties. The interface listens only on 127.0.0.1. The only intended
exception: if in the "LLM server" panel you choose "Network server", the questions and the
content read by the agent go to that internal network server (the report states it).

The cases are in ~/CasiForensi.

INTEGRITY AND ACCEPTANCE TEST
- The case compares the hash of the data with the acquisition hash recorded in the E01 or in
  the log of the acquisition tool (FTK Imager, Guymager...); the case log is hash-chained.
- ./collaudo.sh: with the RepertIA-collaudo folder (from the RepertIA-collaudo.zip archive, next
  to this file, on the Desktop or in Downloads) it checks that RepertIA gives the expected results
  on reference images (including the public DFTT ones, with the published values) and writes the
  report in ~/CasiForensi/_collaudo. With ./collaudo.sh --lingua en the test cases are in English.
- CROSS-CHECK: "Cross-check with another tool" button in the case: compares files and hashes
  with the list exported by Autopsy, FTK Imager, X-Ways... from the same image.

Personal project of silvexe, carried out privately and not connected with any office or administration. Developed with the help of Claude, an artificial intelligence model by Anthropic; design choices, verifications and tests are the author's.
