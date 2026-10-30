RepertIA 2.20.2 - By silvexe (Linux x86_64)
Forensic analysis of disk images and smartphone extractions with a local language model (LLM).

LINUX VERSION (EXPERIMENTAL)
Same program as the Mac and Windows versions (same source fingerprint). The acceptance test was
run by the author in a Linux development environment; before using it in a case, run the
acceptance test on your computer (see below) and keep the report.
Systems: Ubuntu 24.04 or later, Debian 13 or other distributions with Python 3.12 or later,
64-bit Intel/AMD processor.

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
     tar -xzf RepertIA-2.20.2-Linux.tar.gz
2. Open a terminal in the RepertIA folder and run:
     ./installa.sh
   Internet access and the administrator password are required. The script:
   - installs with apt Sleuth Kit, libewf, PhotoRec, Poppler, ExifTool, Tesseract (OCR) and zenity
     (file selection dialogs) and, if the distribution has it, bulk_extractor;
   - creates in python/ the Python environment with plaso, the libyal libraries, pytsk3, Pillow and
     the openai client, at the same versions as the Mac and Windows packages (requirements-linux.txt);
     the libyal libraries are compiled: it takes 10-20 minutes;
   - adds RepertIA to the applications menu.
   The installation log is in installa.log. The script can be run again.
3. Start RepertIA from the applications menu or with ./RepertIA.sh: the browser opens.

Included in the archive: 7-Zip 26.01 (strumenti/7zip) and the Italian/English OCR data
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
