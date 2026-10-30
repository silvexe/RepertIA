; SPDX-License-Identifier: GPL-3.0-or-later
; Copyright (C) 2026 silvexe
Unicode true
!include "MUI2.nsh"
!define APP "RepertIA"
!ifndef VER
  !define VER "2.20.2"
!endif
Name "${APP} ${VER}"
OutFile "RepertIA-${VER}-Setup.exe"
InstallDir "$LOCALAPPDATA\Programs\RepertIA"
InstallDirRegKey HKCU "Software\RepertIA" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma
SetCompressorDictSize 64
BrandingText "RepertIA - By silvexe"
!ifndef VIVER
  !define VIVER "${VER}.0"
!endif
VIProductVersion "${VIVER}"
VIAddVersionKey "ProductName" "RepertIA"
VIAddVersionKey "CompanyName" "silvexe"
VIAddVersionKey "FileDescription" "Installazione di RepertIA"
VIAddVersionKey "FileVersion" "${VER}"
VIAddVersionKey "LegalCopyright" "By silvexe"

!define MUI_ICON "app\repertia.ico"
!define MUI_UNICON "app\repertia.ico"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "$(LS_WELCOME_TITLE)"
!define MUI_WELCOMEPAGE_TEXT "$(LS_WELCOME_TEXT)"
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "$(LS_RUN)"
!define MUI_FINISHPAGE_RUN_FUNCTION AvviaRepertIA
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\$(LS_README_FILE)"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "$(LS_README_TEXT)"
; lingua dell'installazione: scelta all'avvio, ricordata per l'aggiornamento e usata da RepertIA al primo avvio
!define MUI_LANGDLL_REGISTRY_ROOT "HKCU"
!define MUI_LANGDLL_REGISTRY_KEY "Software\RepertIA"
!define MUI_LANGDLL_REGISTRY_VALUENAME "Lingua"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE $(LS_LICENSE)
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Italian"
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_RESERVEFILE_LANGDLL

LangString LS_WELCOME_TITLE ${LANG_ITALIAN} "Installazione di RepertIA ${VER}"
LangString LS_WELCOME_TITLE ${LANG_ENGLISH} "RepertIA ${VER} Setup"
LangString LS_WELCOME_TEXT ${LANG_ITALIAN} "RepertIA - By silvexe$\r$\n$\r$\nAnalisi forense di copie di dischi con un modello linguistico locale. Tutto resta su questo computer: nessun dato viene inviato a terzi.$\r$\n$\r$\nVengono installati anche Python, plaso, The Sleuth Kit, ExifTool, Poppler, PhotoRec e bulk_extractor, usati solo da RepertIA. Non servono diritti di amministratore.$\r$\n$\r$\nL'interfaccia è in italiano o in inglese (si cambia dal programma)."
LangString LS_WELCOME_TEXT ${LANG_ENGLISH} "RepertIA - By silvexe$\r$\n$\r$\nForensic analysis of disk images with a local language model. Everything stays on this computer: no data is sent to third parties.$\r$\n$\r$\nPython, plaso, The Sleuth Kit, ExifTool, Poppler, PhotoRec and bulk_extractor are also installed, used only by RepertIA. No administrator rights are needed.$\r$\n$\r$\nThe interface is in English or Italian (it can be changed from the program)."
LangString LS_RUN ${LANG_ITALIAN} "Avvia RepertIA"
LangString LS_RUN ${LANG_ENGLISH} "Start RepertIA"
LangString LS_README_FILE ${LANG_ITALIAN} "LEGGIMI.txt"
LangString LS_README_FILE ${LANG_ENGLISH} "README_EN.txt"
LangString LS_README_TEXT ${LANG_ITALIAN} "Leggi le note (LLM, LibreOffice)"
LangString LS_README_TEXT ${LANG_ENGLISH} "Read the notes (LLM, LibreOffice)"
LicenseLangString LS_LICENSE ${LANG_ITALIAN} "LEGGIMI.txt"
LicenseLangString LS_LICENSE ${LANG_ENGLISH} "README_EN.txt"
LangString LS_SEC_MAIN ${LANG_ITALIAN} "RepertIA (obbligatorio)"
LangString LS_SEC_MAIN ${LANG_ENGLISH} "RepertIA (required)"
LangString LS_SEC_DESK ${LANG_ITALIAN} "Icona sul desktop"
LangString LS_SEC_DESK ${LANG_ENGLISH} "Desktop icon"
LangString LS_DESC_MAIN ${LANG_ITALIAN} "Programma, Python e strumenti forensi."
LangString LS_DESC_MAIN ${LANG_ENGLISH} "Program, Python and forensic tools."
LangString LS_DESC_DESK ${LANG_ITALIAN} "Collegamento a RepertIA sul desktop."
LangString LS_DESC_DESK ${LANG_ENGLISH} "RepertIA shortcut on the desktop."
LangString LS_LNK_UPDATE ${LANG_ITALIAN} "Aggiorna strumenti"
LangString LS_LNK_UPDATE ${LANG_ENGLISH} "Update tools"
LangString LS_LNK_README ${LANG_ITALIAN} "Leggimi"
LangString LS_LNK_README ${LANG_ENGLISH} "Readme"
LangString LS_LNK_TEST ${LANG_ITALIAN} "Collaudo"
LangString LS_LNK_TEST ${LANG_ENGLISH} "Acceptance test"
LangString LS_LNK_CASES ${LANG_ITALIAN} "Cartella dei casi"
LangString LS_LNK_CASES ${LANG_ENGLISH} "Cases folder"
LangString LS_LNK_UNINST ${LANG_ITALIAN} "Disinstalla RepertIA"
LangString LS_LNK_UNINST ${LANG_ENGLISH} "Uninstall RepertIA"
LangString LS_CODE ${LANG_ITALIAN} "it"
LangString LS_CODE ${LANG_ENGLISH} "en"

Function .onInit
  !insertmacro MUI_LANGDLL_DISPLAY
FunctionEnd

Function un.onInit
  !insertmacro MUI_UNGETLANGUAGE
FunctionEnd

Function AvviaRepertIA
  ExecShell "" "$INSTDIR\RepertIA.bat" "" SW_SHOWNORMAL
FunctionEnd

Section "$(LS_SEC_MAIN)" SecMain
  SectionIn RO
  ; una versione precedente viene sostituita (programma e strumenti, non i casi)
  RMDir /r "$INSTDIR\RepertIA"
  RMDir /r "$INSTDIR\python"
  RMDir /r "$INSTDIR\strumenti"
  SetOutPath "$INSTDIR"
  File /r "app\*.*"
  WriteRegStr HKCU "Software\RepertIA" "InstallDir" "$INSTDIR"
  ; lingua predefinita di RepertIA (vale finché l'utente non ne sceglie un'altra nel programma)
  FileOpen $0 "$INSTDIR\lingua_predefinita.txt" w
  FileWrite $0 "$(LS_CODE)"
  FileClose $0
  WriteUninstaller "$INSTDIR\Disinstalla.exe"
  CreateDirectory "$SMPROGRAMS\RepertIA"
  CreateShortcut "$SMPROGRAMS\RepertIA\RepertIA.lnk" "$INSTDIR\RepertIA.bat" "" "$INSTDIR\repertia.ico"
  CreateShortcut "$SMPROGRAMS\RepertIA\$(LS_LNK_UPDATE).lnk" "$INSTDIR\Aggiorna strumenti.bat" "" "$INSTDIR\repertia.ico"
  CreateShortcut "$SMPROGRAMS\RepertIA\$(LS_LNK_README).lnk" "$INSTDIR\$(LS_README_FILE)"
  CreateShortcut "$SMPROGRAMS\RepertIA\$(LS_LNK_TEST).lnk" "$INSTDIR\Collaudo.bat" "" "$INSTDIR\repertia.ico"
  CreateShortcut "$SMPROGRAMS\RepertIA\$(LS_LNK_CASES).lnk" "$PROFILE\CasiForensi"
  CreateShortcut "$SMPROGRAMS\RepertIA\$(LS_LNK_UNINST).lnk" "$INSTDIR\Disinstalla.exe"
  CreateDirectory "$PROFILE\CasiForensi"
  !define UNKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\RepertIA"
  WriteRegStr HKCU "${UNKEY}" "DisplayName" "RepertIA"
  WriteRegStr HKCU "${UNKEY}" "DisplayVersion" "${VER}"
  WriteRegStr HKCU "${UNKEY}" "Publisher" "silvexe"
  WriteRegStr HKCU "${UNKEY}" "DisplayIcon" "$INSTDIR\repertia.ico"
  WriteRegStr HKCU "${UNKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNKEY}" "UninstallString" '"$INSTDIR\Disinstalla.exe"'
  WriteRegDWORD HKCU "${UNKEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNKEY}" "NoRepair" 1
SectionEnd

Section "$(LS_SEC_DESK)" SecDesk
  CreateShortcut "$DESKTOP\RepertIA.lnk" "$INSTDIR\RepertIA.bat" "" "$INSTDIR\repertia.ico"
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "$(LS_DESC_MAIN)"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesk} "$(LS_DESC_DESK)"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  RMDir /r "$INSTDIR\RepertIA"
  RMDir /r "$INSTDIR\python"
  RMDir /r "$INSTDIR\strumenti"
  Delete "$INSTDIR\RepertIA.bat"
  Delete "$INSTDIR\Aggiorna strumenti.bat"
  Delete "$INSTDIR\Collaudo.bat"
  Delete "$INSTDIR\LEGGIMI.txt"
  Delete "$INSTDIR\README_EN.txt"
  Delete "$INSTDIR\lingua_predefinita.txt"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\THIRD_PARTY_LICENSES.md"
  Delete "$INSTDIR\VALIDAZIONE.md"
  Delete "$INSTDIR\repertia.ico"
  Delete "$INSTDIR\Disinstalla.exe"
  RMDir "$INSTDIR"
  RMDir /r "$SMPROGRAMS\RepertIA"
  Delete "$DESKTOP\RepertIA.lnk"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RepertIA"
  DeleteRegKey HKCU "Software\RepertIA"
  ; i casi (CasiForensi) e le impostazioni restano
SectionEnd
