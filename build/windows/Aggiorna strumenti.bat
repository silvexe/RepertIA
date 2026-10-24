@echo off
rem SPDX-License-Identifier: GPL-3.0-or-later
rem Copyright (C) 2026 silvexe
chcp 65001 >nul
title RepertIA - Aggiornamento strumenti
cd /d "%~dp0"
set __COMPAT_LAYER=RunAsInvoker
set PATH=%~dp0strumenti\sleuthkit\bin;%~dp0strumenti\exiftool;%~dp0strumenti\poppler\Library\bin;%~dp0strumenti\testdisk;%~dp0strumenti\bulk_extractor;%PATH%
echo == RepertIA - Strumenti inclusi ==
echo plaso, Sleuth Kit, exiftool, Poppler, PhotoRec e bulk_extractor sono inclusi in RepertIA:
echo si aggiornano installando una nuova versione di RepertIA. Non serve internet ne' Docker.
echo.
echo Versioni incluse:
for /f "delims=" %%v in ('fls -V 2^>nul') do echo   Sleuth Kit:     %%v
for /f "delims=" %%v in ('exiftool -ver 2^>nul') do echo   exiftool:       %%v
for /f "delims=" %%v in ('pdftotext -v 2^>^&1 ^| findstr /b pdftotext') do echo   Poppler:        %%v
for /f "delims=" %%v in ('photorec /version 2^>nul ^| findstr /b Version') do echo   PhotoRec:       %%v
for /f "delims=" %%v in ('bulk_extractor -V 2^>nul') do echo   %%v
<nul set /p "=  plaso:          "
"%~dp0python\python.exe" -m plaso.scripts.log2timeline --version 2>&1
echo.
pause
