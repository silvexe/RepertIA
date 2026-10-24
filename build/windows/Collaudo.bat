@echo off
rem SPDX-License-Identifier: GPL-3.0-or-later
rem Copyright (C) 2026 silvexe
chcp 65001 >nul
title RepertIA - Collaudo
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
set PYTHONDONTWRITEBYTECODE=1
set "DIR="
for %%D in ("%~dp0RepertIA-collaudo" "%USERPROFILE%\Desktop\RepertIA-collaudo" "%USERPROFILE%\Downloads\RepertIA-collaudo") do if not defined DIR if exist "%%~D\atteso.json" set "DIR=%%~D"
if not defined DIR set /p "DIR=Trascina qui la cartella RepertIA-collaudo e premi Invio: "
set "DIR=%DIR:"=%"
echo == Collaudo di RepertIA con le immagini di %DIR% ==
"%~dp0python\python.exe" "%~dp0RepertIA\forense_collaudo.py" "%DIR%"
echo.
echo Il rapporto (collaudo_^<data^>.md) e in %USERPROFILE%\CasiForensi\_collaudo
start "" "%USERPROFILE%\CasiForensi\_collaudo"
pause
