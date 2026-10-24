@echo off
rem SPDX-License-Identifier: GPL-3.0-or-later
rem Copyright (C) 2026 silvexe
chcp 65001 >nul
title RepertIA - By silvexe
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
set PYTHONDONTWRITEBYTECODE=1
echo == RepertIA - By silvexe ==
echo Analisi forense con IA locale: i dati restano su questo computer.
echo Lascia aperta questa finestra mentre usi RepertIA; chiudila per uscire.
echo.
"%~dp0python\python.exe" "%~dp0RepertIA\forense_gui.py"
if errorlevel 1 pause
