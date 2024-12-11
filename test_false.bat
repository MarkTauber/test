@echo off
title [SearchEngine]
setlocal enabledelayedexpansion
chcp 65001 >nul

echo Проверка прав доступа к файлам процессов
for /f "tokens=2 delims==" %%x in ('wmic process list full ^| find /i "executablepath" ^| find /i /v "system32" ^| find ":"') do (
    for /f eol^=^"^ delims^=^" %%z in ('echo.%%x') do (
        icacls "%%z" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%"
        if %ERRORLEVEL% EQU 0 echo. %%z >> "./Процессы_кратк".txt 
    )
)
for /f "tokens=2 delims==" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
    for /f "tokens=* delims=" %%y in ('echo.%%x') do (
        icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" 
        if %errorlevel% EQU 0  echo %%~dpy >> "./Процессы2_кратк".txt 
    )
)