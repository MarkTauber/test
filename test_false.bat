@echo off
title [SearchEngine]
setlocal enabledelayedexpansion
chcp 65001 >nul

echo Проверка прав доступа к файлам процессов
for /f "tokens=2 delims==" %%x in ('wmic process list full ^| find /i "executablepath" ^| find /i /v "system32" ^| find ":"') do (
    for /f eol^=^"^ delims^=^" %%z in ('echo.%%x') do (
        echo. %%z 
        icacls "%%z" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%"
        
    )
)
for /f "tokens=2 delims==" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
    for /f "tokens=* delims=" %%y in ('echo.%%x') do (
        echo %%~dpy
        icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" 
    )
)
