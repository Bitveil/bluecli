@echo off
REM Build the Windows release archive.
REM
REM Produces bluecli-<VERSION>-windows-x64.zip in the project root.
REM Contents: source tree + shim wheels + Windows-flavor bundled binaries.
REM End user needs Python 3.10+ on PATH; the launcher handles venv on first run.

SETLOCAL EnableDelayedExpansion

CD /D "%~dp0.."

REM --- Read version from __init__.py (single source of truth) -------------
FOR /F "tokens=2 delims==" %%A IN ('findstr "__version__" src\bluecli\__init__.py') DO (
    SET "VERSION=%%~A"
)
SET "VERSION=!VERSION:"=!"
SET "VERSION=!VERSION: =!"
IF "!VERSION!"=="" (
    echo ERROR: could not read __version__ from src\bluecli\__init__.py
    EXIT /B 1
)
echo Building BlueCLI v!VERSION! (Windows x86-64)

SET "PKG=bluecli-windows-x64"
IF EXIST "%PKG%" rmdir /s /q "%PKG%"
mkdir "%PKG%"

REM --- Source tree + launcher ---------------------------------------------
xcopy /e /q /y src             "%PKG%\src\"             >nul
xcopy /e /q /y wheels          "%PKG%\wheels\"          >nul
xcopy /e /q /y wheelhouse_src  "%PKG%\wheelhouse_src\"  >nul
copy /y pyproject.toml "%PKG%\" >nul
copy /y bluecli.bat    "%PKG%\" >nul
copy /y cleanup.bat    "%PKG%\" >nul

REM --- Bundled binaries — Windows only ------------------------------------
mkdir "%PKG%\bin\wireguard"
copy /y bin\wireguard\wireguard.exe "%PKG%\bin\wireguard\" >nul

mkdir "%PKG%\bin\v2ray"
copy /y bin\v2ray\v2ray.exe     "%PKG%\bin\v2ray\" >nul
copy /y bin\v2ray\tun2socks.exe "%PKG%\bin\v2ray\" >nul
copy /y bin\v2ray\wintun.dll    "%PKG%\bin\v2ray\" >nul
copy /y bin\v2ray\geoip.dat     "%PKG%\bin\v2ray\" >nul
copy /y bin\v2ray\geosite.dat   "%PKG%\bin\v2ray\" >nul

REM --- README -------------------------------------------------------------
(
echo BlueCLI v!VERSION!  --  Sentinel dVPN client
echo =============================================
echo.
echo Requirements
echo ------------
echo   - Python 3.10 or newer ^(install from https://www.python.org/^,
echo     tick "Add Python to PATH" during setup^)
echo   - Administrator rights ^(the launcher requests them automatically^)
echo   - That's it. WireGuard, v2ray, tun2socks and wintun are bundled.
echo.
echo Quick start
echo -----------
echo   Double-click bluecli.bat
echo.
echo On first run the launcher sets up a local Python virtual environment
echo inside the unzipped folder ^(takes ~60 seconds, only once^). After that,
echo launches are instant.
echo.
echo To remove everything
echo --------------------
echo   Double-click cleanup.bat ^(wipes the venv and your wallet/sessions data^)
echo   Then delete this folder.
echo.
echo For source, documentation, and issues:
echo   https://github.com/YOUR-ORG/bluecli
) > "%PKG%\README.txt"

REM --- Zip ----------------------------------------------------------------
SET "ARCHIVE=bluecli-!VERSION!-windows-x64.zip"
IF EXIST "!ARCHIVE!" del "!ARCHIVE!"
echo === Creating !ARCHIVE! ===
powershell -NoProfile -Command "Compress-Archive -Path '%PKG%' -DestinationPath '!ARCHIVE!' -Force"

echo === SHA256 ===
certutil -hashfile "!ARCHIVE!" SHA256 | findstr /v "hash" > "!ARCHIVE!.sha256"
type "!ARCHIVE!.sha256"

echo.
echo Output: !ARCHIVE!
echo Cleanup intermediate dir:  rmdir /s /q %PKG%

ENDLOCAL
