@echo off
REM BlueCLI launcher for Windows.
REM
REM Auto-elevates to Administrator on first launch. WireGuard tunnel
REM management requires Admin privileges; the V2Ray full-tunnel does too
REM (it touches the routing table). We elevate uniformly so the user is
REM prompted once at startup instead of mid-session.

setlocal
cd /d "%~dp0"

REM --- 1. Elevate if not already Administrator. ------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 goto need_admin
goto check_python

:need_admin
echo Requesting Administrator privileges...
powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0' -WorkingDirectory '%~dp0'"
exit /b 0

:check_python
set "BLUECLI_HOME=%CD%"
where python >nul 2>&1
if %errorlevel% neq 0 goto need_python
goto ensure_venv

:need_python
echo Error: Python is not installed or not on PATH.
echo Install Python 3.10-3.14 from https://www.python.org/downloads/ and tick "Add Python to PATH".
pause
exit /b 1

:ensure_venv
if exist "venv\Scripts\python.exe" goto run
echo First-time setup: creating a local virtual environment...
python -m venv venv
if %errorlevel% neq 0 goto venv_fail
"venv\Scripts\pip.exe" install --upgrade pip >nul
REM Pre-install the bundled shim wheels (safe-pysha3 and ed25519-blake2b).
REM These satisfy two transitive deps of sentinel-sdk that otherwise ship
REM as C-extension sources only — pip would invoke MSVC to compile them,
REM which most users don't have. Installing the shims first makes pip
REM consider those deps already met when it processes the main package.
"venv\Scripts\pip.exe" install --quiet --no-deps wheels\safe_pysha3-1.0.5-py3-none-any.whl wheels\ed25519_blake2b-1.4.1-py3-none-any.whl wheels\coincurve-18.0.0-py3-none-any.whl
if %errorlevel% neq 0 goto pip_fail
"venv\Scripts\pip.exe" install --quiet .
if %errorlevel% neq 0 goto pip_fail
REM Force bip-utils onto its pure-Python ecdsa secp256k1 backend. The
REM coincurve shim above satisfies pip without compiling the real
REM coincurve C extension (no wheel for Python 3.13+ in the pinned
REM range; source builds need a C toolchain most users lack). ecdsa
REM derives byte-identical keys/addresses.
"venv\Scripts\python.exe" -c "import pathlib; [p.write_text(p.read_text().replace('USE_COINCURVE: bool = True', 'USE_COINCURVE: bool = False')) for p in pathlib.Path('venv').rglob('bip_utils/ecc/conf.py')]"
if exist "build" rmdir /s /q "build"
if exist "src\bluecli.egg-info" rmdir /s /q "src\bluecli.egg-info"
echo Setup complete.
goto run

:venv_fail
echo Failed to create the virtual environment.
pause
exit /b 1

:pip_fail
echo Failed to install BlueCLI dependencies.
pause
exit /b 1

:run
"venv\Scripts\python.exe" -m bluecli %*
endlocal
