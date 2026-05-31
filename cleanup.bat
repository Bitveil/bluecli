@echo off
REM Removes everything BlueCLI ever wrote to disk:
REM   - data\   the wallet, config, and connection state
REM   - venv\   the Python virtual environment created on first launch
REM
REM After running this script, the folder is back to the way it was right
REM after you unzipped it. To uninstall BlueCLI completely, also delete the
REM folder this script lives in.

setlocal
cd /d "%~dp0"

set "removed=0"
for %%T in (data venv build) do (
    if exist "%%T" (
        rmdir /s /q "%%T"
        echo   removed: %%T\
        set "removed=1"
    )
)
if exist "src\bluecli.egg-info" (
    rmdir /s /q "src\bluecli.egg-info"
    echo   removed: src\bluecli.egg-info\
    set "removed=1"
)

if "%removed%"=="0" (
    echo Nothing to clean up.
) else (
    echo Done. To uninstall BlueCLI completely, delete this folder.
)
endlocal
