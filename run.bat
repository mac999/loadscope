@echo off
setlocal

rem LoadScope launcher.
rem Usage: run.bat [port]   (default port 7878)
rem ASCII only: cmd.exe reads .bat files in the OEM code page.

set "PORT=%~1"
if "%PORT%"=="" set "PORT=7878"

set "ROOT=%~dp0"
set "EXE=%ROOT%target\release\loadscope.exe"

rem The gnu toolchain here needs dlltool on PATH to build some crates.
set "SELF_CONTAINED=%USERPROFILE%\.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained"
if exist "%SELF_CONTAINED%" set "PATH=%PATH%;%SELF_CONTAINED%"

if not exist "%EXE%" (
    echo [*] Binary not found, building...
    pushd "%ROOT%"
    cargo build --release
    popd
)

if not exist "%EXE%" (
    echo [x] Build failed.
    exit /b 1
)

echo [*] Serving on http://127.0.0.1:%PORT%
start "" "http://127.0.0.1:%PORT%/"
"%EXE%" %PORT%

endlocal
