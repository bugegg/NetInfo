# Build dist\NetInfoView\ (PyInstaller, Python and PyQt6 bundled) and the
# installer dist\NetInfoView-<version>-windows-x64-setup.exe. Run on Windows with
# Python 3.14 and Inno Setup 6 installed:
#
#   py -3.14 -m venv .venv
#   .venv\Scripts\pip install -r requirements-lock.txt pillow
#   .\build_windows.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$match = Select-String -Path NetInfoView\__init__.py -Pattern '^__version__ = "(.*)"$'
if (-not $match) { throw "No __version__ in NetInfoView\__init__.py" }
$version = $match.Matches[0].Groups[1].Value

Remove-Item -Recurse -Force build, dist -ErrorAction SilentlyContinue
# Pillow lets PyInstaller turn the macOS .icns into the .exe's icon.
.venv\Scripts\pyinstaller `
    --noconfirm `
    --windowed `
    --paths . `
    --name NetInfoView `
    --icon NetInfoView.app\Contents\Resources\AppIcon.icns `
    --exclude-module tkinter `
    --exclude-module pytest `
    packaging\launch.py
if ($LASTEXITCODE) { throw "PyInstaller failed" }
Remove-Item -Force NetInfoView.spec -ErrorAction SilentlyContinue

$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 (ISCC.exe) not found" }
& $iscc "/DAppVersion=$version" packaging\windows\NetInfoView.iss
if ($LASTEXITCODE) { throw "Inno Setup failed" }
Write-Host "Built dist\NetInfoView-$version-windows-x64-setup.exe"
