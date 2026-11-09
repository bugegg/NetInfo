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

# PuTTY's plink: SSH and Telnet from the right-click menu (MIT licence,
# shipped beside it). Pinned, and checked against the SHA-256 in PuTTY's own
# https://the.earth.li/~sgtatham/putty/<version>/sha256sums.
$plinkVersion = "0.85"
$plinkSha256 = "969f36879d5716aa1a9811f43a6a6510e8f08372dbeb9695b810b9c776f39c75"
New-Item -ItemType Directory -Force build\putty | Out-Null
Invoke-WebRequest "https://the.earth.li/~sgtatham/putty/$plinkVersion/w64/plink.exe" `
    -OutFile build\putty\plink.exe
$plinkHash = (Get-FileHash build\putty\plink.exe -Algorithm SHA256).Hash
if ($plinkHash -ne $plinkSha256) { throw "plink.exe checksum mismatch: $plinkHash" }
Copy-Item packaging\windows\PuTTY-LICENCE.txt build\putty\

# A ready-made MAC vendor database, so a fresh install has vendor names
# without going online. Optional: without it, Options > Update
# MAC Vendor Database still fetches one.
$vendorData = @()
.venv\Scripts\python packaging\make_vendor_db.py build\vendor\vendor.sqlite
if ($LASTEXITCODE -eq 0) { $vendorData = @("--add-data", "build\vendor;NetInfoView\data") }
$global:LASTEXITCODE = 0

# Pillow lets PyInstaller turn the macOS .icns into the .exe's icon.
.venv\Scripts\pyinstaller `
    --noconfirm `
    --windowed `
    --paths . `
    --name NetInfoView `
    --icon NetInfoView.app\Contents\Resources\AppIcon.icns `
    --exclude-module tkinter `
    --exclude-module pytest `
    --add-data "NetInfoView\fonts;NetInfoView\fonts" `
    --add-data "NetInfoView\flags;NetInfoView\flags" `
    --add-data "build\putty;NetInfoView\putty" `
    @vendorData `
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
