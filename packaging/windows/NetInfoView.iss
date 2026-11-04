; Inno Setup script for the Windows installer. build_windows.ps1 runs it after
; PyInstaller has produced dist\NetInfoView\, passing the version:
;   ISCC.exe /DAppVersion=1.4 packaging\windows\NetInfoView.iss
; Installs per user (no administrator rights), so the app can update itself:
; it runs a newer installer with /SILENT, which closes the app, installs over
; it, and starts it again (the WizardSilent [Run] entry below).

#ifndef AppVersion
  #define AppVersion "0.0"
#endif

[Setup]
AppId={{E3B1448B-724E-4F22-9A9E-604BC216405D}
AppName=NetInfoView
AppVersion={#AppVersion}
AppVerName=NetInfoView {#AppVersion}
AppPublisher=bugegg
AppPublisherURL=https://github.com/bugegg/NetInfo
AppUpdatesURL=https://github.com/bugegg/NetInfo/releases
DefaultDirName={localappdata}\Programs\NetInfoView
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\..\dist
OutputBaseFilename=NetInfoView-{#AppVersion}-windows-x64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\NetInfoView.exe
UninstallDisplayName=NetInfoView
CloseApplications=yes
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
; An update must not leave the previous version's libraries behind.
Type: filesandordirs; Name: "{app}\_internal"
; Up to 1.4 the app was called NetInfo: drop its exe and shortcuts.
Type: files; Name: "{app}\NetInfo.exe"
Type: files; Name: "{autoprograms}\NetInfo.lnk"
Type: files; Name: "{autodesktop}\NetInfo.lnk"

[Files]
Source: "..\..\dist\NetInfoView\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\NetInfoView"; Filename: "{app}\NetInfoView.exe"
Name: "{autodesktop}\NetInfoView"; Filename: "{app}\NetInfoView.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\NetInfoView.exe"; Description: "{cm:LaunchProgram,NetInfoView}"; Flags: nowait postinstall skipifsilent
; A silent install is the app updating itself: start the new version.
Filename: "{app}\NetInfoView.exe"; Flags: nowait; Check: WizardSilent
