#define AppName "Unlimited Download Manager"
#ifndef AppVersion
  #define AppVersion "1.1"
#endif

[Setup]
AppId={{B7C6E3A2-5D1F-4C2B-9E0A-7A1D4F3C8E21}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=UDM
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=installer_output
OutputBaseFilename=UDM-Setup
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
UninstallDisplayIcon={app}\UDM.exe
WizardStyle=modern
SetupIconFile=assets\udm.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"
Name: "startup"; Description: "Start with Windows"; GroupDescription: "Other:"; Flags: unchecked

[Files]
Source: "dist\UDM\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\UDM.exe"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\UDM.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "UnlimitedDownloadManager"; ValueData: """{app}\UDM.exe"" --minimized"; Tasks: startup; Flags: uninsdeletevalue

[Run]
Filename: "{app}\UDM.exe"; Parameters: "--register-native"; Flags: runhidden waituntilterminated
Filename: "{app}\UDM.exe"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\UDM.exe"; Parameters: "--unregister-native"; RunOnceId: "UdmUnregNative"; Flags: runhidden waituntilterminated
