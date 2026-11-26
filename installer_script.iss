; BI Antivirus Enterprise - Windows Professional Setup Script
; Inno Setup 6 Script
; Black Intel Cyber Defense Platform

#define MyAppName "BI Antivirus Enterprise"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Black Intel Cyber Defense Platform"
#define MyAppURL "https://github.com/jitendersainik2006-ops/BI-Antivirus"
#define MyAppExeName "Launch_BIAntivirus.vbs"
#define SourceDir "D:\bit defender"

[Setup]
; Unique application GUID
AppId={{C27E4B25-F79B-4B7C-A5D8-31688B7F5389}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\Black Intel\BI Antivirus
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir={#SourceDir}\releases\Windows\Installer
OutputBaseFilename=BI_Antivirus_Enterprise_v1.0.0_Setup
SetupIconFile={#SourceDir}\bi_antivirus\resources\bi_antivirus.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
WizardSizePercent=100
DisableWelcomePage=no
DisableDirPage=no
DisableProgramGroupPage=no
DisableReadyPage=no
DisableFinishedPage=no
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
UninstallDisplayIcon={app}\bi_antivirus.ico
VersionInfoVersion=1.0.0.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=BI Antivirus Enterprise Endpoint Protection
VersionInfoCopyright=Copyright (C) 2026 Black Intel Cyber Defense
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion=1.0.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce
Name: "quickscan"; Description: "Execute initial baseline scan upon first launch"; GroupDescription: "First-Run Optimization:"; Flags: checkedonce

[Files]
; Core Launchers & Entrypoints
Source: "{#SourceDir}\main.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\Launch_BIAntivirus.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\Launch_BIAntivirus.vbs"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\run_gui.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\run_demo.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\requirements.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\bi_antivirus\resources\bi_antivirus.ico"; DestDir: "{app}"; Flags: ignoreversion

; Core Python Modules (recursive, excluding bytecode and pycache)
Source: "{#SourceDir}\bi_antivirus\*"; DestDir: "{app}\bi_antivirus"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "*.pyc,__pycache__,*.log"

; Documentation & Shared Standards
Source: "{#SourceDir}\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\shared\*"; DestDir: "{app}\shared"; Flags: ignoreversion recursesubdirs createallsubdirs

; Baseline Data directories (signatures, certs, empty structure)
Source: "{#SourceDir}\data\settings.json"; DestDir: "{app}\data"; Flags: ignoreversion onlyifdoesntexist
Source: "{#SourceDir}\data\signatures.db"; DestDir: "{app}\data"; Flags: ignoreversion onlyifdoesntexist

[Dirs]
Name: "{app}\data\quarantine"; Flags: uninsneveruninstall
Name: "{app}\data\backups"; Flags: uninsneveruninstall
Name: "{app}\data\logs"

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "wscript.exe"; Parameters: """{app}\Launch_BIAntivirus.vbs"""; WorkingDir: "{app}"; IconFilename: "{app}\bi_antivirus.ico"; Comment: "Launch BI Antivirus Enterprise"
Name: "{group}\BI Antivirus (Safe Mode Console)"; Filename: "{app}\Launch_BIAntivirus.bat"; WorkingDir: "{app}"; IconFilename: "{app}\bi_antivirus.ico"; Comment: "Launch BI Antivirus with diagnostic console"
Name: "{group}\Documentation & Setup Guide"; Filename: "{app}\docs\WINDOWS_SETUP.md"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"; IconFilename: "{app}\bi_antivirus.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "wscript.exe"; Parameters: """{app}\Launch_BIAntivirus.vbs"""; WorkingDir: "{app}"; IconFilename: "{app}\bi_antivirus.ico"; Tasks: desktopicon; Comment: "Launch BI Antivirus Enterprise"

[Run]
Filename: "wscript.exe"; Parameters: """{app}\Launch_BIAntivirus.vbs"""; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: postinstall nowait skipifsilent

[UninstallDelete]
Type: files; Name: "{app}\*.pyc"
Type: files; Name: "{app}\data\logs\*.log"
Type: files; Name: "{app}\data\cache\*"
Type: dirifempty; Name: "{app}\data\logs"
Type: dirifempty; Name: "{app}\data\cache"

[Code]
// Pascal Script for Prerequisite Checking and Safe Quarantine Retention

function IsPythonInstalled(): Boolean;
var
  ResultCode: Integer;
begin
  // Check if python or pythonw responds on system
  Result := Exec('cmd.exe', '/c where pythonw >nul 2>&1 || where python >nul 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
  if not Result then
  begin
    // Check local appdata path
    Result := FileExists(ExpandConstant('{localappdata}\Programs\Python\Python312\pythonw.exe')) or
              FileExists(ExpandConstant('{localappdata}\Programs\Python\Python311\pythonw.exe')) or
              FileExists(ExpandConstant('{localappdata}\Programs\Python\Python310\pythonw.exe'));
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsPythonInstalled() then
  begin
    if MsgBox('Python 3.10+ was not detected in your system PATH.' + #13#10 + #13#10 +
              'BI Antivirus can finish installation now, but requires Python 3.10 or higher to run.' + #13#10 +
              'Would you like to continue with the installation?' + #13#10#13#10 +
              '(You can easily install Python later by running "winget install Python.Python.3.12")',
              mbConfirmation, MB_YESNO) = IDNO then
    begin
      Result := False;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  QuarantineDir: String;
  Preserve: Boolean;
begin
  if CurUninstallStep = usUninstall then
  begin
    QuarantineDir := ExpandConstant('{app}\data\quarantine');
    if DirExists(QuarantineDir) then
    begin
      Preserve := True;
      if not UninstallSilent then
      begin
        Preserve := (MsgBox('Do you want to retain your encrypted Quarantine Vault and threat history?' + #13#10#13#10 +
                            'Choosing "Yes" keeps quarantined files safely locked in your application folder ' +
                            'in case you reinstall in the future.' + #13#10#13#10 +
                            '(Recommended: Yes)', mbConfirmation, MB_YESNO) = IDYES);
      end;
      if Preserve then
      begin
        Log('Preserving quarantine directory as requested: ' + QuarantineDir);
      end
      else
      begin
        DelTree(QuarantineDir, True, True, True);
        Log('Purged quarantine directory per user request.');
      end;
    end;
  end;
end;
