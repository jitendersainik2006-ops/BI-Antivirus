' BI Antivirus Enterprise - Silent Window Launcher
' Black Intel Cyber Defense Platform
Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
strDir = fso.GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = strDir

' Run the launcher batch silently (window style 0 = hidden)
strCmd = Chr(34) & strDir & "\Launch_BIAntivirus.bat" & Chr(34)
WshShell.Run strCmd, 0, False
