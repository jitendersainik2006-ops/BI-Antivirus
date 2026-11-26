import os
import sys
import time
import subprocess
from pathlib import Path

# Desktop shortcut paths
user_desktop_onedrive = Path(os.path.expanduser(r"~\OneDrive\Desktop\BI Antivirus Enterprise.lnk"))
user_desktop_local = Path(os.path.expanduser(r"~\Desktop\BI Antivirus Enterprise.lnk"))

target_lnk = user_desktop_onedrive if user_desktop_onedrive.exists() else user_desktop_local
print(f"Target Desktop Shortcut: {target_lnk}")
assert target_lnk.exists(), f"Shortcut does not exist at {target_lnk}"

# Check shortcut properties via PowerShell
ps_script = f"""
$sh = New-Object -ComObject WScript.Shell
$lnk = $sh.CreateShortcut('{target_lnk}')
Write-Host "TARGET:" $lnk.TargetPath
Write-Host "ARGS:" $lnk.Arguments
Write-Host "WORKDIR:" $lnk.WorkingDirectory
Write-Host "ICON:" $lnk.IconLocation
Write-Host "DESC:" $lnk.Description
"""
out = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps_script], text=True)
print("\nShortcut Metadata:")
print(out)

# Verify icon exists
lines = out.strip().splitlines()
icon_loc = next((l.split("ICON:")[1].strip() for l in lines if "ICON:" in l), "")
icon_path = icon_loc.split(",")[0]
print(f"Icon Path: {icon_path}")
assert os.path.exists(icon_path), f"Icon path does not exist: {icon_path}"

# Launch application via shortcut
print("\nLaunching application from Desktop shortcut...")
subprocess.Popen(["powershell", "-NoProfile", "-Command", f"Invoke-Item '{target_lnk}'"])

time.sleep(3)

# Check for running pythonw process
ps_check = """
Get-Process -Name "pythonw", "python" -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*Python*" } | Select-Object Id, ProcessName, Path
"""
procs = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps_check], text=True)
print("\nDetected Running Processes:")
print(procs)

# Clean up launched process
subprocess.run(["powershell", "-NoProfile", "-Command", "Get-Process -Name 'pythonw' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue"])
print("Test completed successfully!")
