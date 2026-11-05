# BI Antivirus - Start Genuine n8n Community Edition
# Bound to 127.0.0.1:5679 on D: drive

$ErrorActionPreference = "Stop"
$n8nDir = "D:\bit defender\n8n"
$configFile = "D:\bit defender\config\n8n\n8n.env"
$pidFile = "D:\bit defender\data\n8n\n8n.pid"
$logDir = "D:\bit defender\logs\n8n"

# Ensure directories exist
if (-not (Test-Path "D:\bit defender\data\n8n")) { New-Item -ItemType Directory -Path "D:\bit defender\data\n8n" -Force | Out-Null }
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

# 1. Check if already running on port 5679
$conn = Get-NetTCPConnection -LocalPort 5679 -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Listen" }
if ($conn) {
    Write-Host "[!] n8n is already running on port 5679 (PID: $($conn.OwningProcess))"
    exit 0
}

# 2. Load environment variables from n8n.env
if (Test-Path $configFile) {
    Get-Content $configFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line -match "^([^=]+)=(.*)$") {
            $name = $matches[1].Trim()
            $val = $matches[2].Trim()
            [Environment]::SetEnvironmentVariable($name, $val, "Process")
        }
    }
}

# 3. Locate n8n executable
$nodeExe = "D:\Program Files\nodejs\node.exe"
$n8nBin = "$n8nDir\node_modules\n8n\bin\n8n"

if (-not (Test-Path $n8nBin)) {
    Write-Host "[!] n8n binary not found at $n8nBin"
    exit 1
}

$stdoutLog = "$logDir\n8n_stdout.log"
$stderrLog = "$logDir\n8n_stderr.log"

$foregroundScript = "D:\bit defender\scripts\n8n\start_n8n_foreground.ps1"
$proc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$foregroundScript`"" -WorkingDirectory $n8nDir -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru -WindowStyle Hidden

if ($proc) {
    $proc.Id | Out-File -FilePath $pidFile -Encoding ascii -Force
    Write-Host "[*] Genuine n8n Community Edition started (PID: $($proc.Id))"
    Write-Host "[*] Web Editor URL: http://127.0.0.1:5679"
}
