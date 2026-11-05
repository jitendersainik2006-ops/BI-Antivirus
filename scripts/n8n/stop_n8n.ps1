# BI Antivirus - Stop Genuine n8n Community Edition

$pidFile = "D:\bit defender\data\n8n\n8n.pid"
$stopped = $false

# 1. Stop by PID file if present
if (Test-Path $pidFile) {
    $procId = (Get-Content $pidFile).Trim()
    if ($procId) {
        try {
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
            Write-Host "[*] Stopped n8n process PID $procId"
            $stopped = $true
        } catch {}
    }
    Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
}

# 2. Stop any process listening on port 5679 or 5680
$conns = Get-NetTCPConnection -LocalPort 5679, 5680 -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Listen" }
foreach ($c in $conns) {
    try {
        Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
        Write-Host "[*] Stopped process on port $($c.LocalPort) (PID $($c.OwningProcess))"
        $stopped = $true
    } catch {}
}

if (-not $stopped) {
    Write-Host "[*] No active n8n instance found on port 5679."
} else {
    Write-Host "[*] n8n shutdown complete."
}
