$n8nDir = "D:\bit defender\n8n"
$configFile = "D:\bit defender\config\n8n\n8n.env"
$pidFile = "D:\bit defender\data\n8n\n8n.pid"
$logDir = "D:\bit defender\logs\n8n"

if (Test-Path $configFile) {
    Get-Content $configFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line -match "^([^=]+)=(.*)$") {
            [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), "Process")
        }
    }
}

$nodeExe = "D:\Program Files\nodejs\node.exe"
$n8nBin = "$n8nDir\node_modules\n8n\bin\n8n"
$stdoutLog = "$logDir\n8n_stdout.log"
$stderrLog = "$logDir\n8n_stderr.log"

$arg = "`"$n8nBin`" start"
Write-Host "Starting with ArgumentList: $arg"
$proc = Start-Process -FilePath $nodeExe -ArgumentList $arg -WorkingDirectory $n8nDir -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru

Start-Sleep -Seconds 4
$alive = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
if ($alive) {
    Write-Host "Process $proc.Id is ALIVE! CPU: $($alive.CPU), RAM: $($alive.WorkingSet64)"
} else {
    Write-Host "Process exited. Checking logs..."
}
Get-Content $stdoutLog -Tail 15 -ErrorAction SilentlyContinue
Get-Content $stderrLog -Tail 15 -ErrorAction SilentlyContinue
