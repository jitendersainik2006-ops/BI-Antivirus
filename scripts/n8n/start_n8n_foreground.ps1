# Foreground / Daemon launcher for n8n Community Edition
$ErrorActionPreference = "Stop"

$configFile = "D:\bit defender\config\n8n\n8n.env"
if (Test-Path $configFile) {
    Get-Content $configFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line -match "^([^=]+)=(.*)$") {
            [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), "Process")
        }
    }
}

$nodeExe = "D:\Program Files\nodejs\node.exe"
$n8nBin = "D:\bit defender\n8n\node_modules\n8n\bin\n8n"

& $nodeExe $n8nBin start
