# BI Antivirus - Import Demonstration Workflow into Genuine n8n Community Edition
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
$workflowFile = "D:\bit defender\bi_antivirus_health_monitor.json"

Write-Host "[*] Importing workflow from: $workflowFile"
& $nodeExe $n8nBin import:workflow --input="$workflowFile"
