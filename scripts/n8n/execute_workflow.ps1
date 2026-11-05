# BI Antivirus - Execute Demonstration Workflow (BI Antivirus Health Monitor)
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

# Separate broker port for CLI runner to avoid colliding with live daemon on 5680
[Environment]::SetEnvironmentVariable("N8N_RUNNERS_BROKER_PORT", "5681", "Process")

$nodeExe = "D:\Program Files\nodejs\node.exe"
$n8nBin = "D:\bit defender\n8n\node_modules\n8n\bin\n8n"
$workflowId = "ZIsNBbDMmjbASuu6"

Write-Host "[*] Executing workflow ID: $workflowId"
& $nodeExe $n8nBin execute --id="$workflowId"
