$configFile = "D:\bit defender\config\n8n\n8n.env"
if (Test-Path $configFile) {
    Get-Content $configFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line -match "^([^=]+)=(.*)$") {
            $k = $matches[1].Trim()
            $v = $matches[2].Trim()
            [Environment]::SetEnvironmentVariable($k, $v, "Process")
            Write-Host "ENV: $k = $v"
        }
    }
}

$nodeExe = "D:\Program Files\nodejs\node.exe"
$n8nBin = "D:\bit defender\n8n\node_modules\n8n\bin\n8n"

Write-Host "Running n8n version..."
& $nodeExe $n8nBin --version

Write-Host "Running n8n start --help..."
& $nodeExe $n8nBin start --help
