# Start PhishGuard locally (Windows PowerShell).
#   .\run.ps1            -> http://127.0.0.1:8000  (web UI at /ui, API docs at /docs)
#   .\run.ps1 -Port 9000
#   .\run.ps1 -Lan       -> also reachable from your phone on the same Wi-Fi
#                           (for the PhishGuard Shield Android app in mobile/android)
param([int]$Port = 8000, [switch]$Lan)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path .\.venv\Scripts\python.exe)) {
    Write-Host "Creating virtual environment..."
    python -m venv .venv
}
& .\.venv\Scripts\python.exe -c "import fastapi, uvicorn, numpy" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing dependencies..."
    & .\.venv\Scripts\python.exe -m pip install --disable-pip-version-check -e ".[dev]"
}

$bindHost = "127.0.0.1"
Write-Host ""
Write-Host "  Web UI : http://127.0.0.1:$Port/ui/"
Write-Host "  API    : http://127.0.0.1:$Port/docs"
if ($Lan) {
    $bindHost = "0.0.0.0"
    $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" -and $_.PrefixOrigin -ne "WellKnown" } |
        Select-Object -ExpandProperty IPAddress
    foreach ($ip in $ips) { Write-Host "  Phone  : http://${ip}:$Port   (enter this in the app's server field)" }
    if (-not $env:PG_API_KEYS) {
        Write-Host "  WARNING: anyone on this network can use the API. Set an API key first, e.g." -ForegroundColor Yellow
        Write-Host "           `$env:PG_API_KEYS = 'choose-a-long-secret'; .\run.ps1 -Lan" -ForegroundColor Yellow
    }
    Write-Host "  If the phone can't connect, allow Python through Windows Firewall (Private networks)."
}
Write-Host "  Stop   : Ctrl+C"
Write-Host ""
$env:PG_LOG_JSON = "false"
& .\.venv\Scripts\python.exe -m uvicorn phishguard.api.main:app --host $bindHost --port $Port --no-server-header
