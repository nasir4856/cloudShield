param([int]$Port = 5000)
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

if (Test-Path ".venv\Scripts\python.exe") {
    $python = ".venv\Scripts\python.exe"
}
elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $python = "python"
}
else {
    Write-Error "Python was not found. Install Python and retry."
    exit 1
}

if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env" -Force
    }
    else {
        Set-Content -Path ".env" -Value "SECRET_KEY=replace-with-a-long-random-secret"
    }
}

& $python .\failsafe_start.py
