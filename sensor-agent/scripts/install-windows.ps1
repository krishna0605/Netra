$ErrorActionPreference = "Stop"
$SensorRoot = Split-Path -Parent $PSScriptRoot
$Venv = Join-Path $SensorRoot ".venv"

if (-not (Test-Path $Venv)) {
    py -3 -m venv $Venv
}

& (Join-Path $Venv "Scripts\python.exe") -m pip install --require-hashes --only-binary=:all: -r (Join-Path $SensorRoot "requirements.txt")

Write-Host "Netra sensor installed."
Write-Host "Run: npm run netra:sensor:check"
