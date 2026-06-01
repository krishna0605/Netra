param(
    [Parameter(Position = 0)]
    [ValidateSet("check", "interfaces", "run")]
    [string]$Command = "run"
)

$ErrorActionPreference = "Stop"
$SensorRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $SensorRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    throw "Sensor virtual environment missing. Run .\sensor-agent\scripts\install-windows.ps1 first."
}

$env:PYTHONPATH = $SensorRoot
& $Python -m netra_sensor.cli $Command
