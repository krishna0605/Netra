param(
    [switch]$SkipContainers
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Invoke-Checked {
    param([scriptblock]$Command, [string]$Label)
    Write-Host "==> $Label"
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$Label failed with exit code $LASTEXITCODE." }
}

Push-Location $RepositoryRoot
try {
    if (git status --porcelain) { throw "The release gate requires a clean working tree." }
    if ((git branch --format="%(refname:short)") -ne "main") { throw "Only the local main branch may exist." }

    Push-Location backend
    try {
        $PreviousPythonPath = $env:PYTHONPATH
        $PreviousExecutablePath = $env:PATH
        $env:PYTHONPATH = Join-Path $RepositoryRoot "ml-services\anomaly-engine"
        $LocalWireshark = "C:\Program Files\Wireshark"
        if (Test-Path -LiteralPath (Join-Path $LocalWireshark "tshark.exe")) {
            $env:PATH = "$LocalWireshark$([IO.Path]::PathSeparator)$env:PATH"
        }
        Invoke-Checked { python manage.py test apps.forensics.tests } "Django test suite"
        Invoke-Checked { python manage.py makemigrations --check --dry-run } "Django migration drift check"
        Invoke-Checked { python manage.py check } "Django system check"
        Invoke-Checked { python manage.py generate_route_policy_inventory --check } "Route-policy inventory"
    } finally {
        $env:PYTHONPATH = $PreviousPythonPath
        $env:PATH = $PreviousExecutablePath
        Pop-Location
    }

    Push-Location frontend
    try {
        Invoke-Checked { npm ci } "Reproducible frontend install"
        Invoke-Checked { npm test -- --run } "Frontend unit tests"
        Invoke-Checked { npm run lint } "Frontend lint"
        Invoke-Checked { npm run build } "Frontend production build"
        Invoke-Checked { npm run check:bundle } "Frontend bundle budget"
        Invoke-Checked { npm audit --omit=dev --audit-level=high } "Frontend production dependency audit"
        Invoke-Checked { npm audit --audit-level=high } "Frontend complete dependency audit"
    } finally { Pop-Location }

    Invoke-Checked { python scripts/validate_workflows.py } "Workflow policy"
    Invoke-Checked { python scripts/validate_github_governance.py } "GitHub governance policy"
    Invoke-Checked { python scripts/validate_deployment_contract.py } "Hosted deployment contract"
    Invoke-Checked { python scripts/lint_supabase_sql.py } "Supabase SQL lint"
    Invoke-Checked { python scripts/validate_vex.py } "VEX expiry policy"
    Invoke-Checked { git diff --check } "Repository whitespace gate"

    if (-not $SkipContainers) {
        Invoke-Checked { docker build -f backend/Dockerfile -t netra-api:release . } "API image build"
        Invoke-Checked { docker build -f backend/Dockerfile.worker -t netra-worker:release . } "Worker image build"
        Invoke-Checked { docker build -f frontend/Dockerfile -t netra-frontend:release frontend } "Frontend image build"
        Invoke-Checked { docker run --rm --entrypoint sh netra-api:release -c 'test "$(id -u)" != 0; ! command -v tshark; ! command -v zeek; ! command -v tcpdump' } "API runtime isolation"
        Invoke-Checked { docker run --rm --entrypoint sh netra-worker:release -c 'test "$(id -u)" != 0; tshark --version | grep -F 4.6.7; zeek --version | grep -F 8.2.1' } "Worker parser versions"
        Invoke-Checked { docker run --rm --entrypoint sh netra-frontend:release -c 'test "$(id -u)" != 0; nginx -v' } "Frontend non-root runtime"
    }

    Write-Host "All local release gates passed for $(git rev-parse HEAD)."
} finally {
    Pop-Location
}
