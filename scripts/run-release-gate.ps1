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
        Invoke-Checked { npm run test:e2e } "Browser security journeys"
        Invoke-Checked { npm run test:a11y } "Desktop and mobile accessibility journeys"
        Invoke-Checked { npm audit --omit=dev --audit-level=high } "Frontend production dependency audit"
        Invoke-Checked { npm audit --audit-level=high } "Frontend complete dependency audit"
    } finally { Pop-Location }

    $PostgresProject = "netra-release-postgres"
    $PreviousDatabaseUrl = $env:DATABASE_URL
    $PreviousPostgresFlag = $env:NETRA_TEST_POSTGRES
    $PreviousDatabaseTls = $env:NETRA_DATABASE_SSL_REQUIRED
    $PreviousPostgresPort = $env:NETRA_TEST_POSTGRES_PORT
    try {
        $PortReservation = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $PortReservation.Start()
        $ReleasePostgresPort = ([Net.IPEndPoint]$PortReservation.LocalEndpoint).Port
        $PortReservation.Stop()
        $env:NETRA_TEST_POSTGRES_PORT = [string]$ReleasePostgresPort
        Invoke-Checked { docker compose -p $PostgresProject -f docker-compose.test-postgres.yml up -d --wait } "Disposable PostgreSQL 17 startup"
        $env:DATABASE_URL = "postgresql://netra_test:netra_test_local_only@127.0.0.1:$ReleasePostgresPort/netra_test"
        $env:NETRA_TEST_POSTGRES = "1"
        $env:NETRA_DATABASE_SSL_REQUIRED = "0"
        $env:PYTHONPATH = Join-Path $RepositoryRoot "ml-services\anomaly-engine"
        Push-Location backend
        try {
            Invoke-Checked {
                python manage.py test `
                    apps.forensics.tests.test_postgres_concurrency `
                    apps.forensics.tests.test_custody_concurrency `
                    apps.forensics.tests.test_admin_invariants `
                    apps.forensics.tests.test_user_provisioning `
                    apps.forensics.tests.test_integration_delivery `
                    apps.forensics.tests.test_jwt_verification
            } "PostgreSQL-backed security invariants"
        } finally { Pop-Location }
    } finally {
        $env:DATABASE_URL = $PreviousDatabaseUrl
        $env:NETRA_TEST_POSTGRES = $PreviousPostgresFlag
        $env:NETRA_DATABASE_SSL_REQUIRED = $PreviousDatabaseTls
        $env:NETRA_TEST_POSTGRES_PORT = $PreviousPostgresPort
        $env:PYTHONPATH = $PreviousPythonPath
        docker compose -p $PostgresProject -f docker-compose.test-postgres.yml down --volumes | Out-Null
    }

    # These locks are compiled for the Linux/Python 3.13 production runtime.
    # Audit the committed, hashed graph directly so the Windows release host
    # cannot introduce platform-only dependencies while resolving it.
    Invoke-Checked { python -m pip_audit --disable-pip --require-hashes -r backend/requirements.api.txt } "API dependency audit"
    Invoke-Checked { python -m pip_audit --disable-pip --require-hashes -r backend/requirements.worker.txt } "Worker dependency audit"
    Invoke-Checked { python -m pip_audit --disable-pip --require-hashes -r sensor-agent/requirements.txt } "Sensor dependency audit"

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
        Invoke-Checked {
            docker run --rm -v "${RepositoryRoot}:/workspace" -w /workspace `
                python:3.13-slim-bookworm@sha256:de89ed8283721548f7f9c8acfd19d638f435fa3870693a017890e94be5d37fc6 `
                sh -c "python -m pip install --disable-pip-version-check --require-hashes --only-binary=:all: -r backend/requirements.dev.txt >/dev/null && bandit -q -c pyproject.toml -r backend && semgrep --config .semgrep.yml --error"
        } "Bandit and Semgrep"
        Invoke-Checked {
            & (Join-Path $RepositoryRoot "scripts\container_security.ps1") `
                -Images @("netra-api:release", "netra-worker:release", "netra-frontend:release") `
                -OutputDirectory "artifacts/sbom"
        } "SBOM and fixable high/critical image scans"
    }

    Write-Host "All local release gates passed for $(git rev-parse HEAD)."
} finally {
    Pop-Location
}
