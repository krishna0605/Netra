param(
    [ValidateSet("PrepareCandidate", "VerifyCandidate", "PublishMain", "DeleteCandidate")]
    [string]$Action = "PrepareCandidate",
    [string]$CandidateTag = "",
    [string]$ExpectedRemoteMainSha = "",
    [string]$BackupDirectory = (Join-Path ([Environment]::GetFolderPath("Desktop")) "Netra-Release-Backups"),
    [switch]$SkipLocalGate
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RequiredChecks = @("ci-policy-gate", "security-policy-gate", "container-policy-gate")

function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $result = & git @Arguments
    if ($LASTEXITCODE -ne 0) { throw "git $($Arguments -join ' ') failed." }
    return $result
}

function Assert-ReleaseWorkspace {
    if ((Invoke-Git rev-parse --abbrev-ref HEAD).Trim() -ne "main") { throw "The release must run from main." }
    if (Invoke-Git status --porcelain) { throw "The release requires a clean working tree." }
    $branches = @(Invoke-Git branch --format="%(refname:short)")
    if ($branches.Count -ne 1 -or $branches[0].Trim() -ne "main") { throw "Only the local main branch may exist." }
    $signature = (Invoke-Git log -1 --format="%G?").Trim()
    if ($signature -ne "G") { throw "HEAD must have a locally verified SSH signature." }
}

function Get-RemoteMainSha {
    $line = @(Invoke-Git ls-remote origin refs/heads/main)
    if ($line.Count -ne 1) { throw "origin/main could not be resolved unambiguously." }
    return ($line[0] -split "`t")[0].Trim()
}

function New-EncryptedBundle {
    New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null
    $stamp = [DateTime]::UtcNow.ToString("yyyyMMdd-HHmmss")
    $plainPath = Join-Path ([IO.Path]::GetTempPath()) "netra-release-$stamp.bundle"
    $encryptedPath = Join-Path $BackupDirectory "netra-release-$stamp.bundle.dpapi"
    try {
        Invoke-Git bundle create $plainPath --all | Out-Null
        $plain = [IO.File]::ReadAllBytes($plainPath)
        $encrypted = [Security.Cryptography.ProtectedData]::Protect(
            $plain,
            [Text.Encoding]::UTF8.GetBytes("Netra release bundle v1"),
            [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        [IO.File]::WriteAllBytes($encryptedPath, $encrypted)
        $roundTrip = [Security.Cryptography.ProtectedData]::Unprotect(
            [IO.File]::ReadAllBytes($encryptedPath),
            [Text.Encoding]::UTF8.GetBytes("Netra release bundle v1"),
            [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        if (-not [Linq.Enumerable]::SequenceEqual[byte]($plain, $roundTrip)) {
            throw "The encrypted bundle failed its round-trip verification."
        }
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $encryptedPath).Hash.ToLowerInvariant()
        Write-Host "Encrypted verified Git bundle: $encryptedPath"
        Write-Host "Encrypted bundle SHA-256: $hash"
    } finally {
        if (Test-Path -LiteralPath $plainPath) { Remove-Item -LiteralPath $plainPath -Force }
    }
}

function Assert-CandidateChecks {
    param([string]$Sha)
    $json = gh api -H "Accept: application/vnd.github+json" "/repos/krishna0605/Netra/commits/$Sha/check-runs?per_page=100"
    if ($LASTEXITCODE -ne 0) { throw "GitHub check-run lookup failed." }
    $runs = @((ConvertFrom-Json $json).check_runs)
    foreach ($name in $RequiredChecks) {
        $matches = @($runs | Where-Object { $_.name -eq $name -and $_.head_sha -eq $Sha })
        if ($matches.Count -ne 1) { throw "Required check $name is missing, duplicated, or stale for $Sha." }
        if ($matches[0].status -ne "completed" -or $matches[0].conclusion -ne "success") {
            throw "Required check $name is not successful for $Sha."
        }
    }
    Write-Host "All required GitHub policy gates passed for $Sha."
}

Push-Location $RepositoryRoot
try {
    Assert-ReleaseWorkspace
    $sha = (Invoke-Git rev-parse HEAD).Trim()

    switch ($Action) {
        "PrepareCandidate" {
            if (-not $SkipLocalGate) { & (Join-Path $PSScriptRoot "run-release-gate.ps1") }
            if ($LASTEXITCODE -ne 0) { throw "The local release gate failed." }
            $remoteSha = Get-RemoteMainSha
            New-EncryptedBundle
            $tag = "release-candidate-$([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))-$($sha.Substring(0, 8))"
            Invoke-Git tag -s $tag $sha -m "Netra verified release candidate $sha" | Out-Null
            # Braces are required before the colon; otherwise PowerShell parses
            # `$tag:refs` as a scoped variable and corrupts the refspec.
            Invoke-Git push origin "refs/tags/${tag}:refs/tags/${tag}" | Out-Null
            Write-Host "Candidate tag: $tag"
            Write-Host "Candidate SHA: $sha"
            Write-Host "Recorded origin/main SHA: $remoteSha"
        }
        "VerifyCandidate" {
            if (-not $CandidateTag) { throw "-CandidateTag is required." }
            $tagSha = (Invoke-Git rev-list -n 1 $CandidateTag).Trim()
            if ($tagSha -ne $sha) { throw "The candidate tag does not identify HEAD." }
            Invoke-Git verify-tag $CandidateTag | Out-Null
            Assert-CandidateChecks -Sha $sha
        }
        "PublishMain" {
            if (-not $CandidateTag -or -not $ExpectedRemoteMainSha) {
                throw "-CandidateTag and -ExpectedRemoteMainSha are required."
            }
            $tagSha = (Invoke-Git rev-list -n 1 $CandidateTag).Trim()
            if ($tagSha -ne $sha) { throw "The candidate tag does not identify HEAD." }
            Invoke-Git verify-tag $CandidateTag | Out-Null
            Assert-CandidateChecks -Sha $sha
            if ((Get-RemoteMainSha) -ne $ExpectedRemoteMainSha) { throw "origin/main changed after candidate preparation." }
            Invoke-Git push "--force-with-lease=refs/heads/main:$ExpectedRemoteMainSha" origin "main:main" | Out-Null
            if ((Get-RemoteMainSha) -ne $sha) { throw "Published origin/main does not match the verified candidate." }
            Write-Host "Published verified main at $sha."
        }
        "DeleteCandidate" {
            if (-not $CandidateTag) { throw "-CandidateTag is required." }
            Invoke-Git push origin ":refs/tags/${CandidateTag}" | Out-Null
            Invoke-Git tag -d $CandidateTag | Out-Null
            Write-Host "Deleted temporary candidate tag $CandidateTag."
        }
    }
} finally {
    Pop-Location
}
