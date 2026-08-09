param(
    [string]$Owner = "krishna0605",
    [string]$Repository = "Netra",
    [string]$Token = $env:GITHUB_TOKEN
)

$ErrorActionPreference = "Stop"
if (-not $Token) {
    throw "A read-only GitHub token is required through GITHUB_TOKEN or -Token."
}

$Headers = @{
    Accept = "application/vnd.github+json"
    Authorization = "Bearer $Token"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent" = "Netra-Protection-Reader/1"
}
$Base = "https://api.github.com/repos/$Owner/$Repository"
$Rulesets = Invoke-RestMethod -Method Get -Headers $Headers -Uri "$Base/rulesets"
$Summary = $Rulesets | Where-Object { $_.name -eq "Netra protected main" } | Select-Object -First 1
if (-not $Summary) {
    throw "The Netra protected main ruleset is not active."
}
$Ruleset = Invoke-RestMethod -Method Get -Headers $Headers -Uri "$Base/rulesets/$($Summary.id)"
if ($Ruleset.enforcement -ne "active") {
    throw "The main ruleset exists but is not active."
}

$RuleTypes = @($Ruleset.rules | ForEach-Object { $_.type })
$RequiredTypes = @("deletion", "non_fast_forward", "required_linear_history", "required_review_thread_resolution", "pull_request", "required_status_checks")
foreach ($Type in $RequiredTypes) {
    if ($Type -notin $RuleTypes) { throw "Required rule is missing: $Type" }
}
$StatusRule = $Ruleset.rules | Where-Object { $_.type -eq "required_status_checks" } | Select-Object -First 1
$Contexts = @($StatusRule.parameters.required_status_checks | ForEach-Object { $_.context })
foreach ($Context in @("ci-policy-gate", "security-policy-gate", "container-policy-gate")) {
    if ($Context -notin $Contexts) { throw "Required status check is missing: $Context" }
}
if (@($Ruleset.bypass_actors).Count -ne 0) {
    throw "Unexpected main-ruleset bypass actors are configured."
}

Write-Host "Main protection is active with PR-only changes, no bypass actors, and all Phase 7 policy gates."
