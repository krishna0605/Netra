param(
    [string[]]$Images = @("netra-api:local", "netra-worker:local", "netra-frontend:local"),
    [string]$OutputDirectory = "artifacts/sbom"
)

$ErrorActionPreference = "Stop"
$SyftImage = "anchore/syft@sha256:1288ea4c8b38767b4e620c1e312c8cb26b6e887a99b4f07ab6cd19fc6f225026"
$TrivyImage = "aquasec/trivy@sha256:7cced7cae583819fc7806d4cbc0dbbc7cad18b99f7d3e235192e6da8c091045c"
$ResolvedOutput = Join-Path (Get-Location) $OutputDirectory
New-Item -ItemType Directory -Path $ResolvedOutput -Force | Out-Null

python scripts/validate_vex.py
foreach ($Image in $Images) {
    docker image inspect $Image | Out-Null
    $SafeName = $Image.Replace(":", "-").Replace("/", "-")
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "${ResolvedOutput}:/output" $SyftImage $Image -o "cyclonedx-json=/output/$SafeName.cdx.json"
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock $TrivyImage image --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed $Image
}
