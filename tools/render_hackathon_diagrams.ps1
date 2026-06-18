$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$sourceRoot = Join-Path $repoRoot "submission\source\diagrams"
$outputRoot = Join-Path $repoRoot "tmp\pdfs\hackathon-submission\research-diagrams"
$puppeteerConfig = Join-Path $repoRoot "tmp\pdfs\hackathon-submission\puppeteer-config.json"

New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null

Get-ChildItem -LiteralPath $sourceRoot -Filter "*.mmd" | Sort-Object Name | ForEach-Object {
  $output = Join-Path $outputRoot ($_.BaseName + ".png")
  Write-Host "Rendering $($_.Name)..." -ForegroundColor Cyan
  & npx --yes @mermaid-js/mermaid-cli `
    -i $_.FullName `
    -o $output `
    -w 1800 `
    -s 2 `
    -b white `
    -p $puppeteerConfig
  if ($LASTEXITCODE -ne 0) {
    throw "Mermaid rendering failed for $($_.FullName)."
  }
}

Write-Host "Research diagrams rendered to $outputRoot" -ForegroundColor Green
