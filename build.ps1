$ErrorActionPreference = "Stop"

$cargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
$cargoExe = if ($cargoCommand) {
    $cargoCommand.Source
} else {
    Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
}

if (-not (Test-Path -LiteralPath $cargoExe)) {
    throw "Rust was not found. Install it from https://rustup.rs and run build.ps1 again."
}

& $cargoExe build --release
if ($LASTEXITCODE -ne 0) {
    throw "Rust build failed. Distribution files were not updated."
}

$source = Join-Path $PSScriptRoot "target\release\morty-steam-auth.exe"
$outputDirectory = Join-Path $PSScriptRoot "dist"
$outputExe = Join-Path $outputDirectory "MortySteamAuth.exe"
$shareArchive = Join-Path $outputDirectory "MortySteamAuth-share.zip"
$shareReadme = Join-Path $PSScriptRoot "SHARE_README.txt"
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
Copy-Item -LiteralPath $source -Destination $outputExe -Force

Compress-Archive -LiteralPath @($outputExe, $shareReadme) -DestinationPath $shareArchive -Force

foreach ($legacyArtifact in @("SteamVault.exe", "SteamVault-share.zip")) {
    $legacyPath = Join-Path $outputDirectory $legacyArtifact
    if (Test-Path -LiteralPath $legacyPath) {
        Remove-Item -LiteralPath $legacyPath -Force
    }
}

Write-Host "Ready: $outputExe" -ForegroundColor Green
Write-Host "Share: $shareArchive" -ForegroundColor Cyan
