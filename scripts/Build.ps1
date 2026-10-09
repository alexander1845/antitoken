param([string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    dotnet restore TokenVault.sln
    if ($LASTEXITCODE -ne 0) { throw 'Restore failed' }
    dotnet build TokenVault.sln -c $Configuration --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
    dotnet run --project tests/TokenVault.Tests -c $Configuration --no-build
    if ($LASTEXITCODE -ne 0) { throw 'Security tests failed' }
    dotnet publish src/TokenVault.App -c $Configuration -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/TokenVault
    if ($LASTEXITCODE -ne 0) { throw 'Publish failed' }
    Write-Host "Done: artifacts/TokenVault/TokenVault.exe (keep AuthlibProbe.java next to it)."
} finally { Pop-Location }
