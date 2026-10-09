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
    dotnet publish src/TokenVault.Vault -c $Configuration -r win-x64 --self-contained true -o artifacts/Vault
    if ($LASTEXITCODE -ne 0) { throw 'Vault publish failed' }
    dotnet publish src/TokenVault.Launcher -c $Configuration -r win-x64 --self-contained true -o artifacts/Launcher
    if ($LASTEXITCODE -ne 0) { throw 'Launcher publish failed' }
} finally { Pop-Location }
