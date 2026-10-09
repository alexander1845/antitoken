$ErrorActionPreference = 'Stop'
$exe = Join-Path $env:ProgramFiles 'TokenVault/Launcher/TokenVault.Launcher.exe'
$config = Join-Path $env:ProgramData 'TokenVault/config.json'
& $exe launch $config
exit $LASTEXITCODE
