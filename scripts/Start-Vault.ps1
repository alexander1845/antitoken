param([string]$VaultUser = 'TokenVaultBroker')
$ErrorActionPreference = 'Stop'
$credential = Get-Credential -UserName "$env:COMPUTERNAME\$VaultUser" -Message 'Dedicated Windows vault account'
$exe = Join-Path $env:ProgramFiles 'TokenVault/Vault/TokenVault.Vault.exe'
$config = Join-Path $env:ProgramData 'TokenVault/config.json'
Start-Process -FilePath $exe -ArgumentList @('host',('"' + $config + '"')) -Credential $credential -LoadUserProfile
