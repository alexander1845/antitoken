#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory)][string]$Config,
    [Parameter(Mandatory)][string]$GameUser,
    [string]$VaultUser = 'TokenVaultBroker'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$install = Join-Path $env:ProgramFiles 'TokenVault'
$settings = Join-Path $env:ProgramData 'TokenVault'
$data = Join-Path $settings 'Data'
foreach ($binary in @('artifacts/Vault/TokenVault.Vault.exe','artifacts/Launcher/TokenVault.Launcher.exe')) {
    if (-not (Test-Path (Join-Path $root $binary))) { throw 'Run scripts/Build.ps1 successfully before installation.' }
}
$c = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
$gameSid = ([System.Security.Principal.NTAccount]$GameUser).Translate([System.Security.Principal.SecurityIdentifier]).Value
if ((Test-Path $install) -or (Test-Path $settings)) { throw 'Installation already exists. Review and back it up before an explicit upgrade.' }
if (Get-LocalUser -Name $VaultUser -ErrorAction SilentlyContinue) { throw 'Choose a new dedicated local account name.' }
$password = Read-Host 'New dedicated vault account password (not your Microsoft password)' -AsSecureString
New-LocalUser -Name $VaultUser -Password $password -Description 'Restricted Minecraft token vault' | Out-Null
$vaultSid = (Get-LocalUser -Name $VaultUser).SID.Value
if (-not (Get-LocalGroupMember -SID 'S-1-5-32-545' | Where-Object { $_.SID.Value -eq $vaultSid })) {
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $VaultUser
}
if ($vaultSid -eq $gameSid) { throw 'Game and vault identities must differ' }
New-Item -ItemType Directory -Path $install,$settings,$data | Out-Null
function Set-ProtectedDirectory([string]$Path, [bool]$PrivateData) {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner([System.Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.SecurityIdentifier]$sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    $rights = if ($PrivateData) { 'Modify' } else { 'ReadAndExecute' }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        [System.Security.Principal.SecurityIdentifier]$vaultSid,$rights,'ContainerInherit,ObjectInherit','None','Allow')))
    if (-not $PrivateData) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.SecurityIdentifier]$gameSid,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
    }
    Set-Acl -Path $Path -AclObject $acl
}
Set-ProtectedDirectory $install $false
Set-ProtectedDirectory $settings $false
Set-ProtectedDirectory $data $true
Copy-Item (Join-Path $root 'artifacts/Vault') $install -Recurse
Copy-Item (Join-Path $root 'artifacts/Launcher') $install -Recurse
$c.HardeningMode = 'separate-user'; $c.GameUserSid = $gameSid; $c.VaultUserSid = $vaultSid; $c.DataDirectory = $data
$c | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $settings 'config.json') -Encoding UTF8
Write-Host 'Installed. Sign into the dedicated vault Windows account once to initialize its profile and system browser.'
Write-Host "Vault account: $env:COMPUTERNAME\$VaultUser"
Write-Host 'Then use Start-Vault.ps1 from your gaming account; never run the vault elevated.'
