# Creates the ECDSA P-256 key pair that signs Token Vault releases for the built-in updater. Run once, with PowerShell 7,
# on a computer you trust:
#
#   pwsh scripts/New-UpdateSigningKey.ps1
#
# Then, in the GitHub repository settings (Secrets and variables > Actions):
#   * secret   UPDATE_SIGNING_KEY = the whole contents of update-signing.pem (then delete the file, or keep it offline)
#   * variable UPDATE_PUBLIC_KEY  = the public key printed below (public; it is built into TokenVault.exe)
#
# Anyone with the private key can push code to every installed copy. Keep it out of the repository, chats and issues.
# Losing it means players must download the next release by hand once (it is built with a new public key).
param([string]$OutFile = 'update-signing.pem')
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Run this with PowerShell 7 (pwsh).' }
if (Test-Path $OutFile) { throw "$OutFile already exists; refusing to overwrite a signing key." }
$key = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
try {
    [IO.File]::WriteAllText((Join-Path (Get-Location) $OutFile), $key.ExportPkcs8PrivateKeyPem())
    Write-Host "Private key written to $OutFile (store it as the UPDATE_SIGNING_KEY secret)."
    Write-Host ''
    Write-Host 'UPDATE_PUBLIC_KEY ='
    Write-Host ([Convert]::ToBase64String($key.ExportSubjectPublicKeyInfo()))
} finally { $key.Dispose() }
