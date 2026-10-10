# Starts a published TokenVault.exe on a clean Windows machine (CI), walks through the first-run screens and the main
# pages with UI Automation, and saves a screenshot of each to $OutDir. Doubles as a smoke test: it fails if the app
# doesn't start or crashes. Changes the machine (sandbox setup, C:\TokenVault), so only run it on a throwaway runner.
param([Parameter(Mandatory)][string]$Exe, [Parameter(Mandatory)][string]$OutDir)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Drawing, System.Windows.Forms
Add-Type @'
using System; using System.Runtime.InteropServices;
public static class Win {
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hwnd, int cmd);
}
'@
New-Item -ItemType Directory -Force $OutDir | Out-Null
$crashLog = Join-Path $env:LOCALAPPDATA 'TokenVault\Data\crash.log'
$failures = [System.Collections.Generic.List[string]]::new()
$A = [System.Windows.Automation.AutomationElement]

function Start-App {
    $script:proc = Start-Process -FilePath $Exe -PassThru
    for ($i = 0; $i -lt 90; $i++) {
        Start-Sleep -Milliseconds 500
        $script:proc.Refresh()
        if ($script:proc.HasExited) { Show-Crash; throw "TokenVault.exe exited with code $($script:proc.ExitCode)" }
        if ($script:proc.MainWindowHandle -ne 0 -and $script:proc.MainWindowTitle -eq 'Token Vault') { break }
    }
    if ($script:proc.MainWindowHandle -eq 0) { Show-Crash; throw 'No window appeared within 45 s.' }
    Start-Sleep -Seconds 3
    if (Test-Path $crashLog) { Show-Crash; throw 'Token Vault reported a crash.' }
    $script:window = $A::FromHandle($script:proc.MainWindowHandle)
}

function Show-Crash {
    if (Test-Path $crashLog) { Write-Host '--- crash.log ---'; Get-Content $crashLog | Write-Host }
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = '.NET Runtime' } -MaxEvents 2 -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host '--- .NET Runtime event ---'; Write-Host $_.Message }
}

function Save-Shot([string]$Name) {
    $hwnd = $script:proc.MainWindowHandle
    [Win]::SetForegroundWindow($hwnd) | Out-Null
    Start-Sleep -Milliseconds 700
    $r = $script:window.Current.BoundingRectangle
    $bitmap = New-Object System.Drawing.Bitmap ([int]$r.Width), ([int]$r.Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen([int]$r.X, [int]$r.Y, 0, 0, $bitmap.Size)
    $bitmap.Save((Join-Path $OutDir "$Name.png"), [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose(); $bitmap.Dispose()
    Write-Host "Saved $Name.png"
}

function Find-Control([string]$Name, [string]$Type = 'Button') {
    $types = @{ Button = [System.Windows.Automation.ControlType]::Button; RadioButton = [System.Windows.Automation.ControlType]::RadioButton }
    $condition = New-Object System.Windows.Automation.AndCondition (
        (New-Object System.Windows.Automation.PropertyCondition ($A::NameProperty, $Name)),
        (New-Object System.Windows.Automation.PropertyCondition ($A::ControlTypeProperty, $types[$Type])))
    for ($i = 0; $i -lt 20; $i++) {
        $found = $script:window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
        if ($found) { return $found }
        Start-Sleep -Milliseconds 500
    }
    throw "Couldn't find $Type '$Name'."
}

function Invoke-Control([string]$Name, [string]$Type = 'Button', [int]$Wait = 1500) {
    $control = Find-Control $Name $Type
    if ($Type -eq 'RadioButton') { $control.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select() }
    else { $control.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke() }
    Start-Sleep -Milliseconds $Wait
}

function Step([string]$What, [scriptblock]$Action) {
    try { & $Action } catch { $failures.Add("${What}: $($_.Exception.Message)"); Write-Host "::warning::${What}: $($_.Exception.Message)" }
}

# ---- Light theme, first run
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' AppsUseLightTheme 1 -Type DWord -Force
Start-App
Step 'welcome'   { Save-Shot '01-welcome' }
Step 'safety'    { Invoke-Control 'Get started'; Save-Shot '02-how-it-works' }
Step 'sandbox'   { Invoke-Control 'Continue'; Save-Shot '03-sandbox' }
Step 'sign-in'   { Invoke-Control 'Not now'; Save-Shot '04-sign-in' }
Step 'done'      { Invoke-Control 'Skip for now'; Save-Shot '05-done' }
Step 'library'   { Invoke-Control 'Start playing'; Save-Shot '06-library' }
Step 'security'  { Invoke-Control 'Security' 'RadioButton'; Save-Shot '07-security' }
Step 'settings'  { Invoke-Control 'Settings' 'RadioButton'; Save-Shot '08-settings' }
Step 'play'      {
    Invoke-Control 'Library' 'RadioButton'
    Invoke-Control 'Play' -Wait 2000
    Save-Shot '09-setup-prompt'
    Invoke-Control 'Continue' -Wait 9000   # runs the one-time setup (no UAC prompt on CI runners), then starts downloading
    Save-Shot '10-launching'
}
Step 'stop'      { Invoke-Control 'Stop' -Wait 2500 }
$proc.Refresh()
if ($proc.HasExited) { Show-Crash; throw "Token Vault exited during the run (code $($proc.ExitCode))." }
Stop-Process -Id $proc.Id -Force
Start-Sleep -Seconds 2

# ---- Dark theme, returning player
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' AppsUseLightTheme 0 -Type DWord -Force
Start-App
Step 'library-dark'  { Save-Shot '11-library-dark' }
Step 'security-dark' { Invoke-Control 'Security' 'RadioButton'; Save-Shot '12-security-dark' }
$proc.Refresh()
if ($proc.HasExited) { Show-Crash; throw "Token Vault exited during the dark-theme run (code $($proc.ExitCode))." }
Stop-Process -Id $proc.Id -Force

if ($failures.Count -gt 0) { Write-Host "Steps that didn't work:"; $failures | ForEach-Object { Write-Host "  $_" } }
