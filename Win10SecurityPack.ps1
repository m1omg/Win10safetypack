#Requires -Version 5.1
<#
.SYNOPSIS
    Windows 10 Security Pack - hardening and free security tools for Windows 10 after end of support.

.DESCRIPTION
    A single-file PowerShell tool with a Windows Forms GUI that:
      * configures the protection already built into Windows 10 (Microsoft Defender, Attack Surface
        Reduction rules, Windows Firewall, UAC, SmartScreen, removal of legacy SMBv1 / PowerShell 2.0,
        safe registry defaults, optional network hardening and malware-blocking DNS),
      * installs free third-party tools (0patch Agent, Malwarebytes Free, Sysinternals Autoruns and
        Process Explorer, Mozilla Firefox, winget),
      * installs any remaining Windows Updates and runs a Defender scan,
      * can revert its own hardening changes (registry values, ASR rules, DNS, network settings),
      * shows a system status overview (support state, ESU enrollment, Defender health, firewall ...).

    Everything the tool changes is written to a log file. Files downloaded directly from vendors are
    checked for a valid Authenticode signature from the expected publisher before they are run.

    Windows 10 support ended on 14 October 2025. Microsoft still offers *free* consumer Extended
    Security Updates until 12 October 2027 (Settings > Windows Update > Enroll now; needs 22H2 and a
    Microsoft account). Enrolling is the single best thing you can do - this tool complements it.

.PARAMETER Tasks
    Run the given task IDs without the GUI (see -ListTasks). Separate IDs with commas.
    Example: -Tasks restore,defender,asr,firewall

.PARAMETER ListTasks
    Print the available task IDs and exit.

.EXAMPLE
    .\Win10SecurityPack.ps1
    Opens the GUI (asks for administrator rights).

.EXAMPLE
    .\Win10SecurityPack.ps1 -Tasks restore,defender,asr,firewall,legacy,harden
    Runs the given tasks without a GUI and prints the log to the console.

.NOTES
    Requires Windows 10 (22H2 recommended), Windows PowerShell 5.1 and administrator rights.
    Tested approach: Windows Forms GUI + background runspace so the window stays responsive.

    Copyright (C) 2026 m1omg. Licensed under the GNU General Public License v3.0 or later;
    see the LICENSE file or https://www.gnu.org/licenses/gpl-3.0.html. Provided WITHOUT ANY WARRANTY.
#>
[CmdletBinding()]
param(
    [string[]]$Tasks,
    [switch]$ListTasks
)

$ErrorActionPreference = 'Continue'
$script:ToolVersion = '1.0.0'

# ===========================================================================================
#  Task catalogue (data only - the implementation is in the Task-<Id> functions below)
# ===========================================================================================
$TaskDefs = @(
    [pscustomobject]@{
        Id = 'restore'; Group = '1. Before changing anything'; Name = 'Create a System Restore point'
        Recommended = $true; Hidden = $false
        Description = @'
Creates a System Restore point so the hardening changes can be rolled back from Windows itself
(Settings > System > About > System protection > System Restore).

Enables System Protection on the Windows drive if it is off. If a restore point was already created in
the last 24 hours Windows normally refuses to make another one; the tool lifts that limit temporarily.
'@
    },
    [pscustomobject]@{
        Id = 'defender'; Group = '2. Windows built-in protection'; Name = 'Microsoft Defender: enable, update and tighten'
        Recommended = $true; Hidden = $false
        Description = @'
Microsoft Defender Antivirus keeps receiving definition ("Security Intelligence") updates on Windows 10
until at least October 2028, so it stays useful even without OS patches. This task:
  - makes sure the Defender service and real-time protection are on,
  - turns on cloud-delivered protection (block level High), behaviour monitoring, script scanning,
    scanning of downloads/attachments, removable drives and archives,
  - enables blocking of Potentially Unwanted Applications (adware, bundlers),
  - enables Network Protection (blocks connections to known-malicious domains),
  - checks for definition updates every 4 hours and right now.

Tamper Protection cannot be switched on by a script - the tool reminds you to turn it on manually in
Windows Security if it is off. If a third-party antivirus is installed, Defender runs in passive mode
and most of these settings have no effect.
'@
    },
    [pscustomobject]@{
        Id = 'asr'; Group = '2. Windows built-in protection'; Name = 'Attack Surface Reduction rules (block common malware tricks)'
        Recommended = $true; Hidden = $false
        Description = @'
Attack Surface Reduction (ASR) rules are a Defender feature that works on every edition of Windows 10,
including Home. They block behaviours malware relies on rather than specific files - very valuable on an
unpatched system. Enabled in BLOCK mode:
  - credential theft from LSASS, abuse of vulnerable signed drivers, persistence via WMI,
  - Office apps / Adobe Reader / Outlook spawning child processes, Office creating executable content or
    injecting code, Win32 API calls from macros,
  - executable content from e-mail and webmail, JavaScript/VBScript launching downloaded executables,
    potentially obfuscated scripts,
  - untrusted or unsigned programs started from USB, rebooting into Safe Mode by malware,
  - advanced ransomware protection.
Enabled in AUDIT mode only (they log but do not block, because they can affect legitimate software):
  - block executables that fail prevalence/age/trusted-list checks,
  - block process creation from PsExec/WMI,
  - block copied or impersonated system tools.
The previous rule set is saved so "Revert hardening" can restore it.
'@
    },
    [pscustomobject]@{
        Id = 'cfa'; Group = '2. Windows built-in protection'; Name = 'Controlled Folder Access (ransomware protection for your documents)'
        Recommended = $false; Hidden = $false
        Description = @'
Only trusted applications may modify files in protected folders (Documents, Pictures, Desktop, ...).
Strong protection against ransomware, BUT programs Microsoft does not know (games, niche tools, some
backup software) will be blocked from saving into those folders until you allow them in
Windows Security > Virus & threat protection > Ransomware protection > Allow an app.

Off by default because of that friction. Turn it on if you are willing to approve apps occasionally.
'@
    },
    [pscustomobject]@{
        Id = 'firewall'; Group = '2. Windows built-in protection'; Name = 'Windows Firewall on for all network profiles'
        Recommended = $true; Hidden = $false
        Description = @'
Ensures the Windows Firewall service runs automatically and the firewall is enabled for the Domain,
Private and Public profiles, with inbound connections blocked by default (outbound allowed) and
notifications when a program asks to listen. Existing allow-rules are kept.
'@
    },
    [pscustomobject]@{
        Id = 'legacy'; Group = '2. Windows built-in protection'; Name = 'Remove SMBv1 and PowerShell 2.0 (legacy attack surface)'
        Recommended = $true; Hidden = $false
        Description = @'
SMBv1 is the 30-year-old file-sharing protocol exploited by WannaCry/NotPetya (EternalBlue). PowerShell 2.0
is an old engine attackers use to bypass modern script logging and AMSI scanning. Neither is needed on a
modern PC; this task disables the Windows optional features for both. A restart may be required.

Only very old devices (e.g. a NAS or printer from before 2010) still need SMBv1 for file sharing.
'@
    },
    [pscustomobject]@{
        Id = 'harden'; Group = '2. Windows built-in protection'; Name = 'Safe defaults: AutoRun off, show extensions, UAC max, SmartScreen block, credential protection'
        Recommended = $true; Hidden = $false
        Description = @'
Registry changes (the previous values are backed up for "Revert hardening"):
  - disables AutoRun/AutoPlay for all drive types (USB-borne malware),
  - shows file extensions in Explorer (so "invoice.pdf.exe" is visible),
  - sets UAC to always prompt on the secure desktop and keeps installer detection on,
  - sets SmartScreen for apps and files to "Block" and enables SmartScreen + PUA blocking in Edge,
  - prevents WDigest from caching clear-text passwords, restricts anonymous SAM enumeration,
  - enables LSA Protection (RunAsPPL), which shields the logon process from credential-dumping tools.
Explorer changes show after the next sign-in; LSA Protection needs a restart.
'@
    },
    [pscustomobject]@{
        Id = 'network'; Group = '2. Windows built-in protection'; Name = 'Network hardening: LLMNR/NetBIOS off, Remote Desktop & Remote Assistance off'
        Recommended = $false; Hidden = $false
        Description = @'
  - Disables LLMNR and NetBIOS over TCP/IP name resolution (classic spoofing/relay attack vectors on
    shared Wi-Fi). Side effect: very old devices on your LAN may no longer be reachable by name.
  - Disables Remote Assistance and incoming Remote Desktop connections (and their firewall rules).
    Do NOT enable this if you connect to this PC with Remote Desktop.
Off by default because it changes how the PC behaves on a home network. Reversible with "Revert hardening".
'@
    },
    [pscustomobject]@{
        Id = 'dns'; Group = '2. Windows built-in protection'; Name = 'Use Quad9 malware-blocking DNS (9.9.9.9)'
        Recommended = $false; Hidden = $false
        Description = @'
Points the active network adapters at Quad9 (9.9.9.9 / 149.112.112.112 and IPv6), a free, non-profit
DNS resolver that refuses to resolve known malware, phishing and botnet domains. This blocks many
threats before they reach the browser or an exploit kit reaches the unpatched OS.

The current DNS configuration is saved and restored by "Revert hardening". Off by default because it
overrides the DNS your router/ISP provides (and local names from some routers may stop resolving).
'@
    },
    [pscustomobject]@{
        Id = 'wu'; Group = '2. Windows built-in protection'; Name = 'Install any remaining Windows Updates'
        Recommended = $true; Hidden = $false
        Description = @'
Uses the Windows Update API to find, download and install everything still pending: Defender platform
and definition updates, the Malicious Software Removal Tool, the last pre-October-2025 cumulative update
if it was never installed, the ESU "Licensing Preparation Package" (needed to enrol in free ESU) and -
if the PC is enrolled in ESU - the monthly security updates.

Feature upgrades (e.g. the Windows 11 offer) and updates that need user interaction are skipped.
This can take a long time; a restart may be required afterwards.
'@
    },
    [pscustomobject]@{
        Id = 'winget'; Group = '3. Free third-party tools'; Name = 'winget - Windows Package Manager (installs & updates the tools below)'
        Recommended = $true; Hidden = $false
        Description = @'
winget is Microsoft's command-line package manager (part of "App Installer" from the Store). It is used
to install Malwarebytes and Firefox silently and, later, to keep *all* your installed programs patched
with one command: winget upgrade --all

Skipped if winget is already present. Otherwise it is bootstrapped with Microsoft's own
Microsoft.WinGet.Client PowerShell module (Repair-WinGetPackageManager). Needs Windows 10 1809 or later.
If that fails, install "App Installer" from the Microsoft Store manually.
'@
    },
    [pscustomobject]@{
        Id = '0patch'; Group = '3. Free third-party tools'; Name = '0patch Agent - security micropatches for Windows 10 after end of support'
        Recommended = $true; Hidden = $false
        Description = @'
0patch (ACROS Security) delivers tiny in-memory "micropatches" for vulnerabilities in Windows 10 22H2
after Microsoft's support ended - promised until at least October 2030. The agent is downloaded from
0patch's official server and its digital signature is verified before installation.

You need a 0patch account (https://0patch.com) and must sign in once via the 0patch Console (tray icon):
  - FREE plan: selected 0-day patches only, non-commercial use.
  - PRO plan (about 25 EUR per PC per year): ALL patches, including the full Windows 10 post-end-of-support
    stream. This is the paid part - the agent itself and the FREE plan cost nothing.
Micropatches apply to the final official Windows 10 binaries, so install all Windows Updates first.
'@
    },
    [pscustomobject]@{
        Id = 'mbam'; Group = '3. Free third-party tools'; Name = 'Malwarebytes Free (second-opinion on-demand scanner)'
        Recommended = $true; Hidden = $false
        Description = @'
Installs Malwarebytes for Windows. After a 14-day Premium trial it reverts to the Free edition, which is
an on-demand scanner and cleaner that is good at adware, PUPs and things Defender misses. It does not
replace Defender's real-time protection (and the Free edition does not try to).

Installed with winget when available, otherwise downloaded from downloads.malwarebytes.com and
signature-checked (publisher: Malwarebytes). You can decline the trial inside the app.
'@
    },
    [pscustomobject]@{
        Id = 'autoruns'; Group = '3. Free third-party tools'; Name = 'Sysinternals Autoruns + Process Explorer (find what starts with Windows)'
        Recommended = $true; Hidden = $false
        Description = @'
Two free Microsoft tools for checking a PC by hand:
  - Autoruns lists everything that starts automatically (services, scheduled tasks, Run keys, drivers,
    browser helpers) and can check each entry against VirusTotal - the fastest way to spot persistence.
  - Process Explorer is a powerful Task Manager replacement that also shows VirusTotal results.
Downloaded from download.sysinternals.com, extracted to C:\Program Files\Sysinternals, signatures
verified (publisher: Microsoft), Start-menu shortcuts created.
'@
    },
    [pscustomobject]@{
        Id = 'firefox'; Group = '3. Free third-party tools'; Name = 'Mozilla Firefox (an up-to-date browser not tied to Windows support)'
        Recommended = $false; Hidden = $false
        Description = @'
The browser is the most exposed program on any PC. Mozilla has committed to supporting Firefox on
Windows 10 for the foreseeable future (Microsoft Edge is also supported until at least October 2028;
Google has not announced an end date for Chrome). Firefox is a good second browser and pairs well with
the uBlock Origin extension, which blocks malicious ads and scripts.

Installed with winget when available, otherwise from download.mozilla.org (signature-checked).
Off by default - tick it if you want it.
'@
    },
    [pscustomobject]@{
        Id = 'upgradeall'; Group = '3. Free third-party tools'; Name = 'Update all installed programs now (winget upgrade --all)'
        Recommended = $false; Hidden = $false
        Description = @'
Out-of-date third-party programs (PDF readers, media players, archivers, browsers, runtimes) are the
most common way malware gets onto an unpatched PC. This runs "winget upgrade --all" to update every
program winget recognises, silently. Run it regularly.

Off by default because it can update many programs at once (and some updates may change features).
Requires winget.
'@
    },
    [pscustomobject]@{
        Id = 'scan'; Group = '4. Scan'; Name = 'Microsoft Defender quick scan'
        Recommended = $true; Hidden = $false
        Description = @'
Runs a Defender quick scan (memory, start-up locations, common malware folders) after the other tasks and
lists any threats detected. Usually takes 5-15 minutes. For a full scan use Windows Security afterwards.
'@
    },
    [pscustomobject]@{
        Id = 'revert'; Group = 'Maintenance'; Name = 'Revert hardening changes made by this tool'
        Recommended = $false; Hidden = $true
        Description = @'
Restores the registry values, ASR rules, DNS servers and NetBIOS settings this tool changed, from the
backups it kept in C:\ProgramData\Win10SecurityPack, and turns Controlled Folder Access off.
Defender settings, the firewall, SMBv1/PowerShell 2.0 removal and installed programs are left alone.
'@
    }
)

if ($ListTasks) {
    Write-Host ''
    Write-Host ('{0,-11} {1,-12} {2}' -f 'Id', 'Recommended', 'Task') -ForegroundColor Cyan
    Write-Host ('{0,-11} {1,-12} {2}' -f '--', '-----------', '----') -ForegroundColor Cyan
    foreach ($t in $TaskDefs) {
        Write-Host ('{0,-11} {1,-12} {2}' -f $t.Id, $(if ($t.Recommended) { 'yes' } else { '' }), $t.Name)
    }
    Write-Host ''
    Write-Host 'Example: .\Win10SecurityPack.ps1 -Tasks restore,defender,asr,firewall,legacy,harden'
    exit 0
}

# Normalise -Tasks (when launched through powershell.exe -File the value arrives as one "a,b,c" string)
if ($Tasks) {
    $Tasks = @($Tasks | ForEach-Object { $_ -split '[,; ]+' } | Where-Object { $_ } | ForEach-Object { $_.Trim().ToLower() })
}

# ===========================================================================================
#  Elevation
# ===========================================================================================
function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass')
    if ($Tasks) { $argList += '-NoExit' } else { $argList += @('-WindowStyle', 'Hidden') }
    $argList += @('-File', ('"{0}"' -f $PSCommandPath))
    if ($Tasks) { $argList += @('-Tasks', ($Tasks -join ',')) }
    try {
        Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -ErrorAction Stop | Out-Null
    } catch {
        Write-Host ''
        Write-Host 'This tool needs administrator rights (the UAC prompt was declined or failed).' -ForegroundColor Yellow
        Write-Host $_.Exception.Message -ForegroundColor DarkGray
        Read-Host 'Press Enter to close' | Out-Null
    }
    exit
}

# ===========================================================================================
#  Environment
# ===========================================================================================
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$ScriptDir = Split-Path -Parent $PSCommandPath
$StateDir  = Join-Path $env:ProgramData 'Win10SecurityPack'
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

# Log next to the script if that location is writable, otherwise under ProgramData.
$LogDir = Join-Path $ScriptDir 'logs'
try {
    New-Item -ItemType Directory -Path $LogDir -Force -ErrorAction Stop | Out-Null
    $probe = Join-Path $LogDir '.write-test'
    [IO.File]::WriteAllText($probe, 'ok')
    Remove-Item -LiteralPath $probe -Force
} catch {
    $LogDir = Join-Path $StateDir 'logs'
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

$DownloadDir = Join-Path $env:TEMP 'Win10SecurityPack'
New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null

# Shared state between the GUI thread and the background worker runspace.
$sync = [hashtable]::Synchronized(@{})
$sync.Log          = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
$sync.Status       = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
$sync.Cancel       = $false
$sync.Progress     = 0
$sync.NeedReboot   = $false
$sync.Advice       = New-Object System.Collections.ArrayList
$sync.PostLaunch   = New-Object System.Collections.ArrayList
$sync.Results      = [hashtable]::Synchronized(@{})
$sync.LogFile      = Join-Path $LogDir ('Win10SecurityPack_{0:yyyyMMdd_HHmmss}.log' -f (Get-Date))
$sync.StateDir     = $StateDir
$sync.DownloadDir  = $DownloadDir
$sync.Cli          = [bool]$Tasks
$sync.TaskDefs     = $TaskDefs
$sync.StatusResult = $null

# ===========================================================================================
#  Shared functions - everything defined between the two markers is also injected into the
#  background runspace, so keep UI code out of this region.
# ===========================================================================================
$__fnBefore = @(Get-ChildItem Function: | Select-Object -ExpandProperty Name)

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info', 'Warn', 'Error', 'Success', 'Step', 'Debug')][string]$Level = 'Info'
    )
    $entry = [pscustomobject]@{ Time = Get-Date; Level = $Level; Message = $Message }
    if ($sync.Cli) {
        $line = '[{0:HH:mm:ss}] [{1,-7}] {2}' -f $entry.Time, $Level.ToUpper(), $Message
        $color = switch ($Level) {
            'Warn'    { 'Yellow' }
            'Error'   { 'Red' }
            'Success' { 'Green' }
            'Step'    { 'Cyan' }
            'Debug'   { 'DarkGray' }
            default   { 'Gray' }
        }
        Write-Host $line -ForegroundColor $color
        try { [IO.File]::AppendAllText($sync.LogFile, $line + [Environment]::NewLine, [Text.Encoding]::UTF8) } catch { }
    } else {
        $sync.Log.Enqueue($entry)
    }
}

function Set-TaskStatus {
    param([string]$Id, [string]$Status)
    $sync.Results[$Id] = $Status
    $sync.Status.Enqueue([pscustomobject]@{ Id = $Id; Status = $Status })
}

function Add-Advice {
    param([string]$Text)
    if (-not $sync.Advice.Contains($Text)) { [void]$sync.Advice.Add($Text) }
}

# ---- registry with backup -----------------------------------------------------------------
function Get-RegBackupPath { Join-Path $sync.StateDir 'registry-backup.json' }

function Add-RegBackupEntry {
    param([string]$Path, [string]$Name)
    $file = Get-RegBackupPath
    $list = @()
    if (Test-Path -LiteralPath $file) {
        try { $list = @((Get-Content -LiteralPath $file -Raw) | ConvertFrom-Json) } catch { $list = @() }
    }
    foreach ($e in $list) { if ($e.Path -eq $Path -and $e.Name -eq $Name) { return } }

    $existed = $false; $value = $null; $kind = $null
    if (Test-Path -LiteralPath $Path) {
        $key = Get-Item -LiteralPath $Path
        if (@($key.GetValueNames()) -contains $Name) {
            $existed = $true
            $value = $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
            $kind = $key.GetValueKind($Name).ToString()
        }
    }
    $list += [pscustomobject]@{
        Path = $Path; Name = $Name; Existed = $existed; Value = $value; Kind = $kind
        Saved = (Get-Date).ToString('s')
    }
    ConvertTo-Json -InputObject @($list) -Depth 5 | Set-Content -LiteralPath $file -Encoding UTF8
}

function Set-RegValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('DWord', 'QWord', 'String', 'ExpandString')][string]$Type = 'DWord',
        [switch]$NoBackup
    )
    if (-not $NoBackup) { Add-RegBackupEntry -Path $Path -Name $Name }
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    $old = $null
    try { $old = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $old = $null }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    $oldText = if ($null -eq $old) { '(not set)' } else { "$old" }
    Write-Log ('  {0}\{1}: {2} -> {3}' -f ($Path -replace ':', ''), $Name, $oldText, $Value) Debug
}

# ---- downloads, signatures, installers ----------------------------------------------------
function Test-FileSignature {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Signer)
    $leaf = Split-Path -Leaf $Path
    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($sig.Status -ne 'Valid') {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        throw "Digital signature check FAILED for $leaf (status: $($sig.Status)). The file was deleted and NOT installed."
    }
    $subject = $sig.SignerCertificate.Subject
    if ($subject -notmatch [regex]::Escape($Signer)) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        throw "Unexpected signer for ${leaf}: '$subject' (expected a certificate containing '$Signer'). File deleted."
    }
    Write-Log "  signature OK: $subject" Debug
}

function Get-Download {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$FileName,
        [string]$Signer
    )
    $dest = Join-Path $sync.DownloadDir $FileName
    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue }
    Write-Log "  downloading $Url"
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Win10SecurityPack/1.0')
    try { $wc.DownloadFile($Url, $dest) } finally { $wc.Dispose() }
    if (-not (Test-Path -LiteralPath $dest)) { throw "Download failed: $FileName was not saved." }
    $size = (Get-Item -LiteralPath $dest).Length
    if ($size -lt 10KB) {
        Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
        throw "Download of $FileName is suspiciously small ($size bytes) - probably an error page."
    }
    Write-Log ('  saved {0} ({1:N1} MB)' -f $FileName, ($size / 1MB)) Debug
    if ($Signer) { Test-FileSignature -Path $dest -Signer $Signer }
    return $dest
}

function Install-Msi {
    param([Parameter(Mandatory)][string]$Path, [string[]]$Properties = @())
    $msiLog = Join-Path $sync.DownloadDir ((Split-Path -Leaf $Path) + '.install.log')
    $argList = @('/i', ('"{0}"' -f $Path), '/qn', '/norestart', '/L*v', ('"{0}"' -f $msiLog)) + $Properties
    Write-Log ('  msiexec {0}' -f ($argList -join ' ')) Debug
    $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $argList -Wait -PassThru
    switch ($p.ExitCode) {
        0    { Write-Log '  installed.' Success }
        3010 { Write-Log '  installed - a restart is required.' Success; $sync.NeedReboot = $true }
        1641 { Write-Log '  installed - a restart is required.' Success; $sync.NeedReboot = $true }
        default { throw "msiexec exited with code $($p.ExitCode). Details: $msiLog" }
    }
}

function Start-Installer {
    param([Parameter(Mandatory)][string]$Path, [string[]]$Arguments = @())
    Write-Log ('  running {0} {1}' -f (Split-Path -Leaf $Path), ($Arguments -join ' ')) Debug
    if ($Arguments.Count -gt 0) {
        $p = Start-Process -FilePath $Path -ArgumentList $Arguments -Wait -PassThru
    } else {
        $p = Start-Process -FilePath $Path -Wait -PassThru
    }
    if ($p.ExitCode -eq 3010) { $sync.NeedReboot = $true; return }
    if ($p.ExitCode -ne 0) { throw "Installer exited with code $($p.ExitCode)." }
}

function New-Shortcut {
    param([string]$Target, [string]$ShortcutPath, [string]$Description)
    $dir = Split-Path -Parent $ShortcutPath
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut($ShortcutPath)
    $lnk.TargetPath = $Target
    $lnk.WorkingDirectory = Split-Path -Parent $Target
    $lnk.Description = $Description
    $lnk.Save()
}

function Get-ProgramFilesDirs {
    # Both Program Files folders (only one exists on 32-bit Windows).
    return @($env:ProgramFiles, ${env:ProgramFiles(x86)} | Where-Object { $_ } | Select-Object -Unique)
}

# ---- winget -------------------------------------------------------------------------------
function Get-WingetPath {
    $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $alias = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
    if (Test-Path -LiteralPath $alias) { return $alias }
    $pattern = Join-Path $env:ProgramFiles 'WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe'
    $pkg = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($pkg) { return $pkg.FullName }
    return $null
}

function Invoke-Winget {
    param([string[]]$Arguments)
    $winget = Get-WingetPath
    if (-not $winget) { throw 'winget is not available on this PC.' }
    # Native stderr output must not become a terminating error in Windows PowerShell 5.1.
    $ErrorActionPreference = 'Continue'
    Write-Log ('  winget {0}' -f ($Arguments -join ' ')) Debug
    $output = & $winget @Arguments 2>&1
    $code = $LASTEXITCODE
    foreach ($line in @($output)) {
        $text = ("$line" -replace '[\u2588\u2592\u2591\u25A0-\u25FF\u2800-\u28FF\u00A0]', '').Trim()
        if ($text.Length -gt 1 -and $text -notmatch '^[-\\|/\s]+$') { Write-Log "    $text" Debug }
    }
    return $code
}

function Install-WithWinget {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Name)
    if (-not (Get-WingetPath)) { return $false }
    Write-Log "Installing $Name with winget ($Id) ..."
    $code = Invoke-Winget @('install', '--id', $Id, '--exact', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
    switch ($code) {
        0             { Write-Log "  $Name installed." Success; return $true }
        (-1978335189) { Write-Log "  $Name is already installed and up to date." Success; return $true }
        (-1978335135) { Write-Log "  $Name is already installed." Success; return $true }
        default       { Write-Log ('  winget failed with 0x{0:X8} ({0}); trying the vendor download instead.' -f $code) Warn; return $false }
    }
}

# ---- system status (for the Status tab) ---------------------------------------------------
function Get-SystemStatus {
    $items = New-Object System.Collections.ArrayList
    function Add-StatusItem($Name, $Value, $State) {
        [void]$items.Add([pscustomobject]@{ Name = $Name; Value = "$Value"; State = $State })
    }

    # Windows version
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $displayVersion = if ($cv.DisplayVersion) { $cv.DisplayVersion } else { $cv.ReleaseId }
    $buildNumber = [int]$cv.CurrentBuildNumber
    $isWin10 = $buildNumber -lt 22000
    Add-StatusItem 'Windows' ('{0} {1} (build {2}.{3})' -f $cv.ProductName, $displayVersion, $cv.CurrentBuildNumber, $cv.UBR) 'info'
    if ($isWin10) {
        if ($displayVersion -ne '22H2') {
            Add-StatusItem 'Windows 10 version' "$displayVersion - ESU and 0patch require 22H2. Upgrade to 22H2 first (Windows Update or the Media Creation Tool)." 'bad'
        }
        Add-StatusItem 'OS support' 'Windows 10 support ended 14 Oct 2025. OS security patches only via ESU (Microsoft) or 0patch (third party).' 'warn'
    } else {
        Add-StatusItem 'OS support' 'This is Windows 11. The tool targets Windows 10, but most tasks still apply.' 'info'
    }

    # ESU enrolment
    $esu = 'Unknown'; $esuState = 'warn'
    try {
        $lic = @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "Name like '%ESU%' and LicenseStatus = 1" -ErrorAction SilentlyContinue)
        $consumer = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\ConsumerESU' -ErrorAction SilentlyContinue
        if ($lic.Count -gt 0) {
            $esu = 'Licensed: ' + $lic[0].Name; $esuState = 'ok'
        } elseif ($consumer -and ($consumer.ESUEligibility -eq 3 -or $consumer.ESUEligibility -eq 5)) {
            $esu = 'Enrolled in consumer ESU - security updates until 12 Oct 2027.'; $esuState = 'ok'
        } elseif ($consumer -and $consumer.ESUEligibility -eq 2) {
            $esu = 'Eligible but NOT enrolled. Free enrolment (Windows Backup sync) is open until 12 Oct 2027: Settings > Update & Security > Windows Update > Enroll now.'; $esuState = 'bad'
        } elseif ($consumer -and $consumer.ESUEligibility -eq 1) {
            $esu = 'Reported ineligible. Needs 22H2 + latest updates (incl. KB5126256), an administrator Microsoft account, not domain-joined/MDM.'; $esuState = 'warn'
        } elseif ($isWin10) {
            $esu = 'No enrolment found. Free consumer ESU is still open until 12 Oct 2027 - check Settings > Windows Update (needs 22H2 + Microsoft account).'; $esuState = 'bad'
        } else {
            $esu = 'Not applicable'; $esuState = 'info'
        }
    } catch { $esu = "Could not determine: $($_.Exception.Message)" }
    Add-StatusItem 'Extended Security Updates (ESU)' $esu $esuState

    # Last OS update
    try {
        $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $total = $searcher.GetTotalHistoryCount()
        $last = $null
        if ($total -gt 0) {
            $hist = $searcher.QueryHistory(0, [Math]::Min($total, 300))
            $candidates = @()
            for ($i = 0; $i -lt $hist.Count; $i++) {
                $h = $hist.Item($i)
                if ($h.ResultCode -eq 2 -and $h.Operation -eq 1 -and
                    $h.Title -notmatch 'KB2267602|KB4052623|KB890830|Defender|Antimalware|Security Intelligence') {
                    $candidates += $h
                }
            }
            if ($candidates.Count -gt 0) { $last = ($candidates | Sort-Object Date -Descending)[0] }
        }
        if ($last) {
            $age = (New-TimeSpan -Start $last.Date -End (Get-Date)).Days
            Add-StatusItem 'Last Windows update installed' ('{0:yyyy-MM-dd}  {1}' -f $last.Date, $last.Title) $(if ($age -gt 45) { 'warn' } else { 'ok' })
        } else {
            Add-StatusItem 'Last Windows update installed' 'No successful installs found in Windows Update history.' 'warn'
        }
    } catch { Add-StatusItem 'Last Windows update installed' "Could not read Windows Update history: $($_.Exception.Message)" 'warn' }

    # Defender
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $pref = Get-MpPreference -ErrorAction Stop
        $rtOk = [bool]$mp.RealTimeProtectionEnabled
        $modeOk = ($mp.AMRunningMode -eq 'Normal')
        Add-StatusItem 'Defender Antivirus' ('mode: {0}; real-time protection: {1}; platform {2}' -f $mp.AMRunningMode, $(if ($rtOk) { 'on' } else { 'OFF' }), $mp.AMProductVersion) $(if ($rtOk -and $modeOk) { 'ok' } else { 'bad' })
        $sigAge = [int]$mp.AntivirusSignatureAge
        Add-StatusItem 'Defender definitions' ('version {0}, updated {1:yyyy-MM-dd HH:mm} ({2} day(s) old)' -f $mp.AntivirusSignatureVersion, $mp.AntivirusSignatureLastUpdated, $sigAge) $(if ($sigAge -le 3) { 'ok' } else { 'warn' })
        Add-StatusItem 'Defender tamper protection' $(if ($mp.IsTamperProtected) { 'on' } else { 'OFF - turn on in Windows Security > Virus & threat protection > Manage settings' }) $(if ($mp.IsTamperProtected) { 'ok' } else { 'warn' })
        $cloud = ([int]$pref.MAPSReporting -gt 0); $pua = ([int]$pref.PUAProtection -eq 1); $np = ([int]$pref.EnableNetworkProtection -eq 1)
        Add-StatusItem 'Defender cloud / PUA / network protection' ('cloud protection {0}; PUA blocking {1}; network protection {2}' -f $(if ($cloud) { 'on' } else { 'off' }), $(if ($pua) { 'on' } else { 'off' }), $(if ($np) { 'on' } else { 'off' })) $(if ($cloud -and $pua -and $np) { 'ok' } else { 'warn' })
        $ids = @($pref.AttackSurfaceReductionRules_Ids); $acts = @($pref.AttackSurfaceReductionRules_Actions)
        $asrBlock = 0
        for ($i = 0; $i -lt $ids.Count; $i++) { if ($i -lt $acts.Count -and [int]$acts[$i] -eq 1) { $asrBlock++ } }
        Add-StatusItem 'Attack Surface Reduction rules' ('{0} configured, {1} in block mode' -f $ids.Count, $asrBlock) $(if ($asrBlock -ge 10) { 'ok' } else { 'warn' })
        $cfaText = switch ([int]$pref.EnableControlledFolderAccess) { 1 { 'on (block)' } 2 { 'audit mode' } default { 'off' } }
        Add-StatusItem 'Controlled folder access (ransomware)' $cfaText $(if ([int]$pref.EnableControlledFolderAccess -eq 1) { 'ok' } else { 'info' })
    } catch { Add-StatusItem 'Defender Antivirus' "Not available: $($_.Exception.Message)" 'bad' }

    # Firewall
    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        $off = @($profiles | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
        Add-StatusItem 'Windows Firewall' $(if ($off.Count -eq 0) { 'enabled on all profiles' } else { 'DISABLED on: ' + ($off -join ', ') }) $(if ($off.Count -eq 0) { 'ok' } else { 'bad' })
    } catch { Add-StatusItem 'Windows Firewall' "Could not query: $($_.Exception.Message)" 'warn' }

    # SMBv1
    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        Add-StatusItem 'SMBv1 file-sharing protocol' $(if ($smb.EnableSMB1Protocol) { 'ENABLED - legacy protocol abused by WannaCry/EternalBlue' } else { 'disabled' }) $(if ($smb.EnableSMB1Protocol) { 'bad' } else { 'ok' })
    } catch { }

    # UAC
    $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    $uacOn = ($null -eq $pol.EnableLUA) -or ($pol.EnableLUA -ne 0)
    $uacText = if (-not $uacOn) { 'DISABLED' } elseif ($pol.ConsentPromptBehaviorAdmin -eq 2) { 'on - always notify (secure desktop)' } else { 'on (admin prompt level {0})' -f $pol.ConsentPromptBehaviorAdmin }
    Add-StatusItem 'User Account Control' $uacText $(if ($uacOn) { 'ok' } else { 'bad' })

    # SmartScreen
    $ssPol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction SilentlyContinue
    $ssExp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -ErrorAction SilentlyContinue
    $ssText = if ($ssPol.EnableSmartScreen -eq 1) { 'policy: ' + $ssPol.ShellSmartScreenLevel }
              elseif ($ssPol.EnableSmartScreen -eq 0) { 'DISABLED by policy' }
              elseif ($ssExp.SmartScreenEnabled -eq 'Off') { 'OFF' }
              else { 'on (default: warn)' }
    Add-StatusItem 'SmartScreen for apps & files' $ssText $(if ($ssText -match 'DISABLED|OFF') { 'bad' } elseif ($ssText -match 'Block') { 'ok' } else { 'info' })

    # LSA protection
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    Add-StatusItem 'LSA protection (RunAsPPL)' $(if ($lsa.RunAsPPL -ge 1) { 'on' } else { 'off' }) $(if ($lsa.RunAsPPL -ge 1) { 'ok' } else { 'info' })

    # Tools
    $zp = Get-Service -Name '0patchService' -ErrorAction SilentlyContinue
    if (-not $zp) { $zp = Get-Service | Where-Object { $_.DisplayName -like '*0patch*' } | Select-Object -First 1 }
    Add-StatusItem '0patch Agent' $(if ($zp) { 'installed (service {0}: {1})' -f $zp.Name, $zp.Status } else { 'not installed' }) $(if ($zp) { 'ok' } else { 'info' })

    $mb = Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'Malwarebytes\Anti-Malware\mbam.exe')
    Add-StatusItem 'Malwarebytes' $(if ($mb) { 'installed' } else { 'not installed' }) $(if ($mb) { 'ok' } else { 'info' })

    $wg = Get-WingetPath
    $wgVer = ''
    if ($wg) { try { $ErrorActionPreference = 'Continue'; $wgVer = "$(& $wg --version 2>$null | Select-Object -First 1)".Trim() } catch { $wgVer = '' } }
    Add-StatusItem 'winget (Windows Package Manager)' $(if ($wg) { "available $wgVer" } else { 'not available' }) $(if ($wg) { 'ok' } else { 'info' })

    $sysint = (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'Sysinternals\Autoruns\Autoruns64.exe')) -or
              (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'Sysinternals\Autoruns\Autoruns.exe'))
    Add-StatusItem 'Sysinternals Autoruns' $(if ($sysint) { 'installed' } else { 'not installed' }) $(if ($sysint) { 'ok' } else { 'info' })

    # Pending restart
    $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
               (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
    if ($pending) { Add-StatusItem 'Pending restart' 'Windows is waiting for a restart to finish installing updates/features.' 'warn' }

    return $items.ToArray()
}

# ===========================================================================================
#  Tasks
# ===========================================================================================
function Task-restore {
    $drive = $env:SystemDrive + '\'
    try {
        Enable-ComputerRestore -Drive $drive -ErrorAction Stop
        Write-Log "  System Protection is enabled on $drive" Debug
    } catch {
        Write-Log "  could not enable System Protection: $($_.Exception.Message)" Warn
    }
    # Windows refuses more than one restore point per 24 h unless this value is 0.
    $srKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $prev = $null
    try { $prev = (Get-ItemProperty -LiteralPath $srKey -Name SystemRestorePointCreationFrequency -ErrorAction Stop).SystemRestorePointCreationFrequency } catch { $prev = $null }
    Set-RegValue -Path $srKey -Name SystemRestorePointCreationFrequency -Value 0 -NoBackup
    try {
        Write-Log '  creating restore point (this can take a minute) ...'
        Checkpoint-Computer -Description ('Win10 Security Pack {0:yyyy-MM-dd HH:mm}' -f (Get-Date)) -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Log 'Restore point created.' Success
    } catch {
        throw "Restore point could not be created: $($_.Exception.Message). Other tasks will still run."
    } finally {
        if ($null -ne $prev) {
            Set-ItemProperty -LiteralPath $srKey -Name SystemRestorePointCreationFrequency -Value $prev
        } else {
            Remove-ItemProperty -LiteralPath $srKey -Name SystemRestorePointCreationFrequency -ErrorAction SilentlyContinue
        }
    }
}

function Set-MpPrefSafe {
    param([string]$Name, $Value)
    try {
        $p = @{ $Name = $Value }
        Set-MpPreference @p -ErrorAction Stop
        Write-Log "  $Name = $Value" Debug
    } catch {
        Write-Log "  could not set $Name = ${Value}: $($_.Exception.Message)" Warn
    }
}

function Task-defender {
    $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    if (-not $svc) { throw 'The Microsoft Defender Antivirus service (WinDefend) is not present. Is Defender removed or replaced by another product?' }
    if ($svc.Status -ne 'Running') {
        try { Start-Service -Name WinDefend -ErrorAction Stop; Write-Log '  Defender service started.' }
        catch { Write-Log "  could not start the Defender service: $($_.Exception.Message)" Warn }
    }
    $status = $null
    try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { throw "Defender is not responding: $($_.Exception.Message)" }
    if ($status.AMRunningMode -ne 'Normal') {
        Write-Log "  Defender is in '$($status.AMRunningMode)' mode - usually because another antivirus is installed. Settings below may not take effect." Warn
        Add-Advice "Defender is in $($status.AMRunningMode) mode. Keep your third-party antivirus updated, or uninstall it to let Defender protect the PC."
    }

    Write-Log '  applying protection settings ...'
    Set-MpPrefSafe DisableRealtimeMonitoring $false
    Set-MpPrefSafe DisableBehaviorMonitoring $false
    Set-MpPrefSafe DisableIOAVProtection $false
    Set-MpPrefSafe DisableScriptScanning $false
    Set-MpPrefSafe DisableArchiveScanning $false
    Set-MpPrefSafe DisableRemovableDriveScanning $false
    Set-MpPrefSafe DisableBlockAtFirstSeen $false
    Set-MpPrefSafe MAPSReporting 2            # Advanced
    Set-MpPrefSafe SubmitSamplesConsent 1     # Send safe samples
    Set-MpPrefSafe CloudBlockLevel 2          # High
    Set-MpPrefSafe CloudExtendedTimeout 50
    Set-MpPrefSafe PUAProtection 1            # Enabled
    Set-MpPrefSafe EnableNetworkProtection 1  # Enabled
    Set-MpPrefSafe CheckForSignaturesBeforeRunningScan $true
    Set-MpPrefSafe SignatureUpdateInterval 4

    Write-Log ('  definitions before: {0} ({1:yyyy-MM-dd HH:mm})' -f $status.AntivirusSignatureVersion, $status.AntivirusSignatureLastUpdated) Debug
    Write-Log '  checking for definition updates ...'
    try {
        Update-MpSignature -ErrorAction Stop
        $after = Get-MpComputerStatus
        Write-Log ('  definitions now: {0} ({1:yyyy-MM-dd HH:mm})' -f $after.AntivirusSignatureVersion, $after.AntivirusSignatureLastUpdated) Success
    } catch {
        Write-Log "  definition update failed: $($_.Exception.Message) (Windows Update will retry automatically)" Warn
    }

    if (-not $status.IsTamperProtected) {
        Write-Log '  Tamper Protection is OFF. It can only be enabled manually: Windows Security > Virus & threat protection > Manage settings > Tamper Protection.' Warn
        Add-Advice 'Turn on Tamper Protection: Windows Security > Virus & threat protection > Manage settings.'
    }
    Write-Log 'Microsoft Defender configured.' Success
}

function Get-AsrRuleSets {
    $block = [ordered]@{
        '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
        'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
        'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript/VBScript from launching downloaded executable content'
        '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
        '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication application from creating child processes'
        '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
        'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
    }
    $audit = [ordered]@{
        '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files unless they meet prevalence/age/trusted-list criteria'
        'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations originating from PsExec and WMI commands'
        'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied or impersonated system tools'
    }
    return @{ Block = $block; Audit = $audit }
}

function Task-asr {
    $pref = Get-MpPreference -ErrorAction Stop
    $backup = Join-Path $sync.StateDir 'asr-backup.json'
    if (-not (Test-Path -LiteralPath $backup)) {
        $saved = [pscustomobject]@{
            Ids     = @($pref.AttackSurfaceReductionRules_Ids)
            Actions = @($pref.AttackSurfaceReductionRules_Actions | ForEach-Object { [int]$_ })
            Saved   = (Get-Date).ToString('s')
        }
        ConvertTo-Json -InputObject $saved -Depth 4 | Set-Content -LiteralPath $backup -Encoding UTF8
        Write-Log "  previous ASR configuration saved to $backup" Debug
    }
    $sets = Get-AsrRuleSets
    $ok = 0; $failed = 0
    foreach ($id in $sets.Block.Keys) {
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
            Write-Log ('  BLOCK  {0}' -f $sets.Block[$id]) Debug; $ok++
        } catch { Write-Log ('  failed: {0} - {1}' -f $sets.Block[$id], $_.Exception.Message) Warn; $failed++ }
    }
    foreach ($id in $sets.Audit.Keys) {
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions AuditMode -ErrorAction Stop
            Write-Log ('  AUDIT  {0}' -f $sets.Audit[$id]) Debug; $ok++
        } catch { Write-Log ('  failed: {0} - {1}' -f $sets.Audit[$id], $_.Exception.Message) Warn; $failed++ }
    }
    if ($ok -eq 0) { throw 'No ASR rule could be applied (is Defender active?).' }
    Write-Log ("Attack Surface Reduction: {0} rules applied{1}." -f $ok, $(if ($failed) { ", $failed failed" } else { '' })) Success
    Write-Log '  If a legitimate program is blocked later, look in Windows Security > Protection history and add an exclusion with Add-MpPreference -AttackSurfaceReductionOnlyExclusions.' Debug
}

function Task-cfa {
    Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop
    Write-Log 'Controlled Folder Access enabled (block mode).' Success
    Add-Advice 'Controlled Folder Access is on: if a trusted program cannot save to Documents/Pictures, allow it in Windows Security > Ransomware protection.'
}

function Task-firewall {
    $svc = Get-Service -Name mpssvc -ErrorAction Stop
    if ($svc.StartType -ne 'Automatic') { Set-Service -Name mpssvc -StartupType Automatic; Write-Log '  firewall service set to Automatic' Debug }
    if ($svc.Status -ne 'Running') { Start-Service -Name mpssvc; Write-Log '  firewall service started' Debug }
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -ErrorAction Stop
    foreach ($p in Get-NetFirewallProfile) {
        Write-Log ('  {0}: enabled={1}, inbound default={2}' -f $p.Name, $p.Enabled, $p.DefaultInboundAction) Debug
    }
    Write-Log 'Windows Firewall is on for all profiles (inbound blocked by default).' Success
}

function Task-legacy {
    $features = @('SMB1Protocol', 'SMB1Protocol-Client', 'SMB1Protocol-Server', 'SMB1Protocol-Deprecation',
                  'MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')
    foreach ($name in $features) {
        $feat = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction SilentlyContinue
        if (-not $feat) { continue }
        if ($feat.State -eq 'Enabled') {
            Write-Log "  disabling optional feature $name ..."
            $r = Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart -ErrorAction Stop
            if ($r.RestartNeeded) { $sync.NeedReboot = $true }
            Write-Log "  $name disabled$(if ($r.RestartNeeded) { ' (restart needed)' })" Debug
        } else {
            Write-Log "  $name already $($feat.State)" Debug
        }
    }
    try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop; Write-Log '  SMB server: SMB1 disabled' Debug } catch { }
    Write-Log 'Legacy components (SMBv1, PowerShell 2.0) are disabled.' Success
}

function Task-harden {
    $console = $null
    try { $console = (Get-CimInstance Win32_ComputerSystem).UserName } catch { }
    if ($console -and ($console -notlike "*\$env:USERNAME")) {
        Write-Log "  Note: you are elevated as '$env:USERNAME' but signed in as '$console'. Per-user settings (AutoPlay, file extensions) apply to '$env:USERNAME'." Warn
    }

    Write-Log '  AutoRun / AutoPlay ...'
    Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255
    Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 1
    Set-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' 'DisableAutoplay' 1

    Write-Log '  show file extensions ...'
    Set-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'HideFileExt' 0

    Write-Log '  User Account Control ...'
    $uac = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-RegValue $uac 'EnableLUA' 1
    Set-RegValue $uac 'ConsentPromptBehaviorAdmin' 2
    Set-RegValue $uac 'PromptOnSecureDesktop' 1
    Set-RegValue $uac 'EnableInstallerDetection' 1

    Write-Log '  SmartScreen ...'
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 1
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel' 'Block' -Type String
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled' 1
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenPuaEnabled' 1

    Write-Log '  credential protection ...'
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' 1
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' 1
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 1
    $sync.NeedReboot = $true

    Write-Log 'Safe defaults applied (Explorer changes appear after sign-out; LSA protection after a restart).' Success
}

function Task-network {
    Write-Log '  disabling LLMNR ...'
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0

    Write-Log '  disabling NetBIOS over TCP/IP on IP-enabled adapters ...'
    foreach ($nic in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE')) {
        try {
            $r = Invoke-CimMethod -InputObject $nic -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } -ErrorAction Stop
            Write-Log ('  {0}: result {1}' -f $nic.Description, $r.ReturnValue) Debug
            if ($r.ReturnValue -eq 1) { $sync.NeedReboot = $true }
        } catch { Write-Log ('  {0}: {1}' -f $nic.Description, $_.Exception.Message) Warn }
    }

    Write-Log '  disabling Remote Assistance and incoming Remote Desktop ...'
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp' 0
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1
    try {
        Disable-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -ErrorAction Stop   # "Remote Desktop" rule group (language independent)
        Write-Log '  Remote Desktop firewall rules disabled' Debug
    } catch { Write-Log "  Remote Desktop firewall rules: $($_.Exception.Message)" Debug }

    Set-Content -LiteralPath (Join-Path $sync.StateDir 'network-applied') -Value (Get-Date).ToString('s')
    Write-Log 'Network hardening applied.' Success
}

function Task-dns {
    $file = Join-Path $sync.StateDir 'dns-backup.json'
    $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' })
    if ($adapters.Count -eq 0) { throw 'No active physical network adapter found.' }

    if (-not (Test-Path -LiteralPath $file)) {
        $backup = @()
        foreach ($a in $adapters) {
            $g = $a.InterfaceGuid
            $v4 = $null; $v6 = $null
            try { $v4 = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$g" -Name NameServer -ErrorAction Stop).NameServer } catch { }
            try { $v6 = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$g" -Name NameServer -ErrorAction Stop).NameServer } catch { }
            $servers = @()
            foreach ($s in @($v4, $v6)) { if ($s) { $servers += @($s -split '[,\s]+' | Where-Object { $_ }) } }
            $backup += [pscustomobject]@{ InterfaceIndex = $a.InterfaceIndex; Name = $a.Name; Guid = $g; StaticServers = $servers; Saved = (Get-Date).ToString('s') }
        }
        ConvertTo-Json -InputObject @($backup) -Depth 4 | Set-Content -LiteralPath $file -Encoding UTF8
        Write-Log "  previous DNS settings saved to $file" Debug
    }

    $quad9 = @('9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9')
    foreach ($a in $adapters) {
        Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ServerAddresses $quad9 -ErrorAction Stop
        Write-Log "  '$($a.Name)': DNS -> Quad9" Debug
    }
    Clear-DnsClientCache
    Write-Log 'DNS set to Quad9 (malware-blocking) on all active adapters. "Revert hardening" restores the previous servers.' Success
}

function Restore-DnsBackup {
    $file = Join-Path $sync.StateDir 'dns-backup.json'
    if (-not (Test-Path -LiteralPath $file)) { return }
    $entries = @((Get-Content -LiteralPath $file -Raw) | ConvertFrom-Json)
    foreach ($e in $entries) {
        try {
            $null = Get-NetAdapter -InterfaceIndex $e.InterfaceIndex -ErrorAction Stop
            Set-DnsClientServerAddress -InterfaceIndex $e.InterfaceIndex -ResetServerAddresses -ErrorAction Stop
            if ($e.StaticServers -and @($e.StaticServers).Count -gt 0) {
                Set-DnsClientServerAddress -InterfaceIndex $e.InterfaceIndex -ServerAddresses @($e.StaticServers) -ErrorAction Stop
                Write-Log ('  DNS on {0} restored to {1}' -f $e.Name, (@($e.StaticServers) -join ', ')) Debug
            } else {
                Write-Log ('  DNS on {0} restored to automatic (DHCP)' -f $e.Name) Debug
            }
        } catch { Write-Log ('  could not restore DNS on interface {0}: {1}' -f $e.InterfaceIndex, $_.Exception.Message) Warn }
    }
    Move-Item -LiteralPath $file -Destination ($file + '.restored_' + (Get-Date -Format 'yyyyMMdd_HHmmss')) -Force
    Clear-DnsClientCache
    Write-Log 'DNS settings restored.' Success
}

function Task-wu {
    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'Win10SecurityPack'
    $searcher = $session.CreateUpdateSearcher()
    Write-Log '  searching Windows Update (this can take several minutes) ...'
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    $count = $result.Updates.Count
    if ($count -eq 0) { Write-Log 'Windows Update: nothing pending.' Success; return }

    $upgradesCategory = '3689bdc8-b205-4af4-8d4a-a63924c5e9d5'
    $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
    for ($i = 0; $i -lt $count; $i++) {
        $u = $result.Updates.Item($i)
        $isUpgrade = $false
        for ($c = 0; $c -lt $u.Categories.Count; $c++) {
            if ($u.Categories.Item($c).CategoryID -eq $upgradesCategory) { $isUpgrade = $true }
        }
        if ($isUpgrade) { Write-Log "  skipping feature upgrade: $($u.Title)" Debug; continue }
        if ($u.InstallationBehavior.CanRequestUserInput) { Write-Log "  skipping (needs user input): $($u.Title)" Debug; continue }
        if (-not $u.EulaAccepted) { try { $u.AcceptEula() } catch { } }
        Write-Log "  - $($u.Title)"
        [void]$toInstall.Add($u)
    }
    if ($toInstall.Count -eq 0) { Write-Log 'Windows Update: nothing installable without interaction.' Success; return }

    Write-Log "  downloading $($toInstall.Count) update(s) ..."
    $downloader = $session.CreateUpdateDownloader()
    $downloader.Updates = $toInstall
    $dres = $downloader.Download()
    if ($dres.ResultCode -notin @(2, 3)) { throw "Download failed (result code $($dres.ResultCode), HRESULT 0x$('{0:X8}' -f $dres.HResult))." }

    Write-Log '  installing ...'
    $installer = $session.CreateUpdateInstaller()
    $installer.Updates = $toInstall
    $ires = $installer.Install()
    for ($i = 0; $i -lt $toInstall.Count; $i++) {
        $rc = $ires.GetUpdateResult($i).ResultCode
        $text = switch ($rc) { 2 { 'installed' } 3 { 'installed with errors' } 4 { 'FAILED' } 5 { 'aborted' } default { "result $rc" } }
        Write-Log ('  {0}: {1}' -f $text, $toInstall.Item($i).Title) $(if ($rc -eq 2) { 'Debug' } else { 'Warn' })
    }
    if ($ires.RebootRequired) { $sync.NeedReboot = $true }
    if ($ires.ResultCode -in @(2, 3)) {
        Write-Log ("Windows Update: {0} update(s) processed{1}." -f $toInstall.Count, $(if ($ires.RebootRequired) { ' - restart required' } else { '' })) Success
    } else {
        throw "Installation finished with result code $($ires.ResultCode) (HRESULT 0x$('{0:X8}' -f $ires.HResult))."
    }
}

function Task-winget {
    $existing = Get-WingetPath
    if ($existing) {
        Write-Log "winget is already available: $existing" Success
        return
    }
    $build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    if ($build -lt 17763) { throw "winget needs Windows 10 1809 (build 17763) or later; this is build $build." }

    Write-Log '  installing the Microsoft.WinGet.Client PowerShell module from the PowerShell Gallery ...'
    try {
        try {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers -ErrorAction Stop | Out-Null
        } catch { Write-Log "  NuGet provider: $($_.Exception.Message)" Debug }
        if (-not (Get-Module -ListAvailable -Name Microsoft.WinGet.Client)) {
            Install-Module -Name Microsoft.WinGet.Client -Force -AllowClobber -Scope AllUsers -Repository PSGallery -ErrorAction Stop
        }
        Import-Module Microsoft.WinGet.Client -ErrorAction Stop
        Write-Log '  bootstrapping winget (Repair-WinGetPackageManager) ...'
        Repair-WinGetPackageManager -AllUsers -Latest -Force -ErrorAction Stop
    } catch {
        try { Start-Process 'ms-windows-store://pdp/?productid=9NBLGGH4NNS1' } catch { }
        throw "Automatic winget installation failed: $($_.Exception.Message). Install 'App Installer' from the Microsoft Store (opened for you) and run this task again."
    }
    Start-Sleep -Seconds 3
    $path = Get-WingetPath
    if (-not $path) { throw 'winget was installed but is not yet visible to this process. Sign out and in again (or restart) and re-run the tools tasks.' }
    Write-Log "winget installed: $path" Success
}

function Task-0patch {
    $svc = Get-Service -Name '0patchService' -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Log "0patch Agent is already installed (service $($svc.Name): $($svc.Status))." Success
    } else {
        $msi = Get-Download -Url 'https://dist.0patch.com/download/latestagent' -FileName '0patchInstaller.msi' -Signer 'ACROS'
        Install-Msi -Path $msi
        $svc = Get-Service -Name '0patchService' -ErrorAction SilentlyContinue
        if (-not $svc) { Write-Log '  the 0patch service was not found after installation - check the MSI log.' Warn }
    }
    $dirs = @(Get-ProgramFilesDirs | ForEach-Object { Join-Path $_ '0patch' } | Where-Object { Test-Path -LiteralPath $_ })
    $console = $null
    if ($dirs.Count -gt 0) {
        $console = Get-ChildItem -Path $dirs -Filter '0patchConsole.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if ($console) { [void]$sync.PostLaunch.Add([pscustomobject]@{ Name = '0patch Console'; Path = $console.FullName }) }
    Add-Advice 'Sign in to 0patch: open the 0patch Console (tray icon), create a free account at https://0patch.com or enter PRO credentials. Only PRO receives the full Windows 10 post-end-of-support patch stream.'
    Write-Log '0patch Agent ready. Sign in via the 0patch Console to start receiving micropatches.' Success
}

function Task-mbam {
    $exe = Join-Path $env:ProgramFiles 'Malwarebytes\Anti-Malware\mbam.exe'
    if (Test-Path -LiteralPath $exe) { Write-Log 'Malwarebytes is already installed.' Success; return }
    if (-not (Install-WithWinget -Id 'Malwarebytes.Malwarebytes' -Name 'Malwarebytes')) {
        $setup = Get-Download -Url 'https://downloads.malwarebytes.com/file/mb-windows' -FileName 'MBSetup.exe' -Signer 'Malwarebytes'
        Start-Installer -Path $setup -Arguments @('/VERYSILENT', '/NORESTART')
    }
    Add-Advice 'Malwarebytes starts a 14-day Premium trial; afterwards it becomes the Free on-demand scanner. Run a scan from it every few weeks.'
    Write-Log 'Malwarebytes installed.' Success
}

function Task-autoruns {
    $x64 = [Environment]::Is64BitOperatingSystem
    $tools = @(
        [pscustomobject]@{ Name = 'Autoruns';         Zip = 'https://download.sysinternals.com/files/Autoruns.zip';         Exe = $(if ($x64) { 'Autoruns64.exe' } else { 'Autoruns.exe' }); RegKey = 'HKCU:\Software\Sysinternals\AutoRuns' },
        [pscustomobject]@{ Name = 'Process Explorer'; Zip = 'https://download.sysinternals.com/files/ProcessExplorer.zip';  Exe = $(if ($x64) { 'procexp64.exe' } else { 'procexp.exe' });   RegKey = 'HKCU:\Software\Sysinternals\Process Explorer' }
    )
    $root = Join-Path $env:ProgramFiles 'Sysinternals'
    foreach ($t in $tools) {
        $dir = Join-Path $root $t.Name
        $zip = Get-Download -Url $t.Zip -FileName (($t.Name -replace ' ', '') + '.zip')
        if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Expand-Archive -LiteralPath $zip -DestinationPath $dir -Force
        $exePath = Join-Path $dir $t.Exe
        if (-not (Test-Path -LiteralPath $exePath)) { throw "$($t.Exe) not found in the downloaded archive." }
        Test-FileSignature -Path $exePath -Signer 'Microsoft'
        Set-RegValue -Path $t.RegKey -Name 'EulaAccepted' -Value 1 -NoBackup
        New-Shortcut -Target $exePath -ShortcutPath (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Sysinternals\$($t.Name).lnk") -Description "Sysinternals $($t.Name)"
        Write-Log "  $($t.Name) -> $dir" Debug
    }
    Add-Advice 'Run Autoruns (Start menu > Sysinternals) and enable Options > Scan Options > Check VirusTotal.com to review everything that starts with Windows.'
    Write-Log 'Sysinternals Autoruns and Process Explorer installed (Start menu > Sysinternals).' Success
}

function Task-firefox {
    $installed = @(Get-ProgramFilesDirs | Where-Object { Test-Path -LiteralPath (Join-Path $_ 'Mozilla Firefox\firefox.exe') }).Count -gt 0
    if ($installed) { Write-Log 'Firefox is already installed.' Success; return }
    if (-not (Install-WithWinget -Id 'Mozilla.Firefox' -Name 'Mozilla Firefox')) {
        $culture = (Get-UICulture).Name
        $langs = @($culture.Split('-')[0], $culture, 'en-US') | Select-Object -Unique
        $setup = $null
        foreach ($lang in $langs) {
            try {
                $setup = Get-Download -Url "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=$lang" -FileName 'FirefoxSetup.exe' -Signer 'Mozilla'
                Write-Log "  Firefox language: $lang" Debug
                break
            } catch { Write-Log "  no installer for language '$lang' ($($_.Exception.Message))" Debug }
        }
        if (-not $setup) { throw 'Could not download the Firefox installer.' }
        Start-Installer -Path $setup -Arguments @('/S')
    }
    Add-Advice 'In Firefox, install the uBlock Origin extension (addons.mozilla.org) to block malicious ads and scripts.'
    Write-Log 'Firefox installed.' Success
}

function Task-upgradeall {
    if (-not (Get-WingetPath)) { throw 'winget is not available - run the winget task first.' }
    Write-Log '  upgrading all winget-managed programs (this may take a while) ...'
    $code = Invoke-Winget @('upgrade', '--all', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
    switch ($code) {
        0             { Write-Log 'All programs known to winget are up to date.' Success }
        (-1978335189) { Write-Log 'No upgrades available.' Success }
        default       { Write-Log ('winget upgrade finished with 0x{0:X8} - some packages may have failed (see log above).' -f $code) Warn }
    }
}

function Task-scan {
    Write-Log '  running a Defender quick scan (typically 5-15 minutes) ...'
    Start-MpScan -ScanType QuickScan -ErrorAction Stop
    $threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10)
    if ($threats.Count -eq 0) {
        Write-Log 'Quick scan finished - no threats recorded.' Success
    } else {
        Write-Log "Quick scan finished. Most recent detections ($($threats.Count) shown):" Warn
        foreach ($d in $threats) {
            $name = "ThreatID $($d.ThreatID)"
            try { $name = (Get-MpThreat -ThreatID $d.ThreatID -ErrorAction Stop).ThreatName } catch { }
            Write-Log ('  {0:yyyy-MM-dd HH:mm}  {1}  [{2}]' -f $d.InitialDetectionTime, $name, (@($d.Resources) -join '; ')) Warn
        }
        Add-Advice 'Threats were detected in the past - review them in Windows Security > Virus & threat protection > Protection history.'
    }
}

function Task-revert {
    Write-Log 'Reverting hardening changes made by this tool ...' Step

    # 1. Registry values
    $file = Get-RegBackupPath
    if (Test-Path -LiteralPath $file) {
        $list = @((Get-Content -LiteralPath $file -Raw) | ConvertFrom-Json)
        foreach ($e in $list) {
            try {
                if ($e.Existed) {
                    if (-not (Test-Path -LiteralPath $e.Path)) { New-Item -Path $e.Path -Force | Out-Null }
                    $val = $e.Value
                    if ($e.Kind -eq 'Binary' -and $null -ne $val) { $val = [byte[]]@($val) }
                    if ($e.Kind -eq 'MultiString') { $val = [string[]]@($val) }
                    New-ItemProperty -LiteralPath $e.Path -Name $e.Name -Value $val -PropertyType $e.Kind -Force | Out-Null
                    Write-Log ('  restored {0}\{1} = {2}' -f ($e.Path -replace ':', ''), $e.Name, $val) Debug
                } else {
                    Remove-ItemProperty -LiteralPath $e.Path -Name $e.Name -ErrorAction SilentlyContinue
                    Write-Log ('  removed {0}\{1}' -f ($e.Path -replace ':', ''), $e.Name) Debug
                }
            } catch { Write-Log ('  could not restore {0}\{1}: {2}' -f $e.Path, $e.Name, $_.Exception.Message) Warn }
        }
        Move-Item -LiteralPath $file -Destination ($file + '.restored_' + (Get-Date -Format 'yyyyMMdd_HHmmss')) -Force
        Write-Log "  $($list.Count) registry value(s) restored." Success
    } else {
        Write-Log '  no registry backup found - nothing to restore.'
    }

    # 2. Defender ASR rules and Controlled Folder Access
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $current = @($pref.AttackSurfaceReductionRules_Ids)
        if ($current.Count -gt 0) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $current -ErrorAction Stop }
        $asrFile = Join-Path $sync.StateDir 'asr-backup.json'
        if (Test-Path -LiteralPath $asrFile) {
            $b = (Get-Content -LiteralPath $asrFile -Raw) | ConvertFrom-Json
            if ($b.Ids -and @($b.Ids).Count -gt 0) {
                Add-MpPreference -AttackSurfaceReductionRules_Ids @($b.Ids) -AttackSurfaceReductionRules_Actions @($b.Actions | ForEach-Object { [int]$_ }) -ErrorAction Stop
                Write-Log ('  previous ASR configuration restored ({0} rules)' -f @($b.Ids).Count) Debug
            } else {
                Write-Log '  ASR rules removed (none were configured before)' Debug
            }
            Move-Item -LiteralPath $asrFile -Destination ($asrFile + '.restored_' + (Get-Date -Format 'yyyyMMdd_HHmmss')) -Force
        }
        Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
        Write-Log '  ASR rules reverted; Controlled Folder Access off.' Success
    } catch { Write-Log "  Defender revert: $($_.Exception.Message)" Warn }

    # 3. NetBIOS back to default (only if the network task ran)
    $marker = Join-Path $sync.StateDir 'network-applied'
    if (Test-Path -LiteralPath $marker) {
        foreach ($nic in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE')) {
            try { Invoke-CimMethod -InputObject $nic -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]0 } -ErrorAction Stop | Out-Null } catch { }
        }
        try { Enable-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -ErrorAction Stop } catch { }
        Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
        Write-Log '  NetBIOS set back to default; Remote Desktop firewall rules re-enabled (RDP itself follows the restored registry value).' Success
    }

    # 4. DNS
    Restore-DnsBackup

    $sync.NeedReboot = $true
    Write-Log 'Revert finished. Defender settings, firewall, SMBv1/PowerShell 2.0 removal and installed programs were intentionally left in place.' Success
}

# ---- task runner (used by both the GUI worker and the CLI mode) ---------------------------
function Invoke-TaskRun {
    param([Parameter(Mandatory)][string[]]$Ids)
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $ConfirmPreference = 'None'
    Import-Module Defender, NetSecurity, DnsClient, NetAdapter, SmbShare, Dism -ErrorAction SilentlyContinue

    $defs = @($sync.TaskDefs | Where-Object { $Ids -contains $_.Id })
    $total = $defs.Count
    $n = 0
    Write-Log ('Starting {0} task(s): {1}' -f $total, (($defs | ForEach-Object { $_.Id }) -join ', ')) Step
    Write-Log "Log file: $($sync.LogFile)" Debug

    foreach ($t in $defs) {
        if ($sync.Cancel) {
            Set-TaskStatus $t.Id 'Cancelled'
            Write-Log "Skipped (cancelled): $($t.Name)" Warn
            continue
        }
        $sync.Progress = [int](100 * $n / [Math]::Max($total, 1))
        Set-TaskStatus $t.Id 'Running'
        Write-Log ('[{0}/{1}] {2}' -f ($n + 1), $total, $t.Name) Step
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            & ('Task-' + $t.Id)
            Set-TaskStatus $t.Id 'Done'
            Write-Log ('  finished in {0:N0} s' -f $sw.Elapsed.TotalSeconds) Debug
        } catch {
            Set-TaskStatus $t.Id 'Failed'
            Write-Log ('FAILED: {0} - {1}' -f $t.Name, $_.Exception.Message) Error
        }
        $n++
    }
    $sync.Progress = 100

    $done = @($sync.Results.Values | Where-Object { $_ -eq 'Done' }).Count
    $failed = @($sync.Results.Values | Where-Object { $_ -eq 'Failed' }).Count
    Write-Log ('All tasks processed: {0} succeeded, {1} failed{2}.' -f $done, $failed, $(if ($sync.NeedReboot) { ' - a RESTART is required to finish' } else { '' })) Step
    if ($sync.Advice.Count -gt 0) {
        Write-Log 'Next steps for you:' Step
        foreach ($a in $sync.Advice) { Write-Log "  * $a" }
    }
    foreach ($p in @($sync.PostLaunch)) {
        try { Start-Process -FilePath $p.Path -ErrorAction Stop; Write-Log "Opened $($p.Name)." } catch { Write-Log "Could not open $($p.Name): $($_.Exception.Message)" Warn }
    }
}

$SharedFunctions = @(Get-ChildItem Function: | Where-Object { $__fnBefore -notcontains $_.Name })
# ===========================================================================================
#  end of shared region
# ===========================================================================================

# ===========================================================================================
#  CLI mode
# ===========================================================================================
if ($Tasks) {
    $known = @($TaskDefs | ForEach-Object { $_.Id })
    $invalid = @($Tasks | Where-Object { $known -notcontains $_ })
    if ($invalid.Count -gt 0) {
        Write-Host ("Unknown task id(s): {0}. Use -ListTasks to see the available ids." -f ($invalid -join ', ')) -ForegroundColor Red
        exit 2
    }
    Write-Host ''
    Write-Host "Windows 10 Security Pack $ToolVersion - command-line mode" -ForegroundColor Cyan
    Invoke-TaskRun -Ids $Tasks
    if ($sync.NeedReboot) { Write-Host 'A restart is required to complete the changes.' -ForegroundColor Yellow }
    $anyFailed = @($sync.Results.Values | Where-Object { $_ -eq 'Failed' }).Count -gt 0
    exit $(if ($anyFailed) { 1 } else { 0 })
}

# ===========================================================================================
#  GUI
# ===========================================================================================
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
try {
    Add-Type -Namespace Win10SecurityPack -Name Native -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
'@ -ErrorAction Stop
    [void][Win10SecurityPack.Native]::SetProcessDPIAware()
} catch { }
[System.Windows.Forms.Application]::EnableVisualStyles()

$ui = @{}
$script:Worker = $null

function New-Control {
    param([string]$Type, [hashtable]$Props)
    $c = New-Object ('System.Windows.Forms.' + $Type)
    foreach ($k in $Props.Keys) { $c.$k = $Props[$k] }
    return $c
}

function Add-LogLine {
    param($Entry)
    $rtb = $ui.Log
    $line = '[{0:HH:mm:ss}] {1}' -f $Entry.Time, $Entry.Message
    $color = switch ($Entry.Level) {
        'Warn'    { [System.Drawing.Color]::DarkOrange }
        'Error'   { [System.Drawing.Color]::Firebrick }
        'Success' { [System.Drawing.Color]::ForestGreen }
        'Step'    { [System.Drawing.Color]::RoyalBlue }
        'Debug'   { [System.Drawing.Color]::Gray }
        default   { [System.Drawing.SystemColors]::WindowText }
    }
    $rtb.SelectionStart = $rtb.TextLength
    $rtb.SelectionLength = 0
    $rtb.SelectionColor = $color
    $rtb.SelectionFont = $(if ($Entry.Level -eq 'Step') { $ui.LogBold } else { $ui.LogFont })
    $rtb.AppendText($line + "`r`n")
    $rtb.SelectionStart = $rtb.TextLength
    $rtb.ScrollToCaret()
    try {
        $fileLine = '[{0:yyyy-MM-dd HH:mm:ss}] [{1,-7}] {2}' -f $Entry.Time, $Entry.Level.ToUpper(), $Entry.Message
        [IO.File]::AppendAllText($sync.LogFile, $fileLine + [Environment]::NewLine, [Text.Encoding]::UTF8)
    } catch { }
}

function Write-UiLog {
    param([string]$Message, [string]$Level = 'Info')
    Add-LogLine ([pscustomobject]@{ Time = Get-Date; Level = $Level; Message = $Message })
}

function Update-ItemStatus {
    param([string]$Id, [string]$Status)
    $item = $ui.ItemsById[$Id]
    if (-not $item) { return }
    $item.SubItems[1].Text = $Status
    $item.SubItems[1].ForeColor = switch ($Status) {
        'Done'      { [System.Drawing.Color]::ForestGreen }
        'Failed'    { [System.Drawing.Color]::Firebrick }
        'Running'   { [System.Drawing.Color]::RoyalBlue }
        'Cancelled' { [System.Drawing.Color]::Gray }
        'Queued'    { [System.Drawing.Color]::DimGray }
        default     { [System.Drawing.SystemColors]::WindowText }
    }
    $item.UseItemStyleForSubItems = $false
    if ($Status -eq 'Running') { $item.EnsureVisible() }
}

function Drain-Queues {
    $entry = $null
    while ($sync.Log.TryDequeue([ref]$entry)) { Add-LogLine $entry }
    $st = $null
    while ($sync.Status.TryDequeue([ref]$st)) { Update-ItemStatus $st.Id $st.Status }
}

function Set-UiBusy {
    param([bool]$Busy)
    $ui.BtnRun.Enabled      = -not $Busy
    $ui.BtnCancel.Enabled   = $Busy
    $ui.BtnRevert.Enabled   = -not $Busy
    $ui.BtnRefresh.Enabled  = -not $Busy
    $ui.BtnRecommended.Enabled = -not $Busy
    $ui.BtnAll.Enabled      = -not $Busy
    $ui.BtnNone.Enabled     = -not $Busy
    $ui.List.Enabled        = -not $Busy
    $ui.Form.UseWaitCursor  = $Busy
}

function Start-Worker {
    param([string]$Kind, [scriptblock]$Script, [object[]]$Arguments = @())
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($fn in $SharedFunctions) {
        $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fn.Name, $fn.Definition)))
    }
    $iss.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry('sync', $sync, 'shared state')))
    $rs = [runspacefactory]::CreateRunspace($iss)
    $rs.ApartmentState = 'STA'
    $rs.ThreadOptions = 'ReuseThread'
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($Script.ToString())
    foreach ($a in $Arguments) { [void]$ps.AddArgument($a) }
    $script:Worker = @{ Kind = $Kind; PS = $ps; Runspace = $rs; Handle = $ps.BeginInvoke() }
    $ui.Timer.Start()
}

function Fill-StatusList {
    param($Items)
    $lv = $ui.StatusList
    $lv.BeginUpdate()
    $lv.Items.Clear()
    foreach ($s in @($Items)) {
        $glyph = switch ($s.State) { 'ok' { [char]0x2714 } 'warn' { [char]0x26A0 } 'bad' { [char]0x2716 } default { [char]0x2022 } }
        $item = New-Object System.Windows.Forms.ListViewItem(("$glyph  " + $s.Name))
        [void]$item.SubItems.Add($s.Value)
        $item.ForeColor = switch ($s.State) {
            'ok'   { [System.Drawing.Color]::ForestGreen }
            'warn' { [System.Drawing.Color]::DarkOrange }
            'bad'  { [System.Drawing.Color]::Firebrick }
            default { [System.Drawing.SystemColors]::WindowText }
        }
        $item.ToolTipText = $s.Value
        [void]$lv.Items.Add($item)
    }
    $lv.EndUpdate()
    $ui.StatusInfo.Text = 'Last refreshed {0:HH:mm:ss}. Red = fix this, orange = worth attention, green = fine. Hover a row for the full text.' -f (Get-Date)
}

function Show-RunSummary {
    param([string]$Kind)
    $done = @($sync.Results.Values | Where-Object { $_ -eq 'Done' }).Count
    $failed = @($sync.Results.Values | Where-Object { $_ -eq 'Failed' }).Count
    $sb = New-Object System.Text.StringBuilder
    if ($Kind -eq 'revert') {
        [void]$sb.AppendLine('Revert finished.')
    } else {
        [void]$sb.AppendLine(('{0} task(s) succeeded, {1} failed.' -f $done, $failed))
    }
    if ($failed -gt 0) { [void]$sb.AppendLine('See the log for details of the failures.') }
    if ($sync.Advice.Count -gt 0) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('Next steps for you:')
        foreach ($a in $sync.Advice) { [void]$sb.AppendLine(' - ' + $a) }
    }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('Log file: ' + $sync.LogFile)
    $icon = $(if ($failed -gt 0) { 'Warning' } else { 'Information' })
    [void][System.Windows.Forms.MessageBox]::Show($ui.Form, $sb.ToString(), 'Windows 10 Security Pack', 'OK', $icon)
    if ($sync.NeedReboot) {
        $r = [System.Windows.Forms.MessageBox]::Show($ui.Form, 'A restart is required to finish applying the changes. Restart now?', 'Restart required', 'YesNo', 'Question', 'Button2')
        if ($r -eq 'Yes') { Restart-Computer -Force }
    }
}

function Complete-Worker {
    $w = $script:Worker
    $script:Worker = $null
    try { [void]$w.PS.EndInvoke($w.Handle) } catch { Write-UiLog "Worker error: $($_.Exception.Message)" 'Error' }
    foreach ($err in @($w.PS.Streams.Error)) { Write-UiLog "$err" 'Error' }
    Drain-Queues
    try { $w.PS.Dispose(); $w.Runspace.Dispose() } catch { }
    switch ($w.Kind) {
        'status' { if ($sync.StatusResult) { Fill-StatusList $sync.StatusResult } }
        'run'    { Show-RunSummary -Kind 'run' }
        'revert' { Show-RunSummary -Kind 'revert' }
    }
    $ui.Progress.Value = 0
    Set-UiBusy $false
    if (-not $script:Worker) { $ui.Timer.Stop() }
}

function Reset-RunState {
    $sync.Cancel = $false
    $sync.Progress = 0
    $sync.NeedReboot = $false
    $sync.Advice.Clear()
    $sync.PostLaunch.Clear()
    $sync.Results.Clear()
}

function Start-StatusRefresh {
    if ($script:Worker) { return }
    $ui.StatusInfo.Text = 'Collecting system status ...'
    Set-UiBusy $true
    Start-Worker -Kind 'status' -Script { $sync.StatusResult = Get-SystemStatus }
}

# ---- build the window ---------------------------------------------------------------------
$form = New-Control Form @{
    Text = "Windows 10 Security Pack $ToolVersion"
    StartPosition = 'CenterScreen'
    Size = New-Object System.Drawing.Size(1060, 780)
    MinimumSize = New-Object System.Drawing.Size(900, 640)
    Font = New-Object System.Drawing.Font('Segoe UI', 9)
    AutoScaleMode = 'Dpi'
}
try { $form.Icon = [System.Drawing.SystemIcons]::Shield } catch { }
$ui.Form = $form
$ui.LogFont = New-Object System.Drawing.Font('Consolas', 9)
$ui.LogBold = New-Object System.Drawing.Font('Consolas', 9, [System.Drawing.FontStyle]::Bold)

# Header
$header = New-Control Panel @{ Dock = 'Top'; Height = 66 }
$title = New-Control Label @{
    Text = 'Windows 10 Security Pack'; AutoSize = $true; Location = New-Object System.Drawing.Point(12, 8)
    Font = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
}
$subtitle = New-Control Label @{
    Text = 'Hardening and free security tools for Windows 10 after end of support (14 Oct 2025). Tick the tasks you want, then press "Run selected". Everything is logged.'
    AutoSize = $true; Location = New-Object System.Drawing.Point(14, 40); ForeColor = [System.Drawing.Color]::DimGray
}
$header.Controls.AddRange(@($title, $subtitle))

# Bottom button bar
$bar = New-Control Panel @{ Dock = 'Bottom'; Height = 46; Padding = New-Object System.Windows.Forms.Padding(10, 8, 10, 8) }
$progress = New-Control ProgressBar @{ Dock = 'Fill'; Minimum = 0; Maximum = 100; Value = 0; Style = 'Continuous' }
$flow = New-Control FlowLayoutPanel @{ Dock = 'Right'; Width = 770; FlowDirection = 'LeftToRight'; WrapContents = $false; Padding = New-Object System.Windows.Forms.Padding(8, 0, 0, 0) }
function New-BarButton([string]$Text, [int]$Width = 120) {
    New-Control Button @{ Text = $Text; Width = $Width; Height = 30; Margin = New-Object System.Windows.Forms.Padding(4, 0, 0, 0) }
}
$ui.BtnRun      = New-BarButton 'Run selected' 130
$ui.BtnRun.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$ui.BtnCancel   = New-BarButton 'Cancel' 80
$ui.BtnCancel.Enabled = $false
$ui.BtnRevert   = New-BarButton 'Revert hardening...' 130
$ui.BtnSecurity = New-BarButton 'Windows Security' 120
$ui.BtnUpdate   = New-BarButton 'Windows Update / ESU' 145
$ui.BtnLog      = New-BarButton 'Open log folder' 115
$flow.Controls.AddRange(@($ui.BtnRun, $ui.BtnCancel, $ui.BtnRevert, $ui.BtnSecurity, $ui.BtnUpdate, $ui.BtnLog))
$bar.Controls.Add($progress)
$bar.Controls.Add($flow)
$progress.BringToFront()
$ui.Progress = $progress

# Log panel
$logBox = New-Control GroupBox @{ Dock = 'Bottom'; Height = 210; Text = 'Activity log'; Padding = New-Object System.Windows.Forms.Padding(8, 4, 8, 8) }
$rtb = New-Control RichTextBox @{ Dock = 'Fill'; ReadOnly = $true; BackColor = [System.Drawing.SystemColors]::Window; Font = $ui.LogFont; WordWrap = $true; DetectUrls = $false; HideSelection = $false }
$logBox.Controls.Add($rtb)
$ui.Log = $rtb

# Tabs
$tabs = New-Control TabControl @{ Dock = 'Fill'; Padding = New-Object System.Drawing.Point(14, 6) }
$tabTasks = New-Control TabPage @{ Text = 'Tasks'; Padding = New-Object System.Windows.Forms.Padding(8) }
$tabStatus = New-Control TabPage @{ Text = 'System status'; Padding = New-Object System.Windows.Forms.Padding(8) }
$tabs.TabPages.AddRange(@($tabTasks, $tabStatus))

# Tasks tab: list on the left, description on the right
$split = New-Control SplitContainer @{ Dock = 'Fill'; Orientation = 'Vertical'; SplitterWidth = 6; FixedPanel = 'Panel2' }
$lv = New-Control ListView @{
    Dock = 'Fill'; View = 'Details'; CheckBoxes = $true; FullRowSelect = $true; HideSelection = $false
    MultiSelect = $false; GridLines = $false; ShowGroups = $true; ShowItemToolTips = $true
}
[void]$lv.Columns.Add('Task', 470)
[void]$lv.Columns.Add('Status', 110)
$ui.List = $lv
$ui.ItemsById = @{}
$groups = @{}
foreach ($t in $TaskDefs) {
    if ($t.Hidden) { continue }
    if (-not $groups.ContainsKey($t.Group)) {
        $g = New-Object System.Windows.Forms.ListViewGroup($t.Group, 'Left')
        $groups[$t.Group] = $g
        [void]$lv.Groups.Add($g)
    }
    $item = New-Object System.Windows.Forms.ListViewItem($t.Name)
    [void]$item.SubItems.Add('')
    $item.Group = $groups[$t.Group]
    $item.Tag = $t.Id
    $item.Checked = [bool]$t.Recommended
    $item.ToolTipText = $t.Name
    [void]$lv.Items.Add($item)
    $ui.ItemsById[$t.Id] = $item
}
$selectBar = New-Control FlowLayoutPanel @{ Dock = 'Bottom'; Height = 36; FlowDirection = 'LeftToRight'; Padding = New-Object System.Windows.Forms.Padding(0, 4, 0, 0) }
$ui.BtnRecommended = New-Control Button @{ Text = 'Select recommended'; Width = 140; Height = 28 }
$ui.BtnAll  = New-Control Button @{ Text = 'Select all'; Width = 90; Height = 28 }
$ui.BtnNone = New-Control Button @{ Text = 'Select none'; Width = 90; Height = 28 }
$ui.SelCount = New-Control Label @{ Text = ''; AutoSize = $true; Padding = New-Object System.Windows.Forms.Padding(10, 7, 0, 0); ForeColor = [System.Drawing.Color]::DimGray }
$selectBar.Controls.AddRange(@($ui.BtnRecommended, $ui.BtnAll, $ui.BtnNone, $ui.SelCount))
$split.Panel1.Controls.Add($lv)
$split.Panel1.Controls.Add($selectBar)
$lv.BringToFront()

$detailTitle = New-Control Label @{ Dock = 'Top'; Height = 44; Text = 'Select a task to see what it does'; Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold); Padding = New-Object System.Windows.Forms.Padding(6, 4, 4, 0) }
$detailMeta = New-Control Label @{ Dock = 'Top'; Height = 20; Text = ''; ForeColor = [System.Drawing.Color]::DimGray; Padding = New-Object System.Windows.Forms.Padding(6, 0, 4, 0) }
$detail = New-Control TextBox @{ Dock = 'Fill'; Multiline = $true; ReadOnly = $true; ScrollBars = 'Vertical'; BackColor = [System.Drawing.SystemColors]::Window; BorderStyle = 'None'; Font = New-Object System.Drawing.Font('Segoe UI', 9.5) }
$split.Panel2.Controls.Add($detail)
$split.Panel2.Controls.Add($detailMeta)
$split.Panel2.Controls.Add($detailTitle)
$detail.BringToFront()
$ui.DetailTitle = $detailTitle; $ui.DetailMeta = $detailMeta; $ui.Detail = $detail
$tabTasks.Controls.Add($split)

# Status tab
$statusTop = New-Control Panel @{ Dock = 'Top'; Height = 40 }
$ui.BtnRefresh = New-Control Button @{ Text = 'Refresh status'; Width = 120; Height = 28; Location = New-Object System.Drawing.Point(0, 4) }
$ui.StatusInfo = New-Control Label @{ AutoSize = $true; Location = New-Object System.Drawing.Point(130, 10); ForeColor = [System.Drawing.Color]::DimGray; Text = 'Status is collected when the window opens.' }
$statusTop.Controls.AddRange(@($ui.BtnRefresh, $ui.StatusInfo))
$slv = New-Control ListView @{ Dock = 'Fill'; View = 'Details'; FullRowSelect = $true; GridLines = $true; ShowItemToolTips = $true; HideSelection = $false; MultiSelect = $false }
[void]$slv.Columns.Add('Check', 290)
[void]$slv.Columns.Add('Result', 1000)
$ui.StatusList = $slv
$tabStatus.Controls.Add($slv)
$tabStatus.Controls.Add($statusTop)
$slv.BringToFront()

# Assemble (Fill control first so it takes the remaining space)
$form.Controls.Add($tabs)
$form.Controls.Add($logBox)
$form.Controls.Add($bar)
$form.Controls.Add($header)
$tabs.BringToFront()

$ui.Timer = New-Object System.Windows.Forms.Timer
$ui.Timer.Interval = 200

# ---- events -------------------------------------------------------------------------------
function Update-SelectionCount {
    $n = $ui.List.CheckedItems.Count
    $ui.SelCount.Text = "$n task(s) selected"
}

$ui.Timer.add_Tick({
    Drain-Queues
    $ui.Progress.Value = [Math]::Min(100, [Math]::Max(0, [int]$sync.Progress))
    if ($script:Worker -and $script:Worker.Handle.IsCompleted) { Complete-Worker }
})

$lv.add_SelectedIndexChanged({
    if ($ui.List.SelectedItems.Count -eq 0) { return }
    $id = $ui.List.SelectedItems[0].Tag
    $t = $sync.TaskDefs | Where-Object { $_.Id -eq $id } | Select-Object -First 1
    if (-not $t) { return }
    $ui.DetailTitle.Text = $t.Name
    $ui.DetailMeta.Text = 'id: {0}   -   {1}' -f $t.Id, $(if ($t.Recommended) { 'recommended for most PCs' } else { 'optional - read before enabling' })
    $ui.Detail.Text = ($t.Description -replace "(?<!\r)\n", "`r`n")
})
$lv.add_ItemChecked({ Update-SelectionCount })

$ui.BtnRecommended.add_Click({
    foreach ($item in $ui.List.Items) {
        $t = $sync.TaskDefs | Where-Object { $_.Id -eq $item.Tag } | Select-Object -First 1
        $item.Checked = [bool]$t.Recommended
    }
})
$ui.BtnAll.add_Click({ foreach ($item in $ui.List.Items) { $item.Checked = $true } })
$ui.BtnNone.add_Click({ foreach ($item in $ui.List.Items) { $item.Checked = $false } })

$ui.BtnRun.add_Click({
    if ($script:Worker) { return }
    $ids = @($ui.List.CheckedItems | ForEach-Object { $_.Tag })
    if ($ids.Count -eq 0) {
        [void][System.Windows.Forms.MessageBox]::Show($ui.Form, 'Tick at least one task first.', 'Nothing selected', 'OK', 'Information')
        return
    }
    $names = ($sync.TaskDefs | Where-Object { $ids -contains $_.Id } | ForEach-Object { '  - ' + $_.Name }) -join "`r`n"
    $msg = "Run these tasks now?`r`n`r`n$names`r`n`r`nChanges are logged to:`r`n$($sync.LogFile)"
    $r = [System.Windows.Forms.MessageBox]::Show($ui.Form, $msg, 'Confirm', 'YesNo', 'Question')
    if ($r -ne 'Yes') { return }
    Reset-RunState
    foreach ($item in $ui.List.Items) { Update-ItemStatus $item.Tag $(if ($ids -contains $item.Tag) { 'Queued' } else { '' }) }
    Set-UiBusy $true
    Start-Worker -Kind 'run' -Script { param($ids) Invoke-TaskRun -Ids $ids } -Arguments @(, $ids)
})

$ui.BtnCancel.add_Click({
    if (-not $script:Worker) { return }
    $sync.Cancel = $true
    $ui.BtnCancel.Enabled = $false
    Write-UiLog 'Cancel requested - the current task will finish, remaining tasks are skipped.' 'Warn'
})

$ui.BtnRevert.add_Click({
    if ($script:Worker) { return }
    $msg = "This restores the registry values, Attack Surface Reduction rules, DNS servers and NetBIOS/Remote Desktop settings changed by this tool (from its backups in $StateDir) and turns Controlled Folder Access off.`r`n`r`nDefender settings, the firewall, SMBv1/PowerShell 2.0 removal and installed programs are kept.`r`n`r`nContinue?"
    $r = [System.Windows.Forms.MessageBox]::Show($ui.Form, $msg, 'Revert hardening', 'YesNo', 'Warning', 'Button2')
    if ($r -ne 'Yes') { return }
    Reset-RunState
    Set-UiBusy $true
    Start-Worker -Kind 'revert' -Script { Invoke-TaskRun -Ids @('revert') }
})

$ui.BtnRefresh.add_Click({ Start-StatusRefresh })
$ui.BtnSecurity.add_Click({ try { Start-Process 'windowsdefender:' } catch { Write-UiLog "Could not open Windows Security: $($_.Exception.Message)" 'Warn' } })
$ui.BtnUpdate.add_Click({ try { Start-Process 'ms-settings:windowsupdate' } catch { Write-UiLog "Could not open Windows Update settings: $($_.Exception.Message)" 'Warn' } })
$ui.BtnLog.add_Click({ try { Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f (Split-Path -Parent $sync.LogFile)) } catch { } })

$form.add_Shown({
    try { $split.SplitterDistance = [int]($split.Width * 0.58) } catch { }
    Update-SelectionCount
    if ($ui.List.Items.Count -gt 0) { $ui.List.Items[0].Selected = $true }
    Write-UiLog "Windows 10 Security Pack $ToolVersion started. Log: $($sync.LogFile)" 'Step'
    $build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    if ($build -ge 22000) {
        Write-UiLog 'This appears to be Windows 11. The tool is designed for Windows 10; most tasks still work, but ESU/0patch items do not apply.' 'Warn'
    }
    Write-UiLog 'Tip: Windows 10 consumer ESU is still FREE until 12 Oct 2027 (Settings > Windows Update > Enroll now, needs 22H2 and a Microsoft account). Check the "System status" tab.' 'Info'
    Start-StatusRefresh
})

$form.add_FormClosing({
    if ($script:Worker) {
        $r = [System.Windows.Forms.MessageBox]::Show($ui.Form, 'A task is still running. Closing now may leave an installer or update half-finished. Close anyway?', 'Task running', 'YesNo', 'Warning', 'Button2')
        if ($r -ne 'Yes') { $_.Cancel = $true; return }
        $sync.Cancel = $true
        try { $script:Worker.PS.Stop() } catch { }
    }
    $ui.Timer.Stop()
})

try {
    [System.Windows.Forms.Application]::Run($form)
} catch {
    [void][System.Windows.Forms.MessageBox]::Show("The tool hit an unexpected error:`r`n`r`n$($_.Exception.Message)`r`n`r`nLog: $($sync.LogFile)", 'Windows 10 Security Pack', 'OK', 'Error')
    try { [IO.File]::AppendAllText($sync.LogFile, "FATAL: $($_ | Out-String)", [Text.Encoding]::UTF8) } catch { }
}
