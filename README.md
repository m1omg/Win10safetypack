# Windows 10 Security Pack

A single-file PowerShell tool with a graphical interface that hardens a **Windows 10 PC that no longer
receives security updates** and installs free security tools. Everything it does is logged, direct
downloads are signature-checked, and the hardening it applies can be reverted from the same window.

---

## Read this first: you may still get free official updates

Windows 10 support ended on **14 October 2025**, but Microsoft's *consumer Extended Security Updates*
program was extended in June 2026 and now runs **until 12 October 2027**. Enrolment is still open and is
**free** if you let Windows Backup sync your settings (alternatives: 1,000 Microsoft Rewards points or a
one-time $30 purchase). Requirements: Windows 10 **22H2**, all current updates (including the "Licensing
Preparation Package" KB5126256), and an administrator **Microsoft account** on a PC that is not
domain-joined or MDM-managed.

Open **Settings > Update & Security > Windows Update** and look for **Enroll now**. The tool's
*System status* tab tells you whether the PC is enrolled, and the **Windows Update / ESU** button opens
that page. Official patches beat any third-party mitigation - this tool is for PCs that cannot or will
not enrol, and as a complement for those that do.

Sources: [Microsoft ESU page](https://www.microsoft.com/windows/extended-security-updates),
[Thurrott](https://www.thurrott.com/?p=337939), [Pureinfotech](https://pureinfotech.com/windows-10-esu-extended-2027-microsoft-update/).

---

## What is in the box

| File | Purpose |
|---|---|
| `Run-Win10SecurityPack.cmd` | Double-click launcher. Starts PowerShell with the right flags and triggers the UAC prompt. |
| `Win10SecurityPack.ps1` | The tool itself (GUI + command-line mode). |
| `logs\` | Created on first run; one log file per session. (Falls back to `C:\ProgramData\Win10SecurityPack\logs` if the folder is read-only.) |

Backups the tool keeps for *Revert hardening* live in `C:\ProgramData\Win10SecurityPack\`
(`registry-backup.json`, `asr-backup.json`, `dns-backup.json`).

## How to run it

1. Get the files onto the Windows 10 PC: on GitHub click **Code > Download ZIP**, then extract the ZIP
   (right-click > *Extract All...*). A USB stick or network share works just as well.
2. Double-click **`Run-Win10SecurityPack.cmd`** and accept the UAC prompt.
   *If SmartScreen complains about an unknown publisher, choose "More info" > "Run anyway" - the script is plain text, you can read it.*
3. The window opens on the **Tasks** tab with the recommended tasks pre-ticked. Click a task to read exactly
   what it changes in the right-hand pane.
4. Check the **System status** tab (red = fix this, orange = worth attention, green = fine).
5. Press **Run selected**, confirm, and watch the activity log. The window stays responsive; **Cancel** stops
   after the current task.
6. When it finishes you get a summary with manual follow-up steps, and a restart prompt if one is needed.

Command-line use (also elevates itself):

```powershell
.\Win10SecurityPack.ps1 -ListTasks
.\Win10SecurityPack.ps1 -Tasks restore,defender,asr,firewall,legacy,harden,wu
```

## The tasks

Default = ticked when the window opens. Everything is explained again inside the tool.

### 1. Before changing anything

| Task | Default | What it does |
|---|---|---|
| **Create a System Restore point** | on | Enables System Protection on the Windows drive if needed and creates a restore point (lifting the one-per-24-hours limit for this call). |

### 2. Windows built-in protection

| Task | Default | What it does |
|---|---|---|
| **Microsoft Defender: enable, update and tighten** | on | Starts the service if stopped; turns on real-time, behaviour, script, download, archive and removable-drive scanning; cloud protection at block level *High*; PUA (adware/bundler) blocking; Network Protection; definition checks every 4 h and an immediate update. Defender definitions keep flowing on Windows 10 until at least **October 2028**. Warns if Tamper Protection is off (it can only be enabled by hand) or if a third-party AV has Defender in passive mode. |
| **Attack Surface Reduction rules** | on | 15 Microsoft ASR rules in **block** mode (LSASS credential theft, vulnerable drivers, WMI persistence, Office/Adobe/Outlook child processes, Office code injection, macro Win32 API calls, executables from e-mail, JS/VBS downloaders, obfuscated scripts, unsigned USB executables, Safe-Mode reboot, ransomware heuristics) plus 3 noisier rules in **audit** mode. Works on Windows 10 Home. Previous rule set is backed up. GUIDs come from [Microsoft's ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference). |
| **Controlled Folder Access** | off | Ransomware protection for Documents/Pictures/Desktop. Off by default because unknown-but-legitimate programs get blocked until you allow them in Windows Security. |
| **Windows Firewall on for all profiles** | on | Firewall service automatic and running; Domain/Private/Public enabled; inbound blocked by default; notifications on. Existing rules kept. |
| **Remove SMBv1 and PowerShell 2.0** | on | Disables the optional features `SMB1Protocol*` and `MicrosoftWindowsPowerShellV2*` (EternalBlue/WannaCry vector and AMSI-bypass engine). Restart may be needed. |
| **Safe defaults** | on | Registry: AutoRun/AutoPlay off for all drives; show file extensions; UAC *always notify* on the secure desktop; SmartScreen for apps/files = **Block** and SmartScreen + PUA blocking in Edge; WDigest clear-text caching off; anonymous SAM enumeration restricted; `NoLMHash`; **LSA Protection (RunAsPPL)**. All previous values are backed up. |
| **Network hardening** | off | LLMNR off, NetBIOS over TCP/IP off on all adapters, Remote Assistance off, incoming Remote Desktop off (+ its firewall rule group). Off by default: it can break name resolution for very old LAN devices and RDP access to this PC. |
| **Quad9 malware-blocking DNS** | off | Sets 9.9.9.9 / 149.112.112.112 (+ IPv6) on active physical adapters. Previous servers are saved for revert. Off by default because it overrides the router/ISP DNS. |
| **Install any remaining Windows Updates** | on | Windows Update API: searches, downloads and installs pending *software* updates (Defender platform/definitions, MSRT, missed pre-EOS cumulative updates, the ESU licensing-prep package, and ESU updates if enrolled). Feature upgrades and updates needing interaction are skipped. Slow. |

### 3. Free third-party tools

| Task | Default | What it does |
|---|---|---|
| **winget** | on | Skips if present. Otherwise bootstraps Windows Package Manager with Microsoft's `Microsoft.WinGet.Client` module (`Repair-WinGetPackageManager`). Needs 1809+. On failure it opens the Store page for *App Installer*. |
| **0patch Agent** | on | Downloads `https://dist.0patch.com/download/latestagent` (official), verifies the ACROS Authenticode signature, installs silently, and opens the 0patch Console at the end so you can sign in. **FREE plan = selected 0-day patches only; PRO (about 25 EUR/PC/year) = the full Windows 10 post-EOS patch stream, promised until at least October 2030.** The agent and the FREE account cost nothing; the comprehensive patches do not. ([0patch pricing](https://0patch.com/pricing.html), [0patch Win10](https://0patch.com/Win10.html)) |
| **Malwarebytes Free** | on | `winget install Malwarebytes.Malwarebytes`, or the official `MBSetup.exe` (`/VERYSILENT /NORESTART`, signature-checked) as fallback. 14-day Premium trial, then Free on-demand scanner. |
| **Sysinternals Autoruns + Process Explorer** | on | Official zips from `download.sysinternals.com`, extracted to `C:\Program Files\Sysinternals\`, executables signature-checked (Microsoft), EULA pre-accepted, Start-menu shortcuts under *Sysinternals*. |
| **Mozilla Firefox** | off | `winget install Mozilla.Firefox`, or the official installer for your UI language (signature-checked, `/S`). Mozilla supports Firefox on Windows 10 for the foreseeable future; Edge is supported until at least Oct 2028. |
| **Update all installed programs** | off | `winget upgrade --all --silent`. Run it regularly - outdated third-party apps are the main infection route on an unpatched OS. |

### 4. Scan

| Task | Default | What it does |
|---|---|---|
| **Defender quick scan** | on | `Start-MpScan -ScanType QuickScan`, then lists recent detections. |

### Buttons

* **Revert hardening...** - restores backed-up registry values, the previous ASR rule set, DNS servers and
  NetBIOS/RDP settings; turns Controlled Folder Access off. Defender settings, the firewall, SMBv1/PS2
  removal and installed programs are intentionally left alone (they are safe to keep).
* **Windows Security** / **Windows Update / ESU** - open the corresponding Windows pages.
* **Open log folder** - the session log is written line by line, so it is complete even after a crash.

## After the tool has run - things only you can do

1. **Enrol in free ESU** if the status tab says you are eligible (see top of this file).
2. **Turn on Tamper Protection**: Windows Security > Virus & threat protection > Manage settings.
3. **Sign in to 0patch** in the 0patch Console (tray icon). Decide whether PRO is worth ~25 EUR/year to you;
   it is currently the only source of OS-level patches besides ESU.
4. **Use a standard (non-administrator) account for daily work.** Most malware on a home PC runs with the
   rights of the signed-in user; UAC prompts for a separate admin password stop a lot of it.
5. **Keep applications updated** (`winget upgrade --all`, or the tool's *Update all installed programs* task),
   especially browsers, PDF readers, Office and runtimes.
6. **Use a modern browser with uBlock Origin** (Firefox or Edge). The browser is the main attack surface.
7. **Back up** your files offline or to the cloud. No hardening replaces a backup when ransomware wins.
8. **Plan the exit.** Hardening an unsupported OS buys time; it does not make it supported. Windows 11 on
   the same hardware (officially supported or not), a Linux desktop, or ChromeOS Flex are the long-term fixes.

## Safety notes and limitations

* **Requires** Windows 10 (22H2 recommended), Windows PowerShell 5.1 (built in) and an administrator account.
  It also runs on Windows 11, but the ESU/0patch items do not apply there.
* **Developed on Linux, reviewed by hand, not executed on a real Windows 10 machine before delivery.**
  Please run it first on a PC you can restore (the restore-point task runs first for a reason) and read the
  activity log. Report anything odd - the log file contains everything needed to diagnose it.
* The tool only downloads from the vendors' own domains over HTTPS and refuses to run any file whose
  Authenticode signature is invalid or from an unexpected publisher. winget packages are hash-verified by
  winget itself.
* Settings written under `HKEY_CURRENT_USER` (AutoPlay, file extensions, Sysinternals EULA) apply to the
  account that approved the UAC prompt. On a PC where a standard user elevates with a different admin
  account, the tool logs a warning about this.
* If a **third-party antivirus** is installed, Defender runs in passive mode and the Defender/ASR tasks have
  little effect; the status tab and the log tell you so.
* Some hardening can interfere with legitimate software: ASR rules (check *Protection history* in Windows
  Security and add exclusions), LSA Protection (very old smart-card/authentication plug-ins), NetBIOS/LLMNR
  (old NAS/printers by name), Controlled Folder Access (unknown apps saving to Documents). Everything in
  that list is undone by **Revert hardening**.
* The ESU enrolment detection reads a registry key that is community-documented, not officially documented;
  treat "not enrolled" as "check Settings", not as gospel.
* The SmartScreen, Edge and LLMNR settings are written as *policies* (the same keys Group Policy uses), so
  Windows Security and Edge will show "Some settings are managed by your organization" for those items.
  That is cosmetic. If the ESU enrolment wizard ever refuses with a similar message, run **Revert hardening**
  (which removes those policy values), enrol, then run the hardening again.

## Sources

* Microsoft - [Windows 10 Extended Security Updates](https://www.microsoft.com/windows/extended-security-updates)
* Microsoft - [Attack surface reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
* Microsoft - [End of Windows 10 support: what Defender customers need to know](https://techcommunity.microsoft.com/blog/microsoftdefenderatpblog/end-of-windows-10-support-what-defender-customers-need-to-know/4461349)
* Microsoft - [Install winget / Microsoft.WinGet.Client](https://learn.microsoft.com/windows/package-manager/winget/)
* 0patch - [Windows 10 post-EOS](https://0patch.com/Win10.html), [Pricing](https://0patch.com/pricing.html), [Long Live Windows 10](https://0patch.com/blog/long-live-windows-10-with-0patch)
* Mozilla - [What Windows 10 end of support means for Firefox users](https://support.mozilla.org/kb/firefox-support-windows-10-end-support)
* Microsoft Q&A - [Am I enrolled in Extended Security Updates?](https://learn.microsoft.com/en-us/answers/questions/5567587/am-i-enrolled-in-extended-security-updates) (ConsumerESU registry key)
