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
(`registry-backup.json`, `asr-backup.json`, `cfa-backup.json`, `dns-backup.json`, `netbios-backup.json`,
`rdp-firewall-backup.json`), together with the `downloads\` folder for installers. On every start the tool
makes this folder writable by administrators only; anything in it that a non-administrator account created
or could change is renamed to `*.untrusted_<date>` and never used.

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
   Each task ends as **Done**, **Partial** (it ran, but something in it did not take effect - the log says
   what, e.g. one Windows update failed or a policy overrides a Defender setting) or **Failed**.

Command-line use (also elevates itself):

```powershell
.\Win10SecurityPack.ps1 -ListTasks
.\Win10SecurityPack.ps1 -Tasks restore,defender,asr,firewall,legacy,harden,wu
```

Started without administrator rights, the command opens an elevated window, waits for it and returns its exit
code: `0` all tasks done, `1` at least one task failed or was only partly done, `2` unknown task id,
`3` the state folder could not be secured, `1223` the UAC prompt was declined.

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

* **Revert hardening...** - puts back exactly what the tool changed, from its backups: registry values, the
  ASR rules it set (rules configured by anyone else are not touched), Controlled Folder Access (to the mode
  it had before), DNS servers, each adapter's NetBIOS mode and each Remote Desktop firewall rule's own
  on/off state. What cannot be restored right now - an unplugged adapter, a per-user setting of an account
  that is not signed in, a failed write - stays in the backup and is tried again by the next revert; the
  revert is then reported as *Partial*. Defender settings, the firewall, SMBv1/PS2 removal and installed
  programs are intentionally left alone (they are safe to keep).
* **Windows Security** / **Windows Update / ESU** - open the corresponding Windows pages.
* **Open log folder** - every message is written to the log file the moment it happens (not when the window
  shows it), so the log is complete even after a crash. If the file cannot be written, the window says so.

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
* The tool only downloads from the vendors' own domains over HTTPS, into its administrator-only folder, and
  refuses to run any file whose Authenticode signature is invalid or whose publisher name is not exactly the
  vendor's (Microsoft Corporation, Mozilla Corporation, Malwarebytes Inc., and ACROS - the company behind
  0patch - under its registered Slovenian name). Every
  program file in the Sysinternals archives is checked before anything is copied to Program Files. winget
  packages are hash-verified by winget itself.
* Settings written under `HKEY_CURRENT_USER` (AutoPlay, file extensions, Sysinternals EULA) apply to the
  account that approved the UAC prompt. On a PC where a standard user elevates with a different admin
  account, the tool logs a warning about this. The backup records which account they belong to, so Revert
  puts them back in that account, whichever administrator runs it (that account must be signed in).
* The firewall check and the status tab read the firewall policy *in effect*, so a Group Policy or another
  firewall product that overrides the local settings shows up as a problem instead of being hidden.
* If a **third-party antivirus** is installed, Defender runs in passive mode and the Defender/ASR tasks have
  little effect; the status tab and the log tell you so.
* Some hardening can interfere with legitimate software: ASR rules (check *Protection history* in Windows
  Security and add exclusions), LSA Protection (very old smart-card/authentication plug-ins), NetBIOS/LLMNR
  (old NAS/printers by name), Controlled Folder Access (unknown apps saving to Documents). Everything in
  that list is undone by **Revert hardening**, with one caveat: on a PC with UEFI Secure Boot, Windows may
  also store the LSA Protection setting in a firmware variable. Revert restores the registry value, but LSA
  Protection can then stay on until that variable is cleared with Microsoft's
  [LSA Protected Process Opt-out tool](https://www.microsoft.com/download/details.aspx?id=40897).
* **Revert hardening** only undoes what the tool itself changed (see *Buttons* above). Changes made with
  version 1.0.x were not fully recorded: for those, Controlled Folder Access is left as it is (turn it off in
  Windows Security if you want), NetBIOS goes back to the Windows default and the Remote Desktop rules are
  re-enabled only if Remote Desktop itself is allowed.
* The ESU enrolment detection reads a registry key that is community-documented, not officially documented;
  treat "not enrolled" as "check Settings", not as gospel.
* The SmartScreen, Edge and LLMNR settings are written as *policies* (the same keys Group Policy uses), so
  Windows Security and Edge will show "Some settings are managed by your organization" for those items.
  That is cosmetic. If the ESU enrolment wizard ever refuses with a similar message, run **Revert hardening**
  (which removes those policy values), enrol, then run the hardening again.

## Changelog

**1.1.0** - safer backups and revert, honest results:

* The state folder `C:\ProgramData\Win10SecurityPack` is made administrator-only on every start; content a
  standard user could have planted there is set aside unused. Installers are downloaded there instead of
  `%TEMP%`. Revert only writes registry values from a fixed list and validates every backup entry.
* Publisher check: the certificate's name must be exactly the vendor's, not just contain it. All program
  files of the Sysinternals archives are verified before they are installed.
* Revert: restores only the ASR rules the tool set (after reading the backup, not before); puts Controlled
  Folder Access back to its previous mode instead of always turning it off; restores each adapter's NetBIOS
  mode and each Remote Desktop rule's state; puts per-user settings back in the account they came from;
  finds adapters by GUID only. Anything that could not be restored stays in the backup for the next revert.
* No task changes DNS, ASR, Controlled Folder Access, NetBIOS or registry values when its backup cannot be
  read or the original values cannot be determined.
* New *Partial* result: Windows Update failures, Defender/ASR settings that did not take effect, firewall
  settings overridden by policy, failed `winget upgrade` packages, an unreadable Defender detection history and
  features that could not be disabled are no longer reported as success. The command line exits with `1`.
* The firewall is checked against the policy in effect; a stopped 0patch service is shown red.
* The SMBv1/PowerShell 2.0 task stops if DISM cannot list the optional features, instead of assuming they
  are absent, and checks the result.
* Command line without administrator rights: waits for the elevated run and returns its exit code;
  `1223` when UAC is declined.
* The log file is written immediately from the background task, not when the window gets to it; write
  errors are shown.

**1.0.1** - bug fixes, no change to what the tasks do:

* *Revert hardening* could not read its own backups on Windows PowerShell 5.1 (a JSON array comes back as
  one object there), so registry values and, with more than one network adapter, DNS servers were not
  restored correctly, and the registry backup file itself was damaged by each new entry. Backups are now
  read and written correctly; files written by 1.0.0 are still read as far as they are intact.
* *Revert hardening* no longer removes Attack Surface Reduction rules when the ASR task was never run, and
  no longer enables the Remote Desktop firewall rules on a PC where Remote Desktop was off before.
* The task list showed "Left" as the header of every group.
* The window no longer opens taller than a 1366x768 screen (the button bar was off-screen).
* *System status*: no failure of the Defender rows when there are no definitions, the ASR row no longer
  counts one rule when none is configured, Malwarebytes is detected whatever its executable is called,
  and a failed refresh is no longer shown as fresh data.
* Quad9 DNS: an adapter that was offline during an earlier run is now added to the backup; DNS is restored
  by adapter GUID, so a changed interface index no longer matters.
* Firefox: the vendor-download fallback fetched the 64-bit installer on 32-bit Windows.
* SMBv1/PowerShell 2.0 task: an optional feature that the Windows build does not have is skipped whichever
  way DISM reports it.
* Closing the window while only the status check is running no longer warns about a half-finished installer.

## License

Free software under the **GNU General Public License v3.0** (or any later version) - see [LICENSE](LICENSE).
The tool is provided *without any warranty*; it changes system security settings, so read the task
descriptions and keep the restore point it creates.

## Sources

* Microsoft - [Windows 10 Extended Security Updates](https://www.microsoft.com/windows/extended-security-updates)
* Microsoft - [Attack surface reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
* Microsoft - [End of Windows 10 support: what Defender customers need to know](https://techcommunity.microsoft.com/blog/microsoftdefenderatpblog/end-of-windows-10-support-what-defender-customers-need-to-know/4461349)
* Microsoft - [Install winget / Microsoft.WinGet.Client](https://learn.microsoft.com/windows/package-manager/winget/)
* 0patch - [Windows 10 post-EOS](https://0patch.com/Win10.html), [Pricing](https://0patch.com/pricing.html), [Long Live Windows 10](https://0patch.com/blog/long-live-windows-10-with-0patch)
* Mozilla - [What Windows 10 end of support means for Firefox users](https://support.mozilla.org/kb/firefox-support-windows-10-end-support)
* Microsoft Q&A - [Am I enrolled in Extended Security Updates?](https://learn.microsoft.com/en-us/answers/questions/5567587/am-i-enrolled-in-extended-security-updates) (ConsumerESU registry key)
