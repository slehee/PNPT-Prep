# Web Proxy Guide

An intercepting proxy sits between a test browser and the target application. It records requests and responses, lets you modify them safely, and makes authorization, session, and input-handling behavior easier to compare. Burp Suite and OWASP ZAP provide the same core workflow even when their menu names differ.

{% hint style="warning" %}
Configure target scope before testing. Intercept, replay, and automate requests only against authorized hosts, and remove the proxy CA certificate from normal browser profiles after the engagement.
{% endhint %}

## Where the proxy fits

1. Discover hosts, endpoints, and parameters with [Web Enumeration](web-enumeration.md).
2. Capture normal application behavior in the proxy history.
3. Send one request to a manual editor such as Burp Repeater or ZAP Requester.
4. Change one property at a time and compare responses.
5. Preserve the original request, modified request, and response as evidence.

| Proxy task | Apply it to |
| --- | --- |
| Change object identifiers, methods, and headers | [HTTP Attacks](http-attacks.md) |
| Place payloads in each reflected or stored input | [Cross-Site Scripting](xss.md) |
| Compare syntax errors, booleans, and response timing | [SQL Injection](sql-injection.md) |
| Modify names, MIME types, and multipart boundaries | [File Upload](file-upload.md) |
| Test URLs, templates, XML, and serialized input | [Server-Side Attacks](server-side-attacks.md) |

## Build an isolated test browser

Use a separate browser profile so proxy settings, cookies, and trusted certificates do not affect normal browsing.

Default local listeners:

| Tool | Listener |
| --- | --- |
| Burp Suite | `127.0.0.1:8080` |
| OWASP ZAP | `127.0.0.1:8080` |

Configure the browser to use the listener for HTTP and HTTPS. With Burp running, visit `http://burp`, export the CA certificate, and trust it only in the test profile. ZAP exposes its certificate under Network settings.

After testing:

- Remove the imported CA certificate
- Clear the test profile's cookies and storage
- Delete captured credentials from project files or redact them before sharing
- Restore system proxy settings

## Scope first

Add only authorized hosts and paths to scope. Scope controls reduce accidental traffic to third-party analytics, identity providers, and unrelated APIs.

In Burp:

1. Open **Target > Site map**.
2. Select the authorized host and choose **Add to scope**.
3. Configure Proxy history and interception to show in-scope traffic only.

In ZAP, create a **Context**, include the authorized URL patterns, and exclude logout, destructive, or third-party routes as needed.

{% hint style="info" %}
A scope filter is a guardrail, not authorization. Keep the written target list and prohibited actions available while testing.
{% endhint %}

## Capture and replay

Browse the application normally before changing traffic. In the HTTP history, identify:

- Authentication and session-establishment requests
- Object identifiers and ownership boundaries
- State-changing methods such as `POST`, `PUT`, `PATCH`, and `DELETE`
- Hidden fields, JSON properties, and multipart uploads
- Redirects, cache behavior, and security headers
- Requests made by JavaScript rather than visible forms

Send a request to Repeater or Requester and preserve an untouched baseline tab. Duplicate it for each hypothesis so response differences remain attributable to one change.

A useful comparison records:

| Property | Baseline | Modified |
| --- | --- | --- |
| Method and path | Original request | One deliberate change |
| Identity | Original session | Authorized comparison account or no session |
| Input | Valid application value | Boundary or test value |
| Status and length | Expected response | Difference to investigate |
| Body evidence | Normal object/result | Unauthorized data, error, or changed behavior |

## Read the request structurally

Treat each request as separate control surfaces:

```http
POST /api/profile/<OBJECT_ID> HTTP/1.1
Host: <TARGET>
Authorization: Bearer <TOKEN>
Content-Type: application/json

{"displayName":"<VALUE>","role":"user"}
```

Test method, path, query, headers, cookies, and body independently. When the application uses HTTP/2, let the proxy handle framing rather than manually copying pseudo-headers into an HTTP/1 request.

## Match and Replace

Match-and-replace rules apply repeatable changes while browsing. Use narrow scope and an unmistakable value so the rule cannot silently alter unrelated traffic.

Common authorized uses:

| Purpose | Match | Replacement |
| --- | --- | --- |
| Mark test traffic | Existing or absent header | `X-Assessment-ID: <ENGAGEMENT_ID>` |
| Test header trust | `X-Forwarded-For` | `<AUTHORIZED_TEST_IP>` |
| Exercise alternate content path | `Content-Type` | An expected supported media type |
| Inspect client-side controls | `disabled` or `readonly` in a response | Remove locally, then verify server enforcement |

Client-side changes do not prove a vulnerability. The finding is the server accepting an operation it should reject.

## Decoder and Inspector

Use Decoder or ZAP's Encode/Decode/Hash tool to inspect one transformation at a time.

| Encoding | Typical location |
| --- | --- |
| URL encoding | Paths, query strings, form bodies |
| HTML entities | Rendered markup and attributes |
| Base64 | Cookies, tokens, serialized values, binary transport |
| Hex | Binary fields and escaped payloads |
| Unicode escapes | JSON and JavaScript strings |

Common URL characters:

| Character | Encoded |
| --- | --- |
| Space | `%20` or `+` in form data |
| `&` | `%26` |
| `#` | `%23` |
| `=` | `%3D` |
| `?` | `%3F` |
| `/` | `%2F` |
| `+` | `%2B` |

Inspector is useful for viewing decoded cookies, parameters, and nested encodings in context. Record each decoding layer so another tester can reproduce the result.

## Cookies and sessions

Start by comparing sessions from two accounts you control. Record cookie attributes and server behavior before editing values.

Check:

- Whether session identifiers rotate after login and privilege changes
- Whether logout invalidates the server-side session
- `Secure`, `HttpOnly`, and `SameSite` attributes
- Whether unsigned client-side state controls identity or authorization
- Whether changing an object ID succeeds across authorized test accounts

A Base64 value is encoding, not integrity protection. Decode it for inspection, but do not assume modifying and re-encoding it will be accepted. Signed or encrypted values should fail closed when altered.

{% hint style="danger" %}
Never place live session tokens, passwords, or personal data in shared notes. Redact secrets while retaining enough request structure to reproduce the finding.
{% endhint %}

## Header and trust-boundary testing

Some applications make authorization or routing decisions from client-controlled headers. Within scope, test whether removing or changing these values affects access:

```http
X-Forwarded-For: <AUTHORIZED_TEST_IP>
X-Real-IP: <AUTHORIZED_TEST_IP>
X-Forwarded-Host: <TARGET>
X-Forwarded-Proto: https
Referer: https://<TARGET>/
Origin: https://<TARGET>
```

A changed response is a lead, not proof. Confirm that the backend trusts the header and document the affected control. Avoid sending internal addresses or third-party domains unless that behavior is explicitly authorized.

## Burp and ZAP workflow map

| Task | Burp Suite | OWASP ZAP |
| --- | --- | --- |
| Browse captured traffic | Proxy > HTTP history | History tab |
| Pause and edit traffic | Proxy > Intercept | Break request/response |
| Manual replay | Repeater | Requester / Manual Request Editor |
| Automated replacement | Proxy settings > Match and Replace | Options > Replacer |
| Decode values | Decoder / Inspector | Encode/Decode/Hash |
| Organize target scope | Target > Scope | Contexts |

Useful Burp shortcuts vary by keymap, but common defaults include `Ctrl+R` to send to Repeater and `Ctrl+I` to send to Intruder. Confirm shortcuts in the installed version rather than relying on memory.

## Evidence and cleanup

For each confirmed issue, retain:

- The unmodified baseline request and response
- The minimum modified request that demonstrates the issue
- Account roles and ownership assumptions
- Server response, timing, and relevant headers
- A concise explanation of the missing control

Export only the required traffic. Redact secrets, remove out-of-scope hosts, delete temporary Match and Replace rules, and remove the test CA certificate when the engagement ends.

## References

- [Burp Suite documentation](https://portswigger.net/burp/documentation)
- [OWASP ZAP documentation](https://www.zaproxy.org/docs/)
- [Web Enumeration](web-enumeration.md)
- [HTTP Attacks](http-attacks.md)
