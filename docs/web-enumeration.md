# Web Enumeration

Every web port is an engagement of its own. Before you attack anything, map the app: who owns the domain, what subdomains and virtual hosts exist, what software is running and at what version, what directories and parameters are hidden, and where the app leaks its own internals. This is the hub page for the whole web workflow — most other pages start from a finding you surface here, and link back to it.

{% hint style="info" %}
Work outside-in: passive OSINT (no packets to the target) → active discovery (DNS, ports, tech) → content discovery (dirs, vhosts, params) → application-specific enumeration → hand each finding to the matching attack page. Note the exact version of everything — a precise version is the fastest route to a CVE.
{% endhint %}

{% hint style="warning" %}
Stay in scope. Passive OSINT against public services is generally low impact, but active brute-forcing, vhost fuzzing, and scanning must stay inside the engagement's authorized targets.
{% endhint %}

---

## Phase 1 — External Reconnaissance (OSINT)

Zero-touch intelligence. None of this sends packets from your IP to the target.

### Whois & domain registration

```bash
whois <TARGET>                          # registrar, contacts, name servers, dates
```

### Online fingerprinting portals

Fingerprint through public services — nothing hits the target from you.

| Service | URL pattern | What it returns |
| --- | --- | --- |
| Netcraft | `https://sitereport.netcraft.com/?url=<TARGET>` | Hosting history, OS, netblock, SSL history |
| Wappalyzer | `https://www.wappalyzer.com/lookup/<TARGET>/` | CMS/framework/analytics/CDN, no extension needed |
| Security Headers | `https://securityheaders.com/?q=<URL>` | HSTS/CSP/X-Frame grade — below `B` is report-worthy |
| SSL Labs | `https://www.ssllabs.com/ssltest/?d=<TARGET>` | TLS grade, ciphers, cert chain — `B` or worse = weak |
| BuiltWith | `https://builtwith.com/<TARGET>` | Deep tech-stack history |
| crt.sh | `https://crt.sh/?q=%25.<TARGET>` | Certificate Transparency subdomains |

### Shodan — the whole IPv4 space, pre-scanned

Shodan indexes service banners globally. Fastest way to find exposed services an org owns without touching them.

```
# Filters — paste into shodan.io
hostname:<TARGET>                       # any host whose reverse DNS matches
org:"<ORG>"                             # WHOIS-registered organisation
net:<CIDR>                              # a specific netblock
ssl.cert.subject.CN:"*.<TARGET>"        # hosts serving a wildcard cert
port:22 country:US product:OpenSSH      # protocol + geo + product
http.title:"admin login"                # admin panels
product:Confluence version:7.13         # version-specific CVE hunting
"Server: Apache/2.4.49"                 # exact banner (path-traversal era)
vuln:CVE-2021-44228                     # Log4Shell candidates
```

```bash
shodan init <API_KEY>
shodan search --limit 25 --fields ip_str,port,org 'hostname:<TARGET>'
shodan host <IP>                                    # single-host detail
shodan count 'product:MongoDB port:27017'           # cheap volume check
```

### GitHub OSINT — leaked secrets

Public repos leak credentials, keys, and internal config constantly.

```
# GitHub UI advanced search
"<company>" in:file
"<company>.com" language:python
filename:.env "AWS_SECRET"
"aws_access_key_id" "<company>"
"BEGIN RSA PRIVATE KEY" "<company>"
"password=" "<company>"
```

```bash
# Gitleaks — regex, offline
gitleaks detect --source=./repo -v --report-format=json --report-path=gitleaks.json

# TruffleHog — high-signal, verifies live where it can
trufflehog git https://github.com/<org>/<repo>
trufflehog github --org=<org>                       # every public repo in an org
trufflehog filesystem /path/to/checkout

# Gitrob — enumerates org members, scans their public repos
gitrob analyze <org>
```

### Search-engine dorking

```
site:<TARGET> filetype:pdf
site:<TARGET> inurl:admin
site:<TARGET> intitle:"index of"
site:<TARGET> inurl:config
site:<TARGET> "password"
site:<TARGET> inurl:php?id=            # candidate SQLi/IDOR params
site:pastebin.com "<TARGET>"           # leaked creds/tokens
```

Full operator and dork tables are in the [Reference](#reference-tables) section at the bottom.

### Historical content — Wayback

```bash
waybackurls <TARGET>                                        # go tool
curl -s "https://web.archive.org/cdx/search/cdx?url=*.<TARGET>&output=json" | jq
```

Old snapshots surface retired endpoints, dev paths, and parameters still wired up behind the current UI.

### People, emails, and breach data

```bash
theHarvester -d <TARGET> -b all                             # emails, subdomains, hosts
theHarvester -d <TARGET> -b duckduckgo,baidu,bing,yahoo,hunter,urlscan
linkedin2username -c "<COMPANY_NAME>"                       # org username list
```

| Source | URL | Use |
| --- | --- | --- |
| Dehashed | `https://dehashed.com/` | Breach data search (paid) |
| HaveIBeenPwned | `https://haveibeenpwned.com/` | Check breached emails |
| Grayhat Warfare | `https://grayhatwarfare.com/` | Exposed cloud buckets |
| Hunter.io | `https://hunter.io/` | Email format for a domain |
| [OSINT Industries](https://app.osint.industries/) | `https://app.osint.industries/` | Pivot across authorized phone, email, username, name, wallet, IP, domain, and image searches |

**Common email formats** to build a username list from a single known name:

| Format | Example |
| --- | --- |
| first.last | john.smith@domain.com |
| flast | jsmith@domain.com |
| firstl | johns@domain.com |
| first_last | john_smith@domain.com |

Also read job postings (LinkedIn/Indeed/Glassdoor) for stack intel — software versions, SIEM/EDR/AV vendors, cloud platform, legacy systems.

### Lab setup — /etc/hosts

The hosts file maps names to IPs, bypassing DNS — essential for lab and internal domains.

```bash
# Linux/macOS: /etc/hosts   |   Windows: C:\Windows\System32\drivers\etc\hosts
echo "<TARGET_IP>  target.local admin.target.local dev.target.local" | sudo tee -a /etc/hosts
```

Changes take effect immediately. Add every vhost you discover here or you can't reach it.

---

## Phase 2 — DNS & Subdomain Enumeration

### dig reference

| Command | Description |
| --- | --- |
| `dig <TARGET> A` | IPv4 address |
| `dig <TARGET> AAAA` | IPv6 address |
| `dig <TARGET> MX` | Mail servers |
| `dig <TARGET> NS` | Authoritative name servers |
| `dig <TARGET> TXT` | SPF/DKIM/DMARC records |
| `dig <TARGET> SOA` | Start of authority |
| `dig @<DNS_SERVER> <TARGET>` | Query a specific resolver |
| `dig +trace <TARGET>` | Full resolution path |
| `dig -x <IP>` | Reverse lookup |
| `dig +short <TARGET>` | Concise answer |

### Zone transfer (AXFR)

A misconfigured name server dumps its entire zone — every subdomain, IP, and record.

```bash
dig NS <TARGET> +short                  # find the authoritative servers first
dig axfr @<NS_SERVER> <TARGET>          # try AXFR on each
```

Most servers restrict transfers to secondaries, but always try — a hit is a full map of the estate.

### Passive subdomain discovery

```bash
subfinder -d <TARGET> -o subfinder.txt
amass enum -passive -d <TARGET> -o amass.txt
findomain -t <TARGET> -u findomain.txt
cat subfinder.txt amass.txt findomain.txt | sort -u > subs_all.txt
```

### Active brute-force & permutation

```bash
# amass with brute + active
amass enum -active -brute -d <TARGET> -o amass_active.txt

# dnsx resolve a wordlist
dnsx -silent -d <TARGET> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# gobuster DNS mode
gobuster dns -d <TARGET> -w <wordlist> -r <RESOLVER>

# altdns / dnsgen — permutations of known names (dev, stg, api prefixes)
altdns -i subs_all.txt -o /tmp/perms.txt -w words.txt

# massdns — high-speed resolution
cat perms.txt | massdns -r resolvers.txt -t A -o S -w resolved.txt

# Resolve + keep only live hosts
subfinder -silent -d <TARGET> | dnsx -silent -a -resp | tee resolved.txt
cat resolved.txt | grep -v NXDOMAIN | cut -d' ' -f1 | sort -u > live_subs.txt
```

**Brute-force workflow:** pick a wordlist (general → targeted → intel-driven) → generate candidates (`dnsgen`) → resolve (`puredns`/`dnsx`/`massdns`) → de-wildcard and probe HTTP with `httpx` → dedupe and save.

| Tool | Strength |
| --- | --- |
| `subfinder` | Fast passive, many sources |
| `amass` | Most thorough, active + passive |
| `dnsenum` | Enum + brute + AXFR + Google scrape + reverse DNS in one run |
| `fierce` | Recursive, wildcard detection |
| `dnsrecon` | Multiple techniques, flexible output |
| `puredns` | Fast brute-force with de-wildcarding |
| `sublist3r` | Search-engine sourced (`-b` to add brute) |

### Certificate Transparency logs

CT logs are append-only records of every CA-issued cert — real hostnames, no guessing, and they surface stale/expired services.

```bash
# All subdomains from crt.sh
curl -s "https://crt.sh/?q=%25.<TARGET>&output=json" | jq -r '.[].name_value' | sort -u

# Strip wildcards to root domains
curl -s "https://crt.sh/?q=%25.<TARGET>&output=json" | jq -r '.[].name_value' | sed 's/^\*\.//' | sort -u

# Filter for a pattern (e.g. dev)
curl -s "https://crt.sh/?q=<TARGET>&output=json" | jq -r '.[] | select(.name_value|contains("dev")) | .name_value' | sort -u
```

Censys (free tier, registration) gives richer filtering by cert/IP/domain attributes.

---

## Phase 3 — Ports, Services & Technology Detection

### Web port sweep

```bash
nmap -p 80,443,8000,8080,8180,8443,8888,10000 --open -oA web_discovery -iL scope.txt
sudo nmap --open -sV <TARGET>                       # version detection on open ports
naabu -host <TARGET> -o ports.txt                   # fast port sweep, feed to nmap
```

### Technology fingerprinting

```bash
whatweb -a 3 http://<TARGET>
httpx -u 'https://<TARGET>' -title -tech-detect -status-code -follow-redirects
webanalyze -host <TARGET> -crawl 1
curl -I http://<TARGET>                             # Server, X-Powered-By headers
wafw00f http://<TARGET>                             # detect a WAF before you fuzz
```

### Nikto — fingerprint + misconfig sweep

```bash
nikto -h http://<TARGET> -Tuning b                  # software identification only (fast)
nikto -h http://<TARGET>                            # full scan
```

### Version fingerprints — the fast CVE route

Get the exact version *before* dirbusting. Headers and status endpoints are the source of truth.

```bash
curl -sI http://<TARGET>:3000/                              # Server, X-Powered-By, X-Version
curl -s  http://<TARGET>:3000/api/v1/version                # Gitea / derivatives
curl -s  http://<TARGET>/bugtracker/api/rest/ -H "Authorization: Bearer x" -i  # MantisBT
curl -s  http://<TARGET>:3000/status                        # Grafana
```

**Banner tells worth memorizing:**

| Tell | Application |
| --- | --- |
| Favicon MD5 `E4888EE8491B4EB75501996E41AF6460` | Openfire (nmap mislabels as Hadoop) |
| Werkzeug banner | Flask dev server |
| Thin banner | Ruby Rack / Sinatra |
| Gunicorn banner | Python WSGI |
| Rails dev-mode error page | Leaks `Rails.root`, app name, versions |
| `Server: Apache-Coyote/1.1` | Apache Tomcat |
| `X-Jenkins:` header | Jenkins |
| `Splunkd httpd` in `-sV` | Splunk web (8000) |
| `Indy httpd ... (Paessler PRTG...)` | PRTG |

```bash
# Favicon hash lookup
curl -sk http://<TARGET>/favicon.ico | md5sum      # compare against favicon databases / Shodan
```

### Visual triage — screenshot everything

When a subnet has dozens of web services, screenshot them all first and cluster visually.

```bash
eyewitness --web -x web_discovery.xml -d out/       # screenshots + default-cred hints
cat web_discovery.xml | aquatone -nmap -out aquatone_report
httpx -u 'https://<TARGET>' -title -tech-detect -status-code
xsltproc web_discovery.xml -o web_discovery.html    # nmap XML -> browsable HTML
```

---

## Phase 4 — Content Discovery (directories, files, params)

### Directory & file fuzzing with ffuf

```bash
# Basic
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<TARGET>/FUZZ

# With extensions and output
ffuf -w <wordlist> -u http://<TARGET>/FUZZ -e .php,.html,.txt,.bak -o results.json -of json

# Recursion
ffuf -w <wordlist> -u http://<TARGET>/FUZZ -recursion -recursion-depth 2 -e .php -v

# Extension-only fuzzing (web-extensions.txt already includes the dot)
ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://<TARGET>/blog/indexFUZZ

# Case-insensitive / follow redirects
ffuf -w <wordlist> -u http://<TARGET>/FUZZ -ic -L
```

### ffuf filtering & matching — the part that actually matters

```bash
-mc 200,301        # match these codes
-mc all            # match everything, then filter (pairs with -fs)
-fc 404            # filter these codes
-fs <size>         # filter by response size (drop the default page)
-fw <words>        # filter by word count
-fl <lines>        # filter by line count
-ms <size>         # match a specific size
-mr "pattern"      # match by regex
-fr "error|exception"   # filter by regex
-rate 500          # rate limit
-t 100             # threads
```

### gobuster & feroxbuster

```bash
# gobuster — simple, good defaults
gobuster dir -u http://<TARGET> -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -t 50
gobuster dns -d <TARGET> -w <wordlist> -r <DNS_IP>
gobuster vhost -u http://<TARGET> -w <wordlist> --append-domain

# feroxbuster — recursive, modern
feroxbuster -u http://<TARGET> -w <wordlist> --depth 3 -x php,html,js,json
feroxbuster -u http://<TARGET> -w <wordlist> --filter-status 404 --filter-size 0
```

**gobuster API pattern mode (`-p`)** — fuzz `/<word>/v1` and `/<word>/v2` for REST APIs:

```bash
printf '{GOBUSTER}/v1\n{GOBUSTER}/v2\n' > pattern
gobuster dir -u http://<TARGET>:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
# hits like /books/v1, /users/v1 pop out
```

### Parameter & value discovery

```bash
# GET parameter names
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u "http://<TARGET>/admin.php?FUZZ=key" -fs <SIZE>

# POST parameter names
ffuf -w <wordlist>:FUZZ -u http://<TARGET>/admin.php -X POST \
  -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs <SIZE>

# Value / ID enumeration
ffuf -w <(seq 1 1000):FUZZ -u http://<TARGET>/user?id=FUZZ -fs <SIZE>

# Custom ID wordlists
seq -w 001 999 > ids.txt                                    # leading zeros
for i in $(seq 1 255); do printf '%02x\n' $i; done > hex.txt # hex
```

### Always-check paths

```
/admin /administrator /login /signin /user /account /profile
/config /settings /backup /.git /.env /config.php /web.config /web.xml
/api /api/v1 /api/v2 /rest /graphql /.well-known/
/robots.txt /sitemap.xml /phpmyadmin
/wp-admin /wp-login.php /wp-json        (WordPress)
```

### robots.txt & sitemap — read them, don't obey them

```bash
curl -s http://<TARGET>/robots.txt | grep -Ei '^(Disallow|Allow|Sitemap|Crawl-delay):'
curl -s http://<TARGET>/sitemap.xml
```

Disallowed paths advertise admin areas, backups, staging, and API roots. Treat every one as a lead (in scope). Watch for honeypot trap paths like `/honeypot/`.

### Well-known URIs (RFC 8615)

```bash
curl -s https://<TARGET>/.well-known/security.txt              # disclosure contact
curl -s https://<TARGET>/.well-known/openid-configuration | jq . # OIDC auth/token/JWKS endpoints
curl -s https://<TARGET>/.well-known/change-password           # standard pw-change URL
```

Note OIDC fields: `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `scopes_supported`.

---

## Phase 5 — Virtual Host Enumeration

Apps often share one IP behind different `Host` headers. VHost fuzzing finds hosts with **no public DNS record** — invisible to subdomain enumeration.

| Type | How it routes | Where it's used |
| --- | --- | --- |
| Name-based | `Host` header; many sites, one IP (TLS via SNI) | Most modern web apps |
| IP-based | One site per IP | Strict isolation, legacy TLS |
| Port-based | Same IP, different ports | Internal tools, labs |

### Workflow

1. Run one scan with no filter — note the default response size.
2. Add `-fs <default_size>` to drop the default page.
3. Different sizes = real vhosts.
4. Add each discovered vhost to `/etc/hosts`.

```bash
# HTTP vhost fuzzing
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://<TARGET>/ -H 'Host: FUZZ.target.local' -fs <DEFAULT_SIZE>

# HTTPS — baseline the size first, add -k for self-signed
curl -sk https://<TARGET>/ | wc -c
ffuf -w <wordlist>:FUZZ -u https://<TARGET>/ -H "Host: FUZZ.target.local" -fs <BASELINE> -k

# gobuster vhost mode
gobuster vhost -u http://<TARGET> -w <wordlist> --append-domain -t 50 -k
```

### Pull vhosts from the certificate first

SSL cert SANs frequently leak internal vhost names before you fuzz.

```bash
openssl s_client -connect <TARGET>:443 2>/dev/null | openssl x509 -noout -text | grep -i "dns:"
openssl s_client -connect <TARGET>:443 -showcerts 2>/dev/null | openssl x509 -noout -text \
  | grep -oP 'DNS:\K[^,]+' | sort -u
nmap --script ssl-cert <TARGET> -p 443
```

### Post-shell vhost discovery (Nginx)

After a foothold, read the server config for hidden hosts and internal upstreams:

```bash
cat /etc/nginx/sites-enabled/*
grep -r 'server_name\|proxy_pass' /etc/nginx/sites-enabled/
nginx -T 2>/dev/null                                # full merged config
```

### WordPress catch-all trap

Nginx-hosted WordPress may 301 any unknown path to `http://<vhost>/...`, so gobuster returns endless fixed-size 301s. Measure the catch-all size and exclude it:

```bash
curl -s http://<vhost>/definitely-does-not-exist | wc -c          # e.g. 51576
gobuster dir -u http://<vhost>/ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,txt,html -b 301,404 --exclude-length 51576 -t 30
```

If every "found" path returns the same size, you're being trolled by rewrite rules, not finding files.

---

## Phase 6 — Crawling & Spidering

| Tool | Best for | Notes |
| --- | --- | --- |
| Burp Suite Spider | App pentests with login/state | Tight with the proxy; finds forms/params fast |
| OWASP ZAP Spider | Free CLI/API automation | Baseline crawl + passive checks |
| katana / hakrawler | Fast modern crawling | Feed URLs/params into a pipeline |
| Scrapy | Custom spiders, data mining | Tailored pipelines |

```bash
# ZAP headless quick crawl + passive scan
zap.sh -cmd -quickurl https://<TARGET> -quickprogress -quickout zap-report.html

# Scrapy custom spider
pip3 install scrapy && scrapy startproject recon && cd recon
scrapy genspider site <TARGET> && scrapy crawl site -O urls.json

# ReconSpider — extracts emails, links, JS, external files, HTML comments
python3 ReconSpider.py http://<TARGET>
jq -r '.js_files[]' results.json | sort -u
jq -r '.emails[]' results.json | sort -u
```

HTML comments and JS files leak internal hostnames, dev TODOs, API endpoints, and sometimes credentials — always grep them. Seed crawls from `robots.txt`, sitemaps, and CT/DNS findings; handle auth and CSRF tokens; de-dupe by canonical URL.

### Exposed .git → recover deleted secrets

`git rm` does not delete history — files survive in `.git/objects/`. A commit titled "cleanup", "Oops", or "remove creds" is a neon sign.

```bash
pipx install git-dumper 2>/dev/null || pip3 install git-dumper --break-system-packages
git-dumper http://<TARGET>/.git ./src && cd src
git log --all --oneline
git log --all -p | grep -iE '(password|secret|token|api[_-]?key|db_password)'
git show <commit>:<deleted_file>
git log --all --format='%an %ae' | sort -u             # author identities for usernames
```

For self-hosted Gogs/Gitea/GitLab, clone with any harvested creds and diff the full history the same way, or browse `http://<TARGET>/<user>/<repo>/commit/<hash>` in the web UI.

---

## Phase 7 — Application-Specific Enumeration

Once you know the software, enumerate it precisely.

### WordPress

```bash
wpscan --url http://<TARGET>/ --enumerate u,vp,vt      # users, vuln plugins/themes
curl -s http://<TARGET>/wp-json/wp/v2/users            # user enumeration via REST
```

### Joomla

```bash
curl -s http://<TARGET>/administrator/manifests/files/joomla.xml | xmllint --format -  # version
droopescan scan joomla --url http://<TARGET>/
```

Admin portal `/administrator/`. Component enum via `index.php?option=com_<NAME>`. Joomla does **not** leak usernames via error messages (unlike WordPress).

### Drupal

```bash
curl -s http://<TARGET>/CHANGELOG.txt | grep -m2 ""    # version
droopescan scan drupal -u http://<TARGET>
curl -s http://<TARGET>/node/1                          # node-based content URLs
```

Login `/user/login`. Creds in `sites/default/settings.php`. Vulnerable modules: PHP filter (code exec), RESTful Web Services (auth bypass), Services (RCE).

### Tomcat

Ports 8080/8443/8005/8009/8180.

```bash
curl -I http://<TARGET>:8080/                           # Server header
curl -s http://<TARGET>:8080/docs/ | grep Tomcat        # version
```

Key endpoints: `/manager/html` (WAR upload → RCE), `/host-manager/html`. Default creds: `tomcat:tomcat`, `admin:admin`, `admin:s3cr3t`, `role1:role1`. Credentials live in `tomcat-users.xml`; the useful role is `manager-script`/`manager-gui`.

### Jenkins

Ports 8080/8443/50000.

```bash
curl -I http://<TARGET>:8080/                           # X-Jenkins header
curl -s http://<TARGET>:8080/api/json | python3 -m json.tool
```

Key endpoints: `/script` (Groovy console → RCE), `/asynchPeople/` (users), `/credentials/`. Default creds: `admin:admin`, `admin:password`. Common misconfig: anonymous read, signup enabled, script console exposed.

### Splunk

Ports 8000 (web), 8089 (REST). Often runs as root/SYSTEM; Enterprise Trial drops to auth-free Free after 60 days.

```bash
curl -k https://<TARGET>:8089/services/
curl -k https://<TARGET>:8089/services/apps/local
```

Default creds (older): `admin:changeme`. Attack vector: scripted inputs (Bash/PowerShell/Python) → RCE.

### ColdFusion

Ports 8500/5500/1935. Extensions `.cfm`, `.cfc`.

```bash
curl -I http://<TARGET>:8500/CFIDE/administrator/
gobuster dir -u http://<TARGET>:8500/ -w /usr/share/wordlists/dirb/common.txt -x cfm,cfc
```

### osTicket / PRTG / others

```bash
curl -v http://<TARGET>/ 2>&1 | grep -i "OSTSESSID"     # osTicket cookie
# osTicket: /scp/login.php staff panel — harvest emails/usernames via tickets
# PRTG: default prtgadmin:prtgadmin, CVE-2018-9276 authenticated cmd injection
```

### IIS tilde (8.3 short-name) enumeration

Discover hidden files on vulnerable IIS via short filenames.

```bash
java -jar iis_shortname_scanner.jar 0 5 http://<TARGET>/
curl -I "http://<TARGET>/~a"
# Recover full name from a prefix (TRANSF~1.ASP -> "transf...")
egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt
gobuster dir -u http://<TARGET>/ -w /tmp/list.txt -x .aspx,.asp
```

### WAF / localhost-only API bypass via headers

Many poorly protected internal APIs are gated by one client-controlled header. Test these variations before concluding that an authorized endpoint is inaccessible.

```bash
for h in "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1" "X-Client-IP: 127.0.0.1" \
         "X-Originating-IP: 127.0.0.1" "Forwarded: for=127.0.0.1" "Host: localhost"; do
  echo "=== $h ==="; curl -s -H "$h" http://<TARGET>/api/internal | head -c 200; echo
done
```

---

## Manual HTTP with curl

```bash
# GET
curl -s http://<TARGET>/api/endpoint
curl -H "Authorization: Bearer <token>" http://<TARGET>/api/endpoint
curl -L http://<TARGET>/page                # follow redirects
curl -I http://<TARGET>                      # headers only
curl -v http://<TARGET>                      # full request + response

# POST
curl -X POST http://<TARGET>/api -H "Content-Type: application/json" -d '{"key":"value"}'
curl -X POST http://<TARGET>/login -d "user=admin&pass=admin"
curl -F "file=@/path/to/file" http://<TARGET>/upload
curl -u username:password http://<TARGET>/api

# Cookies
curl -c cookies.txt http://<TARGET>/login    # save
curl -b cookies.txt http://<TARGET>/dashboard # reuse
curl -b "PHPSESSID=abc123" http://<TARGET>/dashboard

# GraphQL introspection
curl -X POST http://<TARGET>/graphql -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'
```

---

## Automated recon pipeline

For breadth over many hosts, chain the tools:

```
1. Seed        normalize target domains/roots
2. DNS/Subs    subfinder -> puredns resolve -> dnsx
3. Ports       naabu -> nmap -sV -p <open>
4. Web probe   httpx -> tech headers -> screenshots
5. Crawl       katana / hakrawler -> store URLs & params
6. Tech/WAF    whatweb / Wappalyzer -> wafw00f
7. CT/Wayback  crt.sh export -> waybackurls / gau
8. Store/Diff  JSON/CSV in a repo; nightly diffs & alerts
```

All-in-one frameworks: **FinalRecon** (`./finalrecon.py --full --url https://<TARGET>`), **Recon-ng**, **SpiderFoot**, **theHarvester**.

---

## The web enumeration checklist

```
Phase 1 — External recon
[ ] Whois + online fingerprint portals (Netcraft, SecurityHeaders, SSL Labs)
[ ] Shodan / GitHub OSINT / Google dorks
[ ] Wayback + breach data + email format

Phase 2 — DNS & subdomains
[ ] dig A/NS/MX/TXT + attempt AXFR
[ ] Passive (subfinder/amass) -> active brute -> resolve live
[ ] crt.sh certificate transparency

Phase 3 — Ports, services, tech
[ ] nmap web-port sweep + -sV
[ ] whatweb / httpx / nikto fingerprint + exact version
[ ] wafw00f + screenshot triage (EyeWitness/Aquatone)

Phase 4 — Content discovery
[ ] Directory + extension fuzzing (ffuf/feroxbuster)
[ ] Parameter + ID enumeration
[ ] robots.txt / sitemap.xml / .well-known
[ ] Backup files (.bak, .old, ~), .git, .env, config files

Phase 5 — Virtual hosts
[ ] Cert SANs first, then vhost fuzz with -fs filter
[ ] Add discovered vhosts to /etc/hosts

Phase 6 — Crawl
[ ] Spider for forms/params; grep JS + HTML comments
[ ] Exposed .git -> git-dumper -> deleted secrets

Phase 7 — App-specific
[ ] CMS scan (wpscan/droopescan), default creds, admin panels
[ ] Header-based WAF/localhost bypass on "protected" endpoints
```

---

## Reference tables

### Tool comparison

| Tool | Purpose | Speed | Accuracy | Notes |
| --- | --- | --- | --- | --- |
| ffuf | Web fuzzing | Very fast | High | Flexible, best filters |
| gobuster | Web fuzzing | Fast | Medium | Simple, good defaults |
| feroxbuster | Web fuzzing | Fast | High | Recursive, modern |
| subfinder | Subdomains | Medium | High | Passive, many sources |
| amass | Subdomains | Slow | Very high | Most thorough |
| httpx | HTTP probing | Medium | High | Multi-purpose |
| curl | Manual HTTP | N/A | Perfect | Precise control |
| Aquatone | Screenshots | Slow | High | Clusters visually |
| EyeWitness | Screenshots | Medium | High | Web + RDP |

### Google search operators

| Operator | Description | Example |
| --- | --- | --- |
| `site:` | Limit to a domain | `site:<TARGET>` |
| `inurl:` | Term in the URL | `inurl:login` |
| `filetype:` | File extension | `filetype:pdf` |
| `intitle:` | Term in the title | `intitle:"index of"` |
| `intext:` | Term in the body | `intext:"password reset"` |
| `-term` | Exclude | `site:<TARGET> -inurl:sports` |
| `cache:` | Cached copy | `cache:<TARGET>` |
| `*` | Wildcard word | `user* manual` |

### High-value Google dorks

| Goal | Dork |
| --- | --- |
| Login pages | `site:<TARGET> (inurl:login OR inurl:admin)` |
| Exposed files | `site:<TARGET> (filetype:pdf OR filetype:xlsx OR filetype:docx)` |
| Config files | `site:<TARGET> (inurl:config.php OR ext:conf OR ext:cnf)` |
| DB backups | `site:<TARGET> (inurl:backup OR filetype:sql)` |
| Dir listings | `site:<TARGET> intitle:"Index of /"` |
| Error leaks | `site:<TARGET> ("Warning: mysql_" OR "Stack trace")` |
| Secrets in code | `site:<TARGET> (filetype:env OR "AWS_ACCESS_KEY_ID")` |
| IDOR/SQLi params | `site:<TARGET> inurl:php?id=` |

### IP / DNS research portals

| Tool | URL | Use |
| --- | --- | --- |
| BGP Toolkit | `https://bgp.he.net/` | ASN, netblocks, routing |
| ARIN / RIPE | `arin.net` / `ripe.net` | Regional IP registries |
| ViewDNS.info | `https://viewdns.info/` | Reverse IP, DNS history |
| DNSdumpster | `https://dnsdumpster.com/` | Subdomain map |

---

## Related

* [HTTP Attacks](http-attacks.md) — IDOR, verb tampering, header injection on the endpoints you mapped
* [Server-Side Attacks](server-side-attacks.md) — SSRF/XXE/SSTI against the parameters and services found here
* [SQL Injection](sql-injection.md) — test the `?id=` params this page surfaces
* [XSS](xss.md) — fire payloads into the inputs, forms, and headers enumerated here
* [Command Injection](command-injection.md) · [File Inclusion](file-inclusion.md) · [File Upload](file-upload.md)
* [Enumeration & Scanning](enumeration-scanning.md) — host/port/service enumeration that feeds the web layer
* [Report Writing](report-writing.md) — turning enumeration evidence into findings
