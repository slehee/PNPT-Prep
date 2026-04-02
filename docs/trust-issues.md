# Trust Issues — CTF Investigation Report
## Cloud Security Championship | Challenge #9

---

## Overview

| Field | Detail |
|---|---|
| **Challenge** | Trust Issues |
| **Platform** | Cloud Security Championship (Wiz Research) |
| **Author** | Eden Abergil |
| **Status** | 🔄 In Progress — Flag NOT yet found |
| **Solved By** | 59 other players |
| **Flag Format** | `CTF{...}` |

---

## Mission

> You are an incident responder at Acme Inc. A security researcher contacts your team: Acme's name appeared in a newly uncovered threat campaign. They provide a link to a public GitHub repository believed to be used by the attacker to leak stolen data.

**Three Objectives:**

1. Understand what happened on the machine
2. Identify the attacker's data exfiltration method
3. Find the flag

---

## Investigation Timeline

### Step 1 — Entry Point: The Attacker's Repo

**What we did:** Navigated to the provided link.

**URL:** `https://github.com/m4gicst34l3r/stolen-sparkles`

**What we found:**

- A public GitHub repo owned by `m4gicst34l3r`
- A `README.md` and a `data/` folder
- **241 Fernet-encrypted `.secret` files** in `data/`
- Each file is named after a Kubernetes service account (e.g., `magic-runner-acme.secret`, `default.secret`, `tools-runner.secret`)
- The repo has a branch called `tool-building` in addition to `main`

**Why it matters:** This is the attacker's exfiltration destination. The secrets were stolen from somewhere and encrypted before being pushed here.

---

### Step 2 — Investigating the Compare URL

**What we did:** Visited the compare URL provided in the challenge.

**URL:** `https://github.com/m4gicst34l3r/stolen-sparkles/compare/tool-building...main`

**What we found:**

- The `tool-building` branch contains actual Python source code for a Kubernetes tool
- Files: `collector.py`, `run_inventory.py`, `tests/test_collector.py`, `requirements.txt`
- This is the **same codebase** as `acme-codebase-prod/k8s-magic-tool`
- This confirms the attacker **built the tool** before planting it at Acme

**Why it matters:** The attacker's own repo contains the source code of the tool that was deployed at Acme. This is how we found the victim org.

---

### Step 3 — Finding the Victim Organisation

**What we did:** Searched GitHub for `acme-codebase-prod`.

**URL:** `https://github.com/acme-codebase-prod/k8s-magic-tool`

**What we found:**

- A GitHub organisation called `acme-codebase-prod`
- One public repo: `k8s-magic-tool`
- Contains: `collector.py`, `run_inventory.py`, `requirements.txt`, `tests/`, and `.github/workflows/k8s-magic-tool-testing.yml`
- The GitHub Actions workflow runs `pip install -r requirements.txt` then `pytest`
- The runner is **self-hosted** — named `magic-runner-acme`
- The runner has **GCP/GKE credentials** to connect to a Kubernetes cluster

**Why it matters:** This is the compromised machine. The self-hosted runner has access to real Kubernetes secrets.

---

### Step 4 — Full Commit & Branch Analysis

**What we did:** Examined all 15 commits across both repos, all branches, all PRs.

**Key commits in `acme-codebase-prod/k8s-magic-tool`:**

| Commit | Message | What Changed |
|---|---|---|
| `b9e7c4f` | initial commit | Base repo setup |
| `b188277` | add test files | Added test_collector.py |
| `020a40f` | added GitHub Action | Added workflow YAML |
| `d657c8e` | updated cron | Changed schedule `*/10` → `*/30` |
| `af58566` | added schedule | Added `*/15` cron |
| `be916f5` | removed schedule | Removed cron |
| `1f338d4` | updated intervals | Added `0 * * * *` hourly cron |
| `6f1c7bc` | changed schedule | Removed cron, left `workflow_dispatch` only |

**Finding:** ALL YAML changes only toggled the `on:` trigger. **No malicious code was ever added to the repo.**

**PRs examined:**

- PR #1: Tool building (merged from tool-building branch)
- PR #2: Changed README
- PR #3: GitHub action creation — had **2 Wiz bot IaC misconfiguration findings** (then cleared)

---

### Step 5 — Source Code Analysis

**What we did:** Read every Python file in both repos.

**Files examined:**

| File | Finding |
|---|---|
| `collector.py` | Clean — lists K8s nodes, pods, service accounts |
| `run_inventory.py` | Clean — runs collector and prints output |
| `tests/test_collector.py` | Clean — standard pytest tests |
| `tests/__init__.py` | Clean — just a docstring |
| `requirements.txt` | Only `kubernetes>=28.1.0` and `pytest>=7.4.0` |

**Finding:** Zero malicious code anywhere in the repository. The attack did NOT come from the repo code itself.

---

### Step 6 — Revealing the Hints

**What we did:** Clicked Hint #1 and Hint #2 on the challenge page (cost points).

**Hint #1 (-2 pts):** *"What is this machine's purpose?"*

- Answer: It's a GitHub Actions **self-hosted runner** with GKE credentials

**Hint #2 (-4 pts):** *"The security researcher contacts you once again saying this is a supply chain attack."*

- Answer: The attack came through a **dependency**, not the repo code

**Why it matters:** Confirmed the attack vector is in the **supply chain** — specifically the `pip install` step.

---

### Step 7 — Profile & Network Investigation

**What we did:** Checked all associated GitHub users, forks, and gists.

| User/Repo | Finding |
|---|---|
| `m4gicst34l3r` | Only 1 public repo (stolen-sparkles), 0 gists |
| `edenbrgl` | 0 public repos, 0 gists |
| `acme-john-doe` | Merged PRs, manually triggered workflow runs |
| `alevan22/stolen-sparkles` | CTF player fork, no extra content |
| `stepacchioni/stolen-sparkles` | CTF player fork, no extra content |

**Finding:** No hidden data found in profiles or forks.

---

### Step 8 — Accessing the Compromised Machine

**What we did:** Discovered an interactive terminal on the challenge page by scrolling down.

**Machine name:** `root@magic-runner-acme`

**What we found in the terminal so far:**
```bash
# Machine has:
/home/ubuntu/actions-runner/     # GitHub Actions runner installation
/home/ubuntu/actions-runner/_work/  # Only has actions/checkout files
/home/ubuntu/actions-runner/_diag/  # Runner diagnostic logs (6 log files!)

# Python site-packages at:
/usr/local/lib/python3.10/dist-packages/
/usr/lib/python3/dist-packages/
/usr/lib/python3.10/dist-packages/

# pip list shows ONLY:
cryptography    3.4.8
# (NO kubernetes package installed currently)

# Environment variables: nothing with key/secret/fernet/token
# Bash history: empty
# /tmp/: only systemd temp files
```

**Runner diagnostic logs found:**
```
Runner_20260128-115635-utc.log
Runner_20260128-115737-utc.log  
Runner_20260201-125843-utc.log
Runner_20260201-130349-utc.log
Runner_20260201-130900-utc.log  (blocks)
Runner_20260201-152916-utc.log  (pages)
Runner_20260201-200556-utc.log
Runner_20260201-200609-utc.log
```

**Log content so far:** Jan 28 log shows runner was configured with service name `actions.runner.acme-codebase-prod-k8s-magic-tool.magic-runner-acme`

---

## Current Status

### What We Know for Certain

- ✅ The compromised machine is a GitHub Actions self-hosted runner
- ✅ The attack is a supply chain attack (confirmed by hint)
- ✅ Kubernetes secrets were exfiltrated and Fernet-encrypted into 241 `.secret` files
- ✅ The `cryptography` package (which provides Fernet) IS installed on the machine (v3.4.8)
- ✅ The source code in the repo is completely clean
- ✅ We have interactive shell access to the machine via the challenge terminal
- ✅ Runner diagnostic logs exist and are readable

### What We're Still Missing

- ❌ **The Fernet encryption key** — not found yet
- ❌ **The malicious package/code** — not located yet
- ❌ **The flag** — requires decrypting a `.secret` file

---

## Attack Theory (Best Current Hypothesis)
```
Attacker
  │
  ├─ Created acme-codebase-prod/k8s-magic-tool with clean-looking code
  ├─ Added GitHub Actions workflow that runs: pip install + pytest
  ├─ Injected a MALICIOUS PyPI package into the dependency chain
  │     (either a malicious version of 'kubernetes' OR a dependency of it)
  │
  └─ When GitHub Actions ran on magic-runner-acme:
        pip install -r requirements.txt  ← MALICIOUS PACKAGE INSTALLED HERE
        pytest                           ← conftest.py auto-executed HERE
              │
              ├─ Read Kubernetes secrets using runner's GKE credentials
              ├─ Encrypted each secret with Fernet (key hardcoded in package)
              └─ Pushed encrypted .secret files to stolen-sparkles repo
```

---

## What Needs To Be Done Next

### Priority 1 — Search the Machine More Deeply

We have a live shell. We need to search:
```bash
# Check the _diag Worker logs (not just Runner logs)
ls /home/ubuntu/actions-runner/_diag/
# Look for Worker_*.log files which contain actual job output

# Check pip install history
cat /var/log/dpkg.log | grep -i "python\|pip"
find / -name "*.log" -newer /home/ubuntu/actions-runner/_diag/Runner_20260128* 2>/dev/null

# Search all Python packages for suspicious conftest.py
find /usr/lib/python3 /usr/local/lib/python3* -name "conftest.py" -exec grep -l "fernet\|encrypt\|kubernetes\|secret" {} \;

# Look for the kubernetes package installation location
find / -path "*/kubernetes/__init__.py" 2>/dev/null

# Check if there's a hidden file with the key
find /home/ubuntu /root /opt -name ".*" -type f 2>/dev/null
```

### Priority 2 — Check PyPI for Malicious Package

If the key isn't on the machine, it's hardcoded in the malicious PyPI package:
```bash
# On PyPI, look for:
# - A malicious 'kubernetes' package version
# - A typosquatted package (e.g., 'kubernets', 'kubernetez')
# - A package that was recently yanked/removed from PyPI
```

**URL to check:** `https://pypi.org/project/kubernetes/#history`

### Priority 3 — Decrypt the Flag

Once the Fernet key is found:
```python
from cryptography.fernet import Fernet
import base64

key = b"THE_KEY"  # Found from machine or PyPI package
f = Fernet(key)

# Read magic-runner-acme.secret from GitHub
encrypted = b"gAAAAAB..."  # contents of the .secret file
decrypted = f.decrypt(encrypted)
print(decrypted.decode())
# Expected output: CTF{...}
```

---

## Files & URLs Reference

| Resource | URL |
|---|---|
| Attacker repo | https://github.com/m4gicst34l3r/stolen-sparkles |
| Victim repo | https://github.com/acme-codebase-prod/k8s-magic-tool |
| Challenge page (with terminal) | https://www.cloudsecuritychampionship.com/challenge/9 |
| Key secret file | https://github.com/m4gicst34l3r/stolen-sparkles/blob/main/data/magic-runner-acme.secret |
| Fernet docs | https://cryptography.io/en/latest/fernet/ |

---

## Summary

> The attacker set up a fake-but-legitimate-looking Kubernetes tool at Acme, with a GitHub Actions CI/CD pipeline that runs on a self-hosted runner with real GKE access. The malicious code was **not in the repo** but injected via a **supply chain attack on a PyPI dependency**. When the workflow ran `pip install` + `pytest`, the malicious package silently read all K8s secrets, encrypted them with Fernet, and pushed them to the attacker's public repo. We have shell access to the compromised machine and need to find the Fernet key — either in the runner logs, a hidden file on the machine, or inside the malicious PyPI package itself.