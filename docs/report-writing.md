# Report Writing (PNPT Deliverable)

The PNPT is not passed when you get Domain Admin — it's passed when you deliver a professional report **and** a live debrief. You get the 5-day practical, then extra time to write the report; miss the report or the debrief and the compromise counts for nothing. This page covers what to record while you're testing and how to turn it into a document a client would actually pay for.

{% hint style="danger" %}
The PNPT has two graded deliverables most people forget until it's too late: a written report **and a ~15-minute video debrief** where you present findings as if to the client's stakeholders. Record notes and screenshots as if a non-technical exec and a patching engineer will both read them — because they will. Start the report on day one, not after the exam.
{% endhint %}

## The two audiences in one document

Every finding you write serves two readers at once. Write for both or you lose points:

| Audience | Reads | Wants |
| --- | --- | --- |
| **Executives / stakeholders** | Executive summary, risk ratings | Business impact in plain English, "how bad and how much" |
| **Engineers / IT** | Technical findings, PoCs, remediation | Exact reproduction steps and a concrete fix |

The debrief is aimed at the first group. The written report carries both.

## Note-taking during the exam

### Pick a portable, offline tool

Choose something that renders offline, exports cleanly to PDF/Markdown/HTML, and handles inline screenshots:

* **Obsidian** — markdown, offline, live preview, plugin ecosystem
* **CherryTree** — SQLite-backed hierarchical notebook, good for long command output
* **Sublime Text / VS Code** — plaintext, never crashes on you
* A per-target `screenshots/` folder next to the vault

Install Obsidian as a portable AppImage on Kali (no root):

```bash
wget https://github.com/obsidianmd/obsidian-releases/releases/download/v1.5.3/Obsidian-1.5.3.AppImage
chmod +x Obsidian-1.5.3.AppImage
./Obsidian-1.5.3.AppImage
```

Swap the version for the latest release off the GitHub releases page.

### Auto-log every terminal

Start every shell with `script` so every command and its output lands in a file. If notes crash or a shell dies, you still have the transcript.

```bash
script -a ~/pnpt-exam.log
```

* `-a` — append, don't clobber the previous log

### Per-action test log template

Record every action with **what**, **where**, **when**, **result**. Keeping this discipline turns your notes into the report body almost verbatim.

```
Testing for LLMNR Poisoning
Target:      <TARGET> / <DOMAIN>
Attacker:    <ATTACKER_IP>
Date:        <YYYY-MM-DD> 14:32 UTC

1. Started Responder on eth0 to poison LLMNR/NBT-NS
   Command: sudo responder -I eth0 -wv
   Result:  Captured NTLMv2 hash for <DOMAIN>\jsmith

2. Cracked the hash offline
   Command: hashcat -m 5600 jsmith.hash rockyou.txt
   Result:  jsmith:Winter2024!  (recovered in 3m)

3. Validated the credential over SMB
   Command: nxc smb <DC_IP> -u jsmith -p 'Winter2024!'
   Result:  [+] <DOMAIN>\jsmith  (valid, non-admin)
```

Rules of thumb:

* Store the **exact command line** verbatim — never paraphrased
* Store the **exact request and response** for web findings
* Store the **payload verbatim** in a code block so markdown can't mangle it
* Timestamp each action so the report reads as an attack timeline

### Folder layout

```
pnpt-exam/
  ├── external/
  │    ├── nmap.png
  │    └── foothold.png
  ├── <DC_IP>/
  │    ├── responder-hash.png
  │    ├── secretsdump.png
  │    └── domain-admin-proof.png
  ├── loot/
  │    ├── ntds.txt
  │    └── cracked.txt
  └── notes.md
```

## Screenshots

{% hint style="warning" %}
Screenshot the moment a payload works. Shells die, sessions drop, and you cannot re-take the shot of a foothold you no longer have. Capture proof **before** you pivot deeper.
{% endhint %}

### A good screenshot shows

* The **command and its output** in one frame
* The **prompt** (proves the context: `whoami` / `hostname` visible)
* The **URL bar** for web findings (proves target + endpoint)
* Enough surrounding context to prove it's real, not staged

### A bad screenshot

* Cropped so tight you can't see what host you're on
* Shows the payload but not the result (no shell, no popup, no creds)
* Missing terminal/browser chrome

### Tools

| Tool | Use |
| --- | --- |
| `flameshot gui` | Annotate + area-select, most flexible on Kali |
| KSnip | GUI area-select, annotate, auto-save |
| `gnome-screenshot -a` | Quick area grab to file |
| `import -window root shot.png` | ImageMagick, headless snapshots |
| `Win`+`Shift`+`S` | Windows Snipping Tool for pivot-host shots |

## Report structure

A PNPT report generally runs in this order. Front-load the business story, back-load the raw evidence.

1. **Cover page** — client name, your name, engagement dates, "Confidential"
2. **Executive summary** — non-technical, one page
3. **Assessment scope & methodology** — what was in scope, what wasn't
4. **Attack narrative / summary of findings** — the story of the compromise
5. **Technical findings** — one entry per vulnerability, rated
6. **Remediation summary** — prioritized fix list
7. **Appendices** — raw output, cracked hashes, tool versions

### Executive summary — four beats

Beat 1 — **scope box**, the what/when/how in plain bullets:

```
- Scope: <DOMAIN> internal network, 10.0.0.0/24
- Timeframe: Jan 3 - 7, 2026
- Methodology: PTES / OWASP, black-box internal assessment
- Social engineering and DoS testing were out of scope
- No test accounts were provided; testing began with network access only
- All tests were run from <ATTACKER_IP>
```

Beat 2 — **engagement paragraph** (2-3 sentences, plain English):

```
The Client engaged <YOU> to perform an internal network penetration
test of the <DOMAIN> environment in January 2026. Testing was
conducted from a single attacker host on the internal network with no
credentials provided, simulating a malicious actor who had gained a
foothold on the corporate LAN.
```

Beat 3 — **what went well** (credit the hardening you saw):

```
The environment showed several positive controls. SMB signing was
enforced on the majority of servers, limiting relay opportunities. The
password policy enforced complexity and lockout thresholds, and modern
operating systems were largely patched against public exploits. These
reflect a maturing security program.
```

Beat 4 — **what went wrong**, framed as themes, not a bug list:

```
However, <YOU> was able to escalate from an unauthenticated position on
the network to full Domain Administrator control. The path relied on a
recurring theme of weak credential hygiene: a service account with a
guessable password, credentials cached in memory on a shared server,
and excessive permissions granted to standard user accounts. Addressing
credential management and least-privilege access would break this chain
at multiple points.
```

Closer — invite follow-up:

```
These findings and their remediations are detailed below. Should any
questions arise, <YOU> is happy to provide further guidance and
remediation support.
```

## Severity and CVSS scoring

Every finding needs a rating. Use CVSS 3.1 for a defensible number, then map it to a plain-English severity the executive summary can use.

| Severity | CVSS 3.1 | Rough meaning |
| --- | --- | --- |
| **Critical** | 9.0 – 10.0 | Full compromise, trivial to exploit (Domain Admin, RCE, unauth data theft) |
| **High** | 7.0 – 8.9 | Serious impact or serious ease (privilege escalation, credential theft) |
| **Medium** | 4.0 – 6.9 | Real risk, needs conditions (auth required, limited scope) |
| **Low** | 0.1 – 3.9 | Minor / defense-in-depth (info disclosure, verbose errors) |
| **Info** | 0.0 | No direct risk, worth noting (banner leakage, best-practice gaps) |

Build vectors with the FIRST calculator and paste the full string so the client can audit your math:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H   → 9.8 Critical
```

Vector cheatsheet for the common metrics:

| Metric | Values | Ask yourself |
| --- | --- | --- |
| **AV** Attack Vector | N / A / L / P | Network, Adjacent, Local, or Physical? |
| **AC** Attack Complexity | L / H | Any special conditions to exploit? |
| **PR** Privileges Required | N / L / H | Do you need creds first? |
| **UI** User Interaction | N / R | Must a victim click something? |
| **C/I/A** Impact | N / L / H | Confidentiality, Integrity, Availability loss |

{% hint style="info" %}
Rate the finding, not the machine. A crackable Kerberoastable service account is **High** even before you use it to reach Domain Admin — the DA compromise is the *impact* you describe, not a separate finding to double-count.
{% endhint %}

## Per-finding template

```
### Finding N - <short, specific title>

Severity:      Critical / High / Medium / Low / Info
CVSS 3.1:      <score> (<full vector string>)
Affected:      <IP / hostname / URL / account>
CVE / CWE:     <if applicable>

Description
-----------
<what the vulnerability is, in engineering terms — one or two paragraphs>

Impact
------
<what an attacker gains and why the business cares: RCE, credential
access, domain compromise, data exposure. Tie it to the environment.>

Proof of Concept
----------------
Command / request (verbatim):
    <exact command with placeholders for client-specific values>

Response / evidence:
    <verbatim output OR screenshot reference>

Steps to Reproduce
------------------
1. ...
2. ...
3. ...

Remediation
-----------
<concrete fix: patch level, config change, code change, or a
compensating control. Be specific — "enable SMB signing via GPO",
not "improve security".>

References
----------
- <vendor advisory / CVE URL>
- <MITRE ATT&CK technique / exploit-db link>
```

### Example finding

```
### Finding 1 - LLMNR/NBT-NS Poisoning Leads to Credential Theft

Severity:  High
CVSS 3.1:  8.1 (CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)
Affected:  Internal network broadcast domain (10.0.0.0/24)
CWE:       CWE-300 (Man-in-the-Middle)

Description
-----------
The network permits Link-Local Multicast Name Resolution (LLMNR) and
NetBIOS Name Service (NBT-NS). When a host fails DNS resolution it
broadcasts a name query that any machine on the segment can answer,
allowing an attacker to masquerade as the requested resource and
capture NTLMv2 authentication material.

Impact
------
<YOU> captured the NTLMv2 hash for the domain account jsmith and
cracked it offline in under five minutes, yielding valid domain
credentials that were reused to enumerate the domain and pivot toward
further compromise.

Proof of Concept
----------------
Command: sudo responder -I eth0 -wv
Result:  [SMB] NTLMv2-SSP Hash captured for <DOMAIN>\jsmith
         hashcat -m 5600 jsmith.hash rockyou.txt  ->  Winter2024!

Steps to Reproduce
------------------
1. Connect to the internal network.
2. Run Responder on the interface and wait for a name-resolution miss.
3. Crack the captured NTLMv2 hash offline with hashcat mode 5600.

Remediation
-----------
Disable LLMNR via GPO (Turn off multicast name resolution = Enabled)
and disable NBT-NS on all adapters. Enforce SMB signing to blunt relay.

References
----------
- https://attack.mitre.org/techniques/T1557/001/
```

## Attack narrative

Beyond individual findings, PNPT reports read well when you include a short **attack narrative** — the story of how you went from network access to Domain Admin, in order. It lets the reader see the chain instead of disconnected findings.

```
1. Poisoned LLMNR to capture and crack jsmith's NTLMv2 hash.
2. Sprayed the recovered password across the domain and found reuse
   on the SQL01 local admin account.
3. Dumped LSASS on SQL01, recovering a cached Domain Admin session.
4. Used the DA credential to DCSync the krbtgt hash and confirm full
   domain compromise.
```

Cross-reference each step back to the numbered finding that documents the vulnerability it exploited.

## Remediation summary

Give the client a prioritized, deduplicated fix list up front so leadership can plan work. Group by theme, highest impact first:

* **Credential management** — disable LLMNR/NBT-NS, enforce SMB signing, rotate service-account passwords, remove password reuse
* **Least privilege** — remove standard users from local Administrators, tier admin accounts
* **Patch management** — bring hosts current, remediate the flagged CVEs
* **Monitoring** — alert on LSASS access, Responder-style poisoning, and DCSync-pattern replication

## PNPT evidence checklist

Before you submit, confirm the report contains:

* [ ] Executive summary readable by a non-technical stakeholder
* [ ] Every finding rated with severity **and** a full CVSS vector
* [ ] Verbatim commands and output for each PoC
* [ ] Screenshots proving each compromise (prompt/URL visible)
* [ ] The full attack narrative from foothold to Domain Admin
* [ ] Concrete remediation for every finding
* [ ] Appendix with raw enumeration output and cracked credentials
* [ ] A rehearsed debrief covering the same story in ~15 minutes

## Producing the PDF

Compile as you go, not at the end. Convert markdown to a clean PDF with pandoc:

```bash
pandoc report.md -o report.pdf --pdf-engine=xelatex \
  -V geometry:margin=1in \
  -V mainfont="DejaVu Serif" \
  -V monofont="DejaVu Sans Mono" \
  --toc --number-sections
```

Flag legend:

* `--pdf-engine=xelatex` — needed for wide Unicode + custom fonts
* `-V geometry:margin=1in` — one-inch margins all round
* `-V mainfont` / `monofont` — override defaults (DejaVu ships on Kali)
* `--toc --number-sections` — table of contents + numbered `1.1.2` headings

Templates worth pre-downloading:

* **SysReptor** — `pip install reptor`, produces exam-ready PDFs from findings
* **noraj/OSCP-Exam-Report-Template-Markdown** — pandoc-based, adapts cleanly to PNPT
* **TCM Security sample report** — matches the grader's expectations for structure and tone

## The debrief

The PNPT debrief is a recorded presentation to imagined stakeholders. Score it like a real client meeting:

* **Lead with business impact**, not tooling. "We achieved full control of your Active Directory" beats "I ran Responder".
* **Walk the attack narrative** as a story: how you got in, how you escalated, how far you got.
* **Name the top fixes** and why they matter, in plain language.
* **Keep it tight** — practice to land near 15 minutes without rushing.
* **Assume the audience is non-technical** — no jargon left unexplained.

## Related

* [Relay & Coerce](relay-and-coerce.md) — the attack chains you'll be writing up
* [CrackMapExec / NetExec](crackmapexec-netexec.md) · [Mimikatz](mimikatz.md) — evidence-generating tools
* [AD Attacks](ad-attacks.md) · [Kerberos Attacks](kerberos-attacks.md) — the domain compromise story
* [Credential Dumping](credential-dumping.md) · [Password Hash Attacks](password-hash-attacks.md) · [Lateral Movement](lateral-movement.md) — findings feeding the narrative
