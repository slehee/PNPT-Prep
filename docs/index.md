# Security Engineering Notes

Practical notes from PNPT preparation, penetration-testing labs, malware analysis, and cloud security CTFs. The collection combines methodology with commands, attack paths, troubleshooting notes, and reporting guidance.

## Start with the PNPT path

Begin with the [PNPT overview](intro.md) for engagement types and expectations, then use the [PNPT methodology](method.md) as the end-to-end workflow. Continue through [enumeration and scanning](enumeration-scanning.md), [web enumeration](web-enumeration.md), the [Active Directory attack chain](ad-attacks.md), and [report writing](report-writing.md).

## What's inside

* **Recon and enumeration.** Network, service, and web discovery techniques for building an attack surface.
* **Web exploitation.** HTTP weaknesses, XSS, SQL and command injection, file attacks, and server-side vulnerabilities.
* **Access and post-exploitation.** Shells, payloads, file transfers, credential dumping, lateral movement, and pivoting.
* **Privilege escalation.** Windows and Linux methodologies alongside password and hash attacks.
* **Active Directory.** Core concepts, Kerberos abuse, ACL and ADCS attacks, relay techniques, NetExec, and Mimikatz.
* **Reporting.** Evidence collection, finding structure, remediation guidance, and delivery.
* **Malware analysis.** Static and dynamic triage, analysis tools, and a WannaCry case study.
* **Labs and cloud CTFs.** Linux privilege-escalation walkthroughs and Wiz Cloud Security Championship writeups.

## Using these notes

Commands are starting points, not universal recipes. Replace values such as `<TARGET>`, `<DOMAIN>`, and `<USER>` with details from your authorized lab or engagement, and review a command before running it. The sidebar provides the complete topic index; links within each page connect related techniques and supporting material.

{% hint style="warning" %}
Everything here is for legal, authorized practice: labs, CTFs, and systems you own or have written permission to test.
{% endhint %}
