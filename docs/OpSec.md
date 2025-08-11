# OpSec

## OpSec For Hackers

### Questions to Think About

- **What is OpSec?**  
Operational Security (OpSec) is the process of protecting sensitive information and activities from being discovered by adversaries. It involves identifying potential leaks and minimizing risks during operations.

- **Who needs it?**  
Anyone involved in sensitive activities, especially hackers, penetration testers, and security professionals, needs OpSec to avoid detection and protect themselves and their operations.

- **Why do we need it?**  
OpSec is essential to prevent exposure, legal consequences, and to ensure the success of operations by keeping methods, tools, and identities hidden from targets and authorities.

- **How long does it take?**  
OpSec is an ongoing process. It starts before an operation and continues throughout and after, requiring constant vigilance and adaptation.

- **Can we do OSINT without it?**  
Technically yes, but it is risky. Conducting OSINT (Open Source Intelligence) without OpSec can expose your identity, intentions, and methods, making you a target or compromising your mission.

---

## Types of Leakage

- **Technical:** Accidental exposure through logs, network traffic, or misconfigured services.
- **Social Engineering:** Revealing information through human interaction or manipulation.
- **Geo Locating Pictures:** Photos may contain GPS data that reveals your location.
- **Leaving Behind Metadata:** Files and images can contain hidden metadata (author, device, location, etc.).
- **Triggering Canary Tokens:** Accessing or interacting with canary tokens can alert defenders to your presence.
- **Leaving Clues in Code:** Comments, variable names, or commit history can leak sensitive info.
- **Writing Style:** Unique writing patterns can be used to identify individuals.
- **Old/Dormant Accounts:** Forgotten accounts may still be linked to your identity.
- **Breaches:** Previously leaked data can be used to correlate your activities.
- **Archives:** Archived web pages or files may contain information you thought was deleted.
- **Time Zone:** Timestamps can reveal your likely location.
- **Activity/Time of Day:** Patterns in when you are active can provide clues about your habits or location.

## Threat Levels

Understand your threat levels.

### Who are you hiding from?
- Family
- Stalkers
- Data Brokers
- Advertisers
- ISP
- Government
- Nation State threats

### Links
- [California DMV is making $50M a year selling drivers' personal information (Vice)](https://www.vice.com/en/article/the-california-dmv-is-making-dollar50m-a-year-selling-drivers-personal-information/)

## Notes/Links

- [IP Location](https://www.iplocation.net/)
- [LinkedIn OSINT Search](https://www.linkedin.com/search/results/content/?keywords=osintforfun)
- [Wayback Machine](https://web.archive.org)
- [Have I Been Pwned](https://haveibeenpwned.com/)
- [What's My Name App](https://whatsmyname.app/)
- Twitter Timestamps
- [FastPeopleSearch.com](https://www.fastpeoplesearch.com/)

## Leak Tests

Analyze the digital breadcrumbs you leave behind.

### Multiple Tests
- [BrowserLeaks](https://browserleaks.com/)
- [Device Info](https://www.deviceinfo.me/)
- [BrowserAudit](https://browseraudit.com)

### Tracking Tests
- [Cover Your Tracks (EFF)](https://coveryourtracks.eff.org/)
- [Privacy.net Analyzer](https://privacy.net/analyzer/)

### IP Test
- [Whoer](https://whoer.net/)
- [IPLeak](https://ipleak.net/)
- [IP Location](https://www.iplocation.net/)
- [What's My IP](https://www.whatsmyip.org/)
- [I Know What You Download](https://iknowwhatyoudownload.com)

### DNS Leak Test
- [DNS Leak Test](https://www.dnsleaktest.com)

### Fingerprinting
- [Am I Unique?](https://amiunique.org/)

---

## Password Managers

Password managers are essential tools for maintaining strong, unique credentials and improving your overall security posture.

### Open Source
- [Bitwarden Password Manager](https://bitwarden.com/) *(Open Source, Free & Paid options)*
- [KeePassXC](https://keepassxc.org/) *(Open Source, Free)*

### Payable/Commercial
- [1Password](https://1password.com/) *(Commercial, Paid)*
- [LastPass](https://www.lastpass.com/) *(Commercial, Free & Paid)*
- [Dashlane](https://www.dashlane.com/) *(Commercial, Free & Paid)*
- [NordPass](https://nordpass.com/) *(Commercial, Free & Paid)*

### Note
- Use them to generate unique usernames and strong passwords.
- Store secure notes and sensitive information.
- Store TOTP codes and backup codes, but for better security, consider using a separate app for TOTP (don't keep all your eggs in one basket).

---

## MFA (MultiFactor Authentication) - Hardware Keys

Hardware security keys provide a strong layer of protection for your accounts by requiring physical presence for authentication.

### Examples
- **Yubikey**: A popular hardware security key supporting multiple authentication protocols (FIDO2, U2F, OTP, etc.).
- [WebAuthn Demo/Test](https://webauthn.io/): Try out WebAuthn authentication with hardware keys.

**Tip:** Use hardware keys for your most important accounts (email, password manager, cloud services) to significantly reduce the risk of phishing and account takeover.

---

## OS Hardening

Operating System (OS) hardening is the process of securing your system by reducing its attack surface and improving privacy.

### Tools
- [Privacy.sexy](https://privacy.sexy/) — Cross-platform tool for automating privacy and security settings.
- [BleachBit](https://www.bleachbit.org/) — Open source system cleaner for Windows and Linux to remove unnecessary files and protect privacy.

**Tip:** Regularly review and update your OS privacy and security settings, and use these tools to automate and simplify the process.

---

## DNS Privacy

Protecting your DNS queries is crucial for privacy, as DNS requests can reveal the websites you visit even if you use HTTPS.

### Tools/Services
- [NextDNS](https://nextdns.io/) — Customizable, privacy-focused DNS resolver with ad/tracker blocking and analytics.
- [1.1.1.1 by Cloudflare](https://1.1.1.1/) — Fast, privacy-first DNS resolver.

### Ad Test
- Try visiting [The New York Times](https://www.nytimes.com) to check if your DNS/ad-blocking solution is working (ads should be blocked or reduced).

**Tip:** Use encrypted DNS (DNS-over-HTTPS or DNS-over-TLS) for additional privacy.

---

*Next up: Hardened Security*

*Paste your notes or answers to these questions below, and I will help you expand and organize them further.*
