# PNPT Preparation & Cybersecurity Training

Welcome to the **Comprehensive Cybersecurity Training Documentation**, powered by **MkDocs**.

This repository contains structured learning materials and practical guides for multiple cybersecurity domains:

## Content Areas

### PNPT (Practical Network Penetration Tester)
- **Introduction & Methodology** - Core penetration testing concepts and systematic approaches
- **Active Directory** - AD enumeration, attacks, and post-exploitation techniques

### PMAT (Practical Malware Analysis & Triage)
- **Static & Dynamic Analysis** - Comprehensive malware analysis techniques
- **Advanced Analysis Methods** - Deep-dive analysis and reverse engineering
- **Tools & Resources** - Essential malware analysis toolkit

### Linux Privilege Escalation
- **Core Techniques** - Systematic privilege escalation methodologies
- **Practice Machines** - Hands-on CTF challenges (UltraTech, Lazy Admin, Anonymous, GhostCat, etc.)
- **Wiz CTF Challenges** - Advanced scenarios and real-world practice

### OpSec & Security Intelligence
- **Operational Security** - Best practices and methodologies
- **Critical CVE Analysis** - Latest vulnerability research and impact assessment

## Quick Start

### Running with Docker

**Option 1: Docker Compose (Recommended)**
```bash
docker-compose up --build
```

**Option 2: Manual Docker Build**
```bash
docker build -t pnpt-docs -f Docker/Dockerfile .
docker run -d -p 8000:8000 pnpt-docs
```

**Option 3: Pre-built Image**
```bash
docker pull ghcr.io/slehee/linux-privesc:latest
docker run -d -p 8000:8000 --name pnpt-training ghcr.io/slehee/linux-privesc
```

Then visit **http://localhost:8000** to access the documentation.

## Features

- **Full-text search** across all documentation
- **Responsive design** with dark/light mode toggle
- **Interactive content** with code highlighting and diagrams
- **Structured navigation** by training domain
- **PDF export** capability for offline study
- **Tagged content** for easy cross-referencing

## Learning Path

1. **Start with PNPT Intro** - Understand methodology and fundamentals
2. **Practice Linux PrivEsc** - Build foundational skills with hands-on labs
3. **Explore Active Directory** - Advanced network penetration techniques
4. **Dive into PMAT** - Develop malware analysis capabilities
5. **Master OpSec** - Learn to operate securely and stay current with threats

---

*Based on TCM Security Academy courses and real-world penetration testing experience.*
