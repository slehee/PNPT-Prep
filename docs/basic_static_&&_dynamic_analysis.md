![PMAT](assets/img/PMAT.png)

- Do not download these samples to a computer you do not own.
- Do not execute any of these samples on a computer you do not own.
- Do not download and/or execute these samples in an environment where you cannot revert to a saved state, i.e. a virtual machine.
- Practice safe malware handling procedures at all times when using these samples.


# Static Malware Analysis

Basic static analysis involves examining malware without executing it, using a variety of tools and techniques:

- **Hashing Malware Samples:** Generate unique identifiers for files to track and compare them.

    For example, on Linux you can use:
    ```bash
    sha256sum malware.exe
    md5sum malware.exe
    ```
    On Windows (PowerShell):
    ```powershell
    Get-FileHash malware.exe -Algorithm SHA256
    Get-FileHash malware.exe -Algorithm MD5
    ```


- **Malware Repositories (e.g., VirusTotal):** Submit and analyze samples using online databases for threat intelligence.
- **Strings & FLOSS:** Extract readable strings from binaries to uncover clues about functionality, commands, or embedded URLs.

!!! tip
    FLOSS can be run with the "-n" argument to specify your desired minimum string length. Sometimes, longer strings can be more useful to an analyst than your standard string of len(4).

    For example, to pull all strings of length 6 or greater:
    ```
    floss.exe -n 6 [malware_name.exe]
    ```


- **Import Address Table (IAT) Analysis:** Review imported functions to infer capabilities and behaviors.

    PEview is a lightweight Windows tool used to inspect the internal structure of PE (Portable Executable) files. It allows analysts to view headers, sections, and the Import Address Table, making it easier to identify which Windows API functions a binary imports and potentially uses during execution.

![PeView](assets/img/Peview.png)

- **Windows API Introduction:** Understand how malware interacts with the operating system through API calls.
- **MalAPI.io:** Use online resources to look up Windows API functions and their security implications. ([malapi.io](https://malapi.io/))
- **Packed Malware Analysis:** Identify if a sample is packed or obfuscated, which can hide its true behavior.
- **Combining Methods (e.g., PEStudio):** Use multiple static analysis tools for a comprehensive overview.


![pestudio](assets/img/pestudio.png)

- **MITRE ATT&CK Mapping:** Relate discovered capabilities to known adversary techniques for better context.

## Malware.Unknown.exe

| Analysis Step                | Details |
|-----------------------------|---------|
| **File Hash & VT Analysis**  | 92730427321a14ccfc0d0580834daef98121efa9bb8963da332bfd6cf1fda8a  (*Malware.Unknown.exe.malz*)<br>1d8562c0adcace734d63f7baaca02f7c  (*Malware.Unknown.exe.malz*)<br>VT Analysis: No results |
| **Strings & Floss Output**   | **FLOSS static Unicode strings:**<br>- jjjj<br>- cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q "%s"<br>- [http]://ssl-6582datamanager[.]helpdeskbros[.]local/favicon.ico<br>- C:\Users\Public\Documents\CR433101.dat.exe<br>- Mozilla/5.0<br>- [http]://huskyhacks[.]dev<br>- ping 1.1.1.1 -n 1 -w 3000 > Nul & C:\Users\Public\Documents\CR433101.dat.exe<br>- open |
| **IAT & PEView**             | **Window API Calls:**<br>- DownloadFromURL<br>- InternetOpenURLA<br>- ShellExec |

---

### About the Sample

The sample analyzed here, `Malware.Unknown.exe.malz`, is provided as part of the PMAT-labs at `labs/1-1.BasicStaticAnalysis/Malware.Unknown.exe.malz/Malware.Unknown.exe.7z`. Our goal during basic static analysis is to triage threats quickly and accurately by correlating static indicators.

### Introducing Capa

To further assist in this phase, we can use a tool called [Capa](https://github.com/mandiant/capa). Capa detects malicious capabilities in suspicious programs by matching technical indicators (like API calls or strings) against a set of high-level, human-readable rules. For example, Capa can identify if a binary is capable of "receiving data" or "connecting to a URL" by analyzing its features and matching them to rules.

- Capa comes with a default rule set and an open-source repository of community-contributed rules: [capa-rules](https://github.com/mandiant/capa-rules).
- To use Capa, run `capa -h` to see the usage menu and available options.
- Example usage: `capa Malware.Unknown.exe.malz`

Capa's output provides both technical details (like hashes) and high-level information, including mappings to MITRE ATT&CK tactics and techniques.

### What is MITRE ATT&CK?

[MITRE ATT&CK](https://attack.mitre.org/) is a widely adopted framework that classifies adversary tactics, techniques, and procedures (TTPs). It helps analysts understand and communicate about the types of actions adversaries take, such as gaining initial access (TA0001 - Initial Access) or executing code. The framework is an industry standard for threat intelligence and incident response.

## Malware Sample Sources

References:

- PMAT Labs: [https://github.com/HuskyHacks/PMAT-labs](https://github.com/HuskyHacks/PMAT-labs)
- theZoo: [https://github.com/ytisf/theZoo](https://github.com/ytisf/theZoo)
- vx-underground main site: [https://www.vx-underground.org/](https://www.vx-underground.org/)
- vx-underground GitHub repo: [https://github.com/vxunderground/MalwareSourceCode](https://github.com/vxunderground/MalwareSourceCode)
- Zeltser Resources: [https://zeltser.com/malware-sample-sources/](https://zeltser.com/malware-sample-sources/)
- MalwareBazaar: [https://bazaar.abuse.ch/](https://bazaar.abuse.ch/)



## Step-by-Step Static Analysis Workflow

Follow these steps to perform basic static analysis on a malware sample:

1. **Hash the Sample**
   - Generate file hashes (SHA256, MD5) to uniquely identify and track the sample.
   - Tools: `sha256sum`, `md5sum` (Linux), `Get-FileHash` (Windows PowerShell)

2. **Check Online Repositories**
   - Submit the hash or sample to services like VirusTotal for threat intelligence and prior analysis.
   - Tools: VirusTotal

3. **Extract Strings**
   - Use FLOSS or the `strings` utility to extract readable strings, looking for URLs, file paths, commands, or suspicious keywords.
   - Tools: FLOSS, `strings`

4. **Analyze Import Address Table (IAT)**
   - Inspect the binary’s IAT to identify imported Windows API functions and infer capabilities.
   - Tools: PEview

5. **Research API Functions**
   - Look up suspicious or unfamiliar API calls to understand their purpose and potential risks.
   - Tools: MalAPI.io

6. **Detect Malicious Capabilities**
   - Use Capa to automatically identify high-level malicious behaviors and map them to MITRE ATT&CK techniques.
   - Tools: Capa

7. **Check for Packing/Obfuscation**
   - Determine if the sample is packed or obfuscated, which may hide its true behavior.
   - In PEview, compare the Image Section Header’s Virtual Size and Raw Data Size:
     - If the Virtual Size is much larger than the Raw Data Size, this may indicate packing or obfuscation.
     - Packed samples often have a small Raw Data Size but a large Virtual Size, as the unpacked code is loaded into memory at runtime.
   - Tools: PEview, PEStudio

8. **Map to MITRE ATT&CK**
   - Relate discovered capabilities and indicators to MITRE ATT&CK techniques for context.

9. **Document Findings**
   - Record all indicators, hashes, strings, API calls, packing status, and analysis results for reference in dynamic analysis.

# Dynamic (Heuristic) Malware Analysis

![dynm](assets/img/dynam.png)

At the start of dynamic malware analysis, the focus is on observing two main types of indicators: host-based and network-based. Host indicators involve changes or actions on the local system, such as file deletion or persistence mechanisms, while network indicators involve activity visible on the network, like calling out to domains or downloading files. It doesn't matter which type you examine first, as long as both are covered thoroughly. By monitoring both host and network behaviors when detonating malware, you gain valuable insights that will inform deeper analysis in later phases.

First thing to think about is that we have a certain amount of notes now, and we should let this inform how we perform our basic dynamic analysis. In other words, from the strings that we pulled out, we already have a bead on a couple of potential indicators, host and network indicators. So we'll be on the lookout for things like this, and I'll show you exactly how to apply that and what to look for here in a moment. But the other thing that we have to worry about is making sure that our tools are up and ready to go as far as the detonation of this malware is concerned. So I want to start by doing something here. If we don't have all of our tools up and running, let's say we arm this piece of malware, and we say, all right, it's time to see what this does, and we double-click, and we get a command prompt window briefly, and then the malware disappears. And so what just happened? Well, we're not totally sure, right? Because we didn't have all of our tools up and running and ready to go. Now, one thing that this malware does is that it reaches out to a domain and tries to see if it's online. And in a sandbox without an internet connection, there's not going to be any domain for the malware to contact. And the second part of the logic of this malware says, hey, if you don't find a domain there, go ahead and exit out of the program and delete yourself from disk. And so that can be very detrimental to our analysis, because what if that was the only copy of that sample that we had on hand? Now we've got to go track down the sample again. So it's important to make sure that all of our tools are up and running and ready to go.

Before starting dynamic analysis, ensure your REMnux box is running `INetSim` to simulate internet services and is set as your network's DNS server. Start Wireshark with `sudo wireshark`, select your main network adapter, and begin capturing packets. Test the setup by browsing to a site like google.com or a test domain (e.g., http://freet-shirts.info) to confirm that INetSim is serving responses and network traffic is being captured. This step verifies that your simulated internet environment and monitoring tools are working before proceeding with malware detonation and analysis.

Now, moving from basic static to basic dynamic analysis, the next step is to remove the `.malz` extension from the sample and convert it to an executable format. Using the notes and indicators gathered from the static analysis (see the table above), we can focus on both host-based and network-based indicators during execution. For example, the URL `ssl-6582datamanager.helpdeskbros.local/favicon.ico` found in the strings is a potential network indicator. In Wireshark, we can use display filters like `http.request.uri contains "favicon.ico"` to monitor for related network activity when the malware is detonated. This approach allows us to directly correlate static findings with dynamic network behavior as we analyze the sample in real time.

In Wireshark, we examine the captured traffic and look under the Hypertext Transfer Protocol header to see the details of the request. We observe a GET request for favicon.ico, with the user agent matching what was found in the static strings output. The full URI in the packet matches the indicator we identified earlier. This confirms a strong correlation between static and dynamic analysis: the string extracted from the binary is seen as actual network activity when the malware runs. Capturing and documenting this packet provides clear evidence of the malware's network behavior and helps build a set of network signatures for further analysis.

![dynw](assets/img/dywire.png)



## Host-Based Indicators with ProcMon

Now, let's pivot to host-based indicators. One of the primary tools for this is ProcMon from the Sysinternals suite. ProcMon provides detailed, real-time monitoring of process activity, including file, registry, and network operations.

- Launch ProcMon and accept the EULA.
- Use the filter icon to set criteria:
    - Filter by `Process Name` set to the malware’s filename (e.g., `malware.unknown.exe`).
    - Optionally, filter by `Operation` (e.g., contains "File") to focus on file-related events.
- Detonate the malware and observe events in ProcMon:
    - Key columns: Process Name, Process ID, Operation, Path.
    - Look for file creation events, especially those matching paths found during static analysis (e.g., `C:\Users\Public\Documents\CR433101.dat.exe`).
- Confirm indicators by checking the file system for newly created files.
- Test persistence by deleting the file and re-running the malware to see if it is recreated.

![procmon](assets/img/procmon.png)

### Correlating Network and Host-Based Indicators

When analyzing dynamic behavior, observe both the network activity and resulting changes on the host:

- The malware reaches out to a specific URI (e.g., requesting `favicon.ico`), and creates a file on the system—often on the Desktop or in a user directory.
- In a simulated environment like INetSim, requests to non-existent domains (e.g., `doesntexist.com/evil.exe`) will return a default INetSim binary, not the actual intended payload.
- This behavior suggests the malware may function as a dropper, attempting to download and save a second-stage payload from a remote address.
- The use of `favicon.ico` is a common technique, as browsers automatically request this file when visiting a site. Adversaries may abuse this to deliver payloads or mask malicious activity.
- If a file is written to disk after such a request, it is reasonable to hypothesize that the downloaded content (e.g., `favicon.ico`) could be the intended payload.
- Without access to the real remote resource, the actual payload cannot be confirmed, but the correlation between the network request and file creation is a strong indicator of dropper behavior.

### Host-Based Indicators (Part 2): Self-Deletion Logic

Some malware samples include a self-deletion mechanism as a kill switch. In this case, if INETSim is not running when the malware is executed, the sample deletes itself from disk. This behavior can be confirmed and analyzed using ProcMon:

- The malware uses a command involving `cmd.exe`, a ping command, and a delete operation (e.g., `cmd.exe /C ping ... & Del /f /q "malware.exe"`).
- Extract this command from the static strings and use it as a filter in ProcMon (Details contains the command, Process Name is the malware filename).
- Detonate the malware with INETSim running: the sample executes normally and does not delete itself.
- Stop INETSim and detonate again: the malware triggers its self-deletion logic, visible in ProcMon as a call to `cmd.exe` and a file deletion event.
- This logic acts as a kill switch—if the malware cannot reach its intended URL, it exits and removes itself from the system.

This technique helps adversaries avoid detection and analysis if their command-and-control infrastructure is offline.

![evidence](assets/img/delete.png)

### Program Execution Flow (Summary)

Based on the observed behavior and limited reverse engineering, the malware’s logic can be summarized as follows:

- **If the target URL exists (e.g., `helpdeskbros.local/favicon.ico`):**
  - Download `favicon.ico`.
  - Write the downloaded file to disk as `CR433101.dat.exe`.
  - Execute `CR433101.dat.exe`.

- **If the target URL does not exist:**
  - Do not download or write any file.
  - Delete itself from disk.
  - Do not execute further.

This flow demonstrates how the malware uses network connectivity as a trigger for its actions, either deploying a second-stage payload or activating a self-deletion kill switch.

## Malware.Unknown.exe: Combined Static and Dynamic Analysis Report

| Analysis Step                | Details |
|-----------------------------|---------|
| **File Hash & VT Analysis**  | 92730427321a14ccfc0d0580834daef98121efa9bb8963da332bfd6cf1fda8a  (*Malware.Unknown.exe.malz*)<br>1d8562c0adcace734d63f7baaca02f7c  (*Malware.Unknown.exe.malz*)<br>VT Analysis: No results |
| **Strings & Floss Output**   | **FLOSS static Unicode strings:**<br>- jjjj<br>- cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q "%s"<br>- [http]://ssl-6582datamanager[.]helpdeskbros[.]local/favicon.ico<br>- C:\Users\Public\Documents\CR433101.dat.exe<br>- Mozilla/5.0<br>- [http]://huskyhacks[.]dev<br>- ping 1.1.1.1 -n 1 -w 3000 > Nul & C:\Users\Public\Documents\CR433101.dat.exe<br>- open |
| **IAT & PEView**             | **Window API Calls:**<br>- DownloadFromURL<br>- InternetOpenURLA<br>- ShellExec |
| **Capa Capabilities**        | Detected capabilities: Download files, Execute files, Network communication, Self-deletion (mapped to MITRE ATT&CK techniques) |
| **Packing/Obfuscation**      | Compared Virtual Size and Raw Data Size in PEview:<br>- No significant difference (not packed)<br>or<br>- Large difference (likely packed/obfuscated) |
| **MITRE ATT&CK Mapping**     | Initial Access, Execution, Defense Evasion (self-deletion), Command and Control (network requests) |

---

### Dynamic Analysis

| Indicator Type   | Details |
|------------------|---------|
| **Network**      | Malware attempts to reach `helpdeskbros.local/favicon.ico`.<br>If successful, downloads and writes `CR433101.dat.exe`.<br>Observed in Wireshark using filter `http.request.uri contains "favicon.ico"`.<br>![Wireshark](assets/img/dywire.png) |
| **Host**         | File creation: `C:\Users\Public\Documents\CR433101.dat.exe`.<br>Confirmed in ProcMon.<br>![ProcMon](assets/img/procmon.png) |
| **Self-Deletion**| If INetSim is not running, malware deletes itself from disk.<br>Observed as a call to `cmd.exe` and file deletion event in ProcMon.<br>![Evidence](assets/img/delete.png) |

---

### Program Execution Flow

- If the target URL exists:
  - Download `favicon.ico`
  - Write to disk as `CR433101.dat.exe`
  - Execute the file
- If the target URL does not exist:
  - Do not download or write any file
  - Delete itself from disk
  - Do not execute further

# Basic Dynamic Analysis: `rat.unknown.exe.mals`

This section documents the analysis of the new sample, `rat.unknown.exe.mals`, located in the Basic Dynamic Analysis directory. The IR team suspects command execution capability and requests identification of network and host-based signatures, as well as any other notable findings.

## Initial Artifacts

| Artifact Type | Details |
|---------------|--------|
| **MD5 Hash**      | 689FF2C6F94E31ABBA1DDEBF68BE810E |
| **SHA-1 Hash**    | 69B8ECF6B7CDE185DAED76D66100B6A31FD1A668 |
| **SHA-256 Hash**  | 248D491F89A10EC3289EC4CA448B19384464329C442BAC395F680C4F3A345C8C |
| **Archive Password** | infected |
| **Extraction Method** | 7-zip archive, extracted to desktop |
| **Sample Name**   | rat.unknown.exe.mals |

## Basic Static Artifact Collection

| Step | Tool/Method | Result/Notes |
|------|-------------|--------------|
| Extract readable strings | FLOSS | *(to be filled as analysis progresses)* |
| ...existing steps... | ... | ... |

## rat.unknown.exe.mals

### Strings & FLOSS Output

| Type                | Details |
|---------------------|---------|
| **Network/HTTP Indicators** | Proxy-Authorization: basic, Content-Length, PATCH, PUT, POST, Connection: Keep-Alive, Host, HTTP/1.1, User-Agent, user-agent, SSL support is not available, https, No uri scheme supplied, http://serv1.ec2-102-95-13-2-ubuntu.local |
| **Windows API Calls** | InternetOpenW, InternetOpenUrlW, wininet, MultiByteToWideChar, kernel32, MessageBoxW, user32 |
| **Nim Language/Client** | Nim httpclient/1.0.6, nymhttp client |
| **Command Execution/Strings** | [+] what command can I run for you, [+] online, NO SOUP FOR YOU |
| **File/Path Indicators** | mscordll.exe, msdcorelib.exe, AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup |
| **Other** | Unknown error, intrt explr, tables.nim, iterators.nim |

---

### Raw Interesting Strings (FLOSS Output)

```
@iterators.nim(189, 11) `len(a) == L` the length of the seq changed while iterating over it
@Proxy-Authorization: basic 
@Content-Length: 
@Content-Length
@PATCH
@PUT
@POST
@Connection: Keep-Alive
@Connection
@Host: 
@ HTTP/1.1
@User-Agent
@user-agent
@tables.nim(1103, 13) `len(t) == L` the length of the table changed while iterating over it
@SSL support is not available. Cannot connect over SSL. Compile with -d:ssl to enable.
@https
@No uri scheme supplied.
InternetOpenW
InternetOpenUrlW
@wininet
@wininet
MultiByteToWideChar
@kernel32
@kernel32
MessageBoxW
@user32
@user32
@[+] what command can I run for you
@[+] online
@NO SOUP FOR YOU
@\mscordll.exe
@Nim httpclient/1.0.6
@/msdcorelib.exe
@AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
@intrt explr
@http://serv1.ec2-102-95-13-2-ubuntu.local
Unknown error
```


## Dynamic Analysis: rat.unknown.exe.mals

### Initial Detonation & Triage

| Step                      | Observation/Indicator                | Evidence |
|---------------------------|--------------------------------------|----------|
| Initial execution         | Message box appears: "NO SOUP FOR YOU" | ![no_soup_for_you](assets/img/no_soup_for_you.png) |

- Upon double-clicking the executable (after renaming), the malware displays a message box with the text "NO SOUP FOR YOU".
- This is a clear host-based indicator and may be used for further behavioral correlation.


![evidence_soupe](assets/img/no_soupe.png)

---

### Network-Based Indicators

| Step                | Observation/Indicator |
|---------------------|----------------------|
| Network activity    | GET request to `http://serv1.ec2-102-95-13-2-ubuntu.local/msdcorelib.exe` |
| User-Agent string   | `intrt explr` in HTTP request |
| Host header         | `serv1.ec2-102-95-13-2-ubuntu.local` |
| Second stage payload| GET request for `msdcorelib.exe` (possible additional capability) |

- After detonation, with INetSim and Wireshark running, the malware initiates a TCP handshake and sends an HTTP GET request to a suspicious URI.
- The request includes a unique user agent string: `intrt explr`.
- The Host header is set to `serv1.ec2-102-95-13-2-ubuntu.local`.
- The GET request for `msdcorelib.exe` may indicate an attempt to download a second stage payload.

![evidence_rat](assets/img/rat.png)

---

### Potential File Download & Name Decoupling

During dynamic analysis, following the HTTP stream in Wireshark reveals a GET request for `msdcorelib.exe` to the remote resource `serv1.ec2-102-95-13-2-ubuntu.local`. INetSim responds with its default binary, indicating a successful transaction and potential file download.

It is important to note that malware often employs a tactic known as name decoupling or dechaining: the file downloaded from a web resource may be written to disk under a different name. This technique helps adversaries evade detection and complicates analysis, as the downloaded data and the file system artifact may not share the same name. Analysts should always verify the actual file written to disk and not assume it matches the name in the network request.

This behavior suggests the malware may be attempting to download a second stage payload or additional capability, and the actual file name on disk should be investigated further.

---

### Host-Based Indicators & Persistence Mechanism

After detonation and network analysis, we pivot to host-based indicators using ProcMon. By filtering for file operations and the startup directory path, we observe the following:

- The malware writes a file named `mscoredll.exe` to the user's startup directory: `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`.
- The file name on disk (`mscoredll.exe`) is different from the name in the network request (`msdcorelib.exe`), demonstrating the name decoupling tactic.
- Writing to the startup directory is a classic persistence mechanism, ensuring the binary will execute upon user login.
- The actual file written is the INetSim default binary, confirming a successful download and write operation.
- The malware dynamically determines the user profile path, so the full path will reflect the current user (e.g., `C:\Users\<username>\AppData\...`).

- Web request to a remote server for a payload.
- Downloaded executable written to disk under a different name in the startup directory.
- Persistence achieved via startup folder placement.
- All actions contingent on a working internet connection; otherwise, an error message is displayed.

![create_file_rat](assets/img/create_file_rat.png)


---

### Host-Based TCP Artifacts & TCPView

When analyzing malware, it's important to recognize that some network-related indicators are only observable from the host itself, not on the network wire. These are known as TCP artifacts. For example, when a binary initiates a TCP connection, the operating system uses specific functions to open sockets and manage connections. These events can be detected as host-based indicators, even if they don't appear in network captures like Wireshark.

**Key Points:**
- **TCP Artifacts:** Indicators such as opened sockets and outbound connections are visible on the host, not on the network wire.
- **Detection Tools:** Tools like TCPView (from the Sysinternals Suite) allow you to monitor active TCP connections and sockets on the host.


![tcpview](assets/img/tcpview.png)

![base64](assets/img/base64.png)