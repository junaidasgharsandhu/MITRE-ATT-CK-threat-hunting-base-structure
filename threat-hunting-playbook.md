# Microsoft Sentinel Threat Hunting Cheat Sheet

> Purpose: Fast, structured threat hunting using Microsoft Sentinel (Log Analytics)  
> Focus: SOC-style investigations mapped to MITRE ATT&CK  
> Works for: Azure VMs, Microsoft Defender for Endpoint, Azure AD, Microsoft 365 logs

---

## Table of Contents

- [Standard Sentinel Hunt Flow](#standard-sentinel-hunt-flow)
- [MITRE ATT&CK Phases — Sentinel View](#mitre-attck-phases--sentinel-view)
  - [Initial Access (TA0001)](#initial-access-ta0001)
  - [Execution (TA0002)](#execution-ta0002)
  - [Persistence (TA0003)](#persistence-ta0003)
  - [Defense Evasion (TA0005)](#defense-evasion-ta0005)
  - [Discovery (TA0007)](#discovery-ta0007)
  - [Credential Access (TA0006)](#credential-access-ta0006)
  - [Command and Control (TA0011)](#command-and-control-ta0011)
  - [Collection (TA0009)](#collection-ta0009)
  - [Exfiltration (TA0010)](#exfiltration-ta0010)
  - [Lateral Movement (TA0008)](#lateral-movement-ta0008)
  - [Anti-Forensics / Impact (TA0005 / TA0040)](#anti-forensics--impact-ta0005--ta0040)
- [Sentinel Analyst Final Checklist](#sentinel-analyst-final-checklist)

---

## Standard Sentinel Hunt Flow

1. Initial Access  
2. Execution  
3. Persistence  
4. Defense Evasion  
5. Discovery  
6. Credential Access  
7. Command and Control  
8. Collection  
9. Exfiltration  
10. Lateral Movement  
11. Anti-Forensics / Impact  

---

## MITRE ATT&CK Phases — Sentinel View

---

## Initial Access (TA0001)
> Think: How did the attacker gain access..

### What to Look For
- Successful logons from external IPs
- RDP / SMB / SSH access
- Valid account abuse

### Primary Tables
- `DeviceLogonEvents` (from MDE)
- `SigninLogs` (Azure AD)

### High-Signal Indicators
- `LogonType == RemoteInteractive`
- External `RemoteIP`
- `ResultType == 0` (Azure AD successful sign-in)

### Go-To Sentinel Query
```kql
let startTime = datetime(2025-10-24 18:55:00);
let endTime   = datetime(2025-12-24 19:10:00);
DeviceLogonEvents
| where TimeGenerated  between (startTime .. endTime )
| where DeviceName contains "Azuki"
| summarize Count = count()
    by RemoteIP, ActionType, LogonType
| order by Count desc
````

---

## Execution (TA0002)
> Think: “What code or command actually ran on the system after access was gained?”
> - Focus on **process execution**, not intent or outcome (those map to later phases)

### What to Look For

* Script execution
* Living-off-the-land binaries (LOLBins)
* PowerShell with suspicious arguments

### Primary Tables

* `DeviceProcessEvents`
* `SecurityEvent` (Event ID 4688)

### Common Binaries

* `powershell.exe`
* `cmd.exe`
* `mshta.exe`
* `wscript.exe`
* `certutil.exe`

### Go-To Sentinel Query

```kql
let startTime = datetime(2025-10-24 18:55:00);
let endTime   = datetime(2025-12-24 19:10:00);
DeviceProcessEvents
| where TimeGenerated between (startTime .. endTime )
| where DeviceName contains "azuki"
| where FileName in ("powershell.exe","cmd.exe","mshta.exe","wscript.exe","certutil.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
```

---

## Persistence (TA0003)
> How do i stay after reboot without logging in agian?

### What to Look For

* Scheduled task creation
* New services
* New local administrator accounts
* Registry Run keys

### Primary Tables

* `DeviceProcessEvents: (what executes after reboot)`
* `DeviceRegistryEvents: (Run keys, persistence registry entries)`

### Key Commands

* `schtasks.exe /create`
* `net user /add`
* `sc create`

### Go-To Sentinel Queries

**Scheduled Task Creation**

```kql
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "/create"
```

**Local Account Creation**

```kql
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Account, TargetAccount
```

---

## Defense Evasion (TA0005)

### What to Look For

* Windows Defender exclusions
* Hidden files or folders
* Log clearing
* Antivirus tampering

### Primary Tables

* `DeviceRegistryEvents`
* `DeviceProcessEvents`

### Defender Registry Locations

* `Exclusions\Paths`
* `Exclusions\Extensions`
* `Exclusions\Processes`

### Go-To Sentinel Query

```kql
DeviceRegistryEvents
| where RegistryKey has "Windows Defender\\Exclusions"
| project TimeGenerated, RegistryKey, RegistryValueName
```

---

## Discovery (TA0007)

### What to Look For

* Network enumeration
* User or session discovery
* System information gathering

### Primary Tables

* `DeviceProcessEvents`

### Common Commands

* `arp -a`
* `ipconfig`
* `net view`
* `whoami`
* `qwinsta`

### Go-To Sentinel Query

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("arp","ipconfig","net view","whoami","qwinsta")
| project TimeGenerated, FileName, ProcessCommandLine
```

---

## Credential Access (TA0006)

### What to Look For

* LSASS memory access
* Mimikatz-style modules
* Short or renamed executables

### Primary Tables

* `DeviceProcessEvents`
* `SecurityEvent` (Event IDs 4688, 4673)

### High-Confidence Indicators

* `sekurlsa::logonpasswords`
* `privilege::debug`

### Go-To Sentinel Query

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("sekurlsa","logonpasswords","privilege::debug")
| project TimeGenerated, FileName, ProcessCommandLine
```

---

## Command and Control (TA0011)

### What to Look For

* Outbound traffic from non-browser processes
* Repeated connections to the same IP
* HTTPS abuse (port 443)

### Primary Tables

* `DeviceNetworkEvents`
* `CommonSecurityLog` (firewalls)

### High-Signal Patterns

* Non-browser processes communicating over port 443
* Same `RemoteIP` appearing across multiple phases

### Go-To Sentinel Query

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName !in ("chrome.exe","msedge.exe","firefox.exe")
| project TimeGenerated, InitiatingProcessFileName, RemoteIP, RemotePort
```

---

## Collection (TA0009)

### What to Look For

* File compression
* Data staging
* ZIP or RAR archive creation

### Primary Tables

* `DeviceProcessEvents`
* `DeviceFileEvents`

### Go-To Sentinel Query

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("Compress-Archive",".zip",".rar")
| project TimeGenerated, ProcessCommandLine
```

---

## Exfiltration (TA0010)

### What to Look For

* Cloud service abuse
* Upload traffic after data staging
* Long-running HTTPS sessions

### Primary Tables

* `DeviceNetworkEvents`
* `OfficeActivity` (Microsoft 365)

### Common Services

* Discord
* Dropbox
* Google Drive
* OneDrive
* Telegram

### Go-To Sentinel Query

```kql
DeviceNetworkEvents
| where RemotePort == 443
| where InitiatingProcessFileName !in ("chrome.exe","msedge.exe")
| project TimeGenerated, RemoteIP, InitiatingProcessFileName
```

---

## Lateral Movement (TA0008)

### What to Look For

* Internal RDP connections
* Credential reuse
* Administrative tool abuse

### Primary Tables

* `DeviceProcessEvents`
* `DeviceLogonEvents`
* `SecurityEvent` (Event ID 4624)

### Common Tools

* `mstsc.exe`
* `cmdkey.exe`
* `psexec.exe`

### Go-To Sentinel Query

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("mstsc","cmdkey","psexec")
| project TimeGenerated, FileName, ProcessCommandLine
```

---

## Anti-Forensics / Impact (TA0005 / TA0040)

### What to Look For

* Event log clearing
* Evidence destruction
* Account manipulation

### Primary Tables

* `DeviceProcessEvents`
* `SecurityEvent`

### High-Risk Command

* `wevtutil cl`

### Go-To Sentinel Query

```kql
DeviceProcessEvents
| where ProcessCommandLine has "wevtutil"
| where ProcessCommandLine has "cl"
| project TimeGenerated, ProcessCommandLine
```

---

## Sentinel Analyst Final Checklist

* ☐ Initial access IP and account identified
* ☐ Execution method confirmed
* ☐ Persistence mechanisms identified and removed
* ☐ Credential theft validated
* ☐ Command-and-control infrastructure identified
* ☐ Exfiltration channel confirmed
* ☐ Lateral movement scoped
* ☐ Impact assessed
* ☐ Remediation recommendations provided

---

> This cheat sheet is intended for defensive threat hunting and SOC operations only.



## Other useful KQL queries.. 

```
AzureActivity
| where TimeGenerated >= ago(7d)
| where ResourceProviderValue =~ "Microsoft.Compute"
| where tolower(ResourceGroup) == tolower("student-rg")
| where OperationNameValue contains "DELETE"
| where ActivityStatusValue == "Success"
| order by TimeGenerated, Caller desc
| project TimeGenerated, OperationNameValue, ResourceGroup, Caller, CategoryValue
```

## KQL Cheat Sheet – Pre vs Post Event Process Comparison (Delta Analysis)

### Purpose
Compare process execution behavior **before and after a known event** (crash, alert, outage) to identify:
- New processes
- Stopped processes
- Significant execution increases or decreases

This technique is used to validate incidents, detect persistence, and identify environmental degradation.

---

### KQL Query – Process Delta Comparison

```kql
// Define the PRE-event window
let pre = 
DeviceProcessEvents
| where DeviceName == "windows-target-1"            // Target host
| where TimeGenerated between                       // Time window BEFORE event
    (datetime(2025-11-20) .. datetime(2025-11-24))
| summarize PreCount = count() by FileName;          // Count executions per process

// Define the POST-event window
let post =
DeviceProcessEvents
| where DeviceName == "windows-target-1"             // Same host
| where TimeGenerated between                        // Time window AFTER event
    (datetime(2025-11-24) .. datetime(2025-11-28))
| summarize PostCount = count() by FileName;         // Count executions per process

// Join both datasets to compare behavior
pre
| join kind=fullouter post on FileName               // Include processes that started or stopped
| extend 
    PreCount  = coalesce(PreCount, 0),               // Replace nulls with 0
    PostCount = coalesce(PostCount, 0)
| extend Delta = PostCount - PreCount                // Calculate execution change
| order by Delta desc                                // Show biggest increases first


