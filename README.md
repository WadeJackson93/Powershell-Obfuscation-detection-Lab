# PowerShell Obfuscation Detection Lab

## Objective
This lab demonstrates how to detect suspicious PowerShell obfuscation and encoded command execution using Microsoft Sentinel, Sysmon, Windows Event Logs, and KQL queries. The goal was to simulate attacker behavior, generate telemetry, and investigate the activity through log analysis and threat detection techniques.

## Tools Used
- Microsoft Sentinel
- Sysmon
- Windows Event Logs
- KQL (Kusto Query Language)

## Attack Simulation
Simulated suspicious PowerShell activity using encoded commands to generate telemetry for detection.

### Simulated Command

```powershell
powershell.exe -EncodedCommand SQBFAFgA
```

### Purpose

This simulation was used to imitate potentially malicious PowerShell behavior commonly observed during:
- Malware execution
- Obfuscated command execution
- Defense evasion techniques
- Post-exploitation activity

The command generated Windows Security Event ID 4688 process creation logs, which were successfully ingested into Microsoft Sentinel for investigation and detection.

### Logging Configuration

To capture this activity:
- Process Creation auditing was enabled
- Command line logging was enabled through Group Policy
- Logs were forwarded into Microsoft Sentinel

### Detection Outcome

The encoded PowerShell execution was successfully identified using a custom KQL detection query within Microsoft Sentinel.## Detection Query

```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has_any (
    "-enc",
    "-EncodedCommand",
    "Invoke-Expression",
    "IEX",
    "DownloadString",
    "FromBase64String"
)
| project TimeGenerated, Account, Computer, NewProcessName, CommandLine
```

## Detection Results

The suspicious PowerShell activity was successfully detected in Microsoft Sentinel using a custom KQL query focused on encoded and obfuscated PowerShell execution.

### Detection Logic

The query searched for:
- Encoded PowerShell commands
- Obfuscation indicators
- Suspicious PowerShell execution patterns

### KQL Detection Query

```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has_any (
    "-enc",
    "-EncodedCommand",
    "Invoke-Expression",
    "IEX",
    "DownloadString",
    "FromBase64String"
)
| project TimeGenerated, Account, Computer, NewProcessName, CommandLine
| order by TimeGenerated desc
```

### Detection Findings

The query successfully identified:
- Encoded PowerShell execution
- The originating host
- User account involved
- Full PowerShell command line activity
- Process creation telemetry

### MITRE ATT&CK Mapping

| Technique | Description |
|---|---|
| T1059.001 | PowerShell |
| T1027 | Obfuscated Files or Information |
| T1140 | Deobfuscate/Decode Files or Information |

### Outcome

This lab demonstrated how Microsoft Sentinel can detect suspicious PowerShell activity using Windows Event Logs, Sysmon telemetry, and KQL-based threat hunting queries.


## Skills Demonstrated
- Threat Detection
- KQL Querying
- Log Analysis
- Sysmon Configuration
- Microsoft Sentinel Investigation
- PowerShell Monitoring
