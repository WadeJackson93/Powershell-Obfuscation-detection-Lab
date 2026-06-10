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

## Detection Query

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
The query successfully identified suspicious PowerShell execution activity containing encoded command indicators.

## Skills Demonstrated
- Threat Detection
- KQL Querying
- Log Analysis
- Sysmon Configuration
- Microsoft Sentinel Investigation
- PowerShell Monitoring
