# PowerShell Obfuscation Detection Lab

## Objective

This lab demonstrates how to detect suspicious and potentially malicious PowerShell activity using Microsoft Sentinel, Sysmon, Windows Event Logs, and KQL (Kusto Query Language).  

The goal of this project was to simulate encoded PowerShell execution, generate telemetry, and create a detection query capable of identifying common indicators of PowerShell obfuscation and abuse.

---

## Tools Used

- Microsoft Sentinel
- Microsoft Azure
- Sysmon
- Windows Event Logs
- KQL (Kusto Query Language)
- PowerShell

---

## Lab Environment

- Windows Virtual Machine
- Microsoft Sentinel Workspace
- Sysmon installed for enhanced process creation logging
- Log ingestion configured into Sentinel

---

## Attack Simulation

A simulated PowerShell command utilizing encoded execution was executed within the lab environment to generate telemetry associated with suspicious PowerShell behavior.

The activity included:
- Encoded PowerShell execution
- Obfuscated command-line arguments
- Suspicious PowerShell execution patterns commonly observed during adversary activity

Example techniques detected:
- `-enc`
- `-EncodedCommand`
- `Invoke-Expression`
- `IEX`
- `FromBase64String`

---

## Detection Logic

The detection query searched Windows Security Event logs for:
- PowerShell process creation events
- Encoded PowerShell commands
- Obfuscation indicators
- Suspicious execution patterns associated with attacker tradecraft

The query focused on Event ID `4688`, which logs process creation activity.

---

## KQL Detection Query

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

---

## Detection Results

The custom KQL query successfully identified suspicious PowerShell activity generated during the attack simulation.

Microsoft Sentinel captured:
- Encoded PowerShell execution
- Suspicious command-line arguments
- PowerShell process creation telemetry
- User and host context related to the execution

This demonstrates how Sentinel can be used to detect potentially malicious PowerShell behavior commonly leveraged during cyber attacks and post-exploitation activity.

---

## Screenshots

### Microsoft Sentinel Detection Query

[
](https://github.com/WadeJackson93/Powershell-Obfuscation-detection-Lab/blob/main/Powershell%20Obfusucation.png)### Detection Results in Microsoft Sentinel
![Detection Results](./PowerShell%20Screenshot.png)
---

## Key Takeaways

- PowerShell obfuscation is a common attacker technique used to evade detection
- Sysmon provides enhanced visibility into PowerShell activity
- Microsoft Sentinel can detect suspicious execution patterns through KQL queries
- Event ID 4688 is valuable for identifying malicious process creation activity
- KQL enables defenders to rapidly hunt for suspicious behavior across log sources

---

## Skills Demonstrated

- Threat Detection
- Log Analysis
- KQL Query Development
- Microsoft Sentinel Investigation
- Sysmon Configuration
- PowerShell Monitoring
- Security Operations (SOC) Analysis
