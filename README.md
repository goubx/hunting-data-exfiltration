# Hunting Insider Data Exfiltration on a Corporate Endpoint

A hands-on threat hunt run through Microsoft Defender for Endpoint. An employee on a performance improvement plan raised insider risk concerns. This hunt investigates their corporate device for signs of proprietary data being collected, compressed, and prepared for theft, then chases the activity from archive creation back to the process behind it and out to the network.

> Note: hostnames and account names in this writeup have been sanitized. File and script names shown are lab artifacts and contain no real data.

| | |
|---|---|
| **Platform** | Microsoft Defender for Endpoint (Advanced Hunting) |
| **Query Language** | KQL |
| **Tactic** | Collection / Exfiltration |
| **MITRE Technique** | T1560.001 Archive Collected Data |
| **Outcome** | Automated archiving and local staging of employee data confirmed. No network exfiltration observed |

## Contents

- [Background](#background)
- [Hypothesis](#hypothesis)
- [The Hunt](#the-hunt)
- [Findings](#findings)
- [Timeline](#timeline)
- [Indicators](#indicators)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Response](#response)
- [Lessons and Improvements](#lessons-and-improvements)
- [Files](#files)

## Background

An employee in a sensitive department was recently placed on a performance improvement plan and reacted badly. Management raised concerns that the employee might try to steal proprietary information before leaving. The task was to investigate their corporate device for any sign of data being staged for theft.

The employee is a local administrator on the device with no restrictions on the applications they can run. That makes archiving sensitive data and pushing it to a personal destination a realistic concern, since nothing on the host would block it.

## Hypothesis

The employee may be collecting sensitive company data, compressing it into an archive, and preparing to move it off the device to a private destination.

## The Hunt

The hunt follows a structured lifecycle: build the hypothesis, collect the data, analyze it, investigate, respond, and document. The flow here pivots from archive files, to the process that created them, to the network, to confirm whether anything actually left the box.

### Step 1: Hunt for archive activity

```kql
DeviceFileEvents
| where DeviceName == "WIN-TARGET-01"
| where FileName endswith ".zip"
| order by Timestamp desc
```

Starting at the file system, the hunt looks for archive files being created. The result showed steady `.zip` creation activity, with the archives being moved into a folder named like a backup location. The regular cadence stood out as worth a closer look.

### Step 2: Pivot to the process behind a single archive

```kql
let VMName = "WIN-TARGET-01";
let specificTime = datetime(2026-06-13T15:43:03.8113194Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```

Taking the timestamp of one archive and looking at process activity in a two minute window around it told the whole story. A PowerShell script ran, silently installed 7-Zip, then used it to compress employee data into an archive.

Key command lines observed:

- PowerShell launching the script: `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1`
- 7-Zip installed silently: `7z2408-x64.exe /S` (the `/S` flag suppresses the install UI so it runs without prompting)
- 7-Zip archiving the data: `7z.exe a C:\ProgramData\employee-data-20260613154255.zip C:\ProgramData\employee-data-temp20260613154255.csv`

### Step 3: Check the network for exfiltration

```kql
let VMName = "WIN-TARGET-01";
let specificTime = datetime(2026-06-13T15:43:03.8113194Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 4m) .. (specificTime + 4m))
| where DeviceName == VMName
| order by Timestamp desc
```

With the archiving confirmed, the last question was whether the data actually left the device. Searching network events around the same window turned up no evidence of exfiltration. The data was being staged, but no outbound transfer was observed.

## Findings

A PowerShell script, `exfiltratedata.ps1`, was running on the device and creating archives of employee data at regular intervals. Each run silently installed 7-Zip and used it to compress a CSV of employee data into a timestamped `.zip` file staged locally in `C:\ProgramData`.

This is textbook collection and staging behavior. Data was gathered from the local system, compressed with an archive utility, and parked in a staging location, which is exactly what an insider would do before moving it out. That said, the network events showed no sign that any archive was actually exfiltrated during the observed window. The staging was confirmed. The exfiltration leg was not.

## Timeline

| Time (UTC) | Event |
|------------|-------|
| 2026-06-13 15:43:03 | `exfiltratedata.ps1` runs via PowerShell and silently installs 7-Zip |
| 2026-06-13 15:43:03 | 7-Zip compresses an employee data CSV into a `.zip` staged in `C:\ProgramData` |
| Recurring | Archives created at regular intervals by the script, moved to a backup-style folder |
| Same window | Network events checked, no exfiltration observed |
| On detection | Host isolated, findings relayed to the employee's manager |

## Indicators

| Type | Value |
|------|-------|
| Host | WIN-TARGET-01 |
| Script | exfiltratedata.ps1 (C:\programdata\exfiltratedata.ps1) |
| Launched via | powershell.exe -ExecutionPolicy Bypass |
| Tool installed | 7-Zip, silent install (7z2408-x64.exe /S) |
| Archiving command | 7z.exe a employee-data-[timestamp].zip |
| Staging location | C:\ProgramData |
| Exfiltration | None observed |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|----|
| Collection | Data from Local System | T1005 | Employee data gathered from the device into a CSV |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 | 7-Zip used to compress the data into a `.zip` |
| Collection | Local Data Staging | T1074.001 | Archives staged in `C:\ProgramData` |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | `exfiltratedata.ps1` run via PowerShell with execution policy bypass |
| Command and Control | Ingress Tool Transfer | T1105 | 7-Zip silently installed onto the host by the script |
| Exfiltration | Exfiltration Over Web Service | T1567 | The intended next stage. Not observed in the network logs |

## Response

- Isolated the device as soon as the archiving activity was confirmed.
- Relayed the full findings to the employee's manager through security operations, including that archives were being created at regular intervals by a PowerShell script.
- Noted that no evidence of exfiltration was found, so the situation was staging caught before any data left the device.

## Lessons and Improvements

**What allowed this:**

- The employee being a local administrator with no application restrictions let a script silently install software and archive data unchecked. Removing local admin and applying application control would block both the install and the archiving tool.
- Execution policy bypass let an unsigned script run freely. Constrained language mode or script signing requirements would stop that.
- Sensitive data sitting where it could be collected and staged with no controls made the collection trivial. Data loss prevention and tighter access to sensitive files would raise the bar.

**What would sharpen the next hunt:**

- Build a scheduled detection for archive utilities being installed or run shortly after a sensitive file is touched, especially when launched by PowerShell.
- Alert on archives being written to staging locations like `C:\ProgramData` on a recurring schedule, which is the cadence that gave this away.
- Pair the staging detection with outbound network monitoring so that if the exfiltration leg ever fires, it links straight back to the staged archive.

## Files

- `README.md` - this writeup
- `queries.kql` - every KQL query used in the hunt

---

Part of an ongoing series of threat hunting and SOC investigations by Mohamed Yagoub.
