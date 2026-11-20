# Persistence and discovery

## Scheduled task created from the command line
**MITRE ATT&CK:** T1053.005 (Scheduled Task/Job: Scheduled Task)

```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^schtasks\.exe$/i
| CommandLine=/\s\/create\s/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```

**Triage:** focus on tasks that run from user-writable paths (AppData, Temp, ProgramData) or launch script hosts.

## Burst of discovery commands from one host
**MITRE ATT&CK:** T1087 (Account Discovery), T1082 (System Information Discovery)

```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(whoami|net|net1|nltest|systeminfo|ipconfig|quser|tasklist)\.exe$/i
| bucket(span=10m, field=[ComputerName, UserName], function=count(FileName, distinct=true, as=tools))
| tools >= 4
```

**Triage:** admins run these too; the signal is several in a short burst from a non-admin account or right after an initial-access alert.
