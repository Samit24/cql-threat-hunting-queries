# Defense evasion and impact

## Volume shadow copies deleted
**MITRE ATT&CK:** T1490 (Inhibit System Recovery)

```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|wbadmin(\.exe)?\s+delete\s+catalog)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```

**Triage:** a classic ransomware precursor. Escalate immediately and look for mass file modification on the same host.

## Certutil used to download or decode files
**MITRE ATT&CK:** T1105 (Ingress Tool Transfer), T1140 (Deobfuscate/Decode Files)

```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^certutil\.exe$/i
| CommandLine=/(urlcache|verifyctl|-decode|-split)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```
