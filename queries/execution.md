# Execution

## PowerShell with an encoded command
**MITRE ATT&CK:** T1059.001 (Command and Scripting Interpreter: PowerShell)

```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(powershell|pwsh)\.exe$/i
| CommandLine=/\s-e(nc|ncodedcommand)?\s/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine], limit=1000)
```

**Triage:** decode the Base64 (it is UTF-16LE). Benign hits are usually management agents; check the parent process and whether the decoded script downloads or runs code from the internet.

## Office application spawning a shell or script host
**MITRE ATT&CK:** T1204.002 (User Execution: Malicious File)

```
#event_simpleName=ProcessRollup2 event_platform=Win
| ParentBaseFileName=/^(winword|excel|powerpnt|outlook|onenote)\.exe$/i
| FileName=/^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\.exe$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

**Triage:** very few legitimate workflows do this. Find the document that was open, check how it arrived (email, download) and look for follow-on network connections.

## MSHTA running remote or inline script
**MITRE ATT&CK:** T1218.005 (System Binary Proxy Execution: Mshta)

```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^mshta\.exe$/i
| CommandLine=/(https?:\/\/|javascript:|vbscript:)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```
