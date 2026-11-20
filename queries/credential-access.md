# Credential access

## LSASS memory dump with comsvcs.dll
**MITRE ATT&CK:** T1003.001 (OS Credential Dumping: LSASS Memory)

```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^rundll32\.exe$/i
| CommandLine=/comsvcs(\.dll)?[,\s]+(#\s*24|minidump)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```

**Triage:** treat as a likely compromise. Contain the host, identify which accounts had sessions on it, and plan credential resets.

## Password spraying from one source
**MITRE ATT&CK:** T1110.003 (Brute Force: Password Spraying)

```
#event_simpleName=UserLogonFailed2
| groupBy([RemoteAddressIP4], function=[count(as=failures), count(UserName, distinct=true, as=accounts)])
| accounts >= 10
| sort(accounts, order=desc)
```

**Triage:** check whether the source is internal (misconfigured service) or external, and whether any of the targeted accounts later logged on successfully from the same address.
