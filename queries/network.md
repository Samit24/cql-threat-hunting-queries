# Command and control

## Rare domains across the estate
**MITRE ATT&CK:** T1071.004 (Application Layer Protocol: DNS), T1568 (Dynamic Resolution)

```
#event_simpleName=DnsRequest
| groupBy([DomainName], function=[count(aid, distinct=true, as=hosts), count(as=requests)])
| hosts <= 2
| sort(requests, order=desc, limit=200)
```

**Triage:** remove known internal and CDN domains, then look up the rest in threat intel. Repeated requests from a single host to a new domain deserve a closer look.

## Connections to ports linked to backdoors
**MITRE ATT&CK:** T1571 (Non-Standard Port)

```
#event_simpleName=NetworkConnectIP4
| in(field="RemotePort", values=["4444", "1337", "31337", "6667", "5555"])
| table([@timestamp, ComputerName, RemoteAddressIP4, RemotePort, ContextBaseFileName])
```
