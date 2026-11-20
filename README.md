# CQL Threat Hunting Queries

A small, practical library of **CrowdStrike Query Language (CQL)** hunts for **Falcon LogScale** and **Falcon Next-Gen SIEM**, grouped by MITRE ATT&CK tactic. Every query comes with the technique it targets and short triage notes.

| File | Hunts |
|---|---|
| [`queries/execution.md`](queries/execution.md) | Encoded PowerShell, Office spawning shells, MSHTA abuse |
| [`queries/credential-access.md`](queries/credential-access.md) | LSASS dump via comsvcs.dll, password spraying |
| [`queries/defense-evasion-impact.md`](queries/defense-evasion-impact.md) | Shadow copy deletion, certutil download/decode |
| [`queries/persistence-discovery.md`](queries/persistence-discovery.md) | Scheduled task creation, bursts of discovery commands |
| [`queries/network.md`](queries/network.md) | Rare domains, backdoor ports |

## How to use

1. Open **Event search / Advanced event search** in the Falcon console (or LogScale).
2. Paste a query and set the time range (start with 7 days).
3. Review the results with the triage notes, then tune exclusions for your environment.
4. Promising hunts can be turned into scheduled searches or custom detections.

## Important

- Field names and event names can differ between Falcon versions, data sources and parsers. **Test each query in your own tenant** before relying on it.
- These are hunting starting points, not tuned detections. Expect some benign results.
- Contributions and corrections are welcome. Open an issue or a pull request.

## Author

**Samit Pudasaini**, Security Engineer, Kathmandu, Nepal
[samitpudasaini.com.np](https://www.samitpudasaini.com.np) | [LinkedIn](https://linkedin.com/in/samit-pudasaini)

Licensed under the MIT License.
