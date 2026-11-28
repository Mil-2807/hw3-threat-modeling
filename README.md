# hw3-threat-modeling
Homework 3 for Security Governance
Deadline : 11th  December, 2026
## Security Goals
| Objectif | Cible	| Privilège requis |	Propriété	Impact |
|---|---|---|---|
| G1 |	H20 – Database root |	Confidentiality |	Leak of Customers' Personal Data |
| G2 | H13 – Serveur	root | Intégrity | Taking Control of the Estate |
| G3 | H21 – Database	user | Confidentiality | Reading payroll and general ledger data |

## STRIDE Analysis – Misconfigurations

The STRIDE script identified two additional threats caused by host misconfigurations:

| ID | Host | Misconfiguration | STRIDE category | Potential impact |
|---|---|---|---|---|
| MC1 | H12 – printer-floor2 | Default administrator credentials on the web interface | Spoofing | An attacker may use default credentials to impersonate an authorized user. |
| MC2 | H26 – jump-host | SSH password authentication enabled without account lockout | Spoofing | An attacker may perform repeated password attempts to impersonate the SSH user. |

Both issues affect authentication and may allow unauthorized access. MC2 is particularly relevant because H26 is an administrative jump host in the management zone.

## Task 3 — Vulnerability Mapping and Coverage

The mapping process identified 22 unique CVEs across the network infrastructure.

### Mapping coverage

- **CWE:** 19 of 22 CVEs mapped (86.4%).
- **CAPEC:** 3 of 22 CVEs mapped (13.6%).
- **MITRE ATT&CK:** 2 of 22 CVEs mapped (9.1%).

The three CAPEC mappings use CAPEC-126 (Path Traversal), derived through CWE-22 for CVE-2019-11510, CVE-2021-41773 and CVE-2021-43798.

Two CVEs currently have ATT&CK technique mappings: CVE-2019-11510 and CVE-2021-41773. CVE-2021-43798 remains unmapped to ATT&CK because no sufficiently supported association was established.

Three CVEs have no CWE mapping in the retrieved NVD data. These gaps are retained as unknown rather than filled with unsupported assumptions.

### STRIDE distribution

The CVE classification contains:

- Elevation of Privilege: 17
- Tampering: 14
- Information Disclosure: 7
- Spoofing: 2
- Repudiation: 0
- Denial of Service: 0

A CVE may be associated with multiple STRIDE categories; therefore, these counts are not mutually exclusive.

### Limitations

The mapping is incomplete, particularly at the CAPEC and ATT&CK levels. CWE mappings were retrieved from the NVD API, while CAPEC and ATT&CK associations were added only where a defensible relationship could be established. Missing mappings indicate gaps in available evidence or analysis, not an absence of security risk.