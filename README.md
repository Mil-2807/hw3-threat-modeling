# hw3-threat-modeling
Homework 3 for Security Governance
Deadline : 11th  December, 2026
## Security Goals
| Objectif | Cible	| Privilège requis |	Propriété	Impact |
|---|---|---|---|
G1	H20 – Database	root	Confidentiality	Leak of Customers' Personal Data
G2	H13 – Serveur	root	Intégrity	Taking Control of the Estate
G3	H21 – Database	user	Confidentiality	Reading payroll and general ledger data

## STRIDE Analysis – Misconfigurations

The STRIDE script identified two additional threats caused by host misconfigurations:

| ID | Host | Misconfiguration | STRIDE category | Potential impact |
|---|---|---|---|---|
| MC1 | H12 – printer-floor2 | Default administrator credentials on the web interface | Spoofing | An attacker may use default credentials to impersonate an authorized user. |
| MC2 | H26 – jump-host | SSH password authentication enabled without account lockout | Spoofing | An attacker may perform repeated password attempts to impersonate the SSH user. |

Both issues affect authentication and may allow unauthorized access. MC2 is particularly relevant because H26 is an administrative jump host in the management zone.
