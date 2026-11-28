
import csv

file_path = "output/cve_mapping.csv"

mappings = {
    "CVE-2019-11510": {
        "techniques": "T1083;T1552.001;T1059;T1133",
        "tactics": "Discovery;Credential Access;Execution;Initial Access",
        "status": "CWE, CAPEC and ATT&CK mapped (ATT&CK v15.1)"
    },
    "CVE-2021-41773": {
        "techniques": "T1059;T1210",
        "tactics": "Execution;Lateral Movement",
        "status": "CWE, CAPEC and ATT&CK mapped (ATT&CK v15.1)"
    },
    "CVE-2021-43798": {
        "techniques": "Unmapped",
        "tactics": "Unmapped",
        "status": "CWE and CAPEC mapped; ATT&CK unmapped"
    }
}

with open(file_path, "r", encoding="utf-8-sig") as file:
    reader = csv.DictReader(file)
    rows = list(reader)
    fields = reader.fieldnames

for row in rows:
    cve = row["CVE"]

    if cve in mappings:
        row["ATTACK_Technique"] = mappings[cve]["techniques"]
        row["ATTACK_Tactic"] = mappings[cve]["tactics"]
        row["Mapping_Status"] = mappings[cve]["status"]

with open(file_path, "w", newline="", encoding="utf-8-sig") as file:
    writer = csv.DictWriter(file, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

print("ATT&CK mappings updated.")
