
import csv

file_path = "output/cve_mapping.csv"

with open(file_path, "r", encoding="utf-8-sig") as file:
    reader = csv.DictReader(file)
    rows = list(reader)
    fields = reader.fieldnames

for row in rows:
    if row["CVE"] == "CVE-2019-11510":
        row["ATTACK_Tactic"] = (
            "Discovery;Credential Access;Execution;"
            "Initial Access;Persistence"
        )

with open(file_path, "w", newline="", encoding="utf-8-sig") as file:
    writer = csv.DictWriter(file, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

print("ATT&CK tactics corrected.")
