
import csv

input_file = "output/cve_mapping.csv"
capec_url = "https://capec.mitre.org/data/definitions/126.html"

with open(input_file, "r", encoding="utf-8-sig") as file:
    reader = csv.DictReader(file)
    rows = list(reader)
    fields = reader.fieldnames

updated = 0

for row in rows:
    if "CWE-22" in row["CWE"].split(";"):
        row["CAPEC"] = "CAPEC-126"

        if capec_url not in row["Sources"]:
            row["Sources"] += "; " + capec_url

        row["Mapping_Status"] = (
            "CWE and CAPEC mapped; ATT&CK pending"
        )

        updated += 1

with open(input_file, "w", newline="", encoding="utf-8-sig") as file:
    writer = csv.DictWriter(file, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

print("CAPEC mappings updated:", updated)
print("File saved:", input_file)
