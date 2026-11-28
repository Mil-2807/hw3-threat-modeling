
import csv
from collections import Counter

file_path = "output/cve_mapping.csv"

with open(file_path, "r", encoding="utf-8-sig") as file:
    rows = list(csv.DictReader(file))

total = len(rows)

cwe_mapped = sum(
    1 for row in rows
    if row["CWE"] != "Unknown"
)

capec_mapped = sum(
    1 for row in rows
    if row["CAPEC"] != "Unmapped"
)

attack_mapped = sum(
    1 for row in rows
    if row["ATTACK_Technique"] != "Unmapped"
)

cwe_unknown = total - cwe_mapped
capec_unknown = total - capec_mapped
attack_unknown = total - attack_mapped

print("===== CVE MAPPING COVERAGE =====")
print("Total unique CVEs:", total)

print("\nCWE:")
print("Mapped:", cwe_mapped)
print("Unmapped:", cwe_unknown)

print("\nCAPEC:")
print("Mapped:", capec_mapped)
print("Unmapped:", capec_unknown)

print("\nMITRE ATT&CK:")
print("Mapped:", attack_mapped)
print("Unmapped:", attack_unknown)

print("\n===== COVERAGE PERCENTAGES =====")
print(f"CWE: {cwe_mapped / total * 100:.1f}%")
print(f"CAPEC: {capec_mapped / total * 100:.1f}%")
print(f"ATT&CK: {attack_mapped / total * 100:.1f}%")

print("\n===== STRIDE DISTRIBUTION =====")
stride_counter = Counter()

for row in rows:
    for category in row["STRIDE"].split(";"):
        if category:
            stride_counter[category] += 1

for category, count in sorted(stride_counter.items()):
    print(category, ":", count)
