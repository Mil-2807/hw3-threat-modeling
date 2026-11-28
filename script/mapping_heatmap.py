
import csv
import matplotlib.pyplot as plt
import numpy as np

file_path = "output/cve_mapping.csv"

with open(file_path, "r", encoding="utf-8-sig") as file:
    rows = list(csv.DictReader(file))

categories = ["CWE", "CAPEC", "ATT&CK"]
mapped_counts = [
    sum(1 for row in rows if row["CWE"] != "Unknown"),
    sum(1 for row in rows if row["CAPEC"] != "Unmapped"),
    sum(1 for row in rows if row["ATTACK_Technique"] != "Unmapped")
]

total = len(rows)

coverage = np.array([
    [count, total - count]
    for count in mapped_counts
])

fig, ax = plt.subplots(figsize=(8, 4))

image = ax.imshow(coverage, cmap="YlGn", aspect="auto")

ax.set_xticks([0, 1])
ax.set_xticklabels(["Mapped", "Unmapped"])

ax.set_yticks(range(len(categories)))
ax.set_yticklabels(categories)

ax.set_title("CVE Mapping Coverage Heatmap")
ax.set_xlabel("Mapping status")

for i in range(len(categories)):
    for j in range(2):
        ax.text(
            j, i,
            str(coverage[i, j]),
            ha="center",
            va="center",
            color="black",
            fontsize=12
        )

fig.colorbar(image, ax=ax, label="Number of CVEs")
plt.tight_layout()

plt.savefig(
    "output/mapping_heatmap.png",
    dpi=300,
    bbox_inches="tight"
)

print("Heatmap saved: output/mapping_heatmap.png")

plt.show()
