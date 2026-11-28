
import json
import csv
import ssl
import time
import urllib.request
import urllib.parse
import certifi


def load_network(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def load_stride_classification(file_path):
    classifications = {}

    with open(file_path, "r", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        for row in reader:
            classifications[row["CVE"]] = row["STRIDE"]

    return classifications


def collect_cves(network):
    cve_hosts = {}

    for host in network["hosts"]:
        for vulnerability in host.get("vulnerabilities", []):
            cve = vulnerability.get("cve")

            if cve:
                cve_hosts.setdefault(cve, []).append(host["id"])

    return cve_hosts


def fetch_cwe(cve_id, context):
    """Retrieve CWE information from the official NVD API."""

    params = urllib.parse.urlencode({"cveId": cve_id})
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}"

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ACME-Educational-Threat-Model"}
    )

    try:
        with urllib.request.urlopen(
            request, context=context, timeout=30
        ) as response:
            data = json.load(response)

        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            return "Unknown"

        cve_data = vulnerabilities[0]["cve"]
        weaknesses = cve_data.get("weaknesses", [])

        cwe_ids = set()

        for weakness in weaknesses:
            for description in weakness.get("description", []):
                value = description.get("value", "")

                if value.startswith("CWE-") and value not in (
                    "NVD-CWE-noinfo",
                    "NVD-CWE-Other"
                ):
                    cwe_ids.add(value)

        if cwe_ids:
            return ";".join(sorted(cwe_ids))

        return "Unknown"

    except Exception as error:
        print(f"Could not retrieve {cve_id}: {error}")
        return "Unknown"


def create_mapping_template(
    cve_hosts, stride_data, output_file
):
    fields = [
        "CVE",
        "Hosts",
        "CWE",
        "CAPEC",
        "ATTACK_Technique",
        "ATTACK_Tactic",
        "STRIDE",
        "Mapping_Status",
        "Sources"
    ]

    context = ssl.create_default_context(
        cafile=certifi.where()
    )

    with open(
        output_file, "w", newline="", encoding="utf-8-sig"
    ) as file:

        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        total = len(cve_hosts)

        for index, (cve, hosts) in enumerate(
            sorted(cve_hosts.items()), start=1
        ):
            print(f"[{index}/{total}] Checking {cve}...")

            cwe = fetch_cwe(cve, context)

            writer.writerow({
                "CVE": cve,
                "Hosts": ";".join(hosts),
                "CWE": cwe,
                "CAPEC": "Unmapped",
                "ATTACK_Technique": "Unmapped",
                "ATTACK_Tactic": "Unmapped",
                "STRIDE": stride_data.get(cve, "Unknown"),
                "Mapping_Status": (
                    "CWE found; CAPEC and ATT&CK pending"
                    if cwe != "Unknown"
                    else "CWE unavailable; CAPEC and ATT&CK pending"
                ),
                "Sources": (
                    f"https://nvd.nist.gov/vuln/detail/{cve}"
                )
            })

            # NVD public API rate limit: wait between requests.
            if index < total:
                time.sleep(6.5)

    print("\nMapping file saved:", output_file)
    print("Unique CVEs processed:", total)


def main():
    network_data = load_network("data/network.json")
    network = network_data["network"]

    stride_data = load_stride_classification(
        "output/stride_cve_classification.csv"
    )

    cve_hosts = collect_cves(network)

    create_mapping_template(
        cve_hosts,
        stride_data,
        "output/cve_mapping.csv"
    )


if __name__ == "__main__":
    main()
