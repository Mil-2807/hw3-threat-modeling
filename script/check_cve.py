
import json
import ssl
import urllib.request
import certifi
import time

cve_ids = [
    "CVE-2019-11510",
    "CVE-2021-41773",
    "CVE-2021-43798"
]

context = ssl.create_default_context(cafile=certifi.where())

for cve in cve_ids:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ACME-Educational-Threat-Model"}
    )

    with urllib.request.urlopen(
        request, context=context, timeout=30
    ) as response:
        data = json.load(response)

    item = data["vulnerabilities"][0]["cve"]

    description = next(
        (
            entry["value"]
            for entry in item["descriptions"]
            if entry["lang"] == "en"
        ),
        "No description available"
    )

    print("\n" + cve)
    print(description)

    time.sleep(6.5)
