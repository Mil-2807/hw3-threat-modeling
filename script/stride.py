import json
from pathlib import Path
import csv

STRIDE_CATEGORIES = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege"
}

def load_network(file_path):
    """Load the network configuration from a JSON file."""

    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"Network file not found: {file_path}")

    try:
        with file_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON file: {error}")

    if not isinstance(data, dict):
        raise ValueError("The JSON root must be an object.")

    if "network" not in data:
        raise ValueError("Missing 'network' section in JSON.")

    return data

def load_cve_classifications(file_path):
    """Load manual STRIDE classifications from a CSV file."""

    classifications = {}

    with open(file_path, "r", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            cve = row["CVE"].strip()
            categories = row["STRIDE"].strip()

            classifications[cve] = categories.split(";")

    return classifications

def analyze_host_threats(network, cve_classifications):
    """Classify host vulnerabilities using the STRIDE CSV mapping."""

    threats = []

    for host in network["hosts"]:
        host_id = host["id"]

        for vulnerability in host.get("vulnerabilities", []):
            cve = vulnerability.get("cve", "Unknown CVE")
            service = vulnerability.get("service", "Unknown service")

            categories = cve_classifications.get(cve, ["TBD"])

            for category in categories:
                category_name = STRIDE_CATEGORIES.get(
                    category, "Classification pending"
                )

                threats.append({
                    "target": host_id,
                    "hostname": host_id,
                    "category": category,
                    "category_name": category_name,
                    "description": (
                        f"{cve} affects the {service} service on {host_id}. "
                        f"Proposed STRIDE impact: {category_name}."
                    ),
                    "source": cve
                })

    return threats

def analyze_data_flow_threats(network):
    """Identify potential STRIDE threats related to data flows."""

    threats = []

    for flow in network["data_flows"]:
        flow_id = flow.get("id", "Unknown")
        source = flow.get("src", "Unknown")
        destination = flow.get("dst", "Unknown")
        protocol = flow.get("protocol", "").upper()

        if protocol in ["HTTP", "FTP"]:
            threats.append({
                "target": flow_id,
                "hostname": f"{source} -> {destination}",
                "category": "I",
                "category_name": STRIDE_CATEGORIES["I"],
                "description": (
                    f"Data transmitted using {protocol} may be intercepted."
                ),
                "source": protocol
            })

    return threats

def analyze_trust_threats(network):
    """Identify potential abuse of trusted credentials and keys."""

    threats = []

    for relation in network["trust_relations"]:
        relation_id = relation.get("id", "Unknown")
        source = relation.get("from_host", "Unknown")
        destination = relation.get("to_host", "Unknown")
        trust_type = relation.get("type", "Unknown")
        privilege = relation.get("grants", "Unknown")
        requires = relation.get("requires")

        precondition = (
            f" The attacker must first obtain {requires}."
            if requires
            else f" The attacker must first compromise {source}."
        )

        threats.append({
            "target": relation_id,
            "hostname": f"{source} -> {destination}",
            "category": "S",
            "category_name": STRIDE_CATEGORIES["S"],
            "description": (
                f"An attacker may abuse the {trust_type} relationship "
                f"from {source} to authenticate to {destination} "
                f"with {privilege} privileges."
                f"{precondition}"
            ),
            "source": trust_type
        })

    return threats

def analyze_misconfiguration_threats(network):
    """Identify threats caused by host misconfigurations."""

    threats = []

    for host in network["hosts"]:
        for misconfiguration in host.get("misconfigurations", []):
            mc_id = misconfiguration.get("id", "Unknown")
            description = misconfiguration.get("description", "")
            service = misconfiguration.get("service", "Unknown service")

            if mc_id == "MC1":
                category = "S"
                category_name = "Spoofing"
                threat_description = (
                    f"{description}. An attacker may use default "
                    "credentials to impersonate an authorized user."
                )

            elif mc_id == "MC2":
                category = "S"
                category_name = "Spoofing"
                threat_description = (
                    f"{description}. An attacker may perform repeated "
                    "password attempts to impersonate the SSH user."
                )

            else:
                category = "TBD"
                category_name = "Classification pending"
                threat_description = description

            threats.append({
                "target": host["id"],
                "hostname": host["id"],
                "category": category,
                "category_name": category_name,
                "description": threat_description,
                "source": mc_id
            })

    return threats

def export_threats_to_csv(threats, output_file):
    """Export detected threats to a CSV file."""

    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "target",
        "hostname",
        "category",
        "category_name",
        "description",
        "source"
    ]

    with output_file.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(threats)

    print(f"\nThreat report saved: {output_file.resolve()}")

if __name__ == "__main__":
    network_data = load_network("data/network.json")
    network = network_data["network"]

    print("Network loaded successfully!")
    print("Zones:", len(network["zones"]))
    print("Hosts:", len(network["hosts"]))
    print("Data flows:", len(network["data_flows"]))
    print("Trust relations:", len(network["trust_relations"]))

    cve_classifications = load_cve_classifications(
        "output/stride_cve_classification.csv"
    )

    host_threats = analyze_host_threats(network, cve_classifications)
    flow_threats = analyze_data_flow_threats(network)
    trust_threats = analyze_trust_threats(network)
    misconfiguration_threats = analyze_misconfiguration_threats(network)

    threats = (
        host_threats
        + flow_threats
        + trust_threats
        + misconfiguration_threats
    )

    export_threats_to_csv(threats, "output/stride_threats.csv")

    print("\nHost threats detected:", len(host_threats))
    print("Data flow threats detected:", len(flow_threats))
    print("Trust threats detected:", len(trust_threats))
    print("Total potential threats:", len(threats))

    print("Misconfiguration threats detected:", len(misconfiguration_threats))

    for threat in threats[:10]:
        print(
            threat["target"],
            "|",
            threat["category_name"],
            "|",
            threat["source"]
        )