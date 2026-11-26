
import json
import sys
from pathlib import Path


def network_preview(data):
    """Display a short preview of the JSON structure."""

    preview = {}

    for key, value in data.items():

        if isinstance(value, dict):
            preview[key] = list(value.keys())[:10]

        elif isinstance(value, list):
            preview[key] = f"List containing {len(value)} items"

        else:
            preview[key] = value

    return preview


def validate_network_data(data):
    """Validate hosts and network zones."""

    network = data["network"]

    zones = network["zones"]
    hosts = network["hosts"]

    # Check that zones and hosts are lists
    if not isinstance(zones, list):
        raise ValueError("'zones' must be a list.")

    if not isinstance(hosts, list):
        raise ValueError("'hosts' must be a list.")

    # Extract zone identifiers
    zone_ids = set()

    for zone in zones:
        if not isinstance(zone, dict) or "id" not in zone:
            raise ValueError("A zone is missing its 'id' field.")

        if zone["id"] in zone_ids:
            raise ValueError(
                f"Duplicate zone identifier: {zone['id']}"
            )

        zone_ids.add(zone["id"])

    # Check hosts
    host_ids = set()

    for host in hosts:
        if not isinstance(host, dict):
            raise ValueError("Each host must be a JSON object.")

        if "id" not in host:
            raise ValueError("A host is missing its 'id' field.")

        if host["id"] in host_ids:
            raise ValueError(
                f"Duplicate host identifier: {host['id']}"
            )

        host_ids.add(host["id"])

        if "zone" not in host:
            raise ValueError(
                f"Host {host['id']} is missing its zone."
            )

        if host["zone"] not in zone_ids:
            raise ValueError(
                f"Host {host['id']} references an unknown zone: "
                f"{host['zone']}"
            )

    print("\nHost and zone validation successful!")
    print(f"Number of zones: {len(zones)}")
    print(f"Number of hosts: {len(hosts)}")


def validate_network_connections(data):
    """Validate firewall rules, trust relations and data flows."""

    network = data["network"]

    firewall_rules = network["firewall_rules"]
    trust_relations = network["trust_relations"]
    data_flows = network["data_flows"]

    # Check that all three sections are lists
    sections = {
        "firewall_rules": firewall_rules,
        "trust_relations": trust_relations,
        "data_flows": data_flows
    }

    for name, items in sections.items():
        if not isinstance(items, list):
            raise ValueError(f"'{name}' must be a list.")

    # Check that every item is a JSON object
    for name, items in sections.items():
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise ValueError(
                    f"Item {index} in '{name}' must be an object."
                )

    print("\nNetwork connections validation successful!")
    print(f"Firewall rules: {len(firewall_rules)}")
    print(f"Trust relations: {len(trust_relations)}")
    print(f"Data flows: {len(data_flows)}")

def validate_data_flow_hosts(data):
    """Check that data flows reference valid endpoints."""

    network = data["network"]

    hosts = network["hosts"]
    data_flows = network["data_flows"]

    host_ids = {host["id"] for host in hosts}

    # External entities are not network hosts
    external_entities = {
        "ext-customer",
        "ext-partner",
        "ext-employee"
    }

    for flow in data_flows:

        source = flow.get("src")
        destination = flow.get("dst")

        if not source or not destination:
            raise ValueError(
                f"Data flow {flow.get('id', 'unknown')} "
                "is missing src or dst."
            )

        if source not in host_ids and source not in external_entities:
            raise ValueError(
                f"Unknown source endpoint in data flow: {source}"
            )

        if destination not in host_ids and destination not in external_entities:
            raise ValueError(
                f"Unknown destination endpoint in data flow: "
                f"{destination}"
            )

    print("\nData flow endpoint validation successful!")
    print(f"Validated data flows: {len(data_flows)}")

def load_network(file_path):
    """Load and validate the basic JSON structure."""

    path = Path(file_path)

    # 1. Check if the file exists
    if not path.is_file():
        raise FileNotFoundError(
            f"Network file not found: {path}"
        )

    # 2. Parse the JSON file
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)

    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON at line {error.lineno}, "
            f"column {error.colno}: {error.msg}"
        ) from error

    # 3. Check the root type
    if not isinstance(data, dict):
        raise ValueError("JSON root must be an object.")

    if not data:
        raise ValueError("JSON object is empty.")

    # 4. Check top-level sections
    required_sections = [
        "metadata",
        "network",
        "attacker_scenarios",
        "goals",
        "mitigations",
        "total_mitigation_cost"
    ]

    missing_sections = [
        section for section in required_sections
        if section not in data
    ]

    if missing_sections:
        raise ValueError(
            "Missing top-level sections: "
            + ", ".join(missing_sections)
        )

    # 5. Check network subsections
    required_network_sections = [
        "zones",
        "hosts",
        "firewall_rules",
        "trust_relations",
        "data_flows"
    ]

    network = data["network"]

    if not isinstance(network, dict):
        raise ValueError("'network' must be a JSON object.")

    missing_network_sections = [
        section for section in required_network_sections
        if section not in network
    ]

    if missing_network_sections:
        raise ValueError(
            "Missing network sections: "
            + ", ".join(missing_network_sections)
        )

    # 6. Display the structure
    print("\nJSON structure validated successfully!")

    print("\nAvailable sections:")
    print(
        json.dumps(
            network_preview(data),
            indent=2,
            ensure_ascii=False
        )
    )

    return data



def main():
    """Main program."""

    # Find the project directory automatically
    project_root = Path(__file__).resolve().parent.parent

    # Locate network.json
    json_file = project_root / "data" / "network.json"

    try:
        network = load_network(json_file)
        validate_network_data(network)
        validate_network_connections(network)
        validate_data_flow_hosts(network)

        print("\n" + "=" * 40)
        print(" ACME RETAIL - NETWORK LOADER")
        print("=" * 40)

        print("\nJSON successfully loaded!")

        print("\nLOADER completed successfully.")

    except (FileNotFoundError, ValueError) as error:
        print(f"\nERROR: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
