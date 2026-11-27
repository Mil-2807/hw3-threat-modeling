
import json
import csv
from pathlib import Path


def load_network(json_path):
    """Load network configuration from JSON."""
    with open(json_path, "r", encoding="utf-8") as file:
        return json.load(file)


def expand_endpoint(zone, host, hosts):
    """Expand wildcard hosts into the hosts belonging to a zone."""

    if host != "*":
        return [host]

    zone_hosts = [
        item["id"]
        for item in hosts
        if item["zone"] == zone
    ]

    # Keep a zone-level endpoint if no host exists in that zone.
    if not zone_hosts:
        return [f"{zone}/*"]

    return zone_hosts


def build_reachability(network):
    """Build detailed reachability entries from firewall rules."""

    hosts = network["hosts"]
    firewall_rules = network["firewall_rules"]

    entries = []

    for rule_number, rule in enumerate(firewall_rules, start=1):

        sources = expand_endpoint(
            rule["src_zone"],
            rule["src_host"],
            hosts
        )

        destinations = expand_endpoint(
            rule["dst_zone"],
            rule["dst_host"],
            hosts
        )

        for source in sources:
            for destination in destinations:
                for port in rule["ports"]:

                    entries.append({
                        "source": source,
                        "destination": destination,
                        "port": port,
                        "action": rule["action"],
                        "rule": rule_number
                    })

    return entries


def export_details(entries, output_dir):
    """Export all expanded firewall rules."""

    file_path = output_dir / "reachability_details.csv"

    with open(file_path, "w", newline="", encoding="utf-8") as file:
        fieldnames = [
            "source",
            "destination",
            "port",
            "action",
            "rule"
        ]

        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(entries)

    print("Detailed rules saved:", file_path)


def export_matrix(entries, output_dir):
    """Export a source-destination reachability matrix."""

    endpoints = sorted(
        set(entry["source"] for entry in entries)
        | set(entry["destination"] for entry in entries)
    )

    matrix = {}

    for source in endpoints:
        matrix[source] = {}

        for destination in endpoints:
            matrix[source][destination] = []

    for entry in entries:
        source = entry["source"]
        destination = entry["destination"]

        matrix[source][destination].append(
            (entry["port"], entry["action"])
        )

    file_path = output_dir / "reachability_matrix.csv"

    with open(file_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow(["Source / Destination"] + endpoints)

        for source in endpoints:
            row = [source]

            for destination in endpoints:
                rules = matrix[source][destination]

                if not rules:
                    value = "NO RULE"
                else:
                    allowed = sorted({
                        port for port, action in rules
                        if action == "allow"
                    })

                    denied = sorted({
                        port for port, action in rules
                        if action == "deny"
                    })

                    parts = []

                    if allowed:
                        parts.append(
                            "ALLOW: " + ",".join(map(str, allowed))
                        )

                    if denied:
                        parts.append(
                            "DENY: " + ",".join(map(str, denied))
                        )

                    value = " | ".join(parts)

                row.append(value)

            writer.writerow(row)

    print("Reachability matrix saved:", file_path)


def main():

    project_dir = Path(__file__).resolve().parent.parent

    json_path = project_dir / "data" / "network.json"
    output_dir = project_dir / "output"

    output_dir.mkdir(parents=True, exist_ok=True)

    data = load_network(json_path)

    network = data["network"]

    entries = build_reachability(network)

    export_details(entries, output_dir)
    export_matrix(entries, output_dir)

    print("\nReachability analysis completed!")
    print("Firewall rules:", len(network["firewall_rules"]))
    print("Expanded entries:", len(entries))


if __name__ == "__main__":
    main()
