
import json
import math
from pathlib import Path

import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from matplotlib.lines import Line2D


def generate_dfd_level1(json_path, output_path):
    """Generate a Level-1 DFD grouped by network trust zones."""

    # Load the JSON file
    with open(json_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    network = data["network"]

    zones = network["zones"]
    hosts = network["hosts"]
    data_flows = network["data_flows"]
    trust_relations = network["trust_relations"]

    # Create graphs
    flow_graph = nx.DiGraph()
    trust_graph = nx.DiGraph()

    # Add hosts to both graphs
    for host in hosts:
        label = f'{host["id"]}\n{host["name"]}'

        flow_graph.add_node(host["id"], label=label)
        trust_graph.add_node(host["id"], label=label)

    # External entities
    external_entities = {
        "ext-customer": "Customer",
        "ext-partner": "Partner",
        "ext-employee": "Employee",
    }

    for entity_id, label in external_entities.items():
        flow_graph.add_node(entity_id, label=label)

    # Add data flows
    for flow in data_flows:
        flow_graph.add_edge(
            flow["src"],
            flow["dst"],
            label=f'{flow["protocol"]}: {flow["data"]}'
        )

    # Add trust relations
    for relation in trust_relations:
        trust_graph.add_edge(
            relation["from_host"],
            relation["to_host"],
            label=f'{relation["type"]}: {relation["grants"]}'
        )

    # Define zone positions
    zone_positions = {
        "dmz": (0, 3),
        "corp-lan": (6, 3),
        "server-lan": (12, 3),
        "dev-lan": (0, -3),
        "db-zone": (6, -3),
        "mgmt": (12, -3),
        "internet": (-6.5, 0),
    }

    # Calculate host positions inside each zone
    positions = {}

    for zone in zones:
        zone_id = zone["id"]
        center_x, center_y = zone_positions[zone_id]

        zone_hosts = [
            host for host in hosts
            if host["zone"] == zone_id
        ]

        columns = 3
        spacing_x = 1.35
        spacing_y = 1.0

        for index, host in enumerate(zone_hosts):
            row = index // columns
            column = index % columns

            # Center the last row when it has fewer than 3 hosts
            hosts_in_row = min(
                columns,
                len(zone_hosts) - row * columns
            )

            start_x = center_x - (
                (hosts_in_row - 1) * spacing_x / 2
            )

            x = start_x + column * spacing_x
            y = center_y + 0.75 - row * spacing_y

            positions[host["id"]] = (x, y)

    # Position external entities inside the Internet zone
    positions["ext-customer"] = (-7.3, 0.8)
    positions["ext-partner"] = (-5.7, 0.8)
    positions["ext-employee"] = (-6.5, -0.8)

    # Create figure
    fig, ax = plt.subplots(figsize=(28, 18))

    # Draw trust boundaries before drawing nodes and edges
    for zone in zones:
        zone_id = zone["id"]
        center_x, center_y = zone_positions[zone_id]

        zone_hosts = [
            host for host in hosts
            if host["zone"] == zone_id
        ]

        if zone_id == "internet":
            width = 5.2
            height = 4.5
        else:
            width = 5.2
            height = 4.5

        color = "darkgreen" if zone["trusted"] else "darkorange"

        boundary = FancyBboxPatch(
            (center_x - width / 2, center_y - height / 2),
            width,
            height,
            boxstyle="round,pad=0.15",
            linewidth=2.5,
            edgecolor=color,
            facecolor=color,
            alpha=0.10,
            zorder=0
        )

        ax.add_patch(boundary)

        zone_label = (
            f'{zone_id} - '
            f'{"TRUSTED" if zone["trusted"] else "UNTRUSTED"}'
        )

        ax.text(
            center_x,
            center_y + height / 2 - 0.15,
            zone_label,
            ha="center",
            va="top",
            fontsize=10,
            fontweight="bold",
            color=color
        )

    # Draw data flows in blue
    nx.draw_networkx_edges(
        flow_graph,
        positions,
        ax=ax,
        edge_color="blue",
        style="solid",
        arrows=True,
        arrowsize=18,
        width=1.5,
        connectionstyle="arc3,rad=0.12"
    )

    # Draw trust relations in red
    nx.draw_networkx_edges(
        trust_graph,
        positions,
        ax=ax,
        edge_color="red",
        style="dashed",
        arrows=True,
        arrowsize=18,
        width=1.5,
        connectionstyle="arc3,rad=-0.12"
    )

    # Draw hosts
    host_nodes = [host["id"] for host in hosts]

    nx.draw_networkx_nodes(
        flow_graph,
        positions,
        nodelist=host_nodes,
        node_color="skyblue",
        node_size=1400,
        edgecolors="black",
        ax=ax
    )

    # Draw external entities
    nx.draw_networkx_nodes(
        flow_graph,
        positions,
        nodelist=list(external_entities.keys()),
        node_color="lightgray",
        node_shape="s",
        node_size=1500,
        edgecolors="black",
        ax=ax
    )

    # Draw labels
    nx.draw_networkx_labels(
        flow_graph,
        positions,
        labels={
            node: flow_graph.nodes[node]["label"]
            for node in flow_graph.nodes
        },
        font_size=10,
        ax=ax
    )

    # Edge labels
    nx.draw_networkx_edge_labels(
        flow_graph,
        positions,
        edge_labels=nx.get_edge_attributes(flow_graph, "label"),
        font_size=8,
        font_color="blue",
        label_pos=0.25,
        ax=ax
    )

    nx.draw_networkx_edge_labels(
        trust_graph,
        positions,
        edge_labels=nx.get_edge_attributes(trust_graph, "label"),
        font_size=8,
        font_color="red",
        label_pos=0.75,
        ax=ax
    )

    # Legend
    legend_items = [
        Line2D([0], [0], color="blue", linewidth=2,
               label="Data flow"),
        Line2D([0], [0], color="red", linewidth=2,
               linestyle="dashed", label="Trust relation"),
        Line2D([0], [0], color="darkgreen", linewidth=2,
               label="Trusted zone"),
        Line2D([0], [0], color="darkorange", linewidth=2,
               label="Untrusted zone"),
    ]

    ax.legend(handles=legend_items, loc="lower right")

    ax.set_title(
        "ACME Retail - DFD Level 1 with Trust Boundaries",
        fontsize=16,
        fontweight="bold"
    )

    ax.axis("off")
    ax.margins(0.08)
    plt.tight_layout()

    # Save PNG
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path = Path(output_path).resolve()

    output_path.parent.mkdir(parents=True, exist_ok=True)

    print("Saving diagram to:", str(output_path))

    fig.savefig(
        str(output_path),
        format="png",
        dpi=300,
        bbox_inches="tight"
    )

    print("PNG saved successfully!")

    plt.close(fig)

    print("\nDFD Level 1 generated successfully!")
    print(f"Zones: {len(zones)}")
    print(f"Hosts: {len(hosts)}")
    print(f"Data flows: {len(data_flows)}")
    print(f"Trust relations: {len(trust_relations)}")
    print(f"Output: {output_path}")


if __name__ == "__main__":

    project_dir = Path(__file__).resolve().parent.parent

    json_path = project_dir / "data" / "network.json"
    output_path = project_dir / "output" / "dfd_level1.png"

    generate_dfd_level1(json_path, output_path)
