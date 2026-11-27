
import json
import networkx as nx
import matplotlib.pyplot as plt
from pathlib import Path


def generate_dfd_level1(json_path, output_path):
    """Generate a Level-1 Data Flow Diagram."""

    # Load network data
    with open(json_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    network = data["network"]

    hosts = network["hosts"]
    zones = network["zones"]
    data_flows = network["data_flows"]

    # Create directed graph
    graph = nx.DiGraph()

    # Add external entities
    external_entities = {
        "ext-customer": "Customer",
        "ext-partner": "Partner",
        "ext-employee": "Employee",
    }

    for entity_id, label in external_entities.items():
        graph.add_node(
            entity_id,
            label=label,
            kind="external"
        )

    # Add hosts
    for host in hosts:
        graph.add_node(
            host["id"],
            label=f'{host["id"]}\n{host["name"]}',
            kind="host",
            zone=host["zone"]
        )

    # Add data flows
    for flow in data_flows:
        graph.add_edge(
            flow["src"],
            flow["dst"],
            label=f'{flow["protocol"]}: {flow["data"]}'
        )

    # Define colors by node type
    colors = []

    for node in graph.nodes:
        if graph.nodes[node]["kind"] == "external":
            colors.append("lightgray")
        else:
            colors.append("skyblue")

    # Draw graph
    plt.figure(figsize=(18, 12))

    positions = nx.spring_layout(
        graph,
        seed=42,
        k=1.5
    )

    nx.draw_networkx_nodes(
        graph,
        positions,
        node_color=colors,
        node_size=1800
    )

    nx.draw_networkx_labels(
        graph,
        positions,
        labels={
            node: graph.nodes[node]["label"]
            for node in graph.nodes
        },
        font_size=7
    )

    nx.draw_networkx_edges(
        graph,
        positions,
        arrows=True,
        arrowsize=15,
        edge_color="gray"
    )

    edge_labels = nx.get_edge_attributes(graph, "label")

    nx.draw_networkx_edge_labels(
        graph,
        positions,
        edge_labels=edge_labels,
        font_size=6
    )

    plt.title("ACME Retail - DFD Level 1")
    plt.axis("off")
    plt.tight_layout()

    # Save PNG
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    plt.savefig(output_path, dpi=200, bbox_inches="tight")
    plt.close()

    print(f"DFD Level 1 generated: {output_path}")


if __name__ == "__main__":
    project_dir = Path(__file__).resolve().parent.parent

    json_path = project_dir / "data" / "network.json"
    output_path = project_dir / "output" / "dfd_level1.png"

    generate_dfd_level1(json_path, output_path)
