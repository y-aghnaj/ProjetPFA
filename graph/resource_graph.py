import networkx as nx

class ResourceGraph:
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_resource(self, resource: dict):
        """
        Add a cloud resource as a node
        """
        self.graph.add_node(
            resource["id"],
            **resource
        )

    def add_relation(self, src: str, dst: str, relation: str):
        """
        Add a relationship between two resources
        """
        self.graph.add_edge(
            src,
            dst,
            relation=relation
        )

    def load_from_state(self, state: dict):
        """
        Load resources and relations from JSON state
        """
        for res in state.get("resources", []):
            self.add_resource(res)

        for rel in state.get("relations", []):
            self.add_relation(
                rel["from"],
                rel["to"],
                rel["relation"]
            )

    def summary(self):
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges()
        }

    def to_dot(self) -> str:
        """
        Return a DOT representation for Graphviz rendering.
        """
        lines = ["digraph G {"]
        # nodes
        for node_id, data in self.graph.nodes(data=True):
            label = f"{node_id}\\n{data.get('type', '')}"
            lines.append(f'"{node_id}" [label="{label}"];')
        # edges
        for src, dst, edata in self.graph.edges(data=True):
            rel = edata.get("relation", "")
            lines.append(f'"{src}" -> "{dst}" [label="{rel}"];')
        lines.append("}")
        return "\n".join(lines)
