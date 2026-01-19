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
