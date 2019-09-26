import re

from ..graph_helper import get_label, reserve_and_get_next_available_numbered_node_name, attr_encode, attr_decode
from .. import DecisionGraphNode, decision_graph_from_agraph


class SuccessorCategoryNode(DecisionGraphNode):
    def __init__(self, category, successors=()):
        super(SuccessorCategoryNode, self).__init__()
        self.category = category
        self.successors = successors

    def set_successors(self, succs):
        if succs is None:
            raise ValueError("You can't set the successors of a SuccessorsNode to None! Use an empty list")

        self.successors = succs

    def get_successors(self):
        return self.successors

    @classmethod
    def from_graph(cls, g, node_name):
        name_match = re.match(cls.get_node_name_regex(), node_name)
        if not name_match:
            raise ValueError("Trying to parse a node with invalid name as {}: {}".format(cls, node_name))

        graph_succs = g.successors(node_name)
        node_succs = (decision_graph_from_agraph(g, succ) for succ in graph_succs)

        data = attr_decode(get_label(g, node_name))
        instance = cls(data['category'], successors=node_succs)
        return instance

    def to_graph(self, g, node_to_name_map):
        name = reserve_and_get_next_available_numbered_node_name(g, self.get_node_type_name(), name_to_next_idx_mapping)
        data = {'category': self.category}

        g.add_node(name, shape='box', label=attr_encode(data))

        for succ in self.successors:
            succ_name = node_to_name_map[succ.to_graph]
            g.add_edge(name, succ_name)

        return name
