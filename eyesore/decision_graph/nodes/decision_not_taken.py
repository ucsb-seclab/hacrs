import re

from ..graph_helper import get_label, reserve_and_get_next_available_numbered_node_name, attr_encode, attr_decode
from .. import DecisionGraphNode, register_node_type


class DecisionNotTakenNode(DecisionGraphNode):
    def __init__(self, reachable_constraints_options, address, reachable_string_refs):
        super(DecisionNotTakenNode, self).__init__()
        self.reachable_constraints_options = reachable_constraints_options
        self.address = address
        self.reachable_string_refs = reachable_string_refs

    def set_successors(self, succs):
        raise ValueError("set_successors() should never be called on a DecisionNotTakenNode! Got: {}".format(succs))

    def get_successors(self):
        return ()

    @classmethod
    def from_graph(cls, g, node_name):
        name_match = re.match(cls.get_node_name_regex(), node_name)
        if not name_match:
            raise ValueError("Trying to parse a node with invalid name as {}: {}".format(cls, node_name))

        succs = g.successors(node_name)
        if len(succs) != 0:
            raise ValueError("DecisionNotTakenNode has successors? Got: {}".format(succs))

        data = attr_decode(get_label(g, node_name))
        instance = cls(data['reachable_constraints_options'], data['address'], data['reachable_string_refs'], successor=None)
        return instance

    def to_graph(self, g, node_to_name_map):
        name = node_to_name_map[self]
        data = {'reachable_constraints_options': self.reachable_constraints_options,
                'address': self.address,
                'reachable_string_refs': self.reachable_string_refs}
        g.add_node(name, shape='box', label=attr_encode(data))
        return name

    def update_successors(self, visitor, replacements):
        pass

register_node_type(DecisionNotTakenNode, 'decision-not-taken')
