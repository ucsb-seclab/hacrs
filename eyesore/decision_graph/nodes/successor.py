import re

from ..graph_helper import get_label, reserve_and_get_next_available_numbered_node_name, attr_encode, attr_decode
from .. import DecisionGraphNode, decision_graph_from_agraph, register_node_type


class SuccessorNode(DecisionGraphNode):
    def __init__(self, fresh_constraints, category, address, sat, reachable_string_refs, successor=None):
        super(SuccessorNode, self).__init__()
        self.fresh_constraints = fresh_constraints
        self.category = category
        self.address = address
        self.satisfiable = sat
        self.reachable_string_refs = reachable_string_refs
        self.successor = successor

    def set_successors(self, succs):
        if succs is None or len(succs) > 1:
            raise ValueError(
                "We can't have more than one successor following a SuccessorNode! Got: {}".format(succs))

        self.successor = succs[0] if len(succs) == 1 else None

    def get_successors(self):
        return () if self.successor is None else (self.successor,)

    @classmethod
    def from_graph(cls, g, node_name):
        name_match = re.match(cls.get_node_name_regex(), node_name)
        if not name_match:
            raise ValueError("Trying to parse a node with invalid name as {}: {}".format(cls, node_name))

        succs = g.successors(node_name)
        if len(succs) > 1:
            raise ValueError("SuccessorNode has more than 1 successor? Got: {}".format(succs))
        succ = None if len(succs) == 0 else decision_graph_from_agraph(g, succs[0])

        data = attr_decode(get_label(g, node_name))
        instance = cls(data['fresh_constraints'], data['category'], data['address'], data['satisfiable'],
                       data['reachable_string_refs'], successor=succ)
        return instance

    def to_graph(self, g, node_to_name_map):
        name = node_to_name_map[self]
        data = {'fresh_constraints': self.fresh_constraints,
                'category': self.category,
                'address': self.address,
                'satisfiable': self.satisfiable,
                'reachable_string_refs': self.reachable_string_refs}

        g.add_node(name, shape='box', label=attr_encode(data))

        if self.successor is not None:
            succ_name = node_to_name_map[self.successor]
            g.add_edge(name, succ_name)

        return name

    def update_successors(self, visitor, replacements):
        """

        :type visitor: DecisionGraphVisitor
        :type node: SuccessorNode
        :return:
        """
        if self.successor is not None:
            compact_successors = replacements[self.successor]
            assert len(compact_successors) < 2, "The {} visitor returned more than one successor for {}! " \
                                                "Got: {}".format(visitor, self.successor, compact_successors)
            compact_successor = compact_successors[0]
            self.successor = compact_successor

register_node_type(SuccessorNode, 'successor')
