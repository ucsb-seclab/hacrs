import re

from ..graph_helper import get_label, reserve_and_get_next_available_numbered_node_name, attr_encode, attr_decode
from .. import DecisionGraphNode, decision_graph_from_agraph, register_node_type


class TextFlatNode(DecisionGraphNode):
    def __init__(self, text, successor=None):
        super(TextFlatNode, self).__init__()

        self.text = text
        self.successor = successor

    def set_successors(self, succs):
        if succs is None or len(succs) > 1:
            raise ValueError("We can't have more than one successor following a TextFlatNode! Got: {}".format(succs))

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
            raise ValueError("ActionsNode has more than 1 successor? Got: {}".format(succs))
        succ = None if len(succs) == 0 else decision_graph_from_agraph(g, succs[0])

        text = get_label(g, node_name)
        instance = cls(text, successor=succ)
        return instance

    def to_graph(self, g, node_to_name_map):
        name = node_to_name_map[self]
        g.add_node(name, shape='box', label=self.text)

        if self.successor is not None:
            succ_name = node_to_name_map[self.successor]
            g.add_edge(name, succ_name)

        return name

    def update_successors(self, visitor, replacements):
        """

        :type visitor: DecisionGraphVisitor
        :type node: ActionsNode
        :return:
        """
        if self.successor is not None:
            compact_successors = replacements[self.successor]
            assert len(compact_successors) < 2, "The {} visitor returned more than one successor for {}! " \
                                                "Got: {}".format(visitor, self.successor, compact_successors)
            compact_successor = compact_successors[0]
            self.successor = compact_successor


register_node_type(TextFlatNode, 'text-flat')
