import re

from ..graph_helper import get_label, reserve_and_get_next_available_numbered_node_name, attr_encode, attr_decode
from .. import DecisionGraphNode, decision_graph_from_agraph, register_node_type
from .successor import SuccessorNode


class SuccessorsNode(DecisionGraphNode):
    def __init__(self, taken_constraints, sat_succs=(), unsat_succs=(), flat_succs=(), unconstrained_succs=()):
        super(SuccessorsNode, self).__init__()
        self.taken_constraints = taken_constraints
        self.sat_succs = sat_succs
        self.unsat_succs = unsat_succs
        self.flat_succs = flat_succs
        self.unconstrained_succs = unconstrained_succs

    def set_successors(self, succs):
        if succs is None:
            raise ValueError("You can't set the successors of a SuccessorsNode to None! Use an empty list")

        if any(not isinstance(x, SuccessorNode) for x in succs):
            raise ValueError("{} contains successors that aren't SuccessorNode instances????")

        self.sat_succs = [x for x in succs if x.category == 'satisfiable']
        self.unsat_succs = [x for x in succs if x.category == 'unsatisfiable']
        self.flat_succs = [x for x in succs if x.category == 'flat']
        self.unconstrained_succs = [x for x in succs if x.category == 'unconstrained']

    def get_successors(self):
        return self.sat_succs + self.unsat_succs + self.flat_succs + self.unconstrained_succs

    @classmethod
    def from_graph(cls, g, node_name):
        name_match = re.match(cls.get_node_name_regex(), node_name)
        if not name_match:
            raise ValueError("Trying to parse a node with invalid name as {}: {}".format(cls, node_name))

        decoded_successors = [decision_graph_from_agraph(g, succ_name) for succ_name in g.successors_iter(node_name)]

        data = attr_decode(get_label(g, node_name))
        instance = cls(data['taken_constraints'])
        instance.set_successors(decoded_successors)
        return instance

    def to_graph(self, g, node_to_name_map):
        name = node_to_name_map[self]
        data = {'taken_constraints': self.taken_constraints}

        g.add_node(name, shape='box', label=attr_encode(data))

        for succ in self.sat_succs + self.unsat_succs + self.flat_succs + self.unconstrained_succs:
            g.add_edge(name, node_to_name_map[succ])

        return name

    def update_successors(self, visitor, replacements):
        """

        :type visitor: DecisionGraphVisitor
        :type node: SuccessorsNode
        :return:
        """
        sat_succs = [x for succ in self.sat_succs for x in replacements[succ]]
        unsat_succs = [x for succ in self.unsat_succs for x in replacements[succ]]
        flat_succs = [x for succ in self.flat_succs for x in replacements[succ]]
        unconstr_succs = [x for succ in self.unconstrained_succs for x in replacements[succ]]

        self.sat_succs = sat_succs
        self.unsat_succs = unsat_succs
        self.flat_succs = flat_succs
        self.unconstrained_succs = unconstr_succs

register_node_type(SuccessorsNode, 'successors')
