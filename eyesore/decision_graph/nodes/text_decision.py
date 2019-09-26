import re
import pygraphviz as pgv

from ..graph_helper import get_label
from .. import DecisionGraphNode, decision_graph_from_agraph, register_node_type


class TextDecisionNode(DecisionGraphNode):
    def __init__(self, taken_succs=(), unsat_succs=(), text=''):
        super(TextDecisionNode, self).__init__()
        self.text = text
        self.taken_successors = taken_succs
        self.unsat_successors = unsat_succs

    def set_successors(self, succs):
        raise ValueError("set_successors() should not be used on a TextDecisionNode! Got: {}".format(succs))

    def get_successors(self):
        return self.taken_successors + self.unsat_successors

    @classmethod
    def from_graph(cls, g, node_name):
        """

        :param g:
        :type g: pgv.AGraph
        :param node_name:
        :return:
        """

        name_match = re.match(cls.get_node_name_regex(), node_name)
        if not name_match:
            raise ValueError("Trying to parse a node with invalid name as {}: {}".format(cls, node_name))

        outbound = [(g.get_edge(edge[0], edge[1]), decision_graph_from_agraph(g, edge[1])) for edge in g.out_edges()]
        taken_succs = [node for edge, node in outbound if edge.attr['color'] == 'green']
        unsat_succs = [node for edge, node in outbound if edge.attr['color'] == 'red']

        instance = cls(taken_succs=taken_succs, unsat_succs=unsat_succs, text=get_label(g, node_name))
        return instance

    def to_graph(self, g, node_to_name_map):
        name = node_to_name_map[self]

        try:
            g.add_node(name, shape='diamond', label=self.text)
        except:
            import sys, traceback, ipdb
            type, value, tb = sys.exc_info()
            traceback.print_exc()
            ipdb.post_mortem(tb)


        for succ in self.taken_successors:
            g.add_edge(name, node_to_name_map[succ], color='green')

        for succ in self.unsat_successors:
            g.add_edge(name, node_to_name_map[succ], color='red')

        return name

    def update_successors(self, visitor, replacements):
        """

        :type visitor: DecisionGraphVisitor
        :type node: DecisionBaseNode
        :return:
        """
        taken_succs = [x for succ in self.taken_successors for x in replacements[succ]]
        unsat_succs = [x for succ in self.unsat_successors for x in replacements[succ]]

        self.taken_successors = taken_succs
        self.unsat_successors = unsat_succs

register_node_type(TextDecisionNode, 'text-decision')
