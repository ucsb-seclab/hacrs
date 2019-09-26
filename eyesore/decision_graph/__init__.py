from collections import Counter

import pygraphviz as pgv

from .traversal import bfs
from .graph_helper import attr_encode

class DecisionGraphNode(object):
    @classmethod
    def get_node_type_name(cls):
        return DECISION_GRAPH_NODE_TYPES[cls]

    @classmethod
    def get_node_name_regex(cls):
        return '^({})_([0-9]*)'.format(cls.get_node_type_name())

    @classmethod
    def from_graph(cls, g, node_name):
        raise NotImplementedError("from_graph() not implemented!")

    def to_graph(self, g, node_to_name_map):
        raise NotImplementedError("to_graph() not implemented!")

    def set_successors(self, successors):
        raise NotImplementedError("set_successors() not implemented!")

    def get_successors(self):
        raise NotImplementedError("get_successors() not implemented!")

    def update_successors(self, visitor, replacements):
        raise NotImplementedError("This node type does not define a default visitor implementation!")


def build_node_to_name_map(head):
    """

    :type head: DecisionGraphNode
    :return:
    """
    node_to_name_map = {}
    name_to_next_idx_map = Counter()

    def add_node_name(node):
        assert node not in node_to_name_map

        node_type_name = node.get_node_type_name()

        idx = name_to_next_idx_map[node_type_name]
        name_to_next_idx_map[node_type_name] += 1

        name = "{}_{}".format(node_type_name, idx)
        node_to_name_map[node] = name

    bfs(head, add_node_name)

    return node_to_name_map


def register_node_type(clazz, node_type_str):
    if not hasattr(clazz, 'to_graph') or not hasattr(clazz, 'from_graph'):
        raise ValueError('Decision graph nodes must implement to_graph() and from_graph()!')

    DECISION_GRAPH_NODE_TYPES[clazz] = node_type_str


def node_name_to_node_class(node_name):
    if len(node_name) == 0:
        raise ValueError("Empty node_name??")

    type_str = node_name.split('_')[0]
    for nt in DECISION_GRAPH_NODE_TYPES:
        if DECISION_GRAPH_NODE_TYPES[nt] == type_str:
            return nt

    raise ValueError("Unknown node type: {} in node_name {}".format(type_str, node_name))


def decision_graph_from_agraph(g, node_name):
    clazz = node_name_to_node_class(node_name)
    return clazz.from_graph(g, node_name)


def agraph_from_decision_graph(graph_head):
    g = pgv.AGraph(directed=True, strict=False)

    node_to_name_map = build_node_to_name_map(graph_head)

    def node_to_graph(cur_node):
        cur_node.to_graph(g, node_to_name_map)

    bfs(graph_head, node_to_graph)
    return g


DECISION_GRAPH_NODE_TYPES = {}

from .visitor import Visitor
from nodes import *
import compacting
