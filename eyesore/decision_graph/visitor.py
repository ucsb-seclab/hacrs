from collections import deque

from . import DecisionGraphNode


class Visitor(object):
    def visit_node(self, node, results):
        if node is None or not isinstance(node, DecisionGraphNode):
            raise ValueError('visit_node() invalid DecisionGraphNode instance: {}'.format(node))

        type_name = node.get_node_type_name()
        visitor_name = '_visit_{}_node'.format(type_name.replace('-', '_'))
        if hasattr(self, visitor_name):
            visitor = getattr(self, visitor_name)
            return visitor(node, results)
        else:
            # By default just pass it down to the successors and return the node as-is
            node.update_successors(self, results)
            return [node]
