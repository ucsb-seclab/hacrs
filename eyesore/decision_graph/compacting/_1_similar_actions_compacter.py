from .. import ActionsNode
from ..visitor import Visitor


class SimilarActionsCompacter(Visitor):
    def _visit_actions_node(self, node, replacements):
        """

        :param node:
        :type node: ActionsNode
        :return:
        """
        compact_successors = replacements[node.successor]
        #import ipdb
        #ipdb.set_trace()
        assert len(compact_successors) < 2, "The {} visitor returned more than one successor for an ActionNode, this is" \
                                           "not allowed. Got: {}".format(self, compact_successors)
        compact_successor = compact_successors[0]

        if isinstance(compact_successor, ActionsNode) and compact_successor.get_action_type() == node.get_action_type():
            node.actions_info = node.actions_info + compact_successor.actions_info
            node.successor = compact_successor.successor
        else:
            node.successor = compact_successor
        return [node]
