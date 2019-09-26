from .. import SuccessorsNode, SuccessorNode, DecisionNode, DecisionNotTakenNode
from ..visitor import Visitor


class DecisionNodeCompacter(Visitor):
    def _visit_successors_node(self, node, results):
        """

        :param node:
        :type node: SuccessorsNode
        :return:
        """
        sat_succs = [compact_succ for succ in node.sat_succs for compact_succ in results[succ]]
        if len(node.taken_constraints) == 0:
            return sat_succs

        unsat_succs = [compact_succ for succ in node.unsat_succs for compact_succ in results[succ]]
        return [DecisionNode(sat_succs, unsat_succs, taken_constraints=node.taken_constraints)]

    def _visit_successor_node(self, node, replacements):
        """

        :param node:
        :type node: SuccessorNode
        :return:
        """

        if node.satisfiable:
            if node.successor is not None:
                return replacements[node.successor]
            else:
                return [node]
        else:
            return [DecisionNotTakenNode([node.fresh_constraints], node.address,
                                         reachable_string_refs=node.reachable_string_refs)]
