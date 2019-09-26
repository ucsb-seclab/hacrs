from .. import ReadEvalNode, ReadEvalLoopNode
from ..visitor import Visitor


class ConsecutiveInputComparisonCompacter(Visitor):
    def _visit_read_eval_node(self, node, replacements):
        """

        :param node:
        :type node: ReadEvalNode
        :return:
        """
        node.update_successors(self, replacements)

        if len(node.taken_successors) != 1 or len(node.unsat_successors) != 1:
            return [node]

        next_node = node.taken_successors[0]

        act_constr_pairs = [(node.read_actions, node.taken_constraints)]
        if isinstance(next_node, ReadEvalNode):
            act_constr_pairs.append((next_node.read_actions, next_node.taken_constraints))
        elif isinstance(next_node, ReadEvalLoopNode):
            act_constr_pairs.extend(next_node.actions_constraints_pairs)

        else:
            return [node]

        if len(next_node.unsat_successors) != 1:
            return [node]

        a_unsat, b_unsat = node.unsat_successors[0], next_node.unsat_successors[0]
        if a_unsat.address != b_unsat.address or a_unsat.reachable_string_refs != b_unsat.reachable_string_refs:
            return [node]

        taken_succs = next_node.taken_successors
        unsat_succs = next_node.unsat_successors

        return [ReadEvalLoopNode(taken_succs, unsat_succs, actions_constraints_pairs=act_constr_pairs)]


