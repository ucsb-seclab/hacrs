from collections import defaultdict

from .compacting_helper import extract_symbolic_file_offsets_from_constraints
from .. import DecisionNode, DecisionNotTakenNode, InputByteSwitchTableNode, DecisionBaseNode
from ..visitor import Visitor


class SingleByteJumpTableCompacter(Visitor):
    def _visit_decision_node(self, node, replacements):
        """

        :param node:
        :type node: DecisionNode
        :return:
        """
        node.update_successors(self, replacements)

        referenced_input_bytes = extract_symbolic_file_offsets_from_constraints(node.taken_constraints)
        if len(referenced_input_bytes) != 1:
            return [node]

        referenced_input_byte = referenced_input_bytes.pop()

        if len(node.taken_successors) != 1:
            return [node]

        next_node = node.taken_successors[0]

        if not isinstance(next_node, (DecisionNode, InputByteSwitchTableNode)):
            return [node]

        next_taken_constraints = next_node.taken_constraints
        next_referenced_input_bytes = extract_symbolic_file_offsets_from_constraints(next_taken_constraints)
        if len(next_referenced_input_bytes) != 1 or next_referenced_input_bytes.pop() != referenced_input_byte:
            return [node]

        taken_constraints = next_taken_constraints

        unsat_succ_map = defaultdict(list)
        for succ in node.unsat_successors + next_node.unsat_successors:
            assert isinstance(succ, DecisionNotTakenNode)
            #unsat_succ_map[(succ.address, tuple(succ.reachable_string_refs))].extend(succ.reachable_constraints_options)
            unsat_succ_map[(0, tuple(succ.reachable_string_refs))].extend(succ.reachable_constraints_options)

        unsat_succs = [DecisionNotTakenNode(unsat_succ_map[key], key[0], list(key[1])) for key in unsat_succ_map]
        return [InputByteSwitchTableNode(taken_succs=next_node.taken_successors,
                                         unsat_succs=unsat_succs,
                                         input_byte_offset=referenced_input_byte,
                                         taken_constraints=taken_constraints)]
