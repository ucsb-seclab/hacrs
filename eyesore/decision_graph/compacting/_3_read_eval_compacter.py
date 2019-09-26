from .compacting_helper import extract_symbolic_file_offsets_from_constraints, extract_read_addresses_from_actions
from .. import ReadEvalNode, ActionsNode, DecisionNotTakenNode, DecisionNode
from ..visitor import Visitor


class ReadEvalCompacter(Visitor):
    def _visit_actions_node(self, node, replacements):
        """

        :param node:
        :type node: ActionsNode
        :return:
        """
        processed_succ = replacements[node.successor]
        if len(processed_succ) > 1:
            raise ValueError("Got more than one possible successor of an ActionsNode? Got: {}".format(processed_succ))

        compact_succ = processed_succ[0]
        node.successor = compact_succ

        if not isinstance(compact_succ, DecisionNode):
            return [node]

        if node.get_action_type() != 'read':
            return [node]

        read_action_offsets = extract_read_addresses_from_actions(node.actions_info)
        symbolic_offsets = extract_symbolic_file_offsets_from_constraints(compact_succ.taken_constraints)

        if read_action_offsets != symbolic_offsets:
            return [node]

        unsat_succ = compact_succ.unsat_successors[0]
        addr = unsat_succ.address
        reachable_string_refs = unsat_succ.reachable_string_refs
        unsat_reachable_constraints_options = []

        for succ in compact_succ.unsat_successors:
            assert isinstance(succ, DecisionNotTakenNode)
            assert succ.address == addr
            assert succ.reachable_string_refs == reachable_string_refs
            for option in succ.reachable_constraints_options:
                unsat_reachable_constraints_options.append(option)

        not_taken = DecisionNotTakenNode(unsat_reachable_constraints_options,
                                         addr,
                                         reachable_string_refs=reachable_string_refs)

        res = ReadEvalNode(compact_succ.taken_successors, [not_taken],
                           read_actions=node.actions_info,
                           taken_constraints=compact_succ.taken_constraints)
        return [res]
