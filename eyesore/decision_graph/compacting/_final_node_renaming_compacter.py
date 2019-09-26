from .constraint_rewriter import rewrite_constraints, rewrite_ast
from .. import SuccessorsNode, SuccessorNode, DecisionNotTakenNode, TextDecisionNode, TextFlatNode, \
    InputByteSwitchTableNode, ReadEvalLoopNode, ReadEvalNode, ActionsNode, DecisionNode
from ..visitor import Visitor


def readable_encode_dnf(dnf, conjunction_sep=' AND ', disjunction_sep='\nOR\n'):
    return disjunction_sep.join(conjunction_sep.join(inner for inner in outer) for outer in dnf)

def readable_encode_cnf(dnf, conjunction_sep=' AND ', disjunction_sep='\nOR\n'):
    return conjunction_sep.join(disjunction_sep.join(inner for inner in outer) for outer in dnf)

def readable_encode_action(act):
    if act['type'] == 'write':
        return "output @ {} = {}".format(act['addrs'], rewrite_ast(act['value']))
    elif act['type'] == 'read':
        return "Read input @ {}".format(act['addrs'])
    else:
        assert False

class ReadabilityCompacter(Visitor):

    def _visit_actions_node(self, node, replacements):
        """
        :param node:
        :type node: ActionsNode
        :return:
        """
        succs = replacements[node.successor] if node.successor else []
        assert len(succs) < 2, "An action node cannot be follow by more than one node! Got: {}".format(succs)
        succ = succs[0] if len(succs) > 0 else None

        acts = node.actions_info
        text = '\n'.join(readable_encode_action(act) for act in acts)

        return [TextFlatNode(text, succ)]

    def _visit_successors_node(self, node, replacements):
        """

        :param node:
        :type node: SuccessorsNode
        :return:
        """
        sat_succs = [compact_succ for succ in node.sat_succs for compact_succ in replacements[succ]]
        if len(node.taken_constraints) == 0:
            return sat_succs

        unsat_succs = [compact_succ for succ in node.unsat_succs for compact_succ in replacements[succ]]

        text = ''
        text += "Successful checks: \n-> " + '\n-> '.join(rewrite_constraints(node.taken_constraints))
        return [TextDecisionNode(sat_succs, unsat_succs, text=text)]

    def _visit_successor_node(self, node, replacements):
        """

        :param node:
        :type node: SuccessorNode
        :return:
        """

        succs = replacements[node.successor] if node.successor else []
        assert len(succs) < 2, "A successor node cannot be follow by more than one node! Got: {}".format(succs)
        succ = succs[0] if len(succs) > 0 else None

        text = ''
        text += "Necessary checks: \n-> " + '\n-> '.join(rewrite_constraints(node.fresh_constraints))
        text += "Nearby reachable text: \n-> "
        text += '\n-> '.join([s.replace('\n', '') for s in node.reachable_string_refs])
        return [TextFlatNode(text, succ)]

    def _visit_decision_not_taken_node(self, node, replacements):
        """

        :param node:
        :type node: DecisionNotTakenNode
        :return:
        """
        text = ''
        text += "Reachable if: \n-> "

        dnf = [[c_txt for c_txt in rewrite_constraints(constr)] for constr in node.reachable_constraints_options]
        text += readable_encode_dnf(dnf).encode('string-escape')

        text += "\n\nNearby reachable text: \n-> "
        text += '\n-> '.join([s.replace('\n', '<newline>') for s in node.reachable_string_refs])
        return [TextFlatNode(text, None)]

    def _visit_decision_node(self, node, replacements):
        """

        :param node:
        :type node: DecisionNode
        :return:
        """
        sat_succs = [compact_succ for succ in node.taken_successors for compact_succ in replacements[succ]]
        unsat_succs = [compact_succ for succ in node.unsat_successors for compact_succ in replacements[succ]]

        text = ''
        text += readable_encode_dnf([rewrite_constraints(node.taken_constraints)]).encode('string-escape') + '\n'
        return [TextDecisionNode(sat_succs, unsat_succs, text=text)]

    def _visit_input_byte_switch_table_node(self, node, replacements):
        """

        :param node:
        :type node: InputByteSwitchTableNode
        :return:
        """
        return self._visit_decision_node(node, replacements)

    def _visit_read_eval_node(self, node, replacements):
        """

        :type node: ReadEvalNode
        :param node:
        :param replacements:
        :return:
        """
        sat_succs = [compact_succ for succ in node.taken_successors for compact_succ in replacements[succ]]
        unsat_succs = [compact_succ for succ in node.unsat_successors for compact_succ in replacements[succ]]

        text = ''

        actions = node.read_actions
        read_bytes_str = ''
        addrs = set()
        for action in actions:
            assert action['type'] == 'read'
            addrs.update(action['addrs'])

        read_bytes_str += ','.join(map(str, sorted(addrs)))
        const = readable_encode_dnf([rewrite_constraints(node.taken_constraints)]).encode('string-escape') + '\n'
        text += 'Read input characters at {} => Check {}'.format(read_bytes_str, const)

        return [TextDecisionNode(sat_succs, unsat_succs, text)]

    def _visit_read_eval_loop_node(self, node, replacements):
        """

        :type node: ReadEvalLoopNode
        :param node:
        :param replacements:
        :return:
        """
        sat_succs = [compact_succ for succ in node.taken_successors for compact_succ in replacements[succ]]
        unsat_succs = [compact_succ for succ in node.unsat_successors for compact_succ in replacements[succ]]

        text = ''

        for act_const_pair in node.actions_constraints_pairs:
            actions = act_const_pair[0]
            read_bytes_str = ''
            addrs = set()
            for action in actions:
                assert action['type'] == 'read'
                addrs.update(action['addrs'])

            read_bytes_str += ','.join(map(str, sorted(addrs)))
            const = ('(' + ') AND ('.join(rewrite_constraints(act_const_pair[1])) + ')').encode('string-escape') + '\n'
            text += 'Read input characters at {} => Check {}'.format(read_bytes_str, const)

        return [TextDecisionNode(sat_succs, unsat_succs, text)]

