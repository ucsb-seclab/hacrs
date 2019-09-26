from collections import defaultdict
from collections import namedtuple

from decision_graph.visitation import visit_parent_first
from decision_graph.compacting.constraint_rewriter import rewrite_constraints
from decision_graph.compacting.compacting_helper import extract_symbolic_file_offsets_from_constraints
from decision_graph.visitor import Visitor
from decision_graph import SuccessorsNode, SuccessorNode


InputByteInfluences = namedtuple('InputByteInfluences', 'value taken_constraints reachable_strings other_options output_writes')


inverse_constraint_pairs = {
    ('SGT', 'SLE'),
    ('SLT', 'SGE'),
    ('__eq__', '__ne__'),
}


def invert_constraint(ast):
    assert isinstance(ast, dict)
    for one, two in inverse_constraint_pairs:
        if ast['op'] == one:
            return {'op': two, 'args': ast['args']}
        elif ast['op'] == two:
            return {'op': one, 'args': ast['args']}

    raise ValueError("Unimplemented invertible operator {} in {}".format(ast['op'], ast))


def invert_constraints(csts):
    return [invert_constraint(ast) for ast in csts]


debug = True

class InputInfluenceExtractor(Visitor):
    def __init__(self, input_string):
        super(InputInfluenceExtractor, self).__init__()

        # 1st list: taken constraints
        # 2nd list: not taken constraints
        # 3rd list: influenced output writes
        self.input_influences = {}
        for i, c in enumerate(input_string):
            self.input_influences[i] = {'value': c,
                                        'taken_constraints': set(),
                                        'reachable_strings': set(),
                                        'other_options': defaultdict(set),
                                        'output_writes': []}

    def register_successor(self, node):
        """

        :type node: SuccessorNode
        :return:
        """
        if node.category not in ['satisfiable', 'unsatisfiable']:
            return [node]

        constrained_offsets = extract_symbolic_file_offsets_from_constraints(node.fresh_constraints)
        for offset in constrained_offsets:
            if node.satisfiable:
                self.input_influences[offset]['taken_constraints'].update(rewrite_constraints(node.fresh_constraints))
                self.input_influences[offset]['reachable_strings'].update(node.reachable_string_refs)
            else:
                csts = rewrite_constraints(node.fresh_constraints)

                self.input_influences[offset]['other_options'][tuple(csts)].update(node.reachable_string_refs)

                #print "[Offset: {}] Other: {} after adding {}".format(offset,
                #                                                      self.input_influences[offset]['other_options'],
                #                                                      csts)

    def _visit_successors_node(self, node, results):
        """

        :param node:
        :type node: SuccessorsNode
        :param results:
        :return:
        """

        # is this one we should consider?
        if len(node.unsat_succs) != 0 and len(node.taken_constraints) != 0:
            for succ in node.sat_succs:
                self.register_successor(succ)
            for succ in node.unsat_succs:
                self.register_successor(succ)

        return [node]

    def _visit_actions_node(self, node, results):
        return [node]

    def _visit_successor_node(self, node, results):
        return [node]


    def finalize(self):
        result = {}
        for offset, val in self.input_influences.iteritems():
            other_options = list({'constraints': csts, 'reachable_strings': list(sorted(refs))}
                                 for csts, refs in val['other_options'].iteritems())
            other_options_sorted = list(sorted(other_options, key=lambda a: a['constraints']))
            result[offset] = dict(value=val['value'],
                                  taken_constraints=list(val['taken_constraints']),
                                  reachable_strings=list(val['reachable_strings']),
                                  other_options=other_options_sorted,
                                  output_writes=val['output_writes'])

        return result

def extract_influences(graph_head, stdin):
    extractor = InputInfluenceExtractor(stdin)
    visit_parent_first(graph_head, extractor)
    input_influences = extractor.finalize()
    return input_influences