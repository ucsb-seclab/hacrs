from .. import register_node_type
from decision_base import DecisionBaseNode


class ReadEvalNode(DecisionBaseNode):
    def __init__(self, taken_succs=(), unsat_succs=(), read_actions=(), taken_constraints=()):
        super(ReadEvalNode, self).__init__(taken_succs, unsat_succs,
                                           read_actions=read_actions, new_constraints=taken_constraints)
        self.read_actions = read_actions
        self.taken_constraints = taken_constraints


register_node_type(ReadEvalNode, 'read-eval')
