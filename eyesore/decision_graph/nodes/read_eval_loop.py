from .. import register_node_type
from .decision_base import DecisionBaseNode

class ReadEvalLoopNode(DecisionBaseNode):
    def __init__(self, taken_succs=(), unsat_succs=(), actions_constraints_pairs=()):
        super(ReadEvalLoopNode, self).__init__(taken_succs, unsat_succs,
                                               actions_constraints_pairs=actions_constraints_pairs)
        self.actions_constraints_pairs = actions_constraints_pairs

register_node_type(ReadEvalLoopNode, 'read-eval-loop')
