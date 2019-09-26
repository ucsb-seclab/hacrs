from .. import register_node_type
from .decision_base import DecisionBaseNode


class DecisionNode(DecisionBaseNode):
    def __init__(self, taken_succs=(), unsat_succs=(), taken_constraints=()):
        super(DecisionNode, self).__init__(taken_succs, unsat_succs, new_constraints=taken_constraints)
        self.taken_constraints = taken_constraints

register_node_type(DecisionNode, 'decision')
