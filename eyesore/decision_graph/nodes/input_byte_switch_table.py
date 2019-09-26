from .. import register_node_type
from .decision_base import DecisionBaseNode


class InputByteSwitchTableNode(DecisionBaseNode):
    def __init__(self, taken_succs=(), unsat_succs=(), input_byte_offset=-1, taken_constraints=()):
        super(InputByteSwitchTableNode, self).__init__(taken_succs, unsat_succs,
                                                       input_byte_offset=input_byte_offset,
                                                       taken_constraints=taken_constraints)
        self.input_byte_offset = input_byte_offset
        self.taken_constraints = taken_constraints

register_node_type(InputByteSwitchTableNode, 'input-byte-switch-table')