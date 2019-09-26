from _0_decision_node_compacter import DecisionNodeCompacter
from _1_similar_actions_compacter import SimilarActionsCompacter
from _2_single_byte_jump_table import SingleByteJumpTableCompacter
from _3_read_eval_compacter import ReadEvalCompacter
from _4_read_eval_loop_compacter import ReadEvalLoopCompacter
from _final_node_renaming_compacter import ReadabilityCompacter
from ..visitation import visit_children_first


def compact_to_decision_nodes(head):
    r = visit_children_first(head, DecisionNodeCompacter())
    assert len(r) == 1, "How did compacting to decision nodes result in more than one head? Got: {}".format(r)
    return r[0]

def compact_similar_actions(head):
    r = visit_children_first(head, SimilarActionsCompacter())
    assert len(r) == 1, "How did compacting similar actions result in more than one head? Got: {}".format(r)
    return r[0]

def compact_to_input_byte_switch_tables(head):
    r = visit_children_first(head, SingleByteJumpTableCompacter())
    assert len(r) == 1, "How did compacting input byte switch tables result in more than one head? Got: {}".format(r)
    return r[0]

def compact_to_read_eval_nodes(head):
    r = visit_children_first(head, ReadEvalCompacter())
    assert len(r) == 1, "How did compacting to read-eval nodes result in more than one head? Got: {}".format(r)
    return r[0]

def compact_to_read_eval_loop_nodes(head):
    r = visit_children_first(head, ReadEvalLoopCompacter())
    assert len(r) == 1, "How did compacting read-evals into loops result in more than one head? Got: {}".format(r)
    return r[0]

def rewrite_readable(head):
    r = visit_children_first(head, ReadabilityCompacter())
    assert len(r) == 1, "How did rewriting to a more readable form result in more than one head? Got: {}".format(r)
    return r[0]



def compact_all(head):
    head = compact_to_decision_nodes(head)
    head = compact_similar_actions(head)
    head = compact_to_input_byte_switch_tables(head)
    head = compact_to_read_eval_nodes(head)
    head = compact_to_read_eval_loop_nodes(head)
    return head
