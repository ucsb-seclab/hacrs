import json
import re
from collections import defaultdict

from decision_graph.compacting.compacting_helper import extract_symbolic_file_offsets_from_constraints, \
    extract_symbolic_file_offsets_from_file_desc


def extract_vars(expressions):
    todo = list(expressions)
    vars = set()
    while len(todo) > 0:
        ast = todo.pop()
        if not hasattr(ast, 'op') or not hasattr(ast, 'args'):
            continue

        if ast.op != 'BVS':
            todo.extend(ast.args)
            continue

        vars.add(ast.args[0])
    return vars


def _get_dummy_var_mapping( expressions, dummy_prefix):
    vars = extract_vars(expressions)
    return {var: dummy_prefix + hex(i) for i, var in enumerate(sorted(vars))}


def _dummy_out_vars(ast, mapping):
    if not hasattr(ast, 'op') or not hasattr(ast, 'args'):
        return ast

    dummied_args = [_dummy_out_vars(arg, mapping) for arg in ast.args]
    if ast.op == 'BVS':
        dummied_args[0] = mapping[dummied_args[0]]

    return ast.make_like(ast.op, dummied_args, variables=[mapping[v] for v in ast.variables])


def dummy_out_vars(expressions, dummy_prefix='__dummy_val_'):
    mapping = _get_dummy_var_mapping(expressions, dummy_prefix)
    return mapping, {_dummy_out_vars(ast, mapping) for ast in expressions}


def input_byte_range(var_name):

    regex = "^file_([^_]+)_" + '_'.join(["([0-9a-fA-F]+)"] * 4) + "$"
    match_stdin = re.match(regex, var_name)
    assert match_stdin, "This is new, we not conforming to the file descriptor syntax?? Why does {} not match '{}'?".format(
        file, regex)

    f = match_stdin.group(1)

    assert f == '/dev/stdin', "how are the constraints checking anything but stdin?? Got: {}".format(file)

    return extract_symbolic_file_offsets_from_file_desc(f)


def file_byte_index(var_name):
    return int(var_name.split('_')[3], base=16)

