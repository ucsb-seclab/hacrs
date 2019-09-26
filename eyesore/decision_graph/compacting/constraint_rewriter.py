import re

from .compacting_helper import extract_symbolic_file_offsets_from_file_desc

binop_mapping = {
    '__ne__': "!=",#u"\u2260",
    '__add__': '+',
    '__sub__': '-',
    '__mul__': '*',
    '__lt__': '<',
    '__le__': "<=",#u"\u2264",
    '__gt__': '>',
    '__ge__': ">=",#u"\u2265",
    '__eq__': '=',
    'SGT': ">",
    'SGE': ">=",
    'SLT': "<",
    'SLE': ">=",
    'SDiv': "/",
    'SMod': '%',
}

def decode_file_descriptor(file):
    """

    :param file:
    :type file: str
    :return:
    """
    regex = "^file_([^_]+)_" + '_'.join(["([0-9a-fA-F]+)"] * 4) + "$"
    match_stdin = re.match(regex, file)
    assert match_stdin, "This is new, we not conforming to the file descriptor syntax?? Why does {} not match '{}'?".format(file, regex)
    f = match_stdin.group(1)
    assert f == '/dev/stdin', "how are the constraints checking anything but stdin?? Got: {}".format(file)
    return 'input @ {}'.format(list(extract_symbolic_file_offsets_from_file_desc(file)))

def rewrite_ast(ast):
    if isinstance(ast, (int, long)):
        if 0 <= ast < 256:
            #return "['{}' (0x{:02x}|{:d})]".format(chr(ast).encode('string-escape'), ast, ast)
            return "'{}'".format(chr(ast).encode('string-escape'))
        else:
            return str(ast)
    if not isinstance(ast, dict):
        return str(ast)

    op = ast['op']
    args = ast['args']

    if op in binop_mapping:
        new_args = [rewrite_ast(c) for c in args]
        op_str = ' ' + binop_mapping[op] + ' '
        return '(' + op_str.join(new_args) + ')'

    # elif op == '__rshift__':
    #    assert len(args) == 2, "Right shift must have 2 arguments, not {}".format(args)
    #    new_args = [rewrite_ast(c) for c in args]
    #    return "{} * 2^({})".format(new_args[0], new_args[1])
    #
    # elif op == '__lshift__':
    #    assert len(args) == 2, "Left shift must have 2 arguments, not {}".format(args)
    #    new_args = [rewrite_ast(c) for c in args]
    #    return "{} / 2^({})".format(new_args[0], new_args[1])

    elif op in ['ZeroExt', 'SignExt']:
        return rewrite_ast(args[1])

    elif op == 'BVS':
        return decode_file_descriptor(args[0])

    elif op == 'BVV':
        return rewrite_ast(args[0])

    elif op == 'Extract':
        return rewrite_ast(args[2])

    else:
        raise NotImplementedError("Rewriting of operand {} with args [{}] is not yet implemented.".format(op, args))


def rewrite_constraints(constraints):
    return [rewrite_ast(c) for c in constraints]

"""
def rewrite_ast_inner(ast, is_char_value=True):
    if isinstance(ast, (int, long)):
        if 0 <= ast < 128:
            if is_char_value:
                return "'{}'".format(chr(ast).encode('string-escape')), True
            else:
                return "{}".format(ast), False
        else:
            return str(ast), False
    if not isinstance(ast, dict):
        return str(ast), False

    op = ast['op']
    args = ast['args']

    if op == '__sub__':
        if len(args) != 2:
            new_args = [rewrite_ast_inner(c, False)[0] for c in args]
            return '(' + ' - '.join(new_args) + ')'
        else:
            arg_1, char_1 = rewrite_ast_inner(args[0], True)
            arg_2, char_2 = rewrite_ast_inner(args[0], True)
            if char_1 and char_2: # char - char = number
                return '({} - {})'.format(arg_1, arg_2), False
            elif char_1 and not char_2: # char - num = char
                return '({} - {})'.format(arg_1, arg_2), True
            else: # subtracting from numbers always gives numbers ...?
                return '({} - {})'.format(arg_1, arg_2), False

    elif op == '__add__':
        arg_1, char_1 = rewrite_ast_inner(ast, True)
        result_is_char = char_1
        result = ''
        for i in range(1, len(args)):
            result += ' - {}'.format()






    if op in binop_mapping:
        new_args = [rewrite_ast_inner(c) for c in args]
        op_str = ' ' + binop_mapping[op] + ' '
        return '(' + op_str.join(new_args) + ')'


    # elif op == '__rshift__':
    #    assert len(args) == 2, "Right shift must have 2 arguments, not {}".format(args)
    #    new_args = [rewrite_ast(c) for c in args]
    #    return "{} * 2^({})".format(new_args[0], new_args[1])
    #
    # elif op == '__lshift__':
    #    assert len(args) == 2, "Left shift must have 2 arguments, not {}".format(args)
    #    new_args = [rewrite_ast(c) for c in args]
    #    return "{} / 2^({})".format(new_args[0], new_args[1])

    elif op in ['ZeroExt', 'SignExt']:
        return rewrite_ast_inner(args[1], is_char_value)

    elif op == 'BVS':
        return decode_file_descriptor(args[0]), True

    elif op == 'BVV':
        return rewrite_ast_inner(args[0], is_char_value)

    elif op == 'Extract':
        return rewrite_ast_inner(args[2], is_char_value)

    else:
        raise NotImplementedError("Rewriting of operand {} with args [{}] is not yet implemented.".format(op, args))


"""