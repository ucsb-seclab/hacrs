import claripy
import functools

def normalize_constraint(c):
    """

    :param c:
    :type c: claripy.ast.Base
    :return:
    """

    if not hasattr(c, 'op') or not hasattr(c, 'args') or not hasattr(c, 'length'):
        return c

    normalized_args = [normalize_constraint(arg) for arg in c.args]

    if c.op in ['__eq__', '__ne__']:
        sorted_args = list(sorted(normalized_args, key=lambda v: (len(v.variables), hash(v)), reverse=True))
        return c.make_like(c.op, sorted_args)
    else:
        return c.make_like(c.op, c.args)
