def extract_symbolic_file_offsets_from_file_desc(f, file_prefix='file_/dev/stdin_'):
    if not f.startswith(file_prefix):
        return set()
    offset = int(f[len(file_prefix):].split('_')[1], base=16)
    num_bytes = int(f[len(file_prefix):].split('_')[3], base=16) / 8
    return set(range(offset, offset + num_bytes))

def extract_symbolic_file_offsets_from_constraint(ast, file_prefix='file_/dev/stdin_'):
    if not isinstance(ast, dict) or 'op' not in ast or 'args' not in ast:
        return set()

    if ast['op'] != 'BVS':
        if 'args' not in ast:
            return set()

        result = set()
        for arg in ast['args']:
            result |= extract_symbolic_file_offsets_from_constraint(arg, file_prefix)
        return result

    f = ast['args'][0]
    return extract_symbolic_file_offsets_from_file_desc(f, file_prefix)

def extract_symbolic_file_offsets_from_constraints(constraints, file_prefix='file_/dev/stdin_'):
    symbolic_offsets = set()
    for constraint in constraints:
        symbolic_offsets |= extract_symbolic_file_offsets_from_constraint(constraint)
    return symbolic_offsets

def extract_read_addresses_from_actions(actions):
    read_offsets = set()
    for act in actions:
        for addr in act['addrs']:
            read_offsets.add(addr)

    return read_offsets