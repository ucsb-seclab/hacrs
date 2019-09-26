import json


def get_all_numbered_nodes(graph, fmt_str):
    i = 0
    name = fmt_str.format(i)
    while graph.has_node(name):
        yield name


def reserve_and_get_next_available_numbered_node_name(graph, node_type, name_to_next_idx_mapping):
    # return node_type + '_' + str(len(tuple(n for n in graph.nodes() if n.startswith(node_type + '_'))))

    if node_type not in name_to_next_idx_mapping:
        graph.graph_attr[node_type] = 0

    val = name_to_next_idx_mapping[node_type]
    name_to_next_idx_mapping[node_type] += 1
    return node_type + '_' + str(val)


def attr_encode(data):
    return json.dumps(data, indent=0).encode('string-escape')


def attr_decode(text):
    return json.loads(text.decode('string-escape'))


def get_label(g, node):
    return g.get_node(node).attr['label']


def set_label(g, node, val):
    g.get_node(node).attr['label'] = val


def get_top_level_nodes(g):
    return [node for node, degree in g.in_degree_iter() if degree == 0]


def encode_ast(ast):
    data = ast
    if hasattr(ast, 'op') and hasattr(ast, 'args'):
        data = {'op': ast.op, 'args': [encode_ast(arg) for arg in ast.args]}
    return data
