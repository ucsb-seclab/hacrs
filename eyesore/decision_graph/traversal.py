from collections import deque


def bfs(graph_head, visit_node_func, *args, **kwargs):
    todo = deque()
    todo.append(graph_head)

    while len(todo) > 0:
        node = todo.pop()
        visit_node_func(node, *args, **kwargs)
        succs = node.get_successors()
        if any(not hasattr(succ, 'get_successors') for succ in succs):
            import ipdb
            ipdb.set_trace()
        todo.extendleft(succs)


def dfs(graph_head, visit_node_func, *args, **kwargs):
    todo = deque()
    todo.append(graph_head)

    while len(todo) > 0:
        node = todo.pop()
        visit_node_func(node, *args, **kwargs)
        todo.extend(node.get_successors())
