from collections import deque
from .visitor import Visitor


def visit_children_first(graph_head, visitor):
    """

    :type graph_head: DecisionGraphNode
    :param visitor: Visitor
    :return:
    """
    todo = deque()
    todo.append(graph_head)
    todo_set = {graph_head}

    results = {}

    while len(todo) != 0:
        node = todo.pop()
        todo_set.remove(node)

        if node in results:
            continue

        if len(node.get_successors()) == 0 or all(succ in results for succ in node.get_successors()):
            results[node] = visitor.visit_node(node, results)
        else:
            todo.append(node)
            todo_set.add(node)
            for succ in node.get_successors():
                if succ not in todo_set:
                    todo.append(succ)
                    todo_set.add(succ)

    return results[graph_head]


def visit_parent_first(graph_head, visitor):
    """

    :type graph_head: DecisionGraphNode
    :param visitor: Visitor
    :return:
    """
    todo = deque()
    todo.append(graph_head)
    todo_set = {graph_head}

    results = {}

    while len(todo) != 0:
        node = todo.pop()
        todo_set.remove(node)

        results[node] = visitor.visit_node(node, results)
        for succ in node.get_successors():
            if succ not in todo_set:
                todo.append(succ)
                todo_set.add(succ)

    return results[graph_head]


""" Alternate visit implementation, maybe think of bringing back when difficulties arise

    def visit(self, graph_head):
        todo = deque()
        todo.append(graph_head)
        todo_set = {graph_head}

        #import ipdb
        #ipdb.set_trace()

        replacements = {}

        while len(todo) != 0:
            node = todo.pop()
            todo_set.remove(node)

            if node in replacements:
                continue

            done, result = self.visit_node(node, replacements)
            if done:
                # We are done, the result is the replacement
                replacements[node] = result
                continue

            # We are not done, the result are the missing dependencies
            todo.append(node)
            todo_set.add(node)
            missing_deps = result
            for succ in missing_deps:
                if succ not in todo_set:
                    todo.append(succ)
                    todo_set.add(succ)


        return replacements[graph_head]
"""