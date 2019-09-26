from graph_creator import DecisionGraphCreator

from .decision_graph.graph_helper import get_successors_category, get_label, label_encode


class GraphCompacter(DecisionGraphCreator):
    def __init__(self, graph_to_compact, names_only=False):
        super(GraphCompacter, self).__init__(names_only)
        self.source = graph_to_compact

    def visit_actions_node(self, name):
        successors = self.source.successors(name)
        assert len(successors) == 1, 'Following an action must be either another action node or the ' \
                                     'successors header, not {}'.format(successors)

        new_successors = self.visit_node(successors[0])
        assert len(new_successors) == 1, 'In the new graph only a successors node or another action node can follow ' \
                                         'an action node, not {}'.format(new_successors)

        self.add_node(name, label=get_label(self.source, name), shape='box')
        self.add_edge(name, new_successors[0])
        return [name]

    def visit_actions_header(self, name):
        successors = self.source.successors(name)
        assert len(successors) == 1
        return self.visit_node(successors[0])

    def visit_run_header(self, name):
        successors = self.source.successors(name)
        assert len(successors) == 1, 'Following the run header must be the actions header, not {}'.format(successors)
        return self.visit_actions_header(name+'_actions')

    def visit_successors_header(self, name):
        successors = self.source.successors(name)

        assert len(successors) == 4, 'The successors header should have exactly 4 children, not {}'.format(successors)
        assert set(successors) == {name+'_satisfiable', name+'_unsatisfiable', name+'_unconstrained', name+'_flat'}, \
            "We should have 'satisfiable', 'unsatisfiable', 'flat' and 'unconstrained', not {}".format(successors)

        satisfiable_simplified = self.visit_node(name + '_satisfiable')

        data = label_decode(get_label(self.source, name))
        if len(data['constraints']) == 0:
            return satisfiable_simplified

        unsatisfiable_simplified = self.visit_node(name + '_unsatisfiable')
        if len(unsatisfiable_simplified) == 0:
            return satisfiable_simplified

        decision_node = self.add_node(name, label=label_encode(data), shape='diamond')
        for succ in satisfiable_simplified:
            self.add_edge(decision_node, succ, color='green')

        for succ in unsatisfiable_simplified:
            self.add_edge(decision_node, succ, color='red')

        return [decision_node]

    def visit_successors_category_node(self, name):
        category = get_successors_category(name)
        successors = self.source.successors(name)

        if category == 'unsatisfiable':
            assert len(successors) == 0, 'Unsatisfiable nodes should have no successors, not {}'.format(successors)
            run_node = self.add_node(name, label=get_label(self.source, name), shape='box')
            return [run_node]

        if category == 'satisfiable':
            if len(successors) == 0:
                return [self.add_node(name, label=get_label(self.source, name), shape='box')]
            elif len(successors) == 1:
                return self.visit_node(successors[0])
            else:
                raise "Following a satisfiable state should only be either a new run node or the end of the graph, not {}".format(successors)

        else:
            return []

    def visit_successors_category_header(self, name):
        category = get_successors_category(name)
        successors = self.source.successors(name)

        if category == 'satisfiable':
            assert len(successors) < 2, "How did we end up with more than one satisfiable successor?"
            if len(successors) != 0:
                return self.visit_node(successors[0])
            else:
                return []
        elif category == 'unsatisfiable':
            assert len(successors) < 2, "How did we end up with more than one unsatisfiable successor?"
            return self.visit_node(successors[0]) if len(successors) != 0 else []
        else:
            return []

    def visit_node(self, name):
        if len(name) == 0:
            raise ValueError('An empty string is not a valid graph name')

        num_splits = name.count('_')

        if num_splits == 0: # Run header
            return self.visit_run_header(name)

        node_type = get_node_type(name)
        if node_type == 'actions':
            if num_splits == 1: # actions header
                return self.visit_actions_header(name)
            else:
                assert num_splits == 2
                return self.visit_actions_node(name)

        elif node_type == 'successors':
            if num_splits == 1:  # successors header
                return self.visit_successors_header(name)
            elif num_splits == 2:
                return self.visit_successors_category_header(name)
            elif num_splits == 3:
                return self.visit_successors_category_node(name)
            else:
                assert num_splits < 4

        else:
            raise ValueError('{} is not a valid header name'.format(node_type))


def compact_graph(graph, start_node_name='0'):
    compacter = GraphCompacter(graph_to_compact=graph)
    compacter.visit_node(start_node_name)
    return compacter.new_graph