import json
import os
import tempfile
import time

from simuvex import SimActionConstraint, SimActionExit

from constraint_helper import dummy_out_vars
from decision_graph.compacting.constraint_rewriter import rewrite_constraints
from decision_graph.graph_helper import encode_ast, attr_encode
from decision_graph import ActionsNode, SuccessorNode, SuccessorsNode


def get_reachable_references(cfg, addr, max_depth):
    all_nodes = cfg.get_all_nodes(addr)

    result = set()
    for node in all_nodes:
        result.update(mem_data for mem_data in node.accessed_data_references)
        if max_depth != 0:
            for succ in node.successors:
                result.update(get_reachable_references(cfg, succ.addr, max_depth - 1))
    return result


def filter_interesting_actions(actions):
    filtered_actions = []
    for action in actions:
        if isinstance(action, SimActionConstraint) or isinstance(action, SimActionExit):
            continue

        if action.action not in ['read', 'write'] or not action.type.startswith('file_'):
            continue

        assert len(action.actual_addrs) == 1, "How can you have more than one address for the action {}? " \
                                              "Addresses are: {}".format(action, action.actual_addrs)
        assert type(action.size.ast) in (int, long), "The size is always assumed to be an integer"
        filtered_actions.append(action)

    return filtered_actions


supported_opcodes = ['__add__',
                     '__sub__',
                     '__eq__',
                     '__ne__',
                     '__lt__',
                     '__le__',
                     '__gt__',
                     '__ge__',
                     'SGT',
                     'SGE',
                     'SLT',
                     'SLE',
                     'ZeroExt',
                     'SignExt',
                     'BVS',
                     'BVV',
                     'Extract',
                     ]

def is_too_complex_ast(ast):
    if not hasattr(ast, 'op') or not hasattr(ast, 'args'):
        return False

    # Supported but too complicated
    if ast.op in ['__mul__', 'SDiv', 'SMod']:
        return True

    # Not supported
    if ast.op not in supported_opcodes:
        return True

    for arg in ast.args:
        if is_too_complex_ast(arg):
            return True

    return False


def filter_constraints(constraints):
    return filter(lambda c: not (c.is_false() or c.is_true() or is_too_complex_ast(c)), constraints)


def encode_action(state, action):
    value = state.se.exactly_int(action.actual_value.ast) if action.actual_value is not None else None
    size = state.se.exactly_int(action.size.ast)
    d = {'type': action.action,
         'num_bytes': size / 8,
         'size': size,
         'addrs': action.actual_addrs,
         'value': value}
    return d


def encode_ref(data):
    return data.content
    # return {'address': data.address, 'size': data.size, 'sort': data.sort, 'content': data.content}


def constraints_to_string(constraints):
    return list(set(rewrite_constraints(map(encode_ast, filter_constraints(constraints)))))


class FullGraphCreator(object):
    def __init__(self, project, cfg, find_string_refs=True, max_depth=3):
        super(FullGraphCreator, self).__init__()
        self.start_node = None
        self.extension_points = []

        self.project = project
        self.cfg = cfg
        self.find_string_refs = find_string_refs
        self.max_depth = max_depth

        self.component_constraint_dir = None

    def _make_successor_info(self, category, succ_state, next=None):
        block_addr = succ_state.se.exactly_int(succ_state.ip)

        refs = []
        if self.find_string_refs:
            refs = get_reachable_references(self.cfg, block_addr, self.max_depth)
            refs = filter(lambda data: data.sort == 'string', refs)

        introduced_constraints = map(encode_ast, filter_constraints(succ_state.log.fresh_constraints))

        node = SuccessorNode(fresh_constraints=introduced_constraints,
                             category=category,
                             address=str(succ_state.ip),
                             sat=succ_state.satisfiable(),
                             reachable_string_refs=sorted([encode_ref(d) for d in refs]),
                             successor=next)

        return node, [node,]

    def _make_successor_category_info(self, category, successor_list):
        result_nodes = []
        extension_points = []
        for succ_state in successor_list:
            node, extension_points = self._make_successor_info(category, succ_state, next=None)
            result_nodes.append(node)
            extension_points.extend(extension_points)

        return result_nodes, extension_points

    def _make_successors_info(self, path):
        sat_succs, sat_ext = self._make_successor_category_info('satisfiable', path.previous_run.successors)
        unsat_succs, _ = self._make_successor_category_info('unsatisfiable', path.previous_run.unsat_successors)
        flat_succs, _ = self._make_successor_category_info('flat', path.previous_run.flat_successors)
        unconst_succs, _ = self._make_successor_category_info('unconstrained', path.previous_run.unconstrained_successors)

        introduced_constraints = map(encode_ast, filter_constraints(path.state.log.fresh_constraints))
        succs_node = SuccessorsNode(introduced_constraints, sat_succs, unsat_succs, flat_succs, unconst_succs)
        return succs_node, sat_ext



    def _constraint_look_ahead(self, path, max_num_lookahead_constraints):
        if self.component_constraint_dir is None:
            self.component_constraint_dir = tempfile.mkdtemp(prefix='component_constraints_', dir=os.getcwd())
            print "Compartment constraints will be dumped to ", self.component_constraint_dir

        if all(c.is_true() or c.is_false() for c in path.state.log.fresh_constraints):
            return

        interesting_guards = [c for c in path.guards.hardcopy[:-len(path.state.log.fresh_constraints)] if not c.is_true()]
        mapping, constraints = dummy_out_vars(path.state.log.fresh_constraints)
        #print interesting_guards, path.state.log.fresh_constraints

        longest_subset_match = None
        for i in range(1, 3):
            map, const = dummy_out_vars(interesting_guards[-i:])
            if constraints.issubset(const):
                longest_subset_match = const

        if any(is_too_complex_ast(c) for c in path.state.log.fresh_constraints):
            print "NO Lookahead for: ", path.state.log.fresh_constraints, ", TOO COMPLEX"
            print
            return

        if longest_subset_match is not None:
            print "NO Lookahead for: ", constraints_to_string(path.state.log.fresh_constraints), ", matched with ", str(longest_subset_match)
            print
            # Seems to have some regularity, keep going
            return

        data = {'fresh': constraints_to_string(path.state.log.fresh_constraints),
                'interesting_guards': constraints_to_string(interesting_guards)}

        print "Lookahead for: ", path.state.log.fresh_constraints
        print
        #print "Interesting guards: ", interesting_guards

        pg = self.project.factory.path_group(path.copy())
        pg.one_active.state.se._solver.clear_replacements()

        before = time.time()
        while len(pg.active) > 0:
            #print ".",
            #print "Lookahead step on: ", pg, ", elapsed: ", time.time() - before
            pg.step()

            def stash_filter(p):
                step_interesting_guards = [c for c in p.guards if not c.is_true()]
                return (len(step_interesting_guards) - len(interesting_guards)) >= max_num_lookahead_constraints

            pg.move(filter_func=stash_filter, from_stash='active', to_stash='finished_lookahead')

        time_taken = time.time() - before
        print "Lookahead finished: ", pg, ", elapsed: ", time_taken

        """
        def stash_filter(p):
            step_mapping, step_constraints = self.dummy_out_vars(p.guards)
            same_compartment_constraints = step_constraints.intersection(constraints)
            b_all_true = all(c.is_true() for c in step_constraints)
            b_same_compartment = len(same_compartment_constraints) > 0
            keep = b_all_true or b_same_compartment
            return not keep

        pg.stash(filter_func=stash_filter, from_stash='active', to_stash='finished_compartment')
        """

        def get_compartment_constraints(p):
            step_mapping, step_constraints = dummy_out_vars(p.guards)
            same_compartment_constraints = step_constraints.intersection(constraints)

            for c in p.guards:
                if any(var in c.variables for var in step_mapping if var in mapping):
                    yield c

        def get_new_constraints(p):
            for c in p.history.constraints_since(path):
                if c.is_true():
                    continue
                yield c

        data['compartment_constraints'] = {stash: [constraints_to_string(get_compartment_constraints(p)) for p in pg.stashes[stash]] for stash in pg.stashes}
        data['all_found_constraints'] = {stash: [constraints_to_string(get_new_constraints(p)) for p in pg.stashes[stash]] for stash in pg.stashes}
        data['stashes'] = {stash: len(pg.stashes[stash]) for stash in pg.stashes}
        data['time_taken'] = time_taken

        with open(os.path.join(self.component_constraint_dir, '{:08x}_runs'.format(path.length)), 'w') as f:
            json.dump(data, f, indent=2, sort_keys=True)
        return


    def _make_run_info(self, path):
        next, extension_points = self._make_successors_info(path)

        #self._constraint_look_ahead(path, max_num_lookahead_constraints=10)

        filtered_actions = filter_interesting_actions(path.last_actions)
        for action in reversed(filtered_actions):
            next = ActionsNode([encode_action(path.state, action)], successor=next)

        return next, extension_points

    def analyze_and_add_last_run_info(self, path):
        node, ext = self._make_run_info(path)

        for ext_point in self.extension_points:
            ext_point.set_successors([node])

        self.start_node = self.start_node or node
        self.extension_points = ext

    def finalize_decision_graph(self):
        return self.start_node
