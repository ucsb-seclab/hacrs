import json
import os
import select
import sys
import time
from collections import defaultdict

import angr
import claripy
import gc
import ipdb
import psutil
import simuvex
from simuvex.procedures.cgc.receive import receive

from input_characteristics import extract_input_characteristics
from json_helper import CustomEncoder
from graph_interaction_extractor import extract_interaction
from decision_graph.graph_helper import set_label
from graph_input_constraint_extractor import extract_influences
from full_graph_creator import FullGraphCreator
from decision_graph import agraph_from_decision_graph
from decision_graph.compacting import compact_similar_actions, compact_to_decision_nodes, compact_to_read_eval_nodes, \
    compact_to_read_eval_loop_nodes, compact_to_input_byte_switch_tables, rewrite_readable

"""
import enaml
from angrmanagement.data.instance import Instance
from enaml.qt.qt_application import QtApplication
"""


def _path(f):
    return os.path.join(os.path.dirname(__file__), '..', '..', f)


def _get_chall_dir(event='examples', name='CADET_00003'):
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'cyborg-generator', 'bins', 'challenges_{}'.format(event), name))



first_time_receive_fail = True
stop = False
class TerminatingReceive(receive):
    # pylint:disable=arguments-differ
    """
    Receive which fixes the input to file descriptor to 0.
    """
    def run(self, fd, buf, count, rx_bytes):
        global first_time_receive_fail, stop
        stdin = self.state.posix.files[0]

        if self.state.se.satisfiable(extra_constraints=(stdin.pos < stdin.size,)):
            first_time_receive_fail = True
            ret_val = super(TerminatingReceive, self).run(fd, buf, count, rx_bytes)

        elif first_time_receive_fail:
            first_time_receive_fail = False
            ret_val = super(TerminatingReceive, self).run(fd, buf, count, rx_bytes)
        else:
            print '#\n' * 4 + '#'
            print "DOUBLE RECEIVE FAIL, DIIIIIIIIIIIIIIIEEEEEEEEEEEEEEEEEE!!!!!!!!!!"
            print '#\n' * 4 + '#'
            stop = True
            ret_val = -1

        #print 'Recv({}, {}, {}, {}) returns {}'.format(fd, buf, count, rx_bytes, ret_val)
        return ret_val

class FixedRandom(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, buf, count, rnd_bytes):
        # return code
        r = self.state.se.ite_cases((
                (self.state.cgc.addr_invalid(buf), self.state.cgc.EFAULT),
                (self.state.se.And(rnd_bytes != 0, self.state.cgc.addr_invalid(rnd_bytes)), self.state.cgc.EFAULT),
            ), claripy.BVV(0, self.state.arch.bits))

        if self.state.satisfiable(extra_constraints=[count!=0]):
            self.state.memory.store(buf, claripy.BVV("A" * self.state.se.max_int(count)), size=count)
        self.state.memory.store(rnd_bytes, count, endness='Iend_LE', condition=rnd_bytes != 0)

        return r


"""
def launch_gui(app, pg):
    inst = Instance(proj=proj)
    initialize_instance(inst, {})
    inst.path_groups.add_path_group(pg)

    view = Main(inst=inst)
    view.show()

    app.start()
"""


def print_pg_info(pg, i, start_time):
    stash_len = {}
    for stash in pg.stashes:
        if len(pg.stashes[stash]) == 0:
            continue
        stash_len[stash] = 0

    for stash in stash_len:
        stash_len[stash] = len(pg.stashes[stash])

    print time.time() - start_time, i, stash_len


def heardEnter():
    i, o, e = select.select([sys.stdin], [], [], 0.0001)
    for s in i:
        if s == sys.stdin:
            stdin_line = sys.stdin.readline()
            return True
    return False

def make_initial_state(proj, stdin, stdout, preconstrain_method='replace'):

    add_options = set()
    add_options |= simuvex.o.unicorn
    add_options.add(simuvex.o.CONSTRAINT_TRACKING_IN_SOLVER)
    #add_options.add(simuvex.o.TRACK_ACTION_HISTORY)
    add_options.add(simuvex.o.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY)
    add_options.add(simuvex.o.CGC_NO_SYMBOLIC_RECEIVE_LENGTH)
    add_options.add(simuvex.o.UNICORN_THRESHOLD_CONCRETIZATION)
    add_options.add(simuvex.options.CGC_ENFORCE_FD)
    add_options.add(simuvex.options.CGC_NON_BLOCKING_FDS)
    if preconstrain_method == 'replace':
        add_options.add(simuvex.o.REPLACEMENT_SOLVER)

    remove_options = simuvex.o.simplification
    remove_options |= {simuvex.o.LAZY_SOLVES}
    remove_options |= {simuvex.o.SUPPORT_FLOATING_POINT}
    remove_options |= {simuvex.o.COMPOSITE_SOLVER}
    remove_options |= {simuvex.o.UNICORN_HANDLE_TRANSMIT_SYSCALL}

    state = proj.factory.full_init_state(
        add_options=add_options,
        remove_options=remove_options
    )

    csr = state.unicorn.cooldown_symbolic_registers
    state.unicorn.max_steps = 2000000
    state.unicorn.concretization_threshold_registers = 25000 / csr
    state.unicorn.concretization_threshold_memory = 25000 / csr

    stdin_file = state.posix.get_file(0)
    stdin_file.size = len(stdin)

    for b in stdin:
        b_bvv = state.se.BVV(b)
        v = stdin_file.read_from(1)

        if preconstrain_method == 'replace':
            state.se._solver.add_replacement(v, b_bvv, invalidate_cache=False)
        elif preconstrain_method == 'constrain_symbolic':
            state.add_constraints(v == b_bvv)
        else:
            raise NotImplementedError("Preconstraining strategy {} is unknown".format(preconstrain_method))

    stdin_file.seek(0)
    return state


def dump_agraph(head, name):
    print("[{}] Dumping the graph .dot file .. ".format(name))
    graph = agraph_from_decision_graph(head)
    graph.write(name + '.dot')
    return head, graph

def dump_decision_graph(head):
    full, graph                                 = dump_agraph(head, 'decision_graph_full')
    compacted_decision_nodes, graph             = dump_agraph(compact_to_decision_nodes(full), 'decision_graph_compact_0_decision_nodes')
    compacted_similar_actions, graph            = dump_agraph(compact_similar_actions(compacted_decision_nodes), 'decision_graph_compact_1_similar_actions')
    compacted_input_byte_switch_tables, graph   = dump_agraph(compact_to_input_byte_switch_tables(compacted_similar_actions), 'decision_graph_compact_2_switch_tables')
    compacted_read_eval, graph                  = dump_agraph(compact_to_read_eval_nodes(compacted_input_byte_switch_tables), 'decision_graph_compact_3_read_eval_nodes')
    compacted_read_eval_loops, graph            = dump_agraph(compact_to_read_eval_loop_nodes(compacted_read_eval), 'decision_graph_compact_4_read_eval_loop_nodes')
    compacted_human_readable, graph             = dump_agraph(rewrite_readable(compacted_read_eval_loops), 'decision_graph_compact_5_human_readable_nodes')
    for node_name in graph.nodes():
        set_label(graph, node_name, node_name)

    print("[decision_graph_compact_5_human_readable_node_names] Dumping the graph .dot file .. ")
    graph.write('decision_graph_compact_5_human_readable_node_names.dot')

    print "Final Graph: {} nodes, {} edges".format(len(graph.nodes()), len(graph.edges()))


if __name__ == '__main__':
    import logging
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    #logging.getLogger("claripy.backends.backend_z3").setLevel(logging.DEBUG)

    simuvex.SimProcedures['cgc']['random'] = FixedRandom
    simuvex.SimProcedures['cgc']['receive'] = TerminatingReceive

    proj = angr.Project(sys.argv[1])
    stdin = ''
    output = ''
    with open(os.path.abspath(sys.argv[2]), 'r') as inf:
        stdin = inf.read()

    if len(stdin) == 0:
        print "SKIPPING input {} for {}, it's empty!".format(sys.argv[1], sys.argv[2])
        sys.exit(0)

    s = make_initial_state(proj, stdin, output, preconstrain_method='replace')
    p = proj.factory.path(s)

    hierarchy = angr.PathHierarchy(weakkey_path_mapping=True)
    pg = proj.factory.path_group(p, immutable=False, hierarchy=hierarchy)
    pg.use_technique(angr.exploration_techniques.Oppologist())

    cfg = proj.analyses.CFGFast(collect_data_references=True, extra_cross_references=True)

    """
    with enaml.imports():
        from angrmanagement.ui.main import Main, initialize_instance

    app = QtApplication()
    """

    strings_classification_path = sys.argv[3]
    timeout = int(sys.argv[4]) if len(sys.argv) > 4 else -1



    before = time.time()
    interrupt = False
    i = 0
    last_num_steps = 0
    last_time = before

    #import ipdb
    #ipdb.set_trace()
    var_before_touch_state_map = defaultdict(list)
    graph_creator = FullGraphCreator(proj, cfg, find_string_refs=True, max_depth=5)
    while not stop and len(pg.active) > 0 and (timeout == -1 or (time.time() - before) < timeout):

        assert len(pg.active) == 1
        before_state = pg.one_active.state
        before_length = pg.one_active.length

        pg.step()

        all_paths = [path for stash in pg.stashes for path in pg.stashes[stash]]

        assert len(all_paths) == 1, 'We should always have exactly one path, how did we end up with {}???'.format(str(pg))
        path = all_paths[0]

        before_const = set(before_state.se.constraints)
        after_const = set(path.state.se.constraints)

        if before_const != after_const:
            assert len(before_const - after_const) == 0

            # All the new constraints
            for c in after_const - before_const:
                for var in c.variables:
                    var_before_touch_state_map[var].append((before_length, c, before_state))

        graph_creator.analyze_and_add_last_run_info(path)

        #del path.history.state
        #path.history.state = None

        i += 1

        #if i > 450:
        #    break

        if i % 100 == 0:
            current_time = time.time()
            mem = psutil.Process(os.getpid()).memory_info().rss
            print "Currently used memory: {}\tMB =>".format(mem / (1024 * 1024))
            print "Traced so far: {}".format(len(path.addr_trace.hardcopy))
            print "Steps per second: {}".format(float(i - last_num_steps) / float(current_time - last_time))

            """
            graph_creator.add_layer(graph_creator.add_node(str(i)))
            dump_graph(graph_creator.new_graph, 'info_graph_full_{}'.format(i))
            graph_creator = FullGraphCreator(cfg, names_only=False, find_string_refs=True, max_depth=5)
            """

            last_num_steps = i
            last_time = time.time()

        if heardEnter():
            interrupt = True

        if interrupt:
            interrupt = False
            #launch_gui(app, pg)
            import IPython
            IPython.embed()

    complete_retrace_time = time.time() - before
    print "Retracing the original trace took {} seconds".format(complete_retrace_time)

    all_paths = [path for stash in pg.stashes for path in pg.stashes[stash]]
    assert len(all_paths) == 1, 'We should always have exactly one path, how did we end up with {}???'.format(str(pg))
    final_path = all_paths[0]

    #ipdb.set_trace()
    input_base = sys.argv[2][:sys.argv[2].rindex('.')]

    del pg
    claripy.downsize()
    gc.collect()

    decision_graph_head = graph_creator.finalize_decision_graph()


    with open(input_base + '.output', 'w') as outf:
        print "Dumping {}".format(outf.name)
        outf.write(final_path.state.posix.dumps(1))


    interaction = extract_interaction(decision_graph_head)
    with open(input_base + '.interaction.json', 'w') as outf:
        print "Dumping {}".format(outf.name)
        json.dump(interaction, outf, ensure_ascii=False, indent=2, cls=CustomEncoder)

    input_influences = extract_influences(decision_graph_head, stdin)
    with open(input_base + '.influence.json', 'w') as outf:
        print "Dumping {}".format(outf.name)
        json.dump(input_influences, outf, ensure_ascii=False, indent=2, cls=CustomEncoder)


    with open(strings_classification_path, 'r') as inf:
        string_classification_data = json.load(inf)

    before_input_characteristic_extraction = time.time()
    constraints, similarities, comp_descriptors, other_opts = extract_input_characteristics(proj,
                                                                                            final_path,
                                                                                            stdin,
                                                                                            var_before_touch_state_map,
                                                                                            string_classification_data)
    other_options_time_after = time.time()

    after_input_characteristic_extraction = time.time()

    with open(input_base + '.character_similarities.csv', 'w') as outf:
        print "Dumping {}".format(outf.name)
        lines = [(','.join(map(str, level)) + '\n') for level in similarities]
        outf.writelines(lines)

    with open(input_base + '.compartment_information.json', 'w') as outf:
        print "Dumping {}".format(outf.name)
        json.dump(comp_descriptors, outf, indent=1, cls=CustomEncoder)

    # dump_decision_graph(decision_graph_head)

    print "$" * 80
    print "Timing Summary: Retracing the input took {} seconds, extracting input characteristics took {} seconds".format(
        complete_retrace_time, after_input_characteristic_extraction - before_input_characteristic_extraction
    )
    print "$" * 80
    #


