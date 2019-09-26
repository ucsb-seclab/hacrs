import json
import os
import string
from collections import defaultdict

import angr
import claripy
import sys

import time

import psutil
from angr import SimUnsatError

from constraint_helper import file_byte_index, dummy_out_vars


def get_bounded_ast_complexity(c, limit):
    """

    :param c:
    :type c: claripy.ast.Base
    :return:
    """
    if c is None:
        return False, 0

    complexity = 1
    for _ in c.recursive_children_asts:
        complexity += 1
        if complexity > limit:
            return True, limit

    return False, complexity


def is_reasonable_constraint(c, ast_depth_limit=20, ast_complexity_limit=40):
    if c.depth >= ast_depth_limit:
        return False

    too_complex, complexity = get_bounded_ast_complexity(c, ast_complexity_limit)
    print "Constraint {} has complexity {}, too complex: {}".format(c, complexity, too_complex)
    return not too_complex


def extract_input_constraint_similarities(path, input_text):
    constraints = defaultdict(set)

    vars = set()
    for c in path.guards:
        if c.is_true():
            continue

        if not is_reasonable_constraint(c):
            print "IGNORING unreasonable constraint of depth {}".format(c.depth)
            continue

        print "HANDLING reasonable constraint of depth {}: {}".format(c.depth, c)

        vars.update(c.variables)
        for var in c.variables:
            mapping, dummied_constraints = dummy_out_vars((c,))
            constraints[var].update(dummied_constraints)

    if len(vars) == 0:
        return constraints, []

    var_names = [None] * len(input_text)

    for v in vars:
        var_names[file_byte_index(v)] = v
    #assert all(file_byte_index(vars[i]) == i for i in range(len(vars)))

    similarity = tuple(tuple(len(constraints[one].intersection(constraints[two])) for two in var_names) for one in var_names)
    if None in constraints:
        del constraints[None]
    return constraints, similarity


def get_compartment_starts(similarities):
    if len(similarities) == 0:
        return list()

    num_vars = len(similarities)

    assert all(num_vars == len(similarities[var]) for var in range(num_vars))

    compartment_starts = [0]
    for i in range(1, len(similarities)):
        if similarities[i - 1][i - 1] < similarities[i][i]:
            compartment_starts.append(i)

    return compartment_starts

def make_unique_compartment_constraint_sequence(var_constraints, start_inc, end_exc):
    comp_const_seq = []
    for var in sorted(var_constraints.keys()):
        if not (start_inc <= file_byte_index(var) < end_exc):
            continue

        prev = comp_const_seq[-1] if len(comp_const_seq) != 0 else None
        # No previous entry to compare against, unique!
        if prev is not None and len(prev) == len(var_constraints[var]):

            unique_const = False
            for a, b in zip(prev, var_constraints[var]):
                if hash(a) != hash(b):
                    unique_const = True

            if not unique_const:
                continue

        comp_const_seq.append(tuple(var_constraints[var]))

    return tuple(comp_const_seq)

def extract_input_compartment_descriptors(final_path, input_text):
    var_constraints, similarities = extract_input_constraint_similarities(final_path, input_text)
    starts = get_compartment_starts(similarities) + [len(similarities)]

    comps = zip(starts[:-1], starts[1:])
    comp_descriptors = tuple({'start': start,
                              'end': end,
                              'val': input_text[start:end],
                              'const_seq': make_unique_compartment_constraint_sequence(var_constraints, start, end),
                              } for start, end in comps)

    return var_constraints, similarities, comp_descriptors

def constrain_and_concretize(state, file, value, offset=0, length=None):
    file.seek(offset)
    for b in value[offset:(len(value) if length is None else offset + length)]:
        b_bvv = state.se.BVV(b)
        v = file.read_from(1)

        # Add constraint, and let it be concretized in unicorn for any further processing
        state.add_constraints(v == b_bvv)
        state.unicorn.always_concretize.add(v)

def constrain_acceptable(state, file, offset, length):

    file.seek(offset)
    for i in range(length):
        bv = file.read_from(1)

        escapeable_nonprint = claripy.And(bv >= 0x7, bv <= 0xd)
        accepted_nonprint = claripy.Or(bv == 0, escapeable_nonprint)
        printable = claripy.And(bv >= 0x20, bv <= 0x7f)
        all_accepted = claripy.Or(accepted_nonprint, printable)
        state.add_constraints(all_accepted)

def constrain_ascii(state, file, offset, length):
    file.seek(offset)
    for i in range(length):
        bv = file.read_from(1)
        state.add_constraints(bv < 0x7f)

def get_chr_idx_to_constraints_mapping(guards):
    chr_idx_to_constraints = defaultdict(list)
    for c in guards:
        for var in c.variables:
            chr_idx_to_constraints[file_byte_index(var)].append(c)
    return chr_idx_to_constraints


def get_chr_idx_to_dummied_mapping(chr_idx_to_constraints):
    chr_idx_to_dummied = defaultdict(set)
    for var, constraints in chr_idx_to_constraints.iteritems():
        chr_idx_to_dummied[var] = dummy_out_vars(constraints)[1]

    return chr_idx_to_dummied


def guards_match_compartment(comp_descriptor, guards):

    import ipdb; ipdb.set_trace()
    chr_idx_to_constraints = get_chr_idx_to_constraints_mapping(guards)
    chr_idx_to_dummied = get_chr_idx_to_dummied_mapping(chr_idx_to_constraints)

    #import ipdb; ipdb.set_trace()

    i = 0
    const_seq = list(comp_descriptor['const_seq'])
    end = max(chr_idx_to_dummied.keys()) # Take the last variable we have constraints on!
    for chr_idx in range(comp_descriptor['start'], end + 1):
        if i >= len(const_seq):
            break

        cur_const = chr_idx_to_dummied[chr_idx]
        if cur_const.issubset(const_seq[i]): # We're still working on the current element
            continue
        elif i + 1 < len(const_seq) and cur_const.issubset(const_seq[i + 1]): # Try advancing
            i += 1
        else: # Not in the current, not advanceable, diverging!
            return False

    # No collisions found, we must still be in!
    return True


def get_all_paths(pg):
    return [p for stash in pg.stashes for p in pg.stashes[stash]]

def longest_common_prefix(a, b):
    i = 0
    while i < min(len(a), len(b)):
        if a[i] != b[i]:
            break
        i += 1

    assert a[:i] == b[:i]
    return a[:i]

def input_strings_match_other_options(other_options, string_classification_data):
    matches = defaultdict(int)
    result = dict()
    input_strings = [string_ref['content'] for string_ref in string_classification_data['inputs']]
    for stash in other_options:
        result[stash] = dict()
        for option in other_options[stash]:
            result[stash][option] = []
            for input_str in input_strings:
                prefix = longest_common_prefix(input_str, option)
                if len(prefix) == 0: # Not a match
                    continue

                matches[input_str] = max(matches[input_str], len(prefix))
                result[stash][option].append((len(prefix), prefix, input_str))

    result_dict = {}
    for stash in result.keys():
        result_dict[stash] = dict()
        for option in result[stash].keys():
            result_dict[stash][option] = sorted(result[stash][option], key=lambda v: v[0], reverse=True)

    matches_sorted = sorted(matches.iteritems(), key=lambda t: t[1], reverse=True)

    return {'binary_string_options': matches_sorted,
            'generated_options': set([s for stash in other_options for s in other_options[stash] if len(s) > 0])}

def extract_option(compartment_descriptor, p):
    chr_idx_to_constraints = get_chr_idx_to_constraints_mapping(p.state.se.constraints)
    last_var_idx = max(chr_idx_to_constraints.keys())
    input = p.state.posix.dumps(0)
    last_interesting_character = compartment_descriptor['start']

    for i in range(compartment_descriptor['start'], last_var_idx):
        if not input[i] in string.printable or input[i] in string.whitespace:
            break
        last_interesting_character = i

    return input[compartment_descriptor['start']:last_interesting_character]

def extract_other_options(p, state_to_explore, comp_descriptor, input_text, string_classification_data,
                          new_guard_limit=30, timeout=30, max_paths=150):
    state = state_to_explore.copy()
    state.se._solver.clear_replacements()

    stdin_file = state.posix.get_file(0)
    preserved_seek_pos = stdin_file.read_pos

    # All: ASCII only, no high chars
    constrain_ascii(state, stdin_file, 0, len(input_text))

    # Before: concretize
    constrain_and_concretize(state, stdin_file, input_text,
                             offset=0,
                             length=comp_descriptor['start'])

    end_concretizing_offset = min(comp_descriptor['end'], len(input_text))

    # Interesting: Printable chars only in interesting region
    #constrain_acceptable(state, stdin_file, offset=comp_descriptor['start'], length=end_concretizing_offset - comp_descriptor['start'])

    # After: concretize what we reasonably can't expect to reach anyway
    constrain_and_concretize(state, stdin_file, input_text,
                             offset=end_concretizing_offset + 10,
                             length=len(input_text) - end_concretizing_offset)

    #stdin_file.size = None

    stdin_file.seek(preserved_seek_pos)

    print "Retracing for compartment: {}".format(comp_descriptor)
    pg = p.factory.path_group(state)

    start_time = time.time()
    i = 0
    while len(pg.active) > 0:
        sys.stdout.write("\r#{}: States: {}, elapsed: {}, ".format(i, {stash: len(pg.stashes[stash]) for stash in pg.stashes},
                                                      time.time() - start_time))

        mem = psutil.Process(os.getpid()).memory_info().rss
        sys.stdout.write("used memory: {}\tMB".format(mem / (1024 * 1024)))
        sys.stdout.flush()

        if time.time() - start_time >= timeout:
            print " => Timeout of {} exceeded!".format(timeout)
            break

        if len(get_all_paths(pg)) > max_paths:
            print " => More than {} paths!".format(max_paths)
            break

        pg.step()
        i += 1

    def is_interesting_guard(g):
        if g is None or g.is_true():
            return False

        return any(comp_descriptor['start'] <= file_byte_index(v) < comp_descriptor['end'] for v in g.variables)

    def comp_filter(path):
        interesting_guards = [g for g in path.state.se.constraints if g is not None and not g.is_true()]
        if len(interesting_guards) > new_guard_limit:
            return True

        if path.history._guard is None or path.history._guard.is_true():
            return False

    #def compartment_leave_filter(path):
    #    return not guards_match_compartment(comp_descriptor, path.state.se.constraints)

    #pg.stash(filter_func=compartment_leave_filter, from_stash='active', to_stash='left_compartment')

    #import ipdb; ipdb.set_trace()
    other_options = defaultdict(set)
    for stash in pg.stashes:
        for p in pg.stashes[stash]:
            try:
                other_options[stash].add(extract_option(comp_descriptor, p))
            except SimUnsatError:
                print "Got unsat in stash {}".format(stash)
                pass

    return input_strings_match_other_options(other_options, string_classification_data)

def extract_input_characteristics(proj, final_path, input_text, var_before_touch_state_map, string_classification_data):
    var_constraints, similarities, comp_descriptors = extract_input_compartment_descriptors(final_path, input_text)
    comp_set = set([c['const_seq'] for c in comp_descriptors])
    print len(comp_set), '/', len(comp_descriptors)

    other_opts = {}
    for comp in comp_descriptors:
        if comp['const_seq'] in other_opts and other_opts[comp['const_seq']] is not None:
            continue

        var_idx_to_state_mapping = {file_byte_index(k): v for k, v in var_before_touch_state_map.iteritems()}

        #import ipdb; ipdb.set_trace()

        by_runs = defaultdict(list)
        for var in range(comp['start'], comp['end']):
            if var in var_idx_to_state_mapping:
                for r, g, s in var_idx_to_state_mapping[var]:
                    by_runs[r].append((g, s))

        first_idx = -1
        for idx in range(comp['start'], comp['end']):
            if idx in var_idx_to_state_mapping:
                first_idx = idx
                break

        if first_idx == -1:
            other_opts[comp['const_seq']] = None
            continue # We can't do anything with this compartment!

        interesting_guard_creators = var_idx_to_state_mapping[first_idx]

        run, guard, state = interesting_guard_creators[-1]
        removed_guards = []
        for r in sorted(by_runs.keys(), reverse=True):
            if r > run:
                continue

            still_matching = False
            for g, s in by_runs[r]:
                #if any(comp['start'] <= file_byte_index(v) < comp['end'] for v in g.variables):
                if any(comp['start'] == file_byte_index(v) for v in g.variables):
                    # still constraining our input, we're good!
                    run, guard, state = r, g, s
                    still_matching = True
                    break

            if not still_matching:
                break

            removed_guards.append(guard)

        #import ipdb; ipdb.set_trace()

        #print "Finding other options when ignoring {}".format(removed_guards)
        other_string_options = extract_other_options(proj, state, comp, input_text, string_classification_data)
        other_opts[comp['const_seq']] = other_string_options

    for comp in comp_descriptors:
        comp['other_options'] = other_opts[comp['const_seq']]

    return var_constraints, similarities, comp_descriptors, other_opts
