#!/usr/bin/env python

import os
import re
import sys
import time
import angr
import json
import shutil
import cPickle as pickle
import argparse
#import networkx
import tempfile
#import termcolor
import subprocess
import shellphish_qemu

#
# Argument parsing
#

parser = argparse.ArgumentParser(description="HaCRS HAI helper")
parser.add_argument('command', choices=[
    'seed', 'drill', 'seek', 'exec', 'annotate', 'continuous-seed', 'continuous-seek', 'update-bitmap', 'htmlize', 'vuln-output'
], help="what to do")
parser.add_argument('binary', help="the binary")
parser.add_argument("bitmap", help="AFL bitmap file")
parser.add_argument("-B", "--copy-bitmap", help="copy the default bitmap if it does not exist", action='store_true')
parser.add_argument("-d", "--seed-dir", nargs='*', default=[], help="a directory with currently known seeds")
parser.add_argument("-p", "--session-discoveries", nargs='*', default=[], help="a directory with previously-created seeds by this tasklet")
parser.add_argument("-r", "--result-file", default="/dev/stderr", help="analysis result destination")
parser.add_argument(
    "-i", "--input-file",
    default="/dev/stdin", help="program input source"
)
parser.add_argument(
    "-o", "--output-file",
    default="/dev/stdout", help="program output destination"
)
parser.add_argument("-t", "--trace-file", help="QEMU trace")
parser.add_argument("-a", "--target_address", help="target address (for seeking)")
args = parser.parse_args()

if args.output_file is not None:
    try:
        os.makedirs(os.path.dirname(args.output_file))
    except OSError:
        pass

if args.result_file is not None:
    try:
        os.makedirs(os.path.dirname(args.result_file))
    except OSError:
        pass

if args.copy_bitmap and not os.path.exists(args.bitmap):
    parent_bitmap = os.path.join(os.path.dirname(os.path.dirname(args.bitmap)), "bitmap")
    if os.path.exists(parent_bitmap):
        shutil.copy2(parent_bitmap, args.bitmap)

#
# Seed and trace analysis
#

def seed_blocks(seed):
    if os.path.exists(seed + ".coverage"):
        with open(seed + ".coverage") as pf:
            return pickle.load(pf)
    else:
        tname = tempfile.mktemp(dir='/dev/shm')
        execute_binary(seed, '/dev/null', tname)
        traced_blocks = set(trace_addrs(tname))
        os.unlink(tname)
        try:
            with open(seed + ".coverage", "w") as pf:
                pickle.dump(traced_blocks, pf, -1)
        except (OSError, IOError):
            pass
        return traced_blocks

def tracefile_blocks(tracefile):
    return set(trace_addrs(tracefile))

def trace_addrs_from_lines(trace_lines):
    for line in trace_lines:
        result = re.match(r'Trace 0x[0-9a-fA-F]* \[([0-9a-fA-F]*)\]', line)
        if not result:
            continue

        addr = int(result.group(1), base=16)
        yield addr

def trace_addrs(tracefile):
    with open(tracefile) as tf:
        return list(trace_addrs_from_lines(tf.readlines()))

def execute_binary(iname, oname, tname, trace_blocks=True, trace_syscalls=True):
    infile = open(iname)
    outfile = open(oname, 'w')
    tracefile = open(tname, 'w') if tname != oname else outfile

    cmd_args = [ "timeout", "60", shellphish_qemu.qemu_path('cgc-tracer') ]
    if trace_blocks:
        cmd_args += [ '-d', 'exec' ]
    if trace_syscalls:
        cmd_args += [ '-strace' ]
    if trace_blocks and not trace_syscalls:
        tracefile.close()
        cmd_args += [ '-D', tname ]
        tracefile = open('/dev/null', 'w')
    cmd_args += [ args.binary ]

    process = subprocess.Popen(cmd_args, stdin=infile, stdout=outfile, stderr=tracefile)
    process.wait()
    return process.pid

#
# Block tracking
#

p = angr.Project(args.binary)

def map_seed_dir(seed_dir, function):
    if not os.path.exists(seed_dir):
        return

    for s in os.listdir(seed_dir):
        if not s.endswith("seed"):
            continue

        try:
            function(os.path.join(seed_dir, s))
        except (IOError, OSError) as e:
            print "Failed processing seed: %s, %s" % (s, e)

class Blocks(object):
    def __init__(self, prior_file, need_cfg=True):
        self.prior = pickle.load(open(prior_file)) if args.bitmap and os.path.exists(args.bitmap) else set()
        if need_cfg:
            self.cfg = p.analyses.CFG()
            #cfg.normalize()
            self.all = set(_n.addr for _n in self.cfg.graph.nodes())
        else:
            self.cfg = None
            self.all = set()
        self.found = set()

    def add_prior_seed(self, seed):
        new_blocks = self.seed_blocks_new(seed)
        self.prior.update(new_blocks)
        self.all.update(new_blocks)

    def add_session_seed(self, seed):
        new_blocks = self.seed_blocks_new(seed)
        self.found.update(new_blocks)
        self.all.update(new_blocks)

    def seed_blocks_new(self, seed):
        return seed_blocks(seed) - self.triggered

    def tracefile_blocks_new(self, tracefile):
        return tracefile_blocks(tracefile) - self.prior

    @property
    def missing(self):
        return self.all - self.triggered

    @property
    def triggered(self):
        """
        Any blocks that have ever been triggered, in this session or prior sessions.
        """
        return self.prior | self.found

    @property
    def goal_blocks(self):
        return len(self.missing)/10

    @property
    def coverage(self):
        return float(len(self.triggered)) / len(self.all)

    @property
    def prior_coverage(self):
        return float(len(self.prior)) / len(self.all)

    @property
    def coverage_improvement(self):
        """
        (new coverage * 100) / old_coverage
        """
        prior_coverage = self.prior_coverage or 1
        return (self.coverage * 100) / prior_coverage

blocks = Blocks(args.bitmap, need_cfg=args.command not in [ 'htmlize' ])
if blocks.cfg is not None:
    for _seed_dir in args.seed_dir:
        map_seed_dir(_seed_dir, blocks.add_prior_seed)
    for _dir in args.session_discoveries:
        map_seed_dir(_dir, blocks.add_session_seed)

#
# Interpretation of sessions
#

def replay_session(iname, oname, tname, receive_callback, transmit_callback):
    input_data = open(iname).read()
    output_data = open(oname).read()

    last_was = None
    s = ""

    for t in open(tname):
        if 'transmit' not in t and 'receive' not in t:
            continue

        if 'transmit' in t and last_was == 'receive':
            receive_callback(s)
            s = ""
        elif 'receive' in t and last_was == 'transmit':
            transmit_callback(s)
            s = ""

        byte_count = int(t.split('count=')[-1].split(',')[0])
        if 'receive' in t:
            last_was = 'receive'
            received, input_data = input_data[:byte_count], input_data[byte_count:]
            s += received
        elif 'transmit' in t:
            transmitted, output_data =  output_data[:byte_count], output_data[byte_count:]
            s += transmitted
            last_was = 'transmit'

    if last_was == 'receive':
        receive_callback(s)
    elif last_was == 'transmit':
        transmit_callback(s)

#def interpret_session(iname, oname, tname):
#   input_data = open(iname).read()
#   output_data = open(oname).read()
#
#   actions = [ ]
#
#   cur_deviations = [ ]
#   for t in open(tname):
#       if t.startswith("Trace"):
#           # if it's a basic block, figure out what deviations are possible here
#           addr = int(t.split('[').split(']')[0], 16)
#           block = cfg.get_any_node(addr, anyaddr=True)
#           successor_addrs = [ b.addr for b in block.successors ]
#           cur_deviations += [ (addr,sa) for sa in successor_addrs if (addr,sa) not in bitmap ]
#       elif 'receive' in t:
#           # if it's a receive call, add the data
#           actions.append(('deviations', cur_deviations))
#           cur_deviations = [ ]
#
#           byte_count = int(t.split('count=')[-1].split(',')[0])
#           actions.append(('receive', input_data[:byte_count]))
#           input_data = input_data[byte_count:]
#       elif 'transmit' in t:
#           # if it's a transmit, add the data
#           actions.append(('deviations', cur_deviations))
#           cur_deviations = [ ]
#
#           byte_count = int(t.split('count=')[-1].split(',')[0])
#           actions.append(('transmit', output_data[:byte_count]))
#           output_data = output_data[byte_count:]
#
#   actions.append(('deviations', cur_deviations))
#
#   # consolidate the deviations to the reads
#   consolidated_actions = [ ]
#   last_deviations = [ ]
#   for t,data in reversed(actions):
#       if t == 'deviations':
#           last_deviations += data
#       elif t == 'transmit':
#           consolidated_actions.append((t, data))
#       elif t == 'receive':
#           if last_deviations:
#               consolidated_actions.append(('deviations', last_deviations))
#           last_deviations = [ ]
#           consolidated_actions.append((t, data))
#   consolidated_actions.reverse()
#
#   # consolidate the successive reads
#   final_actions = [ ]
#   for t,data in consolidated_actions:
#       if len(final_actions) <= 2:
#           final_actions.append((t, data))
#       elif final_actions[-1][0] == t:
#           final_actions[-1] = (t, final_actions[-1][1] + data)
#       elif t == 'receive' and final_actions[-2][0] == t and final_actions[-1][0] == 'deviations':
#           final_actions[-2] = ('receive', final_actions[-2][1] + data)
#       else:
#           final_actions.append((t, data))
#
#   #import pprint
#   #pprint.pprint(consolidated_actions)
#   #pprint.pprint(final_actions)
#
#   return final_actions

#def annotate_interaction(iname, final_oname, deviation_annotations=False):
#   tname = tempfile.mktemp()
#   oname = tempfile.mktemp()
#   final_out = open(final_oname, 'w')
#
#   # run it
#   execute_binary(iname, oname, tname)
#   actions = interpret_session(args.input_file, oname, tname)
#
#   point = 0
#   for t,data in actions:
#       if t == 'transmit':
#           final_out.write(data)
#       elif t == 'receive':
#           final_out.write(termcolor.colored(data, 'green'))
#       elif t == 'deviations' and deviation_annotations:
#           final_out.write(termcolor.colored("[POINT_%d_DEVIATIONS=%d]" % (point,len(data)), 'blue'))
#           point += 1



#
# Evaluation of sessions
#

#def seeker_closeness(tracefile, target):
#   G = networkx.DiGraph(cfg.graph)
#   G.reverse(copy=False)
#
#   trace = trace_addrs(tracefile)
#   trace_blocks = { cfg.get_any_node(t, anyaddr=True) for t in trace }
#   target_block = cfg.get_any_node(target, anyaddr=True)
#
#   distances = networkx.single_source_shortest_path_length(G, target_block)
#   known_addrs = [
#       e[1]
#       for e in all_transitions
#       if (e[0], e[1]) in bitmap
#   ]
#   known_blocks = { cfg.get_any_node(a, anyaddr=True) for a in known_addrs }
#
#   return {
#       'current_distance': min(distances[n] for n in known_blocks) if known_blocks else 999999,
#       'new_distance': min(distances[n] for n in trace_blocks)
#   }


#def evaluate_seek(sname, target, tname=None):
#   if not tname:
#       tf = tempfile.mktemp(dir='/dev/shm')
#       execute_binary(sname, '/dev/null', tf)
#   else:
#       tf = tname
#   #r = seeker_closeness(tf, target)
#   r = { 'todo': "TODO" }
#   if tname is None:
#       os.unlink(tf)
#   return r
#
#def seeker_closeness_2(trace_file_lines, target):
#   G = networkx.DiGraph(cfg.graph)
#   G.reverse(copy=False)
#
#   trace = list(set(trace_addrs_from_lines(trace_file_lines)))
#
#   print "getting trace blocks ..."
#   trace_blocks = { cfg.get_any_node(t, anyaddr=True) for t in trace }
#   print "getting trace block ..."
#   target_block = cfg.get_any_node(target, anyaddr=True)
#   if target_block is None:
#       sys.exit(66)
#
#   print "calculating distances ..."
#   distances = networkx.single_source_shortest_path_length(G, target_block)
#   print "calculating new distance ..."
#   new_dist = min(distances[n] for n in trace_blocks if n in distances)
#   print "calculated new distance, returning ..."
#   return {
#       'new_distance': new_dist
#   }

#def evaluate_seek_2_maybe_because_something_was_really_fucked_up_apparently(sname, target, tname=None):
#   if not tname:
#       tf_fd, tf = tempfile.mkstemp()
#       execute_binary(sname, '/dev/null', tf)
#   else:
#       tf = tname
#       tf_fd = -1
#
#   with open(tf, 'r') as f:
#       trace_file_lines = f.readlines()
#
#   r = seeker_closeness_2(trace_file_lines, target)
#   if tname is None:
#       os.close(tf_fd)
#       os.unlink(tf)
#   return r

def evaluate_seed(sname, tname=None):
    if not tname:
        tf = tempfile.mktemp(dir='/dev/shm')
        execute_binary(sname, '/dev/null', tf, trace_syscalls=False)
    else:
        tf = tname

    new_blocks = blocks.tracefile_blocks_new(tf)
    blocks.found.update(new_blocks)

    r = {
        'timestamp': int(time.time()),
        'seed_length': os.path.getsize(sname),
        'total_transitions': len(blocks.all),
        'previous_transitions': len(blocks.prior),
        'missing_transitions': len(blocks.missing),
        'goal_transitions': len(blocks.missing)/10,
        'new_transitions': len(blocks.found),
        'coverage_improvement': blocks.coverage_improvement,
        'coverage': blocks.coverage
    }
    if tname is None:
        os.unlink(tf)
    return r

def monitor_interaction(oname, rname, result_callback):
    proc = subprocess.Popen("stdbuf -i0 -o0 python -u %s/fixup_input.py %s | stdbuf -i0 -o0 tee %s 2>/dev/null | (%s %s; sleep 2; killall -2 tee 2>/dev/null; kill -2 $PPID 2>/dev/null) | %s ./color" % (
        os.path.dirname(__file__), os.path.basename(args.binary),
        oname, shellphish_qemu.qemu_path('cgc-tracer'), args.binary, sys.executable
    ), shell=True)
    last_size = -1
    try:
        while proc.poll() is None:
            time.sleep(1)
            new_size = os.path.getsize(oname)
            if new_size != last_size:
                last_size = new_size
                with open(rname, 'a') as rf:
                    r = result_callback(oname)
                    r['output_file'] = oname
                    json.dump(r, rf)
                    rf.write('\n')
    except KeyboardInterrupt:
        pass

#def driller_deviated(tracefile1, tracefile2):
#    pass

if args.command == 'seed':
    json.dump(evaluate_seed(args.input_file, tname=args.trace_file), open(args.result_file, 'w'))
#elif args.command == 'seek':
#   data = evaluate_seek_2_maybe_because_something_was_really_fucked_up_apparently(args.input_file,
#                                                                                  int(args.target_address, 16),
#                                                                                  tname=args.trace_file)
#   json.dump(data, open(args.result_file, 'w'))
elif args.command == 'continuous-seed':
    monitor_interaction(args.output_file, args.result_file, evaluate_seed)
#elif args.command == 'continuous-seek':
#   monitor_interaction(
#       args.output_file, args.result_file,
#       #lambda o: evaluate_seek(o, int(args.target_address, 16))
#       lambda o: evaluate_seek(o, 0)
#   )
elif args.command == 'exec':
    _tf = args.trace_file or tempfile.mktemp()
    execute_binary(args.input_file, args.output_file, _tf)
    print "Tracefile:", _tf
#elif args.command == 'annotate':
#   annotate_interaction(args.input_file, args.output_file, False)
elif args.command == 'update-bitmap':
    with open(args.output_file, 'w') as _b:
        pickle.dump(blocks.prior, _b, -1)
    _r = {
        'timestamp': int(time.time()),
        'total_transitions': len(blocks.all),
        'previous_transitions': len(blocks.triggered),
        'missing_transitions': len(blocks.missing),
        'goal_transitions': len(blocks.missing)/10,
        'coverage': blocks.coverage
    }
    json.dump(_r, open(args.result_file, 'w'))
elif args.command == 'htmlize':
    _fof = open(args.output_file, 'w')
    def _sanitize(s):
        return s.replace(' ', '&nbsp;').replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br>')
    def _rc(s):
        _fof.write('<span class="program_recevied">%s</span>' % _sanitize(s))
    def _tc(s):
        _fof.write('<span class="program_transmitted">%s</span>' % _sanitize(s))
    _tf = args.trace_file or tempfile.mktemp(dir='/dev/shm')
    _ofn = tempfile.mktemp(dir='/dev/shm')
    execute_binary(args.input_file, _ofn, _tf, trace_blocks=False)
    time.sleep(1)
    replay_session(args.input_file, _ofn, _tf, _rc, _tc)
    os.unlink(_tf)
    os.unlink(_ofn)
elif args.command == 'vuln-output':
    vuln_out = ""
    did_input = False
    def _rc(s): #pylint:disable=unused-argument
        global did_input
        did_input = True
    def _tc(s):
        global vuln_out, did_input
        if not s:
            return
        if did_input:
            vuln_out = s
        else:
            vuln_out += s
        did_input = False
    _tf = args.trace_file or tempfile.mktemp(dir='/dev/shm')
    _ofn = tempfile.mktemp(dir='/dev/shm')
    execute_binary(args.input_file, _ofn, _tf, trace_blocks=False)
    replay_session(args.input_file, _ofn, _tf, _rc, _tc)
    with open(args.output_file, 'w') as _fof:
        _fof.write(vuln_out)
    os.unlink(_ofn)
    os.unlink(_tf)
