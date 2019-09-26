import os
import sys
import time
import random
import shutil
import tracer
import tarfile
import operator
import itertools
import subprocess
import networkx as nx
import shellphish_qemu
from multiprocessing import Pool
from collections import defaultdict


import os


def exec_cmd(args, cwd=None, shell=False, pipe_input=None):
    pipe = subprocess.PIPE
    if pipe_input is None:
        pipe_input = pipe
    p = subprocess.Popen(args, cwd=cwd, shell=shell, stdin=pipe_input, stdout=pipe, stderr=pipe)
    std = p.communicate()
    retcode = p.poll()
    res = (std[0], std[1], retcode)
    return res


def get_trace(some_args):
    input_path, qemu_path, binary_path = some_args
    # fix input path by escaping
    # input_path = input_path.replace(":","\:").replace(",","\,")

    nonce = random.randint(0, 1000000000)
    log_file = "/tmp/log" + str(nonce)
    # print str([qemu_path, "-d", "exec", "-D", log_file, binary_path, "<", input_path]).replace("[","").replace("]","").replace("'","")
    f = open(input_path, "rb")
    res = exec_cmd(["timeout", "-k", "1", "3", qemu_path, "-d", "exec", "-D", log_file, binary_path], pipe_input=f)
    f.close()
    # if res[-1]:
    #    print "error:", res
    with open(log_file, "r") as f:
        data = f.read()
    blocks = []
    for line in data.split("\n"):
        if "Trace" not in line:
            continue
        block = int(line.split("[")[1].split("]")[0], 16)
        blocks.append(block)
    exec_cmd(["rm", log_file])

    # get transitions
    transitions = set()
    for i, b in enumerate(blocks):
        if i > 0:
            transitions.add((b, blocks[i - 1]))
    return set(blocks), transitions


def analyze_single(tar_path):
    if "nrfin00056" in tar_path or "NRFIN_00056" in tar_path:
        return

    print "analyze_single", tar_path
    bin_name = os.path.basename(os.path.dirname(tar_path))
    res_dir = os.path.dirname(tar_path)
    experiment_name = "-".join(os.path.basename(tar_path).split("-")[1:])
    experiment_name = experiment_name.split(".tar.gz")[0]
    print "experiment name", experiment_name
    if os.path.exists(os.path.join(res_dir, "over_time-" + experiment_name)):
        print "already done"
        return

    # get the cfgfast # of block
    # coverage out of cfgfast
    p = os.path.join("/results/bins", bin_name)
    import angr
    b = angr.Project(p)
    cfg = b.analyses.CFG()
    num_nodes = len([n.addr for n in cfg.graph.nodes() if not n.is_syscall and not n.is_simprocedure])

    # unpack tar
    try:
        shutil.rmtree("/home/angr/tmp")
    except:
        pass
    tar = tarfile.open(tar_path, "r:gz")
    tar.extractall(path="/home/angr")
    tar.close()
    # get all inputs to run to analyze coverage
    fuzzer_dir = "/home/angr/tmp/afl_sync/fuzzer-master/queue/"

    min_time = None
    trace_to_time = dict()
    for x in os.listdir(fuzzer_dir):
        # print x, t, type(t)
        if not x.startswith("id"):
            continue
        # if not x.endswith(".seed"):
        #    continue
        x = os.path.join(fuzzer_dir, x)
        t = os.path.getmtime(x)

        if min_time is None or t < min_time:
            min_time = t
        trace_to_time[x] = t

    # do it multiprocessing
    sorted_traces = sorted(trace_to_time.items(), key=operator.itemgetter(1))

    sorted_traces = [x for x in sorted_traces if trace_to_time[x[0]] - min_time < 60 * 60]
    to_run = []
    for x, t in sorted_traces:
        # print seconds
        # input_path, qemu_path, binary_path
        tracer_path = shellphish_qemu.qemu_path('cgc-tracer')
        to_run.append((x, tracer_path, p))

    print "first to run:", to_run[0]
    print "path exits:", [os.path.exists(x) for x in to_run[0]]

    pool = Pool(8)
    traces_iter = pool.imap(get_trace, to_run, chunksize=2)

    blocks_hit = set()
    block_fraction_over_time = list()
    count = 0
    for a, trace in itertools.izip(sorted_traces, traces_iter):
        count += 1
        if count % 10 == 0:
            print "count:", count, "/", len(sorted_traces)
        path, t = a
        blocks, transitions = trace
        blocks_hit.update(blocks)
        block_fraction_over_time.append(((t - min_time), float(len(blocks_hit)) / num_nodes))

    pool.close()

    with open(os.path.join(res_dir, "over_time-" + experiment_name), "wb") as f:
        for a, b in block_fraction_over_time:
            f.write(str(int(a)) + ", " + str(b) + "\n")

    with open(os.path.join(res_dir, "fraction-" + experiment_name), "wb") as f:
        f.write(str(float(len(blocks_hit)) / num_nodes) + "\n")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        analyze_single(sys.argv[1])
        sys.exit(0)
