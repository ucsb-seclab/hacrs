import json
import os
import sys
import re
import subprocess
import tempfile

import shellphish_qemu


def execute_binary(binary_path, iname, oname, tname, blocks=True, syscalls=True):
    infile = open(iname)
    outfile = open(oname, 'w')
    tracefile = open(tname, 'w') if tname != oname else outfile

    cmd_args = [shellphish_qemu.qemu_path('cgc-tracer')]
    if blocks:
        cmd_args += ['-d', 'exec']
    if syscalls:
        cmd_args += ['-strace']
    cmd_args += [binary_path]

    print cmd_args
    process = subprocess.Popen(cmd_args, stdin=infile, stdout=outfile, stderr=tracefile)
    process.wait()
    return process.pid


def trace_addrs_from_lines(trace_lines):
    for line in trace_lines:
        result = re.match(r'Trace 0x[0-9a-fA-F]* \[([0-9a-fA-F]*)\]', line)
        if not result:
            continue

        addr = int(result.group(1), base=16)
        yield addr


def get_seek_results(binary_path, bitmap_path, seed_path, target_address, target_string):
    print "Getting seek results for seed {}".format(os.path.basename(seed_path))

    output_fd, output_path = tempfile.mkstemp()
    trace_fd, trace_path = tempfile.mkstemp()

    execute_binary(binary_path, seed_path, output_path, trace_path)

    command = [sys.executable, '/home/angr/angr-dev/cyborg/hal/hal.py', 'seek',
               '-a', hex(target_address)[2:],
               '-t', trace_path, binary_path, bitmap_path]

    print command
    p = subprocess.Popen(command, stdin=subprocess.PIPE, stderr=subprocess.PIPE)

    with open(seed_path, 'r') as f:
        _, error_stream = p.communicate(f.read())
        if p.returncode != 0:
            print "{} failed! stderr: {}".format(' '.join(command), error_stream)
            closeness = 313371337
        else:
            result = json.loads(error_stream)
            closeness = result['new_distance']

    with open(output_path, 'r') as f:
        stdout = f.read()

    os.close(output_fd)
    os.close(trace_fd)

    return {'closeness': closeness, 'triggered': target_string in stdout}


