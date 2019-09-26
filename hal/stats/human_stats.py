import argparse
import json
import os
import re

import sys
from glob import iglob

from seeker_stats import trace_addrs_from_lines, get_seek_results


parser = argparse.ArgumentParser(description="HaCRS human seeker stats generation script")
parser.add_argument('--preserve-existing', action='store_true', help="whether to recreate existing results or preserve them")
parser.add_argument('tasklet_id', help="the tasklet identifier")
parser.add_argument("program_id", help="the binary identifier ")
parser.add_argument("vuln_output_file", help="the path to the file with the seek target string")
args = parser.parse_args()

if __name__ == '__main__':
    binary_id = args.program_id
    tasklet_id = args.tasklet_id
    output_file = args.vuln_output_file
    print "Handling tasklet {} for binary {}".format(tasklet_id, binary_id)

    pov = re.search('(pov_[0-9a-fA-F]*)\.vuln-output', output_file).group(1)

    binary_path = os.path.join('/', 'results', 'bins', binary_id)
    bitmap_path = os.path.join('/', 'results', binary_id, 'initial.bitmap')
    binary_results_dir = os.path.join('/', 'results', binary_id)
    results_output_path = os.path.join(binary_results_dir, '{}-seek.json'.format(tasklet_id))

    if args.preserve_existing and os.path.isfile(results_output_path):
        print "Skipping tasklet {} for binary {} as it already exists!".format(tasklet_id, binary_id)
        sys.exit(0)

    if not os.path.isdir('/results/{}'.format(binary_id)):
        print "Skipping tasklet {} for binary {} as /results/{} was not found.".format(tasklet_id, binary_id, binary_id)
        with open(results_output_path, 'w') as f:
            f.write('INVALID')
        sys.exit(0)

    with open('/results/vuln-output/' + output_file, 'r') as f:
        target_string = f.read()

    crash_info_paths = list(iglob('/home/angr/cyborg-generator/bins/challenges_*/{}/pov/{}.crash_info'.format(binary_id, pov)))
    if len(crash_info_paths) != 1:
        print "Binary '{}', pov '{}' had unreasonable amounts of crash_info files: {}".format(binary_id, pov, crash_info_paths)
        sys.exit(0)

    with open(crash_info_paths[0], 'r') as f:
        addr_line = json.load(f)['crash_trace']
        target_addr = list(trace_addrs_from_lines([addr_line]))[0]

    closest = 313371338
    triggered = False
    had_results = False
    for seed_path in iglob('/results/{}/{}*/seeds/*.seed'.format(binary_id, tasklet_id)):
        result = get_seek_results(binary_path, bitmap_path, seed_path, target_addr, target_string)
        closest = min(closest, result['closeness'])
        triggered = triggered or result['triggered']
        had_results = True

    if not had_results:
        print "Skipping tasklet {} for binary {}, it has no results!".format(tasklet_id, binary_id)
        sys.exit(0)

    with open(results_output_path, 'w') as f:
        data = {'triggered': triggered, 'closeness': closest}
        print "Dumping {} to {}".format(data, f.name)
        json.dump(data, f)

    print "DONE calculating human seeker results."