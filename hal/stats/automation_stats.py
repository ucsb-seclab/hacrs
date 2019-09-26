import argparse
import json
import os

import sys
from glob import iglob

from seeker_stats import trace_addrs_from_lines, get_seek_results

parser = argparse.ArgumentParser(description="HaCRS human seeker stats generation script")
parser.add_argument('--preserve-existing', action='store_true', help="whether to recreate existing results or preserve them")
parser.add_argument("program_id", help="the binary identifier ")
parser.add_argument("pov_name", help="the name of the pov, e.g. pov_0")
args = parser.parse_args()

if __name__ == '__main__':
    binary_id = args.program_id
    pov_name = args.pov_name
    print "Calculating automated seeking stats for binary {}, pov: {}".format(binary_id, pov_name)

    binary_path = os.path.join('/', 'results', 'bins', binary_id)
    bitmap_path = os.path.join('/', 'results', binary_id, 'initial.bitmap')
    binary_results_dir = os.path.join('/', 'results', binary_id, 'automated_seekers')
    results_output_path = os.path.join(binary_results_dir, '{}.json'.format(pov_name))

    if args.preserve_existing and os.path.isfile(results_output_path):
        print "Skipping results for pov {} for binary {} because they already exist!".format(pov_name, binary_id)
        sys.exit(0)

    if not os.path.isdir('/results/{}'.format(binary_id)):
        print "Skipping binary {} as /results/{} was not found.".format(binary_id, binary_id)
        with open(results_output_path, 'w') as f:
            f.write('INVALID')
        sys.exit(0)

    with open('/results/vuln-output/{}_{}.vuln-output'.format(binary_id, pov_name), 'r') as f:
        target_string = f.read()

    crash_info_paths = list(iglob('/home/angr/cyborg-generator/bins/challenges_*/{}/pov/{}.crash_info'.format(binary_id, pov_name)))
    if len(crash_info_paths) != 1:
        print "Binary '{}', pov '{}' had unreasonable amounts of crash_info files: {}".format(binary_id, pov_name, crash_info_paths)
        sys.exit(0)

    with open(crash_info_paths[0], 'r') as f:
        addr_line = json.load(f)['crash_trace']
        target_addr = list(trace_addrs_from_lines([addr_line]))[0]

    closest = 313371338
    triggered = False
    had_results = False
    for seed_path in iglob('/results/{}/automated_seekers/seeds_{}_min/*.seed'.format(binary_id, pov_name)):
        result = get_seek_results(binary_path, bitmap_path, seed_path, target_addr, target_string)
        closest = min(closest, result['closeness'])
        triggered = triggered or result['triggered']
        had_results = True

    if not had_results:
        print "Skipping {} for binary {}, it has no results!".format(pov_name, binary_id)
        sys.exit(0)

    with open(results_output_path, 'w') as f:
        data = {'triggered': triggered, 'closeness': closest}
        print "Dumping {} to {}".format(data, f.name)
        json.dump(data, f)

    print "DONE calculating automated seeker results."
