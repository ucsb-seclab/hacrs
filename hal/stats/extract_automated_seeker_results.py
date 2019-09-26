import glob
import json
import os

from general_seeker_results import extract_seeker_results


for vuln_output_path in sorted(glob.iglob('/results/vuln-output/?????_?????_pov_?.vuln-output'), key=lambda path: os.path.basename(path)):
    filename = os.path.basename(vuln_output_path)
    split = filename[:-len('.vuln-output')].split('_')
    binary_id = '{}_{}'.format(split[0], split[1])
    pov_name = '{}_{}'.format(split[2], split[3])

    binary_path = '/results/bins/{}'.format(binary_id)
    results_path = '/results/{}/automated_seekers/{}.json'.format(binary_id, pov_name)
    closeness, triggered, string_in_bin = extract_seeker_results(binary_path, vuln_output_path, results_path)
    print '_'.join([binary_id, pov_name]), closeness, triggered, string_in_bin
