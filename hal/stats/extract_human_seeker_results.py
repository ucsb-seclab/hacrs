import json
import os
import re
import sys

from general_seeker_results import extract_seeker_results

mtutil_path = os.path.abspath(os.path.join(__file__, '../../../mtutil'))
sys.path.append(mtutil_path)

from HaCRSDB import HaCRSDB

db = HaCRSDB()
seek_tasklets = db.get_seek_tasklets()
for tasklet in sorted(seek_tasklets, key=lambda val: val['outputfile']):
    output_file = tasklet['outputfile']
    pov_name = re.search('(pov_[0-9a-fA-F]*)\.vuln-output', output_file).group(1)
    binary_id = tasklet['program']
    tasklet_id = str(tasklet['id'])

    binary_path = '/results/bins/{}'.format(binary_id)
    vuln_output_path = '/results/vuln-output/{}'.format(output_file)
    results_path = '/results/{}/{}-seek.json'.format(binary_id, tasklet_id)

    closeness, triggered, string_in_bin = extract_seeker_results(binary_path, vuln_output_path, results_path)
    print '_'.join([binary_id, pov_name]), closeness, triggered, string_in_bin

