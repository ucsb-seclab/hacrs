import glob
import json
import os
import re
import sys


def extract_seeker_results(binary_path, vuln_output_path, results_path):
    with open(vuln_output_path, 'rb') as output_f:
        target = output_f.read()
        with open(binary_path, 'rb') as bin_file:
            data = bin_file.read()
            target_string_in_binary = target in data

    if os.path.isfile(results_path):
        with open(results_path, 'r') as f:
            result = json.load(f)
            closeness, triggered = result['closeness'], result['triggered']
    else:
        closeness, triggered = "N/A", "N/A"

    return closeness, triggered, target_string_in_binary
