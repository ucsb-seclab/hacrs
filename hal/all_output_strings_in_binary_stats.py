import glob
import os

for vuln_output in glob.iglob('/results/vuln-output/?????_?????_pov_?.vuln-output'):
    filename = os.path.basename(vuln_output)
    split = filename[:-len('.vuln-output')].split('_')
    binary_id = '{}_{}'.format(split[0], split[1])
    pov_name = '{}_{}'.format(split[2], split[3])

    with open(vuln_output, 'rb') as output_file:
        target = output_file.read()
        with open('/results/bins/{}'.format(binary_id), 'rb') as bin_file:
            data = bin_file.read()
            print '{}_{}'.format(binary_id, pov_name), target in data