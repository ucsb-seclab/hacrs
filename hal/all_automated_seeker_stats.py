import glob
import os
import sys
import subprocess
from multiprocessing import Pool


def run(arg_tuple):
    program_id, pov_name = arg_tuple
    args = [sys.executable, 'stats/automation_stats.py', '--preserve-existing', program_id, pov_name]
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    if p.returncode != 0:
        print "{} failed, stdout: {}, stderr: {}".format(args, stdout, stderr)
    print "{} succeeded, stdout: {}, stderr: {}".format(args, stdout, stderr)
    return arg_tuple

# to make sure that we don't have them all assigned to one core
os.system('taskset -p 0xffffffff %d' % os.getpid())

pool = Pool(processes=4)
results = []
for vuln_output in glob.iglob('/results/vuln-output/?????_?????_pov_?.vuln-output'):
    filename = os.path.basename(vuln_output)
    split = filename[:-len('.vuln-output')].split('_')
    binary_id = '{}_{}'.format(split[0], split[1])
    pov_name = '{}_{}'.format(split[2], split[3])

    args = (binary_id, pov_name)

    def finished_task_callback(value):
        print "{} has completed!".format(value)

    print "Scheduling {}".format(args)

    async_result = pool.apply_async(run, (args,), callback=finished_task_callback)
    results.append((args, async_result))

for args, result in results:
    print "Waiting for {} to finish!".format(args)
    result.get()

pool.close()
pool.join()


