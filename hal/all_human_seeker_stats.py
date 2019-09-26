import os
import sys
import subprocess
from multiprocessing import Process, Pool

mtutil_path = os.path.abspath(os.path.join(__file__, '../../mtutil'))
sys.path.append(mtutil_path)

from HaCRSDB import HaCRSDB

def run(arg_tuple):
    task_id, program_id, output_file, = arg_tuple
    args = [sys.executable, 'stats/human_stats.py', '--preserve-existing', task_id, program_id, output_file]
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    if p.returncode != 0:
        print "{} failed, stdout: {}, stderr: {}".format(args, stdout, stderr)
    print "{} succeeded, stdout: {}, stderr: {}".format(args, stdout, stderr)
    return arg_tuple

# to make sure that we don't have them all assigned to one core
os.system('taskset -p 0xffffffff %d' % os.getpid())

db = HaCRSDB()
seek_tasklets = db.get_seek_tasklets()

pool = Pool(processes=4)
results = []
for tasklet in seek_tasklets:
    args = (str(tasklet['id']), tasklet['program'], tasklet['outputfile'])

    def finished_task_callback(value):
        print "{} has completed!".format(value)

    async_result = pool.apply_async(run, (args,), callback=finished_task_callback)
    results.append((args, async_result))

for args, result in results:
    print "Waiting for {} to finish!".format(args)
    result.get()

pool.close()
pool.join()


