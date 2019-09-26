import glob
import os


def run_cmd(cmd):
    print cmd
    os.system(cmd)


def minimize(binary_id):
    afl_path = "/home/angr/.virtualenvs/angr/bin/afl-cgc/tracers/i386/"
    afl_cmin_path = '/home/angr/angr-dev/fuzzer/afl-cmin'
    seeds_to_min_dir = "/results/{}/automated_seeders/seeds".format(binary_id)
    seeds_min_tmp_out_dir = seeds_to_min_dir + '_tmp_min'
    seeds_min_out_dir = seeds_to_min_dir + '_min'
    bin_path = '/results/bins/{}'.format(binary_id)

    if os.path.isdir(seeds_min_out_dir):
        print "Skipping seeders for binary {}, minimized already exists!".format(binary_id)
        return

    cmin_cmd_fmt = 'AFL_PATH={afl_path} {afl_cmin} -Q -i {in_dir} -o {out_dir} -m 8000 -- {bin_path}'
    cmin_cmd = cmin_cmd_fmt.format(afl_path=afl_path, afl_cmin=afl_cmin_path,
                         in_dir=seeds_to_min_dir, out_dir=seeds_min_tmp_out_dir,
                         bin_path=bin_path)

    run_cmd('rm -rf {tmp}'.format(tmp=seeds_min_tmp_out_dir))
    run_cmd('rm -rf {dst}'.format(dst=seeds_min_out_dir))
    run_cmd(cmin_cmd)

    if len(glob.glob('{tmp}/*'.format(tmp=seeds_min_tmp_out_dir))) > 0:
        run_cmd('mkdir {dst}/'.format(dst=seeds_min_out_dir))
        run_cmd('mv {tmp}/* {dst}/'.format(tmp=seeds_min_tmp_out_dir, dst=seeds_min_out_dir))

    run_cmd('rm -rf {tmp}'.format(tmp=seeds_min_tmp_out_dir))

if __name__ == '__main__':
    showmap_path = "/home/angr/.virtualenvs/angr/bin/afl-cgc/afl-showmap"
    tracers_dir = "/home/angr/.virtualenvs/angr/bin/afl-cgc/tracers/i386/"
    run_cmd('cp {} {}'.format(showmap_path, tracers_dir))

    for binary_path in glob.iglob('/results/bins/?????_?????'):
        binary_id = os.path.basename(binary_path)

        print
        print "Minimizing seeders for binary {}".format(binary_id)
        minimize(binary_id)

