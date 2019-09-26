import os
import sys
import glob
import shutil
import hashlib
#import tarfile
import subprocess
import shellphish_afl

if __name__ == "__main__":
    # minimizing code
    p = os.path.join("/tmp/", "afl_seeds")
    try:
        os.mkdir(p)
    except OSError:
        pass

    afl_path_var = shellphish_afl.afl_path_var('cgc')
    afl_path = shellphish_afl.afl_bin('cgc')
    BIN = sys.argv[1]
    IN_DIR = sys.argv[2]
    OUT_DIR = sys.argv[3]
    os.environ['AFL_PATH'] = afl_path_var

    # set afl-showmap (super hacky)
    shutil.copy2(os.path.join(afl_path_var, "../../afl-showmap"), afl_path_var)

    # run afl-cmin
    print "### cmin time (binary %s)" % BIN

    args = [os.path.join(os.path.dirname(__file__), "../afl-cmin")]

    print "collecting seeds"
    if os.path.exists("/home/angr/cmin-input"):
        shutil.rmtree("/home/angr/cmin-input")
    if os.path.exists("/home/angr/cmin-output"):
        shutil.rmtree("/home/angr/cmin-output")
    os.makedirs("/home/angr/cmin-input")
    for i in glob.glob(IN_DIR + ("/*.seed" if 'queue' not in IN_DIR else "/*")):
        print "... seed: " + i
        shutil.copy2(i, "/home/angr/cmin-input")

    args += ["-Q"]
    args += ["-i", "/home/angr/cmin-input"]
    args += ["-o", "/home/angr/cmin-output"]
    args += ["-m", "8000"]

    args += ["--"]
    args += [BIN]
    subprocess.call(args)

    queue_files = [os.path.join("/home/angr/cmin-output", x) for x in os.listdir("/home/angr/cmin-output")]

    print "### tmin time"
    if not os.path.exists(OUT_DIR):
        os.makedirs(OUT_DIR)

    all_minified = set()
    for i in queue_files:
        # MINIMIZE
        input_type = i.split('/')[-1].split('-')[0]
        if True or input_type in ("INPUT", "HUMAN"):
            print "NOT MINIMIZING HUMAN INPUT %s" % i
            with open(i, 'r') as sf:
                seed = sf.read()
        else:
            print "MINIMIZING: %s" % i
            args = [afl_path.replace("afl-fuzz", "afl-tmin")]

            args += ["-Q"]
            args += ["-i", i]
            args += ["-o", "/dev/shm/tmp_seed"]
            args += ["-m", "6G"]

            args += ["--"]
            args += [sys.argv[1]]
            subprocess.call(args)

            if not os.path.exists("/dev/shm/tmp_seed"):
                continue
            with open("/dev/shm/tmp_seed", 'r') as sf:
                seed = sf.read()

        md5 = hashlib.md5(seed).hexdigest()
        out_name = input_type+"-"+md5+".seed"
        out_path = os.path.join(OUT_DIR, out_name)
        print "WRITING OUT: %s to %s (md5 %s)" % (i,out_path,md5)
        with open(out_path, 'w') as sf:
            sf.write(seed)
        all_minified.add(out_name.split('.')[0])

        # shutil.copy2(i, os.path.join(p, "AUTO-" + os.path.basename(i) + ".seed"))

    print "### moving mongofied dudes"
    mongofied_dir = OUT_DIR.replace('minified', 'mongofied')
    for i in os.listdir(OUT_DIR):
        if not any(i.startswith(j) for j in all_minified):
            print "... moving:",i
            shutil.move(os.path.join(OUT_DIR, i), os.path.join(mongofied_dir, i))

    #tar_name = "/tmp/afl_seeds-" + socket.gethostname() + ".tar.gz"
    #tar = tarfile.open(tar_name, "w:gz")
    #tar.add(p)
    #tar.close()
    #print "copying out seeds"
    #shutil.copy2(tar_name, os.path.join("/results/" + os.path.basename(d.binary_path) + "/"))
    #print "done!"
