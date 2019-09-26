import os
#import glob
import fuzzer
import cPickle as pickle
#fuzzer.hierarchy.l.setLevel('WARNING')

def analyze_dir(DIR):
    DIR = DIR.rstrip('/')
    pname = DIR + '.results'
    if os.path.exists(pname):
        print "ALREADY EXISTS:",pname
        return

    BIN = os.path.basename(DIR).split('-')[-1]
    f = fuzzer.Fuzzer('/results/bins/%s'%BIN, '', job_dir=DIR)
    h = fuzzer.InputHierarchy(fuzzer=f, load_crashes=True)

    for i in h.inputs.values():
        print i,len(i.block_set),len(i._trace)
    #for o,v in h.technique_contributions():
    #   print o.timestamp,o,v

    print "SAVING TO:",pname
    with open(pname, 'w') as of:
        pickle.dump(h, of, -1)

    return h

#def analyze_dirs(g):
#   for i in glob.glob(g):
#       if not os.path.isdir(i): continue
#       #DIR = 'fuzz4-ha-kprca00068-KPRCA_00068'
#
#       print "###############################################################################"
#       print "###############################################################################"
#       print "### DIR:",i
#       try:
#           analyze_dir(i)
#       except KeyboardInterrupt:
#           print "AAA"
#           raw_input()
#       print "###############################################################################"
#       print ""
#
#analyze_dirs('/results/tarballs/fuzz4-ha-forced*')
#history

if __name__ == '__main__':
    import sys
    analyze_dir(sys.argv[1])
