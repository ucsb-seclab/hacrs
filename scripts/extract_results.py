import os
import sys
#import tqdm
import fuzzer

DIR = sys.argv[1].rstrip('/')
BIN = os.path.basename(DIR).split('-')[-1]
print DIR,BIN
f = fuzzer.Fuzzer('/results/bins/%s'%BIN, '', job_dir=DIR)
h = fuzzer.InputHierarchy(fuzzer=f, load_crashes=True)

def good(_i):
    return _i.instance not in ('fuzzer-1', 'fuzzer-2', 'fuzzer-3')

#all_blocks = set()
all_inputs = [ i for i in h.inputs.values() if not i.crash and good(i) ]
all_crashes = [ i for i in h.inputs.values() if i.crash and good(i) ]
min_timestamp = min(i.timestamp for i in all_inputs)
if all_crashes:
    first_crash = min(all_crashes, key=lambda i: i.timestamp)
    time_to_crash = first_crash.timestamp - min_timestamp
    first_crash_techniques = first_crash.contributing_techniques
    if 'grease' in first_crash_techniques :
        # TODO: figure out how long that input took
        time_to_crash += 120
else:
    first_crash = None
    time_to_crash = -1
    first_crash_techniques = set()

#for i in tqdm.tqdm(all_inputs):
#   all_blocks.update(i.block_set)

fuzzer_only = { i for i in all_inputs if list(i.contributing_techniques) == ['fuzzer'] }
human_derived = { i for i in all_inputs if 'grease' in i.contributing_techniques }
driller_derived = { i for i in all_inputs if 'driller' in i.contributing_techniques }
hybrid_derived = human_derived & driller_derived
#tc = h.technique_contributions()

tag = ''.join(DIR.split('/')[-1].split('-')[:-2])

#print "RESULT",tag,BIN,": blocks:",len(all_blocks)
print "RESULT",tag,BIN,": testcases:",len(all_inputs)
print "RESULT",tag,BIN,": crashed:",len(all_crashes)>0
print "RESULT",tag,BIN,": # crashes:",len(all_crashes)
print "RESULT",tag,BIN,": time-to-crash:",time_to_crash
print "RESULT",tag,BIN,": crash techniques:",tuple(first_crash_techniques)
print "RESULT",tag,BIN,": human-assisted crash:",'grease' in first_crash_techniques
print "RESULT",tag,BIN,": driller-assisted crash:",'driller' in first_crash_techniques
print "RESULT",tag,BIN,": fuzzer-assisted crash:",'fuzzer' in first_crash_techniques
print "RESULT",tag,BIN,": fuzzer-only testcases:",len(fuzzer_only)
print "RESULT",tag,BIN,": human-derived testcases:",len(human_derived)
print "RESULT",tag,BIN,": driller-derived testcases:",len(driller_derived)
print "RESULT",tag,BIN,": hybrid-derived testcases:",len(hybrid_derived)
#print "RESULT",tag,BIN,": fuzzer blocks:",tc.get('fuzzer', (0,0))[0]
#print "RESULT",tag,BIN,": driller blocks:",tc.get('driller', (0,0))[0]
#print "RESULT",tag,BIN,": human blocks:",tc.get('grease', (0,0))[0]
#print "RESULT",tag,BIN,": fuzzer crashes:",tc.get('fuzzer', (0,0))[1]
#print "RESULT",tag,BIN,": driller crashes:",tc.get('driller', (0,0))[1]
#print "RESULT",tag,BIN,": human crashes:",tc.get('grease', (0,0))[1]
