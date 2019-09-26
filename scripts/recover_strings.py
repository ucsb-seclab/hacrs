import os
import sys
import angr
import json

BIN = os.path.join(os.path.dirname(__file__), "../hal/bins", sys.argv[1])
RES = os.path.join(os.path.dirname(__file__), "../results", sys.argv[1], "strings.json")

project = angr.Project(BIN)
cfg = project.analyses.CFG(normalize=True, collect_data_references=True, show_progressbar=True)
#all_variable_recoveries = {
#   f: project.analyses.VariableRecoveryFast(f)
#   for f in cfg.kb.functions.values() if not f.is_simprocedure
#}
#
#categorization = project.analyses.FunctionCategorizationAnalysis()
#tag_manager = categorization.function_tag_manager
#
#input_functions = tag_manager.input_functions()
#output_functions = tag_manager.output_functions()
#
#io_strings = {
#   f: project.analyses.IOStrings(f, cfg, input_functions, output_functions)
#   for f in cfg.kb.functions.values() if not f.is_simprocedure
#}

all_outs = { }
all_ins = { }
#for f,iostring in io_strings.items():
#   print "Function: %#x" % f.addr
#
#   for s in iostring.output_strings.values():
#       print "... output string: %r" % s.content
#   all_outs.update(iostring.output_strings)
#
#   for s in iostring.input_strings.values():
#       print "... input string: %r" % s.content
#   all_outs.update(iostring.input_strings) # what fish considers input strings are actually outputs for us
#
#   for s in iostring.other_strings.values():
#       print "... other string: %r" % s.content
#   all_ins.update(iostring.other_strings)

for a,md in cfg.memory_data.items():
    if md.sort != 'string':
        continue

    if a in all_outs:
        continue
    if a in all_ins:
        continue
    all_ins[a] = md

result = { }

def to_dict(sr):
    return {
        'bbl_addrs': [ vr[0] for vr in sr.refs ],
        'content': sr.content,
        'address': sr.address
    }

result['outputs'] = [ to_dict(s) for s in all_outs.values() ]
result['inputs'] = [ to_dict(s) for s in all_ins.values() if not s.content.startswith("The DECREE packages used in the creation") ]

json.dump(result, open(RES, "w"))
