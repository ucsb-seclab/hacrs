delimiters = {
  "CADET_00001": "\n",
  "CADET_00003": "\n",
  "CROMU_00001": "\n",
  "CROMU_00002": "\n",
  "CROMU_00003": "\n",
  "CROMU_00005": "\n",  # chess game, short receive, newlines, see service.c:parseUserInput
  "CROMU_00008": "\n",
  "CROMU_00009": "\n",
  "CROMU_00010": "\n",
  "CROMU_00011": "\n",
  "CROMU_00014": "\n",
  "CROMU_00015": "\n",
  "CROMU_00017": "\n",  # looks like a short receive as well, new lines in math_lib.c:get_user_answer
  "CROMU_00019": "\n",
  "CROMU_00021": "\n",
  "CROMU_00022": "\n",
  "CROMU_00023": "\n",
  "CROMU_00025": "\n",
  "CROMU_00029": "\n",
  "CROMU_00030": "\n",  # new lines, see service.c:85
  "CROMU_00031": "\n",
  # "CROMU_00032": "",  # video streaming thing, hardcoded and received size, no line terminators
  "CROMU_00034": "\n",  # new lines, see service.c:837
  "CROMU_00035": "\n",
  "CROMU_00037": "\n",
  "CROMU_00040": "\n",
  "CROMU_00041": "\n",
  "CROMU_00042": "\n",
  # "CROMU_00047": "",  # no lines, custom packet structure
  "CROMU_00048": "\n",
  "CROMU_00051": "\n\r", # technically only \r is also possible (see io.c:250,256), but this is from the pollers/povs
  "CROMU_00054": "\n",
  # "CROMU_00057": "",   # no lines anywhere, custom message format
  "CROMU_00065": "\n",
  "CROMU_00071": "\n",  # new lines, see lib/stdlib.c:getline
  "CROMU_00076": "\n",  # new lines, see service.c:116
  # "CROMU_00078": "",  # binary interaction format
  #"CROMU_00082": "",   # binary interaction format
  "CROMU_00083": "\n",
  "CROMU_00087": "\n",
  "CROMU_00096": "\n",  # new line, see shell.h:29
  "CROMU_00098": "\n",
  "EAGLE_00005": "\n",
  "KPRCA_00007": "\n",
  "KPRCA_00010": "\n",
  "KPRCA_00011": "\n",
  "KPRCA_00013": "\n",
  "KPRCA_00017": "\n",
  "KPRCA_00018": "\n",
  "KPRCA_00021": "\n",
  "KPRCA_00022": "\n",
  "KPRCA_00023": "\n",
  "KPRCA_00028": "\n",
  "KPRCA_00030": "\n",  # newlines, see main.c:readline
  "KPRCA_00031": "\n",  # newlines, see common.c:readline
  "KPRCA_00036": "\n",
  "KPRCA_00041": "\n",
  "KPRCA_00042": "\n",
  "KPRCA_00043": "\n",
  "KPRCA_00045": "\n",
  "KPRCA_00049": "\n",
  "KPRCA_00051": "\n",
  "KPRCA_00052": "\n",
  "KPRCA_00053": "\n",
  "KPRCA_00054": "\n",
  "KPRCA_00055": "\n",
  "KPRCA_00056": "\n",  # newlines, see service.c:291
  "KPRCA_00064": "\n",
  "KPRCA_00068": "\n",  # newlines, see interface.cc:menuMain
  "KPRCA_00071": "\n",  # newlines, see main.c:152
  "KPRCA_00079": "\n",
  # "KPRCA_00100": "",  # binary interaction format
  "LUNGE_00002": "\n",
  "NRFIN_00001": "\x07",  # see libc.c:recvline
  "NRFIN_00004": "\n",
  "NRFIN_00005": "\x07",  # see libc.c:recvline
  "NRFIN_00008": "\n",
  "NRFIN_00009": "\x07",  # see libc.c:recvline
  # "NRFIN_00013": "",    # binary interaction format
  # "NRFIN_00017": "",    # binary interaction format
  "NRFIN_00054": "\n",
  "NRFIN_00055": "\n",
  "NRFIN_00064": "\n",    # newlines, see dungeon.c:getName
  "NRFIN_00065": "\n",
  "NRFIN_00069": "#",     # hash/pound/what ever the fuck this is called, see service.c:getMoveInBoat
  # "NRFIN_00071": "",    # binary interaction format somewhat for the command opcodes
  "TNETS_00002": "\n",
  "YAN01_00001": "\n",
  "YAN01_00002": "\n",
  "YAN01_00007": "\n",
  "YAN01_00011": "\n",
  "YAN01_00015": "\n"
}

# above was generated using scripts/extract_delimiters.py and manually filling in the missing ones

import sys
#import readchar

try:
    while True:
        #c = readchar.readchar()
        c = sys.stdin.read(1)
        if not len(c):
            break
        if c in '\n\r' and sys.argv[1] in delimiters:
            sys.stdout.write(delimiters[sys.argv[1]])
        else:
            sys.stdout.write(c)
        sys.stdout.flush()
except: #pylint:disable=bare-except
    sys.stderr.write("\n")
    sys.stderr.write("###\n")
    sys.stderr.write("### INTERACTION TERMINATED\n")
    sys.stderr.write("###\n")
    sys.stderr.write("\n")
    pass #pylint:disable=unnecessary-pass
