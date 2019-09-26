#/bin/bash
BIN=$1
SEED=$2
ipython --pdb ./symbolic_tracer.py results/bins/$BIN results/$BIN/$SEED results/$BIN/strings.json
