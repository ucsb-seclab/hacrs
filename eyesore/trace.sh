#!/bin/bash

cd $(dirname $0)

SEED=$2
BIN=$(echo $SEED | sed -e "s/\/.*//")
/home/angr/.virtualenvs/angr-pypy/bin/python symbolic_tracer.py /results/bins/$BIN /results/$SEED /results/$BIN/strings.json 1200 2> /results/$SEED.process_errors
[ -s /results/$SEED.process_errors ] || rm -f /results/$SEED.process_errors
exit 0
