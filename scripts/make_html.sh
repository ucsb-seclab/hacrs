#!/bin/bash

SEED=$1
BIN="bins/${SEED///*/}"
INTERACTION_FILE="results/${SEED//.seed/.html}"

docker run -i --shm-size 1073741824 --rm -v /home/mturk/results:/home/angr/results hal htmlize $BIN empty_bitmap -i results/$SEED -o $INTERACTION_FILE
