#!/bin/sh

BIN=$1
INPUT=$2

mkdir -p results/$BIN
scp cgc-4:/results/bins/$BIN ./results/bins/
scp cgc-4:/results/$BIN/strings.json ./results/$BIN
scp cgc-4:/results/$BIN/unique_seeds/$INPUT ./results/$BIN
