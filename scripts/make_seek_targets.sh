#!/bin/bash

TF=/dev/shm/$$.trace
OF=/dev/shm/$$.output

function finish {
	rm -f $TF $OF
}
trap finish EXIT

INPUT=$1
BIN_DIR=~/code/angr/cyborg/hal/bins/
OUT_DIR=~/code/angr/cyborg/descriptions
RES_DIR=~/code/angr/cyborg/results
BIN=$(basename ${INPUT//\/pov*/})
cat $INPUT | shellphish-qemu-cgc-tracer -d exec -D /dev/shm/$$.trace $BIN_DIR/$BIN 2>/dev/null >/dev/shm/$$.output
R=$?

[ $R -ne 139 ] && exit 0

#echo "$INPUT returned $R"
TARGET_ADDR=$(egrep "Trace.*\[08" $TF | tail -n1 | sed -e "s/.*\[//" -e "s/\].*//")
MUST_TRIGGER=$(cat $OF | tr -dc '[[:print:]]\n' | sed -n "s/^$//;t;p;" | tail -n1)

grep $TARGET_ADDR $RES_DIR/$BIN.triggered && exit 0

echo "$INPUT"
echo "0x$TARGET_ADDR" | tee $OUT_DIR/$BIN.seek_target
echo "$MUST_TRIGGER" | tee $OUT_DIR/$BIN.seek_line
