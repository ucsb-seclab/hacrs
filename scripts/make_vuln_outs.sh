#!/bin/bash

BINDIR=$(dirname $0)/../hal/bins
QEMU=$VIRTUAL_ENV/site-packages/shellphish_qemu/bin/shellphish-qemu-cgc-tracer

for SEED in */pov/*input
do
	BIN=${SEED%%/*}
	[ -f $BINDIR/$BIN ] || continue
	OUT=${BIN}_$(basename ${SEED%%.input})
	timeout 10 $QEMU -strace $BINDIR/$BIN < $SEED > /dev/null 2>&1 && continue
	
	echo BIN=$BIN SEED=$SEED OUT=$OUT
done | parallel 'env $(eval echo {}) bash -xc "python ~/code/angr/cyborg/hal/hal.py vuln-output ~/code/angr/cyborg/hal/bins/\$BIN /dev/null -o \$OUT.vuln-output -i \$SEED"'

