#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd /results

for NAME in ?????_?????
do
	for SEED in $(ls $NAME/minified_seeds/*.seed)
	do
		[ -f ${SEED%.seed}.interaction.json ] && echo "SKIPPING: $SEED" >&2 && continue
		echo "$SEED"
	done
done | parallel -v $SCRIPT_DIR/run_trace.sh {}
