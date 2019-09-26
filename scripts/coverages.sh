#!/bin/bash

BIN=$1
cd /results/$BIN
TASKS=$(ls -tr */result.json | parallel -k dirname)
SOFAR=""
for TASK in $TASKS
do
	echo "bins/$BIN /results/$BIN/initial.bitmap -o /dev/null -r /dev/stderr $SOFAR -p /results/$BIN/$TASK/seeds"
	SOFAR="$SOFAR -d /results/$BIN/$TASK/seeds"
done | parallel -k -- '$(echo docker run -i --rm -v /results:/results hal update-bitmap {}); echo'
