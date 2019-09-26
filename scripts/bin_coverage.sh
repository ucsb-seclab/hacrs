#!/bin/bash -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

BIN=$1

# first, consolidate seeds
cd /results/$BIN

OLD_COUNT=$(ls unique_seeds | wc -l)
find . -iname *seed | grep -- "-" | grep "/seeds/" | parallel -v 'SEEDFILE={}; MD5=$(cat $SEEDFILE | md5sum | sed -e "s/ .*//"); cp $SEEDFILE unique_seeds/HUMAN-$MD5.seed'
NEW_COUNT=$(ls unique_seeds | wc -l)

if [ ! -e /results/$BIN/bitmap -o $OLD_COUNT -ne $NEW_COUNT ]
then
	echo "Updating bitmap for $BIN"
	$SCRIPT_DIR/hal.sh update-bitmap /results/bins/$BIN /results/empty_bitmap -o /results/$BIN/bitmap -r /results/$BIN/latest.json -d /results/$BIN/initial_seeds -d /results/$BIN/unique_seeds
else
	echo "No new inputs for $BIN -- not updating bitmap."
fi
