#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd /results

for NAME in ?????_?????
do
	for SEED in $(ls $NAME/minified_seeds/*.seed)
	do
		INTERACTION_HTML=${SEED//.seed/.html}

		# If the interaction html already exists, don't redo it
		[ -f $INTERACTION_HTML ] && continue

		# If the parsing hasn't gotten to dump the compartment information it's not done! Don't do it!
		[ ! -f ${SEED//.seed/.compartment_information.json} ] && continue

		echo "$SEED"
	done
done | parallel -v $SCRIPT_DIR/make_html.sh {}
