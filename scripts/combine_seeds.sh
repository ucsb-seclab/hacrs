#!/bin/bash

cd $(dirname $0)/../hal/results

for NAME in ?????_?????
do
	echo $NAME
	mkdir -p $NAME/unique_seeds
	chmod 777 $NAME/unique_seeds
	cp -a $NAME/*/seeds/*.seed $NAME/all_seeds
	for i in $(ls -tr $NAME/all_seeds/*.seed)
	do
		BASENAME=${i##*/}
		ID=${BASENAME%%.*}
		UNIQUE_NAME=$NAME/unique_seeds/INPUT-$(cat $i | md5sum | sed -e "s/ .*//")

		for j in $NAME/all_seeds/$ID*
		do
			SUFFIX=${j#*.}
			cp -a $j $UNIQUE_NAME.$SUFFIX
		done
		HTML_FILE=${i/all_seeds/interactions}
		[ -f $HTML_FILE ] && cp -a $HTML_FILE $UNIQUE_NAME.html
	done
	ls $NAME/unique_seeds/*.seed | wc -l
done
