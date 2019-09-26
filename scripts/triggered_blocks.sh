#!/bin/bash -e

ls -d ?????_????? | parallel '
for i in {}/all_seeds/*
do
	cat $i | {
		timeout 10 shellphish-qemu-cgc-tracer -d exec -D /dev/stderr
		../hal/bins/{} 2>&1 >/dev/null
	}
done | grep Trace | sed -e "s/.*\[//" -e "s/\].*//" | sort -u > {}.triggered; echo {}
'
