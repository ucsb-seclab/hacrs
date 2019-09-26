#!/bin/bash

~/.virtualenvs/angr-dev/lib/python2.7/site-packages/shellphish_qemu/bin/shellphish-qemu-cgc-tracer -d exec -D $2.log ~/lukas/tools/angr-dev/cyborg-generator/bins/challenges_qualifiers/$1/bin/$1 < ./$2.seed > ./$2.output
