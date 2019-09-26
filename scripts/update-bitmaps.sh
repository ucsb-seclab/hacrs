#!/bin/bash

cd $(dirname $0)/../hal/results

ls -d ?????_????? | parallel -j5 -v docker run -i --rm -v /home/mw/cyborg/cyborg/hal/results:/home/angr/results hal update-bitmap bins/{} results/{}/initial.bitmap -o results/{}/latest.bitmap -r results/{}/latest.json -d results/{}/unique_seeds
