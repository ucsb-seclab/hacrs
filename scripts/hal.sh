#!/bin/bash

docker run -i --rm --shm-size 1073741824 -v /results:/results hal "$@"
