#!/bin/bash

docker run --rm --env-file env -it -v $(git rev-parse --show-toplevel):/home/angr/cyborg zardus/research:cyborg "$@"
