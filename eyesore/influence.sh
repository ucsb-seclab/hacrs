#!/bin/bash

set -e
set -o pipefail

for f in results/$2/*.seed; 
do
    echo "Processing $f"
    python symbolic_tracer.py $1 $2 $f
done
