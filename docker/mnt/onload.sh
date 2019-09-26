#!/bin/bash

if [ $# != 5 ] ; then
    echo "Provide password, ID and program name and run type as argument"
    exit 1;
fi

su - seclab -c "~seclab/mnt/as_seclab.sh ${1} ${2} ${3} ${4} ${5}"

