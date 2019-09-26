#!/bin/bash

docker build -t "zardus/research:cyborg" --build-arg CACHEBUST=`date +%s` . 
#docker push zardus/research:cyborg
