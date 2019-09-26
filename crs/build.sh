#!/bin/bash -e

docker pull angr/angr
docker pull shellphish/mechaphish
docker build --build-arg CACHE=$(date +%s) -t zardus/research:cyborg .
docker push zardus/research:cyborg

#docker build -t zardus/research:ssh -f ssh.dockerfile .
#docker push zardus/research:ssh
