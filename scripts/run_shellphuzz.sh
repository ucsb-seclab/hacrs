#!/bin/bash

BIN=$1
AFL_CORES=${AFL_CORES:-4}
DRILLER_CORES=${DRILLER_CORES:-4}
HUMAN_INPUTS=${HUMAN_INPUTS:-no}
FORCE_INTERVAL=${FORCE_INTERVAL:-0}
TIMEOUT=${TIMEOUT:-28800}

CMD="[ '/home/angr/.virtualenvs/angr/bin/shellphuzz', '/results/bins/$BIN', '--no-dictionary', '-m', '/home/angr/angr-dev/cyborg/scripts/fuzzhelper.py', '-t', '$TIMEOUT', '-c', '$AFL_CORES'"
NAME="round3-fuzz$AFL_CORES"
[ $DRILLER_CORES -ne 0 ] && NAME=$NAME-drill$DRILLER_CORES && CMD="$CMD, '-d', '$DRILLER_CORES'"
[ $HUMAN_INPUTS != "no" ] && NAME=$NAME-ha && CMD="$CMD, '-g', '/results/$BIN/minified_seeds'"
[ $FORCE_INTERVAL -ne 0 ] && NAME=$NAME-forced && CMD="$CMD, '-f', '$FORCE_INTERVAL'"
NAME=$NAME-$(echo $BIN | sed -e "s/\.//g" -e "s/\_//g" | tr '[:upper:]' '[:lower:]')
CMD="$CMD, '-T', '/results/tarballs/{}.tar.gz' ]"

mkdir -p /tmp/pods
cat <<END >/tmp/pods/pod-$NAME
apiVersion: v1
kind: Pod
metadata:
  name: $NAME
spec:
  containers:
    - name: $NAME
      command: $CMD
      image: zardus/research:cyborg
      imagePullPolicy: Always
      stdin: true
      tty: true
      volumeMounts:
        - name: cyborg-results
          mountPath: "/results"
      resources:
        limits:
          cpu: $(($AFL_CORES+$DRILLER_CORES))000m
          memory: $((1+2*$DRILLER_CORES))Gi
        requests:
          cpu: $(($AFL_CORES+$DRILLER_CORES))000m
          memory: $((1+(3*$DRILLER_CORES)/2))Gi
  restartPolicy: Never
  imagePullSecrets:
    - name: ucsbseclab-dockerhub
  volumes:
  - name: cyborg-results
    persistentVolumeClaim:
      claimName: cyborg-results
END
kubectl create -f /tmp/pods/pod-$NAME
