#!/bin/bash

BIN=$1
MINIFIER_ID=$(stat /results/$BIN/bitmap | grep Modify | sed -e "s/^.*-..-//" -e "s/\..*//" | tr ' :' '-')
#NAME=$(echo trace-$BIN-$(basename $SEED) | sed -e "s/\.//g" -e "s/\_//g" | tr '[:upper:]' '[:lower:]')
NAME=$(echo minifier-$BIN-$MINIFIER_ID | sed -e "s/[^A-Za-z0-9\-]//g" | tr '[:upper:]' '[:lower:]')

cat <<END >/tmp/pod-$NAME
apiVersion: v1
kind: Pod
metadata:
  name: $NAME
spec:
  containers:
    - name: $NAME
      command: [ "/home/angr/.virtualenvs/angr/bin/python", "/home/angr/angr-dev/cyborg/scripts/testcase-postprocess.py", "/results/bins/$BIN", "/results/$BIN/unique_seeds", "/results/$BIN/minified_seeds" ]
      image: zardus/research:cyborg
      imagePullPolicy: Always
      stdin: true
      tty: true
      volumeMounts:
        - name: cyborg-results
          mountPath: "/results"
      resources:
        limits:
          cpu: 1000m
          memory: 8Gi
        requests:
          cpu: 1000m
          memory: 3Gi
  restartPolicy: Never
  imagePullSecrets:
    - name: ucsbseclab-dockerhub
  volumes:
  - name: cyborg-results
    persistentVolumeClaim:
      claimName: cyborg-results
END

kubectl create -f /tmp/pod-$NAME
