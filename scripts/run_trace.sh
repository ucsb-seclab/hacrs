#!/bin/bash

BIN=$(echo $1 | sed -e "s/\/.*//")
SEED=$1
#NAME=$(echo trace-$BIN-$(basename $SEED) | sed -e "s/\.//g" -e "s/\_//g" | tr '[:upper:]' '[:lower:]')
NAME=$(echo mintrace-$BIN-$(basename $SEED) | sed -e "s/[^A-Za-z0-9\-]//g" | tr '[:upper:]' '[:lower:]')

cat <<END >/tmp/pod-$NAME
apiVersion: v1
kind: Pod
metadata:
  name: $NAME
spec:
  containers:
    - name: $NAME
      command: [ "timeout", "--preserve-status", "1800", "/home/angr/angr-dev/cyborg/eyesore/trace.sh", "$BIN", "$SEED" ]
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
          memory: 10Gi
        requests:
          cpu: 1000m
          memory: 6Gi
  restartPolicy: Never
  imagePullSecrets:
    - name: ucsbseclab-dockerhub
  volumes:
  - name: cyborg-results
    persistentVolumeClaim:
      claimName: cyborg-results
END

kubectl create -f /tmp/pod-$NAME
