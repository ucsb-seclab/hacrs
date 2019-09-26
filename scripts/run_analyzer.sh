#!/bin/bash

AFL_DIR=$1
NAME=analyzer-$(basename $AFL_DIR | sed -e "s/\.//g" -e "s/\_//g" | tr '[:upper:]' '[:lower:]')
CMD="[ '/home/angr/.virtualenvs/angr-pypy/bin/python', '/home/angr/angr-dev/cyborg/scripts/analyze_fuzzing.py', '$AFL_DIR' ]"
CPU_REQUEST=1000m
MEMORY_REQUEST=500Mi
CPU_LIMIT=1000m
MEMORY_LIMIT=5Gi

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
          cpu: $CPU_LIMIT
          memory: $MEMORY_LIMIT
        requests:
          cpu: $CPU_REQUEST
          memory: $MEMORY_REQUEST
  restartPolicy: Never
  imagePullSecrets:
    - name: ucsbseclab-dockerhub
  volumes:
  - name: cyborg-results
    persistentVolumeClaim:
      claimName: cyborg-results
END
kubectl create -f /tmp/pods/pod-$NAME
