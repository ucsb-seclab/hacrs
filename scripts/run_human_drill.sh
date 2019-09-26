#!/bin/bash

BIN=$1
NAME=$(echo drill-new-human-$BIN | sed -e "s/\.//g" -e "s/\_//g" | tr '[:upper:]' '[:lower:]')

cat <<END >/tmp/pod-$NAME
apiVersion: v1
kind: Pod
metadata:
  name: $NAME
spec:
  containers:
    - name: $NAME
      command: [ "/home/angr/.virtualenvs/angr/bin/python", "/home/angr/angr-dev/fuzzer/fuzzer/extensions/driller_manager.py", "/results/bins/$BIN", "hacrs"  ]
      image: zardus/research:cyborg
      imagePullPolicy: Always
      stdin: true
      tty: true
      volumeMounts:
        - name: cyborg-results
          mountPath: "/results"
      resources:
        limits:
          cpu: 4000m
          memory: 8Gi
        requests:
          cpu: 2000m
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
