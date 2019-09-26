#!/bin/bash

FILE=$1
NAME=$(echo drill-coverage-$(basename $FILE) | sed -e "s/[^A-Za-z0-9\-]//g" | tr '[:upper:]' '[:lower:]')

cat <<END >/tmp/pod-$NAME
apiVersion: v1
kind: Pod
metadata:
  name: $NAME
spec:
  containers:
    - name: $NAME
      command: [ "/home/angr/.virtualenvs/angr/bin/python", "/home/angr/angr-dev/fuzzer/fuzzer/extensions/analyze_tar.py", "$FILE" ]
      image: zardus/research:cyborg
      imagePullPolicy: Always
      stdin: true
      tty: true
      volumeMounts:
        - name: cyborg-results
          mountPath: "/results"
      resources:
        limits:
          cpu: 8000m
          memory: 10Gi
        requests:
          cpu: 8000m
          memory: 10Gi
  restartPolicy: Never
  imagePullSecrets:
    - name: ucsbseclab-dockerhub
  volumes:
  - name: cyborg-results
    persistentVolumeClaim:
      claimName: cyborg-results
END

kubectl create -f /tmp/pod-$NAME
