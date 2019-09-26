#!/usr/bin/env python
from datetime import datetime
import subprocess
import time
import json
import sys
import pdb
import re
import os
sys.path.append('../mtutil')
from HaCRSUtil import HaCRSUtil

def kill_container(killcontainer, action):
    assert re.match('[a-f0-9]{12}', killcontainer) != None
    print "removing: {}".format(killcontainer)
    args = ['docker', action, killcontainer]
    pr = subprocess.Popen(args, stdout=subprocess.PIPE, stderr = subprocess.PIPE)


def cleanup(config):
    images = ['hal', 'cyborg_ubuntu']
    args = ['docker', 'ps', '-a', '--format', """{ "id": "{{.ID}}", "created":"{{.CreatedAt}}", "image": "{{.Image}}" }"""]
    pr = subprocess.Popen(args, stdout=subprocess.PIPE, stderr = subprocess.PIPE)
    stdout, stderr = pr.communicate()

    assert pr.returncode == 0

    for line in stdout.split('\n'):
        if len(line.strip())  == 0:
            continue

        obj = json.loads(line)
        if obj['image'] not in images:
            print 'skipping: {}'.format(obj['image'])
            continue
        crtime = datetime.strptime(obj['created'][:-10], "%Y-%m-%d %H:%M:%S")
        minutes_age = ((datetime.now() - crtime).total_seconds() ) /60
        if minutes_age > config.getint('cleanup', 'killafterminutes'):
            kill_container(obj['id'], 'stop')
        if minutes_age > config.getint('cleanup', 'rmafterminutes'):
            kill_container(obj['id'], 'rm')

if __name__ == "__main__":
    config = HaCRSUtil.get_config('../config.ini')
    while True:
        cleanup(config)
        time.sleep(60)

