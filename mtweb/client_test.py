#!/usr/bin/env python

from pprint import pprint
import binascii
import tarfile
import requests
import glob
import json
import sys
sys.path.append('../mtutil')
from HaCRSTurker import HaCRSTurker
import pdb
import re
import os

def create_programs():
    url = 'http://localhost:8989/create_standard_programs'
    r = requests.post(url)
    print r.text

def create_seed_tasklet(program = 'CROMU_00008', transitions=2112, previous_transitions=0):
    url = 'http://localhost:8989/create_tasklet/seed'
    seed_data = {'programname': program,
                'total_transitions': transitions,
                'previous_transitions': previous_transitions
                }

    r = requests.post(url, json=seed_data)
    print r.text

def get_biggest_seed(fname):
    tar = tarfile.open(fname)
    members = tar.getmembers()
    maxmember = None
    for member in members:
        if not member.isfile():
            continue
        if ( maxmember == None ) or member.size > maxmember.size:
            maxmember = member
    return maxmember.name

def initial_seed_tasklets():
    programs = json.load(open('../json/bins.json'))
    for program in programs:
        print program
        info = json.load(open('/home/mw/cyborg/cyborg/hal/results/{}/latest.json'.format(program)))
        create_seed_tasklet(program, info['total_transitions'], info['previous_transitions'])

def redo_seed_tasklets():
    programs = json.load(open('../json/bins.json'))
    for program in programs:
        print program
        info = json.load(open('/home/mw/cyborg/cyborg/hal/results/{}/latest.json'.format(program)))
        create_seed_tasklet(program, info['total_transitions'], info['previous_transitions'])

def get_newest_file(seedfiles):
    maxtime = -1
    rcseed = None
    for seedfile in seedfiles:
        if os.stat(seedfile).st_ctime > maxtime:
            rcseed = seedfile
    return rcseed

if __name__ == '__main__':
    #create_programs()
    #initial_seed_tasklets()
    redo_seed_tasklets()


