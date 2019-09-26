#!/usr/bin/env python

# Cyborg Web Control

import ConfigParser
import subprocess
import argparse
import random
import socket
import time
import pdb
import sys
import os

class VNCRunner:

    def get_docker_args(self, localport, password, turkerinfo, programname, tasktype):
        assert programname.find(' ') == -1
        args = [
            'docker', 'run', '-t',
            # This port forwards to VNC proper - and we probably won't need it.
            # '-p', '127.0.0.1:{0}:5901'.format(localport + 5),
            '-p', '0.0.0.0:{0}:4321'.format(localport),
            '-v', '{0}:/home/seclab/mnt:ro'.format(self.config.get('docker', 'mntdir')),
            '-v', '{}:/home/angr/descriptions:ro'.format(self.config.get('general', 'descriptionsfolder')),
            '-w', '/home/seclab/mnt' ]

        if self.cmdargs.no_rm == False:
            args.append('--rm')

        args.extend( [
            '-u', 'root',
            '-i', 'cyborg_ubuntu', '/bin/bash','onload.sh', password, turkerinfo, programname, tasktype, self.config.get('general', 'runtype')] )


        return args

    def get_config(self, conffile = 'config.ini'):
        try:
            self.config = ConfigParser.ConfigParser()
            self.config.readfp(open(conffile))
        except Exception as e:
            sys.stderr.write("Couldn't read config ({}): {}\n".format(conffile, e)) 
            sys.exit(1)

    def port_available(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return sock.connect_ex(('127.0.0.1',port)) != 0

    @staticmethod
    def parseargs( ):
        parser = argparse.ArgumentParser(description='Cyborg')

        parser.add_argument('--interactive', action='store_true', required=False,
                        help='Run docker shell interactively')

        parser.add_argument('--no-rm', action='store_true', required=False,
                        help='Do not remove image after termination')

        args = parser.parse_args()
        return args

    def find_open_port(self):
        port_start = self.config.getint('docker', 'vncportrange_start')
        port_end = self.config.getint('docker', 'vncportrange_end')

        assert( port_start < port_end )

        portrange = range(port_start, port_end)
        random.shuffle(portrange)
        for p in portrange:
            if self.port_available(p):
                return p
        raise Exception('No open port available!')

    def run_instance(self):
        dargs = self.get_docker_args(self.useport, self.password, self.turkerinfo, self.tasklet['program'], self.tasklet['type'])
        pwwrite=open('/tmp/vn.{}.log'.format(self.useport), 'w')
        pwwrite.write(self.password)
        pwwrite.close()

        if self.cmdargs.interactive:
            print 'WebSocket Port: {}'.format(self.useport)
            subprocess.call(dargs)
        else:
            subprocess.Popen(dargs, stderr = subprocess.PIPE, stdout = subprocess.PIPE)

    def __init__(self, tasklet, turkerinfo, password):
        self.get_config('../config.ini')
        self.tasklet = tasklet
        self.turkerinfo = turkerinfo
        self.password = password



        class standardargs:
            no_rm = True
            interactive = False

        self.cmdargs = standardargs
        self.useport = self.find_open_port()

    def do_run(self):
        return self.run_instance()

def main():
    tasklet = {'tid': 1, 'program' :'testing_around', 'type': 'SEED'}
    turkerinfo = "this-is-a-test-{}".format(random.randint(1,100))
    password='swordfish'
    vr = VNCRunner(tasklet, turkerinfo, password)
    vr.cmdargs = VNCRunner.parseargs( )
    vr.do_run()

if __name__ == "__main__":
    main ()

