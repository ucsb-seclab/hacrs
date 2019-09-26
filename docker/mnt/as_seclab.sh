#!/bin/bash
export USER=seclab
export DISPLAY=:1

# Configure VNC password
umask 0077                                       
mkdir -p "$HOME/.vnc"                            
chmod go-rwx "$HOME/.vnc"                        


if [ $# != 5 ] ; then
    echo "Provide password, ID, program name and run type as argument"
    exit 1;
fi

export TASKID=${2}
export PROGRAMNAME=${3}
export TASKTYPE=${4}
export RUNTYPE=${5}

vncpasswd -f <<<"${1}" >"$HOME/.vnc/passwd" 

vncserver -geometry '800x600'

PRIVKEYNAME="privkey.pem"
FULLCHAIN="fullchain.pem"

if [ $RUNTYPE = "test" ]; then
    PRIVKEYNAME="privkey-test.pem"
    FULLCHAIN="fullchain-test.pem"
fi

websockify --ssl-only --key="/home/seclab/mnt/certs/${PRIVKEYNAME}" --cert="/home/seclab/mnt/certs/${FULLCHAIN}" --web /home/seclab/mnt/www 4321 localhost:5901 &

cd ~/mnt

# this is just to show *something*
#gnome-help &> /dev/null # &
xterm -cr white -fg white -bg black -geometry 125x40+0+0 /home/seclab/mnt/do_seed.sh &> /dev/null # &
#echo "REMOVE THIS FOR PRODUCTION, DON'T bg terminal"
#/bin/bash

