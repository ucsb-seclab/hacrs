#!/bin/bash

mkdir -p ~/.ssh
ssh-keyscan 172.17.0.1 2>/dev/null >> ~/.ssh/known_hosts

TASK_DIR=results/$PROGRAMNAME/$TASKID/
PRIOR_SEEDS=$TASK_DIR/seeds
CURRENT_SEED=$TASK_DIR/seeds/HUMAN-$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM.seed
BINARY=bins/$PROGRAMNAME
BITMAP=$TASK_DIR/bitmap

#if [ $TASKTYPE == "SEED" ]
#then
ssh -t mturk@172.17.0.1 -i /home/seclab/mnt/turk continuous-seed $BINARY $BITMAP -B -p $PRIOR_SEEDS -o $CURRENT_SEED -r $TASK_DIR/result.json 2>/dev/null
#elif [ $TASKTYPE == "SEEK" ]
#then
#    ssh -t mturk@172.17.0.1 -i /home/seclab/mnt/turk continuous-seek $BINARY $BITMAP -o $CURRENT_SEED -r $TASK_DIR/result.json 2>/dev/null
#fi

echo ""
echo ""
echo "###"
echo "### The application has terminated. To restart the application (and continue"
echo "### the HIT), please click the \"Reset VM\" button on the left. If you have"
echo "### triggered enough functions, and do not wish to try for further bonuses,"
echo "### please click the \"Submit\" button."
echo "###"

sleep 1000000000
