from angr/angr

user angr
run bash -i -c "pip install shellphish_qemu"
run bash -i -c "pip install termcolor"
copy color /home/angr
copy html /home/angr
copy training /home/angr/training
copy bins /home/angr/bins
copy default_seeds /home/angr/default_seeds
copy hal.py /home/angr
copy fixup_input.py /home/angr
workdir /home/angr
entrypoint [ "/home/angr/.virtualenvs/angr/bin/python", "/home/angr/hal.py" ]
