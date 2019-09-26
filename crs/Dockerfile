# -*- mode: conf -*-
FROM shellphish/mechaphish
MAINTAINER Nobody

#some other setup
RUN sudo apt-get install -y parallel

# set up ssh stuff
COPY resources/angr_deploy_key /home/angr/.ssh/id_rsa
RUN sudo chown -R angr.angr /home/angr/.ssh
RUN chmod 600 /home/angr/.ssh/id_rsa
RUN ssh-keyscan github.com git.seclab.cs.ucsb.edu >> ~/.ssh/known_hosts
RUN ssh-keyscan 192.168.51.63 >> ~/.ssh/known_hosts
RUN ssh-keyscan 192.168.51.63 | sed -e "s/192.168.51.63/192.168.222.20/g" >> ~/.ssh/known_hosts

# first clone, then install (for quicker builds from cache)
RUN git clone git@git.seclab.cs.ucsb.edu:yans/cyborg angr-dev/cyborg
#RUN ~/.virtualenvs/angr/bin/pip install -e angr-dev/cyborg

RUN ~/.virtualenvs/angr-pypy/bin/pip install psutil tqdm
RUN ~/.virtualenvs/angr/bin/pip install psutil tqdm

ARG CACHE=5
RUN git -C angr-dev/cyborg pull
# RUN git -C angr-dev/fuzzer remote set-url origin git@git.seclab.cs.ucsb.edu:cgc/fuzzer
RUN git -C angr-dev/fuzzer pull
# RUN git -C angr-dev/fuzzer checkout fuzzer_driller_hackers

WORKDIR /home/angr
ENTRYPOINT [ "bash", "-i" ]
