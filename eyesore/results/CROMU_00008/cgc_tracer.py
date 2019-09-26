# IPython log file

import tracer
data = open('./12130252971812747651385316796.seed').read()
t = tracer.Tracer('/home/lukas/lukas/tools/angr-dev/cyborg-generator/bins/challenges_qualifiers/CROMU_00008/bin/CROMU_00008', data)
tracer.tracer.l.setLevel('DEBUG')
p = t.run()[0]
