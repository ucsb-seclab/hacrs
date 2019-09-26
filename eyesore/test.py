import angr
import simuvex
from decision_graph.compacting.constraint_normalizer import normalize_constraint


proj = angr.Project('../../cyborg-generator/bins/challenges_qualifiers/KPRCA_00052/bin/KPRCA_00052', load_options={"auto_load_libs": False})

add_options = {simuvex.o.CGC_NO_SYMBOLIC_RECEIVE_LENGTH}
add_options |= simuvex.o.unicorn
add_options.add(simuvex.o.CONSTRAINT_TRACKING_IN_SOLVER)
add_options.add(simuvex.o.TRACK_ACTION_HISTORY)
add_options.add(simuvex.o.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY)
add_options.add(simuvex.o.CGC_NO_SYMBOLIC_RECEIVE_LENGTH)
add_options.add(simuvex.o.UNICORN_THRESHOLD_CONCRETIZATION)
s = proj.factory.full_init_state(add_options=add_options)

pg = proj.factory.path_group(s)
i = 0
while len(pg.active) < 25:
    print i, len(pg.active), len(pg.one_active.addr_trace.hardcopy)
    pg.step()
    i += 1

path = pg.one_active
constraints = path.state.se.constraints

normalized_constraints = [normalize_constraint(c) for p in pg.active for c in p.state.log.fresh_constraints]

print normalized_constraint()
