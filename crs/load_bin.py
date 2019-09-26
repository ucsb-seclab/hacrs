import os
import sys
import farnsworth.models

# make the round
round = farnsworth.models.Round.get_or_create_latest(0)[0]
round.ready()

# make the teams
for i in range(7): farnsworth.models.Team.create_or_get(name=str(i))
our_team = farnsworth.models.Team.get_our()

def upload_bin(filename):
	cs = farnsworth.models.ChallengeSet.create(name=os.path.basename(filename))
	cs.seen_in_round(round)
	cbn = farnsworth.models.ChallengeBinaryNode.create(
		name=os.path.basename(filename),
		blob=open(filename).read(), 
		cs=cs
	)
	csf = farnsworth.models.ChallengeSetFielding.create(
		cs=cs,
		team=our_team,
		available_round=round,
		cbns=[cbn],
	)

if __name__ == "__main__":
	upload_bin(sys.argv[1])
