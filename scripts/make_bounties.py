import glob
import json
import os
import traceback


def str_to_bounty(s, cost, seen):
    return {
                'string': s['content'],
                'cost': cost,
                'seen': seen
            }

for d in glob.iglob('/results/?????_?????'):
    print d
    bounties = []
    try:
        strings_path = os.path.join(d, 'strings.json')
        if not os.path.isfile(strings_path):
            print "{} was not found!".format(strings_path)
            continue

        with open(strings_path, 'rb') as f:
            all_strings = json.load(f)

        #print all_strings.keys()

        for s in all_strings['outputs']:
            bounties.append(str_to_bounty(s, 0.2, False))

        for s in all_strings['inputs']:
            bounties.append(str_to_bounty(s, 0.1, False))

        with open(os.path.join(d, 'string_bounties.json'), 'w') as f:
            json.dump(bounties, f)

    except Exception as e:
        print "Error while handling {}".format(d)
        traceback.print_exc()
