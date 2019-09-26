import json
import glob
import os
from collections import defaultdict, Counter


def parse_similarities_csv(text):
    return [list(map(int, l.split(','))) for l in text.strip().split('\n')]

def extract_delim(seed, similarities):
    if len(similarities) < len(seed): # this seed was not fully processed, skip it
        return None

    dimension = len(seed)

    assert len(seed) == len(similarities) and all(len(similarities[i]) == len(seed) for i in range(len(seed)))

    #for i in range(dimension):
    #    print similarities[i]
    #matches = [(i, seed[i], Counter(similarities[i])) for i in range(dimension)]
    #print matches

    possible_terminators = {}
    for i in range(dimension):
        count = dict(Counter(similarities[i]))
        accumulated = sum(similarities[i])
        if len(count.keys()) == 2: # we want the ones that only match themselves and no other checks
            if seed[i] not in possible_terminators or possible_terminators[seed[i]][0] > accumulated:
                possible_terminators[seed[i]] = (accumulated, count)

            #possible_terminators[seed[i]].append({'sum': sum(similarities[i]), 'count': count})

    #for c, info_set in possible_terminators.iteritems():
    #    for info in info_set:
    #        sorted_count_keys = sorted(info['count'].keys())

    return map(lambda t: t[0], sorted(possible_terminators.iteritems(), key=lambda t: t[1][0]))

delim_options = defaultdict(lambda: {'count': Counter(), 'total_analyzed': 0, 'total': 0, 'subset': None})

binaries = set()
for f in glob.glob('/results/?????_?????/minified_seeds/INPUT-*.seed'):
    binary = f.split('/')[2]
    binaries.add(binary)
    seed_file = f
    input_base = seed_file[:seed_file.rindex('.')]

    similarities_path = input_base + '.character_similarities.csv'

    with open(seed_file, 'r') as seed_f:
        seed = seed_f.read()

    if os.path.isfile(similarities_path):
        with open(similarities_path, 'r') as sim_f:
            similarities_text = sim_f.read()
    else:
        similarities_text = ''

    if len(seed) > 0 and len(similarities_text) > 0:
        similarities = parse_similarities_csv(similarities_text)
        delim = extract_delim(seed, similarities)
        if delim:
            print binary, repr(delim), f
            delims = set(delim)
            delim_options[binary]['count'] += Counter(delims)
            if delim_options[binary]['subset'] is None:
                delim_options[binary]['subset'] = delims
            else:
                delim_options[binary]['subset'].intersection_update(delims)

        delim_options[binary]['total_analyzed'] += 1

    delim_options[binary]['total'] += 1


for b in binaries:
    if b not in delim_options:
        delim_options[b] = Counter()


print '$' * 40


#with open('./delimiter_info.json', 'w') as f:
#    to_dump = {}
#    for k, v in delim_options.iteritems():
#        to_dump[k] = dict(total=v['total'], total_analyzed= v['total_analyzed'], count=dict(v['count']), common_subset=list(v['subset'] or []))
#    json.dump(to_dump, f, indent=2, sort_keys=True)
#
#with open('./most_likely_delimiters.json', 'w') as f:
#    to_dump = {}
#    for k, v in delim_options.iteritems():
#        to_dump[k] = v['count'].most_common(1)  # should be delimiter
#
#    json.dump(to_dump, f, indent=2, sort_keys=True)


with open('./delimiters.json', 'w') as f:
    to_dump = {}

    for k, v in delim_options.iteritems():
        subset = list(v['subset'] or [])
        to_dump[k] = subset[0] if len(subset) == 1 else ''

    json.dump(to_dump, f, indent=2, sort_keys=True)


