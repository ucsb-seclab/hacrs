import sys
import json
from collections import defaultdict

from constraint_helper import file_byte_index


def load_similarity(path):
    result = defaultdict(lambda: defaultdict(lambda: {'similarity': 0, 'shared_constraints': []}))
    with open(path, 'r') as f:
        loaded = json.load(f)

    return result.update(loaded)

def load_input(path):
    with open(path, 'r') as f:
        return f.read()

def dump_table(data, input_text):
    def print_entries(entries, fmt = '{:>4}'):
        print ', '.join([fmt.format(e) for e in entries])

    print_entries([''] * 3 + ['{:02x}'.format(ord(c)) for c in  input_text])
    print_entries([''] * 3 + [repr(c) for c in input_text])
    print

    for one in sorted(data.keys(), key=file_byte_index):
        entries = []
        input_char = input_text[file_byte_index(one)]
        entries.append('{}'.format(repr(input_char)))
        entries.append('{:02x}'.format(ord(input_char)))
        entries.append('')
        for two in sorted(data[one].keys(), key=file_byte_index):
            val = data[one][two][0]
            entries.append(val)

        print_entries(entries)


def dump_compartments(data, input_text):
    names = tuple(sorted([(file_byte_index(key), key) for key in data.keys()]))
    if len(names) == 0:
        return tuple()

    assert [name[0] for name in names] == range(len(names))

    #compartment_start =
    #for i in range(1, )

    compartments = {}
    for i_one, one in names:
        zipped = []
        for i_two, two in names:
            if i_two < i_one:
                continue

        partial_compartments = tuple(split(lambda a, b: a[2] < b[2], zipped))
        compartments.append(tuple(partial_compartments))

    compartments = list(set(compartments))

    return compartments

"""
        previous = data[one][sorted_keys[0]]

        for j, two in enumerate(sorted_keys):
            val = data[one][two]
            if val[0] <= previous[0]:
                compartment_constraint_collection.append(tuple(val[1]))
            else:
                length = len(compartment_constraint_collection)
                compartment = { 'length': length,
                                'value': input_text[start:start + length],
                                'constraints': tuple(compartment_constraint_collection)}
                compartments.append(compartment)

                compartment_constraint_collection = []
                start = i

            last = val
            i += 1

        if len(compartment_constraint_collection) > 0:
            length = len(compartment_constraint_collection)
            compartment = { 'length': length,
                            'value': input_text[start:start + length],
                            'constraints': tuple(compartment_constraint_collection)}
            compartments.append(compartment)

    return compartments
"""

def do_stuff(data, input_text):
    names = tuple(sorted([(file_byte_index(key), key) for key in data.keys()]))
    if len(names) == 0:
        return tuple()

    assert [name[0] for name in names] == range(len(names))
    contexts = []
    text_compartments = []

    cur_start = 0
    for i in range(1, len(names) - 1):
        before = names[i - 1][1]
        current = names[i][1]
        after = names[i + 1][1]

        pred_sim = data[before][current]['similarity']
        self_sim = data[current][current]['similarity']
        succ_sim = data[current][after]['similarity']

        should_be_explored = self_sim > succ_sim
        more_interesting_than_pred = self_sim > data[before][before]['similarity']
        more_interesting_than_succ = self_sim > data[before][before]['similarity']

        unique_checks = self_sim > max(pred_sim, succ_sim)
        seperator = succ_sim == pred_sim and unique_checks
        poi = unique_checks and pred_sim != succ_sim

        compartment_start = pred_sim < succ_sim
        #compartment_start2 = data[before][before][0] < data[current][current]['similarity']
        #compartment_start3 = data[before][before][0] != data[current][current]['similarity']
        #compartment_start4 = data[before][before][0] > data[current][current]['similarity']
        #compartment_start4 = data[current][current][0] > data[after][after]['similarity']
        compartment_end = succ_sim < self_sim

        context = {'val': input_text[i:i+1],
                   'pred': pred_sim,
                   'self': self_sim,
                   'succ': succ_sim,
                   'compart_start': 1 if compartment_start else 0,
                   'sep': 1 if seperator else 0,
                   }

        contexts.append(context)

    return tuple(contexts), tuple(text_compartments)

if __name__ == '__main__':
    data = load_similarity(sys.argv[2])
    input_text = load_input(sys.argv[3])

    if sys.argv[1] == 'table':
        dump_table(data, input_text)
    elif sys.argv[1] == 'compartments':
        compartments_list = dump_compartments(data, input_text)

        with open("./compartments.json", 'w') as f:
            json.dump(compartments_list, f, indent=2, sort_keys=True)
    elif sys.argv[1] == 'stuff':
        result, comp = do_stuff(data, input_text)

        fmt = '{:20}: ' + '{:4},' * len(input_text)
        print fmt.format('input', *map(repr, input_text))

        t = defaultdict(list)
        for ent in result:
            for key, val in ent.iteritems():
                t[key].append(val)

        for key in sorted(t.keys()):
            fmt = '{:20}: ' + '{:4},' * len(input_text)
            print fmt.format(key, '', *map(repr, t[key]) + [''])

        #print json.dumps(result, sort_keys=True, indent=2)
        #print json.dumps(comp, sort_keys=True, indent=2)
