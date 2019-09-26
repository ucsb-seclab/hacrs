import os

def grease_filter(x):
    return x.endswith(".seed")

def grease_sorter(x):
    return sorted(x, key=os.path.getsize)
