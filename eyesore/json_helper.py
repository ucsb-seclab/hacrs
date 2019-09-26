import json
import claripy
from collections import defaultdict


class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, defaultdict):
            return {k: v for k, v in obj.iteritems()}
        if isinstance(obj, claripy.ast.Base):
            return repr(obj)

        return json.JSONEncoder.default(self, obj)

