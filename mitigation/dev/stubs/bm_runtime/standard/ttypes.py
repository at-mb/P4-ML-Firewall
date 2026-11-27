# test stub of the thrift-generated types used by mitigation.py
class _S:
    def __init__(self, *a, **k): self.a, self.k = a, k
    def __repr__(self): return "%s%r" % (type(self).__name__, (self.a, self.k))
class BmMatchParam(_S): pass
class BmMatchParamExact(_S): pass
class BmAddEntryOptions(_S): pass
class BmMatchParamType: EXACT = 0
