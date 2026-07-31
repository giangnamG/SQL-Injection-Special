#!/usr/bin/env python3
"""
Shim cho lib.core.datatype - cung cap `AttribDict` va `OrderedSet` ma tamper can.

- AttribDict: dict cho phep truy cap key nhu attribute. Ban rut gon (khong keo
  thirdparty.six nhu sqlmap). Dung `keycheck=False` -> key thieu tra ve None thay vi
  raise, tien de lam `kb` gia (tamper doc field la se nhan None, khong crash).
- OrderedSet: sao nguyen ban tu sqlmap, chi doi import collections.abc chuan Python 3.
"""

from collections import abc as _collections


class AttribDict(dict):
    """Dictionary cho phep truy cap thanh vien bang attribute.

    >>> d = AttribDict()
    >>> d.foo = 1
    >>> d.foo
    1
    >>> d2 = AttribDict(keycheck=False)
    >>> d2.missing is None
    True
    """

    def __init__(self, indict=None, keycheck=True):
        if indict is None:
            indict = {}
        dict.__init__(self, indict)
        self.__dict__["_keycheck"] = keycheck
        self.__dict__["_initialized"] = True

    def __getattr__(self, item):
        if item.startswith("__") and item.endswith("__"):
            raise AttributeError(item)
        try:
            return self.__getitem__(item)
        except KeyError:
            if self.__dict__.get("_keycheck"):
                raise AttributeError("unable to access item '%s'" % item)
            return None

    def __setattr__(self, item, value):
        if "_initialized" not in self.__dict__ or item in self.__dict__:
            self.__dict__[item] = value
        else:
            self.__setitem__(item, value)

    def __delattr__(self, item):
        try:
            return self.pop(item)
        except KeyError:
            if self.__dict__.get("_keycheck"):
                raise AttributeError("unable to access item '%s'" % item)
            return None


class OrderedSet(_collections.MutableSet):
    """Set giu thu tu them vao. Sao nguyen ban tu sqlmap/lib/core/datatype.py."""

    def __init__(self, iterable=None):
        self.end = end = []
        end += [None, end, end]         # sentinel node for doubly linked list
        self.map = {}                   # key --> [key, prev, next]
        if iterable is not None:
            self |= iterable

    def __len__(self):
        return len(self.map)

    def __contains__(self, key):
        return key in self.map

    def add(self, value):
        if value not in self.map:
            end = self.end
            curr = end[1]
            curr[2] = end[1] = self.map[value] = [value, curr, end]

    def discard(self, value):
        if value in self.map:
            value, prev, next = self.map.pop(value)
            prev[2] = next
            next[1] = prev

    def __iter__(self):
        end = self.end
        curr = end[2]
        while curr is not end:
            yield curr[0]
            curr = curr[2]

    def __reversed__(self):
        end = self.end
        curr = end[1]
        while curr is not end:
            yield curr[0]
            curr = curr[1]

    def pop(self, last=True):
        if not self:
            raise KeyError("set is empty")
        key = self.end[1][0] if last else self.end[2][0]
        self.discard(key)
        return key

    def __repr__(self):
        if not self:
            return "%s()" % (self.__class__.__name__,)
        return "%s(%r)" % (self.__class__.__name__, list(self))

    def __eq__(self, other):
        if isinstance(other, OrderedSet):
            return len(self) == len(other) and list(self) == list(other)
        return set(self) == set(other)
