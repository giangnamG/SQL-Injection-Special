#!/usr/bin/env python3
"""
Shim cho lib.core.compat - chi can `xrange` (Python 2/3 compat cua sqlmap).
Tren Python 3, xrange chinh la range.
"""

xrange = range
