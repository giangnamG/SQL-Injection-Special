#!/usr/bin/env python3
"""
Shim cho lib.core.compat - chỉ cần `xrange` (Python 2/3 compat của sqlmap).
Trên Python 3, xrange chính là range.
"""

xrange = range
