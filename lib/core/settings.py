#!/usr/bin/env python3
"""
Shim cho lib.core.settings - chỉ các hằng số mà tamper script sử dụng.
Giá trị sao nguyên văn từ sqlmap/lib/core/settings.py.
"""

REPLACEMENT_MARKER = "__REPLACEMENT__"

DEFAULT_GET_POST_DELIMITER = '&'

IGNORE_SPACE_AFFECTED_KEYWORDS = (
    "CAST", "COUNT", "EXTRACT", "GROUP_CONCAT", "MAX", "MID", "MIN",
    "SESSION_USER", "SUBSTR", "SUBSTRING", "SUM", "SYSTEM_USER", "TRIM",
)
