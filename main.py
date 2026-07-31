#!/usr/bin/env python3
"""
Entrypoint cho stinger - chay tu thu muc root:

    python main.py -r request.txt --query "select content from final_flag limit 1"
    python main.py -r request.txt --dbms mysql --vector mysql-inline-sleep
    python main.py -r request.txt --tamper between,space2comment

Chi la lop mong chuyen tiep sang stinger.cli:main(). Toan bo logic o package stinger/.
"""

import os
import sys

# Bao dam import duoc package stinger/ va lib/ du chay tu thu muc nao.
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from stinger.cli import main

if __name__ == "__main__":
    sys.exit(main())
