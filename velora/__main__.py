#!/usr/bin/env python3
"""
Velora CLI entry point for `python -m velora`.

Usage:
    python -m velora scan app.py
    python -m velora solve "x |-> 5 |- x |-> 5"
    python -m velora check entailments.txt
    python -m velora parse "x |-> 5 * y |-> 3"
    python -m velora repl
"""

import sys
from velora.cli import main

if __name__ == "__main__":
    sys.exit(main())
