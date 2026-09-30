"""
Entailment checking and heuristic reasoning.

This module contains the main entailment checker and various
heuristic checks for fast verification without invoking Z3.
"""

from velora.checking.checker import EntailmentChecker, EntailmentResult
from velora.checking.heuristics import HeuristicChecker
