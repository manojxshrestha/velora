"""
Inductive Predicates for Separation Logic

Modular predicate definitions organized by type.
"""

# Base classes
from velora.predicates.base import (
    PredicateValidationError,
    PredicateValidator,
    InductivePredicate
)

# Parsed predicates
from velora.predicates.parsed import (
    ParsedPredicate,
    GenericPredicate
)

# List predicates
from velora.predicates.list_predicates import (
    ListSegment,
    ListSegmentWithLength,
    LinkedList,
    ReverseList,
    NestedList
)

# Tree predicates
from velora.predicates.tree_predicates import Tree

# DLL predicates
from velora.predicates.dll_predicates import DoublyLinkedList

# Skip list predicates
from velora.predicates.skiplist_predicates import (
    SkipList1,
    SkipList2,
    SkipList3
)

# Sorted predicates
from velora.predicates.sorted_predicates import SortedListSegment

# Registry
from velora.predicates.registry import PredicateRegistry

# Base computation (compositional)
from velora.predicates.base_registry import (
    BaseRegistry,
    BaseComputer,
    UnfoldingTree,
    UnfoldingTreeNode,
    get_base_registry,
    reset_base_registry
)

__all__ = [
    # Base
    'PredicateValidationError',
    'PredicateValidator',
    'InductivePredicate',
    # Parsed
    'ParsedPredicate',
    'GenericPredicate',
    # Lists
    'ListSegment',
    'ListSegmentWithLength',
    'LinkedList',
    'ReverseList',
    'NestedList',
    # Tree
    'Tree',
    # DLL
    'DoublyLinkedList',
    # Skip lists
    'SkipList1',
    'SkipList2',
    'SkipList3',
    # Sorted
    'SortedListSegment',
    # Registry
    'PredicateRegistry',
    # Base computation
    'BaseRegistry',
    'BaseComputer',
    'UnfoldingTree',
    'UnfoldingTreeNode',
    'get_base_registry',
    'reset_base_registry',
]
