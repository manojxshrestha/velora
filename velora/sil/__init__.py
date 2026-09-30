"""
Velora SIL: Separation Intermediate Language for Security Analysis

A language-agnostic IR inspired by Infer's SIL that captures:
1. Memory operations (heap manipulation)
2. Security-relevant operations (taint sources/sinks)
3. Procedure boundaries (for compositional analysis)
4. Control flow (for path sensitivity)

Architecture:
    Source Code → Frontend (tree-sitter) → SIL → Translator → Velora Formulas → Verification

Example usage:
    from velora.sil import PythonFrontend, SILTranslator, VeloraScanner

    # Full pipeline
    scanner = VeloraScanner(language="python")
    results = scanner.scan(source_code)

    # Or step by step
    frontend = PythonFrontend()
    program = frontend.translate(source_code)

    translator = SILTranslator()
    checks = translator.translate_program(program)

    for check in checks:
        result = checker.verify(check.formula)
        if result.reachable:
            print(f"Vulnerability found: {check.vuln_type}")
"""

# Core types
from velora.sil.types import (
    Ident,
    PVar,
    Location,
    Typ,
    TypeKind,
    # Expressions
    Exp,
    ExpVar,
    ExpConst,
    ExpBinOp,
    ExpUnOp,
    ExpFieldAccess,
    ExpIndex,
    ExpCast,
    ExpStringConcat,
    ExpCall,
)

# Instructions
from velora.sil.instructions import (
    # Core SIL instructions
    Instr,
    Load,
    Store,
    Alloc,
    Free,
    Prune,
    Call,
    Assign,
    # Security extensions
    TaintSource,
    TaintSink,
    Sanitize,
    AssertSafe,
    # Enums
    TaintKind,
    SinkKind,
    PruneKind,
)

# Procedure and program
from velora.sil.procedure import (
    Node,
    Procedure,
    ProcSpec,
    Program,
)

# Translator
from velora.sil.translator import (
    SILTranslator,
    SymbolicState,
    VulnerabilityCheck,
    VulnType,
)

# Scanner
from velora.sil.scanner import (
    VeloraScanner,
    FrameScanner,  # deprecated alias for VeloraScanner
    ScanResult,
    Vulnerability,
    Severity,
    scan_code,
    scan_file,
)

__all__ = [
    # Types
    "Ident", "PVar", "Location", "Typ", "TypeKind",
    "Exp", "ExpVar", "ExpConst", "ExpBinOp", "ExpUnOp",
    "ExpFieldAccess", "ExpIndex", "ExpCast", "ExpStringConcat", "ExpCall",
    # Instructions
    "Instr", "Load", "Store", "Alloc", "Free", "Prune", "Call", "Assign",
    "TaintSource", "TaintSink", "Sanitize", "AssertSafe",
    "TaintKind", "SinkKind", "PruneKind",
    # Procedure
    "Node", "Procedure", "ProcSpec", "Program",
    # Translator
    "SILTranslator", "SymbolicState", "VulnerabilityCheck", "VulnType",
    # Scanner
    "VeloraScanner", "FrameScanner", "ScanResult", "Vulnerability", "Severity",
    "scan_code", "scan_file",
]
