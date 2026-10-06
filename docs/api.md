# Python API & Symbolic Core

[← Back to README](../README.md)

## Python API

```python
from velora import EntailmentChecker
from velora.sil import VeloraScanner

# Security scanning
scanner = VeloraScanner()
result = scanner.scan_file("app.py")
for vuln in result.vulnerabilities:
    print(f"{vuln.cwe_id}: {vuln.description}")

# Separation logic verification
checker = EntailmentChecker()
result = checker.check_entailment("x |-> 5 * y |-> 3 |- x |-> 5")
print(result.valid)  # True
```

## The Symbolic Core: Separation Logic + Z3

Velora's soundness rests on a mathematical foundation. It models heaps in separation
logic and discharges the resulting proof obligations with the Z3 SMT solver, so the
symbolic engine can prove a vulnerability is reachable (reporting it with no false
positives) or prove it cannot happen. That same engine is exposed directly for
verifying heap properties:

| Syntax | Meaning |
|--------|---------|
| `x \|-> v` | x points to value v |
| `emp` | Empty heap |
| `P * Q` | P and Q in separate memory |
| `P -* Q` | Magic wand (Python AST / internal pipelines only — the string parser does **not** accept `-*`) |
| `P \|- Q` | P entails Q |

**Built-in predicates:** `ls(x,y)`, `list(x)`, `tree(x)`, `dll(x,p,y,n)`

```bash
velora solve "ls(x, y) * ls(y, z) * x != z |- ls(x, z)"  # list-segment transitivity
```

The core is validated on the standard logic suites: SL-COMP (separation logic) at
79.9% and SMT-LIB QF_S (string theory) at 99.3%. Run the full suite with
`python -m benchmarks run --curated`; [benchmarks/README.md](../benchmarks/README.md) has
every division, the real-world corpora, per-tool comparisons, and methods.
