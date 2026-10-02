# Detection

[← Back to README](../README.md)

## Supported Languages

The symbolic engine has sound frontends for five languages:

| Language | Frameworks & Libraries |
|----------|----------------------|
| **Python** | Flask, Django, FastAPI, SQLAlchemy, subprocess |
| **Java** | Spring, JDBC, Hibernate, JNDI |
| **JavaScript/TypeScript** | Express, Node.js, DOM APIs |
| **C/C++** | POSIX, Windows API, memory operations |
| **C#** | ASP.NET, Entity Framework, ADO.NET |

The LLM layer (`--ai`) runs on any language, including ones with no symbolic frontend (PHP, Ruby, Go, and more). Those findings stay in the LLM tier, never mixed with the sound symbolic results. Directory scans pick files with `--pattern`; each file's language is auto-detected from its extension, and `-l <language>` sets the fallback for unknown extensions (e.g. `-l go`).

## What Velora Detects

Velora recognizes 80+ vulnerability classes across the families below. The symbolic core proves the ones reachable by taint or memory reasoning; the LLM layer adds context-dependent, authorization, and business-logic flaws.

<table>
<tr>
<td width="50%">

**Injection**
- SQL / NoSQL / ORM Injection (CWE-89)
- Cross-Site Scripting (CWE-79)
- Command & Code Injection (CWE-78/94)
- Template Injection (SSTI)
- LDAP / XPath / XML Injection
- Header & Log Injection

</td>
<td width="50%">

**Access Control & Auth**
- IDOR / BOLA (CWE-639)
- Authorization Bypass (CWE-285)
- Mass Assignment (CWE-915)
- Broken Authentication
- Session Fixation
- CSRF (CWE-352)

</td>
</tr>
<tr>
<td>

**Data Exposure & Crypto**
- Path Traversal (CWE-22)
- SSRF (CWE-918)
- Open Redirect (CWE-601)
- XXE (CWE-611)
- Hardcoded Secrets, Insecure Deserialization
- Weak Crypto / Hashing / Random

</td>
<td>

**Memory Safety**
- Buffer Overflow / Underflow (CWE-121/122)
- Use-After-Free (CWE-416)
- Double / Invalid Free (CWE-415)
- Null Pointer Dereference
- Integer Overflow, Format String

</td>
</tr>
</table>

## How It Works

Velora runs one investigation at rising commitment (detect, triage, exploit, fix), with a sound symbolic core grounding every stage so the LLM can't hallucinate:

<p align="center">
  <img src="../assets/how-it-works.svg" alt="Velora pipeline: source code flows through DETECT, TRIAGE, EXPLOIT, and FIX" width="620">
</p>

- **Detect:** the sound core proves reachable bugs with zero false positives; the LLM layer adds recall, tracing flows across files. Symbolic and LLM findings are never conflated.
- **Triage:** the LLM drops confident false positives, keeping a finding unless it *finds* the mitigating control.
- **Exploit:** an LLM agent develops and executes a working proof-of-concept against a live, authorized target.
- **Fix:** Velora generates a patch, re-scans, and confirms the vulnerability is gone with no regressions.

**Inside detect:** a per-language frontend lowers source into SIL (a separation intermediate language); taint tracking follows untrusted data from sources to sinks, symbolic execution explores paths, and Z3 discharges the reachability proof. A bug is reported only when it is provably reachable.
