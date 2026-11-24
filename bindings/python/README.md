# betterleaks

Python bindings and CLI for [Betterleaks](https://github.com/betterleaks/betterleaks), the fast secret and credential detection engine written in Go.

A single `pip install betterleaks` installs **both**:
- The **`betterleaks` Python library** (`import betterleaks`) for fast in-process scanning via `ctypes` and Betterleaks' C ABI (`bindings/c`).
- The **`betterleaks` CLI executable** (`betterleaks git .`, `betterleaks dir .`, `betterleaks stdin`).

---

## Installation

```bash
pip install betterleaks
```

### Platform Support

| Platform | Architecture | CLI (`betterleaks`) | Python API (`scan_string` / `scan_file`) |
| --- | --- | --- | --- |
| macOS 12+ | ARM64 & x86-64 | Bundled binary | Native C ABI (`libbetterleaks_ffi.dylib`) |
| Linux (glibc) | x86-64 & ARM64 | Bundled binary | Native C ABI (`libbetterleaks_ffi.so`) |
| Windows | x86-64 | Bundled binary | Bundled CLI subprocess fallback |

### Building from Source

Building from a repository checkout requires Python `>= 3.8`, Go `>= 1.26`, and a C compiler (for CGO on macOS/Linux):

```bash
git clone https://github.com/betterleaks/betterleaks.git
cd betterleaks
pip install ./bindings/python
```

---

## Python Quickstart

### Scanning Strings & Files

```python
import betterleaks

content = """
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
"""

findings = betterleaks.scan_string(content)

for finding in findings:
    print(f"[{finding.rule_id}] Secret: {finding.secret}")
    print(f"  Confidence: {finding.confidence}")
    print(f"  Line: {finding.location.start_line}, Col: {finding.location.start_column}")
    print(f"  Description: {finding.description}")

    if finding.component_sets:
        print(f"  Correlated components: {len(finding.component_sets)}")

file_findings = betterleaks.scan_file("path/to/settings.env")
```

### Reusable Scanners & Custom Configuration

Use `create_scanner` (or `Scanner`) as a context manager when scanning with inline TOML rules or custom config files:

```python
import betterleaks

with betterleaks.create_scanner(config_path="betterleaks.toml") as scanner:
    findings = scanner.scan_string("API_KEY = 'XYZ12345'")
    file_findings = scanner.scan_file("config.py")
```

Inline TOML configuration is also supported:

```python
toml_rules = """
[extend]
useDefault = true

[[rules]]
id = "internal-token"
description = "Internal token"
regex = '''INTERNAL_[A-Z0-9]{16}'''
keywords = ["INTERNAL_"]
"""

with betterleaks.create_scanner(config_toml=toml_rules) as scanner:
    findings = scanner.scan_string("token = INTERNAL_1234567890ABCDEF")
```

---

## CLI Usage

The `betterleaks` CLI is available directly in your Python environment's `PATH`:

```bash
betterleaks --version
betterleaks git .
betterleaks dir path/to/project
```

---

## Data Models

### `Finding`

| Attribute | Type | Description |
| --- | --- | --- |
| `rule_id` | `str` | Identifier of the triggered rule (e.g. `github-pat`, `aws-access-token`). |
| `description` | `str` | Description of the credential risk. |
| `confidence` | `str` | Detection confidence rating (`low`, `medium`, `high`). |
| `secret` | `str` | Matched credential / secret value (alias for `match.value`). |
| `file` | `Optional[str]` | Target file path, when scanning files. |
| `match` | `Match` | Match object with `full`, `value`, `fingerprint`, and `captures`. |
| `location` | `Location` | `path`, `start_line`, `end_line`, `start_column`, `end_column`. |
| `component_sets` | `List[dict]` | Correlated multi-part component findings. |
| `encodings` | `List[str]` | Encodings detected during decode passes. |
| `tags` | `List[str]` | Rule tags. |

`Finding` implements `collections.abc.Mapping` and supports both attribute access (`finding.rule_id`) and dictionary subscripting (`finding["rule_id"]`).

---

## Benchmarks & Tests

See [docs/benchmarks.md](docs/benchmarks.md) and [scripts/bench.py](scripts/bench.py) for library vs. CLI subprocess benchmarks.

```bash
pytest -v bindings/python/tests
```

## License

MIT License. See [LICENSE](../../LICENSE) for details.
