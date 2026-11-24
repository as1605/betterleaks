# Benchmarks: Library vs. CLI Subprocess

> **One-liner:** the in-process Python library is **1,000× – 10,000× faster than spawning the CLI via `subprocess.run()`** for repeated scans, and **~15–25% faster even on a single cold start**.

---

## Overview

`betterleaks` ships two execution paths in a single package:

| Mode | How it works |
|------|---|
| **Python library** (`betterleaks.scan_string` / `scan_file`) | On macOS and Linux, the Go shared library (`libbetterleaks_ffi.so/.dylib`) is loaded **once** into the Python process via `ctypes`. The scanner engine, compiled regexes, and rule filters stay warm in memory across all subsequent calls. |
| **CLI subprocess** (`subprocess.run(["betterleaks", ...])`) | Each call spawns a brand-new OS process: the Go runtime boots, all rules are parsed and compiled, the scan runs, results are serialized to JSON over stdout, and the process exits. |

The benchmark script lives in [`scripts/bench.py`](../scripts/bench.py).

---

## Running the Benchmarks

### Prerequisites

```bash
pip install -e ./bindings/python
```

### Hot-run benchmark (default)

```bash
python bindings/python/scripts/bench.py
```

Measures repeated calls inside a **single warm process**. Performs 2 warm-up calls before timing begins; GC is disabled during measurement.

### Cold-run benchmark

```bash
python bindings/python/scripts/bench.py --cold            # 100 iterations (default)
python bindings/python/scripts/bench.py --cold --cold-runs 50
```

Every iteration is executed in a **brand-new, isolated OS process** (spawned via `subprocess.run([sys.executable, ...])`). Calls are interleaved (Library -> Subprocess -> Direct CLI) to prevent thermal or scheduler bias.

---

## Choosing the Right Mode

| Use case | Recommended |
|---|---|
| Python service, web hook, stream consumer, or data pipeline | **Library** — always wins on repeated calls |
| Pre-commit hook or CI step scanning a batch of files | **Library** — orders of magnitude faster than looping subprocess calls |
| One-off shell pipeline or cron job | **Direct CLI** — simpler invocation, comparable cold-start cost |
| Full repository scan (`betterleaks git ...`, `betterleaks filesystem ...`) | **Direct CLI** — uses native Go parallel filesystem/git walker |
| Integrating into existing Python tooling | **Library** — typed `Finding` objects, no JSON parsing |
