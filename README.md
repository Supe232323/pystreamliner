# pystreamliner
[![PyPI version](https://img.shields.io/pypi/v/pystreamliner.svg)](https://pypi.org/project/pystreamliner/)
[![Python](https://img.shields.io/badge/python-3.13%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/pypi/l/pystreamliner.svg)](https://github.com/Supe232323/pystreamliner/blob/main/LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/Supe232323/pystreamliner/ci.yml?branch=main&label=CI)](https://github.com/Supe232323/pystreamliner/actions)
[![Last commit](https://img.shields.io/github/last-commit/Supe232323/pystreamliner)](https://github.com/Supe232323/pystreamliner/commits/main)


**Automatically clean up messy Python files — without breaking anything.**

pystreamliner uses Python's AST (abstract syntax tree) to safely detect and fix common code issues. It operates on two tiers: things it can fix automatically with zero risk, and things it flags for you to review manually.

Supports single files, multiple files, and recursive directory cleaning with a tight summary mode for large runs. Emits JSON and **SARIF 2.1.0** for CI. Optional mtime cache for repeated local runs.

**Discord:** [https://discord.gg/Z6cXxhSKS](https://discord.gg/Z6cXxhSKS)

---

## What it does

**Auto-fixes (Tier 1 — applied immediately):**
- Removes unused imports, or trims partially unused `from x import y` statements
- Removes consecutive duplicate lines
- Caps excessive blank lines

**Warnings (Tier 2 — reported, never auto-changed):**
- Unused variables
- Unused top-level functions
- Unused classes
- Vague variable names (`x`, `tmp`, `foo`, `bar`, etc.)
- Shadowed built-ins
- Dangerous calls (`eval`, `exec`, `pickle`, `os.system`, `subprocess(..., shell=True)`, unsafe `yaml.load`)
- Possible hardcoded secrets
- Assert statements
- Broad `except:` / `except Exception`

pystreamliner never touches code it isn't certain about. If there's any doubt, it warns you instead.

---

## Install

```bash
pip install pystreamliner
```

No dependencies. Runs on Python 3.13+.

---

## Usage

**Single file:**
```bash
pystreamliner your_file.py
```

**Multiple files:**
```bash
pystreamliner file1.py file2.py utils/*.py
```

**Entire project (recursive):**
```bash
pystreamliner .
# or
pystreamliner src/ tests/
```

Directories are walked recursively. Common junk directories (`.git`, `__pycache__`, `venv`, `node_modules`, etc.) are automatically skipped when they appear as *sub*-directories.

**Preview without modifying:**
```bash
pystreamliner --dry-run .
```

**CI mode (exit non-zero on issues):**
```bash
pystreamliner --check --quiet .
```

**SARIF for Code Scanning / security dashboards:**
```bash
pystreamliner --sarif --dry-run . > results.sarif
```

**JSON for scripts:**
```bash
pystreamliner --json --dry-run .
```

**Faster repeated local runs (mtime cache):**
```bash
pystreamliner --cache .
# optional custom cache path
pystreamliner --cache --cache-file /tmp/ps-cache.json .
```

**Parallelism:**
```bash
# default is sequential (-j 1) — safest for small trees
pystreamliner .

# auto (capped workers)
pystreamliner -j 0 .

# explicit workers; prefer threads on many small files
pystreamliner -j 4 --threads .
```

**Cross-file unused functions / classes (opt-in):**
```bash
pystreamliner --project --dry-run src/
```

Name-based: if another file in the same run imports or references the name, the unused_function / unused_class warning is dropped. Default remains per-file. Zero extra dependencies.

---

## Big runs / Summary mode

When you process 5 or more files (configurable with `--summary-threshold`), pystreamliner switches to a compact summary instead of dumping a full report for every file.

---

## CLI reference (high-signal flags)

| Flag | Purpose |
|------|---------|
| `-d, --dry-run` | Analyze / report only; do not write |
| `-c, --check` | Exit 1 if changes or warnings (CI) |
| `-q, --quiet` | Suppress human report |
| `--json` | Machine-readable JSON (includes `import_details`) |
| `--sarif` | SARIF 2.1.0 report on stdout |
| `--cache` | Skip unchanged files (mtime + size) |
| `--cache-file PATH` | Cache location (default `.pystreamliner_cache.json`) |
| `-j, --jobs N` | Workers; **default 1**; `0` = auto (capped) |
| `--threads` | Use threads instead of processes when `jobs > 1` |
| `--project` | Suppress unused function/class warnings if the name is referenced in another file in this run |
| `-w, --warn-only` | Report only; never rewrite |
| `--fix-only` | Tier-1 fixes only; suppress Tier-2 warnings |
| `--select` / `--ignore` | Filter warning categories |
| `--exclude-path` | Glob path excludes (repeatable) |
| `--aggressive` | Stricter blank-line collapsing |

Config file support (zero deps): `.pystreamliner.toml` or `[tool.pystreamliner]` in `pyproject.toml`. CLI always wins.

---

## Limitations / By design

These behaviours are intentional. They keep the tool zero-dependency, fast, and conservative.

### Unused function / class detection is **per-file by default**

By default pystreamliner analyses each file independently using only that file's AST.  
It does **not** follow imports across modules unless you pass **`--project`**.

Consequence without `--project`: a function or class that is defined in one file and imported + used in another file will be reported as unused when you run the tool on the definition file alone.

**`--project`** (also `project = true` in config) builds a cheap name index over every file in the current run and suppresses `unused_function` / `unused_class` when the name is referenced elsewhere (imports, attribute access, identifier strings, `__all__`). Still zero third-party deps. It is **not** a full import resolver: it does not understand types, `import *`, or dynamic getattr beyond literal strings.

This stays opt-in so the default remains conservative and single-pass cheap.

**Work-arounds without `--project`:**
- Put public API names in `__all__` — they are automatically treated as used.
- Use `--ignore unused_function,unused_class` (or the config equivalent).
- Run with `--project` on the whole package so definitions and call sites share one index.

### Directory name collisions with the ignore list

The built-in ignore list contains common junk directories (`__pycache__`, `.git`, `venv`, `coverage`, `htmlcov`, etc.).  
These are only skipped when they appear as *sub-directories* of a path you gave the tool.

If you explicitly pass a directory that happens to be named one of those (e.g. `pystreamliner coverage/`), its contents **are** processed. (This was fixed in 1.19.1.)

Nested junk directories inside that tree are still skipped as expected.

### Summary mode vs detailed reports

When ≥ 5 files are processed (configurable), output switches to a compact summary that shows counts only.  
Detailed per-file reports (with every warning message) appear only for smaller runs. This is intentional so large projects stay readable.

### Parallelism defaults

Default is sequential (`-j 1`). Process pools have non-trivial spawn cost; for many small files prefer `--threads` or leave the default alone. Use `-j 0` only when you know you want capped multi-core.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
