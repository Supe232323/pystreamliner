# pystreamliner

[![PyPI version](https://shields.io)](https://pypi.org)
[![Downloads](https://shields.io)](https://pypistats.org)
[![License](https://shields.io)](https://opensource.org)

**Automatically clean up messy Python files — without breaking anything.**

pystreamliner uses Python's AST (abstract syntax tree) to safely detect and fix common code issues. It operates on two tiers: things it can fix automatically with zero risk, and things it flags for you to review manually.

---

## What it does

**Auto-fixes (Tier 1 — applied immediately):**
- Removes unused imports, or trims partially unused `from x import y` statements
- Removes consecutive duplicate lines
- Caps excessive blank lines

**Warnings (Tier 2 — reported, never auto-changed):**
- Unused variables
- Unused top-level functions
- Vague variable names (`x`, `tmp`, `foo`, `bar`, etc.)

pystreamliner never touches code it isn't certain about. If there's any doubt, it warns you instead.

---

## Install

```bash
pip install pystreamliner
```

No dependencies. Runs on Python 3.10+.

---

## Usage

```bash
python streamliner.py your_file.py
```

This will:
1. Analyze `your_file.py`
2. Write the cleaned version in-place
3. Print a full report of what was changed and what needs manual review
4. Show a diff of every modification

**Preview changes without modifying anything:**

```bash
python streamliner.py --dry-run your_file.py
```

---

## Example output

```
══════════════════════════════════════════
  PyStreamliner Report
══════════════════════════════════════════
  File:                        main.py
  Lines analyzed:                   312

  Auto-fixes applied:
    Unused imports removed:           3
    Duplicate lines removed:          1
    Blank lines reduced:              2

  Warnings (manual review needed):
    Unused variables detected:        2
    Unused functions detected:        1
    Vague variable names:             1
──────────────────────────────────────────

  Unused imports removed:
    • line 4:  import os
    • line 5:  import sys
    • line 7:  from pathlib import Path, PurePath  (partially cleaned: kept 'Path')

  Unused variables:
    ⚠ line 42:  result
    ⚠ line 87:  temp_val

  Vague variable names:
    ⚠ line 23:  tmp
══════════════════════════════════════════
```

---

## Why not just use Black / isort / autoflake?

Those are great tools and pystreamliner doesn't replace them. The difference:

- **Black** formats style. pystreamliner removes dead code.
- **autoflake** removes unused imports but doesn't warn about unused variables, vague names, or dead functions.
- **pystreamliner** combines lightweight static analysis with conservative auto-fixing and a human-readable report — in a single file with zero dependencies.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
