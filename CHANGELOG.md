# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com).

## - 2026-06-29

### Added
- `--warn-only` flag to run checks in CI/linting pipelines without making modifications.
- `--diff` flag to display a unified diff of proposed or completed changes.
- `--backup` CLI flag to duplicate original files using `shutil.copy2` before modification.
- `--dry-run` flag to print reports and diffs without writing to disk.
- `--no-color` flag to strip ANSI character codes for clean log piping.
- `_find_shadowed_builtins()` Tier 2 rule to catch variables overriding common built-ins (e.g., `id`, `len`).
- Robust argument parsing CLI architecture using native `argparse`.
- Pre-flight `ast.parse()` safety check to gracefully handle files with syntax errors.

### Fixed
- Replaced fragile line-number comprehension matching with robust parent-tree mapping (`_is_in_comprehension_or_lambda()`).
- Blocked false-positive unused variable flags on pure type assignments (`x: int`) and forward references.
- Added full multiline range removal and line reconstruction support for `from x import y` groupings.
- Replaced fragile, complex regular expressions with `line.strip() == ""` for blank line checks.
- Wrapped file reading and writing routines in try/except blocks to handle file-existence and permissions errors.
- Standardized ANSI colors throughout `ReportPrinter` and `print_diff`.

### Changed
- Elevated minimum Python environment floor requirement to `requires-python = ">=3.10"` to leverage modern PEG parser AST stability.
- Explicitly documented consecutive-only duplicate line removal restriction to preserve functional logical branching.
