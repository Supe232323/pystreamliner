# SPDX-License-Identifier: AGPL-3.0
# Copyright (c) 2026 Supe232323
#!/usr/bin/env python3
"""PyStreamliner — A conservative, zero-dependency Python source code cleaner.
Two-tier model:
  Tier 1 (Auto-fix): Provably safe modifications only.
  Tier 2 (Warn-only): Detection + report, zero modification.
Supports single files, multiple files, recursive directory cleaning,
parallel processing via --jobs, config files, path excludes, mtime cache,
JSON and SARIF output. Optional --project cross-file unused suppression.
"""
from __future__ import annotations

import argparse
import ast
import dataclasses
import difflib
import fnmatch
import json
import os
import re
import shutil
import sys
import tomllib
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

# ─── ANSI Color Constants ────────────────────────────────────────────────────
RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
DIM = "\033[2m"

# ─── Constants ────────────────────────────────────────────────────────────────
MAX_CONSECUTIVE_BLANKS = 2
MAX_CONSECUTIVE_BLANKS_AGGRESSIVE = 1
SUMMARY_THRESHOLD = 5
CACHE_FILENAME = ".pystreamliner_cache.json"
# Default jobs=1 avoids ProcessPool spawn tax on small trees.
# -j 0 means "auto" (capped).
DEFAULT_JOBS = 1
AUTO_JOBS_CAP = 4
PROJECT_UNUSED_CATEGORIES: frozenset[str] = frozenset({"unused_function", "unused_class"})

IGNORE_DIRS: frozenset[str] = frozenset({
    ".git", "__pycache__", "venv", ".venv", "env", ".env",
    "node_modules", "dist", "build", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "eggs", ".eggs", ".idea",
    ".vscode", "htmlcov", "coverage",
})

VAGUE_NAMES: frozenset[str] = frozenset({
    "x", "y", "z", "temp", "tmp", "foo", "bar", "baz",
    "a", "b", "c", "d", "e", "f",
})


# SARIF level mapping for warning categories
SARIF_LEVEL: dict[str, str] = {
    "dangerous_call": "error",
    "hardcoded_secret": "error",
    "broad_except": "warning",
    "assert_used": "note",
    "unused_variable": "note",
    "unused_function": "note",
    "unused_class": "note",
    "vague_name": "note",
    "shadowed_builtin": "warning",
    "unused_import_fixed": "note",
    "duplicate_lines_fixed": "note",
    "blank_lines_fixed": "note",
}

TOOL_VERSION = "1.21.1"

SARIF_RULE_HELP: dict[str, str] = {
    "dangerous_call": "Call that can execute untrusted code or spawn a shell (eval, exec, pickle, os.system, shell=True, unsafe yaml.load).",
    "hardcoded_secret": "String literal assigned to a name that looks like a secret (password, token, api_key, etc.).",
    "broad_except": "Bare except: or except Exception: — catches more than intended.",
    "assert_used": "assert is stripped under -O; do not use it for security checks.",
    "unused_variable": "Assigned name that is never read in this file.",
    "unused_function": "Top-level function never referenced in this file (or project index if --project).",
    "unused_class": "Top-level class never referenced in this file (or project index if --project).",
    "vague_name": "Very short or placeholder name (x, tmp, foo, …).",
    "shadowed_builtin": "Name shadows a common builtin (id, len, type, …).",
    "unused_import_fixed": "Tier-1: unused import removed or trimmed.",
    "duplicate_lines_fixed": "Tier-1: consecutive duplicate line removed.",
    "blank_lines_fixed": "Tier-1: excess blank lines collapsed.",
}


def _sarif_rule_id(category: str) -> str:
    return f"PYS/{category}"


def _sarif_clean_message(text: str) -> str:
    """Strip leading warning emoji so Code Scanning / SARIF viewers stay plain."""
    t = text.strip()
    if t.startswith("⚠"):
        t = t.lstrip("⚠").strip()
    return t


def _sarif_uri(path: Path, cwd: Path) -> str:
    """Prefer repo-relative POSIX paths; fall back to absolute."""
    try:
        return path.resolve().relative_to(cwd.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _sarif_ensure_rule(rules_seen: dict[str, dict[str, Any]], category: str) -> str:
    rid = _sarif_rule_id(category)
    if rid in rules_seen:
        return rid
    short = category.replace("_", " ")
    level = SARIF_LEVEL.get(category, "warning")
    help_text = SARIF_RULE_HELP.get(category, short)
    rules_seen[rid] = {
        "id": rid,
        "name": short.title().replace(" ", ""),
        "shortDescription": {"text": short},
        "fullDescription": {"text": help_text},
        "helpUri": "https://github.com/Supe232323/pystreamliner#what-it-does",
        "defaultConfiguration": {"level": level},
        "properties": {
            "tags": ["python", "pystreamliner", category.split("_")[0]],
            "precision": "high" if category in {"dangerous_call", "unused_import_fixed"} else "medium",
        },
    }
    return rid
def build_sarif(
    results: list[FileResult],
    tool_name: str = "pystreamliner",
    tool_version: str = TOOL_VERSION,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document suitable for GitHub Code Scanning upload.

    Improvements over the minimal emitter:
    - relative artifact URIs when possible (stable across machines)
    - fullDescription + helpUri + tags on rules
    - Tier-1 fix notes for imports, duplicate lines, blank lines
    - plain messages (no leading emoji)
    - partialFingerprints for stable alert identity across runs
    """
    rules_seen: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []
    cwd = Path.cwd()

    for r in results:
        uri = _sarif_uri(r.path, cwd)
        if r.error:
            sarif_results.append({
                "level": "error",
                "message": {"text": r.error},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                    }
                }],
            })
            continue

        if r.had_changes:
            if r.stats.unused_imports_removed:
                rid = _sarif_ensure_rule(rules_seen, "unused_import_fixed")
                msg = f"Removed {r.stats.unused_imports_removed} unused import(s)"
                sarif_results.append({
                    "ruleId": rid,
                    "level": "note",
                    "message": {"text": msg},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                        }
                    }],
                    "partialFingerprints": {
                        "primaryLocationLineHash": f"{uri}|unused_import_fixed|{r.stats.unused_imports_removed}",
                    },
                    "properties": {"category": "unused_import_fixed"},
                })
            if r.stats.duplicate_lines_removed:
                rid = _sarif_ensure_rule(rules_seen, "duplicate_lines_fixed")
                msg = f"Removed {r.stats.duplicate_lines_removed} consecutive duplicate line(s)"
                sarif_results.append({
                    "ruleId": rid,
                    "level": "note",
                    "message": {"text": msg},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                        }
                    }],
                    "partialFingerprints": {
                        "primaryLocationLineHash": f"{uri}|duplicate_lines_fixed|{r.stats.duplicate_lines_removed}",
                    },
                    "properties": {"category": "duplicate_lines_fixed"},
                })
            if r.stats.blank_lines_reduced:
                rid = _sarif_ensure_rule(rules_seen, "blank_lines_fixed")
                msg = f"Reduced {r.stats.blank_lines_reduced} excess blank line(s)"
                sarif_results.append({
                    "ruleId": rid,
                    "level": "note",
                    "message": {"text": msg},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                        }
                    }],
                    "partialFingerprints": {
                        "primaryLocationLineHash": f"{uri}|blank_lines_fixed|{r.stats.blank_lines_reduced}",
                    },
                    "properties": {"category": "blank_lines_fixed"},
                })

        for w in r.warnings:
            rid = _sarif_ensure_rule(rules_seen, w.category)
            level = SARIF_LEVEL.get(w.category, "warning")
            msg = _sarif_clean_message(w.message)
            sarif_results.append({
                "ruleId": rid,
                "level": level,
                "message": {"text": msg},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": max(1, int(w.lineno or 1))},
                    }
                }],
                "partialFingerprints": {
                    "primaryLocationLineHash": f"{uri}|{w.category}|{w.name}|{w.lineno}",
                },
                "properties": {"category": w.category, "symbol": w.name},
            })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "semanticVersion": tool_version,
                    "informationUri": "https://github.com/Supe232323/pystreamliner",
                    "rules": list(rules_seen.values()),
                }
            },
            "results": sarif_results,
            "columnKind": "utf16CodeUnits",
        }],
    }

# ─── Data Structures ─────────────────────────────────────────────────────────
@dataclasses.dataclass
class ImportFinding:
    lineno: int
    end_lineno: int
    original_text: str
    bound_names: list[str]
    unused_names: list[str]
    used_names: list[str]
    is_from_import: bool
    indent: str
    module: str | None = None

@dataclasses.dataclass
class Warning:
    category: str
    name: str
    lineno: int
    message: str

@dataclasses.dataclass
class AnalysisResult:
    unused_imports: list[ImportFinding]
    warnings: list[Warning]
    all_names_in_all: set[str]

@dataclasses.dataclass
class CleaningStats:
    unused_imports_removed: int = 0
    duplicate_lines_removed: int = 0
    blank_lines_reduced: int = 0

@dataclasses.dataclass
class ImportDetail:
    lineno: int
    text: str

@dataclasses.dataclass
class FileResult:
    path: Path
    lines_analyzed: int
    stats: CleaningStats
    warnings: list[Warning]
    import_details: list[ImportDetail]
    had_changes: bool
    original_source: str
    cleaned_source: str
    error: str | None = None

# ─── Config ───────────────────────────────────────────────────────────────────
def _load_config() -> dict:
    """Load config from .pystreamliner.toml or pyproject.toml [tool.pystreamliner].
    Pure stdlib (tomllib). Returns empty dict if nothing found.
    """
    for path in (Path(".pystreamliner.toml"), Path("pyproject.toml")):
        if not path.is_file():
            continue
        try:
            with path.open("rb") as f:
                data = tomllib.load(f)
            if path.name == "pyproject.toml":
                return dict(data.get("tool", {}).get("pystreamliner", {}) or {})
            return dict(data or {})
        except Exception:
            continue
    return {}

def _path_is_excluded(path: Path, patterns: list[str]) -> bool:
    if not patterns:
        return False
    s = str(path)
    name = path.name
    for pat in patterns:
        if fnmatch.fnmatch(s, pat) or fnmatch.fnmatch(name, pat):
            return True
        try:
            rel = str(path.relative_to(Path.cwd()))
            if fnmatch.fnmatch(rel, pat):
                return True
        except ValueError:
            pass
    return False

# ─── Mtime / content cache ────────────────────────────────────────────────────
def _file_fingerprint(path: Path) -> str:
    """Cheap fingerprint: size + mtime_ns. Good enough for skip-unchanged."""
    try:
        st = path.stat()
        return f"{st.st_size}:{getattr(st, 'st_mtime_ns', int(st.st_mtime * 1e9))}"
    except OSError:
        return ""

def _load_cache(cache_path: Path) -> dict[str, str]:
    if not cache_path.is_file():
        return {}
    try:
        with cache_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return dict(data.get("files", {})) if isinstance(data, dict) else {}
    except Exception:
        return {}

def _save_cache(cache_path: Path, files: dict[str, str]) -> None:
    try:
        payload = {"version": 1, "files": files}
        cache_path.write_text(json.dumps(payload, indent=0, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        pass

def _filter_cached_files(files: list[Path], cache: dict[str, str]) -> tuple[list[Path], list[Path]]:
    """Return (to_process, skipped_unchanged)."""
    to_process: list[Path] = []
    skipped: list[Path] = []
    for p in files:
        key = str(p.resolve())
        fp = _file_fingerprint(p)
        if cache.get(key) == fp and fp:
            skipped.append(p)
        else:
            to_process.append(p)
    return to_process, skipped

# ─── Project-wide unused function/class suppression ───────────────────────────
def _collect_project_refs(source: str) -> set[str]:
    """Names referenced in a file: loads, attributes, imports, identifier strings, __all__.

    Used by --project to suppress unused_function / unused_class when another
    file in the same run references the name. Name-based, not a full resolver.
    """
    names: set[str] = set()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return names
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
            if isinstance(node.value, ast.Name):
                names.add(node.value.id)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            candidate = node.value.strip()
            if candidate.isidentifier():
                names.add(candidate)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                for part in alias.name.split("."):
                    if part:
                        names.add(part)
                if alias.asname:
                    names.add(alias.asname)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                for part in node.module.split("."):
                    if part:
                        names.add(part)
            for alias in node.names:
                if alias.name != "*":
                    names.add(alias.name)
                if alias.asname:
                    names.add(alias.asname)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(node.value, (ast.List, ast.Tuple)):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                names.add(elt.value)
    return names


def _index_project_refs(files: list[Path]) -> dict[str, set[str]]:
    """Map resolved path -> referenced names. Cheap extra parse; stdlib only."""
    index: dict[str, set[str]] = {}
    for path in files:
        key = str(path.resolve())
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            index[key] = set()
            continue
        index[key] = _collect_project_refs(source)
    return index


def _apply_project_unused(results: list[FileResult], file_refs: dict[str, set[str]]) -> None:
    """Drop unused_function / unused_class warnings whose names are referenced elsewhere."""
    if len(file_refs) < 2:
        return
    for result in results:
        if result.error or not result.warnings:
            continue
        key = str(result.path.resolve())
        external: set[str] = set()
        for other_key, refs in file_refs.items():
            if other_key != key:
                external |= refs
        if not external:
            continue
        result.warnings = [
            w for w in result.warnings
            if not (w.category in PROJECT_UNUSED_CATEGORIES and w.name in external)
        ]

# ─── Helpers ──────────────────────────────────────────────────────────────────
def _build_parent_map(tree: ast.AST) -> dict[int, ast.AST]:
    parent_map: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent_map[id(child)] = node
    return parent_map

def _parse_exclude(exclude: str | None) -> set[int]:
    if not exclude:
        return set()
    lines: set[int] = set()
    for part in exclude.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start_s, end_s = part.split("-", 1)
                start, end = int(start_s), int(end_s)
                lines.update(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                lines.add(int(part))
            except ValueError:
                continue
    return lines

def _filter_warnings(
    warnings: list[Warning],
    select: str | None,
    ignore: str | None,
    excluded_lines: set[int],
) -> list[Warning]:
    selected = {s.strip() for s in select.split(",")} if select else None
    ignored = {i.strip() for i in ignore.split(",")} if ignore else set()
    result: list[Warning] = []
    for w in warnings:
        if w.lineno in excluded_lines:
            continue
        if selected is not None and w.category not in selected:
            continue
        if w.category in ignored:
            continue
        result.append(w)
    return result

def _collect_python_files(paths: list[Path], exclude_globs: list[str] | None = None) -> list[Path]:
    """Collect all .py files from given paths, honouring exclude globs.

    Junk directories listed in IGNORE_DIRS are skipped *only when they appear
    as sub-directories*. If the user explicitly passes a directory that
    happens to be named one of those (e.g. a project folder called
    "coverage"), its contents are still processed.
    """
    files: list[Path] = []
    seen: set[Path] = set()
    globs = exclude_globs or []

    def should_skip_dir(name: str) -> bool:
        return name in IGNORE_DIRS or name.endswith(".egg-info")

    for path in paths:
        path = path.resolve()
        if not path.exists():
            sys.stderr.write(f"Warning: path not found, skipping: {path}\n")
            continue
        if path.is_file():
            if path.suffix == ".py" and path not in seen and not _path_is_excluded(path, globs):
                files.append(path)
                seen.add(path)
        elif path.is_dir():
            root_parts_len = len(path.parts)
            for p in path.rglob("*.py"):
                relative_parts = p.parts[root_parts_len:]
                if any(should_skip_dir(part) for part in relative_parts):
                    continue
                if _path_is_excluded(p, globs):
                    continue
                if p not in seen:
                    files.append(p)
                    seen.add(p)
    return sorted(files)# ─── SourceAnalyzer (unchanged core logic) ────────────────────────────────────
class SourceAnalyzer:
    def __init__(self, source: str, filename: str) -> None:
        self._source = source
        self._filename = filename
        self._tree = ast.parse(source, filename=filename)
        self._lines = source.splitlines(True)
        self._used_names: set[str] | None = None
        self._all_names: set[str] = set()
        self._parent_map: dict[int, ast.AST] = _build_parent_map(self._tree)

    def analyze(self) -> AnalysisResult:
        # Single combined walk for used names, __all__, assignments, and
        # most warning categories (dangerous calls, secrets, asserts, excepts).
        self._used_names, assigned, early_warnings = self._combined_collect()
        unused_imports = self._find_unused_imports()
        warnings: list[Warning] = list(early_warnings)
        warnings.extend(self._warnings_from_assignments(assigned))
        warnings.extend(self._find_unused_functions())
        warnings.extend(self._find_unused_classes())
        return AnalysisResult(
            unused_imports=unused_imports,
            warnings=warnings,
            all_names_in_all=self._all_names,
        )

    def _combined_collect(self) -> tuple[set[str], list[tuple[str, int]], list[Warning]]:
        """One ast.walk for used names, __all__, and several warning kinds."""
        names: set[str] = set()
        assigned: list[tuple[str, int]] = []
        warnings: list[Warning] = []
        SECRET_NAMES = frozenset({
            "password", "passwd", "pwd", "secret", "api_key", "apikey", "token",
            "access_token", "auth_token", "private_key", "secret_key", "client_secret",
            "aws_secret", "db_password",
        })
        DANGEROUS_NAMES = frozenset({"eval", "exec", "compile"})
        PICKLE_FUNCS = frozenset({"loads", "load", "dumps", "dump"})
        OS_DANGEROUS = frozenset({"system", "popen", "popen2", "popen3", "popen4"})
        secret_seen: set[tuple[str, int]] = set()

        for node in ast.walk(self._tree):
            # --- used names ---
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
                if isinstance(node.value, ast.Name):
                    names.add(node.value.id)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                candidate = node.value.strip()
                if candidate.isidentifier():
                    names.add(candidate)

            # --- __all__ ---
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "__all__":
                        if isinstance(node.value, (ast.List, ast.Tuple)):
                            for elt in node.value.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    self._all_names.add(elt.value)

            # --- assignments (for unused / vague / shadow) ---
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    self._extract_names_from_target(target, assigned)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                self._extract_names_from_target(node.target, assigned)
            elif isinstance(node, ast.For):
                self._extract_names_from_target(node.target, assigned)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars:
                        self._extract_names_from_target(item.optional_vars, assigned)
            elif isinstance(node, ast.NamedExpr):
                self._extract_names_from_target(node.target, assigned)

            # --- dangerous calls ---
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_NAMES:
                    warnings.append(Warning("dangerous_call", node.func.id, node.lineno,
                                            f"⚠ Dangerous call '{node.func.id}()' at line {node.lineno}"))
                elif isinstance(node.func, ast.Attribute):
                    attr = node.func.attr
                    if isinstance(node.func.value, ast.Name):
                        mod = node.func.value.id
                        if mod in {"pickle", "marshal", "shelve"} and attr in PICKLE_FUNCS:
                            warnings.append(Warning("dangerous_call", f"{mod}.{attr}", node.lineno,
                                                    f"⚠ Dangerous call '{mod}.{attr}()' at line {node.lineno}"))
                        elif mod == "os" and attr in OS_DANGEROUS:
                            warnings.append(Warning("dangerous_call", f"os.{attr}", node.lineno,
                                                    f"⚠ Dangerous call 'os.{attr}()' at line {node.lineno}"))
                        elif mod == "yaml" and attr == "load":
                            has_safe = any(
                                kw.arg in {"Loader", "loader"} and isinstance(kw.value, ast.Attribute)
                                and kw.value.attr in {"SafeLoader", "CSafeLoader"}
                                for kw in node.keywords
                            )
                            if not has_safe:
                                warnings.append(Warning("dangerous_call", "yaml.load", node.lineno,
                                                        f"⚠ Dangerous call 'yaml.load()' without SafeLoader at line {node.lineno}"))
                        elif mod == "subprocess":
                            for kw in node.keywords:
                                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                    warnings.append(Warning("dangerous_call", f"subprocess.{attr}", node.lineno,
                                                            f"⚠ subprocess.{attr}() called with shell=True at line {node.lineno}"))
                                    break

            # --- hardcoded secrets ---
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        name_lower = target.id.lower()
                        if name_lower in SECRET_NAMES or any(s in name_lower for s in ("password", "secret", "token", "api_key")):
                            key = (target.id, target.lineno)
                            if key not in secret_seen:
                                secret_seen.add(key)
                                warnings.append(Warning("hardcoded_secret", target.id, target.lineno,
                                                        f"⚠ Possible hardcoded secret in '{target.id}' at line {target.lineno}"))
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                if isinstance(node.target, ast.Name) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    name_lower = node.target.id.lower()
                    if name_lower in SECRET_NAMES or any(s in name_lower for s in ("password", "secret", "token", "api_key")):
                        key = (node.target.id, node.target.lineno)
                        if key not in secret_seen:
                            secret_seen.add(key)
                            warnings.append(Warning("hardcoded_secret", node.target.id, node.target.lineno,
                                                    f"⚠ Possible hardcoded secret in '{node.target.id}' at line {node.target.lineno}"))

            # --- asserts ---
            if isinstance(node, ast.Assert):
                warnings.append(Warning("assert_used", "assert", node.lineno,
                                        f"⚠ assert used at line {node.lineno} (stripped with -O; do not use for security checks)"))

            # --- broad excepts ---
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    warnings.append(Warning("broad_except", "except:", node.lineno,
                                            f"⚠ Bare 'except:' at line {node.lineno}"))
                elif isinstance(node.type, ast.Name) and node.type.id == "Exception":
                    warnings.append(Warning("broad_except", "except Exception", node.lineno,
                                            f"⚠ Broad 'except Exception' at line {node.lineno}"))

        return names, assigned, warnings

    def _warnings_from_assignments(self, assigned: list[tuple[str, int]]) -> list[Warning]:
        assert self._used_names is not None
        warnings: list[Warning] = []
        seen: set[tuple[str, int]] = set()
        SHADOWED = frozenset({
            "id", "type", "list", "dict", "set", "tuple", "str", "int", "float", "bool",
            "input", "open", "range", "len", "map", "filter", "sum", "min", "max",
            "next", "iter", "hash", "format", "print", "object", "bytes", "complex",
            "frozenset", "property", "staticmethod", "classmethod", "super",
        })
        for name, lineno in assigned:
            key = (name, lineno)
            if key in seen:
                continue
            seen.add(key)
            if name == "_" or (name.startswith("__") and name.endswith("__")):
                pass
            elif name not in self._all_names and name not in self._used_names:
                warnings.append(Warning("unused_variable", name, lineno,
                                        f"⚠ Unused variable '{name}' at line {lineno}"))
            if name.lower() in VAGUE_NAMES and not self._is_in_comprehension_or_lambda(name, lineno):
                warnings.append(Warning("vague_name", name, lineno,
                                        f"⚠ Vague variable name '{name}' at line {lineno}"))
            if name in SHADOWED:
                warnings.append(Warning("shadowed_builtin", name, lineno,
                                        f"⚠ Variable '{name}' shadows a built-in at line {lineno}"))
        return warnings

    def _find_unused_imports(self) -> list[ImportFinding]:
        assert self._used_names is not None
        findings: list[ImportFinding] = []
        for node in ast.iter_child_nodes(self._tree):
            if isinstance(node, ast.Import):
                result = self._check_import(node)
                if result is not None:
                    findings.append(result)
            elif isinstance(node, ast.ImportFrom):
                result = self._check_from_import(node)
                if result is not None:
                    findings.append(result)
        return findings

    def _check_import(self, node: ast.Import) -> ImportFinding | None:
        assert self._used_names is not None
        line_text = self._get_line_text(node.lineno)
        indent = self._get_indent(line_text)
        end_lineno = getattr(node, "end_lineno", node.lineno) or node.lineno
        if end_lineno > node.lineno:
            original_text = "".join(self._lines[node.lineno - 1:end_lineno]).rstrip()
        else:
            original_text = line_text.rstrip()
        bound_names: list[str] = []
        unused: list[str] = []
        used: list[str] = []
        for alias in node.names:
            bound = alias.asname if alias.asname else alias.name.split(".")[0]
            bound_names.append(bound)
            if bound in self._used_names or bound in self._all_names:
                if alias.asname:
                    used.append(f"{alias.name} as {alias.asname}")
                else:
                    used.append(alias.name)
            else:
                unused.append(bound)
        if not unused:
            return None
        return ImportFinding(
            lineno=node.lineno, end_lineno=end_lineno, original_text=original_text,
            bound_names=bound_names, unused_names=unused, used_names=used,
            is_from_import=False, indent=indent,
        )

    def _check_from_import(self, node: ast.ImportFrom) -> ImportFinding | None:
        assert self._used_names is not None
        if node.module == "__future__" or any(alias.name == "*" for alias in node.names):
            return None
        line_text = self._get_line_text(node.lineno)
        indent = self._get_indent(line_text)
        end_lineno = getattr(node, "end_lineno", node.lineno) or node.lineno
        if end_lineno > node.lineno:
            original_text = "".join(self._lines[node.lineno - 1:end_lineno]).rstrip()
        else:
            original_text = line_text.rstrip()
        bound_names: list[str] = []
        unused: list[str] = []
        used: list[str] = []
        for alias in node.names:
            bound = alias.asname if alias.asname else alias.name
            bound_names.append(bound)
            if bound in self._used_names or bound in self._all_names:
                used.append(alias.name if not alias.asname else f"{alias.name} as {alias.asname}")
            else:
                unused.append(bound)
        if not unused:
            return None
        return ImportFinding(
            lineno=node.lineno, end_lineno=end_lineno, original_text=original_text,
            bound_names=bound_names, unused_names=unused, used_names=used,
            is_from_import=True, indent=indent, module=node.module,
        )

    def _extract_names_from_target(self, target: ast.expr, result: list[tuple[str, int]]) -> None:
        if isinstance(target, ast.Name) and isinstance(target.ctx, ast.Store):
            result.append((target.id, target.lineno))
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._extract_names_from_target(elt, result)

    def _find_unused_functions(self) -> list[Warning]:
        assert self._used_names is not None
        warnings: list[Warning] = []
        for node in ast.walk(self._tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            name = node.name
            if name == "main" or node.decorator_list or (name.startswith("__") and name.endswith("__")):
                continue
            if name in self._used_names or name in self._all_names:
                continue
            if self._is_inside_name_main_block(node):
                continue
            parent = self._parent_map.get(id(node))
            kind = "method" if isinstance(parent, ast.ClassDef) else "function"
            warnings.append(Warning("unused_function", name, node.lineno, f"⚠ Unused {kind} '{name}()' at line {node.lineno}"))
        return warnings

    def _find_unused_classes(self) -> list[Warning]:
        assert self._used_names is not None
        warnings: list[Warning] = []
        for node in ast.walk(self._tree):
            if not isinstance(node, ast.ClassDef):
                continue
            name = node.name
            if name.startswith("__") and name.endswith("__"):
                continue
            if name in self._used_names or name in self._all_names:
                continue
            if self._is_inside_name_main_block(node) or node.decorator_list:
                continue
            warnings.append(Warning("unused_class", name, node.lineno, f"⚠ Unused class '{name}' at line {node.lineno}"))
        return warnings

    def _is_inside_name_main_block(self, node: ast.AST) -> bool:
        for top in ast.iter_child_nodes(self._tree):
            if not isinstance(top, ast.If):
                continue
            test = top.test
            if (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and test.left.id == "__name__"):
                for child in ast.walk(top):
                    if child is node:
                        return True
        return False

    def _is_in_comprehension_or_lambda(self, name: str, lineno: int) -> bool:
        comp_types = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.Lambda)
        for node in ast.walk(self._tree):
            if (isinstance(node, ast.Name) and node.id == name and node.lineno == lineno and isinstance(node.ctx, ast.Store)):
                current: ast.AST = node
                while True:
                    parent = self._parent_map.get(id(current))
                    if parent is None:
                        break
                    if isinstance(parent, comp_types):
                        return True
                    current = parent
        return False

    def _get_line_text(self, lineno: int) -> str:
        if 1 <= lineno <= len(self._lines):
            return self._lines[lineno - 1]
        return ""

    @staticmethod
    def _get_indent(line: str) -> str:
        match = re.match(r"^(\s*)", line)
        return match.group(1) if match else ""

# ─── SourceCleaner ────────────────────────────────────────────────────────────
class SourceCleaner:
    def __init__(self, lines: list[str], analysis: AnalysisResult, aggressive: bool = False, excluded_lines: set[int] | None = None) -> None:
        self._lines = list(lines)
        self._analysis = analysis
        self._stats = CleaningStats()
        self._import_details: list[ImportDetail] = []
        self._max_blanks = MAX_CONSECUTIVE_BLANKS_AGGRESSIVE if aggressive else MAX_CONSECUTIVE_BLANKS
        self._excluded = excluded_lines or set()

    def clean(self) -> tuple[list[str], CleaningStats, list[ImportDetail]]:
        self._remove_unused_imports()
        self._remove_duplicate_lines()
        self._reduce_blank_lines()
        self._ensure_trailing_newline()
        return self._lines, self._stats, self._import_details

    def _remove_unused_imports(self) -> None:
        lines_to_remove: set[int] = set()
        line_replacements: dict[int, str] = {}
        range_removals: list[tuple[int, int]] = []
        for imp in self._analysis.unused_imports:
            if imp.lineno in self._excluded:
                continue
            start_idx = imp.lineno - 1
            end_idx = imp.end_lineno - 1
            if start_idx < 0 or end_idx >= len(self._lines):
                continue
            is_multiline = end_idx > start_idx
            if not imp.used_names:
                if is_multiline:
                    range_removals.append((start_idx, end_idx))
                else:
                    lines_to_remove.add(start_idx)
                self._import_details.append(ImportDetail(lineno=imp.lineno, text=imp.original_text.strip()))
                self._stats.unused_imports_removed += len(imp.unused_names)
            else:
                if imp.is_from_import:
                    module = imp.module or ""
                    new_line = f"{imp.indent}from {module} import {', '.join(imp.used_names)}"
                else:
                    new_line = f"{imp.indent}import {', '.join(imp.used_names)}"
                last = self._lines[end_idx]
                if last.endswith("\r\n"):
                    new_line += "\r\n"
                elif last.endswith("\n"):
                    new_line += "\n"
                if is_multiline:
                    line_replacements[start_idx] = new_line
                    for idx in range(start_idx + 1, end_idx + 1):
                        lines_to_remove.add(idx)
                else:
                    line_replacements[start_idx] = new_line
                kept = ", ".join(f"'{n}'" for n in imp.used_names)
                self._import_details.append(ImportDetail(lineno=imp.lineno, text=f"{imp.original_text.strip()} (partially cleaned: kept {kept})"))
                self._stats.unused_imports_removed += len(imp.unused_names)
        for start, end in range_removals:
            for idx in range(start, end + 1):
                lines_to_remove.add(idx)
        new_lines: list[str] = []
        for idx, line in enumerate(self._lines):
            if idx in lines_to_remove:
                continue
            new_lines.append(line_replacements.get(idx, line))
        self._lines = new_lines

    def _remove_duplicate_lines(self) -> None:
        if not self._lines:
            return
        result: list[str] = [self._lines[0]]
        for i in range(1, len(self._lines)):
            current = self._lines[i]
            if current.strip() == "":
                result.append(current)
                continue
            if current == self._lines[i - 1]:
                self._stats.duplicate_lines_removed += 1
                continue
            result.append(current)
        self._lines = result

    def _reduce_blank_lines(self) -> None:
        result: list[str] = []
        consecutive = 0
        for line in self._lines:
            if line.strip() == "":
                consecutive += 1
                if consecutive <= self._max_blanks:
                    result.append(line)
                else:
                    self._stats.blank_lines_reduced += 1
            else:
                consecutive = 0
                result.append(line)
        self._lines = result

    def _ensure_trailing_newline(self) -> None:
        if self._lines and not self._lines[-1].endswith("\n"):
            self._lines[-1] += "\n"# ─── Report / Diff / process_file ─────────────────────────────────────────────
class ReportPrinter:
    BORDER_DOUBLE = "═" * 38
    BORDER_SINGLE = "─" * 38
    def __init__(self, filename: str, lines_analyzed: int, stats: CleaningStats, warnings: list[Warning], import_details: list[ImportDetail], use_color: bool = True) -> None:
        self._filename = filename
        self._lines_analyzed = lines_analyzed
        self._stats = stats
        self._warnings = warnings
        self._import_details = import_details
        self._use_color = use_color
    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self._use_color else text
    def print_report(self) -> None:
        print()
        print(self._c(CYAN, self.BORDER_DOUBLE))
        print(self._c(BOLD, " PyStreamliner Report"))
        print(self._c(CYAN, self.BORDER_DOUBLE))
        print(f" File: {self._c(BOLD, self._filename)}")
        print(f" Lines analyzed: {self._lines_analyzed}")
        print()
        print(" Auto-fixes applied:")
        print(f"   Unused imports removed: {self._stats.unused_imports_removed}")
        print(f"   Duplicate lines removed: {self._stats.duplicate_lines_removed}")
        print(f"   Blank lines reduced: {self._stats.blank_lines_reduced}")
        print()
        print(f" Warnings (manual review needed): {len(self._warnings)}")
        print(self._c(CYAN, self.BORDER_SINGLE))

        if self._import_details:
            print("\n Unused imports removed:")
            for d in self._import_details:
                print(f"   • line {d.lineno}:  {d.text}")

        if self._warnings:
            by_cat: dict[str, list[Warning]] = {}
            for w in self._warnings:
                by_cat.setdefault(w.category, []).append(w)
            for cat, items in by_cat.items():
                print(f"\n {cat.replace('_', ' ').title()}:")
                for w in items:
                    print(f"   {w.message}")

        print(self._c(CYAN, self.BORDER_DOUBLE))
        print()

def print_summary(results: list[FileResult], use_color: bool = True) -> None:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if use_color else text
    total = len(results)
    ok = [r for r in results if r.error is None]
    changed = [r for r in ok if r.had_changes]
    warned = [r for r in ok if r.warnings]
    clean = [r for r in ok if not r.had_changes and not r.warnings]
    print()
    print(c(CYAN, "═" * 50))
    print(c(BOLD, " PyStreamliner Summary"))
    print(c(CYAN, "═" * 50))
    print(f" Files processed: {total}")
    print(f" Clean: {len(clean)}  Modified: {len(changed)}  Warnings only: {len([r for r in warned if not r.had_changes])}")
    print(c(CYAN, "═" * 50))
    print()

def print_diff(original_lines: list[str], cleaned_lines: list[str], filename: str = "source", use_color: bool = True) -> bool:
    diff = list(difflib.unified_diff(original_lines, cleaned_lines, fromfile=f"a/{filename}", tofile=f"b/{filename}", lineterm=""))
    if not diff:
        return False
    for line in diff:
        sys.stdout.write(line + "\n")
    return True

# ─── SARIF 2.1.0 emitter ──────────────────────────────────────────────────────
def _sarif_rule_id(category: str) -> str:
    return f"PYS/{category}"

def build_sarif(results: list[FileResult], tool_name: str = "pystreamliner", tool_version: str = "1.21.0") -> dict[str, Any]:
    """Build a minimal SARIF 2.1.0 document from FileResults."""
    rules_seen: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for r in results:
        if r.error:
            sarif_results.append({
                "level": "error",
                "message": {"text": r.error},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(r.path).replace("\\", "/")},
                    }
                }],
            })
            continue
        if r.had_changes and r.stats.unused_imports_removed:
            rid = _sarif_rule_id("unused_import_fixed")
            if rid not in rules_seen:
                rules_seen[rid] = {
                    "id": rid,
                    "name": "UnusedImportFixed",
                    "shortDescription": {"text": "Unused import removed"},
                    "defaultConfiguration": {"level": "note"},
                }
            sarif_results.append({
                "ruleId": rid,
                "level": "note",
                "message": {"text": f"Removed {r.stats.unused_imports_removed} unused import(s)"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(r.path).replace("\\", "/")},
                    }
                }],
            })
        for w in r.warnings:
            rid = _sarif_rule_id(w.category)
            if rid not in rules_seen:
                rules_seen[rid] = {
                    "id": rid,
                    "name": w.category.replace("_", " ").title().replace(" ", ""),
                    "shortDescription": {"text": w.category.replace("_", " ")},
                    "defaultConfiguration": {"level": SARIF_LEVEL.get(w.category, "warning")},
                }
            level = SARIF_LEVEL.get(w.category, "warning")
            sarif_results.append({
                "ruleId": rid,
                "level": level,
                "message": {"text": w.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(r.path).replace("\\", "/")},
                        "region": {"startLine": w.lineno},
                    }
                }],
            })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/Supe232323/pystreamliner",
                    "rules": list(rules_seen.values()),
                }
            },
            "results": sarif_results,
        }],
    }

def process_file(filepath: Path, args: argparse.Namespace, excluded_lines: set[int]) -> FileResult:
    try:
        source = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return FileResult(filepath, 0, CleaningStats(), [], [], False, "", "", str(exc))
    try:
        ast.parse(source, filename=str(filepath))
    except SyntaxError as exc:
        return FileResult(filepath, 0, CleaningStats(), [], [], False, source, source, f"Syntax error: {exc}")
    original_lines = source.splitlines(True)
    analyzer = SourceAnalyzer(source, str(filepath))
    analysis = analyzer.analyze()
    if args.fix_only:
        analysis.warnings = []
    else:
        analysis.warnings = _filter_warnings(analysis.warnings, args.select, args.ignore, excluded_lines)
    if args.warn_only:
        cleaned_lines, stats, import_details = list(original_lines), CleaningStats(), []
    else:
        cleaner = SourceCleaner(original_lines, analysis, aggressive=args.aggressive, excluded_lines=excluded_lines)
        cleaned_lines, stats, import_details = cleaner.clean()
    cleaned_source = "".join(cleaned_lines)
    return FileResult(filepath, len(original_lines), stats, analysis.warnings, import_details, cleaned_source != source, source, cleaned_source)

def _process_file_worker(payload: tuple[str, dict, list[int]]) -> FileResult:
    filepath_str, args_dict, excluded_list = payload
    args = argparse.Namespace(**args_dict)
    return process_file(Path(filepath_str), args, set(excluded_list))

# ─── CLI ──────────────────────────────────────────────────────────────────────
def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pystreamliner",
        description="PyStreamliner - conservative zero-dependency Python cleaner. Supports multi-file, parallel, config, path excludes, and optional --project cross-file unused suppression.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("paths", nargs="*", default=[], help="Files or directories to clean")
    parser.add_argument("-d", "--dry-run", action="store_true")
    parser.add_argument("-b", "--backup", action="store_true")
    parser.add_argument("-v", "--diff", action="store_true")
    parser.add_argument("-n", "--no-color", action="store_true")
    parser.add_argument("-w", "--warn-only", action="store_true")
    parser.add_argument("-c", "--check", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON summary")
    parser.add_argument("--sarif", action="store_true", help="Emit SARIF 2.1.0 report (stdout)")
    parser.add_argument("--fix-only", action="store_true")
    parser.add_argument("--aggressive", action="store_true")
    parser.add_argument("--stdin", action="store_true")
    parser.add_argument("--select", type=str, default=None)
    parser.add_argument("--ignore", type=str, default=None)
    parser.add_argument("--exclude", type=str, default=None, help="Line numbers/ranges to skip")
    parser.add_argument("--exclude-path", action="append", default=[], dest="exclude_paths",
                        help="Glob patterns to exclude (repeatable). Also settable in config.")
    parser.add_argument("--summary-threshold", type=int, default=None)
    parser.add_argument("-j", "--jobs", type=int, default=None,
                        help="Parallel workers. Default 1. Use 0 for auto (capped).")
    parser.add_argument("--cache", action="store_true",
                        help="Skip files unchanged since last run (mtime+size cache).")
    parser.add_argument("--cache-file", type=str, default=None,
                        help=f"Cache file path (default: ./{CACHE_FILENAME})")
    parser.add_argument("--threads", action="store_true",
                        help="Use threads instead of processes when jobs > 1 (lower overhead).")
    parser.add_argument("--project", action="store_true",
                        help="Best-effort cross-file unused function/class suppression (name-based, zero extra deps).")
    return parser

def main() -> int:
    parser = _build_argument_parser()
    args = parser.parse_args()

    cfg = _load_config()
    if args.summary_threshold is None:
        args.summary_threshold = int(cfg.get("summary_threshold", SUMMARY_THRESHOLD))
    if args.jobs is None:
        args.jobs = int(cfg.get("jobs", DEFAULT_JOBS))
    if not args.aggressive and cfg.get("aggressive"):
        args.aggressive = True
    if not args.fix_only and cfg.get("fix_only"):
        args.fix_only = True
    if not args.warn_only and cfg.get("warn_only"):
        args.warn_only = True
    if args.select is None and cfg.get("select"):
        args.select = cfg["select"] if isinstance(cfg["select"], str) else ",".join(cfg["select"])
    if args.ignore is None and cfg.get("ignore"):
        args.ignore = cfg["ignore"] if isinstance(cfg["ignore"], str) else ",".join(cfg["ignore"])
    if not args.cache and cfg.get("cache"):
        args.cache = True
    if args.cache_file is None and cfg.get("cache_file"):
        args.cache_file = str(cfg["cache_file"])
    if not args.project and cfg.get("project"):
        args.project = True

    exclude_globs: list[str] = list(args.exclude_paths or [])
    cfg_exclude = cfg.get("exclude") or []
    if isinstance(cfg_exclude, str):
        cfg_exclude = [cfg_exclude]
    for g in cfg_exclude:
        if g not in exclude_globs:
            exclude_globs.append(g)

    use_color = not args.no_color
    excluded_lines = _parse_exclude(args.exclude)

    if args.stdin:
        source = sys.stdin.read()
        try:
            ast.parse(source)
        except SyntaxError as exc:
            sys.stderr.write(f"Syntax error: {exc}\n")
            return 1
        original_lines = source.splitlines(True)
        analyzer = SourceAnalyzer(source, "<stdin>")
        analysis = analyzer.analyze()
        if args.fix_only:
            analysis.warnings = []
        else:
            analysis.warnings = _filter_warnings(analysis.warnings, args.select, args.ignore, excluded_lines)
        if args.warn_only:
            cleaned_lines, stats = list(original_lines), CleaningStats()
        else:
            cleaner = SourceCleaner(original_lines, analysis, aggressive=args.aggressive, excluded_lines=excluded_lines)
            cleaned_lines, stats, _ = cleaner.clean()
        if not args.json:
            sys.stdout.write("".join(cleaned_lines))
        return 0

    if not args.paths:
        parser.error("paths required (or use --stdin)")

    paths = [Path(p) for p in args.paths]
    files = _collect_python_files(paths, exclude_globs=exclude_globs)
    if not files:
        sys.stderr.write("No Python files found.\n")
        return 1

    project_refs: dict[str, set[str]] = {}
    if args.project and len(files) >= 2:
        project_refs = _index_project_refs(files)

    cache_path = Path(args.cache_file) if args.cache_file else Path(CACHE_FILENAME)
    cache: dict[str, str] = {}
    skipped: list[Path] = []
    if args.cache and not args.check:
        cache = _load_cache(cache_path)
        files, skipped = _filter_cached_files(files, cache)
        if skipped and not args.quiet and not args.json and not args.sarif:
            sys.stderr.write(f"Cache: skipped {len(skipped)} unchanged file(s)\n")

    if args.jobs < 0:
        max_workers = 1
    elif args.jobs == 0:
        max_workers = min(AUTO_JOBS_CAP, max(1, os.cpu_count() or 2))
    else:
        max_workers = max(1, args.jobs)

    args_dict = {
        "fix_only": args.fix_only, "select": args.select, "ignore": args.ignore,
        "warn_only": args.warn_only, "aggressive": args.aggressive,
        "dry_run": args.dry_run, "backup": args.backup, "diff": args.diff,
        "no_color": args.no_color, "check": args.check, "quiet": args.quiet,
        "json": args.json, "sarif": args.sarif, "summary_threshold": args.summary_threshold,
    }
    excluded_list = sorted(excluded_lines)
    results: list[FileResult] = []

    if not files:
        results = []
    elif max_workers == 1 or len(files) <= 1:
        for fp in files:
            results.append(process_file(fp, args, excluded_lines))
    else:
        payloads = [(str(fp), args_dict, excluded_list) for fp in files]
        Executor = ThreadPoolExecutor if args.threads else ProcessPoolExecutor
        with Executor(max_workers=max_workers) as executor:
            futures = {executor.submit(_process_file_worker, p): p[0] for p in payloads}
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as exc:
                    results.append(FileResult(Path(futures[fut]), 0, CleaningStats(), [], [], False, "", "", str(exc)))

    results.sort(key=lambda r: str(r.path))

    if args.project and project_refs:
        _apply_project_unused(results, project_refs)

    for result in results:
        if result.error is None and result.had_changes and not args.dry_run and not args.warn_only:
            if args.backup:
                try:
                    shutil.copy2(str(result.path), str(result.path) + ".bak")
                except OSError:
                    pass
            try:
                result.path.write_text(result.cleaned_source, encoding="utf-8")
            except OSError as exc:
                result.error = str(exc)

    if args.cache and not args.dry_run:
        for r in results:
            if r.error is None:
                key = str(r.path.resolve())
                cache[key] = _file_fingerprint(r.path)
        for p in skipped:
            key = str(p.resolve())
            cache[key] = _file_fingerprint(p)
        _save_cache(cache_path, cache)

    if args.sarif:
        print(json.dumps(build_sarif(results), indent=2))
    elif args.json:
        print(json.dumps([{
            "file": str(r.path), "lines_analyzed": r.lines_analyzed, "error": r.error,
            "had_changes": r.had_changes,
            "stats": {"unused_imports_removed": r.stats.unused_imports_removed,
                      "duplicate_lines_removed": r.stats.duplicate_lines_removed,
                      "blank_lines_reduced": r.stats.blank_lines_reduced},
            "warnings": [{"category": w.category, "name": w.name, "lineno": w.lineno, "message": w.message} for w in r.warnings],
            "import_details": [{"lineno": d.lineno, "text": d.text} for d in r.import_details],
        } for r in results], indent=2))
    elif not args.quiet:
        if len(results) + len(skipped) >= args.summary_threshold:
            print_summary(results, use_color=use_color)
            if skipped and not args.quiet:
                print(f" (cache skipped {len(skipped)} unchanged)")
        else:
            for r in results:
                if r.error:
                    sys.stderr.write(f"Error in {r.path}: {r.error}\n")
                    continue
                ReportPrinter(str(r.path), r.lines_analyzed, r.stats, r.warnings, r.import_details, use_color).print_report()

    if args.check:
        for r in results:
            if r.error or r.had_changes or r.warnings:
                return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
