#!/usr/bin/env python3
"""PyStreamliner — A conservative, single-file, command-line Python source code cleaner.

Two-tier model:
  Tier 1 (Auto-fix):  Provably safe modifications only.
  Tier 2 (Warn-only): Detection + report, zero modification.
"""
from __future__ import annotations

import argparse
import ast
import copy
import dataclasses
import difflib
import re
import shutil
import sys
import textwrap
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

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

VAGUE_NAMES: FrozenSet[str] = frozenset({
    "x", "y", "z", "temp", "tmp", "foo", "bar", "baz",
    "a", "b", "c", "d", "e", "f",
})


# ─── Data Structures ─────────────────────────────────────────────────────────

@dataclasses.dataclass
class ImportFinding:
    """A single import statement with usage information."""

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
    """A Tier 2 warning for manual review."""

    category: str
    name: str
    lineno: int
    message: str


@dataclasses.dataclass
class AnalysisResult:
    """Complete analysis output."""

    unused_imports: List[ImportFinding]
    warnings: List[Warning]
    all_names_in_all: Set[str]


@dataclasses.dataclass
class CleaningStats:
    """Counts of auto-fix actions taken."""

    unused_imports_removed: int = 0
    duplicate_lines_removed: int = 0
    blank_lines_reduced: int = 0


@dataclasses.dataclass
class ImportDetail:
    """Detail line for the report."""

    lineno: int
    text: str


# ─── AST Parent Map Builder ──────────────────────────────────────────────────

def _build_parent_map(tree: ast.AST) -> Dict[int, ast.AST]:
    """Build a mapping from id(child) -> parent node for the entire AST.

    This allows reliable parent-tracking instead of fragile line-number
    matching when determining whether a node lives inside a comprehension,
    lambda, or other construct.
    """
    parent_map: Dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent_map[id(child)] = node
    return parent_map


# ─── SourceAnalyzer ───────────────────────────────────────────────────────────

class SourceAnalyzer:
    """Analyzes Python source code for issues without modifying it."""

    def __init__(self, source: str, filename: str) -> None:
        """Initialize the analyzer with source text and a filename for diagnostics."""
        self._source = source
        self._filename = filename
        self._tree = ast.parse(source, filename=filename)
        self._lines = source.splitlines(True)
        self._used_names: Optional[Set[str]] = None
        self._all_names: Set[str] = set()
        self._parent_map: Dict[int, ast.AST] = _build_parent_map(self._tree)
        self._type_checking_import_names: Set[str] = set()

    def analyze(self) -> AnalysisResult:
        """Run all analysis passes and return combined results."""
        self._collect_type_checking_imports()
        self._used_names = self._collect_all_used_names()
        self._collect_all_list_names()

        unused_imports = self._find_unused_imports()
        warnings: List[Warning] = []
        warnings.extend(self._find_unused_variables())
        warnings.extend(self._find_unused_functions())
        warnings.extend(self._find_vague_names())
        warnings.extend(self._find_shadowed_builtins())

        return AnalysisResult(
            unused_imports=unused_imports,
            warnings=warnings,
            all_names_in_all=self._all_names,
        )

    # ── Name collection helpers ───────────────────────────────────────────

    def _collect_type_checking_imports(self) -> None:
        """Identify import names inside ``if TYPE_CHECKING:`` blocks.

        These imports exist only for static analysis tooling and must never be
        flagged as unused at runtime.
        """
        for node in ast.walk(self._tree):
            if not isinstance(node, ast.If):
                continue
            # Match both ``if TYPE_CHECKING:`` and ``if typing.TYPE_CHECKING:``
            test = node.test
            is_tc = False
            if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
                is_tc = True
            elif isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING":
                is_tc = True
            if not is_tc:
                continue
            for child in ast.walk(node):
                if isinstance(child, ast.Import):
                    for alias in child.names:
                        bound = alias.asname if alias.asname else alias.name.split(".")[0]
                        self._type_checking_import_names.add(bound)
                elif isinstance(child, ast.ImportFrom):
                    for alias in child.names:
                        bound = alias.asname if alias.asname else alias.name
                        self._type_checking_import_names.add(bound)

    def _collect_all_used_names(self) -> Set[str]:
        """Collect every name referenced in Load context across the entire AST.

        Also collects names used as type annotations (string or otherwise) so
        that variables used exclusively in type hints are not false-positived.
        """
        names: Set[str] = set()
        for node in ast.walk(self._tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                val = node.value
                if isinstance(val, ast.Name):
                    names.add(val.id)
            # Capture string-form annotations (e.g. ``x: "SomeType"``).
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                # Only consider it a name reference if it looks like a valid
                # Python identifier (avoids matching arbitrary strings).
                candidate = node.value.strip()
                if candidate.isidentifier():
                    names.add(candidate)
        return names

    def _collect_all_list_names(self) -> None:
        """Collect string literals inside __all__ assignments."""
        for node in ast.walk(self._tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not (isinstance(target, ast.Name) and target.id == "__all__"):
                    continue
                if not isinstance(node.value, (ast.List, ast.Tuple)):
                    continue
                for elt in node.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        self._all_names.add(elt.value)

    # ── Unused imports ────────────────────────────────────────────────────

    def _find_unused_imports(self) -> List[ImportFinding]:
        """Detect imports whose bound names are never referenced."""
        assert self._used_names is not None
        findings: List[ImportFinding] = []

        for node in ast.iter_child_nodes(self._tree):
            # Skip imports guarded by ``if TYPE_CHECKING:``
            if self._is_inside_type_checking_block(node):
                continue
            if isinstance(node, ast.Import):
                findings.extend(self._check_import(node))
            elif isinstance(node, ast.ImportFrom):
                result = self._check_from_import(node)
                if result is not None:
                    findings.append(result)

        return findings

    def _is_inside_type_checking_block(self, target: ast.AST) -> bool:
        """Return True if *target* lives inside an ``if TYPE_CHECKING:`` guard."""
        for node in ast.walk(self._tree):
            if not isinstance(node, ast.If):
                continue
            test = node.test
            is_tc = False
            if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
                is_tc = True
            elif isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING":
                is_tc = True
            if not is_tc:
                continue
            for child in ast.walk(node):
                if child is target:
                    return True
        return False

    def _check_import(self, node: ast.Import) -> List[ImportFinding]:
        """Check a plain 'import x' statement."""
        assert self._used_names is not None
        findings: List[ImportFinding] = []
        line_text = self._get_line_text(node.lineno)
        indent = self._get_indent(line_text)
        end_lineno = getattr(node, "end_lineno", node.lineno) or node.lineno

        for alias in node.names:
            bound = alias.asname if alias.asname else alias.name.split(".")[0]
            if bound in self._used_names or bound in self._all_names:
                continue
            findings.append(ImportFinding(
                lineno=node.lineno,
                end_lineno=end_lineno,
                original_text=line_text.rstrip(),
                bound_names=[bound],
                unused_names=[bound],
                used_names=[],
                is_from_import=False,
                indent=indent,
            ))

        return findings

    def _check_from_import(self, node: ast.ImportFrom) -> Optional[ImportFinding]:
        """Check a 'from x import y' statement (including multiline)."""
        assert self._used_names is not None

        if node.module and node.module == "__future__":
            return None

        if any(alias.name == "*" for alias in node.names):
            return None

        line_text = self._get_line_text(node.lineno)
        indent = self._get_indent(line_text)
        end_lineno = getattr(node, "end_lineno", node.lineno) or node.lineno

        # Build the full original text for multiline imports
        if end_lineno > node.lineno:
            original_lines = self._lines[node.lineno - 1:end_lineno]
            original_text = "".join(original_lines).rstrip()
        else:
            original_text = line_text.rstrip()

        bound_names: List[str] = []
        unused: List[str] = []
        used: List[str] = []

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
            lineno=node.lineno,
            end_lineno=end_lineno,
            original_text=original_text,
            bound_names=bound_names,
            unused_names=unused,
            used_names=used,
            is_from_import=True,
            indent=indent,
            module=node.module,
        )

    # ── Unused variables ──────────────────────────────────────────────────

    def _find_unused_variables(self) -> List[Warning]:
        """Detect variables assigned but never read.

        Skips variables that appear only in type annotations (AnnAssign with
        no value) because those are declarations, not real assignments.
        """
        assert self._used_names is not None
        warnings: List[Warning] = []
        assigned = self._collect_assigned_names()

        for name, lineno in assigned:
            if name == "_":
                continue
            if name.startswith("__") and name.endswith("__"):
                continue
            if name in self._all_names:
                continue
            if name in self._used_names:
                continue
            warnings.append(Warning(
                category="unused_variable",
                name=name,
                lineno=lineno,
                message=f"\u26a0 Unused variable '{name}' at line {lineno}",
            ))

        return warnings

    def _collect_assigned_names(self) -> List[Tuple[str, int]]:
        """Collect all variable assignment targets with line numbers.

        Annotation-only declarations (``x: int`` with no value) are excluded
        because the name is not actually bound to a runtime value.
        """
        assigned: List[Tuple[str, int]] = []

        for node in ast.walk(self._tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    self._extract_names_from_target(target, assigned)
            elif isinstance(node, ast.AnnAssign):
                # Only include annotated assignments that actually have a value
                # (``x: int = 5``).  Pure annotations (``x: int``) are
                # declarations, not assignments.
                if node.value is not None and node.target is not None:
                    self._extract_names_from_target(node.target, assigned)
            elif isinstance(node, ast.For):
                self._extract_names_from_target(node.target, assigned)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars:
                        self._extract_names_from_target(item.optional_vars, assigned)
            elif isinstance(node, ast.NamedExpr):
                self._extract_names_from_target(node.target, assigned)

        return assigned

    def _extract_names_from_target(
        self,
        target: ast.expr,
        result: List[Tuple[str, int]],
    ) -> None:
        """Recursively extract name targets from assignment LHS."""
        if isinstance(target, ast.Name) and isinstance(target.ctx, ast.Store):
            result.append((target.id, target.lineno))
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._extract_names_from_target(elt, result)

    # ── Unused functions ──────────────────────────────────────────────────

    def _find_unused_functions(self) -> List[Warning]:
        """Detect top-level and class-level functions that are never called.

        Class methods (except those exempted by naming convention or decorators)
        and nested functions are now also checked.
        """
        assert self._used_names is not None
        warnings: List[Warning] = []

        # Collect all function / method definitions across the tree
        func_nodes: List[Tuple[ast.AST, bool]] = []  # (node, is_method)

        for node in ast.walk(self._tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # Determine if this is a method inside a class body
            parent = self._parent_map.get(id(node))
            is_method = isinstance(parent, ast.ClassDef)

            func_nodes.append((node, is_method))

        for func_node, is_method in func_nodes:
            assert isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef))
            name = func_node.name

            # Always skip ``main``
            if name == "main":
                continue

            # Skip decorated functions/methods — decorators can register them
            if func_node.decorator_list:
                continue

            # Skip dunder methods
            if name.startswith("__") and name.endswith("__"):
                continue

            # Skip names referenced elsewhere
            if name in self._used_names or name in self._all_names:
                continue

            # For methods, skip common interface names that are expected by
            # frameworks / protocols but may not be explicitly called in the
            # same file (setUp, tearDown, etc.).
            if is_method and name.startswith("_") and not name.startswith("__"):
                # Private methods are fair game for a warning
                pass

            # Functions inside ``if __name__ == "__main__":`` are entry-points
            if self._is_inside_name_main_block(func_node):
                continue

            kind = "method" if is_method else "function"
            warnings.append(Warning(
                category="unused_function",
                name=name,
                lineno=func_node.lineno,
                message=f"\u26a0 Unused {kind} '{name}()' at line {func_node.lineno}",
            ))

        return warnings

    def _is_inside_name_main_block(self, node: ast.AST) -> bool:
        """Check if a node is inside an 'if __name__ == ...' block."""
        for top_node in ast.iter_child_nodes(self._tree):
            if not isinstance(top_node, ast.If):
                continue
            test = top_node.test
            if not isinstance(test, ast.Compare):
                continue
            if not isinstance(test.left, ast.Name):
                continue
            if test.left.id != "__name__":
                continue
            for child in ast.walk(top_node):
                if child is node:
                    return True
        return False

    # ── Vague names ───────────────────────────────────────────────────────

    def _find_vague_names(self) -> List[Warning]:
        """Detect vague or single-letter variable names."""
        warnings: List[Warning] = []
        assigned = self._collect_assigned_names()
        seen: Set[Tuple[str, int]] = set()

        for name, lineno in assigned:
            if (name, lineno) in seen:
                continue
            seen.add((name, lineno))

            if self._is_in_comprehension_or_lambda(name, lineno):
                continue

            if name.lower() in VAGUE_NAMES:
                warnings.append(Warning(
                    category="vague_name",
                    name=name,
                    lineno=lineno,
                    message=f"\u26a0 Vague variable name '{name}' at line {lineno}",
                ))

        return warnings

    def _is_in_comprehension_or_lambda(self, name: str, lineno: int) -> bool:
        """Check whether an assignment target lives inside a comprehension or lambda.

        Uses the AST parent map for reliable detection instead of fragile
        line-number matching.
        """
        comp_types = (ast.ListComp, ast.SetComp, ast.DictComp,
                      ast.GeneratorExp, ast.Lambda)
        for node in ast.walk(self._tree):
            if not isinstance(node, ast.Name):
                continue
            if node.id != name or node.lineno != lineno:
                continue
            if not isinstance(node.ctx, ast.Store):
                continue
            # Walk up the parent chain looking for a comprehension / lambda
            current: ast.AST = node
            while True:
                parent = self._parent_map.get(id(current))
                if parent is None:
                    break
                if isinstance(parent, comp_types):
                    return True
                current = parent
        return False

    # ── Shadowed builtins (new Tier 2 rule) ───────────────────────────────

    def _find_shadowed_builtins(self) -> List[Warning]:
        """Detect assignments that shadow Python built-in names.

        Only a conservative subset of commonly-shadowed builtins is checked to
        avoid excessive noise.
        """
        SHADOWED_BUILTINS: FrozenSet[str] = frozenset({
            "id", "type", "list", "dict", "set", "tuple", "str", "int",
            "float", "bool", "input", "open", "range", "len", "map",
            "filter", "sum", "min", "max", "next", "iter", "hash",
            "format", "print", "object", "bytes", "complex", "frozenset",
            "property", "staticmethod", "classmethod", "super",
        })
        warnings: List[Warning] = []
        assigned = self._collect_assigned_names()
        seen: Set[Tuple[str, int]] = set()

        for name, lineno in assigned:
            if (name, lineno) in seen:
                continue
            seen.add((name, lineno))
            if name in SHADOWED_BUILTINS:
                warnings.append(Warning(
                    category="shadowed_builtin",
                    name=name,
                    lineno=lineno,
                    message=f"\u26a0 Variable '{name}' shadows a built-in at line {lineno}",
                ))

        return warnings

    # ── Helpers ────────────────────────────────────────────────────────────

    def _get_line_text(self, lineno: int) -> str:
        """Get the original source line by 1-based line number."""
        if lineno < 1 or lineno > len(self._lines):
            return ""
        return self._lines[lineno - 1]

    @staticmethod
    def _get_indent(line: str) -> str:
        """Extract leading whitespace from a line."""
        match = re.match(r"^(\s*)", line)
        return match.group(1) if match else ""


# ─── SourceCleaner ────────────────────────────────────────────────────────────

class SourceCleaner:
    """Applies Tier 1 auto-fixes to source lines."""

    def __init__(self, lines: List[str], analysis: AnalysisResult) -> None:
        """Initialize the cleaner with source lines and analysis results."""
        self._lines = list(lines)
        self._analysis = analysis
        self._stats = CleaningStats()
        self._import_details: List[ImportDetail] = []

    def clean(self) -> Tuple[List[str], CleaningStats, List[ImportDetail]]:
        """Apply all auto-fixes and return cleaned lines with stats."""
        self._remove_unused_imports()
        self._remove_duplicate_lines()
        self._reduce_blank_lines()
        self._ensure_trailing_newline()
        return self._lines, self._stats, self._import_details

    def _remove_unused_imports(self) -> None:
        """Remove or trim unused import statements (including multiline)."""
        lines_to_remove: Set[int] = set()
        line_replacements: Dict[int, str] = {}
        # For multiline imports we may need to remove a range of lines
        range_removals: List[Tuple[int, int]] = []  # (start_idx, end_idx) inclusive

        for imp in self._analysis.unused_imports:
            start_idx = imp.lineno - 1
            end_idx = imp.end_lineno - 1
            if start_idx < 0 or end_idx >= len(self._lines):
                continue

            is_multiline = end_idx > start_idx

            if not imp.used_names:
                # Remove the entire import (possibly spanning multiple lines)
                if is_multiline:
                    range_removals.append((start_idx, end_idx))
                else:
                    lines_to_remove.add(start_idx)
                self._import_details.append(ImportDetail(
                    lineno=imp.lineno,
                    text=imp.original_text.strip(),
                ))
                self._stats.unused_imports_removed += len(imp.unused_names)
            elif imp.is_from_import:
                # Partially clean — keep only the used names
                module = imp.module or ""
                new_line = f"{imp.indent}from {module} import {', '.join(imp.used_names)}"

                # Preserve the line ending of the *last* line of the import
                last_line = self._lines[end_idx]
                if last_line.endswith("\r\n"):
                    new_line += "\r\n"
                elif last_line.endswith("\n"):
                    new_line += "\n"

                if is_multiline:
                    # Replace start line, remove the rest
                    line_replacements[start_idx] = new_line
                    for idx in range(start_idx + 1, end_idx + 1):
                        lines_to_remove.add(idx)
                else:
                    line_replacements[start_idx] = new_line

                kept = ", ".join(f"'{n}'" for n in imp.used_names)
                self._import_details.append(ImportDetail(
                    lineno=imp.lineno,
                    text=f"{imp.original_text.strip()}  (partially cleaned: kept {kept})",
                ))
                self._stats.unused_imports_removed += len(imp.unused_names)

        # Expand range removals into individual line indices
        for start_idx, end_idx in range_removals:
            for idx in range(start_idx, end_idx + 1):
                lines_to_remove.add(idx)

        new_lines: List[str] = []
        for idx, line in enumerate(self._lines):
            if idx in lines_to_remove:
                continue
            if idx in line_replacements:
                new_lines.append(line_replacements[idx])
            else:
                new_lines.append(line)

        self._lines = new_lines

    def _remove_duplicate_lines(self) -> None:
        """Remove consecutive exact duplicate non-blank lines."""
        if not self._lines:
            return

        result: List[str] = [self._lines[0]]
        for i in range(1, len(self._lines)):
            current = self._lines[i]
            previous = self._lines[i - 1]

            # Never collapse blank lines here — that's handled by
            # ``_reduce_blank_lines``.
            if current.strip() == "":
                result.append(current)
                continue

            if current == previous:
                self._stats.duplicate_lines_removed += 1
                continue

            result.append(current)

        self._lines = result

    def _reduce_blank_lines(self) -> None:
        """Cap consecutive blank lines at MAX_CONSECUTIVE_BLANKS."""
        result: List[str] = []
        consecutive = 0

        for line in self._lines:
            if line.strip() == "":
                consecutive += 1
                if consecutive <= MAX_CONSECUTIVE_BLANKS:
                    result.append(line)
                else:
                    self._stats.blank_lines_reduced += 1
            else:
                consecutive = 0
                result.append(line)

        self._lines = result

    def _ensure_trailing_newline(self) -> None:
        """Ensure the file ends with exactly one newline."""
        if not self._lines:
            return
        last = self._lines[-1]
        if not last.endswith("\n"):
            self._lines[-1] = last + "\n"


# ─── Report Printer ──────────────────────────────────────────────────────────

class ReportPrinter:
    """Prints the structured PyStreamliner report."""

    BORDER_DOUBLE = "\u2550" * 38
    BORDER_SINGLE = "\u2500" * 38

    def __init__(
        self,
        filename: str,
        lines_analyzed: int,
        stats: CleaningStats,
        warnings: List[Warning],
        import_details: List[ImportDetail],
        use_color: bool = True,
    ) -> None:
        """Initialize the report printer."""
        self._filename = filename
        self._lines_analyzed = lines_analyzed
        self._stats = stats
        self._warnings = warnings
        self._import_details = import_details
        self._use_color = use_color

    def _c(self, code: str, text: str) -> str:
        """Wrap *text* in an ANSI color code if color output is enabled."""
        if not self._use_color:
            return text
        return f"{code}{text}{RESET}"

    def print_report(self) -> None:
        """Print the full structured report to stdout."""
        unused_vars = [w for w in self._warnings if w.category == "unused_variable"]
        unused_funcs = [w for w in self._warnings if w.category == "unused_function"]
        vague_names = [w for w in self._warnings if w.category == "vague_name"]
        shadowed = [w for w in self._warnings if w.category == "shadowed_builtin"]

        print()
        print(self._c(CYAN, self.BORDER_DOUBLE))
        print(self._c(BOLD, "  PyStreamliner Report"))
        print(self._c(CYAN, self.BORDER_DOUBLE))
        print(f"  File:  {self._c(BOLD, self._filename):>44s}")
        print(f"  Lines analyzed:  {self._lines_analyzed:>20d}")
        print()
        print(self._c(BOLD, "  Auto-fixes applied:"))
        print(f"    Unused imports removed:  {self._stats.unused_imports_removed:>10d}")
        print(f"    Duplicate lines removed: {self._stats.duplicate_lines_removed:>10d}")
        print(f"    Blank lines reduced:     {self._stats.blank_lines_reduced:>10d}")
        print()
        print(self._c(BOLD, "  Warnings (manual review needed):"))
        print(f"    Unused variables detected: {len(unused_vars):>8d}")
        print(f"    Unused functions detected: {len(unused_funcs):>8d}")
        print(f"    Vague variable names:      {len(vague_names):>8d}")
        print(f"    Shadowed built-ins:        {len(shadowed):>8d}")
        print(self._c(CYAN, self.BORDER_SINGLE))

        if self._import_details:
            print()
            print(self._c(BOLD, "  Unused imports removed:"))
            for detail in self._import_details:
                print(f"    \u2022 line {detail.lineno}:  {self._c(DIM, detail.text)}")

        if unused_vars:
            print()
            print(self._c(BOLD, "  Unused variables detected:"))
            for w in unused_vars:
                print(f"    {self._c(YELLOW, '\u26a0')} line {w.lineno}:  {w.name}")

        if unused_funcs:
            print()
            print(self._c(BOLD, "  Unused functions detected:"))
            for w in unused_funcs:
                print(f"    {self._c(YELLOW, '\u26a0')} line {w.lineno}:  {w.name}()")

        if vague_names:
            print()
            print(self._c(BOLD, "  Vague variable names:"))
            for w in vague_names:
                print(f"    {self._c(YELLOW, '\u26a0')} line {w.lineno}:  {w.name}")

        if shadowed:
            print()
            print(self._c(BOLD, "  Shadowed built-in names:"))
            for w in shadowed:
                print(f"    {self._c(YELLOW, '\u26a0')} line {w.lineno}:  {w.name}")

        print(self._c(CYAN, self.BORDER_DOUBLE))
        print()


# ─── Diff Printer ─────────────────────────────────────────────────────────────

def print_diff(
    original_lines: List[str],
    cleaned_lines: List[str],
    filename: str = "source",
    use_color: bool = True,
) -> bool:
    """Print a color-coded unified diff between original and cleaned source.

    Returns ``True`` if there were any differences, ``False`` otherwise.
    """
    diff = list(difflib.unified_diff(
        original_lines,
        cleaned_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        lineterm="",
    ))

    if not diff:
        return False

    for line in diff:
        if use_color:
            if line.startswith("+++") or line.startswith("---"):
                sys.stdout.write(f"{BOLD}{line}{RESET}\n")
            elif line.startswith("@@"):
                sys.stdout.write(f"{CYAN}{line}{RESET}\n")
            elif line.startswith("+"):
                sys.stdout.write(f"{GREEN}{line}{RESET}\n")
            elif line.startswith("-"):
                sys.stdout.write(f"{RED}{line}{RESET}\n")
            else:
                sys.stdout.write(f"{DIM}{line}{RESET}\n")
        else:
            sys.stdout.write(line + "\n")

    return True


# ─── CLI Argument Parsing ─────────────────────────────────────────────────────

def _build_argument_parser() -> argparse.ArgumentParser:
    """Construct and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="pystreamliner",
        description=(
            "PyStreamliner — A conservative, zero-dependency Python source"
            " cleaner.\n\n"
            "Tier 1 auto-fixes are applied in-place (unless --dry-run is"
            " given).\n"
            "Tier 2 issues are reported as warnings for manual review."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "file",
        type=str,
        help="Path to the Python source file to analyze / clean.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Preview changes without modifying the file.",
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        default=False,
        help="Create a .bak copy of the original file before modifying it.",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        default=False,
        help="Show a unified diff of the changes (implied by --dry-run).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI color output.",
    )
    parser.add_argument(
        "--warn-only",
        action="store_true",
        default=False,
        help="Only report warnings (Tier 2); do not apply any auto-fixes.",
    )
    return parser


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def main() -> int:
    """CLI entry point.  Returns an exit code (0 = success, 1 = error)."""
    parser = _build_argument_parser()
    args = parser.parse_args()

    filepath = Path(args.file)
    use_color: bool = not args.no_color

    if not filepath.exists():
        sys.stderr.write(f"Error: file not found: {filepath}\n")
        return 1

    if not filepath.is_file():
        sys.stderr.write(f"Error: not a regular file: {filepath}\n")
        return 1

    try:
        source = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        sys.stderr.write(f"Error reading {filepath}: {exc}\n")
        return 1

    # ── Parse check ───────────────────────────────────────────────────────
    try:
        ast.parse(source, filename=str(filepath))
    except SyntaxError as exc:
        sys.stderr.write(f"Syntax error in {filepath}: {exc}\n")
        return 1

    original_lines = source.splitlines(True)

    # ── Analysis ──────────────────────────────────────────────────────────
    analyzer = SourceAnalyzer(source, str(filepath))
    analysis = analyzer.analyze()

    # ── Cleaning ──────────────────────────────────────────────────────────
    if args.warn_only:
        cleaned_lines = list(original_lines)
        stats = CleaningStats()
        import_details: List[ImportDetail] = []
    else:
        cleaner = SourceCleaner(original_lines, analysis)
        cleaned_lines, stats, import_details = cleaner.clean()

    # ── Report ────────────────────────────────────────────────────────────
    printer = ReportPrinter(
        filename=str(filepath),
        lines_analyzed=len(original_lines),
        stats=stats,
        warnings=analysis.warnings,
        import_details=import_details,
        use_color=use_color,
    )
    printer.print_report()

    # ── Diff ──────────────────────────────────────────────────────────────
    show_diff = args.diff or args.dry_run
    if show_diff:
        had_diff = print_diff(
            [l.rstrip("\n").rstrip("\r") for l in original_lines],
            [l.rstrip("\n").rstrip("\r") for l in cleaned_lines],
            filename=str(filepath),
            use_color=use_color,
        )
        if not had_diff:
            print("No changes." if not use_color else f"{DIM}No changes.{RESET}")

    # ── Write ─────────────────────────────────────────────────────────────
    if args.dry_run or args.warn_only:
        # Don't modify the file
        return 0

    cleaned_source = "".join(cleaned_lines)
    if cleaned_source == source:
        # Nothing changed — skip writing
        return 0

    # Backup if requested
    if args.backup:
        backup_path = filepath.with_suffix(filepath.suffix + ".bak")
        try:
            shutil.copy2(str(filepath), str(backup_path))
        except OSError as exc:
            sys.stderr.write(f"Error creating backup {backup_path}: {exc}\n")
            return 1
        if use_color:
            print(f"{DIM}Backup saved to {backup_path}{RESET}")
        else:
            print(f"Backup saved to {backup_path}")

    try:
        filepath.write_text(cleaned_source, encoding="utf-8")
    except OSError as exc:
        sys.stderr.write(f"Error writing {filepath}: {exc}\n")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())


# PyStreamliner automatic backups
*.bak

    
