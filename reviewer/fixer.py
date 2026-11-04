from __future__ import annotations

import ast
import difflib
import tempfile
from pathlib import Path

from .models import Finding
from .static_scan import scan_repository

MAX_FIX_LINES = 80


def function_context(path: Path, line: int, radius: int = 10) -> tuple[int, int, str]:
	"""Return (start, end, source) of the function enclosing `line`, else a +/- radius window."""
	try:
		text = path.read_text(encoding="utf-8", errors="replace")
	except OSError:
		return line, line, ""
	lines = text.splitlines()
	start, end = max(1, line - radius), min(len(lines), line + radius)
	try:
		tree = ast.parse(text)
		best: ast.AST | None = None
		for node in ast.walk(tree):
			if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
				node_end = getattr(node, "end_lineno", None) or node.lineno
				if node.lineno <= line <= node_end and node_end - node.lineno + 1 <= MAX_FIX_LINES:
					if best is None or node.lineno > best.lineno:
						best = node
		if best is not None:
			start, end = best.lineno, getattr(best, "end_lineno", None) or best.lineno
	except SyntaxError:
		pass
	return start, end, "\n".join(lines[start - 1 : end])


def _rule_counts(findings: list[Finding]) -> dict[str, int]:
	counts: dict[str, int] = {}
	for finding in findings:
		counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
	return counts


def verify_patch(
	root: Path, finding: Finding, start: int, end: int, fixed_code: str, baseline: dict[str, int] | None = None
) -> tuple[str, bool, str]:
	"""Apply an LLM-proposed patch to a copy of the file and re-run the scanners on it.

	Returns (unified_diff, verified, note). A patch is verified only if it still parses, removes at
	least one occurrence of the targeted rule, and introduces no additional findings for any rule.
	"""
	source_path = root / finding.file_path
	try:
		original = source_path.read_text(encoding="utf-8", errors="replace")
	except OSError:
		return "", False, "Source file could not be read."
	lines = original.splitlines()
	if not 1 <= start <= end <= len(lines):
		return "", False, "Patch range is outside the file."
	patched_lines = lines[: start - 1] + fixed_code.rstrip("\n").splitlines() + lines[end:]
	patched = "\n".join(patched_lines) + "\n"
	diff = "".join(
		difflib.unified_diff(
			[line + "\n" for line in lines],
			[line + "\n" for line in patched_lines],
			fromfile=f"a/{finding.file_path}",
			tofile=f"b/{finding.file_path}",
			n=2,
		)
	)
	if not diff:
		return "", False, "The proposed fix did not change the code."
	try:
		ast.parse(patched)
	except SyntaxError as error:
		return diff, False, f"Patched file does not parse: {error.msg} (line {error.lineno})."
	try:
		with tempfile.TemporaryDirectory(prefix="ai-code-review-fix-") as directory:
			workdir = Path(directory)
			target = workdir / Path(finding.file_path).name
			if baseline is None:
				target.write_text(original, encoding="utf-8")
				baseline = _rule_counts(scan_repository(workdir, [target]))
			target.write_text(patched, encoding="utf-8")
			after = _rule_counts(scan_repository(workdir, [target]))
	except (RuntimeError, ValueError, OSError) as error:
		return diff, False, f"Could not re-scan the patched file: {str(error)[:200]}"
	if after.get(finding.rule_id, 0) >= baseline.get(finding.rule_id, 0):
		return diff, False, f"Re-scan still reports {finding.rule_id}."
	regressions = [rule for rule, count in after.items() if count > baseline.get(rule, 0)]
	if regressions:
		return diff, False, f"Patch introduces new findings: {', '.join(sorted(regressions))}."
	return diff, True, f"Re-scan with Bandit, Ruff and the secret scanner no longer reports {finding.rule_id}."


def baseline_for(root: Path, file_path: str) -> dict[str, int]:
	try:
		with tempfile.TemporaryDirectory(prefix="ai-code-review-base-") as directory:
			target = Path(directory) / Path(file_path).name
			target.write_text((root / file_path).read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
			return _rule_counts(scan_repository(Path(directory), [target]))
	except (RuntimeError, ValueError, OSError):
		return {}
