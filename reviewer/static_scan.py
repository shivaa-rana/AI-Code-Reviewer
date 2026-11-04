from __future__ import annotations

import json
import shutil
from functools import lru_cache
import subprocess
from pathlib import Path

from .models import Finding

SCANNER_TIMEOUT_SECONDS = 60


IMPORT_ONLY_RULES = {f"B{number}" for number in range(403, 416)}


@lru_cache(maxsize=512)
def _read_lines(file_path: Path) -> tuple[str, ...]:
        try:
                return tuple(file_path.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
                return ()


def _is_test_path(file_path: str) -> bool:
        parts = [part.lower() for part in Path(file_path).parts]
        name = parts[-1] if parts else ""
        return (
                any(part in {"test", "tests", "testing"} for part in parts[:-1])
                or name.startswith("test_")
                or name.endswith("_test.py")
                or name == "conftest.py"
        )


def _is_noise(finding: Finding) -> bool:
        if finding.source != "bandit":
                return False
        if finding.rule_id in IMPORT_ONLY_RULES:
                return True
        return _is_test_path(finding.file_path) and finding.severity == "low"


def _snippet(file_path: Path, line: int, root: Path) -> str:
	try:
		lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
	except OSError:
		return ""
	start = max(0, line - 4)
	end = min(len(lines), line + 3)
	return "\n".join(f"{index + 1}: {lines[index]}" for index in range(start, end))


def _run_scanner(command: list[str], cwd: Path, name: str) -> str:
	try:
		result = subprocess.run(
			command,
			cwd=cwd,
			capture_output=True,
			text=True,
			timeout=SCANNER_TIMEOUT_SECONDS,
			check=False,
		)
	except subprocess.TimeoutExpired as error:
		raise RuntimeError(f"{name} scan timed out after {SCANNER_TIMEOUT_SECONDS} seconds.") from error
	except OSError as error:
		raise RuntimeError(f"Could not start {name}: {error}") from error
	if result.returncode not in (0, 1):
		details = result.stderr.strip() or result.stdout.strip() or "unknown scanner error"
		raise RuntimeError(f"{name} failed: {details[:500]}")
	return result.stdout


def _relative_path(raw_path: str, root: Path) -> Path:
	path = Path(raw_path)
	absolute_path = path if path.is_absolute() else root / path
	try:
		return absolute_path.resolve().relative_to(root.resolve())
	except ValueError:
		return Path("outside-repository.py")


def scan_repository(root: Path, python_files: list[Path]) -> list[Finding]:
	if not python_files:
		return []
	root = root.resolve()
	relative_files: list[str] = []
	for path in python_files:
		try:
			relative = path.resolve().relative_to(root)
		except ValueError as error:
			raise ValueError("Scanner inputs must remain inside the cloned repository.") from error
		if relative.suffix.lower() == ".py":
			relative_files.append("./" + relative.as_posix())
	if not relative_files:
		return []

	bandit = shutil.which("bandit")
	ruff = shutil.which("ruff")
	if not bandit or not ruff:
		missing = ", ".join(name for name, path in (("Bandit", bandit), ("Ruff", ruff)) if not path)
		raise RuntimeError(f"Required scanner executable(s) not found: {missing}. Install requirements.txt.")

	findings: list[Finding] = []
	bandit_output = _run_scanner([bandit, "-q", "-f", "json", *relative_files], root, "Bandit")
	try:
		bandit_results = json.loads(bandit_output).get("results", [])
	except (json.JSONDecodeError, AttributeError) as error:
		raise RuntimeError("Bandit returned invalid JSON output.") from error
	for result in bandit_results:
		location = result.get("filename", "")
		relative = _relative_path(location, root)
		line = max(1, int(result.get("line_number") or 1))
		source_path = root / relative
		severity = str(result.get("issue_severity", "LOW")).lower()
		findings.append(
			Finding(
				id=f"bandit:{result.get('test_id', 'unknown')}:{relative}:{line}",
				title=str(result.get("issue_text", "Security finding")),
				message=str(result.get("issue_text", "")),
				category="security",
				severity=severity if severity in {"critical", "high", "medium", "low", "info"} else "low",
				rule_id=str(result.get("test_id", "BANDIT")),
				source="bandit",
				file_path=relative.as_posix(),
				line=line,
				column=max(1, int(result.get("col_offset") or 1)),
				code_snippet=_snippet(source_path, line, root),
			)
		)

	ruff_output = _run_scanner(
		[
			ruff,
			"check",
			"--isolated",
			"--select",
			"E,F,B,UP",
			"--output-format",
			"json",
			*relative_files,
		],
		root,
		"Ruff",
	)
	try:
		ruff_results = json.loads(ruff_output)
	except json.JSONDecodeError as error:
		raise RuntimeError("Ruff returned invalid JSON output.") from error
	for result in ruff_results:
		location = result.get("location") or {}
		relative = _relative_path(result.get("filename", ""), root)
		line = max(1, int(location.get("row") or 1))
		column = max(1, int(location.get("column") or 1))
		code = str(result.get("code") or "RUFF")
		category = "bug" if code.startswith(("B", "F")) else "style"
		findings.append(
			Finding(
				id=f"ruff:{code}:{relative}:{line}:{column}",
				title=str(result.get("message", "Ruff finding")),
				message=str(result.get("message", "")),
				category=category,
				severity="medium" if category == "bug" else "low",
				rule_id=code,
				source="ruff",
				file_path=relative.as_posix(),
				line=line,
				column=column,
				code_snippet=_snippet(root / relative, line, root),
			)
		)
	severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	category_order = {"security": 0, "bug": 1, "style": 2}
	return sorted(
		findings,
		key=lambda finding: (
			severity_order[finding.severity],
			category_order[finding.category],
			finding.file_path,
			finding.line,
			finding.id,
		),
	)
