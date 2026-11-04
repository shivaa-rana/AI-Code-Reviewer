from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from .models import Finding

SCANNER_TIMEOUT_SECONDS = 60
MAX_SECRET_SCAN_BYTES = 1_000_000

# Import-only Bandit rules (B403-B415) only say "this module exists"; they are noise.
IMPORT_ONLY_RULES = {f"B{number}" for number in range(403, 416)}
# E501 (line length) is style noise for a security/bug oriented review.
RUFF_IGNORED = "E501"

SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
	("SEC001", "AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
	("SEC002", "GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
	("SEC003", "Groq API key", re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b")),
	("SEC004", "OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
	("SEC005", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
	("SEC006", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
	("SEC007", "Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
]


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


def _redact(text: str) -> str:
	"""Mask anything that looks like a secret so reports never leak it."""
	for _, _, pattern in SECRET_PATTERNS:
		text = pattern.sub(lambda m: m.group(0)[:4] + "*" * 8, text)
	return text


def _snippet(file_path: Path, line: int) -> str:
	try:
		lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
	except OSError:
		return ""
	start = max(0, line - 4)
	end = min(len(lines), line + 3)
	return _redact("\n".join(f"{index + 1}: {lines[index]}" for index in range(start, end)))


def _run_scanner(command: list[str], cwd: Path, name: str) -> str:
	try:
		result = subprocess.run(  # nosec B603 - fixed argument list; shell execution is not enabled
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


def _scan_secrets(root: Path, relative_files: list[str]) -> list[Finding]:
	findings: list[Finding] = []
	for relative in relative_files:
		path = root / relative
		try:
			if path.stat().st_size > MAX_SECRET_SCAN_BYTES:
				continue
			lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
		except OSError:
			continue
		for number, text in enumerate(lines, start=1):
			for rule_id, label, pattern in SECRET_PATTERNS:
				match = pattern.search(text)
				if not match:
					continue
				clean = Path(relative).as_posix().removeprefix("./")
				findings.append(
					Finding(
						id=f"secrets:{rule_id}:{clean}:{number}",
						title=f"Possible hardcoded secret: {label}",
						message=f"A value matching the {label} format is committed in source. Rotate it and load it from the environment.",
						category="security",
						severity="critical",
						rule_id=rule_id,
						source="secrets",
						file_path=clean,
						line=number,
						column=match.start() + 1,
						code_snippet=_snippet(path, number),
					)
				)
	return findings


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
		relative = _relative_path(result.get("filename", ""), root)
		line = max(1, int(result.get("line_number") or 1))
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
				code_snippet=_snippet(root / relative, line),
			)
		)

	ruff_output = _run_scanner(
		[
			ruff, "check", "--isolated", "--select", "E,F,B", "--ignore", RUFF_IGNORED,
			"--output-format", "json", *relative_files,
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
				code_snippet=_snippet(root / relative, line),
			)
		)

	findings.extend(_scan_secrets(root, relative_files))
	findings = [finding for finding in findings if not _is_noise(finding)]

	severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	category_order = {"security": 0, "bug": 1, "style": 2}
	return sorted(
		findings,
		key=lambda f: (severity_order[f.severity], category_order[f.category], f.file_path, f.line, f.id),
	)
