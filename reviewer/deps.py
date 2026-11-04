from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .models import Finding

AUDIT_TIMEOUT_SECONDS = 60
_PINNED = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.!+\-]+)")


def audit_dependencies(root: Path) -> tuple[list[Finding], str]:
	"""Check pinned entries of requirements.txt for known vulnerabilities with pip-audit."""
	requirements = root / "requirements.txt"
	if not requirements.is_file():
		return [], "No requirements.txt found at the repository root."
	executable = shutil.which("pip-audit")
	if not executable:
		return [], "pip-audit is not installed; dependency audit skipped."
	pinned = []
	for line in requirements.read_text(encoding="utf-8", errors="replace").splitlines():
		match = _PINNED.match(line)
		if match:
			pinned.append(f"{match.group(1)}=={match.group(2)}")
	if not pinned:
		return [], "requirements.txt has no pinned (==) packages to audit."
	with tempfile.TemporaryDirectory(prefix="ai-code-review-deps-") as directory:
		pinned_file = Path(directory) / "requirements.txt"
		pinned_file.write_text("\n".join(pinned[:300]) + "\n", encoding="utf-8")
		try:
			result = subprocess.run(
				[executable, "-r", str(pinned_file), "--no-deps", "--disable-pip", "-f", "json", "--progress-spinner", "off"],
				capture_output=True,
				text=True,
				timeout=AUDIT_TIMEOUT_SECONDS,
				check=False,
			)
			data = json.loads(result.stdout or "{}")
		except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
			return [], "Dependency audit could not complete (timeout or service unavailable)."
	findings: list[Finding] = []
	for dependency in data.get("dependencies", []):
		for vulnerability in dependency.get("vulns", []):
			fixes = ", ".join(vulnerability.get("fix_versions") or []) or "no fix released"
			name, version = dependency.get("name", "?"), dependency.get("version", "?")
			findings.append(
				Finding(
					id=f"pip-audit:{vulnerability.get('id', 'unknown')}:{name}",
					title=f"Vulnerable dependency: {name} {version} ({vulnerability.get('id', 'unknown')})",
					message=str(vulnerability.get("description", "Known vulnerability."))[:500],
					category="security",
					severity="high",
					rule_id=str(vulnerability.get("id", "VULN")),
					source="pip-audit",
					file_path="requirements.txt",
					line=1,
					suggested_fix=f"Upgrade {name} to: {fixes}.",
				)
			)
	note = f"Audited {len(pinned)} pinned packages: {len(findings)} known vulnerabilities found."
	return findings, note
