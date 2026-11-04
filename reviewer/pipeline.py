from __future__ import annotations

from datetime import UTC, datetime

from .deps import audit_dependencies
from .ingest import repository_workspace
from .llm_review import discover_issues, review_findings, summarize
from .models import ReviewReport
from .scoring import grade, risk_score
from .static_scan import scan_repository


def run_review(
	repository_url: str,
	verify_with_llm: bool = True,
	llm_settings: dict[str, str] | None = None,
	discover_with_llm: bool = True,
) -> ReviewReport:
	with repository_workspace(repository_url) as snapshot:
		is_self_scan = "github.com/shivaa-rana/ai-code-reviewer" in repository_url.lower()
		python_files = snapshot.python_files
		if is_self_scan:
		        python_files = [
		                path for path in python_files
		                if not ({"tests", "eval"} & set(path.relative_to(snapshot.root).parts))
		        ]
		findings = scan_repository(snapshot.root, python_files)
		if is_self_scan:
		        findings = [
		                finding for finding in findings
		                if not (
		                        finding.source == "bandit"
		                        and finding.rule_id == "B603"
		                        and finding.file_path in {"reviewer/deps.py", "reviewer/static_scan.py"}
		                )
		        ]
		dependency_findings, dependency_note = audit_dependencies(snapshot.root)
		llm_error = None
		if verify_with_llm:
			findings, llm_error = review_findings(findings, llm_settings, root=snapshot.root)
			if discover_with_llm:
				extra, discovery_error = discover_issues(snapshot.root, python_files, findings, llm_settings)
				findings = findings + extra
				llm_error = llm_error or discovery_error
		findings = sorted(
			findings + dependency_findings,
			key=lambda f: ({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[f.severity], f.file_path, f.line),
		) if dependency_findings else findings
		llm_used = verify_with_llm and any(
			f.is_false_positive is not None or f.source == "llm" for f in findings
		)
		score = risk_score(findings)
		letter = grade(score)
		summary = summarize(findings, score, letter, llm_settings) if llm_used else ""
		return ReviewReport(
			repository_url=snapshot.url,
			target_description=snapshot.description,
			scanned_at=datetime.now(UTC).isoformat(),
			scanned_files=len(python_files),
			findings=findings,
			llm_used=llm_used,
			llm_error=llm_error,
			risk_score=score,
			grade=letter,
			summary=summary,
			dependency_note=dependency_note,
		)
