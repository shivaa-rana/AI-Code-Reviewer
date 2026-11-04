from __future__ import annotations

from datetime import UTC, datetime

from .ingest import repository_workspace
from .llm_review import review_findings
from .models import ReviewReport
from .static_scan import scan_repository


def run_review(
	repository_url: str,
	verify_with_llm: bool = True,
	llm_settings: dict[str, str] | None = None,
) -> ReviewReport:
	with repository_workspace(repository_url) as snapshot:
		findings = scan_repository(snapshot.root, snapshot.python_files)
		llm_error = None
		llm_used = False
		if verify_with_llm:
			findings, llm_error = review_findings(findings, llm_settings)
			llm_used = llm_error is None and bool(findings)
		return ReviewReport(
			repository_url=snapshot.url,
			scanned_at=datetime.now(UTC).isoformat(),
			scanned_files=len(snapshot.python_files),
			findings=findings,
			llm_used=llm_used,
			llm_error=llm_error,
		)
