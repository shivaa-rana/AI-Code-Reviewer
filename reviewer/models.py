from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Category = Literal["security", "bug", "style"]
Severity = Literal["critical", "high", "medium", "low", "info"]
Source = Literal["bandit", "ruff", "secrets", "llm", "pip-audit"]


class Finding(BaseModel):
	model_config = ConfigDict(extra="forbid")

	id: str
	title: str
	message: str
	category: Category
	severity: Severity
	rule_id: str
	source: Source
	file_path: str
	line: int = Field(ge=1)
	column: int = Field(default=1, ge=1)
	code_snippet: str = ""
	is_false_positive: bool | None = None
	explanation: str = ""
	confidence: int = Field(default=0, ge=0, le=100)
	evidence: str = ""
	attack_scenario: str = ""
	suggested_fix: str = ""
	# Auto-fix agent output: unified diff and whether the patch passed re-scanning.
	fix_diff: str = ""
	fix_verified: bool | None = None
	fix_note: str = ""
	generated_test: str = ""
	generated_test_note: str = ""


class ReviewReport(BaseModel):
	model_config = ConfigDict(extra="forbid")

	repository_url: str
	scanned_at: str
	scanned_files: int = Field(ge=0)
	target_description: str = ""
	findings: list[Finding] = Field(default_factory=list)
	llm_used: bool = False
	llm_error: str | None = None
	risk_score: int = Field(default=100, ge=0, le=100)
	grade: str = "A"
	summary: str = ""
	dependency_note: str = ""
