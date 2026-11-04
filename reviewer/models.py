from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Category = Literal["security", "bug", "style"]
Severity = Literal["critical", "high", "medium", "low", "info"]


class Finding(BaseModel):
	model_config = ConfigDict(extra="forbid")

	id: str
	title: str
	message: str
	category: Category
	severity: Severity
	rule_id: str
	source: Literal["bandit", "ruff"]
	file_path: str
	line: int = Field(ge=1)
	column: int = Field(default=1, ge=1)
	code_snippet: str = ""
	is_false_positive: bool | None = None
	explanation: str = ""
	suggested_fix: str = ""


class ReviewReport(BaseModel):
	model_config = ConfigDict(extra="forbid")

	repository_url: str
	scanned_at: str
	scanned_files: int = Field(ge=0)
	findings: list[Finding] = Field(default_factory=list)
	llm_used: bool = False
	llm_error: str | None = None
