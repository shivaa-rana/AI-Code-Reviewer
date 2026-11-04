from __future__ import annotations

from .models import Finding

_WEIGHTS = {"critical": 25, "high": 12, "medium": 4, "low": 1, "info": 0}
_CAPS = {"critical": 60, "high": 45, "medium": 25, "low": 10, "info": 0}


def risk_score(findings: list[Finding]) -> int:
	"""Health score from 0 (worst) to 100 (clean). Findings the AI rejected are ignored."""
	penalty = 0
	for severity, weight in _WEIGHTS.items():
		count = sum(f.severity == severity and f.is_false_positive is not True for f in findings)
		penalty += min(count * weight, _CAPS[severity])
	return max(0, 100 - penalty)


def grade(score: int) -> str:
	for threshold, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
		if score >= threshold:
			return letter
	return "F"
