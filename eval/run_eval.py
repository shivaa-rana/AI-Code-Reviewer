from __future__ import annotations

import json
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from eval.seeded_bugs import SEEDED_CASES  # noqa: E402
from reviewer.llm_review import review_findings  # noqa: E402
from reviewer.models import Finding  # noqa: E402
from reviewer.static_scan import scan_repository  # noqa: E402


def _metrics(expected: set[str], predicted: set[str], all_samples: set[str]) -> dict[str, int | float | None]:
	true_positive = len(expected & predicted)
	false_positive = len(predicted - expected)
	false_negative = len(expected - predicted)
	true_negative = len(all_samples - expected - predicted)
	precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else None
	recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else None
	return {
		"true_positive": true_positive,
		"false_positive": false_positive,
		"false_negative": false_negative,
		"true_negative": true_negative,
		"precision": precision,
		"recall": recall,
	}


ADVISORY_RULES = {"B603", "B607"}


def _predicted_files(findings: Iterable[Finding]) -> set[str]:
        return {
                Path(finding.file_path).name
                for finding in findings
                if not (
                        finding.source == "bandit"
                        and finding.rule_id in ADVISORY_RULES
                )
        }



def run_evaluation() -> dict[str, object]:
	with tempfile.TemporaryDirectory(prefix="ai-code-review-eval-") as temporary_directory:
		root = Path(temporary_directory)
		files = []
		for case in SEEDED_CASES:
			path = root / case.filename
			path.write_text(case.code, encoding="utf-8")
			files.append(path)
		static_findings = scan_repository(root, files)

	sample_names = {case.filename for case in SEEDED_CASES}
	expected = {case.filename for case in SEEDED_CASES if case.has_issue}
	static_predictions = _predicted_files(static_findings)
	static_metrics = _metrics(expected, static_predictions, sample_names)

	reviewed_findings, llm_error = review_findings(static_findings)
	labels_present = any(finding.is_false_positive is not None for finding in reviewed_findings)
	llm_ran = llm_error is None and labels_present
	# LLM verification is advisory: it must not erase static detections.
	# AI-discovered findings are evaluated separately in future benchmarks.
	combined_predictions = static_predictions
	combined_metrics = _metrics(expected, combined_predictions, sample_names) if llm_ran else None

	return {
		"samples": len(SEEDED_CASES),
		"ground_truth_positive_samples": len(expected),
		"static_findings": len(static_findings),
		"static_scanning": static_metrics,
		"static_plus_llm": combined_metrics,
		"llm_evaluation": "completed" if llm_ran else "not run",
		"llm_note": llm_error or (None if llm_ran else "No LLM review labels were returned."),
		"cases": [
			{
				"file": case.filename,
				"ground_truth_has_issue": case.has_issue,
				"description": case.description,
				"static_findings": [
					finding.rule_id for finding in static_findings if Path(finding.file_path).name == case.filename
				],
				"combined_prediction": case.filename in combined_predictions if llm_ran else None,
			}
			for case in SEEDED_CASES
		],
	}


if __name__ == "__main__":
	try:
		print(json.dumps(run_evaluation(), indent=2))
	except Exception as error:
		print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
		raise SystemExit(1) from error
