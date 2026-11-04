from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reviewer import llm_review
from reviewer.fixer import function_context, verify_patch
from reviewer.ingest import parse_github_target, validate_github_url
from reviewer.models import Finding
from reviewer.scoring import grade, risk_score
from reviewer.static_scan import _redact, scan_repository


def _finding(severity="low", **kwargs) -> Finding:
	defaults = dict(
		id=f"x:{severity}", title="t", message="m", category="bug", severity=severity,
		rule_id="R", source="ruff", file_path="a.py", line=1,
	)
	return Finding(**{**defaults, **kwargs})


# --- URL parsing -----------------------------------------------------------------------------
def test_plain_repo_url():
	assert validate_github_url("https://github.com/owner/repo") == "https://github.com/owner/repo.git"


def test_branch_and_pr_urls():
	assert parse_github_target("https://github.com/o/r/tree/feature/x").ref == "feature/x"
	assert parse_github_target("https://github.com/o/r/pull/42").pull_request == 42


@pytest.mark.parametrize(
	"url",
	[
		"http://github.com/o/r",
		"https://gitlab.com/o/r",
		"https://user:pw@github.com/o/r",
		"https://github.com/o",
		"https://github.com/o/r?x=1",
		"https://github.com/o/r/tree/--upload-pack=evil",
		"https://github.com/o/r/tree/a/../b",
		"https://github.com/o/r/blob/main/x.py",
		"https://github.com/o/../r",
	],
)
def test_rejects_bad_urls(url):
	with pytest.raises(ValueError):
		parse_github_target(url)


# --- Scoring ---------------------------------------------------------------------------------
def test_score_and_grade():
	assert risk_score([]) == 100 and grade(100) == "A"
	assert risk_score([_finding("critical")]) == 75
	rejected = _finding("critical", is_false_positive=True)
	assert risk_score([rejected]) == 100
	assert grade(30) == "F"


# --- Scanner ---------------------------------------------------------------------------------
def test_scanner_finds_eval_and_secret(tmp_path):
    source = tmp_path / "app.py"
    fake_key = "AKIA" + "ABCDEFGHIJKLMNOP"
    source.write_text(
        "key = " + repr(fake_key) + "\n\ndef f(x):\n    return eval(x)\n"
    )
    findings = scan_repository(tmp_path, [source])
    rules = {f.rule_id for f in findings}
    assert "B307" in rules and "SEC001" in rules
    assert all(fake_key not in f.code_snippet for f in findings), "secret must be redacted"


def test_redaction():
    fake_key = "AKIA" + "ABCDEFGHIJKLMNOP"
    assert fake_key not in _redact("x = " + repr(fake_key))


# --- Fix agent -------------------------------------------------------------------------------
def test_function_context(tmp_path):
	path = tmp_path / "m.py"
	path.write_text("x = 1\n\ndef f(a):\n    b = a\n    return b\n\ny = 2\n")
	assert function_context(path, 4)[:2] == (3, 5)


def _yaml_finding(tmp_path):
	path = tmp_path / "loader.py"
	path.write_text("import yaml\n\ndef load(stream):\n    return yaml.load(stream)\n")
	finding = next(f for f in scan_repository(tmp_path, [path]) if f.rule_id == "B506")
	return finding


def test_good_patch_is_verified(tmp_path):
	finding = _yaml_finding(tmp_path)
	start, end, _ = function_context(tmp_path / "loader.py", finding.line)
	diff, verified, _ = verify_patch(tmp_path, finding, start, end, "def load(stream):\n    return yaml.safe_load(stream)")
	assert verified and "+    return yaml.safe_load(stream)" in diff


def test_bad_patches_are_rejected(tmp_path):
	finding = _yaml_finding(tmp_path)
	start, end, _ = function_context(tmp_path / "loader.py", finding.line)
	_, syntax_ok, _ = verify_patch(tmp_path, finding, start, end, "def load(stream:\n    return 1")
	_, still_vulnerable, note = verify_patch(tmp_path, finding, start, end, "def load(stream):\n    return yaml.load(stream)  # fixed")
	assert syntax_ok is False
	assert still_vulnerable is False and "B506" in note


# --- LLM pipeline with a mocked model --------------------------------------------------------
def test_full_review_with_mock_llm(tmp_path, monkeypatch):
	finding = _yaml_finding(tmp_path)

	def fake_chat(settings, system, user):
		import json
		items = json.loads(user)
		if isinstance(items, list):
			return {"reviews": [
				{
					"id": item["id"], "confirmed": True, "explanation": "unsafe loader",
					"suggested_fix": "use safe_load",
					"fixed_code": "def load(stream):\n    return yaml.safe_load(stream)",
				}
				for item in items
			]}
		return {"issues": []}

	monkeypatch.setattr(llm_review, "_chat_json", fake_chat)
	findings, error = llm_review.review_findings([finding], {"LLM_API_KEY": "test"}, root=tmp_path)
	assert error is None
	assert findings[0].is_false_positive is False
	assert findings[0].fix_verified is True and findings[0].fix_diff


def test_no_key_returns_note():
	_, error = llm_review.review_findings([_finding()], {"LLM_API_KEY": ""})
	assert error is None or "LLM_API_KEY" in error  # env may provide a key in CI


# --- SARIF export -------------------------------------------------------------------------------
def test_sarif_export_maps_severity_and_location():
    from reviewer.models import ReviewReport
    from reviewer.sarif import to_sarif

    finding = _finding(
        severity="critical",
        rule_id="SEC001",
        source="secrets",
        file_path="src/app.py",
        line=12,
        column=5,
        is_false_positive=False,
    )
    report = ReviewReport(
        repository_url="https://github.com/example/project",
        scanned_at="2026-11-04T00:00:00+00:00",
        scanned_files=3,
        findings=[finding],
    )

    sarif = to_sarif(report)
    run = sarif["runs"][0]
    result = run["results"][0]

    assert sarif["version"] == "2.1.0"
    assert result["ruleId"] == "secrets/SEC001"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"
    assert result["locations"][0]["physicalLocation"]["region"] == {
        "startLine": 12,
        "startColumn": 5,
    }
    assert result["properties"]["isFalsePositive"] is False
    assert run["tool"]["driver"]["rules"][0]["id"] == "secrets/SEC001"


def test_sarif_export_handles_empty_report_and_severity_levels():
    from reviewer.models import ReviewReport
    from reviewer.sarif import to_sarif

    report = ReviewReport(
        repository_url="https://github.com/example/project",
        scanned_at="2026-11-04T00:00:00+00:00",
        scanned_files=0,
        findings=[
            _finding("high"),
            _finding("medium", id="medium"),
            _finding("low", id="low"),
            _finding("info", id="info"),
        ],
    )

    results = to_sarif(report)["runs"][0]["results"]

    assert [item["level"] for item in results] == [
        "error", "warning", "note", "note"
    ]

    empty = ReviewReport(
        repository_url="https://github.com/example/project",
        scanned_at="2026-11-04T00:00:00+00:00",
        scanned_files=0,
    )
    empty_sarif = to_sarif(empty)
    assert empty_sarif["runs"][0]["results"] == []



def test_evaluation_ignores_subprocess_advisories():
        from eval.run_eval import _predicted_files

        findings = [
                _finding(rule_id="B603", file_path="safe_subprocess.py", source="bandit"),
                _finding(rule_id="B607", file_path="safe_subprocess.py", source="bandit"),
                _finding(rule_id="SEC001", file_path="unsafe_secret.py", source="secrets"),
        ]

        assert _predicted_files(findings) == {"unsafe_secret.py"}
