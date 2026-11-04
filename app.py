from __future__ import annotations

import html
import json
import time
from datetime import datetime

import streamlit as st

from reviewer.models import Finding, ReviewReport
from reviewer.pipeline import run_review
from reviewer.sarif import to_sarif

st.set_page_config(page_title="AI Code Reviewer", page_icon="CR", layout="wide")
st.markdown(
	"""
	<style>
	:root { --ink: #e8eee9; --muted: #9daaa5; --line: #293630; --mint: #83e1b5; --amber: #f1bd72; }
	.stApp { background: radial-gradient(ellipse at 86% 0%, #17271f 0, #101714 34%, #0c100e 74%); color: var(--ink); }
	[data-testid="stHeader"] { background: transparent; }
	[data-testid="stSidebar"] { background: #101714; border-right: 1px solid var(--line); }
	h1, h2, h3 { color: var(--ink); letter-spacing: 0; }
	.eyebrow { color: var(--mint); font-size: .75rem; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; }
	.lede { color: var(--muted); max-width: 720px; margin: .25rem 0 1.4rem; }
	.metric-label { color: var(--muted); font-size: .84rem; }
	.finding-meta { color: var(--muted); font-size: .84rem; margin-bottom: .4rem; }
	.pill { display: inline-block; border: 1px solid var(--line); border-radius: 4px; padding: 2px 8px; margin-right: 6px; font-size: .76rem; text-transform: uppercase; }
	.pill-security { color: #ff9a86; border-color: #664137; }
	.pill-bug { color: #f1bd72; border-color: #685237; }
	.pill-llm { color: #c9a6ff; border-color: #55467a; }
	.grade { font-size: 3.2rem; font-weight: 800; line-height: 1; }
	.pill-style { color: #9bb9f2; border-color: #3e4e6d; }
	.pill-severity-critical, .pill-severity-high { color: #ff9a86; border-color: #664137; }
	.pill-severity-medium { color: #f1bd72; border-color: #685237; }
	.pill-severity-low, .pill-severity-info { color: #b7c5be; border-color: #44524b; }
	div[data-testid="stMetric"] { background: rgba(26, 37, 31, .75); border: 1px solid var(--line); border-radius: 6px; padding: 14px 16px; }
	div[data-testid="stMetricValue"] { color: var(--ink); }
	div.stButton > button[kind="primary"] { background: var(--mint); color: #102018; border: 0; font-weight: 700; }
	div.stButton > button[kind="primary"]:hover { background: #a4efcb; }
	div[data-testid="stExpander"] { border: 1px solid var(--line); border-radius: 6px; background: rgba(17, 24, 20, .72); }
	</style>
	""",
	unsafe_allow_html=True,
)


COOLDOWN_SECONDS = 15


def _secret(name: str) -> str:
	try:
		value = st.secrets.get(name, "")
		return str(value) if value else ""
	except (OSError, KeyError):
		return ""


def _llm_settings() -> dict[str, str]:
	return {
		"LLM_API_KEY": _secret("LLM_API_KEY"),
		"LLM_BASE_URL": _secret("LLM_BASE_URL"),
		"LLM_MODEL": _secret("LLM_MODEL"),
	}


def _state(finding: Finding) -> str:
	if finding.is_false_positive is True:
		return "Filtered as false positive"
	if finding.is_false_positive is False:
		return "Confirmed"
	return "AI-detected" if finding.source == "llm" else "Unverified"


def _markdown_report(report: ReviewReport) -> str:
	lines = [
		"# AI Code Review",
		"",
		f"- Repository: {report.repository_url}",
		f"- Target: {report.target_description or 'Default branch'}",
		f"- Scanned at: {report.scanned_at}",
		f"- Python files scanned: {report.scanned_files}",
		f"- Health score: {report.risk_score}/100 (grade {report.grade})",
		f"- Findings: {len(report.findings)}",
		f"- LLM verification: {'used' if report.llm_used else 'not used'}",
		f"- Dependencies: {report.dependency_note}",
		"",
	]
	if report.summary:
		lines.extend(["## Summary", "", report.summary, ""])
	if report.llm_error:
		lines.extend([f"> AI verification note: {report.llm_error}", ""])
	if not report.findings:
		lines.append("No findings detected.")
	for finding in report.findings:
		lines.extend(
			[
				f"## {finding.title}",
				"",
				f"**{finding.category.title()} / {finding.severity.title()} / {_state(finding)}**",
				f"`{finding.file_path}:{finding.line}:{finding.column}` · `{finding.rule_id}` · {finding.source}",
				"",
				finding.message,
				"",
			]
		)
		if finding.explanation:
			lines.extend([f"**AI explanation:** {finding.explanation}", ""])
		if finding.suggested_fix:
			lines.extend([f"**Suggested fix:** {finding.suggested_fix}", ""])
		if finding.fix_diff:
			label = "verified by re-scan" if finding.fix_verified else "NOT verified"
			lines.extend([f"**Proposed patch ({label}):**", "", "```diff", finding.fix_diff, "```", ""])
		if finding.code_snippet:
			lines.extend(["```python", finding.code_snippet, "```", ""])
	return "\n".join(lines)


def _render_finding(finding: Finding, index: int) -> None:
	icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(finding.severity, "⚪")
	title = f"{icon} {index}. {finding.title} · {finding.file_path}:{finding.line} · {_state(finding).upper()}"
	with st.expander(title):
		safe_category = finding.category if finding.category in {"bug", "security", "style"} else "style"
		safe_severity = finding.severity if finding.severity in {"critical", "high", "medium", "low", "info"} else "info"
		st.markdown(
			f'<span class="pill pill-{safe_category}">{html.escape(finding.category)}</span>'
			f'<span class="pill pill-severity-{safe_severity}">{html.escape(finding.severity)}</span>'
			f'<span class="pill pill-{"llm" if finding.source == "llm" else "style"}">'
			f"{html.escape(finding.source)}: {html.escape(finding.rule_id)}</span>",
			unsafe_allow_html=True,
		)
		st.markdown(f"**Finding**  \n{finding.message}")
		if finding.code_snippet:
			st.code(finding.code_snippet, language="python")
		if finding.explanation:
			st.markdown(f"**AI review**  \n{finding.explanation}")
		if finding.suggested_fix:
			st.markdown(f"**Suggested fix**  \n{finding.suggested_fix}")
		if finding.fix_diff:
			if finding.fix_verified:
				st.success(f"Auto-fix verified: {finding.fix_note}")
			else:
				st.warning(f"Auto-fix proposed but NOT verified: {finding.fix_note}")
			st.code(finding.fix_diff, language="diff")


with st.sidebar:
	st.header("Review options")
	verify_with_llm = st.checkbox("AI verification and auto-fix (Groq)", value=True)
	discover_with_llm = st.checkbox(
		"AI bug discovery", value=True, help="Asks the model to look for logic bugs the linters miss in the largest files."
	)
	st.caption("Verification reviews up to 40 findings in parallel batches. Patches are only marked verified if a re-scan passes.")
	st.divider()
	st.caption("Accepted URLs: repo, /tree/<branch>, or /pull/<number> (changed files only).")

st.markdown('<div class="eyebrow">Neural Storm 2026 · FT-05</div>', unsafe_allow_html=True)
st.title("AI Code Reviewer")
st.markdown(
	'<p class="lede">Static analysis finds candidates, an AI agent confirms them, writes a patch, and re-scans the patch '
	"before showing it. Source is scanned as data and never executed.</p>",
	unsafe_allow_html=True,
)

with st.container(border=True):
	repository_url = st.text_input(
		"GitHub repository, branch or pull request URL",
		placeholder="https://github.com/owner/repository  ·  .../tree/branch  ·  .../pull/123",
		help="Public GitHub only. Shallow clone, up to 400 Python files.",
	)
	run_clicked = st.button("Run Review", type="primary", icon=":material/search:")

if run_clicked:
	wait = max(0, COOLDOWN_SECONDS - (time.time() - st.session_state.get("last_run", 0)))
	if not repository_url.strip():
		st.error("Enter a GitHub URL to begin.")
	elif wait > 0:
		st.warning(f"Please wait {int(wait) + 1}s before starting another review.")
	else:
		st.session_state["last_run"] = time.time()
		try:
			with st.spinner("Cloning, scanning, verifying and patching..."):
				report = run_review(repository_url, verify_with_llm, _llm_settings(), discover_with_llm)
			st.session_state["review_report"] = report.model_dump(mode="json")
		except (ValueError, RuntimeError, OSError) as error:
			st.error(str(error))

stored_report = st.session_state.get("review_report")
if stored_report:
	report = ReviewReport.model_validate(stored_report)
	visible = [f for f in report.findings if f.is_false_positive is not True]
	filtered = [f for f in report.findings if f.is_false_positive is True]
	confirmed_count = sum(f.is_false_positive is False for f in report.findings)
	verified_fixes = sum(bool(f.fix_verified) for f in report.findings)
	st.divider()
	st.caption(
		f"{report.repository_url} · {report.target_description or 'Default branch'} · scanned "
		f"{datetime.fromisoformat(report.scanned_at).strftime('%Y-%m-%d %H:%M UTC')} · {report.scanned_files} Python files"
	)

	score_col, summary_col = st.columns([1, 3])
	with score_col:
		st.markdown(f'<div class="grade">{html.escape(report.grade)}</div>', unsafe_allow_html=True)
		st.caption(f"Health score {report.risk_score}/100")
	with summary_col:
		if report.summary:
			st.markdown(f"**AI summary**  \n{report.summary}")
		else:
			st.markdown("**Summary**  \nEnable AI verification for a written summary of the top risks.")

	metric_columns = st.columns(5)
	metric_columns[0].metric("Findings shown", len(visible))
	metric_columns[1].metric("AI-confirmed", confirmed_count)
	metric_columns[2].metric("Verified auto-fixes", verified_fixes)
	metric_columns[3].metric("Filtered by AI", len(filtered))
	metric_columns[4].metric("Unverified", sum(f.is_false_positive is None for f in report.findings))

	if report.llm_error:
		st.info(report.llm_error)
	if report.dependency_note:
		st.caption(f"Dependency audit: {report.dependency_note}")
	if not report.findings:
		st.success("No findings detected in the scanned Python files.")

	chart_left, chart_right = st.columns(2)
	with chart_left:
		st.subheader("By severity")
		st.bar_chart({s: sum(f.severity == s for f in visible) for s in ("critical", "high", "medium", "low", "info")})
	with chart_right:
		st.subheader("By category")
		st.bar_chart({c: sum(f.category == c for f in visible) for c in ("security", "bug", "style")})

	st.subheader("Review details")
	severity_filter = st.multiselect(
		"Severity", ["critical", "high", "medium", "low", "info"], default=["critical", "high", "medium", "low", "info"]
	)
	shown = [f for f in visible if f.severity in severity_filter]
	for index, finding in enumerate(shown, start=1):
		_render_finding(finding, index)
	if not shown and report.findings and not visible:
		st.info("All findings were filtered as false positives by the AI verifier.")

	if filtered:
		with st.expander(f"Filtered by AI as false positives ({len(filtered)}) - audit these decisions"):
			for index, finding in enumerate(filtered, start=1):
				_render_finding(finding, index)

	json_bytes = json.dumps(report.model_dump(mode="json"), indent=2).encode("utf-8")
	markdown_bytes = _markdown_report(report).encode("utf-8")
	sarif_bytes = json.dumps(to_sarif(report), indent=2).encode("utf-8")
	export_json, export_markdown, export_sarif = st.columns(3)
	export_json.download_button("Download JSON report", json_bytes, file_name="code-review-report.json", mime="application/json")
	export_markdown.download_button(
		"Download Markdown report", markdown_bytes, file_name="code-review-report.md", mime="text/markdown"
	)
	export_sarif.download_button(
		"Download SARIF report", sarif_bytes,
		file_name="code-review-report.sarif", mime="application/sarif+json"
	)
