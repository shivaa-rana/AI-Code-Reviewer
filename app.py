from __future__ import annotations

import json
from datetime import datetime

import streamlit as st

from reviewer.models import Finding, ReviewReport
from reviewer.pipeline import run_review

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


def _markdown_report(report: ReviewReport) -> str:
	lines = [
		"# AI Code Review",
		"",
		f"- Repository: {report.repository_url}",
		f"- Scanned at: {report.scanned_at}",
		f"- Python files scanned: {report.scanned_files}",
		f"- Findings: {len(report.findings)}",
		f"- LLM verification: {'used' if report.llm_used else 'not used'}",
		"",
	]
	if report.llm_error:
		lines.extend([f"> AI verification note: {report.llm_error}", ""])
	if not report.findings:
		lines.append("No findings detected.")
	for finding in report.findings:
		state = "Filtered as false positive" if finding.is_false_positive else (
			"Confirmed" if finding.is_false_positive is False else "Unverified"
		)
		lines.extend(
			[
				f"## {finding.title}",
				"",
				f"**{finding.category.title()} / {finding.severity.title()} / {state}**",
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
		if finding.code_snippet:
			lines.extend(["```python", finding.code_snippet, "```", ""])
	return "\n".join(lines)


def _render_finding(finding: Finding, index: int) -> None:
	state = (
		"FALSE POSITIVE" if finding.is_false_positive is True else
		"CONFIRMED" if finding.is_false_positive is False else "UNVERIFIED"
	)
	title = f"{index}. {finding.title} · {finding.file_path}:{finding.line} · {state}"
	with st.expander(title):
		st.markdown(
			f'<span class="pill pill-{finding.category}">{finding.category}</span>'
			f'<span class="pill pill-severity-{finding.severity}">{finding.severity}</span>'
			f'<span class="pill">{finding.source}: {finding.rule_id}</span>',
			unsafe_allow_html=True,
		)
		st.markdown(f"**Finding**  \n{finding.message}")
		if finding.code_snippet:
			st.code(finding.code_snippet, language="python")
		if finding.explanation:
			st.markdown(f"**AI review**  \n{finding.explanation}")
		if finding.suggested_fix:
			st.markdown(f"**Suggested fix**  \n{finding.suggested_fix}")


st.markdown('<div class="eyebrow">Neural Storm 2026 · FT-05</div>', unsafe_allow_html=True)
st.title("AI Code Reviewer")
st.markdown(
	'<p class="lede">A focused static and AI-assisted review for public Python repositories. '
	'Source is scanned as data and never executed.</p>',
	unsafe_allow_html=True,
)

with st.container(border=True):
	repository_url = st.text_input(
		"GitHub repository URL",
		placeholder="https://github.com/owner/repository",
		help="Public GitHub repositories only. Shallow clone, up to 400 Python files.",
	)
	left, right = st.columns([1, 3])
	with left:
		verify_with_llm = st.checkbox("Verify with Groq AI", value=True)
	with right:
		st.caption("AI verification reviews up to 15 findings. Configure LLM_API_KEY in .env or Streamlit secrets.")
	run_clicked = st.button("Run Review", type="primary", icon=":material/search:")

if run_clicked:
	if not repository_url.strip():
		st.error("Enter a GitHub repository URL to begin.")
	else:
		try:
			with st.spinner("Cloning and scanning Python files..."):
				report = run_review(repository_url, verify_with_llm, _llm_settings())
			st.session_state["review_report"] = report.model_dump(mode="json")
		except (ValueError, RuntimeError, OSError) as error:
			st.error(str(error))

stored_report = st.session_state.get("review_report")
if stored_report:
	report = ReviewReport.model_validate(stored_report)
	visible_findings = [finding for finding in report.findings if finding.is_false_positive is not True]
	confirmed_count = sum(finding.is_false_positive is False for finding in report.findings)
	false_positive_count = sum(finding.is_false_positive is True for finding in report.findings)
	st.divider()
	st.caption(f"{report.repository_url} · scanned {datetime.fromisoformat(report.scanned_at).strftime('%Y-%m-%d %H:%M UTC')} · {report.scanned_files} Python files")
	metric_columns = st.columns(4)
	metric_columns[0].metric("Total findings", len(report.findings))
	metric_columns[1].metric("Confirmed", confirmed_count)
	metric_columns[2].metric("Filtered false positives", false_positive_count)
	metric_columns[3].metric("Unverified", len(report.findings) - confirmed_count - false_positive_count)

	if report.llm_error:
		st.info(report.llm_error)
	if not report.findings:
		st.success("No findings detected in the scanned Python files.")

	st.subheader("Findings by category")
	categories = st.columns(3)
	for column, category in zip(categories, ("security", "bug", "style")):
		count = sum(finding.category == category for finding in visible_findings)
		column.metric(category.title(), count)

	st.subheader("Review details")
	if visible_findings:
		for index, finding in enumerate(visible_findings, start=1):
			_render_finding(finding, index)
	elif report.findings:
		st.info("All findings were filtered as false positives by the AI verifier.")

	json_bytes = json.dumps(report.model_dump(mode="json"), indent=2).encode("utf-8")
	markdown_bytes = _markdown_report(report).encode("utf-8")
	export_json, export_markdown = st.columns(2)
	export_json.download_button(
		"Download JSON report", json_bytes, file_name="code-review-report.json", mime="application/json"
	)
	export_markdown.download_button(
		"Download Markdown report", markdown_bytes, file_name="code-review-report.md", mime="text/markdown"
	)
