from __future__ import annotations

import ast
from pathlib import Path

from openai import OpenAIError

from .llm_review import _chat_json, _settings
from .models import Finding
from .fixer import function_context


def generate_test(root: Path, finding: Finding, settings=None) -> tuple[str, str | None]:
    """Generate one pytest test file for a confirmed finding. Never execute it."""
    selected = _settings(settings)
    if not selected["api_key"]:
        return "", "LLM API key is not configured."

    source = root / finding.file_path
    if not source.is_file():
        return "", "Source file is unavailable."

    _, _, context = function_context(source, finding.line)
    if not context:
        return "", "Could not extract the relevant function context."

    prompt = {
        "finding": {
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity,
            "rule_id": finding.rule_id,
            "message": finding.message,
            "file": finding.file_path,
            "line": finding.line,
        },
        "source_context": context,
    }

    system = (
        "You are an expert Python QA engineer. Generate focused pytest tests that would "
        "catch the supplied bug or security issue. Return one JSON object with a 'test_code' "
        "string containing a complete Python pytest test module. Include necessary imports. "
        "Use temporary files and mocks where appropriate. Do not access networks or real "
        "credentials. Do not include markdown fences. Do not invent project APIs. "
        "If a meaningful test cannot be written from the context, return an empty string."
    )

    try:
        result = _chat_json(selected, system, __import__("json").dumps(prompt))
        code = result.get("test_code", "")
        if not isinstance(code, str) or not code.strip():
            return "", "The model could not generate a meaningful test."
        if len(code) > 12000:
            return "", "Generated test exceeded the size limit."
        ast.parse(code)
        return code.strip(), None
    except OpenAIError as error:
        status_code = getattr(error, "status_code", None)
        if status_code == 429:
            return "", (
                "Groq rate limit reached (HTTP 429). "
                "Wait for your token quota to reset, then run the review again."
            )
        return "", f"Test generation API error: {str(error)[:180]}"
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        return "", f"Test generation unavailable: {str(error)[:180]}"
