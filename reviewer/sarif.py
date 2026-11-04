from __future__ import annotations

from .models import ReviewReport


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def to_sarif(report: ReviewReport) -> dict:
    """Convert an AI Code Reviewer report into SARIF 2.1.0."""

    rules: dict[str, dict] = {}
    results: list[dict] = []

    for finding in report.findings:
        rule_id = f"{finding.source}/{finding.rule_id}"

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.message},
                "properties": {
                    "category": finding.category,
                    "source": finding.source,
                },
            }

        result = {
            "ruleId": rule_id,
            "level": LEVELS[finding.severity],
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line,
                            "startColumn": finding.column,
                        },
                    }
                }
            ],
            "properties": {
                "severity": finding.severity,
                "category": finding.category,
                "source": finding.source,
                "isFalsePositive": finding.is_false_positive,
                "fixVerified": finding.fix_verified,
            },
        }

        if finding.explanation:
            result["properties"]["aiExplanation"] = finding.explanation

        if finding.suggested_fix:
            result["properties"]["suggestedFix"] = finding.suggested_fix

        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Neural Storm AI Code Reviewer",
                        "informationUri": "https://github.com/shivaa-rana/AI-Code-Reviewer",
                        "rules": list(rules.values()),
                    }
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": "file:///"}
                },
                "results": results,
                "properties": {
                    "repository": report.repository_url,
                    "riskScore": report.risk_score,
                    "grade": report.grade,
                    "scannedFiles": report.scanned_files,
                },
            }
        ],
    }
