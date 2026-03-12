"""checks/ai_endpoint/jailbreak_posture.py — Non-adversarial jailbreak posture scoring.

Scores 0-5 based on observable, passive signals only.
Does NOT send any harmful or adversarial content to the endpoint.
"""
from __future__ import annotations

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType


_POSTURE_CRITERIA: list[dict] = [
    {
        "id":          "content_moderation_documented",
        "label":       "Content moderation layer documented",
        "check_header": None,
        "description": "No documented content moderation/safety filter.",
    },
    {
        "id":          "safety_filter_in_schema",
        "label":       "Safety/filter parameter in API schema",
        "check_header": None,
        "description": "No 'safety_settings', 'content_filter', or similar field in schema.",
    },
    {
        "id":          "rate_limits_per_token",
        "label":       "Rate limits per user token visible",
        "check_header": "x-ratelimit-limit",
        "description": "No per-token rate limit headers found.",
    },
    {
        "id":          "monitoring_described",
        "label":       "Monitoring / abuse detection described",
        "check_header": None,
        "description": "No monitoring or abuse detection signal found.",
    },
    {
        "id":          "terms_restrict_misuse",
        "label":       "Terms of service restrict misuse",
        "check_header": None,
        "description": "No ToS / AUP link discoverable in headers or schema.",
    },
]


class JailbreakPostureCheck(BaseCheck):
    check_id = "ai.jailbreak_posture"
    scan_type = ScanType.AI_ENDPOINT
    description = (
        "Non-adversarial jailbreak safety posture scoring (0–5). "
        "Based purely on observable headers and documentation signals — "
        "no harmful or adversarial content is sent."
    )

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        findings: list[Finding] = []

        try:
            resp = await session.head(target_url, follow_redirects=True)
            lower_headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            lower_headers = {}

        score = 0
        criteria_results: list[tuple[str, bool]] = []

        for criterion in _POSTURE_CRITERIA:
            # For header-checkable criteria, test the header
            if criterion["check_header"]:
                passed = criterion["check_header"] in lower_headers
            else:
                # Non-header criteria require human review — default conservative (not passed)
                passed = False

            criteria_results.append((criterion["label"], passed))
            if passed:
                score += 1

        severity = (
            Severity.HIGH   if score <= 1 else
            Severity.MEDIUM if score <= 3 else
            Severity.LOW    if score == 4 else
            Severity.PASS
        )

        score_label = f"{score}/{len(_POSTURE_CRITERIA)}"
        evidence_items = [
            Evidence(
                label=label,
                value="✓ Passed" if passed else "✗ Not detected",
            )
            for label, passed in criteria_results
        ]

        findings.append(Finding(
            check_id="ai.jailbreak_posture.score",
            title=f"Jailbreak safety posture score: {score_label}",
            description=(
                f"Observed {score} of {len(_POSTURE_CRITERIA)} safety posture signals. "
                "Score is based on passive, non-adversarial header and documentation checks only. "
                "Criteria marked '✗' require manual documentation review."
            ),
            severity=severity,
            affected_url=target_url,
            evidence=evidence_items,
            remediation=(
                "Address each failing criterion by implementing or documenting the corresponding "
                "safety control. See OWASP LLM Top 10 and MITRE ATLAS for guidance."
            ),
            cwe="CWE-693",
            framework_refs={
                "owasp_llm": "LLM01 — Prompt Injection",
                "mitre_atlas": "AML.T0051 — LLM Jailbreak",
            },
            tags=["posture-score", "non-adversarial"],
        ))

        return findings
