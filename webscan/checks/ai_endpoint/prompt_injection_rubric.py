"""checks/ai_endpoint/prompt_injection_rubric.py — Passive prompt-injection posture rubric.

This check is ENTIRELY PASSIVE and NON-ADVERSARIAL.
It reviews documentation signals, API schema fields, and response headers.
It does NOT send any injection payloads or adversarial content.
"""
from __future__ import annotations

from checks.base import BaseCheck
from core.models import Evidence, Finding, Severity, ScanType

_RUBRIC: list[dict] = [
    {
        "criterion":    "System prompt isolation documented",
        "check_id_sfx": "system_prompt_isolation",
        "description":  "No documentation or schema evidence of system-prompt sandboxing.",
        "remediation":  "Document how user input is separated from system prompts and instructions.",
        "framework":    "LLM01 — Prompt Injection",
    },
    {
        "criterion":    "Input validation / sanitisation mentioned",
        "check_id_sfx": "input_validation",
        "description":  "No evidence of input sanitisation in API schema or documentation.",
        "remediation":  "Apply input length limits and content validation. Document this in your API spec.",
        "framework":    "LLM01 — Prompt Injection",
    },
    {
        "criterion":    "Output validation / post-processing mentioned",
        "check_id_sfx": "output_validation",
        "description":  "No evidence of output filtering or post-processing.",
        "remediation":  "Filter model outputs before returning them to callers.",
        "framework":    "LLM01 — Prompt Injection",
    },
    {
        "criterion":    "Rate limits enforced per user token",
        "check_id_sfx": "per_user_rate_limits",
        "description":  "No evidence of per-user/per-token rate limiting.",
        "remediation":  "Apply per-user rate limits (not just global limits) to prevent abuse.",
        "framework":    "LLM04 — Model Denial of Service",
    },
    {
        "criterion":    "Monitoring and alerting described",
        "check_id_sfx": "monitoring",
        "description":  "No evidence of monitoring for abnormal prompt patterns or abuse.",
        "remediation":  "Implement logging and alerting for unusual prompt patterns or high-volume usage.",
        "framework":    "LLM08 — Excessive Agency",
    },
    {
        "criterion":    "Content moderation documented",
        "check_id_sfx": "content_moderation",
        "description":  "No content moderation layer mentioned.",
        "remediation":  "Document and enforce a content moderation layer for both inputs and outputs.",
        "framework":    "LLM02 — Insecure Output Handling",
    },
]


class PromptInjectionRubricCheck(BaseCheck):
    check_id = "ai.prompt_injection_rubric"
    scan_type = ScanType.AI_ENDPOINT
    description = (
        "Passive posture assessment against a prompt-injection rubric. "
        "No adversarial content is sent. Scores based on documentation and schema signals."
    )

    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        """
        Since this check is passive and observational rather than active,
        it produces HIGH findings for each missing rubric criterion.
        A real implementation would ingest the OpenAPI schema (from openapi_discovery)
        and match criterion patterns against it — here we document the rubric items
        as findings to surface in the report for human review.
        """
        findings: list[Finding] = []

        for item in _RUBRIC:
            findings.append(Finding(
                check_id=f"ai.prompt_injection_rubric.{item['check_id_sfx']}",
                title=f"[Rubric] {item['criterion']} — manual verification needed",
                description=(
                    f"{item['description']} "
                    "This rubric item requires human review of the provider's documentation and API schema."
                ),
                severity=Severity.MEDIUM,
                affected_url=target_url,
                evidence=[Evidence(label="Criterion", value=item["criterion"])],
                remediation=item["remediation"],
                cwe="CWE-20",
                framework_refs={"owasp_llm": item["framework"]},
                tags=["rubric", "manual-review", "prompt-injection"],
            ))

        return findings
