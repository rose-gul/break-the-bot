"""OWASP LLM Top 10 (2025) mapping + severity helpers. Gives every finding a
shared vocabulary hiring managers and security teams recognize.
"""

from __future__ import annotations

from redteam.schemas import Severity

# OWASP LLM Top 10 (2025) — id -> (name, default severity, default remediation).
OWASP_LLM_TOP_10: dict[str, dict] = {
    "LLM01": {
        "name": "Prompt Injection",
        "severity": Severity.high,
        "remediation": "Treat retrieved/user content as data, not instructions; "
                       "separate system vs. context with strong delimiters; add an "
                       "input/output guardrail and a citation check.",
    },
    "LLM02": {
        "name": "Sensitive Information Disclosure",
        "severity": Severity.high,
        "remediation": "Keep secrets out of the prompt/context; add an output filter "
                       "for system-prompt and secret patterns; least-privilege context.",
    },
    "LLM03": {"name": "Supply Chain", "severity": Severity.medium,
              "remediation": "Vet models/plugins; pin and scan dependencies."},
    "LLM04": {"name": "Data and Model Poisoning", "severity": Severity.high,
              "remediation": "Validate + provenance-check training/RAG data."},
    "LLM05": {"name": "Improper Output Handling", "severity": Severity.high,
              "remediation": "Encode/validate model output before it hits downstream systems."},
    "LLM06": {"name": "Excessive Agency", "severity": Severity.high,
              "remediation": "Minimize tool scope/permissions; require human approval for high-risk actions."},
    "LLM07": {"name": "System Prompt Leakage", "severity": Severity.medium,
              "remediation": "Assume the system prompt is public; never put secrets in it."},
    "LLM08": {"name": "Vector and Embedding Weaknesses", "severity": Severity.medium,
              "remediation": "Access-control the vector store; detect poisoned embeddings."},
    "LLM09": {"name": "Misinformation", "severity": Severity.medium,
              "remediation": "Enforce grounding/citations; measure faithfulness."},
    "LLM10": {"name": "Unbounded Consumption", "severity": Severity.medium,
              "remediation": "Rate-limit; cap output length and cost per request."},
}


def name_for(owasp_id: str) -> str:
    return OWASP_LLM_TOP_10.get(owasp_id, {}).get("name", "Unknown")


def default_severity(owasp_id: str) -> Severity:
    return OWASP_LLM_TOP_10.get(owasp_id, {}).get("severity", Severity.medium)


def remediation_for(owasp_id: str) -> str:
    return OWASP_LLM_TOP_10.get(owasp_id, {}).get(
        "remediation", "Review against OWASP LLM Top 10 guidance."
    )
