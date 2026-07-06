"""Pentest-style vulnerability report + the CI guardrail-regression gate.

The report is what makes this look professional rather than a pile of jailbreaks:
an executive summary, coverage per OWASP category, and per-finding repro + fix.
"""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Template

from redteam.schemas import CampaignReport, Severity

_MD = Template(
    """# Vulnerability Report — {{ r.name }}

**Attacks run:** {{ r.total_attacks }} · **Findings:** {{ r.findings|length }}
{% set highs = r.findings|selectattr('severity','equalto',sev_high)|list -%}
**High severity:** {{ highs|length }}

## Coverage by OWASP category
| Category | Attacks | Successes | Success rate |
|---|---|---|---|
{% for cat, c in r.coverage.items() -%}
| {{ cat }} | {{ c.attacks }} | {{ c.successes }} | {{ '%.0f' % (c.success_rate * 100) }}% |
{% endfor %}

## Findings
{% for f in r.findings -%}
### [{{ f.severity.value|upper }}] {{ f.title }}  ·  {{ f.owasp }}
- **Detector:** `{{ f.detector }}`
- **Attack:** `{{ f.attack_prompt[:160] }}`
- **Response excerpt:** {{ f.response_excerpt }}
- **Remediation:** {{ f.remediation }}
- **Reproduce:** case `{{ f.reproduction.case_id }}` — {{ f.reproduction.reason }}

{% endfor %}
{% if not r.findings %}_No successful attacks. Guardrails held across all categories._{% endif %}
"""
)


def write_report(report: CampaignReport, out_dir: str) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(report.model_dump_json(indent=2))
    md = _MD.render(r=report, sev_high=Severity.high)
    path = out / "report.md"
    path.write_text(md, encoding="utf-8")
    return path


def gate(findings_dir: str, baseline_path: str, fail_on: str = "high") -> int:
    """CI gate. Fails if:
      (a) any NEW finding at/above `fail_on` severity, or
      (b) a REGRESSION — an attack listed as blocked in the baseline now succeeds.
    Returns a process exit code.
    """
    report = CampaignReport(**json.loads((Path(findings_dir) / "findings.json").read_text()))
    baseline = json.loads(Path(baseline_path).read_text()) if Path(baseline_path).exists() else {}
    previously_blocked = set(baseline.get("blocked_case_ids", []))
    accepted = set(baseline.get("accepted_finding_ids", []))  # triaged/won't-fix

    threshold = Severity(fail_on).rank
    new_high = [f for f in report.findings
                if f.severity.rank >= threshold and f.id not in accepted]
    regressions = [f for f in report.findings if f.id in previously_blocked]

    if new_high or regressions:
        print("❌ RED-TEAM GATE FAILED")
        for f in new_high:
            print(f"   NEW {f.severity.value}: {f.id} ({f.owasp}) — {f.title}")
        for f in regressions:
            print(f"   REGRESSION: {f.id} was blocked in baseline but now succeeds")
        return 1
    print(f"✅ RED-TEAM GATE PASSED — no new ≥{fail_on} findings, no regressions.")
    return 0
