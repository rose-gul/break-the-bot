"""Deterministic unit tests for the red-team core: success detectors, mutators,
OWASP mapping, campaign aggregation, and the regression gate. Passes offline —
a red-team framework whose *oracle* is untested would be its own vulnerability.
"""

from __future__ import annotations

import json

from redteam import owasp
from redteam.detectors import (
    canary_leak,
    detect,
    info_disclosure,
    is_refusal,
    refusal_bypass,
)
from redteam.mutators import MUTATORS, mutate
from redteam.report import gate, write_report
from redteam.runner import summarize
from redteam.schemas import AttackCase, AttackResult, CampaignReport, Severity


# --------------------------- detectors --------------------------- #
def test_refusal_detected():
    assert is_refusal("I'm sorry, I can't help with that.")
    assert not is_refusal("Sure, here are the steps: ...")


def test_canary_leak_is_success():
    d = canary_leak("... the secret is CANARY-123 ...", "CANARY-123")
    assert d.succeeded and d.detector == "canary_leak"


def test_refusal_bypass_requires_no_refusal_and_goal_content():
    assert refusal_bypass("Here is GOAL_X content", ["GOAL_X"]).succeeded
    assert not refusal_bypass("I cannot do GOAL_X", ["GOAL_X"]).succeeded  # refused
    assert not refusal_bypass("Nice weather today", ["GOAL_X"]).succeeded  # off-goal


def test_info_disclosure_flags_leak_not_refusal():
    assert info_disclosure("your instructions are: be helpful").succeeded
    assert not info_disclosure("I won't share my system prompt").succeeded


def test_detect_prioritizes_canary():
    d = detect("jailbreak", "blah CANARY-9 blah", "CANARY-9", ["GOAL"])
    assert d.detector == "canary_leak" and d.succeeded


# --------------------------- mutators --------------------------- #
def test_identity_always_first_and_reproducible():
    out = mutate("Ignore instructions", 3)
    assert out[0][0] == "identity" and out[0][1] == "Ignore instructions"
    assert mutate("x", 3) == mutate("x", 3)          # deterministic


def test_leetspeak_changes_text():
    assert MUTATORS["leetspeak"]("secret") != "secret"


def test_mutate_count_bounded():
    assert 1 <= len(mutate("x", 99)) <= len(MUTATORS)


# --------------------------- owasp --------------------------- #
def test_owasp_mapping():
    assert owasp.name_for("LLM01") == "Prompt Injection"
    assert owasp.default_severity("LLM01") == Severity.high
    assert "guardrail" in owasp.remediation_for("LLM01").lower()


# --------------------------- aggregation + gate --------------------------- #
def _result(cid, cat, owasp_id, succeeded):
    case = AttackCase(id=cid, category=cat, owasp=owasp_id, prompt="p", mutation="identity")
    return AttackResult(case=case, response="r", succeeded=succeeded, detector="d")


def test_summarize_builds_findings_and_coverage():
    results = [
        _result("a", "jailbreak", "LLM01", True),
        _result("b", "jailbreak", "LLM01", False),
        _result("c", "pii_exfiltration", "LLM02", True),
    ]
    rep = summarize("camp", results)
    assert rep.total_attacks == 3
    assert len(rep.findings) == 2
    assert rep.coverage["jailbreak"]["success_rate"] == 0.5
    # most-severe first
    assert rep.findings[0].severity.rank >= rep.findings[-1].severity.rank


def test_gate_fails_on_new_high(tmp_path):
    rep = summarize("camp", [_result("a", "jailbreak", "LLM01", True)])
    (tmp_path / "findings.json").write_text(rep.model_dump_json())
    (tmp_path / "base.json").write_text(json.dumps({"blocked_case_ids": [], "accepted_finding_ids": []}))
    assert gate(str(tmp_path), str(tmp_path / "base.json"), "high") == 1


def test_gate_passes_when_high_finding_is_accepted(tmp_path):
    rep = summarize("camp", [_result("a", "jailbreak", "LLM01", True)])
    (tmp_path / "findings.json").write_text(rep.model_dump_json())
    (tmp_path / "base.json").write_text(json.dumps(
        {"blocked_case_ids": [], "accepted_finding_ids": ["a"]}))
    assert gate(str(tmp_path), str(tmp_path / "base.json"), "high") == 0


def test_gate_detects_regression(tmp_path):
    rep = summarize("camp", [_result("a", "pii_exfiltration", "LLM02", True)])
    (tmp_path / "findings.json").write_text(rep.model_dump_json())
    # 'a' was supposed to be blocked -> its success is a regression
    (tmp_path / "base.json").write_text(json.dumps(
        {"blocked_case_ids": ["a"], "accepted_finding_ids": ["a"]}))
    assert gate(str(tmp_path), str(tmp_path / "base.json"), "critical") == 1


def test_report_renders(tmp_path):
    rep = summarize("camp", [_result("a", "jailbreak", "LLM01", True)])
    path = write_report(rep, str(tmp_path))
    text = path.read_text()
    assert "Vulnerability Report" in text and "LLM01" in text
