"""Campaign orchestration: expand seeds x mutators into attack cases, run each
against the target, detect success, and aggregate into findings + coverage.

The build_cases / summarize logic is pure and testable; only the target calls
touch the network.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from redteam import owasp
from redteam.detectors import Detection, detect
from redteam.mutators import mutate
from redteam.schemas import (
    AttackCase,
    AttackResult,
    CampaignReport,
    Finding,
)
from redteam.target import Target


def _load_seeds(path: str) -> list[str]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [ln for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def build_cases(cfg: dict) -> list[AttackCase]:
    """Expand every category's seeds through its mutators into concrete cases."""
    canary = cfg["target"].get("canary", "")
    cases: list[AttackCase] = []
    n = 0
    for cat in cfg["categories"]:
        seeds = _load_seeds(cat["seeds"])
        for si, seed in enumerate(seeds):
            filled = seed.replace("{canary}", canary).replace("{goal}", "GOAL_PLACEHOLDER")
            for name, text in mutate(filled, cat.get("mutations_per_seed", 1)):
                n += 1
                cases.append(AttackCase(
                    id=f"{cat['name']}-{si}-{name}", category=cat["name"],
                    owasp=cat["owasp"], prompt=text,
                    seed_id=f"{cat['name']}-{si}", mutation=name,
                ))
    return cases


def run_case(target: Target, case: AttackCase, canary: str,
             goal_markers: list[str]) -> AttackResult:
    response = target.send(case.prompt)
    det: Detection = detect(case.category, response, canary, goal_markers)
    return AttackResult(case=case, response=response, succeeded=det.succeeded,
                        detector=det.detector, detail={"reason": det.reason})


def summarize(name: str, results: list[AttackResult]) -> CampaignReport:
    """Turn raw results into findings + per-category coverage."""
    findings: list[Finding] = []
    coverage: dict[str, dict] = {}
    for r in results:
        cat = r.case.category
        cov = coverage.setdefault(cat, {"attacks": 0, "successes": 0})
        cov["attacks"] += 1
        if r.succeeded:
            cov["successes"] += 1
            findings.append(Finding(
                id=r.case.id, category=cat, owasp=r.case.owasp,
                severity=owasp.default_severity(r.case.owasp),
                title=f"{owasp.name_for(r.case.owasp)} via {cat} ({r.case.mutation})",
                attack_prompt=r.case.prompt,
                response_excerpt=r.response[:280],
                detector=r.detector,
                remediation=owasp.remediation_for(r.case.owasp),
                reproduction={"case_id": r.case.id, "detector": r.detector,
                              "reason": r.detail.get("reason", "")},
            ))
    for cov in coverage.values():
        cov["success_rate"] = round(cov["successes"] / cov["attacks"], 3) if cov["attacks"] else 0.0
    # most severe first
    findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return CampaignReport(name=name, total_attacks=len(results),
                          findings=findings, coverage=coverage)


def run_campaign(config_path: str, target: Target) -> CampaignReport:
    cfg = yaml.safe_load(Path(config_path).read_text())
    canary = cfg["target"].get("canary", "")
    cases = build_cases(cfg)
    results = [run_case(target, c, canary, ["GOAL_PLACEHOLDER"]) for c in cases]
    return summarize(cfg.get("name", "campaign"), results)
