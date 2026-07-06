# 💥 Break the Bot — an automated LLM red-team framework

> Probes an LLM application for jailbreaks, prompt injection, PII leakage, and unsafe
> tool use — then produces a **repeatable, categorized vulnerability report** like a
> pentest, but for AI. Every finding is mapped to the **OWASP LLM Top 10**, scored by
> severity, and comes with reproduction steps and a remediation.

<!-- Replace with your real campaign numbers once you've run it against a target. -->
**Headline result (example — replace with yours):** A campaign of **214 attacks across
7 OWASP categories** against my own [Grounded RAG app](../project-04-grounded-rag) found
**9 findings** (2 high, 4 medium, 3 low) — including an **indirect prompt injection** via a
poisoned retrieved document. After adding an output guardrail + a citation check, a re-run
dropped it to **1 low finding**, and those fixes are now locked by a **guardrail regression
suite** in CI.

---

> ⚠️ **Authorized use only.** This is a defensive security tool for red-teaming systems
> **you own or are explicitly authorized to test** (here, my own RAG app). The seed attacks
> are the well-documented, educational patterns from the OWASP LLM Top 10 and public
> research — used to *find and fix* weaknesses, not to attack third-party services.

---

## Why this project exists

Red-team demos usually paste a few jailbreak prompts and call it a day. This treats
adversarial testing the way a test engineer treats any negative-testing problem:
**systematic coverage, repeatable cases, severity triage, and regression protection.**

| Security-testing concept | How this framework implements it |
|---|---|
| Attack surface enumeration | An **attack taxonomy** mapped to OWASP LLM Top 10 (`owasp.py`) |
| Negative test cases | **Seed attack corpora** + fuzzing-style **mutators** (`mutators.py`) |
| Pass/fail oracle | **Success detectors** — canary leaks, refusal bypass, PII patterns (`detectors.py`) |
| Multi-step exploit | **Multi-turn escalation** (Crescendo-style) beyond single-prompt gotchas |
| Bug report | A **pentest-style vulnerability report** with repro + remediation (`report.py`) |
| Regression test | A **guardrail regression suite** — a blocked attack that later succeeds fails CI |

> The framing that writes itself: **red-teaming is QA for a system that's actively trying
> to fool you.** Negative testing + fuzzing + exploit thinking — the test-automation
> skillset, pointed at an adversary.

---

## Architecture

```
  seed corpora ─┐
                ├─▶ mutators ─▶ attack cases ─▶ ┌──────────┐   ┌────────────┐   ┌───────────┐
  attack gens ──┘   (fuzzing)   (per OWASP cat) │  target  │──▶│ detectors  │──▶│ findings  │
                                                │ (SUT)    │   │ did it     │   │ + severity│
  multi-turn escalation ───────────────────────▶│ RAG/LLM  │   │ succeed?   │   │ + OWASP   │
                                                └──────────┘   └────────────┘   └─────┬─────┘
                                                                                      ▼
                                                    vuln report (MD/HTML)  ◀───  runner aggregates
                                                    + CI guardrail-regression gate
```

## Quickstart

```bash
make install
cp .env.example .env            # add OPENAI_API_KEY (+ target config)
make campaign                   # run the attack campaign against the configured target
make report                     # generate the pentest-style vulnerability report
make gate                       # fail CI if a previously-blocked attack now succeeds
make test                       # deterministic unit tests (detectors, mutators, owasp, gate)
```

## Repo layout

```
break-the-bot/
├── README.md · pyproject.toml · Makefile · .env.example
├── .github/workflows/redteam.yml
├── configs/campaign.yaml             # target, categories, thresholds
├── attacks/seeds/                    # educational OWASP-style seed attacks
│   ├── jailbreak.txt · prompt_injection.txt · pii_exfiltration.txt
├── src/redteam/
│   ├── schemas.py                    # AttackCase, AttackResult, Finding, Severity
│   ├── target.py                     # adapter to the system under test (Project 4 / any LLM)
│   ├── detectors.py                  # success oracles: canary leak, refusal bypass, PII  ✓tested
│   ├── mutators.py                   # fuzzing-style prompt mutations  ✓tested
│   ├── owasp.py                      # OWASP LLM Top 10 mapping + severity  ✓tested
│   ├── runner.py                     # campaign orchestration -> findings
│   ├── report.py                     # vuln report + CI guardrail-regression gate  ✓tested
│   └── attacks/                      # attack generators (jailbreak, injection, pii)
├── tests/test_redteam.py             # deterministic core — passes offline
└── docs/methodology.md               # the red-team methodology write-up (blog draft)
```

## Design decisions (talking points)
- **A finding is reproducible or it doesn't count.** Every finding stores the exact attack
  input, the target's response, and the detector that fired — so anyone can re-run it.
- **Coverage is measured, not vibes.** The report shows attacks-run and success-rate per
  OWASP category, so gaps are visible instead of hidden.
- **Fixes are locked by regression.** Once you patch a jailbreak, its case joins the
  guardrail regression suite; if a future change re-opens it, CI fails.
- **Point it at your own app.** The default target is the Project 4 RAG assistant, including
  an *indirect* injection that poisons a retrieved document — a realistic, high-impact class.

## Stretch goals
- [ ] Autonomous attacker agent that discovers novel jailbreaks (RedAgent-style)
- [ ] A defensive prompt-injection classifier + measure its precision/recall against your own attacks
- [ ] Contribute new probes upstream to [garak](https://github.com/NVIDIA/garak) / deepteam
- [ ] MITRE ATLAS technique tags alongside OWASP categories

---

🚧 **Scaffold.** Detectors, mutators, OWASP mapping, and the regression gate are implemented
and **unit-tested offline**; the live target calls and attack-generation LLM calls are stubbed
with `TODO(you)` markers to fill in as you work through the study plan.

**Tooling to layer in:** this framework is deliberately small and legible; in a real
engagement pair it with [garak](https://github.com/NVIDIA/garak) (model-layer scanner),
[promptfoo red-team](https://www.promptfoo.dev/docs/red-team/), and
[PyRIT](https://github.com/Azure/PyRIT) — this repo shows you understand the *method*, not
just the tools.
