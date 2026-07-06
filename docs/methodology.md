# Red-teaming is just QA for systems that fight back

> Draft for the second portfolio blog post. Pairs with
> [Break the Bot]({{repo-link}}) and the [judge-calibration post]({{link}}).

For a decade I wrote negative tests: feed the system garbage, malformed input, the
boundary case nobody planned for, and prove it fails safely. Red-teaming an LLM is the
same instinct with a twist — **the system under test is non-deterministic, and the
"bug" is that it can be *talked into* misbehaving.**

Here's the methodology I use, framed the way a test engineer already thinks.

## 1. Enumerate the attack surface (test-plan design)
A jailbreak dump isn't coverage. I start from the **OWASP LLM Top 10** and treat each
risk as a test category: prompt injection (direct + indirect), sensitive-information
disclosure, excessive agency, and so on. Now "what did I test?" has an auditable answer.

## 2. Seeds × mutators (fuzzing)
Each category has a small seed corpus of known patterns. Then **mutators** fuzz them —
leetspeak, base64 wrapping, role-play framing, zero-width spaces — to probe whether a
guardrail matches on *surface strings* or actual *intent*. A filter that blocks
`ignore previous instructions` but not `1gn0r3 pr3v10u5 1n5truct10n5` isn't a guardrail,
it's a speed bump. (This is input fuzzing, straight out of the QA playbook.)

## 3. The success oracle is the hard part
In traditional testing the oracle is easy: does the assertion pass? Here, deciding
whether an attack *worked* is itself the crux. I use layered detectors:
- **Canary leak** (strongest): plant a secret in the system prompt or a poisoned
  document; if it appears in the output, injection/exfiltration succeeded — unambiguous.
- **Refusal bypass:** the model didn't refuse *and* produced goal content.
- **Info disclosure:** sensitive patterns leaked without a refusal.

A red-team framework whose oracle is wrong is worse than none — so the detectors are the
first thing I unit-test.

## 4. Multi-turn escalation
Modern guardrails hold against a single hostile prompt but crack under a slow build-up
(Crescendo): establish a benign frame, then narrow the ask over several turns. Testing
only single prompts misses the attacks that actually work in the wild.

## 5. Indirect injection — attack your own RAG
The highest-impact class for a RAG app: the injection rides in through a **retrieved
document**, not the user. I poison a doc in my own [Grounded RAG]({{link}}) corpus and
check whether the app treats retrieved text as *data* or as *commands*. It's the AI
version of stored XSS.

## 6. A finding is reproducible or it doesn't count
Every finding records the exact input, the response, the detector that fired, and an
OWASP mapping + remediation — a real bug report, not a screenshot. The output reads like
a pentest, because that's the bar.

## 7. Lock the fix with a regression suite
When I patch a jailbreak, its case joins a **guardrail regression baseline**. If a future
prompt or model change re-opens it, CI fails. This is the single most QA-native idea in
the whole project: *a fixed bug that comes back is a process failure, and process
failures are preventable with a test.*

## The takeaway
Red-teaming looks like security and it is — but the day-to-day is negative testing,
fuzzing, oracle design, and regression protection. If you've done test automation, you
already have the instincts; you just point them at an adversary instead of a compiler.
