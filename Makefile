PY ?= python
CONFIG ?= configs/campaign.yaml
OUT ?= findings

.PHONY: help install campaign report gate test lint fmt clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install:  ## Install deps
	@if command -v uv >/dev/null 2>&1; then uv pip install -e ".[dev]"; \
	else $(PY) -m pip install -e ".[dev]"; fi

campaign:  ## Run the attack campaign against the configured target
	$(PY) -m redteam run --config $(CONFIG) --out $(OUT)

report:  ## Generate the pentest-style vulnerability report
	$(PY) -m redteam report --findings $(OUT) --out report

gate:  ## Fail if a previously-blocked attack now succeeds (guardrail regression)
	$(PY) -m redteam gate --findings $(OUT) --baseline baselines/blocked.json

test:  ## Deterministic unit tests (detectors, mutators, owasp mapping, gate)
	$(PY) -m pytest

lint:  ## Ruff + mypy
	ruff check src tests && mypy src

fmt:
	ruff check --fix src tests && ruff format src tests

clean:
	rm -rf $(OUT) report .pytest_cache .ruff_cache **/__pycache__
