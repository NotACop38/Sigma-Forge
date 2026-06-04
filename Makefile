# sigma-forge — developer task runner.
# Everything runs through `uv` so a clean clone needs no manual venv steps.
.DEFAULT_GOAL := help
RUN := uv run
RULES := rules/classic rules/llm
PROMPT ?=
export PROMPT

.PHONY: help install lint typecheck convert evaluate coverage test golden draft clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## Sync the environment (deps + sigma plugins)
	uv sync

lint: ## Run ruff (lint) over src + tests
	$(RUN) ruff check src tests

typecheck: ## Run mypy over the package
	$(RUN) mypy

convert: ## Convert every rule to Splunk SPL and Sentinel KQL
	$(RUN) sigma-forge convert --all

evaluate: ## Fire-test every rule against its synthetic sample logs
	$(RUN) sigma-forge evaluate --all

coverage: ## Emit the ATT&CK Navigator layer JSON + render the heatmap PNG
	$(RUN) sigma-forge coverage --layer docs/attack-layer.json --png docs/images/attack-layer.png

golden: ## Regenerate golden SPL/KQL conversion snapshots
	$(RUN) python -m tests.regen_golden

test: ## Run the full test suite (lint, convert, evaluate)
	$(RUN) ruff check src tests
	$(RUN) pytest

draft: ## Draft a rule from a threat sentence via a LOCAL LLM (needs a running endpoint)
	$(RUN) sigma-forge draft "$$PROMPT"

clean: ## Remove caches and build artifacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -not -path './.venv/*' -exec rm -rf {} +
