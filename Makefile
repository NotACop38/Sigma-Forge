# sigma-forge developer tasks. Everything runs through uv, so a fresh clone needs
# only `make install`. `make test` runs the same gates as CI.
.DEFAULT_GOAL := help
RUN := uv run

.PHONY: help install lint typecheck check test coverage golden docs requirements taxonomy clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-13s\033[0m %s\n", $$1, $$2}'

install: ## Create the virtualenv with runtime and dev dependencies
	uv sync

lint: ## Ruff lint and format check
	$(RUN) ruff check src tests scripts
	$(RUN) ruff format --check src tests scripts

typecheck: ## Strict mypy over src, tests, and scripts
	$(RUN) mypy

check: ## The rule gate: lint, convert, and fire-test every rule
	$(RUN) sigma-forge check

test: lint typecheck ## All CI gates: lint, types, tests (>=90% branch coverage), rule gate, artifacts
	$(RUN) pytest --cov
	$(RUN) sigma-forge check
	$(RUN) sigma-forge coverage --check

coverage: ## Regenerate the ATT&CK Navigator layer and the SVG coverage card
	$(RUN) sigma-forge coverage

golden: ## Regenerate conversion snapshots after an intended change (review the diff)
	$(RUN) python -m tests.regen_golden

docs: coverage ## Regenerate every generated image under docs/
	$(RUN) python scripts/render_check_svg.py

requirements: ## Re-export requirements.txt (pip fallback) from uv.lock
	uv export --frozen --no-hashes --no-emit-project -o requirements.txt

taxonomy: ## Refresh the pinned ATT&CK/ATLAS snapshots (network; maintainers only)
	$(RUN) python scripts/update_taxonomy.py

clean: ## Remove caches and build output
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov build dist
	find . -type d -name __pycache__ -not -path './.venv/*' -exec rm -rf {} +
