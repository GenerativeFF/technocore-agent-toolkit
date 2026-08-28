# Convenience targets for local development and CI parity.
#
# These targets mirror what GitHub Actions does on every push so
# contributors can reproduce CI failures before opening a PR. None
# of them require network access beyond `pip install -r
# requirements.txt`.

PYTHON ?= python3

.PHONY: help test vectors regenerate-vectors all check clean

help:
	@echo "Targets:"
	@echo "  test              run the full unit-test suite (CI parity)"
	@echo "  vectors           regenerate every committed vector file"
	@echo "  regenerate-vectors"
	@echo "                    alias of 'vectors'"
	@echo "  check             alias of 'test'"
	@echo "  all               test + vectors"
	@echo "  clean             remove Python bytecode caches"

test:
	$(PYTHON) -m unittest discover tests -v

vectors: regenerate-vectors

regenerate-vectors:
	$(PYTHON) scripts/gen_vectors.py
	$(PYTHON) scripts/gen_nonce_vectors.py
	$(PYTHON) scripts/gen_scanner_vectors.py

check: test

all: test vectors

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete