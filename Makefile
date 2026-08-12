PYTHON ?= python3

.PHONY: init package publish publish-test test lint fuzz clean

# A uv-created venv has no pip, so `make init` needs a stdlib venv or the system
# interpreter. With uv, the equivalent is: uv sync --group dev
# `--group` needs pip 25.1 or newer, which is why init upgrades pip first.
init:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install --group dev -e .
package:
	rm -rf dist/*
	$(PYTHON) -m build --no-isolation
# Dry run first: a version number on PyPI is permanent, so a bad 0.2.0 costs a
# 0.2.1 rather than a re-upload. TestPyPI accepts the same artifacts.
publish-test:
	$(PYTHON) -m twine upload --repository testpypi dist/* -u __token__
publish:
	$(PYTHON) -m twine upload dist/* -u __token__
test:
	$(PYTHON) -m pytest -q
lint:
	$(PYTHON) -m ruff check .
# A quick pass. CI runs a longer one nightly with a rotating seed.
fuzz:
	$(PYTHON) tools/fuzz.py --iterations 2000 --seed 0
clean:
	find . \( -name '__pycache__' -o -name '*.pyc' -o -name '*.pyo' \) -prune -exec rm -rf {} +
	rm -rf .pytest_cache
	rm -rf dist/*
