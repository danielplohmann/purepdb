PYTHON ?= python3

.PHONY: init package publish publish-test test clean

# A uv-created venv has no pip, so `make init` needs a stdlib venv or the system
# interpreter. With uv, the equivalent is: uv pip install -e ".[dev]"
init:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"
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
clean:
	find . \( -name '__pycache__' -o -name '*.pyc' -o -name '*.pyo' \) -prune -exec rm -rf {} +
	rm -rf .pytest_cache
	rm -rf dist/*
