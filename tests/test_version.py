"""The version is written in two places, so they have to be checked against
each other.

`pyproject.toml` decides what the built artefact is called and what the release
workflow compares the tag against. `purepdb.__version__` is what a caller reads
at runtime. Nothing ties them together, so a bump that touches one and not the
other ships a package whose metadata and its own report disagree -- and the
release workflow would not notice, because it only reads pyproject.
"""

import tomllib
from pathlib import Path

import pytest

import purepdb

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def test_the_two_version_strings_agree():
    if not PYPROJECT.exists():
        pytest.skip("running outside a source tree")
    packaged = tomllib.loads(PYPROJECT.read_text())["project"]["version"]
    assert purepdb.__version__ == packaged
