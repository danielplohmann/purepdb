"""The release gate (`.github/workflows/scripts/release_guard.py`) runs once per release, minutes
before the artefact becomes permanent, so here is the only place its checks can be exercised
before they matter."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / ".github" / "workflows" / "scripts" / "release_guard.py"

CHANGELOG = """# Changelog

## [Unreleased]

### Fixed

- something not yet released.

## [0.6.0] - 2026-09-20

### Changed

- the thing this release did.

## [0.6.0rc1] - 2026-09-15

### Added

- the candidate.

## [0.5.0] - 2026-09-10

### Fixed

- an older release.
"""


@pytest.fixture(scope="module")
def guard():
    if not SCRIPT.exists():
        pytest.skip("running outside a source tree")
    spec = importlib.util.spec_from_file_location("release_guard", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tree(tmp_path: Path, version: str, changelog: str = CHANGELOG) -> Path:
    pyproject = f'[project]\nname = "purepdb"\nversion = "{version}"\n'
    (tmp_path / "pyproject.toml").write_text(pyproject)
    (tmp_path / "purepdb").mkdir()
    (tmp_path / "purepdb" / "__init__.py").write_text(f'__version__ = "{version}"\n')
    (tmp_path / "CHANGELOG.md").write_text(changelog)
    return tmp_path


def test_the_section_for_a_version_is_returned_and_stops_at_the_next(guard):
    notes = guard.changelogSection(CHANGELOG, "0.6.0")
    assert "the thing this release did" in notes
    assert "the candidate" not in notes
    assert "not yet released" not in notes


def test_a_missing_or_empty_section_fails(guard):
    with pytest.raises(SystemExit, match="Unreleased"):
        guard.changelogSection(CHANGELOG, "0.7.0")
    with pytest.raises(SystemExit, match="nothing under it"):
        empty = "# Changelog\n\n## [9.0.0] - 2026-01-01\n\n## [8.0.0] - 2025-01-01\n\n- x\n"
        guard.changelogSection(empty, "9.0.0")


def test_an_undated_heading_is_not_a_section(guard):
    with pytest.raises(SystemExit):
        guard.changelogSection("# Changelog\n\n## [9.0.0]\n\n- something.\n", "9.0.0")


def test_a_v_prefixed_heading_is_accepted(guard):
    assert "x" in guard.changelogSection("## [v9.0.0] - 2026-01-01\n\n- x\n", "9.0.0")


def test_the_declared_versions_in_this_tree_agree(guard):
    versions = guard.declaredVersions(ROOT)
    assert set(versions) == {"pyproject.toml", "purepdb.__version__"}
    assert len(set(versions.values())) == 1


def test_a_matching_tag_passes_and_writes_notes_and_outputs(guard, tmp_path):
    root = _tree(tmp_path, "0.6.0")
    notes, output = root / "notes.md", root / "output.txt"
    argv = ["--tag", "v0.6.0", "--root", str(root)]
    argv += ["--notes", str(notes), "--github-output", str(output)]
    assert guard.main(argv) == 0
    assert "the thing this release did" in notes.read_text()
    assert output.read_text() == "version=0.6.0\nprerelease=false\n"


def test_a_pre_release_tag_is_flagged(guard, tmp_path):
    root = _tree(tmp_path, "0.6.0rc1")
    output = root / "output.txt"
    argv = ["--tag", "v0.6.0rc1", "--root", str(root), "--github-output", str(output)]
    assert guard.main(argv) == 0
    assert "prerelease=true" in output.read_text()


@pytest.mark.parametrize("tag", ["0.6.0", "v0.6", "v0.6.0-rc1", "v0.6.0.dev1", "vlatest"])
def test_a_malformed_tag_fails(guard, tmp_path, tag):
    root = _tree(tmp_path, "0.6.0")
    with pytest.raises(SystemExit):
        guard.main(["--tag", tag, "--root", str(root)])


def test_a_tag_disagreeing_with_any_declared_version_fails(guard, tmp_path):
    root = _tree(tmp_path, "0.5.0")
    with pytest.raises(SystemExit, match=r"0\.5\.0"):
        guard.main(["--tag", "v0.6.0", "--root", str(root)])
    (root / "pyproject.toml").write_text('[project]\nname = "purepdb"\nversion = "0.6.0"\n')
    with pytest.raises(SystemExit, match=r"purepdb\.__version__ = 0\.5\.0"):
        guard.main(["--tag", "v0.6.0", "--root", str(root)])
