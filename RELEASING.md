# Releasing purepdb

This repository follows the release process shared across the MCRIT ecosystem
([smda](https://github.com/danielplohmann/smda), [purepdb](https://github.com/danielplohmann/purepdb),
[mcrit](https://github.com/danielplohmann/mcrit), [mcritweb](https://github.com/fkie-cad/mcritweb),
[mcrit-plugin](https://github.com/danielplohmann/mcrit-plugin),
[docker-mcrit](https://github.com/danielplohmann/docker-mcrit)). The shape is the same everywhere;
this file states the values that are specific to this repository.

## Versioning

purepdb follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) over the API
listed in `purepdb.__all__`; see the note at the top of `CHANGELOG.md` for what that does and does
not cover.

The version is declared in `pyproject.toml` (`[project].version`) and `purepdb/__init__.py` (`__version__`). The release workflow refuses a tag that does not
match every one of them, so a bump that misses one fails before anything is published.

## Supported Python versions

purepdb supports Python 3.11 through 3.14, and CI runs every one of them: the floor and the
ceiling on Linux, plus the floor on macOS and Windows.

purepdb sits at the bottom of the ecosystem's dependency stack — SMDA depends on it as
`purepdb>=0.3.0`, and MCRIT reaches it through SMDA — so this floor is the one that constrains
everything above it rather than the one that follows. An installer resolves a dependency by the
interpreter's version, so a purepdb that stopped supporting an interpreter SMDA still declares
would be silently held back to its last compatible release under SMDA on that interpreter, with
nothing reporting the downgrade. Nothing in the parser needs a version above 3.11: it reads a
little-endian format with `struct` and `pathlib`.

3.11 support ends at whichever of these comes first:

- SMDA and MCRIT both move their floor to 3.12,
- a runtime dependency drops 3.11 — purepdb has none today, so this is the least likely of the
  three, or
- 3.11 reaches end of life, in October 2027.

The release that raises the floor says so in its `Removed` section, and the one before it carries
a `Deprecated` notice. Raising it is not only metadata: Ruff's pyupgrade rules key on
`target-version`, so the same change starts rewriting syntax to the new floor and stops being
reversible by a one-line edit. The places that state it are `requires-python`, the classifiers,
`[tool.ruff] target-version` and the `ci.yml` matrix.

## Changelog

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). It is the one
authoritative record of what a release contains: the GitHub release notes are generated from it, and
nothing is written twice.

- Every pull request that changes something a user can observe adds its own bullet under
  `## [Unreleased]`, in the subsection it belongs to (`Added`, `Changed`, `Deprecated`, `Removed`,
  `Fixed`, `Security`), while the change is fresh. The `Changelog` check fails a PR that touches
  shipped files without touching `CHANGELOG.md`; apply the `no-changelog` label when a change
  genuinely needs no entry (a typo, a CI-only change), and say why in the PR.
- An entry says what changed and what it costs the reader: what to do when upgrading, what may
  behave differently, which issue or PR it closes.
- Dependency bumps need no entry. GitHub lists them under their own heading in the release notes,
  from the `dependencies` / `github_actions` labels (`.github/release.yml`).

## Cutting a release

1. Check that `main` is green and that everything meant for the release has merged.
2. In one commit on a branch, then merged through a PR:
   - set the new version in `pyproject.toml` (`[project].version`) and `purepdb/__init__.py` (`__version__`);
   - in `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, drop the empty
     subsections, open a fresh empty `## [Unreleased]` above it, and update the compare links at
     the foot of the file.
3. Wait for CI to pass on the merge commit. Then tag that commit and push the tag:

   ```bash
   git tag -a vX.Y.Z -m "purepdb X.Y.Z"
   git push origin vX.Y.Z
   ```

Pushing the tag is the release. `.github/workflows/publish-release.yml` then:

1. **Verify** — refuses to continue unless the tag matches both version strings, `CHANGELOG.md`
   has a `## [X.Y.Z] - <date>` section (which becomes the release notes), the tagged commit is on
   `main`, CI passed on that commit, and the milestone named for the tag, if there is one, has no
   open items.
2. **Build** — builds the sdist and wheel in an isolated environment, checks their metadata with
   `twine check --strict`, and installs the wheel into a clean virtual environment to import it,
   check `__version__` and run the `purepdb` entry point.
3. **Publish** — uploads to PyPI through [trusted publishing](https://docs.pypi.org/trusted-publishers/)
   with signed provenance attestations. No API token is stored anywhere.
4. **Release** — creates the GitHub release for the tag with the changelog section as its body,
   GitHub's generated contributor and PR list appended under it, and the sdist and wheel attached;
   then closes the milestone.

A milestone is optional here: name one `vX.Y.Z`, exactly as the tag is written, to have the gate
see it. A tag with no milestone releases with a notice rather than a failure, so tracking a release
this way is a choice per release and not a step that has to be remembered.

Each gate fails with a message naming what to fix. Nothing has to be remembered at the console.

## Pre-releases

A release candidate is tagged `vX.Y.Zrc1` (also `a1`, `b1`), with the same version string in
`pyproject.toml` (`[project].version`) and `purepdb/__init__.py` (`__version__`) and a `## [X.Y.Zrc1] - YYYY-MM-DD` changelog section. The workflow marks the
GitHub release as a pre-release and does not make it "latest". PyPI
does not install a pre-release unless it is asked for explicitly (`pip install --pre`).

## Rehearsing

Run *Publish release* manually from the Actions tab, choosing a tag as the ref. A manual run goes
through the same gates and build, publishes to [TestPyPI](https://test.pypi.org/p/purepdb) instead of
PyPI (an already-present version is skipped rather than failed), and stops before creating the
GitHub release. Rehearse the first release after any change to the workflow.

## When a release fails

- **A gate failed before anything was published** (tag/version mismatch, missing changelog section,
  tag not on `main`, CI not green): fix the cause on `main`, delete the
  tag locally and on the remote (`git push --delete origin vX.Y.Z`), and tag again once the fix has
  merged. Nothing needs cleaning up.
- **Publishing to PyPI failed part-way**: a version number on PyPI is permanent even when yanked,
  so do not try to reuse it. Fix the cause, bump the patch version, and release again. Yank the
  incomplete version on PyPI if any of its files were accepted.
- **The GitHub release step failed after publishing**: re-run only the failed job from the Actions
  UI; the built artifacts are kept as workflow artifacts and the step is idempotent.

## Maintainer configuration

Done once, by a repository owner; the workflow cannot create these for itself.

- **PyPI trusted publisher** for the `purepdb` project: owner `danielplohmann`, repository `purepdb`,
  workflow `publish-release.yml`, environment `pypi`. The project already exists on PyPI, so this is
  added under its own Publishing settings.
- **TestPyPI trusted publisher**, the same four values with environment `testpypi`, to enable
  rehearsals. `purepdb` does not exist on TestPyPI, so this one is added as a *pending* publisher
  (Your projects → Publishing → add a pending publisher), which names a project that is not there
  yet; the first rehearsal that uploads creates the project and turns it into an ordinary publisher.
  A rehearsal is the only thing that publishes to TestPyPI — pushing a tag always goes to PyPI.
- **GitHub environments** `pypi` and `testpypi` (Settings → Environments). Restricting `pypi` to
  the `v*` tag pattern and requiring a reviewer is recommended: it makes the publish step a
  deliberate click even if a tag is pushed by mistake.
- **Label** `no-changelog`, used by the changelog check.
- Optionally, **immutable releases** (Settings → General → Releases), so a published release's
  assets and tag can no longer be changed.
