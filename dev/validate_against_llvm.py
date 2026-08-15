#!/usr/bin/env python3
"""Cross-check purepdb against llvm-pdbutil, record by record.

The suite in `tests/` must not need an LLVM toolchain, so the strongest
evidence this parser has -- agreement with the reference implementation -- can
only live outside it. That is what this script is: the comparisons that were
run by hand and reported in pull request descriptions, written down so anyone
can re-run them, and so a nightly job can fail when one stops holding.

    python dev/validate_against_llvm.py                 # tests/data/**/*.pdb
    python dev/validate_against_llvm.py path/to/one.pdb  # or a private corpus

Exit status is 0 when every check agrees, 1 on any disagreement, and 0 with a
message when `llvm-pdbutil` is not on PATH -- pass `--require-tool` to make
that an error instead, which is what CI does.

Seven checks, over the subsystems whose accuracy was claimed in a PR
description and nowhere else:

    procs           S_*PROC32 name, address and code size
    publics         S_PUB32 name, address and function flag
    labels          S_LABEL32 name and address
    constants       S_CONSTANT name and value
    udts            S_UDT name and type index
    contributions   the Section Contribution table, and the module each
                    function is attributed to through it
    lines           every file:line and the address it starts at
    inline sites    each inlined body, its name, and every code range it covers

Three things about llvm-pdbutil's output are worth knowing before trusting a
comparison against it, all of them handled here:

  * `dump -l` prints line blocks under modules whose debug stream is 0xFFFF,
    repeating the previous module's blocks. Those modules hold no line info at
    all; `dump --modules` is what says so, and their blocks are skipped.
  * it renders the line number 0xF00F00 -- "do not step into this" -- as the
    label `NSI` rather than as a number.
  * addresses print as `segment:offset` with the offset in *decimal*, while
    line-table offsets in the same output print in hex.
"""

from __future__ import annotations

import argparse
import bisect
import collections
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from purepdb import PDB, PdbError

REPO = Path(__file__).resolve().parent.parent
DEFAULT_CORPUS = REPO / "tests" / "data"

# 0xF00F00, the "do not step into this" marker, which llvm-pdbutil labels.
NSI_LINE = 0xF00F00
NO_STREAM = 0xFFFF


class ParseError(Exception):
    """llvm-pdbutil printed something this script does not understand.

    Raised rather than skipped: a comparison that quietly parsed half of the
    reference output would report agreement it did not verify.
    """


@dataclass
class Result:
    ours: list
    theirs: list
    notes: list[str] = field(default_factory=list)


@dataclass
class Check:
    name: str
    args: tuple[str, ...]  # what to pass to `llvm-pdbutil dump`
    compare: Callable[[PDB, str], Result]


# --- running the reference implementation -----------------------------------

def dump(tool: str, path: Path, args: Iterable[str], cache: dict) -> str:
    key = (str(path), tuple(args))
    if key not in cache:
        proc = subprocess.run([tool, "dump", *args, str(path)],
                              capture_output=True, text=True)
        if proc.returncode != 0 and not proc.stdout:
            raise ParseError(f"llvm-pdbutil {' '.join(args)} failed: "
                             f"{proc.stderr.strip()[:200]}")
        cache[key] = proc.stdout
    return cache[key]


# --- parsing what it printed ------------------------------------------------

_MODULE = re.compile(r"^\s*Mod (\d+) \| `(?P<name>.*)`:")
_RECORD = re.compile(r"^\s*(?P<offset>\d+) \| (?P<kind>S_\w+) \[size = \d+\]"
                     r"(?P<rest>.*)$")
_NAME = re.compile(r"`(?P<name>.*)`")
# Segment and offset both print in decimal here -- `addr = 0001:193488` -- which
# is not the base the line tables use.
_ADDR = re.compile(r"addr = (?P<segment>\d+):(?P<offset>\d+)")


@dataclass
class RefRecord:
    kind: str
    header: str
    body: list[str]
    module: int

    @property
    def name(self) -> str:
        m = _NAME.search(self.header)
        return m.group("name") if m else ""

    def address(self) -> tuple[int, int] | None:
        for line in (self.header, *self.body):
            m = _ADDR.search(line)
            if m:
                return int(m.group("segment")), int(m.group("offset"))
        return None

    def field(self, pattern: str) -> str | None:
        for line in (self.header, *self.body):
            m = re.search(pattern, line)
            if m:
                return m.group(1)
        return None


def iter_records(text: str):
    """Yield one RefRecord per symbol record, with its continuation lines."""
    current: RefRecord | None = None
    module = -1
    for line in text.splitlines():
        mod = _MODULE.match(line)
        if mod:
            if current is not None:
                yield current
                current = None
            module = int(mod.group(1))
            continue
        rec = _RECORD.match(line)
        if rec:
            if current is not None:
                yield current
            current = RefRecord(kind=rec.group("kind"), header=rec.group("rest"),
                                body=[], module=module)
        elif current is not None:
            current.body.append(line)
    if current is not None:
        yield current


def module_names(text: str) -> dict[int, str]:
    """Module index -> name, from `dump --modules`."""
    return {int(m.group(1)): m.group("name")
            for m in (_MODULE.match(line) for line in text.splitlines())
            if m}


def modules_without_a_stream(text: str) -> set[int]:
    """Modules whose debug stream is 0xFFFF, from `dump --modules`.

    `dump -l` prints line blocks under these -- a repeat of the previous
    module's -- and they are not real: the module has no debug stream to hold
    them. Comparing them would fail against any parser that reads the file.
    """
    out, current = set(), -1
    for line in text.splitlines():
        mod = _MODULE.match(line)
        if mod:
            current = int(mod.group(1))
            continue
        m = re.match(r"^\s*debug stream: (\d+),", line)
        if m and int(m.group(1)) == NO_STREAM:
            out.add(current)
    return out


# --- the checks -------------------------------------------------------------

PROC_KINDS = {"S_GPROC32", "S_LPROC32", "S_GPROC32_ID", "S_LPROC32_ID"}


def check_procs(pdb: PDB, text: str) -> Result:
    ours = [(p.name, p.segment, p.offset, p.code_size) for p in pdb.module_procs()]
    theirs = []
    for rec in iter_records(text):
        if rec.kind not in PROC_KINDS:
            continue
        addr = rec.address()
        size = rec.field(r"code size = (\d+)")
        if addr is None or size is None:
            raise ParseError(f"no address or code size on {rec.kind} `{rec.name}`")
        theirs.append((rec.name, addr[0], addr[1], int(size)))
    return Result(ours, theirs)


def check_publics(pdb: PDB, text: str) -> Result:
    ours = [(p.name, p.segment, p.offset, p.is_function)
            for p in pdb.public_symbols()]
    theirs = []
    for rec in iter_records(text):
        if rec.kind != "S_PUB32":
            continue
        addr = rec.address()
        flags = rec.field(r"flags = (.*), addr")
        if addr is None or flags is None:
            raise ParseError(f"no address or flags on S_PUB32 `{rec.name}`")
        theirs.append((rec.name, addr[0], addr[1], "function" in flags))
    return Result(ours, theirs)


def check_labels(pdb: PDB, text: str) -> Result:
    """S_LABEL32 by name and address, including the ones that carry neither.

    A nameless label with segment 0 is a real record that rust-lld emits, and
    both sides report it, so it is compared rather than filtered -- dropping it
    on either side would hide a producer purepdb has to keep reading.
    """
    ours = [(label.name, label.segment, label.offset) for label in pdb.labels()]
    theirs = []
    for rec in iter_records(text):
        if rec.kind != "S_LABEL32":
            continue
        addr = rec.address()
        if addr is None:
            raise ParseError(f"no address on S_LABEL32 `{rec.name}`")
        theirs.append((rec.name, addr[0], addr[1]))
    return Result(ours, theirs)


def check_constants(pdb: PDB, text: str) -> Result:
    ours = [(c.name, c.value) for c in pdb.constants()]
    theirs = []
    for rec in iter_records(text):
        if rec.kind != "S_CONSTANT":
            continue
        value = rec.field(r"value = (-?\d+)")
        if value is None:
            # A value purepdb does not decode either -- a real leaf kind it
            # skips, or one llvm prints as something other than an integer.
            # Counted rather than compared, since neither side has a number.
            continue
        theirs.append((rec.name, int(value)))
    return Result(ours, theirs)


def check_udts(pdb: PDB, text: str) -> Result:
    ours = [(u.name, u.type_index) for u in pdb.udts()]
    theirs = []
    for rec in iter_records(text):
        if rec.kind != "S_UDT":
            continue
        index = rec.field(r"original type = (0x[0-9A-Fa-f]+)")
        if index is None:
            raise ParseError(f"no type index on S_UDT `{rec.name}`")
        theirs.append((rec.name, int(index, 16)))
    return Result(ours, theirs)


_SC = re.compile(r"^\s*SC\[(?P<section>[^\]]*)\]\s*\| mod = (?P<mod>\d+), "
                 r"(?P<segment>\d+):(?P<offset>\d+), size = (?P<size>\d+)")


def _reference_contributions(text: str) -> list[tuple[int, int, int, int]]:
    return [(int(m.group("segment")), int(m.group("offset")),
             int(m.group("size")), int(m.group("mod")))
            for m in (_SC.match(line) for line in text.splitlines()) if m]


def check_contributions(pdb: PDB, text: str) -> Result:
    ours = [(c.segment, c.offset, c.size, c.module_index)
            for c in pdb.section_contributions()]
    return Result(ours, _reference_contributions(text))


def check_module_attribution(pdb: PDB, text: str, modules: dict[int, str]) -> Result:
    """Every function's `module`, against a lookup built from llvm's table.

    The table check above compares the rows; this compares what purepdb *does*
    with them, which is the claim `Function.module` actually makes. The lookup
    here is deliberately a separate implementation from `dbi.ContributionMap`.
    """
    contributions = sorted(_reference_contributions(text))
    keys = [(segment, offset) for segment, offset, _size, _mod in contributions]

    def attribute(segment: int, offset: int) -> str | None:
        i = bisect.bisect_right(keys, (segment, offset)) - 1
        if i < 0:
            return None
        seg, off, size, mod = contributions[i]
        if seg != segment or not off <= offset < off + size:
            return None
        return modules.get(mod)

    ours, theirs = [], []
    for fn in pdb.functions():
        ours.append((fn.name, fn.segment, fn.offset, fn.module))
        theirs.append((fn.name, fn.segment, fn.offset,
                       attribute(fn.segment, fn.offset)))
    return Result(ours, theirs)


# A file heading carries a checksum, or says it has none. Every form is
# spelled out rather than matched loosely, because a heading this script does
# not recognise would be read as more of the previous file's lines -- which is
# not a parse failure, it is 70000 entries attributed to the wrong file.
_LINE_FILE = re.compile(r"^(?P<file>\S.*?) \((?:no checksum"
                        r"|(?:MD5|SHA-1|SHA-256|None): ?[0-9A-Fa-f]*)\)\s*$")
_LINE_UNRESOLVED = re.compile(r"^\s*\(unknown file name offset")
_LINE_BLOCK = re.compile(r"^\s*(?P<segment>\d+):[0-9A-Fa-f]{8}-"
                         r"[0-9A-Fa-f]{8}, line/addr entries = (?P<count>\d+)")
# `NSI` where a line number would be, and the offset in hex -- the other base
# from the one addresses use.
_LINE_ENTRY = re.compile(r"(?P<line>\d+|NSI)\s+(?P<offset>[0-9A-Fa-f]{8})")


def check_lines(pdb: PDB, text: str, streamless: set[int],
                modules: dict[int, str]) -> Result:
    ours = [(line.module, line.file, line.line, line.segment, line.offset)
            for line in pdb.lines()]

    theirs: list[tuple] = []
    module, file, segment, expected, seen = -1, None, 0, 0, 0
    unresolved = 0

    def check_block_is_complete():
        if expected != seen:
            raise ParseError(f"module {module}: read {seen} line entries where "
                             f"the block header said {expected}")

    for raw in text.splitlines():
        mod = _MODULE.match(raw)
        if mod:
            check_block_is_complete()
            module, file, expected, seen = int(mod.group(1)), None, 0, 0
            continue
        if module == -1 or not raw.strip():
            continue  # the banner above the first module, and blank lines
        if module in streamless:
            # See `modules_without_a_stream`: these blocks are a repeat of the
            # previous module's and describe nothing.
            continue
        block = _LINE_BLOCK.match(raw)
        if block:
            check_block_is_complete()
            segment = int(block.group("segment"))
            expected, seen = int(block.group("count")), 0
            continue
        named = _LINE_FILE.match(raw)
        if named:
            file = named.group("file")
            continue
        if _LINE_UNRESOLVED.match(raw):
            # llvm reports the offset it could not resolve; purepdb drops the
            # entry. Both sides lose it, so it is counted, not compared.
            file = None
            continue
        entries = list(_LINE_ENTRY.finditer(raw))
        if not entries or _LINE_ENTRY.sub("", raw).strip(" \t!"):
            raise ParseError(f"module {module}: unrecognised line {raw!r}")
        for entry in entries:
            seen += 1
            if file is None:
                unresolved += 1
                continue
            number = (NSI_LINE if entry.group("line") == "NSI"
                      else int(entry.group("line")))
            theirs.append((modules.get(module, ""), file, number, segment,
                           int(entry.group("offset"), 16)))
    check_block_is_complete()

    notes = []
    if unresolved:
        notes.append(f"{unresolved} entry(ies) name a file neither side could "
                     f"resolve; not compared")
    return Result(ours, theirs, notes)


_INLINEE = re.compile(r"inlinee = (?P<id>0x[0-9A-Fa-f]+) \((?P<name>.*)\), parent")
_CODE_END = re.compile(r"code end (?P<end>0x[0-9A-Fa-f]+) "
                       r"\(\+(?P<length>0x[0-9A-Fa-f]+)\)")


def check_inline_sites(pdb: PDB, text: str) -> Result:
    ours = [(site.parent, site.inlinee, site.name, tuple(site.ranges))
            for site in pdb.inline_sites()]

    theirs = []
    proc: tuple[str, int] | None = None  # (name, offset) of the enclosing proc
    for rec in iter_records(text):
        if rec.kind in PROC_KINDS:
            addr = rec.address()
            proc = (rec.name, addr[1]) if addr else None
            continue
        if rec.kind != "S_INLINESITE" or proc is None:
            continue
        inlinee = _INLINEE.search(" ".join([rec.header, *rec.body]))
        if inlinee is None:
            raise ParseError("no inlinee on an S_INLINESITE record")
        # The annotations give a running cursor relative to the procedure's
        # start; each `code end` closes a range, so its start is end - length.
        ranges = []
        for line in rec.body:
            m = _CODE_END.search(line)
            if m:
                end = int(m.group("end"), 16)
                length = int(m.group("length"), 16)
                ranges.append((proc[1] + end - length, length))
        if not ranges:
            # purepdb drops a site whose annotations describe no code, since
            # there is no address to report it at.
            continue
        theirs.append((proc[0], int(inlinee.group("id"), 16),
                       inlinee.group("name"), tuple(ranges)))
    return Result(ours, theirs)


CHECKS = [
    Check("procs", ("--symbols",), check_procs),
    Check("publics", ("--publics",), check_publics),
    Check("labels", ("--symbols",), check_labels),
    Check("constants", ("--globals",), check_constants),
    Check("udts", ("--globals",), check_udts),
    Check("contributions", ("--section-contribs",), check_contributions),
    Check("inline sites", ("--symbols",), check_inline_sites),
]


# --- reporting --------------------------------------------------------------

def differences(result: Result, limit: int) -> list[str]:
    """Every record one side has and the other does not, with multiplicity."""
    ours, theirs = collections.Counter(result.ours), collections.Counter(result.theirs)
    only_ours = sorted((ours - theirs).elements(), key=repr)
    only_theirs = sorted((theirs - ours).elements(), key=repr)
    out = []
    for label, records in (("purepdb only", only_ours),
                           ("llvm-pdbutil only", only_theirs)):
        for record in records[:limit]:
            out.append(f"      {label}: {record}")
        if len(records) > limit:
            out.append(f"      ... and {len(records) - limit} more {label}")
    return out


def validate(path: Path, tool: str, limit: int) -> str:
    """Compare one file, and say whether it agreed, disagreed, or was skipped."""
    print(f"{path}")
    try:
        pdb = PDB.open(str(path))
    except PdbError as exc:
        # A file purepdb rejects outright is not a disagreement -- there is
        # nothing to compare -- but it must not be counted as agreement either.
        print(f"  skipped: {exc}")
        return "skipped"

    cache: dict = {}
    ok = True
    try:
        modules_text = dump(tool, path, ("--modules",), cache)
        modules = module_names(modules_text)
        streamless = modules_without_a_stream(modules_text)

        # The last two need what `dump --modules` said, so they are bound here
        # rather than in the table above.
        checks = [
            *CHECKS,
            Check("module attribution", ("--section-contribs",),
                  lambda p, text: check_module_attribution(p, text, modules)),
            Check("lines", ("-l",),
                  lambda p, text: check_lines(p, text, streamless, modules)),
        ]

        for check in checks:
            result = check.compare(pdb, dump(tool, path, check.args, cache))
            diffs = differences(result, limit)
            status = "ok  " if not diffs else "FAIL"
            print(f"  {status} {check.name:<20s} "
                  f"purepdb {len(result.ours)}, llvm-pdbutil {len(result.theirs)}")
            for note in result.notes:
                print(f"      note: {note}")
            for line in diffs:
                print(line)
            ok = ok and not diffs
    except ParseError as exc:
        # Not a disagreement: this script failed to read the reference output,
        # which most likely means llvm-pdbutil's format moved. Reporting it as
        # a mismatch would send the reader after the wrong thing.
        print(f"  ERROR reading llvm-pdbutil output: {exc}")
        return "failed"
    return "agreed" if ok else "failed"


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", type=Path,
                    help=f"PDBs to check (default: {DEFAULT_CORPUS}/**/*.pdb)")
    ap.add_argument("--llvm-pdbutil", default=os.environ.get("LLVM_PDBUTIL",
                                                            "llvm-pdbutil"),
                    help="path to llvm-pdbutil (or set LLVM_PDBUTIL)")
    ap.add_argument("--require-tool", action="store_true",
                    help="fail instead of skipping when llvm-pdbutil is absent")
    ap.add_argument("--max-diffs", type=int, default=10,
                    help="records to print per direction per check")
    args = ap.parse_args()

    tool = shutil.which(args.llvm_pdbutil) or (
        args.llvm_pdbutil if Path(args.llvm_pdbutil).is_file() else None)
    if tool is None:
        message = (f"llvm-pdbutil not found (looked for {args.llvm_pdbutil!r}). "
                   f"It ships with LLVM; on Debian/Ubuntu it is in the llvm "
                   f"package, on macOS in the llvm formula.")
        if args.require_tool:
            print(f"error: {message}", file=sys.stderr)
            return 1
        print(f"skipped: {message}")
        return 0

    paths = args.paths or sorted(DEFAULT_CORPUS.rglob("*.pdb"))
    if not paths:
        print(f"no PDBs found under {DEFAULT_CORPUS}")
        return 0

    outcomes = [(path, validate(path, tool, args.max_diffs)) for path in paths]
    failed = [path for path, outcome in outcomes if outcome == "failed"]
    skipped = sum(1 for _path, outcome in outcomes if outcome == "skipped")
    aside = f", {skipped} skipped" if skipped else ""

    print()
    if failed:
        print(f"FAIL: {len(failed)} of {len(paths)} file(s) disagree with "
              f"llvm-pdbutil{aside}")
        for path in failed:
            print(f"  {path}")
        return 1
    print(f"ok: {len(paths) - skipped} file(s) agree with llvm-pdbutil on "
          f"every check{aside}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
