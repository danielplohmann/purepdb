#!/usr/bin/env python3
"""Cross-check purepdb against llvm-pdbutil, record by record.

The suite in `tests/` must not need an LLVM toolchain, so the strongest
evidence this parser has -- agreement with the reference implementation -- can
only live outside it. That is what this script is: the comparisons that were
run by hand and reported in pull request descriptions, written down so anyone
can re-run them, and so a nightly job can fail when one stops holding.

    python dev/validate_against_llvm.py                 # tests/data/**/*.pdb
    python dev/validate_against_llvm.py path/to/one.pdb  # or a private corpus

The tool is found on PATH, or named by `--llvm-pdbutil` or `$LLVM_PDBUTIL`.
Exit status is 0 only when every file was read and every check agreed. It is 1
on a disagreement, on a file purepdb could not open (`--allow-unreadable` to
sweep a mixed corpus anyway), and on a corpus with no PDBs in it -- each of
those verified nothing, and a run that verified nothing must not print `ok`.
A missing `llvm-pdbutil` exits 0 with a message, so running this is never a
requirement; `--require-tool` makes it an error instead, which is what CI does.

Nine checks, over the subsystems whose accuracy was claimed in a PR
description and nowhere else:

    procs               S_*PROC32 name, address and code size
    publics             S_PUB32 name, address and function flag
    labels              S_LABEL32 name and address
    constants           S_CONSTANT name and value
    udts                S_UDT name and type index
    contributions       the Section Contribution table
    inline sites        each inlined body, its name, and every code range
    module attribution  the module each function is attributed to
    lines               every file:line and the address it starts at

Eight things about llvm-pdbutil's output are worth knowing before trusting a
comparison against it, all of them handled here:

  * `dump -l` prints line blocks under modules whose debug stream is 0xFFFF,
    repeating the previous module's blocks. Those modules hold no line info at
    all; `dump --modules` is what says so, and their blocks are skipped.
  * it renders the line number 0xF00F00 -- "do not step into this" -- as the
    label `NSI` rather than as a number.
  * a symbol address prints as `segment:offset` with **both parts in decimal**,
    while a line block's header prints **both parts in hex**. Same dump, two
    bases, and neither is labelled.
  * the section-contribution row is `SC[...]` for the Ver60 table and
    `SC2[...]` for the V2 one, which purepdb also reads.
  * a file heading is `path (MD5: ...)` or `path (no checksum)`; a line block
    is `line/addr entries` or `line/column/addr entries`.
  * `--section-contribs` needs the section-header stream, and exits 1 with
    "PDB does not contain the requested image section header type" on a PDB
    that has no slot 5. That is the reference implementation declining to
    answer, not a disagreement, so the two checks reading that dump are
    skipped for such a file rather than failing it.
  * it opens the IPI stream only when the PDB info stream advertises the
    feature code saying there is one. A file whose feature codes were dropped
    reports `Has IDs: false` with a perfectly good IPI in stream 4, and every
    item id then resolves against the *TPI*, printing a type name where an
    inlinee's function name belongs. The name is left out of the inline-site
    comparison for such a file; the id and the ranges are still compared.
  * its inline-site cursor moves past the length of a standalone
    `ChangeCodeLength` and *not* past the one fused into
    `ChangeCodeLengthAndCodeOffset`, so a file using the fused opcode has
    every range after the first printed short by the lengths before it. Ranges
    are therefore rebuilt from the deltas rather than read off the absolute
    offsets -- and llvm's own cursor is tracked alongside, so that if this
    stops being true the script says so instead of comparing quietly.

A module heading, a section-contribution row or a line entry this script does
not recognise raises `ParseError` rather than being skipped: mis-reading one of
those silently reattributes or drops whole blocks of records.

The record walk is not strict in the same way -- a line that is neither a
module heading nor an `S_*` record header is treated as a continuation of the
record above it, because that is what the multi-line record bodies are. So a
change to the record header format does not raise; it empties that side of the
comparison, which is caught instead by the rule that a check comparing nothing
fails the run.
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

# The file for a block llvm could not name, kept distinct from "no heading seen
# yet": one is a shared blind spot to report, the other is a parse failure.
_UNRESOLVED_FILE = object()


class ParseError(Exception):
    """llvm-pdbutil printed something this script does not understand.

    Raised rather than skipped: a comparison that quietly parsed half of the
    reference output would report agreement it did not verify.
    """


class ToolLimitation(Exception):
    """llvm-pdbutil cannot answer for this file, and said so.

    Deliberately not a `ParseError`. A dump that failed because the reference
    implementation declines to read a shape it does not support establishes
    nothing about purepdb either way, so the check reading it is skipped and
    the file is not failed. Every such case is a specific, recognised message
    -- an unrecognised failure is still a `ParseError`, because "the tool
    exited 1" is otherwise indistinguishable from "the tool changed".
    """


# Failures that are the tool declining rather than the tool breaking, each with
# the reason a reader of the log needs. Matched on llvm's stderr.
_CANNOT_ANSWER = (
    ("PDB does not contain the requested image section header type",
     "this file has no section-header stream (optional debug header slot 5), "
     "which llvm-pdbutil needs before it will name a contribution's section"),
)


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

# Generous: the slowest dump in the fixture corpus is `-l` on sqlite3 x86, at
# well under a second. This is a hang guard, not a performance budget.
DUMP_TIMEOUT = 600


def dump(tool: str, path: Path, args: Iterable[str], cache: dict) -> str:
    """One `llvm-pdbutil dump` run, remembered -- `--symbols` feeds three of
    the checks.

    The cache is per file, so the arguments alone identify a run.
    """
    key = tuple(args)
    if key not in cache:
        try:
            proc = subprocess.run(
                [tool, "dump", *key, str(path)],
                capture_output=True, timeout=DUMP_TIMEOUT,
                # Not strict: llvm-pdbutil passes PDB name bytes through
                # verbatim, and a localized build carries names that are not
                # UTF-8. Decoding them strictly ended the sweep with a
                # UnicodeDecodeError rather than reporting the file.
                text=True, errors="replace")
        except OSError as exc:
            raise ParseError(f"could not run {tool!r}: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ParseError(
                f"llvm-pdbutil {' '.join(key)} did not finish within "
                f"{DUMP_TIMEOUT}s") from exc
        if proc.returncode != 0:
            # A reference run that failed did not establish anything, whether
            # or not it printed something first: a truncated dump compared
            # against a full listing reads as purepdb inventing records, and a
            # crash that prints only its banner reads as agreement on nothing.
            # Both used to be a printed note over a zero exit status.
            detail = proc.stderr.strip().splitlines()
            note = (detail[0][:200] if detail
                    else f"exit status {proc.returncode}")
            for marker, why in _CANNOT_ANSWER:
                if marker in proc.stderr:
                    # Remembered rather than re-raised on each call: two checks
                    # share `--section-contribs`, and the second would
                    # otherwise re-run a dump whose answer is already known.
                    cache[key] = ToolLimitation(why)
                    break
            else:
                raise ParseError(f"llvm-pdbutil {' '.join(key)} failed: {note}")
        else:
            cache[key] = proc.stdout
    remembered = cache[key]
    if isinstance(remembered, ToolLimitation):
        raise remembered
    return remembered


# --- parsing what it printed ------------------------------------------------

# A module heading names its module, or says llvm could not resolve the index.
_MODULE = re.compile(r"^\s*Mod (?P<index>\d+) \| "
                     r"(?:`(?P<name>.*)`:|Invalid module index)")
_MODULE_ANY = re.compile(r"^\s*Mod \d+ \|")
_RECORD = re.compile(r"^\s*(?P<offset>\d+) \| (?P<kind>S_\w+) \[size = \d+\]"
                     r"(?P<rest>.*)$")
# Greedy, because a name may contain backticks -- sqlite3 has three, of the
# form `` `dllmain_crt_process_attach'::`1'::fin$0 ``. No header this script
# reads carries a second backticked field after the name.
_NAME = re.compile(r"`(?P<name>.*)`")
# Both parts decimal -- `addr = 0001:193488`. Across the corpus no segment here
# ever contains a hex digit while `0010` does appear, which is the proof.
_ADDR = re.compile(r"addr = (?P<segment>\d+):(?P<offset>\d+)")


def module_start(line: str) -> int | None:
    """The module index a `Mod NNNN |` heading opens, or None for other lines.

    A heading shape this script does not know raises, because the alternative
    is attributing every record and line block after it to the previous module.
    """
    m = _MODULE.match(line)
    if m:
        return int(m.group("index"))
    if _MODULE_ANY.match(line):
        raise ParseError(f"unrecognised module heading {line.strip()!r}")
    return None


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
        index = module_start(line)
        if index is not None:
            if current is not None:
                yield current
                current = None
            module = index
            continue
        rec = _RECORD.match(line)
        if rec:
            if current is not None:
                yield current
            current = RefRecord(kind=rec.group("kind"),
                                header=rec.group("rest"),
                                body=[], module=module)
        elif current is not None:
            current.body.append(line)
    if current is not None:
        yield current


_HAS_IDS = re.compile(r"^\s*Has IDs: (?P<answer>true|false)\s*$", re.M)


def resolves_item_ids(text: str) -> bool:
    """Whether llvm-pdbutil will resolve an item id, from `dump --summary`.

    It opens the IPI stream only when the PDB info stream advertises the
    feature code that says there is one, so a file whose feature codes were
    dropped answers `Has IDs: false` over a perfectly good IPI in stream 4.
    Every item id then resolves against the TPI instead, which turns an
    inlinee's name into the name of whatever type shares its index.
    """
    m = _HAS_IDS.search(text)
    if m is None:
        raise ParseError("`dump --summary` did not say whether the file has "
                         "an ID stream")
    return m.group("answer") == "true"


def module_names(text: str) -> dict[int, str]:
    """Module index -> name, from `dump --modules`.

    A module llvm could not resolve has no name to record, and is left out.
    """
    out = {}
    for line in text.splitlines():
        m = _MODULE.match(line)
        if m and m.group("name") is not None:
            out[int(m.group("index"))] = m.group("name")
    return out


def modules_without_a_stream(text: str) -> set[int]:
    """Modules whose debug stream is 0xFFFF, from `dump --modules`.

    `dump -l` prints line blocks under these -- a repeat of the previous
    module's -- and they are not real: the module has no debug stream to hold
    them. Comparing them would fail against any parser that reads the file.
    """
    out, current = set(), -1
    for line in text.splitlines():
        index = module_start(line)
        if index is not None:
            current = index
            continue
        m = re.match(r"^\s*debug stream: (\d+),", line)
        if m and int(m.group(1)) == NO_STREAM:
            out.add(current)
    return out


# --- the checks -------------------------------------------------------------

PROC_KINDS = {"S_GPROC32", "S_LPROC32", "S_GPROC32_ID", "S_LPROC32_ID"}


def check_procs(pdb: PDB, text: str) -> Result:
    ours = [(p.name, p.segment, p.offset, p.code_size)
            for p in pdb.module_procs()]
    theirs = []
    for rec in iter_records(text):
        if rec.kind not in PROC_KINDS:
            continue
        addr = rec.address()
        size = rec.field(r"code size = (\d+)")
        if addr is None or size is None:
            raise ParseError(
                f"no address or code size on {rec.kind} `{rec.name}`")
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
    ours = [(label.name, label.segment, label.offset)
            for label in pdb.labels()]
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
    unparsed = 0
    for rec in iter_records(text):
        if rec.kind != "S_CONSTANT":
            continue
        value = rec.field(r"value = (-?\d+)")
        if value is None:
            # A numeric leaf llvm prints as something other than an integer,
            # which is also the shape purepdb skips. Neither side has a number,
            # so it cannot be compared -- but it is said, because "both blind"
            # is the one way this check agrees without verifying anything.
            unparsed += 1
            continue
        theirs.append((rec.name, int(value)))
    notes = ([f"{unparsed} constant(s) print a non-integer value; "
              f"not compared"] if unparsed else [])
    return Result(ours, theirs, notes)


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


# `SC[...]` is the Ver60 table and `SC2[...]` the V2 one, which differs only by
# a trailing `coff section` field. purepdb reads both, so both are compared.
_SC = re.compile(r"^\s*SC2?\[(?P<section>[^\]]*)\]\s*\| mod = (?P<mod>\d+), "
                 r"(?P<segment>\d+):(?P<offset>\d+), size = (?P<size>\d+)")
_SC_ANY = re.compile(r"^\s*SC")


def _reference_contributions(text: str) -> list[tuple[int, int, int, int]]:
    out = []
    for line in text.splitlines():
        m = _SC.match(line)
        if m:
            out.append((int(m.group("segment")), int(m.group("offset")),
                        int(m.group("size")), int(m.group("mod"))))
        elif _SC_ANY.match(line):
            raise ParseError(f"unrecognised contribution row {line.strip()!r}")
    return out


def check_contributions(pdb: PDB, text: str) -> Result:
    ours = [(c.segment, c.offset, c.size, c.module_index)
            for c in pdb.section_contributions()]
    return Result(ours, _reference_contributions(text))


def check_module_attribution(pdb: PDB, text: str,
                             modules: dict[int, str]) -> Result:
    """Every function's `module`, against a lookup built from llvm's table.

    The table check above compares the rows; this compares what purepdb *does*
    with them, which is the claim `Function.module` actually makes. The lookup
    here is deliberately a separate implementation from `dbi.ContributionMap`.

    Note what this does *not* check: both sides iterate purepdb's own
    `functions()`, so the two lengths are equal by construction and only the
    module label is cross-checked. The function list itself is checked where it
    comes from -- `procs` covers the S_*PROC32 half; the publics- and
    thunk-derived entries have no llvm listing to compare against, which the
    report line says so a green run is not read as more than it is.
    """
    contributions = sorted(_reference_contributions(text))
    keys = [(segment, offset)
            for segment, offset, _size, _mod in contributions]

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
    return Result(ours, theirs, [
        f"the module label on each of purepdb's {len(ours)} functions, not "
        f"the function list itself, which is equal by construction here",
    ])


# A file heading carries a checksum, or says it has none. Every form is spelled
# out rather than matched loosely: an unrecognised heading leaves the previous
# file in place, and the entries under it would be attributed to that file --
# which is a wrong answer rather than a parse failure. What catches it is the
# entry-line guard below, which refuses to read a heading as entries.
_LINE_FILE = re.compile(r"^(?P<file>\S.*?) \((?:no checksum"
                        r"|(?:MD5|SHA-1|SHA-256|None): ?[0-9A-Fa-f]*)\)\s*$")
_LINE_UNRESOLVED = re.compile(r"^\s*\(unknown file name offset")
# Both parts of a block header are hex here -- segment included, unlike the
# decimal `addr = ` of a symbol record.
_LINE_BLOCK = re.compile(r"^\s*(?P<segment>[0-9A-Fa-f]+):[0-9A-Fa-f]{8}-"
                         r"[0-9A-Fa-f]{8}, line(?:/column)?/addr entries = "
                         r"(?P<count>\d+)")
# `NSI` where a line number would be, and the offset in hex.
# The column, when the block header said `line/column/addr`, sits between the
# line and the address as `line:column`. Without consuming it the column was
# read *as* the line and the line became unmatched residual, so every file
# built with column info -- which clang-cl emits by default -- failed the run.
_LINE_ENTRY = re.compile(
    r"(?P<line>\d+|NSI)(?::\d+)?\s+(?P<offset>[0-9A-Fa-f]{8})")


def check_lines(pdb: PDB, text: str, streamless: set[int],
                modules: dict[int, str]) -> Result:
    ours = [(line.module, line.file, line.line, line.segment, line.offset)
            for line in pdb.lines()]

    theirs: list[tuple] = []
    module, file, segment, expected, seen = -1, None, 0, 0, 0
    unresolved = skipped_modules = skipped_entries = 0

    def check_block_is_complete():
        if expected != seen:
            raise ParseError(f"module {module}: read {seen} line entries "
                             f"where the block header said {expected}")

    for raw in text.splitlines():
        index = module_start(raw)
        if index is not None:
            check_block_is_complete()
            module, file, expected, seen = index, None, 0, 0
            if module in streamless:
                skipped_modules += 1
            continue
        if module == -1 or not raw.strip():
            continue  # the banner above the first module, and blank lines
        if module in streamless:
            # See `modules_without_a_stream`: these blocks are a repeat of the
            # previous module's and describe nothing. Counted, because this is
            # the largest filter here -- 97% of the reference output on the
            # rust fixture -- and a silent one would stop being noticed on the
            # day it stops being right.
            skipped_entries += len(_LINE_ENTRY.findall(raw))
            continue
        block = _LINE_BLOCK.match(raw)
        if block:
            check_block_is_complete()
            segment = int(block.group("segment"), 16)
            expected, seen = int(block.group("count")), 0
            continue
        named = _LINE_FILE.match(raw)
        if named:
            file = named.group("file")
            continue
        if _LINE_UNRESOLVED.match(raw):
            # llvm reports the offset it could not resolve; purepdb drops the
            # entry. Both sides lose it, so it is counted, not compared.
            file = _UNRESOLVED_FILE
            continue
        entries = list(_LINE_ENTRY.finditer(raw))
        if not entries or _LINE_ENTRY.sub("", raw).strip(" \t!"):
            raise ParseError(f"module {module}: unrecognised line {raw!r}")
        if file is None:
            # Entries before any heading: the file cannot be known, and
            # guessing the previous one is how a whole file lands on the wrong
            # path. Neither is acceptable, so this stops the run.
            raise ParseError(f"module {module}: line entries before any file "
                             f"heading, at {raw.strip()!r}")
        for entry in entries:
            seen += 1
            if file is _UNRESOLVED_FILE:
                unresolved += 1
                continue
            number = (NSI_LINE if entry.group("line") == "NSI"
                      else int(entry.group("line")))
            theirs.append((modules.get(module, ""), file, number, segment,
                           int(entry.group("offset"), 16)))
    check_block_is_complete()

    notes = []
    if skipped_modules:
        notes.append(f"{skipped_modules} module(s) have no debug stream: "
                     f"{skipped_entries} repeated entries skipped")
    if unresolved:
        notes.append(f"{unresolved} entry(ies) name a file llvm-pdbutil could "
                     f"not resolve either; not compared")
    return Result(ours, theirs, notes)


_INLINEE = re.compile(r"inlinee = (?P<id>0x[0-9A-Fa-f]+) "
                      r"\((?P<name>.*)\), parent")
# Every annotation prints its own bytes first, and the first of those is the
# opcode: the compressed encoding of an opcode in 1..13 is the byte itself.
_ANNOTATION = re.compile(r"^\s+(?P<opcode>[0-9A-F]{2})[0-9A-F]*\s+"
                         r"(?P<text>\S.*)$")
# `code 0x143 (+0x143)` moves the cursor; `code end 0x145 (+0x2)` closes a
# range. An annotation prints one or the other, or -- for the fused opcode --
# both, in that order.
_CODE = re.compile(r"code (?P<end>end )?0x(?P<value>[0-9A-F]+) "
                   r"\(\+0x(?P<delta>[0-9A-F]+)\)")

_BA_CHANGE_CODE_OFFSET_BASE = "02"
_BA_CHANGE_CODE_LENGTH = "04"
_BA_CHANGE_CODE_LENGTH_AND_CODE_OFFSET = "0C"
_CLOSES_A_RANGE = (_BA_CHANGE_CODE_LENGTH,
                   _BA_CHANGE_CODE_LENGTH_AND_CODE_OFFSET)


def inline_site_ranges(rec: RefRecord) -> list[tuple[int, int]]:
    """The code ranges one S_INLINESITE covers, relative to its procedure.

    Rebuilt from the deltas rather than read off the absolute offsets llvm
    prints, because on some files those two disagree and the deltas are the
    part both sides read the same way. `ChangeCodeLength` moves
    llvm's cursor past the range it closed; the length fused into
    `ChangeCodeLengthAndCodeOffset` does not move it, so from the second range
    on, a site built out of the fused opcode prints every offset short by the
    lengths before it. A cursor that a range's length advances is the reading
    that makes the two opcodes mean the same thing, and it is what purepdb
    does.

    llvm's own cursor is tracked beside it and checked against every absolute
    offset printed. That is what keeps this from being an assumption: the day
    the tool stops behaving this way, the run says so rather than comparing
    against a rule that no longer holds.
    """
    offset = 0  # the cursor a range's length advances
    theirs = 0  # llvm-pdbutil's, which only a standalone length advances
    ranges: list[tuple[int, int]] = []
    for line in rec.body:
        annotation = _ANNOTATION.match(line)
        if annotation is None:
            continue
        opcode = annotation.group("opcode")
        clauses = _CODE.findall(annotation.group("text"))
        if clauses and opcode == _BA_CHANGE_CODE_OFFSET_BASE:
            # Rebases the cursor rather than advancing it, and purepdb stops
            # at one for that reason -- nothing in the corpus has ever emitted
            # one, so neither reading is verified. Comparing a rebase we did
            # not model against a parser that gave up would report a
            # disagreement about the wrong thing.
            raise ParseError("an inline site rebases its code offset "
                             "(ChangeCodeOffsetBase), which neither side of "
                             "this comparison has ever been checked against")
        for end, value, delta in clauses:
            step = int(delta, 16)
            if not end:
                offset += step
                theirs += step
                expected = theirs
            else:
                if opcode not in _CLOSES_A_RANGE:
                    raise ParseError(f"annotation {opcode} closed a code "
                                     f"range, which only 04 and 0C do")
                ranges.append((offset, step))
                offset += step
                expected = theirs + step
                if opcode == _BA_CHANGE_CODE_LENGTH:
                    theirs += step
            if int(value, 16) != expected:
                raise ParseError(
                    f"llvm-pdbutil's inline-site cursor reads 0x{expected:X} "
                    f"here and it printed 0x{int(value, 16):X}: the way this "
                    f"script models annotation {opcode} no longer holds")
    return ranges


def check_inline_sites(pdb: PDB, text: str, named: bool) -> Result:
    """Compare inline sites; `named` says whether to compare inlinee names.

    An item id llvm resolved against the TPI names a type rather than the
    inlined function, so for a file it reports no ID stream for, the name is
    left out of both sides. Left out rather than blanked, so that a difference
    prints the tuple that was actually compared.
    """
    def site(parent: str, inlinee: int, name: str, ranges: tuple) -> tuple:
        if not named:
            return (parent, inlinee, ranges)
        return (parent, inlinee, name, ranges)

    ours = [site(s.parent, s.inlinee, s.name, tuple(s.ranges))
            for s in pdb.inline_sites()]

    theirs = []
    proc: tuple[str, int] | None = None  # (name, offset) of the enclosing proc
    module = -1
    for rec in iter_records(text):
        if rec.module != module:
            # A procedure's scope cannot span modules, so carrying the last one
            # across the boundary would attribute the next module's sites to a
            # procedure in this one.
            module, proc = rec.module, None
        if rec.kind in PROC_KINDS:
            addr = rec.address()
            if addr is None:
                raise ParseError(f"no address on {rec.kind} `{rec.name}`")
            proc = (rec.name, addr[1])
            continue
        if rec.kind != "S_INLINESITE":
            continue
        if proc is None:
            raise ParseError("an S_INLINESITE record outside any procedure")
        inlinee = _INLINEE.search(" ".join([rec.header, *rec.body]))
        if inlinee is None:
            raise ParseError("no inlinee on an S_INLINESITE record")
        ranges = [(proc[1] + start, length)
                  for start, length in inline_site_ranges(rec)]
        if not ranges:
            # purepdb drops a site whose annotations describe no code, since
            # there is no address to report it at.
            continue
        theirs.append(site(proc[0], int(inlinee.group("id"), 16),
                           inlinee.group("name"), tuple(ranges)))
    notes = [] if named else [
        "llvm-pdbutil reports no ID stream for this file, so it resolved every "
        "inlinee id against the TPI and printed a type name; names not compared"
    ]
    return Result(ours, theirs, notes)


CHECKS = [
    Check("procs", ("--symbols",), check_procs),
    Check("publics", ("--publics",), check_publics),
    Check("labels", ("--symbols",), check_labels),
    Check("constants", ("--globals",), check_constants),
    Check("udts", ("--globals",), check_udts),
    Check("contributions", ("--section-contribs",), check_contributions),
]

# The three bound per file in `validate()`, named here so that "did every check
# verify something?" can be asked without running one.
LATE_CHECKS = ("inline sites", "module attribution", "lines")


def check_names() -> list[str]:
    return [check.name for check in CHECKS] + list(LATE_CHECKS)


# --- reporting --------------------------------------------------------------

def differences(result: Result, limit: int) -> list[str]:
    """Every record one side has and the other does not, with multiplicity."""
    # Counters, not sets: a repeated record is a real record, and rustpe has
    # one label tuple that occurs 34 times.
    ours = collections.Counter(result.ours)
    theirs = collections.Counter(result.theirs)
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


def validate(path: Path, tool: str, limit: int, verified: set[str]) -> str:
    """Compare one file: did it agree, disagree, or fail to open at all?

    `verified` collects the checks that actually compared a record, so that a
    corpus-wide run can say which of them established nothing.
    """
    print(f"{path}")
    try:
        pdb = PDB.open(str(path))
    except (PdbError, OSError) as exc:
        # OSError as well as PdbError: a directory named *.pdb, a dangling
        # symlink or an unreadable file used to end the whole sweep with a
        # traceback, and `--allow-unreadable` -- whose entire purpose is
        # sweeping a corpus that holds such files -- did not cover it.
        # Nothing was compared, so this is not agreement. On the fixture corpus
        # it is a regression in `PDB.open` or a damaged checkout, either of
        # which must fail the run; `--allow-unreadable` is for sweeping a
        # private corpus that legitimately holds files purepdb rejects.
        print(f"  unreadable: {exc}")
        return "unreadable"

    cache: dict = {}
    ok = True
    try:
        modules_text = dump(tool, path, ("--modules",), cache)
        modules = module_names(modules_text)
        streamless = modules_without_a_stream(modules_text)
        named_inlinees = resolves_item_ids(dump(tool, path, ("--summary",),
                                               cache))

        # The last three need something a second dump said, so they are bound
        # here rather than in the table above.
        checks = [
            *CHECKS,
            Check("inline sites", ("--symbols",),
                  lambda p, text: check_inline_sites(p, text, named_inlinees)),
            Check("module attribution", ("--section-contribs",),
                  lambda p, text: check_module_attribution(p, text, modules)),
            Check("lines", ("-l",),
                  lambda p, text: check_lines(p, text, streamless, modules)),
        ]

        for check in checks:
            try:
                reference = dump(tool, path, check.args, cache)
            except ToolLimitation as exc:
                # Neither agreement nor disagreement: there is no reference
                # answer for this file to compare against. The check stays out
                # of `verified`, so if no file in the corpus could answer for
                # it the run still fails on the gate at the end.
                print(f"  skip {check.name:<20s} {exc}")
                continue
            result = check.compare(pdb, reference)
            diffs = differences(result, limit)
            compared = max(len(result.ours), len(result.theirs))
            if compared:
                verified.add(check.name)
            # Two empty lists agree, so a check with nothing on either side
            # printed `ok` and was indistinguishable from one that verified
            # thousands of records. It is not a failure per file -- rustpe32
            # genuinely has no labels -- so it is tracked across the corpus
            # and answered for at the end.
            status = "ok  " if not diffs else "FAIL"
            if not diffs and not compared:
                status = "----"
            print(f"  {status} {check.name:<20s} "
                  f"purepdb {len(result.ours)}, "
                  f"llvm-pdbutil {len(result.theirs)}")
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
    # `or` rather than a default, so `LLVM_PDBUTIL=` set to nothing -- what an
    # unset shell variable expands to in a CI script -- still falls back to
    # PATH instead of looking for a tool named "".
    ap.add_argument("--llvm-pdbutil",
                    default=os.environ.get("LLVM_PDBUTIL") or "llvm-pdbutil",
                    help="path to llvm-pdbutil (or set LLVM_PDBUTIL)")
    ap.add_argument("--require-tool", action="store_true",
                    help="fail rather than skip when llvm-pdbutil is absent")
    ap.add_argument("--allow-unreadable", action="store_true",
                    help="do not fail on a file purepdb cannot open")
    ap.add_argument("--max-diffs", type=int, default=10,
                    help="records to print per direction per check")
    args = ap.parse_args()
    if args.max_diffs < 0:
        # `-1` is the usual "unlimited" idiom, and it did the opposite: the
        # overflow test is `len(records) > limit`, which an *empty* difference
        # list satisfies, so every agreeing check reported FAIL.
        ap.error("--max-diffs cannot be negative")

    # `which` already resolves an absolute or ./-relative path and rejects a
    # directory or a file without the executable bit, so it is the whole test.
    tool = shutil.which(args.llvm_pdbutil)
    if tool is None:
        message = (f"llvm-pdbutil not found (looked for "
                   f"{args.llvm_pdbutil!r}). It ships with LLVM; on "
                   f"Debian/Ubuntu it is in the llvm package, on macOS in "
                   f"the llvm formula.")
        if args.require_tool:
            print(f"error: {message}", file=sys.stderr)
            return 1
        print(f"skipped: {message}")
        return 0

    paths = args.paths or sorted(DEFAULT_CORPUS.rglob("*.pdb"))
    if not paths:
        # Verified nothing. Silently succeeding here is how a nightly job stays
        # green through a checkout that lost its fixtures.
        print(f"error: no PDBs found under {DEFAULT_CORPUS}", file=sys.stderr)
        return 1

    verified: set[str] = set()
    outcomes = [(path, validate(path, tool, args.max_diffs, verified))
                for path in paths]
    failed = [path for path, outcome in outcomes if outcome == "failed"]
    unreadable = [path for path, outcome in outcomes
                  if outcome == "unreadable"]
    if not args.allow_unreadable:
        failed += unreadable
    aside = (f", {len(unreadable)} unreadable and allowed"
             if unreadable and args.allow_unreadable else "")

    print()
    if failed:
        print(f"FAIL: {len(failed)} of {len(paths)} file(s) disagree with "
              f"llvm-pdbutil or could not be read{aside}")
        for path in sorted(set(failed)):
            print(f"  {path}")
        return 1

    # Checked before the per-check gate below, which would also fire here but
    # would describe the symptom rather than the cause.
    if len(unreadable) == len(paths):
        print(f"FAIL: all {len(paths)} file(s) were unreadable, so nothing "
              f"was compared")
        return 1

    # A check that compared no record on any file in the corpus verified
    # nothing, and two empty lists agree -- so without this it printed `ok`
    # and was indistinguishable from one that checked thousands. The same
    # reasoning as the empty-corpus guard above, one level further down.
    if unverified := [name for name in check_names() if name not in verified]:
        print(f"FAIL: {len(unverified)} check(s) compared no record on any "
              f"file, so they verified nothing:")
        for name in unverified:
            print(f"  {name}")
        return 1

    print(f"ok: {len(paths) - len(unreadable)} file(s) agree with "
          f"llvm-pdbutil on every check{aside}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
