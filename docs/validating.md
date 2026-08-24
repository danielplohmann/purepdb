# Knowing a parser is right

A parser whose failure mode is an empty list cannot be tested by running it.
`assert functions()` passes on a parser that reads the wrong stream, because the
wrong stream yields nothing and nothing is falsy in the shape of a short list.

That is the problem this project kept running into, and these are the five
checks that answer it. What they have in common is **independence**: each one
gets its expected answer from somewhere other than the code under test. A test
whose expectation comes from the implementation only records what the code did
on the day it was written.

## 1. A builder that is not the reader

`tests/_synth.py` serialises MSF containers, DBI streams and CodeView records
from scratch, deliberately **without using purepdb's parsing code**. Tests build
a byte stream and require the reader to recover what went in.

The point is the round trip. If the builder called the reader's own structure
definitions, a field read at the wrong offset would be written at the wrong
offset too and the test would pass. Keeping them independent means a
disagreement is a real disagreement.

This is the cheapest layer and it catches most ordinary mistakes. What it cannot
catch is a shared *misunderstanding* of the format — if we believe a field is
two bytes and it is four, both halves agree and both are wrong. For that you
need something that did not come from us.

## 2. A PE reader that never opens the PDB

`tests/_pe.py` reads the companion image with nothing but `struct`. It has no
dependency on purepdb, and the rule is that **it must never acquire one**.

That constraint is the whole value. When the PDB's section table and the image's
own agree, the agreement is evidence. If `_pe.py` shared purepdb's section
parsing, the two would agree by construction and the test would assert nothing.

It gives three independent oracles:

- **The section table.** The PDB's copy must reproduce the image's, field for
  field.
- **Executable placement.** Every function's RVA must land inside a section the
  image marks executable. Cheap, and it catches a whole class of resolution
  error at once — reading `segment` and `offset` in the wrong order still
  produces addresses, and they scatter out of `.text`.
- **Exports.** The image's export directory names functions and their addresses
  without consulting the PDB at all. Exports point at `jmp rel32` thunks rather
  than at bodies, so the thunk is followed first: 272 of sqlite3's 277 exports
  are code and must land exactly on a function purepdb found; the other five are
  exported variables and must **not** appear as functions.

The export oracle turned out to be the strongest tool available, and it is what
[`omap.md`](omap.md) uses to check address translation against real Windows
binaries.

## 3. Pinned counts, because zero is a passing number

`tests/test_groundtruth.py` asserts exact numbers per fixture — procedures,
publics, functions, aliases, sections. This looks like the brittle kind of test
and is not optional here.

A parser reading the wrong stream returns an empty list rather than raising, so
the numbers *are* the check. `assert len(publics) > 0` would have caught
purepdb's publics bug; `assert len(publics) == 685` also catches the day it
starts returning 12.

Two disciplines make them useful rather than annoying:

- **A count that moves is a decision, not a chore.** Recovering more symbols is
  legitimate and expected. The requirement is that the change is deliberate,
  recorded in the changelog, and explained — not silently absorbed.
- **A row of zeroes asserts nothing.** A fixture with `0` constants passes just
  as well against an accessor stubbed to return `[]`. Where the zero was a
  property of the source rather than of the format, the fixture was changed to
  carry some. Where it is structural, it says so in a comment — a `thunks()` row
  of zero on a `/nodefaultlib` binary with no import directory guards against
  records appearing where the image has none, as long as nobody mistakes it for
  coverage.

The same trap appears as a loop that iterates zero times. Two golden tests here
passed for months while checking nothing, on the two fixtures that address no
label. They now assert **how many** items they checked.

## 4. A reference implementation, compared record by record

`dev/validate_against_llvm.py` compares purepdb against `llvm-pdbutil` across
nine checks: procedures, publics, labels, constants, UDTs, the section
contribution table, module attribution, every `file:line` entry, and every
inline site with all its code ranges.

Two design choices matter more than the comparison itself.

**Record by record, not count by count.** Two parsers can agree on 3539
procedures and disagree about which ones. The check compares the sets.

**Outside the test suite.** The suite must not need an LLVM toolchain, and the
reference is a moving target — a runner-image LLVM bump changing one record's
formatting would turn an unrelated pull request red. It runs nightly and on
demand instead, and skips cleanly when the tool is absent so that running it is
never a requirement.

The subtle failure here is a harness that reports agreement it never got. Two
empty lists agree, so a check whose extraction silently broke prints `ok`. Every
check is registered in a "verified nothing" gate that fails the run if it
compared nothing, and a test asserts that every check is in that gate — so a
tenth check cannot be added without one.

## 5. Fuzzing the boundary, not the format

`tools/fuzz.py` drives every public entry point over random, structurally
corrupted, and bit-flipped input. It does not check that parsing is *correct*.
It checks the one contract a caller writes code against: that nothing but
`PdbError` escapes.

No `struct.error`, `IndexError`, `EOFError` or `KeyError` may cross the public
boundary, and no single input may hang. Three input sources reach different
depths — uniform random bytes mostly die in the MSF superblock; a valid container
with corrupted interior fields is what actually reaches the DBI and CodeView
parsers; bit-flipped real fixtures keep enough structure to get deep into the
record walkers.

Two details are load-bearing:

- **Results are collected, not discarded.** `lines()` is a generator, and never
  consuming it would leave the C13 walker untested.
- **Order matters.** An entry point that rejects malformed input early must come
  last, or it ends the sweep before the others run.

What fuzzing does not find is worth stating. The `PDB.info()` bound was a leak
of exactly the kind this exists to catch, and 10000 iterations across all three
generators never hit it: the target needed a valid container, a parseable DBI
stream, and stream 1 present but short — a combination mutation almost never
produces. It was found by auditing fixed-size reads for one whose length comes
from the file. **Fuzzing covers the reachable space, not the narrow one**, and an
audit of a specific shape is a different tool.

## Two failure modes to watch for in your own tests

Both of these bit this project, and both are invisible while they are happening.

**A test that passes for the wrong reason.** A helper wrote a stream and left it
unreferenced, so a test asking for a particular shape did not get it — and since
it was asserting an *absence*, it passed. The fix is to assert the state you
built before asserting the property you want from it. An absence test whose setup
silently failed is indistinguishable from a pass.

**A guard that quietly stops guarding.** A list of record kinds was documented as
"every kind the dispatch covers", maintained by hand, and drifted three times in
one day's merges. Each time the suite went green *because* its coverage had
shrunk.

The instructive part is that the obvious fix is worse. Deriving the list from the
dispatch was tried and measured: removing a kind then removes its test case, so
the suite reports one fewer passing test and no failure. Deriving an expectation
from the thing under test cannot detect the thing being removed. The list stays
written out, with an equality assertion coupling it to the dispatch — so drift
fails in both directions.

## The shape of all of this

Every check above answers "how would I know if this were wrong?" with something
other than "the code says so":

| check | where the expectation comes from |
| --- | --- |
| synthetic round trip | a builder that does not use the reader |
| PE oracle | the image, read by code that never opens a PDB |
| pinned counts | measured once, deliberately, and defended |
| llvm cross-check | a different implementation |
| fuzzing | a contract, not an expected value |
| relinked OMAP | bytes that actually moved |
| Windows OMAP check | a linker's own export table |

The last two are described in [`omap.md`](omap.md).
