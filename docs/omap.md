# OMAP, slot 10, and the two address spaces

Field notes on the one part of the PDB format where ignoring a stream gives
**wrong** answers rather than missing ones.

Every number here was measured with purepdb against a named file, and the
scripts that produce them are in the repository. Where a claim is about "real
Windows binaries" it means the six pairs listed under [What was
measured](#what-was-measured) — an XP and a Win7 installation — and not the
platform in general.

## What OMAP is for

Microsoft's Basic Block Tools (BBT) reorder code *after* the linker has run, to
put hot blocks together. The linker has already written the PDB by then, and BBT
does not rewrite it. Instead it leaves the debug info describing the
pre-optimisation image and appends two translation tables.

So a BBT-processed PDB describes a layout that the shipped binary does not have.
Every symbol in it carries the address it had *before* the move.

Four Optional Debug Header slots matter:

| slot | contents |
| ---: | --- |
| 3 | `OmapToSrc` — final image → original image |
| 4 | `OmapFromSrc` — original image → final image |
| 5 | section headers of the **final**, shipped image |
| 10 | section headers of the **original**, pre-BBT image |

Each map is a dense array of `struct OMAP { uint32 rva; uint32 rvaTo; }` sorted
by `rva`. Translation is a range lookup: find the entry with the largest `rva`
not exceeding the address, then add the difference to its `rvaTo`. An `rvaTo` of
0 marks a range with no counterpart — code the optimiser dropped — and
translates to nothing.

## Why it cannot be treated as optional

Everywhere else in this format, an unread stream costs coverage: fewer symbols,
or an address that comes back `None`. Here it costs correctness, silently, because
a `segment:offset` resolved against the wrong section table still produces a
number that looks exactly like an RVA.

On Win7 x64 `ntdll`, **1961 of 1961 exported functions land at a different
address after translation than before it**. Not a subset — every single one.
Across the six map-bearing pairs measured, **0 of 8730 exports match the
untranslated address**. (Only pairs that carry a map count toward that: a file
with no map has nothing to leave untranslated, and including the eight modern
pairs would inflate the number to 21790 while proving nothing.)

That is the number worth remembering. A consumer that skips OMAP does not get a
slightly worse answer on a BBT-processed file; it gets an answer where nothing
is where it says it is.

## The resolution order

purepdb resolves a symbol's `segment:offset` against slot 10 when present, then
translates the result through slot 4. So the RVA it reports is always a final,
post-BBT address.

That ordering matters, and the two halves have to be present together:

- **Map without slot 10.** There is no pre-optimisation address space to
  translate out of, so the map must *not* be applied — applying it would
  double-translate an already-final address. `diagnose()` warns.
- **Slot 10 without the map.** Every address is in the pre-optimisation space
  and matches nothing in the shipped image. `diagnose()` warns.
- **Slot 10 without slot 5.** Symbol RVAs are final; the only section table left
  to show is the pre-BBT one. A consumer pairing the two compares across address
  spaces. This is the case in [issue #39][i39], and `diagnose()` warns.
- **Both tables and the map.** The ordinary BBT shape, and the one where
  everything works. `diagnose()` stays silent.

Of those four, only three have ever been seen in a real file. Across nineteen —
eighteen Windows pairs spanning XP, 7, 10 and 11 on both architectures, and
Syzygy's own test data — the shapes observed are *both tables with a map* (6),
*a map without slot 10* (Syzygy, 1), and *no map at all* (12). **Slot 10 without
slot 5 has not been observed once.**

That matters for how much weight to put on it. The case is real in the sense that
the code paths compose that way, and purepdb warns about it; whether any producer
emits it is a different question, and the answer so far is that none of the ones
reachable here does.

## Translating the section table is harder than it looks

A caller who wants `functions()` and `sections()` to be comparable naturally
reaches for "run each section start through the map". That algorithm is wrong,
and it fails in the worst way — confidently.

Measured on `ntdll` from two installations:

```
winxp ntdll                                   win7-x64 ntdll
section  orig_va   omap()    final_va         section  orig_va    omap()     final_va
.text     0x1000   None       0x1000  DIFF    .text     0x1000    None        0x1000  DIFF
.data    0x76000   None      0x7b000  DIFF    RT      0x101000    None      0x102000  DIFF
.rsrc    0x7b000   0x80000   0x80000  MATCH   .rdata  0x102000    None      0x103000  DIFF
.reloc   0xa7000   None      0xac000  DIFF    .data   0x12d000    0x13ab40  0x132000  DIFF
                                              .pdata  0x13a000    None      0x13e000  DIFF
1 of 4 correct                                .rsrc   0x149000    0x151000  0x151000  MATCH
                                              .reloc  0x1a0000    None      0x1a8000  DIFF
                                              1 of 7 correct
```

Most section starts fall below the first map entry or into a gap and translate
to nothing. Worse, Win7's `.data` translates to `0x13ab40` — not a section start
at all, and 0x8b40 past the right answer. A naive implementation would report it
as fact.

The map describes where *code* went. Section boundaries are not code, and
nothing obliges them to appear in it.

purepdb does not translate the section table, and after [#39][i39] that is a
decision rather than a gap. The case for doing it rests on the shape where slot
10 is present and slot 5 is absent, so that the pre-BBT table is the only one a
caller can display — and that shape has not been observed in any of the nineteen
files measured here. Building a translation nobody can exercise, on an algorithm
whose obvious form is measurably wrong, would trade a correct warning for a
plausible answer. The warning is the answer.

## Which files have it

**Nothing public writes slot 10.** This was searched properly:

- **Microsoft BBT** was never publicly released in any form.
- **Google Syzygy `relink`** is the only open-source tool that writes an address
  map at all. Measured on its own committed test data
  (`test_vtables_omap.dll.pdb`, 1228 entries): it writes slots 3 and 4 and
  **never slot 10**. That file is now a fixture in this repository, so OMAP
  *parsing* has real coverage — but not the slot-10 branch.
- **MSVC's PGO** (`/LTCG:PGO`) does not produce OMAP. OMAP comes from post-link
  rewriting, not from compile-time optimisation.

That leaves Microsoft's own operating-system binaries, whose PDBs are on the
public symbol server and are **not redistributable**. So the shape can be
checked but not committed, which is the whole reason this document exists rather
than a fixture.

### Looking for it in a corpus

`dev/survey_pdb_shapes.py` sweeps a directory for these shapes, and finding
`slot 10, NO slot 5` is what it exists for. Two things make it cheap:

**No binaries are needed.** Which shape a file has is decided by the Optional
Debug Header alone, so nothing has to be paired with an image. That matters,
because a PDB cannot practically be turned back into its image anyway — the
symbol server keys binaries on `TimeDateStamp` and `SizeOfImage`, and while
`SizeOfImage` is derivable from the section table (on Win7 x64 `ntdll` the
rounded last-section end is `0x1a9000`, exactly what the image records),
`TimeDateStamp` is not in the PDB at all. The PDB's signature is its own
creation time, 13779 seconds off the image's on that file. Half a key is no key.

**It reads only the header**, not every module stream as `diagnose()` does —
roughly seventy real system PDBs a second, so a bag of ten thousand is a couple
of minutes.

A single hit would be worth having even if the file itself could not be
committed. It would establish that the shape exists, and nothing has.

### Why it probably cannot exist

The sweep has now run over every corpus available: the fixtures, eighteen
Windows system PDBs spanning XP, 7, 10 and 11, and 2.5 GB of assorted real
PDBs — among them some of the largest and oldest on VirusTotal, and a good
deal of Roslyn output. **Zero of 64 files carried slot 10 without slot 5.**

That is worth more than a null result, because the two conditions turn out to
pull against each other:

* **Slot 10 and a map** mean the file was BBT-processed, which means Microsoft,
  and the era measurements put that between roughly XP and Windows 7.
* **No slot 5** means a linker that did not write a section-header stream.

But BBT ran on binaries produced by the same toolchain that always writes slot
5 — every one of the eighteen Windows pairs carries both — and a linker old
enough to omit slot 5 predates BBT. The combination is not merely rare; there
is no producer in that intersection.

So issue 25 was closed on this reasoning rather than left open indefinitely.
purepdb still handles the case, and `diagnose()` still warns about it, because
the code paths compose that way and costing nothing to keep correct is
different from being worth hunting for. If a file ever turns up, the sweep
costs a tenth of a second over 2.5 GB, and the question reopens.

### The era question, answered

BBT is not an XP-era artefact, and it is not a current practice either. It
stopped, and the window can be dated from the binaries themselves:

| pair | omap entries | slot 10 | slot 5 |
| --- | ---: | :---: | :---: |
| winxp `ntdll` | 37061 | yes | yes |
| winxp `kernel32` | 42229 | yes | yes |
| win7-x86 `ntdll` | 67696 | yes | yes |
| win7-x86 `kernel32` | 60037 | yes | yes |
| win7-x64 `ntdll` | 84434 | yes | yes |
| win7-x64 `kernel32` | 70894 | yes | yes |
| win10-x86 `ntdll` | **0** | no | yes |
| win10-x86 `kernel32` | **0** | no | yes |
| win10-x86 `KernelBase` | **0** | no | yes |
| win10-x64 `ntdll` | **0** | no | yes |
| win10-x64 `kernel32` | **0** | no | yes |
| win10-x64 `KernelBase` | **0** | no | yes |
| win11-x86 `ntdll` | **0** | no | yes |
| win11-x86 `kernel32` | **0** | no | yes |
| win11-x86 `KernelBase` | **0** | no | yes |
| win11-x64 `ntdll` | **0** | no | yes |
| win11-x64 `kernel32` | **0** | no | yes |
| win11-x64 `KernelBase` | **0** | no | yes |

Every XP and Win7 PDB measured carries a map and slot 10; Win7 x64 `ntdll` has
the largest of the set at 84434 entries, more than double XP's. **Not one Win10
or Win11 PDB carries a single OMAP entry**, on either architecture, and none
carries slot 10. `KernelBase` is included deliberately: post-Win7 it is where the
implementations moved, so it is the module a modern consumer would most want
translated, and it has nothing to translate. The Win10 binaries measured are from
2018 and the Win11 ones are current.

So the practice ended somewhere between Windows 7 SP1 and that Windows 10 build.
This was not narrowed further, and the boundary was not searched for — Windows 8
and 8.1 were not tested, and a single build of each release is not the release.

What it means for a consumer is worth stating plainly: **OMAP is a compatibility
concern, not a current one.** A tool that only ever sees binaries from the last
decade may never encounter a map. A tool that reads older system binaries, or
anything a post-link rewriter has been through, cannot skip it — and the cost of
skipping it does not degrade gracefully, as the numbers above show.

## What was measured

`dev/validate_omap_against_windows.py` performs the check. It takes a directory
of Windows DLLs, reads each one's CodeView identity out of its debug directory,
fetches the matching PDB from Microsoft's symbol server into an untracked cache,
and compares.

**Nothing is redistributed.** The images are the developer's own and the symbols
stay in `dev/symbols/`, which is not tracked. That is the arrangement that makes
this checkable at all — see [`tests/data/README.md`](../tests/data/README.md) on
why the files cannot simply be committed.

The oracle is the **export table**: addresses the linker wrote in the shipped
image's own space, owing nothing to the PDB. Comparing them against purepdb's
translated addresses is independent evidence rather than the parser agreeing
with itself.

```
pair                     omap   compared  exact  thunk  near   far
winxp    ntdll          37061      1294    1292      0     1      1
winxp    kernel32       42229       915     910      0     2      3
win7-x86 ntdll          67696      2000    1994      4     1      1
win7-x86 kernel32       60037      1273     851      7   233    182
win7-x64 ntdll          84434      1961    1961      0     0      0
win7-x64 kernel32       70894      1287     870    139   166    112

untranslated matches: 0 of 8730, over the pairs that carry a map
```

`ntdll` agrees on 99.8%–100% of its exports on all three targets. It is the
module BBT rearranges most and the one whose PDB carries the largest map, so it
is the strongest of the six.

The twelve Win10 and Win11 pairs are in the same run and are not in the table above,
because with no map there is no translation for them to get right. They are still
worth having: purepdb matches 2322 of 2323 `ntdll` exports on Win10 x64, 2462 of
2464 on Win11 x64, and 1661 of 1746 on Win10 x64 `KernelBase` — which says the
rest of the parser holds up on current system binaries. That is a different claim
from the one this document is about, and the same command produces it for free.

### Reading the residue honestly

`kernel32` looks worse and is not. Its mismatches are not disagreement about
*addresses* but about which address belongs to a *name*: Win7 exports it through
stubs, so the export points at a stub and the PDB names the body. The offsets
cluster hard — **146 at exactly +8** on x64, **175 at exactly +13** on x86.

That clustering is the tell. A wrong translation does not produce the same delta
175 times; it scatters. Distinguishing a convention from an error is most of the
work in a check like this, and a check that cannot tell them apart is worse than
none.

### One trap that makes the check pass while comparing nothing

x86 publics are stdcall-decorated (`_NtCreateFile@44`) and exports are not
(`NtCreateFile`). Without undecorating, the two sets barely intersect: an early
version of this comparison matched **2 names on XP `ntdll`** and reported
success. x64 needs no undecoration, which is why its numbers were clean first
and hid the problem.

Any comparison between a PDB's names and an image's exports has to assert *how
many* names it compared, or it will pass by comparing none.

## Testing it without a fixture

Two things stand in for the file that cannot be committed.

**A real move, described by real tables.** `tests/_relink.py` (with
`tools/relink_omap.py` as its command line) takes one of our own fixtures,
physically moves 235 function bodies in `.text` with 30 distinct deltas, and
writes slots 3, 4, 5 and 10 to describe the move. Then the PE oracle applies:
the bytes at the address purepdb reports must be the bytes of the function it
names. 222 of 229 checked addresses move, and every one lands on its own code.
Three mutations of the translation rule — off by one, ignoring the offset into
the range, taking the nearest entry rather than the largest not exceeding — each
fail it.

**A real map, from a real producer.** `tests/data/syzygy/` carries 1228 genuine
OMAP entries. Its PDB and its image describe different layouts, because
`relink` instrumented the image after the linker wrote the PDB — the image
gained a `.syzygy` section and moved everything after `.rdata`.

Between them, the arithmetic is checked against moved bytes and the parsing
against a producer's output. What neither covers is Microsoft's slot-10
conventions, which is what `dev/validate_omap_against_windows.py` is for.

## References

- The `OMAP` structure and its translation rule:
  <https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-omap>
- The Optional Debug Header slot assignment:
  <https://llvm.org/docs/PDB/DbiStream.html>
- Google Syzygy, the only public OMAP producer:
  <https://github.com/google/syzygy>

[i39]: https://github.com/danielplohmann/purepdb/issues/39
