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
Across all six pairs measured, **0 of 8730 exports match the untranslated
address**.

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
nothing obliges them to appear in it. Whatever the right algorithm is, it needs
a real file to check against rather than reasoning — which is why purepdb does
not do this yet, and why [#39][i39] tracks it rather than guessing.

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

### The era question, answered

It is easy to assume BBT is an XP-era artefact. It is not: **every Win7 SP1 PDB
measured carries slot 10**, and Win7 x64 `ntdll` has the largest map of the set
at 84434 entries — more than double XP's `ntdll`.

| pair | omap entries | slot 10 |
| --- | ---: | :---: |
| winxp `ntdll` | 37061 | yes |
| winxp `kernel32` | 42229 | yes |
| win7-x86 `ntdll` | 67696 | yes |
| win7-x86 `kernel32` | 60037 | yes |
| win7-x64 `ntdll` | 84434 | yes |
| win7-x64 `kernel32` | 70894 | yes |

Whether later Windows releases still do was not tested.

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

untranslated matches: 0 of 8730
```

`ntdll` agrees on 99.8%–100% of its exports on all three targets. It is the
module BBT rearranges most and the one whose PDB carries the largest map, so it
is the strongest of the six.

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
