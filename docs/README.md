# purepdb notes

Three documents about reading PDB files, written while building purepdb. They
are not a format reference — [LLVM's PDB documentation][llvm] and `cvinfo.h` in
[microsoft/microsoft-pdb][mspdb] do that job well, and a fourth structural
walkthrough would add nothing.

What is thin on the ground, and what these cover, is the layer above: **what
real files do**, which fields cannot be trusted, and how to know a parser has
got it right. That knowledge tends to live as comments and bug fixes inside
individual implementations rather than anywhere a reader can find it.

| document | subject |
| --- | --- |
| [`omap.md`](omap.md) | OMAP, Optional Debug Header slot 10, and the one place in the format where a missing stream gives wrong answers rather than missing ones |
| [`reading-real-pdbs.md`](reading-real-pdbs.md) | Field notes: unreliable flags, symbols described twice, one address with several correct names, and why an empty result is the normal failure mode |
| [`validating.md`](validating.md) | How the claims here were checked, and the two ways a test can pass while asserting nothing |

## On the numbers

Every figure in these documents was measured with purepdb against a specific
file, and the fixtures are described in
[`tests/data/README.md`](../tests/data/README.md). Where a claim concerns real
Windows binaries it means the six pairs named in
[`omap.md`](omap.md#what-was-measured) — one XP and one Win7 installation — and
not the platform in general.

They are also version-specific in ways worth remembering. A count belongs to a
build of a fixture, not to a toolchain; "`rust-lld` leaves the function flag
clear" is a statement about the builds measured, and the underlying cause turned
out to be the contributing object's COFF symbol type rather than the linker.
Where something was not tested, these documents say so rather than generalising.

Nothing here is a novelty claim. It is a record of what was measured, in enough
detail to be re-run and contradicted.

[llvm]: https://llvm.org/docs/PDB/
[mspdb]: https://github.com/microsoft/microsoft-pdb
