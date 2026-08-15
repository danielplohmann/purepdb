"""Command-line interface: python -m purepdb <command> <file.pdb>

Every listing is one record per line with stable leading columns, so `grep`,
`sort` and `awk` work on the output directly. Record counts and warnings go to
stderr, so a redirected stdout holds records and nothing else.

Names are printed exactly as the PDB stores them -- decorated, mangled, or
empty. An address the PDB cannot resolve prints as `??????` rather than as a
number that would be wrong.
"""

from __future__ import annotations

import collections
import sys
from collections.abc import Callable

from . import PDB, PdbError

# What an unresolvable address prints as, the same width as the addresses
# beside it so the column stays aligned.
NO_RVA = "    ??????"

# A record can carry an empty name -- rust-lld emits S_LABEL32 records with
# nothing in them, and an inline site has no name when the PDB has no IPI
# stream. Printing that as a blank would silently shorten the line.
NO_NAME = "?"


def _guid_str(g: bytes) -> str:
    if len(g) != 16:
        return g.hex()
    import struct
    d1, d2, d3 = struct.unpack_from("<IHH", g, 0)
    d4 = g[8:10]
    d5 = g[10:16]
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4.hex().upper()}-{d5.hex().upper()}"


def _rva(value: int | None) -> str:
    return f"{value:#010x}" if value is not None else NO_RVA


def _warn(pdb: PDB) -> None:
    """Print why a listing came back short, if it did.

    An empty or RVA-less result is the parser's normal failure mode rather than
    an exception, so the CLI must never let one pass unremarked.
    """
    for w in pdb.diagnose().warnings:
        print(f"WARNING: {w}", file=sys.stderr)


def _info(pdb: PDB) -> None:
    info = pdb.info()
    print(f"version   : {info.version}")
    print(f"signature : {info.signature:#010x}")
    print(f"age       : {info.age}")
    print(f"guid      : {_guid_str(info.guid)}")


def _diagnose(pdb: PDB) -> None:
    from . import codeview

    d = pdb.diagnose()
    print(f"modules            : {d.modules} ({d.modules_with_symbols} with symbols)")
    print(f"proc records       : {d.proc_records} "
          f"({d.proc_refs} in the globals index)")
    print(f"public records     : {d.public_records}")
    print(f"inline sites       : {d.inline_sites}")
    print(f"labels             : {d.labels}")
    print(f"line info          : {d.line_bytes} bytes"
          f"{'' if d.has_string_table else ', /names MISSING'}")
    print(f"section headers    : {'yes' if d.has_section_headers else 'NO'}")
    print(f"truncated streams  : {d.truncated_streams}")
    print(f"malformed records  : {d.malformed_records}")
    if d.derived_sections:
        print(f"derived segments   : {d.derived_sections} (from the DBI Section Map)")
    if d.omap_entries or d.has_original_sections:
        print(f"omap entries       : {d.omap_entries} "
              f"(rvas translated to the post-link layout)")
    print(f"section contribs   : {d.section_contributions}")
    print("module record kinds:")
    for kind, count in sorted(d.module_kinds.items(), key=lambda kv: -kv[1]):
        print(f"  {codeview.kind_name(kind):<16s} {count}")
    for w in d.warnings:
        print(f"\nWARNING: {w}")


def _functions(pdb: PDB) -> int:
    fns = pdb.functions()
    for f in fns:
        size = f"{f.code_size:#x}" if f.code_size is not None else "-"
        extra = f"  (+{len(f.aliases)} alias)" if f.aliases else ""
        print(f"{_rva(f.rva)}  {f.source:7s}  size={size:6s}  {f.name}{extra}")
    return len(fns)


def _publics(pdb: PDB) -> int:
    pubs = pdb.public_symbols()
    for p in pubs:
        kind = "func" if p.is_function else "data"
        print(f"seg={p.segment} off={p.offset:#x}  [{kind}]  {p.name}")
    return len(pubs)


def _data(pdb: PDB) -> int:
    symbols = pdb.data_symbols()
    for d in symbols:
        scope = "global" if d.is_global else "static"
        print(f"{_rva(pdb.to_rva(d.segment, d.offset))}  {scope:7s}  {d.name}")
    return len(symbols)


def _sections(pdb: PDB) -> int:
    """The table addresses resolve against, whichever one that is.

    `sections` when the PDB carries the image's own headers, and the table
    rebuilt from the Section Map when it does not -- in which case the warning
    that follows says the addresses are a reconstruction.
    """
    sections = pdb.sections or pdb.derived_sections
    for s in sections:
        print(f"{s.virtual_address:#010x}  size={s.virtual_size:<10x} "
              f"{'X' if s.executable else '-'}  {s.name}")
    return len(sections)


def _labels(pdb: PDB) -> int:
    labels = pdb.labels()
    for label in labels:
        print(f"{_rva(label.rva)}  {label.name or NO_NAME}")
    return len(labels)


def _thunks(pdb: PDB) -> int:
    thunks = pdb.thunks()
    for t in thunks:
        print(f"{_rva(pdb.to_rva(t.segment, t.offset))}  size={t.length:<6x} "
              f"{t.ordinal_name:<10s}  {t.name}")
    return len(thunks)


def _trampolines(pdb: PDB) -> int:
    tramps = pdb.trampolines()
    for t in tramps:
        target = pdb.to_rva(t.target_segment, t.target_offset)
        print(f"{_rva(pdb.to_rva(t.segment, t.offset))}  size={t.size:<6x} "
              f"-> {_rva(target)}")
    return len(tramps)


def _inline(pdb: PDB) -> int:
    sites = pdb.inline_sites()
    for site in sites:
        print(f"{_rva(site.rva)}  size={site.code_size:<6x} "
              f"{site.name or NO_NAME}  <- {site.parent}")
    return len(sites)


def _lines(pdb: PDB) -> int:
    total = 0
    for line in pdb.lines():
        # 0xFEEFEE and 0xF00F00 are markers rather than line numbers; they are
        # printed as they are stored, since filtering them here would hide a
        # record the PDB does contain.
        print(f"{_rva(line.rva)}  {line.file}:{line.line}")
        total += 1
    return total


def _constants(pdb: PDB) -> int:
    constants = pdb.constants()
    for c in constants:
        print(f"{c.value:<#18x}  {c.name}")
    return len(constants)


def _udts(pdb: PDB) -> int:
    udts = pdb.udts()
    for u in udts:
        print(f"{u.type_index:#010x}  {u.name}")
    return len(udts)


def _modules(pdb: PDB) -> int:
    """One line per linker input, with how much of the image it claims."""
    counts = collections.Counter(c.module_index
                                 for c in pdb.section_contributions())
    for i, mod in enumerate(pdb.dbi.modules):
        print(f"{counts.pop(i, 0):8d}  {mod.module_name}")
    # A contribution naming a module the module list does not have is what
    # `module_of()` answers None for. Reporting the total keeps the column sums
    # honest rather than losing those entries between the lines above.
    stray = sum(counts.values())
    if stray:
        print(f"{stray:8d}  <{len(counts)} module index(es) not in the module list>")
    return len(pdb.dbi.modules)


# name -> (handler, what one line is, the columns it prints). The listings all
# return how many records they printed; `info` and `diagnose` are reports
# rather than listings, so they carry no noun and get no count line.
_COMMANDS: dict[str, tuple[Callable[[PDB], int | None], str | None, str]] = {
    "info": (_info, None, "PDB metadata (version/age/GUID)"),
    "diagnose": (_diagnose, None, "what the PDB contains, and why a listing is thin"),
    "functions": (_functions, "functions", "rva  source  size  name"),
    "publics": (_publics, "public symbols", "seg  off  kind  name"),
    "data": (_data, "data symbols", "rva  scope  name"),
    "labels": (_labels, "labels", "rva  name"),
    "thunks": (_thunks, "thunks", "rva  size  ordinal  name"),
    "trampolines": (_trampolines, "trampolines", "rva  size  -> target rva"),
    "inline": (_inline, "inline sites", "rva  size  name  <- parent"),
    "lines": (_lines, "line entries", "rva  file:line"),
    "constants": (_constants, "constants", "value  name"),
    "udts": (_udts, "type names", "type-index  name"),
    "modules": (_modules, "modules", "contributions  module"),
    "sections": (_sections, "sections", "rva  size  executable  name"),
}


def usage() -> str:
    width = max(len(name) for name in _COMMANDS)
    out = [__doc__.strip() if __doc__ else "", "", "Commands:"]
    out += [f"    {name:<{width}s}  {columns}"
            for name, (_handler, _noun, columns) in _COMMANDS.items()]
    return "\n".join(out)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(usage())
        return 2
    cmd, path = argv[1], argv[2]
    entry = _COMMANDS.get(cmd)
    if entry is None:
        print(f"unknown command: {cmd}", file=sys.stderr)
        print(usage(), file=sys.stderr)
        return 2

    try:
        pdb = PDB.open(path)
    except PdbError as exc:
        # These are expected on a directory of real binaries -- report the
        # reason, don't hand the user a traceback.
        print(f"error: {path}: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    handler, noun, _columns = entry
    count = handler(pdb)
    if noun is not None:
        print(f"\n{count} {noun}", file=sys.stderr)
        _warn(pdb)
    return 0


def cli() -> int:
    """Console-script entry point (see pyproject `[project.scripts]`)."""
    return main(sys.argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
