"""Command-line interface: python -m purepdb <command> <file.pdb>

Commands:
    functions <pdb>   list functions (name + entry-point RVA)
    publics   <pdb>   list public symbols
    info      <pdb>   print PDB metadata (version/age/GUID)
    diagnose  <pdb>   report what the PDB contains, and why a listing is thin
"""

from __future__ import annotations

import sys

from . import PDB, PdbError


def _guid_str(g: bytes) -> str:
    if len(g) != 16:
        return g.hex()
    import struct
    d1, d2, d3 = struct.unpack_from("<IHH", g, 0)
    d4 = g[8:10]
    d5 = g[10:16]
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4.hex().upper()}-{d5.hex().upper()}"


def _warn(pdb) -> None:
    """Print why a listing came back short, if it did.

    An empty or RVA-less result is the parser's normal failure mode rather than
    an exception, so the CLI must never let one pass unremarked.
    """
    for w in pdb.diagnose().warnings:
        print(f"WARNING: {w}", file=sys.stderr)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    cmd, path = argv[1], argv[2]
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

    if cmd == "info":
        # Guarded as well as the open: a short or too-old Info stream raises
        # from this read rather than from `PDB.open`, so leaving it outside
        # would still hand the user a traceback. Guarding the whole dispatch
        # this way is what the command-table rewrite in issue #28 does.
        try:
            info = pdb.info()
        except PdbError as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            return 1
        print(f"version   : {info.version}")
        print(f"signature : {info.signature:#010x}")
        print(f"age       : {info.age}")
        print(f"guid      : {_guid_str(info.guid)}")
        return 0

    if cmd == "functions":
        fns = pdb.functions()
        for f in fns:
            rva = f"{f.rva:#010x}" if f.rva is not None else "    ??????"
            size = f"{f.code_size:#x}" if f.code_size is not None else "-"
            extra = f"  (+{len(f.aliases)} alias)" if f.aliases else ""
            print(f"{rva}  {f.source:7s}  size={size:6s}  {f.name}{extra}")
        print(f"\n{len(fns)} functions", file=sys.stderr)
        _warn(pdb)
        return 0

    if cmd == "publics":
        pubs = pdb.public_symbols()
        for p in pubs:
            kind = "func" if p.is_function else "data"
            print(f"seg={p.segment} off={p.offset:#x}  [{kind}]  {p.name}")
        print(f"\n{len(pubs)} public symbols", file=sys.stderr)
        _warn(pdb)
        return 0

    if cmd == "diagnose":
        d = pdb.diagnose()
        print(f"modules            : {d.modules} ({d.modules_with_symbols} with symbols)")
        print(f"proc records       : {d.proc_records} "
              f"({d.proc_refs} in the globals index)")
        print(f"public records     : {d.public_records}")
        print(f"inline sites       : {d.inline_sites}")
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
        from . import codeview
        for kind, count in sorted(d.module_kinds.items(), key=lambda kv: -kv[1]):
            print(f"  {codeview.kind_name(kind):<16s} {count}")
        for w in d.warnings:
            print(f"\nWARNING: {w}")
        return 0

    print(f"unknown command: {cmd}", file=sys.stderr)
    return 2


def cli() -> int:
    """Console-script entry point (see pyproject `[project.scripts]`)."""
    return main(sys.argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
