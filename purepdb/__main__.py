"""Command-line interface: python -m purepdb <command> <file.pdb>

Every listing is one record per line with stable leading columns, so `grep`,
`sort` and `awk` work on the output directly. Record counts and warnings go to
stderr, as does the usage text, so a redirected stdout holds records and
nothing else. `diagnose` is a report rather than a listing: its output *is*
stdout, warnings included.

A name can hold anything, including spaces -- `std::rt::lang_start::closure$0
<tuple$<> >` is one name -- so **the name is the last field on its line**, and
nothing is printed after it. The one line that carries two names, an inline
site and the function it was inlined into, separates them with a tab, which a
name cannot contain because every unprintable character in one is escaped: a
name holding a newline would otherwise put a record on two lines, and one
holding an escape sequence would drive the terminal. A backslash is left
alone, so `a\x0ab` on screen is either of two names -- readable paths are
worth more here than a mapping that can be inverted. Names are otherwise
printed exactly as the PDB stores them -- decorated, mangled, or empty.

An address the PDB cannot resolve prints as `??????` rather than as a number
that would be wrong.
"""

from __future__ import annotations

import collections
import contextlib
import os
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

def _escape(char: str) -> str:
    code = ord(char)
    if code < 0x100:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}"


def _text(value: str) -> str:
    """A name or path, safe to print as one line of a terminal.

    Everything Python calls unprintable is escaped, which is a wider net than
    the C0 controls: it also catches U+2028 and U+2029, which `splitlines()`
    breaks a line on, and the bidirectional overrides, which can make a name
    display as a different name entirely. Escaped rather than stripped, so the
    line still says what the record holds, and by codepoint rather than
    through `unicode_escape`, which would also mangle the legitimate non-ASCII
    in a path or a Rust symbol.
    """
    if value.isprintable():
        return value  # every name in the corpus, so this is the path that runs
    return "".join(ch if ch.isprintable() or ch == " " else _escape(ch)
                   for ch in value)


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


def _eprint(text: str = "") -> None:
    """Write a diagnostic to stderr, or to nowhere if there is no stderr.

    `print(..., file=None)` means *stdout*, and the shell can leave
    `sys.stderr` as None -- `purepdb labels x.pdb 2>&-` does. Printing to it
    unguarded would put every warning, count and error message in among the
    records, which is exactly what this command line promises never to do.
    """
    if sys.stderr is not None:
        print(text, file=sys.stderr)


def _warn(pdb: PDB) -> None:
    """Everything `diagnose()` found wrong with the file, after the listing.

    An empty or RVA-less result is the parser's normal failure mode rather than
    an exception, so the CLI must never let one pass unremarked.

    Deliberately not filtered to the command: a warning about a stream this
    listing never read is still the reason the next listing comes back short,
    and deciding which warning belongs to which subcommand would be a table
    that drifts out of step with `Diagnostics.warnings`.
    """
    for w in pdb.diagnose().warnings:
        # Escaped like a listing: a warning quotes the module name it found
        # the damage in, and that name comes out of the file.
        _eprint(f"WARNING: {_text(w)}")


def _info(pdb: PDB) -> None:
    info = pdb.info()
    print(f"version   : {info.version}")
    print(f"signature : {info.signature:#010x}")
    print(f"age       : {info.age}")
    print(f"guid      : {_guid_str(info.guid)}")


def _diagnose(pdb: PDB) -> None:
    from . import codeview

    d = pdb.diagnose()
    print(f"modules            : {d.modules} "
          f"({d.modules_with_symbols} with symbols)")
    print(f"proc records       : {d.proc_records} "
          f"({d.proc_refs} in the globals index)")
    print(f"public records     : {d.public_records}")
    print(f"inline sites       : {d.inline_sites}")
    print(f"labels             : {d.labels}")
    if d.thread_local_records:
        print(f"thread-local recs  : {d.thread_local_records} "
              f"(thread_locals(), not data_symbols())")
    print(f"line info          : {d.line_bytes} bytes"
          f"{'' if d.has_string_table else ', /names MISSING'}")
    print(f"section headers    : {'yes' if d.has_section_headers else 'NO'}")
    print(f"truncated streams  : {d.truncated_streams}")
    print(f"malformed records  : {d.malformed_records}")
    if d.derived_sections:
        print(f"derived segments   : {d.derived_sections} "
              f"(from the DBI Section Map)")
    if d.omap_entries or d.has_original_sections:
        print(f"omap entries       : {d.omap_entries} "
              f"(rvas translated to the post-link layout)")
    print(f"section contribs   : {d.section_contributions}")
    print("module record kinds:")
    for kind, count in sorted(d.module_kinds.items(), key=lambda kv: -kv[1]):
        print(f"  {codeview.kind_name(kind):<16s} {count}")
    for w in d.warnings:
        print(f"\nWARNING: {_text(w)}")


def _functions(pdb: PDB) -> int:
    fns = pdb.functions()
    for f in fns:
        size = f"{f.code_size:#x}" if f.code_size is not None else "-"
        aliases = f"+{len(f.aliases)}" if f.aliases else "-"
        print(f"{_rva(f.rva)}  {f.source:7s}  size={size:8s}  {aliases:3s}  "
              f"{_text(f.name)}")
    return len(fns)


def _publics(pdb: PDB) -> int:
    pubs = pdb.public_symbols()
    for p in pubs:
        kind = "func" if p.is_function else "data"
        print(f"seg={p.segment:<3d} off={p.offset:#010x}  [{kind}]  "
              f"{_text(p.name)}")
    return len(pubs)


def _data(pdb: PDB) -> int:
    """Distinct data symbols, one line each.

    `data_symbols()` reads the module streams and the symbol-record stream, and
    a file-static symbol is described by both -- 633 records for the 481 symbols
    sqlite3 x86 actually holds. It deduplicates on name, segment, offset and
    kind, so the count here is symbols rather than records, and `diagnose()` is
    where the record count lives.
    """
    symbols = pdb.data_symbols()
    for d in symbols:
        scope = "global" if d.is_global else "static"
        print(f"{_rva(pdb.to_rva(d.segment, d.offset))}  {scope:7s}  "
              f"{_text(d.name) or NO_NAME}")
    return len(symbols)


def _thread(pdb: PDB) -> int:
    """Thread-local variables, at their TLS template addresses.

    The column is headed `template-rva` and not `rva` because that is what the
    address is: where a new thread's copy is initialised *from*, not where any
    variable lives. Pairing one with a `functions` rva compares two different
    address spaces, so the header says so on every invocation.
    """
    locals_ = pdb.thread_locals()
    for t in locals_:
        scope = "global" if t.is_global else "static"
        print(f"{_rva(t.template_rva)}  {scope:7s}  "
              f"{_text(t.name) or NO_NAME}")
    return len(locals_)


def _sections(pdb: PDB) -> int:
    """The section table, whichever of the three the PDB has.

    The image's own headers when it carries them; then the pre-BBT table from
    Optional Debug Header slot 10, which is the only one a BBT-processed PDB
    may have; then the table rebuilt from the Section Map, in which case the
    warning that follows says the addresses are a reconstruction.

    Falsiness rather than `is not None` at each step: an empty-but-present
    stream parses into a valid table describing nothing, and printing that as
    the answer is how this listed nothing at all on a slot-10-only PDB while
    every address in the file resolved perfectly well.
    """
    sections = pdb.sections or pdb.original_sections or pdb.derived_sections
    for s in sections:
        print(f"{s.virtual_address:#010x}  size={s.virtual_size:<10x} "
              f"{'X' if s.executable else '-'}  {_text(s.name)}")
    return len(sections)


def _labels(pdb: PDB) -> int:
    labels = pdb.labels()
    for label in labels:
        print(f"{_rva(label.rva)}  {_text(label.name) or NO_NAME}")
    return len(labels)


def _thunks(pdb: PDB) -> int:
    thunks = pdb.thunks()
    for t in thunks:
        print(f"{_rva(pdb.to_rva(t.segment, t.offset))}  size={t.length:<8x} "
              f"{t.ordinal_name:<18s}  {_text(t.name)}")
    return len(thunks)


def _trampolines(pdb: PDB) -> int:
    tramps = pdb.trampolines()
    for t in tramps:
        target = pdb.to_rva(t.target_segment, t.target_offset)
        print(f"{_rva(pdb.to_rva(t.segment, t.offset))}  size={t.size:<8x} "
              f"-> {_rva(target)}")
    return len(tramps)


def _inline(pdb: PDB) -> int:
    sites = pdb.inline_sites()
    for site in sites:
        print(f"{_rva(site.rva)}  size={site.code_size:<8x} "
              f"{_text(site.name) or NO_NAME}\t<- {_text(site.parent)}")
    return len(sites)


def _lines(pdb: PDB) -> int:
    total = 0
    for line in pdb.lines():
        # 0xFEEFEE and 0xF00F00 print as themselves: they are markers rather
        # than line numbers, and hiding one would hide a record the PDB holds.
        print(f"{_rva(line.rva)}  {_text(line.file)}:{line.line}")
        total += 1
    return total


def _constants(pdb: PDB) -> int:
    constants = pdb.constants()
    for c in constants:
        print(f"{c.value:<#18x}  {_text(c.name)}")
    return len(constants)


def _udts(pdb: PDB) -> int:
    udts = pdb.udts()
    for u in udts:
        print(f"{u.type_index:<#10x}  {_text(u.name)}")
    return len(udts)


def _modules(pdb: PDB) -> int:
    """One line per linker input, with how much of the image it claims."""
    counts = collections.Counter(c.module_index
                                 for c in pdb.section_contributions())
    printed = 0
    for i, mod in enumerate(pdb.dbi.modules):
        print(f"{counts.pop(i, 0):8d}  {_text(mod.module_name)}")
        printed += 1
    # A contribution naming a module the module list does not have is what
    # `module_of()` answers None for. Reporting the total keeps the column sums
    # honest rather than losing those entries between the lines above.
    stray = sum(counts.values())
    if stray:
        print(f"{stray:8d}  <{len(counts)} module index(es) not in the "
              f"module list>")
        # Deliberately not counted: the noun is "modules", and this line is
        # the contributions that name no module. Counting it would report one
        # module more than the file has.
    return printed


# name -> (handler, what one line is, the columns it prints). The listings all
# return how many records they printed; `info` and `diagnose` are reports
# rather than listings, so they carry no noun and get no count line.
_COMMANDS: dict[str, tuple[Callable[[PDB], int | None], str | None, str]] = {
    "info": (_info, None, "version, signature, age and GUID"),
    "diagnose": (_diagnose, None,
                 "what the PDB contains, and why a listing is thin"),
    "functions": (_functions, "functions", "rva  source  size  aliases  name"),
    "publics": (_publics, "public symbols", "seg  off  kind  name"),
    "data": (_data, "data symbols", "rva  scope  name"),
    "labels": (_labels, "labels", "rva  name"),
    "thunks": (_thunks, "thunks", "rva  size  ordinal  name"),
    "trampolines": (_trampolines, "trampolines", "rva  size  -> target rva"),
    "inline": (_inline, "inline sites", "rva  size  name <TAB> <- parent"),
    "lines": (_lines, "line entries", "rva  file:line"),
    "constants": (_constants, "constants", "value  name"),
    "udts": (_udts, "type names", "type-index  name"),
    "modules": (_modules, "modules", "contributions  module"),
    "thread": (_thread, "thread-local variables",
               "template-rva  scope  name"),
    "sections": (_sections, "sections", "rva  size  executable  name"),
}


def usage() -> str:
    width = max(len(name) for name in _COMMANDS)
    out = [__doc__.strip() if __doc__ else "", "", "Commands:"]
    out += [f"    {name:<{width}s}  {columns}"
            for name, (_handler, _noun, columns) in _COMMANDS.items()]
    return "\n".join(out)


HELP_FLAGS = ("-h", "--help")


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] in HELP_FLAGS:
        # Asked for, so it is the output: stdout, and not a failure.
        print(usage())
        return 0
    if len(argv) < 3:
        # Not asked for, so it is a diagnostic. On stderr, where it cannot
        # land in a file somebody meant to fill with records.
        _eprint(usage())
        return 2
    cmd, path = argv[1], argv[2]
    entry = _COMMANDS.get(cmd)
    if entry is None:
        _eprint(f"unknown command: {_text(cmd)}")
        _eprint(usage())
        return 2

    handler, noun, _columns = entry
    try:
        pdb = PDB.open(path)
        count = handler(pdb)
        if noun is not None:
            _eprint(f"\n{count} {noun}")
            _warn(pdb)
    except PdbError as exc:
        # Every stage is inside this, not just the open. A stream the listing
        # reaches only part-way through can be unreadable -- a nil stream, a
        # bad block map -- and `diagnose()` reads more streams than the listing
        # did, so the warning step can raise on a file the listing survived.
        # These are expected on a directory of real binaries: report the
        # reason, don't hand the user a traceback.
        # The path is escaped too: sweeping a directory of untrusted files
        # means the *file name* is attacker-chosen as surely as the records
        # inside it.
        _eprint(f"error: {_text(path)}: {_text(str(exc))}")
        return 1
    except BrokenPipeError:
        # Before OSError, which it is a subclass of. `| head` closes the pipe
        # under us: not an error, and the shell would have reported 141 for
        # the SIGPIPE this stands in for.
        return 141
    except OSError as exc:
        _eprint(f"error: {_text(str(exc))}")
        return 1
    return 0


def _stop_writing_to_stdout() -> None:
    """Keep the interpreter from raising again on the way out.

    Python flushes stdout at exit, which on a stream that cannot be written --
    a closed pipe, a closed descriptor -- raises a second time and prints a
    message nothing caught. Pointing the descriptor at the null device is the
    remedy the standard library documents.
    """
    # Suppressed rather than handled: stdout may not be a real file at all --
    # a test's capture buffer has no descriptor -- and then there is nothing
    # for the interpreter to flush into either.
    with contextlib.suppress(OSError, ValueError):
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())


def _settle_stdout() -> None:
    """Flush what is buffered, and give up on stdout only if that fails.

    Abandoning stdout unconditionally would discard a listing that was merely
    interrupted: on Ctrl-C the records written so far are still wanted, and
    the descriptor is usually perfectly healthy.
    """
    try:
        sys.stdout.flush()
    except (OSError, ValueError):
        _stop_writing_to_stdout()


def cli() -> int:
    """Console-script entry point (see pyproject `[project.scripts]`).

    Everything that is about being a process rather than about PDBs lives
    here, so that `main()` stays callable from a test.
    """
    if sys.stdout is None:
        # `purepdb labels x.pdb >&-`. The shell closed the descriptor before
        # the interpreter could build a stream over it, so there is nowhere to
        # put the records -- and `print()` discards them in silence, which
        # would leave the count on stderr describing a listing nobody got.
        _eprint("error: standard output is closed")
        return 1
    for stream in (sys.stdout, sys.stderr):
        # A name from a damaged file can hold a character the console cannot
        # encode -- cp1252 has no U+FFFD, which is what an undecodable byte in
        # a symbol name becomes. Escaping beats dying with the listing
        # half-written.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(OSError, ValueError):
                reconfigure(errors="backslashreplace")
    try:
        status = main(sys.argv)
        # The flush belongs here, not to the interpreter's exit. A listing
        # small enough to sit in the stdio buffer performs no write at all
        # while `main()` is running, so `| head` or any reader that leaves
        # early is discovered only on the way out -- where nothing catches it,
        # and the user gets a message from the interpreter and status 120
        # instead of the 141 that says the pipe closed.
        sys.stdout.flush()
        return status
    except KeyboardInterrupt:
        _eprint()  # finish the line the listing was on
        # Ctrl-C is the one exit here that does not mean stdout is broken, so
        # the records already written are flushed rather than thrown away.
        # Without this the interpreter's exit flush raises where nothing
        # catches it, and 130 becomes 120.
        _settle_stdout()
        return 130
    except BrokenPipeError:
        _stop_writing_to_stdout()
        return 141
    except OSError as exc:
        _stop_writing_to_stdout()
        _eprint(f"error: {_text(str(exc))}")
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
