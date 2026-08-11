"""High-level PDB API.

    from purepdb import PDB

    pdb = PDB.open("app.pdb")
    for fn in pdb.functions():
        print(hex(fn.rva), fn.name)

`functions()` merges two sources:
  * module-level S_GPROC32/S_LPROC32 records (rich: has code size, locals),
  * public S_PUB32 records flagged as functions (broad coverage, incl. thunks
    and symbols without full proc info).

Both are resolved to image RVAs via the section-header table when available.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import codeview
from .dbi import DbiStream
from .gsi import PublicsStream
from .msf import MsfFile
from .sections import SectionTable

# Fixed stream indices in every PDB.
STREAM_PDB_INFO = 1
STREAM_TPI = 2
STREAM_DBI = 3

# CodeView signature that prefixes each module symbol substream.
CV_SIGNATURE_C13 = 4


@dataclass
class Function:
    name: str
    segment: int
    offset: int
    rva: int | None
    code_size: int | None
    source: str  # "proc" or "public"
    aliases: list[str] = field(default_factory=list)
    """Other names sharing this entry point, in discovery order.

    Linkers fold identical function bodies (MSVC /OPT:ICF, rust-lld by
    default), so one address legitimately carries several names. `name` is one
    of them -- proc records win over publics -- and the rest live here rather
    than being dropped."""

    @property
    def names(self) -> list[str]:
        """Every name at this entry point, `name` first."""
        return [self.name] + self.aliases


@dataclass
class PdbInfo:
    version: int
    signature: int
    age: int
    guid: bytes


@dataclass
class Diagnostics:
    """Why a PDB yielded the symbols it did -- especially when that is none.

    Every failure mode this parser has hit on real files is an *empty result*,
    not an exception: a PDB with no section-header stream resolves no RVAs, and
    one whose module streams hold records we don't decode yields no procs. Both
    look identical to a caller reading `functions()`. This is what tells them
    apart.
    """

    modules: int
    modules_with_symbols: int
    proc_records: int
    public_records: int
    has_section_headers: bool
    module_kinds: dict[int, int]  # record kind -> count, module streams only

    @property
    def managed_proc_records(self) -> int:
        """Count of .NET method records, which are not native functions."""
        from . import codeview

        return sum(n for kind, n in self.module_kinds.items()
                   if kind in codeview.MANAGED_PROC_KINDS)

    @property
    def warnings(self) -> list[str]:
        from . import codeview

        out = []
        if not self.has_section_headers:
            out.append(
                "no section-header stream (Optional Debug Header slot 5): "
                "segment:offset cannot be resolved, every rva is None"
            )
        if self.proc_records == 0 and self.modules_with_symbols:
            if self.managed_proc_records:
                out.append(
                    f"this PDB describes managed (.NET) code: "
                    f"{self.managed_proc_records} S_GMANPROC/S_LMANPROC "
                    f"records, which are keyed by metadata token rather than "
                    f"segment:offset and have no RVA to resolve. purepdb reads "
                    f"native code only"
                )
            else:
                top = sorted(self.module_kinds.items(), key=lambda kv: -kv[1])[:3]
                shape = ", ".join(f"{codeview.kind_name(k)}x{n}" for k, n in top)
                out.append(
                    f"no procedure records in {self.modules_with_symbols} "
                    f"module streams (dominant kinds: {shape}); function names "
                    f"can only come from the {self.public_records} public "
                    f"records. This is what /DEBUG:FASTLINK and some pre-2010 "
                    f"toolchains produce"
                )
        if self.public_records == 0:
            out.append(
                "no public records in the symbol-record stream; thunks and "
                "folded entries will be missing"
            )
        return out


class PDB:
    def __init__(self, msf: MsfFile):
        self.msf = msf
        self.dbi = DbiStream.parse(msf.read_stream(STREAM_DBI))
        self._sections: SectionTable | None = None
        self._load_sections()

    @classmethod
    def open(cls, path: str) -> "PDB":
        return cls(MsfFile.open(path))

    @classmethod
    def from_bytes(cls, data: bytes) -> "PDB":
        return cls(MsfFile(data))

    # -- metadata -----------------------------------------------------------

    def info(self) -> PdbInfo:
        data = self.msf.read_stream(STREAM_PDB_INFO)
        version, signature, age = struct.unpack_from("<III", data, 0)
        guid = data[12:28]
        return PdbInfo(version=version, signature=signature, age=age, guid=guid)

    # -- sections -----------------------------------------------------------

    def _load_sections(self) -> None:
        idx = self.dbi.section_header_stream
        if self.msf.is_valid_stream(idx):
            self._sections = SectionTable.parse(self.msf.read_stream(idx))

    @property
    def sections(self) -> list:
        """The image's section table, or an empty list if the PDB omits it.

        Read from the section-header stream named by Optional Debug Header slot
        5. Without it there is no way to turn segment:offset into an RVA, so
        `Function.rva` is None throughout.
        """
        return self._sections.sections if self._sections else []

    def _rva(self, segment: int, offset: int) -> int | None:
        if self._sections is None:
            return None
        return self._sections.to_rva(segment, offset)

    # -- symbols ------------------------------------------------------------

    def publics_stream(self) -> PublicsStream | None:
        """The publics *hash* stream: header, address map, thunk table.

        It contains no symbol records -- only offsets into the symbol-record
        stream. Returns None when absent or unparsable.
        """
        idx = self.dbi.public_stream_index
        if not self.msf.is_valid_stream(idx):
            return None
        try:
            return PublicsStream.parse(self.msf.read_stream(idx))
        except (ValueError, struct.error):
            return None

    def public_symbols(self) -> list[codeview.PublicSymbol]:
        """All S_PUB32 records, in ascending address order where possible.

        Records are read from the symbol-record stream. The publics hash
        stream is consulted only for its address map, which supplies the
        ordering; if it is missing or disagrees, stream order is used.
        """
        idx = self.dbi.symrecord_stream_index
        if not self.msf.is_valid_stream(idx):
            return []
        publics = codeview.extract_publics(self.msf.read_stream(idx))

        stream = self.publics_stream()
        if stream is None or not stream.addr_map:
            return publics
        rank = {off: i for i, off in enumerate(stream.addr_map)}
        if not all(p.record_offset in rank for p in publics):
            # Address map does not cover every record; don't trust it to sort.
            return publics
        return sorted(publics, key=lambda p: rank[p.record_offset])

    def module_symbol_bytes(self, mod) -> bytes:
        """The symbol-record region of one module's stream, signature stripped.

        A module stream is `signature | symbols | C11 line info | C13 line
        info`, and only the first region holds symbol records. `sym_byte_size`
        bounds it *including* the 4-byte signature, so parsing past it walks
        line-info bytes as if they were records. Returns b"" when the module
        has no symbols.
        """
        if not mod.has_symbols or not self.msf.is_valid_stream(mod.sym_stream):
            return b""
        raw = self.msf.read_stream(mod.sym_stream)
        end = min(mod.sym_byte_size, len(raw))
        if len(raw) >= 4 and struct.unpack_from("<I", raw, 0)[0] == CV_SIGNATURE_C13:
            return raw[4:end]
        return raw[:end]

    def module_procs(self) -> list[codeview.ProcSymbol]:
        procs: list[codeview.ProcSymbol] = []
        for mod in self.dbi.modules:
            procs.extend(codeview.extract_procs(self.module_symbol_bytes(mod)))
        return procs

    def data_symbols(self) -> list[codeview.DataSymbol]:
        """Global/static data symbols (S_GDATA32/S_LDATA32) across all modules,
        plus any in the symbol-record stream."""
        out: list[codeview.DataSymbol] = []
        for mod in self.dbi.modules:
            out.extend(codeview.extract_data(self.module_symbol_bytes(mod)))
        if self.msf.is_valid_stream(self.dbi.symrecord_stream_index):
            out.extend(codeview.extract_data(self.msf.read_stream(self.dbi.symrecord_stream_index)))
        return out

    def diagnose(self) -> Diagnostics:
        """Summarise what this PDB actually contains. See `Diagnostics`."""
        kinds: dict[int, int] = {}
        with_symbols = 0
        for mod in self.dbi.modules:
            body = self.module_symbol_bytes(mod)
            if not body:
                continue
            with_symbols += 1
            for kind, count in codeview.count_kinds(body).items():
                kinds[kind] = kinds.get(kind, 0) + count
        return Diagnostics(
            modules=len(self.dbi.modules),
            modules_with_symbols=with_symbols,
            proc_records=len(self.module_procs()),
            public_records=len(self.public_symbols()),
            has_section_headers=self._sections is not None,
            module_kinds=kinds,
        )

    def _is_code(self, segment: int) -> bool:
        return self._sections is not None and self._sections.is_executable(segment)

    def functions(self, *, code_publics: bool = True) -> list[Function]:
        """Return all discoverable functions, merged by (segment, offset).

        Two sources feed this: module proc records (rich -- they carry code
        size) and publics (broad -- they cover thunks, CRT stubs and folded
        entries that have no proc record). Where both describe one address the
        proc record wins the `name` slot; every other name lands in `aliases`
        rather than being dropped, because folded bodies really do have several
        correct names.

        A public counts as a function when `PUBLIC_FLAG_FUNCTION` is set *or*
        it resolves into an executable section. The second clause is not
        redundant: `link.exe` sets the flag on every code public (all 438 of
        sqlite3 x86's), but `rust-lld` leaves it clear on 143 of 280, including
        `mainCRTStartup` and `__chkstk`. Trusting the flag alone loses those.
        Pass `code_publics=False` for flag-only behaviour.
        """
        seen: dict[tuple[int, int], Function] = {}

        def add(key, name, make):
            fn = seen.get(key)
            if fn is None:
                seen[key] = make()
            elif name != fn.name and name not in fn.aliases:
                fn.aliases.append(name)

        for p in self.module_procs():
            add((p.segment, p.offset), p.name, lambda p=p: Function(
                name=p.name,
                segment=p.segment,
                offset=p.offset,
                rva=self._rva(p.segment, p.offset),
                code_size=p.code_size,
                source="proc",
            ))

        for pub in self.public_symbols():
            if not pub.is_function:
                if not (code_publics and self._is_code(pub.segment)):
                    continue
            add((pub.segment, pub.offset), pub.name, lambda pub=pub: Function(
                name=pub.name,
                segment=pub.segment,
                offset=pub.offset,
                rva=self._rva(pub.segment, pub.offset),
                code_size=None,
                source="public",
            ))

        return sorted(seen.values(), key=lambda f: (f.rva is None, f.rva or 0, f.name))
