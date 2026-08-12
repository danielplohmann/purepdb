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
from .dbi import ContributionMap, DbiStream, ModuleInfo, SectionContribution
from .gsi import PublicsStream
from .msf import MsfFile
from .omap import OmapTable
from .sections import SectionTable, sections_from_map

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
    module: str | None = None
    """The linker input this address came from, per the Section Contribution
    substream: an `.obj` path, a library member, or `Import:foo.dll` for an
    import thunk. None when the PDB has no usable contribution table, or when
    the address falls in a gap between contributions."""
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
    malformed_records: int = 0
    """Records whose payload is shorter than the kind they claim to be. They
    are skipped; the symbols they would have carried are lost."""
    truncations: list[tuple[str, codeview.Truncation]] = field(default_factory=list)
    """Record streams that stopped short, as (stream description, where).

    Symbols past the bad record are simply absent, so an unreported truncation
    is a short listing with no explanation -- the one thing `diagnose()` exists
    to prevent."""
    derived_sections: int = 0
    """Segments rebuilt from DBI's Section Map because the section-header
    stream was absent. Non-zero means every rva is a reconstruction."""
    omap_entries: int = 0
    """Size of the original-to-final address map, 0 when the image is not
    BBT-processed. Non-zero means every RVA reported went through it."""
    has_original_sections: bool = False
    section_contributions: int = 0
    """Entries in the Section Contribution substream. Zero means `Function.module`
    is None throughout -- the substream is absent, or a version we do not read."""

    @property
    def truncated_streams(self) -> int:
        return len(self.truncations)

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
        if not self.has_section_headers and not self.has_original_sections:
            if self.derived_sections:
                out.append(
                    f"no section-header stream (Optional Debug Header slot 5): "
                    f"addresses come from {self.derived_sections} segments "
                    f"rebuilt from DBI's Section Map, which records segment "
                    f"sizes but no addresses. Every rva is a reconstruction "
                    f"assuming the default 0x1000 section alignment"
                )
            else:
                out.append(
                    "no section-header stream (Optional Debug Header slot 5) "
                    "and no usable Section Map: segment:offset cannot be "
                    "resolved, every rva is None"
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
        if self.malformed_records:
            out.append(
                f"{self.malformed_records} record(s) are shorter than the kind "
                f"they claim to be and were skipped; the symbols they carried "
                f"are missing"
            )
        if self.truncations:
            where, first = self.truncations[0]
            out.append(
                f"{self.truncated_streams} record stream(s) stopped early; "
                f"every symbol after that point is missing. First: {where} at "
                f"byte {first.offset:#x} ({first.reason})"
            )
        if self.omap_entries and not self.has_original_sections:
            out.append(
                "an original-to-final address map is present (Optional Debug "
                "Header slot 4) but the original section table in slot 10 is "
                "not, so there is no pre-optimisation address space to "
                "translate out of; addresses are reported as the section "
                "headers give them and the map is not applied"
            )
        if self.has_original_sections and not self.omap_entries:
            out.append(
                "this image was processed after linking (Optional Debug Header "
                "slot 10 carries its original section table) but the "
                "original-to-final address map in slot 4 is missing: every rva "
                "is in the pre-optimisation address space and does not match "
                "the shipped image"
            )
        return out


def _table_or_none(data: bytes) -> "SectionTable | None":
    """A parsed section table, or None when it describes no sections.

    A stream can be present and empty, which parses into a table that is
    perfectly valid and resolves nothing. Treating that as absent is what
    lets the Section Map fallback run and keeps `diagnose()` honest.
    """
    table = SectionTable.parse(data)
    return table if table.sections else None


class PDB:
    def __init__(self, msf: MsfFile):
        self.msf = msf
        self.dbi = DbiStream.parse(msf.read_stream(STREAM_DBI))
        self._sections: SectionTable | None = None
        self._derived_sections: SectionTable | None = None
        self._original_sections: SectionTable | None = None
        self._omap: OmapTable | None = None
        self._contributions = ContributionMap(self.dbi.section_contributions)
        self._stream_cache_index: int | None = None
        self._stream_cache: bytes = b""
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
            self._sections = _table_or_none(self.msf.read_stream(idx))
        if self._sections is None and self.dbi.section_map:
            derived = sections_from_map(self.dbi.section_map)
            if derived:
                self._derived_sections = SectionTable(derived)

        idx = self.dbi.original_section_header_stream
        if self.msf.is_valid_stream(idx):
            self._original_sections = _table_or_none(self.msf.read_stream(idx))

        idx = self.dbi.omap_from_src_stream
        if self.msf.is_valid_stream(idx):
            self._omap = OmapTable.parse(self.msf.read_stream(idx))

    @property
    def sections(self) -> list:
        """The image's section table, or an empty list if the PDB omits it.

        Read from the section-header stream named by Optional Debug Header slot
        5, and reported only when that stream is present -- these are the
        image's own headers, names and all. When it is absent, addresses still
        resolve through `derived_sections`.
        """
        return self._sections.sections if self._sections else []

    @property
    def derived_sections(self) -> list:
        """A section table rebuilt from DBI's Section Map, or an empty list.

        Populated only when the section-header stream is missing, which is the
        one case where it is needed. The Section Map records no addresses, so
        these are reconstructed; see `sections_from_map` for what that assumes.
        """
        return self._derived_sections.sections if self._derived_sections else []

    @property
    def original_sections(self) -> list:
        """The pre-BBT section table (Optional Debug Header slot 10), if any.

        Present only on images whose code was moved after linking. Symbol
        `segment:offset` pairs are expressed against *this* table, not against
        `sections`, which describes the shipped layout.
        """
        return self._original_sections.sections if self._original_sections else []

    @property
    def omap(self) -> OmapTable | None:
        """The original-to-final address map, when the image was BBT-processed."""
        return self._omap

    @property
    def _symbol_sections(self) -> SectionTable | None:
        """The section table symbol addresses are expressed against.

        The pre-BBT table when the image was reordered after linking, then the
        image's own headers, then the one rebuilt from the Section Map.
        """
        return (self._original_sections or self._sections
                or self._derived_sections)

    def _rva(self, segment: int, offset: int) -> int | None:
        table = self._symbol_sections
        if table is None:
            return None
        rva = table.to_rva(segment, offset)
        # Two ways the map must not be applied. An empty one maps nothing, so
        # testing falsiness rather than None keeps it from nulling every rva.
        # And it translates out of the *pre-BBT* address space, so an address
        # resolved against any other table is already final -- running it
        # through the map would move it somewhere no symbol lives.
        if rva is None or not self._omap:
            return rva
        if table is not self._original_sections:
            return rva
        return self._omap.lookup(rva)

    # -- section contributions ----------------------------------------------

    def section_contributions(self) -> list[SectionContribution]:
        """Every linker input's claim on a range of the image, address-ordered."""
        return self._contributions.contributions

    def module_of(self, segment: int, offset: int) -> ModuleInfo | None:
        """The linker input that contributed `segment:offset`, if it is known."""
        contrib = self._contributions.find(segment, offset)
        if contrib is None or contrib.module_index >= len(self.dbi.modules):
            return None
        return self.dbi.modules[contrib.module_index]

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

    def proc_refs(self) -> list[codeview.ProcRef]:
        """Every procedure, indexed by the globals, from a single stream.

        `module_procs()` finds the same set by walking every module stream;
        this reads one. The two agree exactly on all three fixtures, which is
        what makes it useful as a cross-check -- and as the only listing left
        when a module stream is unreadable.

        A ProcRef carries no address of its own, only the offset of the proc
        record inside its module's stream. `resolve_proc_ref()` follows it.
        """
        idx = self.dbi.symrecord_stream_index
        if not self.msf.is_valid_stream(idx):
            return []
        return codeview.extract_proc_refs(self.msf.read_stream(idx))

    def _cached_stream(self, index: int) -> bytes:
        """The last stream read, remembered.

        Proc refs arrive grouped by module -- 3539 of them span 29 runs on
        sqlite3 x86 -- so holding one stream turns a read per ref into a read
        per module, and bounds the memory at a single stream.
        """
        if self._stream_cache_index != index:
            self._stream_cache = self.msf.read_stream(index)
            self._stream_cache_index = index
        return self._stream_cache

    def resolve_proc_ref(self, ref: codeview.ProcRef) -> codeview.ProcSymbol | None:
        """Read the proc record a ProcRef points at, or None if it does not.

        The offset is into the module stream as stored, signature included, so
        it is used against the raw stream rather than the symbol region.
        """
        if not 0 <= ref.module_index < len(self.dbi.modules):
            return None
        mod = self.dbi.modules[ref.module_index]
        if not self.msf.is_valid_stream(mod.sym_stream):
            return None
        raw = self._cached_stream(mod.sym_stream)
        if ref.sym_offset + 4 > len(raw):
            return None
        rec_len, kind = struct.unpack_from("<HH", raw, ref.sym_offset)
        end = ref.sym_offset + 2 + rec_len
        if rec_len < 2 or kind not in codeview.PROC_KINDS or end > len(raw):
            return None
        try:
            return codeview.parse_proc(kind, raw[ref.sym_offset + 4 : end])
        except EOFError:
            # RecordLen is the record's own claim; a short one is damage, not
            # a proc we can read.
            return None

    def data_symbols(self) -> list[codeview.DataSymbol]:
        """Global/static data symbols (S_GDATA32/S_LDATA32) across all modules,
        plus any in the symbol-record stream."""
        out: list[codeview.DataSymbol] = []
        for mod in self.dbi.modules:
            out.extend(codeview.extract_data(self.module_symbol_bytes(mod)))
        if self.msf.is_valid_stream(self.dbi.symrecord_stream_index):
            out.extend(codeview.extract_data(self.msf.read_stream(self.dbi.symrecord_stream_index)))
        return out

    def _symbol_records(self) -> bytes:
        idx = self.dbi.symrecord_stream_index
        if not self.msf.is_valid_stream(idx):
            return b""
        return self.msf.read_stream(idx)

    def constants(self) -> list[codeview.Constant]:
        """Named compile-time values (S_CONSTANT) from the symbol-record stream.

        The global set, the one the globals hash indexes. Module streams carry
        their own file-static constants, overlapping these by name; merging the
        two would double-count, so they are deliberately not included.

        A constant whose value uses a numeric leaf purepdb does not decode is
        skipped -- its name sits after the value, so an unknown value length
        means the name cannot be reached either.
        """
        return codeview.extract_constants(self._symbol_records())

    def udts(self) -> list[codeview.UserDefinedType]:
        """Type names (S_UDT) from the symbol-record stream.

        `type_index` refers to the TPI stream, which purepdb does not read, so
        it is carried uninterpreted. The names are useful on their own.
        """
        return codeview.extract_udts(self._symbol_records())

    def diagnose(self) -> Diagnostics:
        """Summarise what this PDB actually contains. See `Diagnostics`."""
        kinds: dict[int, int] = {}
        with_symbols = 0
        truncations: list[tuple[str, codeview.Truncation]] = []
        malformed = 0
        for mod in self.dbi.modules:
            body = self.module_symbol_bytes(mod)
            if not body:
                continue
            with_symbols += 1
            malformed += codeview.count_malformed_records(body)
            report: list[codeview.Truncation] = []
            for kind, count in codeview.count_kinds(body, truncation=report).items():
                kinds[kind] = kinds.get(kind, 0) + count
            for t in report:
                truncations.append((f"module {mod.index} ({mod.module_name})", t))

        idx = self.dbi.symrecord_stream_index
        if self.msf.is_valid_stream(idx):
            symrecords = self.msf.read_stream(idx)
            malformed += codeview.count_malformed_records(symrecords)
            t = codeview.find_truncation(symrecords)
            if t is not None:
                truncations.append(("the symbol-record stream", t))

        return Diagnostics(
            modules=len(self.dbi.modules),
            modules_with_symbols=with_symbols,
            proc_records=len(self.module_procs()),
            public_records=len(self.public_symbols()),
            has_section_headers=self._sections is not None,
            module_kinds=kinds,
            malformed_records=malformed,
            truncations=truncations,
            derived_sections=len(self.derived_sections),
            omap_entries=len(self._omap) if self._omap else 0,
            has_original_sections=self._original_sections is not None,
            section_contributions=len(self._contributions),
        )

    def _is_code(self, segment: int) -> bool:
        table = self._symbol_sections
        return table is not None and table.is_executable(segment)

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

        def module_name(segment, offset):
            mod = self.module_of(segment, offset)
            return mod.module_name if mod else None

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
                module=module_name(p.segment, p.offset),
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
                module=module_name(pub.segment, pub.offset),
            ))

        return sorted(seen.values(), key=lambda f: (f.rva is None, f.rva or 0, f.name))
