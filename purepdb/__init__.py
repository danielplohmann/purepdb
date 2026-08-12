"""purepdb — a minimal pure-Python PDB parser.

Scope: extract function names and entry points (and public/data symbols) from
Microsoft PDB debug-info files, with no native dependencies.

Not in scope: type stream (TPI/IPI) decoding, column info, injected sources.
`/DEBUG:FASTLINK` PDBs carry no procedure records at all -- publics still work,
and `PDB.diagnose()` says so rather than letting the caller read an unexplained
empty list.
"""

from .msf import MsfFile, MsfError, PdbError, UnsupportedPdbError
from .pdb import PDB, Diagnostics, Function, InlineFunction, Line, PdbInfo
from .codeview import (
    Constant, DataSymbol, ProcRef, ProcSymbol, PublicSymbol, Truncation,
    UserDefinedType,
)
from .dbi import ModuleInfo, SectionContribution
from .gsi import PublicsStream
from .ipi import IdTable
from .names import StringTable
from .omap import OmapTable
from .sections import (
    Section, SectionMapEntry, SectionTable, sections_from_map,
)

__version__ = "0.2.0"

__all__ = [
    "PDB",
    "Diagnostics",
    "Function",
    "Line",
    "InlineFunction",
    "PdbInfo",
    "PublicSymbol",
    "ProcSymbol",
    "ProcRef",
    "DataSymbol",
    "Truncation",
    "ModuleInfo",
    "SectionContribution",
    "Constant",
    "UserDefinedType",
    "PublicsStream",
    "OmapTable",
    "StringTable",
    "IdTable",
    "Section",
    "SectionTable",
    "SectionMapEntry",
    "sections_from_map",
    "MsfFile",
    "PdbError",
    "MsfError",
    "UnsupportedPdbError",
]
