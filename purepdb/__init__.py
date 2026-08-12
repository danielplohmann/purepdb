"""purepdb — a minimal pure-Python PDB parser.

Scope: extract function names and entry points (and public/data symbols) from
Microsoft PDB debug-info files, with no native dependencies.

Not in scope: type stream (TPI/IPI) decoding, line/column info, source file
tables, injected sources. `/DEBUG:FASTLINK` PDBs carry no procedure records at
all -- publics still work, and `PDB.diagnose()` says so rather than letting the
caller read an unexplained empty list.
"""

from .msf import MsfFile, MsfError, PdbError, UnsupportedPdbError
from .pdb import PDB, Diagnostics, Function, PdbInfo
from .codeview import DataSymbol, ProcSymbol, PublicSymbol, Truncation
from .gsi import PublicsStream
from .sections import (
    Section, SectionMapEntry, SectionTable, sections_from_map,
)

__version__ = "0.2.0"

__all__ = [
    "PDB",
    "Diagnostics",
    "Function",
    "PdbInfo",
    "PublicSymbol",
    "ProcSymbol",
    "DataSymbol",
    "Truncation",
    "PublicsStream",
    "Section",
    "SectionTable",
    "SectionMapEntry",
    "sections_from_map",
    "MsfFile",
    "PdbError",
    "MsfError",
    "UnsupportedPdbError",
]
