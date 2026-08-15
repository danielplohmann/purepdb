"""purepdb — a minimal pure-Python PDB parser.

Scope: extract function names and entry points (and public/data symbols) from
Microsoft PDB debug-info files, with no native dependencies.

Not in scope: type stream (TPI/IPI) decoding, column info, injected sources.
`/DEBUG:FASTLINK` PDBs carry no procedure records at all -- publics still work,
and `PDB.diagnose()` says so rather than letting the caller read an unexplained
empty list.
"""

from .codeview import (
    CompileInfo,
    Constant,
    DataSymbol,
    LabelSymbol,
    ProcRef,
    ProcSymbol,
    PublicSymbol,
    Truncation,
    UserDefinedType,
)
from .dbi import ModuleInfo, SectionContribution
from .gsi import PublicsStream
from .ipi import IdTable
from .msf import MsfError, MsfFile, PdbError, UnsupportedPdbError
from .names import StringTable
from .omap import OmapTable
from .pdb import (
    PDB,
    Diagnostics,
    Function,
    InlineFunction,
    Label,
    Line,
    PdbInfo,
)
from .sections import (
    Section,
    SectionMapEntry,
    SectionTable,
    sections_from_map,
)

__version__ = "0.3.0"

__all__ = [
    "PDB",
    "CompileInfo",
    "Constant",
    "DataSymbol",
    "Diagnostics",
    "Function",
    "IdTable",
    "InlineFunction",
    "Label",
    "LabelSymbol",
    "Line",
    "ModuleInfo",
    "MsfError",
    "MsfFile",
    "OmapTable",
    "PdbError",
    "PdbInfo",
    "ProcRef",
    "ProcSymbol",
    "PublicSymbol",
    "PublicsStream",
    "Section",
    "SectionContribution",
    "SectionMapEntry",
    "SectionTable",
    "StringTable",
    "Truncation",
    "UnsupportedPdbError",
    "UserDefinedType",
    "sections_from_map",
]
