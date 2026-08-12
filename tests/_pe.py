"""A minimal stdlib PE reader, used only to give the tests an oracle.

The point of this module is independence: it reads the *image*, not the PDB, so
when it agrees with purepdb about a section layout or an export address, that
agreement is evidence rather than a shared assumption. Deliberately no LIEF
dependency -- the test suite must stay installable with nothing but pytest.

Only what the tests need: section table, image base, and the export directory.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

IMAGE_SCN_MEM_EXECUTE = 0x20000000

_PE32 = 0x10B
_PE32PLUS = 0x20B


@dataclass
class PeSection:
    name: str
    virtual_address: int
    virtual_size: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    def contains(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.virtual_address + self.virtual_size


@dataclass
class PeImage:
    image_base: int
    machine: int
    sections: list[PeSection]
    exports: dict[str, int]  # name -> RVA

    def section_of(self, rva: int) -> PeSection | None:
        for s in self.sections:
            if s.contains(rva):
                return s
        return None

    @classmethod
    def parse(cls, data: bytes) -> PeImage:
        if data[:2] != b"MZ":
            raise ValueError("not a PE image (no MZ)")
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("not a PE image (no PE signature)")

        coff = e_lfanew + 4
        machine, num_sections = struct.unpack_from("<HH", data, coff)
        (size_of_optional,) = struct.unpack_from("<H", data, coff + 16)

        opt = coff + 20
        (magic,) = struct.unpack_from("<H", data, opt)
        if magic == _PE32:
            (image_base,) = struct.unpack_from("<I", data, opt + 28)
            dir_off = opt + 96
        elif magic == _PE32PLUS:
            (image_base,) = struct.unpack_from("<Q", data, opt + 24)
            dir_off = opt + 112
        else:
            raise ValueError(f"unknown optional header magic {magic:#x}")
        export_rva, export_size = struct.unpack_from("<II", data, dir_off)

        sec_off = opt + size_of_optional
        sections = []
        for i in range(num_sections):
            (name, vsize, vaddr, _rawsize, _rawptr,
             _relocs, _lines, _nrelocs, _nlines, chars) = struct.unpack_from(
                "<8sIIIIIIHHI", data, sec_off + i * 40)
            sections.append(PeSection(
                name=name.rstrip(b"\x00").decode("ascii", "replace"),
                virtual_address=vaddr,
                virtual_size=vsize,
                characteristics=chars,
            ))

        image = cls(image_base=image_base, machine=machine, sections=sections,
                    exports={})
        if export_rva and export_size:
            image.exports = _parse_exports(data, image, export_rva)
        return image


def _rva_to_file_offset(data: bytes, image: PeImage, rva: int) -> int | None:
    """Map an RVA to a file offset using the raw section pointers."""
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    coff = e_lfanew + 4
    _machine, num_sections = struct.unpack_from("<HH", data, coff)
    (size_of_optional,) = struct.unpack_from("<H", data, coff + 16)
    sec_off = coff + 20 + size_of_optional
    for i in range(num_sections):
        _name, vsize, vaddr, rawsize, rawptr = struct.unpack_from(
            "<8sIIII", data, sec_off + i * 40)
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rawptr + (rva - vaddr)
    return None


def _parse_exports(data: bytes, image: PeImage, export_rva: int) -> dict[str, int]:
    base = _rva_to_file_offset(data, image, export_rva)
    if base is None:
        return {}
    (_flags, _stamp, _major, _minor, _name_rva, _ordinal_base,
     num_functions, num_names, functions_rva, names_rva,
     ordinals_rva) = struct.unpack_from("<IIHHIIIIIII", data, base)

    fn_off = _rva_to_file_offset(data, image, functions_rva)
    nm_off = _rva_to_file_offset(data, image, names_rva)
    or_off = _rva_to_file_offset(data, image, ordinals_rva)
    if None in (fn_off, nm_off, or_off):
        return {}

    out = {}
    for i in range(num_names):
        (name_rva,) = struct.unpack_from("<I", data, nm_off + i * 4)
        (ordinal,) = struct.unpack_from("<H", data, or_off + i * 2)
        if ordinal >= num_functions:
            continue
        (target,) = struct.unpack_from("<I", data, fn_off + ordinal * 4)
        name_off = _rva_to_file_offset(data, image, name_rva)
        if name_off is None:
            continue
        end = data.find(b"\x00", name_off)
        out[data[name_off:end].decode("ascii", "replace")] = target
    return out
