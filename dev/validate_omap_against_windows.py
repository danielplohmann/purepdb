#!/usr/bin/env python3
"""Check OMAP translation against Windows system binaries.

purepdb resolves a BBT-processed PDB's symbols against the *original* section
table in Optional Debug Header slot 10 and then translates through the address
map, so every rva it reports for such a file is a final, post-BBT address. That
is the one branch where ignoring a stream gives wrong answers rather than
missing ones -- on Win7 x64 ntdll, all 1961 exported functions land at a
different address after translation than before it -- and no fixture in this
repository can exercise it. Microsoft's BBT was never released, Syzygy's
`relink` never writes slot 10, and a vendor symbol-server PDB is not
redistributable, so it cannot be committed either. See `tests/data/README.md`.

What can be done is to check it, locally, against files the developer already
has. This is that check. Nothing it touches is redistributed: the images come
from a Windows installation, the PDBs from Microsoft's symbol server, and both
stay in a cache directory that is not tracked.

**The oracle is the export table.** A PE's exports are addresses in the shipped,
post-BBT image, produced by the linker rather than by anything in the PDB. So
comparing them against purepdb's translated addresses is independent evidence,
and the counterfactual is the point of it: the same comparison without applying
the map matches essentially nothing.

    python dev/validate_omap_against_windows.py ~/win-dlls --fetch

Recorded results, six pairs from a Windows XP and a Windows 7 installation.
Every one of them carries slot 10, so BBT was still in use for Win7 -- worth
knowing, because the era was an open question before this was run.

    pair                   omap   common  exact  thunk  near   far
    winxp    ntdll        37061    1294    1292     0     1      1
    winxp    kernel32     42229     915     910     0     2      3
    win7-x86 ntdll        67696    2000    1994     4     1      1
    win7-x86 kernel32     60037    1273     851     7   233    182
    win7-x64 ntdll        84434    1961    1961     0     0      0
    win7-x64 kernel32     70894    1287     870   139   166    112

    untranslated matches: 0 of 8730

ntdll agrees on 99.8% to 100% of its exports on all three targets, which is the
result that matters: it is the module BBT rearranges most and the one whose PDB
carries the largest map. kernel32's residue is not disagreement about addresses
but about which address belongs to a name -- Win7 exports it through stubs, and
the offsets cluster hard (146 at exactly +8 on x64, 175 at exactly +13 on x86),
which is a calling convention rather than a translation error. A wrong
translation does not produce the same delta 175 times.
"""

from __future__ import annotations

import argparse
import collections
import re
import struct
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from purepdb import PDB, PdbError
from tests._pe import PeImage, _rva_to_file_offset

SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"
USER_AGENT = "Microsoft-Symbol-Server/10.0.0.0"

# How close a mismatch has to be before it is reported as a stub offset rather
# than as a disagreement. Judged by the clustering, not by this number.
NEAR = 16


def codeview_identity(data: bytes) -> tuple[str, str, int] | None:
    """(pdb name, GUID, age) from the image's CodeView debug record."""
    (pe,) = struct.unpack_from("<I", data, 0x3C)
    magic = struct.unpack_from("<H", data, pe + 24)[0]
    n_sections = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    directory = pe + 24 + (96 if magic == 0x10B else 112)
    rva, size = struct.unpack_from("<II", data, directory + 6 * 8)
    if not rva:
        return None

    table = pe + 24 + opt_size

    def to_offset(target: int) -> int | None:
        for i in range(n_sections):
            f = struct.unpack_from("<8sIIII", data, table + i * 40)
            if f[2] <= target < f[2] + max(f[1], f[3]):
                return f[4] + (target - f[2])
        return None

    base = to_offset(rva)
    if base is None:
        return None
    for i in range(size // 28):
        entry = struct.unpack_from("<IIHHIIII", data, base + i * 28)
        if entry[4] != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        cv = entry[7]
        if data[cv:cv + 4] != b"RSDS":
            continue
        d1, d2, d3 = struct.unpack_from("<IHH", data, cv + 4)
        guid = f"{d1:08X}{d2:04X}{d3:04X}{data[cv + 12:cv + 20].hex().upper()}"
        age = struct.unpack_from("<I", data, cv + 20)[0]
        end = data.index(b"\0", cv + 24)
        return data[cv + 24:end].decode("utf-8", "replace"), guid, age
    return None


def undecorate(name: str) -> str:
    """`_NtCreateFile@44` -> `NtCreateFile`, which is how the export spells it.

    x86 publics are stdcall-decorated and exports are not, so without this the
    two sets barely intersect and the check would silently compare almost
    nothing. x64 needs none of it, which is why its numbers are the cleanest.
    """
    for pattern in (r"_([A-Za-z_][\w@?$]*?)@\d+", r"@([A-Za-z_][\w@?$]*?)@\d+"):
        m = re.fullmatch(pattern, name)
        if m:
            return m.group(1)
    if name.startswith("_") and "@" not in name:
        return name[1:]
    return name


def fetch_pdb(name: str, guid: str, age: int, cache: Path) -> Path | None:
    out = cache / f"{guid}{age:X}" / name
    if out.exists():
        return out
    url = f"{SYMBOL_SERVER}/{name}/{guid}{age:X}/{name}"
    out.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            out.write_bytes(response.read())
    except (urllib.error.URLError, OSError) as exc:
        print(f"  fetch failed: {url} ({exc})", file=sys.stderr)
        return None
    return out


def check(image_path: Path, pdb_path: Path) -> dict | None:
    data = image_path.read_bytes()
    image = PeImage.parse(data)
    if not image.exports:
        return None
    try:
        pdb = PDB.open(str(pdb_path))
        diagnostics = pdb.diagnose()
    except PdbError as exc:
        print(f"  {pdb_path.name}: {exc}", file=sys.stderr)
        return None

    original = pdb.original_sections
    translated: dict[str, int | None] = {}
    untranslated: dict[str, int | None] = {}
    for fn in pdb.functions():
        raw = (original[fn.segment - 1].virtual_address + fn.offset
               if 1 <= fn.segment <= len(original) else None)
        for name in fn.names:
            for key in (name, undecorate(name)):
                translated.setdefault(key, fn.rva)
                untranslated.setdefault(key, raw)

    def follow_thunk(rva: int) -> int | None:
        offset = _rva_to_file_offset(data, image, rva)
        if offset is None or data[offset] != 0xE9:
            return None
        (delta,) = struct.unpack_from("<i", data, offset + 1)
        return rva + 5 + delta

    common = [(n, r) for n, r in image.exports.items() if n in translated]
    result = {"omap": diagnostics.omap_entries,
              "slot10": diagnostics.has_original_sections,
              "common": len(common), "exact": 0, "thunk": 0, "near": 0,
              "far": 0, "untranslated": 0,
              "deltas": collections.Counter()}
    for name, export_rva in common:
        got = translated[name]
        if got == export_rva:
            result["exact"] += 1
        elif follow_thunk(export_rva) == got:
            result["thunk"] += 1
        elif got is not None and abs(got - export_rva) <= NEAR:
            result["near"] += 1
            result["deltas"][got - export_rva] += 1
        else:
            result["far"] += 1
        if untranslated.get(name) == export_rva:
            result["untranslated"] += 1
    return result


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("images", type=Path,
                    help="directory of Windows DLLs, searched recursively")
    ap.add_argument("--pdbs", type=Path,
                    help="directory of PDBs to pair by file name; without it, "
                         "PDBs come from the cache or --fetch")
    ap.add_argument("--cache", type=Path, default=Path("dev/symbols"),
                    help="where fetched PDBs are kept (default dev/symbols, "
                         "which is not tracked)")
    ap.add_argument("--fetch", action="store_true",
                    help="download missing PDBs from Microsoft's symbol server")
    ap.add_argument("--min-exact", type=float, default=0.0,
                    help="fail if any ntdll pair agrees on less than this "
                         "fraction of its exports")
    args = ap.parse_args(argv[1:])

    images = sorted(p for p in args.images.rglob("*.dll"))
    if not images:
        print(f"error: no .dll files under {args.images}", file=sys.stderr)
        return 1

    rows, failures = [], []
    for image in images:
        identity = codeview_identity(image.read_bytes())
        label = f"{image.parent.name}/{image.name}"
        if identity is None:
            print(f"{label}: no CodeView record, skipped", file=sys.stderr)
            continue
        name, guid, age = identity

        pdb_path = None
        if args.pdbs:
            candidate = args.pdbs / name
            pdb_path = candidate if candidate.exists() else None
        if pdb_path is None:
            cached = args.cache / f"{guid}{age:X}" / name
            if cached.exists():
                pdb_path = cached
            elif args.fetch:
                print(f"{label}: fetching {name} {guid}{age:X}")
                pdb_path = fetch_pdb(name, guid, age, args.cache)
        if pdb_path is None:
            print(f"{label}: no PDB for {guid}{age:X} "
                  f"(pass --fetch or --pdbs)", file=sys.stderr)
            continue

        result = check(image, pdb_path)
        if result is None:
            continue
        rows.append((label, result))
        if not result["slot10"]:
            print(f"{label}: no slot 10, so nothing here exercises translation",
                  file=sys.stderr)
        if result["common"] and "ntdll" in image.name.lower():
            rate = result["exact"] / result["common"]
            if rate < args.min_exact:
                failures.append(f"{label}: {rate:.1%} exact, "
                                f"below {args.min_exact:.1%}")
        if result["untranslated"]:
            failures.append(f"{label}: {result['untranslated']} export(s) match "
                            f"the *untranslated* address, so the map is not "
                            f"doing what this checks")

    if not rows:
        print("error: nothing was compared", file=sys.stderr)
        return 1

    print(f"\n{'pair':28s} {'omap':>7s} {'common':>7s} {'exact':>6s} "
          f"{'thunk':>6s} {'near':>5s} {'far':>5s}")
    total_common = total_untranslated = 0
    for label, r in rows:
        print(f"{label:28s} {r['omap']:7d} {r['common']:7d} {r['exact']:6d} "
              f"{r['thunk']:6d} {r['near']:5d} {r['far']:5d}")
        if r["deltas"]:
            top = ", ".join(f"{d:+d}x{n}" for d, n in r["deltas"].most_common(3))
            print(f"{'':28s} near-miss offsets: {top}")
        total_common += r["common"]
        total_untranslated += r["untranslated"]

    print(f"\nuntranslated matches: {total_untranslated} of {total_common}")
    print("  (this is the counterfactual: resolving against slot 10 without "
          "applying\n   the map should match essentially nothing)")

    for line in failures:
        print(f"FAIL: {line}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
