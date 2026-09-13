#!/usr/bin/env python3
"""Build the audit corpus of real PDB files, and the manifest that describes it.

The corpus lives *outside* the repository (default ``/home/user/corpus``, or
``$PUREPDB_CORPUS``) because most of it is not ours to redistribute: Microsoft's
symbol server is licensed for debugging only, and the python.org and nodejs.org
PDBs are large. Nothing this script produces is meant to be committed. What is
committed is this script, so the corpus can be rebuilt, and
``docs/audit/corpus.md``, the manifest without local paths.

Stages, each selectable with a flag and run in this order by default:

    --fetch     download and unpack python.org, nodejs.org, Microsoft symbol
                server, Mozilla symbol server and Internet Archive material
    --build     compile freestanding C, C++ and Rust with clang / clang-cl,
                lld-link and rustc, in a fixed matrix of debug-info variants
    --corrupt   derive truncated, zeroed and mis-sized MSF files from the small
                committed fixtures in tests/data/
    --omap      pair the msdl PE images with their PDBs and run
                dev/validate_omap_against_windows.py; record debug-header slots
    --smoke     run ``llvm-pdbutil dump --summary``, ``purepdb diagnose`` and a
                timed ``purepdb functions`` over every file, caching results
    --manifest  write MANIFEST.md (and, with --docs, docs/audit/corpus.md)

Stdlib only, plus subprocess to: curl, 7z, msiextract, clang-18, clang-cl-18,
lld-link, rustc, llvm-pdbutil. Every step is idempotent; a file already present
with the right size is not fetched or built again.

Toolchain notes that matter for reading the manifest:

* No Windows SDK or CRT is present, so everything self-built is linked
  ``/nodefaultlib`` with an explicit entry point and is not runnable. The
  approach is the one in tests/data/tls/build.sh and tests/data/rustpe32/build.sh.
* The Rust builds resolve every symbol the rlibs need but nothing defines --
  CRT functions and Win32 imports alike -- with a generated assembly file of
  ``ret`` stubs, and empty import libraries made by llvm-dlltool stand in for
  the kernel32.lib etc. that std's link line names. The image imports nothing.
* lld-link's ``/incremental`` only affects import-library rewriting; it does
  not produce incrementally-linked PDBs (no S_TRAMPOLINE). The variant is kept
  so the manifest says so.
* lld-link 18 ignores ``/pdbstripped`` ("not yet supported"), so there is no
  self-built stripped PDB; the stripped files in the corpus are Microsoft's.
* ``/DEBUG:FASTLINK``, VS2003 ``_ST``-era, and managed PDBs cannot be
  produced here (no MSVC, no old Visual Studio). If you have any, set
  ``PUREPDB_EXTRA_PDBS`` to a directory of ``.pdb`` files; ``--fetch``
  copies them into ``corpus/extra/`` so the smoke pass and validator see
  them. S_FASTLINK (0x1167) is named in the parser but its layout is
  untested until such a file appears.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import time
import zipfile
from pathlib import Path

CORPUS = Path(os.environ.get("PUREPDB_CORPUS", "/home/user/corpus"))
REPO = Path(__file__).resolve().parent.parent
PUREPDB = REPO / ".venv" / "bin" / "purepdb"
PDBUTIL = shutil.which("llvm-pdbutil-18") or shutil.which("llvm-pdbutil") or "llvm-pdbutil"
CLANG = shutil.which("clang-18") or "clang"
CLANG_CL = shutil.which("clang-cl-18") or "clang-cl"
LLD_LINK = "lld-link"
RUSTC = "rustc"
SMOKE_TIMEOUT = 600
USER_AGENT = "Microsoft-Symbol-Server/10.0.0.0"

MSDL = "https://msdl.microsoft.com/download/symbols"
MOZ = "https://symbols.mozilla.org"
PSF = "Python Software Foundation License (PSF-2.0)"
MIT_NODE = "MIT (Node.js) plus the licences of V8, ICU, OpenSSL, ... (nodejs LICENSE)"
MS_SYMBOLS = ("Microsoft symbol-server terms: for debugging only, NOT redistributable")
MPL = "MPL-2.0 (Mozilla)"
OURS = "our own build, BSD-3-Clause like the repository"

# ---------------------------------------------------------------------------
# Provenance bookkeeping
# ---------------------------------------------------------------------------

PROVENANCE = CORPUS / "provenance.json"
SMOKE = CORPUS / "smoke.json"


def load_json(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {}


def save_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")


def record(prov: dict, rel: str, **fields: object) -> None:
    """Attach provenance to a corpus file (path relative to CORPUS)."""
    path = CORPUS / rel
    entry = prov.get(rel, {})
    entry.update(fields)
    if path.exists():
        entry["size"] = path.stat().st_size
        entry["sha256"] = sha256(path)
    prov[rel] = entry
    save_json(PROVENANCE, prov)


def rustc_id() -> str:
    """The rustc on PATH, for provenance. Never a version we did not run."""
    try:
        out = subprocess.check_output(
            [RUSTC, "--version"], text=True, timeout=10,
            stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return "rustc"
    # "rustc 1.83.0 (hash date)" -- first two tokens are the id.
    parts = out.split()
    if len(parts) >= 2 and parts[0] == "rustc":
        return f"rustc {parts[1]}"
    return "rustc"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str], cwd: Path | None = None,
        timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    print("  $", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, text=True, capture_output=True,
                          cwd=cwd, timeout=timeout)


def curl(url: str, dest: Path, user_agent: str | None = None) -> bool:
    """Fetch url to dest; False on a non-2xx status (dest removed)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 0:
        print(f"  have {dest.name}")
        return True
    cmd = ["curl", "-sSL", "--retry", "3", "-o", str(dest), "-w", "%{http_code}", url]
    if user_agent:
        cmd += ["-A", user_agent]
    print("  $", " ".join(cmd), flush=True)
    code = subprocess.run(cmd, text=True, capture_output=True).stdout.strip()
    if not code.startswith("2") or not dest.exists() or dest.stat().st_size == 0:
        print(f"  !! {url} -> HTTP {code}")
        dest.unlink(missing_ok=True)
        return False
    return True


# ---------------------------------------------------------------------------
# --fetch
# ---------------------------------------------------------------------------

# python.org ships one MSI per component; msiextract unpacks it. The build
# toolchain per release is from PCbuild/readme.txt of that release.
PYTHON_MSI = [
    # version, arch, toolchain, PGO?
    ("3.5.0", "amd64", "MSVC 14.0 (VS2015)", True),
    ("3.5.0", "win32", "MSVC 14.0 (VS2015)", True),
    ("3.8.10", "amd64", "MSVC 14.2x (VS2019)", True),
    ("3.8.10", "win32", "MSVC 14.2x (VS2019)", True),
    ("3.12.0", "amd64", "MSVC 14.3x (VS2022)", True),
    ("3.13.15", "amd64", "MSVC 14.3x (VS2022)", True),
    ("3.14.7", "amd64", "MSVC 14.4x (VS2022)", True),
    ("3.14.7", "arm64", "MSVC 14.4x (VS2022), ARM64", True),
]
PYTHON_MSI_PARTS = ("core_pdb", "exe_pdb", "lib_pdb")

PYTHON_ZIP = [
    ("2.7.18", "https://www.python.org/ftp/python/2.7.18/python-2.7.18.amd64-pdb.zip",
     "MSVC 9.0 (VS2008), x64", ["python27.pdb", "python.pdb", "_ctypes.pdb", "_sqlite3.pdb"]),
    ("3.4.4", "https://www.python.org/ftp/python/3.4.4/python-3.4.4.amd64-pdb.zip",
     "MSVC 10.0 (VS2010), x64", ["python34.pdb", "python.pdb", "_ctypes.pdb", "_sqlite3.pdb"]),
]

NODE = [
    # version, arch, keep
    ("v22.0.0", "win-x64", "MSVC 14.3x (VS2022), x64, /LTCG /OPT:ICF; huge"),
    ("v22.0.0", "win-arm64", "MSVC 14.3x (VS2022), ARM64; huge"),
]

# Microsoft symbol server. GUID+age pairs come from public crash reports
# (crash-stats.mozilla.org ProcessedCrash json_dump.modules) and from public
# bug reports that print the download URL; the manifest says which.
MSDL_FILES = [
    # pdb name, guid+age, what it is, where the id came from
    ("ntdll.pdb", "7085D40969F52F81F19C0989038AEF8A1",
     "ntdll.dll 10.0.22621.2215 x64 (Windows 11 22H2)",
     "crash-stats.mozilla.org crash 208097cb-3c9a-4539-b230-535ea0260906"),
    ("kernel32.pdb", "A2C37028AD6F5938272B266A25B8CD3C1",
     "kernel32.dll 10.0.22621.2215 x64 (Windows 11 22H2)",
     "crash-stats.mozilla.org crash 208097cb-3c9a-4539-b230-535ea0260906"),
    ("ucrtbase.pdb", "A3F6745C6328B7866DD6274B30A35BA11",
     "ucrtbase.dll 10.0.22621.608 x64 (Windows 11 22H2)",
     "crash-stats.mozilla.org crash 208097cb-3c9a-4539-b230-535ea0260906"),
    ("ntdll.pdb", "F2209D21763245EF9C87572ED12D7BA52",
     "ntdll.dll 6.1.7601.24335 x86 (Windows 7 SP1)",
     "crash-stats.mozilla.org crash f4026d82-bf42-4a06-a4f5-7acb60260905"),
    ("kernel32.pdb", "4F32B3F53E994AF58D86E9D25D0A2DA92",
     "kernel32.dll 6.1.7601.24335 x86 (Windows 7 SP1)",
     "crash-stats.mozilla.org crash f4026d82-bf42-4a06-a4f5-7acb60260905"),
    ("user32.pdb", "4D326E236E094B18A318D2D66E1AB33D2",
     "user32.dll 6.1.7601.23594 x86 (Windows 7 SP1)",
     "crash-stats.mozilla.org crash f4026d82-bf42-4a06-a4f5-7acb60260905"),
    ("ntkrnlmp.pdb", "1B4A6F5E0766C552C90710C8ACC0295C1",
     "ntoskrnl.exe (Windows 10/11 x64 kernel; version per PDB info)",
     "github.com/mstange/pdb-addr2line/issues/46"),
    ("ntkrnlmp.pdb", "15B12C74F0E177581B6B27DD4C5022C21",
     "ntoskrnl.exe (Windows 10 x64 kernel; version per PDB info)",
     "blogs.jpcert.or.jp/en/2021/09/volatility3_offline.html"),
    ("ntdll.pdb", "1B97D8849C140AFE54A40E6ED4FB118B1",
     "ntdll.dll (Windows 10 x64; version per PDB info)",
     "learn.microsoft.com Q&A 2721858"),
]

# PE images matching the msdl PDBs above, served by the same server under
# <name>/<TimeDateStamp:08X><SizeOfImage:X>/<name>. The code ids come from the
# same crash-stats module lists as the PDB ids; codeview_identity() in
# dev/validate_omap_against_windows.py confirms each image names its PDB.
# No image could be found for the XP PDBs: winbindex indexes 10.0 only, and
# the last POSReady 2009 packages (KB4493563 ships ntdll/kernel32
# 5.1.2600.7682) are intra-package deltas that need the base files.
MSDL_IMAGES = [
    ("ntdll.dll", "7A9F67F2214000", "ntdll.pdb", "7085D40969F52F81F19C0989038AEF8A1"),
    ("kernel32.dll", "FE3DC5C1C4000", "kernel32.pdb", "A2C37028AD6F5938272B266A25B8CD3C1"),
    ("ucrtbase.dll", "F5FC15A3111000", "ucrtbase.pdb", "A3F6745C6328B7866DD6274B30A35BA11"),
    ("ntdll.dll", "5C267E95142000", "ntdll.pdb", "F2209D21763245EF9C87572ED12D7BA52"),
    ("kernel32.dll", "5C267EC7D5000", "kernel32.pdb", "4F32B3F53E994AF58D86E9D25D0A2DA92"),
    ("user32.dll", "58249E2BC9000", "user32.pdb", "4D326E236E094B18A318D2D66E1AB33D2"),
]

# Internet Archive item xp_pdb: a symbol-store tree for a fully patched x86
# Windows XP SP3 (POSReady 2009) install. The PDBs are Microsoft's; the archive
# only mirrors them. Kept entries are <name>/<guid+age>/<name> in the 7z.
XP_ARCHIVE = "https://archive.org/download/xp_pdb/symbols.7z"
XP_KEEP = [
    "ntdll.pdb/08DE4D91BE654ACEB9F397576108EF3E2/ntdll.pdb",
    "kernel32.pdb/6E23380B2D034BD7B04DF09B354004052/kernel32.pdb",
    "ntkrnlpa.pdb/F83A340EE44D479BA1FE3BA96ADB67A11/ntkrnlpa.pdb",
    "ntkrpamp.pdb/270E083F57714738A1895FE542CFB8DE1/ntkrpamp.pdb",
    "hal.pdb/36D1EEBD32624718A02E68DABD3593DD1/hal.pdb",
]

# Mozilla: xul.pdb for Firefox 153.0.4 x64 (debug id from the same crash
# report as the Windows 11 modules above). Served cab-compressed as xul.pd_.
MOZILLA = [
    ("xul.pdb", "31CD312D1D4C0FCA4C4C44205044422E1", "xul.dll 153.0.4.591 x64, clang-cl + lld-link"
     " (Firefox 153.0.4 release); >1 GB"),
]


def fetch_python(prov: dict) -> None:
    dl = CORPUS / "_dl"
    for ver, arch, toolchain, pgo in PYTHON_MSI:
        out = CORPUS / "python" / f"{ver}-{arch}"
        for part in PYTHON_MSI_PARTS:
            url = f"https://www.python.org/ftp/python/{ver}/{arch}/{part}.msi"
            msi = dl / f"python-{ver}-{arch}-{part}.msi"
            marker = out / f".{part}.done"
            if marker.exists():
                continue
            if not curl(url, msi):
                continue
            stage = dl / f"stage-{ver}-{arch}-{part}"
            shutil.rmtree(stage, ignore_errors=True)
            stage.mkdir(parents=True)
            run(["msiextract", "-C", str(stage), str(msi)])
            out.mkdir(parents=True, exist_ok=True)
            for pdb in sorted(stage.rglob("*.pdb")):
                dest = out / pdb.name
                shutil.move(str(pdb), dest)
                record(prov, str(dest.relative_to(CORPUS)), url=url, toolchain=toolchain,
                       licence=PSF, redistributable=True, group="python",
                       note=f"{part}.msi; {'PGO build' if pgo else ''}".strip("; "))
            shutil.rmtree(stage, ignore_errors=True)
            marker.touch()
    for ver, url, toolchain, keep in PYTHON_ZIP:
        out = CORPUS / "python" / f"{ver}-amd64"
        zpath = dl / url.rsplit("/", 1)[1]
        if (out / ".zip.done").exists() or not curl(url, zpath):
            continue
        out.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zpath) as z:
            for name in z.namelist():
                base = name.rsplit("/", 1)[-1]
                if base in keep:
                    (out / base).write_bytes(z.read(name))
                    record(prov, str((out / base).relative_to(CORPUS)), url=url,
                           toolchain=toolchain, licence=PSF, redistributable=True,
                           group="python", note="pdb zip; PGO build")
        (out / ".zip.done").touch()


def fetch_node(prov: dict) -> None:
    dl = CORPUS / "_dl"
    for ver, arch, toolchain in NODE:
        url = f"https://nodejs.org/dist/{ver}/{arch}/node_pdb.7z"
        out = CORPUS / "node" / f"{ver}-{arch}"
        dest = out / "node.pdb"
        if dest.exists():
            continue
        archive = dl / f"node-{ver}-{arch}_pdb.7z"
        if not curl(url, archive):
            continue
        out.mkdir(parents=True, exist_ok=True)
        run(["7z", "x", "-y", f"-o{out}", str(archive), "node.pdb"])
        record(prov, str(dest.relative_to(CORPUS)), url=url, toolchain=toolchain,
               licence=MIT_NODE, redistributable=True, group="node",
               note="node_pdb.7z from nodejs.org/dist")


def fetch_msdl(prov: dict) -> None:
    for name, ident, what, origin in MSDL_FILES:
        url = f"{MSDL}/{name}/{ident}/{name}"
        dest = CORPUS / "msdl" / f"{name}-{ident}" / name
        if not curl(url, dest, USER_AGENT):
            # Older files are stored cab-compressed under the .pd_ name.
            alt = url[:-1] + "_"
            cab = dest.with_suffix(".pd_")
            if not curl(alt, cab, USER_AGENT):
                continue
            run(["7z", "x", "-y", f"-o{dest.parent}", str(cab)])
            cab.unlink()
        record(prov, str(dest.relative_to(CORPUS)), url=url, toolchain="MSVC (Microsoft"
               " internal), BBT/OMAP-era where old, stripped public symbols", licence=MS_SYMBOLS,
               redistributable=False, group="msdl", note=f"{what}; id from {origin}")


def fetch_msdl_images(prov: dict) -> None:
    for name, code_id, pdb_name, pdb_id in MSDL_IMAGES:
        url = f"{MSDL}/{name}/{code_id}/{name}"
        dest = CORPUS / "msdl_images" / f"{name}-{code_id}" / name
        if not curl(url, dest, USER_AGENT):
            continue
        record(prov, str(dest.relative_to(CORPUS)), url=url, toolchain="Microsoft, shipped"
               " image", licence=MS_SYMBOLS, redistributable=False, group="msdl_images",
               note=f"PE image whose CodeView record names msdl/{pdb_name}-{pdb_id}")


def fetch_xp(prov: dict) -> None:
    dl = CORPUS / "_dl"
    archive = dl / "xp_symbols.7z"
    out = CORPUS / "xp"
    if all((out / f"{k.split('/')[0]}-{k.split('/')[1]}" / k.split("/")[0]).exists()
           for k in XP_KEEP):
        return
    if not curl(XP_ARCHIVE, archive):
        return
    stage = dl / "stage-xp"
    shutil.rmtree(stage, ignore_errors=True)
    run(["7z", "x", "-y", f"-o{stage}", str(archive), *XP_KEEP])
    for k in XP_KEEP:
        name, ident, _ = k.split("/")
        dest = out / f"{name}-{ident}" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(stage / k), dest)
        record(prov, str(dest.relative_to(CORPUS)), url=XP_ARCHIVE, toolchain="MSVC 7.x/8.x"
               " (Microsoft internal), Windows XP SP3 x86, BBT/OMAP-processed, stripped",
               licence=MS_SYMBOLS, redistributable=False, group="xp",
               note=f"symbol-store path {k}; also on msdl as {MSDL}/{k}")
    shutil.rmtree(stage, ignore_errors=True)


def fetch_mozilla(prov: dict) -> None:
    dl = CORPUS / "_dl"
    for name, ident, what in MOZILLA:
        dest = CORPUS / "mozilla" / f"{name}-{ident}" / name
        if dest.exists():
            continue
        url = f"{MOZ}/{name}/{ident}/{name[:-1]}_"
        cab = dl / f"{name}-{ident}.pd_"
        if not curl(url, cab):
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        run(["7z", "x", "-y", f"-o{dest.parent}", str(cab)])
        if not dest.exists():  # the cab may carry the file under another case
            for f in dest.parent.iterdir():
                if f.suffix.lower() == ".pdb":
                    f.rename(dest)
        record(prov, str(dest.relative_to(CORPUS)), url=url, toolchain="clang-cl + lld-link"
               " (Mozilla's LLVM), x64, PGO+LTO", licence=MPL, redistributable=True,
               group="mozilla", note=what)


def fetch_extra_pdbs(prov: dict) -> None:
    """Copy caller-supplied PDBs the rest of this script cannot produce.

    /DEBUG:FASTLINK, VS2003 _ST, and managed PDBs need a Windows MSVC
    toolchain this box does not have. A directory named by
    PUREPDB_EXTRA_PDBS is copied into corpus/extra/ as-is; the smoke
    pass then exercises whatever landed there.
    """
    src = os.environ.get("PUREPDB_EXTRA_PDBS")
    if not src:
        print("  skip: PUREPDB_EXTRA_PDBS unset "
              "(FASTLINK / _ST / managed not produced here)")
        return
    root = Path(src)
    if not root.is_dir():
        print(f"  skip: {root} is not a directory")
        return
    dest_dir = CORPUS / "extra"
    dest_dir.mkdir(parents=True, exist_ok=True)
    found = 0
    for path in sorted(root.rglob("*.pdb")):
        rel = f"extra/{path.name}"
        dest = CORPUS / rel
        if not dest.exists() or dest.stat().st_size != path.stat().st_size:
            shutil.copy2(path, dest)
        record(prov, rel, url=f"PUREPDB_EXTRA_PDBS:{path}",
               toolchain="caller-supplied (FASTLINK/_ST/managed if that is what it is)",
               licence="as supplied; not produced here")
        found += 1
    print(f"  copied {found} extra PDB(s) from {root}")


def stage_fetch(prov: dict) -> None:
    (CORPUS / "_dl").mkdir(parents=True, exist_ok=True)
    for step in (fetch_python, fetch_node, fetch_msdl, fetch_msdl_images, fetch_xp,
                 fetch_mozilla, fetch_extra_pdbs):
        print(f"== {step.__name__}")
        try:
            step(prov)
        except subprocess.CalledProcessError as e:
            print(f"  !! {step.__name__} failed: {e}\n{e.stderr}")


# ---------------------------------------------------------------------------
# --build: freestanding C / C++ / Rust
# ---------------------------------------------------------------------------

TARGETS = {
    "x64": "x86_64-pc-windows-msvc",
    "x86": "i686-pc-windows-msvc",
    "arm64": "aarch64-pc-windows-msvc",
}


def gen_c_source(n_unique: int = 300, n_identical: int = 40) -> str:
    """C with a few hundred functions and a block of byte-identical bodies.

    The identical bodies exist so /OPT:ICF has something to fold. They are only
    foldable when each lands in its own COMDAT section, which is what /Gy
    (-ffunction-sections) gives clang-cl.
    """
    out = [
        "/* generated by tools/fetch_corpus.py -- freestanding, no CRT */",
        "typedef unsigned int u32; typedef unsigned long long u64;",
        "volatile u32 sink; u32 table[64]; static u32 counter;",
        "u32 __declspec(noinline) leaf(u32 x) { return x * 2654435761u ^ (x >> 13); }",
    ]
    for i in range(n_unique):
        out.append(
            f"u32 __declspec(noinline) fn_{i:03d}(u32 a, u32 b) {{\n"
            f"    u32 acc = {i * 7919 + 1}u;\n"
            f"    for (u32 k = 0; k < (b & {(i % 13) + 1}); k++) acc = leaf(acc + a + k);\n"
            f"    table[{i % 64}] += acc; counter += {i % 5 + 1};\n"
            f"    return acc ^ b;\n}}"
        )
    for i in range(n_identical):
        out.append(
            f"u32 __declspec(noinline) same_{i:03d}(u32 a) {{\n"
            "    u32 r = leaf(a) + 17u; sink = r; return r;\n}"
        )
    # A big frame so clang emits a __chkstk probe (stubbed in stubs.c).
    out.append(
        "u32 __declspec(noinline) bigframe(u32 s) {\n"
        "    u32 buf[3000]; for (u32 i = 0; i < 3000; i++) buf[i] = s + i;\n"
        "    u32 acc = 0; for (u32 i = 0; i < 3000; i += 7) acc ^= buf[i]; return acc;\n}"
    )
    calls = " ^ ".join(f"fn_{i:03d}(s, {i})" for i in range(n_unique))
    calls2 = " ^ ".join(f"same_{i:03d}(s)" for i in range(n_identical))
    out.append(f"u32 all_unique(u32 s) {{ return {calls}; }}")
    out.append(f"u32 all_same(u32 s) {{ return {calls2}; }}")
    out.append("int start(void) { u32 s = 0x9E3779B9u; return (int)(all_unique(s) ^"
               " all_same(s) ^ bigframe(s)); }")
    return "\n".join(out) + "\n"


CPP_SOURCE = r"""
/* generated by tools/fetch_corpus.py -- C++ with inlining, virtual thunks and
   templates; freestanding, no CRT, no exceptions, no RTTI. */
typedef unsigned int u32;
volatile u32 sink;

static inline u32 rotl(u32 x, u32 r) { return (x << r) | (x >> (32 - r)); }
static inline u32 mix(u32 a, u32 b) { return rotl(a * 0x9E3779B1u, 5) ^ b; }
inline u32 hash_bytes(const unsigned char *p, u32 n) {
    u32 h = 0x811C9DC5u;
    for (u32 i = 0; i < n; i++) h = mix(h, p[i]);
    return h;
}

struct Left  { virtual u32 left(u32 x)  { return mix(x, 1); } u32 lpad; };
struct Right { virtual u32 right(u32 x) { return mix(x, 2); } u32 rpad; };
/* Overriding a base that is not at offset 0 makes the compiler emit an
   adjustor thunk (`[thunk]:...`adjustor{16}'`) -- a named jump stub in code. */
struct Both : Left, Right {
    u32 right(u32 x) override { return mix(x, 3) + lpad; }
    u32 left(u32 x) override { return mix(x, 4) + rpad; }
};

template <typename T, int N> struct Ring {
    T buf[N]; u32 head = 0;
    __declspec(noinline) void push(T v) { buf[head++ % N] = v; }
    T sum() const { T s = 0; for (int i = 0; i < N; i++) s += buf[i]; return s; }
};

namespace corpus { namespace detail {
    template <int K> __declspec(noinline) u32 rounds(u32 s) {
        for (int i = 0; i < K; i++) s = mix(s, (u32)i);
        return s;
    }
} }

__declspec(noinline) u32 use_both(Both *b, u32 x) {
    Right *r = b; Left *l = b;
    return r->right(x) ^ l->left(x);
}

__declspec(noinline) u32 drive(u32 seed) {
    unsigned char bytes[64];
    for (u32 i = 0; i < 64; i++) bytes[i] = (unsigned char)(seed + i);
    Ring<u32, 8> ring;
    for (u32 i = 0; i < 20; i++) ring.push(hash_bytes(bytes, i + 1));   // inlined
    Both b; b.lpad = seed; b.rpad = ~seed;
    return ring.sum() ^ use_both(&b, seed) ^ corpus::detail::rounds<7>(seed)
         ^ corpus::detail::rounds<11>(seed) ^ hash_bytes(bytes, 64);
}

extern "C" int start() { u32 r = drive(0x1234567u); sink = r; return (int)r; }
"""

STUBS_C = """
/* CRT shims the freestanding builds need: clang emits a stack probe for large
   frames, and memset/memcpy for aggregate initialisation. On x86 the C name
   _chkstk decorates to the __chkstk the code generator calls. */
#if defined(_M_IX86)
void _chkstk(void) {}
#else
void __chkstk(void) {}
#endif
void *memset(void *d, int c, __SIZE_TYPE__ n) {
    unsigned char *p = d; while (n--) *p++ = (unsigned char)c; return d; }
void *memcpy(void *d, const void *s, __SIZE_TYPE__ n) {
    unsigned char *p = d; const unsigned char *q = s; while (n--) *p++ = *q++; return d; }
"""

RUST_STUBS_C = """
/* Platform stubs for the no_std Rust crate (tests/data/rustpe32/main.rs). */
unsigned int platform_seed(void) { return 0x9E3779B9u; }
void platform_report(unsigned int v) { (void)v; }
unsigned int platform_ticks(void) { return 0; }
#if defined(_M_IX86)
void _chkstk(void) {}
#else
void __chkstk(void) {}
#endif
"""

RUST_STD_MAIN = r"""
//! A small std-using crate: collections, formatting, sorting, closures and a
//! generic -- enough monomorphised std to make the PDB representative.
use std::collections::HashMap;

fn histogram(words: &[&str]) -> HashMap<String, usize> {
    let mut h = HashMap::new();
    for w in words { *h.entry(w.to_string()).or_insert(0) += 1; }
    h
}

fn checksum<T: AsRef<[u8]>>(data: T) -> u32 {
    data.as_ref().iter().fold(0x811C9DC5u32, |acc, &b| (acc ^ b as u32).wrapping_mul(16777619))
}

fn main() {
    let text = "the quick brown fox jumps over the lazy dog the end";
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut counts: Vec<(String, usize)> = histogram(&words).into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    for (w, n) in &counts { println!("{w}: {n}"); }
    let total: u32 = words.iter().map(|w| checksum(w)).sum();
    println!("checksum {total:#x}");
    std::process::exit((total & 0x7f) as i32);
}
"""


def compile_c(stage: Path, src: Path, target: str, flags: list[str], driver: str = "clang",
              cmds: list[str] | None = None) -> Path:
    obj = stage / (src.stem + ".obj")
    if driver == "clang-cl":
        cmd = [CLANG_CL, f"--target={target}", "/c", "/nologo", "/GS-", "/Zl", *flags,
               f"/Fo{obj}", str(src)]
    else:
        cmd = [CLANG, f"--target={target}", "-c", *(["-fno-stack-protector"] if src.suffix != ".s"
                                                     else []), *flags, "-o", str(obj), str(src)]
    print("  $", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True, cwd=stage)
    if cmds is not None:
        cmds.append(" ".join(c.replace(str(stage) + "/", "") for c in cmd))
    return obj


def link(stage: Path, objs: list[Path], out: str, machine: str, flags: list[str],
         cmds: list[str], entry: str = "start") -> None:
    cmd = [LLD_LINK, *(str(o) for o in objs), f"/out:{out}.exe", f"/pdb:{out}.pdb",
           f"/machine:{machine}", "/nodefaultlib", f"/entry:{entry}", "/subsystem:console",
           *flags]
    print("  $", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True, cwd=stage)
    cmds.append(" ".join(c.replace(str(stage) + "/", "") for c in cmd))


# variant name -> (arch, driver, compile flags, link flags, source kind)
C_VARIANTS: list[tuple[str, str, str, list[str], list[str], str]] = [
    ("c_x64_O2_full", "x64", "clang-cl", ["/O2", "/Z7"], ["/debug:full"], "c"),
    ("c_x64_O0_full", "x64", "clang-cl", ["/Od", "/Z7"], ["/debug:full"], "c"),
    ("c_x64_O2_icf", "x64", "clang-cl", ["/O2", "/Z7", "/Gy"], ["/debug", "/opt:ref", "/opt:icf"],
     "c"),
    ("c_x64_O2_linetables", "x64", "clang", ["-O2", "-gline-tables-only", "-gcodeview"],
     ["/debug"], "c"),
    ("c_x64_O2_ghash", "x64", "clang-cl", ["/O2", "/Z7", "/Gy"], ["/debug:ghash", "/opt:icf"],
     "c"),
    ("c_x64_O2_incremental", "x64", "clang-cl", ["/O2", "/Z7"], ["/debug", "/incremental"], "c"),
    ("c_x86_O2_full", "x86", "clang-cl", ["/O2", "/Z7"], ["/debug:full", "/safeseh:no"], "c"),
    ("c_x86_O0_icf", "x86", "clang-cl", ["/Od", "/Z7", "/Gy"],
     ["/debug", "/opt:icf", "/safeseh:no"], "c"),
    ("c_arm64_O2_full", "arm64", "clang-cl", ["/O2", "/Z7"], ["/debug:full"], "c"),
    ("c_arm64_O0_full", "arm64", "clang", ["-O0", "-g", "-gcodeview"], ["/debug:full"], "c"),
    # clang 18 with -gcodeview but no -g emits S_COMPILE3/S_OBJNAME and nothing
    # else, so this PDB has publics and no procedure records -- the shape
    # /DEBUG:FASTLINK and old toolchains produce.
    ("c_arm64_publics_only", "arm64", "clang", ["-O0", "-gcodeview"], ["/debug"], "c"),
    ("cpp_x64_O2_inline", "x64", "clang-cl", ["/O2", "/Z7", "/GR-", "/EHs-c-", "/std:c++17"],
     ["/debug:full", "/opt:icf"], "cpp"),
    ("cpp_x64_O0_inline", "x64", "clang-cl", ["/Od", "/Z7", "/GR-", "/EHs-c-", "/std:c++17"],
     ["/debug"], "cpp"),
    ("cpp_x86_O2_inline", "x86", "clang-cl", ["/O2", "/Z7", "/GR-", "/EHs-c-", "/std:c++17"],
     ["/debug:full", "/safeseh:no"], "cpp"),
    ("cpp_arm64_O2_inline", "arm64", "clang-cl", ["/O2", "/Z7", "/GR-", "/EHs-c-", "/std:c++17"],
     ["/debug:full"], "cpp"),
]

MACHINE = {"x64": "x64", "x86": "x86", "arm64": "arm64"}
DLLTOOL_MACHINE = {"x64": "i386:x86-64", "x86": "i386", "arm64": "arm64"}


def build_c(prov: dict) -> None:
    out = CORPUS / "clang"
    out.mkdir(parents=True, exist_ok=True)
    stage = Path("/tmp/build/corpus-c")   # neutral path: the PDB records it
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    (stage / "gen.c").write_text(gen_c_source())
    (stage / "gen.cpp").write_text(CPP_SOURCE)
    (stage / "stubs.c").write_text(STUBS_C)
    shutil.copy(stage / "gen.c", out / "gen.c")
    shutil.copy(stage / "gen.cpp", out / "gen.cpp")
    shutil.copy(stage / "stubs.c", out / "stubs.c")
    for name, arch, driver, cflags, lflags, kind in C_VARIANTS:
        if (out / f"{name}.pdb").exists():
            continue
        print(f"== build {name}")
        target = TARGETS[arch]
        cmds: list[str] = []
        src = stage / ("gen.cpp" if kind == "cpp" else "gen.c")
        try:
            objs = [compile_c(stage, src, target, cflags, driver, cmds),
                    compile_c(stage, stage / "stubs.c", target, ["-O1"] if driver == "clang"
                              else ["/O1", "/Z7"], driver, cmds)]
            link(stage, objs, name, MACHINE[arch], lflags, cmds)
        except subprocess.CalledProcessError as e:
            print(f"  !! {name} failed: {e}")
            continue
        for f in stage.glob(f"{name}*"):
            if f.suffix in (".pdb", ".exe"):
                shutil.move(str(f), out / f.name)
        for f in out.glob(f"{name}*.pdb"):
            record(prov, str(f.relative_to(CORPUS)), url="self-built",
                   toolchain=f"clang{'-cl' if driver == 'clang-cl' else ''} 18.1.3 + lld-link"
                   f" 18.1.3, {arch}", licence=OURS, redistributable=True, group="clang",
                   note=("stripped output of " if "stripped.pdb" in f.name else "")
                   + " && ".join(cmds))
        for o in stage.glob("*.obj"):
            o.unlink()


RUST_VARIANTS = [
    # name, arch, kind, rustc flags, extra link args
    ("rust_nostd_x64_release", "x64", "nostd", ["-O", "-C", "debuginfo=2"], []),
    ("rust_nostd_x64_debug", "x64", "nostd", ["-C", "opt-level=0", "-C", "debuginfo=2"], []),
    ("rust_nostd_x86_release", "x86", "nostd", ["-O", "-C", "debuginfo=2"], ["/safeseh:no"]),
    ("rust_nostd_arm64_release", "arm64", "nostd", ["-O", "-C", "debuginfo=2"], []),
    ("rust_nostd_arm64_debug", "arm64", "nostd", ["-C", "opt-level=0", "-C", "debuginfo=2"], []),
    ("rust_nostd_x64_line_tables", "x64", "nostd", ["-O", "-C", "debuginfo=line-tables-only"],
     []),
    ("rust_std_x64_release", "x64", "std", ["-O", "-C", "debuginfo=2"], []),
    ("rust_std_x64_debug", "x64", "std", ["-C", "opt-level=0", "-C", "debuginfo=2"], []),
    ("rust_std_x86_release", "x86", "std", ["-O", "-C", "debuginfo=2"], ["/safeseh:no"]),
    ("rust_std_arm64_release", "arm64", "std", ["-O", "-C", "debuginfo=2"], []),
]

_UNDEF = re.compile(r"undefined symbol: (__declspec\(dllimport\) )?(\S+)")


def asm_stubs(names: set[str]) -> str:
    """One `ret` per undefined symbol: enough to link, never to run."""
    lines = ["\t.text"]
    for n in sorted(names):
        q = f'"{n}"'
        # 8-aligned because some of these are read as data (e.g. _tls_index).
        lines += ["\t.p2align 3", f"\t.globl {q}", f"{q}:", "\tret"]
    return "\n".join(lines) + "\n"


def build_rust(prov: dict) -> None:
    out = CORPUS / "rust"
    out.mkdir(parents=True, exist_ok=True)
    stage = Path("/tmp/build/corpus-rust")
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    shutil.copy(REPO / "tests/data/rustpe32/main.rs", stage / "nostd.rs")
    (stage / "std_main.rs").write_text(RUST_STD_MAIN)
    (stage / "rust_stubs.c").write_text(RUST_STUBS_C)
    for f in ("nostd.rs", "std_main.rs", "rust_stubs.c"):
        shutil.copy(stage / f, out / f)
    for name, arch, kind, rflags, largs in RUST_VARIANTS:
        if (out / f"{name}.pdb").exists():
            continue
        print(f"== build {name}")
        target = TARGETS[arch]
        cmds: list[str] = []
        stubs = compile_c(stage, stage / "rust_stubs.c", target, ["-O1"], "clang", cmds)
        src = "nostd.rs" if kind == "nostd" else "std_main.rs"
        entry = "mainCRTStartup" if kind == "nostd" else "main"
        link_args = ["/nodefaultlib", "/subsystem:console", f"/entry:{entry}", stubs.name,
                     "/libpath:.", "/errorlimit:0", "/demangle:no", *largs]
        for lib in ("kernel32", "ntdll", "userenv", "ws2_32", "dbghelp", "advapi32", "bcrypt"):
            (stage / f"{lib}.def").write_text(f"LIBRARY {lib}.dll\nEXPORTS\n")
            run(["llvm-dlltool-18", "-m", DLLTOOL_MACHINE[arch], "-d", f"{lib}.def",
                 "-l", f"{lib}.lib"], cwd=stage)
        extra_objs: list[str] = []
        ok = False
        needed: set[str] = set()
        imports: set[str] = set()
        for _round in range(12):
            cmd = [RUSTC, "--target", target, *rflags, "-C", "panic=abort",
                   "-C", "linker-flavor=lld-link", "-C", "linker=lld-link"]
            for arg in link_args + extra_objs:
                cmd += ["-C", f"link-arg={arg}"]
            cmd += ["--crate-type", "bin", "-o", f"{name}.exe", src]
            print("  $", " ".join(cmd), flush=True)
            r = subprocess.run(cmd, cwd=stage, text=True, capture_output=True)
            if r.returncode == 0:
                ok = True
                cmds.append(" ".join(cmd))
                break
            hits = [(imp or n.startswith("__imp_"), n.removeprefix("__imp_"))
                    for imp, n in _UNDEF.findall(r.stderr)]
            new_imports = {n.lstrip("_") if arch == "x86" else n for imp, n in hits if imp}
            new_imports -= imports
            new_needed = {n for imp, n in hits if not imp} - needed
            if not new_imports and not new_needed:
                print(f"  !! {name} failed:\n{r.stderr[-3000:]}")
                break
            if new_imports:
                # Win32 imports std names go into one generated import library
                # (all attributed to kernel32.dll: the image is never run).
                imports |= new_imports
                (stage / "kernel32.def").write_text(
                    "LIBRARY kernel32.dll\nEXPORTS\n" + "".join(f"{n}\n" for n in sorted(imports)))
                run(["llvm-dlltool-18", "-m", DLLTOOL_MACHINE[arch], "-d", "kernel32.def",
                     "-l", "kernel32.lib"], cwd=stage)
                shutil.copy(stage / "kernel32.def", out / f"{name}.kernel32.def")
            if new_needed:
                needed |= new_needed
                (stage / "crt_stubs.s").write_text(asm_stubs(needed))
                obj = compile_c(stage, stage / "crt_stubs.s", target, [], "clang")
                extra_objs = [obj.name]
        if not ok:
            continue
        if needed:
            shutil.copy(stage / "crt_stubs.s", out / f"{name}.crt_stubs.s")
        for f in stage.glob(f"{name}*"):
            if f.suffix in (".pdb", ".exe"):
                shutil.move(str(f), out / f.name)
        for f in out.glob(f"{name}*.pdb"):
            record(prov, str(f.relative_to(CORPUS)), url="self-built",
                   toolchain=f"{rustc_id()} + rust-lld (lld-link flavor), {arch}, {kind}",
                   licence=OURS, redistributable=True, group="rust",
                   note=("stripped output of " if "stripped.pdb" in f.name else "")
                   + " && ".join(cmds)
                   + (f"; {len(needed)} undefined symbols stubbed as `ret` in"
                      f" {name}.crt_stubs.s" if needed else "")
                   + (f"; {len(imports)} Win32 imports via llvm-dlltool from"
                      f" {name}.kernel32.def" if imports else ""))
        for o in stage.glob("*.obj"):
            o.unlink()


def stage_build(prov: dict) -> None:
    build_c(prov)
    build_rust(prov)


# ---------------------------------------------------------------------------
# --corrupt
# ---------------------------------------------------------------------------

MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
_SUPERBLOCK = struct.Struct("<32sIIIIII")   # magic, blocksize, fpm, nblocks, dirsize, unk, dirmap

CORRUPT_SOURCES = [
    "tests/data/tls/tls_symbols.pdb",
    "tests/data/rustpe32/rust_pe_symbols_i686.pdb",
    "tests/data/syzygy/test_vtables_omap.dll.pdb",
]


def corrupt_variants(data: bytes) -> dict[str, bytes]:
    magic, bs, fpm, nblocks, dirsize, _unk, dirmap = _SUPERBLOCK.unpack_from(data)
    if magic != MSF_MAGIC:
        raise ValueError("not an MSF 7.00 file")
    v: dict[str, bytes] = {}

    def patched(off: int, fmt: str, *vals: int) -> bytes:
        c = bytearray(data)
        struct.pack_into(fmt, c, off, *vals)
        return bytes(c)

    v["trunc_00_empty"] = b""
    v["trunc_01_magic_only"] = data[:32]
    v["trunc_02_half_superblock"] = data[:40]
    v["trunc_03_superblock_only"] = data[:bs]
    v["trunc_04_before_dirmap"] = data[: dirmap * bs]
    v["trunc_05_mid_dirmap"] = data[: dirmap * bs + 2]
    dirblocks = struct.unpack_from("<I", data, dirmap * bs)[0] if dirmap * bs + 4 <= len(data) \
        else 0
    v["trunc_06_mid_directory"] = data[: dirblocks * bs + dirsize // 2]
    v["trunc_07_after_directory"] = data[: (dirblocks + 1) * bs]
    v["trunc_08_25pct"] = data[: len(data) // 4]
    v["trunc_09_50pct"] = data[: len(data) // 2]
    v["trunc_10_90pct"] = data[: len(data) * 9 // 10]
    v["trunc_11_minus_one_block"] = data[: len(data) - bs]
    v["trunc_12_minus_one_byte"] = data[:-1]
    v["trunc_13_partial_last_block"] = data[: len(data) - bs // 2]
    v["zero_superblock"] = bytes(bs) + data[bs:]
    v["zero_fpm_block"] = data[: fpm * bs] + bytes(bs) + data[(fpm + 1) * bs:]
    v["zero_dirmap_block"] = data[: dirmap * bs] + bytes(bs) + data[(dirmap + 1) * bs:]
    if dirblocks:
        v["zero_directory_block"] = (data[: dirblocks * bs] + bytes(bs)
                                     + data[(dirblocks + 1) * bs:])
    v["ff_directory_block"] = (data[: dirblocks * bs] + b"\xff" * bs
                               + data[(dirblocks + 1) * bs:]) if dirblocks else data
    v["blocksize_512"] = patched(32, "<I", 512)
    v["blocksize_8192"] = patched(32, "<I", 8192)
    v["blocksize_0"] = patched(32, "<I", 0)
    v["blocksize_1"] = patched(32, "<I", 1)
    v["blocksize_odd_4095"] = patched(32, "<I", 4095)
    v["blocksize_huge"] = patched(32, "<I", 0x40000000)
    v["nblocks_0"] = patched(40, "<I", 0)
    v["nblocks_double"] = patched(40, "<I", nblocks * 2)
    v["nblocks_max"] = patched(40, "<I", 0xFFFFFFFF)
    v["dirsize_0"] = patched(44, "<I", 0)
    v["dirsize_huge"] = patched(44, "<I", 0x7FFFFFFF)
    v["dirsize_max"] = patched(44, "<I", 0xFFFFFFFF)
    v["dirmap_0"] = patched(52, "<I", 0)
    v["dirmap_self"] = patched(52, "<I", dirmap)
    v["dirmap_out_of_range"] = patched(52, "<I", nblocks + 5)
    v["dirmap_max"] = patched(52, "<I", 0xFFFFFFFF)
    v["fpm_0"] = patched(36, "<I", 0)
    v["fpm_3"] = patched(36, "<I", 3)
    v["magic_msf200"] = b"Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0" + data[44:]
    v["magic_portable"] = b"BSJB" + data[4:]
    v["magic_garbage"] = b"\x00" * 32 + data[32:]
    if dirblocks:
        # Stream sizes live at the front of the directory: count, then sizes.
        d = dirblocks * bs
        nstreams = struct.unpack_from("<I", data, d)[0]
        v["dir_nstreams_0"] = patched(d, "<I", 0)
        v["dir_nstreams_max"] = patched(d, "<I", 0xFFFFFFFF)
        v["dir_nstreams_plus1"] = patched(d, "<I", nstreams + 1)
        c = bytearray(data)
        for i in range(min(nstreams, 64)):
            struct.pack_into("<I", c, d + 4 + 4 * i, 0xFFFFFFFF)
        v["dir_streamsizes_max"] = bytes(c)
        c = bytearray(data)
        for i in range(min(nstreams, 64)):
            struct.pack_into("<I", c, d + 4 + 4 * i, 0)
        v["dir_streamsizes_0"] = bytes(c)
        if nstreams > 3:
            v["dir_dbi_size_huge"] = patched(d + 4 + 4 * 3, "<I", 0x7FFFFFF0)
            v["dir_pdbinfo_size_1"] = patched(d + 4 + 4 * 1, "<I", 1)
        c = bytearray(data)
        for i in range(nstreams):
            struct.pack_into("<I", c, d + 4 + 4 * i, 0xFFFFFFFF if i % 2 else 0)
        v["dir_streamsizes_nil_alternating"] = bytes(c)
        # Block lists follow the sizes; point every block at the superblock.
        blocklists = d + 4 + 4 * nstreams
        c = bytearray(data)
        for off in range(blocklists, min(d + bs, len(c)) - 4, 4):
            struct.pack_into("<I", c, off, 0)
        v["dir_blocklists_all_zero"] = bytes(c)
        c = bytearray(data)
        for off in range(blocklists, min(d + bs, len(c)) - 4, 4):
            struct.pack_into("<I", c, off, 0xFFFFFFF0)
        v["dir_blocklists_out_of_range"] = bytes(c)
    # Deterministic bit flips across the whole file, several densities.
    for density in (1, 8, 64):
        rnd = random.Random(density)
        c = bytearray(data)
        for _ in range(max(1, len(c) * density // 4096)):
            i = rnd.randrange(len(c))
            c[i] ^= 1 << rnd.randrange(8)
        v[f"bitflip_{density:02d}_per_4k"] = bytes(c)
    # Everything after the first block replaced by a repeating pattern.
    v["body_pattern"] = data[:bs] + (b"\xaa\x55" * (len(data) // 2))[: len(data) - bs]
    v["padded_with_garbage"] = data + b"\xcc" * (bs * 3)
    v["dup_first_block_appended"] = data + data[:bs]
    return v


def stage_corrupt(prov: dict) -> None:
    out = CORPUS / "corrupt"
    for rel in CORRUPT_SOURCES:
        src = REPO / rel
        data = src.read_bytes()
        stem = src.stem.replace(".dll", "")
        d = out / stem
        d.mkdir(parents=True, exist_ok=True)
        for name, blob in corrupt_variants(data).items():
            dest = d / f"{name}.pdb"
            dest.write_bytes(blob)
            record(prov, str(dest.relative_to(CORPUS)), url=f"derived from {rel}",
                   toolchain="tools/fetch_corpus.py --corrupt", licence=OURS,
                   redistributable=True, group="corrupt", note=name.replace("_", " "))


# ---------------------------------------------------------------------------
# --omap: pair images with PDBs and run the repository's OMAP check
# ---------------------------------------------------------------------------

OMAP_REPORT = CORPUS / "omap_validation.txt"
OMAP_SLOTS = CORPUS / "omap_slots.json"


def stage_omap(prov: dict) -> None:
    """Run dev/validate_omap_against_windows.py over msdl_images/, and record
    the debug-header slots and raw DBI BuildNumber of every vendor PDB."""
    cache = CORPUS / "_omap_cache"
    for rel in prov:
        if prov[rel].get("group") in ("msdl", "xp"):
            path = CORPUS / rel
            ident = path.parent.name.split("-", 1)[1]
            (cache / ident).mkdir(parents=True, exist_ok=True)
            link = cache / ident / path.name
            if not link.exists():
                link.symlink_to(path)
    r = subprocess.run([sys.executable, str(REPO / "dev" / "validate_omap_against_windows.py"),
                        str(CORPUS / "msdl_images"), "--cache", str(cache)],
                       text=True, capture_output=True, cwd=REPO)
    OMAP_REPORT.write_text(f"$ python dev/validate_omap_against_windows.py msdl_images"
                           f" --cache _omap_cache\n(exit {r.returncode})\n\n{r.stderr}{r.stdout}")
    print(OMAP_REPORT.read_text())
    sys.path.insert(0, str(REPO))
    from purepdb import PDB  # deferred: the corpus tool otherwise needs no purepdb

    slots: dict[str, dict] = {}
    for rel in sorted(prov):
        if prov[rel].get("group") not in ("msdl", "xp"):
            continue
        pdb = PDB.open(CORPUS / rel)
        build = struct.unpack_from("<H", pdb.msf.read_stream(3), 14)[0]
        slot = {f"slot{i}": (None if pdb.dbi.dbg_stream(i) == 0xFFFF else pdb.dbi.dbg_stream(i))
                for i in (3, 4, 5, 10)}
        slots[rel] = {"build_number": f"0x{build:04x}", "new_format": bool(build & 0x8000),
                      "omap_from_src": len(pdb.omap) if pdb.omap else 0, **slot}
    save_json(OMAP_SLOTS, slots)


# ---------------------------------------------------------------------------
# --smoke
# ---------------------------------------------------------------------------


def timed(cmd: list[str], timeout: int = SMOKE_TIMEOUT) -> tuple[float, int | None, str, str]:
    t0 = time.perf_counter()
    try:
        r = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout,
                           errors="replace")
        return time.perf_counter() - t0, r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as e:
        return time.perf_counter() - t0, None, (e.stdout or b"").decode("utf-8", "replace") \
            if isinstance(e.stdout, bytes) else (e.stdout or ""), "TIMEOUT"


def smoke_one(path: Path) -> dict:
    res: dict = {"size": path.stat().st_size}
    # llvm-pdbutil
    dt, rc, out, err = timed([PDBUTIL, "dump", "--summary", str(path)])
    res["pdbutil_rc"] = rc
    res["pdbutil_time"] = round(dt, 2)
    m = re.search(r"Block Size: (\d+)", out)
    res["block_size"] = int(m.group(1)) if m else None
    m = re.search(r"Number of streams: (\d+)", out)
    res["streams"] = int(m.group(1)) if m else None
    m = re.search(r"Number of blocks: (\d+)", out)
    res["blocks"] = int(m.group(1)) if m else None
    m = re.search(r"Is stripped: (\w+)", out)
    res["pdbutil_stripped"] = m.group(1) if m else None
    m = re.search(r"Is incrementally linked: (\w+)", out)
    res["pdbutil_incremental"] = m.group(1) if m else None
    if rc:
        res["pdbutil_error"] = (err or out).strip().splitlines()[-1][:200] if (err or out) \
            else f"rc={rc}"
    # purepdb diagnose
    dt, rc, out, err = timed([str(PUREPDB), "diagnose", str(path)])
    res["diagnose_rc"] = rc
    res["diagnose_time"] = round(dt, 2)
    res["opened"] = rc == 0
    if rc != 0:
        res["diagnose_error"] = (err or out).strip().splitlines()[-1][:300] if (err or out) \
            else f"rc={rc}"
    if "Traceback" in err:
        res["traceback"] = err.strip().splitlines()[-1][:300]
    for key, pat in (("procs", r"proc records\s*:\s*(\d+)"),
                     ("publics", r"public records\s*:\s*(\d+)"),
                     ("modules", r"modules\s*:\s*(\d+)"),
                     ("truncated_streams", r"truncated streams\s*:\s*(\d+)"),
                     ("malformed", r"malformed records\s*:\s*(\d+)")):
        m = re.search(pat, out)
        res[key] = int(m.group(1)) if m else None
    res["section_headers"] = bool(re.search(r"section headers\s*:\s*yes", out))
    warns = [ln.strip() for ln in out.splitlines() if ln.lower().startswith(("warning", "!"))]
    warns += [ln.strip() for ln in out.splitlines() if re.match(r"\s*-\s", ln)]
    res["warnings"] = warns[:8]
    # purepdb functions, timed
    dt, rc, out, err = timed([str(PUREPDB), "functions", str(path)])
    res["functions_rc"] = rc
    res["functions_time"] = round(dt, 2)
    res["functions"] = sum(1 for ln in out.splitlines() if ln.startswith("0x")) \
        if rc == 0 else None
    if rc not in (0, None):
        res["functions_error"] = (err.strip().splitlines() or ["?"])[-1][:300]
    if "Traceback" in err:
        res["traceback"] = err.strip().splitlines()[-1][:300]
    res["functions_stderr"] = [ln for ln in err.splitlines() if not re.match(r"^\d+ functions",
                                                                              ln)][:5]
    return res


def stage_smoke(prov: dict, only: str | None = None, force: bool = False) -> None:
    smoke = load_json(SMOKE)
    for rel in sorted(prov):
        if only and only not in rel:
            continue
        path = CORPUS / rel
        if not path.exists() or prov[rel].get("group") == "msdl_images":
            continue
        cached = smoke.get(rel)
        if cached and not force and cached.get("sha256") == prov[rel].get("sha256"):
            continue
        print(f"== smoke {rel}", flush=True)
        res = smoke_one(path)
        res["sha256"] = prov[rel].get("sha256")
        smoke[rel] = res
        save_json(SMOKE, smoke)
        print(f"   opened={res['opened']} funcs={res['functions']} "
              f"t={res['functions_time']}s streams={res['streams']} bs={res['block_size']}")


# ---------------------------------------------------------------------------
# --manifest
# ---------------------------------------------------------------------------

GROUP_TITLES = {
    "python": "python.org release PDBs (MSVC, PGO)",
    "node": "nodejs.org release PDBs (MSVC, huge)",
    "msdl": "Microsoft public symbol server (NOT redistributable)",
    "msdl_images": "PE images paired with the msdl PDBs (NOT redistributable)",
    "xp": "Windows XP SP3 x86 symbols via archive.org (NOT redistributable)",
    "mozilla": "Mozilla symbol server (Firefox, clang-cl + lld-link, huge)",
    "clang": "self-built: clang / clang-cl 18 + lld-link 18 (freestanding)",
    "rust": "self-built: rustc + rust-lld (freestanding)",
    "corrupt": "derived corrupt variants of committed fixtures",
}


def human(n: int | None) -> str:
    if n is None:
        return "-"
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return str(size)


def write_manifest(prov: dict, smoke: dict, dest: Path, local: bool) -> None:
    lines = []
    total = sum(e.get("size", 0) for e in prov.values())
    lines.append("# purepdb audit corpus" + (" — MANIFEST" if local else ""))
    lines.append("")
    if local:
        lines.append(f"Root: `{CORPUS}`. Rebuild with `tools/fetch_corpus.py` in the purepdb"
                     " repository; this file is generated by its `--manifest` stage.")
    else:
        lines.append("Generated by `tools/fetch_corpus.py --manifest --docs`; paths are"
                     " relative to the corpus root, which is outside the repository. Nothing"
                     " listed here is committed.")
    lines.append("")
    lines.append(f"{len(prov)} files, {human(total)} total. Smoke pass: `llvm-pdbutil dump"
                 " --summary` (bs = MSF block size, streams = stream count), then"
                 " `purepdb diagnose` (opened = exit 0, procs/publics from its report) and a"
                 " timed `purepdb functions` (funcs = records printed, t = wall seconds)."
                 f" Timeout {SMOKE_TIMEOUT}s each.")
    lines.append("")
    lines.append("Licence key: PSF = Python Software Foundation License; MIT = Node.js;"
                 " MS = Microsoft symbol-server terms (debugging use only, do not"
                 " redistribute); MPL = Mozilla Public License 2.0; ours = built here from"
                 " generated or repository sources, BSD-3-Clause.")
    lines.append("")
    groups: dict[str, list[str]] = {}
    for rel, e in prov.items():
        groups.setdefault(e.get("group", "other"), []).append(rel)
    slots = load_json(OMAP_SLOTS)
    for g in GROUP_TITLES:
        rels = sorted(groups.get(g, []))
        if not rels:
            continue
        title = GROUP_TITLES[g]
        if g == "rust":
            title = f"self-built: {rustc_id()} + rust-lld (freestanding)"
        lines.append(f"## {title}")
        lines.append("")
        gsize = sum(prov[r].get("size", 0) for r in rels)
        lines.append(f"{len(rels)} files, {human(gsize)}.")
        lines.append("")
        if g == "msdl_images":
            lines.append("| image | size | sha256 | names PDB |")
            lines.append("|---|---|---|---|")
            for r in rels:
                e = prov[r]
                lines.append(f"| `{r}` | {human(e.get('size'))} | `{e['sha256'][:16]}` |"
                             f" {e['note'].split('names ')[-1]} |")
            lines.append("")
            if OMAP_REPORT.exists():
                lines.append("OMAP check (`dev/validate_omap_against_windows.py`, exports of"
                             " the shipped image against purepdb's translated publics):")
                lines.append("")
                lines.append("```")
                lines.extend(OMAP_REPORT.read_text().rstrip().splitlines())
                lines.append("```")
                lines.append("")
            continue
        if g in ("msdl", "xp") and slots:
            lines.append("Debug-header slots (stream index or -), OMAP entry count and the raw"
                         " DBI BuildNumber (uint16 at DBI offset 14; top bit set = new"
                         " format, `major.minor` from the low 15 bits):")
            lines.append("")
            lines.append("| file | slot3 OmapToSrc | slot4 OmapFromSrc | slot5 sections |"
                         " slot10 orig sections | omap | BuildNumber |")
            lines.append("|---|---|---|---|---|---|---|")
            for r in rels:
                t = slots.get(r)
                if not t:
                    continue
                b = int(t["build_number"], 16)
                fmt = f"{t['build_number']} ({'new' if t['new_format'] else 'OLD'} format,"
                fmt += f" {(b >> 8) & 0x7F}.{b & 0xFF:02d})"
                cells = [str(t[f"slot{i}"]) if t[f"slot{i}"] is not None else "-"
                         for i in (3, 4, 5, 10)]
                lines.append(f"| `{Path(r).parent.name}` | {' | '.join(cells)} |"
                             f" {t['omap_from_src']} | {fmt} |")
            lines.append("")
        if g == "corrupt":
            # Too many near-identical rows to list one by one; summarise.
            by_src: dict[str, list[str]] = {}
            for r in rels:
                by_src.setdefault(prov[r]["url"], []).append(r)
            for src, rs in by_src.items():
                opened = sum(1 for r in rs if smoke.get(r, {}).get("opened"))
                tb = [r for r in rs if smoke.get(r, {}).get("traceback")]
                slow = [r for r in rs if (smoke.get(r, {}).get("functions_time") or 0) > 5]
                lines.append(f"- `{rs[0].rsplit('/', 1)[0]}/` — {len(rs)} variants {src};"
                             f" purepdb opened {opened} of them (exit 0)")
                lines.append(f"  tracebacks: {len(tb)}; slower than 5 s: {len(slow)}"
                             + (f" ({', '.join(Path(s).stem for s in slow)})" if slow else ""))
                for r in rs:
                    s = smoke.get(r, {})
                    if s.get("traceback"):
                        lines.append(f"  - `{Path(r).name}`: {s['traceback']}")
            lines.append("")
            lines.append("| variant | what |")
            lines.append("|---|---|")
            seen = set()
            for r in rels:
                n = Path(r).stem
                if n in seen:
                    continue
                seen.add(n)
                lines.append(f"| `{n}` | {prov[r]['note']} |")
            lines.append("")
            continue
        lines.append("| file | size | sha256 | bs | streams | opened | procs | publics |"
                     " funcs | t (s) | notes |")
        lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
        for r in rels:
            e = prov[r]
            s = smoke.get(r, {})
            notes = []
            if s.get("traceback"):
                notes.append("TRACEBACK: " + s["traceback"])
            if s.get("diagnose_error") and not s.get("opened"):
                notes.append(s["diagnose_error"])
            if s.get("functions_rc") is None and "functions_time" in s:
                notes.append("functions timed out")
            if s.get("pdbutil_rc"):
                notes.append("llvm-pdbutil: " + s.get("pdbutil_error", "failed"))
            if s.get("pdbutil_stripped") == "true":
                notes.append("stripped")
            if s.get("pdbutil_incremental") == "true":
                notes.append("incremental")
            if s.get("truncated_streams"):
                notes.append(f"{s['truncated_streams']} truncated streams")
            if s.get("malformed"):
                notes.append(f"{s['malformed']} malformed records")
            if s.get("section_headers") is False and s.get("opened"):
                notes.append("no section headers")
            notes += s.get("warnings", [])[:3]
            lines.append(
                f"| `{r}` | {human(e.get('size'))} | `{(e.get('sha256') or '')[:16]}` |"
                f" {s.get('block_size') or '-'} | {s.get('streams') or '-'} |"
                f" {'yes' if s.get('opened') else ('no' if s else '?')} |"
                f" {s.get('procs') if s.get('procs') is not None else '-'} |"
                f" {s.get('publics') if s.get('publics') is not None else '-'} |"
                f" {s.get('functions') if s.get('functions') is not None else '-'} |"
                f" {s.get('functions_time', '-')} | {'; '.join(notes).replace('|', '/')} |")
        lines.append("")
        lines.append("Provenance:")
        lines.append("")
        by_url: dict[str, list[str]] = {}
        for r in rels:
            by_url.setdefault(prov[r]["url"], []).append(r)
        for r in rels:
            e = prov[r]
            lines.append(f"- `{r}` — {e['url']}; toolchain: {e['toolchain']}; licence:"
                         f" {e['licence']}; sha256 `{e.get('sha256')}`"
                         + (f"; {e['note']}" if e.get("note") else ""))
        lines.append("")
    dest.write_text("\n".join(lines) + "\n")
    print(f"wrote {dest}")


def stage_manifest(prov: dict, docs: bool) -> None:
    smoke = load_json(SMOKE)
    write_manifest(prov, smoke, CORPUS / "MANIFEST.md", local=True)
    if docs:
        write_manifest(prov, smoke, REPO / "docs" / "audit" / "corpus.md", local=False)


# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    for flag in ("fetch", "build", "corrupt", "omap", "smoke", "manifest"):
        ap.add_argument(f"--{flag}", action="store_true")
    ap.add_argument("--docs", action="store_true", help="also write docs/audit/corpus.md")
    ap.add_argument("--only", help="smoke: only files whose path contains this")
    ap.add_argument("--force", action="store_true", help="smoke: ignore the cache")
    ap.add_argument("--rehash", action="store_true", help="recompute size/sha256 of every file")
    a = ap.parse_args(argv)
    everything = not (a.fetch or a.build or a.corrupt or a.omap or a.smoke or a.manifest
                      or a.rehash)
    CORPUS.mkdir(parents=True, exist_ok=True)
    prov = load_json(PROVENANCE)
    if a.rehash:
        for rel in list(prov):
            if (CORPUS / rel).exists():
                record(prov, rel)
            else:
                del prov[rel]
        save_json(PROVENANCE, prov)
    if everything or a.fetch:
        stage_fetch(prov)
    if everything or a.build:
        stage_build(prov)
    if everything or a.corrupt:
        stage_corrupt(prov)
    if everything or a.omap:
        stage_omap(prov)
    if everything or a.smoke:
        stage_smoke(prov, a.only, a.force)
    if everything or a.manifest:
        stage_manifest(prov, a.docs or everything)
    return 0


if __name__ == "__main__":
    sys.exit(main())
