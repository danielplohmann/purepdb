#!/bin/sh
# Rebuilds rust_pe_symbols_i686.{exe,pdb}. See ../README.md for why each piece
# is here. Needs rustc with the i686-pc-windows-msvc target installed, plus
# clang and lld-link -- no Microsoft toolchain and no import libraries.
set -eu
cd "$(dirname "$0")"

clang --target=i686-pc-windows-msvc -c -o stubs.obj stubs.s

rustc --target i686-pc-windows-msvc \
      -O -C debuginfo=2 -C panic=abort \
      -C linker-flavor=lld-link -C linker=lld-link \
      -C link-arg=/nodefaultlib \
      -C link-arg=/safeseh:no \
      -C link-arg=/subsystem:console \
      -C link-arg=/entry:mainCRTStartup \
      -C link-arg=stubs.obj \
      --crate-type bin -o rust_pe_symbols_i686.exe main.rs

rm -f stubs.obj
