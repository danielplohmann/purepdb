#!/bin/sh
# Rebuild the thread-local fixture. Needs LLVM's clang and LLD's lld-link on
# PATH; no Windows host, no Windows SDK and no CRT are involved, which is why
# the link is /nodefaultlib with an explicit entry point.
#
# The build runs in $STAGE rather than here because a PDB records the absolute
# path of everything it was built from -- S_OBJNAME, S_ENVBLOCK and the -cc1
# line clang stores in S_COMPILE3 -- and whoever rebuilds this should not be
# publishing their home directory. Everything the fixture records is that one
# neutral path. -ffile-prefix-map does not cover S_OBJNAME, which is why the
# directory is moved rather than rewritten.
#
# The result is not runnable: `start` returns rather than exiting, and nothing
# initialises TLS for a thread. It exists to be parsed.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
STAGE=/tmp/build/tls

rm -rf "$STAGE"
mkdir -p "$STAGE"
cp "$HERE/tls_symbols.c" "$HERE/tls_stubs.c" "$STAGE/"
cd "$STAGE"

for unit in tls_symbols tls_stubs; do
    clang --target=x86_64-pc-windows-msvc -O1 -gcodeview -fno-stack-protector \
          -c "$unit.c" -o "$unit.obj"
done

lld-link tls_symbols.obj tls_stubs.obj \
         /out:tls_symbols.exe /pdb:tls_symbols.pdb \
         /debug /nodefaultlib /entry:start /subsystem:console

cp tls_symbols.exe tls_symbols.pdb "$HERE/"
rm -rf "$STAGE"
