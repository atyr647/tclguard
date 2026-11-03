#!/bin/sh
# Re-wrap the current source tree into the three release binaries using the raw Tcl runtimes kept in
# tools/runtimes/ (build new ones with tools/build-tclkit.sh and copy them there).
# The Windows console build is the same file with the PE subsystem changed 2 -> 3.
set -e
cd "$(dirname "$0")/.."
mkdir -p dist
# The program that runs build.tcl needs Tcl + Metakit (vfs::mk4). By default that is the currently shipped single-file program
# (`<it> eval build.tcl ...`), so no separate build directory is required; set HOSTKIT to any tclkit to use that instead.
HOSTKIT=${HOSTKIT:-releases/tclguard-linux-x86_64}
case "$(basename "$HOSTKIT")" in tclkit*) EVALWORD="" ;; *) EVALWORD="eval" ;; esac
# (copy it first: the build replaces the file it runs from)
cp "$HOSTKIT" /tmp/tg-rewrap-host.$$ && chmod +x /tmp/tg-rewrap-host.$$
trap 'rm -f /tmp/tg-rewrap-host.$$' EXIT
cd dist
rm -f tclguard-linux tclguard.exe tclguard-console.exe
xvfb-run -a /tmp/tg-rewrap-host.$$ $EVALWORD ../build.tcl --runtime ../tools/runtimes/rt-linux-x86_64 --format mk4 --out tclguard-linux </dev/null 2>&1 | tail -1
xvfb-run -a /tmp/tg-rewrap-host.$$ $EVALWORD ../build.tcl --runtime ../tools/runtimes/rt-windows-x86_64.exe --format mk4 --out tclguard.exe </dev/null 2>&1 | tail -1
python3 - <<'PY'
import struct
b = bytearray(open("tclguard.exe", "rb").read())
pe = struct.unpack_from("<I", b, 0x3c)[0]; assert b[pe:pe+4] == b"PE\0\0"
opt = pe + 24; assert struct.unpack_from("<H", b, opt)[0] == 0x20b
off = opt + 68; assert struct.unpack_from("<H", b, off)[0] == 2
struct.pack_into("<H", b, off, 3)
open("tclguard-console.exe", "wb").write(b)
PY
cd ..
cp dist/tclguard-linux releases/tclguard-linux-x86_64
cp dist/tclguard.exe releases/tclguard-windows-x86_64.exe
cp dist/tclguard-console.exe releases/tclguard-windows-x86_64-console.exe
chmod +x releases/tclguard-linux-x86_64
(cd releases && sha256sum tclguard-linux-x86_64 tclguard-windows-x86_64.exe tclguard-windows-x86_64-console.exe > SHA256SUMS && cat SHA256SUMS)
