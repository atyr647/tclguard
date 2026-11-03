#!/bin/sh
# Re-wrap the current source tree into the three release binaries using the runtimes
# kept in dist/ (rt-linux, rt-win64.exe; build them with tools/build-tclkit.sh).
# The Windows console build is the same file with the PE subsystem changed 2 -> 3.
set -e
cd "$(dirname "$0")/.."
HOSTKIT=${HOSTKIT:-.tclkit-build-linux/kc/tclkit-8.6.14}   # any tclkit with vfs::mk4
cd dist
rm -f tclguard-linux tclguard.exe tclguard-console.exe
xvfb-run -a "../$HOSTKIT" ../build.tcl --runtime rt-linux --format mk4 --out tclguard-linux </dev/null 2>&1 | tail -1
xvfb-run -a "../$HOSTKIT" ../build.tcl --runtime rt-win64.exe --format mk4 --out tclguard.exe </dev/null 2>&1 | tail -1
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
