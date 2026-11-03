#!/bin/bash
# Reproduce the tclkit runtimes TclGuard's starpacks are built on.
#
# A tclkit is a single executable containing Tcl, Tk, and a virtual file system. TclGuard needs
#   Tk        (the GUI; headless mode works without it)
#   udp       (tcludp, for the game-server UDP relay)
#   tls       (tcltls + static LibreSSL: HTTPS termination and the self-update downloader)
#   Thread    (bundled by Tcl 8.6; reserved for the optional worker design)
#   vfs::mk4  (Metakit storage; used by build.tcl to write the starpack payload)
# The prebuilt kits on the internet are old and lack Tk/udp, so build one with KitCreator.
#
#   tools/build-tclkit.sh linux     -> tclkit-8.6.14 (native, x86_64)
#   tools/build-tclkit.sh win64     -> tclkit-8.6.14 (Windows x86_64 .exe, cross-compiled with mingw-w64)
#
# Needs: gcc make autoconf, X11/Xft dev headers (libx11-dev libxft-dev libxext-dev libxss-dev),
# curl, tar; for win64 also gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 and an existing native tclkit
# (pass its path in TCLKIT; build the linux one first). Takes ~15 minutes per target.
set -euo pipefail
target=${1:-linux}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
work=${WORK:-$PWD/.tclkit-build-$target}
mkdir -p "$work" && cd "$work"
[ -d kc ] || { curl -fsSL -o kc.tar.gz "https://kitcreator.rkeene.org/fossil/tarball/kitcreator.tar.gz?uuid=trunk"
               mkdir kc && tar xzf kc.tar.gz -C kc --strip-components=1; }
cd kc
# KitCreator pins LibreSSL 2.9.0 (2019: no TLS 1.3, known CVEs) and tcltls 1.7.19. Pin newer, hash-checked
# ones instead (LibreSSL hashes match the OpenBSD-published SHA256 list; tcltls from core.tcl-lang.org).
sed -i \
  -e 's/^version="1.7.19"/version="1.7.22"/' \
  -e 's#^url=.*#url="https://core.tcl-lang.org/tcltls/uv/tcltls-${version}.tar.gz"#' \
  -e "s/^sha256=.*/sha256='e84e2b7a275ec82c4aaa9d1b1f9786dbe4358c815e917539ffe7f667ff4bc3b4'/" \
  -e "s/version='2.9.0'/version='4.0.0'/" \
  -e "s#http://ftp.openbsd.org#https://cdn.openbsd.org#" \
  -e "s/hash='eb5f298408b723f11a0ca0192c122ecb79b4855bfdf7eea183a6264296a13cf4'/hash='4d841955f0acc3dfc71d0e3dd35f283af461222350e26843fea9731c0246a1e4'/" \
  tls/build.sh
# tcltls 1.7.22 does not build against current LibreSSL as shipped: patch it (see tools/patch-tcltls.sh).
sed -i "s#^function preconfigure() {#function preconfigure() {\n\tsh \"$ROOT/tools/patch-tcltls.sh\" || return 1#" tls/build.sh
grep -q patch-tcltls tls/build.sh || { echo "could not hook the tcltls patch"; exit 1; }
# Generate the kitsh configure script (the fossil tarball ships without it). NOTE: this runs
# 'kitcreator distclean', so do it before building, never between a build and its output.
bash build/pre.sh >/dev/null 2>&1 || true
export KITCREATOR_PKGS='tk itcl mk4tcl udp tls'
export KC_TLS_BUILDSSL=1     # build LibreSSL from source and link it statically into tcltls
case $target in
  linux) ./kitcreator 8.6.14 --enable-64bit ;;
  win64)
    : "${TCLKIT:?set TCLKIT to a native tclkit (the linux one built above)}"
    export TCLKIT PKG_CONFIG_LIBDIR=/usr/x86_64-w64-mingw32/lib/pkgconfig
    AR=x86_64-w64-mingw32-ar CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ \
    RANLIB=x86_64-w64-mingw32-ranlib RC=x86_64-w64-mingw32-windres STRIP=x86_64-w64-mingw32-strip \
      ./kitcreator 8.6.14 --host=x86_64-w64-mingw32 --enable-64bit ;;
  *) echo "usage: $0 linux|win64"; exit 2 ;;
esac
ls -la tclkit-8.6.14
echo "Then:  <native tclkit> build.tcl --runtime <COPY of the tclkit> --format mk4 --out tclguard[.exe]"
echo "(use a copy: a running tclkit mounts itself as a virtual directory, so 'file copy' on its own path would copy files, not the binary)"
