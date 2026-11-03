#!/bin/bash
# Reproduce the tclkit runtimes TclGuard's starpacks are built on.
#
# A tclkit is a single executable containing Tcl, Tk, and a virtual file system. TclGuard needs
#   Tk        (the GUI; headless mode works without it)
#   udp       (tcludp, for the game-server UDP relay)
#   tls       (tcltls + static OpenSSL 3.5 LTS built here: HTTPS termination, ACME, signed self-update)
#   Thread    (bundled by Tcl 8.6; reserved for the optional worker design)
#   vfs::mk4  (Metakit storage; used by build.tcl to write the starpack payload)
# The prebuilt kits on the internet are old and lack Tk/udp, so build one with KitCreator.
#
#   tools/build-tclkit.sh linux     -> tclkit-8.6.14 (native, x86_64)
#   tools/build-tclkit.sh win64     -> tclkit-8.6.14 (Windows x86_64 .exe, cross-compiled with mingw-w64)
#   tools/build-tclkit.sh macos     -> tclkit-8.6.14 (macOS, native: arm64 or x86_64 depending on the machine; Tk is Aqua)
#                                      needs Xcode command line tools and `brew install autoconf automake libtool gnu-sed`
#
# Needs: gcc make autoconf, X11/Xft dev headers (libx11-dev libxft-dev libxext-dev libxss-dev),
# curl, tar; for win64 also gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 and an existing native tclkit
# (pass its path in TCLKIT; build the linux one first). Takes ~15 minutes per target.
set -euo pipefail
target=${1:-linux}
# portability helpers: this script also runs on macOS (BSD sed, no sha256sum/nproc)
sedi() { if sed --version >/dev/null 2>&1; then sed -i "$@"; else sed -i '' "$@"; fi; }
sha256check() { if command -v sha256sum >/dev/null 2>&1; then sha256sum -c -; else shasum -a 256 -c -; fi; }
ncpu() { nproc 2>/dev/null || sysctl -n hw.ncpu; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
work=${WORK:-$PWD/.tclkit-build-$target}
mkdir -p "$work" && cd "$work"
[ -d kc ] || { curl -fsSL -o kc.tar.gz "https://kitcreator.rkeene.org/fossil/tarball/kitcreator.tar.gz?uuid=trunk"
               mkdir kc && tar xzf kc.tar.gz -C kc --strip-components=1; }
cd kc
# KitCreator pins tcltls 1.7.19 (+ LibreSSL 2.9.0). Use tcltls 1.7.22 with a current OpenSSL LTS that we build
# ourselves and link statically (LibreSSL builds drop TLS 1.3 key updates and honour unlimited client
# renegotiation; OpenSSL 3 is what tcltls is developed against). Hashes are pinned: openssl.org and the
# GitHub release publish the same SHA-256 for the OpenSSL tarball.
OPENSSL_VERSION=3.5.9
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
# tcltls 1.7.22 segfaults in tls::import on macOS (found on a real Apple-silicon runner), so macOS uses 2.0.1; the other
# platforms keep 1.7.22, which is what the Linux and Windows test suites were run against.
if [ "$target" = macos ]; then
  TLS_VERSION=2.0.1; TLS_URL='https://core.tcl-lang.org/tcltls/tarball/tls-${version}/tcltls-${version}.tar.gz'
  TLS_SHA256=b19da006d63d8f49c2ad2180c8a07afbad6f734503ef273355990c477c623db7
else
  TLS_VERSION=1.7.22; TLS_URL='https://core.tcl-lang.org/tcltls/uv/tcltls-${version}.tar.gz'
  TLS_SHA256=e84e2b7a275ec82c4aaa9d1b1f9786dbe4358c815e917539ffe7f667ff4bc3b4
fi
sedi \
  -e "s/^version=\"1.7.19\"/version=\"$TLS_VERSION\"/" \
  -e "s#^url=.*#url=\"$TLS_URL\"#" \
  -e "s/^sha256=.*/sha256='$TLS_SHA256'/" \
  -e '/patch-tcltls/d' \
  -e '/libtcl86.a/d' \
  tls/build.sh
# On Windows tcltls links the Tcl library by bare file name (libtcl86.a); make it findable from the build directory.
sedi 's#^function preconfigure() {#function preconfigure() {\n\tcp "${pkgdir}/../tcl/inst/lib/libtcl86.a" . 2>/dev/null || true#' tls/build.sh
cd "$work"
inst="$work/openssl-inst"
if [ ! -f "$inst/lib/libssl.a" ]; then
  curl -fsSL -o openssl.tar.gz "https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz"
  echo "$OPENSSL_SHA256  openssl.tar.gz" | sha256check
  rm -rf "openssl-$OPENSSL_VERSION" && tar xzf openssl.tar.gz
  ( cd "openssl-$OPENSSL_VERSION"
    case $target in
      linux) cfg="linux-x86_64" ;;
      win64) cfg="mingw64 --cross-compile-prefix=x86_64-w64-mingw32-" ;;
      macos) case "$(uname -m)" in arm64) cfg="darwin64-arm64-cc" ;; *) cfg="darwin64-x86_64-cc" ;; esac ;;
    esac
    ./Configure $cfg no-shared no-tests no-docs no-apps --prefix="$inst" --libdir=lib >/dev/null
    make -j"$(ncpu)" >/dev/null && make install_sw >/dev/null )
fi
cd kc
if [ "$target" = macos ]; then
  # tcltls 2.x links static OpenSSL on macOS only from an explicit library directory (not from pkg-config)
  export KC_TLS_SSLDIR="$inst"
else
  export KC_TLS_SSLDIR="$inst/lib/pkgconfig"
fi
export KC_TLS_LINKSSLSTATIC=1
# Generate the kitsh configure script (the fossil tarball ships without it). NOTE: this runs
# 'kitcreator distclean', so do it before building, never between a build and its output.
bash build/pre.sh >/dev/null 2>&1 || true
export KITCREATOR_PKGS='tk itcl mk4tcl udp tls'
case $target in
  linux) ./kitcreator 8.6.14 --enable-64bit ;;
  macos)
    # Current Apple clang compiles old C as C17/C23 and rejects what these old sources do (K&R definitions in kitsh, zlib's fdopen
    # stub), so ask for C99; Tk must be the native Aqua build (without this it looks for X11 headers, or builds against XQuartz
    # when that happens to be installed).
    export CFLAGS="${CFLAGS:-} -std=gnu99 -Dfdopen=fdopen"
    # tcltls 1.7 left a "*.a.linkadd" file naming the OpenSSL archives for the final link; 2.0 does not, so say so here
    export KC_KITSH_LIBS="$inst/lib/libssl.a $inst/lib/libcrypto.a"
    # (kitcreator passes whatever follows the version to every package's configure)
    ./kitcreator 8.6.14 --enable-64bit --enable-aqua ;;
  win64)
    : "${TCLKIT:?set TCLKIT to a native tclkit (the linux one built above)}"
    export TCLKIT PKG_CONFIG_LIBDIR=/usr/x86_64-w64-mingw32/lib/pkgconfig
    AR=x86_64-w64-mingw32-ar CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ \
    RANLIB=x86_64-w64-mingw32-ranlib RC=x86_64-w64-mingw32-windres STRIP=x86_64-w64-mingw32-strip \
      ./kitcreator 8.6.14 --host=x86_64-w64-mingw32 --enable-64bit ;;
  *) echo "usage: $0 linux|win64|macos"; exit 2 ;;
esac
if [ "$target" = macos ]; then
  # fix lib/vfs/pkgIndex.tcl (see tools/repair-kit.tcl): repair a copy with the kit itself, then replace the kit
  cp tclkit-8.6.14 tclkit-repaired && ./tclkit-8.6.14 "$ROOT/tools/repair-kit.tcl" "$PWD/tclkit-repaired" && mv tclkit-repaired tclkit-8.6.14 && chmod +x tclkit-8.6.14
fi
ls -la tclkit-8.6.14
echo "Then:  <native tclkit> build.tcl --runtime <COPY of the tclkit> --format mk4 --out tclguard[.exe]"
echo "(use a copy: a running tclkit mounts itself as a virtual directory, so 'file copy' on its own path would copy files, not the binary)"
