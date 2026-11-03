#!/bin/sh
# Run inside the extracted tcltls source directory by tools/build-tclkit.sh.
# tcltls 1.7.22 treats every LibreSSL as pre-1.1 API (it pokes into the DH struct, opaque since LibreSSL 2.7).
# Only genuinely old LibreSSL needs that path.
sed -i 's/^#if (defined(LIBRESSL_VERSION_NUMBER)) ||/#if (defined(LIBRESSL_VERSION_NUMBER) \&\& LIBRESSL_VERSION_NUMBER < 0x2070000fL) ||/' tlsInt.h
grep -q 'LIBRESSL_VERSION_NUMBER < 0x2070000fL' tlsInt.h || { echo "tcltls patch did not apply" >&2; exit 1; }
