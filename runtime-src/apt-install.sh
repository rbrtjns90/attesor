#!/bin/bash
# apt-install.sh — install Debian packages into the Attesor sysroot.
# Usage: apt-install.sh [-u|--update] [-f|--force] <package> [<package>...]
#
# How it works:
#   1. guest apt-get resolves dependencies under the translator and prints
#      the exact .deb URLs it would download (--print-uris downloads nothing)
#   2. native macOS curl fetches those URLs at full link speed
#   3. native-deb-install.sh unpacks each .deb into the sysroot and runs
#      `dpkg --configure -a` under the translator for maintainer scripts
#
# This keeps the two slow/crash-prone translated phases (apt's HTTP event
# loop and dpkg-deb/xz decompression) entirely in native code.
#
# Options:
#   -u, --update   refresh the package index first via apt-update.sh
#                  (native fetch — fast; use when the index is stale)
#   -f, --force    reinstall packages already marked installed (repair mode)

set -uo pipefail

A="$(cd "$(dirname "$0")/.." && pwd)"
S="$A/runtime/sysroots/debian-expanded"
OAH="$A/reconstruct/oah"
INSTALLER="$A/runtime-src/native-deb-install.sh"
UPDATER="$A/runtime-src/apt-update.sh"

update=0
force=0
pkgs=()
for arg in "$@"; do
    case "$arg" in
        -u|--update) update=1 ;;
        -f|--force) force=1 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        --) ;;
        -*) echo "Unknown option: $arg" >&2; exit 2 ;;
        *) pkgs+=("$arg") ;;
    esac
done
if [ "${#pkgs[@]}" -eq 0 ]; then
    echo "usage: $0 [-u|--update] [-f|--force] <package> [<package>...]" >&2
    exit 2
fi

run_guest() {
    env OAH_SYSROOT_STRICT=1 DEBIAN_FRONTEND=noninteractive TMPDIR=/tmp OAH_CACHE_DIR="$A/runtime/var/cache/jit" LC_ALL=C \
        "$OAH" --sysroot "$S" "$@"
}

if [ "$update" = 1 ]; then
    "$UPDATER" || {
        echo "!! apt index refresh failed" >&2
        exit 1
    }
fi

echo "== resolving: ${pkgs[*]}"
# Native resolution is the default — the guest apt-get resolver under the
# translator is kept only as an opt-in fallback (OAH_GUEST_RESOLVE=1) for
# debugging, since it takes minutes where the native pass is instant.
if [ "${OAH_GUEST_RESOLVE:-0}" = 1 ]; then
    resolved=$(run_guest "$S/usr/bin/apt-get" -o Acquire::Languages=none \
        -o Dir::Cache::pkgcache=/var/cache/apt/pkgcache.bin \
        -o Dir::Cache::srcpkgcache=/var/cache/apt/srcpkgcache.bin \
        install --print-uris -y "${pkgs[@]}") || {
        echo "!! apt could not resolve: ${pkgs[*]}" >&2
        exit 1
    }
else
    resolved=$(python3 "$A/runtime-src/native-resolve.py" "$S" "${pkgs[@]}") || {
        echo "!! could not resolve natively: ${pkgs[*]} (try OAH_GUEST_RESOLVE=1)" >&2
        exit 1
    }
fi
# --print-uris output lines: '<url>' <filename> <size> <hash>
uris=$(printf '%s\n' "$resolved" | sed -n "s/^'\([^']*\)'.*/\1/p")
if [ -z "$uris" ]; then
    echo "== nothing to download (already installed, or run with -f to repair)"
    exit 0
fi

dir=$(mktemp -d /tmp/oah-debs.XXXXXX)
trap 'rm -rf "$dir"' EXIT

n=0
for url in $uris; do
    n=$((n + 1))
    echo "== fetch $(basename "$url")"
    curl -fsSL --retry 2 --connect-timeout 15 -o "$dir/$(basename "$url")" "$url" || {
        echo "!! download failed: $url" >&2
        exit 1
    }
done
echo "== $n archive(s) downloaded to $dir"

FORCE="$force" "$INSTALLER" "$S" "$dir"/*.deb || {
    echo "!! native install failed" >&2
    exit 1
}
echo "== installed: ${pkgs[*]}"
"$(dirname "$0")/state-sync.sh" "native-install:${pkgs[*]}" || true
