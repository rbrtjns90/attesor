#!/bin/bash
# apt-update.sh — fetch Debian apt indices natively (replaces the slow
# translated `apt-get update`).
#
# What `apt-get update` does, done here with macOS tools:
#   1. parse /etc/apt/sources.list + sources.list.d/*.list + *.sources
#   2. fetch <uri>/dists/<suite>/InRelease (fallback: Release+Release.gpg)
#   3. verify the signature with the *guest* gpgv under the translator —
#      a tiny file, no decompression, so it's fast even translated
#   4. read the Release's SHA256 table and fetch each component's index
#      (Packages.lz4 preferred, matching apt's on-disk names), verifying
#      size + sha256
#   5. install into var/lib/apt/lists/ atomically via partial/
#
# Files land under the same mangled names apt produces, so the guest sees
# a fully populated index afterwards. pkgcache.bin is dropped so apt
# regenerates it.

set -uo pipefail

A=/Users/rob/Documents/GitHub/attesor
S="$A/runtime/sysroots/debian-expanded"
OAH="$A/reconstruct/oah"
LISTS="$S/var/lib/apt/lists"
PARTIAL="$LISTS/partial"
ETC="$S/etc/apt"
ARCH="${ARCH:-amd64}"

mkdir -p "$PARTIAL"

run_guest() {
    env DEBIAN_FRONTEND=noninteractive OAH_CACHE_DIR="$A/runtime/var/cache/jit" LC_ALL=C \
        "$OAH" --sysroot "$S" "$@"
}

# apt's URItoFileName: scheme stripped, '/' and ':' become '_'.
mangle_uri() {
    local u="${1%/}"
    u="${u#*://}"
    u="${u//\//_}"
    u="${u//:/_}"
    printf '%s' "$u"
}

fetch() { # $1=url $2=host outfile
    curl -fsSL --retry 2 --connect-timeout 15 -o "$2" "$1"
}

# Emit repo entries as "type|uri|suite|components|keyring" rows.
collect_entries() {
    local f
    for f in "$ETC"/sources.list.d/*.sources; do
        [ -f "$f" ] || continue
        awk '
            function emit(  i,j,k,nt,nu,ns,ts,us,ss) {
                nt = split(type, ts, " ")
                nu = split(uris, us, " ")
                ns = split(suites, ss, " ")
                for (i = 1; i <= nt; i++)
                    for (j = 1; j <= nu; j++)
                        for (k = 1; k <= ns; k++)
                            printf "%s|%s|%s|%s|%s\n", ts[i], us[j], ss[k], comps, keyring
            }
            function flush() {
                if (type && uris && suites) emit()
                type=uris=suites=comps=keyring=""
            }
            /^[ \t]*$/  { flush(); next }
            /^[ \t]*#/  { next }
            /^Types:/      { type=$2; for(i=3;i<=NF;i++) type=type" "$i; next }
            /^URIs:/       { uris=$2; for(i=3;i<=NF;i++) uris=uris" "$i; next }
            /^Suites:/     { suites=$2; for(i=3;i<=NF;i++) suites=suites" "$i; next }
            /^Components:/ { comps=$2; for(i=3;i<=NF;i++) comps=comps" "$i; next }
            /^Signed-By:/  { keyring=$2; next }
            END { flush() }' "$f"
    done
    for f in "$ETC/sources.list" "$ETC"/sources.list.d/*.list; do
        [ -f "$f" ] || continue
        awk '!/^[ \t]*(#|$)/ {
                type=$1; i=2; keyring=""
                if (substr($i,1,1)=="[") {
                    while (i<=NF && substr($i,length($i),1)!="]") {
                        if ($i ~ /^signed-by=/) { keyring=$i; sub(/^signed-by=/,"",keyring) }
                        i++
                    }
                    i++
                }
                comps=""; for (j=i+2;j<=NF;j++) comps = comps (comps?" ":"") $j
                printf "%s|%s|%s|%s|%s\n", type, $i, $(i+1), comps, keyring
            }' "$f"
    done
}

# SHA256 table from a Release file -> "path|size|sha" rows.
release_sha256() {
    awk '/^[A-Za-z]/ { sec = ($0 == "SHA256:"); next }
         sec && NF >= 3 { print $3 "|" $2 "|" $1 }' "$1"
}

verify_sig() { # $1=partial data file, $2=keyring, $3=optional detached sig
    local keyring="$2" rc
    local gdata="/var/lib/apt/lists/partial/$(basename "$1")"
    if [ -z "$keyring" ]; then
        echo "   (no Signed-By keyring; sha256 checks only)"
        return 0
    fi
    if [ -x "$S/usr/bin/gpgv" ] && [ -f "$S$keyring" ]; then
        if [ -n "${3:-}" ]; then
            run_guest "$S/usr/bin/gpgv" --keyring "$keyring" \
                "/var/lib/apt/lists/partial/$(basename "$3")" "$gdata" 2>/dev/null
        else
            run_guest "$S/usr/bin/gpgv" --keyring "$keyring" "$gdata" 2>/dev/null
        fi
        rc=$?
        if [ $rc -ne 0 ]; then
            echo "!! signature verification FAILED: $(basename "$1")" >&2
            return 1
        fi
        echo "   signature ok"
    else
        echo "   (guest gpgv or keyring missing; sha256 checks only)"
    fi
    return 0
}

# From $PARTIAL/.sums ("path|size|sha"), pick the best compression for $1.
want_index() {
    local ext line
    for ext in .lz4 .xz .gz .bz2 ""; do
        line=$(awk -F'|' -v p="$1$ext" '$1==p {print; exit}' "$PARTIAL/.sums")
        if [ -n "$line" ]; then
            printf '%s|%s\n' "$1$ext" "$line"
            return 0
        fi
    done
    return 1
}

fail=0
while IFS='|' read -r type uri suite comps keyring; do
    comps="${comps:-main}"
    base="$(mangle_uri "$uri")_dists_${suite//\//_}"
    echo "== $type $uri $suite"

    rel="$PARTIAL/${base}_InRelease"
    if fetch "$uri/dists/$suite/InRelease" "$rel" 2>/dev/null; then
        verify_sig "$rel" "$keyring" || { fail=1; continue; }
        mv "$rel" "$LISTS/${base}_InRelease"
        outname="${base}_InRelease"
    else
        echo "   InRelease missing; trying Release + Release.gpg"
        rel="$PARTIAL/${base}_Release"
        sig="$PARTIAL/${base}_Release.gpg"
        if ! fetch "$uri/dists/$suite/Release" "$rel" 2>/dev/null ||
           ! fetch "$uri/dists/$suite/Release.gpg" "$sig" 2>/dev/null; then
            echo "!! no Release for $uri $suite" >&2
            fail=1; continue
        fi
        verify_sig "$rel" "$keyring" "$sig" || { fail=1; continue; }
        mv "$rel" "$LISTS/${base}_Release"
        mv "$sig" "$LISTS/${base}_Release.gpg"
        outname="${base}_Release"
    fi

    release_sha256 "$LISTS/$outname" > "$PARTIAL/.sums"

    for comp in $comps; do
        case "$type" in
            deb)     idx="$comp/binary-$ARCH/Packages" ;;
            deb-src) idx="$comp/source/Sources" ;;
            *)       continue ;;
        esac
        for rel_target in "$idx" "$comp/i18n/Translation-en"; do
            pick=$(want_index "$rel_target") || {
                if [ "$rel_target" = "$idx" ]; then
                    echo "!! no index for $rel_target" >&2
                    fail=1
                fi
                continue
            }
            rpath="${pick%%|*}"
            expect_size=$(cut -d'|' -f3 <<<"$pick")
            expect_sha=$(cut -d'|' -f4 <<<"$pick")
            fname="${base}_${rpath//\//_}"
            if ! fetch "$uri/dists/$suite/$rpath" "$PARTIAL/$fname"; then
                echo "!! fetch failed: $rpath" >&2
                fail=1; continue
            fi
            got_size=$(stat -f%z "$PARTIAL/$fname")
            got_sha=$(shasum -a 256 "$PARTIAL/$fname" | awk '{print $1}')
            if [ "$got_size" != "$expect_size" ] || [ "$got_sha" != "$expect_sha" ]; then
                echo "!! checksum mismatch: $rpath" >&2
                fail=1; continue
            fi
            # Retire other compressions of the same index — apt prefers
            # lz4 when reading lists, so a stale .lz4 would shadow this.
            rm -f "$LISTS"/"${base}_${rel_target//\//_}".*
            mv "$PARTIAL/$fname" "$LISTS/$fname"
            echo "   $rpath ($got_size bytes)"
        done
    done
done < <(collect_entries)

# apt rebuilds its binary cache itself once lists change.
rm -f "$S/var/cache/apt/pkgcache.bin" "$S/var/cache/apt/srcpkgcache.bin"

echo "== index refreshed in $LISTS"
exit "$fail"
