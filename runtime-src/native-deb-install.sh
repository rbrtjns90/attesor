#!/bin/bash
# native-deb-install.sh — unpack .deb files into the Attesor sysroot using
# native macOS tools, then let the guest dpkg run maintainer scripts.
#
# Usage: native-deb-install.sh <sysroot> <deb...>
#
# The slow/crash-prone parts of apt+dpkg under the translator (HTTP fetch,
# dpkg-deb/xz extraction) run natively here at full speed. Only the
# maintainer-script pass (preinst already done? no — see below) runs under
# the translator via `dpkg --configure -a`.
#
# What this does per package:
#   - skips packages already `install ok installed` in the dpkg status file
#   - extracts data.tar.* into the sysroot (preserving modes/symlinks)
#   - writes var/lib/dpkg/info/<pkg>.{list,md5sums,conffiles,postinst,...}
#   - rewrites/creates the package's status stanza as `install ok unpacked`
# After all packages: run `dpkg --configure -a` under the translator so
# maintainer scripts (which are Linux code) execute in order.
#
# Note: packages that carry a preinst run it at unpack time under real dpkg;
# we run preinst natively-extracted? No — preinst is a Linux script too, so
# it is invoked by `dpkg --configure -a`?? Actually configure only runs
# postinst. We invoke preinst before extraction via the translator when the
# deb ships one (rare outside base system).

set -uo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <sysroot> <deb...>" >&2
    exit 2
fi

SYSROOT=$(cd "$1" && pwd)
shift
A=/Users/rob/Documents/GitHub/attesor
DPKG="$SYSROOT/var/lib/dpkg"
INFO="$DPKG/info"
STATUS="$DPKG/status"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$INFO"

ar_member() { # $1=deb $2=prefix (data.tar | control.tar)
    ar t "$1" | grep -E "^$2\." | head -1
}

control_field() { # $1=control-file $2=field
    awk -v f="$2:" 'BEGIN{IGNORECASE=0}
         $0 ~ ("^" f " ") {sub("^[^ ]* ", ""); print; exit}' "$1"
}

for deb in "$@"; do
    cm=$(ar_member "$deb" control.tar)
    dm=$(ar_member "$deb" data.tar)
    if [ -z "$cm" ] || [ -z "$dm" ]; then
        echo "skip $deb: not a deb" >&2
        continue
    fi
    mkdir -p "$TMP/ctl"
    (cd "$TMP/ctl" && ar -p "$deb" "$cm" | tar -xf -) || continue
    ctl="$TMP/ctl/control"
    pkg=$(control_field "$ctl" Package)
    [ -z "$pkg" ] && { echo "skip $deb: no Package field" >&2; continue; }

    state=$(awk -v p="$pkg" '
        /^Package: / {inpkg = ($2 == p)}
        inpkg && /^Status: / {
            print ($3 == "installed") ? "installed" : "other"; exit
        }' "$STATUS")
    if [ "$state" = "installed" ] && [ "${FORCE:-0}" != "1" ]; then
        echo "== $pkg already installed, skipping"
        rm -rf "$TMP/ctl"
        continue
    fi

    echo "== native unpack: $pkg"

    # preinst, if shipped, must run before files land — the translator
    # executes it like dpkg would, with DPKG_MAINTSCRIPT_* env set.
    if [ -f "$TMP/ctl/preinst" ]; then
        ver=$(control_field "$ctl" Version)
        arch=$(control_field "$ctl" Architecture)
        chmod +x "$TMP/ctl/preinst"
        env DEBIAN_FRONTEND=noninteractive DPKG_MAINTSCRIPT_NAME=preinst DPKG_MAINTSCRIPT_PACKAGE="$pkg" \
            DPKG_MAINTSCRIPT_VERSION="$ver" DPKG_MAINTSCRIPT_ARCH="$arch" \
            OAH_CACHE_DIR=$A/runtime/var/cache/jit LC_ALL=C \
            "$A/reconstruct/oah" --sysroot "$SYSROOT" \
            "$SYSROOT/usr/bin/dash" "$TMP/ctl/preinst" install || {
                echo "!! $pkg preinst failed, skipping" >&2
                rm -rf "$TMP/ctl"
                continue
            }
    fi

    # Extract payload.
    if ! ar -p "$deb" "$dm" | tar -xpf - -C "$SYSROOT"; then
        echo "!! $pkg extraction failed" >&2
        rm -rf "$TMP/ctl"
        continue
    fi

    # info/<pkg>.list — `/.` then every member as absolute path.
    {
        ar -p "$deb" "$dm" | tar -tf - | sed -e 's|/+$||' \
            -e 's|^\./|/|' -e 's|^\.$|/.|'
    } > "$INFO/$pkg.list"

    # Control members become info files verbatim.
    for f in md5sums conffiles postinst preinst prerm postrm config \
             templates triggers shlibs symbols; do
        [ -f "$TMP/ctl/$f" ] && cp "$TMP/ctl/$f" "$INFO/$pkg.$f"
    done
    chmod +x "$INFO/$pkg.postinst" "$INFO/$pkg.preinst" \
             "$INFO/$pkg.prerm" "$INFO/$pkg.postrm" 2>/dev/null

    # Build the replacement status stanza: Package, Status, all remaining
    # control fields, then the Conffiles section dpkg tracks.
    {
        echo "Package: $pkg"
        echo "Status: install ok unpacked"
        grep -v '^Package: ' "$ctl"
        if [ -f "$TMP/ctl/conffiles" ]; then
            echo "Conffiles:"
            while IFS= read -r cf; do
                # conffiles are excluded from md5sums; dpkg records the
                # shipped file's hash so it can detect local edits later.
                md=$(md5 -q "$SYSROOT$cf" 2>/dev/null)
                echo " $cf $md"
            done < "$TMP/ctl/conffiles"
        fi
        echo ""
    } > "$TMP/$pkg.stanza"

    rm -rf "$TMP/ctl"
done

# Rewrite the status file: replace existing stanzas for processed packages,
# append stanzas for packages not already present.
if ls "$TMP"/*.stanza >/dev/null 2>&1; then
    for s in "$TMP"/*.stanza; do
        head -1 "$s" | sed 's/^Package: //'
    done > "$TMP/processed"

    awk -v listfile="$TMP/processed" -v stanza_dir="$TMP" '
        BEGIN {
            while ((getline p < listfile) > 0) repl[p] = 1
        }
        /^Package: / {
            if (repl[$2]) {
                pkg = $2
                while ((getline l < (stanza_dir "/" pkg ".stanza")) > 0)
                    print l
                close(stanza_dir "/" pkg ".stanza")
                seen[pkg] = 1
                skip = 1
                next
            }
            skip = 0
        }
        !skip { print }
        END {
            for (p in repl)
                if (!seen[p]) {
                    while ((getline l < (stanza_dir "/" p ".stanza")) > 0)
                        print l
                    close(stanza_dir "/" p ".stanza")
                }
        }
    ' "$STATUS" > "$STATUS.new" && mv "$STATUS.new" "$STATUS"
fi

echo "== configuring under translator (dpkg --configure -a)"
DEBIAN_FRONTEND=noninteractive OAH_CACHE_DIR=$A/runtime/var/cache/jit LC_ALL=C \
    "$A/reconstruct/oah" --sysroot "$SYSROOT" \
    "$SYSROOT/usr/bin/dpkg" --configure -a
