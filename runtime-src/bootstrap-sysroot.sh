#!/bin/bash
# bootstrap-sysroot.sh — build a minimal Attesor Debian sysroot from
# upstream .debs only. This is what ships as the runtime payload: just
# enough filesystem for dpkg maintainer scripts + the native install
# pipeline (apt-install.sh -> native-resolve.py -> native-deb-install.sh)
# to pull everything else on demand.
#
# Usage: bootstrap-sysroot.sh <sysroot-dir>
#
# Layout notes (learned the hard way):
#   - bookworm debs ship the top-level /bin /lib /sbin dirs themselves;
#     installing usrmerge is neither needed nor safe (its postinst runs
#     `cp -a`, which trips our xattr emulation). We seed a stub
#     `usr-is-merged` package instead so init-system-helpers' dependency
#     `usrmerge | usr-is-merged` resolves without it.
#   - OAH_SKIP_PREINST=1 is required: preinsts need /bin/sh, which doesn't
#     exist until dash unpacks. Postinsts run later via dpkg --configure.
set -euo pipefail

A="$(cd "$(dirname "$0")/.." && pwd)"
S="$(mkdir -p "$1" && cd "$1" && pwd -P)"
REF="$A/runtime/sysroots/debian-expanded"   # donor for apt sources/index

PKGS="dpkg dash bash coreutils tar gzip xz-utils sed grep mawk findutils \
      debconf sensible-utils debianutils base-files base-passwd perl-base \
      perl init-system-helpers ncurses-base diffutils libc-bin"

echo "== skeleton: $S"
mkdir -p "$S"/{etc,var/lib/dpkg/{info,updates,alternatives,parts,triggers},\
var/lib/apt/lists/partial,var/cache/{apt/archives/partial,debconf},var/log,\
root,tmp,usr/bin,usr/sbin,usr/lib64,usr/share,etc/apt}
cp -R "$REF/etc/apt/"* "$S/etc/apt/"
cp "$REF/var/lib/apt/lists/"*.xz "$S/var/lib/apt/lists/"
touch "$S/.attesor-writable" "$S/.attesor-guest-root"
chmod 1777 "$S/tmp"

# Seed dpkg status with a stub marking the root as already merged so
# `usrmerge` is never selected or run.
cat > "$S/var/lib/dpkg/status" <<'EOF'
Package: usr-is-merged
Status: install ok installed
Priority: required
Version: 1.0~attesor
Architecture: amd64
Maintainer: Attesor <local@attesor>
Description: stub marking this sysroot as usr-merged
 .
 usrmerge is intentionally not installed: its postinst conversion runs
 guest `cp -a`, which currently loses files through our xattr emulation.
 The merged /usr layout is already what the debs ship, so nothing is
 required beyond this marker satisfying init-system-helpers' dependency.
EOF
# dpkg status stanzas are blank-line separated; the seed must end with one
# so the first appended stanza doesn't merge into ours.
printf '\n' >> "$S/var/lib/dpkg/status"
touch "$S/var/lib/dpkg/info/usr-is-merged.list"

echo "== resolving base set"
OAH_NO_RECOMMENDS=1 python3 "$A/runtime-src/native-resolve.py" "$S" $PKGS \
    | tr -d "'" > /tmp/oah-boot-urls.txt
wc -l /tmp/oah-boot-urls.txt

echo "== fetching"
DL="$(mktemp -d /tmp/oah-boot-debs.XXXXXX)"
(cd "$DL" && xargs -n1 -P8 curl -fsSLO < /tmp/oah-boot-urls.txt)

echo "== installing"
# First-pass configure can fail on package ordering (e.g. base-files
# postinst chowns to root before base-passwd creates /etc/passwd) — the
# settle pass below resolves them, and verify fails on anything left.
OAH_SKIP_PREINST=1 "$A/runtime-src/native-deb-install.sh" "$S" "$DL"/*.deb || true

# Ordering pass: base-files' postinst chowns to root, but /etc/passwd is
# only created by base-passwd — which configures later in a cold status.
# A second pass settles packages that failed on first-pass ordering.
env OAH_SYSROOT_STRICT=1 DEBIAN_FRONTEND=noninteractive TMPDIR=/tmp \
    LC_ALL=C "$A/reconstruct/oah" --sysroot "$S" \
    "$S/usr/bin/dpkg" --configure -a || true

echo "== verify"
bad=$(env OAH_SYSROOT_STRICT=1 LC_ALL=C "$A/reconstruct/oah" \
    --sysroot "$S" "$S/usr/bin/dpkg" -l 2>/dev/null | grep -cE "^(iU|iF|rc|un ok)" || true)
env OAH_SYSROOT_STRICT=1 LC_ALL=C "$A/reconstruct/oah" \
    --sysroot "$S" "$S/bin/sh" -c 'echo guest-shell-ok' >/dev/null
[ "$bad" -eq 0 ] || { echo "!! $bad package(s) not fully configured" >&2; exit 1; }
du -sh "$S"
