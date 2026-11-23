#!/bin/bash
# release.sh — build the GitHub-Release artifacts for Attesor.
#
# Produces dist/:
#   Attesor-<ver>.dmg           thin app (drag to /Applications)
#   attesor-runtime-<ver>.tar.xz  first-run payload the app downloads
#   attesor-runtime.tar.xz      copy of the payload under the stable name
#                               the app fetches via releases/latest/download
#   SHA256SUMS
#
# Upload these to a GitHub Release tagged <ver>; the app fetches
# releases/latest/download/attesor-runtime.tar.xz on first launch.
#
# Usage: runtime-src/release.sh [version]   (default: git describe)
set -euo pipefail

src="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$src/.." && pwd)"
runtime="$repo/runtime"
ver="${1:-$(git -C "$repo" describe --tags --always 2>/dev/null || echo dev)}"
dist="$repo/dist/$ver"
payload="$dist/payload"

die() { echo "release: $*" >&2; exit 1; }

echo "release: version $ver"

# --- rebuild app bundles ----------------------------------------------------
"$src/assemble.sh"
[ -x "$runtime/Apps/Attesor Package Manager.app/Contents/MacOS/PackageManager" ] \
    || die "Package Manager bundle missing"

# --- payload tarball ---------------------------------------------------------
# Repo-shaped tree so every path lookup (Repo.*) works unchanged.
rm -rf "$payload" "$dist"
mkdir -p "$payload/reconstruct" "$payload/runtime-src" \
         "$payload/runtime/var/cache/jit" "$payload/runtime/var/log" \
         "$payload/runtime/var/freeciv/home" \
         "$payload/runtime/icons" "$payload/runtime/Apps"
cp "$repo/reconstruct/oah" "$payload/reconstruct/"
cp "$src"/*.sh "$payload/runtime-src/" 2>/dev/null || true
cp "$runtime/icons/Penguin.icns" "$payload/runtime/icons/"
cp -R "$runtime/Apps/Attesor Linux Launcher.app" "$payload/runtime/Apps/"
cp -R "$runtime/sysroots" "$payload/runtime/"
# Writable markers assemble.sh maintains.
touch "$payload/runtime/sysroots/freeciv/.attesor-writable" 2>/dev/null || true
touch "$payload/runtime/sysroots/debian-expanded/.attesor-guest-root" 2>/dev/null || true

mkdir -p "$dist"
# Skip the apt .deb cache — apt re-downloads on demand; it only bloats
# the first-run payload (~70 MB uncompressed).
rm -f "$payload/runtime/sysroots"/*/var/cache/apt/archives/*.deb
tar -cJf "$dist/attesor-runtime-$ver.tar.xz" -C "$payload" .
cp "$dist/attesor-runtime-$ver.tar.xz" "$dist/attesor-runtime.tar.xz"

# --- thin app + dmg ----------------------------------------------------------
app="$dist/Attesor.app"
rm -rf "$app"
cp -R "$runtime/Apps/Attesor Package Manager.app" "$app"
# Friendlier bundle name for the shipped artifact.
/usr/libexec/PlistBuddy -c "Set :CFBundleName Attesor" \
    "$app/Contents/Info.plist" 2>/dev/null || true
/usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName Attesor" \
    "$app/Contents/Info.plist" 2>/dev/null || true

dmgdir="$dist/dmg-root"
rm -rf "$dmgdir"; mkdir -p "$dmgdir"
cp -R "$app" "$dmgdir/"
ln -s /Applications "$dmgdir/Applications"
hdiutil create -volname "Attesor" -srcfolder "$dmgdir" -ov -format UDZO \
    "$dist/Attesor-$ver.dmg" >/dev/null

shasum -a 256 "$dist"/*.tar.xz "$dist"/*.dmg > "$dist/SHA256SUMS"
rm -rf "$dmgdir" "$payload"

echo "release: artifacts in $dist"
ls -lh "$dist" | grep -v dmg-root
echo
echo "Upload to a GitHub Release. Keep 'attesor-runtime.tar.xz' as the"
echo "asset name — the app fetches releases/latest/download/attesor-runtime.tar.xz"
