#!/bin/bash
# release.sh — build the GitHub-Release artifacts for Attesor.
#
# Produces dist/:
#   Attesor-<ver>.dmg           app with offline runtime (drag to /Applications)
#   attesor-runtime-<ver>.tar.xz  first-run payload the app downloads
#   attesor-runtime.tar.xz      copy of the payload under the stable name
#                               the app fetches via releases/latest/download
#   SHA256SUMS
#
# A version-matched archive is also available for builds without a bundled runtime.
#
# Usage: runtime-src/release.sh [version]   (default: git describe)
set -euo pipefail

src="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$src/.." && pwd)"
runtime="$repo/runtime"
ver="${1:-$(git -C "$repo" describe --tags --always 2>/dev/null || echo dev)}"
case "$ver" in
    ""|*[!A-Za-z0-9._-]*|.|..) echo "Invalid release version: $ver" >&2; exit 2 ;;
esac
dist="$repo/dist/$ver"
payload="$dist/payload"

die() { echo "release: $*" >&2; exit 1; }

echo "release: version $ver"
export COPYFILE_DISABLE=1
export MACOSX_DEPLOYMENT_TARGET=13.0

# --- rebuild app bundles ----------------------------------------------------
[ ! -e "$dist" ] || die "output already exists: $dist"
make -C "$repo/reconstruct" -B -j 4 oah
"$src/assemble.sh"
[ -x "$runtime/Apps/Attesor Package Manager.app/Contents/MacOS/PackageManager" ] \
    || die "Package Manager bundle missing"

# --- payload tarball ---------------------------------------------------------
# Repo-shaped tree so every path lookup (Repo.*) works unchanged.
mkdir -p "$payload/reconstruct" "$payload/runtime-src" \
         "$payload/runtime/var/cache/jit" "$payload/runtime/var/log" \
         "$payload/runtime/var/freeciv/home" \
         "$payload/runtime/icons" "$payload/runtime/Apps"
cp "$repo/reconstruct/oah" "$payload/reconstruct/"
cp "$src"/*.sh "$payload/runtime-src/" 2>/dev/null || true
cp "$runtime/icons/Penguin.icns" "$payload/runtime/icons/"
cp -R "$runtime/Apps/Attesor Linux Launcher.app" "$payload/runtime/Apps/"
# The payload ships a minimal deb-built sysroot under the canonical
# debian-expanded name — everything else downloads on demand through the
# native package-manager pipeline. Dev sysroots are never shipped.
"$src/bootstrap-sysroot.sh" "$payload/runtime/sysroots/debian-expanded"
# Guest homes in a development sysroot can contain saves and user settings.
# Clear only the staged copies before packaging.
for guest in "$payload/runtime/sysroots"/*; do
    for home in "$guest/root" "$guest/home"; do
        [ -d "$home" ] && [ ! -L "$home" ] || continue
        find "$home" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    done
    rm -f "$guest/etc/apt/auth.conf"
    if [ -d "$guest/etc/apt/auth.conf.d" ] && [ ! -L "$guest/etc/apt/auth.conf.d" ]; then
        find "$guest/etc/apt/auth.conf.d" -mindepth 1 -maxdepth 1 -type f -delete
    fi
done
# Writable markers assemble.sh maintains.
touch "$payload/runtime/sysroots/freeciv/.attesor-writable" 2>/dev/null || true
touch "$payload/runtime/sysroots/debian-expanded/.attesor-guest-root" 2>/dev/null || true

mkdir -p "$dist"
# Prepare catalog indexes for the native UI. Keep the uncompressed Debian
# names so a fresh install does not have to decode XZ under translation.
if command -v xz >/dev/null 2>&1; then
    for index in "$payload/runtime/sysroots/debian-expanded/var/lib/apt/lists/"*_Packages.xz; do
        [ -f "$index" ] || continue
        xz -dc "$index" > "${index%.xz}"
        rm "$index"
    done
fi

# Skip the apt .deb cache — apt re-downloads on demand; it only bloats
# the first-run payload (~70 MB uncompressed).
rm -f "$payload/runtime/sysroots"/*/var/cache/apt/archives/*.deb
if command -v xz >/dev/null 2>&1; then
    tar -cf - -C "$payload" . | xz -T4 -3 > "$dist/attesor-runtime-$ver.tar.xz"
else
    tar -cJf "$dist/attesor-runtime-$ver.tar.xz" -C "$payload" .
fi
cp "$dist/attesor-runtime-$ver.tar.xz" "$dist/attesor-runtime.tar.xz"

# --- app + dmg ----------------------------------------------------------
app="$dist/Attesor.app"
rm -rf "$app"
cp -R "$runtime/Apps/Attesor Package Manager.app" "$app"
cp -c "$dist/attesor-runtime.tar.xz" "$app/Contents/Resources/attesor-runtime.tar.xz"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString ${ver#v}" "$app/Contents/Info.plist"
# Friendlier bundle name for the shipped artifact.
/usr/libexec/PlistBuddy -c "Set :CFBundleName Attesor" \
    "$app/Contents/Info.plist" 2>/dev/null || true
/usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName Attesor" \
    "$app/Contents/Info.plist" 2>/dev/null || true

/usr/bin/codesign --force --sign - "$app"

dmgdir="$dist/dmg-root"
rm -rf "$dmgdir"; mkdir -p "$dmgdir"
cp -R "$app" "$dmgdir/"
ln -s /Applications "$dmgdir/Applications"
hdiutil create -volname "Attesor" -srcfolder "$dmgdir" -format UDRO \
    "$dist/Attesor-$ver.dmg" >/dev/null

shasum -a 256 "$dist"/*.tar.xz "$dist"/*.dmg > "$dist/SHA256SUMS"
rm -rf "$dmgdir" "$payload"

echo "release: artifacts in $dist"
ls -lh "$dist" | grep -v dmg-root
echo
echo "Upload to a GitHub Release. Keep 'attesor-runtime.tar.xz' as the"
echo "asset name for clients that fetch the matching version's runtime."
