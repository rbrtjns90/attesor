#!/bin/sh
# Assemble the macOS runtime tree from tracked sources.
#
# Rebuilds runtime/Apps/*.app from the sources in this directory so a fresh
# checkout can reproduce the working Mac setup without files from a work
# archive. Downloads (sysroots, game data, caches) stay local; this script
# verifies the payloads it expects before creating bundles.
#
# Usage: runtime-src/assemble.sh
set -eu

src="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$src/.." && pwd)"
runtime="$repo/runtime"
apps="$runtime/Apps"

die() { echo "assemble: $*" >&2; exit 1; }

# --- build prerequisites ---------------------------------------------------
[ -x "$repo/reconstruct/oah" ] || {
    echo "assemble: building oah first"
    make -C "$repo/reconstruct" oah
}
[ -x "$repo/reconstruct/oah" ] || die "oah build failed"

# --- icon ------------------------------------------------------------------
mkdir -p "$runtime/icons"
if [ ! -f "$runtime/icons/Penguin.icns" ]; then
    echo "assemble: generating Penguin.icns"
    swift "$src/icons/draw.swift" "$runtime/icons/Penguin.icns" ||
        die "icon generation failed (needs swift)"
fi

# --- the Finder launcher (compiled Swift app) ------------------------------
mkdir -p "$apps/Attesor Linux Launcher.app/Contents/MacOS" \
         "$apps/Attesor Linux Launcher.app/Contents/Resources"
echo "assemble: compiling Launcher.swift"
swiftc -O -o "$apps/Attesor Linux Launcher.app/Contents/MacOS/Launcher" \
    "$src/Launcher.swift" || die "swiftc failed"
cp "$src/apps/Attesor Linux Launcher.plist" \
   "$apps/Attesor Linux Launcher.app/Contents/Info.plist"
cp "$runtime/icons/Penguin.icns" \
   "$apps/Attesor Linux Launcher.app/Contents/Resources/"

# --- program-shortcut syncer ------------------------------------------------
cp "$src/sync-programs.sh" "$runtime/sync-programs.sh"
chmod +x "$runtime/sync-programs.sh"

# --- script-driven app bundles ---------------------------------------------
for name in "Debian Calculator" "Debian Clock" "Debian Eyes" \
            "Debian X Logo" "Freeciv via Attesor"; do
    bundle="$apps/$name.app/Contents"
    mkdir -p "$bundle/MacOS" "$bundle/Resources"
    cp "$src/apps/$name/Info.plist" "$bundle/"
    cp "$src/apps/$name/launch" "$bundle/MacOS/"
    chmod +x "$bundle/MacOS/launch"
    cp "$runtime/icons/Penguin.icns" "$bundle/Resources/"
done

# --- payload verification ---------------------------------------------------
missing=0
need() { [ -e "$1" ] || { echo "assemble: MISSING payload: $1"; missing=1; }; }
need "$runtime/sysroots/freeciv/usr/games/freeciv-sdl2"
need "$runtime/sysroots/freeciv/usr/games/freeciv-server"
need "$runtime/sysroots/freeciv/usr/share/games/freeciv-attesor"
need "$runtime/sysroots/debian-expanded/usr/bin/true"
need "$runtime/sysroots/debian-python/usr/bin/python3.11"
need "$runtime/sysroots/debian-x11"
[ "$missing" = 0 ] || die "payloads missing — fetch sysroots first (see runtime-src/README.md)"

echo "assemble: done — bundles in $apps"
