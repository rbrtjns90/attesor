#!/bin/bash
# install.sh — one-liner installer for Attesor.
#
#   curl -fsSL https://raw.githubusercontent.com/rbrtjns90/attesor/main/runtime-src/install.sh | bash
#
# What it does:
#   1. installs XQuartz via Homebrew (needed for graphical Linux apps)
#   2. downloads the latest Attesor DMG from GitHub Releases
#   3. copies Attesor.app to /Applications and opens it
#
# First launch of Attesor.app downloads the Linux runtime itself.
set -euo pipefail

REPO="rbrtjns90/attesor"
say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }

# --- XQuartz via Homebrew ----------------------------------------------------
if [ -x "/Applications/XQuartz.app/Contents/MacOS/X11.bin" ] \
   || [ -d "/opt/X11" ]; then
    say "XQuartz already installed"
elif command -v brew >/dev/null 2>&1; then
    say "Installing XQuartz via Homebrew (one-time, ~150 MB)…"
    brew install --cask xquartz || warn "XQuartz install failed — GUI apps need it; retry: brew install --cask xquartz"
else
    warn "Homebrew not found and XQuartz not installed."
    warn "GUI apps need it. Install either way:"
    warn "  Homebrew:  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    warn "  Then:      brew install --cask xquartz"
fi

# --- Attesor.app from GitHub Releases ----------------------------------------
say "Fetching latest Attesor release…"
tag="$(curl -fsSL -o /dev/null -w '%{url_effective}' \
       "https://github.com/$REPO/releases/latest" | sed 's:.*/::')"
[ -n "$tag" ] || { warn "couldn't resolve latest release"; exit 1; }
say "Latest release: $tag"

dmg="Attesor-$tag.dmg"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
say "Downloading $dmg…"
curl -fSL --progress-bar -o "$tmp/$dmg" \
    "https://github.com/$REPO/releases/download/$tag/$dmg"

say "Mounting DMG…"
mnt="$(hdiutil attach -nobrowse -readonly -mountpoint /tmp/attesor-mnt "$tmp/$dmg" >/dev/null && echo /tmp/attesor-mnt)"

dest="/Applications/Attesor.app"
rm -rf "$dest"
cp -R "$mnt/Attesor.app" "$dest"
hdiutil detach "$mnt" >/dev/null 2>&1 || true
xattr -dr com.apple.quarantine "$dest" 2>/dev/null || true

say "Installed $dest"
open "$dest"
echo
echo "Attesor is in /Applications. First launch downloads the Linux"
echo "runtime (~350 MB) — after that it works like a normal Mac app."
