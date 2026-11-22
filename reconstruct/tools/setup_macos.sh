#!/bin/sh
set -eu

gui=false
dry_run=false
sysroot=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --gui) gui=true ;;
        --dry-run) dry_run=true ;;
        --sysroot)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                echo "--sysroot requires a new directory." >&2
                exit 2
            fi
            sysroot=$2
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--gui] [--sysroot DIR] [--dry-run]"
            echo "Check Apple Silicon build tools, optionally install XQuartz, and unpack a Debian x86-64 sysroot."
            exit 0 ;;
        *)
            echo "Unknown option $1" >&2
            exit 2 ;;
    esac
    shift
done
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
    echo "This setup is for Apple Silicon macOS. Run it in an ARM64 shell." >&2
    exit 1
fi
if ! xcode-select -p >/dev/null 2>&1; then
    echo "Install the Xcode command-line tools with xcode-select --install, then rerun this script." >&2
    exit 1
fi

if "$gui" || [ -n "$sysroot" ]; then
    brew=$(command -v brew || true)
    if [ -z "$brew" ] && [ -x /opt/homebrew/bin/brew ]; then
        brew=/opt/homebrew/bin/brew
    fi
    if [ -z "$brew" ]; then
        echo "Install Homebrew from https://brew.sh/ and rerun this script." >&2
        exit 1
    fi
fi

if "$gui"; then
    if [ -x /opt/X11/bin/xdpyinfo ] && [ -d /Applications/Utilities/XQuartz.app ]; then
        echo "XQuartz is already installed."
    elif "$dry_run"; then
        printf 'Would run %s install --cask xquartz\n' "$brew"
    else
        "$brew" install --cask xquartz
    fi
fi

if [ -n "$sysroot" ]; then
    image=docker.io/library/debian:bookworm-slim
    if "$dry_run"; then
        printf 'Would install crane if needed and unpack the linux/amd64 filesystem from %s into %s.\n'             "$image" "$sysroot"
    else
        parent=$(cd "$(dirname "$sysroot")" && pwd)
        destination=$parent/$(basename "$sysroot")
        if [ -e "$destination" ] || [ -L "$destination" ]; then
            echo "Choose a new sysroot directory. $destination already exists." >&2
            exit 1
        fi
        crane=$(command -v crane || true)
        if [ -z "$crane" ]; then
            "$brew" install crane
            crane=$("$brew" --prefix crane)/bin/crane
        fi
        stage=$(mktemp -d "$parent/.attesor-sysroot.XXXXXX")
        trap 'rm -r "$stage"' EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM
        mkdir "$stage/root"
        "$crane" export --platform linux/amd64 "$image" "$stage/debian.tar"
        tar -xf "$stage/debian.tar" --exclude dev --exclude './dev' -C "$stage/root"
        loader=usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
        if [ ! -f "$stage/root/$loader" ]; then
            echo "The Debian image did not contain the expected x86-64 loader." >&2
            exit 1
        fi
        if [ -L "$stage/root/lib64" ]; then
            rm "$stage/root/lib64"
        fi
        mkdir -p "$stage/root/lib64"
        if [ -L "$stage/root/lib64/ld-linux-x86-64.so.2" ]; then
            rm "$stage/root/lib64/ld-linux-x86-64.so.2"
        fi
        ln -s "../$loader" "$stage/root/lib64/ld-linux-x86-64.so.2"
        if [ -e "$destination" ] || [ -L "$destination" ]; then
            echo "The destination appeared during setup. Choose a new sysroot directory." >&2
            exit 1
        fi
        mv "$stage/root" "$destination"
        printf 'Debian sysroot ready at %s\n' "$destination"
    fi
fi

echo "Build Attesor with make from the repository root."
echo "For dynamically linked programs, pass --sysroot DIR with the executable's x86-64 Linux loader and libraries."
