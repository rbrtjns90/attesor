#!/bin/sh
# Regenerate ~/Desktop/linux_progs/{terminal,gui} launchers from the
# Debian sysroot's dpkg database. Every executable a package installs
# lands as a .command: GUI programs get the XQuartz preamble, terminal
# programs exec straight into the guest.
#
# Classification: a program is GUI if a package .desktop file launches
# it (with Terminal not set true); everything else is terminal.
# Files marked "Attesor generated" are refreshed; hand-made launchers
# are left alone.
set -eu

A="$(cd "$(dirname "$0")/.." && pwd -P)"
S="${1:-$A/runtime/sysroots/debian-expanded}"
OUT="${LINUX_PROGS_DIR:-$HOME/Desktop/linux_progs}"
TERM_DIR="$OUT/terminal"
GUI_DIR="$OUT/gui"
MARK="# Attesor generated:"
RUNNER="$A/reconstruct/oah"

[ -d "$S/var/lib/dpkg/info" ] || { echo "no dpkg info in $S" >&2; exit 1; }
mkdir -p "$TERM_DIR" "$GUI_DIR"

# Drop previously generated launchers only.
clean_dir() {
    for f in "$1"/*.command; do
        [ -e "$f" ] || continue
        grep -q "^$MARK" "$f" 2>/dev/null && rm -f "$f"
    done
    return 0
}
clean_dir "$TERM_DIR"
clean_dir "$GUI_DIR"

# --- collect GUI programs from .desktop files -----------------------------
# Maps guest binary path -> display name, for Exec= lines that name an
# executable under the sysroot FHS. Terminal=true entries are skipped.
gui_names_file="$(mktemp -t attesor-gui)"
gui_bins_file="$(mktemp -t attesor-guibins)"
all_bins_file="$(mktemp -t attesor-bins)"
trap 'rm -f "$gui_names_file" "$gui_bins_file" "$all_bins_file"' EXIT
: >"$gui_names_file"; : >"$gui_bins_file"

if [ -d "$S/usr/share/applications" ]; then
    for desktop in "$S/usr/share/applications"/*.desktop; do
        [ -e "$desktop" ] || continue
        grep -qiE '^(NoDisplay|Hidden|Terminal)=true' "$desktop" && continue
        name=$(sed -n 's/^Name=\(.*\)/\1/p' "$desktop" | head -1)
        exec_line=$(sed -n 's/^Exec=\(.*\)/\1/p' "$desktop" | head -1)
        [ -n "$exec_line" ] || continue
        # First token, minus env wrappers and %-field codes.
        bin=$(printf '%s' "$exec_line" | sed 's/%[a-zA-Z]//g' | awk '{print $1}')
        [ -n "$bin" ] || continue
        case "$bin" in /*) ;; *) continue ;; esac
        [ -x "$S$bin" ] || continue
        printf '%s\t%s\n' "$bin" "${name:-$(basename "$bin")}" >>"$gui_names_file"
        printf '%s\n' "$bin" >>"$gui_bins_file"
    done
fi

is_gui() { grep -qxF "$1" "$gui_bins_file" 2>/dev/null; }
gui_name() { awk -F '\t' -v b="$1" '$1==b{print $2; exit}' "$gui_names_file"; }

# --- collect every packaged executable ------------------------------------
bindirs='/usr/bin /usr/sbin /usr/local/bin /usr/games /bin /sbin'
{
    for list in "$S/var/lib/dpkg/info"/*.list; do
        [ -e "$list" ] || continue
        for d in $bindirs; do grep -E "^$d/[^/]+$" "$list" || :; done
    done
} | sort -u >"$all_bins_file"

emit_terminal() {
    local bin="$1"
    local name="$(basename "$bin")"
    cat >"$TERM_DIR/$name.command" <<EOF
#!/bin/sh
$MARK terminal — $bin
A=$A
S=$S
export OAH_CACHE_DIR="\$A/runtime/var/cache/jit" LC_ALL=C
exec "\$A/reconstruct/oah" --sysroot "\$S" "\$S$bin" "\$@"
EOF
    chmod +x "$TERM_DIR/$name.command"
}

emit_gui() {
    local bin="$1" name="$2"
    cat >"$GUI_DIR/$name.command" <<EOF
#!/bin/sh
$MARK gui — $bin
set -e
A=$A
S=$S
display=:0
ready() { /opt/X11/bin/xdpyinfo -display "\$display" >/dev/null 2>&1; }
if ! ready; then
    /usr/bin/open -a XQuartz
    i=0
    until ready; do i=\$((i+1)); [ \$i -lt 30 ] || exit 1; /bin/sleep 1; done
fi
export DISPLAY="\$display" LC_ALL=C OAH_CACHE_DIR="\$A/runtime/var/cache/jit"
exec "\$A/reconstruct/oah" --sysroot "\$S" "\$S$bin" "\$@"
EOF
    chmod +x "$GUI_DIR/$name.command"
}

count_t=0; count_g=0
while IFS= read -r bin; do
    [ -x "$S$bin" ] && [ ! -d "$S$bin" ] || continue
    if is_gui "$bin"; then
        emit_gui "$bin" "$(gui_name "$bin")"
        count_g=$((count_g + 1))
    else
        emit_terminal "$bin"
        count_t=$((count_t + 1))
    fi
done <"$all_bins_file"

echo "linux_progs: $count_t terminal, $count_g gui launchers in $OUT"
