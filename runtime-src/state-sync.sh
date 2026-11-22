#!/bin/sh
# state-sync.sh — rebuild runtime/var/state.sqlite, the host-side index of
# installed Linux software, from the canonical sources inside each sysroot:
# dpkg's status/list files, .desktop files, and bin-dir contents.
#
# Sync model:
#   native installs/removals (native-deb-install.sh, apt-install.sh) call
#     this script after finishing.
#   guest installs (apt/dpkg inside the Debian shell) trigger the
#     dpkg post-invoke hook installed below, which touches
#     /var/lib/attesor/state-dirty inside the sysroot; the next host-side
#     sync (app refresh, launcher run, or manual call) sees the marker and
#     rebuilds.
#   The GUI reads the sqlite tables instead of rescanning the sysroot.
#
# Usage: state-sync.sh [-f|--force] [reason]
set -u

A="$(cd "$(dirname "$0")/.." && pwd)"
SYSROOTS="$A/runtime/sysroots"
DB="$A/runtime/var/state.sqlite"
SQLITE=/usr/bin/sqlite3
REASON="${2:-${1:-manual}}"
FORCE=0
case "${1:-}" in -f|--force) FORCE=1; REASON="${2:-manual}" ;; esac

esc() { printf '%s' "$1" | sed "s/'/''/g"; }

# --- dpkg post-invoke hook: guest-side changes drop a marker -------------
for root in "$SYSROOTS"/*/; do
    [ -d "$root/var/lib/dpkg" ] || continue
    mkdir -p "$root/var/lib/attesor" "$root/etc/dpkg/dpkg.cfg.d"
    hook="$root/etc/dpkg/dpkg.cfg.d/99attesor"
    [ -f "$hook" ] || printf 'post-invoke=/usr/bin/touch /var/lib/attesor/state-dirty 2>/dev/null || true\n' >"$hook"
done

# --- early exit when nothing changed ------------------------------------
dirty=0
[ -f "$DB" ] || dirty=1
[ "$FORCE" = 1 ] && dirty=1
for root in "$SYSROOTS"/*/; do
    [ -f "$root/var/lib/attesor/state-dirty" ] && dirty=1
    status="$root/var/lib/dpkg/status"
    [ -f "$status" ] && [ "$status" -nt "$DB" ] && dirty=1
    apps="$root/usr/share/applications"
    if [ -d "$apps" ]; then
        for d in "$apps"/*.desktop; do
            [ -e "$d" ] || continue
            [ "$d" -nt "$DB" ] && dirty=1
        done
    fi
done
[ "$dirty" = 0 ] && exit 0

# --- scan sysroots into TSV streams --------------------------------------
pkg_tsv=$(mktemp -t attesor-pkg.XXXXXX)
prog_tsv=$(mktemp -t attesor-prog.XXXXXX)
trap 'rm -f "$pkg_tsv" "$prog_tsv" "$pkg_tsv.sql"' EXIT

for root in "$SYSROOTS"/*/; do
    sname="$(basename "$root")"
    # .desktop -> GUI binaries (binary<TAB>display name)
    gui_tsv=$(mktemp -t attesor-gui.XXXXXX)
    apps="$root/usr/share/applications"
    if [ -d "$apps" ]; then
        for d in "$apps"/*.desktop; do
            [ -f "$d" ] || continue
            grep -qiE '^(Hidden|NoDisplay|Terminal)=true' "$d" && continue
            name=$(sed -n 's/^Name=\(.*\)/\1/p' "$d" | head -1 | tr -d '\r')
            exec_line=$(sed -n 's/^Exec=\(.*\)/\1/p' "$d" | head -1 | tr -d '\r')
            [ -n "$exec_line" ] || continue
            # first token, %-codes and env wrappers stripped
            set -- $exec_line
            while [ $# -gt 0 ]; do
                case "$1" in
                    env|*=*|-*) shift ;;
                    *) break ;;
                esac
            done
            [ $# -gt 0 ] || continue
            bin="${1%%%[a-zA-Z]}"
            case "$bin" in
                /*) ;;
                *) for bd in /usr/bin /usr/games /usr/local/bin /usr/sbin /bin /sbin; do
                       [ -x "$root$bd/$bin" ] && { bin="$bd/$bin"; break; }
                   done ;;
            esac
            case "$bin" in /*) [ -x "$root$bin" ] || continue ;; *) continue ;; esac
            printf '%s\t%s\n' "$bin" "${name:-$(basename "$bin")}" >>"$gui_tsv"
        done
    fi

    if [ -f "$root/var/lib/dpkg/status" ]; then
        # dpkg-managed: packages table + every packaged executable.
        awk -v RS='' -F'\n' '
            /Status: install ok installed/ {
                pkg=""; ver=""; arch=""
                for (i=1;i<=NF;i++) {
                    if ($i ~ /^Package: /)      pkg=substr($i,10)
                    if ($i ~ /^Version: /)      ver=substr($i,10)
                    if ($i ~ /^Architecture: /) arch=substr($i,14)
                }
                if (pkg != "") printf "%s\t%s\t%s\n", pkg, ver, arch
            }' "$root/var/lib/dpkg/status" >>"$pkg_tsv.$$"
        # reformat with sysroot column
        awk -F'\t' -v s="$sname" '{printf "%s\t%s\t%s\t%s\n", s, $1, $2, $3}' \
            "$pkg_tsv.$$" >>"$pkg_tsv"
        rm -f "$pkg_tsv.$$"

        for list in "$root/var/lib/dpkg/info/"*.list; do
            [ -f "$list" ] || continue
            pkg=$(basename "$list" .list); pkg=${pkg%%:*}
            grep -E '^/(usr/)?(s?bin|games)/[^/]+$|^/usr/local/bin/[^/]+$' "$list" |
            while read -r path; do
                [ -x "$root$path" ] && [ ! -d "$root$path" ] || continue
                if grep -qF "$path	" "$gui_tsv"; then
                    kind=gui
                    disp=$(awk -F'\t' -v p="$path" '$1==p {print $2; exit}' "$gui_tsv")
                else
                    kind=terminal
                    disp=$(basename "$path")
                fi
                printf '%s\t%s\t%s\t%s\t%s\n' "$sname" "$path" "$disp" "$kind" "$pkg" >>"$prog_tsv"
            done
        done
    else
        # Hand-built sysroot: bin-dir scan, GUI via .desktop or ELF NEEDED.
        for bd in /usr/bin /usr/sbin /usr/local/bin /usr/games /bin /sbin; do
            [ -d "$root$bd" ] || continue
            for f in "$root$bd"/*; do
                [ -x "$f" ] && [ ! -d "$f" ] || continue
                path="$bd/$(basename "$f")"
                if grep -qF "$path	" "$gui_tsv"; then
                    kind=gui
                    disp=$(awk -F'\t' -v p="$path" '$1==p {print $2; exit}' "$gui_tsv")
                elif xcrun llvm-objdump -p "$f" 2>/dev/null |
                     grep NEEDED | grep -qE 'libX11|libXaw|libXt\.|libxcb|libgtk|libgdk|libQt|libSDL|libglfw|libGL\.|libEGL|libvulkan|libwayland-client'; then
                    kind=gui
                    disp=$(basename "$path")
                else
                    kind=terminal
                    disp=$(basename "$path")
                fi
                printf '%s\t%s\t%s\t%s\t%s\n' "$sname" "$path" "$disp" "$kind" "" >>"$prog_tsv"
            done
        done
    fi
    rm -f "$gui_tsv"
done

# --- rebuild tables atomically -------------------------------------------
mkdir -p "$(dirname "$DB")"
now=$(date +%s)
{
cat <<'SQL'
BEGIN;
CREATE TABLE IF NOT EXISTS packages (
    sysroot TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    arch TEXT,
    source TEXT DEFAULT '',
    installed_at INTEGER,
    PRIMARY KEY (sysroot, name)
);
CREATE TABLE IF NOT EXISTS programs (
    sysroot TEXT NOT NULL,
    binary TEXT NOT NULL,
    name TEXT,
    kind TEXT NOT NULL,
    package TEXT DEFAULT '',
    PRIMARY KEY (sysroot, binary)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    action TEXT NOT NULL,
    detail TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
DELETE FROM programs;
SQL
# keep package install history: new rows get installed_at, existing keep it
sort -u "$prog_tsv" | while IFS="$(printf '\t')" read -r s b n k p; do
    printf "INSERT INTO programs VALUES ('%s','%s','%s','%s','%s');\n" \
        "$(esc "$s")" "$(esc "$b")" "$(esc "$n")" "$(esc "$k")" "$(esc "$p")"
done
sort -u "$pkg_tsv" | while IFS="$(printf '\t')" read -r s n v a; do
    printf "INSERT INTO packages(sysroot,name,version,arch,installed_at) VALUES ('%s','%s','%s','%s',%s) ON CONFLICT(sysroot,name) DO UPDATE SET version=excluded.version, arch=excluded.arch;\n" \
        "$(esc "$s")" "$(esc "$n")" "$(esc "$v")" "$(esc "$a")" "$now"
done
# drop packages no longer installed: rebuild a live-name table
echo "CREATE TEMP TABLE live(sysroot TEXT, name TEXT);"
sort -u "$pkg_tsv" | while IFS="$(printf '\t')" read -r s n v a; do
    printf "INSERT INTO live VALUES ('%s','%s');\n" "$(esc "$s")" "$(esc "$n")"
done
cat <<SQL
DELETE FROM packages WHERE NOT EXISTS (
    SELECT 1 FROM live WHERE live.sysroot=packages.sysroot AND live.name=packages.name);
INSERT INTO events(ts,action,detail) VALUES ($now,'sync','$(esc "$REASON")');
INSERT INTO meta(key,value) VALUES ('last_sync','$now')
    ON CONFLICT(key) DO UPDATE SET value=excluded.value;
COMMIT;
SQL
} | "$SQLITE" "$DB" || exit 1

# clear guest-side dirty markers now that the index is current
for root in "$SYSROOTS"/*/; do
    rm -f "$root/var/lib/attesor/state-dirty"
done
exit 0
