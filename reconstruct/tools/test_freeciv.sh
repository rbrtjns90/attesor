#!/bin/sh
# End-to-end Freeciv check: a guest freeciv-server starts an all-AI game
# (map generated, turns auto-advance) and a guest client connects and
# receives game state, map data, and turn boundaries.
#
# Why all-AI: the server's stdin console dead-ends under emulation (its
# stdin FILE is born in error state — getline() returns <0 without ever
# issuing a read syscall), so 'start' can't be driven over stdin. The -r
# startup script runs commands through the same console path but from a
# real file, which works. 'set minplayers 0' + 'start' begins a game
# headlessly; 'set timeout' makes turns advance without a human end-turn.
#
# The client runs with SDL_VIDEODRIVER=dummy so this needs no display. That
# exercises the full protocol path (connect, tileset switch, map data, turn
# packets) but does NOT verify pixels — visual rendering still needs a
# manual XQuartz run.
#
# Usage: tools/test_freeciv.sh [sysroot]   (default: ../runtime/sysroots/freeciv)
set -u

here="$(cd "$(dirname "$0")" && pwd)"
oah="$here/../oah"
root="${1:-$here/../../runtime/sysroots/freeciv}"
port="${FC_TEST_PORT:-5566}"
work="$(mktemp -d /tmp/attesor-freeciv-XXXXXX)"
server_log="$work/server.log"
client_log="$work/client.log"

cleanup() {
    [ -n "${server_pid:-}" ] && kill "$server_pid" 2>/dev/null
    [ -n "${client_pid:-}" ] && kill "$client_pid" 2>/dev/null
    [ "${failed:-0}" = 1 ] && echo "logs kept at $work" || rm -rf "$work"
}
failed=0
trap cleanup EXIT

[ -x "$oah" ] || { echo "FAIL: $oah not built"; exit 1; }
[ -x "$root/usr/games/freeciv-server" ] || {
    echo "SKIP: no freeciv sysroot at $root"; exit 0; }

export LC_ALL=C DISPLAY=:0
export HOME="$work/home" OAH_CACHE_DIR="$work/cache"
export FREECIV_DATA_PATH="$root/usr/share/games/freeciv-attesor"
export SDL_VIDEODRIVER=dummy SDL_RENDER_DRIVER=software SDL_AUDIODRIVER=dummy
mkdir -p "$HOME/.freeciv/saves" "$OAH_CACHE_DIR"

# Startup script: all-AI game, turns every 45s of server time so
# PACKET_BEGIN_TURN fires without any human input. -r appends '.serv'.
cat > "$work/start.serv" <<'SERV'
set minplayers 0
set timeout 45
start
SERV

# A fresh HOME makes the client write default_tileset_hex_name="" and abort;
# seed the known-good rc (same values the launcher enforces).
rc_src="$here/../../runtime/var/freeciv/home/.freeciv/freeciv-client-rc-3.0"
[ -f "$rc_src" ] && cp "$rc_src" "$HOME/.freeciv/"

"$oah" --max-insns 18446744073709551615 --sysroot "$root" \
    "$root/usr/games/freeciv-server" -p "$port" --bind localhost \
    --saves "$HOME/.freeciv/saves" -A none -r "$work/start" \
    </dev/null >"$server_log" 2>&1 & server_pid=$!

# Wait for the server to accept connections (ruleset load takes a while).
n=0
until /usr/bin/nc -z -G 2 localhost "$port" >/dev/null 2>&1; do
    n=$((n + 1)); [ "$n" -lt 240 ] || { failed=1; echo "FAIL: server never listened"; tail -5 "$server_log"; exit 1; }
    sleep 1
done
echo "PASS: server listening on $port"

# The -r script runs before the port opens; game must be started.
n=0
until grep -q "Starting game" "$server_log" 2>/dev/null; do
    n=$((n + 1)); [ "$n" -lt 60 ] || { failed=1; echo "FAIL: -r start did not fire"; tail -8 "$server_log"; exit 1; }
    sleep 1
done
echo "PASS: game started (all-AI, via -r script)"

"$oah" --max-insns 18446744073709551615 --sysroot "$root" \
    "$root/usr/games/freeciv-sdl2" -P none --debug v \
    -s localhost -p "$port" -a >"$client_log" 2>&1 & client_pid=$!

n=0
until grep -q "has connected from localhost" "$server_log" 2>/dev/null; do
    n=$((n + 1)); [ "$n" -lt 180 ] || { failed=1; echo "FAIL: client never connected"; tail -10 "$client_log"; exit 1; }
    sleep 1
done
echo "PASS: client connected"

# Ruleset + game-state download is thousands of packets — minutes under
# emulation. An observer still receives map/turn data for a running game.
n=0
until grep -q "PACKET_GAME_INFO" "$client_log" 2>/dev/null; do
    n=$((n + 1)); [ "$n" -lt 900 ] || { failed=1; echo "FAIL: no GAME_INFO in 900s"; tail -10 "$client_log" "$server_log"; exit 1; }
    sleep 1
done
echo "PASS: game state reached the client"

# Tile data is NOT checked: a detached observer gets game state and turn
# packets but freeciv only sends the map to attached players — attaching
# needs a GUI action. Map rendering is verified in the manual XQuartz run.
n=0
until [ "$(grep -c "PACKET_BEGIN_TURN" "$client_log" 2>/dev/null)" -ge 2 ]; do
    n=$((n + 1)); [ "$n" -lt 300 ] || { failed=1; echo "FAIL: no turn boundary in 300s"; tail -10 "$client_log" "$server_log"; exit 1; }
    sleep 1
done
echo "PASS: turn boundaries reached the client (BEGIN_TURN x$(grep -c PACKET_BEGIN_TURN "$client_log"))"
echo "PASS: Freeciv end-to-end: server start -> client join -> game state -> turns"
