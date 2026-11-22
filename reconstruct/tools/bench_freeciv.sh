#!/bin/sh
# Freeciv performance probe under attesor. Headless (dummy SDL), so this
# measures the CPU-bound phases we can observe without a display:
#
#   T_listen  - server start -> port accepting (ruleset + data load)
#   T_start   - listen -> "Starting game" (map gen + AI setup)
#   T_turn    - mean wall time between BEGIN_TURN packets at the client
#   T_join    - client launch -> PACKET_GAME_INFO (full state download)
#
# Run matrix (set MODE):
#   chain    - default JIT + chaining, fresh OAH_CACHE_DIR (cold then warm
#              in-run as fragments persist)
#   nochain  - OAH_JIT_NOCHAIN=1
#   nocache  - OAH_JIT_NOCACHE=1 (persistence disabled, chaining on)
#   warm     - reuse $WARM_CACHE_DIR across runs
#
# Usage: MODE=chain tools/bench_freeciv.sh [sysroot]
set -u

here="$(cd "$(dirname "$0")" && pwd)"
oah="$here/../oah"
root="${1:-$here/../../runtime/sysroots/freeciv}"
mode="${MODE:-chain}"
turns="${TURNS:-4}"
work="$(mktemp -d /tmp/attesor-fcbench-XXXXXX)"
server_log="$work/server.log"
client_log="$work/client.log"

cleanup() {
    [ -n "${server_pid:-}" ] && kill "$server_pid" 2>/dev/null
    [ -n "${client_pid:-}" ] && kill "$client_pid" 2>/dev/null
    echo "logs: $work"
}
trap cleanup EXIT

[ -x "$oah" ] || { echo "FAIL: $oah not built"; exit 1; }
[ -x "$root/usr/games/freeciv-server" ] || {
    echo "SKIP: no freeciv sysroot at $root"; exit 0; }

export LC_ALL=C DISPLAY=:0 HOME="$work/home"
export FREECIV_DATA_PATH="$root/usr/share/games/freeciv-attesor"
export SDL_VIDEODRIVER=dummy SDL_RENDER_DRIVER=software SDL_AUDIODRIVER=dummy
mkdir -p "$HOME/.freeciv/saves"

case "$mode" in
    chain)   export OAH_CACHE_DIR="$work/cache" ;;
    nochain) export OAH_CACHE_DIR="$work/cache" OAH_JIT_NOCHAIN=1 ;;
    nocache) export OAH_JIT_NOCACHE=1 ;;
    warm)    export OAH_CACHE_DIR="${WARM_CACHE_DIR:-$work/cache-warm}" ;
             mkdir -p "$OAH_CACHE_DIR" ;;
    *) echo "unknown MODE=$mode" >&2; exit 2 ;;
esac
mkdir -p "${OAH_CACHE_DIR:-$work/cache}"

rc_src="$here/../../runtime/var/freeciv/home/.freeciv/freeciv-client-rc-3.0"
[ -f "$rc_src" ] && cp "$rc_src" "$HOME/.freeciv/"

cat > "$work/start.serv" <<SERV
set minplayers 0
set timeout 20
set aifill 5
set size 2
start
SERV

now() { python3 -c 'import time; print(time.time())'; }

port="${FC_BENCH_PORT:-5567}"
t0=$(now)
"$oah" --max-insns 18446744073709551615 --sysroot "$root" \
    "$root/usr/games/freeciv-server" -p "$port" --bind localhost \
    --saves "$HOME/.freeciv/saves" -A none -r "$work/start" \
    </dev/null >"$server_log" 2>&1 & server_pid=$!

n=0
until /usr/bin/nc -z -G 2 localhost "$port" >/dev/null 2>&1; do
    n=$((n + 1)); [ "$n" -lt 240 ] || { echo "FAIL: server never listened"; tail -8 "$server_log"; exit 1; }
    sleep 1
done
t_listen=$(now)

n=0
until grep -q "Starting game" "$server_log" 2>/dev/null; do
    n=$((n + 1)); [ "$n" -lt 120 ] || { echo "FAIL: game never started"; tail -8 "$server_log"; exit 1; }
    sleep 1
done
t_start=$(now)

"$oah" --max-insns 18446744073709551615 --sysroot "$root" \
    "$root/usr/games/freeciv-sdl2" -P none --debug v \
    -s localhost -p "$port" -a >"$client_log" 2>&1 & client_pid=$!

n=0
until grep -q "PACKET_GAME_INFO" "$client_log" 2>/dev/null; do
    n=$((n + 1)); [ "$n" -lt 900 ] || { echo "FAIL: no GAME_INFO in 900s"; tail -8 "$client_log"; exit 1; }
    sleep 1
done
t_join=$(now)

# Time the next $turns turn boundaries (BEGIN_TURN packets at the client).
turn_times=""
i=0
while [ "$i" -lt "$turns" ]; do
    i=$((i + 1))
    n=0
    until [ "$(grep -c "PACKET_BEGIN_TURN" "$client_log" 2>/dev/null)" -ge "$i" ]; do
        n=$((n + 1)); [ "$n" -lt 300 ] || { echo "FAIL: turn $i never arrived"; exit 1; }
        sleep 1
    done
    turn_times="$turn_times $(now)"
done

awk -v mode="$mode" -v t0="$t0" -v tl="$t_listen" -v ts="$t_start" \
    -v tj="$t_join" -v tt="$turn_times" 'BEGIN {
    split(tt, a, " ");
    n = length(a) - 1;
    printf "MODE=%s  listen=%.1fs  start=%.1fs  join=%.1fs\n",
           mode, tl - t0, ts - tl, tj - ts;
    sum = 0;
    for (i = 1; i <= n; i++) {
        d = a[i + 1] - a[i];
        sum += d;
        printf "  turn %d: %.1fs\n", i, d;
    }
    if (n > 0) printf "MODE=%s  mean turn cadence: %.1fs\n", mode, sum / n;
}'
