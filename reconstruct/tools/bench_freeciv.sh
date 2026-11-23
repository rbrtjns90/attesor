#!/bin/sh
# Freeciv performance probe under attesor. Headless (dummy SDL) by default,
# so this measures the CPU-bound phases we can observe without a display:
#
#   T_listen  - server start -> port accepting (ruleset + data load)
#   T_start   - listen -> "Starting game" (map gen + AI setup; skip in FC_SAVE)
#   T_join    - client launch -> PACKET_GAME_INFO (full state + map download)
#   T_turn    - mean wall time between BEGIN_TURN packets at the client
#
# With FC_SAVE=<savefile> the server loads a fixed saved game instead of
# generating a fresh map: phases then measure save parse + join on the
# SAME game every run, removing map-gen variance from comparisons.
#
# FC_FLUSH=1 exports OAH_JIT_FLUSH_DEBUG to both processes and reports
# per-reason flush counts at each phase boundary.
#
# PAN=<seconds> (needs a real display, e.g. XQuartz on DISPLAY=:0): after
# the client joins, repeatedly send Right-arrow to the client window and
# report client CPU burn during the pan burst — the observable proxy for
# frame cost while panning.
#
# Run matrix (set MODE):
#   chain    - default JIT + chaining, fresh OAH_CACHE_DIR
#   nochain  - OAH_JIT_NOCHAIN=1
#   noflags  - OAH_JIT_NOFLAGS=1 (flag liveness off / eager flags)
#   nocache  - OAH_JIT_NOCACHE=1 (persistence disabled, chaining on)
#   warm     - reuse $WARM_CACHE_DIR across runs
#
# Usage: MODE=chain [FC_SAVE=file] [FC_FLUSH=1] [PAN=15] tools/bench_freeciv.sh [sysroot]
set -u

here="$(cd "$(dirname "$0")" && pwd)"
oah="$here/../oah"
root="${1:-$here/../../runtime/sysroots/freeciv}"
mode="${MODE:-chain}"
turns="${TURNS:-4}"
save="${FC_SAVE:-}"
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
[ -n "$save" ] && [ ! -f "$save" ] && { echo "FAIL: FC_SAVE=$save missing"; exit 1; }

export LC_ALL=C DISPLAY=:0 HOME="$work/home"
export FREECIV_DATA_PATH="$root/usr/share/games/freeciv-attesor"
if [ "${PAN:-0}" -gt 0 ]; then
    unset SDL_VIDEODRIVER SDL_RENDER_DRIVER SDL_AUDIODRIVER
    export SDL_AUDIODRIVER=dummy
else
    export SDL_VIDEODRIVER=dummy SDL_RENDER_DRIVER=software SDL_AUDIODRIVER=dummy
fi
mkdir -p "$HOME/.freeciv/saves"

case "$mode" in
    chain)   export OAH_CACHE_DIR="$work/cache" ;;
    nochain) export OAH_CACHE_DIR="$work/cache" OAH_JIT_NOCHAIN=1 ;;
    noflags) export OAH_CACHE_DIR="$work/cache" OAH_JIT_NOFLAGS=1 ;;
    nocache) export OAH_JIT_NOCACHE=1 ;;
    warm)    export OAH_CACHE_DIR="${WARM_CACHE_DIR:-$work/cache-warm}" ;
             mkdir -p "$OAH_CACHE_DIR" ;;
    *) echo "unknown MODE=$mode" >&2; exit 2 ;;
esac
mkdir -p "${OAH_CACHE_DIR:-$work/cache}"
[ "${FC_FLUSH:-0}" = 1 ] && export OAH_JIT_FLUSH_DEBUG=1

rc_src="$here/../../runtime/var/freeciv/home/.freeciv/freeciv-client-rc-3.0"
[ -f "$rc_src" ] && cp "$rc_src" "$HOME/.freeciv/"

port="${FC_BENCH_PORT:-5567}"
server_args="-p $port --bind localhost --saves $HOME/.freeciv/saves -A none"
if [ -n "$save" ]; then
    server_args="$server_args -f $save"
else
    cat > "$work/start.serv" <<SERV
set minplayers 0
set timeout 20
set aifill 5
set size 2
start
SERV
    server_args="$server_args -r $work/start"
fi

now() { python3 -c 'import time; print(time.time())'; }
cpu() { ps -o time= -p "$1" 2>/dev/null | awk -F: '{n=NF; s=0; m=1;
    for (i=n; i>0; i--) { s += $i*m; m *= 60 } print s+0 }'; }
flush_counts() {
    for log in "$server_log" "$client_log"; do
        [ -f "$log" ] && grep "jit flush" "$log" 2>/dev/null
    done | sed -n 's/.*jit flush (\(.*\)):.*/\1/p' | sort | uniq -c | tr '\n' ' '
}
phase() { printf "  [%s] flushes: %s\n" "$1" "$(flush_counts)"; }

t0=$(now)
mkfifo "$work/stdin.fifo"
exec 9<>"$work/stdin.fifo"   # keep the writer end open; EOF would disable stdin
"$oah" --max-insns 18446744073709551615 --sysroot "$root" \
    "$root/usr/games/freeciv-server" $server_args \
    <"$work/stdin.fifo" >"$server_log" 2>&1 & server_pid=$!

n=0
until /usr/bin/nc -z -G 2 localhost "$port" >/dev/null 2>&1; do
    n=$((n + 1)); [ "$n" -lt 240 ] || { echo "FAIL: server never listened"; tail -8 "$server_log"; exit 1; }
    sleep 1
done
t_listen=$(now)
[ "${FC_FLUSH:-0}" = 1 ] && phase listen

if [ -z "$save" ]; then
    n=0
    until grep -q "Starting game" "$server_log" 2>/dev/null; do
        n=$((n + 1)); [ "$n" -lt 120 ] || { echo "FAIL: game never started"; tail -8 "$server_log"; exit 1; }
        sleep 1
    done
    t_start=$(now)
else
    # A loaded save parks in a waiting state until "start" resumes it.
    n=0
    until grep -q "Now accepting new client connections" "$server_log" 2>/dev/null; do
        n=$((n + 1)); [ "$n" -lt 300 ] || { echo "FAIL: save never loaded"; tail -8 "$server_log"; exit 1; }
        sleep 1
    done
    echo "start" >&9
    n=0
    until grep -q "Starting game" "$server_log" 2>/dev/null; do
        n=$((n + 1)); [ "$n" -lt 60 ] || { echo "FAIL: loaded game never started"; tail -8 "$server_log"; exit 1; }
        sleep 1
    done
    t_start=$(now)
fi
[ "${FC_FLUSH:-0}" = 1 ] && phase start

"$oah" --max-insns 18446744073709551615 --sysroot "$root" \
    "$root/usr/games/freeciv-sdl2" -P none --debug v \
    -s localhost -p "$port" -a >"$client_log" 2>&1 & client_pid=$!

n=0
until grep -q "PACKET_GAME_INFO" "$client_log" 2>/dev/null; do
    n=$((n + 1)); [ "$n" -lt 900 ] || { echo "FAIL: no GAME_INFO in 900s"; tail -8 "$client_log"; exit 1; }
    sleep 1
done
t_join=$(now)
join_cpu=$(cpu "$client_pid")
[ "${FC_FLUSH:-0}" = 1 ] && phase join

if [ "${PAN:-0}" -gt 0 ]; then
    osascript -e "tell application \"System Events\" to set frontmost of \
        (first process whose unix id is $client_pid) to true" 2>/dev/null
    idle_cpu0=$(cpu "$client_pid")
    sleep "$PAN"
    idle_cpu1=$(cpu "$client_pid")
    pan_cpu0=$(cpu "$client_pid")
    pan_end=$((PAN))
    keys_sent=0
    pan_samples=""
    prev_cpu=$pan_cpu0
    while [ "$pan_end" -gt 0 ]; do
        key_pids=""
        for k in 124 124 124 124; do  # right arrow x4/s
            osascript -e 'tell application "System Events" to key code 124' \
                >/dev/null 2>&1 &
            key_pids="$key_pids $!"
        done
        wait $key_pids   # NOT bare wait — server/client are also bg jobs
        keys_sent=$((keys_sent + 4))
        cur_cpu=$(cpu "$client_pid")
        pan_samples="$pan_samples $(awk -v a="$prev_cpu" -v b="$cur_cpu" \
            'BEGIN { printf "%.3f", b - a }')"
        prev_cpu=$cur_cpu
        pan_end=$((pan_end - 1))
    done
    pan_cpu1=$cur_cpu
    [ "${FC_FLUSH:-0}" = 1 ] && phase pan
    awk -v a="$idle_cpu0" -v b="$idle_cpu1" -v c="$pan_cpu0" -v d="$pan_cpu1" \
        -v s="$PAN" -v k="$keys_sent" -v samples="$pan_samples" 'BEGIN {
        printf "  idle %ds: client cpu %.1fs (%.1f%% core)\n", s, b - a, (b - a) * 100 / s;
        printf "  pan %ds (%d keys): client cpu %.1fs (%.1f%% core), +%.1fs vs idle\n",
               s, k, d - c, (d - c) * 100 / s, (d - c) - (b - a);
        n = split(samples, v, " ");
        for (i = 1; i <= n; i++) v[i] += 0;
        for (i = 1; i <= n; i++)
            for (j = i + 1; j <= n; j++)
                if (v[j] < v[i]) { t = v[i]; v[i] = v[j]; v[j] = t }
        if (n > 0) {
            med = (n % 2) ? v[(n + 1) / 2] : (v[n / 2] + v[n / 2 + 1]) / 2;
            p95 = v[int(n * 0.95) < 1 ? 1 : int(n * 0.95)];
            printf "  frame cost (cpu/key): median %.0fms p95 %.0fms (n=%d)\n",
                   med * 250, p95 * 250, n;   # /4 keys per sample * 1000
        } }'
fi

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
    [ "${FC_FLUSH:-0}" = 1 ] && phase "turn$i"
done

end_cpu=$(cpu "$client_pid")
awk -v mode="$mode" -v save="${save:+load}" -v t0="$t0" -v tl="$t_listen" \
    -v ts="$t_start" -v tj="$t_join" -v tt="$turn_times" \
    -v jc="${join_cpu:-0}" -v ec="${end_cpu:-0}" 'BEGIN {
    split(tt, a, " ");
    n = length(a) - 1;
    printf "MODE=%s%s  listen=%.1fs  start/load=%.1fs  join=%.1fs  join-cpu=%.1fs\n",
           mode, (save != "" ? "+save" : ""), tl - t0, ts - tl, tj - ts, jc;
    sum = 0;
    for (i = 1; i <= n; i++) {
        d[i] = a[i + 1] - a[i];
        sum += d[i];
        printf "  turn %d: %.1fs\n", i, d[i];
    }
    if (n > 0) {
        for (i = 1; i <= n; i++)
            for (j = i + 1; j <= n; j++)
                if (d[j] < d[i]) { t = d[i]; d[i] = d[j]; d[j] = t }
        med = (n % 2) ? d[(n + 1) / 2] : (d[n / 2] + d[n / 2 + 1]) / 2;
        p95 = d[int(n * 0.95) < 1 ? 1 : int(n * 0.95)];
        printf "MODE=%s  mean turn cadence: %.1fs  median %.1fs  p95 %.1fs  total client cpu=%.1fs\n",
                      mode, sum / n, med, p95, ec;
    }
}'
