#!/bin/sh

WATCH="/root/vpn-watch.sh"
RUNTIME_DIR="/tmp/vpn-watch"
LOCK_DIR="$RUNTIME_DIR/lock"
PID_FILE="$LOCK_DIR/pid"
TAG="vpn-watch-supervisor"

mkdir -p "$RUNTIME_DIR"

pid_is_our_daemon() {
    local pid="$1" cmd=""
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    [ -r "/proc/$pid/cmdline" ] || return 1
    cmd="$(tr '\000' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
    echo "$cmd" | grep -Fq '/root/vpn-watch.sh' || return 1
    echo "$cmd" | grep -Fq 'daemon' || return 1
    return 0
}

if [ -f "$PID_FILE" ]; then
    pid="$(cat "$PID_FILE" 2>/dev/null)"
    if pid_is_our_daemon "$pid"; then
        exit 0
    fi
fi

rm -rf "$LOCK_DIR" 2>/dev/null
logger -t "$TAG" "vpn-watch is not running; starting daemon" 2>/dev/null || true

(
    trap '' HUP
    exec "$WATCH" daemon
) </dev/null >/dev/null 2>&1 &

exit 0
