#!/bin/sh

WATCH="/root/vpn-watch.sh"
RUNTIME_DIR="/tmp/vpn-watch"
LOCK_DIR="$RUNTIME_DIR/lock"
PID_FILE="$LOCK_DIR/pid"
TAG="vpn-watch-supervisor"

# Installer owns replacement/startup while this lock exists; cron waits.
[ -d /tmp/vpn-watch-installer-lock ] && [ "${1:-}" != "--installer" ] && exit 0
mkdir -p "$RUNTIME_DIR"
# Serialize supervisor launches. A stale startup lock requires inspection rather
# than deleting another process's daemon lock during a startup race.
mkdir "$RUNTIME_DIR/supervisor-start" 2>/dev/null || exit 0
trap 'rmdir "$RUNTIME_DIR/supervisor-start" 2>/dev/null' EXIT INT TERM

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

# The watchdog owns stale daemon-lock recovery; the supervisor must not delete it.
logger -t "$TAG" "vpn-watch is not running; starting daemon" 2>/dev/null || true

(
    trap '' HUP
    exec "$WATCH" daemon
) </dev/null >/dev/null 2>&1 &

exit 0
