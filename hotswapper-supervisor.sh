#!/bin/sh

WATCH="/root/hotswapper-main.sh"
RUNTIME_DIR="/tmp/hotswapper"
LOCK_DIR="$RUNTIME_DIR/lock"
PID_FILE="$LOCK_DIR/pid"
TAG="hotswapper-supervisor"

mkdir -p "$RUNTIME_DIR"
# Both guards release when their process exits, including SIGKILL.
exec 7>"$RUNTIME_DIR/supervisor.lock" || exit 1
busybox flock -n 7 || exit 0
if [ "${1:-}" != --installer ]; then
    exec 6>"$RUNTIME_DIR/installer.lock" || exit 1
    busybox flock -n -s 6 || exit 0
fi
exec 8>"$RUNTIME_DIR/daemon.lock" || exit 1
busybox flock -n 8 || exit 0
# The daemon acquires its own descriptor. A competing launch simply exits.
exec 8>&-

logger -t "$TAG" "hotswapper is not running; starting daemon" 2>/dev/null || true

(
    trap '' HUP
    exec "$WATCH" daemon
) 6>&- 7>&- </dev/null >/dev/null 2>&1 &

exit 0
