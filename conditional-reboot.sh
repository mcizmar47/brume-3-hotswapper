#!/bin/sh

TARGET_IP="192.168.8.107"
TARGET_MAC="10:ff:e0:82:c8:96"
STATE_FILE="/root/.conditional-reboot-last-date"
TAG="conditional-reboot"

VPN_WATCH="/root/vpn-watch.sh"
VPN_RUNTIME_DIR="/tmp/vpn-watch"
VPN_PID_FILE="$VPN_RUNTIME_DIR/lock/pid"
VPN_REQUEST_FILE="$VPN_RUNTIME_DIR/pre-reboot-request"
VPN_RESULT_FILE="$VPN_RUNTIME_DIR/pre-reboot-result"
VPN_REQUEST_TIMEOUT=75

TODAY="$(date +%F)"
MODE="${1:-normal}"

case "$MODE" in
    normal|--test|--force) ;;
    *)
        echo "Usage: $0 [--test|--force]"
        exit 2
        ;;
esac

if [ "$MODE" != "--force" ]; then
    # Already rebooted today.
    if [ -f "$STATE_FILE" ] && [ "$(cat "$STATE_FILE")" = "$TODAY" ]; then
        logger -t "$TAG" "Router already rebooted today; skipping."
        [ "$MODE" = "--test" ] && echo "Router already rebooted today; WOULD skip."
        exit 0
    fi

    # Try ping first. This may fail if Windows blocks ICMP.
    if ping -c 2 -W 2 "$TARGET_IP" >/dev/null 2>&1; then
        logger -t "$TAG" "DESKTOP-EII167B responded to ping; reboot postponed."
        [ "$MODE" = "--test" ] && echo "DESKTOP-EII167B responded to ping; WOULD postpone."
        exit 0
    fi

    # The failed/blocked ICMP attempt above still forces Linux to refresh ARP/
    # neighbour resolution. If the expected MAC is known and the neighbour is
    # not explicitly FAILED/INCOMPLETE, be conservative and treat the PC as
    # present. A false positive merely postpones the reboot until the next hour.
    NEIGH="$(ip neigh show "$TARGET_IP")"

    if echo "$NEIGH" | grep -Fqi "$TARGET_MAC" && \
       ! echo "$NEIGH" | grep -Eq 'FAILED|INCOMPLETE'; then
        logger -t "$TAG" "DESKTOP-EII167B MAC detected on LAN (neigh: $NEIGH); reboot postponed."
        [ "$MODE" = "--test" ] && echo "DESKTOP-EII167B MAC detected on LAN; WOULD postpone. [$NEIGH]"
        exit 0
    fi

    if [ "$MODE" = "--test" ]; then
        logger -t "$TAG" "DESKTOP-EII167B not detected; WOULD reboot."
        echo "DESKTOP-EII167B not detected; WOULD reboot."
        exit 0
    fi
else
    logger -t "$TAG" "FORCE mode requested; bypassing daily marker and desktop-presence checks."
    echo "FORCE mode: bypassing daily marker and desktop-presence checks."
fi

# Before reboot, give a sticky Tier 2 session one deliberate chance to return
# to Tier 1. The actual VPN manipulation is still performed by vpn-watch.
if [ -x "$VPN_WATCH" ]; then
    mkdir -p "$VPN_RUNTIME_DIR"
    rm -f "$VPN_RESULT_FILE"

    vpn_pid=""
    [ -f "$VPN_PID_FILE" ] && vpn_pid="$(cat "$VPN_PID_FILE" 2>/dev/null)"

    if [ -n "$vpn_pid" ] && kill -0 "$vpn_pid" 2>/dev/null; then
        token="reboot-$$-$(date +%s)"
        printf '%s\n' "$token" > "$VPN_REQUEST_FILE"

        logger -t "$TAG" "Requested pre-reboot Tier 2 -> Tier 1 recovery from vpn-watch daemon."
        echo "Waiting for vpn-watch pre-reboot recovery result..."

        waited=0
        result=""
        while [ "$waited" -lt "$VPN_REQUEST_TIMEOUT" ]; do
            if [ -f "$VPN_RESULT_FILE" ]; then
                result="$(cat "$VPN_RESULT_FILE" 2>/dev/null)"
                case "$result" in
                    "$token|"*)
                        break
                        ;;
                esac
            fi
            sleep 1
            waited=$((waited + 1))
        done

        case "$result" in
            "$token|0")
                logger -t "$TAG" "Pre-reboot VPN recovery completed successfully."
                echo "Pre-reboot VPN recovery completed successfully."
                ;;
            "$token|"*)
                logger -t "$TAG" "Pre-reboot VPN recovery completed with confirmed failure; proceeding with reboot."
                echo "Pre-reboot VPN recovery failed; proceeding with reboot."
                ;;
            *)
                logger -t "$TAG" "Pre-reboot VPN recovery did not answer within ${VPN_REQUEST_TIMEOUT}s; proceeding with reboot."
                echo "Pre-reboot VPN recovery timed out; proceeding with reboot."
                ;;
        esac
    else
        logger -t "$TAG" "vpn-watch daemon not running; performing pre-reboot recovery synchronously."
        echo "vpn-watch daemon not running; attempting synchronous pre-reboot recovery."

        if "$VPN_WATCH" pre_reboot_recover; then
            logger -t "$TAG" "Synchronous pre-reboot VPN recovery completed successfully."
        else
            logger -t "$TAG" "Synchronous pre-reboot VPN recovery completed with failure; proceeding with reboot."
        fi
    fi
fi

echo "$TODAY" > "$STATE_FILE"
sync

if [ "$MODE" = "--force" ]; then
    logger -t "$TAG" "FORCE mode: pre-reboot VPN handling finished; rebooting router."
    echo "FORCE mode: pre-reboot VPN handling finished; rebooting router."
else
    logger -t "$TAG" "DESKTOP-EII167B not detected; rebooting router."
fi

/sbin/reboot
