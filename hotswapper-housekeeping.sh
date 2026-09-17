#!/bin/sh

GUARD_FILE="/root/hotswapper/reboot-guards.tsv"
STATE_FILE="/root/hotswapper/state/housekeeping-last-date"
TAG="hotswapper-housekeeping"

HOTSWAPPER="/root/hotswapper-main.sh"
VPN_RUNTIME_DIR="/tmp/hotswapper"
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

    # A missing, unreadable or malformed guard file postpones reboot.
    # An explicitly empty file represents zero protected devices.
    [ -r "$GUARD_FILE" ] || { logger -t "$TAG" "Guard configuration unavailable; postponing."; exit 1; }
    awk -F '\t' '
        NF != 2 || $1 !~ /^[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]$/ {bad=1}
        {n=split($2,a,"."); if(n!=4) bad=1; for(i=1;i<=n;i++) if(a[i] !~ /^[0-9]+$/ || a[i]>255) bad=1}
        END {exit bad}
    ' "$GUARD_FILE" || { logger -t "$TAG" "Invalid guard configuration; postponing."; exit 1; }
    while IFS="$(printf '\t')" read -r TARGET_MAC TARGET_IP; do
        if ping -c 2 -W 2 "$TARGET_IP" >/dev/null 2>&1; then
            logger -t "$TAG" "Protected device responded; reboot postponed."
            [ "$MODE" = "--test" ] && echo "Protected device responded; WOULD postpone."
            exit 0
        fi
        # A failed ICMP probe refreshes ARP. Unknown/error state is conservative.
        NEIGH="$(ip neigh show "$TARGET_IP")" || { logger -t "$TAG" "Neighbour lookup failed; postponing."; exit 1; }
        if echo "$NEIGH" | grep -Fqi "$TARGET_MAC" && ! echo "$NEIGH" | grep -Eq 'FAILED|INCOMPLETE'; then
            logger -t "$TAG" "Protected MAC detected; reboot postponed."
            [ "$MODE" = "--test" ] && echo "Protected MAC detected; WOULD postpone."
            exit 0
        fi
    done < "$GUARD_FILE"
    if [ "$MODE" = "--test" ]; then
        echo "No protected device detected; WOULD reboot."
        exit 0
    fi
else
    logger -t "$TAG" "FORCE mode requested; bypassing daily marker and protected-device presence checks."
    echo "FORCE mode: bypassing daily marker and protected-device presence checks."
fi

# Before reboot, give a sticky Tier 2 session one deliberate chance to return
# to Tier 1. The actual VPN manipulation is still performed by hotswapper.
if [ -x "$HOTSWAPPER" ]; then
    mkdir -p "$VPN_RUNTIME_DIR"
    rm -f "$VPN_RESULT_FILE"

    vpn_pid=""
    [ -f "$VPN_PID_FILE" ] && vpn_pid="$(cat "$VPN_PID_FILE" 2>/dev/null)"

    if [ -n "$vpn_pid" ] && kill -0 "$vpn_pid" 2>/dev/null; then
        token="reboot-$$-$(date +%s)"
        printf '%s\n' "$token" > "$VPN_REQUEST_FILE"

        logger -t "$TAG" "Requested pre-reboot Tier 2 -> Tier 1 recovery from hotswapper daemon."
        echo "Waiting for hotswapper pre-reboot recovery result..."

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
        logger -t "$TAG" "hotswapper daemon not running; performing pre-reboot recovery synchronously."
        echo "hotswapper daemon not running; attempting synchronous pre-reboot recovery."

        if "$HOTSWAPPER" pre_reboot_recover; then
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
    logger -t "$TAG" "No protected device detected; rebooting router."
fi

/sbin/reboot
