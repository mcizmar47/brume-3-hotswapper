#!/bin/sh

# GL.iNet / NordVPN three-slot watchdog with owned hot candidates
# - one CURRENT tunnel
# - one hot DOWNTIER on the next lower tier
# - a directional UPTIER candidate, never a permanently assigned worker slot
#
# User-facing major tiers:
#   1 Preferred locations from generated configuration
#   2 Ordered sticky fallback locations
#   3 Ordered last-resort locations
#
# Recovery policy:
#   - Tier 1: sticky; no recovery work
#   - Tier 2: prepare best higher rank; promote upward only on CURRENT failure
#   - Tier 3: may recover only to Tier 1 or Tier 2
#   - Offline: recover best-to-worst across all configured ranks
#
# The hot downtier is always the next configured LOWER internal rank.
# Notifications report MAJOR tier changes and recovery from a WAN outage.

LOCATION_FILE="/root/hotswapper/hotswapper-locations.tsv"
SLOTS="wgclient1 wgclient2 wgclient3"

PERSIST_DIR="/root/hotswapper/state"
RUNTIME_DIR="/tmp/hotswapper"
STATE_FILE="$RUNTIME_DIR/state"
LOG_FILE="/root/hotswapper/log/hotswapper.log"
LOCK_DIR="$RUNTIME_DIR/lock"
BACKOFF_FILE="$RUNTIME_DIR/nord-backoff-until"
LAST_UPTIER_FILE="$RUNTIME_DIR/last-recovery"
WAN_STATE_FILE="$RUNTIME_DIR/wan-state"
WAN_PENDING_FILE="$RUNTIME_DIR/wan-notification-pending"
WAN_CYCLE_RESULT=""
PRE_REBOOT_REQUEST_FILE="$RUNTIME_DIR/pre-reboot-request"
PRE_REBOOT_RESULT_FILE="$RUNTIME_DIR/pre-reboot-result"
TEST_FAILOVER_REQUEST_FILE="$RUNTIME_DIR/test-failover-request"
TEST_FAILOVER_RESULT_FILE="$RUNTIME_DIR/test-failover-result"
TEST_FAILOVER_TIMEOUT=90

# Required private configuration and runtime defaults.
CONFIG_FILE="/root/hotswapper/hotswapper.conf"

DETECTOR_NOW=0
NEXT_STANDBY_CHECK=0
WAKE_REQUESTED=0
DELAY_PID=""
POLICY_SECTION=""
DETECTOR_ENABLED=0
IN_DETECTOR=0
DETECT_CURRENT=""
DETECT_UP=""
DETECT_DOWN=""
FAST_FAILURES=0
SLOW_REQUESTED=0
DETECT_FAILED=0
SLOW_PID=""
PROMOTION_EPOCH=0

[ -r "$CONFIG_FILE" ] && sh -n "$CONFIG_FILE" || { echo "Missing or malformed runtime configuration" >&2; exit 1; }
. "$CONFIG_FILE" || exit 1
# Reject missing, non-decimal and oversized values before shell arithmetic.
for value in "$LOOP_SECONDS" "$UPTIER_INTERVAL" "$CONNECT_TIMEOUT" "$HANDSHAKE_MAX_AGE" "$DOWNTIER_ATTEMPTS" "$KEEPALIVE_PROBE_INTERVAL" "$KEEPALIVE_PROBE_TIMEOUT" "$PATH_FAILURE_THRESHOLD" "$LOG_MAX_BYTES" "$NORD_BACKOFF_SECONDS" "$DETECTOR_PERIOD_MS" "$FAST_PROBE_WINDOW_US" "$FAST_FAILURE_THRESHOLD" "$STANDBY_CHECK_MS"; do
    case "$value" in ''|0|0*|*[!0-9]*|??????????*) echo "Invalid runtime numeric setting" >&2; exit 1;; esac
done
case "$DEBUG_TIMING" in 0|1) ;; *) echo "Invalid DEBUG_TIMING" >&2; exit 1;; esac
[ -n "$KEEPALIVE_PROBE_TARGETS" ] && [ "${NTFY_URL+x}" = x ] || { echo "Missing runtime setting" >&2; exit 1; }

# Installer data is mandatory. No developer-specific fallback configuration.
case "$TUNNEL_ID:$GROUP_ID" in *[!0-9:]*|:*|*:) echo "Invalid VPN IDs" >&2; exit 1;; esac
PROFILE_FILE="/etc/vpn_profiles.d/profile${TUNNEL_ID}"
# TSV: rank, major tier, order, identity, display label, peer ID.
# Reject malformed/duplicate mappings before any runtime work.
awk -F '\t' '
    NF != 6 || $1 !~ /^[1-9][0-9]*$/ || $2 !~ /^[123]$/ || $3 !~ /^[1-9][0-9]*$/ || $4 !~ /^[a-f0-9]+$/ || $5 == "" || $6 !~ /^[0-9]+$/ { bad=1 }
    seen[$6]++ { bad=1 }
    ($1 in tiers) && (tiers[$1] != $2 || ids[$1] != $4 || orders[$1] != $3 || labels[$1] != $5) { bad=1 }
    { tiers[$1]=$2; ids[$1]=$4; orders[$1]=$3; labels[$1]=$5; if ($2 == 1) preferred=1 }
    END { if (bad || !NR || !preferred) exit 1 }
' "$LOCATION_FILE" || { echo "Invalid location configuration" >&2; exit 1; }

. /root/hotswapper/gl-coordination.sh || exit 1

umask 077
mkdir -p "$PERSIST_DIR" "$RUNTIME_DIR" "${LOG_FILE%/*}"
chmod 700 "$RUNTIME_DIR"

now() { date +%s; }

rotate_log_if_needed() {
    local size=0
    [ -f "$LOG_FILE" ] || return 0
    size="$(wc -c < "$LOG_FILE" 2>/dev/null)"
    [ "${size:-0}" -lt "$LOG_MAX_BYTES" ] 2>/dev/null && return 0
    mv -f "$LOG_FILE" "$LOG_FILE.1" 2>/dev/null || true
}

log() {
    local msg="$*"
    rotate_log_if_needed
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$msg" >> "$LOG_FILE"
    logger -t hotswapper "$msg" 2>/dev/null || true
}

# Monotonic millisecond clock for v12 promotion diagnostics. /proc/uptime is
# used instead of wall time so NTP/clock adjustments cannot corrupt durations.
# Typical OpenWrt kernel resolution here is ~10 ms.
monotonic_ms() {
    # BusyBox ash on this firmware does not support the 10# decimal-prefix
    # arithmetic used by v12. awk handles /proc/uptime's decimal value
    # directly and gives us a monotonic millisecond clock.
    awk '{printf "%.0f\n", $1 * 1000}' /proc/uptime 2>/dev/null
}

promo_trace() {
    # v14.1: detailed promotion timing is opt-in. Normal operation performs
    # no persistent promotion-timing writes; meaningful events/errors still
    # use the normal bounded watchdog log. Set DEBUG_TIMING=1 in config when
    # diagnosing promotion latency.
    [ "${DEBUG_TIMING:-0}" = "1" ] || return 0
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "${LOG_FILE%/*}/promotion-timing.log"
}

notify() {
    local title="$1" rc
    [ "$(cat "$WAN_STATE_FILE" 2>/dev/null)" = WAN_OFFLINE ] && return 2
    shift
    local body="$*"
    if [ "$IN_DETECTOR" = 1 ] || [ "${PROMOTION_CRITICAL:-0}" = 1 ]; then
        printf '%s\n' "$title" > "$RUNTIME_DIR/notification-title"
        printf '%s\n' "$body" > "$RUNTIME_DIR/notification-body"
        return 0
    fi
    if [ -z "$NTFY_URL" ]; then
        log "ntfy skipped: NTFY_URL is not configured"
        return 2
    fi
    # Feed the private URL on stdin rather than exposing the topic in argv.
    # Configuration generation rejects controls; reject them here as well.
    if printf '%s' "$NTFY_URL" | LC_ALL=C grep -q '[[:cntrl:]]'; then
        log "ntfy URL contains invalid controls"
        return 1
    fi
    slow_command curl -fsS -m 8 -H "Title: $title" -d "$body" --config - <<EOF
url = "$(printf '%s' "$NTFY_URL" | sed 's/\\/\\\\/g; s/"/\\"/g')"
EOF
    rc=$?
    if [ "$rc" -ne 0 ]; then
        log "ntfy delivery failed rc=$rc title=$title"
        return "$rc"
    fi
    return 0
}

release_lock() {
    stop_slow_command
    local pid=""
    [ -f "$LOCK_DIR/pid" ] && pid="$(cat "$LOCK_DIR/pid" 2>/dev/null)"
    [ "$pid" = "$$" ] && rm -f "$LOCK_DIR/pid" 2>/dev/null
    exec 8>&-
}

acquire_lock() {
    mkdir -p "$LOCK_DIR" || return 1
    exec 8>"$RUNTIME_DIR/daemon.lock" || return 1
    busybox flock -n 8 || { exec 8>&-; return 1; }
    # PID is discovery metadata only; the open descriptor owns the lock.
    echo $$ > "$LOCK_DIR/pid"
    trap 'release_lock' EXIT
    trap 'release_lock; exit 0' INT TERM
    return 0
}

# BusyBox applets are build-dependent. Both installer and daemon verify elapsed
# time, not just command existence. No fractional sleep or whole-second fallback.
delay_us() {
    busybox usleep "$1" 8>&- & DELAY_PID=$!
    wait "$DELAY_PID" 2>/dev/null; local rc=$?
    if [ "$WAKE_REQUESTED" = 1 ]; then
        kill "$DELAY_PID" 2>/dev/null || true
        wait "$DELAY_PID" 2>/dev/null || true
        rc=0
    fi
    DELAY_PID=""
    return "$rc"
}

verify_delay() {
    local before after elapsed
    before="$(monotonic_ms)" || return 1
    delay_us 150000 || return 1
    after="$(monotonic_ms)" || return 1
    elapsed=$((after - before))
    [ "$elapsed" -ge 140 ] && [ "$elapsed" -lt 500 ]
}

stop_slow_command() {
    [ -n "$SLOW_PID" ] || return 0
    # Drain the one owned command before releasing the daemon lock. Killing only
    # its shell PID can orphan setup_instance descendants that still change UCI.
    # Installer stop timeout fails closed while this owner remains alive.
    trap '' INT TERM
    while kill -0 "$SLOW_PID" 2>/dev/null; do
        wait "$SLOW_PID" 2>/dev/null || true
    done
    wait "$SLOW_PID" 2>/dev/null || true
    SLOW_PID=""
}

slow_command() {
    local command_rc HS_SLOT_IDENTITY=""
    if [ "$1" = /usr/bin/setup_instance ]; then
        HS_SLOT_IDENTITY=$(cat "$HS_DIR/owned.$3" 2>/dev/null)
    fi
    export HS_SLOT_IDENTITY
    if [ "$IN_DETECTOR" = 1 ] || [ "${PROMOTION_CRITICAL:-0}" = 1 ]; then "$@" >/dev/null 2>&1; return $?; fi
    if [ "$DETECTOR_ENABLED" != 1 ]; then
        "$@" > "$RUNTIME_DIR/command-output" 2>&1
        return $?
    fi
    # One owned child command, never another detector or detached worker.
    # The shell owns all promotions; a provider command only prepares an unused slot.
    "$@" <&0 > "$RUNTIME_DIR/command-output" 2>&1 8>&- &
    SLOW_PID=$!
    while kill -0 "$SLOW_PID" 2>/dev/null; do
        detector_iteration
    done
    wait "$SLOW_PID"; command_rc=$?
    SLOW_PID=""
    return "$command_rc"
}

cooperative_pause() {
    local finish
    if [ "$DETECTOR_ENABLED" != 1 ] || [ "$IN_DETECTOR" = 1 ]; then sleep "$1"; return; fi
    finish=$(( $(monotonic_ms) + $1 * 1000 ))
    while [ "$(monotonic_ms)" -lt "$finish" ]; do detector_iteration; done
}

fast_path_round() {
    local iface="$1" first second elapsed=0 result=1 interrupted=0
    ping -n -I "$iface" -c 1 -W 1 -w 1 1.1.1.1 >/dev/null 2>&1 8>&- & first=$!
    ping -n -I "$iface" -c 1 -W 1 -w 1 8.8.8.8 >/dev/null 2>&1 8>&- & second=$!
    # Check completed children at most four times. A successful reply ends the round.
    while [ "$elapsed" -lt "$FAST_PROBE_WINDOW_US" ]; do
        if [ -n "$first" ] && ! kill -0 "$first" 2>/dev/null; then
            wait "$first" && result=0
            first=""
        fi
        if [ -n "$second" ] && ! kill -0 "$second" 2>/dev/null; then
            wait "$second" && result=0
            second=""
        fi
        [ "$result" = 0 ] && break
        [ "$WAKE_REQUESTED" = 0 ] || { interrupted=1; break; }
        delay_us 50000 || { interrupted=1; break; }
        elapsed=$((elapsed + 50000))
    done
    for child in "$first" "$second"; do
        [ -n "$child" ] || continue
        if ! kill -0 "$child" 2>/dev/null; then
            wait "$child" && result=0
        else
            kill "$child" 2>/dev/null || true
            wait "$child" 2>/dev/null || true
        fi
    done
    # Cancellation is not evidence that the Internet path failed.
    [ "$interrupted" = 0 ] && [ "$WAKE_REQUESTED" = 0 ] || return 2
    return "$result"
}

iface_hard_up() {
    [ -n "$1" ] && [ "$(gl_iface_state "$1")" = connected ] || return 1
    ip link show "$1" 2>/dev/null | grep -Eq '<([^>]*,)?UP(,|>)'
}

refresh_detector_roles() {
    local roles cp cr ct target
    roles="$(reconcile_roles)"
    IFS='|' read -r DETECT_CURRENT cp cr ct DETECT_DOWN DETECT_UP target <<EOF
$roles
EOF
    FAST_FAILURES=0
    write_state_snapshot "$DETECT_CURRENT" "$DETECT_DOWN" "$DETECT_UP"
}

fast_health_pass() {
    local selected candidate peer rc failed=0
    [ "$IN_DETECTOR" = 0 ] || return 0
    WAKE_REQUESTED=0
    prune_detector_candidates
    selected="$(current_iface)"
    if [ "$selected" != "$DETECT_CURRENT" ]; then
        # GL can change policy independently. Never use stale cached role identity.
        DETECT_CURRENT="$selected"; DETECT_UP=""; DETECT_DOWN=""; DETECT_FAILED=0
        FAST_FAILURES=0; SLOW_REQUESTED=1
        return 0
    fi
    [ "$SLOW_REQUESTED" = 0 ] && [ "$DETECT_FAILED" = 0 ] || return 0
    if ! owned_hard_up "$DETECT_CURRENT"; then
        failed=1
    elif fast_path_round "$DETECT_CURRENT"; then
        FAST_FAILURES=0
    else
        rc=$?
        [ "$rc" != 2 ] || return 0
        FAST_FAILURES=$((FAST_FAILURES + 1))
        [ "$FAST_FAILURES" -lt "$FAST_FAILURE_THRESHOLD" ] || failed=1
    fi
    if [ "$failed" != 1 ]; then
        refresh_standby_health
        return 0
    fi
    IN_DETECTOR=1
    DETECT_FAILED=1
    rm -f "$RUNTIME_DIR/ready.$DETECT_CURRENT"
    # Cached roles only: no rank searches, WAN diagnosis or provider work here.
    for candidate in "$DETECT_UP" "$DETECT_DOWN"; do
        [ -n "$candidate" ] && [ "$candidate" != "$DETECT_CURRENT" ] || continue
        peer="" # The armed record supplies the peer under the lock.
        if promote_iface "$candidate" "$peer" current-failure-hot-candidate; then
            DETECT_CURRENT="$candidate"; DETECT_UP=""; DETECT_DOWN=""
            FAST_FAILURES=0; DETECT_FAILED=0
            rm -f "$LAST_UPTIER_FILE" "$WAN_STATE_FILE"
            break
        else
            [ "$?" != 2 ] || break
        fi
    done
    IN_DETECTOR=0
    SLOW_REQUESTED=1
}

detector_iteration() {
    local started remaining
    started=$(monotonic_ms)
    DETECTOR_NOW=$started
    fast_health_pass
    remaining=$((DETECTOR_PERIOD_MS - $(monotonic_ms) + started))
    [ "$remaining" -gt 0 ] || return 0
    [ "$WAKE_REQUESTED" = 0 ] || return 0
    delay_us "$((remaining * 1000))" || exit 1
}

policy_section() {
    [ -z "$POLICY_SECTION" ] || { echo "$POLICY_SECTION"; return; }
    uci -q show route_policy 2>/dev/null | \
        sed -n "s/^route_policy\.\([^.=]*\)\.tunnel_id='${TUNNEL_ID}'$/\1/p" | \
        head -n 1
}

policy_get() {
    local sec
    sec="$(policy_section)"
    [ -n "$sec" ] || return 1
    uci -q get "route_policy.${sec}.$1"
}

iface_peer() {
    local cfg
    cfg="$(uci -q get network."$1".config 2>/dev/null)"
    case "$cfg" in
        peer_*) echo "${cfg#peer_}" ;;
        *) return 1 ;;
    esac
}

peer_name() {
    uci -q get wireguard."peer_$1".name 2>/dev/null
}

peer_location() {
    uci -q get wireguard."peer_$1".location 2>/dev/null
}

# Exact peer membership from installer-generated data; labels never control routing.
peer_rank() {
    awk -F '\t' -v peer="$1" '$6 == peer { print $1; found=1; exit } END { if (!found) print 0 }' "$LOCATION_FILE"
}
peer_tier() { rank_major_tier "$(peer_rank "$1")"; }
rank_major_tier() {
    awk -F '\t' -v rank="$1" '$1 == rank { print $2; found=1; exit } END { if (!found) print 0 }' "$LOCATION_FILE"
}
tier_label() {
    case "$1" in 1|2|3) echo "Tier $1";; *) echo "Unknown";; esac
}
rank_label() {
    awk -F '\t' -v rank="$1" '$1 == rank { print $5; exit }' "$LOCATION_FILE"
}
rank_order() {
    cut -f1 "$LOCATION_FILE" | sort -nu
}
tier1_ranks() {
    awk -F '\t' '$2 == 1 {print $1}' "$LOCATION_FILE" | sort -nu
}

current_iface() {
    policy_get via 2>/dev/null
}

current_peer() {
    local p
    p="$(policy_get peer_id 2>/dev/null)"
    if [ -n "$p" ]; then
        echo "$p"
        return 0
    fi
    p="$(iface_peer "$(current_iface)" 2>/dev/null)" || return 1
    echo "$p"
}

latest_handshake() {
    wg show "$1" latest-handshakes 2>/dev/null | \
        awk 'BEGIN {m=0} {if ($2+0>m) m=$2+0} END {print m+0}'
}

gl_iface_state() {
    cat "/tmp/wireguard/${1}_state" 2>/dev/null
}

probe_stamp_file() {
    printf '%s/probe.%s' "$RUNTIME_DIR" "$1"
}

health_fail_file() {
    printf '%s/health-fail.%s' "$RUNTIME_DIR" "$1"
}

probe_due() {
    local iface="$1" f last=0
    f="$(probe_stamp_file "$iface")"
    [ -f "$f" ] && last="$(cat "$f" 2>/dev/null)"
    [ $(( $(now) - ${last:-0} )) -ge "$KEEPALIVE_PROBE_INTERVAL" ]
}

mark_probe() {
    now > "$(probe_stamp_file "$1")"
}

clear_path_failures() {
    rm -f "$(health_fail_file "$1")" 2>/dev/null
}

record_path_failure() {
    local iface="$1" f n=0
    f="$(health_fail_file "$iface")"
    [ -f "$f" ] && n="$(cat "$f" 2>/dev/null)"
    n=$(( ${n:-0} + 1 ))
    echo "$n" > "$f"
    echo "$n"
}

# GL.iNet's own runtime state is authoritative for a hard tunnel failure.
# Our probes are only a secondary stuck-path detector. A probe round succeeds
# if ANY of several independent Internet targets responds through this iface.
probe_iface_path() {
    local iface="$1" target
    [ -n "$iface" ] || return 1
    ip link show "$iface" >/dev/null 2>&1 || return 1

    for target in $KEEPALIVE_PROBE_TARGETS; do
        if slow_command ping -I "$iface" -c 1 -W "$KEEPALIVE_PROBE_TIMEOUT" "$target"; then
            mark_probe "$iface"
            return 0
        fi
    done

    mark_probe "$iface"
    return 1
}

# Existing/live tunnel health:
# - missing interface or GL state != connected => immediate hard failure
# - otherwise a complete multi-target probe failure is only SUSPECT
# - two consecutive due probe rounds must fail before we call the path dead
iface_healthy() {
    local iface="$1" state failures
    [ -n "$iface" ] || return 1
    if ! ip link show "$iface" >/dev/null 2>&1; then
        clear_path_failures "$iface"
        return 1
    fi

    state="$(gl_iface_state "$iface")"
    if [ "$state" != "connected" ]; then
        clear_path_failures "$iface"
        return 1
    fi

    if probe_due "$iface"; then
        if probe_iface_path "$iface"; then
            clear_path_failures "$iface"
        else
            failures="$(record_path_failure "$iface")"
            if [ "$failures" -ge "$PATH_FAILURE_THRESHOLD" ] 2>/dev/null; then
                log "Path health FAILED on $iface after $failures consecutive multi-target probe rounds"
                return 1
            fi
            log "Path health SUSPECT on $iface: multi-target probe round failed ($failures/$PATH_FAILURE_THRESHOLD); keeping tunnel"
        fi
    fi

    return 0
}

# Newly-created candidate establishment is stricter: it must have completed
# a real WireGuard handshake recently. After establishment, iface_healthy()
# takes over and periodic bound pings maintain/check the path.
iface_established_fresh() {
    local iface="$1" hs age t state
    [ -n "$iface" ] || return 1
    ip link show "$iface" >/dev/null 2>&1 || return 1

    state="$(gl_iface_state "$iface")"
    [ "$state" = "connected" ] || return 1

    hs="$(latest_handshake "$iface")"
    [ "${hs:-0}" -gt 0 ] 2>/dev/null || return 1

    t="$(now)"
    age=$((t - hs))
    [ "$age" -ge 0 ] && [ "$age" -le "$HANDSHAKE_MAX_AGE" ]
}



iface_summary() {
    local iface="$1" peer tier name loc hs age
    peer="$(iface_peer "$iface" 2>/dev/null)"
    tier="$(peer_tier "$peer")"
    name="$(peer_name "$peer")"
    loc="$(peer_location "$peer")"
    hs="$(latest_handshake "$iface")"
    if [ "${hs:-0}" -gt 0 ] 2>/dev/null; then
        age=$(( $(now) - hs ))
    else
        age="none"
    fi
    printf '%s peer=%s tier=%s server=%s location=%s handshake_age=%ss' \
        "$iface" "${peer:-?}" "${tier:-0}" "${name:-?}" "${loc:-?}" "$age"
}

backoff_until() {
    [ -f "$BACKOFF_FILE" ] && cat "$BACKOFF_FILE" 2>/dev/null || echo 0
}

in_backoff() {
    local until
    until="$(backoff_until)"
    [ "${until:-0}" -gt "$(now)" ] 2>/dev/null
}

set_nord_backoff() {
    local reason="$1" until
    until=$(( $(now) + NORD_BACKOFF_SECONDS ))
    echo "$until" > "$BACKOFF_FILE"
    log "Nord auxiliary-connection backoff for 15 minutes: $reason"
    notify "VPN auxiliary backoff" "NordVPN rejected an auxiliary connection ($reason). New probing/precooking is paused for 15 minutes; the current tunnel and any already-connected hot candidate are left untouched."
}

maybe_clear_expired_backoff() {
    local until
    until="$(backoff_until)"
    if [ "${until:-0}" -gt 0 ] 2>/dev/null && [ "$until" -le "$(now)" ] 2>/dev/null; then
        rm -f "$BACKOFF_FILE"
        log "Nord auxiliary-connection backoff expired"
    fi
}

is_limit_error_text() {
    echo "$1" | grep -Eqi '20001226|device limit reached'
}

is_rate_error_text() {
    echo "$1" | grep -Eqi '20001215|20001220|API limit triggered|operation too frequent'
}

teardown_iface() {
    local iface="$1" current
    [ -n "$iface" ] || return 0
    current="$(current_iface)"
    if [ "$iface" = "$current" ]; then
        log "REFUSING to tear down current interface $iface"
        return 1
    fi

    [ "$DETECT_UP" != "$iface" ] || DETECT_UP=""
    [ "$DETECT_DOWN" != "$iface" ] || DETECT_DOWN=""
    hs_lock || return 1
    hs_disarm "$iface" || { hs_unlock; return 1; }
    hs_unlock
    grant_lifecycle "$iface" down
    slow_command ifdown "$iface" || true
    slow_command /usr/bin/setup_instance stop "$iface" || true
    slow_command /usr/bin/setup_instance clean "$iface" || true
    rm -f "$RUNTIME_DIR/ready.$iface" "/tmp/wireguard/${iface}_state" "$(probe_stamp_file "$iface")" "$(health_fail_file "$iface")" 2>/dev/null
    hs_lock || return 1
    [ "$iface" != "$(current_iface)" ] || { hs_unlock; return 1; }
    remove_prepared_firewall "$iface"
    rm -f "$HS_DIR/owned.$iface" "$HS_DIR/reservation.$iface"
    hs_unlock
    return 0
}

# Returns:
#   0 = connected successfully
#   1 = ordinary candidate failure
#   2 = current tunnel failed while a recovery probe was in progress
#   3 = global Nord auxiliary backoff is active / was just entered
prepare_iface() {
    local iface="$1" peer="$2" purpose="$3"
    local out rc i current state token epoch="$PROMOTION_EPOCH"

    in_backoff && return 3

    current="$(current_iface)"
    [ "$iface" != "$current" ] || return 1

    printf '%s|%s|%s|%s\n' "$current" "$purpose" "$iface" "$peer" > "$RUNTIME_DIR/preparing"
    teardown_iface "$iface" || return 1

    log "Preparing $purpose candidate on $iface: peer=$peer server=$(peer_name "$peer") location=$(peer_location "$peer")"

    claim_slot "$iface" "$peer" || return 1
    slow_command /usr/bin/setup_instance generate "$iface" "$GROUP_ID" "$peer"
    rc=$?
    out="$(cat "$RUNTIME_DIR/command-output")"
    [ "$epoch" = "$PROMOTION_EPOCH" ] && [ "$current" = "$(current_iface)" ] || return 2

    if is_limit_error_text "$out"; then
        teardown_iface "$iface" >/dev/null 2>&1 || true
        set_nord_backoff "device limit reached"
        return 3
    fi
    if is_rate_error_text "$out"; then
        teardown_iface "$iface" >/dev/null 2>&1 || true
        set_nord_backoff "provider/API rate limit"
        return 3
    fi
    if [ "$rc" -ne 0 ]; then
        log "setup_instance generate failed for $iface peer=$peer (provider output withheld)"
        teardown_iface "$iface" >/dev/null 2>&1 || true
        return 1
    fi

    slow_command /usr/bin/setup_instance start "$iface"
    rc=$?
    out="$(cat "$RUNTIME_DIR/command-output")"
    [ "$epoch" = "$PROMOTION_EPOCH" ] && [ "$current" = "$(current_iface)" ] || return 2
    if is_limit_error_text "$out"; then
        teardown_iface "$iface" >/dev/null 2>&1 || true
        set_nord_backoff "device limit reached"
        return 3
    fi
    if is_rate_error_text "$out"; then
        teardown_iface "$iface" >/dev/null 2>&1 || true
        set_nord_backoff "provider/API rate limit"
        return 3
    fi
    if [ "$rc" -ne 0 ]; then
        log "setup_instance start failed for $iface peer=$peer (provider output withheld)"
        teardown_iface "$iface" >/dev/null 2>&1 || true
        return 1
    fi

    grant_lifecycle "$iface" up || return 1
    slow_command /etc/init.d/network reload || return 1
    [ "$epoch" = "$PROMOTION_EPOCH" ] && [ "$current" = "$(current_iface)" ] || return 2

    i=0
    while [ "$i" -lt "$CONNECT_TIMEOUT" ]; do
        if iface_established_fresh "$iface"; then
            slow_command /usr/bin/rtp2.sh hotswapper_prepare "$iface" || return 1
            prepare_dataplane "$iface" || return 1
            token=$(readiness_token "$iface") || return 1
            # Probe only after the candidate's actual forwarding/DNS support is installed.
            if probe_iface_path "$iface"; then
                [ "$epoch" = "$PROMOTION_EPOCH" ] && [ "$current" = "$(current_iface)" ] || return 2
                record_readiness "$iface" "$token" || return 1
                log "Connected $purpose candidate: $(iface_summary "$iface")"
                return 0
            fi
        fi

        if [ "$purpose" = uptier ] || [ "$purpose" = downtier ]; then
            [ "$DETECT_FAILED" = 0 ] || return 2
        fi
        [ "$epoch" = "$PROMOTION_EPOCH" ] && [ "$current" = "$(current_iface)" ] || return 2

        state="$(cat "/tmp/wireguard/${iface}_state" 2>/dev/null)"
        [ "$state" = "failed" ] && break
        cooperative_pause 1
        [ "$epoch" = "$PROMOTION_EPOCH" ] && [ "$current" = "$(current_iface)" ] || return 2
        i=$((i + 1))
    done

    log "Candidate failed to establish a fresh handshake: iface=$iface peer=$peer purpose=$purpose"
    teardown_iface "$iface" >/dev/null 2>&1 || true
    return 1
}

profile_peers_for_rank() {
    local wanted_rank="$1" line peer
    [ -f "$PROFILE_FILE" ] || return 1
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        peer="${line#*_}"
        [ "$(peer_rank "$peer")" = "$wanted_rank" ] && echo "$peer"
    done < "$PROFILE_FILE"
}

rank_has_peers() {
    [ -n "$(profile_peers_for_rank "$1" | head -n 1)" ]
}

next_lower_rank() {
    local current="$1" rank seen=0
    for rank in $(rank_order); do
        [ "$rank" = "$current" ] && { seen=1; continue; }
        [ "$seen" -eq 1 ] || continue
        if rank_has_peers "$rank"; then
            echo "$rank"
            return 0
        fi
    done
    return 1
}

recovery_ranks() {
    local current_rank="$1" current_tier rank tier
    current_tier="$(rank_major_tier "$current_rank")"
    [ "$current_tier" -gt 1 ] 2>/dev/null || return 0
    for rank in $(rank_order); do
        [ "$rank" -lt "$current_rank" ] || continue
        tier="$(rank_major_tier "$rank")"
        [ "$tier" -le 2 ] || continue
        rank_has_peers "$rank" && echo "$rank"
    done
}

# Rotates through servers INSIDE one internal location rank.
# Moving between ranks is controlled separately by the state machine, so every
# server in one configured pool belongs to that same internal rank.
next_peer_for_rank() {
    local rank="$1" exclude1="$2" exclude2="$3" exclude3="$4"
    local cursor_file="$PERSIST_DIR/cursor.rank${rank}" last="" first="" after=0 peer
    [ -f "$cursor_file" ] && last="$(cat "$cursor_file" 2>/dev/null)"

    [ -z "$last" ] && after=1
    for peer in $(profile_peers_for_rank "$rank"); do
        [ -z "$first" ] && first="$peer"
        if [ "$after" -eq 1 ]; then
            [ "$peer" = "$exclude1" ] && continue
            [ "$peer" = "$exclude2" ] && continue
            [ "$peer" = "$exclude3" ] && continue
            echo "$peer" > "$cursor_file"
            echo "$peer"
            return 0
        fi
        [ "$peer" = "$last" ] && after=1
    done

    # Wrap within the same location rank.
    for peer in $(profile_peers_for_rank "$rank"); do
        [ "$peer" = "$exclude1" ] && continue
        [ "$peer" = "$exclude2" ] && continue
        [ "$peer" = "$exclude3" ] && continue
        echo "$peer" > "$cursor_file"
        echo "$peer"
        return 0
    done
    return 1
}

find_healthy_iface_for_rank() {
    local rank="$1" exclude="$2" iface peer
    for iface in $SLOTS; do
        [ "$iface" = "$exclude" ] && continue
        peer="$(iface_peer "$iface")"
        [ "$(peer_rank "$peer")" = "$rank" ] || continue
        # Read-only reconciliation: never run the detector in command substitution.
        local armed_peer armed_index armed_sec
        read -r armed_peer armed_index armed_sec < "$HS_DIR/armed.$iface" 2>/dev/null || continue
        [ "$armed_peer" = "$peer" ] || continue
        iface_hard_up "$iface" || continue
        echo "$iface"; return 0
    done
    return 1
}

free_slot() {
    local current="$1" keep="$2" iface

    # Prefer a genuinely unused/down slot so we do not destroy a still-useful
    # old tunnel while another physical slot is available.
    for iface in $SLOTS; do
        [ "$iface" = "$current" ] && continue
        [ "$iface" = "$keep" ] && continue
        if ! uci -q get network."$iface" >/dev/null 2>&1; then
            echo "$iface"
            return 0
        fi
        if ! iface_hard_up "$iface"; then
            echo "$iface"
            return 0
        fi
    done

    # If both auxiliaries are live, one still has to be selected for reuse.
    for iface in $SLOTS; do
        [ "$iface" = "$current" ] && continue
        [ "$iface" = "$keep" ] && continue
        echo "$iface"
        return 0
    done
    return 1
}

fastpath_mark_for_iface() {
    local iface="$1" idx
    case "$iface" in
        wgclient[1-5]) idx="${iface#wgclient}" ;;
        *) return 1 ;;
    esac
    printf '0x%x000\n' "$idx"
}


claim_slot() (
    local iface="$1" peer="$2" generation=0 index=0 previous
    hs_lock || return 1
    hs_disarm "$iface" || return 1
    [ "$(uci -q get "wireguard.peer_$peer.group_id")" = "$GROUP_ID" ] || return 1
    [ -r "$HS_DIR/generation" ] && read -r generation < "$HS_DIR/generation"
    generation=$((generation + 1))
    printf '%s\n' "$generation" > "$HS_DIR/generation"
    [ ! -r "/sys/class/net/$iface/ifindex" ] || read -r index < "/sys/class/net/$iface/ifindex"
    previous=$(uci -q get "network.$iface.config")
    printf '%s %s\n' "$generation" "${previous:-none}" > "$HS_DIR/reservation.$iface"
    printf '%s %s %s %s %s\n' "$peer" "$GROUP_ID" "$TUNNEL_ID" "$generation" "$index" > "$HS_DIR/owned.$iface.new"
    mv "$HS_DIR/owned.$iface.new" "$HS_DIR/owned.$iface"
)

grant_lifecycle() {
    local peer group tunnel generation index
    [ -r "$HS_DIR/owned.$1" ] || return 0
    read -r peer group tunnel generation index < "$HS_DIR/owned.$1" || return 1
    : > "$HS_DIR/permit.$1.$2.$generation"
}

start_ownership() {
    local stamp iface peer
    trap 'WAKE_REQUESTED=1; prune_detector_candidates; [ -z "$DELAY_PID" ] || kill "$DELAY_PID" 2>/dev/null || true' USR1
    [ "$(policy_get killswitch)" = 1 ] &&
        [ "$(policy_get via_type)" = wireguard ] &&
        [ "$(uci -q get route_policy.global.instance_on)" = 1 ] || return 1
    hs_lock fast || return 1
    hs_drain_old_workers || { hs_unlock; return 1; }
    stamp=$(awk '{print $22}' "/proc/$$/stat")
    HS_REQUEST="$$:$stamp"; export HS_REQUEST
    printf '%s %s\n' "$$" "$stamp" > "$HS_DIR/owner.new"
    mv "$HS_DIR/owner.new" "$HS_DIR/owner"
    printf '%s:%s\n' "$TUNNEL_ID" "$GROUP_ID" > "$HS_DIR/tunnel"
    rm -f "$HS_DIR/promotion-waiting"
    for iface in $SLOTS; do hs_disarm "$iface" || { hs_unlock; return 1; }; done
    for iface in $SLOTS; do
        peer=$(iface_peer "$iface")
        [ -n "$peer" ] || continue
        [ "$(peer_rank "$peer")" -gt 0 ] || continue
        claim_slot "$iface" "$peer" || { hs_unlock; return 1; }
    done
    # Normalize an inherited, partly synchronized selector to DROP before
    # preparation. Never reopen it just to make adoption succeed.
    if iptables -w 1 -t mangle -S HOTSWAPPER_SELECTED >/dev/null 2>&1 &&
        ! fastpath_verify_consistency "$(current_iface)" "$(current_peer)" "$(policy_get mark)" "$(policy_section)"; then
        fastpath_rollback "$(current_iface)"
    fi
    hs_unlock
    prepare_dataplane "$(current_iface)" || return 1
    restore_failure_state
}

restore_failure_state() {
    hs_lock fast || return 1
    # An inherited DROP must go through recovery, never ordinary adoption.
    if ! fastpath_verify_consistency "$(current_iface)" "$(current_peer)" "$(policy_get mark)" "$(policy_section)"; then
        fastpath_rollback "$(current_iface)"
    fi
    hs_unlock
}

verify_current() (
    local iface peer mark sec token pid stamp
    hs_lock fast || return 1
    hs_daemon_lock_held || return 1
    read -r pid stamp < "$HS_DIR/owner" || return 1
    [ "$(cat "$LOCK_DIR/pid" 2>/dev/null)" = "$pid" ] || return 1
    iface=$(current_iface); peer=$(current_peer); mark=$(policy_get mark); sec=$(policy_section)
    token=$(readiness_token "$iface") || return 1
    hs_owned "$iface" && owned_hard_up "$iface" && hs_peer_matches "$iface" || return 1
    fastpath_verify_consistency "$iface" "$peer" "$mark" "$sec" && prepared_hooks_match || return 1
    fast_path_round "$iface" || return $?
    [ "$token" = "$(readiness_token "$iface")" ] && hs_peer_matches "$iface" || return 1
    fastpath_verify_consistency "$iface" "$peer" "$mark" "$sec" || return 1
    printf 'CURRENT_OK\n'
)

owned_hard_up() {
    local iface="$1" peer group tunnel generation index actual state link flags route
    case "$iface" in wgclient1|wgclient2|wgclient3) ;; *) return 1;; esac
    read -r peer group tunnel generation index < "$HS_DIR/owned.$iface" || return 1
    [ "$group:$tunnel" = "$GROUP_ID:$TUNNEL_ID" ] || return 1
    [ "$(uci -q get "network.$iface.config")" = "peer_$peer" ] || return 1
    read -r actual < "/sys/class/net/$iface/ifindex" || return 1
    [ "$index" = "$actual" ] || return 1
    read -r state < "/tmp/wireguard/${iface}_state" || return 1
    [ "$state" = connected ] || return 1
    link=$(ip -o link show "$iface" 2>/dev/null) || return 1
    flags=${link#*<}; flags=${flags%%>*}
    case ",$flags," in *,UP,*) ;; *) return 1;; esac
    route=$(ip -4 route get 1.1.1.1 mark "$(fastpath_mark_for_iface "$iface")" 2>/dev/null) || return 1
    case " $route " in *" dev $iface "*) return 0;; *) return 1;; esac
}

prepared_dataplane_matches() {
    local iface="$1" mark
    mark=$(fastpath_mark_for_iface "$iface")
    iptables -w 1 -t filter -C FORWARD -i br-lan -o "$iface" -m mark --mark "$mark/0xf000" -j ACCEPT >/dev/null 2>&1 &&
    iptables -w 1 -t nat -C POSTROUTING -o "$iface" -j MASQUERADE >/dev/null 2>&1 &&
    iptables -w 1 -t mangle -C FORWARD -o "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 &&
    iptables -w 1 -t filter -C FORWARD -i "$iface" -o br-lan -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 &&
    iptables -w 1 -t filter -C HOTSWAPPER_EGRESS -m mark --mark "$mark/0xf000" ! -o "$iface" -j DROP >/dev/null 2>&1 &&
    iptables -w 1 -t filter -C FORWARD -j HOTSWAPPER_EGRESS >/dev/null 2>&1 &&
    iptables -w 1 -t filter -C OUTPUT -j HOTSWAPPER_EGRESS >/dev/null 2>&1 &&
    iptables -w 1 -t mangle -S ROUTE_POLICY | grep -q 'hotswapper-fastpath.*-j HOTSWAPPER_SELECTED' || return 1
    iptables -w 1 -t mangle -S HOTSWAPPER_SELECTED | awk '/^-A / {n++; if ($3 != "-j" || ($4 != "MARK" && $4 != "DROP")) bad=1} END {exit (n!=1 || bad)}' || return 1
    local port
    port=$(uci -q get "dhcp.$iface.port")
    case "$port" in ''|*[!0-9]*) return 1;; esac
    local hexport
    hexport=$(printf '%04X' "$port")
    awk -v port=":$hexport" '$2 ~ port"$" {found=1} END {exit !found}' /proc/net/udp || return 1
    iptables -w 1 -t nat -C policy_redirect -p udp -m mark --mark "$mark/0xf000" -j REDIRECT --to-ports "$port" >/dev/null 2>&1 &&
    iptables -w 1 -t nat -C policy_output -p udp -m mark --mark "$mark/0xf000" -m owner --gid-owner usevpn -m udp --dport 53 -j REDIRECT --to-ports "$port" >/dev/null 2>&1 &&
    iptables -w 1 -t raw -C pre_dns_deal_conn_zone -p udp -m mark --mark "$mark/0xf000" ! -i lo -j CT --zone "$mark" >/dev/null 2>&1 &&
    iptables -w 1 -t raw -C out_dns_deal_conn_zone -p udp --sport "$port" ! -o lo -j CT --zone "$mark" >/dev/null 2>&1
}

prepare_selector() {
    local mark process tid chain position via rules="$HS_DIR/selector.rules"
    mark=$(policy_get mark)
    if iptables -w 1 -t mangle -N HOTSWAPPER_SELECTED 2>/dev/null; then
        iptables -w 1 -t mangle -A HOTSWAPPER_SELECTED -j MARK --set-xmark "$mark/0xf000" || return 1
    else
        # A previous failed promotion deliberately left DROP here. Only a validated
        # promotion may replace it; background preparation must never reopen it.
        iptables -w 1 -t mangle -C HOTSWAPPER_SELECTED -j DROP >/dev/null 2>&1 ||
            iptables -w 1 -t mangle -C HOTSWAPPER_SELECTED -j MARK --set-xmark "$mark/0xf000" >/dev/null 2>&1 || return 1
    fi
    echo '*mangle' > "$rules"
    # Remove just our old bindings; the replacement keeps GL's source/destination scope.
    for chain in ROUTE_POLICY LOCAL_POLICY; do
        iptables -w 1 -t mangle -S "$chain" | awk '/hotswapper-fastpath|hotswapper-process/ {sub(/^-A /,"-D ");print}' >> "$rules"
    done
    position=$(iptables -w 1 -t mangle -S ROUTE_POLICY | awk -v chain="TUNNEL${TUNNEL_ID}_ROUTE_POLICY" '/^-A / && !/hotswapper-fastpath|hotswapper-process/ {n++;if($NF==chain) {print n;exit}}')
    case "$position" in ''|*[!0-9]*) return 1;; esac
    iptables -w 1 -t mangle -S "TUNNEL${TUNNEL_ID}_ROUTE_POLICY" | awk -v position="$position" '
        /-j MARK --set-xmark/ {
            sub(/^-A [^ ]+ /,"-I ROUTE_POLICY "position" -m addrtype ! --dst-type LOCAL -m mark --mark 0x0/0xc000 ")
            gsub(/-m comment --comment "[^"]*" /,"")
            sub(/-m mark --mark 0x0\/0xf000 /,"")
            sub(/-j MARK --set-xmark [^ ]+/,"-m comment --comment hotswapper-fastpath -j HOTSWAPPER_SELECTED")
            print; n++
        }
        END {if(n!=1) exit 1}
    ' >> "$rules" || return 1
    for process in gl_process_vpn gl_process; do
        via=$(uci -q get "route_policy.$process.via")
        if [ "$process" = gl_process_vpn ]; then
            hs_owned "$via" &&
                [ "$(uci -q get "route_policy.$process")" = rule_process ] &&
                [ -z "$(uci -q get "route_policy.$process.group_id")" ] || return 1
        else
            [ "$via" = "$(current_iface)" ] || continue
        fi
        tid=$(uci -q get "route_policy.$process.tunnel_id")
        case "$tid" in ''|*[!0-9]*) return 1;; esac
        position=$(iptables -w 1 -t mangle -S LOCAL_POLICY | awk -v chain="TUNNEL${tid}_LOCAL_POLICY" '/^-A / && !/hotswapper-fastpath|hotswapper-process/ {n++;if($NF==chain) {print n;exit}}')
        case "$position" in ''|*[!0-9]*) return 1;; esac
        iptables -w 1 -t mangle -S "TUNNEL${tid}_LOCAL_POLICY" | awk -v position="$position" '
            /-j MARK --set-xmark/ {
                sub(/^-A [^ ]+ /,"-I LOCAL_POLICY "position" -m mark --mark 0x0/0xc000 ")
                gsub(/-m comment --comment "[^"]*" /,"")
                gsub(/-m (connmark|mark) --mark 0x0\/0xf000 /,"")
                sub(/-j MARK --set-xmark [^ ]+/,"-m comment --comment hotswapper-process -j HOTSWAPPER_SELECTED")
                print; n++
            }
            END {if(!n) exit 1}
        ' >> "$rules" || return 1
    done
    echo COMMIT >> "$rules"
    iptables-restore -w 1 --noflush < "$rules"
}

prepare_dataplane() (
    local iface="$1" slot mark subnet rules="$HS_DIR/egress.rules"
    hs_lock || return 1
    hs_owned "$iface" || return 1
    hs_invalidate_all || return 1
    iptables -w 1 -t filter -N HOTSWAPPER_EGRESS 2>/dev/null || true
    printf '*filter\n-F HOTSWAPPER_EGRESS\n-A HOTSWAPPER_EGRESS -o lo -j RETURN\n' > "$rules"
    for subnet in $(ip -4 route show dev br-lan scope link | awk '$1 != "default" && / proto kernel / && !/ via / {print $1}'); do
        printf '%s\n' "-A HOTSWAPPER_EGRESS -o br-lan -d $subnet -j RETURN" >> "$rules"
    done
    for slot in $SLOTS; do
        mark=$(fastpath_mark_for_iface "$slot")
        printf '%s\n' "-A HOTSWAPPER_EGRESS -m mark --mark $mark/0xf000 ! -o $slot -j DROP" >> "$rules"
    done
    # Install ahead of established/accept rules, atomically with the guard body.
    if iptables -w 1 -t filter -C FORWARD -j HOTSWAPPER_EGRESS >/dev/null 2>&1; then
        echo '-D FORWARD -j HOTSWAPPER_EGRESS' >> "$rules"
    fi
    if iptables -w 1 -t filter -C OUTPUT -j HOTSWAPPER_EGRESS >/dev/null 2>&1; then
        echo '-D OUTPUT -j HOTSWAPPER_EGRESS' >> "$rules"
    fi
    printf '%s\n' '-I FORWARD 1 -j HOTSWAPPER_EGRESS' '-I OUTPUT 1 -j HOTSWAPPER_EGRESS' COMMIT >> "$rules"
    iptables-restore -w 1 --noflush < "$rules" || return 1
    for slot in $SLOTS; do
        hs_owned "$slot" || continue
        ip -4 route replace blackhole default table "100${slot#wgclient}" metric 254 || return 1
        fastpath_prepare_firewall "$slot" || return 1
    done
    prepare_selector
)

readiness_token() {
    local peer group tunnel generation index epoch=0
    read -r peer group tunnel generation index < "$HS_DIR/owned.$1" || return 1
    [ ! -r "$HS_DIR/dataplane-epoch" ] || read -r epoch < "$HS_DIR/dataplane-epoch"
    printf '%s:%s:%s:%s\n' "$peer" "$generation" "$index" "$epoch"
}

record_readiness() (
    local iface="$1" expected="$2" peer group tunnel generation index rank key
    hs_lock || return 1
    [ -n "$expected" ] && [ "$expected" = "$(readiness_token "$iface")" ] || return 1
    hs_owned "$iface" && owned_hard_up "$iface" && prepared_dataplane_matches "$iface" &&
        fastpath_verify_kernel "$iface" "$(fastpath_mark_for_iface "$iface")" &&
        prepared_hooks_match || return 1
    read -r peer group tunnel generation index < "$HS_DIR/owned.$iface" || return 1
    key=$(uci -q get "wireguard.peer_$peer.public_key")
    [ -n "$key" ] && [ "$key" = "$(wg show "$iface" peers 2>/dev/null)" ] || return 1
    rank=$(peer_rank "$peer")
    [ "$rank" -gt 0 ] || return 1
    rm -f "$HS_DIR/invalid.$iface.$generation"
    local sec
    sec=$(policy_section) || return 1
    [ -n "$sec" ] || return 1
    printf '%s %s %s\n' "$peer" "$index" "$sec" > "$HS_DIR/armed.$iface.new"
    mv "$HS_DIR/armed.$iface.new" "$HS_DIR/armed.$iface" || return 1
    printf '%s\n' "$peer" > "$RUNTIME_DIR/ready.$iface"
)


prune_detector_candidates() {
    [ -z "$DETECT_UP" ] || [ -r "$HS_DIR/armed.$DETECT_UP" ] || DETECT_UP=""
    [ -z "$DETECT_DOWN" ] || [ -r "$HS_DIR/armed.$DETECT_DOWN" ] || DETECT_DOWN=""
}

refresh_standby_health() {
    local iface stamp token rc newly_armed=0
    stamp=$DETECTOR_NOW
    [ "$stamp" -ge "$NEXT_STANDBY_CHECK" ] || return 0
    NEXT_STANDBY_CHECK=$((stamp + STANDBY_CHECK_MS))
    # Include disarmed standbys so a repaired generation can become eligible again.
    for iface in $SLOTS; do
        [ "$iface" != "$DETECT_CURRENT" ] || continue
        token=$(readiness_token "$iface") || continue
        rc=1
        if owned_hard_up "$iface"; then
            fast_path_round "$iface"; rc=$?
        fi
        [ "$rc" != 2 ] || return 0
        local was_armed=0
        [ ! -r "$HS_DIR/armed.$iface" ] || was_armed=1
        if [ "$rc" = 0 ] && record_readiness "$iface" "$token"; then
            [ "$was_armed" = 1 ] || newly_armed=1
            continue
        fi
        # Do not let an old probe disarm a newly reused generation.
        if hs_lock; then
            [ "$token" != "$(readiness_token "$iface")" ] || hs_disarm "$iface"
            hs_unlock
        fi
    done
    prune_detector_candidates
    [ "$newly_armed" = 0 ] || refresh_detector_roles
}

select_dns_mark() {
    [ -w "/proc/dns_mark/rule${TUNNEL_ID}/mark" ] || return 1
    printf '%s\n' "$1" > "/proc/dns_mark/rule${TUNNEL_ID}/mark"
}

# Compare each installed selector's actual scope with its GL source rule, and
# require it before that source chain. Other unrelated policies keep their order.
selector_hook_matches() {
    local parent="$1" target="$2" tag="$3" expected actual
    expected=$(iptables -w 1 -t mangle -S "$target" | awk -v parent="$parent" -v tag="$tag" '
        /-j MARK --set-xmark/ {
            prefix="-A "parent" "
            if(parent=="ROUTE_POLICY") prefix=prefix"-m addrtype ! --dst-type LOCAL "
            sub(/^-A [^ ]+ /,prefix"-m mark --mark 0x0/0xc000 ")
            gsub(/-m comment --comment "[^"]*" /,"")
            gsub(/-m (connmark|mark) --mark 0x0\/0xf000 /,"")
            sub(/-j MARK --set-xmark [^ ]+/,"-m comment --comment "tag" -j HOTSWAPPER_SELECTED")
            print; n++
        }
        END {if(!n) exit 1}') || return 1
    actual=$(iptables -w 1 -t mangle -S "$parent") || return 1
    printf '%s\n' "$actual" | awk -v expected="$expected" -v target="$target" -v tag="$tag" '
        BEGIN {n=split(expected, wanted,"\n"); for(i=1;i<=n;i++) need[wanted[i]]++}
        /^-A / {
            if($NF==target) reached=1
            if(need[$0]) {
                if(reached) bad=1
                need[$0]--; found++
            }
        }
        END {exit(!reached || found!=n || bad)}'
}

prepared_hooks_match() {
    local process tid via
    iptables -w 1 -t mangle -C PREROUTING -j VPN_PREROUTING_HOOK || return 1
    iptables -w 1 -t mangle -C VPN_PREROUTING_HOOK -i br-lan -j ROUTE_POLICY || return 1
    iptables -w 1 -t mangle -C OUTPUT -j LOCAL_POLICY || return 1
    iptables -w 1 -t filter -S FORWARD | awk '/^-A / {found=1; good=($0=="-A FORWARD -j HOTSWAPPER_EGRESS"); exit} END {exit(!found || !good)}' || return 1
    iptables -w 1 -t filter -S OUTPUT | awk '/^-A / {found=1; good=($0=="-A OUTPUT -j HOTSWAPPER_EGRESS"); exit} END {exit(!found || !good)}' || return 1
    selector_hook_matches ROUTE_POLICY "TUNNEL${TUNNEL_ID}_ROUTE_POLICY" hotswapper-fastpath || return 1
    for process in gl_process_vpn gl_process; do
        via=$(uci -q get "route_policy.$process.via")
        if [ "$process" = gl_process_vpn ]; then
            hs_owned "$via" || return 1
        else
            [ "$via" = "$(current_iface)" ] || continue
        fi
        tid=$(uci -q get "route_policy.$process.tunnel_id")
        case "$tid" in ''|*[!0-9]*) return 1;; esac
        selector_hook_matches LOCAL_POLICY "TUNNEL${tid}_LOCAL_POLICY" hotswapper-process || return 1
    done
}

synchronize_gl() {
    local sec="$1" iface="$2" peer="$3" mark="$4" process tid chain rules="$HS_DIR/promotion.rules" old via
    old=$(uci -q get "route_policy.$sec.via")
    echo '*mangle' > "$rules"
    for process in "$sec" gl_process_vpn gl_process; do
        if [ "$process" = gl_process_vpn ]; then
            # A previous failed attempt may have moved only some metadata.
            # Accept stale references only to our own slots, never another VPN.
            via=$(uci -q get "route_policy.$process.via")
            hs_owned "$via" &&
                [ "$(uci -q get "route_policy.$process")" = rule_process ] &&
                [ -z "$(uci -q get "route_policy.$process.group_id")" ] || return 1
        else
            [ "$process" = "$sec" ] || [ "$(uci -q get "route_policy.$process.via")" = "$old" ] || continue
        fi
        tid=$(uci -q get "route_policy.$process.tunnel_id")
        case "$tid" in ''|*[!0-9]*) return 1;; esac
        if [ "$process" = "$sec" ]; then chain="TUNNEL${tid}_ROUTE_POLICY"; else chain="TUNNEL${tid}_LOCAL_POLICY"; fi
        printf '%s\n' "-F $chain" >> "$rules"
        iptables -w 1 -t mangle -S "$chain" | awk -v mark="$mark" '
            /^-A / {sub(/--set-xmark 0x[0-9a-fA-F]+\/0xf000/,"--set-xmark "mark"/0xf000");print;n++}
            END {if(!n) exit 1}
        ' >> "$rules" || return 1
        uci set "route_policy.$process.via=$iface" || return 1
        uci set "route_policy.$process.mark=$mark" || return 1
    done
    echo COMMIT >> "$rules"
    iptables-restore -w 1 --noflush < "$rules" || return 1
    uci set "route_policy.$sec.peer_id=$peer" &&
    uci set "route_policy.$sec.group_id=$GROUP_ID" && uci commit route_policy
}

fastpath_prepare_firewall() {
    local iface="$1" mark
    mark=$(fastpath_mark_for_iface "$iface")

    # rtp2 normally creates a firewall zone only for the selected VPN
    # interface. A precooked downtier therefore needs the minimum equivalent
    # dataplane rules before we can point LAN traffic at it.
    iptables -w 1 -t filter -C FORWARD -i br-lan -o "$iface" -m mark --mark "$mark/0xf000" -j ACCEPT >/dev/null 2>&1 ||
        iptables -w 1 -t filter -I FORWARD 2 -i br-lan -o "$iface" -m mark --mark "$mark/0xf000" -j ACCEPT || return 1
    iptables -w 1 -t filter -C FORWARD -i "$iface" -o br-lan -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 ||
        iptables -w 1 -t filter -I FORWARD 2 -i "$iface" -o br-lan -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || return 1
    iptables -w 1 -t nat -C POSTROUTING -o "$iface" -j MASQUERADE >/dev/null 2>&1 ||
        iptables -w 1 -t nat -I POSTROUTING 1 -o "$iface" -j MASQUERADE || return 1
    iptables -w 1 -t mangle -C FORWARD -o "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 ||
        iptables -w 1 -t mangle -I FORWARD 1 -o "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || return 1
    return 0
}

remove_prepared_firewall() {
    local iface="$1" mark
    mark=$(fastpath_mark_for_iface "$iface")
    iptables -w 1 -t filter -D FORWARD -i br-lan -o "$iface" -m mark --mark "$mark/0xf000" -j ACCEPT 2>/dev/null || true
    iptables -w 1 -t filter -D FORWARD -i "$iface" -o br-lan -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -w 1 -t nat -D POSTROUTING -o "$iface" -j MASQUERADE 2>/dev/null || true
    iptables -w 1 -t mangle -D FORWARD -o "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
}

fastpath_install_mark_override() {
    iptables -w 1 -t mangle -R HOTSWAPPER_SELECTED 1 -j MARK --set-xmark "$1/0xf000"
}

fastpath_verify_kernel() {
    local iface="$1" mark="$2" table="100${1#wgclient}" routes
    ip link show "$iface" >/dev/null 2>&1 || return 1
    routes=$(ip -4 route show table "$table") || return 1
    printf '%s\n' "$routes" | awk -v iface="$iface" '
        /^(blackhole|unreachable|prohibit) default( |$)/ {terminal=1; next}
        /^(blackhole|unreachable|prohibit) / {next}
        /^default / {defaults++}
        NF {if ($2!="dev" || $3!=iface || / (via|nexthop|encap) /) bad=1}
        END {exit (!terminal || defaults!=1 || bad)}' || return 1
    ip -4 rule show | awk -v mark="$mark/0xf000" -v table="$table" '
        $0 ~ "fwmark "mark" " {n++; if ($2!="from" || $3!="all" || $4!="fwmark" || $5!=mark || $6!="lookup" || $7!=table || NF!=7) bad=1}
        END {exit(n!=1 || bad)}'
}


acquire_gl_guard() {
    : > "$HS_DIR/promotion-waiting"
    if hs_lock fast; then return 0; fi
    rm -f "$HS_DIR/promotion-waiting"
    return 1
}

release_gl_guard() {
    hs_unlock
    rm -f "$HS_DIR/promotion-waiting"
}

fastpath_verify_consistency() {
    local iface="$1" peer="$2" mark="$3" sec="$4" table idx count rule
    idx="${iface#wgclient}"
    table="100${idx}"

    [ "$(uci -q get "route_policy.${sec}.peer_id")" = "$peer" ] || return 1
    [ "$(uci -q get "route_policy.${sec}.group_id")" = "$GROUP_ID" ] || return 1
    [ "$(uci -q get "route_policy.${sec}.via")" = "$iface" ] || return 1
    [ "$(uci -q get "route_policy.${sec}.mark")" = "$mark" ] || return 1
    fastpath_verify_kernel "$iface" "$mark" || return 1

    iptables -w 1 -t mangle -C HOTSWAPPER_SELECTED -j MARK --set-xmark "$mark/0xf000" || return 1
    iptables -w 1 -t mangle -S "TUNNEL${TUNNEL_ID}_ROUTE_POLICY" | grep -Fq -- "--set-xmark $mark/0xf000" || return 1
    [ "$(uci -q get route_policy.gl_process_vpn.via)" = "$iface" ] || return 1
    local process tid dns_mark
    for process in gl_process_vpn gl_process; do
        [ "$(uci -q get "route_policy.$process.via")" = "$iface" ] || continue
        [ "$(uci -q get "route_policy.$process.mark")" = "$mark" ] || return 1
        tid=$(uci -q get "route_policy.$process.tunnel_id")
        case "$tid" in ''|*[!0-9]*) return 1;; esac
        iptables -w 1 -t mangle -S "TUNNEL${tid}_LOCAL_POLICY" | grep -Fq -- "--set-xmark $mark/0xf000" || return 1
    done
    prepared_dataplane_matches "$iface" || return 1
    dns_mark=$(cat "/proc/dns_mark/rule${TUNNEL_ID}/mark" 2>/dev/null)
    printf '%s\n' "$dns_mark" | grep -Eq '^(0x[0-9a-fA-F]+|0|[1-9][0-9]*)$' || return 1
    [ "$((dns_mark))" = "$((mark))" ] || return 1
    return 0
}


fastpath_rollback() {
    # Never send traffic back to a tunnel which was just declared broken.
    iptables -w 1 -t mangle -R HOTSWAPPER_SELECTED 1 -j DROP ||
        printf '*mangle\n:HOTSWAPPER_SELECTED - [0:0]\n-F HOTSWAPPER_SELECTED\n-A HOTSWAPPER_SELECTED -j DROP\nCOMMIT\n' |
            iptables-restore -w 1 --noflush || {
            # The kernel's selected tables still have terminal DROP routes. Stop
            # this owner instead of announcing a successful/healthy promotion.
            log "CRITICAL: unable to install emergency selector DROP"
            exit 1
        }
    DETECT_FAILED=1
    SLOW_REQUESTED=1
}

promote_iface() {
    local PROMOTION_CRITICAL=1
    local iface="$1" peer="$2" reason="$3" sec mark old_peer old_tier new_tier title body trace_start trace_ready trace_flip
    [ "$DEBUG_TIMING" != 1 ] || trace_start=$(monotonic_ms)
    case "$iface" in wgclient1) mark=0x1000;; wgclient2) mark=0x2000;; wgclient3) mark=0x3000;; *) return 1;; esac
    acquire_gl_guard || return 1
    # One eligibility read closes invalidation while waiting for the lock. No health proof here.
    local armed_peer armed_index actual_index
    if ! read -r armed_peer armed_index sec < "$HS_DIR/armed.$iface" ||
        { [ -n "$peer" ] && [ "$peer" != "$armed_peer" ]; } ||
        ! read -r actual_index < "/sys/class/net/$iface/ifindex" || [ "$actual_index" != "$armed_index" ]; then
        release_gl_guard
        return 1
    fi
    peer=$armed_peer
    if [ "$reason" = current-failure-hot-candidate ] && [ "$iface" = "$DETECT_CURRENT" ]; then
        release_gl_guard
        return 1
    fi
    [ "$DEBUG_TIMING" != 1 ] || trace_ready=$(monotonic_ms)
    if ! fastpath_install_mark_override "$mark" || ! select_dns_mark "$mark"; then
        fastpath_rollback "$iface"
        release_gl_guard
        return 2
    fi
    [ "$DEBUG_TIMING" != 1 ] || trace_flip=$(monotonic_ms)
    # Packets now use the candidate. Keep GL writers excluded until their metadata agrees.
    old_peer=$(uci -q get "route_policy.$sec.peer_id")
    if ! synchronize_gl "$sec" "$iface" "$peer" "$mark"; then
        fastpath_rollback "$iface"
        release_gl_guard
        return 2
    fi
    if ! hs_disarm "$iface"; then
        fastpath_rollback "$iface"
        release_gl_guard
        return 2
    fi
    release_gl_guard
    if [ "$DEBUG_TIMING" = 1 ]; then
        printf 'start=%s ready=%s flip=%s synchronized=%s\n' "$trace_start" "$trace_ready" "$trace_flip" "$(monotonic_ms)" > "$RUNTIME_DIR/promotion-trace"
    fi
    PROMOTION_EPOCH=$((PROMOTION_EPOCH + 1))
    DETECT_CURRENT="$iface"; DETECT_UP=""; DETECT_DOWN=""; FAST_FAILURES=0; DETECT_FAILED=0
    old_tier=$(peer_tier "$old_peer"); new_tier=$(peer_tier "$peer")
    printf '%s\n' "PROMOTED reason=$reason current=$iface" > "$RUNTIME_DIR/promotion-log"
    if [ "$new_tier" != "$old_tier" ]; then
        if [ "$old_tier" = 0 ] || [ "$new_tier" = 1 ]; then title="VPN Restored"
        elif [ "$new_tier" -gt "$old_tier" ]; then title="VPN Degraded"
        else title="VPN Improved"; fi
        case "$new_tier" in
            1) body="Preferred gateway in use: $(peer_name "$peer") ($(peer_location "$peer")).";;
            2) body="Fallback gateway in use: $(peer_name "$peer") ($(peer_location "$peer")).";;
            3) body="Last-resort gateway in use: $(peer_name "$peer") ($(peer_location "$peer")).";;
            *) body="VPN gateway changed: $(peer_name "$peer") ($(peer_location "$peer")).";;
        esac
        notify "$title" "$body" || true
    fi
    return 0
}

write_state_snapshot() {
    local current="$1" downtier="$2" uptier="$3" peer rank role iface
    {
        for role in current downtier uptier; do
            case "$role" in current) iface="$current";; downtier) iface="$downtier";; uptier) iface="$uptier";; esac
            peer="$(iface_peer "$iface" 2>/dev/null)"
            rank="$(peer_rank "$peer")"
            printf '%s_iface=%s\n%s_peer=%s\n%s_rank=%s\n%s_tier=%s\n' \
                "$role" "$iface" "$role" "$peer" "$role" "$rank" "$role" "$(rank_major_tier "$rank")"
        done
        printf 'nord_backoff_until=%s\n' "$(backoff_until)"
    } > "$STATE_FILE.new"
    mv "$STATE_FILE.new" "$STATE_FILE"
}

reconcile_roles() {
    local current cp cr ct downtier="" uptier="" target_rank="" rank
    current="$(current_iface)"; cp="$(current_peer)"
    cr="$(peer_rank "$cp")"; ct="$(rank_major_tier "$cr")"
    if [ "$cr" -gt 0 ] 2>/dev/null; then
        target_rank="$(next_lower_rank "$cr" 2>/dev/null)"
        [ -z "$target_rank" ] || downtier="$(find_healthy_iface_for_rank "$target_rank" "$current")"
        for rank in $(recovery_ranks "$cr"); do
            uptier="$(find_healthy_iface_for_rank "$rank" "$current")"
            [ -z "$uptier" ] || break
        done
    fi
    printf '%s|%s|%s|%s|%s|%s|%s\n' "$current" "$cp" "$cr" "$ct" "$downtier" "$uptier" "${target_rank:-0}"
}

# Release interfaces outside CURRENT and the retained directional candidate.
# Call only after candidate preparation is complete.
cleanup_extras() {
    local current="$1" downtier="$2" iface
    for iface in $SLOTS; do
        [ "$iface" = "$current" ] && continue
        [ "$iface" = "$downtier" ] && continue
        uci -q get network."$iface" >/dev/null 2>&1 || continue
        teardown_iface "$iface" >/dev/null 2>&1 || true
    done
}

ensure_downtier() {
    local current="$1" ap="$2" ar="$3" at="$4" downtier="$5" spare="$6"
    local target_rank slot peer tries rc

    [ "$ar" -gt 0 ] 2>/dev/null || return 1
    target_rank="$(next_lower_rank "$ar" 2>/dev/null)"

    # No lower configured internal rank.
    [ -n "$target_rank" ] || return 0

    if [ -n "$downtier" ] && iface_healthy "$downtier"; then
        return 0
    fi

    in_backoff && return 0

    slot="$spare"
    [ -n "$slot" ] || slot="$(free_slot "$current" "" 2>/dev/null)"
    [ -n "$slot" ] || return 1

    tries=0
    while [ "$tries" -lt "$DOWNTIER_ATTEMPTS" ]; do
        peer="$(next_peer_for_rank "$target_rank" "$ap" "" "")" || return 1
        prepare_iface "$slot" "$peer" "downtier"
        rc=$?
        case "$rc" in
            0)
                log "Hot downtier ready for $(rank_label "$target_rank"): $(iface_summary "$slot")"
                return 0
                ;;
            2) return 2 ;;
            3) return 0 ;;
        esac
        tries=$((tries + 1))
    done

    return 1
}

promote_hot_candidate() {
    local current="$1" cp="$2" cr="$3" ct="$4" down="$5" up="$6" candidate peer
    for candidate in "$up" "$down"; do
        [ -n "$candidate" ] && [ "$candidate" != "$current" ] || continue
        peer=""
        promote_iface "$candidate" "$peer" current-failure-hot-candidate
        case "$?" in 0) return 0;; 2) return 1;; esac
    done
    # If a previous flip left metadata incomplete, a new successful path check
    # may recover that selection. Never reopen DROP just because the device is up.
    if iptables -w 1 -t mangle -C HOTSWAPPER_SELECTED -j DROP >/dev/null 2>&1; then
        peer=$(iface_peer "$current")
        # This is slow recovery of the blocked selection, not hot fallback.
        local token
        token=$(readiness_token "$current") || return 1
        local rc
        fast_path_round "$current"; rc=$?
        [ "$rc" != 2 ] || return 2
        [ "$rc" = 0 ] && record_readiness "$current" "$token" &&
            promote_iface "$current" "$peer" consistency-recovery && return 0
    fi
    return 1
}

recover_emergency() {
    local current="$1" ap="$2" ar="$3" at="$4" target_rank peer slot tries rc
    [ "$ar" -gt 0 ] 2>/dev/null || return 1
    wan_recovery_allowed || return 1
    [ -f "$WAN_PENDING_FILE" ] && return 1

    # No usable hot candidate. Keep kill switch authoritative while attempting one
    # emergency replacement.
    if in_backoff; then
        log "CURRENT failed with no usable hot candidate; auxiliary creation is in Nord backoff, so kill switch remains in force"
        return 1
    fi

    target_rank="$(next_lower_rank "$ar" 2>/dev/null)"
    if [ -z "$target_rank" ]; then
        # Lowest configured rank: try another server in the SAME rank.
        target_rank="$ar"
    fi

    slot="$(free_slot "$current" "" 2>/dev/null)"
    [ -n "$slot" ] || return 1

    log "CURRENT failure with no usable hot candidate; emergency target=$(rank_label "$target_rank") slot=$slot"
    tries=0
    while [ "$tries" -lt "$DOWNTIER_ATTEMPTS" ]; do
        peer="$(next_peer_for_rank "$target_rank" "$ap" "" "")" || return 1
        prepare_iface "$slot" "$peer" "emergency"
        rc=$?
        case "$rc" in
            0)
                promote_iface "$slot" "$peer" "current-failure-emergency" && return 0
                teardown_iface "$slot" >/dev/null 2>&1 || true
                ;;
            2) return 2 ;;
            3) return 1 ;;
        esac
        tries=$((tries + 1))
    done

    log "CRITICAL: unable to establish emergency VPN replacement; kill switch remains in force"
    notify "VPN unavailable" "The current VPN and hot candidate are unavailable, and no emergency VPN replacement connected. Kill switch remains in force; hotswapper did not force direct WAN."
    return 1
}

# Discover IPv4 WAN from the firmware firewall WAN zone and netifd, then
# select its current main-table default device. No fixed logical/device name.
# 0: usable device; 1: configured WAN down/no default; 2: unknown context.
wan_device() {
    local zones zone networks network status dev devices="" seen=0 routes proto
    zones="$(uci -q show firewall)" || return 2
    for zone in $(printf '%s\n' "$zones" | sed -n 's/^\(firewall\.[^=]*\)=zone$/\1/p'); do
        [ "$(uci -q get "$zone.name")" = wan ] || continue
        networks="$(uci -q get "$zone.network")" || return 2
        for network in $networks; do
            case "$network" in ''|*[!a-zA-Z0-9_]*) return 2;; esac
            status="$(ubus -t 2 call "network.interface.$network" status 2>/dev/null)" || continue
            seen=1
            case "$(jsonfilter -s "$status" -e '@.up')" in
                false) continue;; true) :;; *) return 2;;
            esac
            proto="$(jsonfilter -s "$status" -e '@.proto')"
            case "$proto" in ''|wireguard) return 2;; esac
            dev="$(jsonfilter -s "$status" -e '@.l3_device')"
            case "$dev" in ''|lo|wg*|tun*|tap*|*[!a-zA-Z0-9_.:-]*) return 2;; esac
            devices="$devices $dev"
        done
    done
    [ "$seen" -eq 1 ] || return 2
    [ -n "$devices" ] || return 1
    routes="$(ip -4 route show table main default 2>/dev/null)" || return 2
    for dev in $(printf '%s\n' "$routes" | awk '$1 == "default" {for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}'); do
        case " $devices " in *" $dev "*) printf '%s\n' "$dev"; return 0;; esac
    done
    return 1
}

# Subshell confines traps to this probe. ACCEPT ends only mangle OUTPUT,
# ahead of GL LOCAL_POLICY; filter OUTPUT and all client chains stay intact.
# A stale rule remains restricted to root ICMP to one target on this WAN.
wan_probe_target() {
    (
        dev="$1"; target="$2"
        route="$(ip -4 route get "$target" oif "$dev" 2>/dev/null)" || exit 2
        actual="$(printf '%s\n' "$route" | awk 'NR==1 {for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}')"
        source="$(printf '%s\n' "$route" | awk 'NR==1 {for(i=1;i<NF;i++) if($i=="src") print $(i+1)}')"
        [ "$actual" = "$dev" ] || exit 2
        case "$source" in ''|*[!0-9.]*) exit 2;; esac
        set -- OUTPUT -o "$dev" -s "$source/32" -d "$target/32" -p icmp --icmp-type echo-request \
            -m owner --uid-owner 0 -m comment --comment hotswapper-wan-probe -j ACCEPT
        # Remove an identical SIGKILL leftover, then insert ahead of LOCAL_POLICY.
        if iptables -w 2 -t mangle -C "$@" 2>/dev/null; then
            iptables -w 2 -t mangle -D "$@" 2>/dev/null || exit 2
        fi
        trap 'iptables -w 2 -t mangle -D "$@" >/dev/null 2>&1 || true' EXIT
        trap 'exit 2' INT TERM
        iptables -w 2 -t mangle -I "$@" 2>/dev/null || exit 2
        ping -n -I "$dev" -c 1 -W 1 -w 2 "$target" >/dev/null 2>&1
        rc=$?
        # A firewall reload or unsupported ping is not evidence of WAN failure.
        iptables -w 2 -t mangle -C "$@" 2>/dev/null || exit 2
        case "$rc" in 0) exit 0;; 1) exit 1;; *) exit 2;; esac
    )
}

wan_probe_round() {
    local dev rc unknown=0 target
    dev="$(wan_device)"; rc=$?
    [ "$rc" -eq 0 ] || return "$rc"
    # Independent IPv4 targets used by the archived GL kmwan monitor.
    for target in 1.1.1.1 8.8.8.8 208.67.222.222 208.67.220.220; do
        wan_probe_target "$dev" "$target"; rc=$?
        [ "$rc" -eq 0 ] && return 0
        [ "$rc" -eq 2 ] && unknown=1
    done
    [ "$unknown" -eq 0 ] || return 2
    return 1
}

# One round per cycle before emergency/broad creation. A suspect round also
# pauses creation without declaring a confirmed outage.
wan_recovery_allowed() {
    local previous rc state rank
    [ -n "$WAN_CYCLE_RESULT" ] && return "$WAN_CYCLE_RESULT"
    previous="$(cat "$WAN_STATE_FILE" 2>/dev/null)"
    if [ "$DETECTOR_ENABLED" = 1 ]; then slow_command "$0" _wan_probe; else wan_probe_round; fi
    rc=$?
    case "$rc" in
        0)
            state=WAN_UP
            if [ -f "$WAN_PENDING_FILE" ] && [ "$previous" != WAN_UP ]; then
                log "WAN connectivity restored; resuming VPN recovery from best configured rank"
                # Start at the first peer too, rather than a pre-outage cursor.
                for rank in $(rank_order); do
                    rm -f "$PERSIST_DIR/cursor.rank${rank}"
                done
            fi
            WAN_CYCLE_RESULT=0
            ;;
        1)
            state=WAN_SUSPECT
            case "$previous" in
                WAN_SUSPECT|WAN_OFFLINE)
                    state=WAN_OFFLINE
                    : > "$WAN_PENDING_FILE"
                    [ "$previous" = WAN_OFFLINE ] || log "WAN_OFFLINE entered; VPN candidate creation paused"
                    ;;
                *) log "WAN health suspect; waiting for a second failed round";;
            esac
            WAN_CYCLE_RESULT=1
            ;;
        *)
            state=WAN_UNKNOWN
            [ "$previous" = WAN_UNKNOWN ] || log "WAN probe context unavailable; VPN recovery paused (not a provider failure)"
            WAN_CYCLE_RESULT=1
            ;;
    esac
    printf '%s\n' "$state" > "$WAN_STATE_FILE"
    return "$WAN_CYCLE_RESULT"
}

wan_recovery_notification() {
    [ -f "$WAN_PENDING_FILE" ] || return 0
    rm -f "$WAN_PENDING_FILE"
    notify "WAN connectivity restored" "Underlying WAN connectivity was unavailable and has returned. VPN connectivity is restored." || true
}

recovery_due() {
    local last=0
    [ -f "$LAST_UPTIER_FILE" ] && last="$(cat "$LAST_UPTIER_FILE" 2>/dev/null)"
    [ $(( $(now) - ${last:-0} )) -ge "$UPTIER_INTERVAL" ]
}

mark_recovery_attempt() {
    now > "$LAST_UPTIER_FILE"
}

probe_recovery_targets() {
    local current="$1" cp="$2" cr="$3" ct="$4" down="$5" up="$6"
    local rank peer rc slot limit="$cr" keep="$down"
    [ "$ct" -gt 1 ] 2>/dev/null || return 0
    recovery_due || return 0
    in_backoff && return 0
    mark_recovery_attempt
    if [ -n "$up" ]; then
        limit="$(peer_rank "$(iface_peer "$up")")"
        keep="$up"
    fi
    slot="$(free_slot "$current" "$keep")"
    [ -n "$slot" ] || return 0
    for rank in $(recovery_ranks "$cr"); do
        [ "$rank" -lt "$limit" ] || continue
        peer="$(next_peer_for_rank "$rank" "$cp" "$(iface_peer "$keep")" "")"
        [ -n "$peer" ] || continue
        prepare_iface "$slot" "$peer" uptier; rc=$?
        rm -f "$RUNTIME_DIR/preparing"
        case "$rc" in
            0)
                if [ "$ct" -eq 3 ]; then
                    promote_iface "$slot" "$peer" higher-major-tier-recovery || return 0
                fi
                [ "$ct" -ne 2 ] || { DETECT_UP="$slot"; DETECT_DOWN=""; }
                # Tier 2 retains CURRENT. The proven UPTIER replaces DOWNTIER.
                cleanup_extras "$(current_iface)" "$slot"
                return 4;;
            2) return 2;;
            3) return 0;;
        esac
    done
    return 0
}


recover_offline_best() {
    local current slot rank peer tries rc old_active

    wan_recovery_allowed || return 1
    in_backoff && {
        log "Offline recovery deferred: Nord auxiliary backoff is active"
        return 1
    }

    old_active="$(current_iface 2>/dev/null)"
    slot="$(free_slot "$old_active" "" 2>/dev/null)"

    # If free_slot cannot resolve because policy state is malformed, choose any
    # physical slot other than the currently selected route-policy interface.
    if [ -z "$slot" ]; then
        for slot in $SLOTS; do
            [ "$slot" = "$old_active" ] && continue
            break
        done
    fi
    [ -n "$slot" ] || return 1

    log "OFFLINE recovery: searching configured VPN ranks best-to-worst"

    for rank in $(rank_order); do
        rank_has_peers "$rank" || continue
        tries=0
        while [ "$tries" -lt "$DOWNTIER_ATTEMPTS" ]; do
            peer="$(next_peer_for_rank "$rank" "" "" "")" || break

            prepare_iface "$slot" "$peer" "offline-recovery"
            rc=$?
            case "$rc" in
                0)
                    if promote_iface "$slot" "$peer" "offline-recovery"; then
                        log "OFFLINE recovery succeeded: $(iface_summary "$slot")"
                        wan_recovery_notification
                        return 0
                    fi
                    teardown_iface "$slot" >/dev/null 2>&1 || true
                    ;;
                2) return 2;;
                3)
                    return 1
                    ;;
            esac
            tries=$((tries + 1))
        done
    done

    log "CRITICAL: offline recovery could not establish any configured VPN rank"
    return 1
}

repair_prepared_slots() {
    local iface
    for iface in $SLOTS; do
        hs_owned "$iface" && owned_hard_up "$iface" || continue
        prepared_dataplane_matches "$iface" && continue
        slow_command /usr/bin/rtp2.sh hotswapper_prepare "$iface" || return 1
        prepare_dataplane "$iface" || return 1
    done
}

run_cycle() {
    local roles current cp cr ct down up target epoch="$PROMOTION_EPOCH" rc
    WAN_CYCLE_RESULT=""
    maybe_clear_expired_backoff
    if [ -f "$WAN_PENDING_FILE" ]; then
        recover_offline_best || true
        refresh_detector_roles
        SLOW_REQUESTED=0
        return 0
    fi
    repair_prepared_slots || return 1
    roles="$(reconcile_roles)"
    IFS='|' read -r current cp cr ct down up target <<EOF
$roles
EOF
    DETECT_CURRENT="$current"; DETECT_DOWN="$down"; DETECT_UP="$up"
    rc=1
    if [ "$DETECT_FAILED" = 0 ] && [ -n "$current" ] && [ "${cr:-0}" -gt 0 ]; then
        iface_healthy "$current"; rc=$?
    fi
    [ "$epoch" = "$PROMOTION_EPOCH" ] && [ "$current" = "$(current_iface)" ] || { refresh_detector_roles; return 0; }
    if [ "$DETECT_FAILED" = 1 ] || [ "$rc" -ne 0 ]; then
        DETECT_FAILED=1
        rm -f "$RUNTIME_DIR/ready.$current"
        SLOW_REQUESTED=1
        promote_hot_candidate "$current" "$cp" "$cr" "$ct" "$down" "$up"; rc=$?
        [ "$rc" != 2 ] || return 0
        if [ "$rc" != 0 ]; then
            recover_emergency "$current" "$cp" "$cr" "$ct"; rc=$?
            [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ] || recover_offline_best || true
        fi
    else
        SLOW_REQUESTED=0
        rm -f "$WAN_STATE_FILE"
        if [ -n "$up" ] && ! iface_healthy "$up"; then
            hs_lock || return 1
            hs_disarm "$up"
            hs_unlock
            up=""; DETECT_UP=""
        fi
        [ "$epoch" = "$PROMOTION_EPOCH" ] || { refresh_detector_roles; return 0; }
        if [ "$ct" -eq 3 ] && [ -n "$up" ]; then
            promote_iface "$up" "$(iface_peer "$up")" higher-major-tier-recovery || true
        else
            if [ -n "$up" ]; then
                cleanup_extras "$current" "$up"
            else
                ensure_downtier "$current" "$cp" "$cr" "$ct" "$down" "$(free_slot "$current" "$down")" || true
                [ "$DETECT_FAILED" = 0 ] && [ "$epoch" = "$PROMOTION_EPOCH" ] && [ "$current" = "$(current_iface)" ] || { refresh_detector_roles; return 0; }
                rm -f "$RUNTIME_DIR/preparing"
                roles="$(reconcile_roles)"
                IFS='|' read -r current cp cr ct down up target <<EOF
$roles
EOF
                DETECT_DOWN="$down"; DETECT_UP="$up"
            fi
            probe_recovery_targets "$current" "$cp" "$cr" "$ct" "$down" "$up" || true
        fi
    fi
    rm -f "$RUNTIME_DIR/preparing"
    refresh_detector_roles
    SLOW_REQUESTED=0
    if [ "$DETECT_FAILED" = 1 ] && [ -z "$WAN_CYCLE_RESULT" ]; then SLOW_REQUESTED=1; fi
}

pre_reboot_recover_core() {
    local roles current ap ar at downtier uptier target_rank
    local existing peer rc tries=0 preferred_rank slot

    roles="$(reconcile_roles)"
    IFS='|' read -r current ap ar at downtier uptier target_rank <<EOF
$roles
EOF

    if [ -z "$current" ] || [ -z "$ap" ] || [ "${ar:-0}" -eq 0 ]; then
        log "PRE-REBOOT: cannot reconcile current VPN; no Tier 1 recovery attempted"
        echo "PRE-REBOOT: current VPN could not be reconciled."
        return 1
    fi

    if [ "$at" -ne 2 ] 2>/dev/null; then
        log "PRE-REBOOT: current major tier is $at, not Tier 2; no special recovery needed"
        echo "PRE-REBOOT: current VPN is Tier $at; Tier 2 -> Tier 1 recovery not needed."
        return 0
    fi

    log "PRE-REBOOT: Tier 2 current ($(iface_summary "$current")); attempting one deliberate recovery to Tier 1"

    for preferred_rank in $(tier1_ranks); do
    tries=0
    # Reuse an already-live configured Tier 1 tunnel if available.
    existing="$(find_healthy_iface_for_rank "$preferred_rank" "$current" 2>/dev/null)"
    if [ -n "$existing" ]; then
        peer="$(iface_peer "$existing" 2>/dev/null)"
        if promote_iface "$existing" "$peer" "pre-reboot-tier1-recovery"; then
            cooperative_pause 2
            if [ "$(peer_tier "$(current_peer 2>/dev/null)")" -eq 1 ] 2>/dev/null && iface_healthy "$(current_iface)"; then
                log "PRE-REBOOT: Tier 1 recovery verified using existing tunnel"
                echo "PRE-REBOOT: recovered to Tier 1 and verified."
                return 0
            fi
        fi
        log "PRE-REBOOT: existing Tier 1 tunnel could not be promoted/verified"
    fi

    if in_backoff; then
        log "PRE-REBOOT: Nord auxiliary backoff active; Tier 1 attempt cannot be generated now"
        echo "PRE-REBOOT: Tier 1 recovery failed/blocked by Nord backoff."
        return 1
    fi

    slot="$(free_slot "$current" "$downtier" 2>/dev/null)"
    if [ -z "$slot" ]; then
        log "PRE-REBOOT: no auxiliary slot available for Tier 1 probe"
        echo "PRE-REBOOT: no slot available for Tier 1 recovery."
        return 1
    fi

    while [ "$tries" -lt "$DOWNTIER_ATTEMPTS" ]; do
        peer="$(next_peer_for_rank "$preferred_rank" "$ap" "$(iface_peer "$downtier" 2>/dev/null)" "")" || break

        prepare_iface "$slot" "$peer" "pre-reboot-recovery"
        rc=$?

        case "$rc" in
            0)
                if promote_iface "$slot" "$peer" "pre-reboot-tier1-recovery"; then
                    cooperative_pause 2
                    if [ "$(peer_tier "$(current_peer 2>/dev/null)")" -eq 1 ] 2>/dev/null && iface_healthy "$(current_iface)"; then
                        log "PRE-REBOOT: Tier 1 recovery verified: $(iface_summary "$(current_iface)")"
                        echo "PRE-REBOOT: recovered to Tier 1 and verified."
                        return 0
                    fi
                fi
                teardown_iface "$slot" >/dev/null 2>&1 || true
                ;;
            2)
                log "PRE-REBOOT: current Tier 2 tunnel failed while Tier 1 was being probed"
                echo "PRE-REBOOT: Tier 1 recovery aborted because the current tunnel failed."
                return 1
                ;;
            3)
                log "PRE-REBOOT: Tier 1 recovery blocked by Nord/API backoff"
                echo "PRE-REBOOT: Tier 1 recovery failed/blocked by Nord backoff."
                return 1
                ;;
        esac

        tries=$((tries + 1))
    done

    done
    log "PRE-REBOOT: Tier 1 recovery attempt finished without a working preferred tunnel"
    echo "PRE-REBOOT: Tier 1 recovery attempt failed."
    return 1
}

handle_pre_reboot_request() {
    local token rc

    [ -f "$PRE_REBOOT_REQUEST_FILE" ] || return 0
    token="$(cat "$PRE_REBOOT_REQUEST_FILE" 2>/dev/null)"
    [ -n "$token" ] || {
        rm -f "$PRE_REBOOT_REQUEST_FILE"
        return 0
    }

    rm -f "$PRE_REBOOT_REQUEST_FILE"
    log "PRE-REBOOT: daemon received request token=$token"

    pre_reboot_recover_core
    rc=$?

    printf '%s|%s\n' "$token" "$rc" > "$PRE_REBOOT_RESULT_FILE"
    sync
    return 0
}

pre_reboot_recover_once() {
    acquire_lock || {
        echo "hotswapper is already running; use the daemon request mechanism."
        return 2
    }

    start_ownership || return 1
    pre_reboot_recover_core
}


show_status() {
    local roles current cp cr ct down up target preparing_current purpose slot peer
    roles="$(reconcile_roles)"
    IFS='|' read -r current cp cr ct down up target <<EOF
$roles
EOF
    if [ -f "$RUNTIME_DIR/preparing" ]; then
        IFS='|' read -r preparing_current purpose slot peer < "$RUNTIME_DIR/preparing"
        [ "$preparing_current" = "$current" ] || purpose=""
    fi
    case "$(cat "$WAN_STATE_FILE" 2>/dev/null)" in
        WAN_OFFLINE|WAN_SUSPECT|WAN_UNKNOWN) echo "WAN: $(cat "$WAN_STATE_FILE") (VPN recovery paused)";;
    esac
    echo "CURRENT:   $(iface_summary "$current")"
    if [ -n "$up" ]; then echo "UPTIER:    $(iface_summary "$up") [hot]"
    elif [ "$purpose" = uptier ]; then echo "UPTIER:    $slot preparing"
    else echo "UPTIER:    none"; fi
    if [ -n "$up" ]; then echo "DOWNTIER:  not retained while UPTIER is hot"
    elif [ -n "$down" ]; then echo "DOWNTIER:  $(iface_summary "$down") [hot]"
    elif [ "$purpose" = downtier ]; then echo "DOWNTIER:  $slot preparing"
    else echo "DOWNTIER:  none"; fi
    in_backoff && echo "NORD BACKOFF: active" || echo "NORD BACKOFF: inactive"
    echo "Kill switch: $(policy_get killswitch 2>/dev/null || echo '?')"
}


classify_slots() {
    local iface peer loc rank tier hs age healthy
    for iface in $SLOTS; do
        peer="$(iface_peer "$iface" 2>/dev/null)"
        if [ -z "$peer" ]; then
            printf '%s  peer=?  location=?  rank=0  tier=0  runtime=absent
' "$iface"
            continue
        fi

        loc="$(peer_location "$peer")"
        rank="$(peer_rank "$peer")"
        tier="$(peer_tier "$peer")"
        hs="$(latest_handshake "$iface")"

        if [ "${hs:-0}" -gt 0 ] 2>/dev/null; then
            age=$(( $(now) - hs ))
        else
            age="none"
        fi

        if iface_healthy "$iface"; then
            healthy="healthy"
        elif ip link show "$iface" >/dev/null 2>&1; then
            healthy="up-no-fresh-handshake"
        else
            healthy="down"
        fi

        printf '%s  peer=%s  location=%s  rank=%s  tier=%s  runtime=%s  handshake_age=%ss
' \
            "$iface" "$peer" "${loc:-?}" "${rank:-0}" "${tier:-0}" "$healthy" "$age"
    done
}


test_failover_core() {
    local roles current ap ar at downtier uptier target_rank rc candidate

    roles="$(reconcile_roles)"
    IFS='|' read -r current ap ar at downtier uptier target_rank <<EOF
$roles
EOF

    if [ -z "$current" ] || [ -z "$ap" ] || [ "${ar:-0}" -eq 0 ]; then
        echo "Cannot reconcile the current current VPN."
        return 1
    fi

    candidate="${uptier:-$downtier}"
    if [ -z "$candidate" ]; then
        echo "No healthy precooked downtier is available; refusing synthetic failover test."
        return 1
    fi

    if ! iface_healthy "$candidate"; then
        echo "Precooked downtier is not healthy; refusing synthetic failover test."
        return 1
    fi

    echo "=== Synthetic CURRENT failure test ==="
    echo "Current CURRENT:    $(iface_summary "$current")"
    echo "Hot candidate:    $(iface_summary "$candidate")"
    echo
    echo "Injecting ONE synthetic failure event for the current CURRENT."
    echo "No peer/tier blacklist is created; the synthetic failure ends immediately after promotion."

    log "TEST: injecting one synthetic CURRENT failure event current=$current peer=$ap rank=$ar"

    promote_hot_candidate "$current" "$ap" "$ar" "$at" "$downtier" "$uptier"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "Synthetic failover promotion FAILED."
        show_status
        return 1
    fi

    echo
    echo "=== After forced failover ==="
    show_status

    # Synthetic failure is over. Run the ordinary post-failover management
    # cycle. Tier 2 remains sticky by policy, so this should rebuild the next
    # lower fallback without automatically returning to the preferred tier.
    rm -f "$LAST_UPTIER_FILE"
    cooperative_pause 2

    echo
    echo "=== Running normal post-failover cycle ==="
    run_cycle

    echo
    echo "=== Final state ==="
    show_status
    return 0
}

handle_test_failover_request() {
    local token rc output_file

    [ -f "$TEST_FAILOVER_REQUEST_FILE" ] || return 0
    token="$(cat "$TEST_FAILOVER_REQUEST_FILE" 2>/dev/null)"
    [ -n "$token" ] || {
        rm -f "$TEST_FAILOVER_REQUEST_FILE"
        return 0
    }

    rm -f "$TEST_FAILOVER_REQUEST_FILE"
    log "TEST: daemon received synthetic failover request token=$token"

    # Capture the detailed test output so the waiting CLI can print exactly
    # what the daemon did, while keeping the daemon as the sole VPN owner.
    output_file="$RUNTIME_DIR/test-failover-output.$token"
    test_failover_core > "$output_file" 2>&1
    rc=$?
    printf '%s|%s|%s\n' "$token" "$rc" "$output_file" > "$TEST_FAILOVER_RESULT_FILE"
    return 0
}

is_daemon_running() {
    local pid cmdline
    [ -f "$LOCK_DIR/pid" ] || return 1
    pid="$(cat "$LOCK_DIR/pid" 2>/dev/null)"
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    [ -r "/proc/$pid/cmdline" ] || return 1
    cmdline="$(tr '\000' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
    echo "$cmdline" | grep -Fq '/root/hotswapper-main.sh daemon'
}

test_failover_once() {
    local token waited=0 result result_token rc output_file

    if ! is_daemon_running; then
        # Useful for maintenance: if no daemon owns the VPN, retain the old
        # direct test behavior under the normal single-instance lock.
        acquire_lock || {
            echo "hotswapper is already running, but its daemon could not be validated."
            return 1
        }
        start_ownership || return 1
        test_failover_core
        return $?
    fi

    token="test-$$-$(date +%s)"
    rm -f "$TEST_FAILOVER_RESULT_FILE"
    printf '%s\n' "$token" > "$TEST_FAILOVER_REQUEST_FILE"

    echo "Synthetic failover request sent to the running hotswapper daemon."
    echo "Waiting for daemon result (timeout ${TEST_FAILOVER_TIMEOUT}s)..."

    while [ "$waited" -lt "$TEST_FAILOVER_TIMEOUT" ]; do
        if [ -f "$TEST_FAILOVER_RESULT_FILE" ]; then
            result="$(cat "$TEST_FAILOVER_RESULT_FILE" 2>/dev/null)"
            result_token="${result%%|*}"
            if [ "$result_token" = "$token" ]; then
                rest="${result#*|}"
                rc="${rest%%|*}"
                output_file="${rest#*|}"
                [ -f "$output_file" ] && cat "$output_file"
                rm -f "$output_file" "$TEST_FAILOVER_RESULT_FILE"
                return "${rc:-1}"
            fi
        fi
        sleep 1
        waited=$((waited + 1))
    done

    echo "Synthetic failover test TIMED OUT waiting for the daemon."
    echo "Check: /root/hotswapper-main.sh log 30"
    return 1
}

daemon_loop() {
    acquire_lock || { echo "Hotswapper is already running."; exit 1; }
    local next_slow=0 interval title body
    verify_delay || { log "Sub-second delay capability failed"; return 1; }
    POLICY_SECTION=$(policy_section)
    trap 'WAKE_REQUESTED=1; prune_detector_candidates; [ -z "$DELAY_PID" ] || kill "$DELAY_PID" 2>/dev/null || true' USR1
    start_ownership || { log "Unable to establish firmware ownership"; return 1; }
    DETECTOR_ENABLED=1
    refresh_detector_roles
    log "Hotswapper started; owned slots and 400 ms detector cadence"
    while true; do
        detector_iteration
        if [ "$SLOW_REQUESTED" = 1 ] || [ "$DETECTOR_NOW" -ge "$next_slow" ]; then
            SLOW_REQUESTED=0
            refresh_detector_roles
            handle_pre_reboot_request
            handle_test_failover_request
            run_cycle || log "Hotswapper slow cycle returned non-zero"
            if [ -f "$RUNTIME_DIR/promotion-log" ]; then
                log "$(cat "$RUNTIME_DIR/promotion-log")"
                rm -f "$RUNTIME_DIR/promotion-log"
            fi
            if [ -f "$RUNTIME_DIR/promotion-trace" ]; then
                promo_trace "$(cat "$RUNTIME_DIR/promotion-trace")"
                rm -f "$RUNTIME_DIR/promotion-trace"
            fi
            if [ -f "$RUNTIME_DIR/notification-title" ]; then
                title="$(cat "$RUNTIME_DIR/notification-title")"; body="$(cat "$RUNTIME_DIR/notification-body")"
                rm -f "$RUNTIME_DIR/notification-title" "$RUNTIME_DIR/notification-body"
                notify "$title" "$body" || true
            fi
            interval="$LOOP_SECONDS"
            case "$(cat "$WAN_STATE_FILE" 2>/dev/null)" in WAN_OFFLINE|WAN_SUSPECT|WAN_UNKNOWN) interval=10;; esac
            next_slow=$(( $(monotonic_ms) + interval * 1000 ))
        fi
    done
}

case "${1:-status}" in
    verify-current) verify_current; exit $?;;
    _wan_probe) wan_probe_round; exit $?;;
    status)
        show_status
        ;;
    once)
        acquire_lock || { echo "hotswapper is already running."; exit 1; }
        start_ownership || exit 1
        run_cycle
        show_status
        ;;
    daemon|run)
        daemon_loop
        ;;
    notify_test)
        if notify "Hotswapper Test" "hotswapper notification test succeeded."; then
            echo "Notification sent successfully."
        else
            rc=$?
            echo "Notification FAILED (rc=$rc). Check NTFY_URL/network and hotswapper log."
            exit "$rc"
        fi
        ;;
    clear_backoff)
        rm -f "$BACKOFF_FILE"
        echo "Nord auxiliary backoff cleared."
        ;;
    classify)
        classify_slots
        ;;
    test_failover|test_fail)
        test_failover_once
        ;;
    pre_reboot_recover)
        pre_reboot_recover_once
        ;;
    log)
        tail -n "${2:-80}" "$LOG_FILE" 2>/dev/null
        ;;
    *)
        echo "Usage: $0 {status|once|daemon|notify_test|clear_backoff|classify|test_failover|pre_reboot_recover|log [lines]}"
        exit 1
        ;;
esac
