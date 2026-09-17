#!/bin/sh

# GL.iNet / NordVPN three-slot watchdog v14.1 guarded fastpath
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
# v14.1: v14 guarded fastpath with detailed promotion timing disabled by default.
# Set DEBUG_TIMING=1 in /root/hotswapper/hotswapper.conf to restore promotion-timing.log writes.

TUNNEL_ID=""
GROUP_ID=""
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

# Optional local config. Keep secrets here rather than in this script.
# Supported variables:
#   NTFY_URL='https://ntfy.sh/<your-topic>'
#   LOOP_SECONDS=20
#   UPTIER_INTERVAL=60
#   CONNECT_TIMEOUT=18
#   HANDSHAKE_MAX_AGE=75
#   DOWNTIER_ATTEMPTS=3
#   DEBUG_TIMING=1       # optional detailed promotion timing log (default 0)
CONFIG_FILE="/root/hotswapper/hotswapper.conf"

LOOP_SECONDS=20
UPTIER_INTERVAL=60
CONNECT_TIMEOUT=18
HANDSHAKE_MAX_AGE=75
DOWNTIER_ATTEMPTS=3
KEEPALIVE_PROBE_INTERVAL=20
KEEPALIVE_PROBE_TARGETS="1.1.1.1 8.8.8.8 208.67.222.222 208.67.220.220"
KEEPALIVE_PROBE_TIMEOUT=2
PATH_FAILURE_THRESHOLD=2
LOG_MAX_BYTES=524288
NORD_BACKOFF_SECONDS=900
NTFY_URL=""
DEBUG_TIMING=0
# Microseconds; each completed pass is followed by this delay.
DETECTOR_DELAY_US=150000
FAST_PROBE_WINDOW_US=200000
FAST_FAILURE_THRESHOLD=2
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

[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"

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
    [ "$pid" = "$$" ] && rm -rf "$LOCK_DIR" 2>/dev/null
}

acquire_lock() {
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        echo $$ > "$LOCK_DIR/pid"
        trap 'release_lock' EXIT
        trap 'release_lock; exit 0' INT TERM
        return 0
    fi

    local pid=""
    [ -f "$LOCK_DIR/pid" ] && pid="$(cat "$LOCK_DIR/pid" 2>/dev/null)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        return 1
    fi

    # Stale lock left by a crashed/killed process.
    rm -rf "$LOCK_DIR" 2>/dev/null
    mkdir "$LOCK_DIR" 2>/dev/null || return 1
    echo $$ > "$LOCK_DIR/pid"
    trap 'release_lock' EXIT
    trap 'release_lock; exit 0' INT TERM
    return 0
}

# BusyBox applets are build-dependent. Both installer and daemon verify elapsed
# time, not just command existence. No fractional sleep or whole-second fallback.
delay_us() {
    busybox usleep "$1"
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
    local command_rc
    if [ "$IN_DETECTOR" = 1 ] || [ "${PROMOTION_CRITICAL:-0}" = 1 ]; then "$@" >/dev/null 2>&1; return $?; fi
    if [ "$DETECTOR_ENABLED" != 1 ]; then
        "$@" > "$RUNTIME_DIR/command-output" 2>&1
        return $?
    fi
    # One owned child command, never another detector or detached worker.
    # The shell owns all promotions; a provider command only prepares an unused slot.
    "$@" <&0 > "$RUNTIME_DIR/command-output" 2>&1 &
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
    local iface="$1" first second r1 r2
    # Concurrent *packets*, not concurrent detector passes. Both children are
    # always reaped before returning. No GNU timeout/fractional ping assumption.
    ping -n -I "$iface" -c 1 -W 1 -w 1 1.1.1.1 >/dev/null 2>&1 & first=$!
    ping -n -I "$iface" -c 1 -W 1 -w 1 8.8.8.8 >/dev/null 2>&1 & second=$!
    delay_us "$FAST_PROBE_WINDOW_US" || { kill "$first" "$second" 2>/dev/null; wait "$first"; wait "$second"; exit 1; }
    kill "$first" "$second" 2>/dev/null || true
    wait "$first"; r1=$?
    wait "$second"; r2=$?
    [ "$r1" -eq 0 ] || [ "$r2" -eq 0 ]
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
    local selected candidate peer failed=0
    [ "$IN_DETECTOR" = 0 ] || return 0
    selected="$(current_iface)"
    if [ "$selected" != "$DETECT_CURRENT" ]; then
        # GL can change policy independently. Never use stale cached role identity.
        DETECT_CURRENT="$selected"; DETECT_UP=""; DETECT_DOWN=""; DETECT_FAILED=0
        FAST_FAILURES=0; SLOW_REQUESTED=1
        return 0
    fi
    [ "$SLOW_REQUESTED" = 0 ] && [ "$DETECT_FAILED" = 0 ] || return 0
    if ! iface_hard_up "$DETECT_CURRENT"; then
        failed=1
    elif fast_path_round "$DETECT_CURRENT"; then
        FAST_FAILURES=0
    else
        FAST_FAILURES=$((FAST_FAILURES + 1))
        [ "$FAST_FAILURES" -lt "$FAST_FAILURE_THRESHOLD" ] || failed=1
    fi
    [ "$failed" = 1 ] || return 0
    IN_DETECTOR=1
    DETECT_FAILED=1
    rm -f "$RUNTIME_DIR/ready.$DETECT_CURRENT"
    # Cached roles only: no rank searches, WAN diagnosis or provider work here.
    for candidate in "$DETECT_UP" "$DETECT_DOWN"; do
        [ -n "$candidate" ] && [ "$candidate" != "$DETECT_CURRENT" ] || continue
        iface_hard_up "$candidate" && fast_path_round "$candidate" || continue
        peer="$(iface_peer "$candidate")"
        if promote_iface "$candidate" "$peer" current-failure-hot-candidate; then
            DETECT_CURRENT="$candidate"; DETECT_UP=""; DETECT_DOWN=""
            FAST_FAILURES=0; DETECT_FAILED=0
            rm -f "$LAST_UPTIER_FILE" "$WAN_STATE_FILE"
            break
        fi
    done
    IN_DETECTOR=0
    SLOW_REQUESTED=1
}

detector_iteration() {
    fast_health_pass
    # Delay starts AFTER the complete pass, including any promotion.
    delay_us "$DETECTOR_DELAY_US" || exit 1
}

policy_section() {
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
    slow_command ifdown "$iface" || true
    slow_command /usr/bin/setup_instance stop "$iface" || true
    slow_command /usr/bin/setup_instance clean "$iface" || true
    rm -f "$RUNTIME_DIR/ready.$iface" "/tmp/wireguard/${iface}_state" "$(probe_stamp_file "$iface")" "$(health_fail_file "$iface")" 2>/dev/null
    return 0
}

# Returns:
#   0 = connected successfully
#   1 = ordinary candidate failure
#   2 = current tunnel failed while a recovery probe was in progress
#   3 = global Nord auxiliary backoff is active / was just entered
prepare_iface() {
    local iface="$1" peer="$2" purpose="$3"
    local out rc i current state epoch="$PROMOTION_EPOCH"

    in_backoff && return 3

    current="$(current_iface)"
    [ "$iface" != "$current" ] || return 1

    printf '%s|%s|%s|%s\n' "$current" "$purpose" "$iface" "$peer" > "$RUNTIME_DIR/preparing"
    teardown_iface "$iface" || return 1

    log "Preparing $purpose candidate on $iface: peer=$peer server=$(peer_name "$peer") location=$(peer_location "$peer")"

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

    slow_command ifup "$iface" || true
    [ "$epoch" = "$PROMOTION_EPOCH" ] && [ "$current" = "$(current_iface)" ] || return 2

    i=0
    while [ "$i" -lt "$CONNECT_TIMEOUT" ]; do
        if iface_established_fresh "$iface"; then
            # Prove that this specific tunnel also carries traffic before accepting it.
            if probe_iface_path "$iface"; then
                [ "$epoch" = "$PROMOTION_EPOCH" ] && [ "$current" = "$(current_iface)" ] || return 2
                printf '%s\n' "$peer" > "$RUNTIME_DIR/ready.$iface"
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
        [ "$(cat "$RUNTIME_DIR/ready.$iface" 2>/dev/null)" = "$peer" ] || continue
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

fastpath_prepare_firewall() {
    local iface="$1"

    # rtp2 normally creates a firewall zone only for the selected VPN
    # interface. A precooked downtier therefore needs the minimum equivalent
    # dataplane rules before we can point LAN traffic at it.
    iptables -w -t filter -C FORWARD -i br-lan -o "$iface" -j ACCEPT >/dev/null 2>&1 ||
        iptables -w -t filter -I FORWARD 1 -i br-lan -o "$iface" -j ACCEPT || return 1
    iptables -w -t filter -C FORWARD -i "$iface" -o br-lan -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 ||
        iptables -w -t filter -I FORWARD 1 -i "$iface" -o br-lan -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || return 1
    iptables -w -t nat -C POSTROUTING -o "$iface" -j MASQUERADE >/dev/null 2>&1 ||
        iptables -w -t nat -I POSTROUTING 1 -o "$iface" -j MASQUERADE || return 1
    iptables -w -t mangle -C FORWARD -o "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 ||
        iptables -w -t mangle -I FORWARD 1 -o "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || return 1
    return 0
}

fastpath_install_mark_override() {
    local mark="$1"

    # ROUTE_POLICY rule 1 restores an existing connmark. Insert immediately
    # after it so even established LAN flows are forced onto the newly current
    # precooked interface instead of retaining the old interface mark.
    # Delete our previous override first, if present.
    while iptables -w -t mangle -D ROUTE_POLICY \
        -m comment --comment "hotswapper-fastpath" \
        -m addrtype ! --dst-type LOCAL \
        -m set ! --match-set "dst_net${TUNNEL_ID}" dst \
        -j MARK --set-xmark "$mark/0xf000" >/dev/null 2>&1; do :; done

    # Remove an override carrying a different old mark. There can be at most
    # one from us; identify it by comment and delete by line number.
    local n
    n="$(iptables -w -t mangle -L ROUTE_POLICY --line-numbers -n 2>/dev/null | awk '/hotswapper-fastpath/ {print $1; exit}')"
    [ -n "$n" ] && iptables -w -t mangle -D ROUTE_POLICY "$n" || true

    iptables -w -t mangle -I ROUTE_POLICY 2 \
        -m comment --comment "hotswapper-fastpath" \
        -m addrtype ! --dst-type LOCAL \
        -m set ! --match-set "dst_net${TUNNEL_ID}" dst \
        -j MARK --set-xmark "$mark/0xf000"
}

fastpath_verify_kernel() {
    local iface="$1" mark="$2" table idx
    idx="${iface#wgclient}"
    table="100${idx}"

    ip link show "$iface" >/dev/null 2>&1 || return 1
    ip route show table "$table" 2>/dev/null | grep -q "^default dev $iface" || return 1
    ip rule show 2>/dev/null | grep -q "fwmark $mark/0xf000 lookup $table" || return 1
    return 0
}

gl_guard_flag="$RUNTIME_DIR/promotion-in-progress"
gl_guard_pending="$RUNTIME_DIR/gl-reconcile-pending"

acquire_gl_guard() {
    # rtp2.sh guard v1 accepts this lock only while this PID is alive and the
    # timestamp is <=5 seconds old. Use an atomic rename so rtp2 never sees a
    # half-written flag.
    local tmp="${gl_guard_flag}.$$"
    rm -f "$gl_guard_pending" "$tmp"
    {
        echo "pid=$$"
        echo "started=$(now)"
    } > "$tmp" || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$gl_guard_flag" || { rm -f "$tmp"; return 1; }
    return 0
}

release_gl_guard() {
    rm -f "$gl_guard_flag"
    if [ -s "$gl_guard_pending" ]; then
        local n
        n="$(wc -l < "$gl_guard_pending" 2>/dev/null)"
        log "GL_GUARD deferred_rtp2_calls=${n:-unknown}; final state will be verified by hotswapper; details=$gl_guard_pending"
    fi
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

    count="$(iptables -w -t mangle -L ROUTE_POLICY --line-numbers -n 2>/dev/null | grep -c 'hotswapper-fastpath')"
    [ "$count" = "1" ] || return 1
    rule="$(iptables -w -t mangle -S ROUTE_POLICY 2>/dev/null | grep 'hotswapper-fastpath')"
    echo "$rule" | grep -Fq -- "--set-xmark $mark/0xf000" || return 1
    return 0
}

restore_policy_metadata() {
    local sec="$1" peer="$2" group="$3" iface="$4" mark="$5"
    [ -n "$peer" ] && uci set "route_policy.${sec}.peer_id=$peer"
    [ -n "$group" ] && uci set "route_policy.${sec}.group_id=$group"
    [ -n "$iface" ] && uci set "route_policy.${sec}.via=$iface"
    [ -n "$mark" ] && uci set "route_policy.${sec}.mark=$mark"
    uci commit route_policy >/dev/null 2>&1 || true
}

fastpath_rollback() {
    local sec="$1" old_peer="$2" old_group="$3" old_iface="$4" old_mark="$5" why="$6"
    log "FAST_ROLLBACK reason=$why old_iface=$old_iface old_peer=$old_peer old_mark=$old_mark"

    # Connectivity first: if the old independent table still exists, restore
    # the dataplane before repairing GL/UCI bookkeeping.
    if [ -n "$old_iface" ] && [ -n "$old_mark" ] && fastpath_verify_kernel "$old_iface" "$old_mark"; then
        fastpath_prepare_firewall "$old_iface" >/dev/null 2>&1 || true
        fastpath_install_mark_override "$old_mark" >/dev/null 2>&1 || true
    fi
    restore_policy_metadata "$sec" "$old_peer" "$old_group" "$old_iface" "$old_mark"
}

promote_iface() {
    local PROMOTION_CRITICAL=1 # No cooperative yields inside the verified transaction.
    local iface="$1" peer="$2" reason="$3"
    local sec new_tier old_tier old_peer old_iface old_group old_mark loc name title body mark
    local t0 t1 t2 t3 t4 t5 t6 t7 t8 t9 t10 t11 guard_held=0 flipped=0

    t0="$(monotonic_ms)"
    promo_trace "PROMO_BEGIN_V14_1 reason=$reason iface=$iface peer=$peer mono_ms=$t0"

    iface_healthy "$iface" || {
        t1="$(monotonic_ms)"
        promo_trace "PROMO_ABORT stage=initial_iface_healthy elapsed_ms=$((t1-t0))"
        log "Refusing promotion of unhealthy interface $iface"
        return 1
    }
    t1="$(monotonic_ms)"
    promo_trace "PROMO_STAGE initial_iface_healthy_ms=$((t1-t0)) cumulative_ms=$((t1-t0))"

    if ! probe_iface_path "$iface"; then
        t2="$(monotonic_ms)"
        promo_trace "PROMO_ABORT stage=bound_probe stage_ms=$((t2-t1)) cumulative_ms=$((t2-t0))"
        log "Refusing promotion of $iface because immediate bound connectivity probe failed"
        return 1
    fi
    t2="$(monotonic_ms)"
    promo_trace "PROMO_STAGE bound_probe_ms=$((t2-t1)) cumulative_ms=$((t2-t0))"

    sec="$(policy_section)"
    [ -n "$sec" ] || return 1
    old_peer="$(uci -q get "route_policy.${sec}.peer_id")"
    old_group="$(uci -q get "route_policy.${sec}.group_id")"
    old_iface="$(uci -q get "route_policy.${sec}.via")"
    old_mark="$(uci -q get "route_policy.${sec}.mark")"
    old_tier="$(peer_tier "$old_peer")"
    new_tier="$(peer_tier "$peer")"
    mark="$(fastpath_mark_for_iface "$iface")" || return 1
    t3="$(monotonic_ms)"
    promo_trace "PROMO_STAGE metadata_lookup_ms=$((t3-t2)) cumulative_ms=$((t3-t0)) section=$sec old_peer=$old_peer old_tier=$old_tier new_tier=$new_tier mark=$mark"

    fastpath_verify_kernel "$iface" "$mark" || {
        t4="$(monotonic_ms)"
        promo_trace "PROMO_ABORT stage=kernel_precheck stage_ms=$((t4-t3)) cumulative_ms=$((t4-t0))"
        log "Fast promotion precheck failed for $iface; refusing unsafe route flip"
        return 1
    }
    t4="$(monotonic_ms)"
    promo_trace "PROMO_STAGE kernel_precheck_ms=$((t4-t3)) cumulative_ms=$((t4-t0))"

    # Critical section starts only once all non-mutating checks have passed.
    acquire_gl_guard || {
        promo_trace "PROMO_ABORT stage=gl_guard_acquire cumulative_ms=$(($(monotonic_ms)-t0))"
        log "Unable to acquire GL reconciliation guard; refusing fast promotion"
        return 1
    }
    guard_held=1
    t5="$(monotonic_ms)"
    promo_trace "PROMO_GUARD_ACQUIRED stage_ms=$((t5-t4)) cumulative_ms=$((t5-t0))"

    fastpath_prepare_firewall "$iface" || {
        t6="$(monotonic_ms)"
        promo_trace "PROMO_ABORT stage=fast_firewall stage_ms=$((t6-t5)) cumulative_ms=$((t6-t0))"
        log "Fast promotion firewall preparation failed for $iface"
        release_gl_guard; guard_held=0
        return 1
    }
    t6="$(monotonic_ms)"
    promo_trace "PROMO_STAGE fast_firewall_ms=$((t6-t5)) cumulative_ms=$((t6-t0))"

    fastpath_install_mark_override "$mark" || {
        t7="$(monotonic_ms)"
        promo_trace "PROMO_ABORT stage=mark_flip stage_ms=$((t7-t6)) cumulative_ms=$((t7-t0))"
        log "Fast promotion mark flip failed for $iface"
        release_gl_guard; guard_held=0
        return 1
    }
    flipped=1
    t7="$(monotonic_ms)"
    promo_trace "PROMO_DATAPLANE_FLIPPED mark_flip_ms=$((t7-t6)) cumulative_ms=$((t7-t0)) iface=$iface mark=$mark"

    if ! probe_iface_path "$iface"; then
        t8="$(monotonic_ms)"
        promo_trace "PROMO_ABORT stage=postflip_probe stage_ms=$((t8-t7)) cumulative_ms=$((t8-t0))"
        fastpath_rollback "$sec" "$old_peer" "$old_group" "$old_iface" "$old_mark" "postflip-probe"
        release_gl_guard; guard_held=0
        return 1
    fi
    t8="$(monotonic_ms)"
    promo_trace "PROMO_STAGE postflip_probe_ms=$((t8-t7)) cumulative_ms=$((t8-t0))"

    uci set "route_policy.${sec}.peer_id=$peer" || { fastpath_rollback "$sec" "$old_peer" "$old_group" "$old_iface" "$old_mark" "uci-peer"; release_gl_guard; return 1; }
    uci set "route_policy.${sec}.group_id=$GROUP_ID" || { fastpath_rollback "$sec" "$old_peer" "$old_group" "$old_iface" "$old_mark" "uci-group"; release_gl_guard; return 1; }
    uci set "route_policy.${sec}.via=$iface" || { fastpath_rollback "$sec" "$old_peer" "$old_group" "$old_iface" "$old_mark" "uci-via"; release_gl_guard; return 1; }
    uci set "route_policy.${sec}.mark=$mark" || { fastpath_rollback "$sec" "$old_peer" "$old_group" "$old_iface" "$old_mark" "uci-mark"; release_gl_guard; return 1; }
    t9="$(monotonic_ms)"
    promo_trace "PROMO_STAGE uci_set_metadata_ms=$((t9-t8)) cumulative_ms=$((t9-t0))"

    if ! uci commit route_policy; then
        fastpath_rollback "$sec" "$old_peer" "$old_group" "$old_iface" "$old_mark" "uci-commit"
        release_gl_guard; guard_held=0
        return 1
    fi
    t10="$(monotonic_ms)"
    promo_trace "PROMO_STAGE uci_commit_ms=$((t10-t9)) cumulative_ms=$((t10-t0))"

    if ! fastpath_verify_consistency "$iface" "$peer" "$mark" "$sec"; then
        t11="$(monotonic_ms)"
        promo_trace "PROMO_ABORT stage=consistency_verify stage_ms=$((t11-t10)) cumulative_ms=$((t11-t0))"
        fastpath_rollback "$sec" "$old_peer" "$old_group" "$old_iface" "$old_mark" "consistency"
        release_gl_guard; guard_held=0
        return 1
    fi
    t11="$(monotonic_ms)"
    promo_trace "PROMO_STAGE consistency_verify_ms=$((t11-t10)) cumulative_ms=$((t11-t0))"

    release_gl_guard
    guard_held=0
    promo_trace "PROMO_GUARD_RELEASED cumulative_ms=$(($(monotonic_ms)-t0))"

    # A deferred rtp2 invocation is diagnostic evidence of a real collision.
    # Do not replay it blindly: our now-verified final GL/UCI/kernel state makes
    # a stale reconciliation potentially destructive and usually unnecessary.
    if [ -s "$gl_guard_pending" ]; then
        log "GL reconciliation collided with promotion; deferred call retained at $gl_guard_pending"
    fi

    [ "$(current_iface)" = "$iface" ] || {
        log "Promotion post-unlock verification failed: policy no longer on $iface"
        return 1
    }

    loc="$(peer_location "$peer")"
    name="$(peer_name "$peer")"
    promo_trace "PROMO_END_V14_1 total_ms=$(($(monotonic_ms)-t0)) dataplane_flip_at_ms=$((t7-t0)) reason=$reason iface=$iface peer=$peer server=$name location=$loc"

    PROMOTION_EPOCH=$((PROMOTION_EPOCH + 1))
    DETECT_CURRENT="$iface"; DETECT_UP=""; DETECT_DOWN=""; FAST_FAILURES=0; DETECT_FAILED=0
    log "PROMOTED_FAST_GUARDED reason=$reason old_major_tier=$old_tier new_major_tier=$new_tier current=$(iface_summary "$iface")"

    if [ "$new_tier" != "${old_tier:-0}" ]; then
        if [ "${old_tier:-0}" -eq 0 ] 2>/dev/null; then
            title="VPN Restored"
        elif [ "$new_tier" -gt "$old_tier" ] 2>/dev/null; then
            title="VPN Degraded"
        elif [ "$new_tier" -eq 1 ] 2>/dev/null; then
            title="VPN Restored"
        else
            title="VPN Improved"
        fi

        case "$new_tier" in
            1) body="Preferred gateway in use: $name ($loc)." ;;
            2) body="Fallback gateway in use: $name ($loc)." ;;
            3) body="Last-resort gateway in use: $name ($loc)." ;;
            *) body="VPN gateway changed: $name ($loc)." ;;
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
        [ -n "$candidate" ] && iface_healthy "$candidate" || continue
        peer="$(iface_peer "$candidate")"
        promote_iface "$candidate" "$peer" current-failure-hot-candidate && return 0
    done
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
        if ! promote_hot_candidate "$current" "$cp" "$cr" "$ct" "$down" "$up"; then
            recover_emergency "$current" "$cp" "$cr" "$ct"; rc=$?
            [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ] || recover_offline_best || true
        fi
    else
        SLOW_REQUESTED=0
        rm -f "$WAN_STATE_FILE"
        if [ -n "$up" ] && ! iface_healthy "$up"; then
            rm -f "$RUNTIME_DIR/ready.$up"; up=""; DETECT_UP=""
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
    DETECTOR_ENABLED=1
    refresh_detector_roles
    log "Hotswapper started; serial 150 ms post-pass detector delay"
    while true; do
        detector_iteration
        if [ "$SLOW_REQUESTED" = 1 ] || [ "$(monotonic_ms)" -ge "$next_slow" ]; then
            SLOW_REQUESTED=0
            refresh_detector_roles
            handle_pre_reboot_request
            handle_test_failover_request
            run_cycle || log "Hotswapper slow cycle returned non-zero"
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
    _wan_probe) wan_probe_round; exit $?;;
    status)
        show_status
        ;;
    once)
        acquire_lock || { echo "hotswapper is already running."; exit 1; }
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
