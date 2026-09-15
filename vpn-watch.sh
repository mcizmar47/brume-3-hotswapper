#!/bin/sh

# GL.iNet / NordVPN three-slot watchdog v14.1 guarded fastpath
# - one ACTIVE tunnel
# - one hot STANDBY on the next lower tier
# - one RECOVERY slot for probing better tiers
#
# User-facing major tiers:
#   1 Croatia/Zagreb
#   2 Europe: Austria/Vienna -> Spain/Barcelona -> Norway/Oslo -> Malta/Valletta
#   3 Last-resort: New York -> Boston -> Ashburn -> Israel/Tel Aviv
#
# Recovery policy:
#   - Tier 1: sticky; no recovery work
#   - Tier 2: sticky; no recovery to Tier 1 and no same-tier "upgrades"
#   - Tier 3: may recover only to Tier 1 or Tier 2
#   - Offline: recover best-to-worst across all configured ranks
#
# The hot standby is always the next configured LOWER internal rank.
# Notifications are sent only when the MAJOR tier changes.
# v14.1: v14 guarded fastpath with detailed promotion timing disabled by default.
# Set DEBUG_TIMING=1 in /root/vpn-watch.conf to restore promotion-timing.log writes.

TUNNEL_ID="5779"
GROUP_ID="10004"
PROFILE_FILE="/etc/vpn_profiles.d/profile${TUNNEL_ID}"
SLOTS="wgclient1 wgclient2 wgclient3"

PERSIST_DIR="/root/.vpn-watch"
RUNTIME_DIR="/tmp/vpn-watch"
STATE_FILE="$RUNTIME_DIR/state"
LOG_FILE="$PERSIST_DIR/vpn-watch.log"
LOCK_DIR="$RUNTIME_DIR/lock"
BACKOFF_FILE="$RUNTIME_DIR/nord-backoff-until"
LAST_RECOVERY_FILE="$RUNTIME_DIR/last-recovery"
PRE_REBOOT_REQUEST_FILE="$RUNTIME_DIR/pre-reboot-request"
PRE_REBOOT_RESULT_FILE="$RUNTIME_DIR/pre-reboot-result"
TEST_FAILOVER_REQUEST_FILE="$RUNTIME_DIR/test-failover-request"
TEST_FAILOVER_RESULT_FILE="$RUNTIME_DIR/test-failover-result"
TEST_FAILOVER_TIMEOUT=90

# Optional local config. Keep secrets here rather than in this script.
# Supported variables:
#   NTFY_URL='https://ntfy.sh/<your-topic>'
#   LOOP_SECONDS=20
#   RECOVERY_INTERVAL=60
#   CONNECT_TIMEOUT=18
#   HANDSHAKE_MAX_AGE=75
#   STANDBY_ATTEMPTS=3
#   DEBUG_TIMING=1       # optional detailed promotion timing log (default 0)
CONFIG_FILE="/root/vpn-watch.conf"

LOOP_SECONDS=20
RECOVERY_INTERVAL=60
CONNECT_TIMEOUT=18
HANDSHAKE_MAX_AGE=75
STANDBY_ATTEMPTS=3
KEEPALIVE_PROBE_INTERVAL=20
KEEPALIVE_PROBE_TARGETS="1.1.1.1 8.8.8.8 208.67.222.222 208.67.220.220"
KEEPALIVE_PROBE_TIMEOUT=2
PATH_FAILURE_THRESHOLD=2
LOG_MAX_BYTES=524288
NORD_BACKOFF_SECONDS=900
NTFY_URL=""
DEBUG_TIMING=0

[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"

mkdir -p "$PERSIST_DIR" "$RUNTIME_DIR"

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
    logger -t vpn-watch "$msg" 2>/dev/null || true
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
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$PERSIST_DIR/promotion-timing.log"
}

notify() {
    local title="$1" rc
    shift
    local body="$*"
    if [ -z "$NTFY_URL" ]; then
        log "ntfy skipped: NTFY_URL is not configured"
        return 2
    fi
    curl -fsS -m 8 -H "Title: $title" -d "$body" "$NTFY_URL" >/dev/null 2>&1
    rc=$?
    if [ "$rc" -ne 0 ]; then
        log "ntfy delivery failed rc=$rc title=$title"
        return "$rc"
    fi
    return 0
}

release_lock() {
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

# Case-insensitive tolerant substring classifier.
# Uses fixed-string grep instead of shell pattern/lowercase assumptions so it
# behaves consistently on BusyBox ash.
contains_ci() {
    local haystack="$1" needle="$2"
    printf '%s\n' "$haystack" | grep -Fqi -- "$needle"
}

peer_rank() {
    local loc
    loc="$(peer_location "$1" 2>/dev/null)"

    if contains_ci "$loc" "croatia" || contains_ci "$loc" "zagreb"; then
        echo 100
    elif contains_ci "$loc" "austria" || contains_ci "$loc" "vienna"; then
        echo 210
    elif contains_ci "$loc" "spain" || contains_ci "$loc" "barcelona"; then
        echo 220
    elif contains_ci "$loc" "norway" || contains_ci "$loc" "oslo"; then
        echo 230
    elif contains_ci "$loc" "malta" || contains_ci "$loc" "valletta"; then
        echo 240

    # US groups intentionally match only city/state/area terms.
    elif contains_ci "$loc" "new york"; then
        echo 310
    elif contains_ci "$loc" "boston" || contains_ci "$loc" "massachusetts"; then
        echo 320
    elif contains_ci "$loc" "ashburn" || contains_ci "$loc" "virginia"; then
        echo 330

    elif contains_ci "$loc" "israel" || contains_ci "$loc" "tel aviv"; then
        echo 340
    else
        echo 0
    fi
}

peer_tier() {
    local rank
    rank="$(peer_rank "$1")"
    case "$rank" in
        100) echo 1 ;;
        2??) echo 2 ;;
        3??) echo 3 ;;
        *) echo 0 ;;
    esac
}



rank_major_tier() {
    case "$1" in
        100) echo 1 ;;
        2??) echo 2 ;;
        3??) echo 3 ;;
        *) echo 0 ;;
    esac
}



tier_label() {
    case "$1" in
        1) echo "Croatia" ;;
        2) echo "Europe" ;;
        3) echo "Tier 3 fallback" ;;
        *) echo "Unknown" ;;
    esac
}

rank_label() {
    case "$1" in
        100) echo "Croatia/Zagreb" ;;
        210) echo "Austria/Vienna" ;;
        220) echo "Spain/Barcelona" ;;
        230) echo "Norway/Oslo" ;;
        240) echo "Malta/Valletta" ;;
        310) echo "United States/New York" ;;
        320) echo "United States/Boston" ;;
        330) echo "United States/Ashburn" ;;
        340) echo "Israel/Tel Aviv" ;;
        *) echo "Unknown" ;;
    esac
}

rank_order() {
    echo "100 210 220 230 240 310 320 330 340"
}

active_iface() {
    policy_get via 2>/dev/null
}

active_peer() {
    local p
    p="$(policy_get peer_id 2>/dev/null)"
    if [ -n "$p" ]; then
        echo "$p"
        return 0
    fi
    p="$(iface_peer "$(active_iface)" 2>/dev/null)" || return 1
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
        if ping -I "$iface" -c 1 -W "$KEEPALIVE_PROBE_TIMEOUT" "$target" >/dev/null 2>&1; then
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
    notify "VPN auxiliary backoff" "NordVPN rejected an auxiliary connection ($reason). New probing/precooking is paused for 15 minutes; the active tunnel and any already-connected standby are left untouched."
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
    local iface="$1" active
    [ -n "$iface" ] || return 0
    active="$(active_iface)"
    if [ "$iface" = "$active" ]; then
        log "REFUSING to tear down active interface $iface"
        return 1
    fi

    ifdown "$iface" >/dev/null 2>&1 || true
    /usr/bin/setup_instance stop "$iface" >/dev/null 2>&1 || true
    /usr/bin/setup_instance clean "$iface" >/dev/null 2>&1 || true
    rm -f "/tmp/wireguard/${iface}_state" "$(probe_stamp_file "$iface")" "$(health_fail_file "$iface")" 2>/dev/null
    return 0
}

# Returns:
#   0 = connected successfully
#   1 = ordinary candidate failure
#   2 = active tunnel failed while a recovery probe was in progress
#   3 = global Nord auxiliary backoff is active / was just entered
prepare_iface() {
    local iface="$1" peer="$2" purpose="$3"
    local out rc i active state

    in_backoff && return 3

    active="$(active_iface)"
    [ "$iface" != "$active" ] || return 1

    teardown_iface "$iface" || return 1

    log "Preparing $purpose candidate on $iface: peer=$peer server=$(peer_name "$peer") location=$(peer_location "$peer")"

    out="$(/usr/bin/setup_instance generate "$iface" "$GROUP_ID" "$peer" 2>&1)"
    rc=$?

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
        log "setup_instance generate failed for $iface peer=$peer: $out"
        teardown_iface "$iface" >/dev/null 2>&1 || true
        return 1
    fi

    out="$(/usr/bin/setup_instance start "$iface" 2>&1)"
    rc=$?
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
        log "setup_instance start failed for $iface peer=$peer: $out"
        teardown_iface "$iface" >/dev/null 2>&1 || true
        return 1
    fi

    ifup "$iface" >/dev/null 2>&1 || true

    i=0
    while [ "$i" -lt "$CONNECT_TIMEOUT" ]; do
        if iface_established_fresh "$iface"; then
            # Prove that this specific tunnel also carries traffic before accepting it.
            if probe_iface_path "$iface"; then
                log "Connected $purpose candidate: $(iface_summary "$iface")"
                return 0
            fi
        fi

        # Failure of ACTIVE always outranks recovery work.
        if [ "$purpose" = "recovery" ]; then
            active="$(active_iface)"
            if ! iface_healthy "$active"; then
                log "Active tunnel failed during recovery probe; aborting probe immediately"
                teardown_iface "$iface" >/dev/null 2>&1 || true
                return 2
            fi
        fi

        state="$(cat "/tmp/wireguard/${iface}_state" 2>/dev/null)"
        [ "$state" = "failed" ] && break
        sleep 1
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

    # Tier 1 and Tier 2 are intentionally "sticky":
    # no automatic upward recovery and no same-tier upgrades.
    [ "$current_tier" -eq 3 ] 2>/dev/null || return 0

    # Tier 3 may recover only into major Tier 1 or Tier 2.
    # Never churn between New York/Boston/Ashburn/Israel just for marginal gains.
    for rank in $(rank_order); do
        tier="$(rank_major_tier "$rank")"
        [ "$tier" -eq 1 ] 2>/dev/null || [ "$tier" -eq 2 ] 2>/dev/null || continue
        rank_has_peers "$rank" && echo "$rank"
    done
}

# Rotates through servers INSIDE one internal location rank.
# Moving between ranks is controlled separately by the state machine, so every
# Austria server is considered part of the Austria group, etc.
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
        peer="$(iface_peer "$iface" 2>/dev/null)"
        [ -n "$peer" ] || continue
        [ "$(peer_rank "$peer")" = "$rank" ] || continue
        iface_healthy "$iface" || continue
        echo "$iface"
        return 0
    done
    return 1
}

free_slot() {
    local active="$1" keep="$2" iface

    # Prefer a genuinely unused/down slot so we do not destroy a still-useful
    # old tunnel while another physical slot is available.
    for iface in $SLOTS; do
        [ "$iface" = "$active" ] && continue
        [ "$iface" = "$keep" ] && continue
        if ! uci -q get network."$iface" >/dev/null 2>&1; then
            echo "$iface"
            return 0
        fi
        if ! iface_healthy "$iface"; then
            echo "$iface"
            return 0
        fi
    done

    # If both auxiliaries are live, one still has to be selected for reuse.
    for iface in $SLOTS; do
        [ "$iface" = "$active" ] && continue
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
    # interface. A precooked standby therefore needs the minimum equivalent
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
    # after it so even established LAN flows are forced onto the newly active
    # precooked interface instead of retaining the old interface mark.
    # Delete our previous override first, if present.
    while iptables -w -t mangle -D ROUTE_POLICY \
        -m comment --comment "vpn-watch-fastpath" \
        -m addrtype ! --dst-type LOCAL \
        -m set ! --match-set "dst_net${TUNNEL_ID}" dst \
        -j MARK --set-xmark "$mark/0xf000" >/dev/null 2>&1; do :; done

    # Remove an override carrying a different old mark. There can be at most
    # one from us; identify it by comment and delete by line number.
    local n
    n="$(iptables -w -t mangle -L ROUTE_POLICY --line-numbers -n 2>/dev/null | awk '/vpn-watch-fastpath/ {print $1; exit}')"
    [ -n "$n" ] && iptables -w -t mangle -D ROUTE_POLICY "$n" || true

    iptables -w -t mangle -I ROUTE_POLICY 2 \
        -m comment --comment "vpn-watch-fastpath" \
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
        log "GL_GUARD deferred_rtp2_calls=${n:-unknown}; final state will be verified by vpn-watch; details=$gl_guard_pending"
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

    count="$(iptables -w -t mangle -L ROUTE_POLICY --line-numbers -n 2>/dev/null | grep -c 'vpn-watch-fastpath')"
    [ "$count" = "1" ] || return 1
    rule="$(iptables -w -t mangle -S ROUTE_POLICY 2>/dev/null | grep 'vpn-watch-fastpath')"
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

    [ "$(active_iface)" = "$iface" ] || {
        log "Promotion post-unlock verification failed: policy no longer on $iface"
        return 1
    }

    loc="$(peer_location "$peer")"
    name="$(peer_name "$peer")"
    promo_trace "PROMO_END_V14_1 total_ms=$(($(monotonic_ms)-t0)) dataplane_flip_at_ms=$((t7-t0)) reason=$reason iface=$iface peer=$peer server=$name location=$loc"

    log "PROMOTED_FAST_GUARDED reason=$reason old_major_tier=$old_tier new_major_tier=$new_tier active=$(iface_summary "$iface")"

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
            1) body="Croatia gateway in use: $name ($loc)." ;;
            2) body="European gateway in use: $name ($loc)." ;;
            3) body="Last-resort gateway in use: $name ($loc)." ;;
            *) body="VPN gateway changed: $name ($loc)." ;;
        esac
        notify "$title" "$body" || true
    fi

    return 0
}

write_state_snapshot() {
    local active="$1" standby="$2" recovery="$3" ap ar at sp sr st until
    ap="$(iface_peer "$active" 2>/dev/null)"
    ar="$(peer_rank "$ap")"
    at="$(rank_major_tier "$ar")"
    sp="$(iface_peer "$standby" 2>/dev/null)"
    sr="$(peer_rank "$sp")"
    st="$(rank_major_tier "$sr")"
    until="$(backoff_until)"

    cat > "$STATE_FILE" <<EOF
active_iface=$active
active_peer=$ap
active_rank=$ar
active_tier=$at
standby_iface=$standby
standby_peer=$sp
standby_rank=$sr
standby_tier=$st
recovery_iface=$recovery
nord_backoff_until=$until
EOF
}

reconcile_roles() {
    local active ap ar at standby="" recovery="" target_rank=""
    active="$(active_iface)"
    ap="$(active_peer 2>/dev/null)"
    ar="$(peer_rank "$ap")"
    at="$(rank_major_tier "$ar")"

    if [ "$ar" -gt 0 ] 2>/dev/null; then
        target_rank="$(next_lower_rank "$ar" 2>/dev/null)"
        if [ -n "$target_rank" ]; then
            standby="$(find_healthy_iface_for_rank "$target_rank" "$active" 2>/dev/null)"
        fi
    fi

    recovery="$(free_slot "$active" "$standby" 2>/dev/null)"
    write_state_snapshot "$active" "$standby" "$recovery"

    printf '%s|%s|%s|%s|%s|%s|%s\n' \
        "$active" "$ap" "$ar" "$at" "$standby" "$recovery" "${target_rank:-0}"
}

# Remove extra stale/live interfaces that are neither ACTIVE nor selected STANDBY.
# We only do this when they are not currently being used as the recovery worker.
cleanup_extras() {
    local active="$1" standby="$2" iface
    for iface in $SLOTS; do
        [ "$iface" = "$active" ] && continue
        [ "$iface" = "$standby" ] && continue
        uci -q get network."$iface" >/dev/null 2>&1 || continue
        teardown_iface "$iface" >/dev/null 2>&1 || true
    done
}

ensure_standby() {
    local active="$1" ap="$2" ar="$3" at="$4" standby="$5" recovery="$6"
    local target_rank slot peer tries rc

    [ "$ar" -gt 0 ] 2>/dev/null || return 1
    target_rank="$(next_lower_rank "$ar" 2>/dev/null)"

    # No lower configured internal rank (normally Tier 4 / Israel).
    [ -n "$target_rank" ] || return 0

    if [ -n "$standby" ] && iface_healthy "$standby"; then
        return 0
    fi

    in_backoff && return 0

    slot="$recovery"
    [ -n "$slot" ] || slot="$(free_slot "$active" "" 2>/dev/null)"
    [ -n "$slot" ] || return 1

    tries=0
    while [ "$tries" -lt "$STANDBY_ATTEMPTS" ]; do
        peer="$(next_peer_for_rank "$target_rank" "$ap" "" "")" || return 1
        prepare_iface "$slot" "$peer" "standby"
        rc=$?
        case "$rc" in
            0)
                log "Hot standby ready for $(rank_label "$target_rank"): $(iface_summary "$slot")"
                return 0
                ;;
            3) return 0 ;;
        esac
        tries=$((tries + 1))
    done

    return 1
}

promote_hot_standby_on_failure() {
    local active="$1" ap="$2" ar="$3" at="$4" standby="$5"
    local target_rank peer slot tries rc

    [ "$ar" -gt 0 ] 2>/dev/null || return 1

    # Priority 1: promote the already-connected next-lower INTERNAL rank immediately.
    # This can be a silent same-major-tier move such as Austria -> Spain.
    if [ -n "$standby" ] && iface_healthy "$standby"; then
        peer="$(iface_peer "$standby")"
        log "ACTIVE failure detected on $active; immediately promoting hot standby $standby"
        promote_iface "$standby" "$peer" "active-failure-hot-standby" && return 0
    fi

    # No usable hot standby. Keep kill switch authoritative while attempting one
    # emergency replacement.
    if in_backoff; then
        log "ACTIVE failed with no usable hot standby; auxiliary creation is in Nord backoff, so kill switch remains in force"
        return 1
    fi

    target_rank="$(next_lower_rank "$ar" 2>/dev/null)"
    if [ -z "$target_rank" ]; then
        # Lowest configured rank: try another server in the SAME rank.
        target_rank="$ar"
    fi

    slot="$(free_slot "$active" "" 2>/dev/null)"
    [ -n "$slot" ] || return 1

    log "ACTIVE failure with no usable hot standby; emergency target=$(rank_label "$target_rank") slot=$slot"
    tries=0
    while [ "$tries" -lt "$STANDBY_ATTEMPTS" ]; do
        peer="$(next_peer_for_rank "$target_rank" "$ap" "" "")" || return 1
        prepare_iface "$slot" "$peer" "emergency"
        rc=$?
        case "$rc" in
            0)
                promote_iface "$slot" "$peer" "active-failure-emergency" && return 0
                teardown_iface "$slot" >/dev/null 2>&1 || true
                ;;
            3) return 1 ;;
        esac
        tries=$((tries + 1))
    done

    log "CRITICAL: unable to establish emergency VPN replacement; kill switch remains in force"
    notify "VPN unavailable" "The active VPN and hot standby are unavailable, and no emergency VPN replacement connected. Kill switch remains in force; vpn-watch did not force direct WAN."
    return 1
}

recovery_due() {
    local last=0
    [ -f "$LAST_RECOVERY_FILE" ] && last="$(cat "$LAST_RECOVERY_FILE" 2>/dev/null)"
    [ $(( $(now) - ${last:-0} )) -ge "$RECOVERY_INTERVAL" ]
}

mark_recovery_attempt() {
    now > "$LAST_RECOVERY_FILE"
}

probe_recovery_targets() {
    local active="$1" ap="$2" ar="$3" at="$4" standby="$5" recovery="$6"
    local rank peer rc standby_peer

    # Deliberately do not recover from Tier 1 or Tier 2.
    # Only Tier 3 actively searches for Tier 1 / Tier 2.
    [ "$at" -eq 3 ] 2>/dev/null || return 0
    [ -n "$recovery" ] || return 0
    recovery_due || return 0
    in_backoff && return 0

    mark_recovery_attempt
    standby_peer="$(iface_peer "$standby" 2>/dev/null)"

    # Best-to-worst recovery targets:
    # Croatia, then Austria/Spain/Norway/Malta.
    # Tier-3-to-Tier-3 "improvements" are intentionally ignored.
    for rank in $(recovery_ranks "$ar"); do
        peer="$(next_peer_for_rank "$rank" "$ap" "$standby_peer" "")"
        [ -n "$peer" ] || continue

        prepare_iface "$recovery" "$peer" "recovery"
        rc=$?
        case "$rc" in
            0)
                if promote_iface "$recovery" "$peer" "higher-major-tier-recovery"; then
                    return 4
                fi
                teardown_iface "$recovery" >/dev/null 2>&1 || true
                ;;
            2)
                # ACTIVE failed while probing. Caller must immediately fail over.
                return 2
                ;;
            3)
                return 0
                ;;
        esac
    done

    return 0
}


recover_offline_best() {
    local active slot rank peer tries rc old_active

    in_backoff && {
        log "Offline recovery deferred: Nord auxiliary backoff is active"
        return 1
    }

    old_active="$(active_iface 2>/dev/null)"
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
        while [ "$tries" -lt "$STANDBY_ATTEMPTS" ]; do
            peer="$(next_peer_for_rank "$rank" "" "" "")" || break

            prepare_iface "$slot" "$peer" "offline-recovery"
            rc=$?
            case "$rc" in
                0)
                    if promote_iface "$slot" "$peer" "offline-recovery"; then
                        log "OFFLINE recovery succeeded: $(iface_summary "$slot")"
                        return 0
                    fi
                    teardown_iface "$slot" >/dev/null 2>&1 || true
                    ;;
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
    local roles active ap ar at standby recovery target_rank rc roles2

    maybe_clear_expired_backoff

    roles="$(reconcile_roles)"
    IFS='|' read -r active ap ar at standby recovery target_rank <<EOF
$roles
EOF

    if [ -z "$active" ] || [ -z "$ap" ] || [ "${ar:-0}" -eq 0 ]; then
        log "Cannot reconcile active VPN state (active=$active peer=$ap rank=$ar tier=$at); entering offline recovery"
        recover_offline_best || true
        return 0
    fi

    if ! iface_healthy "$active"; then
        promote_hot_standby_on_failure "$active" "$ap" "$ar" "$at" "$standby"
        rc=$?
        if [ "$rc" -eq 0 ]; then
            # New ACTIVE first. Only after continuity is restored do we rebuild.
            roles="$(reconcile_roles)"
            IFS='|' read -r active ap ar at standby recovery target_rank <<EOF
$roles
EOF
            ensure_standby "$active" "$ap" "$ar" "$at" "$standby" "$recovery" || true
        else
            # No downward/same-rank replacement worked: treat this as offline and
            # recover best-to-worst across Tier 1, Tier 2 and Tier 3.
            recover_offline_best || true
        fi
        return 0
    fi

    # ACTIVE healthy: priority 2 is maintaining the immediate next-lower
    # INTERNAL rank as an already-connected hot standby.
    ensure_standby "$active" "$ap" "$ar" "$at" "$standby" "$recovery" || true

    roles="$(reconcile_roles)"
    IFS='|' read -r active ap ar at standby recovery target_rank <<EOF
$roles
EOF

    # Recovery policy is intentionally sticky:
    # - Tier 1: no recovery work
    # - Tier 2: no recovery to Croatia and no same-tier "upgrades"
    # - Tier 3: probe only Tier 1 and Tier 2, best-to-worst
    probe_recovery_targets "$active" "$ap" "$ar" "$at" "$standby" "$recovery"
    rc=$?

    if [ "$rc" -eq 2 ]; then
        # ACTIVE died during upward recovery. Hot-standby promotion outranks all else.
        roles2="$(reconcile_roles)"
        IFS='|' read -r active ap ar at standby recovery target_rank <<EOF
$roles2
EOF
        promote_hot_standby_on_failure "$active" "$ap" "$ar" "$at" "$standby" || true
    elif [ "$rc" -eq 4 ]; then
        # A better rank was promoted. Immediately rebuild the correct next-lower
        # hot standby before housekeeping, rather than waiting for the next loop.
        roles2="$(reconcile_roles)"
        IFS='|' read -r active ap ar at standby recovery target_rank <<EOF
$roles2
EOF
        ensure_standby "$active" "$ap" "$ar" "$at" "$standby" "$recovery" || true
    fi

    roles="$(reconcile_roles)"
    IFS='|' read -r active ap ar at standby recovery target_rank <<EOF
$roles
EOF
    cleanup_extras "$active" "$standby"
    write_state_snapshot "$active" "$standby" "$recovery"
}

pre_reboot_recover_core() {
    local roles active ap ar at standby recovery target_rank
    local existing peer rc tries=0

    roles="$(reconcile_roles)"
    IFS='|' read -r active ap ar at standby recovery target_rank <<EOF
$roles
EOF

    if [ -z "$active" ] || [ -z "$ap" ] || [ "${ar:-0}" -eq 0 ]; then
        log "PRE-REBOOT: cannot reconcile active VPN; no Tier 1 recovery attempted"
        echo "PRE-REBOOT: active VPN could not be reconciled."
        return 1
    fi

    if [ "$at" -ne 2 ] 2>/dev/null; then
        log "PRE-REBOOT: active major tier is $at, not Tier 2; no special recovery needed"
        echo "PRE-REBOOT: active VPN is Tier $at; Tier 2 -> Tier 1 recovery not needed."
        return 0
    fi

    log "PRE-REBOOT: Tier 2 active ($(iface_summary "$active")); attempting one deliberate recovery to Tier 1"

    # Reuse an already-live Croatia tunnel if one happens to exist.
    existing="$(find_healthy_iface_for_rank 100 "$active" 2>/dev/null)"
    if [ -n "$existing" ]; then
        peer="$(iface_peer "$existing" 2>/dev/null)"
        if promote_iface "$existing" "$peer" "pre-reboot-tier1-recovery"; then
            sleep 2
            if [ "$(peer_tier "$(active_peer 2>/dev/null)")" -eq 1 ] 2>/dev/null && iface_healthy "$(active_iface)"; then
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

    [ -n "$recovery" ] || recovery="$(free_slot "$active" "$standby" 2>/dev/null)"
    if [ -z "$recovery" ]; then
        log "PRE-REBOOT: no auxiliary slot available for Tier 1 probe"
        echo "PRE-REBOOT: no slot available for Tier 1 recovery."
        return 1
    fi

    while [ "$tries" -lt "$STANDBY_ATTEMPTS" ]; do
        peer="$(next_peer_for_rank 100 "$ap" "$(iface_peer "$standby" 2>/dev/null)" "")" || break

        prepare_iface "$recovery" "$peer" "pre-reboot-recovery"
        rc=$?

        case "$rc" in
            0)
                if promote_iface "$recovery" "$peer" "pre-reboot-tier1-recovery"; then
                    sleep 2
                    if [ "$(peer_tier "$(active_peer 2>/dev/null)")" -eq 1 ] 2>/dev/null && iface_healthy "$(active_iface)"; then
                        log "PRE-REBOOT: Tier 1 recovery verified: $(iface_summary "$(active_iface)")"
                        echo "PRE-REBOOT: recovered to Tier 1 and verified."
                        return 0
                    fi
                fi
                teardown_iface "$recovery" >/dev/null 2>&1 || true
                ;;
            2)
                log "PRE-REBOOT: active Tier 2 tunnel failed while Tier 1 was being probed"
                echo "PRE-REBOOT: Tier 1 recovery aborted because the active tunnel failed."
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

    log "PRE-REBOOT: Tier 1 recovery attempt finished without a working Croatia tunnel"
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
        echo "vpn-watch is already running; use the daemon request mechanism."
        return 2
    }

    pre_reboot_recover_core
}


show_status() {
    local roles active ap ar at standby recovery target_rank until remain target_desc
    roles="$(reconcile_roles)"
    IFS='|' read -r active ap ar at standby recovery target_rank <<EOF
$roles
EOF

    echo "Tunnel: $TUNNEL_ID"
    echo "ACTIVE:     $(iface_summary "$active")"
    if [ -n "$standby" ]; then
        echo "PRECOOKED:  $(iface_summary "$standby")"
    elif [ "${target_rank:-0}" -gt 0 ] 2>/dev/null; then
        target_desc="$(rank_label "$target_rank")"
        echo "PRECOOKED:  not ready (next fallback: $target_desc)"
    else
        echo "PRECOOKED:  none (lowest configured fallback rank)"
    fi
    echo "RECOVERY:   ${recovery:-none}"

    until="$(backoff_until)"
    if [ "${until:-0}" -gt "$(now)" ] 2>/dev/null; then
        remain=$((until - $(now)))
        echo "NORD BACKOFF: active (${remain}s remaining)"
    else
        echo "NORD BACKOFF: inactive"
    fi

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
    local roles active ap ar at standby recovery target_rank rc

    roles="$(reconcile_roles)"
    IFS='|' read -r active ap ar at standby recovery target_rank <<EOF
$roles
EOF

    if [ -z "$active" ] || [ -z "$ap" ] || [ "${ar:-0}" -eq 0 ]; then
        echo "Cannot reconcile the current active VPN."
        return 1
    fi

    if [ -z "$standby" ]; then
        echo "No healthy precooked standby is available; refusing synthetic failover test."
        return 1
    fi

    if ! iface_healthy "$standby"; then
        echo "Precooked standby is not healthy; refusing synthetic failover test."
        return 1
    fi

    echo "=== Synthetic ACTIVE failure test ==="
    echo "Current ACTIVE:    $(iface_summary "$active")"
    echo "Hot PRECOOKED:     $(iface_summary "$standby")"
    echo
    echo "Injecting ONE synthetic failure event for the current ACTIVE."
    echo "No peer/tier blacklist is created; the synthetic failure ends immediately after promotion."

    log "TEST: injecting one synthetic ACTIVE failure event active=$active peer=$ap rank=$ar"

    promote_hot_standby_on_failure "$active" "$ap" "$ar" "$at" "$standby"
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
    # lower fallback without recovering back to Croatia.
    rm -f "$LAST_RECOVERY_FILE"
    sleep 2

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
    echo "$cmdline" | grep -Fq '/root/vpn-watch.sh daemon'
}

test_failover_once() {
    local token waited=0 result result_token rc output_file

    if ! is_daemon_running; then
        # Useful for maintenance: if no daemon owns the VPN, retain the old
        # direct test behavior under the normal single-instance lock.
        acquire_lock || {
            echo "vpn-watch is already running, but its daemon could not be validated."
            return 1
        }
        test_failover_core
        return $?
    fi

    token="test-$$-$(date +%s)"
    rm -f "$TEST_FAILOVER_RESULT_FILE"
    printf '%s\n' "$token" > "$TEST_FAILOVER_REQUEST_FILE"

    echo "Synthetic failover request sent to the running vpn-watch daemon."
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
    echo "Check: /root/vpn-watch.sh log 30"
    return 1
}

daemon_loop() {
    acquire_lock || {
        echo "vpn-watch is already running."
        exit 1
    }

    log "vpn-watch daemon started pid=$$ loop=${LOOP_SECONDS}s"

    while true; do
        handle_pre_reboot_request
        handle_test_failover_request
        run_cycle || log "vpn-watch cycle returned non-zero"
        sleep "$LOOP_SECONDS"
    done
}

case "${1:-status}" in
    status)
        show_status
        ;;
    once)
        acquire_lock || { echo "vpn-watch is already running."; exit 1; }
        run_cycle
        show_status
        ;;
    daemon|run)
        daemon_loop
        ;;
    notify_test)
        if notify "VPN Watch Test" "vpn-watch notification test succeeded."; then
            echo "Notification sent successfully."
        else
            rc=$?
            echo "Notification FAILED (rc=$rc). Check NTFY_URL/network and vpn-watch log."
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
