#!/bin/sh
# Shared by the watchdog and the few GL writers which touch its slots.
HS_DIR=${HS_DIR:-/tmp/hotswapper}
HS_PROC=${HS_PROC:-/proc}
# Firmware children must not keep the daemon's lifetime lock alive.
exec 8>&-
# Key-up carries a slot name, not its original generation. At least reject a
# slot change between this handler starting and obtaining the mutation lock.
HS_KEYUP_SLOT=""
case "${ACTION:-}:${ifname:-}" in
    KEYPAIR-CREATED:wgclient[123])
        HS_KEYUP_SLOT=$ifname
        HS_KEYUP_IDENTITY=$(cat "$HS_DIR/owned.$ifname" 2>/dev/null)
        ;;
esac

hs_event_still_current() {
    [ -z "$HS_KEYUP_SLOT" ] ||
        [ "$HS_KEYUP_IDENTITY" = "$(cat "$HS_DIR/owned.$HS_KEYUP_SLOT" 2>/dev/null)" ]
}

hs_daemon_alive() {
    local pid stamp actual
    [ -r "$HS_DIR/owner" ] || return 1
    read -r pid stamp < "$HS_DIR/owner" || return 1
    case "$pid:$stamp" in *[!0-9:]*|:*|*:) return 1;; esac
    [ -r "$HS_PROC/$pid/stat" ] || return 1
    actual=$(awk '{print $22}' "$HS_PROC/$pid/stat")
    [ "$actual" = "$stamp" ] && kill -0 "$pid" 2>/dev/null
}

hs_daemon_lock_held() {
    local pid stamp
    hs_daemon_alive || return 1
    read -r pid stamp < "$HS_DIR/owner" || return 1
    [ "$(cat "$HS_DIR/lock/pid" 2>/dev/null)" = "$pid" ] || return 1
    [ "$(readlink "$HS_PROC/$pid/fd/8")" = "$HS_DIR/daemon.lock" ] || return 1
    # flock's short-lived applet may be recorded as the acquisition PID. The
    # lock on this owner's open descriptor, not that applet PID, is authoritative.
    awk '$1=="lock:" && $3=="FLOCK" && $5=="WRITE" {held=1} END {exit !held}' "$HS_PROC/$pid/fdinfo/8"
}

hs_owned() {
    local iface="$1" config="${2:-}" row peer group tunnel generation index
    case "$iface" in wgclient1|wgclient2|wgclient3) ;; *) return 1;; esac
    hs_daemon_alive || return 1
    [ -r "$HS_DIR/owned.$iface" ] || return 1
    read -r peer group tunnel generation index < "$HS_DIR/owned.$iface" || return 1
    case "$peer:$group:$tunnel:$generation:$index" in *[!0-9:]*|:*|*:) return 1;; esac
    local actual_config
    actual_config=$(uci -q get "network.$iface.config")
    [ -z "$config" ] || [ "$config" = "$actual_config" ] || return 1
    config=$actual_config
    if [ "$config" != "peer_$peer" ]; then
        local reserved old_config
        read -r reserved old_config < "$HS_DIR/reservation.$iface" || return 1
        [ "$reserved" = "$generation" ] && [ "${config:-none}" = "$old_config" ] || return 1
    fi
    [ "$(uci -q get "wireguard.peer_$peer.group_id")" = "$group" ] || return 1
    [ "$(cat "$HS_DIR/tunnel" 2>/dev/null)" = "$tunnel:$group" ]
}

hs_tunnel_owned() {
    hs_daemon_alive || return 1
    case "$1" in ''|*[!0-9]*) return 1;; esac
    local identity
    read -r identity < "$HS_DIR/tunnel" || return 1
    [ "${identity%%:*}" = "$1" ]
}

hs_wake() {
    local pid stamp
    hs_daemon_alive || return 0
    read -r pid stamp < "$HS_DIR/owner" || return 0
    kill -USR1 "$pid" 2>/dev/null || true
}

hs_event() (
    local iface="$1" expected="${2:-}" generation peer group tunnel index
    hs_lock || return 1
    hs_owned "$iface" || return 1
    read -r peer group tunnel generation index < "$HS_DIR/owned.$iface" || return 1
    [ -z "$expected" ] || [ "$expected" = "$generation:$index" ] || return 1
    # An event without an identity is only a wakeup. It cannot condemn a reused slot.
    if [ -n "$expected" ] && [ "$expected" = "$generation:$index" ]; then
        hs_invalidate_all
        return
    fi
    hs_wake
)

hs_invalidate_all() {
    local iface peer group tunnel generation index epoch=0
    [ ! -r "$HS_DIR/dataplane-epoch" ] || read -r epoch < "$HS_DIR/dataplane-epoch"
    printf '%s\n' "$((epoch + 1))" > "$HS_DIR/dataplane-epoch.new"
    mv "$HS_DIR/dataplane-epoch.new" "$HS_DIR/dataplane-epoch"
    for iface in wgclient1 wgclient2 wgclient3; do
        [ -r "$HS_DIR/owned.$iface" ] || continue
        read -r peer group tunnel generation index < "$HS_DIR/owned.$iface" || continue
        : > "$HS_DIR/invalid.$iface.$generation"
    done
    hs_wake
}

hs_lock() {
    local priority="${1:-slow}" tries=0
    # Nested synchronous firmware helpers inherit the same open file description.
    if [ "${HS_LOCKED:-0}" = 1 ] && [ -e "$HS_PROC/self/fd/9" ]; then
        hs_event_still_current
        return $?
    fi
    mkdir -p "$HS_DIR" || return 1
    exec 9>"$HS_DIR/mutation.lock" || return 1
    while :; do
        if { [ "$priority" = fast ] || [ ! -e "$HS_DIR/promotion-waiting" ]; } && busybox flock -n 9; then
            HS_LOCKED=1; HS_LOCK_OWNER=$$; export HS_LOCKED HS_LOCK_OWNER
            hs_event_still_current || { hs_unlock; return 1; }
            return 0
        fi
        tries=$((tries + 1))
        [ "$tries" -lt 100 ] || { exec 9>&-; return 1; }
        busybox usleep 20000 || { exec 9>&-; return 1; }
    done
}

hs_unlock() {
    [ "${HS_LOCKED:-0}" = 1 ] || return 0
    [ "${HS_LOCK_OWNER:-}" = "$$" ] || return 0
    busybox flock -u 9
    exec 9>&-
    HS_LOCKED=0; export HS_LOCKED
}

# Apply only one instance's generated DNS rules. No firewall reload or conntrack flush.
hs_prepare_dns() (
    local iface="$1" mark="$2" port table chain option target
    port=$(uci -q get "dhcp.$iface.port")
    case "$port" in ''|*[!0-9]*) return 1;; esac
    set -f
    awk -F '"' -v mark="$mark/0xf000" -v port="$port" '
        {
            table="nat"; chain=""; option=""; target=""
            for(i=1;i<NF;i+=2) {
                if($i=="table=" || $i==";table=") table=$(i+1)
                if($i=="chain=" || $i==";chain=") chain=$(i+1)
                if($i==";option=") option=$(i+1)
                if($i==";target=") target=$(i+1)
            }
            if(index(" "option" "," --mark "mark" ") || option=="-p udp --sport "port" ! -o lo") {
                if(table!="nat" && table!="raw") exit 1
                if(chain!="policy_output" && chain!="policy_redirect" && chain!="pre_dns_deal_conn_zone" && chain!="out_dns_deal_conn_zone") exit 1
                print table "\t" chain "\t" option "\t" target; n++
            }
        }
        END {if(n<5) exit 1}
    ' "$FILE_VPN_DNS_RULE" > "$HS_DIR/dns.$iface" || return 1
    while IFS="$(printf '\t')" read -r table chain option target; do
        iptables -w 1 -t "$table" -C "$chain" $option $target >/dev/null 2>&1 ||
            iptables -w 1 -t "$table" -A "$chain" $option $target || return 1
    done < "$HS_DIR/dns.$iface"
)

# The daemon grants one setup/teardown operation for an exact slot generation.
hs_permit() {
    local iface="$1" action="$2" peer group tunnel generation index permit
    hs_owned "$iface" || return 1
    read -r peer group tunnel generation index < "$HS_DIR/owned.$iface" || return 1
    permit="$HS_DIR/permit.$iface.$action.$generation"
    [ -f "$permit" ] || return 1
    rm -f "$permit"
}

hs_drain_old_workers() {
    local attempt=0 file command workers="" pid stamp actual busy
    # Snapshot workers already executing old code. New patched workers wait on
    # mutation.lock and must not make this drain wait for its own lock holders.
    for file in "$HS_PROC"/[0-9]*/cmdline; do
        [ "$file" != "$HS_PROC/$$/cmdline" ] && [ -r "$file" ] || continue
        command=$(tr '\000' '\n' < "$file" | awk '
            NR==1 && ($0=="/bin/sh" || $0=="/bin/ash" || $0=="sh" || $0=="ash" || $0=="/usr/bin/lua" || $0=="lua") {next}
            {a[++n]=$0}
            END {
                if(a[1]=="/etc/rc.common") print a[2];
                else if(a[1]=="/sbin/hotplug-call") print a[1] " " a[2];
                else print a[1]
            }')
        case "$command" in
            /usr/bin/rtp2.sh|/usr/bin/setup_instance|/usr/bin/setup_instance_via.lua|/usr/bin/tunnel-switch.sh|/lib/netifd/proto/wgclient.sh|/etc/hotplug.d/wireguard/ifup.sh|/etc/hotplug.d/wireguard/ifdown.sh|/etc/hotplug.d/iface/20-firewall|/etc/hotplug.d/iface/99-vpn-client-tunnel-switch|/etc/init.d/firewall|'/sbin/hotplug-call iface'|'/sbin/hotplug-call wireguard')
                pid=${file%/cmdline}; pid=${pid##*/}
                stamp=$(awk '{print $22}' "$HS_PROC/$pid/stat" 2>/dev/null)
                [ -z "$stamp" ] || workers="$workers $pid:$stamp"
                ;;
        esac
    done
    while [ "$attempt" -lt 60 ]; do
        busy=0
        for command in $workers; do
            pid=${command%:*}; stamp=${command#*:}
            actual=$(awk '{print $22}' "$HS_PROC/$pid/stat" 2>/dev/null)
            [ "$actual" != "$stamp" ] || busy=1
        done
        [ "$busy" = 1 ] || return 0
        busybox usleep 500000 || return 1
        attempt=$((attempt + 1))
    done
    return 1
}

hs_request() {
    local pid stamp
    hs_daemon_alive || return 1
    read -r pid stamp < "$HS_DIR/owner" || return 1
    [ "${HS_REQUEST:-}" = "$pid:$stamp" ]
}

hs_worker_allowed() {
    hs_tunnel_owned "$1" && { hs_wake; return 1; }
    [ -z "${2:-}" ] || ! hs_owned "$2"
}

hs_ifindex() {
    local iface="$1" peer group tunnel generation previous index
    hs_owned "$iface" || return 1
    read -r peer group tunnel generation previous < "$HS_DIR/owned.$iface" || return 1
    read -r index < "/sys/class/net/$iface/ifindex" || return 1
    printf '%s %s %s %s %s\n' "$peer" "$group" "$tunnel" "$generation" "$index" > "$HS_DIR/owned.$iface.new"
    mv "$HS_DIR/owned.$iface.new" "$HS_DIR/owned.$iface"
}

hs_peer_matches() {
    local iface="$1" peer group tunnel generation index expected actual
    hs_owned "$iface" || return 1
    read -r peer group tunnel generation index < "$HS_DIR/owned.$iface" || return 1
    [ "$(cat "/sys/class/net/$iface/ifindex" 2>/dev/null)" = "$index" ] || return 1
    expected=$(uci -q get "wireguard.peer_$peer.public_key")
    actual=$(wg show "$iface" peers 2>/dev/null)
    [ -n "$expected" ] && [ "$expected" = "$actual" ] || return 1
    # Bookkeeping uses current config; path readiness is proved separately.
    return 0
}

case "$0" in
    */gl-coordination.sh)
        case "${1:-}" in
            daemon) hs_daemon_lock_held;;
            owned) hs_owned "$2" "${3:-}";;
            event) hs_event "$2" "${3:-}";;
            *) exit 2;;
        esac
        exit $?
        ;;
esac
