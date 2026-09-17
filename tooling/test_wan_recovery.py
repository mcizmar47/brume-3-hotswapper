"""Exercise production shell functions with strict local stubs, never a router."""
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SH = sys.argv[1] if len(sys.argv) > 1 else "sh"
if pathlib.Path(SH).is_absolute():
    os.environ["PATH"] = str(pathlib.Path(SH).parent) + os.pathsep + os.environ.get("PATH", "")
SOURCE = (ROOT / "hotswapper-main.sh").read_text(encoding="utf-8")


def function(name):
    start = SOURCE.index("\n" + name + "() {") + 1
    return SOURCE[start:SOURCE.index("\n}", start) + 2]


COUNT = 0

def check(names, stubs, body):
    global COUNT
    with tempfile.TemporaryDirectory(prefix="brume-wan-") as directory:
        path = pathlib.Path(directory)
        # No set -e: production intentionally examines failing command statuses.
        code = f"cd '{path.as_posix()}' || exit 99\n"
        code += "WAN_STATE_FILE=wan-state; WAN_PENDING_FILE=pending; PERSIST_DIR=.; WAN_CYCLE_RESULT=''; RUNTIME_DIR=.; DETECTOR_ENABLED=0; DETECT_FAILED=0; PROMOTION_EPOCH=0; IN_DETECTOR=0\n"
        code += "log() { echo \"$*\" >> events; }\n"
        code += "\n".join(function(n) for n in names) + "\n" + stubs + "\n" + body
        script = path / "test.sh"
        script.write_text(code, encoding="utf-8", newline="\n")
        result = subprocess.run([SH, str(script)], text=True, capture_output=True, timeout=20)
        assert result.returncode == 0, (COUNT, result.returncode, result.stdout, result.stderr)
        COUNT += 1


# Hot promotion must return before WAN discovery or any emergency candidate.
check(["promote_hot_candidate"], r"""
iface_healthy() { return 0; }
iface_peer() { echo 12; }
promote_iface() { echo "$*" > promoted; return 0; }
wan_recovery_allowed() { echo called > wan-called; return 1; }
""", r"""
promote_hot_candidate wgclient1 11 1 1 wgclient2 || exit 10
[ ! -e wan-called ] && grep -q 'current-failure-hot-candidate' promoted || exit 11
""")

GATE = ["wan_recovery_allowed"]
check(GATE, "wan_probe_round() { echo probe >> probes; return 1; }", r"""
wan_recovery_allowed && exit 10
[ "$(cat wan-state)" = WAN_SUSPECT ] && [ ! -e pending ] || exit 11
wan_recovery_allowed && exit 12
[ "$(wc -l < probes)" -eq 1 ] || exit 13
WAN_CYCLE_RESULT=''
wan_recovery_allowed && exit 14
[ "$(cat wan-state)" = WAN_OFFLINE ] && [ -e pending ] || exit 15
for i in 1 2 3 4 5; do WAN_CYCLE_RESULT=''; wan_recovery_allowed && exit 16; done
[ "$(wc -l < events)" -eq 2 ] || exit 17
""")
check(GATE, "wan_probe_round() { return \"$result\"; }", r"""
result=1; wan_recovery_allowed && exit 10
result=0; WAN_CYCLE_RESULT=''; wan_recovery_allowed || exit 11
[ "$(cat wan-state)" = WAN_UP ] && [ ! -e pending ] || exit 12
result=1; WAN_CYCLE_RESULT=''; wan_recovery_allowed && exit 13
[ "$(cat wan-state)" = WAN_SUSPECT ] || exit 14
""")
check(GATE, "wan_probe_round() { return 2; }", r"""
echo WAN_SUSPECT > wan-state
wan_recovery_allowed && exit 10
[ "$(cat wan-state)" = WAN_UNKNOWN ] && [ ! -e pending ] || exit 11
""")

# Production run_cycle + recovery + gate: no provider calls/cursors during outage,
# restart repeats the safe gate, restoration resets peer cursor and starts rank 1.
engine = ["run_cycle", "recover_offline_best", "promote_hot_candidate",
          "recover_emergency", "wan_recovery_allowed", "wan_recovery_notification", "next_peer_for_rank"]
stubs = r"""
SLOTS='wgclient1 wgclient2 wgclient3'; DOWNTIER_ATTEMPTS=1
result=1; blocked=0
wan_probe_round() { echo probe >> probes; return "$result"; }
maybe_clear_expired_backoff() { :; }
in_backoff() { [ "$blocked" = 1 ]; }
reconcile_roles() { echo 'wgclient1|11|3|3|||0'; }
iface_healthy() { return 1; }
current_iface() { echo wgclient1; }
free_slot() { echo wgclient2; }
rank_order() { printf '1\n2\n3\n'; }
rank_has_peers() { return 0; }
profile_peers_for_rank() { echo "$1"1; echo "$1"2; }
next_lower_rank() { echo 4; }
rank_label() { echo "$1"; }
prepare_iface() { echo "$*" >> candidates; return 0; }
promote_iface() { echo "$*" >> promotions; return 0; }
iface_summary() { echo healthy; }
notify() { echo "$*" >> notifications; return 1; }
ensure_downtier() { :; }
refresh_detector_roles() { :; }
"""
check(engine, stubs, r"""
echo 11 > cursor.rank1
run_cycle || exit 10
[ "$(cat wan-state)" = WAN_SUSPECT ] && [ ! -e candidates ] || exit 11
# Fresh process variables with runtime files retained, as on daemon restart.
WAN_CYCLE_RESULT=''; run_cycle || exit 12
[ "$(cat wan-state)" = WAN_OFFLINE ] && [ ! -e candidates ] || exit 13
for i in 1 2 3; do run_cycle || exit 14; done
[ ! -e candidates ] && [ "$(cat cursor.rank1)" = 11 ] || exit 15
result=0; run_cycle || exit 16
[ "$(cat candidates)" = 'wgclient2 11 offline-recovery' ] || exit 17
[ ! -e pending ] && [ "$(wc -l < notifications)" -eq 1 ] || exit 18
wan_recovery_notification
[ "$(wc -l < notifications)" -eq 1 ] || exit 19
""")
check(engine, stubs, r"""
result=0; run_cycle || exit 10
# Healthy WAN keeps the pre-existing next-lower emergency policy.
[ "$(cat candidates)" = 'wgclient2 41 emergency' ] || exit 11
[ "$(wc -l < probes)" -eq 1 ] && [ ! -e pending ] || exit 12
""")
check(engine, stubs, r"""
echo WAN_OFFLINE > wan-state; : > pending
result=0; blocked=1; run_cycle || exit 10
[ ! -e candidates ] && [ -e pending ] && [ ! -e notifications ] || exit 11
blocked=0; run_cycle || exit 12
[ "$(cat candidates)" = 'wgclient2 11 offline-recovery' ] || exit 13
""")

# Any one target wins; errors without a success stay UNKNOWN, never OFFLINE.
for successful in ["1.1.1.1", "8.8.8.8", "208.67.222.222", "208.67.220.220"]:
    check(["wan_probe_round"], r"""
wan_device() { echo uplink9; }
wan_probe_target() { [ "$1" = uplink9 ] || exit 90; [ "$2" = '""" + successful + "' ]; }", "wan_probe_round || exit 10")
check(["wan_probe_round"], "wan_device() { echo uplink9; }\nwan_probe_target() { return 2; }",
      "wan_probe_round; [ $? -eq 2 ] || exit 10")

# Discovery follows the WAN zone's arbitrary logical name and netifd L3 device.
discovery = r"""
uci() {
    case "$*" in
        '-q show firewall') echo 'firewall.@zone[3]=zone';;
        '-q get firewall.@zone[3].name') echo wan;;
        '-q get firewall.@zone[3].network') echo cable77;;
        *) exit 90;;
    esac
}
ubus() { [ "$*" = '-t 2 call network.interface.cable77 status' ] || exit 91; echo status; }
jsonfilter() {
    case "$4" in '@.up') echo "$up";; '@.proto') echo "$mock_proto";; '@.l3_device') echo "$device";; *) exit 92;; esac
}
ip() { [ "$*" = '-4 route show table main default' ] || exit 93; echo 'default via 192.0.2.1 dev uplink9'; }
up=true; mock_proto=dhcp; device=uplink9
"""
check(["wan_device"], discovery, '[ "$(wan_device)" = uplink9 ] || exit 10')
check(["wan_device"], discovery, 'up=false; wan_device; [ $? -eq 1 ] || exit 10')
check(["wan_device"], discovery, 'mock_proto=wireguard; wan_device; [ $? -eq 2 ] || exit 10')
check(["wan_device"], discovery, 'device=wgclient1; wan_device; [ $? -eq 2 ] || exit 10')

# Strict firewall stub: no client chain, mark, UCI, routing change, or broad rule.
# Same probe rules and cleanup for kill switch ON and OFF; no UCI call permitted.
packet_stubs = r"""
ip() {
    [ "$*" = '-4 route get 1.1.1.1 oif uplink9' ] || exit 91
    echo "1.1.1.1 via 192.0.2.1 dev $route_dev src 192.0.2.2"
}
uci() { exit 92; }
iptables() {
    [ "$1 $2 $3 $4" = '-w 2 -t mangle' ] || exit 93
    shift 4; op="$1"; shift
    [ "$*" = 'OUTPUT -o uplink9 -s 192.0.2.2/32 -d 1.1.1.1/32 -p icmp --icmp-type echo-request -m owner --uid-owner 0 -m comment --comment hotswapper-wan-probe -j ACCEPT' ] || exit 94
    echo "$op" >> firewall
    case "$op" in
        -C) [ -f rule ];;
        -I) [ "$insert_fail" != 1 ] || return 1; : > rule;;
        -D) rm -f rule;;
        *) exit 95;;
    esac
}
ping() {
    [ "$*" = '-n -I uplink9 -c 1 -W 1 -w 2 1.1.1.1' ] || exit 96
    [ -f rule ] || exit 97
    echo ping >> packets
    [ "$reload" != 1 ] || rm -f rule
    return "$ping_rc"
}
route_dev=uplink9; ping_rc=0; insert_fail=0; reload=0
"""
for kill_switch in [0, 1]:
    for rc in [0, 1, 2]:
        check(["wan_probe_target"], packet_stubs + f"\nkillswitch={kill_switch}; ping_rc={rc}\n",
              f"wan_probe_target uplink9 1.1.1.1; [ $? -eq {rc} ] || exit 10\n"
              "[ ! -e rule ] && [ \"$(tail -n 1 firewall)\" = -D ] || exit 11")
check(["wan_probe_target"], packet_stubs, r"""
insert_fail=1; wan_probe_target uplink9 1.1.1.1; [ $? -eq 2 ] || exit 10
[ ! -e packets ] || exit 11
""")
check(["wan_probe_target"], packet_stubs, r"""
route_dev=wgclient1; wan_probe_target uplink9 1.1.1.1; [ $? -eq 2 ] || exit 10
[ ! -e packets ] && [ ! -e firewall ] || exit 11
""")
check(["wan_probe_target"], packet_stubs, r"""
reload=1; wan_probe_target uplink9 1.1.1.1; [ $? -eq 2 ] || exit 10
""")
check(["wan_probe_target"], packet_stubs, r"""
: > rule; wan_probe_target uplink9 1.1.1.1 || exit 10
[ ! -e rule ] && [ "$(grep -c -- '-I' firewall)" -eq 1 ] || exit 11
""")

check(["show_status"], r"""
reconcile_roles() { echo 'wgclient1|11|1|1|wgclient2|wgclient3|2'; }
iface_summary() { echo healthy; }
backoff_until() { echo 0; }
in_backoff() { return 1; }
now() { echo 100; }
policy_get() { echo 1; }
""", r"""
echo WAN_OFFLINE > wan-state
show_status > status
 grep -q 'WAN: WAN_OFFLINE' status || exit 10
rm wan-state
show_status > status
! grep -q 'WAN:' status || exit 11
""")
check(["notify"], "curl() { echo called > network; }", r"""
NTFY_URL=unused; echo WAN_OFFLINE > wan-state
notify test body; [ $? -eq 2 ] && [ ! -e network ] || exit 10
""")

# Actual provider error recognition and prepare path, only executable replaced
# with a local stub. WAN logic must not repurpose Nord's existing backoff.
prepare = function("prepare_iface").replace('/usr/bin/setup_instance', 'setup_instance')
for message in ["API limit triggered", "20001220", "device limit reached"]:
    check(["is_limit_error_text", "is_rate_error_text"], prepare + r"""
in_backoff() { return 1; }
current_iface() { echo wgclient1; }
teardown_iface() { :; }
slow_command() { shift; setup_instance "$@" > "$RUNTIME_DIR/command-output"; }
peer_name() { :; }
peer_location() { :; }
set_nord_backoff() { echo "$*" > backoff; }
setup_instance() { echo '""" + message + r"""'; return 1; }
""", r"""
prepare_iface wgclient2 12 emergency
[ $? -eq 3 ] && [ -s backoff ] || exit 10
""")
# Missing CURRENT (including a fresh reboot) is gated before any peer selection.
check(engine, stubs + "\nreconcile_roles() { echo '||||||'; }\ncurrent_iface() { echo; }\n", r"""
run_cycle || exit 10
[ ! -e candidates ] && [ "$(cat wan-state)" = WAN_SUSPECT ] || exit 11
run_cycle || exit 12
[ ! -e candidates ] && [ "$(cat wan-state)" = WAN_OFFLINE ] || exit 13
""")
# WAN UP with failed emergency creation still uses the existing broad hierarchy.
check(engine, stubs + r"""
result=0
prepare_iface() { echo "$*" >> candidates; [ "$3" = offline-recovery ]; }
teardown_iface() { :; }
""", r"""
run_cycle || exit 10
[ "$(head -n 1 candidates)" = 'wgclient2 41 emergency' ] || exit 11
[ "$(tail -n 1 candidates)" = 'wgclient2 11 offline-recovery' ] || exit 12
[ "$(wc -l < probes)" -eq 1 ] || exit 13
""")
# Actual backoff state remains absent throughout WAN classification.
check(GATE + ["set_nord_backoff"], r"""
wan_probe_round() { return 1; }
BACKOFF_FILE=nord; NORD_BACKOFF_SECONDS=900
now() { echo 100; }
""", r"""
wan_recovery_allowed && exit 10
WAN_CYCLE_RESULT=''; wan_recovery_allowed && exit 11
[ ! -e nord ] || exit 12
""")
print(f"PASS: {COUNT} WAN recovery scenarios (production shell functions, local stubs only)")
