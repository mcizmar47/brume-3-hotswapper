"""New role policy and serial detector regressions; no live router commands."""
import os
import pathlib
import subprocess
import sys
import tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
SH = sys.argv[1] if len(sys.argv)>1 else 'sh'
if pathlib.Path(SH).is_absolute():
    os.environ['PATH']=str(pathlib.Path(SH).parent)+os.pathsep+os.environ.get('PATH','')
SOURCE = (ROOT/'hotswapper-main.sh').read_text(encoding='utf-8')
COUNT = 0

def function(name):
    a=SOURCE.index('\n'+name+'() {')+1
    return SOURCE[a:SOURCE.index('\n}',a)+2]

def check(names, stubs, assertions):
    global COUNT
    with tempfile.TemporaryDirectory(prefix='hotswapper-roles-') as directory:
        path=pathlib.Path(directory)
        # Host-only timing fixture; never models router fractional sleep.
        sleeper=path/'host_pause'
        sleeper.write_text("#!/bin/sh\nexec '"+pathlib.Path(sys.executable).as_posix()+"' -c 'import sys,time; time.sleep(float(sys.argv[1]))' \"$1\"\n",encoding='utf-8',newline='\n')
        sleeper.chmod(0o755)
        code=f"cd '{path.as_posix()}' || exit 99\n"
        code+='PATH="$PWD:$PATH"; export PATH\n'
        code+='RUNTIME_DIR=.; PERSIST_DIR=.; STATE_FILE=state; WAN_STATE_FILE=wan; WAN_PENDING_FILE=pending; LAST_UPTIER_FILE=last-up\n'
        code+='DETECTOR_ENABLED=0; IN_DETECTOR=0; DETECT_FAILED=0; SLOW_REQUESTED=0; PROMOTION_EPOCH=0; FAST_FAILURES=0\n'
        code+='FAST_FAILURE_THRESHOLD=2; DETECTOR_DELAY_US=150000; FAST_PROBE_WINDOW_US=200000\n'
        code+='log() { echo "$*" >> events; }\n'
        code+='\n'.join(function(n) for n in names)+'\n'+stubs+'\n'+assertions
        script=path/'test.sh';script.write_text(code,encoding='utf-8',newline='\n')
        result=subprocess.run([SH,str(script)],text=True,capture_output=True,timeout=20)
        assert result.returncode==0,(COUNT,result.returncode,result.stdout,result.stderr,{p.name:p.read_text(errors="replace") for p in path.iterdir() if p.is_file() and p.name != "test.sh"})
        COUNT+=1

# Sparse arbitrary ranks: no geography or adjacent-only upward assumption.
policy=r"""
rank_order() { printf '2\n7\n13\n29\n35\n'; }
rank_has_peers() { return 0; }
rank_major_tier() { case "$1" in 2) echo 1;; 7|13) echo 2;; *) echo 3;; esac; }
"""
for current,expected in [('2',''),('7','2'),('13','2\n7'),('29','2\n7\n13'),('35','2\n7\n13')]:
    check(['recovery_ranks'],policy,f'[ "$(recovery_ranks {current})" = "{expected}" ] || exit 10')
check(['next_lower_rank'],policy,'[ "$(next_lower_rank 7)" = 13 ] || exit 10')

# Tier 2 tries the best higher rank first, keeps down while trying, releases
# it only on proven success. Tier 3 promotes; Tier 1 performs no up work.
up_stubs=policy+r"""
current_iface() { echo wgclient2; }
recovery_due() { return 0; }
in_backoff() { return 1; }
mark_recovery_attempt() { :; }
iface_peer() { case "$1" in wgclient1) echo 130;; wgclient3) echo 70;; esac; }
peer_rank() { case "$1" in 70) echo 7;; *) echo 13;; esac; }
free_slot() { echo wgclient3; }
next_peer_for_rank() { echo "${1}0"; }
prepare_iface() { echo "try:$2:$3" >> order; [ ! -e released ] || exit 91; [ "$2" = "$succeeds" ]; }
promote_iface() { echo "$*" >> promoted; }
cleanup_extras() { echo "$*" > released; }
succeeds=70
"""
check(['probe_recovery_targets','recovery_ranks'],up_stubs,r"""
probe_recovery_targets wgclient2 130 13 2 wgclient1 ''; [ $? -eq 4 ] || exit 10
[ "$(cat order)" = 'try:20:uptier
try:70:uptier' ] || exit 11
[ ! -e promoted ] && [ "$(cat released)" = 'wgclient2 wgclient3' ] || exit 12
[ "$DETECT_UP" = wgclient3 ] && [ -z "$DETECT_DOWN" ] || exit 13
""")
check(['probe_recovery_targets','recovery_ranks'],up_stubs,r"""
succeeds=none
probe_recovery_targets wgclient2 130 13 2 wgclient1 '' || exit 10
[ ! -e released ] && [ ! -e promoted ] || exit 11
""")
check(['probe_recovery_targets','recovery_ranks'],up_stubs,r"""
succeeds=20
probe_recovery_targets wgclient2 290 29 3 wgclient1 ''; [ $? -eq 4 ] || exit 10
grep -q 'wgclient3 20 higher-major-tier-recovery' promoted || exit 11
[ "$(wc -l < order)" -eq 1 ] || exit 12
""")
check(['probe_recovery_targets','recovery_ranks'],up_stubs,r"""
probe_recovery_targets wgclient2 20 2 1 wgclient1 '' || exit 10
[ ! -e order ] && [ ! -e promoted ] && [ ! -e released ] || exit 11
""")
# A retained rank-7 up candidate can later be replaced by rank 2, never CURRENT.
check(['probe_recovery_targets','recovery_ranks'],up_stubs+r"""
free_slot() { [ "$2" = wgclient3 ] || exit 90; echo wgclient1; }
succeeds=20
""",r"""
probe_recovery_targets wgclient2 130 13 2 '' wgclient3; [ $? -eq 4 ] || exit 10
[ ! -e promoted ] && [ "$(cat released)" = 'wgclient2 wgclient1' ] || exit 11
""")

# Dynamic slots; CURRENT never maps permanently to any wgclient number.
for current,down,up in [('wgclient1','wgclient2','wgclient3'),('wgclient2','wgclient3','wgclient1'),('wgclient3','wgclient1','wgclient2')]:
    stubs=r"""
iface_healthy() { [ "$1" != "$bad" ]; }
iface_peer() { echo 20; }
promote_iface() { echo "$1" > promoted; }
wan_recovery_allowed() { exit 90; }
prepare_iface() { exit 91; }
"""
    check(['promote_hot_candidate'],stubs,f'bad=none\npromote_hot_candidate {current} 70 7 2 {down} {up} || exit 10\n[ "$(cat promoted)" = {up} ] || exit 11')
    check(['promote_hot_candidate'],stubs,f'bad={up}\npromote_hot_candidate {current} 70 7 2 {down} {up} || exit 10\n[ "$(cat promoted)" = {down} ] || exit 11')

fast=r"""
DETECT_CURRENT=wgclient2; DETECT_UP=wgclient1; DETECT_DOWN=wgclient3
MS=0; mock_hard=1; mock_path=1
current_iface() { echo wgclient2; }
iface_hard_up() { [ "$1" != wgclient2 ] || [ "$mock_hard" = 1 ]; }
fast_path_round() {
    MS=$((MS+200))
    [ "$1" != wgclient2 ] || [ "$mock_path" = 1 ]
}
iface_peer() { echo 20; }
promote_iface() { echo "$MS:$1" > promoted; DETECT_FAILED=0; return 0; }
delay_us() { [ "$1" = 150000 ] || exit 91; MS=$((MS+150)); }
prepare_iface() { exit 92; }
rank_order() { exit 93; }
wan_recovery_allowed() { exit 94; }
"""
check(['fast_health_pass','detector_iteration'],fast,r"""
mock_path=0
detector_iteration
[ ! -e promoted ] && [ "$FAST_FAILURES" -eq 1 ] || exit 10
detector_iteration
[ "$(cat promoted)" = '750:wgclient1' ] || exit 11
[ "$MS" -eq 900 ] && [ "$SLOW_REQUESTED" = 1 ] || exit 12
""")
check(['fast_health_pass','detector_iteration'],fast,r"""
mock_hard=0
detector_iteration
[ "$(cat promoted)" = '200:wgclient1' ] && [ "$FAST_FAILURES" -eq 0 ] || exit 10
""")
check(['fast_health_pass','detector_iteration'],fast,r"""
mock_path=0; detector_iteration
mock_path=1; detector_iteration
mock_path=0; detector_iteration
[ ! -e promoted ] && [ "$FAST_FAILURES" -eq 1 ] || exit 10
""")
check(['fast_health_pass','detector_iteration'],fast,r"""
DETECT_UP=''; DETECT_DOWN=''; mock_hard=0
detector_iteration
[ ! -e promoted ] && [ "$SLOW_REQUESTED" = 1 ] && [ "$DETECT_FAILED" = 1 ] || exit 10
# Slow state owns subsequent recovery. Repeated fast passes do no expensive work.
SLOW_REQUESTED=0
for i in 1 2 3 4 5; do detector_iteration; done
[ ! -e promoted ] && [ "$SLOW_REQUESTED" = 0 ] || exit 11
""")
check(['fast_health_pass','detector_iteration'],fast+r"""
current_iface() { echo wgclient3; }
""",r"""
detector_iteration
[ ! -e promoted ] && [ -z "$DETECT_UP" ] && [ "$SLOW_REQUESTED" = 1 ] || exit 10
""")
# Exact requested timing: 400 ms pass, THEN 150 ms delay, no overlapping pass.
check(['detector_iteration'],r"""
MS=0; busy=0
fast_health_pass() {
    [ "$busy" = 0 ] || exit 91
    busy=1; echo "start:$MS" >> times
    MS=$((MS+400)); echo "end:$MS" >> times; busy=0
}
delay_us() {
    [ "$busy" = 0 ] && [ "$1" = 150000 ] || exit 92
    echo "sleep:$MS" >> times; MS=$((MS+150))
}
""",r"""
detector_iteration; detector_iteration
[ "$(cat times)" = 'start:0
end:400
sleep:400
start:550
end:950
sleep:950' ] || exit 10
""")
# Real child process waits; no real network. Parent continues its detector while
# a slow command runs. Notification stdin and provider stdout survive.
check(['slow_command'],r"""
DETECTOR_ENABLED=1
detector_iteration() { echo pass >> passes; host_pause 0.01; }
""",r"""
slow_command sh -c 'host_pause 0.08; cat' <<EOF
private-config-fixture
EOF
[ $? -eq 0 ] && [ -s passes ] && [ -z "$SLOW_PID" ] || exit 10
[ "$(cat command-output)" = private-config-fixture ] || exit 11
""")
# Nested promotion diagnostics cannot truncate the in-flight provider output.
check(['slow_command'],r"""
DETECTOR_ENABLED=1
detector_iteration() { IN_DETECTOR=1; slow_command echo ignored; IN_DETECTOR=0; host_pause 0.01; }
""",r"""
slow_command sh -c 'echo provider-output; host_pause 0.08' || exit 10
[ "$(cat command-output)" = provider-output ] || exit 11
""")
check(['stop_slow_command'],r"""
SLOW_PID=12345
kill() { return 1; }
wait() { echo "$*" > reaped; }
""",r"""
stop_slow_command
[ "$(cat reaped)" = 12345 ] && [ -z "$SLOW_PID" ] || exit 10
""")
# A completed provider call must not start/promote after a detector changed CURRENT.
check(['prepare_iface'],r"""
in_backoff() { return 1; }
current_iface() { echo wgclient2; }
teardown_iface() { :; }
peer_name() { :; }
peer_location() { :; }
slow_command() { echo "$*" >> calls; echo output > command-output; PROMOTION_EPOCH=1; }
""",r"""
prepare_iface wgclient3 20 uptier
[ $? -eq 2 ] && [ "$(wc -l < calls)" -eq 1 ] || exit 10
""")
# In-detector notifications are deferred, not delivered in the critical path.
check(['notify'],r"""
IN_DETECTOR=1
slow_command() { exit 90; }
""",r"""
notify 'Hotswapper restored' 'fixture message' || exit 10
[ "$(cat notification-title)" = 'Hotswapper restored' ] && [ "$(cat notification-body)" = 'fixture message' ] || exit 11
""")
# Establishment keeps handshake+path requirements; no success on only GL state.
check(['prepare_iface'],r"""
CONNECT_TIMEOUT=1; established=0; path=0
in_backoff() { return 1; }
current_iface() { echo wgclient2; }
teardown_iface() { :; }
peer_name() { :; }
peer_location() { :; }
slow_command() { : > command-output; }
is_limit_error_text() { return 1; }
is_rate_error_text() { return 1; }
iface_established_fresh() { [ "$established" = 1 ]; }
probe_iface_path() { [ "$path" = 1 ]; }
iface_summary() { :; }
cooperative_pause() { :; }
""",r"""
prepare_iface wgclient3 20 uptier; [ $? -eq 1 ] && [ ! -e ready.wgclient3 ] || exit 10
established=1
prepare_iface wgclient3 20 uptier; [ $? -eq 1 ] && [ ! -e ready.wgclient3 ] || exit 11
path=1
prepare_iface wgclient3 20 uptier || exit 12
[ "$(cat ready.wgclient3)" = 20 ] || exit 13
""")
# A slow-path promotion is atomic too: no nested detector while its path probe runs.
check(['slow_command'],r"""
DETECTOR_ENABLED=1; PROMOTION_CRITICAL=1
detector_iteration() { exit 92; }
""",r"""
slow_command true || exit 10
""")
# Housekeeping reuses the ready Tier 1 candidate and verifies the resulting policy.
check(['pre_reboot_recover_core'],r"""
reconcile_roles() { echo 'wgclient2|70|7|2||wgclient1|13'; }
tier1_ranks() { echo 2; }
find_healthy_iface_for_rank() { echo wgclient1; }
iface_peer() { echo 20; }
iface_summary() { :; }
promote_iface() { echo "$*" > promoted; }
cooperative_pause() { :; }
current_peer() { echo 20; }
peer_tier() { echo 1; }
current_iface() { echo wgclient1; }
iface_healthy() { return 0; }
prepare_iface() { exit 90; }
""",r"""
pre_reboot_recover_core || exit 10
grep -q 'wgclient1 20 pre-reboot-tier1-recovery' promoted || exit 11
""")
# Healthy Tier 2 with established UP never reconstructs DOWN.
check(['run_cycle'],r"""
maybe_clear_expired_backoff() { :; }
reconcile_roles() { echo 'wgclient2|70|7|2||wgclient1|13'; }
current_iface() { echo wgclient2; }
iface_healthy() { return 0; }
cleanup_extras() { echo "$*" > kept; }
probe_recovery_targets() { :; }
refresh_detector_roles() { :; }
ensure_downtier() { exit 90; }
promote_iface() { exit 91; }
""",r"""
run_cycle || exit 10
[ "$(cat kept)" = 'wgclient2 wgclient1' ] || exit 11
""")
# A failure detected during DOWN construction immediately requests slow recovery,
# without starting an UP provider request against a dead CURRENT.
check(['run_cycle'],r"""
maybe_clear_expired_backoff() { :; }
reconcile_roles() { echo 'wgclient2|70|7|2|||13'; }
current_iface() { echo wgclient2; }
iface_healthy() { return 0; }
free_slot() { echo wgclient3; }
ensure_downtier() { DETECT_FAILED=1; SLOW_REQUESTED=1; return 2; }
refresh_detector_roles() { :; }
probe_recovery_targets() { exit 90; }
""",r"""
run_cycle || exit 10
[ "$SLOW_REQUESTED" = 1 ] || exit 11
""")
# Bound probes use any responding target and reap every ping before returning.
check(['fast_path_round'],r"""
delay_us() { [ "$1" = 200000 ]; }
ping() { [ "$7" = 1 ] || exit 90; case "$*" in *1.1.1.1) return 1;; *) return 0;; esac; }
""",r"""
fast_path_round wgclient2 || exit 10
[ -z "$(jobs -p)" ] || exit 11
""")
# Behavioral timing validation: unsupported, no-op and one-second waits fail.
for elapsed, rc, expected in [(150,0,0),(0,0,1),(1000,0,1),(150,127,1)]:
    check(['verify_delay'], f"""
monotonic_ms() {{ if [ -e clock ]; then echo {elapsed}; else echo 0; fi; }}
delay_us() {{ [ "$1" = 150000 ] || exit 90; touch clock; return {rc}; }}
""", f'verify_delay; [ $? -eq {expected} ] || exit 10')
check(['delay_us'], r"""
busybox() { [ "$1" = usleep ] && [ "$2" = 150000 ]; }
""", 'delay_us 150000 || exit 10')
# Drain real owned work and its synchronous child; do not orphan a mutator.
check(['stop_slow_command'], '', r"""
sh -c 'host_pause 0.08; echo done > completed' &
SLOW_PID=$!
stop_slow_command
[ -e completed ] && [ -z "$SLOW_PID" ] || exit 10
""")
print(f'PASS: {COUNT} directional-role, cooperative-work and serial detector scenarios')
