"""Synthetic coordination tests: Python plus a POSIX shell, no router access."""
import json, os, re, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SH = sys.argv.pop(1) if len(sys.argv)>1 else 'sh'
if Path(SH).is_absolute():
    os.environ['PATH'] = str(Path(SH).parent)+os.pathsep+os.environ.get('PATH','')
MAIN = (ROOT/'hotswapper-main.sh').read_text(encoding='utf-8')
HELPER = (ROOT/'firmware/gl-coordination.sh').read_text(encoding='utf-8')
PATCHES = (ROOT/'firmware/gl-patches.awk').read_text(encoding='utf-8')

def function(name, source=MAIN):
    m = re.search(r'^'+name+r'\(\) ([{(])\n',source,re.M)
    assert m, name
    return source[m.start():source.index('\n'+('}' if m[1]=='{' else ')'),m.end())+2]

def patch(target, number):
    part = PATCHES.split('if (target == "'+target+'") {')[1].split('\n    }')[0]
    return json.loads(re.search(r'replacement\['+str(number)+r'\] = (.*)',part)[1])

class CoordinationTests(unittest.TestCase):
    def shell(self, names, code, helpers=()):
        with tempfile.TemporaryDirectory(prefix='hotswapper-test-') as tmp:
            body = "cd '"+Path(tmp).as_posix()+"' || exit 99\n"+r"""
HS_DIR=.; HS_PROC=./proc; RUNTIME_DIR=.
GROUP_ID=9; TUNNEL_ID=4; SLOTS="wgclient1 wgclient2 wgclient3"
hs_lock() { return 0; }
hs_event_still_current() { return 0; }
hs_unlock() { :; }
hs_daemon_alive() { return 0; }
hs_wake() { echo wake >> wakes; }
owned_hard_up() { [ ! -f down ]; }
prepared_dataplane_matches() { [ ! -f unprepared ]; }
hs_owned() { :; }
hs_disarm() { rm -f "$HS_DIR/armed.$1" "$HS_DIR/ready.$1"; }
fastpath_verify_kernel() { :; }
fastpath_mark_for_iface() { echo 0x2000; }
prepared_hooks_match() { :; }
policy_section() { echo selected; }
prune_detector_candidates() { :; }
refresh_detector_roles() { :; }
monotonic_ms() { echo 10000; }
peer_rank() { echo 2; }
uci() {
    case "$3" in
        network.wgclient2.config) cat config;;
        wireguard.peer_22.group_id) echo 9;;
        wireguard.peer_22.public_key) echo synthetic-key;;
        *) return 1;;
    esac
}
wg() { echo synthetic-key; }
echo '22 9 4 7 12' > owned.wgclient2
echo peer_22 > config
echo 4:9 > tunnel
"""
            body += '\n'.join(function(n).replace('/sys/class/net/', './sys/') for n in names)+'\n'
            body += '\n'.join(function(n,HELPER) for n in helpers)+'\n'+code
            script=Path(tmp)/'case.sh'
            script.write_text(body,encoding='utf-8',newline='\n')
            r=subprocess.run([SH,str(script)],capture_output=True,text=True,timeout=15)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)

    def test_live_config_and_group_required(self):
        self.shell([],r"""
hs_owned wgclient2 peer_22 || exit 10
hs_owned wgclient4 && exit 11
echo peer_33 > config
hs_owned wgclient2 peer_22 && exit 12
echo peer_22 > config
echo '22 8 4 7 12' > owned.wgclient2
hs_owned wgclient2 && exit 13
exit 0
""",['hs_owned'])

    def test_preparing_reservation_generation(self):
        self.shell([],r"""
echo peer_11 > config
echo '7 peer_11' > reservation.wgclient2
hs_owned wgclient2 || exit 10
echo '6 peer_11' > reservation.wgclient2
hs_owned wgclient2 && exit 11
exit 0
""",['hs_owned'])

    def test_old_event_ignored_unversioned_event_only_wakes(self):
        self.shell([],r"""
hs_event wgclient2 6:12 && exit 10
[ ! -f wakes ] && [ ! -f invalid.wgclient2.7 ] || exit 11
hs_event wgclient2 || exit 12
[ -f wakes ] && [ ! -f invalid.wgclient2.7 ] || exit 13
hs_event wgclient2 7:12 || exit 14
[ -f invalid.wgclient2.7 ] && [ "$(cat dataplane-epoch)" = 1 ] || exit 15
hs_event wgclient4 && exit 16
exit 0
""",['hs_owned','hs_event','hs_invalidate_all'])

    def test_worker_cannot_mutate_owned_tunnel_or_target(self):
        self.shell([],r"""
hs_worker_allowed 4 wgclient5 && exit 10
hs_worker_allowed 99 wgclient2 && exit 11
hs_worker_allowed 99 wgclient5 || exit 12
exit 0
""",['hs_owned','hs_tunnel_owned','hs_worker_allowed'])

    def test_hot_path_contains_no_availability_validator(self):
        body = function('promote_iface')
        for name in ['candidate_structurally_ready', 'owned_hard_up', 'fastpath_verify_kernel',
                     'prepared_dataplane_matches', 'fast_path_round', 'wg show', 'ip route', 'readiness_token']:
            self.assertNotIn(name, body)

    def test_background_standby_still_probes(self):
        self.shell(['refresh_standby_health'],r"""
DETECTOR_NOW=10000; NEXT_STANDBY_CHECK=0; STANDBY_CHECK_MS=4000
DETECT_UP=wgclient2; DETECT_DOWN=""
readiness_token() { echo token; }
fast_path_round() { echo probe > probed; }
record_readiness() { echo recorded > recorded; }
refresh_standby_health
[ -f probed ] && [ -f recorded ] && [ "$NEXT_STANDBY_CHECK" = 14000 ]
""")

    def test_inflight_probe_cannot_certify_new_generation_or_firewall(self):
        self.shell(['readiness_token','record_readiness'],r"""
token=$(readiness_token wgclient2)
echo '22 9 4 8 12' > owned.wgclient2
touch invalid.wgclient2.8
record_readiness wgclient2 "$token" && exit 10
[ -f invalid.wgclient2.8 ] || exit 11
token=$(readiness_token wgclient2)
echo 1 > dataplane-epoch
record_readiness wgclient2 "$token" && exit 12
[ -f invalid.wgclient2.8 ] || exit 13
exit 0
""")

    def test_successful_probe_clears_only_matching_invalid_marker(self):
        self.shell(['readiness_token','record_readiness'],r"""
token=$(readiness_token wgclient2)
touch invalid.wgclient2.7 invalid.wgclient2.6
touch down
record_readiness wgclient2 "$token" && exit 10
[ -f invalid.wgclient2.7 ] || exit 11
rm down; touch unprepared
record_readiness wgclient2 "$token" && exit 12
[ -f invalid.wgclient2.7 ] || exit 13
rm unprepared
record_readiness wgclient2 "$token" || exit 14
[ ! -f invalid.wgclient2.7 ] && [ -f invalid.wgclient2.6 ] || exit 15
exit 0
""")

    def test_fast_priority_and_bounded_wait(self):
        # Models flock availability. Native Linux FD exclusion needs hardware validation.
        self.shell([],r"""
busybox() { case "$1" in flock) echo acquired >> locks; return 0;; usleep) return 0;; esac; }
touch promotion-waiting
hs_lock slow && exit 10
[ ! -f locks ] || exit 11
hs_lock fast || exit 12
[ "$(wc -l < locks)" = 1 ] || exit 13
hs_unlock
rm promotion-waiting
hs_lock slow || exit 14
""",['hs_lock','hs_unlock'])

    def test_existing_writer_finishes_before_promotion_enters(self):
        self.shell([],r"""
touch held
waits=0
busybox() {
    case "$1" in
        flock)
            if [ -e held ]; then return 1; fi
            echo fast-entered >> sequence
            return 0;;
        usleep)
            waits=$((waits+1))
            if [ "$waits" = 3 ]; then
                echo slow-finished >> sequence
                rm held
            fi
            return 0;;
    esac
}
hs_lock fast || exit 10
[ "$(cat sequence)" = 'slow-finished
fast-entered' ] || exit 11
[ "$waits" = 3 ] || exit 12
""",['hs_lock'])

    def test_flip_order_and_required_mutation_failure_drop(self):
        self.shell(['promote_iface','fastpath_rollback'],r"""
mkdir -p sys/wgclient2; echo 12 > sys/wgclient2/ifindex
echo '22 12 selected' > armed.wgclient2
candidate_structurally_ready() { exit 91; }
owned_hard_up() { exit 92; }
prepared_dataplane_matches() { exit 93; }
fastpath_verify_kernel() { exit 94; }
fast_path_round() { exit 95; }
wg() { exit 96; }; ip() { exit 97; }
acquire_gl_guard() { echo lock >> order; }
release_gl_guard() { echo unlock >> order; }
peer_tier() { echo tier >> order; echo 2; }
uci() { [ -f flipped ] || exit 98; echo 11; }
fastpath_install_mark_override() { echo flip >> order; touch flipped; [ "$fault" != flip ]; }
select_dns_mark() { echo dns >> order; [ "$fault" != dns ]; }
synchronize_gl() { echo synchronize >> order; [ "$fault" != sync ]; }
iptables() { echo "$*" >> drop; }
notify() { exit 99; }; log() { :; }
PROMOTION_EPOCH=0
promote_iface wgclient2 22 failure || exit 10
[ "$(cat order)" = 'lock
flip
dns
synchronize
unlock
tier
tier' ] || exit 11
[ "$DETECT_CURRENT:$DETECT_FAILED" = wgclient2:0 ] || exit 12
for fault in flip dns sync; do
    echo '22 12 selected' > armed.wgclient2
    promote_iface wgclient2 22 failure
    [ "$?" = 2 ] || exit 13
    [ "$DETECT_FAILED:$SLOW_REQUESTED" = 1:1 ] || exit 14
done
[ "$(grep -c -- '-R HOTSWAPPER_SELECTED 1 -j DROP' drop)" = 3 ] || exit 15
""")

    def test_hot_priority_and_failed_flip_stops_attempts(self):
        self.shell(['promote_hot_candidate'],r"""
iface_peer() { echo 22; }
iptables() { echo restored-old >> attempts; return 0; }
promote_iface() { echo "$1" >> attempts; return "$rc"; }
rc=0
promote_hot_candidate wgclient1 11 1 1 wgclient3 wgclient2 || exit 10
[ "$(cat attempts)" = wgclient2 ] || exit 11
rm attempts
rc=2
promote_hot_candidate wgclient1 11 1 1 wgclient3 wgclient2 && exit 12
[ "$(cat attempts)" = wgclient2 ] || exit 13
rm attempts
promote_iface() { echo "$1" >> attempts; [ "$1" = wgclient3 ]; }
promote_hot_candidate wgclient1 11 1 1 wgclient3 wgclient2 || exit 14
[ "$(cat attempts)" = 'wgclient2
wgclient3' ] || exit 15
rm attempts
iptables() { return 0; }
fast_path_round() { return 1; }
promote_hot_candidate wgclient1 11 1 1 "" "" && exit 16
[ ! -f attempts ] || exit 17
""")

    def test_disarm_while_waiting_prevents_flip(self):
        self.shell(['promote_iface'],r"""
echo '22 12 selected' > armed.wgclient2
acquire_gl_guard() { rm armed.wgclient2; }
release_gl_guard() { touch released; }
fastpath_install_mark_override() { exit 91; }
promote_iface wgclient2 22 failure && exit 10
[ -f released ] || exit 11
""")

    def test_recreated_interface_cannot_consume_old_arm(self):
        self.shell(['promote_iface'],r"""
mkdir -p sys/wgclient2; echo 13 > sys/wgclient2/ifindex
echo '22 12 selected' > armed.wgclient2
acquire_gl_guard() { :; }; release_gl_guard() { :; }
fastpath_install_mark_override() { exit 91; }
promote_iface wgclient2 22 failure && exit 10
exit 0
""")

    def test_dns_preparation_applies_only_its_five_rules(self):
        self.shell([],r"""
FILE_VPN_DNS_RULE=generated
uci() { echo 2253; }
cat > generated <<'EOF'
table="nat";chain="policy_output";option="-p tcp -m mark --mark 0x2000/0xf000 -m owner --uid-owner dnsmasq -m tcp --dport 53";target="-j REDIRECT --to-ports 2253"
table="nat";chain="policy_output";option="-p udp -m mark --mark 0x2000/0xf000 -m owner --gid-owner usevpn -m udp --dport 53";target="-j REDIRECT --to-ports 2253"
chain="policy_redirect";option="-p udp -m mark --mark 0x2000/0xf000";target="-j REDIRECT --to-ports 2253"
table="raw";chain="pre_dns_deal_conn_zone";option="-p udp -m mark --mark 0x2000/0xf000 ! -i lo";target="-j CT --zone 0x2000"
table="raw";chain="out_dns_deal_conn_zone";option="-p udp --sport 2253 ! -o lo";target="-j CT --zone 0x2000"
chain="policy_redirect";option="-p udp -m mark --mark 0x4000/0xf000";target="-j REDIRECT --to-ports 2453"
EOF
iptables() { case "$*" in *' -C '*) return 1;; *) echo "$*" >> applied;; esac; }
hs_prepare_dns wgclient2 0x2000 || exit 10
[ "$(wc -l < applied)" = 5 ] || exit 11
grep -q 0x4000 applied && exit 12
exit 0
""",['hs_prepare_dns'])

    def test_stale_generated_process_reference_is_synchronized(self):
        body=(function('synchronize_gl')+'\n'+function('select_dns_mark')).replace('/proc/dns_mark/','./dns/')
        self.shell([],body+r"""
hs_owned() { case "$1" in wgclient1|wgclient2) return 0;; *) return 1;; esac; }
mkdir -p dns/rule4
touch dns/rule4/mark
uci() {
    if [ "$1" = set ]; then echo "$2" >> changes; return 0; fi
    [ "$1" = commit ] && return 0
    case "$3" in
        route_policy.selected.via) echo wgclient2;;
        route_policy.selected.tunnel_id) echo 4;;
        route_policy.gl_process_vpn.via) echo wgclient1;;
        route_policy.gl_process_vpn) echo rule_process;;
        route_policy.gl_process_vpn.tunnel_id) echo 8;;
        *) return 1;;
    esac
}
iptables() {
    case "$*" in
        *TUNNEL4_ROUTE_POLICY) echo '-A TUNNEL4_ROUTE_POLICY -m mark --mark 0x0/0xf000 -j MARK --set-xmark 0x2000/0xf000';;
        *TUNNEL8_LOCAL_POLICY) echo '-A TUNNEL8_LOCAL_POLICY -m owner --gid-owner 99 -j MARK --set-xmark 0x1000/0xf000';;
        *) return 1;;
    esac
}
iptables-restore() { cat > restored; }
select_dns_mark 0x2000 || exit 9
synchronize_gl selected wgclient2 22 0x2000 || exit 10
grep -Fxq 'route_policy.gl_process_vpn.via=wgclient2' changes || exit 11
grep -q -- '-A TUNNEL8_LOCAL_POLICY.*--set-xmark 0x2000/0xf000' restored || exit 12
[ "$(cat dns/rule4/mark)" = 0x2000 ] || exit 13
""")

    def test_guards_recheck_after_wait(self):
        for target,n in [('rtp',2),('firewall_event',1),('keydown',1)]:
            text=patch(target,n)
            self.assertIn('hs_owned',text[text.index('hs_lock'):])
        self.assertIn('hs_lock && hs_worker_allowed "$1" "$4"',patch('switch',5))
        self.assertIn('hs_lock && hs_worker_allowed "$1" "$2"',patch('switch',5))
        self.assertIn('not owned and not is_instance_config_used',patch('instances',1))
        self.assertIn('hs_setup_identity',patch('proto',2))
        self.assertIn('hs_teardown_identity',patch('proto',4))
        self.assertIn('HS_SLOT_IDENTITY',patch('setup',2))
        for target in ['keydown','iface','firewall_event']:
            self.assertNotIn('promote_iface',patch(target,1))

    def test_hot_path_has_no_rebuild_or_slow_probe(self):
        body=function('promote_iface')
        for command in ['probe_iface_path','iface_healthy','fast_path_round','setup_instance','rtp2','prepare_dataplane']:
            self.assertNotIn(command, body)
        self.assertEqual(body.count('fastpath_install_mark_override'),1)
        self.assertIn('gl_process_vpn gl_process',function('synchronize_gl'))
        self.assertIn('/proc/dns_mark/rule',function('select_dns_mark'))
        self.assertNotIn('firewall reload',patch('rtp',2))
        self.assertIn('hs_prepare_dns',patch('rtp',2))


    def test_probe_cancellation_is_not_failure(self):
        self.shell(['fast_path_round'],r"""
FAST_PROBE_WINDOW_US=100000
ping() { sleep 1; }
delay_us() { WAKE_REQUESTED=1; }
WAKE_REQUESTED=1
fast_path_round wgclient2; [ "$?" = 2 ] || exit 10
WAKE_REQUESTED=0
fast_path_round wgclient2; [ "$?" = 2 ] || exit 11
delay_us() { :; }
WAKE_REQUESTED=0
fast_path_round wgclient2; [ "$?" = 1 ] || exit 12
ping() { return 0; }
delay_us() { sleep 0.01; }
FAST_PROBE_WINDOW_US=200000
fast_path_round wgclient2; [ "$?" = 0 ] || exit 13
""")

    def test_interrupted_current_probe_does_not_increment_failures(self):
        self.shell(['fast_health_pass'],r"""
IN_DETECTOR=0; SLOW_REQUESTED=0; DETECT_FAILED=0; FAST_FAILURES=1
DETECT_CURRENT=wgclient1; WAKE_REQUESTED=0
current_iface() { echo wgclient1; }
fast_path_round() { return 2; }
promote_iface() { exit 91; }
refresh_standby_health() { exit 92; }
fast_health_pass
[ "$FAST_FAILURES:$DETECT_FAILED" = 1:0 ] || exit 10
""")

    def test_disarm_revokes_detector_eligibility_before_permitted_mutation(self):
        self.shell(['prune_detector_candidates'],r"""
echo '22 12 selected' > armed.wgclient2
echo 22 > ready.wgclient2
touch permit.wgclient2.down.7
DETECT_UP=wgclient2; DETECT_DOWN=wgclient2
hs_permit wgclient2 down || exit 10
[ ! -e armed.wgclient2 ] && [ ! -e ready.wgclient2 ] || exit 11
prune_detector_candidates
[ -z "$DETECT_UP$DETECT_DOWN" ] || exit 12
""", ['hs_disarm','hs_permit'])

    def test_terminal_route_and_exact_table_required_before_arming(self):
        self.shell(['fastpath_verify_kernel'],r"""
ip() {
    case "$*" in
        'link show wgclient2') return 0;;
        '-4 route show table 1002') cat routes;;
        '-4 rule show') echo '6000: from all fwmark 0x2000/0xf000 lookup 1002';;
        *) exit 91;;
    esac
}
printf 'default dev wgclient2\nblackhole default metric 254\n' > routes
fastpath_verify_kernel wgclient2 0x2000 || exit 10
echo 'default dev wgclient2' > routes
fastpath_verify_kernel wgclient2 0x2000 && exit 11
printf 'default dev wan\nblackhole default metric 254\n' > routes
fastpath_verify_kernel wgclient2 0x2000 && exit 12
printf 'default dev wgclient2\nblackhole default metric 254\n203.0.113.0/24 via 192.0.2.1 dev wan\n' > routes
fastpath_verify_kernel wgclient2 0x2000 && exit 13
exit 0
""")

    def test_preparation_keeps_guards_for_unowned_broken_slots(self):
        self.shell(['prepare_dataplane'],r"""
hs_owned() { [ "$1" = wgclient1 ]; }
hs_invalidate_all() { :; }
fastpath_mark_for_iface() { case "$1" in wgclient1) echo 0x1000;; wgclient2) echo 0x2000;; wgclient3) echo 0x3000;; esac; }
ip() { case "$*" in '-4 route show dev br-lan scope link') echo '192.0.2.0/24 proto kernel';; *) echo "$*" >> routes;; esac; }
iptables() { return 0; }
iptables-restore() { cat > restored; }
fastpath_prepare_firewall() { :; }; prepare_selector() { :; }
prepare_dataplane wgclient1 || exit 10
for n in 1 2 3; do
    grep -Fxq -- "-A HOTSWAPPER_EGRESS -m mark --mark 0x${n}000/0xf000 ! -o wgclient$n -j DROP" restored || exit 11
done
grep -Fxq -- '-I FORWARD 1 -j HOTSWAPPER_EGRESS' restored || exit 12
grep -Fxq -- '-I OUTPUT 1 -j HOTSWAPPER_EGRESS' restored || exit 13
grep -q -- 'replace blackhole default table 1001 metric 254' routes || exit 14
""")

    def test_lifecycle_mutations_disarm_first(self):
        self.assertLess(function('claim_slot').index('hs_disarm'), function('claim_slot').index('owned.$iface.new'))
        self.assertLess(function('teardown_iface').index('hs_disarm'), function('teardown_iface').index('slow_command ifdown'))
        self.assertLess(patch('proto',5).index('hs_disarm'), len(patch('proto',5)))
        self.assertIn('hs_disarm "$instance_name"', patch('setup',2))
        self.assertIn('hs_disarm "$iface"', function('hs_ifindex',HELPER))
        self.assertIn('hs_disarm "$iface"', function('hs_invalidate_all',HELPER))


    def test_background_failure_disarms_but_cancellation_keeps_arm(self):
        self.shell(['refresh_standby_health','prune_detector_candidates'],r"""
DETECTOR_NOW=10000; NEXT_STANDBY_CHECK=0; STANDBY_CHECK_MS=4000
DETECT_CURRENT=wgclient1; DETECT_UP=wgclient2; DETECT_DOWN=""; SLOTS=wgclient2
readiness_token() { echo token; }
echo '22 12 selected' > armed.wgclient2
fast_path_round() { return 2; }
refresh_standby_health
[ -f armed.wgclient2 ] && [ "$DETECT_UP" = wgclient2 ] || exit 10
NEXT_STANDBY_CHECK=0
fast_path_round() { return 1; }
refresh_standby_health
[ ! -f armed.wgclient2 ] && [ -z "$DETECT_UP" ] || exit 11
""")

    def test_selector_hook_requires_matching_scope_before_gl_jump(self):
        self.shell(['selector_hook_matches'],r"""
iptables() {
    case "$*" in
        *'-S TUNNEL4_ROUTE_POLICY') echo '-A TUNNEL4_ROUTE_POLICY -m mark --mark 0x0/0xf000 -s 192.0.2.0/24 -j MARK --set-xmark 0x1000/0xf000';;
        *'-S ROUTE_POLICY') cat parent;;
        *) return 1;;
    esac
}
hook='-A ROUTE_POLICY -m addrtype ! --dst-type LOCAL -m mark --mark 0x0/0xc000 -s 192.0.2.0/24 -m comment --comment hotswapper-fastpath -j HOTSWAPPER_SELECTED'
jump='-A ROUTE_POLICY -m addrtype ! --dst-type LOCAL -j TUNNEL4_ROUTE_POLICY'
printf '%s\n' "$hook" "$jump" > parent
selector_hook_matches ROUTE_POLICY TUNNEL4_ROUTE_POLICY hotswapper-fastpath || exit 10
printf '%s\n' "$jump" "$hook" > parent
selector_hook_matches ROUTE_POLICY TUNNEL4_ROUTE_POLICY hotswapper-fastpath && exit 11
printf '%s\n' "$hook" "$jump" | sed 's/-s 192.0.2.0\/24 / /' > parent
selector_hook_matches ROUTE_POLICY TUNNEL4_ROUTE_POLICY hotswapper-fastpath && exit 12
exit 0
""")


class PatcherTests(unittest.TestCase):
    def setUp(self):
        import hashlib, shutil
        self.tmp=tempfile.TemporaryDirectory(prefix='hotswapper-patcher-')
        self.base=Path(self.tmp.name)
        self.root=self.base/'root'
        self.assets=self.base/'assets'
        self.assets.mkdir()
        (self.root/'usr/bin').mkdir(parents=True)
        self.env=dict(os.environ,HS_FIRMWARE_ROOT=self.root.as_posix(),
                      HS_BACKUPS=(self.base/'backups').as_posix(),HS_PATCH_WORK=self.base.as_posix())
        shutil.copyfile(ROOT/'firmware/install-gl-guard.sh',self.assets/'install-gl-guard.sh')
        self.stock={}
        self.patched={}
        rows=[]
        for name in ['first','second','third']:
            stock=('#!/bin/sh\n# synthetic '+name+'\nexit 0\n').encode()
            patched=stock.replace(b'# synthetic ',b'# patched ')
            self.stock[name]=stock;self.patched[name]=patched
            (self.root/'usr/bin'/name).write_bytes(stock)
            rows.append('\t'.join([name,'/usr/bin/'+name,hashlib.sha256(stock).hexdigest(),hashlib.sha256(patched).hexdigest()]))
        (self.assets/'gl-targets.tsv').write_text('\n'.join(rows)+'\n',newline='\n')
        (self.assets/'gl-patches.awk').write_text('{sub(/^# synthetic /,"# patched ");print}\n',newline='\n')

    def tearDown(self):
        self.tmp.cleanup()

    def run_patch(self,arg):
        return subprocess.run([SH,str(self.assets/'install-gl-guard.sh'),arg],
                              env=self.env,capture_output=True,text=True,timeout=15)

    def test_stock_install_and_reinstall_are_idempotent(self):
        self.assertEqual(self.run_patch('--check').returncode,0)
        r=self.run_patch('--install');self.assertEqual(r.returncode,0,r.stderr)
        for name,body in self.patched.items():
            self.assertEqual((self.root/'usr/bin'/name).read_bytes(),body)
        self.assertEqual(self.run_patch('--verify').returncode,0)
        before={p.name:p.read_bytes() for p in (self.base/'backups').iterdir()}
        self.assertEqual(self.run_patch('--install').returncode,0)
        self.assertEqual(before,{p.name:p.read_bytes() for p in (self.base/'backups').iterdir()})

    def test_previous_coordinated_upgrade_requires_verified_stock_backup(self):
        import hashlib
        previous = b'#!/bin/sh\n# previous coordinated revision\nexit 0\n'
        old_hash = hashlib.sha256(previous).hexdigest()
        stock_hash = hashlib.sha256(self.stock['first']).hexdigest()
        script = self.assets/'install-gl-guard.sh'
        text = script.read_text().replace('case "$1:$2" in', 'case "$1:$2" in\n        first:'+old_hash+') return 0;;', 1)
        script.write_text(text, newline='\n')
        target = self.root/'usr/bin/first'
        target.write_bytes(previous)
        self.assertNotEqual(self.run_patch('--install').returncode, 0)
        self.assertEqual(target.read_bytes(), previous)
        backups = self.base/'backups'
        backups.mkdir(exist_ok=True)
        (backups/stock_hash).write_bytes(b'wrong')
        self.assertNotEqual(self.run_patch('--install').returncode, 0)
        self.assertEqual(target.read_bytes(), previous)
        (backups/stock_hash).write_bytes(self.stock['first'])
        result = self.run_patch('--install')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(target.read_bytes(), self.patched['first'])

    def test_previous_coordinated_upgrade_can_use_exact_rom_stock(self):
        import hashlib
        previous = b'#!/bin/sh\n# previous revision\nexit 0\n'
        old_hash = hashlib.sha256(previous).hexdigest()
        script = self.assets/'install-gl-guard.sh'
        script.write_text(script.read_text().replace('case "$1:$2" in',
            'case "$1:$2" in\n        first:'+old_hash+') return 0;;', 1), newline='\n')
        target = self.root/'usr/bin/first'
        target.write_bytes(previous)
        rom = self.root/'rom/usr/bin'
        rom.mkdir(parents=True)
        (rom/'first').write_bytes(self.stock['first'])
        result = self.run_patch('--install')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(target.read_bytes(), self.patched['first'])

    def test_unknown_target_changes_nothing(self):
        (self.root/'usr/bin/third').write_bytes(b'unknown')
        self.assertNotEqual(self.run_patch('--install').returncode,0)
        for name in ['first','second']:
            self.assertEqual((self.root/'usr/bin'/name).read_bytes(),self.stock[name])
        self.assertFalse((self.base/'backups').exists())

    def test_previous_firewall_patch_is_normalized_and_upgraded(self):
        import hashlib
        stock = self.stock['first']
        previous = stock.replace(b'#!/bin/sh\n', b'#!/bin/sh\n. /root/hotswapper/gl-coordination.sh || exit 1\n\ths_lock || return 1\n\ths_invalidate_all\n')
        old_hash = hashlib.sha256(previous).hexdigest()
        script = self.assets/'install-gl-guard.sh'
        script.write_text(re.sub(r'OLD_FIREWALL=[a-f0-9]+', 'OLD_FIREWALL='+old_hash, script.read_text()), newline='\n')
        catalog = self.assets/'gl-targets.tsv'
        catalog.write_text(catalog.read_text().replace('first\t', 'firewall\t', 1), newline='\n')
        (self.root/'usr/bin/first').write_bytes(previous)
        self.assertEqual(self.run_patch('--check').returncode, 0)
        result = self.run_patch('--install')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root/'usr/bin/first').read_bytes(), self.patched['first'])
        self.assertEqual((self.base/'backups'/old_hash).read_bytes(), previous)

    def test_bad_output_is_rejected_before_first_replacement(self):
        (self.assets/'gl-patches.awk').write_text('{print}\n')
        self.assertNotEqual(self.run_patch('--install').returncode,0)
        for name,body in self.stock.items():
            self.assertEqual((self.root/'usr/bin'/name).read_bytes(),body)

    def test_partial_replacement_failure_rolls_back(self):
        import shutil
        binary=Path(shutil.which('mv')).as_posix()
        mock=self.base/'bin';mock.mkdir()
        code="#!/bin/sh\nfor arg; do last=$arg; done\n"
        code+="case \"$last\" in */second) exit 1;; esac\n"
        code+="exec '"+binary+"' \"$@\"\n"
        (mock/'mv').write_text(code,newline='\n')
        (mock/'mv').chmod(0o755)
        self.env['PATH']=str(mock)+os.pathsep+self.env['PATH']
        r=self.run_patch('--install')
        self.assertNotEqual(r.returncode,0)
        for name,body in self.stock.items():
            self.assertEqual((self.root/'usr/bin'/name).read_bytes(),body)
        self.assertFalse(list(self.root.rglob('*.hotswap-new-*')))

if __name__=='__main__':
    unittest.main()
