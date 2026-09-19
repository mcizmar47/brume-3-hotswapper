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
HS_DIR=.; HS_PROC=./proc; RUNTIME_DIR=.; READY_MAX_AGE_MS=5000
GROUP_ID=9; TUNNEL_ID=4; SLOTS="wgclient1 wgclient2 wgclient3"
hs_lock() { return 0; }
hs_unlock() { :; }
hs_daemon_alive() { return 0; }
hs_wake() { echo wake >> wakes; }
owned_hard_up() { [ ! -f down ]; }
prepared_dataplane_matches() { [ ! -f unprepared ]; }
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
            body += '\n'.join(function(n) for n in names)+'\n'
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

    def test_fresh_skips_probe_and_stale_refreshes_once(self):
        self.shell(['readiness_token','readiness_fresh','record_readiness','candidate_ready'],r"""
fast_path_round() { echo probe >> probes; return 0; }
echo '22:7:12:0 2 9000' > readiness.wgclient2
candidate_ready wgclient2 || exit 10
[ ! -f probes ] || exit 11
echo '22:7:12:0 2 1000' > readiness.wgclient2
candidate_ready wgclient2 || exit 12
[ "$(wc -l < probes)" = 1 ] || exit 13
candidate_ready wgclient2 || exit 14
[ "$(wc -l < probes)" = 1 ] || exit 15
""")

    def test_inflight_probe_cannot_certify_new_generation_or_firewall(self):
        self.shell(['readiness_token','record_readiness'],r"""
token=$(readiness_token wgclient2)
echo '22 9 4 8 12' > owned.wgclient2
record_readiness wgclient2 "$token" && exit 10
[ ! -f readiness.wgclient2 ] || exit 11
token=$(readiness_token wgclient2)
echo 1 > dataplane-epoch
record_readiness wgclient2 "$token" && exit 12
[ ! -f readiness.wgclient2 ] || exit 13
exit 0
""")

    def test_down_restart_or_unprepared_rejects_cache(self):
        self.shell(['readiness_token','readiness_fresh'],r"""
echo '22:7:12:0 2 9000' > readiness.wgclient2
touch down
readiness_fresh wgclient2 && exit 10
rm down; touch unprepared
readiness_fresh wgclient2 && exit 11
rm unprepared; echo '22 9 4 7 13' > owned.wgclient2
readiness_fresh wgclient2 && exit 12
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

    def test_flip_order_and_failed_verification_drop(self):
        self.shell(['promote_iface','fastpath_rollback'],r"""
candidate_ready() { echo ready >> order; }
readiness_fresh() { echo fresh >> order; }
acquire_gl_guard() { echo lock >> order; }
release_gl_guard() { echo unlock >> order; }
iface_peer() { echo 22; }
policy_section() { echo selected; }
fastpath_mark_for_iface() { echo 0x2000; }
peer_tier() { echo 2; }
uci() { echo 11; }
fastpath_install_mark_override() { echo flip >> order; }
synchronize_gl() { echo synchronize >> order; }
fastpath_verify_consistency() { echo verify >> order; [ ! -f fail ]; }
iptables() { echo "$*" >> drop; }
notify() { exit 91; }
log() { :; }
PROMOTION_EPOCH=0
promote_iface wgclient2 22 failure || exit 10
[ "$(cat order)" = 'ready
lock
fresh
flip
synchronize
verify
unlock' ] || exit 11
touch fail
promote_iface wgclient2 22 failure && exit 12
grep -q -- '-R HOTSWAPPER_SELECTED 1 -j DROP' drop || exit 13
[ "$DETECT_FAILED:$SLOW_REQUESTED" = 1:1 ] || exit 14
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
        body=function('synchronize_gl').replace('/proc/dns_mark/','./dns/')
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
            self.assertNotIn(command,body)
        self.assertEqual(body.count('fastpath_install_mark_override'),1)
        self.assertIn('gl_process_vpn gl_process',function('synchronize_gl'))
        self.assertIn('/proc/dns_mark/rule',function('synchronize_gl'))
        self.assertNotIn('firewall reload',patch('rtp',2))
        self.assertIn('hs_prepare_dns',patch('rtp',2))


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

    def test_unknown_target_changes_nothing(self):
        (self.root/'usr/bin/third').write_bytes(b'unknown')
        self.assertNotEqual(self.run_patch('--install').returncode,0)
        for name in ['first','second']:
            self.assertEqual((self.root/'usr/bin'/name).read_bytes(),self.stock[name])
        self.assertFalse((self.base/'backups').exists())

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
