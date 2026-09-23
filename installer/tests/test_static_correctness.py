"""Focused host-only lifecycle tests. Uses real host flock via util-linux or Perl."""
import json, os, re, shutil, subprocess, sys, tempfile, time, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SH = sys.argv.pop(1) if len(sys.argv) > 1 else "sh"
if Path(SH).is_absolute():
    os.environ["PATH"] = str(Path(SH).parent) + os.pathsep + os.environ.get("PATH", "")
MAIN = (ROOT / "hotswapper-main.sh").read_text()
HELPER = (ROOT / "firmware/gl-coordination.sh").read_text()

def function(name, source=MAIN):
    match = re.search(r"^" + name + r"\(\) ([{(])\n", source, re.M)
    return source[match.start():source.index("\n" + ("}" if match[1] == "{" else ")"), match.end()) + 2]

# Perl exposes the host flock primitive; it does not emulate lock ownership.
FLOCK = r"""
busybox() {
    case "$1" in
        flock)
            shift
            perl -e 'my $op=2; my $fd; for(@ARGV) { $op=1 if $_ eq "-s"; $op=8 if $_ eq "-u"; $fd=$_ if /^\d+$/; } $op|=4 unless $op==8; open(my $fh,"+<&=$fd") or exit 2; exit(flock($fh,$op)?0:1);' -- "$@";;
        usleep) sleep 0.01;;
        *) return 1;;
    esac
}
"""

class StaticCorrectnessTests(unittest.TestCase):
    def run_shell(self, body):
        with tempfile.TemporaryDirectory(prefix="hotswapper-static-") as folder:
            script = Path(folder) / "case.sh"
            script.write_text(body, newline="\n")
            result = subprocess.run([SH, script.as_posix()], cwd=folder, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_restart_drop_requests_recovery_without_reopening(self):
        self.run_shell(function("restore_failure_state") + r"""
hs_lock() { :; }; hs_unlock() { :; }
current_iface() { echo wgclient2; }; current_peer() { echo 22; }
policy_get() { echo 0x2000; }; policy_section() { echo policy; }
fastpath_verify_consistency() { return 1; }
fastpath_rollback() { DETECT_FAILED=1; SLOW_REQUESTED=1; }
DETECT_FAILED=0; SLOW_REQUESTED=0
restore_failure_state || exit 1
[ "$DETECT_FAILED:$SLOW_REQUESTED" = 1:1 ] || exit 2
""")

    def test_current_check_requires_selector_and_probe(self):
        self.run_shell(function("verify_current") + r"""
HS_DIR=.; LOCK_DIR=.; echo '123 456' > owner; echo 123 > pid
hs_lock() { :; }; hs_daemon_lock_held() { :; }
current_iface() { echo wgclient2; }; current_peer() { echo 22; }
policy_get() { echo 0x2000; }; policy_section() { echo policy; }
readiness_token() { echo 22:1:2:3; }
hs_owned() { :; }; owned_hard_up() { :; }; hs_peer_matches() { :; }
prepared_hooks_match() { :; }
fastpath_verify_consistency() { [ "$selector" = MARK ]; }
fast_path_round() { echo probe >> probes; [ "$path" = up ]; }
selector=DROP; path=up
verify_current && exit 1
[ ! -e probes ] || exit 2
selector=MARK; path=down
verify_current && exit 3
path=up
[ "$(verify_current)" = CURRENT_OK ] || exit 4
""")

    def test_authoritative_daemon_requires_lock_on_its_descriptor(self):
        self.run_shell(function("hs_daemon_lock_held", HELPER) + r"""
HS_DIR=.; HS_PROC=./proc; mkdir -p lock proc/123/fdinfo
echo '123 456' > owner; echo 123 > lock/pid
hs_daemon_alive() { :; }
readlink() { echo ./daemon.lock; }
# The applet acquired the lock for its parent; the recorded PID need not be 123.
echo 'lock: 1: FLOCK ADVISORY WRITE 124 00:01:200 0 EOF' > proc/123/fdinfo/8
hs_daemon_lock_held || exit 1
: > proc/123/fdinfo/8
hs_daemon_lock_held && exit 2
exit 0
""")

    def test_worker_drain_waits_and_rejects_busy_worker(self):
        self.run_shell(function("hs_drain_old_workers", HELPER) + r"""
HS_PROC=./proc; mkdir -p proc/123 proc/124
printf '/bin/sh\000/usr/bin/setup_instance\000start\000wgclient2\000' > proc/123/cmdline
awk 'BEGIN {for(i=1;i<=22;i++) printf "%s%s", (i==22?"17":"0"),(i==22?"\n":" ")}' > proc/123/stat
printf '/bin/sh\000-c\000echo /usr/bin/rtp2.sh\000' > proc/124/cmdline
cp proc/123/stat proc/124/stat
busybox() { echo wait >> waits; rm -f proc/123/stat; }
hs_drain_old_workers || exit 1
[ "$(wc -l < waits)" = 1 ] || exit 2
cp proc/124/stat proc/123/stat
busybox() { :; }
hs_drain_old_workers && exit 3
exit 0
""")

    def test_firmware_lock_precedes_procd(self):
        patches = (ROOT / "firmware/gl-patches.awk").read_text()
        part = patches.split('if (target == "firewall") {')[1].split("\n    }")[0]
        entry = json.loads(re.search(r"replacement\[1\] = (.+)", part)[1])
        self.run_shell(FLOCK + r"""
HS_DIR=.; HS_PROC=/proc; HS_KEYUP_SLOT=""
""" + function("hs_event_still_current", HELPER) + "\n" + function("hs_lock", HELPER) + "\n" + function("hs_unlock", HELPER) + "\n" + entry.replace('. /root/hotswapper/gl-coordination.sh || exit 1', ':') .replace('QUIET=""', 'action=trace; QUIET=""') + r"""
[ "$HS_LOCKED" = 1 ] || exit 1
# rc.common takes this service lock only after sourcing the init script.
exec 6>service.lock
busybox flock -n 6 || exit 2
hs_lock || exit 3
hs_unlock
""")

    def test_stale_identified_event_cannot_invalidate_reused_slot(self):
        self.run_shell(function("hs_event", HELPER) + r"""
HS_DIR=.; echo '22 9 4 8 14' > owned.wgclient2
hs_lock() { :; }; hs_owned() { :; }; hs_wake() { echo wake >> events; }
hs_invalidate_all() { echo invalid >> events; }
hs_event wgclient2 7:12 && exit 1
[ ! -e events ] || exit 2
hs_event wgclient2 || exit 3
[ "$(cat events)" = wake ] || exit 4
""")

    def test_keyup_rechecks_generation_after_waiting_for_lock(self):
        self.run_shell(FLOCK + function("hs_event_still_current", HELPER) + "\n" +
                       function("hs_lock", HELPER) + "\n" + function("hs_unlock", HELPER) + r"""
HS_DIR=.; HS_PROC=/proc; HS_KEYUP_SLOT=wgclient2
HS_KEYUP_IDENTITY='22 9 4 7 12'
echo '33 9 4 8 14' > owned.wgclient2
hs_lock fast && exit 1
[ "$HS_LOCKED" = 0 ] || exit 2
HS_KEYUP_IDENTITY='33 9 4 8 14'
hs_lock fast || exit 3
hs_unlock
""")

    def test_private_reference_hashes_and_patch_outputs(self):
        import hashlib
        reference = ROOT / "tooling/firmware-reference/filesystem"
        if not reference.exists():
            self.skipTest("Private firmware reference is not available")
        # Keep firmware bytes in memory; only hashes appear in test failures.
        for row in (ROOT / "firmware/gl-targets.tsv").read_text().splitlines():
            target, path, stock, patched = row.split("\t")
            data = (reference / path.lstrip("/")).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), stock, target)
            result = subprocess.run([SH, "-c", 'awk -v target="$1" -f "$2"', "audit", target,
                                     (ROOT / "firmware/gl-patches.awk").as_posix()], input=data, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, target)
            self.assertEqual(hashlib.sha256(result.stdout).hexdigest(), patched, target)

    def test_old_worker_drain_brackets_patching_and_precedes_ownership(self):
        patcher = (ROOT / "firmware/install-gl-guard.sh").read_text()
        install = patcher[patcher.index("install() {"):]
        first, last = install.index("hs_drain_old_workers"), install.rindex("hs_drain_old_workers")
        self.assertLess(first, install.index('mv -f "$ROOT$path.hotswap-new-$$"'))
        self.assertGreater(last, install.index('mv -f "$ROOT$path.hotswap-new-$$"'))
        adoption = function("start_ownership")
        self.assertLess(adoption.index("hs_drain_old_workers"), adoption.index('> "$HS_DIR/owner.new"'))

    def lifetime_lock(self, kind):
        if not shutil.which("perl"):
            self.skipTest("Perl host flock unavailable")
        with tempfile.TemporaryDirectory(prefix="hotswapper-lock-") as folder:
            script = Path(folder) / "holder.sh"
            if kind == "daemon":
                body = function("acquire_lock") + "\n" + function("release_lock") + r"""
stop_slow_command() { :; }
RUNTIME_DIR=.; LOCK_DIR=./lock
acquire_lock || exit 7
"""
            elif kind == "supervisor":
                body = (ROOT / "hotswapper-supervisor.sh").read_text().split('exec 8>')[0]
                body = body.replace('RUNTIME_DIR="/tmp/hotswapper"', 'RUNTIME_DIR="."')
            else:
                text = (ROOT / "installer/Services/SshInstallerLock.cs").read_text()
                command = json.loads(re.search(r'public const string Command = (".*");', text)[1])
                body = command.replace("/tmp/hotswapper", "./runtime") + "\nexit\n"
            script.write_text(FLOCK + "\n" + body + r"""
printf 'LOCKED\n'
read -r release
""", newline="\n")
            first = subprocess.Popen([SH, script.as_posix()], cwd=folder, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(first.stdout.readline().strip(), "LOCKED")
                second = subprocess.run([SH, script.as_posix()], cwd=folder, input="", capture_output=True, text=True, timeout=5)
                self.assertNotIn("LOCKED", second.stdout)
                # Abrupt death must release the OS lock without deleting its file.
                first.kill(); first.wait(timeout=5)
                again = subprocess.run([SH, script.as_posix()], cwd=folder, input="done\n", capture_output=True, text=True, timeout=5)
                self.assertIn("LOCKED", again.stdout, again.stderr)
            finally:
                if first.poll() is None: first.kill()
                first.communicate(timeout=5)

    def test_daemon_single_instance_and_crash_release(self): self.lifetime_lock("daemon")
    def test_supervisor_crash_release(self): self.lifetime_lock("supervisor")
    def test_installer_session_crash_release(self): self.lifetime_lock("installer")

if __name__ == "__main__":
    unittest.main()
