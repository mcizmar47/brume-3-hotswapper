"""Local, non-network shell regression checks. Never source a complete watchdog or reboot script."""
import pathlib
import os
import subprocess
import sys
import tempfile
import json
import hashlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SH = sys.argv[1] if len(sys.argv) > 1 else "sh"
if pathlib.Path(SH).is_absolute():
    os.environ['PATH'] = str(pathlib.Path(SH).parent) + os.pathsep + os.environ.get('PATH', '')
watch = (ROOT / "vpn-watch.sh").read_text(encoding="utf-8")

def run(code, expected=0):
    result = subprocess.run([SH, "-c", code], capture_output=True, text=True)
    assert result.returncode == expected, (result.returncode, result.stdout, result.stderr)
    return result.stdout.strip()

for path in list(ROOT.glob("*.sh")) + list((ROOT / "firmware").glob("*.sh")):
    subprocess.run([SH, "-n", str(path)], check=True)

def function(name):
    start = watch.index(name + "() {")
    return watch[start:watch.index("\n}", start) + 2]

with tempfile.TemporaryDirectory(prefix="brume-shell-") as directory:
    directory = pathlib.Path(directory)
    # Run the actual installer backup command with synthetic local paths.
    # set -e does not stop at a failed non-final command in an && list.
    installer = (ROOT / 'BrumeHotswapper.Installer/Services/RouterInstaller.cs').read_text(encoding='utf-8')
    statement = next(line for line in installer.splitlines() if 'set -e; test ! -L {Q(backup)}' in line)
    command = statement.split('ExecuteAsync($"', 1)[1].rsplit('", ct)', 1)[0]
    original_file, backup_file = directory / 'original', directory / 'backup'
    original_file.write_bytes(b'concurrent edit')
    backup_file.write_bytes(b'original content')
    expected_hash = hashlib.sha256(backup_file.read_bytes()).hexdigest()
    command = command.replace('{Q(backup)}', "'" + backup_file.as_posix() + "'")
    command = command.replace('{Q(before.Path)}', "'" + original_file.as_posix() + "'")
    command = command.replace('{Q(before.Hash)}', "'" + expected_hash + "'")
    command = command.replace('\\"', '"').replace('{{', '{').replace('}}', '}')
    # The bundled Windows shell omits sha256sum; compute real hashes with Python.
    hash_tool = "sha256sum() { '" + pathlib.Path(sys.executable).as_posix() + "' -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], chr(114)+chr(98)).read()).hexdigest())' \"$1\"; }\n"
    command = hash_tool + command
    run(command, 1)  # A valid old backup must not hide a changed source file.
    original_file.write_bytes(backup_file.read_bytes())
    run(command)
    locations = directory / "locations.tsv"
    locations.write_text("1\t1\t1\taaa\tGermany / Frankfurt\t11\n2\t1\t2\tbbb\tGermany / Berlin\t12\n3\t2\t1\tccc\tFrance / Paris\t13\n4\t3\t1\tddd\tJapan / Tokyo\t14\n", encoding="utf-8")
    definitions = '\n'.join(function(name) for name in ["peer_rank", "peer_tier", "rank_major_tier", "rank_label", "rank_order", "tier1_ranks", "recovery_ranks"])
    prefix = f"LOCATION_FILE='{locations.as_posix()}'\n" + definitions + '\nrank_has_peers() { return 0; }\n'
    assert run(prefix + 'peer_rank 12') == '2'
    assert run(prefix + 'peer_rank 999') == '0'
    assert run(prefix + 'peer_tier 12') == '1'
    assert run(prefix + 'rank_label 3') == 'France / Paris'
    assert run(prefix + 'tier1_ranks') == '1\n2'
    assert run(prefix + 'recovery_ranks 3') == ''  # sticky Tier 2
    assert run(prefix + 'recovery_ranks 4') == '1\n2\n3'  # Tier 3 recovers best-to-worst
    # The captured GL profile format is numeric group_peer, never peer_peerID.
    profile = directory / 'profile42'
    profile.write_text('7_11\n7_12\n8_99\nmalformed\n', encoding='utf-8')
    assert run("sed -n 's/^7_\\([0-9][0-9]*\\)$/peer_\\1/p' '" + profile.as_posix() + "'") == 'peer_11\npeer_12'
    membership = f"PROFILE_FILE='{profile.as_posix()}'\n" + definitions + '\n' + function('profile_peers_for_rank') + '\n'
    assert run(membership + f"LOCATION_FILE='{locations.as_posix()}'\nprofile_peers_for_rank 1", expected=1) == '11'
    target = directory / 'rtp2.sh'
    patcher = (ROOT / 'firmware/install-vpn-watch-gl-guard.sh').as_posix()
    target.write_text('#!/bin/sh\ncmd="$1";shift\n', encoding='utf-8')
    assert 'MATCH:' in run(f"VPN_WATCH_RTP2_TARGET='{target.as_posix()}' sh '{patcher}' --check")
    target.write_text('#!/bin/sh\n# unexpected firmware\n', encoding='utf-8')
    run(f"VPN_WATCH_RTP2_TARGET='{target.as_posix()}' sh '{patcher}' --check", 1)

    reboot = (ROOT / 'conditional-reboot.sh').read_text(encoding='utf-8')
    start = reboot.index('    # A missing, unreadable or malformed guard file')
    end = reboot.index('\nelse\n', start)
    guard_checks = reboot[start:end]  # only presence checks; no daily marker or reboot code
    guard_file = directory / 'guards.tsv'
    guard_prefix = f"GUARD_FILE='{guard_file.as_posix()}'\nMODE=--test\nTAG=test\nlogger() {{ :; }}\n"
    run(guard_prefix + guard_checks, 1)  # missing file fails closed
    guard_file.write_text('', encoding='utf-8')
    assert 'WOULD reboot' in run(guard_prefix + guard_checks)
    guard_file.write_text('malformed\n', encoding='utf-8')
    run(guard_prefix + guard_checks, 1)
    guard_file.write_text('02:00:00:00:00:20\t192.0.2.20\n02:00:00:00:00:21\t192.0.2.21\n', encoding='utf-8')
    ping_second = 'ping() { case "$*" in *192.0.2.21*) return 0;; *) return 1;; esac; }\nip() { return 0; }\n'
    assert 'WOULD postpone' in run(guard_prefix + ping_second + guard_checks)
    stale_neighbor = 'ping() { return 1; }\nip() { echo "192.0.2.20 lladdr 02:00:00:00:00:20 STALE"; }\n'
    assert 'WOULD postpone' in run(guard_prefix + stale_neighbor + guard_checks)
    run(guard_prefix + 'ping() { return 1; }\nip() { return 1; }\n' + guard_checks, 1)

# Hashes from the locally inspected historical v14.1 functions. No archive files needed.
# Promotion baseline normalizes only the two notification wording changes.
for name, expected in json.loads((ROOT / 'tooling/fastpath-baseline.json').read_text()).items():
    assert hashlib.sha256(function(name).encode()).hexdigest() == expected, name + ' changed unexpectedly'
print('PASS: shell syntax, exact peer mapping, Tier 2 stickiness, Tier 3 recovery order, guard fail-closed checks, zero/multiple/malformed reboot guards, historical fastpath hashes')
