"""Reproduce current guard in memory. Never store or execute proprietary firmware."""
import argparse
import difflib
import hashlib
import os
import pathlib
import re
import subprocess
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
STOCK = "749518706ad6af15104c90ddba5aa99142e1a9c678fec9074cd4222f8595f82c"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=pathlib.Path)
    parser.add_argument("shell", type=pathlib.Path)
    parser.add_argument("--print-hash", action="store_true")
    args = parser.parse_args()
    env = dict(os.environ)
    env["PATH"] = str(args.shell.parent) + os.pathsep + env.get("PATH", "")
    with zipfile.ZipFile(args.archive / "brume_dump.zip") as archive:
        stock = archive.read("brume_dump/bin/rtp2.sh")
    assert hashlib.sha256(stock).hexdigest() == STOCK
    def generate(patcher):
        text = patcher.read_text(encoding="utf-8")
        start = text.index("    awk -v anchor=")
        end = text.index(' > "$tmp" || {', start)
        generator = text[start:end].removesuffix(' "$TARGET"')
        result = subprocess.run([str(args.shell), "-c", "ANCHOR='cmd=\"$1\";shift'\n" + generator], input=stock, capture_output=True, env=env)
        assert result.returncode == 0, "Generator failed; output withheld"
        return result.stdout
    patched = generate(ROOT / "firmware/install-gl-guard.sh")
    # This is an immutable historical archive filename, not a deployment path.
    historical = generate(args.archive / "install-vpn-watch-gl-guard-v1.sh")
    renamed = historical.replace(b"vpn-watch", b"hotswapper").replace(b"VPN_WATCH", b"HOTSWAPPER").replace(b"vpn_watch", b"hotswapper")
    assert patched == renamed, "Guard behavior changed beyond names/runtime directory"
    before, after = stock.splitlines(keepends=True), patched.splitlines(keepends=True)
    changes = [x for x in difflib.SequenceMatcher(None, before, after, autojunk=False).get_opcodes() if x[0] != "equal"]
    assert len(changes) == 1 and changes[0][0] == "insert"
    _, i, j, a, b = changes[0]
    assert before[i-1] == b'cmd="$1";shift\n'
    assert b"".join(after[:a] + after[b:]) == stock
    assert patched.count(b"# hotswapper GL reconciliation guard v1") == 1
    assert b'HOTSWAPPER_GUARD_DIR="/tmp/hotswapper"' in patched
    assert subprocess.run([str(args.shell), "-n"], input=patched, capture_output=True, env=env).returncode == 0
    digest = hashlib.sha256(patched).hexdigest()
    if not args.print_hash:
        catalog = (ROOT / "BrumeHotswapper.Installer/Core/Planning.cs").read_text(encoding="utf-8")
        assert re.search(r'const string PatchedHash = "([a-f0-9]{64})"', catalog)[1] == digest
    print("PASS: original firmware preserved byte-for-byte; guard changes only names/directory; shell syntax valid")
    print("Current guarded SHA256: " + digest)

if __name__ == "__main__":
    main()
