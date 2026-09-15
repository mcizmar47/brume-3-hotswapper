"""Read-only archive reconciliation. Firmware bytes stay in memory; never runs a router script."""
import argparse
import difflib
import hashlib
import json
import os
import pathlib
import re
import subprocess
import tarfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
STOCK = '749518706ad6af15104c90ddba5aa99142e1a9c678fec9074cd4222f8595f82c'
REPORTED = '5b1a898d8a4943d256f0674c0050519f1ec1353327f7de0778e1c760d3e57704'
PATCHER = '825b94dd28154ea5d673406dfd43a817641fa5fb77bb60b67edb5cd3ba6bada0'
MARKER = b'# vpn-watch GL reconciliation guard v1'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def members(path):
    if path.suffix == '.zip':
        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                if not entry.is_dir():
                    yield archive.read(entry)
    elif path.name.endswith(('.tar', '.tar.gz')):
        with tarfile.open(path) as archive:
            for entry in archive:
                if entry.isfile():
                    yield archive.extractfile(entry).read()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=pathlib.Path)
    parser.add_argument('shell', type=pathlib.Path)
    args = parser.parse_args()
    patcher = (ROOT / 'firmware/install-vpn-watch-gl-guard.sh').read_bytes().replace(b'\r\n', b'\n')
    historical = (args.archive / 'install-vpn-watch-gl-guard-v1.sh').read_bytes().replace(b'\r\n', b'\n')
    assert sha(patcher) == PATCHER and patcher == historical, 'Patcher changed: inspect before reproducing'
    with zipfile.ZipFile(args.archive / 'brume_dump.zip') as archive:
        stock = archive.read('brume_dump/bin/rtp2.sh')
    assert sha(stock) == STOCK
    text = patcher.decode('utf-8')
    start = text.index('    awk -v anchor=')
    end = text.index(' > "$tmp" || {', start)
    generation = text[start:end]
    assert generation.endswith(' "$TARGET"')
    # Execute only the repository-owned awk generator, feeding firmware via stdin.
    generation = generation.removesuffix(' "$TARGET"')
    env = dict(os.environ)
    env['PATH'] = str(args.shell.parent) + os.pathsep + env.get('PATH', '')
    def generate(data):
        result = subprocess.run([str(args.shell), '-c', "ANCHOR='cmd=\"$1\";shift'\n" + generation], input=data, capture_output=True, env=env)
        assert result.returncode == 0, 'Guard generation failed (output withheld)'
        return result.stdout
    patched = generate(stock)
    catalog = (ROOT / 'BrumeHotswapper.Installer/Core/Planning.cs').read_text(encoding='utf-8')
    expected = re.search(r'const string PatchedHash = "([a-f0-9]{64})"', catalog)[1]
    assert sha(patched) == expected
    before, after = stock.splitlines(keepends=True), patched.splitlines(keepends=True)
    changes = [op for op in difflib.SequenceMatcher(None, before, after, autojunk=False).get_opcodes() if op[0] != 'equal']
    assert len(changes) == 1 and changes[0][0] == 'insert'
    _, i, j, a, b = changes[0]
    assert before[i - 1] == b'cmd="$1";shift\n'
    assert b''.join(after[:a] + after[b:]) == stock
    assert patched.count(MARKER) == 1
    syntax = subprocess.run([str(args.shell), '-n'], input=patched, capture_output=True, env=env)
    assert syntax.returncode == 0, 'Generated syntax failed (output withheld)'
    with tarfile.open(args.archive / 'vpn-fastpath-dump.tar.gz') as archive:
        capture = archive.extractfile('vpn-fastpath-dump/rtp2.sh').read()
    assert capture == b'=== RTP2 ===\n' + stock
    counts = {'archive_members': 0, 'reported_hash_matches': 0, 'generated_hash_matches': 0}
    for path in args.archive.iterdir():
        for data in members(path):
            counts['archive_members'] += 1
            counts['reported_hash_matches'] += sha(data) == REPORTED
            counts['generated_hash_matches'] += sha(data) == expected
    # Output metadata only, never archived content or private identifiers.
    print(json.dumps(dict(stock_sha=sha(stock), patched_sha=sha(patched), patcher_lf_sha=sha(patcher),
        stock_bytes=len(stock), patched_bytes=len(patched), inserted_lines=b-a,
        inserted_bytes=len(patched)-len(stock), stock_preserved=True,
        capture_difference='13-byte capture heading only', patched_capture_sha=sha(generate(capture)), **counts), indent=2))

if __name__ == '__main__':
    main()
