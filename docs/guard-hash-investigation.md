# Guard hash investigation and review of 1916787

## Result

The origin of the reported `5b1a898d8a4943d256f0674c0050519f1ec1353327f7de0778e1c760d3e57704` **cannot be established from the supplied archive**. A hash and guard marker cannot establish that the rest of a file is stock, nor reveal its differences. No second patched variant is whitelisted.

The reproducible transformation is:

| Item | SHA-256 / result |
| --- | --- |
| Archived stock, 79,551 bytes | `749518706ad6af15104c90ddba5aa99142e1a9c678fec9074cd4222f8595f82c` |
| Archived/current patcher, LF-normalized, 5,053 bytes | `825b94dd28154ea5d673406dfd43a817641fa5fb77bb60b67edb5cd3ba6bada0` |
| Generated guarded stock, 81,000 bytes | `c46469acec44023282fd1d6f729f34ab1b7fd5020ed0c83fc1852a091c2bf075` |
| Structural diff | One insertion: 29 lines / 1,449 bytes immediately after the unique command-dispatch anchor. Removing it restores every stock byte. |

The insertion is the patcher's guard code, including its preceding blank line. The generated file has one guard marker and passes shell syntax checking.

### Evidence and ruled-out explanations

- Hashed all 544 regular members of the supplied ZIP/TAR archives. Neither patched hash occurs as a complete archived file. Loose historical script/text candidates were also inspected.
- Stock copies in multiple firmware exports match exactly.
- The apparent alternate unpatched firmware in the fastpath capture has a 13-byte `=== RTP2 ===\n` heading prepended to otherwise identical stock. Applying the generator to that capture produces `f95819a54408ca2491474cc96d06a903a156c9b81bbe36e3c9629d1316c6146e`, not either disputed variant. The heading is a capture artifact, not a compatible firmware modification.
- The archived patcher and Git blobs at 679bc4d, 3a4be60 and 1916787 are byte-identical. The current Windows working copy differs only by CRLF checkout conversion; LF-normalized contents are identical. No different patcher revision was found.
- A bounded check of 180 newline/BOM/near-anchor placement combinations did not reproduce the reported hash. This does not prove that all possible historical formatting changes have been excluded.
- Generation and syntax checks used the bundled Git shell/awk locally. WSL/BusyBox was unavailable; no claim is made that a second AWK implementation was tested.

There is therefore no evidence supporting either a second legitimate guard variant, a different patcher revision, or a particular unrelated modification as the explanation for 5b1a. The precise missing evidence is **the exact bytes of the file with that SHA**, preferably accompanied by the patcher/input backup that produced it. An in-memory structural comparison could then distinguish guard differences from changes elsewhere in firmware.

## Compatibility decision

No classification change in this follow-up. Stock stays known stock; c464 stays the single reproducible known guarded output; 5b1a stays Unknown. The catalog now points to this evidence explicitly. Known guarded output remains an idempotent no-op. A marker-bearing unknown file remains blocked from installation, even if the user acknowledges unknown firmware. A multi-variant catalog would be justified only after validating another exact byte form.

## Static review

Reviewed the production changes in 1916787: anonymous policy quoting, profile parsing, slot references, IPv4/firewall checks, LAN observations, optional standby validation, compatibility, cron changes and rollback boundaries. No fastpath or patcher logic changed in this follow-up.

Two narrow issues were corrected:

1. **Discovery blocker exposed by the real archive layout:** firmware process policies have numeric tunnel IDs but no group_id. Discovery previously treated their missing group lookup as fatal before reaching the selected anonymous VPN rule. Missing group now yields an ineligible candidate and is skipped. Named/anonymous discovery tests now include these process policies. The underlying assumption predated 1916787; its expanded tests had missed this real layout.
2. **Ineffective backup check in the reconciliation change:** adding set -e did not make failed non-final commands in an && list fatal. A valid previous backup could mask a changed source file. Checks now execute as separate commands under set -e. The shell suite exercises the actual generated command against synthetic matching and changed source files.

No further regression was identified by this static pass. This is not proof of live installation safety: documented SSH/UCI/concurrent-writer limitations and conservative manual-recovery boundaries still apply.

## Offline verification

- `tooling/verify_guard_archive.py <archive-directory> <shell>`: reproduces the hash, checks the single insertion and byte preservation, checks syntax, compares patchers, identifies the capture heading and scans archived member hashes. All firmware bytes stay in memory.
- .NET suite: 70 passed, including process-policy discovery, unknown reported hash and patched idempotence.
- Shell/Python suite: passed, including actual backup-command failure behavior and historical fastpath hashes.
- No router was contacted, no archive file changed, and no firmware/configuration copy was added to the repository.

## Read-only preflight: ready, with an installation gate

Ready for a **separate read-only inspection**. This does not authorize Install, patching, UCI commits, reloads, daemon startup or notification tests. The wizard's installation planning may intentionally stop on a marker-bearing unknown hash; collect evidence separately instead of bypassing that gate.

The following is a proposed command/read list, **not executed**. Keep raw configuration, identifiers and firmware bytes private. Shell variables below are populated from validated discovery, never copied from the development router as constants.

### 1. Identity and firmware evidence

Read:
```sh
ubus call system board
head -n 1 /etc/glversion
sha256sum /usr/bin/rtp2.sh
wc -c /usr/bin/rtp2.sh
stat -c '%u:%g %a' /usr/bin/rtp2.sh
grep -Fc '# vpn-watch GL reconciliation guard v1' /usr/bin/rtp2.sh
grep -Fxc 'cmd="$1";shift' /usr/bin/rtp2.sh
sh -n /usr/bin/rtp2.sh
```

If an installed guard patcher or original firmware backup exists, read its SHA/size too. Do not execute it, even with --check. If rtp2 is 5b1a or any other unknown hash, read the file through SFTP **into host memory only**, verify the SHA again, and compare against the locally generated guarded stock. Check all diff regions; removing the exact guard must restore known stock before calling it a stock-plus-guard variant. Report sanitized structure/hashes, not proprietary contents. A hash-only read cannot resolve provenance.

### 2. Selected policy and profile membership

Use the installer's allowlisted discovery query to enumerate policy section/tunnel pairs, preserving anonymous sections. For the selected validated policy, read each option:
```sh
for option in enabled killswitch tunnel_id group_id via peer_id mark; do
    uci -q get "route_policy.${policy}.${option}"
done
uci -q get glipv6.globals.enabled
```

Read numeric group_peer lines from /etc/vpn_profiles.d/profile<tunnel>. For every selected peer read only wireguard.peer_<peer>.group_id and .location; verify membership and complete location pools. For wgclient1–3, read network.<slot>.config and the assigned peer's group. Enumerate route-policy .via references using the installer's allowlisted query; verify any gl_process_vpn exception has the expected type and no group. Do not export WireGuard configuration, keys or provider credentials.

### 3. Runtime dataplane and roles

After validating numeric tunnel, supported active interface and numeric lookup table:
```sh
iptables -w -t mangle -S "TUNNEL${tunnel}_ROUTE_POLICY"
iptables -w -t mangle -S ROUTE_POLICY
iptables -w -t mangle -C ROUTE_POLICY -m addrtype ! --dst-type LOCAL -j "TUNNEL${tunnel}_ROUTE_POLICY"
ip -4 rule show
ip -4 route show table "${table}"
cat /tmp/vpn-watch/state
date +%s
wg show "${active}" latest-handshakes | awk '{print $2}'
```

Check paired marking/DROP scope, chain attachment, lookup precedence, active-interface routes and terminal default; explicitly establish IPv6 state. Compare policy peer/interface against ACTIVE and verify role uniqueness. Repeat timestamp-only handshake reads for a present standby. Count watchdog processes via the installer's exact /proc argv checks. Do not launch status/helper scripts or trigger failover.

### 4. Installation readiness metadata

Read crontab with crontab -l; pending installer transaction/lock existence; installed target hashes/owner/modes; LAN address/netmask and DHCP start/limit; host-section MAC/IP values; leases, neighbours and router-owned IPv4 addresses. Use ip -4 neigh show and ip -o -4 addr show. Check whether uci changes dhcp is empty, reporting only the boolean. Do not read private generated config contents or modify reservations/schedules.

Finish with findings and blockers. No mutation follows automatically from a successful read-only preflight.

