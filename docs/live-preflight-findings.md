# Live preflight findings and focused follow-up

> Policy update: routing/kill-switch discussion below records earlier work. The current [selected GL policy preservation boundary](rpdb-lan-boundary.md) supersedes universal RPDB checks and supports both kill-switch settings.


## Evidence boundary

The completed read-only run is authoritative for the observations below. This local correction pass did not reconnect, install, run the guard patcher, or mutate the router. The original sanitized report omitted raw SFTP errors, routing rules/tables and individual metadata fields. Those missing facts cannot be reconstructed from a BLOCK label.

## Confirmed integration results

- PASS: session-only SSH.NET authentication and interactive host trust; GL-MT5000 and firmware version 4.9.0.
- PASS: production VPN discovery, selected anonymous policy, group_peer membership, 160 peers in nine exact location pools, multiple peers in every pool. Counts are observations, not constants. Pool generation retains all matching peers; regression cases cover 9, 160 and 600 peers.
- PASS: all three reserved slot ownership checks, active policy agreement and one verified firmware process reference.
- PASS: configured kill-switch intent and explicitly disabled IPv6. The verifier reached its routing failure after the paired MARK/DROP and attachment checks succeeded.
- PASS: ACTIVE/PRECOOKED/RECOVERY structure, selected policy agreement and fresh active/standby handshakes.
- PASS: one exact daemon, one owned supervisor job and one maintenance job, no pending installer transaction/lock.
- PASS: DHCP/LAN inspection (one client, one reservation, no address conflicts or duplicate reservation MACs); pending DHCP changes false.

## Firmware retrieval: fixed path, unresolved original cause

The previous SFTP attempt raised SshException. The original report retained neither failure stage nor server reason. It does not prove that the router lacks an SFTP subsystem, that access was denied, or that file bytes were invalid.

ReadFirmwareBytesAsync now reads the fixed /usr/bin/rtp2.sh path through raw SSH command stdout into host memory, without decoding/re-encoding. A bounded stream reader preserves arbitrary bytes. The preflight compares their SHA with the independently inspected SHA, then compares stock/guarded bytes locally. No proprietary contents are written to a file or report. Marker, anchor and syntax checks now run independently of byte retrieval.

The next helper also probes SFTP separately and reports a sanitized failure stage (connection/subsystem initialization, attributes or read) and error category. This matters because installation uploads still use SFTP. Successful raw SSH reading alone does not establish upload readiness. The new transport path has automated byte-preservation coverage but has not yet been exercised against the router.

The previously observed 5b1a898d8a4943d256f0674c0050519f1ec1353327f7de0778e1c760d3e57704 remains unclassified. The archive establishes stock 749518706ad6af15104c90ddba5aa99142e1a9c678fec9074cd4222f8595f82c and reproducible guarded stock c46469acec44023282fd1d6f729f34ab1b7fd5020ed0c83fc1852a091c2bf075 only. No compatibility whitelist change is justified yet.

## Kill switch: retain all three layers

Layer A (configured intent) and layer B (paired firewall MARK/DROP plus attachment) passed. Layer C found no rule/table combination accepted by the existing terminal-route algorithm. The old report cannot distinguish an unsupported rule representation, ambiguous precedence, unsupported/non-VPN table routes, or missing terminal default. It therefore cannot establish either a faulty invariant or missing protection on the router.

The production verifier retains exactly the same acceptance conditions. Added counters identify those rejection branches without exposing identifiers. The follow-up collects sanitized selected-mark rules, attachment, matching tables and active-slot routes. Its broader diagnostic table parser grants no compatibility. An evidence-backed replacement invariant and a regression fixture for the real layout must wait for that evidence; no synthetic fixture is claimed to represent the unseen live layout.

## File metadata and legacy migration

The old generic parser did not retain which field failed. Actual UID/GID/modes for every blocked live file remain unknown. The replacement probe emits separate existence, regular-file, symlink, readability, UID, GID, mode, size and hash-format checks using labeled fields.

| Target | Expected | Migration assessment |
| --- | --- | --- |
| Hotswapper scripts and guard patcher | root:root, 700 | A regular readable root-owned 755 script is a safe legacy permission difference to normalize during authorized installation. |
| Private generated config and TSV files | root:root, 600 | A root-owned 644 file is a normalization case; report no contents. |
| /usr/bin/rtp2.sh | root:root, 755 | Firmware policy, supported by archived file metadata; a different mode blocks pending review. Never apply private-file 600/700 policy to firmware. |
| Any existing target | regular, readable, no symlink, valid metadata/hash | Symlinks, non-root ownership, group/other write, special permission bits, malformed/unreadable metadata block. |

These are classification rules, not claims that the live files have those example modes. No chmod/chown is performed by the helper.

Missing vpn-watch-locations.tsv and reboot-guards.tsv are expected legacy absences, not evidence of corruption. The installation transaction generates both from reviewed configuration, stages private modes, verifies content hashes, and backs up existing targets. Post-install validation requires generated files and matching hashes before validating runtime roles against the reviewed configuration. Legacy inspection correctly withholds generalized RuntimeValidation acceptance when the authoritative rank mapping is absent; it never fabricates ranks.

This migration design is supported by local review/tests, but live migration readiness is not established until firmware compatibility, routing protection, metadata and transport blockers are resolved.

## Additional-only read-only preflight

Use the dedicated helper with --follow-up, existing interactive authentication and host trust. Do not launch the installer transaction. The helper is built locally but was not launched in this correction pass.

1. Recheck session identity/version and the uniquely selected policy/mark/interface for consistency; do not repeat full peer, LAN, daemon or cron discovery.
2. Collect live firmware SHA/size, separate marker/anchor/syntax results, and exact bytes into host memory. Compare with known stock and reproduced guarded stock; report whether removing the identifiable insertion restores every stock byte, insertion/difference sizes and sanitized structural results. Do not save firmware or execute the guard patcher.
3. Run the read-only SFTP stage probe; report only the stage/category on failure.
4. Collect labeled metadata for the eight deployment paths and classify each field separately.
5. Collect selected policy mark, ROUTE_POLICY and selected tunnel-chain shapes, ip -4 rule show, selected fwmark tables and active-slot routes. Redact addresses, provider identifiers, custom names and comments. Re-run the unchanged production verifier and retain branch counters. Recheck selected mark/interface after collection.

No successful result authorizes installation automatically. The current build is ready for this focused read-only evidence collection, **not yet for the first controlled installation test**.

## Local validation

- dotnet test BrumeHotswapper.slnx -c Release --verbosity minimal: 99 passed, zero failed/skipped.
- tooling/test_router_scripts.py with bundled sh: PASS shell syntax, exact peer mapping, Tier 2 stickiness, Tier 3 recovery order, guard fail-closed cases, zero/multiple/malformed reboot guards, historical fastpath hashes.
- Release build of BrumeHotswapper.Preflight into artifacts/preflight-followup: success, zero warnings/errors; not launched.

Tests cover read-only command rejection (including guard --check and uploads), real discovery/inspection/verifier calls through the allowlist, binary reads/limits/cancellation, sanitized diagnostics, metadata classification, diagnostic rule parsing/redaction and larger generated pools. They do not substitute for missing live evidence.

## Superseding final correction

See [final blocker resolution](final-blocker-resolution.md) for the second live run, exact historical guard proof, corrected metadata/routing inspection and verified SSH upload transport. Earlier unresolved conclusions above are retained as history.
