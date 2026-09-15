# Final blocker resolution

This pass made local changes only. No router connection, preflight, installation or router mutation was performed. This document supersedes the unresolved conclusions in the earlier investigation reports.

## Guard: historical variant proved

The archive's known-stock file is 79,551 bytes, SHA-256 `749518706ad6af15104c90ddba5aa99142e1a9c678fec9074cd4222f8595f82c`. The archived/current patcher generates `c46469acec44023282fd1d6f729f34ab1b7fd5020ed0c83fc1852a091c2bf075` locally: 81,000 bytes with a 1,449-byte guard insertion.

The guard-owned printf format in that output contains a literal newline inside single quotes. Representing that newline as the two bytes backslash+n instead produces:

- exactly 81,001 bytes and a 1,450-byte insertion;
- full SHA-256 `5b1a898d8a4943d256f0674c0050519f1ec1353327f7de0778e1c760d3e57704`;
- the exact 100-byte guard line hash `7ec93c0e599a82a581aa3ab906eb221794bb14e4972488c1dfa193a7410e041a` supplied by the live run;
- unchanged stock bytes everywhere outside the same guard insertion.

Both printf formats emit the same newline. This explains the one-byte size increase, two missing expected lines versus one added live line, and why the difference was not whitespace-only. It establishes equivalent guard semantics, not unrelated firmware edits. The exact historical tool/interpreter that chose this representation is not recorded; claiming a particular patcher revision or BusyBox version would go beyond the evidence.

`tooling/verify_guard_archive.py` reproduces both complete hashes and checks printf behavior without writing firmware files. A scan of 2,169,546 archive lines found no literal complete matching line, which is consistent with generator escaping rather than a checked-in generated file. The proof is the exact complete-file reproduction using the archived stock and guard-owned format.

`HistoricalGuardKnownCompatible` preserves variant identity. Both patched forms use `CompatibilityCatalog.IsPatched`, so planning, firmware backup decisions, application and result reporting preserve an already verified guard. Reinstallation does not normalize or repatch the historical variant.

## Layer C: actual cause and correction

The former implementation already skipped the reported same-priority disjoint values under mask 0xf000. Equal priority alone was not the demonstrated bug. The earlier `iif lo lookup ...` and `lookup ... suppress_prefixlength 0` rules independently caused the boolean ambiguity check to reject the candidate without inspecting their tables. Thus the supplied diagnostics do not justify blaming the three disjoint mark rules.

Linux matches fwmarks with `((rule_mark ^ packet_mark) & mask) == 0`, and continues after failed/suppressed table lookups. See the primary [Linux policy-rule implementation](https://raw.githubusercontent.com/torvalds/linux/master/net/core/fib_rules.c). The correction reasons about the selected 0xf000 bits while treating all other mark bits as unknown. Disjoint rules are excluded; overlapping/equal-priority applicable rules remain blocked. Negated or unsupported selectors remain conservative.

Earlier supported conditional lookups are inspected read-only. Every potentially usable route must deliver locally, terminate, or use the selected active VPN interface. A suppressed default is ignored only for the exact suppress_prefixlength 0 shape; a specific WAN route still blocks. Unknown earlier selectors remain blocked. The selected table requires one normal default through the active VPN interface and a terminal unreachable/blackhole/prohibit default, with no non-VPN route. No mark, table, slot or priority from the live example is hardcoded.

The supplied report does not contain the earlier tables' contents or all additional source/interface rules. The final preflight must evaluate those. Tests use the live rule shape with explicitly synthetic earlier tables; they do not claim those synthetic contents were observed on the router. An actual earlier escape remains a genuine safety BLOCK.

## Metadata

The old helper prepended labels with printf and concatenated stat/hash output into one shell response, requiring each field to form exactly one line. The live report establishes failure of that collection/parsing contract, but retained no raw field values or stderr. It cannot establish the exact underlying BusyBox output/error. In particular, it does not prove that BusyBox lacks stat -c.

The replacement uses a separate command/response for each field. UID/GID/mode use the BusyBox-compatible stat -c '%u', '%g', '%a' formats; size uses wc -c with stdin redirection; SHA uses the already proven sha256sum/awk behavior. Boolean shell tests remain separate. Whitespace is trimmed, each scalar is bounded/validated, and a failed command marks only that field unavailable. The same reader now feeds production installation inspection and preflight, eliminating the previous two parser paths.

Root-owned regular readable 755 scripts versus desired 700, and 644 private files versus desired 600, are migration warnings. Symlinks, non-root ownership, group/other write, special bits, unreadability and malformed metadata block. Firmware rtp2 must remain root:root 755. Actual live numeric fields must still be established by the final run. Missing generated TSVs remain expected legacy warnings; post-install generated-file/hash validation is mandatory.

## Upload transport

`DeploymentUpload` uses an `IUploadChannel` backed by SSH.NET. It prefers a verified SSH stdin channel; SFTP remains an optional fallback. A read-only capability probe streams 65,536 synthetic bytes through sha256sum, checking the returned hash without creating a file. SFTP initialization failure does not block when streaming passes. If neither capability works, installation blocks before staging.

Actual installation uploads are limited to 2 MiB and strict flat installer staging paths; traversal, shell metacharacters and the transaction owner file are rejected. Payload bytes never appear in argv, command text, logs or reports. SSH.NET CreateInputStream sends raw chunks with cancellation and a 30-second deadline; EOF closes stdin.

Uploads require a protected root-owned 700 transaction directory and an owner token. A unique .upload temporary file is exclusively created with umask 077. SFTP fallback writes to the same precreated private temporary file. Remote file type, 600/root metadata, byte count and SHA are verified. Size/hash/owner checks are repeated before publishing to the staging filename. No upload streams over a final deployment target. A partial or mismatched transfer never publishes. Cleanup is limited to that unique temporary file, bounded to five seconds and conditional on the owner token; interrupted cleanup leaves evidence inside the existing transaction for recovery.

The read-only probe proves channel transport, not filesystem write permission. Actual staging writes and verification are deliberately confined to the separately authorized installation test.

## UX

Direct launch searches ancestors of the executable/current directory for the repository. It asks for the local historical archive folder, locates a local Git/bundled shell, and chooses a timestamped sanitized report under artifacts/preflight. Missing paths produce a visible error; --help displays usage. Explicit path arguments remain supported. No developer username or machine-specific absolute path is embedded.

The helper reuses bounded local gateway candidate discovery and SSH availability checks. One candidate fills the address field; zero/multiple candidates use manual IPv4 fallback. Authentication and GL-MT5000 verification remain interactive/session-only. Direct launch defaults to the focused follow-up. The helper was not launched in this pass, because its startup now performs gateway probes.

## Transaction audit

The production session verifies an upload capability before calling installation. RouterInstaller still checks pending transactions and repeats identity, firmware compatibility, ownership, configured data and kill-switch validation before creating staging. Unknown/incompatible firmware cannot bypass the gate through an acknowledgement. Safe metadata is validated by the shared reader before writes.

Staging remains private; payload SHA checks and shell syntax checks remain. Transport adds length verification rather than replacing transaction checks. Backups, compare-before-replace, guard preview/application for stock only, private DHCP UCI deltas, unrelated cron preservation, supervisor startup, journal writes, conservative runtime/DHCP recovery boundaries and post-install validation remain authoritative. Generated TSVs are required after installation. Fastpath/watchdog/promotion/tier behavior was not edited.

## Final preflight scope and readiness

The project is ready for one final READ-ONLY preflight. It has not yet passed that run and is not unconditionally cleared for installation.

Re-run only:

1. Session identity/version and selected policy/mark/interface consistency.
2. Firmware hash recognition, marker/anchor/syntax and exact host-memory comparison, accepting the reproduced historical variant.
3. Independent metadata fields for deployment targets; expected legacy TSV absences remain warnings.
4. File-free upload capability test; SFTP failure is informational when SSH streaming passes.
5. Kill-switch A/B/C and IPv6, including selected and earlier applicable tables and supported selectors; retain sanitized diagnostics if any safety invariant fails.
6. Absence of a pending transaction/lock.

Do not repeat full peer/location, DHCP/LAN, cron or daemon discovery in this focused run. The installation transaction will revalidate its own prerequisites immediately before writes. If the final sanitized report has no genuine safety BLOCK, the next step is the first separately authorized controlled installation test, not another broad development pass.

## Validation

- .NET Release suite: 128 tests passed, zero failed/skipped in the final run.
- Release installer and preflight helper builds: success, zero warnings/errors. Neither executable was launched; no router contact.
- Archive verification: both complete patched hashes, exact historical line hash, stock preservation and equivalent printf newline behavior passed.
- Router shell/Python regression suite: syntax, peer mapping, Tier 2 stickiness, Tier 3 recovery order, guard failure cases, reboot-guard cases and historical fastpath hashes passed.
- Focused tests cover historical idempotence, masked-rule overlap, earlier table escapes, WAN/wrong-slot/missing-terminal routes, independent metadata fields, binary/empty/1 MiB uploads, cancellation, truncation, size/hash mismatch, unsafe paths, oversized payloads, SFTP fallback and unavailable transports.

No automated test is presented as a live SSH upload or live filesystem test.
