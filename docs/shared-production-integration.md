> Historical record from before the directional-role/layout refactor. For the current implementation, paths, guard hash and validation results, see [Hotswapper runtime](hotswapper-runtime.md).

# Shared production integration correction

> Policy update: routing/kill-switch discussion below records earlier work. The current [selected GL policy preservation boundary](rpdb-lan-boundary.md) supersedes universal RPDB checks and supports both kill-switch settings.


This pass used the supplied live evidence and local source/tests only. No router connection or modification occurred. This supersedes earlier assumptions that the target provides a stat command or applet. The historical guard and SSH streaming determinations remain closed and unchanged.

## Metadata: cause and complete fix

The GL-MT5000 firmware has neither stat nor the BusyBox stat applet. The previous metadata reader invoked a nonexistent command. Production also depended on it in capability checks, staging permission checks, compare-before-replace, rollback and post-install validation. All those runtime dependencies have been removed; find -printf is not used.

FileMetadata now parses the stable leading fields of LC_ALL=C ls -ldn with a safely quoted absolute path: symbolic type/mode, numeric UID and numeric GID. It ignores dates and filenames, including spaces. The parser converts all permission triplets and s/S/t/T special bits to octal. Independent existence/link/type/access tests remain authoritative and must agree with the listing. Size still comes from wc -c and the hash from sha256sum.

The manually verified watchdog metadata, root:root 0755 and 55,880 bytes, is a safe normalization case to installer mode 0700. Root-owned private 0644 files may normalize to 0600. Group/world write, special permission bits, non-root ownership, symlinks, malformed/unreadable metadata and unexpected firmware permissions remain BLOCKs. The firmware expectation remains root:root 0755.

FileMetadata.Assess owns these decisions for both consumers. MetadataReview only formats the findings. FileMetadata.MatchesCommand applies the same expected symbolic permissions/root ownership inside upload, replacement and post-install shell checks; rollback uses the shared listing parser. No substitute command or weaker policy is used by installation.

## Routing: optional diagnostics cannot prevent verification

Previously, the helper dumped each selected/earlier table before invoking KillSwitchVerifier. One nonzero command escaped the whole Routing follow-up block, so the verifier never ran. After the selected table dump, the remaining table commands for the supplied rules were ip -4 route show table 16800 and ip -4 route show table 9910, followed by the active-interface route dump. The sanitized failure did not retain which earlier table returned nonzero; claiming one exact table would be speculation.

The helper now runs the production verifier first. Only if it fails does it render optional routing diagnostics. Every table dump has its own failure boundary, reports WARN if unavailable and continues. Diagnostic output cannot produce a safety PASS. If the production verifier needs an earlier table and cannot read it, it emits an explicit BLOCK that routing safety cannot be established. No missing table is silently treated as empty.

Regression tests cover a successful selected dump, a failing earlier diagnostic, continued collection, then an independent successful production read/PASS; persistent unavailability remains BLOCK. The routing acceptance invariant itself was not weakened.

## Product and shared services

Both paths use:

- SshRouterSession authentication and RouterIdentity validation;
- RouterPrerequisites firmware/catalog/marker/anchor/syntax, required utilities and pending-transaction checks;
- VpnDiscovery policy discovery and RouterInspection.VerifyPolicySlotsAsync;
- FileMetadata parsing and safety assessment;
- KillSwitchVerifier, including IPv6 and routing protection;
- DeploymentUpload through SshRouterSession.ProbeUploadAsync.

The real session now verifies upload capability before producing a plan. RouterInstaller.PlanAsync runs the same mandatory kill-switch inspection as installation; the former planning bypass was removed. If checks fail, the wizard stays before Review. The transaction repeats its checks before writing.

Normal workflow is the WPF installer: connect, configure, shared pre-install checks, Review, Install, post-install validation. The standalone helper is optional developer tooling, not a required second application. It defaults to compact shared checks and needs no historical archive, firmware export, local shell or machine-specific evidence path. Successful SSH streaming ends transport selection without another SFTP probe.

## Transaction review

The actual transaction retains private staging, remote byte-size/SHA checks, backups, comparison before replacement, catalog-based guard preservation/application, generated location and reboot-guard files, private DHCP UCI deltas, unrelated cron preservation, supervisor startup, journals, conservative recovery boundaries and post-install validation. Only metadata primitives and prerequisite reuse changed. Watchdog/fastpath/promotion/tier logic was not edited.

## Validation and remaining boundary

- dotnet test BrumeHotswapper.slnx -c Release --verbosity minimal: 155 passed, zero failed/skipped.
- Router shell/Python suite: PASS syntax, peer mapping, Tier 2 stickiness, Tier 3 recovery order, guard failure cases, reboot-guard cases and historical fastpath hashes.
- Production source/firmware search and automated regression: no unavailable metadata command dependencies.
- The transaction completion test runs the real RouterInstaller with the production KillSwitchVerifier and shared metadata inspection against its offline command fixture. Upload integrity/failure tests also remain green.
- Release installer and preflight builds: both succeeded with zero warnings/errors. Neither executable was launched during this no-contact pass.

No additional standalone preflight development cycle is required. The normal installer can perform its required checks itself. Live routing safety is not newly certified by this local pass: an unreadable required earlier table or any other genuine failed prerequisite must still block installation in the normal workflow. No missing evidence is converted to PASS.
