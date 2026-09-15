# Repair-capable installation

The actual router state is authoritative. No journal, owner file, completion marker, persistent installer lock or transaction recovery gate is created or required.

## Sequence

1. Revalidate GL-MT5000, the actual firmware hash/catalog, selected policy/profile/peers, slot ownership, configured kill-switch integration and IPv6 prerequisite.
2. Recompute the deployment from current files and requested configuration. A recognized guard applied by a previous attempt is accepted even if the wizard originally saw stock firmware.
3. Create a private, random `run-<id>` directory. Move old `/root/.hotswap-installer/transaction` and `/tmp/vpn-watch-installer-lock` entries to unique `legacy-<id>-…` archive names under `/root/.hotswap-installer`. Their contents are never interpreted. Archives are not gates.
4. Stage payloads using verified SSH stdin (SFTP fallback retained), check hashes and syntax, and preview the authoritative guard when required.
5. Preserve affected existing files in private content-addressed backups, then pause owned cron and reconcile exact-argv watchdog/supervisor processes.
6. Replace owned files through run-specific sibling temporary files, generate configuration/TSVs, reuse or add requested DHCP reservations, and preserve/apply the compatible guard.
7. Merge canonical schedules with unrelated current cron, start the supervisor, and perform the existing concise runtime/integrity checks.
8. Always attempt cleanup of this run's staging and sibling temporary files. A cleanup warning does not undo success or gate any subsequent installation.

## Backups and failure

Backups remain under `/root/.hotswap-installer/backups/<sha256>`, mode 600 in a private directory. Original paths, hashes, modes, cron and changed-file lists are held in host memory only for this execution. No later run is asked to reconstruct these records.

On failure, the installer reports the logical operation and sanitized reason. It stops its new runtime where possible, restores only files still matching this run's known writes, restores owned schedules, and restarts/verifies the prior runtime when selected policy state is unchanged. A failed restoration does not prevent attempting the remaining files. Unrelated modifications are not overwritten. Matching committed DHCP additions are retained and rediscovered/reused on retry rather than removing a reservation that a client may already use.

If SSH is lost or recovery cannot be verified, report that fact and retain ordinary backups. Run-specific temporary paths cannot block a later run. The next installation observes current state and converges again; it does not require forensic recovery, a completion marker, a router dump or manual deletion of bookkeeping.

## Preserved behavior

Firmware safety, historical guard variants, VPN discovery/pools, slot checks, kill-switch ON/OFF preservation, independent IPv6 requirements, host-key trust, session-only credentials, private reporting, ntfy normalization, generic reboot guards and DHCP/cron behavior are retained. No router-side engine files or fastpath semantics changed. Existing process reconciliation handles duplicates and waits for stable PID ownership. The visible ntfy field and bounded subnet-aware discovery remain unchanged.

Only genuine operation/compatibility failures can stop an install: for example unavailable SSH, unknown firmware, conflicting VPN ownership, inability to back up/write files, incompatible IPv6 configuration, or failure to establish the intended runtime. Stale installer bookkeeping alone is not a blocker. Use one installer at a time; this is a deployment sequence, not a concurrent multi-controller service.

## Local validation

Regression coverage includes fresh/legacy/current installs, stale legacy bookkeeping, retry after partial replacement and failed cleanup, unique staging paths, missing TSVs, old permissions, duplicate daemons/supervisors, cron preservation, known guard variants, both kill-switch choices, backup rollback, notification normalization and discovery. Shell tests retain the historical fastpath hashes and exercise exact argv matching. No live router was accessed during this change.
