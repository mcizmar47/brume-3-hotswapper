# Deterministic installer and legacy migration

## Evidence and scope

Reviewed current Git history through cd985e1 and the historical Brume directory, including v14.1, supervisor v3, reboot v5 and guard v1. The guard patcher is identical. The current generalized location/reboot data and supervisor serialization are retained. No router-side engine file was changed.

The actual runtime uses GL connected state and periodic path probes for established interfaces. A 75-second handshake threshold belongs to candidate establishment, not continual installation acceptance. Post-install handshake observations are now warnings. This is a concrete mismatch found in source; the old generic real-router failure does not establish which command failed.

## Remaining blocking checks

- Supported identity, firmware hash/marker/anchor/syntax: required for a safe guard patch.
- Valid configuration, unambiguous selected VPN/profile/pools, slot ownership and ACTIVE mapping: avoid changing an unrelated VPN.
- IPv6 disabled: the proven promotion implementation updates IPv4 only.
- Kill-switch choice readable; ON requires selected GL enforcement integration, OFF does not. Neither is changed.
- Commands, upload integrity, readable regular root-owned targets, verified backups and compare-before-replace: avoid corrupting existing files or overwriting concurrent changes.
- Conflicting DHCP choices or ambiguous compound cron commands: those may belong to other software.
- Active/unverified prior transaction: preserve its recovery evidence.

No universal routing audit and no prerequisite to run standalone preflight tooling.

## Installation sequence

1. Revalidate identity, configuration and reviewed choices; archive only explicitly completed leftover attempts.
2. Establish private staging and a journal of original files/cron and intended hashes.
3. Upload and verify payload hashes/syntax; preview the authoritative guard against a private copy when stock.
4. Back up affected files, then pause owned cron entries.
5. Reconcile watchdog and supervisor processes, waiting up to ten seconds for exit.
6. Replace scripts/configuration/TSVs and normalize permissions.
7. Create/reuse selected DHCP reservations and apply or recognize the guard.
8. Install canonical schedules while retaining unrelated cron; start the supervisor.
9. Validate deployed files, guard, schedules, reservations, runtime state, lock owner, status, selected policy/routing and independent IPv6 prerequisite.
10. Report optional handshake/notification warnings, record completion, and clean staging.

Legacy scripts, safe legacy permissions, absent generated TSVs and duplicate canonical schedules are ordinary migration inputs. The same path handles repeat installation and leaves an already compatible guard unchanged. Payloads are staged before backups, but neither step changes installed targets; all backups precede replacement.

## Runtime reconciliation

Process matching uses complete NUL-delimited argv shapes, never substring grep. It recognizes the exact watchdog daemon/run and supervisor commands, including sh/ash invocation. Same-kind fork children are not counted as independent daemons. The installer stops owned supervisor/daemon roots, rechecks argv before TERM, and retries for ten seconds. It never force-kills or targets unrelated commands. Once no owned processes remain, only an empty supervisor startup mutex may be removed. The engine retains ownership of its daemon lock recovery.

After startup, the lock PID must match the sole daemon root on two consecutive observations. PRECOOKED may be absent during backoff; RECOVERY denotes a slot, not a required live tunnel.

## Pragmatic rollback and prior attempts

Existing backups and hash/ownership checks remain. Startup itself no longer prohibits rollback. The installer stops its runtime, restores only files still matching this attempt, and restarts the previous runtime only when selected policy state is unchanged. It verifies a stable PID owner and structurally valid status before claiming recovery. Concurrent file edits, changed policy state or committed DHCP keep the journal for explicit recovery. The redundant files-intent document was removed; the initial journal already records original files and payload hashes.

- Active transaction: block a second installation; never remove its lock.
- Verified rollback: clean normally; a completion marker allows non-destructive archival if cleanup was interrupted.
- Verified successful install: the same completion/archive path applies.
- Incomplete rollback or crash without verified completion: block with the exact retained path. Preserve journal, backups and runtime/firmware intent evidence. Do not infer safety from age or invent a completion marker.

The reported real-router transaction was made by the previous installer and has no new completion marker. It therefore still needs explicit recovery using its journal and actual file/policy state before another installation. This pass did not access the router and cannot certify or erase that evidence.

## UX and diagnostics

Discovery considers active local IPv4 gateways, then the first/last usable host on each attached subnet, deduplicated and capped at 16 targets. TCP probes have a two-second bound; at most four authentication attempts occur, once per candidate. No fixed router IP, subnet sweep or repeated password attempts. Manual IPv4 remains available. Local tests establish candidate selection, not live discovery success.

The visible ntfy topic-or-URL field uses one normalizer for PC testing and router configuration: trim, accept an ntfy.sh HTTPS topic URL or prepend that prefix to a bare topic; reject invalid topic characters, other URLs, query strings and empty input. Private URLs remain excluded from reports.

Fatal post-install errors identify their logical operation and sanitized exit status/category. Optional notification/handshake diagnostics produce warnings. No private status contents, keys or provider identifiers are reported.
