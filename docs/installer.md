# Windows installer: reconciliation pass

> Current behavior: [repair-capable installation](repair-installer.md). This supersedes the persistent transaction/recovery descriptions below. Old bookkeeping is archived and never gates installation.


Current deployment and recovery behavior: [installer simplification](installer-simplification.md). This supersedes older descriptions below that prohibit all recovery after startup.


The existing GL.iNet kill-switch setting (Enabled or Disabled) is displayed and preserved. Both are supported. IPv6 compatibility is checked independently. See [selected policy preservation](rpdb-lan-boundary.md).


## Operation

Open BrumeHotswapper.slnx from the repository root. Projects and bundled RouterAssets use relative paths. Normal startup uses real discovery; demo data requires --demo. A reviewed plan is revalidated before mutation. Unknown or incompatible firmware is refused. The normal installer runs shared metadata, kill-switch, upload-capability and transaction checks before Review; a standalone preflight is not required. Metadata uses verified ls -ldn, test, wc and sha256sum primitives. See [shared production integration](shared-production-integration.md).

This pass corrects profile membership (numeric group_peer), anonymous UCI policy discovery, firmware-generated process references, configured kill-switch checks, optional standby validation and hidden LAN address conflicts. The historical three-slot engine, promotion, firewall preparation, connmark override, rollback and recovery order were preserved. Twelve critical historical function hashes are pinned in tooling/fastpath-baseline.json; the only normalized promotion differences are two notification labels.

## Transaction and recovery boundaries

1. Recheck identity/hash, selected peers/policy, slot ownership, file metadata, cron, DHCP decisions and kill-switch prerequisites. Refuse an existing transaction or installer lock.
2. Acquire the installer lock and create root-private staging. An attempt token identifies staging if command completion is uncertain. Write an initial journal with original file hashes/modes, original cron, intended payload hashes and planned reservations. Uploads remain in router-private staging; no private Windows temporary configuration is used.
3. Hash and syntax-check payloads. Use the authoritative guard installer against a private preview and record its expected hash. Backups are content-addressed, verified and root-private.
4. Re-read cron, preserve unrelated jobs and compare the current crontab against an uploaded expected snapshot immediately before publishing. Pause only owned schedules. Stop the existing daemon without force-killing.
5. Check target hash/mode again before each script/config replacement. Refuse existing temporary replacement paths and symlinks. Record firmware intent and invoke the existing authoritative guard installer with its unchanged structural checks.
6. New named DHCP host sections use a private UCI delta directory and check for unrelated pending DHCP edits before commit. The installer does not restore a complete DHCP configuration.
7. Merge schedules from current cron, record runtime-start intent, launch the supervisor and validate installed hashes/modes, schedules, reservations, ACTIVE state, any present standby, handshake freshness, daemon count, policy agreement and kill-switch prerequisites.
8. Mark successful validation before cleanup. A cleanup error retains the installation and reports cleanup attention; it never initiates rollback of a validated running installation.

Before DHCP mutation or watchdog startup, automatic recovery restores only files whose observed content/metadata support ownership by this attempt. Backups are rehashed. Unexpected content, metadata-only changes, symlinks, partial replacement files and uncertain staging ownership require manual recovery. Unrelated cron lines are merged from current state. Restarting the previous watchdog requires unchanged policy peer/interface/group/tunnel and verified kill-switch prerequisites.

**After any attempted DHCP mutation or watchdog startup, a failure retains the transaction for manual recovery.** A started watchdog is stopped when possible; the installer does not guess how to reverse runtime promotions or partially committed configuration. The installer lock keeps the scheduled supervisor from restarting it. Existing VPN forwarding is not deliberately undone. Loss of SSH may prevent even stopping the process; the journal/lock must then be inspected locally.

Recovery is conservative, not atomic across SSH, UCI, cron and firmware. GL panel/config writers do not share the installer lock. Immediate comparisons narrow races but cannot eliminate a writer changing data between comparison and replacement. Avoid concurrent administrative changes during a controlled installation. Interrupted transactions are never automatically discarded or replayed.

The existing guard patcher's firmware copy remains non-atomic; an interrupted copy can leave an unexpected hash. That requires manual recovery from the verified backup. This pass retained the authoritative patch path rather than introducing a different firmware writer.

## Secrets

SSH password authentication stays inside SSH.NET; no password or ntfy URL is passed through a Windows process command line. Only allowlisted peer metadata is queried, never a full WireGuard export. Generated private configuration is uploaded in memory into a 0700 staging directory and installed as 0600. Command failures and reports use fixed messages rather than remote stderr or arbitrary exceptions. Router-side notification curl receives its URL through standard input. Journals/backups may contain private settings or identifiers and must remain root-only; do not attach them to public issues.

## Offline verification

Run:

    dotnet test BrumeHotswapper.slnx -c Release --verbosity minimal
    python tooling/test_router_scripts.py <path-to-sh>
    dotnet publish BrumeHotswapper.Installer/BrumeHotswapper.Installer.csproj -c Release --no-restore -o artifacts/installer

The .NET tests include simulated command-boundary failures/cancellation before and after file replacement, partial upload, cron publishing, DHCP commit/reload, startup and cleanup. They also cover anonymous policies, generated process references, kill-switch intent/rules, empty standby, sticky Tier 2, Tier 3 recovery roles, multiple peers and patched reinstall. The command fixture rejects unknown commands but does not emulate the whole router shell/UCI implementation.

Shell/Python checks execute isolated functions and synthetic data, never the complete router daemon or reboot path. They cover actual group_peer parsing, rank/recovery behavior, structural guard checks, conservative maintenance guards and historical fastpath hashes.

These tests do not establish real SFTP cancellation timing, BusyBox/UCI behavior, real firewall changes, reboot behavior or downtime.

## Proposed live-router integration plan — not executed

1. **Read-only identity/compatibility:** record model, GL version, rtp2 SHA and guard marker/anchor counts. Reconcile the historical patched-hash discrepancy privately; stop on unknown contents.
2. **Read-only VPN evidence:** inspect selected anonymous policy, enabled/killswitch values, tunnel/group/profile membership, slot peers and generated process references. Verify every selected location's peers and avoid dumping keys.
3. **Read-only dataplane:** compare fw3 chain ordering/scopes, ROUTE_POLICY attachment, marks, rules, terminal routes and IPv6 state against the verifier. Check ACTIVE/standby handshakes and state while observing normal Tier 1/2/3 transitions; do not trigger outages yet.
4. **Read-only maintenance/recovery readiness:** inspect subnet/pool, all reservations/leases/neighbours/router addresses, exact cron entries, file owners/modes, free space and pending transaction/lock. Arrange local recovery access and private backups. Keep other configuration writers idle.
5. **First controlled mutation:** in a maintenance window, install with notifications and maintenance disabled and zero new reservations. Keep a wired management connection and continuous packet-loss/egress monitoring. Confirm hashes, one daemon, selected policy, kill switch, supervisor and unrelated cron preservation. Abort to manual recovery on uncertain state.
6. **Controlled reinstall and recovery:** verify known-patched no-op and unchanged schedules. With recovery access, exercise selected upload/command interruption boundaries and confirm conservative retained-journal behavior after runtime startup. Do not delete evidence until the actual file/config state is reconciled.
7. **Separate DHCP/maintenance test:** add one disposable guard reservation, verify private UCI commit/reload behavior, check conflict refusal and presence checks in test mode. Zero/missing/malformed guard cases must retain documented behavior. Do not force or automatically trigger reboot.
8. **Controlled failover last:** only after the above succeeds, test standby loss/backoff, internal Tier 1/2 failover, sticky Tier 2 and Tier 3 recovery; measure packet loss and verify no WAN fallback. Test explicit notifications separately if enabled.
