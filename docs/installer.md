# Installer second pass

The existing solution is now at C:/Users/markc/Documents/GitHub/brume-3-hotswapper.
Git metadata and router scripts are at the repository root; project and asset references are relative.
Old Visual Studio caches were cleared. Open BrumeHotswapper.slnx here.
Normal startup uses real services; --demo explicitly selects separate network-free fixtures.

## Implemented path

- Independent stock/already-patched/unknown/incompatible guard states.
- Normalized country/city pools, all eligible peer IDs retained, multiple lists require selection.
- LAN discovery merges reservations, leases and neighbours; excludes router-owned addresses.
- Concrete Review plan: files, guard action, DHCP creates/reuses, schedules and supervisor.
- Read-only preflight checks hardware, hash, policy/group/pools, slot ownership and kill-switch enforcement.
- Private SFTP staging with session-pinned fingerprint, root-only files, syntax and transfer-hash checks.
- Guard preview on a private router-side copy, then the authoritative patcher on the real target.
- Content-addressed backups and targeted rollback; unrelated cron commands preserved.
- Reinstall replaces configuration, deduplicates schedules/reservations and skips known installed guard patches.
- Runtime validation reads watchdog state, ownership, eligibility, handshakes, daemon count, supervisor,
  permissions, schedules, reservations and optional notifications.

Remaining kill-switch evidence is documented in [router-data.md](router-data.md).
No live router was contacted or modified by the coding session. Transaction fixtures do not replace
an integration run on GL firmware. BusyBox, SFTP availability, the firmware's specific kill-switch enforcement,
and provider startup timing still need that run.

## Transaction boundaries

Payloads and journal use /root/.hotswap-installer/transaction (directory 700, private files 600).
Backups in /root/.hotswap-installer/backups are addressed by original content hash, avoiding duplicate
content backups on identical reinstalls. The patcher's existing firmware backups remain intact.

Only the two owned schedules are paused while replacing/stopping the daemon. Supervisor respects the
installer lock and serializes startup. No force-kill is used. Success removes staging; incomplete
recovery retains its private journal and blocks overlapping attempts.

Rollback restores a file only if its hash still matches this attempt's write, removes only matching
DHCP sections created by this attempt, and restores owned cron entries while retaining unrelated edits.
It does not restore whole router configuration or reverse live VPN dataplane changes.
If runtime ownership changed or third-party edits prevent safe rollback, manual inspection is reported.
Backups stay private on the router and are never downloaded into Windows logs.

## Router changes

- Generated TSV ranks/pools and generic IDs remain.
- Notification wording is generic; no fixed country has runtime significance.
- Supervisor no longer deletes the daemon lock, respects installation exclusion and serializes startup.
- Promotion, consistency, rollback, backoff and tier algorithms remain unchanged apart from notification wording.
- Reboot guards remain conservative, support zero/many devices and reject malformed/missing configuration.
- The guard patcher is unchanged. Proprietary rtp2.sh is not distributed.

Configuration contracts: vpn-watch-locations.tsv has rank, major tier, order, logical ID, label and peer ID.
reboot-guards.tsv has MAC and reserved IPv4. Both use tab-separated columns.
Private vpn-watch.conf contains discovered IDs and optional ntfy URL.

## Verification

Run dotnet test BrumeHotswapper.slnx -c Release for core, discovery, transaction/rollback, demo and offscreen WPF tests.
Run python tooling/test_router_scripts.py followed by the shell path for local shell fixtures.
These fixtures use synthetic data, never contact a router and never execute the full watchdog/reboot script.
