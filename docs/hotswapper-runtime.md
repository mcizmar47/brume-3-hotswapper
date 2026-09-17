# Hotswapper directional runtime

## Deployed tree

```text
/root/
  hotswapper-main.sh
  hotswapper-supervisor.sh
  hotswapper-housekeeping.sh
  hotswapper/
    hotswapper.conf
    hotswapper-locations.tsv
    reboot-guards.tsv
    install-gl-guard.sh
    state/
      cursor.rank<N>
      housekeeping-last-date
    log/
      hotswapper.log
      hotswapper.log.1                 # when rotated
      promotion-timing.log            # DEBUG_TIMING=1 only
    firmware-backups/rtp2.sh.<original-SHA256>
    installer/
      backups/<SHA256>
      run-<unique-id>/                # temporary staging
/tmp/hotswapper/
  lock/pid
  supervisor-start/                  # temporary startup mutex
  state                              # directional snapshot
  ready.wgclient<N>                   # validated candidate peer
  preparing                          # current/purpose/slot/peer
  probe.wgclient<N>
  health-fail.wgclient<N>
  nord-backoff-until
  last-recovery
  wan-state
  wan-notification-pending
  promotion-in-progress
  gl-reconcile-pending
  command-output                     # private supervised-command output
  notification-title
  notification-body
  pre-reboot-request
  pre-reboot-result
  test-failover-request
  test-failover-result
  test-failover-output.<token>
/usr/bin/rtp2.sh                      # GL-owned, reconciliation guard only
```

Optional/transient files appear only when used. Scripts are installed as 0700, private configuration as 0600; supporting directories and runtime output are root-only. The physical slots rotate. Unused slots have no logical role.

Repository renames:

| Before | Now |
|---|---|
| vpn-watch.sh | hotswapper-main.sh |
| vpn-watch-supervisor.sh | hotswapper-supervisor.sh |
| conditional-reboot.sh | hotswapper-housekeeping.sh |
| firmware/install-vpn-watch-gl-guard.sh | firmware/install-gl-guard.sh |
| config/vpn-watch.conf.example | config/hotswapper.conf.example |

Deployment, process matching, upload allowlists, reports, status validation, tests and build assets use the new names. No old-file lookup, conversion, removal or migration was added. Previous installer-bookkeeping archival and the obsolete supervisor lock check were removed. Reinstallation repairs only this new layout.

## Directional policy

Rank/peer membership comes from the generated TSV. Smaller ranks are better; no place names drive policy.

| CURRENT | Healthy operation | CURRENT failure |
|---|---|---|
| Tier 1 | Keep next lower configured rank as DOWNTIER; no UPTIER | Promote healthy DOWNTIER |
| Tier 2 | Keep DOWNTIER while preparing UPTIER best-to-worst above CURRENT, starting at Tier 1. Release DOWNTIER only after UPTIER passes handshake and bound-path checks. Stay on CURRENT. | Prefer healthy UPTIER, then DOWNTIER |
| Tier 3 | Retain downward connectivity while searching Tier 1/2 best-to-worst; promote a proven UPTIER immediately. No Tier 3-to-Tier 3 improvements. | Prefer established upward candidate, then downward fallback |

A retained Tier 2 UPTIER can be replaced by a better candidate at a later slow interval. The existing UPTIER remains until its replacement is established. Only CURRENT and one useful hot candidate are retained in steady state; the third slot can temporarily prepare a replacement.

With neither candidate usable, the detector requests slow emergency/offline recovery, gated by WAN diagnosis. Readiness records identify the established peer/interface and are removed on teardown or CURRENT failure. Status can show `preparing` from the separate in-progress record. Snapshot auxiliaries describe established roles; an unused spare is not UPTIER.

## Detector and slow work

There is one daemon and detector owner. `detector_iteration` calls `fast_health_pass` synchronously, then waits 150 ms using `delay_us 150000`. A 400 ms pass therefore starts its successor at 550 ms; no overlapping pass starts at 150 ms.

A missing/non-UP interface or GL state other than connected is a hard failure at the next pass. Otherwise, the round launches two interface-bound numeric ICMP requests (1.1.1.1 and 8.8.8.8) in parallel, observes them for 200 ms, then terminates/reaps both children. Any reply succeeds. Two consecutive failed rounds are required; a successful round clears the count. These are packet helpers, not extra detectors.

Defaults: `FAST_PROBE_WINDOW_US=200000`, `FAST_FAILURE_THRESHOLD=2`, `DETECTOR_DELAY_US=150000`. Healthy passes normally take the observation window plus command overhead, followed by the delay: this is not a fixed 150 ms wall-clock timer. The sustained-failure simulation confirms at 550 ms and calls promotion after validating the hot candidate at 750 ms, measured from the first failing pass. Real scheduling phase, RTT, CPU cost and promotion checks add time. No exact hardware downtime is claimed.

Ping uses integer BusyBox timeouts. `delay_us` invokes `busybox usleep` with integer microseconds (150000 between passes, 200000 for packet observation). The actual router has integer-only `sleep` and no `setsid`; neither unsupported capability is required. Repository/archive evidence does **not** establish that its BusyBox includes `usleep`. Installer prerequisites and daemon startup therefore behaviorally test this exact applet: read monotonic `/proc/uptime` milliseconds, wait 150000 microseconds, read again, require 140 <= elapsed < 500 ms. Missing, failed, no-op or whole-second delay blocks explicitly. There is no busy-spin or one-second fallback. The lower tolerance accommodates uptime granularity; the upper limit rejects unusably slow behavior, including severe load. This is a capability gate, not a claim of verified hardware support.

The fast pass uses cached candidates, current policy identity, interface/GL state and bound probes. It never searches ranks, creates candidates, diagnoses WAN or delivers notifications. An independent GL policy change invalidates the cache and requests slow reconciliation. Known failed CURRENT requests recovery once, rather than repeatedly starting provider work.

Slow work retains the 20-second housekeeping and 60-second UPTIER-search intervals, or runs promptly after failure/promotion. It includes reconciliation, construction, provider/backoff work, WAN diagnosis, cleanup, requests and notifications. External commands run as one owned child command; the parent continues serial detector iterations while waiting. Cooperative pauses do likewise. Completion checks CURRENT identity and promotion generation to prevent stale candidate work after failover. Shutdown stops detector work and drains/reaps the outstanding command before releasing the daemon PID lock. It does not kill only a provider shell and orphan its synchronous descendants. Further INT/TERM signals are ignored during draining. If work does not finish within the installer's existing stop deadline, installation fails closed; it must not replace files or start a second daemon. Commands that independently daemonize were never part of this synchronous command contract.

The archived `vpn-watch-supervisor-v3.sh` confirms the same detachment sequence. The supervisor keeps its proven background subshell, `trap '' HUP`, `exec` and stdin/stdout/stderr redirection. The main script owns the atomic daemon lock and authoritative PID. The supervisor startup mutex serializes launch attempts; the daemon lock rejects duplicate starts even before a PID is visible. No new service, detached worker, or process-group utility is involved.

Promotion itself never yields to another detector, including when started by the slow path. Firewall preparation, mark override, kernel verification, four policy metadata writes/commit, guard, final checks and rollback remain intact. Notifications are deferred outside that transaction; one runtime slot holds the latest pending major-tier message. Seven original dataplane hashes plus next-lower-rank logic remain checked after normalizing names and explicit detector bookkeeping. Intentionally changed policy functions have behavioral tests instead.

## WAN, housekeeping and firmware

[WAN diagnosis](wan-outage-recovery.md) retains discovered WAN binding, exact router-only probe exceptions, two-round confirmation, UNKNOWN pause, no offline churn, best-rank/first-peer restoration and one WAN-restored notification after VPN success. WAN failures do not set provider backoff.

Owned schedules are `*/5 * * * * /root/hotswapper-supervisor.sh` and optional `0 3-14 * * * /root/hotswapper-housekeeping.sh`. Unrelated cron survives. Protected-device checks, the daily marker and deliberate pre-reboot Tier 2-to-Tier 1 recovery remain, including reuse of a ready preferred candidate.

The GL guard changes names/runtime directory only. In-memory reproduction against archived stock yields:

`5c4b26eebdd3cdb6876b7b5e9f48901d8061b525837c1d879f0d059d856f150c`

Only stock `749518…` or this new guard is supported. Older guard hashes point at the wrong runtime directory and are not converted. Manual cleanup must leave stock or the current guard. Archive tests prove that all proprietary bytes outside the insertion remain unchanged and the guard is equivalent after identifier/path renaming. Proprietary firmware was neither saved nor committed.

## Validation and hardware limits

- Release .NET: 200 tests passed.
- Existing shell/Python and syntax regressions, 34 WAN cases and 40 directional/detector/cooperative-work cases passed.
- Seven platform checks plus the real supervisor host lifecycle fixture passed.
- In-memory guard reproduction and generated syntax passed.
- Release solution, installer and read-only utility builds passed without warnings/errors.

Tests use production functions with local synthetic transports/command stubs. They cover serial timing, one-loss tolerance, simulated sub-second promotion entry, hard-down handling, detection during supervised work, transaction non-reentrancy, WAN isolation, provider backoff, notification deferral and pre-reboot reuse. No live router was contacted.

Before deployment, establish that the behavioral `busybox usleep` gate passes on the actual firmware, and measure detector CPU cost and RTT tolerance across configured locations, packet loss, client leak protection, and the GL race. Both targets missing the 200 ms window twice can misclassify a high-latency path. Existing synchronous kernel/UCI/promotion operations can exceed nominal timing when the router is busy.

The next firmware investigation should locate GL's selected-VPN automatic recovery trigger and its setup_instance/network rebuild calls, then establish ordering relative to Hotswapper detection/promotion. The reconciliation guard was not expanded to suppress those actions; that race remains intentionally accepted.


## BusyBox compatibility correction

The supplied Maintenance → Review result is explained by the former chained prerequisite: the first missing command, `command -v setsid`, returned 127 and short-circuited the rest. Its later `sleep 0.001` would independently have failed with status 1. Runtime slow-command launch also called `setsid`; both dependencies are removed. All router waits now use either integer `sleep` or isolated integer-microsecond `delay_us`.

Review attributes router exit codes to identity/firmware, utilities/root, delay behavior, VPN ownership/membership, IPv6, routing/enforcement, pending DHCP, file metadata, cron/PID, or LAN inspection. Deployment transport failure retains the stream exit status when available. Labels are fixed application text; raw commands, stdout/stderr and private values are not copied into errors. Existing installation and post-install stage boundaries remain intact.

Local tests exercise the real supervisor with host fixture paths and production daemon lock functions, including launcher exit, SIGHUP survival, concurrent repeated invocations, one PID and lock release. They do not establish real SSH-session behavior on this BusyBox build. Host-language waits are explicitly host fixtures. Production shell timing is tested with a microsecond-app-let stub and elapsed-time outcomes, including missing/no-op/one-second rejection. The timing model remains two 200 ms failed rounds separated by 150 ms: confirmation at 550 ms, hot candidate verification complete at 750 ms from first failing pass, plus real command/promotion overhead. Hard failures skip the two-round confirmation. Each pass completes before its 150 ms delay; slow work does not create another detector.

Remaining hardware evidence: `usleep` behavioral support, detector CPU/RTT/loss tolerance, actual failover time, SSH-disconnect survival and provider-command drain duration. No router was contacted for this correction. The separately deferred GL automatic-recovery race remains unchanged.
