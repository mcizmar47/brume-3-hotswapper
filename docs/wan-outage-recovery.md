# WAN outage diagnosis

## Scope and behavior

The watchdog now checks the underlying IPv4 WAN before emergency or broad VPN recovery. The complete original healthy PRECOOKED promotion branch runs first and makes no WAN probe. Promotion, firewall preparation, mark override, kernel checks, policy commit, GL guard, tier policy and maintenance handling are unchanged.

`wan_device` reads the firmware's firewall zone named `wan`, its configured logical networks, and netifd status (`ubus`, two-second timeout). It selects a corresponding current main-table default device. Neither the logical network nor the device/address is hardcoded. Missing/unsupported context is UNKNOWN; a configured down WAN or missing default is a failed round. This targets the tested GL fw3 layout, not arbitrary firewall architectures or multi-WAN aggregation.

`wan_probe_target` resolves each numeric target with `ip -4 route get TARGET oif DEVICE`, requires the returned device and a source IPv4 address, and runs `ping -n -I DEVICE -c 1 -W 1 -w 2 TARGET`. There is no DNS lookup. The targets are the archived GL kmwan defaults: 1.1.1.1, 8.8.8.8, 208.67.222.222 and 208.67.220.220. Any successful target ends the round with UP. Route-context/setup/tool errors are UNKNOWN, not proof of an outage. If no target succeeds and any probe has a setup error, the round is UNKNOWN.

## Probe isolation

Before ping, a temporary rule is inserted at the head of mangle OUTPUT. It matches **only root-owned IPv4 ICMP echo requests**, the discovered output device, its exact source /32, and the current target /32. ACCEPT skips GL LOCAL_POLICY for those packets. It does not bypass filter OUTPUT. No routing rules, route tables, UCI settings, client marks, PREROUTING or FORWARD rules are changed. Kill-switch ON/OFF use the same probe.

The route is explicitly bound to WAN before this exception is created. The OUTPUT chain and owner match exclude forwarded LAN traffic. See the [iptables owner documentation](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html) and [route-get interface semantics](https://www.man7.org/linux/man-pages/man8/ip-route.8.html). The archived firmware has LOCAL_POLICY in mangle OUTPUT and permits this ICMP in filter OUTPUT; its process-policy redirects otherwise make interface binding alone insufficient.

A subshell exit/signal trap removes the exact rule after success or failure. A matching leftover is removed before insertion so the new rule precedes LOCAL_POLICY. SIGKILL, power loss or failed deletion cannot guarantee cleanup; any residual rule is still limited to root ICMP to that single target/source/device and cannot admit client traffic. The next matching probe removes it; reboot/firewall reload also discards these nonpersistent rules. A firewall reload that removes the rule during a probe is UNKNOWN.

## State, cadence and recovery

- One failed round sets WAN_SUSPECT and pauses candidate creation without declaring an outage.
- A second consecutive failed round sets WAN_OFFLINE and a runtime-only pending-notification flag.
- There is at most one round per recovery cycle, shared by emergency and broad recovery. Each target has a two-second deadline; outage/suspect/unknown cycles sleep ten seconds afterward (normally about 10–18 seconds between rounds, plus local command overhead).
- While confirmed offline, normal cycles do only WAN diagnosis and existing backoff expiry bookkeeping. They do not select peers, materialize candidates, or call the provider. Log entries occur on state changes rather than every offline iteration. Explicit maintenance/test requests retain their existing behavior.
- UNKNOWN also pauses recovery and is shown distinctly in status. It requires fixing the probe context, not disabling the kill switch.
- On WAN return, configured peer cursors reset once and broad recovery starts at the best internal rank and first peer. Existing provider backoff, if already active, still applies. The pending flag keeps best-first recovery in use until promotion succeeds.
- After VPN promotion succeeds, one WAN-restored notification is attempted and the pending flag is cleared. Delivery failure does not affect recovery or cause repeated attempts. Normal major-tier notifications remain. No notification is attempted while the current state is WAN_OFFLINE.
- Runtime files are under /tmp/vpn-watch. A daemon restart retains an established outage if runtime files remain; a reboot rediscovers it with two rounds before candidate creation. Healthy VPN operation clears stale suspect/unknown status.

## Changes and validation

Production changes are confined to vpn-watch.sh: WAN device/probe/state/notification helpers, gates after hot promotion and before offline recovery, run_cycle outage handling, status, notify suppression and outage sleep cadence.

The shell suite invokes tooling/test_wan_recovery.py, which executes extracted production functions with strict local command stubs. The historical fastpath baseline still verifies all twelve functions; only the exact two-line WAN gate after the original hot-standby branch is normalized out. The baseline hash file is unchanged.

Validation for this change:

- 177 .NET tests passed in Release.
- Existing shell/Python regressions and syntax checks passed.
- 34 new WAN scenarios passed, including hot-standby priority, emergency and broad recovery, two-round confirmation, restart, no churn/backoff, cursor reset, notification failure/one-shot behavior, target fallback, unknown context, WAN discovery, firewall cleanup/reload, both kill-switch settings and real provider error handling.
- Release solution, installer and read-only preflight utility builds passed with no warnings/errors.

All tests use local synthetic data; no router connection or installation was performed.

## Concrete deployment checks

Before deploying this behavior, verify on the intended firmware that netifd/zone discovery selects the actual WAN, bound ICMP receives replies through the intended physical path with kill switch ON and OFF, the OUTPUT owner match is supported and counts the diagnostic packets, and cleanup removes the probe rule. Confirm client VPN enforcement remains in place while probing. This is a hardware integration check, not another implementation/preflight subsystem.

ICMP reachability is deliberately the signal, as in the GL monitor. An upstream network that blocks **all four** ICMP targets can appear offline despite TCP connectivity. Conversely one reachable target proves basic WAN reachability, not availability of every provider endpoint. Custom output filters, different policy-routing layouts, or a renamed/missing firmware WAN zone produce UNKNOWN or failed probes and need review rather than a broader bypass.
