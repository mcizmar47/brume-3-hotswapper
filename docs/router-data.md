# Router evidence and supported layout

## Evidence inspected locally (2026-09-15)

Read-only inspection used the user's Brume archive: firmware scripts and VPN helper functions; exported UCI network, route-policy, WireGuard and DHCP configuration; generated VPN profile membership; captured firewall rules, routing tables and policy rules; historical watchdog v14.1 and the guard installer. Earlier-version inventory and reconnaissance were also inspected. Raw provider configuration and logs were not imported. The archive was not changed and no live router was contacted.

### Established by these captures

- Selected VPN policies can be anonymous UCI sections (`@rule[index]`). Tunnel and group identifiers are numeric and must be discovered, not installation constants.
- `/etc/vpn_profiles.d/profile<tunnel>` contains **group_peer** numeric pairs. Discovery filters by selected group, then checks each `wireguard.peer_<peer>.group_id`. The old `peer_<peer>` profile filter was wrong.
- All 160 peer location entries in the inspected configuration use comma-separated metadata. Exact component trimming and Unicode normalization are a grouping convention, not a provider-issued location ID. The inspected fields expose no dedicated location ID. Every matching peer is retained; generated numeric peer/rank membership controls routing, not display labels.
- The selected rule has `killswitch=1`. Firmware retains its VPN marking while the interface is down and suppresses the non-VPN failover marking rule when this setting is enabled.
- The captured fw3 mangle tunnel chain has a selected VPN mark rule followed by a DROP with the same matching scope. It is attached to ROUTE_POLICY. The routing captures also contain marked-table lookups and blackhole defaults in VPN tables. Thus terminal-route checking was useful but insufficient by itself: it did not verify configured intent or policy marking.
- Firmware maintains `gl_process_vpn` as an internal process rule referring to the active VPN. That reference is not an independent peer group. The installer permits this exact observed generated reference only for the active slot, with the expected section type and no group.
- The historical watchdog explicitly declares `SLOTS="wgclient1 wgclient2 wgclient3"`. These are intentional ACTIVE/PRECOOKED/RECOVERY resources. Other policy references and peer-group ownership still cause refusal, including references to an otherwise empty slot.
- Historical `reconcile_roles` selects the next lower rank with profile peers. A standby may be absent while preparation fails or backoff applies. RECOVERY is a free role slot, not a promise of a healthy tunnel. Tier 2 remains sticky; Tier 3 probes better tiers. Multiple peers share one location rank.
- DHCP exports use host sections with MAC/IP options, including an anonymous host section, plus LAN IPv4 address/netmask and numeric pool start/limit settings. New installer entries use named host sections so no deletion relies on changing anonymous indexes. Leases and neighbours are observations, not proof of online presence.

### Compatibility reconciliation

Stock rtp2 SHA-256, reproduced across several firmware archives:

`749518706ad6af15104c90ddba5aa99142e1a9c678fec9074cd4222f8595f82c`

The archived guard installer matches the repository guard installer. Running only its patch-generating awk expression against archived stock bytes **in memory** gives:

`c46469acec44023282fd1d6f729f34ab1b7fd5020ed0c83fc1852a091c2bf075`

This is the catalog's reproducible patched hash. The previous documentation's patched hash (`5b1a898d8a4943d256f0674c0050519f1ec1353327f7de0778e1c760d3e57704`) could not be reproduced or located as a patched firmware file in the inspected archives. It is now unknown, not silently trusted. Resolving that historical discrepancy requires a read-only comparison with the installed router file. A marker-bearing unknown file is refused pending review.

The unique insertion anchor remains `cmd="$1";shift`; the marker remains `# vpn-watch GL reconciliation guard v1`. No proprietary firmware file is stored in this repository. Known patched bytes produce an idempotent patch no-op; an unmarked unknown hash still requires explicit acknowledgement and structural checks.

GL firmware 4.9.0 is the project's recorded tested version and the supplied export context. This offline pass verifies captured file behavior; it does not establish every device running that version has identical files.

## Conservative installer limits

- Runtime verification currently requires the observed fw3 IPv4 chain shape, paired marking/DROP scope, its attachment, an unambiguous selected-mark lookup, VPN-only table routes and a terminal default. IPv6 must be explicitly disabled. nftables, extra tunnel-chain rules, ambiguous policy-routing precedence or other layouts require review rather than guessed acceptance.
- These are read-only snapshot checks, not a continuous leak detector or proof against an administrator concurrently changing the firewall.
- All assigned peers must still be present in the selected profile during installation. Therefore next configured rank equals next profile-backed rank at validation; an empty standby is allowed. Ongoing profile edits require rediscovery.
- LAN selection is restricted to a usable IPv4 subnet. Pool start/limit are read as metadata; the installer does not allocate a new pool or assume a neighbour is online. Static addresses are checked against every observed lease/neighbour/reservation address, including observations hidden by display grouping. All router-owned IPv4 addresses are excluded.
- Pool allocation behavior, live dnsmasq reloads, UCI private-delta behavior and simultaneous GL panel edits need controlled integration testing. No broader DHCP allocation semantics are inferred from the captured numeric settings.

For the follow-up structural/hash investigation and exact proposed read-only checks, see [guard hash investigation](guard-hash-investigation.md).
