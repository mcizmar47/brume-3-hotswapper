# Verified GL-MT5000 data and remaining runtime evidence

The second-pass findings were supplied by the user from GL-MT5000 / firmware 4.9.0 reconnaissance. No raw dump is checked in.

| Purpose | Verified data |
|---|---|
| Hardware | ubus call system board: model GL.iNet GL-MT5000, board glinet,gl-mt5000 |
| GL firmware | /etc/glversion; tested version 4.9.0, independent from rtp2 |
| Reconciliation | Stock SHA 749518706ad6af15104c90ddba5aa99142e1a9c678fec9074cd4222f8595f82c; patched SHA 5b1a898d8a4943d256f0674c0050519f1ec1353327f7de0778e1c760d3e57704; marker: # vpn-watch GL reconciliation guard v1 |
| VPN relationships | route_policy section: tunnel_id, group_id, via, peer_id, mark; profile membership in /etc/vpn_profiles.d/profile followed by the tunnel ID |
| VPN pools | wireguard peer group_id and location: country,city; trim component whitespace and normalize Unicode, no fuzzy matching |
| LAN | /tmp/dhcp.leases, IPv4 neighbours and router-owned addresses |
| Static reservations | UCI dhcp host entries, mac and ip; create only missing named sections |
| Address validity | network.lan.ipaddr/netmask, dhcp.lan.start/limit; unsupported subnet representations fail specifically |
| Runtime | Existing /tmp/vpn-watch/state, process identity and WireGuard latest-handshakes |

Location metadata is supported for grouping, not claimed as an immutable global provider ID.
Peer display names are not retrieved: IDs, group membership and location are sufficient.
Neighbours are presented as unconfirmed presence, not proof of an online device.

## Kill-switch evidence still needed for firewall-based layouts

The supplied correction confirms an enabled kill switch but does not specify its enforcing UCI option/value or firewall rule.
The verifier accepts a concrete kernel invariant: the selected policy's marked table has a terminal
unreachable/blackhole/prohibit default, and any unicast default uses the selected VPN interface.
This is a conservative supported layout, not a claim that the inspected router uses it.
No guessed kill_switch property or software-version gate is used.

If that invariant is absent, the remaining evidence is the option/value read by GL firmware and its corresponding
enforcement rule. Read-only probes to inspect locally:

- List route-policy option names only: uci -q show route_policy | sed -n 's/^\(route_policy\.[^.]*\.[^=]*\)=.*/\1/p'
- Read the selected policy's mark: uci -q get route_policy.SELECTED_SECTION.mark
- ip -4 rule show
- ip -4 route show table SELECTED_MARK_TABLE
- Relevant DROP/REJECT or terminal-routing code in /usr/bin/rtp2.sh and its corresponding runtime filter rule.

Substitute the discovered section/table. Share only the relevant option/value and enforcement rule.
Do not export full WireGuard/provider configuration or commit proprietary firmware source.
IKillSwitchVerifier isolates the additional firmware-backed check. There is no bypass or blanket installation gate.
The installer never silently changes kill-switch state.
