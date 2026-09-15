# RPDB LAN exception: resolved policy

The project explicitly permits verified local/router and directly connected LAN traffic outside the VPN. Selected VPN traffic must not escape through a non-VPN WAN/Internet path before reaching the selected VPN table.

## Shared production rule

The earlier-table verifier first applies existing Linux default-suppression and terminal-result handling. If a remaining route needs a LAN exception, it uses RouterInspection's shared network.lan.ipaddr/netmask reads and the current `ip -o -4 addr show` output. Exactly one kernel interface must own that configured address/prefix.

The exception requires the exact configured connected subnet, that verified interface, `proto kernel scope link`, and the verified local source address. A gateway, default, external subnet, unknown interface, unsupported route attributes, missing/ambiguous address evidence or mismatched source cannot qualify. No table number, subnet, router address or LAN interface name is hardcoded.

The LAN exception is used only for earlier lookups. Layers A/B and selected VPN-table verification are unchanged: the selected table still needs its expected wgclient default and terminal protection. An unsuppressed WAN default blocks; a default suppressed by suppress_prefixlength 0 still falls through according to Linux semantics.

## Empty earlier table

A failed individual table dump still requires successful complete-dump evidence before an earlier numeric table can be treated as empty. Failed or ambiguous evidence never grants safety. This remains the fix for the previously unavailable empty lookup.

## Resolved findings and validation

The user verified that the earlier connected route is the LAN route and explicitly authorized local LAN access as an intentional exception. The previous strict-policy LAN block is therefore superseded by this semantic rule. No router connection or mutation occurred during implementation.

- 179 .NET Release tests passed, zero failed/skipped.
- Focused tests include the observed LAN shape and a different subnet/interface/table, WAN default and specific external routes, unknown interfaces, gateways, unsupported attributes, ambiguous/missing kernel evidence, suppression behavior and unchanged selected-table requirements.
- Shell/Python regressions passed, including historical fastpath hashes.
- Release installer and diagnostic helper builds succeeded with zero warnings/errors.

The normal installer uses this shared verifier before Review and again before writes. No known genuine installation blocker remains from the supplied evidence. Normal installation still revalidates current state and fails closed if required evidence changes or is unavailable. No additional standalone preflight development cycle is proposed.
