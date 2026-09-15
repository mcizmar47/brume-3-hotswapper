# Selected GL policy preservation

Hotswapper preserves the selected GL.iNet VPN policy, including either kill-switch setting. It verifies routing/firewall integration required for safe tunnel promotion; it does not certify the router's complete network-security policy.

The shared verifier reads the existing setting and always validates selected mark/ACTIVE slot/table and VPN routes. When enabled it additionally checks paired GL MARK/DROP scope, chain attachment and selected-table terminal protection. Disabled is supported and informational. No installer or runtime path writes the kill-switch setting.

Unrelated RPDB lookups and LAN routes are outside this boundary. The universal earlier-table audit, empty-table proof and VerifiedLanLink exception machinery were removed. No suppress_prefixlength semantics are reinterpreted or routing rules changed.

IPv6 independently must be disabled because the existing promotion path updates IPv4 tables and firewall rules only. Turning the kill switch off does not waive this prerequisite.

Policy/profile agreement, runtime slot ownership, firmware compatibility, upload, transaction, rollback and generated configuration checks remain mandatory. Runtime promotion and rollback update only selected peer/group/interface/mark metadata; their proven implementation is unchanged.
