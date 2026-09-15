# Firmware compatibility evidence

The project records GL-MT5000 / GL firmware 4.9.0 as its tested target. The reconciliation pass checked archived stock bytes and reproduced the guard output locally; it did not run a live firmware test.

- Stock rtp2 SHA-256: `749518706ad6af15104c90ddba5aa99142e1a9c678fec9074cd4222f8595f82c`
- Reproducible guarded SHA-256: `c46469acec44023282fd1d6f729f34ab1b7fd5020ed0c83fc1852a091c2bf075`
- Guard marker: `# vpn-watch GL reconciliation guard v1`

The previously reported patched SHA was not reproduced from the archived stock and identical archived patcher. It is no longer classified as known. See [router evidence](router-data.md) for the discrepancy, evidence provenance and fail-closed behavior.

Tunnel/group identifiers are discovered. The three runtime slots and ACTIVE/PRECOOKED/RECOVERY design are intentional. See [installer](installer.md) for verification limits and the proposed live test sequence.
