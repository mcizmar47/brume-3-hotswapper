# Tested Firmware

## GL.iNet Brume 3

- Device: GL.iNet Brume 3
- Model: GL-MT5000
- GL.iNet Admin Panel: v4.9.0
- OpenWrt base: 21.02-SNAPSHOT
- Platform: mediatek/mt7987
- Architecture: aarch64_cortex-a53

## Firmware Integration

The hotswapper integrates with GL.iNet's VPN implementation and applies a small runtime guard patch that prevents a possible race condition to:

`/usr/bin/rtp2.sh`

Original `rtp2.sh` SHA-256 on the tested firmware:

`749518706ad6af15104c90ddba5aa99142e1a9c678fec9074cd4222f8595f82c`

Patched `rtp2.sh` SHA-256:

`5b1a898d8a4943d256f0674c0050519f1ec1353327f7de0778e1c760d3e57704`

## Tested Configuration

- VPN provider: NordVPN
- VPN protocol: WireGuard / NordLynx
- GL.iNet VPN tunnel ID: 5779
- GL.iNet VPN group ID: 10004
- Kill switch: enabled
- Maximum simultaneous WireGuard instances used by the hotswapper: 3
- Roles: active, precooked standby, recovery
