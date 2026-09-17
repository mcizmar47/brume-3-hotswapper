# Hotswapper installer

The Windows installer supports GL-MT5000 and tested firmware 4.9.0 through shared discovery, ownership, routing, kill-switch and IPv6 checks. SSH.NET authentication and host trust remain interactive/session-only. Demo mode is explicitly separate from normal router operation.

## Current layout and repair

See [the deployed tree and role policy](hotswapper-runtime.md). Only the new Hotswapper layout is supported. No old-name cleanup, conversion or migration is performed. Clean the previous deployment manually; firmware must be stock or use the current-layout guard.

Repeated installation rereads file metadata, VPN ownership, selected policy, LAN data and cron. It repairs only new owned files/processes/schedules, preserves unrelated cron and reuses matching DHCP reservations. Uploads use a unique private `/root/hotswapper/installer/run-<id>` directory; backups use `/root/hotswapper/installer/backups/`. Rollback data exists only for the current execution. There is no persistent journal or replay framework.

The three entry programs remain directly under `/root`. Config, rank mapping, reboot guards, patcher, firmware backups, state and logs live under `/root/hotswapper/`; transient state uses `/tmp/hotswapper/`. Validation understands CURRENT/UPTIER/DOWNTIER, optional auxiliary candidates, directional rank membership and distinct rotating slots. Two retained hot directions are rejected in a steady-state snapshot.

## Generated files

- `hotswapper.conf`: quoted numeric tunnel/group IDs and optional normalized ntfy URL; root-only mode 0600.
- `hotswapper-locations.tsv`: rank, major tier, within-tier order, identity, display label, peer ID. Every selected pool member is retained; no geography drives policy.
- `reboot-guards.tsv`: MAC and IPv4 address. Explicitly empty means no protected devices; missing/malformed input postpones housekeeping reboot.

Housekeeping runs at 03:00-14:00 hourly when enabled. Supervisor runs every five minutes. Exact owned lines are reconciled and unrelated cron is preserved.

## Verification

```text
dotnet test BrumeHotswapper.slnx -c Release
python tooling/test_router_scripts.py <path-to-sh>
dotnet build BrumeHotswapper.Installer/BrumeHotswapper.Installer.csproj -c Release -o artifacts/installer
```

Tests use local synthetic transports and isolated production shell functions. See [runtime validation and hardware limits](hotswapper-runtime.md#validation-and-hardware-limits). No router installation was performed in this development pass.
