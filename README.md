# Brume 3 Hotswapper

Windows WPF installer and three-slot VPN runtime for GL.iNet Brume 3 / GL-MT5000.

- **CURRENT** carries client traffic.
- **DOWNTIER** is the next configured lower rank, kept hot until UPTIER is ready.
- **UPTIER** is a better candidate. Tier 2 prepares it but stays sticky until CURRENT fails; Tier 3 promotes it immediately.
- One daemon runs serial health passes, waiting **150 ms after each completed pass**. Slow command waits yield to that same detector.
- WAN outages pause candidate churn; the kill switch and guarded fastpath remain authoritative.

Only the new `/root/hotswapper-*.sh`, `/root/hotswapper/` and `/tmp/hotswapper/` layout is supported. There is no old-layout discovery, cleanup or migration. Clean the previous deployment manually before installation.

Open BrumeHotswapper.slnx in Visual Studio, or build with dotnet build BrumeHotswapper.slnx.
Tests: dotnet test BrumeHotswapper.slnx -c Release.
Normal startup uses real router services; --demo is an explicit test-only option.

[Runtime, deployed tree and validation](docs/hotswapper-runtime.md) · [Installer](docs/installer.md) · [WAN diagnosis](docs/wan-outage-recovery.md)
