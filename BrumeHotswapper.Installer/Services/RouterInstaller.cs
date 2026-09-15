using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BrumeHotswapper.Installer.Core;
namespace BrumeHotswapper.Installer.Services;

// All writes flow through this transaction. No raw router output is reported.
public sealed class RouterInstaller(IRouterTransport router, IKillSwitchVerifier killSwitch)
{
    private const string Home = "/root/.hotswap-installer";
    private const string Stage = Home + "/transaction";
    private readonly RouterInspection inspection = new(router, killSwitch);
    private static string Hash(string content) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content))).ToLowerInvariant();
    private static string Q(string s) => ConfigurationGenerator.Quote(s);
    public async Task<InstallationPlan> PlanAsync(InstallerConfiguration c, CancellationToken ct) =>
        DeploymentPlanning.Create(c, await inspection.InspectAsync(c, ct, enforceKillSwitch: false));

    public async Task<InstallationResult> InstallAsync(InstallationPlan plan, IProgress<string> progress, CancellationToken ct)
    {
        var c = plan.Configuration;
        if ((await router.ExecuteAsync($"if [ -e {Stage} ] || [ -d /tmp/vpn-watch-installer-lock ]; then echo pending; fi", ct)).Trim() == "pending")
            throw new SafeFailure("Another installation is active or has an unfinished recovery journal at /root/.hotswap-installer/transaction. Inspect that transaction before retrying.");
        progress.Report("Validating router, VPN ownership and kill switch…");
        var fresh = await inspection.InspectAsync(c, ct);
        var refreshed = DeploymentPlanning.Create(c, fresh);
        if (!fresh.Files.SequenceEqual(plan.Snapshot.Files) || fresh.Cron != plan.Snapshot.Cron ||
            !refreshed.Reservations.SequenceEqual(plan.Reservations) || fresh.ActivePeer != plan.Snapshot.ActivePeer ||
            fresh.ActiveInterface != plan.Snapshot.ActiveInterface)
            throw new SafeFailure("Router settings changed after Review. Return to the maintenance page and review a fresh plan.");
        var content = new Dictionary<string, string>
        {
            ["/root/vpn-watch.conf"] = ConfigurationGenerator.PrivateConfig(c),
            ["/root/vpn-watch-locations.tsv"] = ConfigurationGenerator.Locations(c),
            ["/root/reboot-guards.tsv"] = ConfigurationGenerator.Guards(c)
        };
        foreach (var name in new[] {"vpn-watch.sh","vpn-watch-supervisor.sh","conditional-reboot.sh","install-vpn-watch-gl-guard.sh"})
            content["/root/" + name] = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "RouterAssets", name), ct)).Replace("\r\n", "\n");
        var changed = new List<(FileState Before, string After)>();
        var created = new List<ReservationChange>();
        bool staged = false, cronChanged = false, runtimeStopped = false, started = false;
        string step = "Create protected staging area";
        string expectedFirmwareHash = c.Router.Rtp2Hash;
        try
        {
            await router.ExecuteAsync($"test ! -e {Stage} && test ! -L {Home} && test ! -L {Home}/backups && mkdir /tmp/vpn-watch-installer-lock || exit 1; trap 'rmdir /tmp/vpn-watch-installer-lock' EXIT; umask 077; mkdir -p {Home}/backups && chmod 700 {Home} {Home}/backups && mkdir {Stage} || exit 1; trap - EXIT", ct);
            staged = true;
            await router.UploadAsync(Stage + "/journal.json", JsonSerializer.Serialize(new { fresh.Files, fresh.Cron, Reservations = plan.Reservations.Where(r => r.Create) }), ct);
            step = "Upload and validate payloads"; progress.Report(step);
            foreach (var (path, body) in content)
            {
                var file = Stage + "/" + Path.GetFileName(path);
                await router.UploadAsync(file, body, ct);
                await router.ExecuteAsync($"test \"$(sha256sum {Q(file)} | awk '{{print $1}}')\" = {Q(Hash(body))} && chmod {(path.EndsWith(".sh") ? "700" : "600")} {Q(file)}", ct);
                if (path.EndsWith(".sh") || path.EndsWith(".conf")) await router.ExecuteAsync($"sh -n {Q(file)}", ct);
            }
            await router.ExecuteAsync($"sh {Stage}/install-vpn-watch-gl-guard.sh --check", ct);
            if (CompatibilityCatalog.Classify(c.Router.Rtp2Hash) != Compatibility.AlreadyPatchedKnownCompatible)
            {
                step = "Validate GL guard against a private firmware copy";
                await router.ExecuteAsync($"cp /usr/bin/rtp2.sh {Stage}/rtp2.preview && chmod 600 {Stage}/rtp2.preview && VPN_WATCH_RTP2_TARGET={Stage}/rtp2.preview sh {Stage}/install-vpn-watch-gl-guard.sh --install", ct);
                expectedFirmwareHash = (await router.ExecuteAsync($"sha256sum {Stage}/rtp2.preview | awk '{{print $1}}'", ct)).Trim();
            }
            step = "Back up affected files"; progress.Report(step);
            foreach (var before in fresh.Files)
            {
                bool firmware = before.Path == "/usr/bin/rtp2.sh";
                if (firmware && CompatibilityCatalog.Classify(c.Router.Rtp2Hash) == Compatibility.AlreadyPatchedKnownCompatible) continue;
                if (!firmware && before.Exists && before.Hash == Hash(content[before.Path]) && before.Mode == (before.Path.EndsWith(".sh") ? "700" : "600")) continue;
                if (before.Exists)
                {
                    var backup = Home + "/backups/" + before.Hash;
                    await router.ExecuteAsync($"test ! -L {Q(backup)} && test \"$(sha256sum {Q(before.Path)} | awk '{{print $1}}')\" = {Q(before.Hash)} && if [ ! -f {Q(backup)} ]; then cp {Q(before.Path)} {Q(backup)} && chmod 600 {Q(backup)}; fi; test \"$(sha256sum {Q(backup)} | awk '{{print $1}}')\" = {Q(before.Hash)}", ct);
                }
            }
            // Exclude only owned jobs while replacing/stopping the watchdog. Other cron lines survive.
            step = "Pause owned schedules"; cronChanged = true;
            await WriteCronAsync(DeploymentPlanning.RestoreOwnedCron(fresh.Cron, ""), ct);
            step = "Stop existing watchdog safely"; runtimeStopped = true;
            await StopDaemonAsync(ct);
            step = "Install scripts and configuration"; progress.Report(step);
            foreach (var (path, body) in content)
            {
                var before = fresh.Files.Single(f => f.Path == path);
                var after = Hash(body);
                if (before.Exists && before.Hash == after && before.Mode == (path.EndsWith(".sh") ? "700" : "600")) continue;
                changed.Add((before, after)); // Record before mutation, including cancellation races.
                await router.ExecuteAsync($"test ! -L {Q(path + ".hotswap-new")} && cp -p {Q(Stage + "/" + Path.GetFileName(path))} {Q(path + ".hotswap-new")} && mv -f {Q(path + ".hotswap-new")} {Q(path)}", ct);
            }
            step = "Reserve maintenance guard addresses"; progress.Report(step);
            foreach (var r in plan.Reservations.Where(r => r.Create))
            {
                string section = ReservationSection(r.Mac);
                await router.ExecuteAsync($"if uci -q get dhcp.{section} >/dev/null; then exit 1; fi", ct);
                var lanNow = await inspection.LanAsync(ct);
                if (lanNow.Reservations.Any(x => x.Ip == r.Ip || x.Mac.Equals(r.Mac, StringComparison.OrdinalIgnoreCase)) ||
                    lanNow.Clients.Any(x => x.Ip == r.Ip && !x.Mac.Equals(r.Mac, StringComparison.OrdinalIgnoreCase)))
                    throw new SafeFailure("A DHCP conflict appeared during installation.");
                created.Add(r);
                // Named host section: rollback never depends on anonymous UCI indexes.
                await router.ExecuteAsync($"uci set dhcp.{section}=host && uci set dhcp.{section}.mac={Q(r.Mac.ToLowerInvariant())} && uci set dhcp.{section}.ip={Q(r.Ip)} && uci commit dhcp", ct);
            }
            if (created.Count > 0) await router.ExecuteAsync("/etc/init.d/dnsmasq reload", ct);
            step = "Apply GL reconciliation guard"; progress.Report(step);
            if (CompatibilityCatalog.Classify(c.Router.Rtp2Hash) != Compatibility.AlreadyPatchedKnownCompatible)
            {
                var before = fresh.Files.Single(f => f.Path == "/usr/bin/rtp2.sh");
                // The authoritative patcher makes its original-file, SHA-named backup as well.
                changed.Add((before, expectedFirmwareHash));
                await router.ExecuteAsync("/root/install-vpn-watch-gl-guard.sh --install", ct);
                var after = (await router.ExecuteAsync("sha256sum /usr/bin/rtp2.sh | awk '{print $1}'", ct)).Trim();
                if (after != expectedFirmwareHash) throw new SafeFailure("The applied reconciliation guard differs from its validated preview.");
            }
            step = "Configure schedules"; progress.Report(step);
            await WriteCronAsync(plan.DesiredCron, ct);
            step = "Start supervisor"; progress.Report(step); started = true;
            await router.ExecuteAsync("rm -f /tmp/vpn-watch/state && /root/vpn-watch-supervisor.sh --installer", ct);
            step = "Validate installed runtime"; progress.Report(step);
            var checks = await ValidateAsync(plan, content, ct);
            await router.ExecuteAsync($"rm -rf {Stage} && rmdir /tmp/vpn-watch-installer-lock", ct);
            return new(true, checks);
        }
        catch (Exception failure)
        {
            bool rollbackOk = true;
            using var recovery = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            progress.Report("Installation did not finish. Restoring changes made by this attempt…");
            try
            {
                if (staged)
                {
                    if (started) await StopDaemonAsync(recovery.Token);
                    foreach (var r in created.AsEnumerable().Reverse())
                    {
                        string section = ReservationSection(r.Mac);
                        await router.ExecuteAsync($"if [ \"$(uci -q get dhcp.{section}.mac)\" = {Q(r.Mac.ToLowerInvariant())} ] && [ \"$(uci -q get dhcp.{section}.ip)\" = {Q(r.Ip)} ]; then uci delete dhcp.{section} && uci commit dhcp; else exit 1; fi", recovery.Token);
                    }
                    if (created.Count > 0) await router.ExecuteAsync("/etc/init.d/dnsmasq reload", recovery.Token);
                    foreach (var item in changed.AsEnumerable().Reverse())
                    {
                        var b = item.Before;
                        // Never clobber a third-party update since our write.
                        var current = (await router.ExecuteAsync($"if [ -f {Q(b.Path)} ]; then sha256sum {Q(b.Path)} | awk '{{print $1}}'; fi", recovery.Token)).Trim();
                        if (current == b.Hash)
                        {
                            var mode = (await router.ExecuteAsync($"stat -c %a {Q(b.Path)}", recovery.Token)).Trim();
                            if (mode == b.Mode) continue;
                            if (mode == (b.Path.EndsWith(".sh") ? "700" : "600"))
                                await router.ExecuteAsync($"chmod {b.Mode} {Q(b.Path)}", recovery.Token);
                            else rollbackOk = false;
                            continue;
                        }
                        if (current != item.After) { rollbackOk = false; continue; }
                        if (b.Exists) await router.ExecuteAsync($"cp {Q(Home + "/backups/" + b.Hash)} {Q(b.Path + ".hotswap-restore")} && chmod {b.Mode} {Q(b.Path + ".hotswap-restore")} && mv -f {Q(b.Path + ".hotswap-restore")} {Q(b.Path)}", recovery.Token);
                        else await router.ExecuteAsync($"rm -f {Q(b.Path)}", recovery.Token);
                    }
                    bool sameRuntime = !started ||
                        (await router.ExecuteAsync($"uci -q get route_policy.{fresh.Policy}.peer_id", recovery.Token)).Trim() == fresh.ActivePeer;
                    if (cronChanged)
                    {
                        var currentCron = await router.ExecuteAsync("crontab -l 2>/dev/null || true", recovery.Token);
                        await WriteCronAsync(DeploymentPlanning.RestoreOwnedCron(currentCron, sameRuntime ? fresh.Cron : ""), recovery.Token);
                    }
                    if (runtimeStopped && fresh.WatchdogRunning && sameRuntime && rollbackOk)
                        await router.ExecuteAsync("/root/vpn-watch-supervisor.sh --installer", recovery.Token);
                    if (!sameRuntime) rollbackOk = false;
                    if (rollbackOk) await router.ExecuteAsync($"rm -rf {Stage} && rmdir /tmp/vpn-watch-installer-lock", recovery.Token);
                }
            }
            catch { rollbackOk = false; }
            string detail = failure is SafeFailure safe ? safe.Message + " " : "";
            string message = $"Installation stopped during: {step}. " + detail + (rollbackOk ? "Changes made by this attempt were rolled back." :
                "Recovery needs attention. The private transaction journal remains at /root/.hotswap-installer/transaction; do not remove it before inspecting the affected files. Runtime VPN changes are not automatically reversed.");
            if (failure is OperationCanceledException && rollbackOk) throw new SafeFailure("Installation cancelled; changes made by this attempt were rolled back.");
            throw new SafeFailure(message);
        }
    }
    public static string ReservationSection(string mac) => "hotswap_" + mac.Replace(":", "").ToLowerInvariant();
    private async Task WriteCronAsync(string cron, CancellationToken ct)
    { await router.UploadAsync(Stage + "/cron", cron, ct); await router.ExecuteAsync($"crontab {Stage}/cron", ct); }
    private async Task StopDaemonAsync(CancellationToken ct)
    {
        foreach (var pid in await inspection.DaemonPidsAsync(ct))
            await router.ExecuteAsync($"if [ -r /proc/{pid}/cmdline ] && tr '\\000' '\\n' < /proc/{pid}/cmdline | grep -Fxq /root/vpn-watch.sh; then kill -TERM {pid}; fi", ct);
        for (int i = 0; i < 20; i++)
        { if ((await inspection.DaemonPidsAsync(ct)).Length == 0) return; await Task.Delay(500, ct); }
        throw new SafeFailure("The existing watchdog did not stop safely. No force-kill was attempted.");
    }
    private async Task<IReadOnlyList<string>> ValidateAsync(InstallationPlan plan, Dictionary<string,string> content, CancellationToken ct)
    {
        var c = plan.Configuration;
        foreach (var (path, body) in content)
            await router.ExecuteAsync($"test -f {Q(path)} && test \"$(stat -c %a {Q(path)})\" = {(path.EndsWith(".sh") ? "700" : "600")} && test \"$(sha256sum {Q(path)} | awk '{{print $1}}')\" = {Q(Hash(body))}", ct);
        await router.ExecuteAsync("test \"$(grep -Fc '# vpn-watch GL reconciliation guard v1' /usr/bin/rtp2.sh)\" = 1 && sh -n /usr/bin/rtp2.sh && /root/install-vpn-watch-gl-guard.sh --check", ct);
        var cron = await router.ExecuteAsync("crontab -l 2>/dev/null", ct);
        if (cron != plan.DesiredCron) throw new SafeFailure("The installed schedules differ from the reviewed plan.");
        foreach (var r in plan.Reservations)
        {
            var reservations = (await inspection.LanAsync(ct)).Reservations;
            if (!reservations.Any(s => s.Mac.Equals(r.Mac, StringComparison.OrdinalIgnoreCase) && s.Ip == r.Ip))
                throw new SafeFailure("A maintenance guard reservation failed validation.");
        }
        string snapshot = "";
        bool healthy = false;
        for (int i = 0; i < 45; i++)
        {
            snapshot = await router.ExecuteAsync("if [ -f /tmp/vpn-watch/state ]; then cat /tmp/vpn-watch/state; fi", ct);
            if (RuntimeValidation.IsHealthy(snapshot, c)) { healthy = true; break; }
            await Task.Delay(2000, ct);
        }
        if (!healthy) throw new SafeFailure("The watchdog did not establish a healthy ACTIVE/PRECOOKED/RECOVERY topology in time.");
        if ((await inspection.DaemonPidsAsync(ct)).Length != 1) throw new SafeFailure("Expected exactly one watchdog daemon.");
        await router.ExecuteAsync("/root/vpn-watch-supervisor.sh --installer", ct);
        if ((await inspection.DaemonPidsAsync(ct)).Length != 1) throw new SafeFailure("Supervisor validation failed.");
        string policy = RouterInspection.Identifier(c.Profile.PolicySection);
        await router.ExecuteAsync($"test \"$(uci -q get route_policy.{policy}.tunnel_id)\" = {Q(c.Profile.TunnelId)} && test \"$(uci -q get route_policy.{policy}.group_id)\" = {Q(c.Profile.GroupId)}", ct);
        var runtime = snapshot.Split('\n').Where(l => l.Contains('=')).Select(l => l.Split('=', 2)).ToDictionary(v => v[0], v => v[1].Trim());
        if ((await router.ExecuteAsync($"uci -q get route_policy.{policy}.via", ct)).Trim() != runtime["active_iface"] ||
            (await router.ExecuteAsync($"uci -q get route_policy.{policy}.peer_id", ct)).Trim() != runtime["active_peer"])
            throw new SafeFailure("The route policy and watchdog runtime disagree.");
        foreach (var iface in new[] { runtime["active_iface"], runtime.GetValueOrDefault("standby_iface", "") }.Where(v => v.Length > 0))
            await router.ExecuteAsync($"wg show {iface} latest-handshakes | awk -v now=\"$(date +%s)\" '$2 > 0 && now-$2 <= 75 {{ok=1}} END {{exit !ok}}'", ct);
        foreach (var peer in c.Tiers.Where(t => t.Tier > 0).SelectMany(t => t.Locations).SelectMany(g => g.Connections))
            await router.ExecuteAsync($"test \"$(uci -q get wireguard.peer_{peer.PeerId}.group_id)\" = {Q(c.Profile.GroupId)} && grep -Fxq 'peer_{peer.PeerId}' /etc/vpn_profiles.d/profile{c.Profile.TunnelId}", ct);
        await killSwitch.VerifyAsync(router, policy, ct);
        // A real router-side delivery test is part of the explicitly enabled notification configuration.
        if (c.Notifications) await router.ExecuteAsync("/root/vpn-watch.sh notify_test", ct);
        return ["VPN Watch: Running", CompatibilityCatalog.Classify(c.Router.Rtp2Hash) == Compatibility.AlreadyPatchedKnownCompatible ? "GL Guard: Already installed" : "GL Guard: Installed", "VPN topology: Healthy", "Supervisor and schedules: Verified",
            c.Notifications ? "Notifications: Enabled and tested" : "Notifications: Disabled",
            c.Maintenance ? "Maintenance: Enabled" : "Maintenance: Disabled"];
    }
}
