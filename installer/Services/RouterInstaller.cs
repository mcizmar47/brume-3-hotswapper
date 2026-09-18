using System.IO;
using System.Security.Cryptography;
using System.Text;
using BrumeHotswapper.Installer.Core;
namespace BrumeHotswapper.Installer.Services;

// Reconcile current router state; rollback information exists only for this execution.
public sealed class RouterInstaller(IRouterTransport router, IKillSwitchVerifier killSwitch)
{
    private const string Home = "/root/hotswapper/installer";
    private string Stage = "";
    private string suffix = "";
    private readonly RouterInspection inspection = new(router, killSwitch);
    private static string Hash(string content) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content))).ToLowerInvariant();
    private static string Q(string s) => ConfigurationGenerator.Quote(s);
    public async Task<InstallationPlan> PlanAsync(InstallerConfiguration c, CancellationToken ct) =>
        DeploymentPlanning.Create(c, await inspection.InspectAsync(c, ct));

    public async Task<InstallationResult> InstallAsync(InstallationPlan plan, IProgress<string> progress, CancellationToken ct)
    {
        var c = plan.Configuration;
        progress.Report("Validating router, VPN ownership and kill switch…");
        var fresh = await inspection.InspectAsync(c, ct);
        c = c with { Router = fresh.Router };
        plan = DeploymentPlanning.Create(c, fresh);
        suffix = Guid.NewGuid().ToString("N");
        Stage = Home + "/run-" + suffix;
        var content = new Dictionary<string, string>
        {
            ["/root/hotswapper/hotswapper.conf"] = ConfigurationGenerator.PrivateConfig(c),
            ["/root/hotswapper/hotswapper-locations.tsv"] = ConfigurationGenerator.Locations(c),
            ["/root/hotswapper/reboot-guards.tsv"] = ConfigurationGenerator.Guards(c),
            ["/root/hotswapper/housekeeping.conf"] = ConfigurationGenerator.Housekeeping(c)
        };
        foreach (var name in new[] {"hotswapper-main.sh","hotswapper-supervisor.sh","hotswapper-housekeeping.sh","install-gl-guard.sh"})
            content[(name == "install-gl-guard.sh" ? "/root/hotswapper/" : "/root/") + name] = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "RouterAssets", name), ct)).Replace("\r\n", "\n");
        var changed = new List<(FileState Before, string After)>();
        var created = new List<ReservationChange>();
        bool staged = false, cronChanged = false, runtimeStopped = false, started = false;
        string step = "Create protected staging area";
        string expectedFirmwareHash = c.Router.Rtp2Hash;
        try
        {
            await router.ExecuteAsync($"test ! -L /root/hotswapper && umask 077 && mkdir -p /root/hotswapper && chmod 700 /root/hotswapper && test ! -L {Home} && test ! -L {Home}/backups && umask 077 && mkdir -p {Home}/backups && chmod 700 {Home} {Home}/backups && mkdir {Stage}", ct);
            staged = true;
            step = "Upload and validate payloads"; progress.Report(step);
            foreach (var (path, body) in content)
            {
                var file = Stage + "/" + Path.GetFileName(path);
                await router.UploadAsync(file, body, ct);
                await router.ExecuteAsync($"test \"$(sha256sum {Q(file)} | awk '{{print $1}}')\" = {Q(Hash(body))} && chmod {(path.EndsWith(".sh") ? "700" : "600")} {Q(file)}", ct);
                if (path.EndsWith(".sh") || path.EndsWith(".conf")) await router.ExecuteAsync($"sh -n {Q(file)}", ct);
            }
            await router.ExecuteAsync($"sh {Stage}/install-gl-guard.sh --check", ct);
            if (!CompatibilityCatalog.IsPatched(c.Router.Rtp2Hash))
            {
                step = "Validate GL guard against a private firmware copy";
                await router.ExecuteAsync($"cp /usr/bin/rtp2.sh {Stage}/rtp2.preview && chmod 600 {Stage}/rtp2.preview && HOTSWAPPER_RTP2_TARGET={Stage}/rtp2.preview sh {Stage}/install-gl-guard.sh --install", ct);
                expectedFirmwareHash = (await router.ExecuteAsync($"sha256sum {Stage}/rtp2.preview | awk '{{print $1}}'", ct)).Trim();
            }
            step = "Back up affected files"; progress.Report(step);
            foreach (var before in fresh.Files)
            {
                bool firmware = before.Path == "/usr/bin/rtp2.sh";
                if (firmware && CompatibilityCatalog.IsPatched(c.Router.Rtp2Hash)) continue;
                if (!firmware && before.Exists && before.Hash == Hash(content[before.Path]) && before.Mode == (before.Path.EndsWith(".sh") ? "700" : "600")) continue;
                if (before.Exists)
                {
                    var backup = Home + "/backups/" + before.Hash;
                    await router.ExecuteAsync($"set -e; test ! -L {Q(backup)}; test \"$(sha256sum {Q(before.Path)} | awk '{{print $1}}')\" = {Q(before.Hash)}; if [ ! -f {Q(backup)} ]; then cp {Q(before.Path)} {Q(backup)}; chmod 600 {Q(backup)}; fi; test \"$(sha256sum {Q(backup)} | awk '{{print $1}}')\" = {Q(before.Hash)}", ct);
                }
            }
            // Exclude only owned jobs while replacing/stopping the Hotswapper. Other cron lines survive.
            step = "Pause owned schedules"; cronChanged = true;
            var currentCron = await router.ExecuteAsync("crontab -l 2>/dev/null || true", ct);
            await WriteCronAsync(DeploymentPlanning.RestoreOwnedCron(currentCron, ""), currentCron, ct);
            step = "Stop existing Hotswapper safely"; runtimeStopped = true;
            await StopDaemonAsync(ct);
            step = "Install scripts and configuration"; progress.Report(step);
            foreach (var (path, body) in content)
            {
                var before = fresh.Files.Single(f => f.Path == path);
                var after = Hash(body);
                if (before.Exists && before.Hash == after && before.Mode == (path.EndsWith(".sh") ? "700" : "600")) continue;
                changed.Add((before, after)); // Record before mutation, including cancellation races.
                await router.ExecuteAsync($"{Unchanged(before)} && test ! -e {Q(path + ".hotswap-new-" + suffix)} && test ! -L {Q(path + ".hotswap-new-" + suffix)} && cp -p {Q(Stage + "/" + Path.GetFileName(path))} {Q(path + ".hotswap-new-" + suffix)} && mv -f {Q(path + ".hotswap-new-" + suffix)} {Q(path)}", ct);
            }
            step = "Reserve maintenance guard addresses"; progress.Report(step);
            foreach (var r in plan.Reservations.Where(r => r.Create))
            {
                string section = ReservationSection(r.Mac);
                await router.ExecuteAsync($"if uci -q get dhcp.{section} >/dev/null; then exit 1; fi", ct);
                var lanNow = await inspection.LanAsync(ct);
                if (lanNow.Reservations.Any(x => x.Ip == r.Ip || x.Mac.Equals(r.Mac, StringComparison.OrdinalIgnoreCase)) ||
                    (lanNow.Observations ?? lanNow.Clients).Any(x => x.Ip == r.Ip && !x.Mac.Equals(r.Mac, StringComparison.OrdinalIgnoreCase)))
                    throw new SafeFailure("A DHCP conflict appeared during installation.");
                created.Add(r);
                // Named host section: rollback never depends on anonymous UCI indexes.
                // Private UCI deltas avoid committing another process's pending edits.
                await router.ExecuteAsync($"test -z \"$(uci changes dhcp)\" && mkdir -p {Stage}/uci && uci -P {Stage}/uci set dhcp.{section}=host && uci -P {Stage}/uci set dhcp.{section}.mac={Q(r.Mac.ToLowerInvariant())} && uci -P {Stage}/uci set dhcp.{section}.ip={Q(r.Ip)} && test -z \"$(uci changes dhcp)\" && uci -P {Stage}/uci commit dhcp", ct);
            }
            if (created.Count > 0) await router.ExecuteAsync("/etc/init.d/dnsmasq reload", ct);
            step = "Apply GL reconciliation guard"; progress.Report(step);
            if (!CompatibilityCatalog.IsPatched(c.Router.Rtp2Hash))
            {
                var before = fresh.Files.Single(f => f.Path == "/usr/bin/rtp2.sh");
                // The authoritative patcher makes its original-file, SHA-named backup as well.
                changed.Add((before, expectedFirmwareHash));
                await router.ExecuteAsync(Unchanged(before), ct);
                await router.ExecuteAsync("/root/hotswapper/install-gl-guard.sh --install", ct);
                var after = (await router.ExecuteAsync("sha256sum /usr/bin/rtp2.sh | awk '{print $1}'", ct)).Trim();
                if (after != expectedFirmwareHash) throw new SafeFailure("The applied reconciliation guard differs from its validated preview.");
            }
            step = "Configure schedules"; progress.Report(step);
            currentCron = await router.ExecuteAsync("crontab -l 2>/dev/null || true", ct);
            await WriteCronAsync(CronPlanner.Generate(currentCron, c.Maintenance), currentCron, ct);
            step = "Start supervisor"; progress.Report(step); started = true;
            await router.ExecuteAsync("rm -f /tmp/hotswapper/state && /root/hotswapper-supervisor.sh --installer", ct);
            step = "Validate installed runtime"; progress.Report(step);
            var checks = await ValidateAsync(plan, content, ct);
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
                    // Restore only this run's known writes; never undo an external file or VPN change.
                    if (started) await StopDaemonAsync(recovery.Token);
                    // Matching DHCP additions are safe to retain: the next install discovers and reuses them.
                    foreach (var item in changed.AsEnumerable().Reverse())
                    {
                        var b = item.Before;
                        try
                        {
                            await router.ExecuteAsync($"test ! -L {Q(b.Path)} && rm -f {Q(b.Path + ".hotswap-new-" + suffix)} {Q(b.Path + ".hotswap-restore-" + suffix)}", recovery.Token);
                            // Never clobber a third-party update since our write.
                            var current = (await router.ExecuteAsync($"if [ -f {Q(b.Path)} ]; then sha256sum {Q(b.Path)} | awk '{{print $1}}'; fi", recovery.Token)).Trim();
                            if (!b.Exists && current.Length == 0) continue;
                            if (current == b.Hash)
                            {
                                var mode = FileMetadata.ParseListing(await router.ExecuteAsync(FileMetadata.ListingCommand(b.Path), recovery.Token)).Mode;
                                if (mode == b.Mode) continue;
                                if (item.After == b.Hash && mode == (b.Path.EndsWith(".sh") ? "700" : "600"))
                                    await router.ExecuteAsync($"chmod {b.Mode} {Q(b.Path)}", recovery.Token);
                                else rollbackOk = false;
                                continue;
                            }
                            if (current != item.After) { rollbackOk = false; continue; }
                            if (b.Exists) await router.ExecuteAsync($"test ! -L {Q(b.Path + ".hotswap-restore-" + suffix)} && test ! -e {Q(b.Path + ".hotswap-restore-" + suffix)} && test \"$(sha256sum {Q(Home + "/backups/" + b.Hash)} | awk '{{print $1}}')\" = {Q(b.Hash)} && cp {Q(Home + "/backups/" + b.Hash)} {Q(b.Path + ".hotswap-restore-" + suffix)} && chmod {b.Mode} {Q(b.Path + ".hotswap-restore-" + suffix)} && mv -f {Q(b.Path + ".hotswap-restore-" + suffix)} {Q(b.Path)}", recovery.Token);
                            else await router.ExecuteAsync($"rm -f {Q(b.Path)}", recovery.Token);
                        }
                        catch {
                            rollbackOk = false;
                            progress.Report("WARN: Could not restore " + b.Path + "; its backup was retained. Other files will still be restored where possible.");
                        }
                    }
                    bool sameRuntime =
                        (await router.ExecuteAsync($"uci -q get route_policy.{RouterInspection.Identifier(fresh.Policy)}.peer_id", recovery.Token)).Trim() == fresh.CurrentPeer &&
                        (await router.ExecuteAsync($"uci -q get route_policy.{RouterInspection.Identifier(fresh.Policy)}.via", recovery.Token)).Trim() == fresh.CurrentInterface &&
                        (await router.ExecuteAsync($"uci -q get route_policy.{RouterInspection.Identifier(fresh.Policy)}.group_id", recovery.Token)).Trim() == c.Profile.GroupId &&
                        (await router.ExecuteAsync($"uci -q get route_policy.{RouterInspection.Identifier(fresh.Policy)}.tunnel_id", recovery.Token)).Trim() == c.Profile.TunnelId;
                    if (sameRuntime) await killSwitch.VerifyAsync(router, c.Profile.PolicySection, recovery.Token);
                    if (cronChanged)
                    {
                        var currentCron = await router.ExecuteAsync("crontab -l 2>/dev/null || true", recovery.Token);
                        await WriteCronAsync(DeploymentPlanning.RestoreOwnedCron(currentCron, sameRuntime ? fresh.Cron : ""), currentCron, recovery.Token);
                    }
                    if (runtimeStopped && fresh.WatchdogRunning && sameRuntime && rollbackOk)
                    {
                        await router.ExecuteAsync("/root/hotswapper-supervisor.sh --installer", recovery.Token);
                        await new HotswapRuntime(router).WaitForOneAsync(recovery.Token);
                        var restoredStatus = await router.ExecuteAsync("/root/hotswapper-main.sh status", recovery.Token);
                        if (!RuntimeValidation.ValidStatus(restoredStatus)) rollbackOk = false;
                    }
                    if (!sameRuntime) rollbackOk = false;

                }
            }
            catch { rollbackOk = false; }
            string detail = failure is SafeFailure safe ? safe.Message + " " : "";
            string message = $"Installation stopped during: {step}. " + detail + (rollbackOk ? "Files and runtime changes made by this attempt were rolled back." :
                "Some changes could not be restored or verified. Backups were retained; rerun Install to reconcile current state. No persistent recovery gate was created.");
            if (created.Count > 0) message += " Matching DHCP reservations created by this run were retained for reuse.";
            if (failure is OperationCanceledException && rollbackOk) throw new SafeFailure("Installation cancelled; changes made by this attempt were rolled back.");
            throw new SafeFailure(message);
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            try {
                string temporary = string.Join(" ", content.Keys.Append("/usr/bin/rtp2.sh").SelectMany(p => new[]{Q(p+".hotswap-new-"+suffix),Q(p+".hotswap-restore-"+suffix)}));
                await router.ExecuteAsync($"rm -f {temporary}; test ! -L /root/hotswapper && umask 077 && mkdir -p /root/hotswapper && chmod 700 /root/hotswapper && test ! -L {Home} && test ! -L {Stage} && rm -rf {Stage}", cleanup.Token);
            } catch {
                progress.Report("WARN: Temporary file cleanup was incomplete. A later installation uses a fresh directory; backups and running state were retained.");
            }
        }
    }
    public static string ReservationSection(string mac) => "hotswap_" + mac.Replace(":", "").ToLowerInvariant();
    private static string Unchanged(FileState before) => before.Exists
        ? $"test ! -L {Q(before.Path)} && test \"$(sha256sum {Q(before.Path)} | awk '{{print $1}}')\" = {Q(before.Hash)} && {FileMetadata.MatchesCommand(before.Path, before.Mode)}"
        : $"test ! -e {Q(before.Path)} && test ! -L {Q(before.Path)}";
    private async Task WriteCronAsync(string cron, string expected, CancellationToken ct)
    {
        await router.UploadAsync(Stage + "/cron", cron, ct);
        await router.ExecuteAsync($"test \"$(crontab -l 2>/dev/null || true)\" = {Q(expected.TrimEnd('\n'))} && crontab {Stage}/cron", ct);
    }
    private Task StopDaemonAsync(CancellationToken ct) => new HotswapRuntime(router).StopAsync(ct);
    private async Task<IReadOnlyList<string>> ValidateAsync(InstallationPlan plan, Dictionary<string,string> content, CancellationToken ct)
    {
        var c = plan.Configuration;
        string operation = "installed files: integrity and permissions";
        var warnings = new List<string>();
        try
        {
            foreach (var (path, body) in content)
            {
                operation = "installed file " + path + ": integrity and permissions";
                await router.ExecuteAsync($"test -f {Q(path)} && {FileMetadata.MatchesCommand(path, path.EndsWith(".sh") ? "700" : "600")} && test \"$(sha256sum {Q(path)} | awk '{{print $1}}')\" = {Q(Hash(body))}", ct);
            }
            operation = "GL reconciliation guard";
            await router.ExecuteAsync("test \"$(grep -Fc '# hotswapper GL reconciliation guard v1' /usr/bin/rtp2.sh)\" = 1 && sh -n /usr/bin/rtp2.sh && /root/hotswapper/install-gl-guard.sh --check", ct);
            operation = "owned cron entries";
            var cron = await router.ExecuteAsync("crontab -l 2>/dev/null", ct);
            if (CronPlanner.Generate(cron, c.Maintenance) != cron) throw new SafeFailure("The installed schedules differ from the reviewed plan.");
            operation = "selected DHCP reservations";
            var reservations = plan.Reservations.Count > 0 ? (await inspection.LanAsync(ct)).Reservations : [];
            foreach (var r in plan.Reservations)
            {
                if (!reservations.Any(s => s.Mac.Equals(r.Mac, StringComparison.OrdinalIgnoreCase) && s.Ip == r.Ip))
                    throw new SafeFailure("A maintenance guard reservation failed validation.");
            }
            operation = "CURRENT/DOWNTIER/UPTIER state";
            string snapshot = "";
            bool healthy = false;
            for (int i = 0; i < 45; i++)
            {
                snapshot = await router.ExecuteAsync("if [ -f /tmp/hotswapper/state ]; then cat /tmp/hotswapper/state; fi", ct);
                if (RuntimeValidation.IsHealthy(snapshot, c)) { healthy = true; break; }
                await Task.Delay(2000, ct);
            }
            if (!healthy) throw new SafeFailure("The Hotswapper did not establish a healthy CURRENT/DOWNTIER/UPTIER topology in time.");
            operation = "Hotswapper startup and PID lock";
            await new HotswapRuntime(router).WaitForOneAsync(ct);
            operation = "hotswapper status command";
            var status = await router.ExecuteAsync("/root/hotswapper-main.sh status", ct);
            if (!RuntimeValidation.ValidStatus(status)) throw new SafeFailure("Status output has no valid CURRENT/DOWNTIER/UPTIER structure.");
            operation = "selected VPN policy agreement";
            string policy = RouterInspection.Identifier(c.Profile.PolicySection);
            await router.ExecuteAsync($"test \"$(uci -q get route_policy.{policy}.tunnel_id)\" = {Q(c.Profile.TunnelId)} && test \"$(uci -q get route_policy.{policy}.group_id)\" = {Q(c.Profile.GroupId)}", ct);
            var runtime = snapshot.Split('\n').Where(l => l.Contains('=')).Select(l => l.Split('=', 2)).ToDictionary(v => v[0], v => v[1].Trim());
            if ((await router.ExecuteAsync($"uci -q get route_policy.{policy}.via", ct)).Trim() != runtime["current_iface"] ||
                (await router.ExecuteAsync($"uci -q get route_policy.{policy}.peer_id", ct)).Trim() != runtime["current_peer"])
                throw new SafeFailure("The route policy and Hotswapper runtime disagree.");
            operation = "WireGuard handshake observation";
            foreach (var iface in new[] { runtime["current_iface"], runtime.GetValueOrDefault("downtier_iface", ""), runtime.GetValueOrDefault("uptier_iface", "") }.Where(v => v.Length > 0))
            {
                try {
                await router.ExecuteAsync($"wg show {iface} latest-handshakes | awk -v now=\"$(date +%s)\" '$2 > 0 && now-$2 <= 75 {{ok=1}} END {{exit !ok}}'", ct);
                } catch(OperationCanceledException){throw;}
                catch { warnings.Add("WARN: A WireGuard handshake observation was unavailable or older than the candidate-establishment threshold; established runtime health is checked by the Hotswapper."); }
            }
            operation = "configured VPN profile membership";
            foreach (var peer in c.Tiers.Where(t => t.Tier > 0).SelectMany(t => t.Locations).SelectMany(g => g.Connections))
                await router.ExecuteAsync($"test \"$(uci -q get wireguard.peer_{peer.PeerId}.group_id)\" = {Q(c.Profile.GroupId)} && grep -Fxq '{c.Profile.GroupId}_{peer.PeerId}' /etc/vpn_profiles.d/profile{c.Profile.TunnelId}", ct);
            operation = "IPv6 prerequisite";
            await Ipv6Compatibility.VerifyAsync(router, ct);
            operation = "selected VPN routing and GL enforcement";
            await killSwitch.VerifyAsync(router, c.Profile.PolicySection, ct);
            // A real router-side delivery test is part of the explicitly enabled notification configuration.
            operation = "notification delivery test";
            if (c.Notifications) {
                try { await router.ExecuteAsync("/root/hotswapper-main.sh notify_test", ct); }
                catch(OperationCanceledException){throw;}
                catch { warnings.Add("WARN: Router notification test failed; installation remains valid. Check the topic or notification service."); }
            }
            return new List<string> { "Hotswapper: Running", CompatibilityCatalog.IsPatched(c.Router.Rtp2Hash) ? "GL Guard: Already installed" : "GL Guard: Installed", "VPN CURRENT: Verified (standby availability may vary)", "Supervisor and schedules: Verified",
                c.Notifications ? "Notifications: Enabled (see delivery warnings, if any)" : "Notifications: Disabled",
                c.Maintenance ? "Maintenance: Enabled" : "Maintenance: Disabled" }.Concat(warnings).ToArray();
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception failure)
        {
            string detail = failure is SafeFailure safe ? safe.Message : failure is TimeoutException ? "Timed out; output withheld." : "Transport/read failure; output withheld.";
            throw new SafeFailure($"Post-install validation failed: {operation}. {detail}");
        }
    }
}
