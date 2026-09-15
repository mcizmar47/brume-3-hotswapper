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
        DeploymentPlanning.Create(c, await inspection.InspectAsync(c, ct));

    public async Task<InstallationResult> InstallAsync(InstallationPlan plan, IProgress<string> progress, CancellationToken ct)
    {
        var c = plan.Configuration;
        await RouterPrerequisites.ArchiveCompletedAsync(router, ct);
        await RouterPrerequisites.EnsureNoTransactionAsync(router, ct);
        progress.Report("Validating router, VPN ownership and kill switch…");
        var fresh = await inspection.InspectAsync(c, ct);
        var refreshed = DeploymentPlanning.Create(c, fresh);
        if (!fresh.Files.SequenceEqual(plan.Snapshot.Files) || fresh.Cron != plan.Snapshot.Cron ||
            !refreshed.Reservations.SequenceEqual(plan.Reservations) || fresh.ActivePeer != plan.Snapshot.ActivePeer ||
            fresh.ActiveInterface != plan.Snapshot.ActiveInterface || fresh.KillSwitchEnabled != plan.Snapshot.KillSwitchEnabled)
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
        string attempt = Guid.NewGuid().ToString("N");
        bool stageAttempted = false, committed = false;
        bool staged = false, cronChanged = false, runtimeStopped = false, started = false;
        string step = "Create protected staging area";
        string expectedFirmwareHash = c.Router.Rtp2Hash;
        try
        {
            stageAttempted = true;
            await router.ExecuteAsync($"test ! -e {Stage} && test ! -L {Home} && test ! -L {Home}/backups && mkdir /tmp/vpn-watch-installer-lock || exit 1; trap 'rmdir /tmp/vpn-watch-installer-lock' EXIT; umask 077; mkdir -p {Home}/backups && chmod 700 {Home} {Home}/backups && mkdir {Stage} && printf %s {attempt} > {Stage}/owner || exit 1; trap - EXIT", ct);
            staged = true;
            await router.UploadAsync(Stage + "/journal.json", JsonSerializer.Serialize(new { Attempt = attempt, fresh.Files, fresh.Cron, PayloadHashes = content.ToDictionary(x => x.Key, x => Hash(x.Value)), Reservations = plan.Reservations.Where(r => r.Create) }), ct);
            step = "Upload and validate payloads"; progress.Report(step);
            foreach (var (path, body) in content)
            {
                var file = Stage + "/" + Path.GetFileName(path);
                await router.UploadAsync(file, body, ct);
                await router.ExecuteAsync($"test \"$(sha256sum {Q(file)} | awk '{{print $1}}')\" = {Q(Hash(body))} && chmod {(path.EndsWith(".sh") ? "700" : "600")} {Q(file)}", ct);
                if (path.EndsWith(".sh") || path.EndsWith(".conf")) await router.ExecuteAsync($"sh -n {Q(file)}", ct);
            }
            await router.ExecuteAsync($"sh {Stage}/install-vpn-watch-gl-guard.sh --check", ct);
            if (!CompatibilityCatalog.IsPatched(c.Router.Rtp2Hash))
            {
                step = "Validate GL guard against a private firmware copy";
                await router.ExecuteAsync($"cp /usr/bin/rtp2.sh {Stage}/rtp2.preview && chmod 600 {Stage}/rtp2.preview && VPN_WATCH_RTP2_TARGET={Stage}/rtp2.preview sh {Stage}/install-vpn-watch-gl-guard.sh --install", ct);
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
            // Exclude only owned jobs while replacing/stopping the watchdog. Other cron lines survive.
            step = "Pause owned schedules"; cronChanged = true;
            var currentCron = await router.ExecuteAsync("crontab -l 2>/dev/null || true", ct);
            await WriteCronAsync(DeploymentPlanning.RestoreOwnedCron(currentCron, ""), currentCron, ct);
            step = "Stop existing watchdog safely"; runtimeStopped = true;
            await StopDaemonAsync(ct);
            step = "Install scripts and configuration"; progress.Report(step);
            foreach (var (path, body) in content)
            {
                var before = fresh.Files.Single(f => f.Path == path);
                var after = Hash(body);
                if (before.Exists && before.Hash == after && before.Mode == (path.EndsWith(".sh") ? "700" : "600")) continue;
                changed.Add((before, after)); // Record before mutation, including cancellation races.
                await router.ExecuteAsync($"{Unchanged(before)} && test ! -e {Q(path + ".hotswap-new")} && test ! -L {Q(path + ".hotswap-new")} && cp -p {Q(Stage + "/" + Path.GetFileName(path))} {Q(path + ".hotswap-new")} && mv -f {Q(path + ".hotswap-new")} {Q(path)}", ct);
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
            await router.UploadAsync(Stage + "/firmware-intent.json", JsonSerializer.Serialize(new { Before = c.Router.Rtp2Hash, After = expectedFirmwareHash }), ct);
            step = "Apply GL reconciliation guard"; progress.Report(step);
            if (!CompatibilityCatalog.IsPatched(c.Router.Rtp2Hash))
            {
                var before = fresh.Files.Single(f => f.Path == "/usr/bin/rtp2.sh");
                // The authoritative patcher makes its original-file, SHA-named backup as well.
                changed.Add((before, expectedFirmwareHash));
                await router.ExecuteAsync(Unchanged(before), ct);
                await router.ExecuteAsync("/root/install-vpn-watch-gl-guard.sh --install", ct);
                var after = (await router.ExecuteAsync("sha256sum /usr/bin/rtp2.sh | awk '{print $1}'", ct)).Trim();
                if (after != expectedFirmwareHash) throw new SafeFailure("The applied reconciliation guard differs from its validated preview.");
            }
            step = "Configure schedules"; progress.Report(step);
            currentCron = await router.ExecuteAsync("crontab -l 2>/dev/null || true", ct);
            await WriteCronAsync(CronPlanner.Generate(currentCron, c.Maintenance), currentCron, ct);
            await router.UploadAsync(Stage + "/runtime-start-intent", "The watchdog may have started; do not automatically reverse runtime changes.\n", ct);
            step = "Start supervisor"; progress.Report(step); started = true;
            await router.ExecuteAsync("rm -f /tmp/vpn-watch/state && /root/vpn-watch-supervisor.sh --installer", ct);
            step = "Validate installed runtime"; progress.Report(step);
            var checks = await ValidateAsync(plan, content, ct);
            committed = true; // Cleanup failure must not roll back a validated running installation.
            await router.UploadAsync(Stage + "/completed", "installed", ct);
            await router.ExecuteAsync(CleanupCommand(attempt), ct);
            return new(true, checks);
        }
        catch (Exception failure)
        {
            if (committed)
                throw new SafeFailure("Installation and runtime validation succeeded, but staging cleanup did not finish. Inspect /root/.hotswap-installer/transaction and the installer lock before retrying; the installation was retained.");
            bool rollbackOk = true;
            using var recovery = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            progress.Report("Installation did not finish. Restoring changes made by this attempt…");
            try
            {
                if (!staged && stageAttempted)
                    staged = (await router.ExecuteAsync($"if [ -f {Stage}/owner ]; then cat {Stage}/owner; fi", recovery.Token)).Trim() == attempt;
                if (!staged && stageAttempted) rollbackOk = false;
                if (staged)
                {
                    // Router config writers and the running engine do not share this transaction's lock.
                    // DHCP remains conservative; after startup, restore files only under the existing hash and policy checks.
                    if (started) await StopDaemonAsync(recovery.Token);
                    if (created.Count > 0)
                        throw new SafeFailure("Committed DHCP recovery requires inspection.");
                    foreach (var item in changed.AsEnumerable().Reverse())
                    {
                        var b = item.Before;
                        // Do not clean up an incomplete replacement or follow a concurrent symlink.
                        await router.ExecuteAsync($"test ! -L {Q(b.Path)} && test ! -e {Q(b.Path + ".hotswap-new")} && test ! -L {Q(b.Path + ".hotswap-new")}", recovery.Token);
                        // Never clobber a third-party update since our write.
                        var current = (await router.ExecuteAsync($"if [ -f {Q(b.Path)} ]; then sha256sum {Q(b.Path)} | awk '{{print $1}}'; fi", recovery.Token)).Trim();
                        if (!b.Exists && current.Length == 0) continue;
                        if (current == b.Hash)
                        {
                            var mode = FileMetadata.ParseListing(await router.ExecuteAsync(FileMetadata.ListingCommand(b.Path), recovery.Token)).Mode;
                            if (mode == b.Mode) continue;
                            rollbackOk = false; // A metadata-only concurrent edit has no provable owner.
                            continue;
                        }
                        if (current != item.After) { rollbackOk = false; continue; }
                        if (b.Exists) await router.ExecuteAsync($"test ! -L {Q(b.Path + ".hotswap-restore")} && test ! -e {Q(b.Path + ".hotswap-restore")} && test \"$(sha256sum {Q(Home + "/backups/" + b.Hash)} | awk '{{print $1}}')\" = {Q(b.Hash)} && cp {Q(Home + "/backups/" + b.Hash)} {Q(b.Path + ".hotswap-restore")} && chmod {b.Mode} {Q(b.Path + ".hotswap-restore")} && mv -f {Q(b.Path + ".hotswap-restore")} {Q(b.Path)}", recovery.Token);
                        else await router.ExecuteAsync($"rm -f {Q(b.Path)}", recovery.Token);
                    }
                    bool sameRuntime =
                        (await router.ExecuteAsync($"uci -q get route_policy.{RouterInspection.Identifier(fresh.Policy)}.peer_id", recovery.Token)).Trim() == fresh.ActivePeer &&
                        (await router.ExecuteAsync($"uci -q get route_policy.{RouterInspection.Identifier(fresh.Policy)}.via", recovery.Token)).Trim() == fresh.ActiveInterface &&
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
                        await router.ExecuteAsync("/root/vpn-watch-supervisor.sh --installer", recovery.Token);
                        await new HotswapRuntime(router).WaitForOneAsync(recovery.Token);
                        var restoredStatus = await router.ExecuteAsync("/root/vpn-watch.sh status", recovery.Token);
                        if (!RuntimeValidation.ValidStatus(restoredStatus)) rollbackOk = false;
                    }
                    if (!sameRuntime) rollbackOk = false;
                    if (rollbackOk) {
                        await router.UploadAsync(Stage + "/completed", "rolled-back", recovery.Token);
                        await router.ExecuteAsync(CleanupCommand(attempt), recovery.Token);
                    }
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
    // A delayed command from an old session must never remove a newer transaction.
    private static string CleanupCommand(string attempt) =>
        $"test ! -L {Stage} && test \"$(cat {Stage}/owner)\" = {Q(attempt)} && rm -rf {Stage} && rmdir /tmp/vpn-watch-installer-lock";
    public static string ReservationSection(string mac) => "hotswap_" + mac.Replace(":", "").ToLowerInvariant();
    private static string Unchanged(FileState before) => before.Exists
        ? $"test ! -L {Q(before.Path)} && test \"$(sha256sum {Q(before.Path)} | awk '{{print $1}}')\" = {Q(before.Hash)} && {FileMetadata.MatchesCommand(before.Path, before.Mode)}"
        : $"test ! -e {Q(before.Path)} && test ! -L {Q(before.Path)}";
    private async Task WriteCronAsync(string cron, string expected, CancellationToken ct)
    {
        await router.UploadAsync(Stage + "/cron.expected", expected, ct);
        await router.UploadAsync(Stage + "/cron", cron, ct);
        await router.ExecuteAsync($"(crontab -l 2>/dev/null || true) > {Stage}/cron.current; cmp -s {Stage}/cron.expected {Stage}/cron.current && crontab {Stage}/cron", ct);
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
            await router.ExecuteAsync("test \"$(grep -Fc '# vpn-watch GL reconciliation guard v1' /usr/bin/rtp2.sh)\" = 1 && sh -n /usr/bin/rtp2.sh && /root/install-vpn-watch-gl-guard.sh --check", ct);
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
            operation = "ACTIVE/PRECOOKED/RECOVERY state";
            string snapshot = "";
            bool healthy = false;
            for (int i = 0; i < 45; i++)
            {
                snapshot = await router.ExecuteAsync("if [ -f /tmp/vpn-watch/state ]; then cat /tmp/vpn-watch/state; fi", ct);
                if (RuntimeValidation.IsHealthy(snapshot, c)) { healthy = true; break; }
                await Task.Delay(2000, ct);
            }
            if (!healthy) throw new SafeFailure("The watchdog did not establish a healthy ACTIVE/PRECOOKED/RECOVERY topology in time.");
            operation = "watchdog startup and PID lock";
            await new HotswapRuntime(router).WaitForOneAsync(ct);
            operation = "vpn-watch status command";
            var status = await router.ExecuteAsync("/root/vpn-watch.sh status", ct);
            if (!RuntimeValidation.ValidStatus(status)) throw new SafeFailure("Status output has no valid ACTIVE/PRECOOKED/RECOVERY structure.");
            operation = "selected VPN policy agreement";
            string policy = RouterInspection.Identifier(c.Profile.PolicySection);
            await router.ExecuteAsync($"test \"$(uci -q get route_policy.{policy}.tunnel_id)\" = {Q(c.Profile.TunnelId)} && test \"$(uci -q get route_policy.{policy}.group_id)\" = {Q(c.Profile.GroupId)}", ct);
            var runtime = snapshot.Split('\n').Where(l => l.Contains('=')).Select(l => l.Split('=', 2)).ToDictionary(v => v[0], v => v[1].Trim());
            if ((await router.ExecuteAsync($"uci -q get route_policy.{policy}.via", ct)).Trim() != runtime["active_iface"] ||
                (await router.ExecuteAsync($"uci -q get route_policy.{policy}.peer_id", ct)).Trim() != runtime["active_peer"])
                throw new SafeFailure("The route policy and watchdog runtime disagree.");
            operation = "WireGuard handshake observation";
            foreach (var iface in new[] { runtime["active_iface"], runtime.GetValueOrDefault("standby_iface", "") }.Where(v => v.Length > 0))
            {
                try {
                await router.ExecuteAsync($"wg show {iface} latest-handshakes | awk -v now=\"$(date +%s)\" '$2 > 0 && now-$2 <= 75 {{ok=1}} END {{exit !ok}}'", ct);
                } catch(OperationCanceledException){throw;}
                catch { warnings.Add("WARN: A WireGuard handshake observation was unavailable or older than the candidate-establishment threshold; established runtime health is checked by the watchdog."); }
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
                try { await router.ExecuteAsync("/root/vpn-watch.sh notify_test", ct); }
                catch(OperationCanceledException){throw;}
                catch { warnings.Add("WARN: Router notification test failed; installation remains valid. Check the topic or notification service."); }
            }
            return new List<string> { "VPN Watch: Running", CompatibilityCatalog.IsPatched(c.Router.Rtp2Hash) ? "GL Guard: Already installed" : "GL Guard: Installed", "VPN ACTIVE: Verified (standby availability may vary)", "Supervisor and schedules: Verified",
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
