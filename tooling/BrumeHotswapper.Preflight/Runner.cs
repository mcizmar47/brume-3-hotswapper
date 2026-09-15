using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Preflight;

public record Check(string Name, string Status, string Detail);
public sealed partial class Runner(SshRouterSession session, string repository, string archive, string shell, Action<Check> report)
{
    private readonly ReadOnlyTransport read = new(session);
    private static string Hash(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();
    private void Add(string name, bool pass, string detail) => report(new(name, pass ? "PASS" : "BLOCK", detail));
    private async Task Step(string name, Func<Task> action)
    {
        try { await action(); }
        catch (Exception e) { report(new(name, "BLOCK", e is SafeFailure ? e.Message : "Read or validation failed; raw output withheld (" + e.GetType().Name + ").")); }
    }
    public async Task RunAsync(RouterIdentity identity, CancellationToken ct)
    {
        Add("Identity", identity.IsBrume, identity.IsBrume ? "GL-MT5000 verified using installer authentication/identity code." : "Unsupported model; no further checks.");
        if (!identity.IsBrume) return;
        Add("Firmware version", identity.Firmware == "4.9.0", "GL version: " + (Regex.IsMatch(identity.Firmware, @"^\d+\.\d+\.\d+$") ? identity.Firmware : "unrecognized"));
        await FirmwareChecksAsync(identity, ct);
        var inspection = new RouterInspection(read, new KillSwitchVerifier());
        IReadOnlyList<VpnProfile> profiles = [];
        await Step("VPN discovery", async () =>
        {
            profiles = await new VpnDiscovery(read).DiscoverAsync(ct);
            Add("VPN discovery", profiles.Count > 0, $"Real VpnDiscovery returned {profiles.Count} eligible profile(s); identifiers withheld.");
        });
        var profile = VpnDiscovery.AutoSelect(profiles);
        if (profile == null) report(new("Selected policy", "BLOCK", "A unique eligible profile was not established; selection-dependent checks skipped."));
        else
        {
            var groups = new ExactLocationResolver().Group(profile.Connections);
            Add("Location pools", groups.Sum(g => g.Connections.Count) == profile.Connections.Count, $"{profile.Connections.Count} peers retained across {groups.Count} exact pools; {groups.Count(g => g.Connections.Count > 1)} pools have multiple peers. Names and identifiers withheld.");
            Add("Anonymous policy", profile.PolicySection.StartsWith("@rule["), profile.PolicySection.StartsWith("@rule[") ? "Selected anonymous rule discovered." : "Selected rule is named.");
            await Step("Profile membership", async () =>
            {
                var entries = (await read.ExecuteAsync(ReadOnlyTransport.ProfileMembers(profile.TunnelId), ct)).Split('\n', StringSplitOptions.RemoveEmptyEntries);
                Add("Profile membership", profile.Connections.All(p => entries.Contains(profile.GroupId + "_" + p.PeerId)), "Compared all discovered peers against live group_peer membership.");
            });
            await Step("Slot ownership", async () => await SlotsAsync(profile, ct));
            await Step("Kill-switch verifier", async () => { await new KillSwitchVerifier().VerifyAsync(read, profile.PolicySection, ct); Add("Kill-switch verifier", true, "Real verifier accepted configured intent, MARK/DROP scope, chain attachment, selected-mark terminal routing and IPv6 prerequisites."); });
            await Step("Kill-switch observations", async () =>
            {
                string policy = RouterInspection.Identifier(profile.PolicySection);
                var intent = (await read.ExecuteAsync($"uci -q get route_policy.{policy}.killswitch || true", ct)).Trim();
                var ipv6 = (await read.ExecuteAsync("uci -q get glipv6.globals.enabled || true", ct)).Trim();
                Add("Kill-switch configured intent", intent == "1", intent == "1" ? "Enabled." : "Not verified enabled.");
                report(new("IPv6 configuration", ipv6 == "0" ? "PASS" : "WARN", ipv6 == "0" ? "Explicitly disabled." : ipv6 == "1" ? "Enabled; current verifier does not accept this layout." : "Missing/nonstandard setting."));
            });
            await Step("Runtime state", async () => await StateAsync(identity, profile, ct));
        }
        await Step("Daemon count", async () => { int count = (await inspection.DaemonPidsAsync(ct)).Length; Add("Daemon count", count == 1, $"{count} exact watchdog daemon process(es). No process action performed."); });
        await Step("Cron", async () =>
        {
            var cron = await read.ExecuteAsync("crontab -l 2>/dev/null || true", ct);
            _ = CronPlanner.Generate(cron, false);
            var lines = cron.Split('\n').Select(l => l.Trim()).ToArray();
            Add("Cron", true, $"Owned supervisor jobs: {lines.Count(l => l == CronPlanner.Supervisor)}; maintenance jobs: {lines.Count(l => l == CronPlanner.Maintenance)}. Unrelated commands withheld.");
        });
        await Step("Pending transaction", async () => { var value = (await read.ExecuteAsync("if [ -e /root/.hotswap-installer/transaction ] || [ -e /tmp/vpn-watch-installer-lock ]; then echo pending; else echo clear; fi", ct)).Trim(); Add("Pending transaction", value == "clear", value == "clear" ? "No transaction or installer lock exists." : "Transaction/lock exists; left untouched."); });
        foreach (string path in DeploymentPlanning.Paths)
            await Step("File " + path, async () =>
            {
                foreach (var check in MetadataReview.Evaluate(path, string.Join("\n", (await FileMetadata.ReadAsync(read, path, ct)).Select(f => f.Key + "=" + f.Value)))) report(check);
            });
        await Step("DHCP/LAN", async () =>
        {
            var lan = await inspection.LanAsync(ct);
            var observed = lan.Observations ?? lan.Clients;
            int conflicts = observed.GroupBy(x => x.Ip).Count(g => g.Select(x => x.Mac.ToLowerInvariant()).Distinct().Count() > 1);
            int duplicates = lan.Reservations.GroupBy(x => x.Mac.ToLowerInvariant()).Count(g => g.Count() > 1);
            Add("DHCP/LAN", conflicts == 0 && duplicates == 0, $"Real LAN inspection: {lan.Clients.Count} clients, {lan.Reservations.Count} reservations, {conflicts} conflicting addresses, {duplicates} duplicate reservation MACs. Addresses/names withheld; neighbours are not treated as proof of presence.");
        });
        await Step("Pending DHCP edits", async () => { var value = (await read.ExecuteAsync("if [ -z \"$(uci changes dhcp)\" ]; then echo false; else echo true; fi", ct)).Trim(); Add("Pending DHCP edits", value == "false", "Pending changes: " + (value == "false" ? "false" : "true") + "."); });
    }
    private async Task SlotsAsync(VpnProfile profile, CancellationToken ct)
    {
        string policy = RouterInspection.Identifier(profile.PolicySection);
        var active = (await read.ExecuteAsync($"uci -q get route_policy.{policy}.via", ct)).Trim();
        var peer = (await read.ExecuteAsync($"uci -q get route_policy.{policy}.peer_id", ct)).Trim();
        int generated = 0;
        bool valid = new[] { "wgclient1", "wgclient2", "wgclient3" }.Contains(active);
        foreach (var slot in new[] { "wgclient1", "wgclient2", "wgclient3" })
        {
            var references = (await read.ExecuteAsync(ReadOnlyTransport.SlotReferences(slot), ct)).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var other in references.Where(x => x != profile.PolicySection))
            {
                bool firmware = other == "gl_process_vpn" && slot == active &&
                    (await read.ExecuteAsync("uci -q get route_policy.gl_process_vpn", ct)).Trim() == "rule_process" &&
                    (await read.ExecuteAsync("uci -q get route_policy.gl_process_vpn.group_id || true", ct)).Trim() == "";
                if (firmware) generated++; else valid = false;
            }
            var config = (await read.ExecuteAsync($"uci -q get network.{slot}.config || true", ct)).Trim();
            if (config.Length == 0)
            { if ((await read.ExecuteAsync($"if ip link show {slot} >/dev/null 2>&1; then echo present; fi", ct)).Trim() == "present") valid = false; }
            else if (Regex.IsMatch(config, "^peer_[0-9]+$"))
                valid &= (await read.ExecuteAsync($"uci -q get wireguard.{config}.group_id", ct)).Trim() == profile.GroupId;
            else valid = false;
            if (slot == active) valid &= config == "peer_" + peer;
        }
        Add("Slot ownership", valid, $"Inspected all three reserved slots, active peer/interface agreement and policy references; {generated} verified firmware process reference(s). Identifiers withheld.");
    }
    private async Task StateAsync(RouterIdentity identity, VpnProfile profile, CancellationToken ct)
    {
        string snapshot = await read.ExecuteAsync("if [ -f /tmp/vpn-watch/state ]; then cat /tmp/vpn-watch/state; fi", ct);
        var fields = snapshot.Split('\n').Where(l => l.Contains('=')).Select(l => l.Split('=', 2)).ToDictionary(x => x[0], x => x[1].Trim());
        string Get(string key) => fields.GetValueOrDefault(key, "");
        var roles = new[] { Get("active_iface"), Get("standby_iface"), Get("recovery_iface") }.Where(x => x.Length > 0).ToArray();
        Add("Runtime role structure", roles.All(x => new[] { "wgclient1", "wgclient2", "wgclient3" }.Contains(x)) && roles.Distinct().Count() == roles.Length && Get("active_iface").Length > 0 && Get("recovery_iface").Length > 0, $"ACTIVE present: {Get("active_iface").Length > 0}; PRECOOKED present: {Get("standby_iface").Length > 0}; RECOVERY present: {Get("recovery_iface").Length > 0}. No transition triggered.");
        string policy = RouterInspection.Identifier(profile.PolicySection);
        Add("Runtime policy agreement", (await read.ExecuteAsync($"uci -q get route_policy.{policy}.via", ct)).Trim() == Get("active_iface") && (await read.ExecuteAsync($"uci -q get route_policy.{policy}.peer_id", ct)).Trim() == Get("active_peer"), "Compared ACTIVE against live selected policy.");
        long now = long.Parse((await read.ExecuteAsync("date +%s", ct)).Trim());
        foreach (var iface in new[] { Get("active_iface"), Get("standby_iface") }.Where(x => Regex.IsMatch(x, "^wgclient[123]$")))
        {
            var timestamps = (await read.ExecuteAsync($"wg show {iface} latest-handshakes | awk '{{print $2}}'", ct)).Split('\n').Where(x => long.TryParse(x, out _)).Select(long.Parse).ToArray();
            Add(iface == Get("active_iface") ? "ACTIVE handshake" : "PRECOOKED handshake", timestamps.Any(x => x > 0 && now >= x && now-x <= 75), "Checked timestamp freshness only; keys withheld.");
        }
        var mapping = await read.ExecuteAsync("if [ -f /root/vpn-watch-locations.tsv ]; then cat /root/vpn-watch-locations.tsv; fi", ct);
        if (string.IsNullOrWhiteSpace(mapping)) { report(new("RuntimeValidation", "WARN", "Installed locations TSV absent; authoritative rank mapping is unavailable to the generalized validator. No fabricated tier mapping was used.")); return; }
        var rows = mapping.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(x => x.Split('\t')).ToArray();
        if (rows.Any(x => x.Length != 6 || !int.TryParse(x[0], out _) || !int.TryParse(x[1], out int t) || t < 1 || t > 3)) throw new SafeFailure("Installed location mapping has an unsupported format.");
        var tiers = Enumerable.Range(0, 4).Select(i => new TierColumn("Tier " + i, i)).ToArray();
        foreach (var rank in rows.GroupBy(x => int.Parse(x[0])).OrderBy(g => g.Key))
        {
            var connections = rank.Select(x => profile.Connections.Single(p => p.PeerId == x[5])).ToArray();
            tiers[int.Parse(rank.First()[1])].Locations.Add(new("rank" + rank.Key, "Location", connections));
        }
        var config = new InstallerConfiguration(identity, profile, tiers, false, "", false, []);
        Add("RuntimeValidation", RuntimeValidation.IsHealthy(snapshot, config), "Executed the real RuntimeValidation against the live snapshot and installed rank membership.");
    }
    private async Task FirmwareAsync(RouterIdentity identity, CancellationToken ct)
    {
        var bytes = await session.ReadFirmwareBytesAsync(ct);
        if (Hash(bytes) != identity.Rtp2Hash) { Array.Clear(bytes); throw new SafeFailure("Firmware SHA changed or raw transfer differed; comparison stopped."); }
        Add("Firmware transfer integrity", Hash(bytes) == identity.Rtp2Hash, "Live SHA-256: " + Hash(bytes) + "; bytes: " + bytes.Length + ". Raw SSH stdout bytes retained only in memory.");
        using var zip = ZipFile.OpenRead(Path.Combine(archive, "brume_dump.zip"));
        using var input = zip.GetEntry("brume_dump/bin/rtp2.sh")!.Open(); using var buffer = new MemoryStream(); await input.CopyToAsync(buffer, ct); var stock = buffer.ToArray();
        if (Hash(stock) != CompatibilityCatalog.StockHash) throw new SafeFailure("Local stock evidence hash changed.");
        string patcher = (await File.ReadAllTextAsync(Path.Combine(repository, "firmware/install-vpn-watch-gl-guard.sh"), ct)).Replace("\r\n", "\n");
        int start = patcher.IndexOf("    awk -v anchor=", StringComparison.Ordinal), end = patcher.IndexOf(" > \"$tmp\" || {", StringComparison.Ordinal);
        string code = patcher[start..end]; if (!code.EndsWith(" \"$TARGET\"")) throw new SafeFailure("Local generator shape changed."); code = code[..^10];
        var psi = new ProcessStartInfo(shell) { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("ANCHOR='cmd=\"$1\";shift'\n" + code); psi.Environment["PATH"] = Path.GetDirectoryName(shell) + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH");
        using var process = Process.Start(psi)!; using var generated = new MemoryStream();
        var outputTask = process.StandardOutput.BaseStream.CopyToAsync(generated, ct); var errorTask = process.StandardError.ReadToEndAsync(ct);
        await process.StandardInput.BaseStream.WriteAsync(stock, ct); process.StandardInput.Close(); await Task.WhenAll(outputTask, process.WaitForExitAsync(ct)); await errorTask;
        var expected = generated.ToArray(); if (process.ExitCode != 0 || Hash(expected) != CompatibilityCatalog.PatchedHash) throw new SafeFailure("Local guard reproduction failed.");
        var anchorBytes = Encoding.UTF8.GetBytes("cmd=\"$1\";shift\n"); int insertion = stock.AsSpan().IndexOf(anchorBytes) + anchorBytes.Length;
        int extra = bytes.Length - stock.Length;
        bool preserved = extra >= 0 && bytes.AsSpan(0, insertion).SequenceEqual(stock.AsSpan(0, insertion)) && bytes.AsSpan(insertion + extra).SequenceEqual(stock.AsSpan(insertion));
        Add("Firmware stock preservation", preserved, preserved ? $"Every original stock byte is preserved; the only insertion is {extra} bytes after dispatch." : "Live differences extend beyond a single guard insertion; do not whitelist.");
        if (preserved)
        {
            var actualGuard = Encoding.UTF8.GetString(bytes.AsSpan(insertion, extra));
            var expectedGuard = Encoding.UTF8.GetString(expected.AsSpan(insertion, expected.Length-stock.Length));
            bool historical = Hash(bytes) == CompatibilityCatalog.HistoricalPatchedHash && actualGuard == expectedGuard.Replace("args=%s\n", "args=%s\\n");
            bool equal = actualGuard == expectedGuard || historical;
            bool whitespace = Regex.Replace(actualGuard, @"\s", "") == Regex.Replace(expectedGuard, @"\s", "");
            report(new("Guard comparison", equal ? "PASS" : "WARN", equal ? historical ? "Verified historical printf newline encoding; exact reproduced historical hash." : "Live guard exactly equals reproducible guard." : $"Guard differs; whitespace-only: {whitespace}; expected bytes: {Encoding.UTF8.GetByteCount(expectedGuard)}; actual bytes: {extra}."));
            var knownLines = expectedGuard.Split('\n'); var liveLines = actualGuard.Split('\n');
            int missing = knownLines.Count(x => !liveLines.Contains(x)), added = liveLines.Count(x => !knownLines.Contains(x));
            report(new("Guard diff summary", equal ? "PASS" : "WARN", $"Missing/changed expected lines: {missing}; added/changed live lines: {added}. Non-guard proprietary contents withheld."));
            // Emit only differences that are demonstrably whitespace changes to known guard lines.
            foreach (var line in liveLines.Where(x => !equal && !knownLines.Contains(x)))
            {
                var known = knownLines.FirstOrDefault(x => Regex.Replace(x, @"\s", "") == Regex.Replace(line, @"\s", ""));
                if (known != null) report(new("Guard formatting difference", "WARN", "Known guard line " + Array.IndexOf(knownLines, known) + ": leading whitespace " + (known.Length-known.TrimStart().Length) + " -> " + (line.Length-line.TrimStart().Length) + "; CR present: " + line.Contains('\r') + "."));
                else report(new("Guard semantic difference", "WARN", "Unmatched guard line withheld; length " + line.Length + ", SHA-256 " + Hash(Encoding.UTF8.GetBytes(line)) + "."));
            }
        }
        Add("Compatibility classification", CompatibilityCatalog.IsPatched(Hash(bytes)), "Current catalog: " + CompatibilityCatalog.Classify(Hash(bytes)) + ". No catalog changes are made by preflight.");
        Array.Clear(bytes); Array.Clear(stock); Array.Clear(expected);
    }
}
