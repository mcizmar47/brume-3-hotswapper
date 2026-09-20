using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace BrumeHotswapper.Installer.Core;

public static class CompatibilityCatalog
{
    public const string StockHash = "749518706ad6af15104c90ddba5aa99142e1a9c678fec9074cd4222f8595f82c";
    public static readonly HashSet<string> TestedFirmware = ["4.9.0"];
    // Current-layout guard hash reproduced from the archived stock firmware.
    public const string PreviousGuardHash = "5c4b26eebdd3cdb6876b7b5e9f48901d8061b525837c1d879f0d059d856f150c";
    public const string PatchedHash = "84339bc25c130a0c2b31dae698bae1b224d0fc58074964a0ade37a8b84b060e1";
    public static bool IsPatched(string hash) => Classify(hash) is Compatibility.AlreadyPatchedKnownCompatible;
    public static readonly HashSet<string> IncompatibleHashes = new(StringComparer.OrdinalIgnoreCase);
    public static Compatibility Classify(string hash) => IncompatibleHashes.Contains(hash) ? Compatibility.KnownIncompatible
        : hash.Equals(StockHash, StringComparison.OrdinalIgnoreCase) ? Compatibility.StockKnownCompatible
        : (hash.Equals(PatchedHash, StringComparison.OrdinalIgnoreCase) || hash.Equals(PreviousGuardHash, StringComparison.OrdinalIgnoreCase)) ? Compatibility.AlreadyPatchedKnownCompatible : Compatibility.Unknown;
}
public interface IVpnLocationResolver { IReadOnlyList<VpnLocationGroup> Group(IEnumerable<VpnConnection> peers); }
// Verified GL 4.9.0 country,city metadata. Identity is scoped to this provider layout,
// not asserted to be a globally immutable provider identifier. No fuzzy matching.
public class ExactLocationResolver : IVpnLocationResolver
{
    public static string Normalize(string location) => string.Join(",", location.Split(',').Select(s => s.Trim().Normalize(NormalizationForm.FormC)));
    public IReadOnlyList<VpnLocationGroup> Group(IEnumerable<VpnConnection> peers) => peers
        .GroupBy(p => string.IsNullOrWhiteSpace(p.Location) ? "Unresolved peer " + p.PeerId : Normalize(p.Location), StringComparer.Ordinal)
        .Select(g => new VpnLocationGroup(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(g.Key))).ToLowerInvariant(),
            g.Key.Replace(",", " / "), g.ToArray())).OrderBy(g => g.Label, StringComparer.Ordinal).ToArray();
}
public static class ConfigurationGenerator
{
    public static string Quote(string value) => "'" + value.Replace("'", "'\"'\"'") + "'";
    public static void Validate(InstallerConfiguration c)
    {
        if (c.RebootWindowStart is < 0 or > 23 || c.RebootWindowEnd is < 0 or > 23 || c.RebootWindowStart > c.RebootWindowEnd)
            throw new SafeFailure("Maintenance hours must be 00–23 with From no later than To (same-day window).");
        if (!c.Router.IsBrume) throw new SafeFailure("Installation is supported only on GL-MT5000.");
        if (CompatibilityCatalog.Classify(c.Router.Rtp2Hash) == Compatibility.KnownIncompatible) throw new SafeFailure("This firmware reconciliation script is incompatible.");
        if (!Regex.IsMatch(c.Profile.TunnelId, "^[0-9]+$") || !Regex.IsMatch(c.Profile.GroupId, "^[0-9]+$")) throw new SafeFailure("VPN identifiers are invalid.");
        if (c.Tiers.Count != 4 || !c.Tiers.Select(t => t.Tier).Order().SequenceEqual(new[] { 0, 1, 2, 3 })) throw new SafeFailure("Invalid tier layout.");
        if (!c.Tiers.Single(t => t.Tier == 1).Locations.Any()) throw new SafeFailure("Assign at least one location to Tier 1.");
        var seen = new HashSet<string>();
        foreach (var t in c.Tiers.Where(t => t.Tier > 0))
        foreach (var g in t.Locations)
        {
            if (g.Connections.Count == 0 || g.Label.StartsWith("Unresolved peer ", StringComparison.Ordinal)) throw new SafeFailure("Unresolved locations must remain unassigned.");
            if (g.Label.IndexOfAny(['\t', '\r', '\n', '\0']) >= 0) throw new SafeFailure("A location label contains unsupported characters.");
            foreach (var p in g.Connections)
                if (!Regex.IsMatch(p.PeerId, "^[0-9]+$") || !seen.Add(p.PeerId) || !c.Profile.Connections.Contains(p)) throw new SafeFailure("Invalid or duplicate VPN pool membership.");
        }
        if (c.Notifications) _ = NtfyTopic.Normalize(c.NtfyUrl);
        foreach (var d in c.Guards) ValidateDevice(d.Mac, d.Ip);
    }
    public static void ValidateDevice(string mac, string ip)
    {
        if (!Regex.IsMatch(mac, "^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$") || !IPAddress.TryParse(ip, out var address)
            || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) throw new SafeFailure("Invalid reboot guard address.");
    }
    // TSV is data, never sourced as shell. Rank is independent of major tier and supports arbitrary tier sizes.
    public static string Locations(InstallerConfiguration c)
    {
        Validate(c); var result = new StringBuilder(); int rank = 0;
        foreach (var t in c.Tiers.Where(t => t.Tier > 0).OrderBy(t => t.Tier))
        { int order = 0; foreach (var g in t.Locations) { rank++; order++;
            foreach (var p in g.Connections) result.AppendLine($"{rank}\t{t.Tier}\t{order}\t{g.Id}\t{g.Label}\t{p.PeerId}"); } }
        return result.ToString().Replace("\r\n", "\n");
    }
    public static string PrivateConfig(InstallerConfiguration c)
    { Validate(c); return ConfigTemplates.Replace(ConfigTemplates.Read("hotswapper.conf"),
        ("TUNNEL_ID", Quote(c.Profile.TunnelId)), ("GROUP_ID", Quote(c.Profile.GroupId)),
        ("NTFY_URL", Quote(c.Notifications ? NtfyTopic.Normalize(c.NtfyUrl) : ""))); }
    public static string Housekeeping(InstallerConfiguration c)
    { Validate(c); return ConfigTemplates.Replace(ConfigTemplates.Read("housekeeping.conf"),
        ("REBOOT_WINDOW_START", c.RebootWindowStart.ToString()), ("REBOOT_WINDOW_END", c.RebootWindowEnd.ToString())); }
    public static string Guards(InstallerConfiguration c) => string.Join("", c.Guards.Select(d => $"{d.Mac.ToLowerInvariant()}\t{d.Ip}\n"));
}
public static class CronPlanner
{
    public const string Supervisor = "*/5 * * * * /root/hotswapper-supervisor.sh";
    public const string Maintenance = "0 * * * * /root/hotswapper-housekeeping.sh";
    public const string PreviousMaintenance = "0 3-14 * * * /root/hotswapper-housekeeping.sh";
    public static bool IsOwned(string line) => line.Trim() is Supervisor or Maintenance or PreviousMaintenance;
    public static string Generate(string existing, bool maintenance)
    {
        var lines = existing.Replace("\r", "").Split('\n').Where(l => l.Length > 0 && !IsOwned(l)).ToList();
        // Refuse ambiguous owned entries instead of deleting unrelated commands that happen to mention a script.
        if (lines.Any(l => !l.TrimStart().StartsWith('#') && (l.Contains("/root/hotswapper-supervisor.sh") || l.Contains("/root/hotswapper-housekeeping.sh"))))
            throw new SafeFailure("A custom cron command references Hotswapper. Resolve it before installation.");
        lines.Add(Supervisor); if (maintenance) lines.Add(Maintenance); return string.Join('\n', lines) + "\n";
    }
}
public static class DhcpPlanner
{
    public static IReadOnlyList<ReservationChange> Plan(IEnumerable<LanClient> selected, IReadOnlyList<Reservation> existing,
        IReadOnlyList<LanClient> clients, string routerIp)
    {
        var result = new List<ReservationChange>();
        foreach (var d in selected)
        {
            ConfigurationGenerator.ValidateDevice(d.Mac, d.Ip);
            if (d.Ip == routerIp) throw new SafeFailure("The router cannot be a reboot guard.");
            var matches = existing.Where(r => r.Mac.Equals(d.Mac, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (matches.Length > 1) throw new SafeFailure("Duplicate DHCP reservations require review.");
            string ip = matches.SingleOrDefault()?.Ip ?? d.Ip;
            if (existing.Any(r => r.Ip == ip && !r.Mac.Equals(d.Mac, StringComparison.OrdinalIgnoreCase))
                || clients.Any(r => r.Ip == ip && !r.Mac.Equals(d.Mac, StringComparison.OrdinalIgnoreCase))
                || result.Any(r => r.Ip == ip || r.Mac.Equals(d.Mac, StringComparison.OrdinalIgnoreCase))) throw new SafeFailure("DHCP address conflict detected.");
            result.Add(new(d.Mac, ip, matches.Length == 0));
        }
        return result;
    }
}
public static class InstallationPlanner
{
    public static IReadOnlyList<InstallationStep> Create(InstallerConfiguration c)
    {
        ConfigurationGenerator.Validate(c);
        var names = new List<string> { "Router prerequisites", "Revalidate identity and compatibility", "Back up affected files",
            "Upload Hotswapper, supervisor and housekeeping", "Install private configuration and location pools" };
        if (c.Maintenance && c.Guards.Count > 0) names.Add("Validate and reserve reboot guard addresses");
        names.AddRange(["Apply structural GL reconciliation guard", "Update owned cron entries", "Restart supervisor", "Validate runtime and kill switch"]);
        return names.Select((n, i) => new InstallationStep(n, i >= 2)).ToArray();
    }
}
// Reports accept only predefined status messages, never remote stdout/stderr or exception text.
public class DiagnosticLog
{
    private readonly List<string> entries = [];
    public void Add(string safeMessage) => entries.Add($"{DateTimeOffset.Now:HH:mm:ss} {safeMessage}");
    public string Report(bool demo) => $"Brume 3 Hotswapper installation report\nMode: {(demo ? "DEMO — no router operations" : "Real")}\n" + string.Join('\n', entries);
    public static string Redact(string text, params string[] secrets)
    {
        foreach (var secret in secrets.Where(s => !string.IsNullOrEmpty(s)).OrderByDescending(s => s.Length)) text = text.Replace(secret, "[redacted]", StringComparison.Ordinal);
        text = Regex.Replace(text, @"https?://[^\s'""<>]+", "[private URL]");
        return Regex.Replace(text, @"(?im)^.*(?:private.?key|password|token|credential|NTFY_URL).*$", "[sensitive line removed]");
    }
}
