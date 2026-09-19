using System.Net;
namespace BrumeHotswapper.Installer.Core;
public record LanNetwork(string Address, string Netmask, int PoolStart, int PoolLimit)
{
    private static uint Number(string value) => BitConverter.ToUInt32(IPAddress.Parse(value).GetAddressBytes().Reverse().ToArray());
    public bool ContainsHost(string ip)
    {
        if (!IPAddress.TryParse(ip, out var parsed) || parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        if (!IPAddress.TryParse(Address, out var address) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            !IPAddress.TryParse(Netmask, out var netmask) || netmask.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        uint mask = Number(Netmask), router = Number(Address), candidate = Number(ip), network = router & mask, inverse = ~mask;
        return (inverse & (inverse + 1)) == 0 && candidate != router && candidate != network && candidate != (network | inverse) && (candidate & mask) == network;
    }
}
public record LanInventory(LanNetwork Network, IReadOnlyList<LanClient> Clients, IReadOnlyList<Reservation> Reservations, IReadOnlyList<LanClient>? Observations = null, IReadOnlyList<string>? RouterAddresses = null);
public record FileState(string Path, string Hash, string Mode, bool Exists);
public record RouterSnapshot(RouterIdentity Router, string Policy, string CurrentInterface, string CurrentPeer,
    string Cron, LanInventory Lan, IReadOnlyList<FileState> Files, bool WatchdogRunning, bool KillSwitchEnabled = true);
public record InstallationPlan(InstallerConfiguration Configuration, RouterSnapshot Snapshot,
    IReadOnlyList<ReservationChange> Reservations, string DesiredCron, string GuardAction, IReadOnlyList<string> Changes)
{
    public override string ToString() => "Installation plan (private configuration omitted)";
}
public static class DeploymentPlanning
{
    public static readonly string[] Paths = ["/root/hotswapper-main.sh", "/root/hotswapper-supervisor.sh", "/root/hotswapper-housekeeping.sh",
        "/root/hotswapper/hotswapper.conf", "/root/hotswapper/hotswapper-locations.tsv", "/root/hotswapper/reboot-guards.tsv", "/root/hotswapper/housekeeping.conf", "/root/hotswapper/install-gl-guard.sh", "/root/hotswapper/gl-coordination.sh", "/root/hotswapper/gl-patches.awk", "/root/hotswapper/gl-targets.tsv", .. FirmwareTargets.All.Select(t => t.Path)];
    public static InstallationPlan Create(InstallerConfiguration config, RouterSnapshot snapshot)
    {
        ConfigurationGenerator.Validate(config);
        var frozen = config.Tiers.Select(t => { var copy = new TierColumn(t.Title, t.Tier); foreach (var g in t.Locations) copy.Locations.Add(g); return copy; }).ToArray();
        config = config with { Tiers = frozen, Router = snapshot.Router };
        var reservations = DhcpPlanner.Plan(config.Guards, snapshot.Lan.Reservations, snapshot.Lan.Observations ?? snapshot.Lan.Clients, snapshot.Lan.Network.Address);
        foreach (var r in reservations)
            if (!snapshot.Lan.Network.ContainsHost(r.Ip) || snapshot.Lan.RouterAddresses?.Contains(r.Ip) == true) throw new SafeFailure("A protected device address is outside the usable LAN subnet. Refresh LAN discovery.");
        var c = config with { Guards = reservations.Select(r => new LanClient("", r.Ip, r.Mac, !r.Create)).ToArray() };
        var guard = snapshot.Files.Where(f => FirmwareTargets.Find(f.Path) != null).All(f => f.Hash == FirmwareTargets.Find(f.Path)!.PatchedHash)
            ? "Already installed â€” no change" : "Install owned-VPN coordination patches";
        var changes = snapshot.Files.Where(f => FirmwareTargets.Find(f.Path) == null).Select(f => $"{(f.Exists ? "Update" : "Install")} {f.Path}").ToList();
        changes.Add(guard);
        changes.AddRange(reservations.Select(r => $"{(r.Create ? "Create" : "Reuse")} DHCP reservation: {r.Mac} â†’ {r.Ip}"));
        changes.Add("Ensure supervisor schedule occurs once (every five minutes)");
        changes.Add(c.Maintenance ? $"Ensure hourly maintenance schedule; reboot window {c.RebootWindowStart:00}:00â€“{c.RebootWindowEnd:00}:00, router time" : "Remove the owned maintenance schedule");
        changes.Add(snapshot.WatchdogRunning ? "Restart the existing Hotswapper via supervisor" : "Start Hotswapper via supervisor");
        return new(c, snapshot, reservations, CronPlanner.Generate(snapshot.Cron, c.Maintenance), guard, changes);
    }
    public static string RestoreOwnedCron(string current, string original)
    {
        static bool Owned(string line) => CronPlanner.IsOwned(line);
        var other = current.Replace("\r", "").Split('\n').Where(l => l.Length > 0 && !Owned(l));
        var oldOwned = original.Replace("\r", "").Split('\n').Where(Owned).Distinct();
        return string.Join('\n', other.Concat(oldOwned)) + "\n";
    }
}
public static class RuntimeValidation
{
    public static bool ValidStatus(string output) =>
        System.Text.RegularExpressions.Regex.IsMatch(output, @"(?m)^CURRENT:\s+wgclient[123] peer=[0-9]+(?: |$)") &&
        System.Text.RegularExpressions.Regex.IsMatch(output, @"(?m)^UPTIER:\s+.+$") &&
        System.Text.RegularExpressions.Regex.IsMatch(output, @"(?m)^DOWNTIER:\s+.+$");
    public static bool IsHealthy(string snapshot, InstallerConfiguration c)
    {
        var rows = snapshot.Split('\n').Where(l => l.Contains('=')).Select(l => l.Split('=', 2)).ToArray();
        if (rows.GroupBy(r => r[0]).Any(g => g.Count() != 1)) return false;
        var values = rows.ToDictionary(r => r[0], r => r[1].Trim());
        string Get(string key) => values.GetValueOrDefault(key, "");
        var slots = new[] { "wgclient1", "wgclient2", "wgclient3" };
        var mapping = ConfigurationGenerator.Locations(c).Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.Split('\t')).ToArray();
        var current = mapping.SingleOrDefault(r => r[5] == Get("current_peer"));
        if (current == null || !slots.Contains(Get("current_iface")) || current[0] != Get("current_rank") || current[1] != Get("current_tier")) return false;
        var used = new[] { Get("current_iface"), Get("uptier_iface"), Get("downtier_iface") }.Where(s => s.Length > 0).ToArray();
        if (used.Distinct().Count() != used.Length || used.Any(s => !slots.Contains(s))) return false;
        int rank = int.Parse(current[0]), tier = int.Parse(current[1]);
        int next = mapping.Select(r => int.Parse(r[0])).Distinct().Order().FirstOrDefault(r => r > rank);
        foreach (var role in new[] { "uptier", "downtier" })
        {
            if (Get(role + "_iface").Length == 0)
            {
                if (Get(role + "_peer").Length > 0 || !new[] { "", "0" }.Contains(Get(role + "_rank")) || !new[] { "", "0" }.Contains(Get(role + "_tier"))) return false;
                continue;
            }
            var candidate = mapping.SingleOrDefault(r => r[5] == Get(role + "_peer"));
            if (candidate == null || candidate[0] != Get(role + "_rank") || candidate[1] != Get(role + "_tier")) return false;
            if (role == "downtier" ? int.Parse(candidate[0]) != next : tier == 1 || int.Parse(candidate[0]) >= rank || int.Parse(candidate[1]) > 2) return false;
        }
        // An established UPTIER replaces DOWNTIER; a spare slot is not a role.
        return Get("uptier_iface").Length == 0 || Get("downtier_iface").Length == 0;
    }
}
