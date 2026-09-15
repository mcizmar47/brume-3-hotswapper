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
public record RouterSnapshot(RouterIdentity Router, string Policy, string ActiveInterface, string ActivePeer,
    string Cron, LanInventory Lan, IReadOnlyList<FileState> Files, bool WatchdogRunning);
public record InstallationPlan(InstallerConfiguration Configuration, RouterSnapshot Snapshot,
    IReadOnlyList<ReservationChange> Reservations, string DesiredCron, string GuardAction, IReadOnlyList<string> Changes)
{
    public override string ToString() => "Installation plan (private configuration omitted)";
}
public static class DeploymentPlanning
{
    public static readonly string[] Paths = ["/root/vpn-watch.sh", "/root/vpn-watch-supervisor.sh", "/root/conditional-reboot.sh",
        "/root/vpn-watch.conf", "/root/vpn-watch-locations.tsv", "/root/reboot-guards.tsv", "/root/install-vpn-watch-gl-guard.sh", "/usr/bin/rtp2.sh"];
    public static InstallationPlan Create(InstallerConfiguration config, RouterSnapshot snapshot)
    {
        ConfigurationGenerator.Validate(config);
        var frozen = config.Tiers.Select(t => { var copy = new TierColumn(t.Title, t.Tier); foreach (var g in t.Locations) copy.Locations.Add(g); return copy; }).ToArray();
        config = config with { Tiers = frozen };
        var reservations = DhcpPlanner.Plan(config.Guards, snapshot.Lan.Reservations, snapshot.Lan.Observations ?? snapshot.Lan.Clients, snapshot.Lan.Network.Address);
        foreach (var r in reservations)
            if (!snapshot.Lan.Network.ContainsHost(r.Ip) || snapshot.Lan.RouterAddresses?.Contains(r.Ip) == true) throw new SafeFailure("A protected device address is outside the usable LAN subnet. Refresh LAN discovery.");
        var c = config with { Guards = reservations.Select(r => new LanClient("", r.Ip, r.Mac, !r.Create)).ToArray() };
        var guard = CompatibilityCatalog.Classify(snapshot.Router.Rtp2Hash) == Compatibility.AlreadyPatchedKnownCompatible
            ? "Already installed — no change" : "Install structural reconciliation guard";
        var changes = snapshot.Files.Where(f => f.Path != "/usr/bin/rtp2.sh").Select(f => $"{(f.Exists ? "Update" : "Install")} {f.Path}").ToList();
        changes.Add(guard);
        changes.AddRange(reservations.Select(r => $"{(r.Create ? "Create" : "Reuse")} DHCP reservation: {r.Mac} → {r.Ip}"));
        changes.Add("Ensure supervisor schedule occurs once (every five minutes)");
        changes.Add(c.Maintenance ? "Ensure maintenance schedule occurs once (03:00–14:00 hourly)" : "Remove the owned maintenance schedule");
        changes.Add(snapshot.WatchdogRunning ? "Restart the existing watchdog via supervisor" : "Start watchdog via supervisor");
        return new(c, snapshot, reservations, CronPlanner.Generate(snapshot.Cron, c.Maintenance), guard, changes);
    }
    public static string RestoreOwnedCron(string current, string original)
    {
        static bool Owned(string line) => line.Trim() == CronPlanner.Supervisor || line.Trim() == CronPlanner.Maintenance;
        var other = current.Replace("\r", "").Split('\n').Where(l => l.Length > 0 && !Owned(l));
        var oldOwned = original.Replace("\r", "").Split('\n').Where(Owned).Distinct();
        return string.Join('\n', other.Concat(oldOwned)) + "\n";
    }
}
public static class RuntimeValidation
{
    public static bool IsHealthy(string snapshot, InstallerConfiguration c)
    {
        var rows = snapshot.Split('\n').Where(l => l.Contains('=')).Select(l => l.Split('=', 2)).ToArray();
        if (rows.GroupBy(r => r[0]).Any(g => g.Count() != 1)) return false;
        var values = rows.ToDictionary(r => r[0], r => r[1].Trim());
        string Get(string key) => values.GetValueOrDefault(key, "");
        var slots = new[] { "wgclient1", "wgclient2", "wgclient3" };
        var tierRows = ConfigurationGenerator.Locations(c).Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.Split('\t')).ToArray();
        var active = tierRows.SingleOrDefault(r => r[5] == Get("active_peer"));
        if (active == null || !slots.Contains(Get("active_iface")) || active[0] != Get("active_rank") || active[1] != Get("active_tier")) return false;
        var used = new[] { Get("active_iface"), Get("standby_iface"), Get("recovery_iface") }.Where(s => s.Length > 0).ToArray();
        if (used.Distinct().Count() != used.Length || used.Any(s => !slots.Contains(s))) return false;
        var next = tierRows.Select(r => int.Parse(r[0])).Distinct().Order().FirstOrDefault(r => r > int.Parse(active[0]));
        if (Get("standby_iface").Length > 0)
        {
            var standby = tierRows.SingleOrDefault(r => r[5] == Get("standby_peer"));
            if (standby == null || int.Parse(standby[0]) != next || Get("standby_rank") != standby[0] || Get("standby_tier") != standby[1] || !slots.Contains(Get("standby_iface"))) return false;
        }
        else if (Get("standby_peer").Length > 0 || !new[] { "", "0" }.Contains(Get("standby_rank")) || !new[] { "", "0" }.Contains(Get("standby_tier"))) return false;
        // reconcile_roles may publish no PRECOOKED during backoff or preparation failure.
        // RECOVERY denotes the remaining slot, not a guaranteed healthy connection.
        return slots.Contains(Get("recovery_iface"));
    }
}
