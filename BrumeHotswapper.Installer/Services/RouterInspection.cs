using System.Text.RegularExpressions;
using System.Text.Json;
using BrumeHotswapper.Installer.Core;
namespace BrumeHotswapper.Installer.Services;

public interface IRouterTransport
{
    Task<string> ExecuteAsync(string command, CancellationToken ct);
    Task UploadAsync(string path, string content, CancellationToken ct);
}
public interface IKillSwitchVerifier { Task VerifyAsync(IRouterTransport router, string policy, CancellationToken ct); }
public sealed class KillSwitchVerifier : IKillSwitchVerifier
{
    // Preserve the selected GL policy; unrelated routing policy is outside this boundary.
    public static async Task<bool> ReadEnabledAsync(IRouterTransport router, string policy, CancellationToken ct)
    {
        var value = (await router.ExecuteAsync($"uci -q get route_policy.{RouterInspection.Identifier(policy)}.killswitch || true", ct)).Trim();
        return value switch { "1" => true, "0" => false, _ => throw new SafeFailure("The selected GL kill-switch setting is unavailable or unsupported.") };
    }
    public async Task VerifyAsync(IRouterTransport router, string policy, CancellationToken ct)
    {
        bool enabled = await ReadEnabledAsync(router, policy, ct);
        policy = RouterInspection.Identifier(policy);
        if ((await router.ExecuteAsync($"uci -q get route_policy.{policy}.enabled || true", ct)).Trim() != "1")
            throw new SafeFailure("The selected VPN policy is disabled.");
        var tunnel = (await router.ExecuteAsync($"uci -q get route_policy.{policy}.tunnel_id", ct)).Trim();
        if (!Regex.IsMatch(tunnel, "^[0-9]+$")) throw new SafeFailure("The selected policy has no valid tunnel identifier.");
        var mark = (await router.ExecuteAsync($"uci -q get route_policy.{policy}.mark", ct)).Trim();
        if (!Regex.IsMatch(mark, "^0x[0-9a-fA-F]{1,8}$")) throw new SafeFailure("The selected policy has no interpretable routing mark.");
        uint selectedMark = Convert.ToUInt32(mark[2..], 16);
        var active = (await router.ExecuteAsync($"uci -q get route_policy.{policy}.via", ct)).Trim();
        // Contract used by hotswapper-main.sh fastpath_mark_for_iface and fastpath_verify_kernel.
        if (!new[] { "wgclient1", "wgclient2", "wgclient3" }.Contains(active) || selectedMark != (uint)(active[^1] - '0') * 0x1000)
            throw new SafeFailure("The selected mark does not match the CURRENT runtime slot.");
        var rules = await router.ExecuteAsync("ip -4 rule show", ct);
        var selected = rules.Split('\n').Where(l => l.Contains($"fwmark {mark}/0xf000 ") && !Regex.IsMatch(l, @"\bnot\b")).ToArray();
        string table = "100" + active[^1];
        if (selected.Length != 1 || !Regex.IsMatch(selected[0], $@"^\s*\d+:\s+from all fwmark {Regex.Escape(mark)}/0xf000 lookup {table}\s*$"))
            throw new SafeFailure("The selected mark does not uniquely map to the expected CURRENT routing table.");
        var routes = await router.ExecuteAsync($"ip -4 route show table {table}", ct);
        var defaults = routes.Split('\n').Select(l => l.Trim()).Where(l => l.StartsWith("default ")).ToArray();
        // Unconditional: OFF never waives CURRENT routing correctness.
        if (defaults.Length != 1 || !Regex.IsMatch(defaults[0], $@"^default dev {Regex.Escape(active)}(?: |$)") || !SelectedRoutesSafe(routes, active))
            throw new SafeFailure("The selected routing table does not route through the expected CURRENT WireGuard interface.");
        if (enabled)
        {
            var chain = "TUNNEL" + tunnel + "_ROUTE_POLICY";
            var firewall = await router.ExecuteAsync($"iptables -w -t mangle -S {chain}", ct);
            if (!HasPolicyRules(firewall, chain, mark))
                throw new SafeFailure("The kill switch is configured, but the selected policy's VPN marking and DROP rules could not be verified.");
            await router.ExecuteAsync($"iptables -w -t mangle -C ROUTE_POLICY -m addrtype ! --dst-type LOCAL -j {chain}", ct);
            if (!routes.Split('\n').Any(l => Regex.IsMatch(l.Trim(), @"^(unreachable|blackhole|prohibit) default(?: |$)")))
                throw new SafeFailure("The enabled GL kill switch has no terminal protection in the selected VPN table.");
        }
    }
    private static bool SelectedRoutesSafe(string routes, string active)
    {
        foreach (var line in routes.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.Trim()))
        {
            if (Regex.IsMatch(line, @"^(unreachable|blackhole|prohibit|local|broadcast) ")) continue;
            if (Regex.IsMatch(line, @"^(throw|unicast|nat|multicast) ") ||
                !Regex.IsMatch(line, $@"\bdev {Regex.Escape(active)}(?: |$)") ||
                Regex.IsMatch(line, @"\b(via|nexthop|encap)\b")) return false;
        }
        return true;
    }
    public static bool HasPolicyRules(string output, string chain, string mark)
    {
        var rules = output.Split('\n').Select(l => Regex.Replace(l.Trim(), " -m comment --comment \"[^\"]*\"", ""))
            .Where(l => l.StartsWith("-A " + chain + " ")).ToArray();
        // A paired scope is essential: a DROP for another destination set proves nothing.
        if (rules.Length != 2) return false;
        string prefix = "-A " + chain + " ", suffix = " -j MARK --set-xmark " + mark + "/0xf000";
        if (!rules[0].EndsWith(suffix)) return false;
        var scope = rules[0][prefix.Length..^suffix.Length];
        return scope.StartsWith("-m mark --mark 0x0/0xf000") &&
            !scope.Contains(" -j ") && !scope.Contains(" -g ") && rules[1] == prefix + scope + " -j DROP";
    }

}
public sealed class RouterInspection(IRouterTransport router, IKillSwitchVerifier killSwitch)
{
    public static bool IsPolicyIdentifier(string id) => Regex.IsMatch(id, @"^([A-Za-z0-9_]+|@rule\[[0-9]+\])$");
    public static string Identifier(string id)
    {
        if (!IsPolicyIdentifier(id)) throw new SafeFailure("An unsupported router identifier was returned.");
        return id.StartsWith('@') ? ConfigurationGenerator.Quote(id) : id;
    }
    private async Task<(string Address,string Mask)> LanAddressAsync(CancellationToken ct) =>
        ((await router.ExecuteAsync("uci -q get network.lan.ipaddr",ct)).Trim(),
         (await router.ExecuteAsync("uci -q get network.lan.netmask",ct)).Trim());
    public async Task<LanInventory> LanAsync(CancellationToken ct)
    {
        var (address, mask) = await LanAddressAsync(ct);
        string start = (await router.ExecuteAsync("uci -q get dhcp.lan.start", ct)).Trim();
        string limit = (await router.ExecuteAsync("uci -q get dhcp.lan.limit", ct)).Trim();
        if (!System.Net.IPAddress.TryParse(address, out var lanAddress) || lanAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            !System.Net.IPAddress.TryParse(mask, out var lanMask) || lanMask.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            !int.TryParse(start, out int poolStart) || !int.TryParse(limit, out int poolLimit) || poolStart < 0 || poolLimit < 0)
            throw new SafeFailure("The LAN IPv4 subnet and DHCP pool could not be read. Multi-subnet or nonstandard LAN layouts require review.");
        var network = new LanNetwork(address, mask, poolStart, poolLimit);
        var reservations = new List<Reservation>();
        var sections = await router.ExecuteAsync("uci -q show dhcp | sed -n 's/^dhcp\\.\\([^.=]*\\)=host$/\\1/p'", ct);
        foreach (var section in sections.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!Regex.IsMatch(section, @"^([A-Za-z0-9_]+|@host\[[0-9]+\])$")) continue;
            var macs = (await router.ExecuteAsync($"uci -q get 'dhcp.{section}.mac' || true", ct)).Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var ip = (await router.ExecuteAsync($"uci -q get 'dhcp.{section}.ip' || true", ct)).Trim();
            foreach (var mac in macs)
            {
                try { ConfigurationGenerator.ValidateDevice(mac, ip); reservations.Add(new(section, mac.ToLowerInvariant(), ip)); }
                catch (SafeFailure) { throw new SafeFailure("A DHCP host entry uses an unsupported MAC/address format. Resolve it before configuring maintenance guards."); }
            }
        }
        var observations = reservations.Select(r => new LanClient("Reservation", r.Ip, r.Mac, true)).ToList();
        var clients = new Dictionary<string, LanClient>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in reservations.Where(r => network.ContainsHost(r.Ip))) clients[r.Mac] = new("Reserved device", r.Ip, r.Mac, true);
        var leases = await router.ExecuteAsync("if [ -r /tmp/dhcp.leases ]; then cat /tmp/dhcp.leases; fi", ct);
        foreach (var line in leases.Split('\n'))
        {
            var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (f.Length < 4 || !network.ContainsHost(f[2])) continue;
            try {
                ConfigurationGenerator.ValidateDevice(f[1], f[2]);
                observations.Add(new("Lease (presence unconfirmed)", f[2], f[1]));
                var reserved = reservations.FirstOrDefault(r => r.Mac.Equals(f[1], StringComparison.OrdinalIgnoreCase));
                clients[f[1]] = new(f[3] == "*" ? "Unnamed device" : f[3], reserved?.Ip ?? f[2], f[1], reserved != null);
            } catch (SafeFailure) { }
        }
        var neighbors = await router.ExecuteAsync("ip -4 neigh show", ct);
        foreach (var line in neighbors.Split('\n'))
        {
            var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries); int at = Array.IndexOf(f, "lladdr");
            if (at < 0 || at + 1 >= f.Length || !network.ContainsHost(f[0])) continue;
            try { ConfigurationGenerator.ValidateDevice(f[at + 1], f[0]); var observed = new LanClient("Neighbour (presence unconfirmed)", f[0], f[at + 1]); observations.Add(observed); clients.TryAdd(f[at + 1], observed); } catch (SafeFailure) { }
        }
        var local = await router.ExecuteAsync("ip -o -4 addr show | awk '{print $4}'", ct);
        var owned = local.Split('\n').Select(l => l.Split('/')[0]).ToHashSet();
        return new(network, clients.Values.Where(c => !owned.Contains(c.Ip)).OrderBy(c => c.Hostname).ToArray(), reservations, observations, owned.ToArray());
    }
    public async Task<(string CurrentInterface,string CurrentPeer)> VerifyPolicySlotsAsync(VpnProfile profile,CancellationToken ct)
    {
        var policy = Identifier(profile.PolicySection);
        string group = (await router.ExecuteAsync($"uci -q get route_policy.{policy}.group_id", ct)).Trim();
        string tunnel = (await router.ExecuteAsync($"uci -q get route_policy.{policy}.tunnel_id", ct)).Trim();
        if (group != profile.GroupId || tunnel != profile.TunnelId) throw new SafeFailure("The selected VPN list changed. Discover it again.");
        var active = (await router.ExecuteAsync($"uci -q get route_policy.{policy}.via", ct)).Trim();
        var activePeer = (await router.ExecuteAsync($"uci -q get route_policy.{policy}.peer_id", ct)).Trim();
        if (!new[] {"wgclient1", "wgclient2", "wgclient3"}.Contains(active))
            throw new SafeFailure("The selected VPN must be active on a supported WireGuard instance before installation.");
        foreach (var slot in new[] {"wgclient1", "wgclient2", "wgclient3"})
        {
            var other = (await router.ExecuteAsync($"uci -q show route_policy | sed -n \"s/^route_policy\\.\\([^.=]*\\)\\.via='{slot}'$/\\1/p\"", ct)).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var reference in other.Where(s => s != profile.PolicySection))
            {
                // Firmware handle_always_vpn_policy maintains this process rule for the active VPN.
                bool generated = reference == "gl_process_vpn" && slot == active &&
                    (await router.ExecuteAsync("uci -q get route_policy.gl_process_vpn", ct)).Trim() == "rule_process" &&
                    (await router.ExecuteAsync("uci -q get route_policy.gl_process_vpn.group_id || true", ct)).Trim().Length == 0;
                if (!generated) throw new SafeFailure($"WireGuard instance {slot} is referenced by another VPN policy.");
            }
            var config = (await router.ExecuteAsync($"uci -q get network.{slot}.config || true", ct)).Trim();
            if (config.Length == 0)
            {
                if ((await router.ExecuteAsync($"if ip link show {slot} >/dev/null 2>&1; then echo present; fi", ct)).Trim() == "present")
                    throw new SafeFailure($"WireGuard instance {slot} has unrecognized runtime ownership. Disconnect the unrelated VPN.");
                continue;
            }
            if (!Regex.IsMatch(config, "^peer_[0-9]+$")) throw new SafeFailure($"WireGuard instance {slot} belongs to an unsupported VPN configuration.");
            var owner = (await router.ExecuteAsync($"uci -q get wireguard.{config}.group_id", ct)).Trim();
            if (owner != group) throw new SafeFailure($"WireGuard instance {slot} is occupied by another VPN list. Disconnect it before installing.");

        }
        if ((await router.ExecuteAsync($"uci -q get network.{active}.config", ct)).Trim() != "peer_" + activePeer)
            throw new SafeFailure("The active VPN policy and WireGuard instance disagree. Reconnect the selected VPN first.");
        return (active,activePeer);
    }
    public async Task<RouterSnapshot> InspectAsync(InstallerConfiguration c, CancellationToken ct)
    {
        string operation = "device identity and firmware";
        try
        {
            ConfigurationGenerator.Validate(c);
            using var board = JsonDocument.Parse(await router.ExecuteAsync("ubus call system board", ct));
            var live = c.Router with { Model = board.RootElement.GetProperty("model").GetString() ?? "", Board = board.RootElement.GetProperty("board_name").GetString() ?? "" };
            if (!live.IsBrume) throw new SafeFailure("The connected device is not a GL-MT5000.");
            live = live with { Rtp2Hash = (await router.ExecuteAsync("sha256sum /usr/bin/rtp2.sh | awk '{print $1}'", ct)).Trim() };
            await RouterPrerequisites.VerifyFirmwareAsync(router, live, ct);
            await RouterPrerequisites.VerifyCapabilitiesAsync(router, ct);
            operation = "VPN policy, slot ownership and profile membership";
            var (active, activePeer) = await VerifyPolicySlotsAsync(c.Profile, ct);
            var policy = Identifier(c.Profile.PolicySection);
            string group = c.Profile.GroupId, tunnel = c.Profile.TunnelId;
            var members = ConfigurationGenerator.Locations(c).Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.Split('\t')[5]).ToHashSet();
            if (!members.Contains(activePeer)) throw new SafeFailure("The currently active VPN location must be assigned to a tier before installation.");
            foreach (var peer in c.Tiers.Where(t => t.Tier > 0).SelectMany(t => t.Locations).SelectMany(g => g.Connections))
            {
                var owner = (await router.ExecuteAsync($"uci -q get wireguard.peer_{peer.PeerId}.group_id", ct)).Trim();
                var location = (await router.ExecuteAsync($"uci -q get wireguard.peer_{peer.PeerId}.location", ct)).Trim();
                if (owner != group || ExactLocationResolver.Normalize(location) != ExactLocationResolver.Normalize(peer.Location))
                    throw new SafeFailure("VPN pool membership changed. Discover VPN lists again.");
                await router.ExecuteAsync($"grep -Fxq '{c.Profile.GroupId}_{peer.PeerId}' /etc/vpn_profiles.d/profile{tunnel}", ct);
            }
            operation = "IPv6 configuration";
            await Ipv6Compatibility.VerifyAsync(router, ct);
            operation = "selected VPN routing and GL enforcement";
            await killSwitch.VerifyAsync(router, c.Profile.PolicySection, ct);
            bool killSwitchEnabled = await KillSwitchVerifier.ReadEnabledAsync(router, c.Profile.PolicySection, ct);
            operation = "pending DHCP changes";
            await router.ExecuteAsync("test -z \"$(uci changes dhcp)\"", ct);
            operation = "installed file metadata";
            var files = new List<FileState>();
            foreach (var path in DeploymentPlanning.Paths)
            {
                files.Add(FileMetadata.Validate(path, await FileMetadata.ReadAsync(router, path, ct)));
            }
            operation = "cron and daemon ownership";
            var cron = await router.ExecuteAsync("crontab -l 2>/dev/null || true", ct);
            _ = CronPlanner.Generate(cron, c.Maintenance);
            var pids = await DaemonPidsAsync(ct);
            operation = "LAN and maintenance guards";
            return new(live, c.Profile.PolicySection, active, activePeer, cron, (c.Guards.Count > 0 ? await LanAsync(ct) : new LanInventory(new("0.0.0.0", "0.0.0.0", 0, 0), [], [])), files, pids.Length > 0, killSwitchEnabled);
        }
        catch (RouterCommandFailure e) { throw new SafeFailure($"Router inspection failed: {operation} (exit status {e.ExitStatus?.ToString() ?? "unknown"}); output withheld."); }
    }
    public async Task<string[]> DaemonPidsAsync(CancellationToken ct) =>
        (await new HotswapRuntime(router).ReadAsync(ct)).Where(p=>p.Kind=="daemon").Select(p=>p.Pid).ToArray();
}
