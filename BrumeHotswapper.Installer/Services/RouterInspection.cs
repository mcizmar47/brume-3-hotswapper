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
    // The supplied reconnaissance does not name a kill-switch UCI option.
    // A terminal route is a kernel-enforced no-fallback invariant for this mark.
    // Other firewall layouts need explicit evidence, never a guessed UCI field.
    public async Task VerifyAsync(IRouterTransport router, string policy, CancellationToken ct)
    {
        var mark = (await router.ExecuteAsync($"uci -q get route_policy.{policy}.mark", ct)).Trim();
        if (!Regex.IsMatch(mark, "^0x[0-9a-fA-F]+$")) throw new SafeFailure("The selected VPN policy has no interpretable routing mark. Enable its connection in the GL panel and retry.");
        var active = (await router.ExecuteAsync($"uci -q get route_policy.{policy}.via", ct)).Trim();
        var rules = await router.ExecuteAsync("ip -4 rule show", ct);
        foreach (var rule in rules.Split('\n').Where(l => l.Contains($"fwmark {mark}/0xf000 ")))
        {
            var table = Regex.Match(rule, $@"^\s*(\d+):\s+from all fwmark {Regex.Escape(mark)}/0xf000 lookup (\d+)\s*$");
            if (!table.Success || int.Parse(table.Groups[1].Value) >= 32766) continue;
            int priority = int.Parse(table.Groups[1].Value);
            bool ambiguousEarlier = rules.Split('\n').Where(l => l.Contains(':')).Any(l =>
            {
                if (!int.TryParse(l.Split(':')[0].Trim(), out var earlier) || earlier >= priority || l.TrimEnd().EndsWith("lookup local")) return false;
                var otherMark = Regex.Match(l, @"fwmark (0x[0-9a-fA-F]+)/(0x[0-9a-fA-F]+)");
                if (otherMark.Success)
                {
                    uint actual = Convert.ToUInt32(mark[2..], 16), value = Convert.ToUInt32(otherMark.Groups[1].Value[2..], 16), mask = Convert.ToUInt32(otherMark.Groups[2].Value[2..], 16);
                    if ((actual & mask) != (value & mask)) return false;
                }
                return true;
            });
            if (ambiguousEarlier) continue;
            var routes = await router.ExecuteAsync($"ip -4 route show table {table.Groups[2].Value}", ct);
            var defaults = routes.Split('\n').Where(l => l.StartsWith("default ")).ToArray();
            if (defaults.Any(l => !Regex.IsMatch(l, $@"\bdev {Regex.Escape(active)}(?: |$)"))) continue;
            if (routes.Split('\n').Any(l => Regex.IsMatch(l.Trim(), @"^(unreachable|blackhole|prohibit) default(?: |$)"))) return;
        }
        throw new SafeFailure("The selected policy's kill-switch enforcement could not be verified: no matching terminal VPN route was found. Keep the GL kill switch enabled and provide its verified policy option/value or firewall enforcement rules. Read-only probes are listed in docs/router-data.md.");
    }
}
public sealed class RouterInspection(IRouterTransport router, IKillSwitchVerifier killSwitch)
{
    public static string Identifier(string id)
    { if (!Regex.IsMatch(id, "^[A-Za-z0-9_]+$")) throw new SafeFailure("An unsupported router identifier was returned."); return id; }
    public async Task<LanInventory> LanAsync(CancellationToken ct)
    {
        string address = (await router.ExecuteAsync("uci -q get network.lan.ipaddr", ct)).Trim();
        string mask = (await router.ExecuteAsync("uci -q get network.lan.netmask", ct)).Trim();
        string start = (await router.ExecuteAsync("uci -q get dhcp.lan.start", ct)).Trim();
        string limit = (await router.ExecuteAsync("uci -q get dhcp.lan.limit", ct)).Trim();
        if (!System.Net.IPAddress.TryParse(address, out _) || !System.Net.IPAddress.TryParse(mask, out _) ||
            !int.TryParse(start, out int poolStart) || !int.TryParse(limit, out int poolLimit))
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
        var clients = new Dictionary<string, LanClient>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in reservations.Where(r => network.ContainsHost(r.Ip))) clients[r.Mac] = new("Reserved device", r.Ip, r.Mac, true);
        var leases = await router.ExecuteAsync("if [ -r /tmp/dhcp.leases ]; then cat /tmp/dhcp.leases; fi", ct);
        foreach (var line in leases.Split('\n'))
        {
            var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (f.Length < 4 || !network.ContainsHost(f[2])) continue;
            try {
                ConfigurationGenerator.ValidateDevice(f[1], f[2]);
                var reserved = reservations.FirstOrDefault(r => r.Mac.Equals(f[1], StringComparison.OrdinalIgnoreCase));
                clients[f[1]] = new(f[3] == "*" ? "Unnamed device" : f[3], reserved?.Ip ?? f[2], f[1], reserved != null);
            } catch (SafeFailure) { }
        }
        var neighbors = await router.ExecuteAsync("ip -4 neigh show", ct);
        foreach (var line in neighbors.Split('\n'))
        {
            var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries); int at = Array.IndexOf(f, "lladdr");
            if (at < 0 || at + 1 >= f.Length || !network.ContainsHost(f[0]) || clients.ContainsKey(f[at + 1])) continue;
            try { ConfigurationGenerator.ValidateDevice(f[at + 1], f[0]); clients[f[at + 1]] = new("Neighbour (presence unconfirmed)", f[0], f[at + 1]); } catch (SafeFailure) { }
        }
        var local = await router.ExecuteAsync("ip -o -4 addr show | awk '{print $4}'", ct);
        var owned = local.Split('\n').Select(l => l.Split('/')[0]).ToHashSet();
        return new(network, clients.Values.Where(c => !owned.Contains(c.Ip)).OrderBy(c => c.Hostname).ToArray(), reservations);
    }
    public async Task<RouterSnapshot> InspectAsync(InstallerConfiguration c, CancellationToken ct, bool enforceKillSwitch = true)
    {
        ConfigurationGenerator.Validate(c);
        using var board = JsonDocument.Parse(await router.ExecuteAsync("ubus call system board", ct));
        var live = c.Router with { Model = board.RootElement.GetProperty("model").GetString() ?? "", Board = board.RootElement.GetProperty("board_name").GetString() ?? "" };
        if (!live.IsBrume) throw new SafeFailure("The connected device is not a GL-MT5000.");
        var hash = (await router.ExecuteAsync("sha256sum /usr/bin/rtp2.sh | awk '{print $1}'", ct)).Trim();
        if (hash != c.Router.Rtp2Hash) throw new SafeFailure("Firmware changed since compatibility review. Reconnect and review it again.");
        var policy = Identifier(c.Profile.PolicySection);
        string group = (await router.ExecuteAsync($"uci -q get route_policy.{policy}.group_id", ct)).Trim();
        string tunnel = (await router.ExecuteAsync($"uci -q get route_policy.{policy}.tunnel_id", ct)).Trim();
        if (group != c.Profile.GroupId || tunnel != c.Profile.TunnelId) throw new SafeFailure("The selected VPN list changed. Discover it again.");
        await router.ExecuteAsync("test -x /usr/bin/setup_instance && test -x /etc/init.d/dnsmasq && command -v wg >/dev/null && command -v crontab >/dev/null && command -v sha256sum >/dev/null && command -v iptables >/dev/null && command -v stat >/dev/null && test \"$(id -u)\" = 0", ct);
        var active = (await router.ExecuteAsync($"uci -q get route_policy.{policy}.via", ct)).Trim();
        var activePeer = (await router.ExecuteAsync($"uci -q get route_policy.{policy}.peer_id", ct)).Trim();
        if (!new[] {"wgclient1", "wgclient2", "wgclient3"}.Contains(active))
            throw new SafeFailure("The selected VPN must be active on a supported WireGuard instance before installation.");
        foreach (var slot in new[] {"wgclient1", "wgclient2", "wgclient3"})
        {
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
            var other = (await router.ExecuteAsync($"uci -q show route_policy | sed -n \"s/^route_policy\\.\\([^.=]*\\)\\.via='{slot}'$/\\1/p\"", ct)).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            if (other.Any(s => s != policy)) throw new SafeFailure($"WireGuard instance {slot} is referenced by another VPN policy.");
        }
        var members = ConfigurationGenerator.Locations(c).Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.Split('\t')[5]).ToHashSet();
        if (!members.Contains(activePeer)) throw new SafeFailure("The currently active VPN location must be assigned to a tier before installation.");
        foreach (var peer in c.Tiers.Where(t => t.Tier > 0).SelectMany(t => t.Locations).SelectMany(g => g.Connections))
        {
            var owner = (await router.ExecuteAsync($"uci -q get wireguard.peer_{peer.PeerId}.group_id", ct)).Trim();
            var location = (await router.ExecuteAsync($"uci -q get wireguard.peer_{peer.PeerId}.location", ct)).Trim();
            if (owner != group || ExactLocationResolver.Normalize(location) != ExactLocationResolver.Normalize(peer.Location))
                throw new SafeFailure("VPN pool membership changed. Discover VPN lists again.");
            await router.ExecuteAsync($"grep -Fxq 'peer_{peer.PeerId}' /etc/vpn_profiles.d/profile{tunnel}", ct);
        }
        if (enforceKillSwitch) await killSwitch.VerifyAsync(router, policy, ct);
        var marker = (await router.ExecuteAsync("grep -Fc '# vpn-watch GL reconciliation guard v1' /usr/bin/rtp2.sh || true", ct)).Trim();
        if (CompatibilityCatalog.Classify(hash) == Compatibility.AlreadyPatchedKnownCompatible)
        { if (marker != "1") throw new SafeFailure("The existing GL reconciliation guard marker is missing or duplicated."); }
        else if (marker != "0") throw new SafeFailure("An unrecognized existing reconciliation guard needs review before updating.");
        else await router.ExecuteAsync("test \"$(grep -Fxc 'cmd=\"$1\";shift' /usr/bin/rtp2.sh)\" = 1 && sh -n /usr/bin/rtp2.sh", ct);
        await router.ExecuteAsync("test -z \"$(uci changes dhcp)\"", ct);
        if ((await router.ExecuteAsync($"uci -q get network.{active}.config", ct)).Trim() != "peer_" + activePeer)
            throw new SafeFailure("The active VPN policy and WireGuard instance disagree. Reconnect the selected VPN first.");
        var files = new List<FileState>();
        foreach (var path in DeploymentPlanning.Paths)
        {
            var result = (await router.ExecuteAsync($"test ! -L '{path}' && if [ -e '{path}' ]; then test -f '{path}' || exit 1; test \"$(stat -c %u '{path}')\" = 0 || exit 1; sha256sum '{path}' | awk '{{print $1}}'; stat -c %a '{path}'; else echo absent; fi", ct)).Trim().Split('\n');
            if (result[0] != "absent" && (!Regex.IsMatch(result[0], "^[a-f0-9]{64}$") || result.Length != 2 || !Regex.IsMatch(result[1], "^[0-7]{3,4}$")))
                throw new SafeFailure("An installation target has unexpected file ownership, type or metadata.");
            files.Add(result[0] == "absent" ? new(path, "", "", false) : new(path, result[0], result.ElementAtOrDefault(1) ?? "", true));
        }
        var cron = await router.ExecuteAsync("crontab -l 2>/dev/null || true", ct);
        _ = CronPlanner.Generate(cron, c.Maintenance);
        var pids = await DaemonPidsAsync(ct);
        if (pids.Length > 1) throw new SafeFailure("Multiple Hotswapper daemons are running. Stop the duplicates before installation.");
        return new(live, policy, active, activePeer, cron, (c.Guards.Count > 0 ? await LanAsync(ct) : new LanInventory(new("0.0.0.0", "0.0.0.0", 0, 0), [], [])), files, pids.Length == 1);
    }
    public async Task<string[]> DaemonPidsAsync(CancellationToken ct)
    {
        var output = await router.ExecuteAsync("for f in /proc/[0-9]*/cmdline; do [ -r \"$f\" ] || continue; tr '\\000' '\\n' < \"$f\" | grep -Fxq '/root/vpn-watch.sh' || continue; tr '\\000' '\\n' < \"$f\" | grep -Fxq daemon || continue; basename \"$(dirname \"$f\")\"; done", ct);
        return output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Where(p => Regex.IsMatch(p, "^[0-9]+$")).ToArray();
    }
}
