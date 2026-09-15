using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
namespace BrumeHotswapper.Installer.Services;
public sealed class VpnDiscovery(IRouterTransport router)
{
    public static VpnProfile? AutoSelect(IReadOnlyList<VpnProfile> profiles) => profiles.Count == 1 ? profiles[0] : null;
    public async Task<IReadOnlyList<VpnProfile>> DiscoverAsync(CancellationToken ct)
    {
        // Never export wireguard config. Only route-policy IDs, profile peer IDs, name and location are read.
        var policies = await router.ExecuteAsync("uci -q show route_policy | sed -n \"s/^route_policy\\.\\([^.=]*\\)\\.tunnel_id='\\([0-9]*\\)'$/\\1 \\2/p\"", ct);
        var profiles = new List<VpnProfile>();
        foreach (var line in policies.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var fields = line.Trim().Split(' ');
            if (fields.Length != 2 || !RouterInspection.IsPolicyIdentifier(fields[0]) || !Regex.IsMatch(fields[1], "^[0-9]+$")) continue;
            var policy = RouterInspection.Identifier(fields[0]);
            var group = (await router.ExecuteAsync($"uci -q get route_policy.{policy}.group_id", ct)).Trim();
            if (!Regex.IsMatch(group, "^[0-9]+$")) continue;
            var peers = await router.ExecuteAsync($"if [ -f /etc/vpn_profiles.d/profile{fields[1]} ]; then sed -n 's/^{group}_\\([0-9][0-9]*\\)$/peer_\\1/p' /etc/vpn_profiles.d/profile{fields[1]}; fi", ct);
            var connections = new List<VpnConnection>();
            foreach (var peer in peers.Split('\n').Select(s => s.Trim()).Where(s => Regex.IsMatch(s, "^peer_[0-9]+$")).Distinct())
            {
                var owner = (await router.ExecuteAsync($"uci -q get wireguard.{peer}.group_id || true", ct)).Trim();
                if (owner != group) continue;
                var name = "VPN connection";
                var location = (await router.ExecuteAsync($"uci -q get wireguard.{peer}.location || true", ct)).Trim();
                connections.Add(new(peer[5..], name, location));
            }
            if (connections.Count > 0) profiles.Add(new(fields[1], group, connections, fields[0]));
        }
        return profiles;
    }
}
