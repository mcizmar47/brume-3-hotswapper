using System.IO;
using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Preflight;

// Exact read operations only. There is no upload, plan or installation entry point.
public sealed class ReadOnlyTransport(IRouterTransport inner) : IRouterTransport
{
    public static readonly string Policies = "uci -q show route_policy | sed -n \"s/^route_policy\\.\\([^.=]*\\)\\.tunnel_id='\\([0-9]*\\)'$/\\1 \\2/p\"";
    public static readonly string Hosts = "uci -q show dhcp | sed -n 's/^dhcp\\.\\([^.=]*\\)=host$/\\1/p'";
    public static readonly string Daemons = "for f in /proc/[0-9]*/cmdline; do [ -r \"$f\" ] || continue; tr '\\000' '\\n' < \"$f\" | grep -Fxq '/root/vpn-watch.sh' || continue; tr '\\000' '\\n' < \"$f\" | grep -Fxq daemon || continue; basename \"$(dirname \"$f\")\"; done";
    public static string SlotReferences(string slot) => $"uci -q show route_policy | sed -n \"s/^route_policy\\.\\([^.=]*\\)\\.via='{slot}'$/\\1/p\"";
    public static string ProfileMembers(string tunnel) => $"sed -n '/^[0-9][0-9]*_[0-9][0-9]*$/p' /etc/vpn_profiles.d/profile{tunnel}";
    private static readonly HashSet<string> Exact = [Policies, Hosts, Daemons, RouterPrerequisites.CapabilitiesCommand,
        "sha256sum /usr/bin/rtp2.sh | awk '{print $1}'",
        "test \"$(grep -Fxc 'cmd=\"$1\";shift' /usr/bin/rtp2.sh)\" = 1 && sh -n /usr/bin/rtp2.sh",
        "uci -q get route_policy.gl_process_vpn", "uci -q get glipv6.globals.enabled || true",
        "ip -4 rule show", "ip -4 neigh show", "ip -o -4 addr show", "ip -o -4 addr show | awk '{print $4}'",
        "if [ -r /tmp/dhcp.leases ]; then cat /tmp/dhcp.leases; fi",
        "crontab -l 2>/dev/null || true", "date +%s", "sh -n /usr/bin/rtp2.sh",
        "grep -Fc '# vpn-watch GL reconciliation guard v1' /usr/bin/rtp2.sh || true",
        "grep -Fxc 'cmd=\"$1\";shift' /usr/bin/rtp2.sh || true",
        "if [ -f /tmp/vpn-watch/state ]; then cat /tmp/vpn-watch/state; fi",
        "if [ -f /root/vpn-watch-locations.tsv ]; then cat /root/vpn-watch-locations.tsv; fi",
        "if [ -e /root/.hotswap-installer/transaction ] || [ -e /tmp/vpn-watch-installer-lock ]; then echo pending; else echo clear; fi",
        "if [ -z \"$(uci changes dhcp)\" ]; then echo false; else echo true; fi"];
    public static bool IsAllowed(string command)
    {
        if (command == HotswapRuntime.ScanCommand || command == HotswapRuntime.PidCommand) return true;
        if (Exact.Contains(command)) return true;
        if (DeploymentPlanning.Paths.Any(p => BrumeHotswapper.Installer.Services.FileMetadata.Commands(p).Values.Contains(command))) return true;
        if (new[] { "wgclient1", "wgclient2", "wgclient3" }.Any(slot => command == SlotReferences(slot) || command == $"if ip link show {slot} >/dev/null 2>&1; then echo present; fi" || command == $"wg show {slot} latest-handshakes | awk '{{print $2}}'")) return true;
        string policy = @"(?:[A-Za-z0-9_]+|'@rule\[[0-9]+\]')";
        string key = @"(?:route_policy\." + policy + @"\.(?:group_id|tunnel_id|via|peer_id|mark|enabled|killswitch)|wireguard\.peer_[0-9]+\.(?:group_id|location)|network\.(?:wgclient[123]\.config|lan\.(?:ipaddr|netmask))|dhcp\.lan\.(?:start|limit)|'dhcp\.(?:[A-Za-z0-9_]+|@host\[[0-9]+\])\.(?:mac|ip)')";
        if (Regex.IsMatch(command, "^uci -q get " + key + @"(?: \|\| true)?$")) return true;
        if (Regex.IsMatch(command, @"^ip -4 route show table [A-Za-z0-9_]+$")) return true;
        if (Regex.IsMatch(command, @"^ip -4 route show table all dev wgclient[123]$")) return true;
        if (Regex.IsMatch(command, @"^iptables -w -t mangle -S (?:ROUTE_POLICY|TUNNEL[0-9]+_ROUTE_POLICY)$")) return true;
        if (Regex.IsMatch(command, @"^iptables -w -t mangle -C ROUTE_POLICY -m addrtype ! --dst-type LOCAL -j TUNNEL[0-9]+_ROUTE_POLICY$")) return true;
        var profile = Regex.Match(command, @"/etc/vpn_profiles\.d/profile([0-9]+)");
        if (profile.Success && command == ProfileMembers(profile.Groups[1].Value)) return true;
        var discovery = Regex.Match(command, @"^if \[ -f /etc/vpn_profiles\.d/profile([0-9]+) \]; then sed -n 's/\^([0-9]+)_");
        if (discovery.Success)
        {
            string tunnel = discovery.Groups[1].Value, group = discovery.Groups[2].Value;
            return command == $"if [ -f /etc/vpn_profiles.d/profile{tunnel} ]; then sed -n 's/^{group}_\\([0-9][0-9]*\\)$/peer_\\1/p' /etc/vpn_profiles.d/profile{tunnel}; fi";
        }
        return false;
    }
    public async Task<string> ExecuteAsync(string command, CancellationToken ct)
    {
        if (!IsAllowed(command)) throw new SafeFailure("Preflight rejected a command outside its read-only allowlist.");
        return await inner.ExecuteAsync(command, ct);
    }
    public Task UploadAsync(string path, string content, CancellationToken ct) => throw new SafeFailure("Preflight cannot upload files.");
}
