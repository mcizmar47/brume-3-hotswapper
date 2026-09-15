using BrumeHotswapper.Preflight;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Tests;
public class ReadOnlyPreflightTests
{
    [Theory]
    [InlineData("uci set network.lan.ipaddr=192.0.2.1")]
    [InlineData("uci commit dhcp")]
    [InlineData("/root/install-vpn-watch-gl-guard.sh --check")]
    [InlineData("/root/install-vpn-watch-gl-guard.sh --install")]
    [InlineData("/root/vpn-watch.sh status")]
    [InlineData("/root/vpn-watch-supervisor.sh --installer")]
    [InlineData("/etc/init.d/dnsmasq reload")]
    [InlineData("crontab /tmp/new-cron")]
    [InlineData("iptables -w -t mangle -A ROUTE_POLICY -j DROP")]
    [InlineData("reboot")]
    [InlineData("touch /tmp/probe")]
    [InlineData("uci -q get route_policy.vpn.mark; reboot")]
    [InlineData("sh -n /usr/bin/rtp2.sh; touch /tmp/probe")]
    public void MutationAndArbitraryShellAreRejected(string command) => Assert.False(ReadOnlyTransport.IsAllowed(command));
    [Fact] public async Task ProductionReadMethodsPassGate()
    {
        var read = new ReadOnlyTransport(new Fixture());
        Assert.Single(await new VpnDiscovery(read).DiscoverAsync(default));
        var inspection = new RouterInspection(read, new KillSwitchVerifier());
        Assert.Empty((await inspection.LanAsync(default)).Clients);
        Assert.Single(await inspection.DaemonPidsAsync(default));
        await new KillSwitchVerifier().VerifyAsync(read, "@rule[0]", default);
        await Assert.ThrowsAsync<SafeFailure>(() => read.UploadAsync("/root/file", "data", default));
        await Assert.ThrowsAsync<SafeFailure>(() => read.ExecuteAsync("reboot", default));
    }
    private sealed class Fixture : IRouterTransport
    {
        public Task UploadAsync(string p,string c,CancellationToken ct) => throw new Exception("Must never reach transport upload");
        public Task<string> ExecuteAsync(string command,CancellationToken ct) => Task.FromResult(command switch {
            var x when x == ReadOnlyTransport.Policies => "@rule[0] 42",
            "uci -q get route_policy.'@rule[0]'.group_id || true" => "7",
            var x when x.Contains("sed -n 's/^7_") => "peer_11",
            "uci -q get wireguard.peer_11.group_id || true" => "7",
            "uci -q get wireguard.peer_11.location || true" => "Example,City",
            "uci -q get network.lan.ipaddr" => "192.0.2.1",
            "uci -q get network.lan.netmask" => "255.255.255.0",
            "uci -q get dhcp.lan.start" => "100",
            "uci -q get dhcp.lan.limit" => "150",
            var x when x == ReadOnlyTransport.Hosts => "",
            "if [ -r /tmp/dhcp.leases ]; then cat /tmp/dhcp.leases; fi" => "",
            "ip -4 neigh show" => "",
            "ip -o -4 addr show | awk '{print $4}'" => "192.0.2.1/24",
            var x when x == ReadOnlyTransport.Daemons => "123",
            "uci -q get route_policy.'@rule[0]'.killswitch || true" => "1",
            "uci -q get route_policy.'@rule[0]'.enabled || true" => "1",
            "uci -q get glipv6.globals.enabled || true" => "0",
            "uci -q get route_policy.'@rule[0]'.tunnel_id" => "42",
            "uci -q get route_policy.'@rule[0]'.mark" => "0x1000",
            "uci -q get route_policy.'@rule[0]'.via" => "wgclient1",
            "iptables -w -t mangle -S TUNNEL42_ROUTE_POLICY" => "-A TUNNEL42_ROUTE_POLICY -m mark --mark 0x0/0xf000 -j MARK --set-xmark 0x1000/0xf000\n-A TUNNEL42_ROUTE_POLICY -m mark --mark 0x0/0xf000 -j DROP",
            "iptables -w -t mangle -C ROUTE_POLICY -m addrtype ! --dst-type LOCAL -j TUNNEL42_ROUTE_POLICY" => "",
            "ip -4 rule show" => "0: from all lookup local\n6000: from all fwmark 0x1000/0xf000 lookup 1001",
            "ip -4 route show table 1001" => "default dev wgclient1\nblackhole default metric 254",
            _ => throw new Exception("Unexpected fixture read")
        });
    }
}
