using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;

namespace BrumeHotswapper.Tests;

public class EarlierRoutingTests
{
    private const string Selected = "6000: from all fwmark 0x2000/0xf000 lookup 1002";
    private sealed class Routes(string earlier, string routes, string lan = "") : IRouterTransport
    {
        public Task UploadAsync(string path, string content, CancellationToken ct) => throw new Exception("Read only");
        public Task<string> ExecuteAsync(string command, CancellationToken ct) => Task.FromResult(command switch {
            "ip -4 route show table all" => routes,
            "ubus call network.interface.lan status" => lan,
            _ => throw new Exception(command)
        });
        public Task Verify() => EarlierRouting.VerifyAsync(this, earlier + "\n" + Selected, Selected, 0x2000, default);
    }
    [Theory]
    [InlineData("9910", "192.0.2", "br-lan")]
    [InlineData("4321", "10.31.87", "home-lan")]
    public async Task ConnectedLanUsesDiscoveredInterfaceAndSubnet(string table, string subnet, string device)
    {
        string lan = $$"""{"up":true,"l3_device":"{{device}}","ipv4-address":[{"address":"{{subnet}}.1","mask":24}]}""";
        await new Routes($"800: from all lookup {table} suppress_prefixlength 0",
            $"{subnet}.0/24 dev {device} table {table} proto kernel scope link src {subnet}.1", lan).Verify();
    }
    [Theory]
    [InlineData("default dev wan table 4321")]
    [InlineData("198.51.100.0/24 dev wan table 4321 proto kernel scope link src 198.51.100.1")]
    [InlineData("192.0.2.0/24 dev unknown table 4321 proto kernel scope link src 192.0.2.1")]
    [InlineData("192.0.2.0/24 via 192.0.2.254 dev home table 4321")]
    [InlineData("throw 192.0.2.0/24 table 4321")]
    public async Task ExternalUnknownGatewayAndUnsupportedRoutesBlock(string route)
    {
        const string lan = """{"up":true,"l3_device":"home","ipv4-address":[{"address":"192.0.2.1","mask":24}]}""";
        await Assert.ThrowsAsync<SafeFailure>(() => new Routes("800: from all lookup 4321", route, lan).Verify());
    }
    [Fact] public async Task SuppressedDefaultIsHarmlessButSpecificWanRouteIsNot()
    {
        const string rule = "800: from all lookup 4321 suppress_prefixlength 0";
        await new Routes(rule, "default via 198.51.100.1 dev wan table 4321").Verify();
        await Assert.ThrowsAsync<SafeFailure>(() => new Routes(rule, "198.51.100.0/24 dev wan table 4321").Verify());
    }
    [Fact] public async Task LocalAndDisjointMarksAreHarmless()
    {
        await new Routes("0: from all lookup local\n100: from all fwmark 0x3000/0xf000 lookup 700",
            "local 192.0.2.1 dev home table local proto kernel scope host src 192.0.2.1\ndefault dev wan table 700").Verify();
        await new Routes("100: not from all fwmark 0x2000/0xf000 lookup 700", "default dev wan table 700").Verify();
    }
    [Theory]
    [InlineData("100: from all fwmark 0x2000/0xf000 lookup 700")]
    [InlineData("100: not from all fwmark 0x3000/0xf000 lookup 700")]
    [InlineData("100: from all fwmark 0x2001/0xffff lookup 700")]
    [InlineData("100: from all goto 700")]
    public async Task ApplicableOrAmbiguousRulesBlock(string rule) =>
        await Assert.ThrowsAsync<SafeFailure>(() => new Routes(rule, "default dev wan table 700").Verify());

    [Fact] public async Task MissingLanEvidenceBlocks()
    {
        await Assert.ThrowsAsync<SafeFailure>(() => new Routes("800: from all lookup 4321",
            "192.0.2.0/24 dev home table 4321 proto kernel scope link src 192.0.2.1", "{}").Verify());
    }
}
