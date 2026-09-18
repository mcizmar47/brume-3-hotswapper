using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Tests;
public class ConfigurationTests
{
    private static InstallerConfiguration Config()
    {
        var peers = new[] { new VpnConnection("11", "A", "Germany / Frankfurt"), new VpnConnection("12", "B", "Switzerland / Zurich"), new VpnConnection("13", "C", "Germany / Frankfurt") };
        var tiers = new[] { new TierColumn("Unused", 0), new TierColumn("Preferred", 1), new TierColumn("Fallback", 2), new TierColumn("Last", 3) };
        foreach (var group in new ExactLocationResolver().Group(peers)) tiers[group.Label.StartsWith("Germany") ? 1 : 2].Locations.Add(group);
        return new(new("192.0.2.1", "GL-MT5000", "glinet,gl-mt5000", "4.9.0", CompatibilityCatalog.StockHash), new("42", "7", peers), tiers, false, "", false, []);
    }
    [Theory]
    [InlineData("GL-MT3000", "glinet,gl-mt3000")]
    [InlineData("GL-MT5000 clone", "other")]
    public void WrongDeviceStops(string model, string board) => Assert.Throws<SafeFailure>(() => ConfigurationGenerator.Validate(Config() with { Router = Config().Router with { Model = model, Board = board } }));
    [Fact] public void GroupingUsesExactLocationsAndKeepsUnknownPeersSeparate()
    {
        var groups = new ExactLocationResolver().Group([new("1", "same server", "Germany / Frankfurt"), new("2", "different server", "Germany / Frankfurt"), new("3", "other", ""), new("4", "other", "")]);
        Assert.Equal(3, groups.Count); Assert.Equal(2, groups.Single(g => g.Label == "Germany / Frankfurt").Connections.Count);
    }
    [Fact] public void TierConfigPreservesPoolMembershipAndPriority()
    {
        var c = Config(); var text = ConfigurationGenerator.Locations(c);
        var rows = text.TrimEnd().Split('\n').Select(l => l.Split('\t')).ToArray();
        Assert.Equal(new[] { "11", "13", "12" }, rows.Select(r => r[5]));
        Assert.Equal(new[] { "1", "1", "2" }, rows.Select(r => r[1]));
        Assert.Contains("TUNNEL_ID='42'", ConfigurationGenerator.PrivateConfig(c));
        Assert.Contains("GROUP_ID='7'", ConfigurationGenerator.PrivateConfig(c));
    }
    [Fact] public void UnassignedPeersAreExcluded()
    {
        var c = Config(); var g = c.Tiers[2].Locations[0]; c.Tiers[2].Locations.Remove(g); c.Tiers[0].Locations.Add(g);
        Assert.DoesNotContain("\t12\n", ConfigurationGenerator.Locations(c));
    }
    [Fact] public void DuplicatePeersStopGeneration()
    { var c = Config(); c.Tiers[2].Locations.Add(c.Tiers[1].Locations[0]); Assert.Throws<SafeFailure>(() => ConfigurationGenerator.Locations(c)); }
    [Fact] public void EmptyTierOneStopsGeneration()
    { var c = Config(); c.Tiers[1].Locations.Clear(); Assert.Throws<SafeFailure>(() => ConfigurationGenerator.Locations(c)); }
    [Theory]
    [InlineData("1;reboot")][InlineData("1\n2")]
    public void UnsafeIdsAreRejected(string id) => Assert.Throws<SafeFailure>(() => ConfigurationGenerator.PrivateConfig(Config() with { Profile = Config().Profile with { TunnelId = id } }));
    [Fact] public void ShellQuotePreservesApostropheAsData() => Assert.Equal("'a'\"'\"'b'", ConfigurationGenerator.Quote("a'b"));
    [Fact] public void DhcpReusesReservation()
    {
        var client = new LanClient("PC", "192.0.2.20", "02:00:00:00:00:20");
        var planned = DhcpPlanner.Plan([client], [new("host1", client.Mac, "192.0.2.30")], [client], "192.0.2.1");
        Assert.False(planned[0].Create); Assert.Equal("192.0.2.30", planned[0].Ip);
    }
    [Fact] public void DhcpRejectsConflict()
    {
        var client = new LanClient("PC", "192.0.2.20", "02:00:00:00:00:20");
        Assert.Throws<SafeFailure>(() => DhcpPlanner.Plan([client], [new("host1", "02:00:00:00:00:21", client.Ip)], [client], "192.0.2.1"));
        Assert.Throws<SafeFailure>(() => DhcpPlanner.Plan([client], [], [client], client.Ip));
    }
    [Fact] public void ReportsRedactKnownSecretsUrlsAndKeys()
    {
        var text = DiagnosticLog.Redact("hello secret-value\nhttps://ntfy.example/private-topic\nPrivateKey=abc\npassword=anything", "secret-value");
        foreach (var secret in new[] { "secret-value", "private-topic", "abc", "anything" }) Assert.DoesNotContain(secret, text);
    }
    [Theory]
    [InlineData(CompatibilityCatalog.StockHash, Compatibility.StockKnownCompatible)]
    [InlineData(CompatibilityCatalog.PatchedHash, Compatibility.AlreadyPatchedKnownCompatible)]
    [InlineData("unknown", Compatibility.Unknown)]
    public void DistinctGuardStates(string hash, Compatibility expected) => Assert.Equal(expected,CompatibilityCatalog.Classify(hash));
    [Fact] public void CommaLocationsNormalizeWithoutWorldMap()
    {
        var groups = new ExactLocationResolver().Group([new("1","unused"," Fictionland , Example City "),new("2","unused","Fictionland,Example City")]);
        var group=Assert.Single(groups); Assert.Equal("Fictionland / Example City",group.Label); Assert.Equal(2,group.Connections.Count);
    }
    [Theory]
    [InlineData("192.0.2.20",true)][InlineData("192.0.3.20",false)][InlineData("192.0.2.0",false)]
    [InlineData("192.0.2.255",false)][InlineData("192.0.2.1",false)]
    public void ReservationsStayInUsableSubnet(string ip,bool expected) => Assert.Equal(expected,new LanNetwork("192.0.2.1","255.255.255.0",100,100).ContainsHost(ip));
    [Fact] public void NewReservationIsMinimal()
    {
        var d=new LanClient("PC","192.0.2.20","02:00:00:00:00:20");
        Assert.True(Assert.Single(DhcpPlanner.Plan([d],[],[d],"192.0.2.1")).Create);
        Assert.Equal("hotswap_020000000020",RouterInstaller.ReservationSection(d.Mac));
    }
    [Theory][InlineData(" my-topic ")][InlineData(" https://ntfy.sh/my-topic ")]
    public void SharedTopicNormalization(string input)
    {
        Assert.Equal("https://ntfy.sh/my-topic",NtfyTopic.Normalize(input));
        var c=InstallerFixture.Config() with {Notifications=true,NtfyUrl=input};
        Assert.Contains("NTFY_URL='https://ntfy.sh/my-topic'",ConfigurationGenerator.PrivateConfig(c));
    }
    [Theory][InlineData("has space")][InlineData("https://ntfy.sh/topic?secret=x")]
    public void InvalidTopicIsRejected(string input)=>Assert.Throws<SafeFailure>(()=>NtfyTopic.Normalize(input));
    [Theory]
    [InlineData(160)]
    public void PoolGenerationKeepsEveryPeerWithoutSmallCountAssumptions(int count)
    {
        var peers = Enumerable.Range(1,count).Select(i => new VpnConnection(i.ToString(), "", "Example,City " + (i % 9))).ToArray();
        var groups = new ExactLocationResolver().Group(peers);
        var c = InstallerFixture.Config(); foreach(var tier in c.Tiers) tier.Locations.Clear();
        foreach(var group in groups) c.Tiers[1].Locations.Add(group);
        c = c with { Profile = c.Profile with { Connections = peers } };
        var rows = ConfigurationGenerator.Locations(c).Split('\n',StringSplitOptions.RemoveEmptyEntries).Select(x => x.Split('\t')).ToArray();
        Assert.Equal(count,rows.Length); Assert.Equal(9,groups.Count); Assert.Equal(count,rows.Select(x => x[5]).Distinct().Count());
    }
}
