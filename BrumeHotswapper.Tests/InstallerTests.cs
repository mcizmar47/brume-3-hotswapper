using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
using BrumeHotswapper.Installer.ViewModels;

namespace BrumeHotswapper.Tests;

public class InstallerTests
{
    private static InstallerConfiguration Config()
    {
        var peers = new[] { new VpnConnection("11", "A", "Germany / Frankfurt"), new VpnConnection("12", "B", "Switzerland / Zurich"), new VpnConnection("13", "C", "Germany / Frankfurt") };
        var tiers = new[] { new TierColumn("Unused", 0), new TierColumn("Preferred", 1), new TierColumn("Fallback", 2), new TierColumn("Last", 3) };
        foreach (var group in new ExactLocationResolver().Group(peers)) tiers[group.Label.StartsWith("Germany") ? 1 : 2].Locations.Add(group);
        return new(new("192.0.2.1", "GL-MT5000", "glinet,gl-mt5000", "4.9.0", CompatibilityCatalog.StockHash), new("42", "7", peers), tiers, false, "", false, []);
    }
    [Fact] public void CompatibilityIsIndependentFromFirmware()
    {
        Assert.Equal(Compatibility.StockKnownCompatible, CompatibilityCatalog.Classify(CompatibilityCatalog.StockHash.ToUpperInvariant()));
        Assert.Equal(Compatibility.Unknown, CompatibilityCatalog.Classify("unknown"));
        var c = Config() with { Router = Config().Router with { Firmware = "9.0.0" } };
        ConfigurationGenerator.Validate(c);
        Assert.DoesNotContain(c.Router.Firmware, CompatibilityCatalog.TestedFirmware);
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
        Assert.DoesNotContain("5779", ConfigurationGenerator.PrivateConfig(c));
        Assert.DoesNotContain("10004", ConfigurationGenerator.PrivateConfig(c));
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
    [InlineData("1;reboot")][InlineData("$(id)")][InlineData("1\n2")]
    public void UnsafeIdsAreRejected(string id) => Assert.Throws<SafeFailure>(() => ConfigurationGenerator.PrivateConfig(Config() with { Profile = Config().Profile with { TunnelId = id } }));
    [Fact] public void ShellQuotePreservesApostropheAsData() => Assert.Equal("'a'\"'\"'b'", ConfigurationGenerator.Quote("a'b"));
    [Fact] public void CronIsIdempotentAndPreservesOtherJobs()
    {
        const string original = "# user jobs\n15 1 * * * /root/backup.sh\n";
        var cron = CronPlanner.Generate(original, true);
        Assert.Equal(cron, CronPlanner.Generate(cron, true)); Assert.StartsWith(original, cron);
        var disabled = CronPlanner.Generate(cron, false); Assert.DoesNotContain(CronPlanner.Maintenance, disabled); Assert.Contains(CronPlanner.Supervisor, disabled);
    }
    [Fact] public void CustomCronRequiresReview() => Assert.Throws<SafeFailure>(() => CronPlanner.Generate("1 * * * * /root/vpn-watch-supervisor.sh && echo custom", false));
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
    [Fact] public void PlanAlwaysIncludesConditionalRebootAndValidatesBeforeMutation()
    { var plan = InstallationPlanner.Create(Config()); Assert.False(plan[0].ChangesRouter); Assert.Contains(plan, s => s.Name.Contains("conditional reboot")); Assert.DoesNotContain(plan, s => s.Name.Contains("reserve")); }
    [Fact] public void ReportsRedactKnownSecretsUrlsAndKeys()
    {
        var text = DiagnosticLog.Redact("hello secret-value\nhttps://ntfy.example/private-topic\nPrivateKey=abc\npassword=anything", "secret-value");
        foreach (var secret in new[] { "secret-value", "private-topic", "abc", "anything" }) Assert.DoesNotContain(secret, text);
    }
    [Fact] public async Task DemoInstallIsExplicitAndCancellable()
    {
        using var demo = new DemoRouterSession(); var c = Config();
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => demo.InstallAsync(c, new Progress<string>(), cancelled.Token));
        var result = await demo.InstallAsync(c, new Progress<string>(), CancellationToken.None);
        Assert.True(result.Success); Assert.All(result.Checks.Take(result.Checks.Count - 1), check => Assert.StartsWith("DEMO", check));
    }
    [Fact] public async Task DemoWizardCanCompleteAllPages()
    {
        using var vm = new WizardViewModel((_, _) => throw new Exception("Demo must not request SSH trust")) { Demo = true, Acknowledged = true };
        await Next(vm); Assert.Equal(1, vm.Page);
        await vm.ConnectAsync("", false); Assert.Equal(2, vm.Page);
        await Next(vm); await Next(vm); Assert.Equal(4, vm.Page);
        vm.LocationAccepted = true; await Next(vm);
        var group = vm.Tiers[0].Locations[0]; vm.Move(group, vm.Tiers[1], 0);
        await Next(vm); await Next(vm); await Next(vm); Assert.Equal(8, vm.Page);
        await Next(vm); Assert.Equal(10, vm.Page); await Next(vm); Assert.Equal(11, vm.Page);
        Assert.Contains("No real router operations", vm.Report);
    }
    private static async Task Next(WizardViewModel vm)
    {
        Assert.True(vm.NextCommand.CanExecute(null)); vm.NextCommand.Execute(null);
        for (int i = 0; vm.Busy && i < 500; i++) await Task.Delay(20);
        Assert.False(vm.Busy);
    }
}
