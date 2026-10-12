using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
using BrumeHotswapper.Installer.ViewModels;
using static BrumeHotswapper.Tests.InstallerFixture;
namespace BrumeHotswapper.Tests;

public class InstallerTests
{
    private sealed class DiscoverySession(RouterIdentity identity, IReadOnlyList<VpnProfile> profiles, bool failDiscovery = false,
        IReadOnlySet<string>? activePolicies = null) : IRouterSession
    {
        public bool IsDemo => true;
        public Task<RouterIdentity> ConnectAsync(string address, string password, CancellationToken ct) => Task.FromResult(identity);
        public Task<IReadOnlyList<VpnProfile>> ProfilesAsync(CancellationToken ct) => failDiscovery
            ? throw new SafeFailure("VPN discovery failed.") : Task.FromResult(profiles);
        public Task VerifyActiveProfileAsync(VpnProfile profile, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (activePolicies != null && !activePolicies.Contains(profile.PolicySection))
                throw new SafeFailure("The selected VPN tunnel is not active.");
            return Task.CompletedTask;
        }
        public Task<IReadOnlyList<LanClient>> ClientsAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<LanClient>>([]);
        public Task<InstallationPlan> PlanAsync(InstallerConfiguration c, CancellationToken ct) => throw new NotSupportedException();
        public Task<InstallationResult> InstallAsync(InstallerConfiguration c, IProgress<string> progress, CancellationToken ct) => throw new NotSupportedException();
        public void Dispose() { }
    }
    private static readonly RouterIdentity Brume = new("192.0.2.1", "GL-MT5000", "glinet,gl-mt5000", "4.9.0", CompatibilityCatalog.StockHash);
    private static VpnProfile Profile(params string[] locations) => new("42", "7",
        locations.Select((place, i) => new VpnConnection((i + 1).ToString(), "VPN connection", place)).ToArray());

    [Fact] public async Task DemoInstallIsExplicitAndCancellable()
    {
        using var demo = new DemoRouterSession(); var c = Config();
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => demo.InstallAsync(c, new Progress<string>(), cancelled.Token));
        var result = await demo.InstallAsync(c, new Progress<string>(), CancellationToken.None);
        Assert.True(result.Success);
        Assert.All(result.Checks.Take(result.Checks.Count - 1), check => Assert.StartsWith("DEMO", check));
    }

    private static async Task Next(WizardViewModel vm)
    {
        Assert.True(vm.PrimaryCommand.CanExecute(null));
        vm.PrimaryCommand.Execute(null);
        for (int i = 0; vm.Busy && i < 600; i++) await Task.Delay(20);
        Assert.False(vm.Busy);
    }

    [Fact] public async Task DemoWizardCanCompleteNewFiveScreenFlow()
    {
        using var vm = new WizardViewModel((_, _) => throw new Exception("Demo must not request SSH trust"), demoMode: true);
        Assert.Equal(0, vm.Page);
        await Next(vm); Assert.Equal(1, vm.Page);
        await vm.ConnectAsync(""); Assert.Equal(3, vm.Page); // Compatibility skipped when verified.
        var one = vm.Tiers[0].Locations[0];
        var two = vm.Tiers[0].Locations[1];
        vm.Move(one, vm.Tiers[1], 0);
        vm.Move(two, vm.Tiers[2], 0);
        await Next(vm); Assert.Equal(4, vm.Page);
        vm.RebootStartText = "03";
        Assert.False(vm.HasGuards);
        await Next(vm); Assert.Equal(5, vm.Page);
        Assert.Contains("No real router operations", vm.InstallationLog);
        Assert.Equal("Installation complete", vm.InstallationHeadline);
    }

    [Fact] public async Task BackFromTiersShowsAlreadyConnectedRouter()
    {
        using var vm = new WizardViewModel((_,_) => true, demoMode: true);
        await Next(vm); await vm.ConnectAsync("");
        vm.BackCommand.Execute(null);
        Assert.Equal(1, vm.Page);
        Assert.True(vm.Connected);
        Assert.False(vm.CanConnect);
        Assert.Equal("Connected", vm.ConnectionButtonLabel);
        Assert.True(vm.PrimaryCommand.CanExecute(null)); // Can resume without disconnecting.
    }

    [Fact] public async Task WrongDeviceTakesPriorityAndCannotContinue()
    {
        var other = Brume with { Model = "Other router", Board = "other,board", Firmware = "4.10.0", Rtp2Hash = "unknown" };
        using var vm = new WizardViewModel((_,_) => true, true, () => new DiscoverySession(other, []));
        await Next(vm);
        await vm.ConnectAsync("");
        Assert.Equal(2, vm.Page);
        Assert.Contains("Brume 3", vm.CompatibilityHeadline);
        Assert.False(vm.ShowPrimary);
    }

    [Fact] public async Task EmptyAndSingleLocationProfilesBlockAtCompatibility()
    {
        using var missing = new WizardViewModel((_,_) => true, true, () => new DiscoverySession(Brume, []));
        await Next(missing); await missing.ConnectAsync("");
        Assert.Equal(2, missing.Page);
        Assert.StartsWith("No VPN tunnel", missing.CompatibilityHeadline);
        Assert.True(missing.ShowVpnHelp);
        Assert.False(missing.ShowPrimary);

        using var empty = new WizardViewModel((_,_) => true, true, () => new DiscoverySession(Brume, [Profile()]));
        await Next(empty); await empty.ConnectAsync("");
        Assert.Equal(2, empty.Page);
        Assert.Contains("two distinct geographic locations", empty.CompatibilityHeadline);

        using var single = new WizardViewModel((_,_) => true, true, () => new DiscoverySession(Brume, [Profile("Croatia,Zagreb")]));
        await Next(single); await single.ConnectAsync("");
        Assert.Equal(2, single.Page);
        Assert.Contains("two distinct geographic locations", single.CompatibilityHeadline);
        Assert.False(single.ShowPrimary);
    }

    [Fact] public async Task DiscoveryFailureLeavesConnectAvailableForRetry()
    {
        using var vm = new WizardViewModel((_,_) => true, true, () => new DiscoverySession(Brume, [], true));
        await Next(vm); await vm.ConnectAsync("");
        Assert.Equal(1, vm.Page);
        Assert.False(vm.Connected);
        Assert.True(vm.CanConnect);
        Assert.Contains("VPN discovery failed", vm.Status);
    }

    [Fact] public async Task InactiveTunnelBlocksAtCompatibility()
    {
        var profile = Profile("Croatia,Zagreb", "Austria,Vienna") with { PolicySection = "inactive" };
        using var vm = new WizardViewModel((_,_) => true, true,
            () => new DiscoverySession(Brume, [profile], activePolicies: new HashSet<string>()));
        await Next(vm); await vm.ConnectAsync("");
        Assert.Equal(2, vm.Page);
        Assert.True(vm.ShowVpnHelp);
        Assert.Contains("active", vm.CompatibilityHeadline);
        Assert.Empty(vm.EligibleProfiles);
        Assert.False(vm.ShowPrimary);
    }

    [Fact] public async Task OnlyVerifiedActiveTunnelsCanBeSelected()
    {
        var inactive = Profile("Croatia,Zagreb", "Austria,Vienna") with { PolicySection = "inactive" };
        var active = Profile("Spain,Barcelona", "Norway,Oslo") with { PolicySection = "active" };
        using var vm = new WizardViewModel((_,_) => true, true,
            () => new DiscoverySession(Brume, [inactive, active], activePolicies: new HashSet<string> { "active" }));
        await Next(vm); await vm.ConnectAsync("");
        Assert.Equal(3, vm.Page);
        Assert.Same(active, vm.SelectedProfile);
        Assert.Equal([active], vm.EligibleProfiles);
    }

    [Fact] public async Task VersionOverrideOnlyAppearsForKnownFilesOnUntestedVersion()
    {
        var profile = Profile("Croatia,Zagreb", "Austria,Vienna");
        using var version = new WizardViewModel((_,_) => true, true,
            () => new DiscoverySession(Brume with { Firmware = "4.10.0" }, [profile]));
        await Next(version); await version.ConnectAsync("");
        Assert.Equal(2, version.Page);
        Assert.True(version.ShowFirmwareOverride);
        Assert.False(version.PrimaryCommand.CanExecute(null));
        version.AcceptUnsupportedFirmware = true;
        Assert.True(version.PrimaryCommand.CanExecute(null));

        using var unknown = new WizardViewModel((_,_) => true, true,
            () => new DiscoverySession(Brume with { Firmware = "4.10.0", Rtp2Hash = "unknown" }, [profile]));
        await Next(unknown); await unknown.ConnectAsync("");
        Assert.False(unknown.ShowFirmwareOverride);
        Assert.False(unknown.ShowPrimary);

        using var unreadable = new WizardViewModel((_,_) => true, true,
            () => new DiscoverySession(Brume with { Firmware = "Unknown" }, [profile]));
        await Next(unreadable); await unreadable.ConnectAsync("");
        Assert.False(unreadable.ShowFirmwareOverride);
        Assert.False(unreadable.ShowPrimary);
    }

    [Fact] public async Task TierTwoIsRequiredBeforeRecovery()
    {
        using var vm = new WizardViewModel((_,_) => true, demoMode: true);
        await Next(vm); await vm.ConnectAsync("");
        vm.Move(vm.Tiers[0].Locations[0], vm.Tiers[1], 0);
        Assert.False(vm.PrimaryCommand.CanExecute(null));
        vm.Move(vm.Tiers[0].Locations[0], vm.Tiers[2], 0);
        Assert.True(vm.PrimaryCommand.CanExecute(null));
    }

    [Fact] public async Task RemovingLastGuardClearsSecondHour()
    {
        using var vm = new WizardViewModel((_,_) => true, demoMode: true);
        await Next(vm); await vm.ConnectAsync("");
        vm.Move(vm.Tiers[0].Locations[0], vm.Tiers[1], 0);
        vm.Move(vm.Tiers[0].Locations[0], vm.Tiers[2], 0);
        await Next(vm); Assert.Equal(4, vm.Page);
        vm.AddGuardCommand.Execute(null);
        var guard = vm.GuardEntries.Single();
        guard.Address = "192.0.2.21";
        vm.RebootEndText = "14";
        Assert.True(vm.HasGuards);
        vm.RemoveGuard(guard);
        Assert.False(vm.HasGuards);
        Assert.Equal("", vm.RebootEndText);
    }

    [Fact] public async Task InstallRequiresTheRelevantRebootHours()
    {
        using var vm = new WizardViewModel((_,_) => true, demoMode: true);
        await Next(vm); await vm.ConnectAsync("");
        vm.Move(vm.Tiers[0].Locations[0], vm.Tiers[1], 0);
        vm.Move(vm.Tiers[0].Locations[0], vm.Tiers[2], 0);
        await Next(vm);
        Assert.False(vm.PrimaryCommand.CanExecute(null));
        vm.RebootStartText = "08";
        Assert.True(vm.PrimaryCommand.CanExecute(null));
        vm.AddGuardCommand.Execute(null);
        var guard = vm.GuardEntries.Single();
        guard.Address = "192.0.2.21";
        Assert.False(vm.PrimaryCommand.CanExecute(null));
        vm.RebootEndText = "07";
        Assert.False(vm.PrimaryCommand.CanExecute(null));
        vm.RebootEndText = "14";
        Assert.True(vm.PrimaryCommand.CanExecute(null));
        vm.RemoveGuard(guard);
        Assert.Equal("", vm.RebootEndText);
        Assert.True(vm.PrimaryCommand.CanExecute(null));
    }

    [Fact] public async Task UnknownFirmwareHashRejectedEvenWithVersionOverride()
    {
        var router = new RouterFixture { FirmwareHash = "unknown" };
        var identity = new RouterIdentity("192.0.2.1", "GL-MT5000", "glinet,gl-mt5000", "4.10.0", "unknown");
        await Assert.ThrowsAsync<SafeFailure>(() => RouterPrerequisites.VerifyFirmwareAsync(router, identity, true, CancellationToken.None));
    }

    [Fact] public async Task VersionOverrideKeepsEveryKnownFileCheck()
    {
        var router = new RouterFixture();
        var identity = Brume with { Firmware = "4.10.0" };
        await Assert.ThrowsAsync<SafeFailure>(() => RouterPrerequisites.VerifyFirmwareAsync(router, identity, CancellationToken.None));
        await RouterPrerequisites.VerifyFirmwareAsync(router, identity, true, CancellationToken.None);
        await Assert.ThrowsAsync<SafeFailure>(() => RouterPrerequisites.VerifyFirmwareAsync(router,
            identity with { Firmware = "Unknown" }, true, CancellationToken.None));
        router.FirmwareHashes[FirmwareTargets.All.First(t => t.Id != "rtp").Path] = "unknown";
        await Assert.ThrowsAsync<SafeFailure>(() => RouterPrerequisites.VerifyFirmwareAsync(router, identity, true, CancellationToken.None));
    }

    [Fact] public void NormalStartupDoesNotSelectDemo()
    {
        using var vm = new WizardViewModel((_,_) => false);
        Assert.Equal("", vm.ModeLabel);
    }
}
