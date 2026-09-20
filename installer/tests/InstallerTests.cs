using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
using BrumeHotswapper.Installer.ViewModels;
using static BrumeHotswapper.Tests.InstallerFixture;
namespace BrumeHotswapper.Tests;
public class InstallerTests
{
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
        await Next(vm);
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
    [Fact] public void UnknownGuardCannotBypassCompatibilityGate()
    {
        using var vm=new WizardViewModel((_,_)=>false);
        typeof(WizardViewModel).GetProperty(nameof(vm.Router))!.SetValue(vm,new RouterIdentity("192.0.2.1","GL-MT5000","glinet,gl-mt5000","4.9.0","unknown"));
        typeof(WizardViewModel).GetProperty(nameof(vm.Page))!.SetValue(vm,3);
        Assert.False(vm.NextCommand.CanExecute(null));
    }
    [Fact] public void NormalStartupDoesNotSelectDemo()
    {
        using var vm=new WizardViewModel((_,_)=>false); Assert.False(vm.Demo); Assert.Equal("",vm.ModeLabel);
    }
}
