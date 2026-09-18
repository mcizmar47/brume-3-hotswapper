using System.IO;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
using BrumeHotswapper.Installer.ViewModels;
namespace BrumeHotswapper.Tests;
public class HousekeepingTests
{
    [Fact] public void MaintenanceUiOffersOnlyWholeHours()
    {
        using var vm = new WizardViewModel((_,_)=>false);
        Assert.Equal(3,vm.RebootWindowStart); Assert.Equal(14,vm.RebootWindowEnd);
        Assert.Equal(Enumerable.Range(0,24).Select(h=>$"{h:00}:00"),vm.Hours);
        vm.RebootWindowStart=8; vm.RebootWindowEnd=20;
        Assert.Equal(8,vm.RebootWindowStart); Assert.Equal(20,vm.RebootWindowEnd);
    }
    [Fact] public void CanonicalDefaultsMatchGeneratedConfiguration()
    {
        var c = InstallerFixture.Config();
        Assert.Equal(3,c.RebootWindowStart); Assert.Equal(14,c.RebootWindowEnd);
        Assert.Equal(File.ReadAllText(Path.Combine(RepositoryFiles.Root,"config","housekeeping.conf")).Replace("\r\n","\n"),ConfigurationGenerator.Housekeeping(c));
        Assert.Empty(File.ReadAllText(Path.Combine(RepositoryFiles.Root,"config","hotswapper-locations.tsv")));
        Assert.Empty(File.ReadAllText(Path.Combine(RepositoryFiles.Root,"config","reboot-guards.tsv")));
    }
    [Theory][InlineData(8,8)][InlineData(7,19)]
    public void SameDayWindowsAreGenerated(int start,int end)
    {
        var c=InstallerFixture.Config() with {RebootWindowStart=start,RebootWindowEnd=end};
        Assert.Equal($"REBOOT_WINDOW_START={start}\nREBOOT_WINDOW_END={end}\n",ConfigurationGenerator.Housekeeping(c));
    }
    [Theory][InlineData(3,24)][InlineData(14,3)]
    public void InvalidWindowIsRejected(int start,int end) => Assert.Throws<SafeFailure>(()=>ConfigurationGenerator.Validate(InstallerFixture.Config() with {RebootWindowStart=start,RebootWindowEnd=end}));
    [Theory][InlineData(true)][InlineData(false)]
    public void CronIsHourlyAndPreservesUnrelatedJobs(bool enabled)
    {
        const string unrelated="12 9 * * * /root/unrelated.sh\n";
        var old=unrelated+CronPlanner.PreviousMaintenance+"\n"+CronPlanner.Supervisor+"\n";
        var generated=CronPlanner.Generate(old,enabled);
        Assert.StartsWith(unrelated,generated);
        Assert.DoesNotContain(CronPlanner.PreviousMaintenance,generated);
        Assert.Equal(enabled?1:0,generated.Split('\n').Count(l=>l=="0 * * * * /root/hotswapper-housekeeping.sh"));
        Assert.Equal(generated,CronPlanner.Generate(generated,enabled));
        Assert.Equal(old,DeploymentPlanning.RestoreOwnedCron(generated,old));
    }
    [Fact] public void MultipleGuardsStaySeparateRows()
    {
        var c=InstallerFixture.Config() with {Guards=[new("A","192.0.2.10","02:00:00:00:00:01"),new("B","192.0.2.11","02:00:00:00:00:02")]};
        Assert.Equal("02:00:00:00:00:01\t192.0.2.10\n02:00:00:00:00:02\t192.0.2.11\n",ConfigurationGenerator.Guards(c));
    }
    [Theory][InlineData(true)][InlineData(false)]
    public async Task InstallationDeploysSelectedWindowWithoutChangingCanonicalFiles(bool enabled)
    {
        var configDirectory=Path.Combine(RepositoryFiles.Root,"config");
        var before=Directory.GetFiles(configDirectory).ToDictionary(p=>p,File.ReadAllBytes);
        var router=new InstallerFixture.RouterFixture();
        var installer=new RouterInstaller(router,new KillSwitchVerifier());
        var c=InstallerFixture.Config() with {Maintenance=enabled,RebootWindowStart=8,RebootWindowEnd=20};
        var plan=await installer.PlanAsync(c,default);
        Assert.True((await installer.InstallAsync(plan,new Progress<string>(),default)).Success);
        Assert.Equal("REBOOT_WINDOW_START=8\nREBOOT_WINDOW_END=20\n",router.Installed["/root/hotswapper/housekeeping.conf"]);
        Assert.Equal(enabled,router.Cron.Contains(CronPlanner.Maintenance));
        foreach(var (path,bytes) in before) Assert.Equal(bytes,File.ReadAllBytes(path));
    }
    [Fact] public void InstalledConfigurationHasExactCanonicalCounterparts()
    {
        var names=Directory.GetFiles(Path.Combine(RepositoryFiles.Root,"config")).Select(Path.GetFileName).Order().ToArray();
        Assert.Equal(new[]{"hotswapper-locations.tsv","hotswapper.conf","housekeeping.conf","reboot-guards.tsv"},names);
        foreach(var name in names) Assert.Contains("/root/hotswapper/"+name,DeploymentPlanning.Paths);
        Assert.DoesNotContain(names,n=>n!.Contains("last-date")||n.EndsWith(".example"));
        var defaults = File.ReadAllLines(Path.Combine(RepositoryFiles.Root,"config","hotswapper.conf"));
        foreach(var key in new[]{"TUNNEL_ID","GROUP_ID","NTFY_URL"})
            Assert.Equal(key+"=''",Assert.Single(defaults,line=>line.StartsWith(key+"=")));
    }
}
