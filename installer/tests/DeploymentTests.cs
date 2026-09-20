using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
using static BrumeHotswapper.Tests.InstallerFixture;
namespace BrumeHotswapper.Tests;
public class DeploymentTests
{
    [Fact] public async Task RealTransactionCanCompleteWithVerifiedPreconditions()
    {
        var fake=new RouterFixture(); var installer=new RouterInstaller(fake,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(Config(),CancellationToken.None);
        var result=await installer.InstallAsync(plan,new Progress<string>(),CancellationToken.None);
        Assert.True(result.Success); Assert.Equal(11, fake.Installed.Count); Assert.True(fake.Running);
        Assert.Equal(CronPlanner.Supervisor+"\n",fake.Cron); Assert.Equal(1,fake.RealPatches);
    }
    [Fact] public async Task GuardFailureRollsBackOnlyOwnedFiles()
    {
        var fake=new RouterFixture {RejectPatch=true, Cron="22 2 * * * /root/unrelated\n"};
        var installer=new RouterInstaller(fake,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(Config(),CancellationToken.None);
        var error=await Assert.ThrowsAsync<SafeFailure>(()=>installer.InstallAsync(plan,new Progress<string>(),CancellationToken.None));
        Assert.Contains("Apply GL reconciliation guard",error.Message);
        Assert.DoesNotContain("synthetic-private-router-output",error.Message);
        Assert.Contains("rolled back",error.Message); Assert.Empty(fake.Installed);
        Assert.Contains("/root/unrelated",fake.Cron); Assert.DoesNotContain(CronPlanner.Supervisor,fake.Cron);
    }
    [Fact] public async Task PrivateUrlNeverAppearsInPlanOrStatus()
    {
        var c=Config() with {Notifications=true,NtfyUrl="https://ntfy.sh/synthetic-test-topic"};
        var fake=new RouterFixture(); var installer=new RouterInstaller(fake,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(c,CancellationToken.None);
        Assert.DoesNotContain(c.NtfyUrl,plan.ToString()); Assert.DoesNotContain(c.NtfyUrl,c.ToString());
        Assert.All(plan.Changes,s=>Assert.DoesNotContain(c.NtfyUrl,s));
    }
    [Fact] public async Task CurrentFirmwareStateReplacesOldReviewedHash()
    {
        var inner=new InstallerFixture.RouterFixture();var installer=new RouterInstaller(inner,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(InstallerFixture.Config(),default);
        // A prior attempt applied the recognized guard, but the UI still carries the stock hash.
        inner.MarkFirmwarePatched();
        Assert.True((await installer.InstallAsync(plan,new Progress<string>(),default)).Success);
        Assert.Equal(0,inner.RealPatches);
        Assert.Equal(CompatibilityCatalog.PatchedHash,inner.FirmwareHash);
    }
    [Fact] public async Task FreshStateWithUnknownFirmwareStillBlocksBeforeWrites()
    {
        var inner=new InstallerFixture.RouterFixture();var installer=new RouterInstaller(inner,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(InstallerFixture.Config(),default);
        inner.FirmwareHash=new string('f',64);
        await Assert.ThrowsAsync<SafeFailure>(()=>installer.InstallAsync(plan,new Progress<string>(),default));
        Assert.Empty(inner.Uploads);Assert.Empty(inner.Installed);
    }
    [Fact] public async Task OldPermissionsAndMissingGeneratedFilesConverge()
    {
        var inner=new InstallerFixture.RouterFixture();inner.Installed["/root/hotswapper-main.sh"]="previous content";
        var router=new RepairRouter(inner){PreviousMode=true};var installer=new RouterInstaller(router,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(InstallerFixture.Config(),default);
        Assert.Equal("755",plan.Snapshot.Files.Single(f=>f.Path=="/root/hotswapper-main.sh").Mode);
        Assert.True((await installer.InstallAsync(plan,new Progress<string>(),default)).Success);
        Assert.False(router.PreviousMode);
        Assert.Contains("/root/hotswapper/hotswapper-locations.tsv",inner.Installed.Keys);
        Assert.Contains("/root/hotswapper/reboot-guards.tsv",inner.Installed.Keys);
        Assert.Contains(router.Commands,c=>c.Contains("chmod 700")&&c.Contains("hotswapper-main.sh"));
        Assert.Contains(router.Commands,c=>c.Contains("chmod 600")&&c.Contains("hotswapper-locations.tsv"));
    }
    private sealed class RepairRouter(RouterFixture inner):IRouterTransport
    {
        public Task<IAsyncDisposable> AcquireInstallerLockAsync(CancellationToken ct)=>inner.AcquireInstallerLockAsync(ct);
        public bool PreviousMode;
        public List<string> Commands=[];
        public Task UploadAsync(string p,string s,CancellationToken ct)=>inner.UploadAsync(p,s,ct);
        public async Task<string> ExecuteAsync(string c,CancellationToken ct)
        {
            Commands.Add(c);
            if(c==FileMetadata.ListingCommand("/root/hotswapper-main.sh")&&PreviousMode)return "-rwxr-xr-x 1 0 0 123 Sep 1 script";
            string result=await inner.ExecuteAsync(c,ct);
            if(c.Contains("cp -p")&&c.Contains("/hotswapper-main.sh"))PreviousMode=false;
            return result;
        }
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task CurrentLayoutRepairAndReinstallReconcileDuplicateDaemons(bool maintenance)
    {
        var fake=new InstallerFixture.RouterFixture{Running=true,Cron=CronPlanner.Supervisor+"\n"+CronPlanner.Supervisor+"\n15 1 * * * /root/user-job\n"};
        fake.Installed["/root/hotswapper-main.sh"]="previous current-layout script";
        var router=new Intercept(fake){Duplicates=true};
        var installer=new RouterInstaller(router,new KillSwitchVerifier());
        var c=InstallerFixture.Config() with {Maintenance=maintenance};
        var plan=await installer.PlanAsync(c,default);
        Assert.True(plan.Snapshot.WatchdogRunning);
        Assert.True((await installer.InstallAsync(plan,new Progress<string>(),default)).Success);
        Assert.Contains("previous current-layout script",fake.Backups.Values);
        Assert.Equal(11, fake.Installed.Count);
        Assert.Contains("user-job",fake.Cron);
        Assert.Equal(1,fake.Cron.Split('\n').Count(l=>l==CronPlanner.Supervisor));
        Assert.Equal(maintenance?1:0,fake.Cron.Split('\n').Count(l=>l==CronPlanner.Maintenance));
        var again=await installer.PlanAsync(c with {Router=c.Router with {Rtp2Hash=CompatibilityCatalog.PatchedHash}},default);
        Assert.True((await installer.InstallAsync(again,new Progress<string>(),default)).Success);
        Assert.Equal(1,fake.RealPatches);
    }
    [Fact] public async Task PostInstallFailureNamesOperationAndRestartsPreviousRuntime()
    {
        var fake=new InstallerFixture.RouterFixture{Running=true};
        fake.Installed["/root/hotswapper-main.sh"]="old script";
        fake.Installed["/root/hotswapper-supervisor.sh"]="old supervisor";
        var router=new Intercept(fake){FailStatus=true};
        var installer=new RouterInstaller(router,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(InstallerFixture.Config(),default);
        var error=await Assert.ThrowsAsync<SafeFailure>(()=>installer.InstallAsync(plan,new Progress<string>(),default));
        Assert.Contains("hotswapper status command",error.Message);Assert.Contains("exit status 7",error.Message);
        Assert.Contains("rolled back",error.Message);Assert.True(fake.Running);
        Assert.Equal("old script",fake.Installed["/root/hotswapper-main.sh"]);
    }
    [Fact] public async Task OptionalHandshakeFailureDoesNotInvalidateInstallation()
    {
        var router=new Intercept(new InstallerFixture.RouterFixture()){FailHandshake=true};
        var installer=new RouterInstaller(router,new KillSwitchVerifier());
        var result=await installer.InstallAsync(await installer.PlanAsync(InstallerFixture.Config(),default),new Progress<string>(),default);
        Assert.True(result.Success);Assert.Contains(result.Checks,c=>c.StartsWith("WARN: A WireGuard"));
    }
    private sealed class Intercept(InstallerFixture.RouterFixture inner):IRouterTransport
    {
        public Task<IAsyncDisposable> AcquireInstallerLockAsync(CancellationToken ct)=>inner.AcquireInstallerLockAsync(ct);
        public bool Duplicates,FailStatus,FailHandshake;
        public Task UploadAsync(string p,string s,CancellationToken ct)=>inner.UploadAsync(p,s,ct);
        public Task<string> ExecuteAsync(string c,CancellationToken ct) {
            if(c==HotswapRuntime.ScanCommand&&Duplicates&&inner.Running)return Task.FromResult("123 1 daemon\n124 123 daemon\n125 1 daemon");
            if(c.Contains("kill -TERM")) Duplicates=false;
            if(c=="/root/hotswapper-main.sh status"&&FailStatus){FailStatus=false;throw new RouterCommandFailure(7);}
            if(c.StartsWith("wg show")&&FailHandshake)throw new RouterCommandFailure(1);
            return inner.ExecuteAsync(c,ct);
        }
    }
}
