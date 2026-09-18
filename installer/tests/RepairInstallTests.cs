using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Tests;
public class RepairInstallTests
{
    [Fact] public async Task RepairTouchesOnlyCurrentLayout()
    {
        var inner=new SecondPassTests.RouterFixture();
        inner.Installed["/root/hotswapper-main.sh"]="partial installation";
        var router=new RepairRouter(inner);
        var installer=new RouterInstaller(router,new KillSwitchVerifier());
        Assert.True((await installer.InstallAsync(await installer.PlanAsync(SecondPassTests.Config(),default),new Progress<string>(),default)).Success);
        Assert.Equal(8,inner.Installed.Count);
        Assert.DoesNotContain(router.Commands,c=>c.Contains("legacy-")||c.Contains("journal.json")||c.Contains("/transaction"));
        Assert.All(router.Uploads,p=>Assert.StartsWith("/root/hotswapper/installer/run-",p));
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task FailedReplacementAndCleanupCanBeRetried(bool cleanupFails)
    {
        var inner=new SecondPassTests.RouterFixture();
        var router=new RepairRouter(inner){FailAfterReplacement=true,FailCleanup=cleanupFails};
        var installer=new RouterInstaller(router,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(SecondPassTests.Config(),default);
        var error=await Assert.ThrowsAsync<SafeFailure>(()=>installer.InstallAsync(plan,new Progress<string>(),default));
        Assert.Contains("Install scripts and configuration",error.Message);
        Assert.Empty(inner.Installed);
        router.FailCleanup=false;
        Assert.True((await installer.InstallAsync(plan,new Progress<string>(),default)).Success);
        Assert.Equal(2,router.Stages.Distinct().Count());
        Assert.Equal(8,inner.Installed.Count);
    }
    [Fact] public async Task CurrentFirmwareStateReplacesOldReviewedHash()
    {
        var inner=new SecondPassTests.RouterFixture();var installer=new RouterInstaller(inner,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(SecondPassTests.Config(),default);
        // A prior attempt applied the recognized guard, but the UI still carries the stock hash.
        inner.FirmwareHash=CompatibilityCatalog.PatchedHash;
        Assert.True((await installer.InstallAsync(plan,new Progress<string>(),default)).Success);
        Assert.Equal(0,inner.RealPatches);
        Assert.Equal(CompatibilityCatalog.PatchedHash,inner.FirmwareHash);
    }
    [Fact] public async Task FreshStateWithUnknownFirmwareStillBlocksBeforeWrites()
    {
        var inner=new SecondPassTests.RouterFixture();var installer=new RouterInstaller(inner,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(SecondPassTests.Config(),default);
        inner.FirmwareHash=new string('f',64);
        await Assert.ThrowsAsync<SafeFailure>(()=>installer.InstallAsync(plan,new Progress<string>(),default));
        Assert.Empty(inner.Uploads);Assert.Empty(inner.Installed);
    }
    [Fact] public async Task OldPermissionsAndMissingGeneratedFilesConverge()
    {
        var inner=new SecondPassTests.RouterFixture();inner.Installed["/root/hotswapper-main.sh"]="previous content";
        var router=new RepairRouter(inner){PreviousMode=true};var installer=new RouterInstaller(router,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(SecondPassTests.Config(),default);
        Assert.Equal("755",plan.Snapshot.Files.Single(f=>f.Path=="/root/hotswapper-main.sh").Mode);
        Assert.True((await installer.InstallAsync(plan,new Progress<string>(),default)).Success);
        Assert.False(router.PreviousMode);
        Assert.Contains("/root/hotswapper/hotswapper-locations.tsv",inner.Installed.Keys);
        Assert.Contains("/root/hotswapper/reboot-guards.tsv",inner.Installed.Keys);
        Assert.Contains(router.Commands,c=>c.Contains("chmod 700")&&c.Contains("hotswapper-main.sh"));
        Assert.Contains(router.Commands,c=>c.Contains("chmod 600")&&c.Contains("hotswapper-locations.tsv"));
    }
    [Fact] public async Task DuplicateSupervisorRootsAreBothReconciled()
    {
        var inner=new SecondPassTests.RouterFixture();var router=new RepairRouter(inner){SupervisorCount=2};
        var installer=new RouterInstaller(router,new KillSwitchVerifier());
        Assert.True((await installer.InstallAsync(await installer.PlanAsync(SecondPassTests.Config(),default),new Progress<string>(),default)).Success);
        Assert.Contains(router.Commands,c=>c.Contains("kill -TERM 200"));Assert.Contains(router.Commands,c=>c.Contains("kill -TERM 201"));
        Assert.Equal(0,router.SupervisorCount);Assert.True(inner.Running);
    }
    private sealed class RepairRouter(SecondPassTests.RouterFixture inner):IRouterTransport
    {
        public bool FailAfterReplacement,FailCleanup,PreviousMode;
        public int SupervisorCount;
        public List<string> Commands=[],Uploads=[],Stages=[];
        public Task UploadAsync(string p,string s,CancellationToken ct){Uploads.Add(p);return inner.UploadAsync(p,s,ct);}
        public async Task<string> ExecuteAsync(string c,CancellationToken ct)
        {
            Commands.Add(c);
            if(c.Contains("mkdir /root/hotswapper/installer/run-"))Stages.Add(Regex.Match(c,@"/run-[a-f0-9]{32}").Value);
            if(c.Contains("journal.json")||c.Contains("/completed")||c.Contains("/owner"))throw new Exception("No previous intent may be read");
            if(c.Contains("rm -rf /root/hotswapper/installer/run-")&&FailCleanup)throw new RouterCommandFailure(1);
            if(c==HotswapRuntime.ScanCommand&&SupervisorCount>0)return "200 1 supervisor\n201 1 supervisor";
            if(c.Contains("kill -TERM 200")||c.Contains("kill -TERM 201")){SupervisorCount--;return "";}
            if(c==FileMetadata.ListingCommand("/root/hotswapper-main.sh")&&PreviousMode)return "-rwxr-xr-x 1 0 0 123 Sep 1 legacy";
            string result=await inner.ExecuteAsync(c,ct);
            if(c.Contains("cp -p")&&c.Contains("/hotswapper-main.sh"))PreviousMode=false;
            if(c.Contains("cp -p")&&FailAfterReplacement){FailAfterReplacement=false;throw new RouterCommandFailure(1);}
            return result;
        }
    }
}
