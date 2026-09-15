using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Tests;
public class RepairInstallTests
{
    [Fact] public async Task StaleJournalAndLockNeverGateRepair()
    {
        var inner=new SecondPassTests.RouterFixture();
        inner.Installed["/root/vpn-watch.sh"]="partial older installation";
        var router=new RepairRouter(inner){Legacy=true};
        var installer=new RouterInstaller(router,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(SecondPassTests.Config(),default);
        Assert.True(router.Legacy); // Planning neither reads nor recovers previous intent.
        Assert.True((await installer.InstallAsync(plan,new Progress<string>(),default)).Success);
        Assert.False(router.Legacy);Assert.True(router.LegacyLockArchived);
        Assert.Equal(7,inner.Installed.Count);
        Assert.DoesNotContain(router.Commands,c=>c.Contains("journal.json")||c.Contains("/owner")||c.Contains("mkdir /tmp/vpn-watch-installer-lock"));
        Assert.All(router.Uploads,p=>Assert.DoesNotContain("transaction",p));
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
        Assert.Equal(7,inner.Installed.Count);
    }
    [Fact] public async Task CurrentFirmwareStateReplacesOldReviewedHash()
    {
        var inner=new SecondPassTests.RouterFixture();var installer=new RouterInstaller(inner,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(SecondPassTests.Config(),default);
        // A prior attempt applied the recognized guard, but the UI still carries the stock hash.
        inner.FirmwareHash=CompatibilityCatalog.HistoricalPatchedHash;
        Assert.True((await installer.InstallAsync(plan,new Progress<string>(),default)).Success);
        Assert.Equal(0,inner.RealPatches);
        Assert.Equal(CompatibilityCatalog.HistoricalPatchedHash,inner.FirmwareHash);
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
        var inner=new SecondPassTests.RouterFixture();inner.Installed["/root/vpn-watch.sh"]="legacy";
        var router=new RepairRouter(inner){LegacyMode=true};var installer=new RouterInstaller(router,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(SecondPassTests.Config(),default);
        Assert.Equal("755",plan.Snapshot.Files.Single(f=>f.Path=="/root/vpn-watch.sh").Mode);
        Assert.True((await installer.InstallAsync(plan,new Progress<string>(),default)).Success);
        Assert.False(router.LegacyMode);
        Assert.Contains("/root/vpn-watch-locations.tsv",inner.Installed.Keys);
        Assert.Contains("/root/reboot-guards.tsv",inner.Installed.Keys);
        Assert.Contains(router.Commands,c=>c.Contains("chmod 700")&&c.Contains("vpn-watch.sh"));
        Assert.Contains(router.Commands,c=>c.Contains("chmod 600")&&c.Contains("vpn-watch-locations.tsv"));
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
        public bool Legacy,LegacyLockArchived,FailAfterReplacement,FailCleanup,LegacyMode;
        public int SupervisorCount;
        public List<string> Commands=[],Uploads=[],Stages=[];
        public Task UploadAsync(string p,string s,CancellationToken ct){Uploads.Add(p);return inner.UploadAsync(p,s,ct);}
        public async Task<string> ExecuteAsync(string c,CancellationToken ct)
        {
            Commands.Add(c);
            if(c.Contains("mkdir /root/.hotswap-installer/run-"))Stages.Add(Regex.Match(c,@"/run-[a-f0-9]{32}").Value);
            if(c.Contains("journal.json")||c.Contains("/completed")||c.Contains("/owner"))throw new Exception("No previous intent may be read");
            if(c.StartsWith("if [ -e '/root/.hotswap-installer/transaction'")){Legacy=false;return "";}
            if(c.StartsWith("if [ -e '/tmp/vpn-watch-installer-lock'")){LegacyLockArchived=true;return "";}
            if(c.Contains("rm -rf /root/.hotswap-installer/run-")&&FailCleanup)throw new RouterCommandFailure(1);
            if(c==HotswapRuntime.ScanCommand&&SupervisorCount>0)return "200 1 supervisor\n201 1 supervisor";
            if(c.Contains("kill -TERM 200")||c.Contains("kill -TERM 201")){SupervisorCount--;return "";}
            if(c==FileMetadata.ListingCommand("/root/vpn-watch.sh")&&LegacyMode)return "-rwxr-xr-x 1 0 0 123 Sep 1 legacy";
            string result=await inner.ExecuteAsync(c,ct);
            if(c.Contains("cp -p")&&c.Contains("/vpn-watch.sh"))LegacyMode=false;
            if(c.Contains("cp -p")&&FailAfterReplacement){FailAfterReplacement=false;throw new RouterCommandFailure(1);}
            return result;
        }
    }
}
