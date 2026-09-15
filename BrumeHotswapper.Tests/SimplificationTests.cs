using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Tests;
public class SimplificationTests
{
    [Theory][InlineData(" my-topic ")][InlineData(" https://ntfy.sh/my-topic ")]
    public void SharedTopicNormalization(string input)
    {
        Assert.Equal("https://ntfy.sh/my-topic",NtfyTopic.Normalize(input));
        var c=SecondPassTests.Config() with {Notifications=true,NtfyUrl=input};
        Assert.Contains("NTFY_URL='https://ntfy.sh/my-topic'",ConfigurationGenerator.PrivateConfig(c));
    }
    [Theory][InlineData("")][InlineData("has space")][InlineData("https://other.invalid/topic")][InlineData("https://ntfy.sh/topic?secret=x")][InlineData("../topic")][InlineData("https://ntfy.sh/")]
    public void InvalidTopicIsRejected(string input)=>Assert.Throws<SafeFailure>(()=>NtfyTopic.Normalize(input));
    [Fact] public void DiscoveryUsesGatewayAndNonGatewaySubnetEdgesWithoutScanning()
    {
        var candidates=RouterDiscovery.Candidates([new("10.20.30.40",24,["10.20.30.253"]),new("172.20.8.10",24,[])]);
        Assert.Equal("10.20.30.253",candidates[0]);
        Assert.Contains("172.20.8.1",candidates);Assert.Contains("172.20.8.254",candidates);
        Assert.DoesNotContain("10.20.30.40",candidates);Assert.True(candidates.Count<=16);
        Assert.Empty(RouterDiscovery.Candidates([new("10.0.0.1",32,[])]));
    }
    [Fact] public void ForkChildrenAreNotDuplicateDaemons()
    {
        var roots=HotswapRuntime.Roots("10 1 daemon\n11 10 daemon\n12 11 daemon\n20 1 supervisor\n21 20 supervisor");
        Assert.Equal(new[]{"10","20"},roots.Select(p=>p.Pid));
    }
    [Fact] public async Task TransientDuplicatesSettleToLockOwner()
    {
        var router=new ProcessFixture(["10 1 daemon\n20 1 daemon","10 1 daemon\n11 10 daemon","10 1 daemon"]);
        await new HotswapRuntime(router,_=>Task.CompletedTask).WaitForOneAsync(default);
        Assert.Equal(3,router.Reads);
    }
    [Fact] public async Task AllOwnedDaemonsAndSupervisorAreStopped()
    {
        var router=new ProcessFixture(["10 1 daemon\n20 1 daemon\n30 1 supervisor","",""]);
        await new HotswapRuntime(router,_=>Task.CompletedTask).StopAsync(default);
        Assert.Equal(3,router.Commands.Count(c=>c.Contains("kill -TERM")));
        Assert.DoesNotContain(router.Commands,c=>c.Contains("kill -TERM 999"));
        Assert.Contains("kill -TERM 30",router.Commands.First(c=>c.Contains("kill -TERM")));
    }
    [Fact] public async Task UnsettledRuntimeHasActionableFailure()
    {
        var router=new ProcessFixture(["10 1 daemon\n20 1 daemon"]);
        var error=await Assert.ThrowsAsync<SafeFailure>(()=>new HotswapRuntime(router,_=>Task.CompletedTask).WaitForOneAsync(default));
        Assert.Contains("within 10 seconds",error.Message);Assert.Equal(20,router.Reads);
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task MigrationAndRepeatedInstallReconcileDuplicateDaemons(bool maintenance)
    {
        var fake=new SecondPassTests.RouterFixture{Running=true,Cron=CronPlanner.Supervisor+"\n"+CronPlanner.Supervisor+"\n15 1 * * * /root/user-job\n"};
        fake.Installed["/root/vpn-watch.sh"]="legacy script";
        var router=new Intercept(fake){Duplicates=true};
        var installer=new RouterInstaller(router,new KillSwitchVerifier());
        var c=SecondPassTests.Config() with {Maintenance=maintenance};
        var plan=await installer.PlanAsync(c,default);
        Assert.True(plan.Snapshot.WatchdogRunning);
        Assert.True((await installer.InstallAsync(plan,new Progress<string>(),default)).Success);
        Assert.Contains("legacy script",fake.Backups.Values);
        Assert.Equal(7,fake.Installed.Count);
        Assert.Contains("user-job",fake.Cron);
        Assert.Equal(1,fake.Cron.Split('\n').Count(l=>l==CronPlanner.Supervisor));
        Assert.Equal(maintenance?1:0,fake.Cron.Split('\n').Count(l=>l==CronPlanner.Maintenance));
        var again=await installer.PlanAsync(c with {Router=c.Router with {Rtp2Hash=CompatibilityCatalog.PatchedHash}},default);
        Assert.True((await installer.InstallAsync(again,new Progress<string>(),default)).Success);
        Assert.Equal(1,fake.RealPatches);
    }
    [Fact] public async Task PostInstallFailureNamesOperationAndRestartsPreviousRuntime()
    {
        var fake=new SecondPassTests.RouterFixture{Running=true};
        fake.Installed["/root/vpn-watch.sh"]="old script";
        fake.Installed["/root/vpn-watch-supervisor.sh"]="old supervisor";
        var router=new Intercept(fake){FailStatus=true};
        var installer=new RouterInstaller(router,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(SecondPassTests.Config(),default);
        var error=await Assert.ThrowsAsync<SafeFailure>(()=>installer.InstallAsync(plan,new Progress<string>(),default));
        Assert.Contains("vpn-watch status command",error.Message);Assert.Contains("exit status 7",error.Message);
        Assert.Contains("rolled back",error.Message);Assert.True(fake.Running);
        Assert.Equal("old script",fake.Installed["/root/vpn-watch.sh"]);
    }
    [Fact] public async Task OptionalHandshakeFailureDoesNotInvalidateInstallation()
    {
        var router=new Intercept(new SecondPassTests.RouterFixture()){FailHandshake=true};
        var installer=new RouterInstaller(router,new KillSwitchVerifier());
        var result=await installer.InstallAsync(await installer.PlanAsync(SecondPassTests.Config(),default),new Progress<string>(),default);
        Assert.True(result.Success);Assert.Contains(result.Checks,c=>c.StartsWith("WARN: A WireGuard"));
    }
    private sealed class Intercept(SecondPassTests.RouterFixture inner):IRouterTransport
    {
        public bool Duplicates,FailStatus,FailHandshake;
        public Task UploadAsync(string p,string s,CancellationToken ct)=>inner.UploadAsync(p,s,ct);
        public Task<string> ExecuteAsync(string c,CancellationToken ct) {
            if(c==HotswapRuntime.ScanCommand&&Duplicates&&inner.Running)return Task.FromResult("123 1 daemon\n124 123 daemon\n125 1 daemon");
            if(c.Contains("kill -TERM")) Duplicates=false;
            if(c=="/root/vpn-watch.sh status"&&FailStatus){FailStatus=false;throw new RouterCommandFailure(7);}
            if(c.StartsWith("wg show")&&FailHandshake)throw new RouterCommandFailure(1);
            return inner.ExecuteAsync(c,ct);
        }
    }
    [Theory][InlineData("installed",true)][InlineData("rolled-back",true)][InlineData("",false)][InlineData("in-progress",false)]
    public async Task StaleStateRequiresVerifiedCompletion(string completion,bool accepted)
    {
        var router=new TransactionState(completion);
        if(accepted) {
            await RouterPrerequisites.EnsureNoTransactionAsync(router,default);
            Assert.False(router.Archived);
            await RouterPrerequisites.ArchiveCompletedAsync(router,default);
            Assert.True(router.Archived);
        } else {
            var error=await Assert.ThrowsAsync<SafeFailure>(()=>RouterPrerequisites.ArchiveCompletedAsync(router,default));
            Assert.Contains("Retain the journal",error.Message);Assert.False(router.Archived);
        }
    }
    private sealed class TransactionState(string completion):IRouterTransport
    {
        public bool Archived;
        public Task UploadAsync(string p,string s,CancellationToken ct)=>throw new Exception();
        public Task<string> ExecuteAsync(string c,CancellationToken ct) {
            if(c==RouterPrerequisites.PendingCommand)return Task.FromResult("pending");
            if(c==RouterPrerequisites.CompletionCommand)return Task.FromResult(completion);
            if(c.Contains("mv /root/.hotswap-installer/transaction")){Assert.DoesNotContain("rm -rf",c);Archived=true;return Task.FromResult("");}
            throw new Exception("Unexpected command");
        }
    }
    private sealed class ProcessFixture(string[] samples):IRouterTransport
    {
        public int Reads; public List<string> Commands=[];
        public Task UploadAsync(string p,string s,CancellationToken ct)=>throw new Exception();
        public Task<string> ExecuteAsync(string command,CancellationToken ct) {
            Commands.Add(command);
            if(command==HotswapRuntime.ScanCommand)return Task.FromResult(samples[Math.Min(Reads++,samples.Length-1)]);
            if(command==HotswapRuntime.PidCommand)return Task.FromResult("10");
            if(command.Contains("kill -TERM")||command.StartsWith("test ! -L /tmp/vpn-watch/supervisor-start"))return Task.FromResult("");
            throw new Exception("Unexpected command");
        }
    }
}
