using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Tests;
public class RuntimeValidationTests
{
    private static InstallerConfiguration Config()
    {
        var c = InstallerFixture.Config();
        var peers = Enumerable.Range(1, 5).Select(n => new VpnConnection((10+n).ToString(), "Synthetic", "Pool"+n+",Site")).ToArray();
        var tiers = new[] {new TierColumn("Unassigned",0),new TierColumn("Tier 1",1),new TierColumn("Tier 2",2),new TierColumn("Tier 3",3)};
        for (int i=0; i<5; i++) tiers[i==0?1:i<3?2:3].Locations.Add(new ExactLocationResolver().Group([peers[i]])[0]);
        return c with { Profile = c.Profile with { Connections=peers }, Tiers=tiers };
    }
    private static string Role(string name, int rank, string slot) => rank==0 ? $"{name}_iface=\n{name}_peer=\n{name}_rank=0\n{name}_tier=0\n"
        : $"{name}_iface={slot}\n{name}_peer={10+rank}\n{name}_rank={rank}\n{name}_tier={(rank==1?1:rank<4?2:3)}\n";
    [Theory]
    [InlineData(1,0,2)][InlineData(2,1,0)][InlineData(3,1,0)][InlineData(3,2,0)]
    [InlineData(3,0,4)][InlineData(4,1,0)][InlineData(4,2,0)][InlineData(5,0,0)]
    public void DirectionalTopologyUsesConfiguredRanks(int current,int up,int down)
    {
        Assert.True(RuntimeValidation.IsHealthy(Role("current",current,"wgclient2")+Role("uptier",up,"wgclient1")+Role("downtier",down,"wgclient3"),Config()));
    }
    [Theory]
    [InlineData(1,2,0)][InlineData(3,4,0)][InlineData(5,4,0)][InlineData(3,1,4)][InlineData(2,0,4)]
    public void InvalidDirectionOrTwoRetainedHotRolesRejected(int current,int up,int down)
    {
        Assert.False(RuntimeValidation.IsHealthy(Role("current",current,"wgclient2")+Role("uptier",up,"wgclient1")+Role("downtier",down,"wgclient3"),Config()));
    }
    [Fact] public void PhysicalSlotsAreDistinctAndCanRotate()
    {
        foreach (var (current,up) in new[] {("wgclient1","wgclient2"),("wgclient2","wgclient3"),("wgclient3","wgclient1")})
            Assert.True(RuntimeValidation.IsHealthy(Role("current",3,current)+Role("uptier",1,up)+Role("downtier",0,""),Config()));
        Assert.False(RuntimeValidation.IsHealthy(Role("current",3,"wgclient1")+Role("uptier",1,"wgclient1"),Config()));
    }
    [Fact] public void OnlyCurrentLayoutIsDeployed()
    {
        Assert.Equal(new[] {"/root/hotswapper-main.sh","/root/hotswapper-supervisor.sh","/root/hotswapper-housekeeping.sh",
            "/root/hotswapper/hotswapper.conf","/root/hotswapper/hotswapper-locations.tsv","/root/hotswapper/reboot-guards.tsv",
            "/root/hotswapper/housekeeping.conf","/root/hotswapper/install-gl-guard.sh","/root/hotswapper/gl-coordination.sh",
            "/root/hotswapper/gl-patches.awk","/root/hotswapper/gl-targets.tsv"}.Concat(FirmwareTargets.All.Select(t=>t.Path)),DeploymentPlanning.Paths);
        DeploymentUpload.ValidatePath("/root/hotswapper/installer/run-"+new string('a',32)+"/hotswapper-main.sh");
        Assert.Contains("/tmp/hotswapper/lock/pid",HotswapRuntime.PidCommand);
    }
    [Fact] public void StatusAllowsAbsentAuxiliariesButRequiresDirectionalLabels()
    {
        Assert.True(RuntimeValidation.ValidStatus("CURRENT: wgclient2 peer=12 tier=2\nUPTIER: none\nDOWNTIER: wgclient3 preparing\n"));
        Assert.False(RuntimeValidation.ValidStatus("CURRENT: wgclient2 peer=12 tier=2\nDOWNTIER: none\n"));
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
    private sealed class ProcessFixture(string[] samples):IRouterTransport
    {
        public int Reads; public List<string> Commands=[];
        public Task UploadAsync(string p,string s,CancellationToken ct)=>throw new Exception();
        public Task<string> ExecuteAsync(string command,CancellationToken ct) {
            Commands.Add(command);
            if(command==HotswapRuntime.ScanCommand)return Task.FromResult(samples[Math.Min(Reads++,samples.Length-1)]);
            if(command==HotswapRuntime.PidCommand)return Task.FromResult("10");
            if(command.Contains("kill -TERM")||command.StartsWith("test ! -L /tmp/hotswapper/supervisor-start"))return Task.FromResult("");
            throw new Exception("Unexpected command");
        }
    }
}
