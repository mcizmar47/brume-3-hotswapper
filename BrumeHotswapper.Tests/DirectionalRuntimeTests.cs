using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Tests;

public class DirectionalRuntimeTests
{
    private static InstallerConfiguration Config()
    {
        var c = SecondPassTests.Config();
        var peers = Enumerable.Range(1, 5).Select(n => new VpnConnection((10+n).ToString(), "Synthetic", "Pool"+n+",Site")).ToArray();
        var tiers = new[] {new TierColumn("Unassigned",0),new TierColumn("Tier 1",1),new TierColumn("Tier 2",2),new TierColumn("Tier 3",3)};
        for (int i=0; i<5; i++) tiers[i==0?1:i<3?2:3].Locations.Add(new ExactLocationResolver().Group([peers[i]])[0]);
        return c with { Profile = c.Profile with { Connections=peers }, Tiers=tiers };
    }
    private static string Role(string name, int rank, string slot) => rank==0 ? $"{name}_iface=\n{name}_peer=\n{name}_rank=0\n{name}_tier=0\n"
        : $"{name}_iface={slot}\n{name}_peer={10+rank}\n{name}_rank={rank}\n{name}_tier={(rank==1?1:rank<4?2:3)}\n";
    [Theory]
    [InlineData(1,0,2)][InlineData(2,1,0)][InlineData(3,1,0)][InlineData(3,2,0)]
    [InlineData(3,0,4)][InlineData(4,0,5)][InlineData(5,0,0)]
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
            "/root/hotswapper/install-gl-guard.sh","/usr/bin/rtp2.sh"},DeploymentPlanning.Paths);
        DeploymentUpload.ValidatePath("/root/hotswapper/installer/run-"+new string('a',32)+"/hotswapper-main.sh");
        Assert.Contains("/tmp/hotswapper/lock/pid",HotswapRuntime.PidCommand);
    }
    [Fact] public void NewCronIsIdempotentAndUnrelatedEntriesSurvive()
    {
        const string unrelated="17 2 * * * /root/user-backup.sh\n";
        string generated=CronPlanner.Generate(unrelated,true);
        Assert.StartsWith(unrelated,generated);
        Assert.Contains("*/5 * * * * /root/hotswapper-supervisor.sh",generated);
        Assert.Contains("0 3-14 * * * /root/hotswapper-housekeeping.sh",generated);
        Assert.Equal(generated,CronPlanner.Generate(generated,true));
    }
    [Fact] public void StatusAllowsAbsentAuxiliariesButRequiresDirectionalLabels()
    {
        Assert.True(RuntimeValidation.ValidStatus("CURRENT: wgclient2 peer=12 tier=2\nUPTIER: none\nDOWNTIER: wgclient3 preparing\n"));
        Assert.False(RuntimeValidation.ValidStatus("CURRENT: wgclient2 peer=12 tier=2\nDOWNTIER: none\n"));
    }
}
