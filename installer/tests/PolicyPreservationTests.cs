using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Tests;
public class PolicyPreservationTests
{
    [Theory][InlineData("0")][InlineData("1")]
    public async Task ExistingChoiceAndUnrelatedRoutingAreSupported(string setting)
    {
        var router = new Fixture(setting);
        await new KillSwitchVerifier().VerifyAsync(router,"vpn",default);
        Assert.DoesNotContain(router.Commands,c=>c.Contains("table 9910") || c.Contains("table 16800"));
        if(setting=="0") Assert.DoesNotContain(router.Commands,c=>c.StartsWith("iptables"));
    }
    [Theory][InlineData("0")][InlineData("1")]
    public async Task WrongActiveRouteBlocksInBothModes(string setting)
    {
        var router=new Fixture(setting){Routes="default dev wgclient3\nblackhole default metric 254"};
        await Assert.ThrowsAsync<SafeFailure>(()=>new KillSwitchVerifier().VerifyAsync(router,"vpn",default));
    }
    [Theory][InlineData("0")][InlineData("1")]
    public async Task WrongSelectedTableBlocksInBothModes(string setting)
    {
        var router=new Fixture(setting){Table="1003"};
        await Assert.ThrowsAsync<SafeFailure>(()=>new KillSwitchVerifier().VerifyAsync(router,"vpn",default));
    }
    [Fact] public async Task EnabledRequiresEnforcement()
    {
        await Assert.ThrowsAsync<SafeFailure>(()=>new KillSwitchVerifier().VerifyAsync(new Fixture("1"){Firewall=""},"vpn",default));
    }
    [Theory][InlineData("0",false)][InlineData("1",false)][InlineData("0",true)][InlineData("1",true)]
    public async Task PlanningInstallationAndRollbackNeverWriteChoice(string setting,bool fail)
    {
        var inner=new SecondPassTests.RouterFixture{RejectPatch=fail};
        var router=new TransactionFixture(inner,setting);
        var installer=new RouterInstaller(router,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(SecondPassTests.Config(),default);
        Assert.Equal(setting=="1",plan.Snapshot.KillSwitchEnabled);
        Assert.Empty(inner.Uploads);Assert.Empty(inner.Installed);
        if(fail) {
            var error=await Assert.ThrowsAsync<SafeFailure>(()=>installer.InstallAsync(plan,new Progress<string>(),default));
            Assert.Contains("rolled back",error.Message);
        } else Assert.True((await installer.InstallAsync(plan,new Progress<string>(),default)).Success);
        Assert.Equal(setting=="1",await KillSwitchVerifier.ReadEnabledAsync(router,"vpn",default));
    }
    [Theory][InlineData("0")][InlineData("1")]
    public async Task SlotConflictsBlockBothChoices(string setting)
    {
        var router=new TransactionFixture(new SecondPassTests.RouterFixture(),setting){Conflict=true};
        await Assert.ThrowsAsync<SafeFailure>(()=>new RouterInstaller(router,new KillSwitchVerifier()).PlanAsync(SecondPassTests.Config(),default));
    }
    [Theory][InlineData("0")][InlineData("1")]
    public async Task Ipv6IsAnIndependentProductionBlock(string setting)
    {
        var router=new TransactionFixture(new SecondPassTests.RouterFixture(),setting){Ipv6=true};
        await new KillSwitchVerifier().VerifyAsync(router,"vpn",default);
        var error=await Assert.ThrowsAsync<SafeFailure>(()=>new RouterInstaller(router,new KillSwitchVerifier()).PlanAsync(SecondPassTests.Config(),default));
        Assert.Contains("IPv6",error.Message);

    }
    private sealed class TransactionFixture(SecondPassTests.RouterFixture inner,string setting):IRouterTransport
    {
        public bool Conflict,Ipv6;
        public Task UploadAsync(string p,string s,CancellationToken ct)=>inner.UploadAsync(p,s,ct);
        public Task<string> ExecuteAsync(string c,CancellationToken ct)
        {
            if(c.Contains("killswitch")) {
                Assert.Equal("uci -q get route_policy.vpn.killswitch || true",c);
                return Task.FromResult(setting);
            }
            if(setting=="0") Assert.False(c.StartsWith("iptables"));
            if(Ipv6&&c=="uci -q get glipv6.globals.enabled || true")return Task.FromResult("1");
            if(Conflict&&c=="uci -q get network.wgclient2.config || true")return Task.FromResult("peer_99");
            if(Conflict&&c=="uci -q get wireguard.peer_99.group_id")return Task.FromResult("99");
            return inner.ExecuteAsync(c,ct);
        }
    }
    [Fact] public async Task DisabledNeedsNoTerminalDropRoute()
    {
        await new KillSwitchVerifier().VerifyAsync(new Fixture("0"){Routes="default dev wgclient2"},"vpn",default);
    }
    [Theory][InlineData("")][InlineData("2")]
    public async Task UnknownChoiceIsNotSilentlyDefaulted(string setting)
    {
        await Assert.ThrowsAsync<SafeFailure>(()=>new KillSwitchVerifier().VerifyAsync(new Fixture(setting),"vpn",default));
    }
    private sealed class Fixture(string setting):IRouterTransport
    {
        public string Table="1002",Routes="default dev wgclient2\nblackhole default metric 254";
        public string Firewall="-A TUNNEL42_ROUTE_POLICY -m mark --mark 0x0/0xf000 -j MARK --set-xmark 0x2000/0xf000\n-A TUNNEL42_ROUTE_POLICY -m mark --mark 0x0/0xf000 -j DROP";
        public List<string> Commands=[];
        public Task UploadAsync(string p,string s,CancellationToken ct)=>throw new Exception("No writes");
        public Task<string> ExecuteAsync(string c,CancellationToken ct)
        {
            Commands.Add(c);
            return Task.FromResult(c switch {
                "uci -q get route_policy.vpn.killswitch || true"=>setting,
                "uci -q get route_policy.vpn.enabled || true"=>"1",
                "uci -q get glipv6.globals.enabled || true"=>"0",
                "uci -q get route_policy.vpn.tunnel_id"=>"42",
                "uci -q get route_policy.vpn.mark"=>"0x2000",
                "uci -q get route_policy.vpn.via"=>"wgclient2",
                "ip -4 rule show"=>"1: from all iif lo lookup 16800\n800: from all lookup 9910 suppress_prefixlength 0\n6000: from all fwmark 0x2000/0xf000 lookup "+Table,
                "ip -4 route show table 1002" or "ip -4 route show table 1003"=>Routes,
                "iptables -w -t mangle -S TUNNEL42_ROUTE_POLICY" when setting=="1"=>Firewall,
                var x when x.StartsWith("iptables -w -t mangle -C") && setting=="1"=>"",
                _=>throw new SafeFailure("Unexpected read or mutation")
            });
        }
    }
}
