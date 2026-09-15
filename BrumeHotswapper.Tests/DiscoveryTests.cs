using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
using BrumeHotswapper.Installer.ViewModels;
namespace BrumeHotswapper.Tests;
public class DiscoveryTests
{
    [Fact] public async Task MultipleListsRequireExplicitSelectionAndUseAllowlistedFields()
    {
        var router = new DiscoveryRouter();
        var profiles = await new VpnDiscovery(router).DiscoverAsync(CancellationToken.None);
        Assert.Equal(2, profiles.Count); Assert.Null(VpnDiscovery.AutoSelect(profiles));
        Assert.Equal("902",profiles[1].TunnelId); Assert.Equal("72",profiles[1].GroupId);
        Assert.All(router.Commands, c => {
            Assert.DoesNotContain("uci -q show wireguard",c);
            Assert.DoesNotContain("private_key",c); Assert.DoesNotContain(".name",c);
        });
        Assert.Same(profiles[0],VpnDiscovery.AutoSelect([profiles[0]]));
    }
    [Fact] public void UnknownGuardRequiresAcknowledgementInWizard()
    {
        using var vm=new WizardViewModel((_,_)=>false);
        typeof(WizardViewModel).GetProperty(nameof(vm.Router))!.SetValue(vm,new RouterIdentity("192.0.2.1","GL-MT5000","glinet,gl-mt5000","4.9.0","unknown"));
        typeof(WizardViewModel).GetProperty(nameof(vm.Page))!.SetValue(vm,3);
        Assert.False(vm.NextCommand.CanExecute(null)); vm.UnknownAccepted=true; Assert.True(vm.NextCommand.CanExecute(null));
    }
    [Fact] public void NormalStartupDoesNotSelectDemo()
    {
        using var vm=new WizardViewModel((_,_)=>false); Assert.False(vm.Demo); Assert.Equal("",vm.ModeLabel);
    }
    [Theory]
    [InlineData("default dev wgclient1\nunreachable default metric 42760",true)]
    [InlineData("default dev wgclient1",false)]
    [InlineData("default dev eth0\nunreachable default metric 42760",false)]
    public async Task KillSwitchRequiresTerminalRouteAndVpnDefault(string routes,bool accepted)
    {
        var router=new RouteRouter(routes);
        if(accepted) await new KillSwitchVerifier().VerifyAsync(router,"vpn",CancellationToken.None);
        else await Assert.ThrowsAsync<SafeFailure>(()=>new KillSwitchVerifier().VerifyAsync(router,"vpn",CancellationToken.None));
    }
    private class RouteRouter(string routes) : IRouterTransport
    {
        public Task UploadAsync(string p,string c,CancellationToken ct)=>throw new Exception("No writes expected");
        public Task<string> ExecuteAsync(string cmd,CancellationToken ct)=>Task.FromResult(cmd switch {
            "uci -q get route_policy.vpn.mark"=>"0x1000",
            "uci -q get route_policy.vpn.via"=>"wgclient1",
            "ip -4 rule show"=>"0: from all lookup local\n100: from all fwmark 0x1000/0xf000 lookup 1001\n32766: from all lookup main\n",
            "ip -4 route show table 1001"=>routes,
            _=>throw new Exception("Unexpected read")
        });
    }
    private class DiscoveryRouter : IRouterTransport
    {
        public List<string> Commands=[];
        public Task UploadAsync(string p,string c,CancellationToken ct)=>throw new Exception("Discovery must not write");
        public Task<string> ExecuteAsync(string cmd,CancellationToken ct)
        {
            Commands.Add(cmd);
            return Task.FromResult(cmd switch {
                var c when c.StartsWith("uci -q show route_policy")=>"policyA 901\npolicyB 902\n",
                "uci -q get route_policy.policyA.group_id"=>"71",
                "uci -q get route_policy.policyB.group_id"=>"72",
                var c when c.Contains("profile901")=>"peer_501\n",
                var c when c.Contains("profile902")=>"peer_502\n",
                "uci -q get wireguard.peer_501.group_id || true"=>"71",
                "uci -q get wireguard.peer_502.group_id || true"=>"72",
                "uci -q get wireguard.peer_501.location || true"=>"Fictionland,Example",
                "uci -q get wireguard.peer_502.location || true"=>"Elsewhere,Another City",
                _=>throw new Exception("Unexpected discovery field")
            });
        }
    }
}
