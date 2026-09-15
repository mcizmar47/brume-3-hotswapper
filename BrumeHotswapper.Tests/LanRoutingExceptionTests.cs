using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
using BrumeHotswapper.Preflight;
namespace BrumeHotswapper.Tests;
public class LanRoutingExceptionTests
{
    [Theory]
    [InlineData("192.168.8.1","255.255.255.0","192.168.8.0",24,"br-lan","9910")]
    [InlineData("10.70.4.17","255.255.252.0","10.70.4.0",22,"home0","52780")]
    public async Task ConfiguredKernelLanLinkIsAcceptedWithoutSnapshotConstants(string ip,string mask,string network,int prefix,string device,string table)
    {
        var router=new Fixture { Address=ip,Mask=mask,Device=device,Prefix=prefix,EarlierTable=table };
        router.Earlier=$"{network}/{prefix} dev {device} proto kernel scope link src {ip}";
        await new KillSwitchVerifier().VerifyAsync(new ReadOnlyTransport(router),"vpn",default);
        Assert.Contains("ip -o -4 addr show",router.Reads);
    }
    [Theory]
    [InlineData("default dev eth0")]
    [InlineData("198.51.100.0/24 dev eth0 proto kernel scope link src 198.51.100.1")]
    [InlineData("192.0.2.0/24 dev unknown0 proto kernel scope link src 192.0.2.1")]
    [InlineData("192.0.2.0/24 via 192.0.2.254 dev home0 proto kernel scope link src 192.0.2.1")]
    [InlineData("192.0.2.0/24 dev home0 proto static scope link src 192.0.2.1")]
    [InlineData("192.0.2.0/24 dev home0 proto kernel scope link src 192.0.2.1 nexthop via 192.0.2.254")]
    [InlineData("198.51.100.0/24 dev home0 proto kernel scope link src 192.0.2.1")]
    public async Task NonlocalOrUnprovenRouteBlocks(string route)
    {
        var router=new Fixture { Earlier=route,Suppress=false };
        await Assert.ThrowsAsync<SafeFailure>(()=>new KillSwitchVerifier().VerifyAsync(router,"vpn",default));
    }
    [Fact] public async Task SuppressedDefaultStillFallsThrough()
    {
        var router=new Fixture { Earlier="default dev eth0",Suppress=true };
        await new KillSwitchVerifier().VerifyAsync(router,"vpn",default);
        Assert.DoesNotContain("ip -o -4 addr show",router.Reads);
    }
    [Theory]
    [InlineData("blackhole default metric 254")]
    [InlineData("default dev wgclient1\nblackhole default metric 254")]
    [InlineData("default dev wgclient2")]
    [InlineData("default dev wgclient2\nblackhole default metric 254\n192.0.2.0/24 dev home0 proto kernel scope link src 192.0.2.1")]
    public async Task LanExceptionCannotRelaxSelectedVpnTable(string routes)
    {
        var router=new Fixture { Selected=routes };
        await Assert.ThrowsAsync<SafeFailure>(()=>new KillSwitchVerifier().VerifyAsync(router,"vpn",default));
    }
    [Theory][InlineData(true)][InlineData(false)]
    public async Task MissingOrAmbiguousKernelLanEvidenceBlocks(bool unavailable)
    {
        var router=new Fixture { MissingEvidence=unavailable,AmbiguousEvidence=!unavailable };
        await Assert.ThrowsAsync<SafeFailure>(()=>new KillSwitchVerifier().VerifyAsync(router,"vpn",default));
    }
    private sealed class Fixture:IRouterTransport
    {
        public string Address="192.0.2.1",Mask="255.255.255.0",Device="home0",EarlierTable="52780";
        public int Prefix=24;public bool Suppress=true,MissingEvidence,AmbiguousEvidence;
        public string Earlier="192.0.2.0/24 dev home0 proto kernel scope link src 192.0.2.1";
        public string Selected="default dev wgclient2 proto static scope link\nblackhole default proto static metric 254";
        public List<string> Reads=[];
        public Task UploadAsync(string p,string c,CancellationToken ct)=>throw new Exception("No writes allowed");
        public Task<string> ExecuteAsync(string c,CancellationToken ct)
        {
            Reads.Add(c);
            if(c=="ip -o -4 addr show"&&MissingEvidence)throw new SafeFailure("Kernel LAN evidence unavailable.");
            return Task.FromResult(c switch {
                "uci -q get route_policy.vpn.killswitch || true" or "uci -q get route_policy.vpn.enabled || true"=>"1",
                "uci -q get glipv6.globals.enabled || true"=>"0",
                "uci -q get route_policy.vpn.tunnel_id"=>"42",
                "uci -q get route_policy.vpn.mark"=>"0x2000",
                "uci -q get route_policy.vpn.via"=>"wgclient2",
                "iptables -w -t mangle -S TUNNEL42_ROUTE_POLICY"=>"-A TUNNEL42_ROUTE_POLICY -m mark --mark 0x0/0xf000 -j MARK --set-xmark 0x2000/0xf000\n-A TUNNEL42_ROUTE_POLICY -m mark --mark 0x0/0xf000 -j DROP",
                var x when x.StartsWith("iptables -w -t mangle -C")=>"",
                "ip -4 rule show"=>$"0: from all lookup local\n800: from all lookup {EarlierTable}"+(Suppress?" suppress_prefixlength 0":"")+"\n6000: from all fwmark 0x8000/0xf000 lookup main\n6000: from all fwmark 0x2000/0xf000 lookup 1002\n9910: not from all fwmark 0/0xf000 blackhole\n32766: from all lookup main",
                var x when x=="ip -4 route show table "+EarlierTable=>Earlier,
                "ip -4 route show table 1002"=>Selected,
                "uci -q get network.lan.ipaddr"=>Address,
                "uci -q get network.lan.netmask"=>Mask,
                "ip -o -4 addr show"=>$"4: {Device}    inet {Address}/{Prefix} brd 192.0.2.255 scope global {Device}\n"+(AmbiguousEvidence?$"5: other0 inet {Address}/{Prefix} scope global other0\n":""),
                _=>throw new Exception("Unexpected production read")
            });
        }
    }
}
