using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Tests;
public class EmptyRoutingTableTests
{
    [Theory]
    [InlineData("",true)]
    [InlineData("default dev wgclient2 table 1002\n192.0.2.0/24 dev br-lan table 9910",true)]
    [InlineData("default dev eth0 table 16800",false)]
    [InlineData("default dev eth0 table custom_alias",false)]
    [InlineData("Dump terminated",false)]
    public void CompleteDumpMustProveAbsence(string dump,bool empty)=>Assert.Equal(empty,RoutingProtection.ProvesEmptyTable(dump,"16800"));
    private const string Selected="6000: from all fwmark 0x2000/0xf000 lookup 1002";
    private const string Rules="0: from all lookup local\n1: from all iif lo lookup 16800\n800: from all lookup 9910 suppress_prefixlength 0\n"+Selected+"\n9910: not from all fwmark 0/0xf000 blackhole";
    [Theory][InlineData(false)][InlineData(true)]
    public async Task EmptyEarlierLookupFallsThroughButSpecificLanRouteDoesNot(bool lan)
    {
        var router=new Fixture { SpecificLan=lan };
        if(lan) {
            var error=await Assert.ThrowsAsync<SafeFailure>(()=>RoutingProtection.EarlierRulesSafeAsync(router,Rules,Selected,6000,0x2000,"wgclient2",default));
            Assert.Contains("priority 800",error.Message);Assert.Contains("LAN evidence",error.Message);
        } else Assert.True(await RoutingProtection.EarlierRulesSafeAsync(router,Rules,Selected,6000,0x2000,"wgclient2",default));
    }
    [Fact] public async Task UnreadableGlobalDumpStillBlocks()
    {
        await Assert.ThrowsAsync<SafeFailure>(()=>RoutingProtection.EarlierRulesSafeAsync(new Fixture { GlobalFails=true },Rules,Selected,6000,0x2000,"wgclient2",default));
    }
    private sealed class Fixture:IRouterTransport {
        public bool SpecificLan,GlobalFails;
        public Task UploadAsync(string p,string c,CancellationToken ct)=>throw new Exception("No writes");
        public Task<string> ExecuteAsync(string c,CancellationToken ct)=>c switch {
            "ip -4 route show table 16800"=>throw new SafeFailure("Dump terminated"),
            "ip -4 route show table all" when GlobalFails=>throw new SafeFailure("Unavailable"),
            "ip -4 route show table all"=>Task.FromResult("default dev wgclient2 table 1002\nblackhole default table 1002 metric 254"),
            "ip -4 route show table 9910"=>Task.FromResult(SpecificLan?"192.0.2.0/24 dev br-lan proto kernel scope link":"default dev eth0"),
            _=>throw new Exception("Unexpected command")
        };
    }
}
