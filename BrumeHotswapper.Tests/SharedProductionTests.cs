using System.IO;
using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
using BrumeHotswapper.Preflight;
namespace BrumeHotswapper.Tests;
public class SharedProductionTests
{
    [Theory]
    [InlineData("-rwxr-xr-x    1 0 0 55880 ... /root/vpn-watch.sh", "755", '-', 0, 0)]
    [InlineData("-rwx------ 1 0 0 10 Sep 12 2026 /root/name with spaces", "700", '-', 0, 0)]
    [InlineData("-rw------- 1 123 456 10 Sep 12 2026 /root/name", "600", '-', 123, 456)]
    [InlineData("-rwxrwxrwx 1 0 0 10 ...", "777", '-', 0, 0)]
    [InlineData("-rwsr-sr-t 1 0 0 10 ...", "7755", '-', 0, 0)]
    [InlineData("-rwSr-Sr-T 1 0 0 10 ...", "7644", '-', 0, 0)]
    [InlineData("drwx------ 2 0 0 4096 ...", "700", 'd', 0, 0)]
    [InlineData("lrwxrwxrwx 1 0 0 10 ... name -> target", "777", 'l', 0, 0)]
    public void ParsesActualBusyBoxLeadingFields(string listing,string mode,char type,uint uid,uint gid)
    {
        var parsed=FileMetadata.ParseListing(listing);
        Assert.Equal(new NumericFileMetadata(type,mode,uid,gid),parsed);
        Assert.Equal(listing[..10],FileMetadata.SymbolicMode(mode,type));
    }
    [Theory]
    [InlineData("")][InlineData("total 1\n-rwxr-xr-x 1 0 0 55880 ...")]
    [InlineData("-rwxr-xr-x 1 root root 55880 ...")][InlineData("-rwxr-xr-z 1 0 0 55880 ...")]
    [InlineData("-rwxr-xr-x 1 9999999999999 0 55880 ...")]
    public void MalformedListingBlocks(string listing)=>Assert.Throws<SafeFailure>(()=>FileMetadata.ParseListing(listing));
    [Theory]
    [InlineData("-rwxr-xr-x",0,0,"WARN")][InlineData("-rwx------",0,0,"PASS")]
    [InlineData("-rwxrwxr-x",0,0,"BLOCK")][InlineData("-rwxr-xrwx",0,0,"BLOCK")]
    [InlineData("-rwsr-xr-x",0,0,"BLOCK")][InlineData("-rwxr-Sr-x",0,0,"BLOCK")]
    [InlineData("-rwxr-xr-T",0,0,"BLOCK")][InlineData("-rwxr-xr-x",10,0,"BLOCK")]
    [InlineData("-rwxr-xr-x",0,10,"BLOCK")][InlineData("lrwxrwxrwx",0,0,"BLOCK")]
    public void InstallerAndHelperApplyIdenticalSafetyPolicy(string symbolic,uint uid,uint gid,string expected)
    {
        var parsed=FileMetadata.ParseListing($"{symbolic} 1 {uid} {gid} 55880 ... file with spaces");
        var fields=new Dictionary<string,string>{{"exists","1"},{"regular","1"},{"symlink",symbolic[0]=='l'?"1":"0"},{"readable","1"},{"type",parsed.Type.ToString()},{"mode",parsed.Mode},{"uid",parsed.Uid.ToString()},{"gid",parsed.Gid.ToString()},{"size","55880"},{"sha256",new string('a',64)}};
        var report=MetadataReview.Evaluate("/root/vpn-watch.sh",fields);
        Assert.Contains(report,f=>f.Status==expected);
        if(expected=="BLOCK") Assert.Throws<SafeFailure>(()=>FileMetadata.Validate("/root/vpn-watch.sh",fields));
        else {FileMetadata.Validate("/root/vpn-watch.sh",fields);Assert.DoesNotContain(report,f=>f.Status=="BLOCK");}
    }
    [Fact] public void ReplacementGuardsQuoteSpacesAndCheckRootMetadata()
    {
        var command=FileMetadata.MatchesCommand("/root/file with ' quote", "700");
        Assert.Contains("LC_ALL=C ls -ldn '/root/file with '\"'\"' quote'",command);
        Assert.Contains("'-rwx------:0:0'",command);
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task OptionalDiagnosticFailureCannotDecideProductionSafety(bool permanentlyUnavailable)
    {
        var router=new RoutingFixture(permanentlyUnavailable);
        var checks=new List<Check>();
        await RoutingDiagnostics.CollectTablesAsync(router,new[]{"1002","16800","9910"},checks.Add,default);
        Assert.Equal(3,checks.Count);Assert.Contains(checks,c=>c.Detail.Contains("unavailable"));
        Assert.Contains("ip -4 route show table 9910",router.Commands);
        checks.Clear();
        await RoutingDiagnostics.VerifyAsync(router,"vpn",checks.Add,default);
        Assert.Contains(checks,c=>c.Name=="Kill switch and IPv6" && c.Status==(permanentlyUnavailable?"BLOCK":"PASS"));
        if(permanentlyUnavailable)Assert.DoesNotContain(checks,c=>c.Status=="PASS");
    }
    private sealed class RoutingFixture(bool unavailable):IRouterTransport
    {
        public List<string> Commands=[];private int earlierReads;
        public Task UploadAsync(string p,string s,CancellationToken ct)=>throw new Exception("No writes allowed");
        public Task<string> ExecuteAsync(string command,CancellationToken ct)
        {
            Commands.Add(command);
            if(command=="ip -4 route show table 16800" && (++earlierReads==1||unavailable))throw new SafeFailure("Command failed.");
            return Task.FromResult(command switch {
                "uci -q get route_policy.vpn.killswitch || true" or "uci -q get route_policy.vpn.enabled || true"=>"1",
                "uci -q get glipv6.globals.enabled || true"=>"0",
                "uci -q get route_policy.vpn.tunnel_id"=>"42",
                "uci -q get route_policy.vpn.mark"=>"0x2000",
                "uci -q get route_policy.vpn.via"=>"wgclient2",
                "iptables -w -t mangle -S TUNNEL42_ROUTE_POLICY"=>"-A TUNNEL42_ROUTE_POLICY -m mark --mark 0x0/0xf000 -j MARK --set-xmark 0x2000/0xf000\n-A TUNNEL42_ROUTE_POLICY -m mark --mark 0x0/0xf000 -j DROP",
                var x when x.StartsWith("iptables -w -t mangle -C")=>"",
                "ip -4 rule show"=>"0: from all lookup local\n1: from all iif lo lookup 16800\n6000: from all fwmark 0x2000/0xf000 lookup 1002",
                "ip -4 route show table 1002"=>"default dev wgclient2\nblackhole default metric 254",
                "ip -4 route show table 16800" or "ip -4 route show table 9910" or "ip -4 route show table local"=>"",
                _=>throw new Exception("Unexpected production command")
            });
        }
    }
    [Fact] public void NoUnavailableMetadataCommandsInProduction()
    {
        var root=Program.FindRepository()!;
        var files=Directory.EnumerateFiles(Path.Combine(root,"BrumeHotswapper.Installer"),"*.cs",SearchOption.AllDirectories)
            .Where(p=>!p.Contains(Path.DirectorySeparatorChar+"obj"+Path.DirectorySeparatorChar)&&!p.Contains(Path.DirectorySeparatorChar+"bin"+Path.DirectorySeparatorChar))
            .Concat(Directory.EnumerateFiles(Path.Combine(root,"firmware"),"*.sh",SearchOption.AllDirectories));
        foreach(var path in files)Assert.False(Regex.IsMatch(File.ReadAllText(path),@"\bstat\b|\bfind\b[^\r\n]*-printf"),Path.GetFileName(path));
    }
}
