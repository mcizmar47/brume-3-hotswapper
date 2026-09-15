using System.Text;
using System.IO;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
using BrumeHotswapper.Preflight;
namespace BrumeHotswapper.Tests;
public class FinalBlockerTests
{
    [Fact] public async Task HistoricalGuardIsPreservedByTransaction()
    {
        var router = new SecondPassTests.RouterFixture { FirmwareHash = CompatibilityCatalog.HistoricalPatchedHash };
        var installer = new RouterInstaller(router, new AcceptKill());
        var plan = await installer.PlanAsync(SecondPassTests.Config(CompatibilityCatalog.HistoricalPatchedHash), default);
        await installer.InstallAsync(plan, new Progress<string>(), default);
        Assert.Equal(0, router.RealPatches);
        Assert.Equal(CompatibilityCatalog.HistoricalPatchedHash, router.FirmwareHash);
    }
    private sealed class AcceptKill : IKillSwitchVerifier { public Task VerifyAsync(IRouterTransport r,string p,CancellationToken ct)=>Task.CompletedTask; }
    [Theory]
    [InlineData("6000: from all fwmark 0x8000/0xf000 lookup main", false)]
    [InlineData("6000: from all fwmark 0x1000/0xf000 lookup 1001", false)]
    [InlineData("6000: from all fwmark 0x2000/0x3000 lookup 1009", true)]
    [InlineData("6000: from all fwmark 0x2001/0xffff lookup 1009", true)]
    [InlineData("6000: not from all fwmark 0/0xf000 lookup main", true)]
    public void MaskOverlapUsesUnknownBitsConservatively(string rule,bool match) => Assert.Equal(match, RoutingProtection.CanMatch(rule, 0x2000));
    private const string Selected = "6000: from all fwmark 0x2000/0xf000 lookup 1002";
    private const string LiveRules = "0: from all lookup local\n1: from all iif lo lookup 16800\n800: from all lookup 9910 suppress_prefixlength 0\n6000: from all fwmark 0x8000/0xf000 lookup main\n" + Selected + "\n6000: from all fwmark 0x1000/0xf000 lookup 1001\n9000: not from all fwmark 0/0xf000 lookup main\n9910: not from all fwmark 0/0xf000 blackhole\n32766: from all lookup main";
    [Fact] public async Task LiveRuleShapeAcceptsOnlyVerifiedSafeEarlierTables()
    {
        var r = new RouteFixture();
        await new KillSwitchVerifier().VerifyAsync(r, "vpn", default);
        Assert.Contains("ip -4 route show table 16800", r.Reads);
        Assert.Contains("ip -4 route show table 9910", r.Reads);
        r.Earlier = "192.0.2.0/24 dev eth0";
        await Assert.ThrowsAsync<SafeFailure>(()=>new KillSwitchVerifier().VerifyAsync(r,"vpn",default));
    }
    [Theory]
    [InlineData("6000: from all fwmark 0x2000/0x3000 lookup 1009")]
    [InlineData("6000: from all fwmark 0x2000/0xf000 lookup 1009")]
    [InlineData("5000: from all fwmark 0x2000/0xf000 lookup 1009")]
    public async Task AmbiguousApplicableRulesBlock(string extra)
    {
        var r = new RouteFixture { Rules = LiveRules + "\n" + extra };
        await Assert.ThrowsAsync<SafeFailure>(()=>new KillSwitchVerifier().VerifyAsync(r,"vpn",default));
    }
    [Theory]
    [InlineData("default dev eth0\nblackhole default metric 254")]
    [InlineData("default dev wgclient2")]
    [InlineData("default dev wgclient1\nblackhole default metric 254")]
    [InlineData("blackhole default metric 254")]
    public async Task UnprotectedOrWrongActiveTableBlocks(string routes)
    {
        var r = new RouteFixture { Routes = routes };
        await Assert.ThrowsAsync<SafeFailure>(()=>new KillSwitchVerifier().VerifyAsync(r,"vpn",default));
    }
    private sealed class RouteFixture : IRouterTransport
    {
        public string Rules = LiveRules, Earlier = "", Routes = "default dev wgclient2 proto static scope link\nblackhole default proto static metric 254\n192.0.2.0/24 dev wgclient2 proto static scope link";
        public List<string> Reads = [];
        public Task UploadAsync(string p,string s,CancellationToken ct)=>throw new Exception("write");
        public Task<string> ExecuteAsync(string c,CancellationToken ct) {
            Reads.Add(c);
            return Task.FromResult(c switch {
                "ip -4 rule show" => Rules,
                "ip -4 route show table 1002" => Routes,
                "ip -4 route show table 1009" => "default dev eth0",
                "ip -4 route show table 16800" => Earlier,
                "ip -4 route show table 9910" => "default dev eth0", // suppressed default alone cannot escape
                "uci -q get route_policy.vpn.killswitch || true" or "uci -q get route_policy.vpn.enabled || true" => "1",
                "uci -q get glipv6.globals.enabled || true" => "0",
                "uci -q get route_policy.vpn.tunnel_id" => "42",
                "uci -q get route_policy.vpn.mark" => "0x2000",
                "uci -q get route_policy.vpn.via" => "wgclient2",
                "iptables -w -t mangle -S TUNNEL42_ROUTE_POLICY" => "-A TUNNEL42_ROUTE_POLICY -m mark --mark 0x0/0xf000 -j MARK --set-xmark 0x2000/0xf000\n-A TUNNEL42_ROUTE_POLICY -m mark --mark 0x0/0xf000 -j DROP",
                var x when x.StartsWith("iptables -w -t mangle -C") => "",
                _ => throw new Exception("Unexpected read")
            });
        }
    }
    [Fact] public async Task BusyBoxFieldsAreIndependentAndTrimmed()
    {
        var fields = await FileMetadata.ReadAsync(new MetadataFixture(), "/root/vpn-watch.sh", default);
        Assert.Equal("0", fields["uid"]); Assert.Equal("755", fields["mode"]); Assert.Equal("81001", fields["size"]);
        Assert.True(FileMetadata.Validate("/root/vpn-watch.sh", fields).Exists);
        Assert.All(FileMetadata.Commands("/root/vpn-watch.sh").Values, command => Assert.True(ReadOnlyTransport.IsAllowed(command)));
    }
    private sealed class MetadataFixture : IRouterTransport {
        public Task UploadAsync(string p,string s,CancellationToken ct)=>throw new Exception();
        public Task<string> ExecuteAsync(string c,CancellationToken ct)=>Task.FromResult(c switch {
            var x when x.StartsWith("if [ -L") => "0\r\n", var x when x.StartsWith("if [") => "1\n",
            var x when x.StartsWith("stat -c '%u'") || x.StartsWith("stat -c '%g'") => "0\n",
            var x when x.StartsWith("stat -c '%a'") => "755\n",
            var x when x.StartsWith("wc -c") => "   81001\n",
            var x when x.StartsWith("sha256sum") => new string('a',64)+"\n", _=>throw new Exception() });
    }
    [Theory] [InlineData(0)] [InlineData(256)] [InlineData(1048576)]
    public async Task UploadPreservesBytesAndPublishesOnlyAfterVerification(int length)
    {
        byte[] data = Enumerable.Range(0,length).Select(i=>(byte)i).ToArray();
        var ch = new UploadFixture(); var uploader = new DeploymentUpload(ch);
        await uploader.UploadAsync(DeploymentUpload.Stage+"/payload", data, default);
        Assert.Equal(data, ch.Data); Assert.True(ch.Published);
        Assert.DoesNotContain(ch.Commands, x=>x.Contains("base64"));
        Assert.DoesNotContain(ch.Commands, x=>x.Contains("synthetic-secret"));
    }
    [Theory] [InlineData("truncate")] [InlineData("hash")] [InlineData("size")]
    public async Task BadTransfersNeverPublish(string fault)
    {
        var ch = new UploadFixture { Fault = fault };
        await Assert.ThrowsAsync<SafeFailure>(()=>new DeploymentUpload(ch).UploadAsync(DeploymentUpload.Stage+"/payload", "synthetic-secret"u8.ToArray(), default));
        Assert.False(ch.Published); Assert.True(ch.Cleaned);
    }
    [Fact] public async Task CancelledTransferNeverPublishes()
    {
        var ch = new UploadFixture { Fault = "cancel" };
        await Assert.ThrowsAsync<OperationCanceledException>(()=>new DeploymentUpload(ch).UploadAsync(DeploymentUpload.Stage+"/payload", new byte[20000], default));
        Assert.False(ch.Published); Assert.True(ch.Cleaned);
    }
    [Theory] [InlineData("/root/final")] [InlineData("/root/.hotswap-installer/transaction/../final")]
    [InlineData("/root/.hotswap-installer/transaction/a';reboot")]
    [InlineData("/root/.hotswap-installer/transaction/owner")]
    public void UnsafePathsRejectBeforeChannel(string path) => Assert.Throws<SafeFailure>(()=>DeploymentUpload.ValidatePath(path));
    [Fact] public async Task CapabilitiesSelectStreamWithoutSftpAndBlockIfBothFail()
    {
        Assert.Equal(UploadKind.SshStream, await new DeploymentUpload(new UploadFixture()).ProbeAsync(default));
        Assert.Equal(UploadKind.Sftp, await new DeploymentUpload(new UploadFixture { StreamAvailable=false,SftpAvailable=true }).ProbeAsync(default));
        await Assert.ThrowsAsync<SafeFailure>(()=>new DeploymentUpload(new UploadFixture { StreamAvailable=false }).ProbeAsync(default));
    }
    [Fact] public async Task SftpFallbackUsesSameIntegrityGate()
    {
        var ch = new UploadFixture { StreamAvailable=false, SftpAvailable=true };
        await new DeploymentUpload(ch).UploadAsync(DeploymentUpload.Stage+"/payload", new byte[]{0,255,13,10}, default);
        Assert.True(ch.Published); Assert.Equal(new byte[]{0,255,13,10}, ch.Data);
    }
    [Fact] public async Task OversizedPayloadRejectedBeforeTransport()
    {
        var ch = new UploadFixture();
        await Assert.ThrowsAsync<SafeFailure>(()=>new DeploymentUpload(ch).UploadAsync(DeploymentUpload.Stage+"/payload", new byte[DeploymentUpload.MaximumBytes+1], default));
        Assert.Empty(ch.Commands);
    }
    private sealed class UploadFixture : IUploadChannel {
        public bool StreamAvailable=true,SftpAvailable,Published,Cleaned; public string Fault=""; public byte[] Data=[]; public List<string> Commands=[];
        public Task<bool> SftpAvailableAsync(CancellationToken ct)=>Task.FromResult(SftpAvailable);
        public Task SftpAsync(string p,ReadOnlyMemory<byte> b,CancellationToken ct) {Data=b.ToArray();return Task.CompletedTask;}
        public Task<string> StreamAsync(string c,ReadOnlyMemory<byte> b,CancellationToken ct) {
            Commands.Add(c);
            if(!StreamAvailable) throw new IOException();
            if(c.StartsWith("sha256sum")) return Task.FromResult(DeploymentUpload.Hash(b.Span));
            Data=b.ToArray();
            if(Fault=="cancel") {Data=Data[..10];throw new OperationCanceledException();}
            if(Fault=="truncate") Data=Data[..^1];
            return Task.FromResult("");
        }
        public Task<string> CommandAsync(string c,CancellationToken ct) {
            Commands.Add(c);
            if(c.StartsWith("cat ")) return Task.FromResult(new string('a',32));
            if(c.StartsWith("if test")) Cleaned=true;
            if(c.Contains(" && mv -f ")) Published=true;
            else if(c.Contains(" && wc -c <")) return Task.FromResult((Data.Length+(Fault=="size"?1:0))+"\n"+(Fault=="hash"?new string('b',64):DeploymentUpload.Hash(Data))+"\n");
            return Task.FromResult("");
        }
    }
}
