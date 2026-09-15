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
            var x when x.StartsWith("LC_ALL=C ls -ldn ") => "-rwxr-xr-x    1 0 0 55880 Jan 1 00:00 /root/vpn-watch.sh\n",
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
