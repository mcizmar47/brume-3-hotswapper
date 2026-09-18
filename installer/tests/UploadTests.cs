using System.IO;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Tests;
public class UploadTests
{
    private const string TestStage = "/root/hotswapper/installer/run-0123456789abcdef0123456789abcdef";
    [Theory] [InlineData(65536)]
    public async Task UploadPreservesBytesAndPublishesOnlyAfterVerification(int length)
    {
        byte[] data = Enumerable.Range(0,length).Select(i=>(byte)i).ToArray();
        var ch = new UploadFixture(); var uploader = new DeploymentUpload(ch);
        await uploader.UploadAsync(TestStage+"/payload", data, default);
        Assert.Equal(data, ch.Data); Assert.True(ch.Published);
        Assert.DoesNotContain(ch.Commands, x=>x.Contains("base64"));
        Assert.DoesNotContain(ch.Commands, x=>x.Contains("synthetic-secret"));
    }
    [Theory] [InlineData("truncate")] [InlineData("hash")]
    public async Task BadTransfersNeverPublish(string fault)
    {
        var ch = new UploadFixture { Fault = fault };
        await Assert.ThrowsAsync<SafeFailure>(()=>new DeploymentUpload(ch).UploadAsync(TestStage+"/payload", "synthetic-secret"u8.ToArray(), default));
        Assert.False(ch.Published); Assert.True(ch.Cleaned);
    }
    [Fact] public async Task CancelledTransferNeverPublishes()
    {
        var ch = new UploadFixture { Fault = "cancel" };
        await Assert.ThrowsAsync<OperationCanceledException>(()=>new DeploymentUpload(ch).UploadAsync(TestStage+"/payload", new byte[20000], default));
        Assert.False(ch.Published); Assert.True(ch.Cleaned);
    }
    [Theory] [InlineData("/root/final")] [InlineData("/root/hotswapper/installer/run-0123456789abcdef0123456789abcdef/../final")]
    [InlineData("/root/hotswapper/installer/run-0123456789abcdef0123456789abcdef/a';reboot")]
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
        await new DeploymentUpload(ch).UploadAsync(TestStage+"/payload", new byte[]{0,255,13,10}, default);
        Assert.True(ch.Published); Assert.Equal(new byte[]{0,255,13,10}, ch.Data);
    }
    [Fact] public async Task OversizedPayloadRejectedBeforeTransport()
    {
        var ch = new UploadFixture();
        await Assert.ThrowsAsync<SafeFailure>(()=>new DeploymentUpload(ch).UploadAsync(TestStage+"/payload", new byte[DeploymentUpload.MaximumBytes+1], default));
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
