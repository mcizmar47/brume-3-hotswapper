using System.IO;
using BrumeHotswapper.Preflight;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
using Renci.SshNet.Common;
namespace BrumeHotswapper.Tests;
public class PreflightFollowUpTests
{
    [Fact] public async Task FirmwareReadPreservesExactBinaryBytes()
    {
        byte[] bytes = [0, 255, 128, 13, 10, 239, 187, 191, 65];
        Assert.Equal(bytes, await FirmwareRead.CopyBoundedAsync(new MemoryStream(bytes), default));
        Assert.Equal(bytes, await FirmwareRead.CopyBoundedAsync(new MemoryStream(bytes), default));
    }
    [Fact] public async Task FirmwareReadIsBoundedAndCancellable()
    {
        await Assert.ThrowsAsync<SafeFailure>(() => FirmwareRead.CopyBoundedAsync(new MemoryStream(new byte[FirmwareRead.MaximumBytes + 1]), default));
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => FirmwareRead.CopyBoundedAsync(new MemoryStream([1]), cancel.Token));
    }
    [Fact] public void SftpDiagnosticsNeverRepeatServerText()
    {
        var category = FirmwareRead.FailureCategory(new SshException("subsystem request failed; synthetic-secret-value"));
        Assert.Contains("subsystem", category); Assert.DoesNotContain("synthetic-secret", category);
        Assert.DoesNotContain("synthetic-secret", FirmwareRead.FailureCategory(new IOException("synthetic-secret")));
    }
    private static string Metadata(string mode = "755", string uid = "0", string gid = "0", string symlink = "0") =>
        $"symlink={symlink}\r\nexists=1\r\ntype=-\r\nregular=1\r\nreadable=1\r\nuid={uid}\r\ngid={gid}\r\nmode={mode}\r\nsize=1234\r\nsha256={new string('a',64)}\r\n";
    [Fact] public void RepairableScript755WarnsAndFirmware755Passes()
    {
        var script = MetadataReview.Evaluate("/root/hotswapper-main.sh", Metadata());
        Assert.DoesNotContain(script, x => x.Status == "BLOCK");
        Assert.Contains(script, x => x.Name.EndsWith(" / mode") && x.Status == "WARN");
        Assert.All(MetadataReview.Evaluate("/usr/bin/rtp2.sh", Metadata()), x => Assert.Equal("PASS", x.Status));
        Assert.Contains(MetadataReview.Evaluate("/usr/bin/rtp2.sh", Metadata("644")), x => x.Name.EndsWith(" / mode") && x.Status == "BLOCK");
        Assert.Contains(MetadataReview.Evaluate("/root/hotswapper/hotswapper.conf", Metadata("644")), x => x.Name.EndsWith(" / mode") && x.Status == "WARN");
    }
    [Theory]
    [InlineData("777", "0", "0", "0", "mode")]
    [InlineData("4755", "0", "0", "0", "mode")]
    [InlineData("755", "10", "0", "0", "uid")]
    [InlineData("755", "0", "10", "0", "gid")]
    [InlineData("755", "0", "0", "1", "symlink")]
    public void UnsafeMetadataIsNotNormalizedSilently(string mode,string uid,string gid,string link,string field)
    {
        Assert.Contains(MetadataReview.Evaluate("/root/hotswapper-main.sh", Metadata(mode,uid,gid,link)), x => x.Name.EndsWith(" / " + field) && x.Status == "BLOCK");
    }
    [Fact] public void MissingGeneratedFileIsNotCorruption()
    {
        var checks = MetadataReview.Evaluate("/root/hotswapper/hotswapper-locations.tsv", "symlink=0\nexists=0\n");
        Assert.DoesNotContain(checks, x => x.Status == "BLOCK");
        Assert.Contains(checks, x => x.Detail.Contains("required after installation"));
    }
    [Theory]
    [InlineData(9)] [InlineData(160)] [InlineData(600)]
    public void PoolGenerationKeepsEveryPeerWithoutSmallCountAssumptions(int count)
    {
        var peers = Enumerable.Range(1,count).Select(i => new VpnConnection(i.ToString(), "", "Example,City " + (i % 9))).ToArray();
        var groups = new ExactLocationResolver().Group(peers);
        var c = SecondPassTests.Config(); foreach(var tier in c.Tiers) tier.Locations.Clear();
        foreach(var group in groups) c.Tiers[1].Locations.Add(group);
        c = c with { Profile = c.Profile with { Connections = peers } };
        var rows = ConfigurationGenerator.Locations(c).Split('\n',StringSplitOptions.RemoveEmptyEntries).Select(x => x.Split('\t')).ToArray();
        Assert.Equal(count,rows.Length); Assert.Equal(9,groups.Count); Assert.Equal(count,rows.Select(x => x[5]).Distinct().Count());
    }
}
