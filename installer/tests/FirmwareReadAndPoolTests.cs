using System.IO;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
using Renci.SshNet.Common;
namespace BrumeHotswapper.Tests;
public class FirmwareReadAndPoolTests
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
