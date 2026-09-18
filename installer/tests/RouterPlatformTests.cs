using System.IO;
using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Tests;
public class RouterPlatformTests
{
    private sealed class FailingTransport(string failed) : IRouterTransport
    {
        public List<string> Commands { get; } = [];
        public Task UploadAsync(string path,string content,CancellationToken ct) => throw new NotSupportedException();
        public Task<string> ExecuteAsync(string command,CancellationToken ct)
        {
            Commands.Add(command);
            if (command == failed) throw new RouterCommandFailure(127);
            return new InstallerFixture.RouterFixture().ExecuteAsync(command,ct);
        }
    }
    [Fact] public async Task PrerequisitesDoNotRequireSessionUtilityOrFractionalSleep()
    {
        var router = new FailingTransport("never");
        await RouterPrerequisites.VerifyCapabilitiesAsync(router,default);
        Assert.Equal(new[] {RouterPrerequisites.CapabilitiesCommand,RouterPrerequisites.DelayCommand},router.Commands);
        Assert.DoesNotContain("setsid",RouterPrerequisites.CapabilitiesCommand);
        Assert.DoesNotContain("sleep 0.",RouterPrerequisites.CapabilitiesCommand);
        Assert.Contains("busybox usleep 150000",RouterPrerequisites.DelayCommand);
    }
    [Theory]
    [InlineData(false,"required utilities and root access")]
    [InlineData(true,"sub-second delay behavior")]
    public async Task PrerequisiteFailureReportsOperationAndStatus(bool delay,string operation)
    {
        var router = new FailingTransport(delay?RouterPrerequisites.DelayCommand:RouterPrerequisites.CapabilitiesCommand);
        var e = await Assert.ThrowsAsync<SafeFailure>(()=>RouterPrerequisites.VerifyCapabilitiesAsync(router,default));
        Assert.Contains(operation,e.Message);
        Assert.Contains("exit status 127",e.Message);
        Assert.Contains("output withheld",e.Message);
        Assert.DoesNotContain("/usr/bin",e.Message);
    }
    [Theory]
    [InlineData("ubus call system board","device identity and firmware")]
    [InlineData("uci -q get route_policy.vpn.group_id","VPN policy, slot ownership and profile membership")]
    [InlineData("ip -4 rule show","selected VPN routing and GL enforcement")]
    public async Task InspectionFailureUsesStaticStageNotRawCommand(string command,string stage)
    {
        var router=new FailingTransport(command);
        var e=await Assert.ThrowsAsync<SafeFailure>(()=>new RouterInspection(router,new KillSwitchVerifier()).InspectAsync(InstallerFixture.Config(),default));
        Assert.Equal($"Router inspection failed: {stage} (exit status 127); output withheld.",e.Message);
        Assert.DoesNotContain(command,e.Message);
    }
    private sealed class FailedUpload : IUploadChannel
    {
        public Task<bool> SftpAvailableAsync(CancellationToken ct)=>Task.FromResult(false);
        public Task<string> StreamAsync(string command,ReadOnlyMemory<byte> bytes,CancellationToken ct)=>throw new RouterCommandFailure(127);
        public Task SftpAsync(string path,ReadOnlyMemory<byte> bytes,CancellationToken ct)=>throw new NotSupportedException();
        public Task<string> CommandAsync(string command,CancellationToken ct)=>throw new NotSupportedException();
    }
    [Fact] public async Task UploadCapabilityFailureRetainsExitStatus()
    {
        var e=await Assert.ThrowsAsync<SafeFailure>(()=>new DeploymentUpload(new FailedUpload()).ProbeAsync(default));
        Assert.Contains("Deployment transport capability check",e.Message);
        Assert.Contains("exit status 127",e.Message);
        Assert.DoesNotContain("sha256sum",e.Message);
    }
    [Fact] public void ProductionUsesSupportedRouterPrimitives()
    {
        var root=RepositoryFiles.Root;
        var files=Directory.EnumerateFiles(Path.Combine(root,"installer"),"*.cs",SearchOption.AllDirectories)
            .Where(p=>!p.Contains(Path.DirectorySeparatorChar+"tests"+Path.DirectorySeparatorChar)&&!p.Contains(Path.DirectorySeparatorChar+"obj"+Path.DirectorySeparatorChar)&&!p.Contains(Path.DirectorySeparatorChar+"bin"+Path.DirectorySeparatorChar))
            .Concat(Directory.EnumerateFiles(Path.Combine(root,"firmware"),"*.sh",SearchOption.AllDirectories));
        files = files.Concat(Directory.EnumerateFiles(root,"*.sh"));
        foreach(var path in files)
            Assert.False(Regex.IsMatch(File.ReadAllText(path),@"\bstat\b|\bfind\b[^\r\n]*-printf|\bsetsid\b|\bsleep\s+[0-9]+\.[0-9]+"),Path.GetFileName(path));
        Assert.Contains("busybox usleep \"$1\"",File.ReadAllText(Path.Combine(root,"hotswapper-main.sh")));
    }
    [Fact] public void DiscoveryUsesGatewayAndNonGatewaySubnetEdgesWithoutScanning()
    {
        var candidates=RouterDiscovery.Candidates([new("10.20.30.40",24,["10.20.30.253"]),new("172.20.8.10",24,[])]);
        Assert.Equal("10.20.30.253",candidates[0]);
        Assert.Contains("172.20.8.1",candidates);Assert.Contains("172.20.8.254",candidates);
        Assert.DoesNotContain("10.20.30.40",candidates);Assert.True(candidates.Count<=16);
        Assert.Empty(RouterDiscovery.Candidates([new("10.0.0.1",32,[])]));
    }
}
