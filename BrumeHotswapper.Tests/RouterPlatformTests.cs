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
            return new SecondPassTests.RouterFixture().ExecuteAsync(command,ct);
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
        var e=await Assert.ThrowsAsync<SafeFailure>(()=>new RouterInspection(router,new KillSwitchVerifier()).InspectAsync(SecondPassTests.Config(),default));
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
}
