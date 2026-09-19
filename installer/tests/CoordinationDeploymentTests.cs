using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
using static BrumeHotswapper.Tests.InstallerFixture;
namespace BrumeHotswapper.Tests;

public class CoordinationDeploymentTests
{
    [Fact] public void CatalogCoversEveryTargetAndDistinguishesPreviousGuard()
    {
        Assert.Equal(10,FirmwareTargets.All.Count);
        Assert.Equal(CompatibilityCatalog.PatchedHash,FirmwareTargets.Find("/usr/bin/rtp2.sh")!.PatchedHash);
        Assert.All(FirmwareTargets.All,t => Assert.Contains(t.Path,DeploymentPlanning.Paths));
        Assert.True(FirmwareTargets.Find("/usr/bin/rtp2.sh")!.Supports(CompatibilityCatalog.PreviousGuardHash));
        Assert.DoesNotContain(FirmwareTargets.All.Where(t=>t.Id!="rtp"),t=>t.Supports(CompatibilityCatalog.PreviousGuardHash));
    }

    [Fact] public async Task UnknownAdditionalFirmwareIsRejectedBeforeUpload()
    {
        var fake=new RouterFixture();
        fake.FirmwareHashes["/usr/bin/tunnel-switch.sh"]=new string('f',64);
        await Assert.ThrowsAsync<SafeFailure>(()=>new RouterInstaller(fake,new KillSwitchVerifier()).PlanAsync(Config(),default));
        Assert.Empty(fake.Uploads);
    }

    [Fact] public async Task PartialFirmwarePatchFailureRestoresAllChangedTargets()
    {
        var fake=new RouterFixture();
        var transport=new FailedPatch(fake);
        var installer=new RouterInstaller(transport,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(Config(),default);
        var error=await Assert.ThrowsAsync<SafeFailure>(()=>installer.InstallAsync(plan,new Progress<string>(),default));
        Assert.Contains("rolled back",error.Message);
        Assert.Equal(CompatibilityCatalog.StockHash,fake.FirmwareHash);
        Assert.All(FirmwareTargets.All.Where(t=>t.Id!="rtp"),t=>Assert.Equal(t.StockHash,fake.FirmwareHashes[t.Path]));
        Assert.Empty(fake.Installed);
    }

    [Theory]
    [InlineData("uci -q get route_policy.vpn.via_type || true", "autovpn")]
    [InlineData("uci -q get route_policy.global.instance_on || true", "0")]
    [InlineData("uci -q get route_policy.gl_process_vpn.via || true", "wgclient5")]
    public async Task UnsupportedRuntimeContractStopsBeforeUpload(string command,string value)
    {
        var fake=new RouterFixture();
        var installer=new RouterInstaller(new OverrideRead(fake,command,value),new KillSwitchVerifier());
        await Assert.ThrowsAsync<SafeFailure>(()=>installer.PlanAsync(Config(),default));
        Assert.Empty(fake.Uploads);
    }

    private sealed class OverrideRead(RouterFixture inner,string command,string value):IRouterTransport
    {
        public Task UploadAsync(string path,string body,CancellationToken ct)=>inner.UploadAsync(path,body,ct);
        public Task<string> ExecuteAsync(string request,CancellationToken ct)=>
            request==command?Task.FromResult(value):inner.ExecuteAsync(request,ct);
    }

    private sealed class FailedPatch(RouterFixture inner):IRouterTransport
    {
        public Task UploadAsync(string path,string body,CancellationToken ct)=>inner.UploadAsync(path,body,ct);
        public Task<string> ExecuteAsync(string command,CancellationToken ct)
        {
            if(command=="/root/hotswapper/install-gl-guard.sh --install")
            {
                inner.FirmwareHash=CompatibilityCatalog.PatchedHash;
                foreach(var t in FirmwareTargets.All.Where(t=>t.Id!="rtp").Take(3))
                    inner.FirmwareHashes[t.Path]=t.PatchedHash;
                throw new RouterCommandFailure(1);
            }
            return inner.ExecuteAsync(command,ct);
        }
    }
}
