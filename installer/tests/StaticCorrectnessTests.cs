using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
using static BrumeHotswapper.Tests.InstallerFixture;

namespace BrumeHotswapper.Tests;

public class StaticCorrectnessTests
{
    [Fact] public async Task ConcurrentInstallerIsRefusedBeforeUploading()
    {
        var router = new RouterFixture();
        var installer = new RouterInstaller(router, new KillSwitchVerifier());
        var plan = await installer.PlanAsync(Config(), default);
        await using (await router.AcquireInstallerLockAsync(default))
        {
            var error = await Assert.ThrowsAsync<SafeFailure>(() => installer.InstallAsync(plan, new Progress<string>(), default));
            Assert.Contains("Another installer", error.Message);
            Assert.Empty(router.Uploads);
        }
        await using var next = await router.AcquireInstallerLockAsync(default);
    }
    [Theory]
    [InlineData("selector DROP")]
    [InlineData("unusable CURRENT")]
    public async Task FailedOperationalCheckCannotReportSuccess(string reason)
    {
        var router = new UnhealthyCurrent(reason);
        var installer = new RouterInstaller(router, new KillSwitchVerifier());
        var plan = await installer.PlanAsync(Config(), default);
        var error = await Assert.ThrowsAsync<SafeFailure>(() => installer.InstallAsync(plan, new Progress<string>(), default));
        Assert.Contains("CURRENT", error.Message);
        Assert.Contains(router.Inner.Uploads.Values, text => text.StartsWith("unfinished;"));
    }
    private sealed class UnhealthyCurrent(string reason) : IRouterTransport
    {
        public RouterFixture Inner { get; } = new();
        public Task<IAsyncDisposable> AcquireInstallerLockAsync(CancellationToken ct) => Inner.AcquireInstallerLockAsync(ct);
        public Task UploadAsync(string path, string content, CancellationToken ct) => Inner.UploadAsync(path, content, ct);
        public Task<string> ExecuteAsync(string command, CancellationToken ct) => command == "/root/hotswapper-main.sh verify-current"
            ? throw new SafeFailure("CURRENT: " + reason) : Inner.ExecuteAsync(command, ct);
    }
}
