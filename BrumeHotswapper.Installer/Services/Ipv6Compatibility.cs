using BrumeHotswapper.Installer.Core;
namespace BrumeHotswapper.Installer.Services;
public static class Ipv6Compatibility
{
    public static async Task VerifyAsync(IRouterTransport router, CancellationToken ct)
    {
        if ((await router.ExecuteAsync("uci -q get glipv6.globals.enabled || true", ct)).Trim() != "0")
            throw new SafeFailure("IPv6 must be disabled for the current IPv4-only Hotswapper promotion path, independently of the GL kill-switch choice.");
    }
}
