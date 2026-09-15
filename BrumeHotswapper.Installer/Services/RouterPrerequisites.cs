using BrumeHotswapper.Installer.Core;
namespace BrumeHotswapper.Installer.Services;
public static class RouterPrerequisites
{
    public const string PendingCommand = "if [ -e /root/.hotswap-installer/transaction ] || [ -L /root/.hotswap-installer/transaction ] || [ -e /tmp/vpn-watch-installer-lock ] || [ -L /tmp/vpn-watch-installer-lock ]; then echo pending; else echo clear; fi";
    public const string CapabilitiesCommand = "test -x /usr/bin/setup_instance && test -x /etc/init.d/dnsmasq && command -v wg >/dev/null && command -v crontab >/dev/null && command -v sha256sum >/dev/null && command -v iptables >/dev/null && command -v ls >/dev/null && command -v wc >/dev/null && test \"$(id -u)\" = 0";
    public static async Task EnsureNoTransactionAsync(IRouterTransport router,CancellationToken ct)
    {
        if ((await router.ExecuteAsync(PendingCommand,ct)).Trim() != "clear")
            throw new SafeFailure("A pending transaction or lock requires review before installation.");
    }
    public static async Task VerifyFirmwareAsync(IRouterTransport router,RouterIdentity identity,CancellationToken ct)
    {
        if (!identity.IsBrume || !CompatibilityCatalog.TestedFirmware.Contains(identity.Firmware)) throw new SafeFailure("Unsupported router identity or firmware version.");
        var hash=(await router.ExecuteAsync("sha256sum /usr/bin/rtp2.sh | awk '{print $1}'",ct)).Trim();
        if (hash != identity.Rtp2Hash || CompatibilityCatalog.Classify(hash) is Compatibility.Unknown or Compatibility.KnownIncompatible)
            throw new SafeFailure("Firmware changed or its compatibility is not established.");
        var marker=(await router.ExecuteAsync("grep -Fc '# vpn-watch GL reconciliation guard v1' /usr/bin/rtp2.sh || true",ct)).Trim();
        if (marker != (CompatibilityCatalog.IsPatched(hash)?"1":"0")) throw new SafeFailure("Firmware guard marker differs from the verified catalog state.");
        await router.ExecuteAsync("test \"$(grep -Fxc 'cmd=\"$1\";shift' /usr/bin/rtp2.sh)\" = 1 && sh -n /usr/bin/rtp2.sh",ct);
    }
}
