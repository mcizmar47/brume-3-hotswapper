using BrumeHotswapper.Installer.Core;
namespace BrumeHotswapper.Installer.Services;
public static class RouterPrerequisites
{
    public const string CapabilitiesCommand = "test -x /usr/bin/setup_instance && test -x /etc/init.d/dnsmasq && command -v ping >/dev/null && command -v ubus >/dev/null && command -v jsonfilter >/dev/null && sleep 0 && command -v wg >/dev/null && command -v crontab >/dev/null && command -v sha256sum >/dev/null && command -v iptables >/dev/null && command -v ls >/dev/null && command -v wc >/dev/null && test \"$(id -u)\" = 0";
    // Same primitive, duration and /proc/uptime bounds as daemon verify_delay.
    public const string DelayCommand = "test -r /proc/uptime && before=$(awk '{printf \"%.0f\\n\", $1 * 1000}' /proc/uptime) && busybox usleep 150000 && after=$(awk '{printf \"%.0f\\n\", $1 * 1000}' /proc/uptime) && elapsed=$((after-before)) && test \"$elapsed\" -ge 140 && test \"$elapsed\" -lt 500";
    public static async Task VerifyCapabilitiesAsync(IRouterTransport router, CancellationToken ct)
    {
        try { await router.ExecuteAsync(CapabilitiesCommand, ct); }
        catch (RouterCommandFailure e) { throw new SafeFailure($"Router prerequisite check failed: required utilities and root access (exit status {e.ExitStatus?.ToString() ?? "unknown"}); output withheld."); }
        try { await router.ExecuteAsync(DelayCommand, ct); }
        catch (RouterCommandFailure e) { throw new SafeFailure($"Router prerequisite check failed: sub-second delay behavior (BusyBox usleep, exit status {e.ExitStatus?.ToString() ?? "unknown"}); output withheld."); }
    }
    public static async Task VerifyFirmwareAsync(IRouterTransport router,RouterIdentity identity,CancellationToken ct)
    {
        if (!identity.IsBrume || !CompatibilityCatalog.TestedFirmware.Contains(identity.Firmware)) throw new SafeFailure("Unsupported router identity or firmware version.");
        var hash=(await router.ExecuteAsync("sha256sum /usr/bin/rtp2.sh | awk '{print $1}'",ct)).Trim();
        if (hash != identity.Rtp2Hash || CompatibilityCatalog.Classify(hash) is Compatibility.Unknown or Compatibility.KnownIncompatible)
            throw new SafeFailure("Firmware changed or its compatibility is not established.");
        foreach (var target in FirmwareTargets.All)
        {
            var actual = (await router.ExecuteAsync($"sha256sum {target.Path} | awk '{{print $1}}'", ct)).Trim();
            if (!target.Supports(actual)) throw new SafeFailure("Unsupported GL coordination target: " + target.Path);
        }
        await router.ExecuteAsync("busybox --list | grep -Fxq flock", ct);
        await router.ExecuteAsync("command -v iptables-restore >/dev/null && command -v lua >/dev/null", ct);
    }
}
